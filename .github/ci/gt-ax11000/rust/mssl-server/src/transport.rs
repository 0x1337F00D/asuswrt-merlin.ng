//! Narrow socket boundary. Never owns or closes the caller's descriptor.
//! A single absolute deadline applies to each high-level TLS operation.
#![deny(unsafe_op_in_unsafe_fn)]

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::time::{Duration, Instant};

/// The borrow prevents Rust callers from closing the socket during an operation.
pub struct Socket<'a> {
    fd: BorrowedFd<'a>,
    deadline: Instant,
}

impl<'a> Socket<'a> {
    pub fn new(fd: BorrowedFd<'a>, timeout: Duration) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(Self { fd, deadline })
    }

    fn wait(&self, events: libc::c_short) -> io::Result<()> {
        loop {
            let left = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
            let millis = left.as_millis().saturating_add(1).min(i32::MAX as u128) as i32;
            let mut pollfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: one valid pollfd; poll cannot outlive this stack frame.
            let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            if pollfd.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            // HUP/ERR must reach recv/send to report EOF or the socket error.
            if pollfd.revents & (events | libc::POLLHUP | libc::POLLERR) != 0 {
                return Ok(());
            }
        }
    }
}

impl Read for Socket<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.wait(libc::POLLIN)?;
            // SAFETY: the borrowed descriptor remains live and the writable
            // slice is valid for exactly the supplied length. Never block
            // after poll (another reader could have consumed the data).
            let count = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if count >= 0 {
                return Ok(count as usize);
            }
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
    }
}

impl Write for Socket<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.wait(libc::POLLOUT)?;
            // SAFETY: live borrowed fd and readable slice. MSG_NOSIGNAL avoids
            // changing the process-wide signal disposition of the C caller.
            let count = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if count >= 0 {
                return Ok(count as usize);
            }
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn idle_read_is_bounded_without_changing_fd_flags() {
        let (a, _b) = UnixStream::pair().unwrap();
        let start = Instant::now();
        let mut socket = Socket::new(a.as_fd(), Duration::from_millis(30)).unwrap();
        assert_eq!(
            socket.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        // The caller still owns a usable descriptor after the adapter expires.
        assert!(a.peer_addr().is_ok());
    }

    #[test]
    fn eof_is_not_a_timeout_and_does_not_close_caller_fd() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(b);
        let mut socket = Socket::new(a.as_fd(), Duration::from_secs(1)).unwrap();
        assert_eq!(socket.read(&mut [0]).unwrap(), 0);
        assert!(socket.write(b"x").is_err());
        assert!(a.peer_addr().is_ok());
    }
}
