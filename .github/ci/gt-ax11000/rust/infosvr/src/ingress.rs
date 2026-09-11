//! One permanently device-bound UDP socket per authorized interface.
//! Binding precedes port activation; outbound replies never unbind ingress.
use std::ffi::CString;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub struct Ingress {
    sockets: Vec<UdpSocket>,
    next: usize,
}
impl Ingress {
    pub fn broadcast(&self, port: u16, packet: &[u8]) {
        for socket in &self.sockets {
            // Replies retain UDP source port 9999 and the original ingress binding.
            let _ = socket.send_to(packet, (std::net::Ipv4Addr::BROADCAST, port));
        }
    }
    pub fn open(interfaces: &[String], port: u16) -> io::Result<Self> {
        let sockets = interfaces
            .iter()
            .map(|name| open_bound(name, port))
            .collect::<io::Result<Vec<_>>>()?;
        if sockets.is_empty() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        Ok(Self { sockets, next: 0 })
    }

    pub fn recv_from(&mut self, bytes: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            for offset in 0..self.sockets.len() {
                let index = (self.next + offset) % self.sockets.len();
                match self.sockets[index].recv_from(bytes) {
                    Ok(value) => {
                        self.next = (index + 1) % self.sockets.len();
                        return Ok(value);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
            let mut fds: Vec<_> = self
                .sockets
                .iter()
                .map(|s| libc::pollfd {
                    fd: s.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            // SAFETY: initialized pollfd array, live descriptors, bounded by
            // the daemon's five-interface limit; poll retains no pointer.
            if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
                return Err(io::Error::last_os_error());
            }
            if fds
                .iter()
                .any(|fd| fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0)
            {
                return Err(io::Error::other("discovery socket failed"));
            }
        }
    }
}

fn open_bound(interface: &str, port: u16) -> io::Result<UdpSocket> {
    let name = CString::new(interface).map_err(|_| io::ErrorKind::InvalidInput)?;
    if interface.is_empty() || interface.len() >= libc::IFNAMSIZ {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: no borrowed pointers; successful fd is immediately owned.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh unique socket descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: name is NUL-terminated and remains live through setsockopt.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    // SAFETY: address and length describe an initialized IPv4 socket address.
    if unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let socket = UdpSocket::from(owned);
    socket.set_broadcast(true)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_interfaces_fail_closed() {
        for name in ["", "bad\0name", "interface-name-too-long", "no-such-dev"] {
            assert!(open_bound(name, 0).is_err());
        }
        assert!(Ingress::open(&[], 0).is_err());
    }
}
