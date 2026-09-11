//! A single connection budget, shared by every read and write.
//! Socket timeout failures are errors, never permission to block indefinitely.
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub struct DeadlineStream {
    socket: TcpStream,
    deadline: Instant,
    operation_limit: Duration,
}

impl DeadlineStream {
    pub fn new(socket: TcpStream, total: Duration, operation_limit: Duration) -> io::Result<Self> {
        if total.is_zero() || operation_limit.is_zero() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let deadline = Instant::now()
            .checked_add(total)
            .ok_or(io::ErrorKind::InvalidInput)?;
        Ok(Self {
            socket,
            deadline,
            operation_limit,
        })
    }

    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(remaining.min(self.operation_limit))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(buffer)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.socket.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (listener.accept().unwrap().0, peer)
    }

    #[test]
    fn expired_budget_refuses_reads_writes_and_flush_even_if_socket_is_ready() {
        let (socket, mut peer) = pair();
        peer.write_all(b"ready").unwrap();
        let mut stream =
            DeadlineStream::new(socket, Duration::from_secs(2), Duration::from_secs(1)).unwrap();
        stream.deadline = Instant::now();
        assert_eq!(
            stream.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream.write(b"late").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(stream.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn a_late_read_uses_remaining_budget_not_a_fresh_operation_timeout() {
        let (socket, _peer) = pair();
        let mut stream =
            DeadlineStream::new(socket, Duration::from_secs(2), Duration::from_secs(1)).unwrap();
        stream.deadline = Instant::now() + Duration::from_millis(80);
        let started = Instant::now();
        let error = stream.read(&mut [0]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_millis(700));
        assert!(stream.socket.read_timeout().unwrap().unwrap() <= Duration::from_millis(85));
    }

    #[test]
    fn successful_io_keeps_the_original_deadline() {
        let (socket, mut peer) = pair();
        let mut stream =
            DeadlineStream::new(socket, Duration::from_secs(2), Duration::from_secs(1)).unwrap();
        let deadline = stream.deadline;
        peer.write_all(b"a").unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"a");
        stream.write_all(b"b").unwrap();
        peer.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"b");
        assert_eq!(stream.deadline, deadline);
    }
}
