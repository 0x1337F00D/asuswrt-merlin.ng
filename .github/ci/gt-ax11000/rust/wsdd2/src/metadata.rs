//! Bounded nonblocking transport; protocol policy stays in the service state.
//! No worker threads, shared locks, detached sockets or unbounded work queues.
#![forbid(unsafe_code)]
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use wsdd2::http::{self, Progress, Status};

const MAX_CONNECTIONS: usize = 8;
const MAX_REPLY: usize = 65536;
const LIFETIME: Duration = Duration::from_secs(2);
const IO_STEPS: usize = 8;

enum Phase {
    Reading(Vec<u8>),
    Writing { bytes: Vec<u8>, offset: usize },
}
struct Connection {
    stream: TcpStream,
    accepted: Instant,
    phase: Phase,
}

#[derive(Default)]
pub struct Pool {
    connections: Vec<Connection>,
}
impl Pool {
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Saturation closes the new descriptor immediately, without a blocking reply.
    pub fn insert(&mut self, stream: TcpStream) -> io::Result<bool> {
        if self.connections.len() == MAX_CONNECTIONS {
            return Ok(false);
        }
        stream.set_nonblocking(true)?;
        self.connections.push(Connection {
            stream,
            accepted: Instant::now(),
            phase: Phase::Reading(Vec::with_capacity(http::MAX_REQUEST)),
        });
        Ok(true)
    }

    pub fn tick(
        &mut self,
        endpoint: &str,
        mut reply: impl FnMut(Result<&[u8], Status>) -> Option<Vec<u8>>,
    ) {
        self.connections
            .retain_mut(|connection| connection.step(endpoint, &mut reply));
    }
}

impl Connection {
    fn step(
        &mut self,
        endpoint: &str,
        reply: &mut impl FnMut(Result<&[u8], Status>) -> Option<Vec<u8>>,
    ) -> bool {
        if self.accepted.elapsed() >= LIFETIME {
            return false;
        }
        for _ in 0..IO_STEPS {
            if self.accepted.elapsed() >= LIFETIME {
                return false;
            }
            match &mut self.phase {
                Phase::Reading(buffer) => {
                    let request = match http::parse_header(buffer, endpoint) {
                        Progress::Failed(status) => Some(Err(status)),
                        Progress::Header {
                            body_offset,
                            content_length,
                        } => match body_offset.checked_add(content_length) {
                            Some(total) if total <= http::MAX_REQUEST => {
                                buffer.get(body_offset..total).map(Ok)
                            }
                            _ => Some(Err(Status::TooLarge)),
                        },
                        Progress::Incomplete => None,
                    };
                    if let Some(request) = request {
                        let Some(bytes) = reply(request) else {
                            return false;
                        };
                        if bytes.len() > MAX_REPLY {
                            return false;
                        }
                        self.phase = Phase::Writing { bytes, offset: 0 };
                        continue;
                    }
                    let remaining = http::MAX_REQUEST.saturating_sub(buffer.len());
                    if remaining == 0 {
                        return false;
                    }
                    let mut chunk = [0u8; 1024];
                    let capacity = remaining.min(chunk.len());
                    match self.stream.read(&mut chunk[..capacity]) {
                        Ok(0) => return false,
                        Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => return false,
                    }
                }
                Phase::Writing { bytes, offset } => {
                    if *offset == bytes.len() {
                        return false;
                    }
                    let end = (*offset + 8192).min(bytes.len());
                    match self.stream.write(&bytes[*offset..end]) {
                        Ok(0) => return false,
                        Ok(n) => *offset += n,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => return false,
                    }
                }
            }
        }
        true
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
    fn silent_peer_does_not_block_another_request() {
        let mut pool = Pool::default();
        let (slow, _held) = pair();
        pool.insert(slow).unwrap();
        let (fast, mut peer) = pair();
        pool.insert(fast).unwrap();
        peer.write_all(b"POST /id HTTP/1.1\r\nContent-Length: 1\r\nContent-Type: application/soap+xml\r\n\r\nx").unwrap();
        let start = Instant::now();
        for _ in 0..40 {
            pool.tick("id", |request| {
                assert_eq!(request.unwrap(), b"x");
                Some(b"ok".to_vec())
            });
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(start.elapsed() < Duration::from_millis(250));
        peer.set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let mut result = [0; 2];
        peer.read_exact(&mut result).unwrap();
        assert_eq!(&result, b"ok");
    }
    #[test]
    fn capacity_expiry_and_disconnect_release_slots() {
        let mut pool = Pool::default();
        let mut peers = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let (s, p) = pair();
            assert!(pool.insert(s).unwrap());
            peers.push(p);
        }
        let (s, _p) = pair();
        assert!(!pool.insert(s).unwrap());
        pool.connections[0].accepted = Instant::now() - LIFETIME;
        pool.tick("id", |_| panic!("silent peer"));
        assert_eq!(pool.connections.len(), MAX_CONNECTIONS - 1);
        drop(peers);
        for _ in 0..40 {
            pool.tick("id", |_| panic!("disconnected peer"));
            if pool.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(pool.is_empty());
    }
    #[test]
    fn fragment_state_and_response_are_bounded() {
        let mut pool = Pool::default();
        let (s, mut p) = pair();
        pool.insert(s).unwrap();
        p.write_all(b"POST /id HTTP/1.1\r\nContent-Length: 2\r\nContent-Type: application/soap+xml\r\n\r\na").unwrap();
        pool.tick("id", |_| panic!("partial body"));
        p.write_all(b"b").unwrap();
        for _ in 0..40 {
            pool.tick("id", |body| {
                assert_eq!(body.unwrap(), b"ab");
                Some(vec![0; MAX_REPLY + 1])
            });
            if pool.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(pool.is_empty());
    }
}
