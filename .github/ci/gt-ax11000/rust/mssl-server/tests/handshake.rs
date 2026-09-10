//! Synthetic credentials only. No router connection or production key access.
use mssl_server::{certificate_key_match, Configuration};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new(ec: bool) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mssl-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let mut command = Command::new("openssl");
        command.current_dir(&path).args(["req", "-x509", "-newkey"]);
        if ec {
            command.args(["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]);
        } else {
            command.arg("rsa:2048");
        }
        let output = command
            .args([
                "-nodes",
                "-keyout",
                "key.pem",
                "-out",
                "cert.pem",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self(path)
    }
    fn cert(&self) -> Vec<u8> {
        fs::read(self.0.join("cert.pem")).unwrap()
    }
    fn key(&self) -> Vec<u8> {
        fs::read(self.0.join("key.pem")).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn exchange(ec: bool, version: &'static rustls::SupportedProtocolVersion) {
    let fixture = Fixture::new(ec);
    let cert = fixture.cert();
    let config = Configuration::new(&cert, &fixture.key(), None).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let socket =
            mssl_server::transport::Socket::new(tcp.as_fd(), Duration::from_secs(3)).unwrap();
        let mut stream = StreamOwned::new(config.connection().unwrap(), socket);
        let mut request = [0; 18];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"GET / HTTP/1.0\r\n\r\n");
        stream
            .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .unwrap();
        stream.flush().unwrap();
        stream.conn.send_close_notify();
        stream.flush().unwrap();
    });
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(&cert).unwrap())
        .unwrap();
    let client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connection =
        ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let tcp = TcpStream::connect(address).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut stream = StreamOwned::new(connection, tcp);
    // Deliberately fragment the application request over multiple records.
    for byte in b"GET / HTTP/1.0\r\n\r\n" {
        stream.write_all(&[*byte]).unwrap();
        stream.flush().unwrap();
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert_eq!(response, b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK");
    assert_eq!(stream.conn.protocol_version(), Some(version.version));
    server.join().unwrap();
}

#[test]
fn rsa_tls12() {
    exchange(false, &rustls::version::TLS12);
}
#[test]
fn rsa_tls13() {
    exchange(false, &rustls::version::TLS13);
}
#[test]
fn ec_tls12() {
    exchange(true, &rustls::version::TLS12);
}
#[test]
fn ec_tls13() {
    exchange(true, &rustls::version::TLS13);
}
#[test]
fn mismatched_valid_keys_are_refused() {
    let a = Fixture::new(false);
    let b = Fixture::new(false);
    assert!(certificate_key_match(&a.cert(), &a.key()));
    assert!(!certificate_key_match(&a.cert(), &b.key()));
    assert!(Configuration::new(&a.cert(), &b.key(), None).is_err());
}
