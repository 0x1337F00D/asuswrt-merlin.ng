//! Server-only TLS policy. Socket and stdio ownership belong to the adapter.
//! No certificate generation, custom cryptography or TLS client fallback.
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod ffi;
#[allow(unsafe_code)]
pub mod transport;

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ServerConfig, ServerConnection};
use std::sync::Arc;

pub const MAX_CERT_BYTES: usize = 256 * 1024;
pub const MAX_KEY_BYTES: usize = 64 * 1024;
pub const MAX_CHAIN: usize = 16;
pub const CONNECTION_BUFFER_LIMIT: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigurationError {
    UnsupportedCipherConfiguration,
    Certificate,
    Key,
    KeyMismatch,
    Limits,
    Provider,
}

/// Parse PEM chain or one DER certificate and a PEM/DER private key.
/// Oversized credentials are rejected before parsing or allocating a chain.
fn credentials(cert: &[u8], key: &[u8]) -> Result<CertifiedKey, ConfigurationError> {
    if cert.is_empty() || key.is_empty() || cert.len() > MAX_CERT_BYTES || key.len() > MAX_KEY_BYTES
    {
        return Err(ConfigurationError::Limits);
    }
    let chain = if cert.starts_with(b"-----BEGIN") {
        let mut chain = Vec::new();
        for item in CertificateDer::pem_slice_iter(cert) {
            if chain.len() == MAX_CHAIN {
                return Err(ConfigurationError::Limits);
            }
            chain.push(item.map_err(|_| ConfigurationError::Certificate)?);
        }
        chain
    } else {
        vec![CertificateDer::from(cert.to_vec())]
    };
    if chain.is_empty() {
        return Err(ConfigurationError::Certificate);
    }
    let key = if key.starts_with(b"-----BEGIN") {
        PrivateKeyDer::from_pem_slice(key).map_err(|_| ConfigurationError::Key)?
    } else {
        PrivateKeyDer::try_from(key.to_vec()).map_err(|_| ConfigurationError::Key)?
    };
    let provider = rustls::crypto::ring::default_provider();
    let signing = provider
        .key_provider
        .load_private_key(key)
        .map_err(|_| ConfigurationError::Key)?;
    let certified = CertifiedKey::new(chain, signing);
    // Do not accept an unknown result as a match: no custom key comparison.
    certified
        .keys_match()
        .map_err(|_| ConfigurationError::KeyMismatch)?;
    Ok(certified)
}

pub fn certificate_key_match(cert: &[u8], key: &[u8]) -> bool {
    credentials(cert, key).is_ok()
}

/// Immutable configuration; existing connections retain their own reference
/// when a caller replaces this value after a successful certificate reload.
pub struct Configuration(Arc<ServerConfig>);

impl Configuration {
    pub fn new(cert: &[u8], key: &[u8], ciphers: Option<&str>) -> Result<Self, ConfigurationError> {
        // No OpenSSL cipher-expression parser is silently emulated.
        if ciphers.is_some() {
            return Err(ConfigurationError::UnsupportedCipherConfiguration);
        }
        let certified = credentials(cert, key)?;
        // A single certificate serves all names, as the vendor mssl did.
        // Use rustls' standard single-cert resolver via its public trait.
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|_| ConfigurationError::Provider)?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
        config.ignore_client_order = true;
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        Ok(Self(Arc::new(config)))
    }

    pub fn connection(&self) -> Result<ServerConnection, rustls::Error> {
        let mut connection = ServerConnection::new(Arc::clone(&self.0))?;
        connection.set_buffer_limit(Some(CONNECTION_BUFFER_LIMIT));
        Ok(connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_cipher_expression_is_not_silently_ignored() {
        assert!(matches!(
            Configuration::new(b"bad", b"bad", Some("DEFAULT")),
            Err(ConfigurationError::UnsupportedCipherConfiguration)
        ));
    }

    #[test]
    fn malformed_or_oversized_credentials_fail_closed() {
        assert!(!certificate_key_match(b"bad", b"bad"));
        assert!(!certificate_key_match(b"", b""));
        assert!(!certificate_key_match(&vec![0; MAX_CERT_BYTES + 1], b"bad"));
        assert!(!certificate_key_match(b"bad", &vec![0; MAX_KEY_BYTES + 1]));
    }
}
