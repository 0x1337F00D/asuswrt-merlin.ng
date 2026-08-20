use crate::{field, parse_fields, valid_identifier, PolicyError};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointHost {
    Ip(IpAddr),
    Dns(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardEndpoint {
    pub host: EndpointHost,
    pub port: u16,
}

impl FromStr for WireGuardEndpoint {
    type Err = PolicyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Err(PolicyError::Empty);
        }
        if input.len() > 260 {
            return Err(PolicyError::TooLong);
        }
        if !input.is_ascii() {
            return Err(PolicyError::NonAscii);
        }
        let (host, port) = if input.starts_with('[') {
            let closing = input.find(']').ok_or(PolicyError::InvalidFormat)?;
            let host = &input[1..closing];
            let port = input
                .get(closing + 1..)
                .and_then(|suffix| suffix.strip_prefix(':'))
                .ok_or(PolicyError::InvalidFormat)?;
            (EndpointHost::Ip(IpAddr::V6(parse_ipv6(host)?)), port)
        } else {
            let (host, port) = input.rsplit_once(':').ok_or(PolicyError::InvalidFormat)?;
            if host.contains(':') {
                return Err(PolicyError::InvalidFormat);
            }
            let host = match host.parse::<IpAddr>() {
                Ok(ip) => EndpointHost::Ip(ip),
                Err(_) if valid_dns_name(host) => EndpointHost::Dns(host.to_ascii_lowercase()),
                Err(_) => return Err(PolicyError::InvalidValue("WireGuard endpoint host")),
            };
            (host, port)
        };
        let port = parse_port(port)?;
        Ok(Self { host, port })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AllowedIp {
    V4 { network: Ipv4Addr, prefix: u8 },
    V6 { network: Ipv6Addr, prefix: u8 },
}

impl AllowedIp {
    pub fn is_default_route(self) -> bool {
        matches!(
            self,
            Self::V4 {
                network: Ipv4Addr::UNSPECIFIED,
                prefix: 0
            } | Self::V6 {
                network: Ipv6Addr::UNSPECIFIED,
                prefix: 0
            }
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowedIpSet(Vec<AllowedIp>);

impl AllowedIpSet {
    pub fn parse(input: &str, allow_default_route: bool) -> Result<Self, PolicyError> {
        if input.is_empty() {
            return Err(PolicyError::Empty);
        }
        if input.len() > 4096 {
            return Err(PolicyError::TooLong);
        }
        if !input.is_ascii() {
            return Err(PolicyError::NonAscii);
        }
        let mut values = Vec::new();
        let mut unique = HashSet::new();
        for raw in input.split(',') {
            if values.len() == 128 {
                return Err(PolicyError::TooLong);
            }
            let cidr = parse_cidr(raw.trim())?;
            if cidr.is_default_route() && !allow_default_route {
                return Err(PolicyError::Invariant(
                    "WireGuard default route requires explicit approval",
                ));
            }
            if !unique.insert(cidr) {
                return Err(PolicyError::Duplicate("AllowedIPs prefix"));
            }
            values.push(cidr);
        }
        Ok(Self(values))
    }

    pub fn values(&self) -> &[AllowedIp] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Identity {
    Ip(IpAddr),
    Dns(String),
}

impl FromStr for Identity {
    type Err = PolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > 253 {
            return Err(PolicyError::TooLong);
        }
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        let dns = value.strip_prefix('@').unwrap_or(value);
        if valid_dns_name(dns) {
            Ok(Self::Dns(dns.to_ascii_lowercase()))
        } else {
            Err(PolicyError::InvalidValue("VPN identity"))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpsecEncryption {
    Aes256Gcm,
    Aes256Cbc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpsecIntegrity {
    Sha256,
    Sha384,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhGroup {
    Modp2048,
    Ecp256,
    Ecp384,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpsecProfile {
    pub name: String,
    pub local_identity: Identity,
    pub remote_identity: Identity,
    pub encryption: IpsecEncryption,
    pub integrity: IpsecIntegrity,
    pub dh_group: DhGroup,
}

impl IpsecProfile {
    pub fn parse(input: &str) -> Result<Self, PolicyError> {
        const FIELDS: [&str; 6] = [
            "name",
            "local_id",
            "remote_id",
            "encryption",
            "integrity",
            "dh",
        ];
        let values = parse_fields(input, 1024, FIELDS)?;
        if values.len() != FIELDS.len() {
            return Err(PolicyError::Missing("IPsec profile field"));
        }
        let name = field(&values, "name")?;
        if !valid_identifier(name, 32) {
            return Err(PolicyError::InvalidValue("IPsec profile name"));
        }
        Ok(Self {
            name: name.to_owned(),
            local_identity: field(&values, "local_id")?.parse()?,
            remote_identity: field(&values, "remote_id")?.parse()?,
            encryption: match field(&values, "encryption")? {
                "aes256-gcm" => IpsecEncryption::Aes256Gcm,
                "aes256-cbc" => IpsecEncryption::Aes256Cbc,
                _ => return Err(PolicyError::InvalidValue("IPsec encryption")),
            },
            integrity: match field(&values, "integrity")? {
                "sha256" => IpsecIntegrity::Sha256,
                "sha384" => IpsecIntegrity::Sha384,
                _ => return Err(PolicyError::InvalidValue("IPsec integrity")),
            },
            dh_group: match field(&values, "dh")? {
                "modp2048" => DhGroup::Modp2048,
                "ecp256" => DhGroup::Ecp256,
                "ecp384" => DhGroup::Ecp384,
                _ => return Err(PolicyError::InvalidValue("IPsec DH group")),
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenVpnTransport {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenVpnCipher {
    Aes256Gcm,
    Chacha20Poly1305,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenVpnAuth {
    Sha256,
    Sha512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMinimum {
    V1_2,
    V1_3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenVpnProfile {
    pub name: String,
    pub transport: OpenVpnTransport,
    pub cipher: OpenVpnCipher,
    pub auth: OpenVpnAuth,
    pub tls_minimum: TlsMinimum,
}

impl OpenVpnProfile {
    pub fn parse(input: &str) -> Result<Self, PolicyError> {
        const FIELDS: [&str; 6] = [
            "name",
            "transport",
            "cipher",
            "auth",
            "tls_min",
            "verify_peer",
        ];
        let values = parse_fields(input, 512, FIELDS)?;
        if values.len() != FIELDS.len() {
            return Err(PolicyError::Missing("OpenVPN profile field"));
        }
        let name = field(&values, "name")?;
        if !valid_identifier(name, 32) {
            return Err(PolicyError::InvalidValue("OpenVPN profile name"));
        }
        if field(&values, "verify_peer")? != "required" {
            return Err(PolicyError::Invariant("OpenVPN peer verification"));
        }
        Ok(Self {
            name: name.to_owned(),
            transport: match field(&values, "transport")? {
                "udp" => OpenVpnTransport::Udp,
                "tcp" => OpenVpnTransport::Tcp,
                _ => return Err(PolicyError::InvalidValue("OpenVPN transport")),
            },
            cipher: match field(&values, "cipher")? {
                "aes256-gcm" => OpenVpnCipher::Aes256Gcm,
                "chacha20-poly1305" => OpenVpnCipher::Chacha20Poly1305,
                _ => return Err(PolicyError::InvalidValue("OpenVPN cipher")),
            },
            auth: match field(&values, "auth")? {
                "sha256" => OpenVpnAuth::Sha256,
                "sha512" => OpenVpnAuth::Sha512,
                _ => return Err(PolicyError::InvalidValue("OpenVPN auth")),
            },
            tls_minimum: match field(&values, "tls_min")? {
                "1.2" => TlsMinimum::V1_2,
                "1.3" => TlsMinimum::V1_3,
                _ => return Err(PolicyError::InvalidValue("OpenVPN TLS minimum")),
            },
        })
    }
}

fn parse_port(value: &str) -> Result<u16, PolicyError> {
    let value = value
        .parse::<u16>()
        .map_err(|_| PolicyError::InvalidValue("endpoint port"))?;
    (value != 0)
        .then_some(value)
        .ok_or(PolicyError::InvalidValue("endpoint port"))
}

fn parse_ipv6(value: &str) -> Result<Ipv6Addr, PolicyError> {
    value
        .parse()
        .map_err(|_| PolicyError::InvalidValue("IPv6 endpoint"))
}

fn valid_dns_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return false;
    }
    let value = value.strip_suffix('.').unwrap_or(value);
    !value.is_empty()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn parse_cidr(value: &str) -> Result<AllowedIp, PolicyError> {
    let (address, prefix) = value.split_once('/').ok_or(PolicyError::InvalidFormat)?;
    if prefix.is_empty() || prefix.len() > 3 || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PolicyError::InvalidValue("AllowedIPs prefix"));
    }
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| PolicyError::InvalidValue("AllowedIPs prefix"))?;
    let ip: IpAddr = address
        .parse()
        .map_err(|_| PolicyError::InvalidValue("AllowedIPs address"))?;
    match ip {
        IpAddr::V4(address) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            if u32::from(address) & mask != u32::from(address) {
                return Err(PolicyError::Invariant(
                    "AllowedIPs must use a canonical network address",
                ));
            }
            Ok(AllowedIp::V4 {
                network: address,
                prefix,
            })
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            if u128::from(address) & mask != u128::from(address) {
                return Err(PolicyError::Invariant(
                    "AllowedIPs must use a canonical network address",
                ));
            }
            Ok(AllowedIp::V6 {
                network: address,
                prefix,
            })
        }
        _ => Err(PolicyError::InvalidValue("AllowedIPs prefix")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_tables_accept_only_unambiguous_hosts_and_ports() {
        for valid in [
            "vpn.example.net:51820",
            "192.0.2.1:1",
            "[2001:db8::1]:65535",
        ] {
            assert!(
                valid.parse::<WireGuardEndpoint>().is_ok(),
                "rejected {valid}"
            );
        }
        for invalid in [
            "",
            "vpn.example.net",
            "vpn.example.net:0",
            "vpn.example.net:65536",
            "2001:db8::1:51820",
            "[not-ip]:51820",
            "-option.example:22",
            "host name:22",
            "[2001:db8::1]garbage:22",
        ] {
            assert!(
                invalid.parse::<WireGuardEndpoint>().is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn dns_endpoints_are_canonicalized() {
        assert_eq!(
            "VPN.Example.NET:51820"
                .parse::<WireGuardEndpoint>()
                .unwrap()
                .host,
            EndpointHost::Dns("vpn.example.net".into())
        );
    }

    #[test]
    fn allowed_ips_require_canonical_networks_and_explicit_defaults() {
        for valid in ["10.0.0.0/8", "192.0.2.4/32", "2001:db8::/32", "::1/128"] {
            assert!(
                AllowedIpSet::parse(valid, false).is_ok(),
                "rejected {valid}"
            );
        }
        for invalid in [
            "10.1.0.1/8",
            "2001:db8::1/32",
            "10.0.0.0/33",
            "::/129",
            "x/24",
            "10.0.0.0",
        ] {
            assert!(
                AllowedIpSet::parse(invalid, false).is_err(),
                "accepted {invalid}"
            );
        }
        assert!(AllowedIpSet::parse("0.0.0.0/0,::/0", false).is_err());
        assert!(AllowedIpSet::parse("0.0.0.0/0,::/0", true).is_ok());
    }

    #[test]
    fn duplicate_allowed_ips_are_rejected() {
        assert_eq!(
            AllowedIpSet::parse("10.0.0.0/8,10.0.0.0/8", false),
            Err(PolicyError::Duplicate("AllowedIPs prefix"))
        );
    }

    #[test]
    fn identities_accept_ip_or_strict_dns_only() {
        for valid in ["192.0.2.4", "2001:db8::1", "vpn.example", "@peer.example"] {
            assert!(valid.parse::<Identity>().is_ok(), "rejected {valid}");
        }
        for invalid in [
            "",
            "a..b",
            "-host.example",
            "host-.example",
            "host name",
            "$(id)",
        ] {
            assert!(invalid.parse::<Identity>().is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn hardened_ipsec_profile_is_typed() {
        let profile = IpsecProfile::parse(
            "name=office;local_id=router.example;remote_id=peer.example;encryption=aes256-gcm;integrity=sha384;dh=ecp384",
        ).unwrap();
        assert_eq!(profile.encryption, IpsecEncryption::Aes256Gcm);

        for weak in [
            "name=office;local_id=router.example;remote_id=peer.example;encryption=3des;integrity=sha256;dh=modp2048",
            "name=office;local_id=router.example;remote_id=peer.example;encryption=aes256-cbc;integrity=sha1;dh=modp2048",
            "name=office;local_id=router.example;remote_id=peer.example;encryption=aes256-cbc;integrity=sha256;dh=modp1024",
        ] {
            assert!(IpsecProfile::parse(weak).is_err());
        }
    }

    #[test]
    fn openvpn_requires_modern_crypto_and_peer_verification() {
        let valid = "name=office;transport=udp;cipher=aes256-gcm;auth=sha256;tls_min=1.2;verify_peer=required";
        assert!(OpenVpnProfile::parse(valid).is_ok());
        for (field, value) in [
            ("cipher=aes256-gcm", "cipher=aes128-cbc"),
            ("auth=sha256", "auth=sha1"),
            ("tls_min=1.2", "tls_min=1.0"),
            ("verify_peer=required", "verify_peer=off"),
        ] {
            assert!(OpenVpnProfile::parse(&valid.replace(field, value)).is_err());
        }
    }

    #[test]
    fn profile_parsers_reject_unknown_duplicate_and_missing_fields() {
        for value in [
            "name=a;name=b;transport=udp;cipher=aes256-gcm;auth=sha256;tls_min=1.2;verify_peer=required",
            "name=a;transport=udp;cipher=aes256-gcm;auth=sha256;tls_min=1.2",
            "name=a;transport=udp;cipher=aes256-gcm;auth=sha256;tls_min=1.2;verify_peer=required;command=id",
        ] {
            assert!(OpenVpnProfile::parse(value).is_err());
        }
    }
}
