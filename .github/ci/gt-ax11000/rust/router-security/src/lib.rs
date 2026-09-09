#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_int, CStr};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use router_policy::testlab::TestlabRequest;

#[path = "../../linux_open_flags.rs"]
mod linux_open_flags;
use linux_open_flags::{O_NOFOLLOW, O_NONBLOCK};

/// Accept only QoS modes implemented by the local kernel/userspace stack.
/// Mode 1 is the removed Trend Micro/BWDPI adaptive path.
///
/// # Safety
///
/// `mode` must address a NUL-terminated string for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn rust_local_qos_mode_allowed(mode: *const c_char) -> c_int {
    if mode.is_null() {
        return 0;
    }
    // SAFETY: The ABI contract requires a readable NUL-terminated string.
    unsafe { CStr::from_ptr(mode) }
        .to_str()
        .is_ok_and(router_policy::qos::local_qos_mode_allowed)
        .into()
}

const MAX_WIREGUARD_CONFIG_SIZE: u64 = 65_536;
const MAX_FIREWALL_RULESET_SIZE: u64 = 128 * 1024;

/// Classify a persisted regulatory profile without accepting an independent
/// channel or power value. `1` is a supported normal country, `2` is the
/// synthetic `ALL` profile, and `0` is invalid.
///
/// # Safety
///
/// `country` must address a NUL-terminated string for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_regulatory_profile_kind(country: *const c_char) -> c_int {
    if country.is_null() {
        return 0;
    }
    // SAFETY: The ABI contract requires a readable NUL-terminated string.
    let Ok(country) = unsafe { CStr::from_ptr(country) }.to_str() else {
        return 0;
    };
    match TestlabRequest::from_country(country) {
        Ok(_) if country == "ALL" => 2,
        Ok(_) => 1,
        Err(_) => 0,
    }
}

fn read_regular_ascii_file(path: &Path, max_size: u64) -> Option<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.file_type().is_file() || metadata.len() > max_size {
        return None;
    }
    let mut contents = String::with_capacity(metadata.len() as usize);
    file.take(max_size + 1).read_to_string(&mut contents).ok()?;
    (contents.len() as u64 <= max_size && contents.is_ascii()).then_some(contents)
}

fn valid_qos_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'@' | b'/' | b'_' | b'-')
        })
}

fn valid_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_admin_ports(value: &str) -> Option<Vec<u16>> {
    if value.is_empty() || value.len() > 95 || !value.is_ascii() {
        return None;
    }
    let mut ports = Vec::new();
    for raw in value.split(',') {
        if ports.len() == 16
            || raw.is_empty()
            || raw.len() > 5
            || !raw.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let port = raw.parse::<u16>().ok().filter(|port| *port != 0)?;
        if ports.contains(&port) {
            return None;
        }
        ports.push(port);
    }
    Some(ports)
}

fn valid_qos_bw_rulelist(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if value.len() > 2048 || !value.is_ascii() {
        return false;
    }

    value.split('<').all(|rule| {
        let mut fields = rule.split('>');
        let valid = matches!(fields.next(), Some("0" | "1"))
            && fields.next().is_some_and(valid_qos_target)
            && fields.next().is_some_and(valid_decimal)
            && fields.next().is_some_and(valid_decimal)
            && fields.next().is_some_and(valid_decimal);
        valid && fields.next().is_none()
    })
}

fn validate_apply_pair(candidate: &str, key: &str) -> bool {
    match key {
        "qos_bw_rulelist" => valid_qos_bw_rulelist(candidate),
        key if key.starts_with("wan") && key.ends_with("_ipaddr") => {
            candidate.parse::<Ipv4Addr>().is_ok()
        }
        _ => false,
    }
}

fn validate_legacy_apply_arguments(first: &str, second: &str) -> bool {
    let first_is_key =
        first == "qos_bw_rulelist" || (first.starts_with("wan") && first.ends_with("_ipaddr"));
    if first_is_key {
        validate_apply_pair(second, first)
    } else {
        validate_apply_pair(first, second)
    }
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

fn valid_ipsec_identity(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok() || valid_dns_name(value)
}

fn valid_ipsec_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value != "."
        && value != ".."
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn replace_wireguard_endpoint(contents: &str, address: &str) -> Option<String> {
    let canonical_address = match address.parse::<IpAddr>() {
        Ok(IpAddr::V6(address)) => format!("[{address}]"),
        Ok(IpAddr::V4(address)) => address.to_string(),
        Err(_) if valid_dns_name(address) => address.trim_end_matches('.').to_ascii_lowercase(),
        Err(_) => return None,
    };

    let mut replaced = false;
    let mut output = String::with_capacity(contents.len() + canonical_address.len());
    for segment in contents.split_inclusive('\n') {
        let (line, ending) = segment
            .strip_suffix('\n')
            .map_or((segment, ""), |line| (line, "\n"));
        if let Some(endpoint) = line.strip_prefix("Endpoint = ") {
            let (_, port) = endpoint.rsplit_once(':')?;
            let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
            output.push_str("Endpoint = ");
            output.push_str(&canonical_address);
            output.push(':');
            output.push_str(&port.to_string());
            output.push_str(ending);
            replaced = true;
        } else {
            output.push_str(segment);
        }
    }
    replaced.then_some(output)
}

/// Validate the two legacy `rc` call sites without granting a generic NVRAM
/// write capability. Unknown keys are deliberately rejected.
///
/// Legacy call sites disagree on argument order. The implementation recognizes
/// only the small typed key allowlist, then treats the other argument as data.
///
/// # Safety
///
/// Both pointers must address NUL-terminated strings for the duration of this
/// call. Invalid UTF-8 is rejected.
#[no_mangle]
pub unsafe extern "C" fn rust_validate_apply_input_value(
    candidate: *const c_char,
    key: *const c_char,
) -> c_int {
    if candidate.is_null() || key.is_null() {
        return 0;
    }

    // SAFETY: The ABI contract requires readable NUL-terminated strings.
    let Ok(candidate) = unsafe { CStr::from_ptr(candidate) }.to_str() else {
        return 0;
    };
    // SAFETY: The ABI contract requires readable NUL-terminated strings.
    let Ok(key) = unsafe { CStr::from_ptr(key) }.to_str() else {
        return 0;
    };

    i32::from(validate_legacy_apply_arguments(candidate, key))
}

/// Validate one imported OpenVPN directive against the typed Rust allowlist.
/// A null argument pointer terminates the argument list; gaps and more than two
/// arguments are rejected.
///
/// # Safety
///
/// Every non-null pointer must address a NUL-terminated string for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_openvpn_import_option_allowed(
    name: *const c_char,
    arg1: *const c_char,
    arg2: *const c_char,
    arg3: *const c_char,
) -> c_int {
    if name.is_null() || !arg3.is_null() {
        return 0;
    }
    // SAFETY: The ABI contract requires a readable NUL-terminated string.
    let Ok(name) = unsafe { CStr::from_ptr(name) }.to_str() else {
        return 0;
    };

    let mut args = Vec::with_capacity(2);
    for argument in [arg1, arg2] {
        if argument.is_null() {
            break;
        }
        // SAFETY: The ABI contract requires readable NUL-terminated strings.
        let Ok(argument) = unsafe { CStr::from_ptr(argument) }.to_str() else {
            return 0;
        };
        args.push(argument);
    }
    if arg1.is_null() && !arg2.is_null() {
        return 0;
    }

    router_policy::vpn::openvpn_import_directive_allowed(name, &args).into()
}

/// Validate the complete vendor OpenVPN custom-configuration field. Unknown
/// directives and any parser ambiguity fail closed.
///
/// # Safety
///
/// `config` must address a NUL-terminated string for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_openvpn_custom_config_allowed(config: *const c_char) -> c_int {
    if config.is_null() {
        return 0;
    }
    // SAFETY: The ABI contract requires a readable NUL-terminated string.
    unsafe { CStr::from_ptr(config) }
        .to_str()
        .is_ok_and(router_policy::vpn::openvpn_custom_config_allowed)
        .into()
}

/// Validate an IPsec certificate identity as an IP address or strict DNS name.
///
/// # Safety
///
/// `value` must address a NUL-terminated string for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_validate_ipsec_identity(value: *const c_char) -> c_int {
    if value.is_null() {
        return 0;
    }
    // SAFETY: The ABI contract requires a readable NUL-terminated string.
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .is_ok_and(valid_ipsec_identity)
        .into()
}

/// Validate a basename used for imported IPsec key material.
///
/// # Safety
///
/// `value` must address a NUL-terminated string for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_validate_ipsec_filename(value: *const c_char) -> c_int {
    if value.is_null() {
        return 0;
    }
    // SAFETY: The ABI contract requires a readable NUL-terminated string.
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .is_ok_and(valid_ipsec_filename)
        .into()
}

/// Atomically update WireGuard endpoint hostnames without invoking a shell or
/// constructing a sed program from NVRAM data.
///
/// # Safety
///
/// Both pointers must address NUL-terminated strings for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_update_wireguard_endpoint(
    path: *const c_char,
    address: *const c_char,
) -> c_int {
    if path.is_null() || address.is_null() {
        return 0;
    }
    // SAFETY: The ABI contract requires readable NUL-terminated strings.
    let (Ok(path), Ok(address)) = (
        unsafe { CStr::from_ptr(path) }.to_str(),
        unsafe { CStr::from_ptr(address) }.to_str(),
    ) else {
        return 0;
    };
    let path = Path::new(path);
    let Ok(source) = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
    else {
        return 0;
    };
    let Ok(metadata) = source.metadata() else {
        return 0;
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_WIREGUARD_CONFIG_SIZE {
        return 0;
    }
    let mut contents = String::with_capacity(metadata.len() as usize);
    if source
        .take(MAX_WIREGUARD_CONFIG_SIZE + 1)
        .read_to_string(&mut contents)
        .is_err()
        || contents.len() as u64 > MAX_WIREGUARD_CONFIG_SIZE
    {
        return 0;
    }
    let Some(updated) = replace_wireguard_endpoint(&contents, address) else {
        return 0;
    };

    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let result: std::io::Result<()> = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(updated.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return 0;
    }
    1
}

/// Verify the effective filter rules produced by the vendor firewall scripts.
/// IPv4 is mandatory. IPv6 is mandatory only when `require_ipv6` is nonzero.
/// Each effective ruleset must end both INPUT and FORWARD with an exact,
/// unconditional DROP rule.
///
/// # Safety
///
/// Required path pointers must address NUL-terminated strings for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_validate_effective_firewall_files(
    ipv4_path: *const c_char,
    ipv6_path: *const c_char,
    require_ipv6: c_int,
) -> c_int {
    if ipv4_path.is_null() || (require_ipv6 != 0 && ipv6_path.is_null()) {
        return 0;
    }
    // SAFETY: The ABI contract requires readable NUL-terminated strings.
    let Ok(ipv4_path) = unsafe { CStr::from_ptr(ipv4_path) }.to_str() else {
        return 0;
    };
    let ipv4 = match read_regular_ascii_file(Path::new(ipv4_path), MAX_FIREWALL_RULESET_SIZE) {
        Some(value) => value,
        None => return 0,
    };
    let ipv6 = if require_ipv6 != 0 {
        // SAFETY: The non-null path is required above for enabled IPv6.
        let Ok(path) = unsafe { CStr::from_ptr(ipv6_path) }.to_str() else {
            return 0;
        };
        match read_regular_ascii_file(Path::new(path), MAX_FIREWALL_RULESET_SIZE) {
            Some(value) => Some(value),
            None => return 0,
        }
    } else {
        None
    };

    router_policy::firewall::FirewallManifest::from_effective_filter_saves(&ipv4, ipv6.as_deref())
        .and_then(|manifest| manifest.validate_terminal_drops(require_ipv6 != 0))
        .is_ok()
        .into()
}

/// Validate terminal DROP plus the first-rule WAN administration guard that
/// is installed after every vendor/VPN/custom firewall hook.
///
/// # Safety
///
/// All required pointers must address NUL-terminated strings for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_validate_effective_firewall_policy_files(
    ipv4_path: *const c_char,
    ipv6_path: *const c_char,
    require_ipv6: c_int,
    wan_ipv4_interface: *const c_char,
    wan_ipv6_interface: *const c_char,
    admin_ports: *const c_char,
) -> c_int {
    if ipv4_path.is_null()
        || wan_ipv4_interface.is_null()
        || admin_ports.is_null()
        || (require_ipv6 != 0 && (ipv6_path.is_null() || wan_ipv6_interface.is_null()))
    {
        return 0;
    }
    // SAFETY: The ABI contract requires readable NUL-terminated strings.
    let (Ok(ipv4_path), Ok(wan_ipv4_interface), Ok(admin_ports)) = (
        unsafe { CStr::from_ptr(ipv4_path) }.to_str(),
        unsafe { CStr::from_ptr(wan_ipv4_interface) }.to_str(),
        unsafe { CStr::from_ptr(admin_ports) }.to_str(),
    ) else {
        return 0;
    };
    let Some(admin_ports) = parse_admin_ports(admin_ports) else {
        return 0;
    };
    let Some(ipv4) = read_regular_ascii_file(Path::new(ipv4_path), MAX_FIREWALL_RULESET_SIZE)
    else {
        return 0;
    };
    let ipv6 = if require_ipv6 != 0 {
        // SAFETY: The non-null path is required above for enabled IPv6.
        let Ok(path) = unsafe { CStr::from_ptr(ipv6_path) }.to_str() else {
            return 0;
        };
        match read_regular_ascii_file(Path::new(path), MAX_FIREWALL_RULESET_SIZE) {
            Some(value) => Some(value),
            None => return 0,
        }
    } else {
        None
    };
    let wan_ipv6_interface = if require_ipv6 != 0 {
        // SAFETY: The non-null path is required above for enabled IPv6.
        match unsafe { CStr::from_ptr(wan_ipv6_interface) }.to_str() {
            Ok(value) => Some(value),
            Err(_) => return 0,
        }
    } else {
        None
    };

    router_policy::firewall::validate_effective_firewall_policy(
        &ipv4,
        ipv6.as_deref(),
        require_ipv6 != 0,
        wan_ipv4_interface,
        wan_ipv6_interface,
        &admin_ports,
    )
    .is_ok()
    .into()
}

const MAX_POLICY_ROUTES_SIZE: u64 = 64 * 1024;
const MAX_VPN_CLIENT_PROFILE_LIST_SIZE: usize = 1024;

fn parse_vpn_client_profiles(
    value: &str,
) -> Option<Vec<router_policy::firewall::VpnClientProfile>> {
    if value.is_empty() || value.len() > MAX_VPN_CLIENT_PROFILE_LIST_SIZE || !value.is_ascii() {
        return None;
    }
    value
        .split(',')
        .map(|entry| router_policy::firewall::VpnClientProfile::parse(entry).ok())
        .collect()
}

/// Validate the per-profile VPN client contract on top of the terminal DROP
/// invariant: the vendor inbound-block chain rules for every profile
/// flagged `fw` and the VPN Director kill-switch policy routes for every
/// profile flagged `ks`. `profiles` is a comma-separated list of
/// `KIND:UNIT[:INTERFACE]:FLAGS` entries such as `openvpn:1:fw+ks` or
/// `wireguard:2:wgc2:ks`. `policy_routes_path` holds `ip rule show` output
/// and may be NULL only while no profile requests `ks`. This complements
/// `rust_validate_effective_firewall_policy_files`, which is unchanged.
///
/// `fw` passes only when the vendor client rules are reachable: nothing
/// ahead of the `OVPNCI`/`WGCI` and `OVPNCF`/`WGCF` hooks (rc/firewall.c
/// :5332/:5343/:6172/:6180; dual-WAN `filter_setting2` :7129/:7140/:8050/
/// :8058) or ahead of the client's rules inside those chains may be able
/// to admit tunnel traffic.
///
/// `ks` is narrower than "the kill switch is on". It is IPv4 only (`ip
/// rule`, never `ip -6 rule`), so it says nothing about IPv6 LAN traffic
/// even with `require_ipv6`. For OpenVPN `rgw=2` and every WireGuard
/// profile the vendor installs one `from SRC prohibit` per enabled VPN
/// Director source (libovpn/amvpn_routing.c:923, :987); one such entry at
/// the slot proves that some source is enforced, not every enabled one,
/// because the VPN Director list is not an input. OpenVPN `rgw=0` and
/// `rgw=3` install no vendor rule at all (:902-929), so callers must
/// request `ks` only for `rgw` in {1, 2}. The slot must also not be
/// shadowed by any lower-numbered rule other than the vendor's own
/// (`router_policy::firewall::FirewallManifest::add_effective_policy_routes`).
///
/// # Safety
///
/// All required pointers must address NUL-terminated strings for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_validate_effective_vpn_client_files(
    ipv4_path: *const c_char,
    ipv6_path: *const c_char,
    require_ipv6: c_int,
    policy_routes_path: *const c_char,
    lan_interface: *const c_char,
    profiles: *const c_char,
) -> c_int {
    if ipv4_path.is_null()
        || lan_interface.is_null()
        || profiles.is_null()
        || (require_ipv6 != 0 && ipv6_path.is_null())
    {
        return 0;
    }
    // SAFETY: The ABI contract requires readable NUL-terminated strings.
    let (Ok(ipv4_path), Ok(lan_interface), Ok(profiles)) = (
        unsafe { CStr::from_ptr(ipv4_path) }.to_str(),
        unsafe { CStr::from_ptr(lan_interface) }.to_str(),
        unsafe { CStr::from_ptr(profiles) }.to_str(),
    ) else {
        return 0;
    };
    let Some(profiles) = parse_vpn_client_profiles(profiles) else {
        return 0;
    };
    let requirements = router_policy::firewall::VpnClientRequirements {
        profiles,
        lan_interface: lan_interface.to_owned(),
    };
    let Some(ipv4) = read_regular_ascii_file(Path::new(ipv4_path), MAX_FIREWALL_RULESET_SIZE)
    else {
        return 0;
    };
    let ipv6 = if require_ipv6 != 0 {
        // SAFETY: The non-null path is required above for enabled IPv6.
        let Ok(path) = unsafe { CStr::from_ptr(ipv6_path) }.to_str() else {
            return 0;
        };
        match read_regular_ascii_file(Path::new(path), MAX_FIREWALL_RULESET_SIZE) {
            Some(value) => Some(value),
            None => return 0,
        }
    } else {
        None
    };
    let policy_routes = if requirements
        .profiles
        .iter()
        .any(|profile| profile.kill_switch)
    {
        if policy_routes_path.is_null() {
            return 0;
        }
        // SAFETY: The pointer was checked for null and the ABI contract
        // requires a readable NUL-terminated string.
        let Ok(path) = unsafe { CStr::from_ptr(policy_routes_path) }.to_str() else {
            return 0;
        };
        match read_regular_ascii_file(Path::new(path), MAX_POLICY_ROUTES_SIZE) {
            Some(value) => Some(value),
            None => return 0,
        }
    } else {
        None
    };

    router_policy::firewall::validate_effective_vpn_client_policy(
        &ipv4,
        ipv6.as_deref(),
        require_ipv6 != 0,
        policy_routes.as_deref(),
        &requirements,
    )
    .is_ok()
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "router-security-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn validates_only_typed_rc_inputs() {
        assert!(validate_apply_pair(
            "1>AA:BB:CC:DD:EE:FF>1024>2048>0",
            "qos_bw_rulelist"
        ));
        assert!(validate_apply_pair("203.0.113.7", "wan0_ipaddr"));
        assert!(!validate_apply_pair(
            "1>AA:BB:CC:DD:EE:FF;reboot>1024>2048>0",
            "qos_bw_rulelist"
        ));
        assert!(!validate_apply_pair("1.2.3.4;reboot", "wan0_ipaddr"));
        assert!(!validate_apply_pair("anything", "unknown_key"));
        assert!(validate_legacy_apply_arguments(
            "wan0_ipaddr",
            "203.0.113.7"
        ));
        assert!(validate_legacy_apply_arguments(
            "203.0.113.7",
            "wan0_ipaddr"
        ));
        assert!(!validate_legacy_apply_arguments(
            "wan0_ipaddr",
            "1.2.3.4;reboot"
        ));
        assert!(!validate_legacy_apply_arguments("unknown_key", "anything"));
    }

    #[test]
    fn validates_ipsec_names_and_wireguard_endpoints() {
        assert!(valid_ipsec_identity("vpn.example.net"));
        assert!(valid_ipsec_identity("2001:db8::1"));
        assert!(!valid_ipsec_identity("vpn.example;reboot"));
        assert!(valid_ipsec_filename("client-01.p12"));
        assert!(!valid_ipsec_filename("../client.p12"));

        let config = "[Peer]\nEndpoint = old.example:51820\nAllowedIPs = 0.0.0.0/0\n";
        assert_eq!(
            replace_wireguard_endpoint(config, "VPN.Example.NET").unwrap(),
            "[Peer]\nEndpoint = vpn.example.net:51820\nAllowedIPs = 0.0.0.0/0\n"
        );
        assert_eq!(
            replace_wireguard_endpoint(config, "2001:db8::1").unwrap(),
            "[Peer]\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 0.0.0.0/0\n"
        );
        assert!(replace_wireguard_endpoint(config, "x';reboot").is_none());
        assert!(replace_wireguard_endpoint("[Peer]\nPublicKey = abc\n", "192.0.2.1").is_none());
    }

    #[test]
    fn ffi_rejects_null_invalid_utf8_and_unknown_keys() {
        let valid = CString::new("203.0.113.7").unwrap();
        let key = CString::new("wan0_ipaddr").unwrap();
        let unknown = CString::new("unknown_key").unwrap();
        let invalid_utf8 = CString::from_vec_with_nul(vec![0xff, 0]).unwrap();

        // SAFETY: All non-null pointers are backed by live C strings.
        unsafe {
            assert_eq!(
                rust_validate_apply_input_value(valid.as_ptr(), key.as_ptr()),
                1
            );
            assert_eq!(
                rust_validate_apply_input_value(valid.as_ptr(), unknown.as_ptr()),
                0
            );
            assert_eq!(
                rust_validate_apply_input_value(invalid_utf8.as_ptr(), key.as_ptr()),
                0
            );
            assert_eq!(
                rust_validate_apply_input_value(core::ptr::null(), key.as_ptr()),
                0
            );
            assert_eq!(rust_validate_ipsec_identity(core::ptr::null()), 0);
            assert_eq!(rust_validate_ipsec_filename(core::ptr::null()), 0);
            assert_eq!(
                rust_update_wireguard_endpoint(core::ptr::null(), valid.as_ptr()),
                0
            );
        }
    }

    #[test]
    fn openvpn_import_ffi_is_typed_and_fail_closed() {
        let auth = CString::new("auth").unwrap();
        let sha256 = CString::new("SHA256").unwrap();
        let sha1 = CString::new("SHA1").unwrap();
        let extra = CString::new("extra").unwrap();
        let invalid_utf8 = CString::from_vec_with_nul(vec![0xff, 0]).unwrap();

        // SAFETY: Every non-null pointer is backed by a live C string.
        unsafe {
            assert_eq!(
                rust_openvpn_import_option_allowed(
                    auth.as_ptr(),
                    sha256.as_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                ),
                1
            );
            assert_eq!(
                rust_openvpn_import_option_allowed(
                    auth.as_ptr(),
                    sha1.as_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                ),
                0
            );
            assert_eq!(
                rust_openvpn_import_option_allowed(
                    auth.as_ptr(),
                    sha256.as_ptr(),
                    core::ptr::null(),
                    extra.as_ptr(),
                ),
                0
            );
            assert_eq!(
                rust_openvpn_import_option_allowed(
                    auth.as_ptr(),
                    core::ptr::null(),
                    sha256.as_ptr(),
                    core::ptr::null(),
                ),
                0
            );
            assert_eq!(
                rust_openvpn_import_option_allowed(
                    invalid_utf8.as_ptr(),
                    sha256.as_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                ),
                0
            );
            assert_eq!(
                rust_openvpn_import_option_allowed(
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                ),
                0
            );

            let safe_custom = CString::new(
                "auth-nocache\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM\n",
            )
            .unwrap();
            let unsafe_custom = CString::new("up /jffs/evil.sh\n").unwrap();
            assert_eq!(rust_openvpn_custom_config_allowed(safe_custom.as_ptr()), 1);
            assert_eq!(
                rust_openvpn_custom_config_allowed(unsafe_custom.as_ptr()),
                0
            );
            assert_eq!(rust_openvpn_custom_config_allowed(core::ptr::null()), 0);
        }
    }

    #[test]
    fn wireguard_update_is_atomic_private_and_rejects_symlinks() {
        let path = temporary_path("wireguard");
        fs::write(
            &path,
            "[Peer]\nEndpoint = old.example:51820\nAllowedIPs = 0.0.0.0/0\n",
        )
        .unwrap();
        let path_c = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let address = CString::new("VPN.Example.NET").unwrap();

        // SAFETY: Both C strings and the file remain valid for the call.
        assert_eq!(
            unsafe { rust_update_wireguard_endpoint(path_c.as_ptr(), address.as_ptr()) },
            1
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "[Peer]\nEndpoint = vpn.example.net:51820\nAllowedIPs = 0.0.0.0/0\n"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let link = temporary_path("wireguard-link");
        symlink(&path, &link).unwrap();
        let link_c = CString::new(link.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: Both C strings and the symlink remain valid for the call.
        assert_eq!(
            unsafe { rust_update_wireguard_endpoint(link_c.as_ptr(), address.as_ptr()) },
            0
        );

        fs::remove_file(link).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn effective_firewall_ffi_is_fail_closed_and_rejects_symlinks() {
        let rules = "*filter\n-A INPUT -j DROP\n-A FORWARD -j DROP\nCOMMIT\n";
        let ipv4 = temporary_path("iptables-save");
        let ipv6 = temporary_path("ip6tables-save");
        fs::write(&ipv4, rules).unwrap();
        fs::write(&ipv6, rules).unwrap();
        let ipv4_c = CString::new(ipv4.as_os_str().as_encoded_bytes()).unwrap();
        let ipv6_c = CString::new(ipv6.as_os_str().as_encoded_bytes()).unwrap();

        // SAFETY: Both path strings and files remain valid for these calls.
        unsafe {
            assert_eq!(
                rust_validate_effective_firewall_files(ipv4_c.as_ptr(), ipv6_c.as_ptr(), 1),
                1
            );
            assert_eq!(
                rust_validate_effective_firewall_files(ipv4_c.as_ptr(), core::ptr::null(), 0),
                1
            );
            assert_eq!(
                rust_validate_effective_firewall_files(core::ptr::null(), ipv6_c.as_ptr(), 1),
                0
            );
        }

        fs::write(
            &ipv4,
            "*filter\n-A INPUT -j DROP\n-A FORWARD -j DROP\n-A INPUT -j ACCEPT\nCOMMIT\n",
        )
        .unwrap();
        // SAFETY: Both path strings and files remain valid for the call.
        assert_eq!(
            unsafe { rust_validate_effective_firewall_files(ipv4_c.as_ptr(), ipv6_c.as_ptr(), 1) },
            0
        );

        let link = temporary_path("iptables-save-link");
        symlink(&ipv6, &link).unwrap();
        let link_c = CString::new(link.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: Both path strings and the symlink remain valid for the call.
        assert_eq!(
            unsafe { rust_validate_effective_firewall_files(link_c.as_ptr(), ipv6_c.as_ptr(), 1) },
            0
        );

        fs::remove_file(link).unwrap();
        fs::remove_file(ipv4).unwrap();
        fs::remove_file(ipv6).unwrap();
    }

    #[test]
    fn effective_firewall_policy_ffi_requires_wan_guard() {
        let rules = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:CODEX_WAN_GUARD - [0:0]\n-A INPUT -i eth0 -j CODEX_WAN_GUARD\n-A INPUT -j DROP\n-A FORWARD -j DROP\n-A CODEX_WAN_GUARD -p tcp -m tcp --dport 22 -j DROP\n-A CODEX_WAN_GUARD -p tcp -m tcp --dport 443 -j DROP\n-A CODEX_WAN_GUARD -j RETURN\nCOMMIT\n";
        let ipv4 = temporary_path("iptables-policy-save");
        let ipv6 = temporary_path("ip6tables-policy-save");
        fs::write(&ipv4, rules).unwrap();
        fs::write(&ipv6, rules).unwrap();
        let ipv4_c = CString::new(ipv4.as_os_str().as_encoded_bytes()).unwrap();
        let ipv6_c = CString::new(ipv6.as_os_str().as_encoded_bytes()).unwrap();
        let wan = CString::new("eth0").unwrap();
        let ports = CString::new("22,443").unwrap();
        let incomplete_ports = CString::new("22,8443").unwrap();

        // SAFETY: All C strings and files remain valid for these calls.
        unsafe {
            assert_eq!(
                rust_validate_effective_firewall_policy_files(
                    ipv4_c.as_ptr(),
                    ipv6_c.as_ptr(),
                    1,
                    wan.as_ptr(),
                    wan.as_ptr(),
                    ports.as_ptr(),
                ),
                1
            );
            assert_eq!(
                rust_validate_effective_firewall_policy_files(
                    ipv4_c.as_ptr(),
                    core::ptr::null(),
                    0,
                    wan.as_ptr(),
                    core::ptr::null(),
                    incomplete_ports.as_ptr(),
                ),
                0
            );
            assert_eq!(
                rust_validate_effective_firewall_policy_files(
                    ipv4_c.as_ptr(),
                    ipv6_c.as_ptr(),
                    1,
                    wan.as_ptr(),
                    core::ptr::null(),
                    ports.as_ptr(),
                ),
                0
            );
        }

        fs::remove_file(ipv4).unwrap();
        fs::remove_file(ipv6).unwrap();
    }

    #[test]
    fn effective_vpn_client_ffi_requires_chain_rules_and_policy_routes() {
        // Vendor shapes: firewall.c:5332/5343/6172/6180 hooks,
        // openvpn_setup.c:965-967 and wireguard.c:697-699 client rules.
        // The dual-WAN filter_setting2 emits the same hooks at
        // firewall.c:7129/7140/8050/8058.
        let rules = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:WGCI - [0:0]\n:WGCF - [0:0]\n:OVPNCI - [0:0]\n:OVPNCF - [0:0]\n-A INPUT -j WGCI\n-A INPUT -j OVPNCI\n-A INPUT -j DROP\n-A FORWARD -j WGCF\n-A FORWARD -j OVPNCF\n-A FORWARD -j DROP\n-A OVPNCI -i tun11 -j DROP\n-A OVPNCF -o tun11 -j ACCEPT\n-A OVPNCF -i tun11 -j DROP\n-A WGCI -i wgc2 -j DROP\n-A WGCF -o wgc2 -j ACCEPT\n-A WGCF -i wgc2 -j DROP\nCOMMIT\n";
        // amvpn_routing.c:903 (priority 12210) and :987 (priority 12216).
        let routes = "0:\tfrom all lookup local\n12210:\tfrom all iif br0 prohibit\n12216:\tfrom 192.168.50.20 prohibit\n32766:\tfrom all lookup main\n";
        let ipv4 = temporary_path("iptables-vpn-save");
        let ipv6 = temporary_path("ip6tables-vpn-save");
        let policy_routes = temporary_path("ip-rule-show");
        let missing = temporary_path("missing-ip-rule-show");
        fs::write(&ipv4, rules).unwrap();
        fs::write(&ipv6, rules).unwrap();
        fs::write(&policy_routes, routes).unwrap();
        let ipv4_c = CString::new(ipv4.as_os_str().as_encoded_bytes()).unwrap();
        let ipv6_c = CString::new(ipv6.as_os_str().as_encoded_bytes()).unwrap();
        let routes_c = CString::new(policy_routes.as_os_str().as_encoded_bytes()).unwrap();
        let missing_c = CString::new(missing.as_os_str().as_encoded_bytes()).unwrap();
        let lan = CString::new("br0").unwrap();
        let other_lan = CString::new("br1").unwrap();
        let both = CString::new("openvpn:1:fw+ks,wireguard:2:wgc2:fw+ks").unwrap();
        let inbound_only = CString::new("openvpn:1:fw,wireguard:2:fw").unwrap();
        let uncovered = CString::new("openvpn:1:fw+ks,wireguard:3:ks").unwrap();
        let malformed = CString::new("openvpn:1:fw+ks,").unwrap();

        // SAFETY: All C strings and files remain valid for these calls.
        unsafe {
            for (ipv6_ptr, require_ipv6) in [(ipv6_c.as_ptr(), 1), (core::ptr::null(), 0)] {
                assert_eq!(
                    rust_validate_effective_vpn_client_files(
                        ipv4_c.as_ptr(),
                        ipv6_ptr,
                        require_ipv6,
                        routes_c.as_ptr(),
                        lan.as_ptr(),
                        both.as_ptr(),
                    ),
                    1
                );
                assert_eq!(
                    rust_validate_effective_vpn_client_files(
                        ipv4_c.as_ptr(),
                        ipv6_ptr,
                        require_ipv6,
                        core::ptr::null(),
                        lan.as_ptr(),
                        inbound_only.as_ptr(),
                    ),
                    1
                );
            }
            for (routes_ptr, lan_ptr, profiles_ptr) in [
                (core::ptr::null(), lan.as_ptr(), both.as_ptr()),
                (missing_c.as_ptr(), lan.as_ptr(), both.as_ptr()),
                (routes_c.as_ptr(), other_lan.as_ptr(), both.as_ptr()),
                (routes_c.as_ptr(), lan.as_ptr(), uncovered.as_ptr()),
                (routes_c.as_ptr(), lan.as_ptr(), malformed.as_ptr()),
                (routes_c.as_ptr(), core::ptr::null(), both.as_ptr()),
                (routes_c.as_ptr(), lan.as_ptr(), core::ptr::null()),
            ] {
                assert_eq!(
                    rust_validate_effective_vpn_client_files(
                        ipv4_c.as_ptr(),
                        ipv6_c.as_ptr(),
                        1,
                        routes_ptr,
                        lan_ptr,
                        profiles_ptr,
                    ),
                    0
                );
            }
            assert_eq!(
                rust_validate_effective_vpn_client_files(
                    ipv4_c.as_ptr(),
                    core::ptr::null(),
                    1,
                    routes_c.as_ptr(),
                    lan.as_ptr(),
                    both.as_ptr(),
                ),
                0
            );
        }

        fs::remove_file(ipv4).unwrap();
        fs::remove_file(ipv6).unwrap();
        fs::remove_file(policy_routes).unwrap();
    }
}
