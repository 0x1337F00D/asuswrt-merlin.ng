#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_int, CStr};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const DISCONNECTED: c_int = 0;
const CONNECTED: c_int = 1;
const CONNECTED_TO_DISCONNECTED: c_int = 3;
const DISCONNECTED_TO_CONNECTED: c_int = 4;
const PHYSICAL_RECONNECT: c_int = 5;
const SET_PIN: c_int = 7;
const SET_USB_SCAN: c_int = 8;

const CASE_SAME_SUBNET: c_int = 6;
const IDLE_COUNTER: c_int = -1;
const START_COUNTER: c_int = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinkState {
    Disconnected,
    Connected,
    PhysicalReconnect,
    SetPin,
    SetUsbScan,
}

impl LinkState {
    fn from_legacy(value: c_int, special_states_enabled: bool) -> Option<Self> {
        match value {
            DISCONNECTED => Some(Self::Disconnected),
            CONNECTED => Some(Self::Connected),
            PHYSICAL_RECONNECT => Some(Self::PhysicalReconnect),
            SET_PIN if special_states_enabled => Some(Self::SetPin),
            SET_USB_SCAN if special_states_enabled => Some(Self::SetUsbScan),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WanduckTransitionInput {
    pub observed_state: c_int,
    pub previous_state: c_int,
    pub changed_state: c_int,
    pub disconnect_count: c_int,
    pub maximum_disconnect_count: c_int,
    pub data_limit_reached: c_int,
    pub disconnect_case: c_int,
    pub wan_disabled: c_int,
    pub ppp_auth_failed: c_int,
    pub other_configured: c_int,
    pub other_link_up: c_int,
    pub other_data_limited: c_int,
    pub special_states_enabled: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WanduckTransitionOutput {
    pub previous_state: c_int,
    pub changed_state: c_int,
    pub disconnect_count: c_int,
}

fn transition(input: WanduckTransitionInput) -> Option<WanduckTransitionOutput> {
    let observed = LinkState::from_legacy(input.observed_state, input.special_states_enabled != 0)?;
    let mut output = WanduckTransitionOutput {
        previous_state: input.previous_state,
        changed_state: input.changed_state,
        disconnect_count: input.disconnect_count,
    };

    if observed == LinkState::PhysicalReconnect {
        output.changed_state = PHYSICAL_RECONNECT;
        output.previous_state = DISCONNECTED;
        if input.other_configured != 0 && input.other_link_up != 0 {
            output.disconnect_count = START_COUNTER;
        }
        return Some(output);
    }

    if input.data_limit_reached != 0 {
        output.changed_state = if input.previous_state == CONNECTED {
            CONNECTED_TO_DISCONNECTED
        } else {
            DISCONNECTED
        };
        output.previous_state = DISCONNECTED;
        output.disconnect_count = if input.other_configured != 0
            && input.other_link_up != 0
            && input.other_data_limited == 0
        {
            input.maximum_disconnect_count
        } else {
            IDLE_COUNTER
        };
        return Some(output);
    }

    match observed {
        LinkState::SetPin => {
            output.changed_state = SET_PIN;
            output.previous_state = DISCONNECTED;
            output.disconnect_count = IDLE_COUNTER;
        }
        LinkState::SetUsbScan => {
            output.changed_state = CONNECTED_TO_DISCONNECTED;
            output.previous_state = DISCONNECTED;
            output.disconnect_count = IDLE_COUNTER;
        }
        LinkState::Connected => {
            output.changed_state = if input.previous_state == DISCONNECTED {
                DISCONNECTED_TO_CONNECTED
            } else {
                CONNECTED
            };
            output.previous_state = CONNECTED;
            output.disconnect_count = IDLE_COUNTER;
        }
        LinkState::Disconnected => {
            output.changed_state = if input.previous_state == CONNECTED {
                CONNECTED_TO_DISCONNECTED
            } else {
                DISCONNECTED
            };
            output.previous_state = DISCONNECTED;

            if input.disconnect_case == CASE_SAME_SUBNET || input.other_link_up == 0 {
                output.disconnect_count = IDLE_COUNTER;
            } else if input.wan_disabled == 0 && input.other_configured != 0 {
                if input.disconnect_count == IDLE_COUNTER {
                    output.disconnect_count = START_COUNTER;
                }
            } else if input.ppp_auth_failed != 0 {
                output.disconnect_count = IDLE_COUNTER;
            }
        }
        LinkState::PhysicalReconnect => unreachable!("handled before data-limit priority"),
    }

    Some(output)
}

/// Apply the pure dual-WAN failover/failback state transition.
///
/// Returns `1` and initializes `output` when the observed legacy state is
/// recognized. Unknown states and invalid pointers return `0`, allowing the C
/// caller to use its legacy fallback without accepting a partially initialized
/// result.
///
/// # Safety
///
/// `input` must point to a readable `WanduckTransitionInput` and `output` must
/// point to writable `WanduckTransitionOutput` storage. The allocations may not
/// overlap.
#[no_mangle]
pub unsafe extern "C" fn rust_wanduck_transition(
    input: *const WanduckTransitionInput,
    output: *mut WanduckTransitionOutput,
) -> c_int {
    if input.is_null() || output.is_null() {
        return 0;
    }

    // SAFETY: Pointer validity and non-overlap are required by the ABI contract.
    let Some(result) = transition(unsafe { *input }) else {
        return 0;
    };
    // SAFETY: `output` is valid writable storage by the ABI contract.
    unsafe { output.write(result) };
    1
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
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return 0;
    };
    if !metadata.file_type().is_file() || metadata.len() > 65_536 {
        return 0;
    }
    let Ok(contents) = fs::read_to_string(path) else {
        return 0;
    };
    let Some(updated) = replace_wireguard_endpoint(&contents, address) else {
        return 0;
    };

    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(updated.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return 0;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(replace_wireguard_endpoint(config, "x';reboot").is_none());
    }

    fn input(observed_state: c_int, previous_state: c_int) -> WanduckTransitionInput {
        WanduckTransitionInput {
            observed_state,
            previous_state,
            changed_state: 99,
            disconnect_count: IDLE_COUNTER,
            maximum_disconnect_count: 12,
            data_limit_reached: 0,
            disconnect_case: 0,
            wan_disabled: 0,
            ppp_auth_failed: 0,
            other_configured: 1,
            other_link_up: 1,
            other_data_limited: 0,
            special_states_enabled: 1,
        }
    }

    #[test]
    fn connected_edges_are_typed_and_reset_counter() {
        let up = transition(input(CONNECTED, DISCONNECTED)).unwrap();
        assert_eq!(up.changed_state, DISCONNECTED_TO_CONNECTED);
        assert_eq!(up.previous_state, CONNECTED);
        assert_eq!(up.disconnect_count, IDLE_COUNTER);

        let steady = transition(input(CONNECTED, CONNECTED)).unwrap();
        assert_eq!(steady.changed_state, CONNECTED);
    }

    #[test]
    fn disconnected_edge_starts_failover_counter_once() {
        let down = transition(input(DISCONNECTED, CONNECTED)).unwrap();
        assert_eq!(down.changed_state, CONNECTED_TO_DISCONNECTED);
        assert_eq!(down.previous_state, DISCONNECTED);
        assert_eq!(down.disconnect_count, START_COUNTER);

        let mut counting = input(DISCONNECTED, DISCONNECTED);
        counting.disconnect_count = 4;
        assert_eq!(transition(counting).unwrap().disconnect_count, 4);
    }

    #[test]
    fn disconnected_line_does_not_count_without_viable_alternate() {
        let mut no_link = input(DISCONNECTED, CONNECTED);
        no_link.other_link_up = 0;
        assert_eq!(transition(no_link).unwrap().disconnect_count, IDLE_COUNTER);

        let mut same_subnet = input(DISCONNECTED, CONNECTED);
        same_subnet.disconnect_case = CASE_SAME_SUBNET;
        assert_eq!(
            transition(same_subnet).unwrap().disconnect_count,
            IDLE_COUNTER
        );
    }

    #[test]
    fn auth_failure_stops_single_line_retry_counter() {
        let mut auth = input(DISCONNECTED, CONNECTED);
        auth.other_configured = 0;
        auth.ppp_auth_failed = 1;
        auth.disconnect_count = 3;
        assert_eq!(transition(auth).unwrap().disconnect_count, IDLE_COUNTER);
    }

    #[test]
    fn physical_reconnect_has_priority_over_data_limit() {
        let mut reconnect = input(PHYSICAL_RECONNECT, CONNECTED);
        reconnect.data_limit_reached = 1;
        reconnect.disconnect_count = IDLE_COUNTER;
        let output = transition(reconnect).unwrap();
        assert_eq!(output.changed_state, PHYSICAL_RECONNECT);
        assert_eq!(output.previous_state, DISCONNECTED);
        assert_eq!(output.disconnect_count, START_COUNTER);
    }

    #[test]
    fn data_limit_uses_maximum_only_for_viable_alternate() {
        let mut limited = input(DISCONNECTED, CONNECTED);
        limited.data_limit_reached = 1;
        let output = transition(limited).unwrap();
        assert_eq!(output.changed_state, CONNECTED_TO_DISCONNECTED);
        assert_eq!(output.disconnect_count, 12);

        limited.other_data_limited = 1;
        assert_eq!(transition(limited).unwrap().disconnect_count, IDLE_COUNTER);
    }

    #[test]
    fn usb_attention_states_never_start_retry_counter() {
        let pin = transition(input(SET_PIN, CONNECTED)).unwrap();
        assert_eq!(pin.changed_state, SET_PIN);
        assert_eq!(pin.disconnect_count, IDLE_COUNTER);

        let scan = transition(input(SET_USB_SCAN, CONNECTED)).unwrap();
        assert_eq!(scan.changed_state, CONNECTED_TO_DISCONNECTED);
        assert_eq!(scan.disconnect_count, IDLE_COUNTER);
    }

    #[test]
    fn disabled_usb_states_and_unknown_values_use_c_fallback() {
        let mut disabled = input(SET_PIN, CONNECTED);
        disabled.special_states_enabled = 0;
        assert_eq!(transition(disabled), None);
        assert_eq!(transition(input(1234, CONNECTED)), None);
    }

    #[test]
    fn ffi_rejects_null_and_does_not_write_for_unknown_state() {
        let mut output = WanduckTransitionOutput {
            previous_state: 10,
            changed_state: 11,
            disconnect_count: 12,
        };
        // SAFETY: Passing null deliberately exercises the guarded ABI path.
        assert_eq!(
            unsafe { rust_wanduck_transition(core::ptr::null(), &mut output) },
            0
        );

        let unknown = input(1234, CONNECTED);
        // SAFETY: Both pointers reference valid, non-overlapping local values.
        assert_eq!(unsafe { rust_wanduck_transition(&unknown, &mut output) }, 0);
        assert_eq!(output.disconnect_count, 12);
    }
}
