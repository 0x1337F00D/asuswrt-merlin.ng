#![forbid(unsafe_code)]

use httpd_parsers::{
    asus_wlan_security_is_valid, is_readonly_wireless_identity_key, multipart_filename_is_safe,
    query_is_valid, url_decode_in_place,
};
use infosvr::{build_response, parse_request, DeviceState, PDU_LEN};
use router_policy::testlab::TestlabRequest;
use router_policy::vpn::openvpn_custom_config_allowed;
use router_policy::vpn::{AllowedIpSet, Identity, IpsecProfile, OpenVpnProfile, WireGuardEndpoint};
use router_policy::wlan::WlanSecurityTuple;
use rstats::{base64_decode, decode_history, decode_speeds};
use std::str::FromStr;
use wanduck_transition::{transition, WanduckTransitionInput};

const DEFAULT_ITERATIONS: u64 = 250_000;
const DEFAULT_SEED: u64 = 0x9e37_79b9_7f4a_7c15;
const MAX_INPUT: usize = 4_096;

#[derive(Clone, Copy)]
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn next_i32(&mut self) -> i32 {
        self.next_u64() as u32 as i32
    }

    fn bytes(&mut self) -> Vec<u8> {
        let length = (self.next_u64() as usize) % (MAX_INPUT + 1);
        (0..length).map(|_| self.next_u64() as u8).collect()
    }
}

fn ascii_projection(input: &[u8]) -> String {
    input
        .iter()
        .map(|byte| char::from(0x20 + byte % 0x5f))
        .collect()
}

fn fuzz_http(input: &[u8]) {
    let _ = query_is_valid(input);
    let _ = multipart_filename_is_safe(input);
    let _ = is_readonly_wireless_identity_key(input);

    for plus_as_space in [false, true] {
        let mut decoded = input.to_vec();
        let original = decoded.clone();
        match url_decode_in_place(&mut decoded, plus_as_space) {
            Ok(length) => {
                assert!(length <= original.len());
                assert!(!decoded[..length].contains(&0));
            }
            Err(_) => assert_eq!(decoded, original),
        }
    }
}

fn fuzz_policy(input: &[u8]) {
    let text = ascii_projection(input);
    let _ = router_policy::vpn_runtime::parse_snapshot(&text);
    let _ = TestlabRequest::parse(&text);
    let _ = WlanSecurityTuple::parse(&text).and_then(WlanSecurityTuple::validate);
    let _ = WireGuardEndpoint::from_str(&text);
    let _ = AllowedIpSet::parse(&text, false);
    let _ = AllowedIpSet::parse(&text, true);
    let _ = Identity::from_str(&text);
    let _ = IpsecProfile::parse(&text);
    let _ = OpenVpnProfile::parse(&text);
    let _ = openvpn_custom_config_allowed(&text);

    let fields = text.split_ascii_whitespace().take(4).collect::<Vec<_>>();
    let authentication = fields.first().copied().unwrap_or_default();
    let cipher = fields.get(1).copied().unwrap_or_default();
    let pmf = fields.get(2).copied().unwrap_or_default();
    let wps = fields.get(3).copied().unwrap_or_default();
    let _ = asus_wlan_security_is_valid(authentication, cipher, pmf, wps);
}

fn fuzz_infosvr(input: &[u8]) {
    let mut packet = [0_u8; PDU_LEN];
    let copied = input.len().min(packet.len());
    packet[..copied].copy_from_slice(&input[..copied]);
    if let Some(request) = parse_request(&packet, [0x02, 0, 0, 0, 0, 1]) {
        let response = build_response(request, &DeviceState::default());
        assert_eq!(response.len(), PDU_LEN);
        assert_eq!(response[0], 12);
        assert_eq!(response[1], 22);
    }
    if input.len() != PDU_LEN {
        assert!(parse_request(input, [0; 6]).is_none());
    }
}

fn fuzz_rstats(input: &[u8]) {
    let _ = decode_history(input);
    let _ = decode_speeds(input);
    let text = ascii_projection(input);
    let _ = base64_decode(&text, MAX_INPUT);
}

fn fuzz_wanduck(rng: &mut Rng) {
    let input = WanduckTransitionInput {
        observed_state: rng.next_i32(),
        previous_state: rng.next_i32(),
        changed_state: rng.next_i32(),
        disconnect_count: rng.next_i32(),
        maximum_disconnect_count: rng.next_i32(),
        data_limit_reached: rng.next_i32(),
        disconnect_case: rng.next_i32(),
        wan_disabled: rng.next_i32(),
        ppp_auth_failed: rng.next_i32(),
        other_configured: rng.next_i32(),
        other_link_up: rng.next_i32(),
        other_data_limited: rng.next_i32(),
        special_states_enabled: rng.next_i32(),
    };
    if let Some(output) = transition(input) {
        assert!([0, 1, 3, 4, 5, 7].contains(&output.changed_state));
        assert!([0, 1].contains(&output.previous_state));
    }
}

fn regression_edges() {
    for length in [65_534, 65_535, 65_536] {
        let query = vec![b'a'; length];
        assert_eq!(query_is_valid(&query), length <= 65_535);
    }
    assert!(query_is_valid(&vec![b'&'; 1_023]));
    assert!(!query_is_valid(&vec![b'&'; 1_024]));

    let mut encoded_nul = b"safe%00suffix".to_vec();
    let original = encoded_nul.clone();
    assert!(url_decode_in_place(&mut encoded_nul, true).is_err());
    assert_eq!(encoded_nul, original);
    assert!(multipart_filename_is_safe(&[b'a'; 63]));
    assert!(!multipart_filename_is_safe(&[b'a'; 64]));

    assert!(!openvpn_custom_config_allowed(&"a".repeat(8 * 1_024 + 1)));
    let _ = decode_history(&vec![0; rstats::HISTORY_V1_LEN]);
    let _ = decode_speeds(&vec![0; rstats::SPEED_RECORD_LEN]);

    for opcode in [31_u16, 52, 53, 54, u16::MAX] {
        let mut packet = [0_u8; PDU_LEN];
        packet[0] = 12;
        packet[1] = 21;
        packet[2..4].copy_from_slice(&opcode.to_le_bytes());
        fuzz_infosvr(&packet);
    }
}

fn run(iterations: u64, seed: u64) {
    regression_edges();
    let mut rng = Rng(seed.max(1));
    for index in 0..iterations {
        let input = rng.bytes();
        match index % 5 {
            0 => fuzz_http(&input),
            1 => fuzz_policy(&input),
            2 => fuzz_infosvr(&input),
            3 => fuzz_rstats(&input),
            _ => fuzz_wanduck(&mut rng),
        }
    }
}

fn parse_u64(value: Option<String>, default: u64) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    value
        .parse::<u64>()
        .map_err(|_| format!("invalid unsigned integer: {value}"))
}

fn main() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let iterations = parse_u64(arguments.next(), DEFAULT_ITERATIONS)?;
    let seed = parse_u64(arguments.next(), DEFAULT_SEED)?;
    if arguments.next().is_some() || iterations == 0 {
        return Err("usage: router-fuzz [positive-iterations] [u64-seed]".into());
    }
    run(iterations, seed);
    println!("RESULT=PASS iterations={iterations} seed={seed}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_structured_fuzz_smoke() {
        for seed in [1, DEFAULT_SEED, u64::MAX] {
            run(10_000, seed);
        }
    }
}
