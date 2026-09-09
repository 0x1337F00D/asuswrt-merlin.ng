#![forbid(unsafe_code)]

use clientlist::amas::{parse_node_types, parse_re_client_details};
use clientlist::cache::cache_is_servable;
use clientlist::layout::Layout;
use clientlist::model::{BuildInputs, ClientList};
use clientlist::nvram::{
    parse_custom_clientlist, parse_multifilter, parse_qos_rulelist, parse_wtf_rulelist,
    schedule_allows, KeyedList, LocalTime, MultifilterInputs,
};
use clientlist::render::{
    self, name_for_ip, parse_database, sdn_client_counts, DatabaseInputs, MAX_OUTPUT,
};
use clientlist::snapshot::builder::SegmentBuilder;
use clientlist::snapshot::Snapshot;
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

fn fuzz_clientlist_text(input: &[u8]) {
    let text = ascii_projection(input);
    let now = LocalTime {
        weekday: (input.first().copied().unwrap_or(0) % 7) as i32,
        hour: (input.get(1).copied().unwrap_or(0) % 24) as i32,
    };
    let custom = parse_custom_clientlist(&text);
    for (mac, entry) in custom.iter() {
        assert!(!mac.contains('>'));
        assert!(!entry.name.contains('<'));
    }
    let _ = parse_qos_rulelist(&text);
    let _ = parse_wtf_rulelist(&text);
    let _ = schedule_allows(&text, now);
    let _ = parse_multifilter(
        MultifilterInputs {
            all: 1,
            mac: &text,
            enable: &text,
            daytime: &text,
        },
        now,
    );
    let _ = parse_node_types(&text);
    let _ = parse_re_client_details(input);
    let _ = cache_is_servable(input);
    let _ = name_for_ip(input, "192.168.50.20");
    let mut counts = [0; 8];
    let _ = sdn_client_counts(input, &mut counts);
    if let Some(database) = parse_database(input) {
        let never_re = |_: &str| false;
        let document = render::render_database(
            Some(database.clone()),
            &DatabaseInputs {
                rog_clientlist: &text,
                custom_clientlist: &text,
                amas_node_types: &text,
                is_re_node: &never_re,
            },
            MAX_OUTPUT,
        );
        if let Ok(document) = document {
            assert!(document.ends_with("\"ClientAPILevel\":\"7\"}"));
            assert!(cache_is_servable(document.as_bytes()) || document.contains("\"maclist\":[]"));
        }
        let _ = render::render_all_basic(&database, &text, MAX_OUTPUT);
        let _ = render::search_device_name(&database, &text, &text);
    }
}

/// Random bytes over the two shared-memory layouts, including random counts
/// and unterminated fields.
fn fuzz_clientlist_segment(rng: &mut Rng, input: &[u8]) {
    let layout = if rng.next_u64() % 2 == 0 {
        Layout::Legacy
    } else {
        Layout::Public
    };
    let mut bytes = SegmentBuilder::new(layout).build();
    let mut offset = 0;
    while offset < bytes.len() {
        let chunk = rng.next_u64() as usize % 4_096 + 1;
        let end = (offset + chunk).min(bytes.len());
        if rng.next_u64() % 3 == 0 {
            for byte in &mut bytes[offset..end] {
                *byte = rng.next_u64() as u8;
            }
        }
        offset = end;
    }
    // Mostly small tables (the 255-client render dominates the runtime), with
    // a random signed count one time in sixteen to exercise the clamp.
    let count = if rng.next_u64() % 16 == 0 {
        rng.next_i32()
    } else {
        (rng.next_u64() % 12) as i32
    };
    let tail = bytes.len() - clientlist::layout::TAIL_SIZE;
    bytes[tail..tail + 4].copy_from_slice(&count.to_ne_bytes());
    let product = if rng.next_u64() % 2 == 0 {
        "GT-AX11000"
    } else {
        "RT-AX88U"
    };
    let Ok(snapshot) = Snapshot::parse(product, &bytes) else {
        assert!(layout == Layout::Legacy && product != "GT-AX11000");
        return;
    };
    assert!(snapshot.clients.len() <= 255);
    let text = ascii_projection(input);
    let details = KeyedList::new();
    let is_re_node = |mac: &str| mac.ends_with('1');
    let list = ClientList::build(
        &snapshot,
        &BuildInputs {
            lan_ipaddr: "192.168.50.1",
            login_ip_str: &text,
            rog_clientlist: &text,
            custom_clientlist: &text,
            qos_rulelist: &text,
            wtf_rulelist: &text,
            multifilter: MultifilterInputs {
                all: 1,
                mac: &text,
                enable: &text,
                daytime: &text,
            },
            amas_support: rng.next_u64() % 2 == 0,
            now: LocalTime {
                weekday: 1,
                hour: 1,
            },
            re_details: &details,
            is_re_node: &is_re_node,
        },
    );
    let document = render::render_live(&list, MAX_OUTPUT).expect("bounded document");
    assert!(document.len() <= MAX_OUTPUT);
    assert!(document.ends_with("\"ClientAPILevel\":\"7\"}"));
    let parsed: serde_json::Value = serde_json::from_str(&document).expect("valid JSON");
    assert_eq!(
        parsed["maclist"].as_array().map(Vec::len),
        Some(list.maclist.len())
    );
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

    // Client-list boundaries: the clamp, the unterminated seven-byte ipMethod
    // and an oversized/rejected cache document.
    let mut builder = SegmentBuilder::new(Layout::Legacy);
    builder.count(i32::MAX).ip_method(0, b"OffLine");
    let snapshot = Snapshot::parse("GT-AX11000", &builder.build()).unwrap();
    assert_eq!(snapshot.clients.len(), 255);
    assert_eq!(snapshot.clients[0].ip_method, b"OffLine");
    assert!(Snapshot::parse("GT-AX11000", &vec![0; 174_963]).is_err());
    assert!(!cache_is_servable(br#"{"maclist":[]}"#));
    assert!(parse_database(&vec![b' '; clientlist::render::MAX_DATABASE + 1]).is_none());

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
        match index % 7 {
            0 => fuzz_http(&input),
            1 => fuzz_policy(&input),
            2 => fuzz_infosvr(&input),
            3 => fuzz_rstats(&input),
            4 => fuzz_clientlist_text(&input),
            5 => fuzz_clientlist_segment(&mut rng, &input),
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
