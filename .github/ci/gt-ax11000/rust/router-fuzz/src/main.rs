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
use httpd_parsers::request::{
    parse_request as parse_http_request, RequestError, ACCEPT_LANGUAGE_CAPACITY, BOUNDARY_CAPACITY,
    COOKIE_CAPACITY, HOST_CAPACITY, IF_NONE_MATCH_CAPACITY, MAX_CONTENT_LENGTH, MAX_HEADERS,
    MAX_HEADER_VALUE, MAX_REQUEST_BLOCK, MAX_REQUEST_LINE, RANGE_CAPACITY, REFERER_CAPACITY,
    TARGET_CAPACITY, USER_AGENT_CAPACITY,
};
use httpd_parsers::{
    asus_wlan_security_is_valid, is_readonly_wireless_identity_key, multipart_filename_is_safe,
    query_is_valid, url_decode_in_place,
};
use infosvr::{build_response, parse_request, DeviceState, PDU_LEN};
use ntp::client::{evaluate_reply, Query as NtpQuery};
use ntp::clock::{
    is_fit as ntp_is_fit, select_peer as ntp_select_peer, Candidate as NtpCandidate,
    ClockAction as NtpClockAction, Discipline as NtpDiscipline, PeerFilter as NtpPeerFilter,
    MAX_POLL_EXP as NTP_MAX_POLL_EXP, MAX_STRATUM as NTP_MAX_STRATUM,
    MIN_POLL_EXP as NTP_MIN_POLL_EXP, PRECISION_SECONDS as NTP_PRECISION,
    SLEW_THRESHOLD as NTP_SLEW_THRESHOLD, STEP_THRESHOLD as NTP_STEP_THRESHOLD,
};
use ntp::packet::{
    Leap as NtpLeap, Mode as NtpMode, Packet as NtpPacket, Timestamp as NtpTimestamp,
    PACKET_LEN as NTP_PACKET_LEN,
};
use ntp::server::{build_reply as build_ntp_reply, ServerState as NtpServerState};
use router_policy::testlab::TestlabRequest;
use router_policy::vpn::openvpn_custom_config_allowed;
use router_policy::vpn::{AllowedIpSet, Identity, IpsecProfile, OpenVpnProfile, WireGuardEndpoint};
use router_policy::wlan::WlanSecurityTuple;
use rstats::{base64_decode, decode_history, decode_speeds};
use std::str::FromStr;
use wanduck_transition::{transition, WanduckTransitionInput};
use wlif_policy::{
    cli_token_ok, cli_word_list_ok, control_prefix_ok, dpp_value_ok, interface_name_ok, is_control,
    is_shell_metacharacter, network_id_ok, passphrase_ok, ssid_ok, supplicant_control_dir,
    supplicant_control_path, wps_pin_ok, MAX_CONTROL_PATH,
};

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

/// Everything an accepted request must satisfy.  A panic here is a remote
/// crash: the workspace builds with `panic = "abort"`.
fn request_invariants(block: &[u8]) {
    let Ok(request) = parse_http_request(block) else {
        return;
    };
    assert!(!block.is_empty() && block.len() <= MAX_REQUEST_BLOCK);
    assert!(!block.contains(&0));
    assert!(block[0] != b'\r' && block[0] != b'\n');
    let line_feed = block
        .iter()
        .position(|byte| *byte == b'\n')
        .expect("a complete block ends its request line");
    assert!(line_feed < MAX_REQUEST_LINE);

    assert!(!request.target.is_empty());
    assert_eq!(request.target[0], b'/');
    assert!(request.target.len() < TARGET_CAPACITY);
    assert!(request
        .target
        .iter()
        .all(|byte| (0x21..=0x7e).contains(byte) || *byte >= 0x80));
    assert!(request.query_offset <= request.target.len());
    if request.query_offset < request.target.len() {
        assert_eq!(request.target[request.query_offset], b'?');
        assert!(!request.target[..request.query_offset].contains(&b'?'));
    } else {
        assert!(!request.target.contains(&b'?'));
    }

    assert!(request.minor_version <= 1);
    if let Some(length) = request.content_length {
        assert!(length <= MAX_CONTENT_LENGTH);
    }

    for (value, capacity) in [
        (request.host, HOST_CAPACITY),
        (request.user_agent, USER_AGENT_CAPACITY),
        (request.cookie, COOKIE_CAPACITY),
        (request.referer, REFERER_CAPACITY),
        (request.range, RANGE_CAPACITY),
        (request.if_none_match, IF_NONE_MATCH_CAPACITY),
        (request.boundary, BOUNDARY_CAPACITY),
        (request.accept_language, ACCEPT_LANGUAGE_CAPACITY),
    ] {
        let Some(value) = value else {
            continue;
        };
        assert!(value.len() < capacity);
        assert!(value.len() <= MAX_HEADER_VALUE);
        assert!(!value.contains(&0));
        assert!(value
            .iter()
            .all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte) || *byte >= 0x80));
    }
    // Everything but the multipart boundary, which is a suffix of its own
    // header value, comes back with the surrounding whitespace removed.
    for value in [
        request.host,
        request.user_agent,
        request.cookie,
        request.referer,
        request.range,
        request.if_none_match,
        request.accept_language,
    ]
    .into_iter()
    .flatten()
    {
        assert!(!value.starts_with(b" ") && !value.starts_with(b"\t"));
        assert!(!value.ends_with(b" ") && !value.ends_with(b"\t"));
    }
}

fn pick<'a>(rng: &mut Rng, items: &'a [&'a [u8]]) -> &'a [u8] {
    items[(rng.next_u64() % items.len() as u64) as usize]
}

/// Assemble request blocks out of the random bytes so the parser sees
/// structurally plausible traffic as well as arbitrary noise.
fn synthesize_request(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    const METHODS: [&[u8]; 7] = [
        b"GET",
        b"POST",
        b"HEAD",
        b"get",
        b"OPTIONS",
        b"",
        b"P\x01OST",
    ];
    const TARGETS: [&[u8]; 7] = [
        b"/",
        b"/apply.cgi?x=1",
        b"//",
        b"index.asp",
        b"http://router/a",
        b"/a b",
        b"*",
    ];
    const VERSIONS: [&[u8]; 6] = [
        b"HTTP/1.1",
        b"HTTP/1.0",
        b"HTTP/2.0",
        b"HTTP/1.9",
        b"HTTP/1.",
        b"",
    ];
    const NAMES: [&[u8]; 13] = [
        b"Host",
        b"Cookie",
        b"User-Agent",
        b"Referer",
        b"Range",
        b"If-None-Match",
        b"Content-Length",
        b"Transfer-Encoding",
        b"Accept-Language",
        b"Content-Type",
        b"X-Pad",
        b"Host-Forwarded",
        b"",
    ];
    const SEPARATORS: [&[u8]; 5] = [b": ", b":", b":\t", b" : ", b" "];
    const ENDINGS: [&[u8]; 5] = [b"\r\n", b"\n", b"\r", b"\r\n ", b"\r\n\t"];

    let mut block = Vec::with_capacity(512);
    block.extend_from_slice(pick(rng, &METHODS));
    block.push(b' ');
    block.extend_from_slice(pick(rng, &TARGETS));
    block.push(b' ');
    block.extend_from_slice(pick(rng, &VERSIONS));
    block.extend_from_slice(b"\r\n");

    let headers = (rng.next_u64() % 6) as usize;
    let mut cursor = 0usize;
    for _ in 0..headers {
        block.extend_from_slice(pick(rng, &NAMES));
        block.extend_from_slice(pick(rng, &SEPARATORS));
        let take = (rng.next_u64() % 24) as usize;
        let end = cursor.saturating_add(take).min(input.len());
        block.extend_from_slice(&input[cursor.min(input.len())..end]);
        cursor = end;
        block.extend_from_slice(pick(rng, &ENDINGS));
    }
    block.extend_from_slice(b"\r\n");
    block
}

fn fuzz_http_request(rng: &mut Rng, input: &[u8]) {
    request_invariants(input);
    let synthesized = synthesize_request(rng, input);
    request_invariants(&synthesized);
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

fn fuzz_wlif(input: &[u8]) {
    // Nothing an accepted identifier carries may be shell syntax, a control
    // character or a leading option marker, and every accepted value stays
    // inside its documented bound.
    if interface_name_ok(input) {
        assert!(!input.is_empty() && input.len() <= wlif_policy::MAX_INTERFACE_NAME);
        assert!(!input.iter().copied().any(is_shell_metacharacter));
        assert!(!input.iter().copied().any(is_control));
        assert!(input[0] != b'-');
    }
    if control_prefix_ok(input) {
        assert!(!input.iter().copied().any(is_shell_metacharacter));
        assert!(input[0] != b'-');
    }
    if cli_token_ok(input) {
        assert!(!input.iter().copied().any(is_shell_metacharacter));
        assert!(!input.iter().copied().any(is_control));
        assert!(!input.contains(&b'/'));
        assert!(input[0] != b'-');
    }
    if cli_word_list_ok(input) {
        assert!(!input.iter().copied().any(is_control));
        assert!(input.split(|&byte| byte == b' ').all(cli_token_ok));
        assert!(input.len() <= wlif_policy::MAX_CLI_WORD_LIST);
    }
    if dpp_value_ok(input) {
        assert!(input.iter().all(|&byte| byte.is_ascii_alphanumeric()
            || matches!(byte, b'+' | b'/' | b'.' | b'_' | b'-' | b'=')));
        assert!(!input.is_empty() && input.len() <= wlif_policy::MAX_DPP_VALUE);
        assert!(input[0] != b'-');
    }
    if wps_pin_ok(input) {
        assert!(matches!(input.len(), 4 | 8));
        assert!(input.iter().all(u8::is_ascii_digit));
    }
    // Credentials stay opaque: only length, NUL/control bytes and encoding
    // are enforced, never a shell charset.
    if ssid_ok(input) {
        assert!(!input.is_empty() && input.len() <= wlif_policy::MAX_SSID);
        assert!(!input.iter().copied().any(is_control));
        assert!(core::str::from_utf8(input).is_ok());
    }
    if passphrase_ok(input) {
        assert!(!input.iter().copied().any(is_control));
        assert!(
            input.len() == wlif_policy::PSK_HEX_LEN || input.len() <= wlif_policy::MAX_PASSPHRASE
        );
    }
    let _ = network_id_ok(input.len() as u64);

    // The built control paths are always NUL-terminated, bounded and derived
    // only from an accepted name.
    let mut buffer = [0_u8; MAX_CONTROL_PATH];
    for (accepted, built) in [
        (
            interface_name_ok(input),
            supplicant_control_path(input, &mut buffer),
        ),
        (
            control_prefix_ok(input),
            supplicant_control_dir(input, &mut buffer),
        ),
    ] {
        match built {
            Some(length) => {
                assert!(accepted);
                assert!(length < MAX_CONTROL_PATH);
                assert_eq!(buffer[length], 0);
                assert!(buffer[..length].starts_with(b"/var/run/"));
                assert!(!buffer[..length].iter().copied().any(is_shell_metacharacter));
            }
            None => assert!(!accepted || input.len() + 24 >= MAX_CONTROL_PATH),
        }
    }
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

/// The NTP daemon runs with `panic = "abort"`, so any panic reachable from a
/// datagram is a remote kill. Drive the client and server parsers with random
/// bytes at random lengths, and with the nonce both matched and mismatched.
fn fuzz_ntp(rng: &mut Rng, input: &[u8]) {
    let _ = NtpPacket::decode(input);

    let nonce = NtpTimestamp {
        seconds: rng.next_u64() as u32,
        fraction: rng.next_u64() as u32,
    };
    let sent_at = 3_913_056_000.0_f64 + (rng.next_u64() % 1_000_000) as f64;
    let received_at = sent_at + (rng.next_u64() % 64) as f64;
    let query = NtpQuery { nonce, sent_at };

    let mut datagram = input.to_vec();
    datagram.resize(NTP_PACKET_LEN, 0);
    // Half the iterations get the nonce written into the origin field, so the
    // checks past the anti-spoofing gate are exercised too.
    if rng.next_u64() % 2 == 0 && datagram.len() >= NTP_PACKET_LEN {
        datagram[24..28].copy_from_slice(&nonce.seconds.to_be_bytes());
        datagram[28..32].copy_from_slice(&nonce.fraction.to_be_bytes());
    }
    if let Ok(sample) = evaluate_reply(&datagram, query, received_at, 0.002) {
        assert!(sample.offset.is_finite());
        assert!(sample.delay.is_finite());
        assert!(sample.stratum >= 1 && sample.stratum < 16);
    }
    // One header that is built to be accepted, with a random byte flipped in
    // it half the time: the checks past the anti-spoofing gate are otherwise
    // reached only by chance, and a filtered sample never is.
    let mut plausible = plausible_ntp_reply(rng, nonce, sent_at, 0.25, 0.01);
    if rng.next_u64() % 2 == 0 {
        let position = (rng.next_u64() as usize) % NTP_PACKET_LEN;
        if let Some(byte) = plausible.get_mut(position) {
            *byte ^= 1 << (rng.next_u64() % 8);
        }
    }
    if let Ok(sample) = evaluate_reply(&plausible, query, sent_at + 0.01, 0.002) {
        let mut filter = NtpPeerFilter::new();
        filter.note_query_sent();
        filter.accept(&sample, sent_at + 0.01);
        assert!(filter.is_reachable());
        assert!(filter.offset.is_finite());
        assert!(filter.root_distance(sent_at + 0.01).is_finite());
    }
    // Truncations and the authenticated length must be refused or accepted,
    // never crash.
    for length in [0, 1, 47, NTP_PACKET_LEN, 49, 67, 68, 69] {
        let mut resized = datagram.clone();
        resized.resize(length, 0);
        let _ = evaluate_reply(&resized, query, received_at, 0.002);
    }

    let state = NtpServerState {
        leap: ntp::packet::Leap::NoWarning,
        stratum: (rng.next_u64() % 18) as u8,
        poll: 6,
        precision: -9,
        root_delay: 0.01,
        root_dispersion: 0.01,
        reference_id: *b"FUZZ",
        reference: NtpTimestamp::from_secs_f64(sent_at),
    };
    let receive = NtpTimestamp::from_secs_f64(received_at);
    let transmit = NtpTimestamp::from_secs_f64(received_at + 0.001);
    if let Ok(reply) = build_ntp_reply(input, &state, receive, transmit) {
        // A reply is never larger than the request, so it can never amplify.
        assert_eq!(reply.len(), NTP_PACKET_LEN);
        assert!(input.len() >= NTP_PACKET_LEN);
        let decoded = NtpPacket::decode(&reply).expect("our own reply decodes");
        assert_eq!(decoded.mode, ntp::packet::Mode::Server);
        assert!(decoded.stratum >= 1 && decoded.stratum < 16);
    }
}

/// Earliest server time the client will believe, plus a margin.
const NTP_BASE_SECONDS: f64 = 3_960_000_000.0;

/// A reply that passes every check in `evaluate_reply`.
///
/// Random bytes almost never do: the origin, mode, version, stratum, leap,
/// root distance, absolute time and delay checks reject them long before a
/// sample exists. Without a generator like this the fuzzer never reaches the
/// peer filter, peer selection or the clock discipline at all.
fn plausible_ntp_reply(
    rng: &mut Rng,
    nonce: NtpTimestamp,
    sent_at: f64,
    offset: f64,
    delay: f64,
) -> [u8; NTP_PACKET_LEN] {
    let receive = sent_at + offset + delay / 2.0;
    let transmit = receive + (rng.next_u64() % 1_000) as f64 / 1e6;
    NtpPacket {
        leap: match rng.next_u64() % 8 {
            0 => NtpLeap::AddSecond,
            1 => NtpLeap::DeleteSecond,
            _ => NtpLeap::NoWarning,
        },
        version: if rng.next_u64() % 2 == 0 { 3 } else { 4 },
        mode: NtpMode::Server,
        stratum: 1 + (rng.next_u64() % 15) as u8,
        poll: 6,
        precision: -(6 + (rng.next_u64() % 20) as i8),
        root_delay: (rng.next_u64() % 1_000) as f64 / 1_000.0,
        root_dispersion: (rng.next_u64() % 1_000) as f64 / 1_000.0,
        reference_id: *b"FUZZ",
        reference: NtpTimestamp::from_secs_f64(receive - 64.0),
        origin: nonce,
        receive: NtpTimestamp::from_secs_f64(receive),
        transmit: NtpTimestamp::from_secs_f64(transmit),
    }
    .encode()
}

/// Drives one to four peers through accepted samples, peer selection and the
/// clock discipline, so the whole path a real reply takes is fuzzed and not
/// just the parsers at the front of it.
fn fuzz_ntp_discipline(rng: &mut Rng) {
    let peer_count = 1 + (rng.next_u64() % 4) as usize;
    let mut filters = vec![NtpPeerFilter::new(); peer_count];
    let mut discipline = NtpDiscipline::new();
    let trust_network = rng.next_u64() % 4 == 0;
    let mut now = NTP_BASE_SECONDS + (rng.next_u64() % 100_000) as f64;
    for _round in 0..(4 + rng.next_u64() % 12) {
        for filter in &mut filters {
            filter.note_query_sent();
            // One query in eight is never answered, so the reachability
            // register really does decay in some runs.
            if rng.next_u64() % 8 == 0 {
                continue;
            }
            let nonce = NtpTimestamp {
                seconds: rng.next_u64() as u32,
                fraction: rng.next_u64() as u32,
            };
            // Offsets spread over +/- two seconds, so some rounds hold peers
            // that disagree by far more than their error bars: that is what
            // makes the Marzullo falseticker loop run rather than fall out on
            // its first pass.
            let offset = ((rng.next_u64() % 4_001) as f64 - 2_000.0) / 1_000.0;
            let delay = (rng.next_u64() % 2_000) as f64 / 1_000.0;
            let datagram = plausible_ntp_reply(rng, nonce, now, offset, delay);
            let received_at = now + delay;
            let query = NtpQuery {
                nonce,
                sent_at: now,
            };
            let Ok(sample) = evaluate_reply(&datagram, query, received_at, NTP_PRECISION) else {
                continue;
            };
            filter.accept(&sample, received_at);
            assert!(filter.is_reachable());
            assert!(filter.offset.is_finite());
            assert!(filter.dispersion.is_finite() && filter.dispersion >= 0.0);
            assert!(filter.jitter >= NTP_PRECISION);
            assert!(filter.delay >= NTP_PRECISION);
            let distance = filter.root_distance(received_at);
            assert!(distance.is_finite() && distance >= 0.0);
        }
        now += 64.0;
        let candidates: Vec<NtpCandidate> = filters
            .iter()
            .enumerate()
            .filter(|(_, filter)| filter.is_reachable())
            .map(|(index, filter)| NtpCandidate {
                index,
                offset: filter.offset,
                root_distance: filter.root_distance(now),
                stratum: filter.stratum,
                reachable_bits: filter.reachable_bits,
            })
            .filter(|candidate| ntp_is_fit(candidate, discipline.poll_exp, trust_network))
            .collect();
        match ntp_select_peer(&candidates) {
            Some(index) => {
                assert!(candidates.iter().any(|candidate| candidate.index == index));
                let filter = filters[index];
                let outcome = discipline.update(
                    filter.offset,
                    filter.received_at,
                    filter.stratum,
                    filter.leap,
                );
                match outcome.action {
                    NtpClockAction::None => {}
                    NtpClockAction::Step(step) => {
                        assert!(step.is_finite());
                        assert!(step.abs() > NTP_STEP_THRESHOLD);
                    }
                    NtpClockAction::Slew {
                        offset_micros,
                        constant,
                        ..
                    } => {
                        assert!(offset_micros.abs() <= (NTP_SLEW_THRESHOLD * 1e6) as i64);
                        assert!(constant >= 0);
                    }
                }
                let _ = discipline.apply_feedback(outcome.feedback);
            }
            None => discipline.increase_poll(),
        }
        assert!((NTP_MIN_POLL_EXP..=NTP_MAX_POLL_EXP).contains(&discipline.poll_exp));
        assert!(discipline.stratum <= NTP_MAX_STRATUM);
        assert!(discipline.poll_seconds() >= 1);
        assert_eq!(
            discipline.is_synchronised(),
            discipline.stratum < NTP_MAX_STRATUM
        );
    }
    // A peer that fell out of reach can never be a candidate again until it
    // answers, which is the property `check_unsync` depends on.
    for filter in &filters {
        if !filter.is_reachable() {
            assert_eq!(filter.reachable_bits, 0);
        }
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

    // Request-line and header boundaries, and every documented rejection.
    assert!(parse_http_request(b"GET / HTTP/1.1\r\n\r\n").is_ok());
    assert!(parse_http_request(b"GET / HTTP/1.0\n\n").is_ok());
    for (block, expected) in [
        (&b"GET / HTTP/1.1\r\n"[..], RequestError::Incomplete),
        (&b"\r\n"[..], RequestError::RequestLine),
        (&b"GET / HTTP/2.0\r\n\r\n"[..], RequestError::RequestLine),
        (&b"GET  / HTTP/1.1\r\n\r\n"[..], RequestError::RequestLine),
        (
            &b"GET /a\tb HTTP/1.1\r\n\r\n"[..],
            RequestError::RequestLine,
        ),
        (&b"GET a HTTP/1.1\r\n\r\n"[..], RequestError::Target),
        (
            &b"GET / HTTP/1.1\r\nHost a\r\n\r\n"[..],
            RequestError::Header,
        ),
        (
            &b"GET / HTTP/1.1\r\nA: 1\r\n b\r\n\r\n"[..],
            RequestError::Header,
        ),
        (
            &b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"[..],
            RequestError::Header,
        ),
        (&b"GET /\0 HTTP/1.1\r\n\r\n"[..], RequestError::EmbeddedNul),
        (
            &b"POST / HTTP/1.1\r\nContent-Length: 0x10\r\n\r\n"[..],
            RequestError::ContentLength,
        ),
        (
            &b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"[..],
            RequestError::ContentLength,
        ),
        (
            &b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: identity\r\n\r\n"[..],
            RequestError::Framing,
        ),
        (
            &b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            RequestError::Framing,
        ),
    ] {
        assert_eq!(parse_http_request(block).unwrap_err(), expected);
    }
    for count in [MAX_HEADERS, MAX_HEADERS + 1] {
        let mut block = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for index in 0..count {
            block.extend_from_slice(format!("X-{index}: v\r\n").as_bytes());
        }
        block.extend_from_slice(b"\r\n");
        assert_eq!(parse_http_request(&block).is_ok(), count == MAX_HEADERS);
    }
    for length in [MAX_HEADER_VALUE, MAX_HEADER_VALUE + 1] {
        let mut block = Vec::from(&b"GET / HTTP/1.1\r\nX-Pad: "[..]);
        block.resize(block.len() + length, b'a');
        block.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            parse_http_request(&block).is_ok(),
            length == MAX_HEADER_VALUE
        );
    }
    for length in [TARGET_CAPACITY - 1, TARGET_CAPACITY] {
        let mut block = Vec::from(&b"GET "[..]);
        block.push(b'/');
        block.resize(b"GET ".len() + length, b'a');
        block.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        assert_eq!(
            parse_http_request(&block).is_ok(),
            length == TARGET_CAPACITY - 1
        );
    }
    for value in [MAX_CONTENT_LENGTH, MAX_CONTENT_LENGTH + 1] {
        let block = format!("POST / HTTP/1.1\r\nContent-Length: {value}\r\n\r\n");
        assert_eq!(
            parse_http_request(block.as_bytes()).is_ok(),
            value == MAX_CONTENT_LENGTH
        );
    }

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

    // Wireless-interface policy boundaries: the exact length limits, the
    // option-like and path-like names, an unterminated control byte, a
    // non-UTF-8 SSID and the shortest/longest accepted credentials.
    for value in [
        &b"wl0.1"[..],
        b"eth12345678901",
        b"eth123456789012",
        b"-i",
        b"../../tmp/x",
        b"wl0;reboot",
        b"wl0\nreboot",
        b"wl0\x00",
        b"",
        b"caf\xc3\xa9",
        b"\xff\xfe",
        &[b'a'; 32],
        &[b'a'; 33],
        &[b'a'; 63],
        &[b'a'; 64],
        &[b'a'; 65],
        &[b'a'; 1024],
        &[b'a'; 1025],
        b"12345670",
        b"1234",
        b"1234567",
    ] {
        fuzz_wlif(value);
    }
    assert!(interface_name_ok(b"wl0.1"));
    assert!(!interface_name_ok(b"wl0;reboot"));
    assert!(ssid_ok("caf\u{e9}".as_bytes()));
    assert!(!ssid_ok(b"caf\xe9"));
    assert!(passphrase_ok(&[b'a'; 64]));
    assert!(!passphrase_ok(&[b'z'; 64]));
    assert!(!network_id_ok(256));
    // Every NTP mode and every stratum boundary, against a fixed nonce.
    let mut edge_rng = Rng(DEFAULT_SEED);
    for mode in 0_u8..8 {
        for stratum in [0_u8, 1, 15, 16, 17, 255] {
            let mut packet = [0_u8; NTP_PACKET_LEN];
            packet[0] = (4 << 3) | mode;
            packet[1] = stratum;
            packet[12..16].copy_from_slice(b"RATE");
            fuzz_ntp(&mut edge_rng, &packet);
        }
    }

    // Peer selection. Two peers that disagree by far more than their error
    // bars are a falseticker pair and must select nobody; two candidates that
    // are really one server agree trivially and are selected, which is why the
    // daemon refuses to let two peers hold the same resolved address.
    let candidate = |index: usize, offset: f64| NtpCandidate {
        index,
        offset,
        root_distance: 0.05,
        stratum: 2,
        reachable_bits: 0xff,
    };
    assert_eq!(
        ntp_select_peer(&[candidate(0, -1.0), candidate(1, 1.0)]),
        None
    );
    assert_eq!(
        ntp_select_peer(&[candidate(0, 1.0), candidate(1, 1.0)]),
        Some(0)
    );
    assert_eq!(ntp_select_peer(&[]), None);
    assert_eq!(ntp_select_peer(&[candidate(3, 0.0)]), Some(3));
    // Fewer than two answered queries in the register is never fit, with or
    // without -t.
    for bits in [0x00_u8, 0x01, 0x80] {
        for trust in [false, true] {
            let mut lonely = candidate(0, 0.0);
            lonely.reachable_bits = bits;
            assert!(!ntp_is_fit(&lonely, 6, trust));
        }
    }
    let mut discipline_rng = Rng(DEFAULT_SEED ^ 0x5555_5555_5555_5555);
    for _ in 0..16 {
        fuzz_ntp_discipline(&mut discipline_rng);
    }

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
        match index % 11 {
            0 => fuzz_http(&input),
            1 => fuzz_policy(&input),
            2 => fuzz_infosvr(&input),
            3 => fuzz_rstats(&input),
            4 => fuzz_clientlist_text(&input),
            5 => fuzz_clientlist_segment(&mut rng, &input),
            6 => fuzz_wlif(&input),
            7 => fuzz_ntp(&mut rng, &input),
            8 => fuzz_ntp_discipline(&mut rng),
            9 => fuzz_wanduck(&mut rng),
            _ => fuzz_http_request(&mut rng, &input),
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
