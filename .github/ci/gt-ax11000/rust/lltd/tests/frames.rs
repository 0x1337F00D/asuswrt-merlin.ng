//! Byte-level fixtures for every opcode this responder implements.
//!
//! Each fixture is written out byte by byte with its offset, so the wire
//! layout is readable without running anything. The offsets are the ones the
//! shipped `lld2d.hnd` reads in `packetio_recv_handler` and writes in
//! `packetio_tx_hello`:
//!
//! ```text
//!   0..6    Ethernet destination
//!   6..12   Ethernet source
//!  12..14   EtherType 0x88D9
//!  14       Version (1)
//!  15       Type of Service (0 = topology discovery)
//!  16       Reserved (0)
//!  17       Function / opcode
//!  18..24   Real destination
//!  24..30   Real source
//!  30..32   Sequence number, big endian
//!  32..     Opcode payload
//! ```

use lltd::device::Device;
use lltd::limit::{GenerationFilter, RateLimiter};
use lltd::responder::{reply_budget, Dropped, Responder, MAX_AMPLIFICATION, MAX_RESPONSE_LEN};
use lltd::wire::{Malformed, Opcode, MIN_FRAME_LEN};

const STATION: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAPPER: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
const BROADCAST: [u8; 6] = [0xFF; 6];

/// A Discover exactly as a mapper sends it, padded to the Ethernet minimum.
///
/// Payload: generation number (32..34) then the number of stations already
/// known (34..36), here zero, so no six-byte station entries follow.
fn discover_fixture(generation: u16) -> Vec<u8> {
    let mut frame = vec![
        // 0..6   Ethernet destination: broadcast
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //
        // 6..12  Ethernet source: the mapper
        0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, //
        // 12..14 EtherType
        0x88, 0xD9, //
        // 14     Version
        0x01, //
        // 15     Type of Service: topology discovery
        0x00, //
        // 16     Reserved
        0x00, //
        // 17     Function: Discover
        0x00, //
        // 18..24 Real destination: broadcast
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //
        // 24..30 Real source: the mapper
        0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, //
        // 30..32 Sequence number
        0x00, 0x00, //
        // 32..34 Generation number, overwritten below
        0x00, 0x00, //
        // 34..36 Number of stations
        0x00, 0x00,
    ];
    frame[32..34].copy_from_slice(&generation.to_be_bytes());
    // Ethernet minimum-length padding, which a real sender's MAC adds.
    frame.resize(60, 0x00);
    frame
}

/// A Query directed at this station. Sequenced, and carrying no payload of
/// its own beyond the Ethernet padding.
fn query_fixture(sequence: u16) -> Vec<u8> {
    let mut frame = vec![
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // 0..6   to this station
        0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // 6..12  from the mapper
        0x88, 0xD9, // 12..14 EtherType
        0x01, // 14     Version
        0x00, // 15     Type of Service
        0x00, // 16     Reserved
        0x06, // 17     Function: Query
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // 18..24 real destination
        0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // 24..30 real source
        0x00, 0x00, // 30..32 sequence, overwritten below
    ];
    frame[30..32].copy_from_slice(&sequence.to_be_bytes());
    frame.resize(60, 0x00);
    frame
}

/// A Reset directed at this station. Unsequenced, no payload.
fn reset_fixture() -> Vec<u8> {
    let mut frame = query_fixture(0);
    frame[17] = 0x08; // Function: Reset
    frame[30..32].copy_from_slice(&[0x00, 0x00]);
    frame
}

fn device() -> Device {
    Device::new(
        STATION,
        Some([192, 168, 50, 1]),
        "GT-AX11000",
        "GT-AX11000",
        86_400_000_000,
    )
}

fn responder() -> Responder {
    Responder::new(device(), 0)
}

/// A responder whose emission policy never limits, for shape tests.
fn unlimited() -> Responder {
    Responder::with_policy(
        device(),
        RateLimiter::new(u32::MAX, 1, 0),
        GenerationFilter::new(0),
    )
}

#[test]
fn discover_produces_a_hello_with_the_expected_bytes() {
    let mut responder = responder();
    let reply = responder
        .handle(&discover_fixture(0x1234), 0)
        .expect("a Hello");

    assert_eq!(&reply[0..6], &BROADCAST, "Hello is broadcast");
    assert_eq!(&reply[6..12], &STATION, "Ethernet source");
    assert_eq!(&reply[12..14], &[0x88, 0xD9], "EtherType");
    assert_eq!(reply[14], 0x01, "version");
    assert_eq!(reply[15], 0x00, "type of service");
    assert_eq!(reply[16], 0x00, "reserved");
    assert_eq!(reply[17], 0x01, "function: Hello");
    assert_eq!(&reply[18..24], &BROADCAST, "real destination");
    assert_eq!(&reply[24..30], &STATION, "real source");
    assert_eq!(&reply[30..32], &[0x00, 0x00], "Hello is unsequenced");
    // 32..34 generation number, echoed from the Discover.
    assert_eq!(&reply[32..34], &[0x12, 0x34]);
    // 34..40 current mapper address, 40..46 apparent mapper address. With no
    // mapping session the blob writes twelve zero bytes here.
    assert_eq!(&reply[34..46], &[0x00; 12]);
    // 46.. the property block, first entry Host ID: type 0x01, length 6.
    assert_eq!(&reply[46..48], &[0x01, 0x06]);
    assert_eq!(&reply[48..54], &STATION);
    // Characteristics: type 0x02, length 4, the constant get_net_flags emits.
    assert_eq!(&reply[54..60], &[0x02, 0x04, 0x30, 0x00, 0x00, 0x00]);
    // Physical Medium: type 0x03, length 4, IANA ifType 6, ethernetCsmacd.
    assert_eq!(&reply[60..66], &[0x03, 0x04, 0x00, 0x00, 0x00, 0x06]);
    // IPv4 Address: type 0x07, length 4.
    assert_eq!(&reply[66..72], &[0x07, 0x04, 192, 168, 50, 1]);
    // Performance Counter Frequency: type 0x0A, length 8, 1,000,000.
    assert_eq!(
        &reply[72..82],
        &[0x0A, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x42, 0x40]
    );
    assert_eq!(*reply.last().expect("a terminator"), 0x00);
}

#[test]
fn the_hello_carries_the_machine_name_as_little_endian_ucs2() {
    let mut responder = Responder::new(Device::new(STATION, None, "AB", "AB", 0), 0);
    let reply = responder.handle(&discover_fixture(1), 0).expect("a Hello");
    // Machine Name: type 0x0F, length 6 = two code units plus the NUL, each
    // stored low byte first, as util_copy_ascii_to_ucs2 does.
    let expected = [0x0F, 0x06, b'A', 0x00, b'B', 0x00, 0x00, 0x00];
    assert!(
        reply
            .windows(expected.len())
            .any(|window| window == expected),
        "machine name TLV missing from {reply:02x?}"
    );
}

#[test]
fn query_produces_an_empty_query_response_with_the_expected_bytes() {
    let mut responder = responder();
    let reply = responder
        .handle(&query_fixture(0x00A5), 0)
        .expect("a reply");
    assert_eq!(reply.len(), MIN_FRAME_LEN + 2);
    assert_eq!(&reply[0..6], &MAPPER, "directed back at the mapper");
    assert_eq!(&reply[6..12], &STATION);
    assert_eq!(&reply[12..14], &[0x88, 0xD9]);
    assert_eq!(reply[14], 0x01);
    assert_eq!(reply[15], 0x00);
    assert_eq!(reply[16], 0x00);
    assert_eq!(reply[17], 0x07, "function: QueryResp");
    assert_eq!(&reply[18..24], &MAPPER);
    assert_eq!(&reply[24..30], &STATION);
    assert_eq!(&reply[30..32], &[0x00, 0xA5], "the sequence is echoed");
    // 32..34: More flag (1 bit) and the descriptor count (15 bits), both zero.
    assert_eq!(&reply[32..34], &[0x00, 0x00]);
}

#[test]
fn reset_is_accepted_and_answered_with_nothing() {
    let mut responder = responder();
    assert_eq!(
        responder.handle(&reset_fixture(), 0),
        Err(Dropped::Accepted(Opcode::Reset))
    );
}

#[test]
fn a_truncated_frame_is_dropped_at_every_length_below_the_header() {
    let mut responder = responder();
    let full = discover_fixture(1);
    for length in 0..MIN_FRAME_LEN {
        assert_eq!(
            responder.handle(&full[..length], 0),
            Err(Dropped::Malformed(Malformed::Truncated)),
            "length {length}"
        );
    }
}

#[test]
fn an_oversized_frame_is_dropped() {
    let mut responder = responder();
    let mut frame = discover_fixture(1);
    frame.resize(lltd::wire::MAX_FRAME_LEN + 1, 0);
    assert_eq!(
        responder.handle(&frame, 0),
        Err(Dropped::Malformed(Malformed::Oversized))
    );
}

#[test]
fn a_wrong_ethertype_is_dropped() {
    let mut responder = responder();
    let mut frame = discover_fixture(1);
    frame[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
    assert_eq!(
        responder.handle(&frame, 0),
        Err(Dropped::Malformed(Malformed::WrongEtherType))
    );
}

#[test]
fn a_wrong_version_is_dropped() {
    let mut responder = responder();
    for version in [0x00, 0x02, 0xFF] {
        let mut frame = discover_fixture(1);
        frame[14] = version;
        assert_eq!(
            responder.handle(&frame, 0),
            Err(Dropped::Malformed(Malformed::WrongVersion)),
            "version {version:#04x}"
        );
    }
}

#[test]
fn the_qos_and_reserved_services_are_dropped() {
    // The blob routes Type of Service 2 to its QoS diagnostics handler and
    // treats 1 as topology discovery. This port answers only 0.
    let mut responder = responder();
    for service in [0x01, 0x02, 0x03, 0xFF] {
        let mut frame = discover_fixture(1);
        frame[15] = service;
        assert_eq!(
            responder.handle(&frame, 0),
            Err(Dropped::Malformed(Malformed::UnsupportedService)),
            "service {service:#04x}"
        );
    }
}

#[test]
fn every_unknown_opcode_is_dropped() {
    let mut responder = responder();
    for function in 13_u8..=255 {
        let mut frame = discover_fixture(1);
        frame[17] = function;
        assert_eq!(
            responder.handle(&frame, 0),
            Err(Dropped::Malformed(Malformed::UnknownOpcode)),
            "function {function:#04x}"
        );
    }
}

#[test]
fn a_station_list_longer_than_the_frame_is_dropped() {
    let mut responder = responder();
    // Claim 0xFFFF stations in a 60-byte frame.
    let mut frame = discover_fixture(1);
    frame[34..36].copy_from_slice(&[0xFF, 0xFF]);
    assert_eq!(
        responder.handle(&frame, 0),
        Err(Dropped::InconsistentStationList)
    );
    // Claim four stations while supplying three.
    let mut frame = discover_fixture(1);
    frame.truncate(36);
    frame[34..36].copy_from_slice(&[0x00, 0x04]);
    frame.extend_from_slice(&[0x11; 18]);
    assert_eq!(
        responder.handle(&frame, 0),
        Err(Dropped::InconsistentStationList)
    );
}

#[test]
fn a_self_addressed_frame_is_dropped() {
    let mut responder = responder();
    // Real source claims to be this station.
    let mut frame = discover_fixture(1);
    frame[24..30].copy_from_slice(&STATION);
    assert_eq!(
        responder.handle(&frame, 0),
        Err(Dropped::Malformed(Malformed::SelfAddressed))
    );
    // Ethernet source claims to be this station: the shape of a reflected
    // broadcast that would otherwise make the responder answer itself.
    let mut frame = discover_fixture(1);
    frame[6..12].copy_from_slice(&STATION);
    assert_eq!(
        responder.handle(&frame, 0),
        Err(Dropped::Malformed(Malformed::SelfAddressed))
    );
}

#[test]
fn a_frame_addressed_to_another_station_is_dropped() {
    let mut responder = responder();
    let mut frame = query_fixture(1);
    frame[18..24].copy_from_slice(&[0x02, 0x99, 0x99, 0x99, 0x99, 0x99]);
    assert_eq!(
        responder.handle(&frame, 0),
        Err(Dropped::Malformed(Malformed::NotAddressedToUs))
    );
}

#[test]
fn a_group_source_address_is_dropped() {
    let mut responder = responder();
    let mut frame = discover_fixture(1);
    frame[6] = 0x01; // the multicast bit of the Ethernet source
    assert_eq!(
        responder.handle(&frame, 0),
        Err(Dropped::Malformed(Malformed::GroupSource))
    );
}

#[test]
fn the_sequencing_rules_are_enforced_in_both_directions() {
    let mut responder = responder();
    // Reset must be unsequenced.
    let mut frame = reset_fixture();
    frame[30..32].copy_from_slice(&[0x00, 0x01]);
    assert_eq!(
        responder.handle(&frame, 0),
        Err(Dropped::Malformed(Malformed::SequenceRuleViolated))
    );
    // Query must be sequenced.
    let frame = query_fixture(0);
    assert_eq!(
        responder.handle(&frame, 0),
        Err(Dropped::Malformed(Malformed::SequenceRuleViolated))
    );
}

#[test]
fn a_reply_is_never_larger_than_the_budget_the_request_earns() {
    let mut responder = unlimited();
    for length in MIN_FRAME_LEN..=lltd::wire::MAX_FRAME_LEN {
        let mut frame = discover_fixture(1);
        frame.resize(length.max(36), 0);
        let received = frame.len();
        if let Ok(reply) = responder.handle(&frame, 0) {
            assert!(reply.len() <= MAX_RESPONSE_LEN, "hard cap at {received}");
            assert!(
                reply.len() <= reply_budget(received),
                "budget at {received}"
            );
            assert!(
                reply.len() <= received.saturating_mul(MAX_AMPLIFICATION),
                "amplification at {received}"
            );
        }
    }
}

#[test]
fn a_reply_to_a_query_never_exceeds_the_query_itself() {
    let mut responder = unlimited();
    for length in MIN_FRAME_LEN..=200 {
        let mut frame = query_fixture(7);
        frame.truncate(MIN_FRAME_LEN);
        frame.resize(length, 0);
        match responder.handle(&frame, 0) {
            Ok(reply) => assert!(reply.len() <= frame.len(), "length {length}"),
            Err(reason) => assert_eq!(reason, Dropped::WouldAmplify, "length {length}"),
        }
    }
}

#[test]
fn a_flood_of_invalid_frames_leaves_the_budget_for_the_real_mapper() {
    // Two tokens, refilling once an hour, so anything charged is visible.
    let mut responder = Responder::with_policy(
        device(),
        RateLimiter::new(2, 3_600_000, 0),
        GenerationFilter::default(),
    );
    let mut junk = discover_fixture(1);
    junk[16] = 0x01; // reserved byte set
    for _ in 0..5_000 {
        assert!(responder.handle(&junk, 0).is_err());
    }
    assert_eq!(responder.tokens(), 2);
    assert!(responder.handle(&discover_fixture(10), 0).is_ok());
    assert!(responder.handle(&discover_fixture(11), 0).is_ok());
    assert_eq!(
        responder.handle(&discover_fixture(12), 0),
        Err(Dropped::RateLimited)
    );
}
