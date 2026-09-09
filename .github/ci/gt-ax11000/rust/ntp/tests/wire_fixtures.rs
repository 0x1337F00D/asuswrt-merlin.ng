//! Byte-level fixtures built straight from the RFC 5905 header layout.
//!
//! Every fixture is assembled field by field so the test states the wire
//! encoding rather than trusting the encoder it is checking.

use ntp::client::{evaluate_reply, Query, Rejection, MIN_PLAUSIBLE_NTP_SECONDS};
use ntp::packet::{
    DecodeError, KissCode, Leap, Mode, Packet, Timestamp, AUTHENTICATED_PACKET_LEN, PACKET_LEN,
};
use ntp::server::{build_reply, Refusal, ReplyBudget, ServerState, REPLY_BUDGET_PER_SECOND};

/// Local time all fixtures are anchored at: 2024-01-01T00:00:00Z in NTP
/// era-0 seconds, i.e. the earliest instant this daemon considers plausible.
const T0: f64 = MIN_PLAUSIBLE_NTP_SECONDS as f64;

/// The nonce the client is pretending to have transmitted.
const NONCE: Timestamp = Timestamp {
    seconds: 0xdead_beef,
    fraction: 0x0bad_f00d,
};

/// Builds a 48-byte header one field at a time.
struct Fixture {
    bytes: [u8; PACKET_LEN],
}

impl Fixture {
    fn new(leap: u8, version: u8, mode: u8) -> Self {
        let mut bytes = [0_u8; PACKET_LEN];
        // byte 0: LI (bits 7..6) | VN (bits 5..3) | Mode (bits 2..0)
        bytes[0] = (leap << 6) | (version << 3) | mode;
        Self { bytes }
    }

    /// byte 1: stratum.
    fn stratum(mut self, stratum: u8) -> Self {
        self.bytes[1] = stratum;
        self
    }

    /// byte 2: peer poll interval, log2 seconds.
    fn poll(mut self, poll: i8) -> Self {
        self.bytes[2] = poll as u8;
        self
    }

    /// byte 3: precision, log2 seconds.
    fn precision(mut self, precision: i8) -> Self {
        self.bytes[3] = precision as u8;
        self
    }

    /// bytes 4..8: root delay, unsigned 16.16 fixed point.
    fn root_delay(mut self, raw: u32) -> Self {
        self.bytes[4..8].copy_from_slice(&raw.to_be_bytes());
        self
    }

    /// bytes 8..12: root dispersion, unsigned 16.16 fixed point.
    fn root_dispersion(mut self, raw: u32) -> Self {
        self.bytes[8..12].copy_from_slice(&raw.to_be_bytes());
        self
    }

    /// bytes 12..16: reference id, or the kiss code when stratum is 0.
    fn reference_id(mut self, id: &[u8; 4]) -> Self {
        self.bytes[12..16].copy_from_slice(id);
        self
    }

    /// bytes 16..24: reference timestamp.
    fn reference(mut self, value: Timestamp) -> Self {
        self.bytes[16..20].copy_from_slice(&value.seconds.to_be_bytes());
        self.bytes[20..24].copy_from_slice(&value.fraction.to_be_bytes());
        self
    }

    /// bytes 24..32: origin timestamp (T1).
    fn origin(mut self, value: Timestamp) -> Self {
        self.bytes[24..28].copy_from_slice(&value.seconds.to_be_bytes());
        self.bytes[28..32].copy_from_slice(&value.fraction.to_be_bytes());
        self
    }

    /// bytes 32..40: receive timestamp (T2).
    fn receive(mut self, value: Timestamp) -> Self {
        self.bytes[32..36].copy_from_slice(&value.seconds.to_be_bytes());
        self.bytes[36..40].copy_from_slice(&value.fraction.to_be_bytes());
        self
    }

    /// bytes 40..48: transmit timestamp (T3).
    fn transmit(mut self, value: Timestamp) -> Self {
        self.bytes[40..44].copy_from_slice(&value.seconds.to_be_bytes());
        self.bytes[44..48].copy_from_slice(&value.fraction.to_be_bytes());
        self
    }

    fn build(self) -> [u8; PACKET_LEN] {
        self.bytes
    }
}

/// A well-formed stratum-2 server reply that puts the local clock 4 s behind
/// with a 20 ms round trip.
fn good_reply() -> [u8; PACKET_LEN] {
    Fixture::new(0, 4, 4)
        .stratum(2)
        .poll(6)
        .precision(-20)
        .root_delay(0x0000_1000) // 0.0625 s
        .root_dispersion(0x0000_0800) // 0.03125 s
        .reference_id(b"GPS\0")
        .reference(Timestamp::from_secs_f64(T0 + 4.0))
        .origin(NONCE)
        .receive(Timestamp::from_secs_f64(T0 + 4.01))
        .transmit(Timestamp::from_secs_f64(T0 + 4.01))
        .build()
}

fn query() -> Query {
    Query {
        nonce: NONCE,
        sent_at: T0,
    }
}

#[test]
fn accepts_a_well_formed_server_reply_and_computes_the_offset() {
    let sample = evaluate_reply(&good_reply(), query(), T0 + 0.02, 0.002).expect("valid reply");
    // T1 = 0, T2 = T3 = 4.01, T4 = 0.02
    // offset = ((4.01 - 0) + (4.01 - 0.02)) / 2 = 4.0
    // delay  = (0.02 - 0) - (4.01 - 4.01) = 0.02
    assert!((sample.offset - 4.0).abs() < 1e-4, "{}", sample.offset);
    assert!(
        (sample.raw_delay - 0.02).abs() < 1e-4,
        "{}",
        sample.raw_delay
    );
    assert_eq!(sample.stratum, 2);
    assert_eq!(sample.leap, Leap::NoWarning);
    assert_eq!(&sample.reference_id, b"GPS\0");
}

#[test]
fn rejects_a_reply_whose_origin_timestamp_was_not_transmitted() {
    let spoofed = Fixture::new(0, 4, 4)
        .stratum(1)
        .precision(-20)
        .origin(Timestamp {
            seconds: 0xdead_beef,
            // One bit different from the nonce.
            fraction: 0x0bad_f00c,
        })
        .receive(Timestamp::from_secs_f64(T0 + 4.0))
        .transmit(Timestamp::from_secs_f64(T0 + 4.0))
        .build();
    assert_eq!(
        evaluate_reply(&spoofed, query(), T0 + 0.02, 0.002),
        Err(Rejection::OriginMismatch)
    );
}

#[test]
fn rejects_replies_that_are_not_server_mode() {
    for mode in [0_u8, 1, 2, 3, 5, 6, 7] {
        let mut bytes = good_reply();
        bytes[0] = (4 << 3) | mode;
        let rejection = evaluate_reply(&bytes, query(), T0 + 0.02, 0.002).unwrap_err();
        assert!(
            matches!(rejection, Rejection::NotServerMode(_)),
            "mode {mode} gave {rejection:?}"
        );
    }
}

#[test]
fn rejects_unsupported_protocol_versions() {
    for version in [0_u8, 1, 2, 5, 6, 7] {
        let mut bytes = good_reply();
        bytes[0] = (version << 3) | 4;
        assert_eq!(
            evaluate_reply(&bytes, query(), T0 + 0.02, 0.002),
            Err(Rejection::UnsupportedVersion(version))
        );
    }
    for version in [3_u8, 4] {
        let mut bytes = good_reply();
        bytes[0] = (version << 3) | 4;
        assert!(evaluate_reply(&bytes, query(), T0 + 0.02, 0.002).is_ok());
    }
}

#[test]
fn classifies_every_kiss_of_death_code_and_never_uses_the_packet() {
    let cases: [(&[u8; 4], KissCode, bool); 4] = [
        (b"RATE", KissCode::Rate, false),
        (b"DENY", KissCode::Deny, true),
        (b"RSTR", KissCode::Restrict, true),
        (b"\x00\x01\x02\x03", KissCode::Other([0, 1, 2, 3]), false),
    ];
    for (code, expected, permanent) in cases {
        let bytes = Fixture::new(0, 4, 4)
            .stratum(0)
            .reference_id(code)
            .origin(NONCE)
            .receive(Timestamp::from_secs_f64(T0 + 4.0))
            .transmit(Timestamp::from_secs_f64(T0 + 4.0))
            .build();
        assert_eq!(
            evaluate_reply(&bytes, query(), T0 + 0.02, 0.002),
            Err(Rejection::KissOfDeath(expected))
        );
        assert_eq!(expected.is_permanent(), permanent);
    }
}

#[test]
fn rejects_unusable_strata() {
    for stratum in [16_u8, 17, 100, 255] {
        let mut bytes = good_reply();
        bytes[1] = stratum;
        assert_eq!(
            evaluate_reply(&bytes, query(), T0 + 0.02, 0.002),
            Err(Rejection::StratumUnusable(stratum))
        );
    }
}

#[test]
fn rejects_every_leap_alarm_and_accepts_the_leap_warnings() {
    for (leap, expected) in [
        (0_u8, Some(Leap::NoWarning)),
        (1, Some(Leap::AddSecond)),
        (2, Some(Leap::DeleteSecond)),
        (3, None),
    ] {
        let mut bytes = good_reply();
        bytes[0] = (leap << 6) | (4 << 3) | 4;
        match expected {
            Some(leap) => {
                let sample = evaluate_reply(&bytes, query(), T0 + 0.02, 0.002).expect("accepted");
                assert_eq!(sample.leap, leap);
            }
            None => assert_eq!(
                evaluate_reply(&bytes, query(), T0 + 0.02, 0.002),
                Err(Rejection::LeapAlarm)
            ),
        }
    }
}

#[test]
fn rejects_datagrams_that_are_not_an_ntp_header() {
    for length in [0_usize, 1, 12, 47] {
        let short = vec![0_u8; length];
        assert_eq!(
            evaluate_reply(&short, query(), T0, 0.002),
            Err(Rejection::Malformed(DecodeError::Truncated { length }))
        );
    }
    for length in [49_usize, 67, 69, 1024] {
        let mut odd = good_reply().to_vec();
        odd.resize(length, 0);
        assert_eq!(
            evaluate_reply(&odd, query(), T0 + 0.02, 0.002),
            Err(Rejection::Malformed(DecodeError::UnexpectedLength {
                length
            }))
        );
    }
    // 68 bytes is the legacy authenticated length and stays acceptable; the
    // trailing key id and digest are never inspected.
    let mut authenticated = good_reply().to_vec();
    authenticated.resize(AUTHENTICATED_PACKET_LEN, 0xff);
    assert!(evaluate_reply(&authenticated, query(), T0 + 0.02, 0.002).is_ok());
}

#[test]
fn rejects_implausible_absolute_times_and_zero_timestamps() {
    let mut stale = good_reply();
    // A transmit timestamp one second before the plausibility floor.
    let before = Timestamp {
        seconds: MIN_PLAUSIBLE_NTP_SECONDS - 1,
        fraction: 0,
    };
    stale[40..44].copy_from_slice(&before.seconds.to_be_bytes());
    stale[44..48].copy_from_slice(&before.fraction.to_be_bytes());
    assert_eq!(
        evaluate_reply(&stale, query(), T0 + 0.02, 0.002),
        Err(Rejection::ImplausibleServerTime(before.seconds))
    );

    let mut zeroed = good_reply();
    zeroed[40..48].fill(0);
    assert_eq!(
        evaluate_reply(&zeroed, query(), T0 + 0.02, 0.002),
        Err(Rejection::ZeroTimestamp)
    );
}

#[test]
fn rejects_a_server_whose_own_error_bound_is_already_useless() {
    let mut bytes = good_reply();
    // root delay 40 s (0x0028_0000 in 16.16) plus dispersion 0.
    bytes[4..8].copy_from_slice(&0x0028_0000_u32.to_be_bytes());
    let rejection = evaluate_reply(&bytes, query(), T0 + 0.02, 0.002).unwrap_err();
    assert!(
        matches!(rejection, Rejection::RootDistanceTooLarge(_)),
        "{rejection:?}"
    );
}

#[test]
fn rejects_a_round_trip_that_took_longer_than_any_usable_measurement() {
    // The reply arrives 40 s after the query while the server processed it
    // instantly, so the measured delay is 40 s.
    let rejection = evaluate_reply(&good_reply(), query(), T0 + 40.0, 0.002).unwrap_err();
    assert!(
        matches!(rejection, Rejection::DelayTooLarge(_)),
        "{rejection:?}"
    );
}

#[test]
fn a_dead_rtc_offset_of_decades_is_still_accepted() {
    // The router boots with its clock at the 2024 floor while the real time
    // is nearly a decade later. This must step, not be dismissed as
    // implausible, or a router with a dead RTC never gets the time.
    let real = T0 + 9.0 * 365.0 * 86_400.0;
    let bytes = Fixture::new(0, 4, 4)
        .stratum(2)
        .precision(-20)
        .origin(NONCE)
        .receive(Timestamp::from_secs_f64(real))
        .transmit(Timestamp::from_secs_f64(real))
        .build();
    let sample = evaluate_reply(&bytes, query(), T0 + 0.02, 0.002).expect("accepted");
    assert!(sample.offset > 2.8e8, "{}", sample.offset);
}

#[test]
fn server_answers_a_client_request_and_echoes_only_the_origin_timestamp() {
    let state = ServerState {
        leap: Leap::NoWarning,
        stratum: 3,
        poll: 6,
        precision: -9,
        root_delay: 0.125,
        root_dispersion: 0.25,
        reference_id: *b"UPST",
        reference: Timestamp::from_secs_f64(T0),
    };
    let client_nonce = Timestamp {
        seconds: 0x0102_0304,
        fraction: 0x0506_0708,
    };
    let request = Fixture::new(0, 4, 3)
        // A client that claims stratum 1 and a wild poll value: none of this
        // may appear in the reply.
        .stratum(1)
        .poll(17)
        .precision(-30)
        .root_delay(u32::MAX)
        .root_dispersion(u32::MAX)
        .reference_id(b"EVIL")
        .reference(Timestamp {
            seconds: 0xffff_ffff,
            fraction: 0xffff_ffff,
        })
        .transmit(client_nonce)
        .build();

    let receive = Timestamp::from_secs_f64(T0 + 10.0);
    let transmit = Timestamp::from_secs_f64(T0 + 10.001);
    let reply = build_reply(&request, &state, receive, transmit).expect("reply");
    assert_eq!(reply.len(), PACKET_LEN, "a reply is never an amplifier");

    let decoded = Packet::decode(&reply).expect("decodes");
    assert_eq!(decoded.mode, Mode::Server);
    assert_eq!(decoded.version, 4);
    assert_eq!(decoded.leap, Leap::NoWarning);
    assert_eq!(decoded.stratum, 3);
    assert_eq!(decoded.poll, 6, "our poll, never the client's");
    assert_eq!(decoded.precision, -9);
    assert_eq!(&decoded.reference_id, b"UPST");
    assert_eq!(decoded.origin, client_nonce, "the one mandatory echo");
    assert_eq!(decoded.receive, receive);
    assert_eq!(decoded.transmit, transmit);
    assert!((decoded.root_delay - 0.125).abs() < 1e-4);
    assert!((decoded.root_dispersion - 0.25).abs() < 1e-4);
}

#[test]
fn server_has_no_control_or_private_surface_at_all() {
    let state = ServerState {
        leap: Leap::NoWarning,
        stratum: 3,
        poll: 6,
        precision: -9,
        root_delay: 0.0,
        root_dispersion: 0.0,
        reference_id: *b"UPST",
        reference: Timestamp::from_secs_f64(T0),
    };
    for mode in [0_u8, 1, 2, 4, 5, 6, 7] {
        let request = Fixture::new(0, 4, mode).build();
        let refusal =
            build_reply(&request, &state, Timestamp::default(), Timestamp::default()).unwrap_err();
        assert!(
            matches!(refusal, Refusal::UnsupportedMode(_)),
            "mode {mode} gave {refusal:?}"
        );
    }
    // A mode-7 "monlist" request carries an implementation/request code in
    // bytes 1..4; there is no code path that reads them.
    let mut monlist = Fixture::new(0, 2, 7).build();
    monlist[1] = 0;
    monlist[2] = 3; // REQ_MON_GETLIST_1
    monlist[3] = 42;
    assert!(matches!(
        build_reply(&monlist, &state, Timestamp::default(), Timestamp::default()),
        Err(Refusal::UnsupportedMode(Mode::Private))
    ));
}

#[test]
fn server_stays_silent_until_the_local_clock_is_disciplined() {
    let unsynced = ServerState {
        leap: Leap::Unsynchronised,
        stratum: 16,
        poll: 6,
        precision: -9,
        root_delay: 0.0,
        root_dispersion: 0.0,
        reference_id: *b"INIT",
        reference: Timestamp::default(),
    };
    let request = Fixture::new(0, 4, 3).build();
    assert_eq!(
        build_reply(
            &request,
            &unsynced,
            Timestamp::default(),
            Timestamp::default()
        ),
        Err(Refusal::Unsynchronised)
    );
}

#[test]
fn server_rejects_malformed_and_odd_length_requests() {
    let state = ServerState {
        leap: Leap::NoWarning,
        stratum: 3,
        poll: 6,
        precision: -9,
        root_delay: 0.0,
        root_dispersion: 0.0,
        reference_id: *b"UPST",
        reference: Timestamp::from_secs_f64(T0),
    };
    for length in [0_usize, 47, 49, 69, 512] {
        let mut request = Fixture::new(0, 4, 3).build().to_vec();
        request.resize(length, 0);
        assert!(matches!(
            build_reply(&request, &state, Timestamp::default(), Timestamp::default()),
            Err(Refusal::Malformed(_))
        ));
    }
}

#[test]
fn the_reply_budget_bounds_a_spoofed_flood() {
    let mut budget = ReplyBudget::new();
    for index in 0..REPLY_BUDGET_PER_SECOND {
        assert!(budget.allow(100.0), "reply {index} should be allowed");
    }
    assert!(!budget.allow(100.5), "the budget is exhausted");
    assert!(budget.allow(101.0), "a new second refills it");
    assert!(!budget.allow(f64::NAN), "a non-finite clock denies");
}

#[test]
fn timestamps_round_trip_through_the_wire_encoding() {
    for value in [
        Timestamp::default(),
        Timestamp {
            seconds: 1,
            fraction: 0,
        },
        Timestamp {
            seconds: MIN_PLAUSIBLE_NTP_SECONDS,
            fraction: 0x8000_0000,
        },
        Timestamp {
            seconds: u32::MAX,
            fraction: u32::MAX,
        },
    ] {
        let bytes = Fixture::new(0, 4, 4).transmit(value).build();
        let decoded = Packet::decode(&bytes).expect("decodes");
        assert_eq!(decoded.transmit, value);
    }
    // Not-a-number and negative inputs collapse to the zero timestamp rather
    // than wrapping through an `as` cast.
    assert_eq!(Timestamp::from_secs_f64(f64::NAN), Timestamp::default());
    assert_eq!(Timestamp::from_secs_f64(-1.0), Timestamp::default());
    assert_eq!(
        Timestamp::from_secs_f64(f64::INFINITY),
        Timestamp::default()
    );
}
