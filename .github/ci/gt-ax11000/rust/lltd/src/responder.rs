//! The reduced LLTD responder.
//!
//! # What is answered
//!
//! | Opcode | Behaviour |
//! |--------|-----------|
//! | `Discover` (0) | Validated, then answered with one broadcast `Hello`. |
//! | `Query` (6) | Validated, then answered with an empty `QueryResp`. |
//! | `Reset` (8) | Validated and accepted; there is no session to discard. |
//!
//! # What is dropped, and why
//!
//! `Emit` (2) asks this station to transmit frames carrying *attacker-chosen*
//! source and destination addresses, once per descriptor in the request. It is
//! simultaneously an unauthenticated layer-2 injection primitive and the only
//! genuine amplifier in the protocol, so it is refused outright rather than
//! reproduced. `Train` (3), `Probe` (4) and `Ack` (5) exist only to serve an
//! `Emit` sweep and are refused with it. `Charge` (9) grants an emission
//! budget that is never used. `Flat` (10) and `QueryLargeTlv` (11) belong to
//! the large-property mechanism, which this port does not advertise: every
//! property it emits is small and inline. `Hello` (1), `QueryResp` (7) and
//! `QueryLargeTlvResp` (12) are responder-to-mapper frames and are never
//! requests.
//!
//! The consequence is recorded in `DEBTS_AND_TODOS.md`: Windows can discover
//! and name this device, but cannot infer its position in the layer-2
//! topology from it, so the network map places it without its true links.

use crate::device::Device;
use crate::limit::{GenerationFilter, RateLimiter};
use crate::tlv::{write_properties, TlvWriter};
use crate::wire::{base_header, Frame, Malformed, Opcode, BROADCAST, MIN_FRAME_LEN};

/// Length of the Hello header that follows the base header: generation
/// number (2), current mapper address (6) and apparent mapper address (6).
/// `packetio_tx_hello` writes the property block at offset 46, which is this
/// 14-byte block placed after the 32-byte demultiplex header.
pub const HELLO_HEADER_LEN: usize = 14;

/// Absolute cap on any frame this responder transmits.
///
/// The complete property block is at most 162 bytes, so a full Hello is 209
/// bytes. The cap is a hard ceiling that holds no matter what the property
/// sources contain.
pub const MAX_RESPONSE_LEN: usize = 300;

/// Largest ratio of reply bytes to request bytes.
///
/// A byte-for-byte "never larger than the request" rule cannot be met by
/// Hello: the shortest conforming Discover is one Ethernet minimum-length
/// frame (60 bytes) and the 46-byte Hello header alone leaves 13 bytes, which
/// is not enough for a name. The reply budget is therefore the smaller of
/// [`MAX_RESPONSE_LEN`] and this multiple of the request, properties that do
/// not fit are dropped rather than the reply being padded, and every other
/// opcode is held to the strict rule. Combined with the generation filter and
/// the emission-charged token bucket, sustained gain is bounded by the bucket,
/// not by the ratio.
pub const MAX_AMPLIFICATION: usize = 4;

/// Largest station list accepted inside a Discover.
///
/// A maximum-length frame can hold `(1514 - 36) / 6 = 246` entries; the cap is
/// stated independently so the bound does not move with the frame size.
pub const MAX_DISCOVER_STATIONS: usize = 246;

/// Why a frame produced no reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dropped {
    /// The demultiplex header did not validate.
    Malformed(Malformed),
    /// A well-formed request this port deliberately does not answer.
    Unanswered(Opcode),
    /// A well-formed request that needs no reply, such as Reset.
    Accepted(Opcode),
    /// The opcode's payload was shorter than its own fixed fields require.
    TruncatedPayload,
    /// A Discover payload whose station count does not match its length.
    InconsistentStationList,
    /// This mapper's generation number was already answered.
    DuplicateGeneration,
    /// The reply would have been larger than the request allows.
    WouldAmplify,
    /// The emission budget is exhausted.
    RateLimited,
}

impl From<Malformed> for Dropped {
    fn from(value: Malformed) -> Self {
        Self::Malformed(value)
    }
}

/// A responder bound to one station.
#[derive(Clone, Debug)]
pub struct Responder {
    device: Device,
    limiter: RateLimiter,
    generations: GenerationFilter,
}

impl Responder {
    /// Creates a responder for `device` with the default emission policy.
    #[must_use]
    pub fn new(device: Device, now_millis: u64) -> Self {
        Self {
            device,
            limiter: RateLimiter::new(
                crate::limit::DEFAULT_BURST,
                crate::limit::DEFAULT_REFILL_MILLIS,
                now_millis,
            ),
            generations: GenerationFilter::default(),
        }
    }

    /// Creates a responder with an explicit emission policy, for tests.
    #[must_use]
    pub fn with_policy(
        device: Device,
        limiter: RateLimiter,
        generations: GenerationFilter,
    ) -> Self {
        Self {
            device,
            limiter,
            generations,
        }
    }

    /// The advertised device description.
    #[must_use]
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// Updates the two properties that change while the daemon runs.
    pub fn refresh(&mut self, ipv4: Option<[u8; 4]>, uptime_micros: u64) {
        self.device.ipv4 = ipv4;
        self.device.uptime_micros = uptime_micros;
    }

    /// Tokens still available for replies, for the self-test and the tests.
    #[must_use]
    pub fn tokens(&self) -> u32 {
        self.limiter.tokens()
    }

    /// Turns one received frame into either the exact bytes of one reply or
    /// the reason nothing is sent.
    ///
    /// Nothing is charged against the emission budget until a complete,
    /// size-checked reply exists. A malformed or unanswered frame therefore
    /// costs an attacker CPU but never costs the legitimate mapper a token.
    ///
    /// # Errors
    /// Returns the first rule that stopped a reply being produced.
    pub fn handle(&mut self, bytes: &[u8], now_millis: u64) -> Result<Vec<u8>, Dropped> {
        let frame = Frame::parse(bytes, &self.device.station)?;
        let reply = match frame.opcode {
            Opcode::Discover => self.build_hello(&frame, now_millis)?,
            Opcode::Query => self.build_query_response(&frame)?,
            Opcode::Reset => return Err(Dropped::Accepted(Opcode::Reset)),
            other => return Err(Dropped::Unanswered(other)),
        };
        // The last gate before the caller may transmit, and the only place the
        // budget is spent.
        if !self.limiter.try_charge(now_millis) {
            return Err(Dropped::RateLimited);
        }
        Ok(reply)
    }

    /// Validates a Discover and renders the Hello it earns.
    fn build_hello(&mut self, frame: &Frame<'_>, now_millis: u64) -> Result<Vec<u8>, Dropped> {
        let generation = discover_generation(frame.payload)?;
        if !self
            .generations
            .accept(frame.real_source, generation, now_millis)
        {
            return Err(Dropped::DuplicateGeneration);
        }

        // Hello answers the broadcast address, exactly as packetio_tx_hello
        // does, and carries no sequence number.
        let mut reply = base_header(&BROADCAST, &self.device.station, Opcode::Hello, 0).to_vec();
        reply.extend_from_slice(&generation.to_be_bytes());
        // Current and apparent mapper address. The blob copies these from a
        // live mapping session; with no session it writes twelve zero bytes,
        // which is the case this port is always in.
        reply.extend_from_slice(&[0_u8; 12]);
        debug_assert_eq!(reply.len(), MIN_FRAME_LEN + HELLO_HEADER_LEN);

        let budget = reply_budget(frame.received_len);
        let mut writer = TlvWriter::new(reply, budget);
        write_properties(&mut writer, &self.device);
        let reply = writer.finish();
        if reply.len() > budget || reply.len() > MAX_RESPONSE_LEN {
            return Err(Dropped::WouldAmplify);
        }
        Ok(reply)
    }

    /// Renders the empty QueryResp.
    ///
    /// This port never captures Probe or Train frames, so the recvee
    /// descriptor list is always empty. Reporting an empty list is what a
    /// station that observed nothing is required to report, and it keeps the
    /// reply strictly smaller than the request.
    fn build_query_response(&mut self, frame: &Frame<'_>) -> Result<Vec<u8>, Dropped> {
        let mut reply = base_header(
            &frame.real_source,
            &self.device.station,
            Opcode::QueryResp,
            frame.sequence,
        )
        .to_vec();
        // More (1 bit) = 0, number of descriptors (15 bits) = 0.
        reply.extend_from_slice(&[0x00, 0x00]);
        if reply.len() > frame.received_len || reply.len() > MAX_RESPONSE_LEN {
            return Err(Dropped::WouldAmplify);
        }
        Ok(reply)
    }
}

/// The reply budget for a request of `received_len` bytes.
#[must_use]
pub fn reply_budget(received_len: usize) -> usize {
    received_len
        .saturating_mul(MAX_AMPLIFICATION)
        .min(MAX_RESPONSE_LEN)
}

/// Reads and bounds-checks a Discover payload, returning its generation.
///
/// Layout after the demultiplex header: generation number (2), number of
/// stations (2), then that many six-byte addresses. The blob warns
/// "rx_discover: truncated frame: ended at station %d, but numstations claimed
/// %d" for a list that does not fit; this port drops the frame instead of
/// answering a partial one.
fn discover_generation(payload: &[u8]) -> Result<u16, Dropped> {
    let generation = payload.get(0..2).ok_or(Dropped::TruncatedPayload)?;
    let generation: [u8; 2] = generation
        .try_into()
        .map_err(|_| Dropped::TruncatedPayload)?;
    let count = payload.get(2..4).ok_or(Dropped::TruncatedPayload)?;
    let count: [u8; 2] = count.try_into().map_err(|_| Dropped::TruncatedPayload)?;
    let count = usize::from(u16::from_be_bytes(count));
    if count > MAX_DISCOVER_STATIONS {
        return Err(Dropped::InconsistentStationList);
    }
    let needed = count
        .checked_mul(6)
        .and_then(|listed| listed.checked_add(4))
        .ok_or(Dropped::InconsistentStationList)?;
    if payload.len() < needed {
        return Err(Dropped::InconsistentStationList);
    }
    Ok(u16::from_be_bytes(generation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limit::GenerationFilter;
    use crate::wire::ETHERTYPE_LLTD;

    const STATION: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAPPER: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

    fn device() -> Device {
        Device::new(
            STATION,
            Some([192, 168, 50, 1]),
            "GT-AX11000",
            "GT-AX11000",
            1_234_567,
        )
    }

    fn responder() -> Responder {
        Responder::new(device(), 0)
    }

    fn request(opcode: Opcode, sequence: u16, payload: &[u8], pad_to: usize) -> Vec<u8> {
        let destination = if opcode == Opcode::Discover {
            BROADCAST
        } else {
            STATION
        };
        let mut frame = base_header(&destination, &MAPPER, opcode, sequence).to_vec();
        frame.extend_from_slice(payload);
        if frame.len() < pad_to {
            frame.resize(pad_to, 0);
        }
        frame
    }

    fn discover(generation: u16) -> Vec<u8> {
        let mut payload = generation.to_be_bytes().to_vec();
        payload.extend_from_slice(&[0x00, 0x00]);
        request(Opcode::Discover, 0, &payload, 60)
    }

    #[test]
    fn a_discover_is_answered_with_a_broadcast_hello() {
        let mut responder = responder();
        let reply = responder.handle(&discover(9), 0).expect("a Hello");
        assert_eq!(reply.get(0..6), Some(&BROADCAST[..]));
        assert_eq!(reply.get(6..12), Some(&STATION[..]));
        assert_eq!(
            reply.get(12..14),
            Some(&ETHERTYPE_LLTD.to_be_bytes()[..]),
            "EtherType"
        );
        assert_eq!(reply.get(14), Some(&1), "version");
        assert_eq!(reply.get(15), Some(&0), "type of service");
        assert_eq!(reply.get(16), Some(&0), "reserved");
        assert_eq!(reply.get(17), Some(&Opcode::Hello.to_byte()), "opcode");
        assert_eq!(reply.get(18..24), Some(&BROADCAST[..]), "real destination");
        assert_eq!(reply.get(24..30), Some(&STATION[..]), "real source");
        assert_eq!(reply.get(30..32), Some(&[0, 0][..]), "sequence");
        assert_eq!(
            reply.get(32..34),
            Some(&9_u16.to_be_bytes()[..]),
            "generation"
        );
        assert_eq!(reply.get(34..46), Some(&[0_u8; 12][..]), "mapper addresses");
        assert_eq!(reply.last(), Some(&0), "end of property");
    }

    #[test]
    fn the_hello_property_block_carries_the_expected_types() {
        let mut responder = responder();
        let reply = responder.handle(&discover(1), 0).expect("a Hello");
        let block = reply.get(46..).expect("a property block");
        let mut types = Vec::new();
        let mut offset = 0;
        while let Some(&tlv_type) = block.get(offset) {
            if tlv_type == crate::tlv::TYPE_END_OF_PROPERTY {
                break;
            }
            let length = usize::from(*block.get(offset + 1).expect("a length byte"));
            types.push(tlv_type);
            offset += 2 + length;
        }
        assert_eq!(
            types,
            vec![0x01, 0x02, 0x03, 0x07, 0x0A, 0x0B, 0x0F, 0x11, 0x14, 0x17, 0x19]
        );
    }

    #[test]
    fn a_query_is_answered_with_an_empty_directed_query_response() {
        let mut responder = responder();
        let reply = responder
            .handle(&request(Opcode::Query, 0x2211, &[], 60), 0)
            .expect("a QueryResp");
        assert_eq!(reply.len(), MIN_FRAME_LEN + 2);
        assert_eq!(reply.get(0..6), Some(&MAPPER[..]), "unicast to the mapper");
        assert_eq!(reply.get(17), Some(&Opcode::QueryResp.to_byte()));
        assert_eq!(reply.get(30..32), Some(&0x2211_u16.to_be_bytes()[..]));
        assert_eq!(reply.get(32..34), Some(&[0, 0][..]), "no descriptors");
    }

    #[test]
    fn a_reset_is_accepted_without_a_reply() {
        let mut responder = responder();
        assert_eq!(
            responder.handle(&request(Opcode::Reset, 0, &[], 60), 0),
            Err(Dropped::Accepted(Opcode::Reset))
        );
    }

    #[test]
    fn every_unanswered_opcode_is_dropped_rather_than_answered() {
        let mut responder = responder();
        for opcode in [
            Opcode::Hello,
            Opcode::Emit,
            Opcode::Train,
            Opcode::Probe,
            Opcode::Ack,
            Opcode::QueryResp,
            Opcode::Charge,
            Opcode::Flat,
            Opcode::QueryLargeTlv,
            Opcode::QueryLargeTlvResp,
        ] {
            let sequence = u16::from(!opcode.must_be_unsequenced());
            let frame = request(opcode, sequence, &[0; 8], 60);
            assert_eq!(
                responder.handle(&frame, 0),
                Err(Dropped::Unanswered(opcode)),
                "opcode {opcode:?}"
            );
        }
        assert_eq!(responder.tokens(), crate::limit::DEFAULT_BURST);
    }

    #[test]
    fn a_repeated_generation_is_answered_only_once() {
        let mut responder = responder();
        assert!(responder.handle(&discover(4), 0).is_ok());
        assert_eq!(
            responder.handle(&discover(4), 10),
            Err(Dropped::DuplicateGeneration)
        );
        assert!(responder.handle(&discover(5), 20).is_ok());
    }

    #[test]
    fn invalid_frames_never_consume_the_emission_budget() {
        // The defect this guards against: charging the limiter on receipt
        // rather than on emission lets an attacker spend the whole budget
        // with frames that are never answered, silencing the responder for
        // the real mapper.
        let mut responder = Responder::with_policy(
            device(),
            RateLimiter::new(2, 1_000_000, 0),
            GenerationFilter::default(),
        );
        let mut junk = discover(1);
        junk[14] = 0xFF; // wrong version
        for _ in 0..1_000 {
            assert!(responder.handle(&junk, 0).is_err());
        }
        for opcode in [Opcode::Emit, Opcode::Probe, Opcode::Charge] {
            let sequence = u16::from(!opcode.must_be_unsequenced());
            for _ in 0..1_000 {
                assert!(responder
                    .handle(&request(opcode, sequence, &[0; 8], 60), 0)
                    .is_err());
            }
        }
        assert_eq!(responder.tokens(), 2, "nothing was charged");
        assert!(responder.handle(&discover(1), 0).is_ok());
        assert!(responder.handle(&discover(2), 0).is_ok());
        assert_eq!(
            responder.handle(&discover(3), 0),
            Err(Dropped::RateLimited),
            "the budget is spent only by real replies"
        );
    }

    #[test]
    fn a_reply_never_exceeds_the_permitted_budget_for_any_request_size() {
        for length in 32..=200 {
            let mut responder = Responder::with_policy(
                device(),
                RateLimiter::new(u32::MAX, 1, 0),
                GenerationFilter::new(0),
            );
            let mut payload = 1_u16.to_be_bytes().to_vec();
            payload.extend_from_slice(&[0x00, 0x00]);
            let mut frame = base_header(&BROADCAST, &MAPPER, Opcode::Discover, 0).to_vec();
            frame.extend_from_slice(&payload);
            frame.resize(length.max(MIN_FRAME_LEN + 4), 0);
            let received = frame.len();
            match responder.handle(&frame, 0) {
                Ok(reply) => {
                    assert!(reply.len() <= reply_budget(received));
                    assert!(reply.len() <= MAX_RESPONSE_LEN);
                    assert!(reply.len() <= received.saturating_mul(MAX_AMPLIFICATION));
                }
                Err(reason) => assert_ne!(reason, Dropped::RateLimited, "{reason:?}"),
            }
        }
    }

    #[test]
    fn a_query_response_is_never_larger_than_the_query() {
        let mut responder = responder();
        // A 32-byte Query cannot fund a 34-byte QueryResp, so nothing is sent.
        let bare = request(Opcode::Query, 1, &[], 0);
        assert_eq!(bare.len(), MIN_FRAME_LEN);
        assert_eq!(responder.handle(&bare, 0), Err(Dropped::WouldAmplify));
        // A conforming, Ethernet-padded Query is answered and the reply is
        // strictly smaller.
        let padded = request(Opcode::Query, 1, &[], 60);
        let reply = responder.handle(&padded, 0).expect("a QueryResp");
        assert!(reply.len() < padded.len());
    }

    #[test]
    fn a_discover_with_a_station_list_that_does_not_fit_is_dropped() {
        let mut responder = responder();
        let mut payload = 1_u16.to_be_bytes().to_vec();
        payload.extend_from_slice(&2_u16.to_be_bytes()); // claims two stations
        payload.extend_from_slice(&[0; 6]); // supplies one
        let frame = request(Opcode::Discover, 0, &payload, 0);
        assert_eq!(
            responder.handle(&frame, 0),
            Err(Dropped::InconsistentStationList)
        );

        let mut payload = 1_u16.to_be_bytes().to_vec();
        payload.extend_from_slice(&u16::MAX.to_be_bytes());
        let frame = request(Opcode::Discover, 0, &payload, 60);
        assert_eq!(
            responder.handle(&frame, 0),
            Err(Dropped::InconsistentStationList)
        );
    }

    #[test]
    fn a_discover_shorter_than_its_own_fixed_fields_is_dropped() {
        let mut responder = responder();
        for payload in [&[][..], &[0][..], &[0, 0][..], &[0, 0, 0][..]] {
            let frame = request(Opcode::Discover, 0, payload, 0);
            assert_eq!(responder.handle(&frame, 0), Err(Dropped::TruncatedPayload));
        }
    }

    #[test]
    fn a_full_station_list_is_accepted_and_answered() {
        let mut responder = responder();
        let mut payload = 3_u16.to_be_bytes().to_vec();
        let count = u16::try_from(MAX_DISCOVER_STATIONS).expect("in range");
        payload.extend_from_slice(&count.to_be_bytes());
        payload.extend_from_slice(&vec![0x11; MAX_DISCOVER_STATIONS * 6]);
        let frame = request(Opcode::Discover, 0, &payload, 0);
        assert!(frame.len() <= crate::wire::MAX_FRAME_LEN);
        assert!(responder.handle(&frame, 0).is_ok());
    }

    #[test]
    fn no_frame_of_any_shape_can_panic_or_produce_an_oversized_reply() {
        let mut responder = Responder::with_policy(
            device(),
            RateLimiter::new(u32::MAX, 1, 0),
            GenerationFilter::new(0),
        );
        let mut value = 1_u8;
        for length in 0_u64..300 {
            let bytes: Vec<u8> = (0..length)
                .map(|index| {
                    let step = u8::try_from(index % 251).unwrap_or(1);
                    value = value.wrapping_mul(101).wrapping_add(step);
                    value
                })
                .collect();
            if let Ok(reply) = responder.handle(&bytes, length) {
                assert!(reply.len() <= MAX_RESPONSE_LEN);
                assert!(reply.len() <= reply_budget(bytes.len()));
            }
        }
    }
}
