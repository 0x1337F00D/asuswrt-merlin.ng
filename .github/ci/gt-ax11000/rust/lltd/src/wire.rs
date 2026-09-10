//! The LLTD demultiplex header and its validation.
//!
//! Layout, byte for byte, as the shipped `lld2d.hnd` reads it in
//! `packetio_recv_handler`:
//!
//! ```text
//!  offset  size  field
//!       0     6  Ethernet destination
//!       6     6  Ethernet source
//!      12     2  EtherType, always 0x88D9
//!      14     1  Version, always 1
//!      15     1  Type of Service
//!      16     1  Reserved
//!      17     1  Function (opcode)
//!      18     6  Network address of the real destination
//!      24     6  Network address of the real source
//!      30     2  Sequence number (big endian)
//!      32     -  Opcode-specific payload
//! ```
//!
//! The blob rejects frames shorter than 14 bytes ("runt frame"), then frames
//! shorter than 32 bytes ("truncated Base header"), then a version other than
//! 1, then an opcode above 12. It routes Type of Service 2 to its QoS
//! diagnostics handler and treats 0 and 1 as topology discovery; anything
//! above 2 is dropped.

/// The LLTD EtherType. `0x88D9` in `packetio_recv_handler`, compared against
/// the two bytes at offset 12.
pub const ETHERTYPE_LLTD: u16 = 0x88D9;

/// Ethernet II header length.
pub const ETH_HEADER_LEN: usize = 14;

/// LLTD base (demultiplex) header length.
pub const BASE_HEADER_LEN: usize = 18;

/// Shortest frame that can carry a complete demultiplex header. The blob uses
/// the same bound: it warns "truncated Base header" for anything below 32.
pub const MIN_FRAME_LEN: usize = ETH_HEADER_LEN + BASE_HEADER_LEN;

/// Longest frame accepted. A standard Ethernet frame without the FCS. The
/// blob reads into a 2048-byte buffer and applies no upper bound at all; this
/// port refuses anything a conforming sender cannot have produced.
pub const MAX_FRAME_LEN: usize = 1514;

/// Version byte the blob requires ("got version %d protocol frame; ignoring").
pub const LLTD_VERSION: u8 = 1;

/// Type of Service for topology discovery, the only service this port answers.
pub const TOS_TOPOLOGY_DISCOVERY: u8 = 0;

/// Highest opcode the blob accepts before warning "g_opcode=%d is out of
/// range".
pub const MAX_OPCODE: u8 = 12;

/// Ethernet broadcast address, the destination `packetio_tx_hello` uses for
/// both the Ethernet header and the base header's real destination.
pub const BROADCAST: [u8; 6] = [0xFF; 6];

/// Offsets inside the frame, named so no bare index appears in the parser.
const OFFSET_ETH_DESTINATION: usize = 0;
const OFFSET_ETH_SOURCE: usize = 6;
const OFFSET_ETHERTYPE: usize = 12;
const OFFSET_VERSION: usize = 14;
const OFFSET_TOS: usize = 15;
const OFFSET_RESERVED: usize = 16;
const OFFSET_OPCODE: usize = 17;
const OFFSET_REAL_DESTINATION: usize = 18;
const OFFSET_REAL_SOURCE: usize = 24;
const OFFSET_SEQUENCE: usize = 30;

/// The topology-discovery opcodes, as the blob's range check defines them.
///
/// The names are the public MS-LLTD ones. Only the variants listed in
/// [`crate::responder`] are answered; the rest are recognised purely so an
/// unknown opcode can be told apart from a known-but-unanswered one in the
/// drop statistics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Opcode {
    Discover,
    Hello,
    Emit,
    Train,
    Probe,
    Ack,
    Query,
    QueryResp,
    Reset,
    Charge,
    Flat,
    QueryLargeTlv,
    QueryLargeTlvResp,
}

impl Opcode {
    /// Decodes the function byte. Returns `None` above [`MAX_OPCODE`], which
    /// is the blob's "out of range" drop.
    #[must_use]
    pub fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Discover,
            1 => Self::Hello,
            2 => Self::Emit,
            3 => Self::Train,
            4 => Self::Probe,
            5 => Self::Ack,
            6 => Self::Query,
            7 => Self::QueryResp,
            8 => Self::Reset,
            9 => Self::Charge,
            10 => Self::Flat,
            11 => Self::QueryLargeTlv,
            12 => Self::QueryLargeTlvResp,
            _ => return None,
        })
    }

    /// The function byte for this opcode.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Discover => 0,
            Self::Hello => 1,
            Self::Emit => 2,
            Self::Train => 3,
            Self::Probe => 4,
            Self::Ack => 5,
            Self::Query => 6,
            Self::QueryResp => 7,
            Self::Reset => 8,
            Self::Charge => 9,
            Self::Flat => 10,
            Self::QueryLargeTlv => 11,
            Self::QueryLargeTlvResp => 12,
        }
    }

    /// True for the opcodes the blob refuses to accept with a non-zero
    /// sequence number ("g_opcode %d with seq=%u is illegal; dropping").
    ///
    /// Derived from the range test in `packetio_recv_handler`: a non-zero
    /// sequence number is legal for opcodes 0, 2, 5, 6, 7, 9, 10, 11 and 12,
    /// which leaves Hello, Train, Probe and Reset unsequenced.
    #[must_use]
    pub fn must_be_unsequenced(self) -> bool {
        matches!(self, Self::Hello | Self::Train | Self::Probe | Self::Reset)
    }

    /// True for the opcodes the blob refuses to accept with a zero sequence
    /// number ("g_opcode %d must have seqnum").
    ///
    /// Derived from the same function: with `seq == 0` the blob warns for
    /// opcodes 5, 6, 7 and 10 and resets its session state for every other
    /// opcode.
    #[must_use]
    pub fn must_be_sequenced(self) -> bool {
        matches!(self, Self::Ack | Self::Query | Self::QueryResp | Self::Flat)
    }
}

/// Why a received frame was not answered. Every variant is a silent drop; the
/// enum exists so the tests and the fuzz target can assert *which* rule fired
/// rather than only that nothing was sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Malformed {
    /// Shorter than [`MIN_FRAME_LEN`].
    Truncated,
    /// Longer than [`MAX_FRAME_LEN`].
    Oversized,
    /// EtherType is not [`ETHERTYPE_LLTD`].
    WrongEtherType,
    /// Version byte is not [`LLTD_VERSION`].
    WrongVersion,
    /// Type of Service is not [`TOS_TOPOLOGY_DISCOVERY`].
    UnsupportedService,
    /// The reserved byte is not zero.
    ReservedNotZero,
    /// Function byte above [`MAX_OPCODE`].
    UnknownOpcode,
    /// The real destination is neither this station nor the broadcast address.
    NotAddressedToUs,
    /// The frame claims to come from this station.
    SelfAddressed,
    /// The Ethernet source is a group address, which no conforming station
    /// may use as a source.
    GroupSource,
    /// The sequence number contradicts the opcode's sequencing rule.
    SequenceRuleViolated,
}

/// A validated demultiplex header plus the payload that followed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    /// Ethernet source address of the frame as it arrived.
    pub ethernet_source: [u8; 6],
    /// Base-header real destination: this station or the broadcast address.
    pub real_destination: [u8; 6],
    /// Base-header real source, the address a reply is directed at.
    pub real_source: [u8; 6],
    /// Decoded function byte.
    pub opcode: Opcode,
    /// Sequence number, echoed unchanged into a sequenced reply.
    pub sequence: u16,
    /// Everything after the 32-byte demultiplex header.
    pub payload: &'a [u8],
    /// Length of the whole received frame, the anti-amplification budget.
    pub received_len: usize,
}

/// Reads a big-endian `u16` from `bytes` at `offset`, or `None` if it does not
/// fit. No indexing, so no reachable panic.
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = bytes.get(offset..end)?;
    let array: [u8; 2] = slice.try_into().ok()?;
    Some(u16::from_be_bytes(array))
}

/// Reads a 6-byte address from `bytes` at `offset`, or `None` if it does not
/// fit.
fn read_address(bytes: &[u8], offset: usize) -> Option<[u8; 6]> {
    let end = offset.checked_add(6)?;
    let slice = bytes.get(offset..end)?;
    slice.try_into().ok()
}

/// True for an Ethernet group (multicast or broadcast) address.
#[must_use]
pub fn is_group_address(address: &[u8; 6]) -> bool {
    address.first().is_some_and(|byte| byte & 0x01 != 0)
}

impl<'a> Frame<'a> {
    /// Validates `bytes` as an LLTD topology-discovery frame addressed to
    /// `station`.
    ///
    /// The checks run in the blob's order so a frame this port drops can be
    /// compared against the blob's own warning for the same input. Three
    /// checks are stricter than the blob: the reserved byte must be zero, the
    /// Ethernet source must be a unicast address, and Type of Service 1 and 2
    /// are refused instead of being routed into the topology and QoS paths.
    ///
    /// # Errors
    /// Returns the first rule that rejected the frame.
    pub fn parse(bytes: &'a [u8], station: &[u8; 6]) -> Result<Self, Malformed> {
        if bytes.len() < MIN_FRAME_LEN {
            return Err(Malformed::Truncated);
        }
        if bytes.len() > MAX_FRAME_LEN {
            return Err(Malformed::Oversized);
        }
        let ethertype = read_u16(bytes, OFFSET_ETHERTYPE).ok_or(Malformed::Truncated)?;
        if ethertype != ETHERTYPE_LLTD {
            return Err(Malformed::WrongEtherType);
        }
        if bytes.get(OFFSET_VERSION).copied() != Some(LLTD_VERSION) {
            return Err(Malformed::WrongVersion);
        }
        if bytes.get(OFFSET_TOS).copied() != Some(TOS_TOPOLOGY_DISCOVERY) {
            return Err(Malformed::UnsupportedService);
        }
        if bytes.get(OFFSET_RESERVED).copied() != Some(0) {
            return Err(Malformed::ReservedNotZero);
        }
        let function = bytes
            .get(OFFSET_OPCODE)
            .copied()
            .ok_or(Malformed::Truncated)?;
        let opcode = Opcode::from_byte(function).ok_or(Malformed::UnknownOpcode)?;

        let real_destination =
            read_address(bytes, OFFSET_REAL_DESTINATION).ok_or(Malformed::Truncated)?;
        if &real_destination != station && real_destination != BROADCAST {
            return Err(Malformed::NotAddressedToUs);
        }
        let real_source = read_address(bytes, OFFSET_REAL_SOURCE).ok_or(Malformed::Truncated)?;
        let ethernet_source = read_address(bytes, OFFSET_ETH_SOURCE).ok_or(Malformed::Truncated)?;
        if &real_source == station || &ethernet_source == station {
            return Err(Malformed::SelfAddressed);
        }
        if is_group_address(&ethernet_source) || is_group_address(&real_source) {
            return Err(Malformed::GroupSource);
        }

        let sequence = read_u16(bytes, OFFSET_SEQUENCE).ok_or(Malformed::Truncated)?;
        if sequence != 0 && opcode.must_be_unsequenced() {
            return Err(Malformed::SequenceRuleViolated);
        }
        if sequence == 0 && opcode.must_be_sequenced() {
            return Err(Malformed::SequenceRuleViolated);
        }

        let payload = bytes.get(MIN_FRAME_LEN..).ok_or(Malformed::Truncated)?;
        Ok(Self {
            ethernet_source,
            real_destination,
            real_source,
            opcode,
            sequence,
            payload,
            received_len: bytes.len(),
        })
    }
}

/// Builds the 32-byte demultiplex header of an outgoing frame.
///
/// `packetio_tx_hello` writes exactly these fields: Ethernet destination and
/// base-header real destination both set to the reply target, both source
/// fields to this station, EtherType 0x88D9, version 1, Type of Service 0 and
/// the reserved byte left zero.
#[must_use]
pub fn base_header(
    destination: &[u8; 6],
    station: &[u8; 6],
    opcode: Opcode,
    sequence: u16,
) -> [u8; MIN_FRAME_LEN] {
    let mut header = [0_u8; MIN_FRAME_LEN];
    let ethertype = ETHERTYPE_LLTD.to_be_bytes();
    let sequence = sequence.to_be_bytes();
    // Every write below is a fixed-size copy into a fixed-size array, so the
    // slice lengths are known equal at compile time.
    header[OFFSET_ETH_DESTINATION..OFFSET_ETH_DESTINATION + 6].copy_from_slice(destination);
    header[OFFSET_ETH_SOURCE..OFFSET_ETH_SOURCE + 6].copy_from_slice(station);
    header[OFFSET_ETHERTYPE..OFFSET_ETHERTYPE + 2].copy_from_slice(&ethertype);
    header[OFFSET_VERSION] = LLTD_VERSION;
    header[OFFSET_TOS] = TOS_TOPOLOGY_DISCOVERY;
    header[OFFSET_OPCODE] = opcode.to_byte();
    header[OFFSET_REAL_DESTINATION..OFFSET_REAL_DESTINATION + 6].copy_from_slice(destination);
    header[OFFSET_REAL_SOURCE..OFFSET_REAL_SOURCE + 6].copy_from_slice(station);
    header[OFFSET_SEQUENCE..OFFSET_SEQUENCE + 2].copy_from_slice(&sequence);
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATION: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAPPER: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

    fn discover() -> Vec<u8> {
        let mut frame = base_header(&BROADCAST, &MAPPER, Opcode::Discover, 0x0102).to_vec();
        frame.extend_from_slice(&[0x00, 0x07]); // Generation number.
        frame.extend_from_slice(&[0x00, 0x00]); // Number of stations.
        frame.resize(60, 0); // Ethernet minimum-length padding.
        frame
    }

    #[test]
    fn a_conforming_discover_parses() {
        let bytes = discover();
        let frame = Frame::parse(&bytes, &STATION).expect("a conforming Discover");
        assert_eq!(frame.opcode, Opcode::Discover);
        assert_eq!(frame.real_source, MAPPER);
        assert_eq!(frame.sequence, 0x0102);
        assert_eq!(frame.received_len, 60);
        assert_eq!(frame.payload.len(), 60 - MIN_FRAME_LEN);
    }

    #[test]
    fn every_header_rule_rejects_its_own_frame() {
        let station = STATION;
        for (mutate, expected) in [
            (
                (|f: &mut Vec<u8>| f.truncate(31)) as fn(&mut Vec<u8>),
                Malformed::Truncated,
            ),
            (|f| f.resize(MAX_FRAME_LEN + 1, 0), Malformed::Oversized),
            (|f| f[12] = 0x08, Malformed::WrongEtherType),
            (|f| f[14] = 2, Malformed::WrongVersion),
            (|f| f[15] = 1, Malformed::UnsupportedService),
            (|f| f[15] = 2, Malformed::UnsupportedService),
            (|f| f[16] = 1, Malformed::ReservedNotZero),
            (|f| f[17] = 13, Malformed::UnknownOpcode),
            (|f| f[18] = 0x02, Malformed::NotAddressedToUs),
            (
                |f| f[24..30].copy_from_slice(&STATION),
                Malformed::SelfAddressed,
            ),
            (
                |f| f[6..12].copy_from_slice(&STATION),
                Malformed::SelfAddressed,
            ),
            (|f| f[6] = 0x01, Malformed::GroupSource),
            (
                |f| f[17] = Opcode::Reset.to_byte(),
                Malformed::SequenceRuleViolated,
            ),
            (
                |f| {
                    f[17] = Opcode::Query.to_byte();
                    f[30..32].copy_from_slice(&[0, 0]);
                },
                Malformed::SequenceRuleViolated,
            ),
        ] {
            let mut bytes = discover();
            mutate(&mut bytes);
            assert_eq!(
                Frame::parse(&bytes, &station).unwrap_err(),
                expected,
                "frame {bytes:02x?}"
            );
        }
    }

    #[test]
    fn opcodes_round_trip_through_their_function_byte() {
        for value in 0..=MAX_OPCODE {
            let opcode = Opcode::from_byte(value).expect("an in-range opcode");
            assert_eq!(opcode.to_byte(), value);
        }
        assert_eq!(Opcode::from_byte(MAX_OPCODE + 1), None);
        assert_eq!(Opcode::from_byte(u8::MAX), None);
    }

    #[test]
    fn a_frame_of_exactly_the_header_length_has_an_empty_payload() {
        let bytes = base_header(&STATION, &MAPPER, Opcode::Reset, 0).to_vec();
        let frame = Frame::parse(&bytes, &STATION).expect("a bare Reset");
        assert!(frame.payload.is_empty());
        assert_eq!(frame.received_len, MIN_FRAME_LEN);
    }

    #[test]
    fn no_input_of_any_length_or_content_can_panic() {
        // panic = "abort" in the release profile, so a panic here would be a
        // remote crash. Walk every length around each boundary.
        let mut value = 0_u8;
        for length in (0..70).chain([MAX_FRAME_LEN - 1, MAX_FRAME_LEN, MAX_FRAME_LEN + 1]) {
            let bytes: Vec<u8> = (0..length)
                .map(|_| {
                    value = value.wrapping_mul(31).wrapping_add(17);
                    value
                })
                .collect();
            let _ = Frame::parse(&bytes, &STATION);
        }
    }
}
