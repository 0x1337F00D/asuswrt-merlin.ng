//! RFC 5905 packet layout, strict decoding and reply construction.
//!
//! The whole module is allocation-free and total: every accessor is bounds
//! checked, every conversion is explicit and no arithmetic can overflow, so a
//! hostile datagram cannot reach a panic in a `panic = "abort"` daemon.

/// Length of an NTP header without the optional authenticator.
pub const PACKET_LEN: usize = 48;
/// Length of an NTP header plus the legacy 4-byte key id and 16-byte digest.
/// The daemon holds no keys, so the authenticator is never inspected; the
/// length is accepted only because busybox's ntpd accepted it too.
pub const AUTHENTICATED_PACKET_LEN: usize = PACKET_LEN + 4 + 16;

/// Seconds between the NTP era-0 epoch (1900-01-01) and the Unix epoch.
pub const NTP_TO_UNIX_EPOCH: u64 = 2_208_988_800;

/// Highest stratum that can still carry time; 16 means "unsynchronised".
pub const MAX_STRATUM: u8 = 16;

/// Field offsets, named exactly as in RFC 5905 figure 8.
mod field {
    /// LI (2 bits) | VN (3 bits) | Mode (3 bits)
    pub const FLAGS: usize = 0;
    /// Stratum, 1..=15 usable, 0 is a kiss-o'-death, 16 is unsynchronised.
    pub const STRATUM: usize = 1;
    /// Peer poll interval, log2 seconds, signed.
    pub const POLL: usize = 2;
    /// Clock precision, log2 seconds, signed.
    pub const PRECISION: usize = 3;
    /// Root delay, unsigned 16.16 fixed point seconds.
    pub const ROOT_DELAY: usize = 4;
    /// Root dispersion, unsigned 16.16 fixed point seconds.
    pub const ROOT_DISPERSION: usize = 8;
    /// Reference id; for stratum 0 it carries the four-byte kiss code.
    pub const REFERENCE_ID: usize = 12;
    /// Reference timestamp, unsigned 32.32 fixed point seconds since 1900.
    pub const REFERENCE: usize = 16;
    /// Origin timestamp: T1, the client's transmit timestamp, echoed back.
    pub const ORIGIN: usize = 24;
    /// Receive timestamp: T2, when the server saw the request.
    pub const RECEIVE: usize = 32;
    /// Transmit timestamp: T3, when the server emitted the reply.
    pub const TRANSMIT: usize = 40;
}

/// Leap indicator, the top two bits of the flags byte.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Leap {
    /// 0: no warning.
    #[default]
    NoWarning,
    /// 1: last minute of the day has 61 seconds.
    AddSecond,
    /// 2: last minute of the day has 59 seconds.
    DeleteSecond,
    /// 3: alarm condition, the peer is not synchronised.
    Unsynchronised,
}

impl Leap {
    fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::NoWarning,
            1 => Self::AddSecond,
            2 => Self::DeleteSecond,
            _ => Self::Unsynchronised,
        }
    }

    fn bits(self) -> u8 {
        match self {
            Self::NoWarning => 0,
            Self::AddSecond => 1,
            Self::DeleteSecond => 2,
            Self::Unsynchronised => 3,
        }
    }
}

/// Association mode, the low three bits of the flags byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// 0: reserved.
    Reserved,
    /// 1: symmetric active.
    SymmetricActive,
    /// 2: symmetric passive.
    SymmetricPassive,
    /// 3: client request.
    Client,
    /// 4: server reply.
    Server,
    /// 5: broadcast.
    Broadcast,
    /// 6: NTP control message (mode 6). Never served.
    Control,
    /// 7: reserved for private use (mode 7, "monlist"). Never served.
    Private,
}

impl Mode {
    fn from_bits(bits: u8) -> Self {
        match bits & 0x07 {
            0 => Self::Reserved,
            1 => Self::SymmetricActive,
            2 => Self::SymmetricPassive,
            3 => Self::Client,
            4 => Self::Server,
            5 => Self::Broadcast,
            6 => Self::Control,
            _ => Self::Private,
        }
    }

    fn bits(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::SymmetricActive => 1,
            Self::SymmetricPassive => 2,
            Self::Client => 3,
            Self::Server => 4,
            Self::Broadcast => 5,
            Self::Control => 6,
            Self::Private => 7,
        }
    }
}

/// A 64-bit NTP timestamp: 32 bits of seconds since 1900 and a 32-bit binary
/// fraction. Era wrap-around (2036) is out of scope for this device, exactly
/// as it is for the busybox applet this replaces.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Timestamp {
    /// Whole seconds since 1900-01-01T00:00:00Z.
    pub seconds: u32,
    /// Binary fraction of a second, unit 2^-32 s.
    pub fraction: u32,
}

impl Timestamp {
    /// Decodes the eight network-order bytes at `offset`, if they are present.
    fn read(bytes: &[u8], offset: usize) -> Option<Self> {
        Some(Self {
            seconds: read_u32(bytes, offset)?,
            fraction: read_u32(bytes, offset.checked_add(4)?)?,
        })
    }

    fn write(self, bytes: &mut [u8; PACKET_LEN], offset: usize) {
        write_u32(bytes, offset, self.seconds);
        write_u32(bytes, offset + 4, self.fraction);
    }

    /// Seconds since 1900 as a float. Exact for the integer part and better
    /// than a nanosecond for the fraction, which is all the discipline needs.
    #[must_use]
    pub fn as_secs_f64(self) -> f64 {
        f64::from(self.seconds) + f64::from(self.fraction) / 4_294_967_296.0
    }

    /// Rebuilds a timestamp from seconds since 1900, saturating outside the
    /// representable era instead of wrapping through an `as` cast.
    #[must_use]
    pub fn from_secs_f64(value: f64) -> Self {
        if !value.is_finite() || value <= 0.0 {
            return Self::default();
        }
        let seconds = value.floor();
        if seconds >= 4_294_967_296.0 {
            return Self {
                seconds: u32::MAX,
                fraction: u32::MAX,
            };
        }
        let fraction = ((value - seconds) * 4_294_967_296.0).clamp(0.0, 4_294_967_295.0);
        Self {
            seconds: seconds as u32,
            fraction: fraction as u32,
        }
    }

    /// True when both halves are zero, which NTP uses to mean "no value".
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.seconds == 0 && self.fraction == 0
    }

    /// The same instant with the binary fraction cleared.
    ///
    /// The reference timestamp a server publishes is the instant its clock was
    /// last corrected. At full precision that is a sub-microsecond reading of
    /// when the last upstream reply arrived, which any LAN client may ask for
    /// and which leaks the exact phase of the poll timer. Whole seconds are
    /// all a client can use, so that is all this daemon publishes.
    #[must_use]
    pub fn truncated_to_seconds(self) -> Self {
        Self {
            seconds: self.seconds,
            fraction: 0,
        }
    }
}

/// A decoded NTP header. The optional authenticator is deliberately dropped.
#[derive(Clone, Copy, Debug)]
pub struct Packet {
    /// Leap indicator.
    pub leap: Leap,
    /// Protocol version, 0..=7 as carried on the wire.
    pub version: u8,
    /// Association mode.
    pub mode: Mode,
    /// Stratum.
    pub stratum: u8,
    /// Peer poll interval, log2 seconds.
    pub poll: i8,
    /// Clock precision, log2 seconds.
    pub precision: i8,
    /// Root delay in seconds.
    pub root_delay: f64,
    /// Root dispersion in seconds.
    pub root_dispersion: f64,
    /// Reference identifier, or the kiss code when `stratum == 0`.
    pub reference_id: [u8; 4],
    /// Reference timestamp.
    pub reference: Timestamp,
    /// Origin timestamp (T1).
    pub origin: Timestamp,
    /// Receive timestamp (T2).
    pub receive: Timestamp,
    /// Transmit timestamp (T3).
    pub transmit: Timestamp,
}

/// Why a datagram is not an NTP header at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Fewer than 48 bytes: not a header.
    Truncated {
        /// Received datagram length.
        length: usize,
    },
    /// Neither 48 nor 68 bytes: not a header this daemon accepts.
    UnexpectedLength {
        /// Received datagram length.
        length: usize,
    },
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { length } => write!(formatter, "truncated datagram ({length} bytes)"),
            Self::UnexpectedLength { length } => {
                write!(formatter, "unexpected datagram length ({length} bytes)")
            }
        }
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(slice))
}

fn write_u32(bytes: &mut [u8; PACKET_LEN], offset: usize, value: u32) {
    let encoded = value.to_be_bytes();
    if let Some(slot) = bytes.get_mut(offset..offset + 4) {
        slot.copy_from_slice(&encoded);
    }
}

/// Converts an unsigned 16.16 fixed-point field to seconds.
fn fixed_16_16(raw: u32) -> f64 {
    f64::from(raw) / 65_536.0
}

/// Converts seconds to an unsigned 16.16 fixed-point field, saturating.
fn to_fixed_16_16(seconds: f64) -> u32 {
    if !seconds.is_finite() || seconds <= 0.0 {
        return 0;
    }
    let scaled = seconds * 65_536.0;
    if scaled >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        scaled as u32
    }
}

impl Packet {
    /// Decodes a datagram. Accepts exactly the two lengths the busybox applet
    /// accepted; anything else is rejected before a single field is read.
    ///
    /// # Errors
    /// Returns [`DecodeError`] when the datagram is not 48 or 68 bytes long.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < PACKET_LEN {
            return Err(DecodeError::Truncated {
                length: bytes.len(),
            });
        }
        if bytes.len() != PACKET_LEN && bytes.len() != AUTHENTICATED_PACKET_LEN {
            return Err(DecodeError::UnexpectedLength {
                length: bytes.len(),
            });
        }
        let flags = bytes.get(field::FLAGS).copied().unwrap_or(0);
        let reference_id: [u8; 4] = bytes
            .get(field::REFERENCE_ID..field::REFERENCE_ID + 4)
            .and_then(|slice| slice.try_into().ok())
            .unwrap_or([0; 4]);
        Ok(Self {
            leap: Leap::from_bits(flags >> 6),
            version: (flags >> 3) & 0x07,
            mode: Mode::from_bits(flags),
            stratum: bytes.get(field::STRATUM).copied().unwrap_or(0),
            poll: bytes.get(field::POLL).copied().unwrap_or(0) as i8,
            precision: bytes.get(field::PRECISION).copied().unwrap_or(0) as i8,
            root_delay: fixed_16_16(read_u32(bytes, field::ROOT_DELAY).unwrap_or(0)),
            root_dispersion: fixed_16_16(read_u32(bytes, field::ROOT_DISPERSION).unwrap_or(0)),
            reference_id,
            reference: Timestamp::read(bytes, field::REFERENCE).unwrap_or_default(),
            origin: Timestamp::read(bytes, field::ORIGIN).unwrap_or_default(),
            receive: Timestamp::read(bytes, field::RECEIVE).unwrap_or_default(),
            transmit: Timestamp::read(bytes, field::TRANSMIT).unwrap_or_default(),
        })
    }

    /// Encodes the header. The authenticator is never emitted: this daemon
    /// never speaks authenticated NTP, so a reply is always 48 bytes and can
    /// never be larger than the request that triggered it.
    #[must_use]
    pub fn encode(&self) -> [u8; PACKET_LEN] {
        let mut bytes = [0_u8; PACKET_LEN];
        bytes[field::FLAGS] =
            (self.leap.bits() << 6) | ((self.version & 0x07) << 3) | self.mode.bits();
        bytes[field::STRATUM] = self.stratum;
        bytes[field::POLL] = self.poll as u8;
        bytes[field::PRECISION] = self.precision as u8;
        write_u32(
            &mut bytes,
            field::ROOT_DELAY,
            to_fixed_16_16(self.root_delay),
        );
        write_u32(
            &mut bytes,
            field::ROOT_DISPERSION,
            to_fixed_16_16(self.root_dispersion),
        );
        bytes[field::REFERENCE_ID..field::REFERENCE_ID + 4].copy_from_slice(&self.reference_id);
        self.reference.write(&mut bytes, field::REFERENCE);
        self.origin.write(&mut bytes, field::ORIGIN);
        self.receive.write(&mut bytes, field::RECEIVE);
        self.transmit.write(&mut bytes, field::TRANSMIT);
        bytes
    }
}

/// The four-character code a stratum-0 "kiss-o'-death" packet carries in the
/// reference-id field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KissCode {
    /// `DENY`: the server refuses service permanently.
    Deny,
    /// `RSTR`: access denied by local policy, permanently.
    Restrict,
    /// `RATE`: the client is polling too fast.
    Rate,
    /// Any other four bytes, including non-printable ones.
    Other([u8; 4]),
}

impl KissCode {
    /// Classifies the reference id of a stratum-0 packet.
    #[must_use]
    pub fn from_reference_id(reference_id: [u8; 4]) -> Self {
        match &reference_id {
            b"DENY" => Self::Deny,
            b"RSTR" => Self::Restrict,
            b"RATE" => Self::Rate,
            _ => Self::Other(reference_id),
        }
    }

    /// True when the peer must never be queried again in this process.
    #[must_use]
    pub fn is_permanent(self) -> bool {
        matches!(self, Self::Deny | Self::Restrict)
    }
}

impl core::fmt::Display for KissCode {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Deny => formatter.write_str("DENY"),
            Self::Restrict => formatter.write_str("RSTR"),
            Self::Rate => formatter.write_str("RATE"),
            Self::Other(code) => {
                for byte in code {
                    if byte.is_ascii_graphic() {
                        write!(formatter, "{}", char::from(*byte))?;
                    } else {
                        write!(formatter, "\\x{byte:02x}")?;
                    }
                }
                Ok(())
            }
        }
    }
}
