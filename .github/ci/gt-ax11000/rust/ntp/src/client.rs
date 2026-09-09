//! Client-side validation of server replies.
//!
//! Everything an attacker controls is checked before it can influence the
//! clock. The order matters: the origin-timestamp check comes first, so an
//! off-path spoofer must guess the 64-bit nonce before any other field of its
//! packet is even looked at.

use crate::packet::{
    DecodeError, KissCode, Leap, Mode, Packet, Timestamp, MAX_STRATUM, NTP_TO_UNIX_EPOCH,
};

/// Largest root distance (`root_delay / 2 + root_dispersion`) still considered
/// usable, in seconds. This is ntpd's MAXDISP; busybox has the same check but
/// left it commented out.
pub const MAX_ROOT_DISTANCE: f64 = 16.0;

/// Largest round-trip delay accepted, in seconds. The delay is a difference of
/// two local readings minus a difference of two server readings, so it stays
/// meaningful even when the local clock is years out of date.
pub const MAX_DELAY: f64 = 16.0;

/// Earliest server time this firmware will believe: 2024-01-01T00:00:00Z
/// expressed in NTP era-0 seconds. Anything before that is a replay or a
/// misconfigured peer, never a fact about the present.
pub const MIN_PLAUSIBLE_NTP_SECONDS: u32 = 3_913_056_000;

/// The nonce sent in a query, kept so the reply can be matched to it.
#[derive(Clone, Copy, Debug)]
pub struct Query {
    /// The random transmit timestamp that was put on the wire.
    pub nonce: Timestamp,
    /// Local time when the query was sent (T1), seconds since 1900.
    pub sent_at: f64,
}

/// Everything a valid reply contributes to the discipline.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Sample {
    /// Local clock offset in seconds; positive means the local clock is slow.
    pub offset: f64,
    /// Round-trip delay in seconds, never below the local precision.
    pub delay: f64,
    /// Round-trip delay exactly as measured, used for the growth heuristic.
    pub raw_delay: f64,
    /// Local time the reply arrived (T4), seconds since 1900.
    pub received_at: f64,
    /// Server stratum, always 1..=15 here.
    pub stratum: u8,
    /// Server leap indicator, never `Unsynchronised` here.
    pub leap: Leap,
    /// Server clock precision, log2 seconds.
    pub precision: i8,
    /// Server root delay in seconds.
    pub root_delay: f64,
    /// Server root dispersion in seconds.
    pub root_dispersion: f64,
    /// Server reference id, forwarded when this router answers as a server.
    pub reference_id: [u8; 4],
}

/// Why a reply was discarded.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Rejection {
    /// Not an NTP header of an accepted length.
    Malformed(DecodeError),
    /// The origin timestamp is not the nonce that was sent: someone else's
    /// packet, a stale reply, or a spoof.
    OriginMismatch,
    /// Not a server-mode reply.
    NotServerMode(Mode),
    /// Protocol version outside 3..=4.
    UnsupportedVersion(u8),
    /// Stratum 0: a kiss-o'-death packet, never a time source.
    KissOfDeath(KissCode),
    /// Stratum 16 or above: the peer is not synchronised.
    StratumUnusable(u8),
    /// The leap indicator signals an alarm condition.
    LeapAlarm,
    /// A mandatory timestamp field is zero.
    ZeroTimestamp,
    /// The server's own error bound already exceeds what can be used.
    RootDistanceTooLarge(f64),
    /// The round trip took longer than any usable measurement.
    DelayTooLarge(f64),
    /// The absolute time the server claims cannot be the present.
    ImplausibleServerTime(u32),
    /// The offset arithmetic did not produce a finite number.
    NotFinite,
}

impl core::fmt::Display for Rejection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(error) => write!(formatter, "{error}"),
            Self::OriginMismatch => formatter.write_str("origin timestamp does not match query"),
            Self::NotServerMode(mode) => write!(formatter, "reply is not server mode ({mode:?})"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported NTP version {version}")
            }
            Self::KissOfDeath(code) => write!(formatter, "kiss-o'-death {code}"),
            Self::StratumUnusable(stratum) => write!(formatter, "unusable stratum {stratum}"),
            Self::LeapAlarm => formatter.write_str("peer is unsynchronised (leap alarm)"),
            Self::ZeroTimestamp => formatter.write_str("mandatory timestamp is zero"),
            Self::RootDistanceTooLarge(distance) => {
                write!(formatter, "root distance {distance:.3}s too large")
            }
            Self::DelayTooLarge(delay) => write!(formatter, "delay {delay:.3}s too large"),
            Self::ImplausibleServerTime(seconds) => {
                write!(formatter, "implausible server time (NTP {seconds})")
            }
            Self::NotFinite => formatter.write_str("offset arithmetic is not finite"),
        }
    }
}

/// Validates a datagram received on a peer socket and turns it into a sample.
///
/// `sent_at` (T1) and `received_at` (T4) are local readings; `T2`/`T3` come
/// from the packet. The classical SNTP formulas are used:
/// `delay = (T4 - T1) - (T3 - T2)` and `offset = ((T2 - T1) + (T3 - T4)) / 2`.
///
/// # Errors
/// Returns the first [`Rejection`] that applies; the sample is produced only
/// when every check passed.
pub fn evaluate_reply(
    datagram: &[u8],
    query: Query,
    received_at: f64,
    precision_seconds: f64,
) -> Result<Sample, Rejection> {
    let packet = Packet::decode(datagram).map_err(Rejection::Malformed)?;

    // Anti-spoofing gate first: nothing below this line can be reached by an
    // attacker who cannot observe the 64 random bits we transmitted.
    if packet.origin != query.nonce {
        return Err(Rejection::OriginMismatch);
    }
    if packet.mode != Mode::Server {
        return Err(Rejection::NotServerMode(packet.mode));
    }
    if !(3..=4).contains(&packet.version) {
        return Err(Rejection::UnsupportedVersion(packet.version));
    }
    if packet.stratum == 0 {
        return Err(Rejection::KissOfDeath(KissCode::from_reference_id(
            packet.reference_id,
        )));
    }
    if packet.stratum >= MAX_STRATUM {
        return Err(Rejection::StratumUnusable(packet.stratum));
    }
    if packet.leap == Leap::Unsynchronised {
        return Err(Rejection::LeapAlarm);
    }
    if packet.transmit.is_zero() || packet.receive.is_zero() {
        return Err(Rejection::ZeroTimestamp);
    }
    let root_distance = packet.root_delay / 2.0 + packet.root_dispersion;
    if !root_distance.is_finite() || root_distance >= MAX_ROOT_DISTANCE {
        return Err(Rejection::RootDistanceTooLarge(root_distance));
    }
    if packet.transmit.seconds < MIN_PLAUSIBLE_NTP_SECONDS {
        return Err(Rejection::ImplausibleServerTime(packet.transmit.seconds));
    }

    let t1 = query.sent_at;
    let t2 = packet.receive.as_secs_f64();
    let t3 = packet.transmit.as_secs_f64();
    let t4 = received_at;
    let raw_delay = (t4 - t1) - (t3 - t2);
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
    if !raw_delay.is_finite() || !offset.is_finite() {
        return Err(Rejection::NotFinite);
    }
    if !(-MAX_DELAY..=MAX_DELAY).contains(&raw_delay) {
        return Err(Rejection::DelayTooLarge(raw_delay));
    }

    Ok(Sample {
        offset,
        // Differing clock rates on a fast network can make the measured delay
        // negative; ntpd clamps it to the local precision rather than
        // reporting an impossible value.
        delay: raw_delay.max(precision_seconds),
        raw_delay: raw_delay.max(0.0),
        received_at,
        stratum: packet.stratum,
        leap: packet.leap,
        precision: packet.precision,
        root_delay: packet.root_delay,
        root_dispersion: packet.root_dispersion,
        reference_id: packet.reference_id,
    })
}

/// Builds the query datagram for a peer. `nonce` must come from a source an
/// off-path attacker cannot predict.
#[must_use]
pub fn build_query(nonce: Timestamp) -> [u8; crate::packet::PACKET_LEN] {
    Packet {
        leap: Leap::NoWarning,
        version: 4,
        mode: Mode::Client,
        stratum: 0,
        poll: 0,
        precision: 0,
        root_delay: 0.0,
        root_dispersion: 0.0,
        reference_id: [0; 4],
        reference: Timestamp::default(),
        origin: Timestamp::default(),
        receive: Timestamp::default(),
        // The transmit timestamp is a nonce, not the local time: the real
        // local clock is never disclosed and the reply must echo the nonce.
        transmit: nonce,
    }
    .encode()
}

/// Converts NTP era-0 seconds to a Unix timestamp, saturating at zero.
#[must_use]
pub fn ntp_to_unix_seconds(ntp_seconds: f64) -> f64 {
    ntp_seconds - NTP_TO_UNIX_EPOCH as f64
}
