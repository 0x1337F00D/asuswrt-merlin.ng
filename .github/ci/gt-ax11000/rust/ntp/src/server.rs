//! LAN server mode (`-l -I <ifname>`).
//!
//! The only request this daemon will ever answer is a well-formed mode-3
//! client packet, and only once the local clock is disciplined. There is no
//! mode-6 (control) and no mode-7 (private/`monlist`) surface at all, which is
//! where the classic NTP amplification and information-disclosure bugs live.
//! The reply is always exactly 48 bytes, so it can never be larger than the
//! request that provoked it.

use crate::packet::{Leap, Mode, Packet, Timestamp, MAX_STRATUM, PACKET_LEN};

/// Local server state, published in every reply.
#[derive(Clone, Copy, Debug)]
pub struct ServerState {
    /// Leap indicator learnt from the selected upstream peer.
    pub leap: Leap,
    /// Local stratum: selected peer's stratum plus one, or 16 when unsynced.
    pub stratum: u8,
    /// Current poll exponent, log2 seconds.
    pub poll: i8,
    /// Local clock precision, log2 seconds.
    pub precision: i8,
    /// Total root delay to the primary reference, seconds.
    pub root_delay: f64,
    /// Total root dispersion to the primary reference, seconds.
    pub root_dispersion: f64,
    /// Reference identifier of the selected upstream peer.
    pub reference_id: [u8; 4],
    /// When the local clock was last set or corrected.
    pub reference: Timestamp,
}

impl ServerState {
    /// True when the local clock may be published to LAN clients.
    #[must_use]
    pub fn is_synchronised(&self) -> bool {
        self.stratum > 0 && self.stratum < MAX_STRATUM
    }
}

/// Why a received request produced no reply.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Refusal {
    /// Not an NTP header of an accepted length.
    Malformed(crate::packet::DecodeError),
    /// Not a mode-3 client request. Mode 6 and mode 7 land here too, and the
    /// daemon implements no handler for either.
    UnsupportedMode(Mode),
    /// Protocol version outside 3..=4.
    UnsupportedVersion(u8),
    /// The local clock is not disciplined yet, so there is nothing truthful to
    /// say. Staying silent is preferred over an alarm-marked reply.
    Unsynchronised,
    /// The per-second reply budget for this interface is exhausted.
    RateLimited,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(error) => write!(formatter, "{error}"),
            Self::UnsupportedMode(mode) => write!(formatter, "unsupported mode {mode:?}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported NTP version {version}")
            }
            Self::Unsynchronised => formatter.write_str("local clock is not synchronised"),
            Self::RateLimited => formatter.write_str("reply budget exhausted"),
        }
    }
}

/// Validates a request and builds the reply.
///
/// `receive` is when the request arrived and `transmit` is the instant the
/// reply is emitted; both are read from the local clock by the caller.
///
/// # Errors
/// Returns the [`Refusal`] that stopped the reply from being built.
pub fn build_reply(
    request: &[u8],
    state: &ServerState,
    receive: Timestamp,
    transmit: Timestamp,
) -> Result<[u8; PACKET_LEN], Refusal> {
    let packet = Packet::decode(request).map_err(Refusal::Malformed)?;
    if packet.mode != Mode::Client {
        return Err(Refusal::UnsupportedMode(packet.mode));
    }
    if !(3..=4).contains(&packet.version) {
        return Err(Refusal::UnsupportedVersion(packet.version));
    }
    if !state.is_synchronised() {
        return Err(Refusal::Unsynchronised);
    }
    Ok(Packet {
        leap: state.leap,
        // Answer in the version the client asked for; it is already validated
        // to be 3 or 4, so no unvalidated bits are echoed.
        version: packet.version,
        mode: Mode::Server,
        stratum: state.stratum,
        // Our own poll exponent, never the client's: nothing the requester
        // sends is reflected except the mandatory origin timestamp.
        poll: state.poll,
        precision: state.precision,
        root_delay: state.root_delay,
        root_dispersion: state.root_dispersion,
        reference_id: state.reference_id,
        reference: state.reference,
        // The one field the protocol requires to be echoed, and it goes only
        // back to the address the request came from.
        origin: packet.transmit,
        receive,
        transmit,
    }
    .encode())
}

/// Number of replies the server will emit in any one-second window.
pub const REPLY_BUDGET_PER_SECOND: u32 = 64;

/// A fixed-size, allocation-free reply budget.
///
/// A 48-byte reply to a 48-byte request offers an attacker no amplification,
/// but a spoofed flood would still cost the router. The budget bounds that at
/// a rate a LAN full of clients cannot reach.
#[derive(Clone, Copy, Debug)]
pub struct ReplyBudget {
    window_start: f64,
    used: u32,
}

impl Default for ReplyBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplyBudget {
    /// A budget that has not been used yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            window_start: f64::NEG_INFINITY,
            used: 0,
        }
    }

    /// Consumes one reply from the budget, returning false when exhausted.
    pub fn allow(&mut self, now: f64) -> bool {
        if !now.is_finite() {
            return false;
        }
        if now < self.window_start || now - self.window_start >= 1.0 {
            self.window_start = now;
            self.used = 0;
        }
        if self.used >= REPLY_BUDGET_PER_SECOND {
            return false;
        }
        self.used = self.used.saturating_add(1);
        true
    }
}
