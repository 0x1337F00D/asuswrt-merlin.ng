//! The facts this station advertises, and the bounds they are held to.
//!
//! Nothing here is derived from a received frame. The binary fills a [`Device`]
//! once at start-up from the interface and from NVRAM, and the responder only
//! ever reads it.

/// Longest machine name emitted, in characters.
///
/// `get_machine_name` in the blob calls `util_copy_ascii_to_ucs2` with a
/// 32-byte output limit and that helper stops while more than 3 bytes remain,
/// so at most 15 characters plus the terminator are produced.
pub const MAX_MACHINE_NAME_CHARS: usize = 15;

/// Longest friendly name emitted, in characters. `get_friendly_name` uses a
/// 64-byte limit, so at most 31 characters plus the terminator.
pub const MAX_FRIENDLY_NAME_CHARS: usize = 31;

/// Characteristics TLV, exactly the four bytes `get_net_flags` produces.
///
/// The blob stores the constant word `0x00000030` into the property buffer and
/// `write_uint32_t` copies it verbatim, so these are the bytes that reach the
/// wire. The individual bit meanings were not determined from the blob.
pub const CHARACTERISTICS: [u8; 4] = [0x30, 0x00, 0x00, 0x00];

/// Physical Medium TLV. `get_physical_medium` stores `0x06000000`, which is
/// the big-endian IANA ifType 6, `ethernetCsmacd`.
pub const PHYSICAL_MEDIUM: [u8; 4] = [0x00, 0x00, 0x00, 0x06];

/// Performance Counter Frequency TLV: 1,000,000 ticks per second, matching the
/// `gettimeofday` microsecond clock the blob measures with. `get_tsc_ticks_
/// per_sec` passes 0x0F4240 through `cpy_hton64`.
pub const PERFORMANCE_COUNTER_FREQUENCY: u64 = 1_000_000;

/// The four bytes `get_pause_granule` stores, big-endian 100,000. The unit was
/// not determined from the blob; the constant is reproduced as-is.
pub const PAUSE_GRANULE: [u8; 4] = [0x00, 0x01, 0x86, 0xA0];

/// QoS Characteristics TLV. `get_qos_flags` stores a zero word: this station
/// advertises no qWave capability. Matching it keeps a mapper from following
/// up with QoS diagnostics frames this port does not answer.
pub const QOS_CHARACTERISTICS: [u8; 4] = [0x00; 4];

/// Sees-List Working Set TLV. `get_sees_max` stores big-endian 4.
pub const SEES_LIST_WORKING_SET: u16 = 4;

/// Everything this responder is willing to say about itself.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Device {
    /// MAC address of the bridge the responder is bound to. Also the Host ID.
    pub station: [u8; 6],
    /// IPv4 address of that bridge, or `None` if it has none yet.
    pub ipv4: Option<[u8; 4]>,
    /// Machine Name, already truncated to [`MAX_MACHINE_NAME_CHARS`].
    pub machine_name: String,
    /// Friendly Name, already truncated to [`MAX_FRIENDLY_NAME_CHARS`].
    pub friendly_name: String,
    /// Microseconds since boot, sampled when the reply is built.
    pub uptime_micros: u64,
}

/// Keeps only printable ASCII and truncates to `max_chars`.
///
/// The blob's `util_copy_ascii_to_ucs2` widens each byte as-is, so a control
/// byte or a non-ASCII byte in NVRAM would reach the wire as a lone UTF-16
/// code unit. Names come from local configuration rather than from a frame, so
/// this is hygiene rather than a boundary, but the output stays a bounded,
/// well-formed UCS-2 string either way.
#[must_use]
pub fn sanitise_name(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_graphic() || *character == ' ')
        .take(max_chars)
        .collect()
}

impl Device {
    /// Builds a device description with both names sanitised and bounded.
    #[must_use]
    pub fn new(
        station: [u8; 6],
        ipv4: Option<[u8; 4]>,
        machine_name: &str,
        friendly_name: &str,
        uptime_micros: u64,
    ) -> Self {
        Self {
            station,
            ipv4,
            machine_name: sanitise_name(machine_name, MAX_MACHINE_NAME_CHARS),
            friendly_name: sanitise_name(friendly_name, MAX_FRIENDLY_NAME_CHARS),
            uptime_micros,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_truncated_and_stripped_of_control_bytes() {
        let device = Device::new(
            [0; 6],
            None,
            "GT-AX11000-very-long-name",
            "a\u{7}b\tc\u{fffd}d",
            0,
        );
        assert_eq!(device.machine_name, "GT-AX11000-very");
        assert_eq!(device.machine_name.chars().count(), MAX_MACHINE_NAME_CHARS);
        assert_eq!(device.friendly_name, "abcd");
    }

    #[test]
    fn a_name_of_only_rejected_characters_becomes_empty() {
        assert_eq!(sanitise_name("\u{0}\u{1}\u{2}", 15), "");
    }
}
