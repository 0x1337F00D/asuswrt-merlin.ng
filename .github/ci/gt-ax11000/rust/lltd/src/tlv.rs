//! Bounded TLV encoding for the Hello property block.
//!
//! An LLTD TLV is `type(1) | length(1) | value(length)`, which the blob's
//! `write_uint32_t`, `write_uint16_t`, `write_etheraddr_t` and
//! `write_ucs2char_t` all produce, and the block is terminated by a single
//! zero byte (the End of Property TLV). `packetio_tx_hello` writes that
//! terminator itself after `tlv_write_info` returns.
//!
//! Every writer in the blob refuses to write when the remaining space is too
//! small and returns zero, and `tlv_write_info` then simply moves on to the
//! next entry. [`TlvWriter`] behaves the same way: a TLV that does not fit the
//! budget is skipped, the ones that follow are still attempted, and the caller
//! is never handed a truncated value.

use crate::device::{
    CHARACTERISTICS, PAUSE_GRANULE, PERFORMANCE_COUNTER_FREQUENCY, PHYSICAL_MEDIUM,
    QOS_CHARACTERISTICS, SEES_LIST_WORKING_SET,
};

/// Host ID. `Tlvs[0]`, written by `write_etheraddr_t`.
pub const TYPE_HOST_ID: u8 = 0x01;
/// Characteristics. `Tlvs[1]`, `write_uint32_t`.
pub const TYPE_CHARACTERISTICS: u8 = 0x02;
/// Physical Medium. `Tlvs[2]`, `write_uint32_t`.
pub const TYPE_PHYSICAL_MEDIUM: u8 = 0x03;
/// IPv4 Address. `Tlvs[6]`, `write_ipv4addr_t`.
pub const TYPE_IPV4_ADDRESS: u8 = 0x07;
/// Performance Counter Frequency. `Tlvs[10]`, `write_uint64_t`.
pub const TYPE_PERFORMANCE_COUNTER_FREQUENCY: u8 = 0x0A;
/// The `get_pause_granule` property. `Tlvs[11]`, `write_uint32_t`.
pub const TYPE_PAUSE_GRANULE: u8 = 0x0B;
/// Machine Name. `Tlvs[13]`, `write_ucs2char_t`.
pub const TYPE_MACHINE_NAME: u8 = 0x0F;
/// Friendly Name. `Tlvs[15]`, `write_ucs2char_t`.
pub const TYPE_FRIENDLY_NAME: u8 = 0x11;
/// QoS Characteristics. `Tlvs[17]`, `write_uint32_t`.
pub const TYPE_QOS_CHARACTERISTICS: u8 = 0x14;
/// The `get_uptime` property. `Tlvs[20]`, `write_uint64_t`.
pub const TYPE_UPTIME: u8 = 0x17;
/// Sees-List Working Set. `Tlvs[22]`, `write_uint16_t`.
pub const TYPE_SEES_LIST_WORKING_SET: u8 = 0x19;

/// End of Property, the single terminating byte.
pub const TYPE_END_OF_PROPERTY: u8 = 0x00;

/// Largest value a single TLV may carry. The length field is one byte, so the
/// protocol maximum is 255; nothing this port emits comes close.
pub const MAX_TLV_VALUE_LEN: usize = u8::MAX as usize;

/// Largest number of TLVs a block may hold. The full property list is 12
/// entries; the cap exists so the loop is bounded independently of the budget.
pub const MAX_TLV_COUNT: usize = 16;

/// Appends TLVs to a byte buffer without ever exceeding a fixed budget.
#[derive(Debug)]
pub struct TlvWriter {
    bytes: Vec<u8>,
    budget: usize,
    written: usize,
    skipped: usize,
}

impl TlvWriter {
    /// Creates a writer that will never let `bytes` grow past `budget`.
    ///
    /// One byte of the budget is reserved for the End of Property terminator,
    /// so a writer created with a budget smaller than the current length plus
    /// one accepts nothing at all.
    #[must_use]
    pub fn new(bytes: Vec<u8>, budget: usize) -> Self {
        Self {
            bytes,
            budget,
            written: 0,
            skipped: 0,
        }
    }

    /// Bytes still available for TLVs, with the terminator already reserved.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.budget
            .saturating_sub(self.bytes.len())
            .saturating_sub(1)
    }

    /// How many TLVs were appended.
    #[must_use]
    pub fn written(&self) -> usize {
        self.written
    }

    /// How many TLVs were skipped because they did not fit or the count cap
    /// was reached.
    #[must_use]
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// Appends one TLV, or skips it if it does not fit.
    ///
    /// Returns true when the TLV was written. A value longer than
    /// [`MAX_TLV_VALUE_LEN`] is always skipped: the length field could not
    /// describe it, and truncating it would put a value on the wire that does
    /// not match its own length.
    pub fn push(&mut self, tlv_type: u8, value: &[u8]) -> bool {
        if value.len() > MAX_TLV_VALUE_LEN || self.written >= MAX_TLV_COUNT {
            self.skipped = self.skipped.saturating_add(1);
            return false;
        }
        let Some(needed) = value.len().checked_add(2) else {
            self.skipped = self.skipped.saturating_add(1);
            return false;
        };
        if needed > self.remaining() {
            self.skipped = self.skipped.saturating_add(1);
            return false;
        }
        self.bytes.push(tlv_type);
        // Checked against MAX_TLV_VALUE_LEN above, so this cast cannot wrap.
        self.bytes.push(value.len() as u8);
        self.bytes.extend_from_slice(value);
        self.written = self.written.saturating_add(1);
        true
    }

    /// Writes the End of Property terminator and returns the finished buffer.
    ///
    /// The terminator was reserved by [`Self::remaining`] on every push, so
    /// this never exceeds the budget.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        self.bytes.push(TYPE_END_OF_PROPERTY);
        self.bytes
    }
}

/// Encodes an ASCII string as the NUL-terminated little-endian UCS-2 the blob
/// produces.
///
/// `util_copy_ascii_to_ucs2` stores each byte followed by a zero byte, so the
/// encoding is UTF-16LE, and `write_ucs2char_t` includes the two-byte
/// terminator in the TLV length.
#[must_use]
pub fn ucs2(value: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(value.len().saturating_mul(2).saturating_add(2));
    for character in value.chars() {
        // Only ASCII survives `device::sanitise_name`, so one code unit each.
        let code = u32::from(character);
        if code > u32::from(u16::MAX) {
            continue;
        }
        let unit = code as u16;
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    encoded.extend_from_slice(&[0, 0]);
    encoded
}

/// Appends the property block this station advertises, in ascending type
/// order, skipping anything the budget cannot hold.
///
/// The order and the constants come from the blob's `Tlvs` table; the omitted
/// entries are listed in `crate::responder`.
pub fn write_properties(writer: &mut TlvWriter, device: &crate::device::Device) {
    writer.push(TYPE_HOST_ID, &device.station);
    writer.push(TYPE_CHARACTERISTICS, &CHARACTERISTICS);
    writer.push(TYPE_PHYSICAL_MEDIUM, &PHYSICAL_MEDIUM);
    if let Some(address) = device.ipv4 {
        writer.push(TYPE_IPV4_ADDRESS, &address);
    }
    writer.push(
        TYPE_PERFORMANCE_COUNTER_FREQUENCY,
        &PERFORMANCE_COUNTER_FREQUENCY.to_be_bytes(),
    );
    writer.push(TYPE_PAUSE_GRANULE, &PAUSE_GRANULE);
    writer.push(TYPE_MACHINE_NAME, &ucs2(&device.machine_name));
    writer.push(TYPE_FRIENDLY_NAME, &ucs2(&device.friendly_name));
    writer.push(TYPE_QOS_CHARACTERISTICS, &QOS_CHARACTERISTICS);
    writer.push(TYPE_UPTIME, &device.uptime_micros.to_be_bytes());
    writer.push(
        TYPE_SEES_LIST_WORKING_SET,
        &SEES_LIST_WORKING_SET.to_be_bytes(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Device;

    #[test]
    fn a_tlv_is_type_length_value_and_the_block_is_nul_terminated() {
        let mut writer = TlvWriter::new(Vec::new(), 64);
        assert!(writer.push(TYPE_HOST_ID, &[1, 2, 3, 4, 5, 6]));
        let bytes = writer.finish();
        assert_eq!(bytes, vec![0x01, 0x06, 1, 2, 3, 4, 5, 6, 0x00]);
    }

    #[test]
    fn ucs2_is_little_endian_and_nul_terminated() {
        // "AB" -> 41 00 42 00 00 00, matching util_copy_ascii_to_ucs2, which
        // stores the byte first and the zero high byte second.
        assert_eq!(ucs2("AB"), vec![0x41, 0x00, 0x42, 0x00, 0x00, 0x00]);
        assert_eq!(ucs2(""), vec![0x00, 0x00]);
    }

    #[test]
    fn a_tlv_that_does_not_fit_is_skipped_and_the_next_one_is_still_tried() {
        // Budget 13: the terminator reserves one, leaving 12. An 8-byte value
        // needs 10 and fits, which leaves 2; a second 8-byte value needs 10
        // and a 1-byte value needs 3, so both are skipped, but a zero-length
        // value needs exactly 2 and is still written after them.
        let mut writer = TlvWriter::new(Vec::new(), 13);
        assert!(writer.push(0x0A, &[0; 8]));
        assert!(!writer.push(0x17, &[0; 8]));
        assert!(!writer.push(0x04, &[0; 1]));
        assert!(writer.push(0x14, &[]));
        assert_eq!(writer.written(), 2);
        assert_eq!(writer.skipped(), 2);
        let bytes = writer.finish();
        assert_eq!(bytes.len(), 13);
    }

    #[test]
    fn the_terminator_always_fits_however_tight_the_budget() {
        for budget in 0..40 {
            let mut writer = TlvWriter::new(Vec::new(), budget);
            let device = Device::new([9; 6], Some([10, 0, 0, 1]), "name", "friendly", 5);
            write_properties(&mut writer, &device);
            let bytes = writer.finish();
            assert!(
                bytes.len() <= budget.max(1),
                "budget {budget} produced {} bytes",
                bytes.len()
            );
            assert_eq!(bytes.last(), Some(&TYPE_END_OF_PROPERTY));
        }
    }

    #[test]
    fn no_more_than_the_tlv_count_cap_is_ever_written() {
        let mut writer = TlvWriter::new(Vec::new(), 4096);
        for _ in 0..(MAX_TLV_COUNT * 4) {
            writer.push(TYPE_QOS_CHARACTERISTICS, &[0; 4]);
        }
        assert_eq!(writer.written(), MAX_TLV_COUNT);
    }

    #[test]
    fn an_over_long_value_is_refused_rather_than_truncated() {
        let mut writer = TlvWriter::new(Vec::new(), 4096);
        assert!(!writer.push(TYPE_MACHINE_NAME, &[0; MAX_TLV_VALUE_LEN + 1]));
        assert!(writer.push(TYPE_MACHINE_NAME, &[0; MAX_TLV_VALUE_LEN]));
        assert_eq!(writer.written(), 1);
    }
}
