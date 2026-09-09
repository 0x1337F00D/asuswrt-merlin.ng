//! Parse an owned copy of the networkmap shared-memory segment.
//!
//! The parser only ever reads inside the asserted field widths
//! (`layout::Fields`), so an unterminated fixed-width string such as the
//! seven-byte `ipMethod` value `OffLine` never runs into the neighbouring
//! entry, unlike the `%s`/`strlcpy` reads of the C reader. The trailer is
//! taken from the segment end and the client count is clamped to
//! `0..=MAX_NR_CLIENT_LIST`.

use crate::layout::{Field, Layout, UnsupportedLayout, MAX_NR_CLIENT_LIST, TAIL_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// The model/segment-size pair is neither the legacy nor the public view.
    UnsupportedLayout(UnsupportedLayout),
    /// The byte copy is shorter than the layout it claims to be.
    Truncated,
}

impl From<UnsupportedLayout> for SnapshotError {
    fn from(error: UnsupportedLayout) -> Self {
        SnapshotError::UnsupportedLayout(error)
    }
}

/// One table row with every string bounded to its field width.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawClient {
    pub ip_addr: [u8; 4],
    pub mac_addr: [u8; 6],
    pub user_define: Vec<u8>,
    pub device_name: Vec<u8>,
    pub vendor_name: Vec<u8>,
    pub apple_model: Vec<u8>,
    pub online: u8,
    pub client_type: u8,
    pub ip_method: Vec<u8>,
    pub op_mode: u8,
    pub device_flag: u8,
    pub wireless: u8,
    pub ssid: Vec<u8>,
    pub txrate: Vec<u8>,
    pub rxrate: Vec<u8>,
    /// Native `int`; the legacy `unsigned int` is reinterpreted like the C
    /// `(int)` cast.
    pub rssi: i32,
    pub conn_time: Vec<u8>,
    /// Public layout only.
    pub ip6_addr: Option<Vec<u8>>,
    pub ip6_prefix: Option<Vec<u8>>,
    pub pap_mac: Option<Vec<u8>>,
    pub is_re: Option<Vec<u8>>,
    pub guest_network: Option<Vec<u8>>,
    pub wireless_auth: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub layout: Layout,
    /// `ip_mac_num` as stored, before clamping.
    pub reported_count: i32,
    pub clients: Vec<RawClient>,
}

/// Bytes of a fixed-width field up to its first NUL, never past `width`.
pub fn c_field(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte == 0) {
        Some(end) => &bytes[..end],
        None => bytes,
    }
}

fn slot(segment: &[u8], field: Field, index: usize) -> &[u8] {
    let start = field.offset + field.width * index;
    &segment[start..start + field.width]
}

fn text(segment: &[u8], field: Field, index: usize) -> Vec<u8> {
    c_field(slot(segment, field, index)).to_vec()
}

fn optional_text(segment: &[u8], field: Option<Field>, index: usize) -> Option<Vec<u8>> {
    field.map(|field| text(segment, field, index))
}

fn byte(segment: &[u8], field: Field, index: usize) -> u8 {
    slot(segment, field, index)[0]
}

fn int(segment: &[u8], field: Field, index: usize) -> i32 {
    let bytes = slot(segment, field, index);
    i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Clamp the stored count like `networkmap_shm_client_count()`.
pub fn clamp_count(reported: i32) -> usize {
    if reported < 0 {
        0
    } else {
        (reported as usize).min(MAX_NR_CLIENT_LIST)
    }
}

/// `ip_mac_num` read from the trailer at the segment end.
pub fn reported_count(segment: &[u8]) -> Option<i32> {
    if segment.len() < TAIL_SIZE {
        return None;
    }
    let tail = &segment[segment.len() - TAIL_SIZE..];
    Some(i32::from_ne_bytes([tail[0], tail[1], tail[2], tail[3]]))
}

impl Snapshot {
    /// Decode `segment` (the complete shared-memory copy) for `product_id`.
    pub fn parse(product_id: &str, segment: &[u8]) -> Result<Snapshot, SnapshotError> {
        let layout = Layout::select(product_id, segment.len())?;
        if segment.len() != layout.size() {
            return Err(SnapshotError::Truncated);
        }
        let fields = layout.fields();
        let reported = reported_count(segment).ok_or(SnapshotError::Truncated)?;
        let count = clamp_count(reported);
        let mut clients = Vec::with_capacity(count);
        for index in 0..count {
            let ip_slot = slot(segment, fields.ip_addr, index);
            let mac_slot = slot(segment, fields.mac_addr, index);
            clients.push(RawClient {
                ip_addr: [ip_slot[0], ip_slot[1], ip_slot[2], ip_slot[3]],
                mac_addr: [
                    mac_slot[0],
                    mac_slot[1],
                    mac_slot[2],
                    mac_slot[3],
                    mac_slot[4],
                    mac_slot[5],
                ],
                user_define: text(segment, fields.user_define, index),
                device_name: text(segment, fields.device_name, index),
                vendor_name: text(segment, fields.vendor_name, index),
                apple_model: text(segment, fields.apple_model, index),
                online: byte(segment, fields.online, index),
                client_type: byte(segment, fields.client_type, index),
                ip_method: text(segment, fields.ip_method, index),
                op_mode: byte(segment, fields.op_mode, index),
                device_flag: byte(segment, fields.device_flag, index),
                wireless: byte(segment, fields.wireless, index),
                ssid: text(segment, fields.ssid, index),
                txrate: text(segment, fields.txrate, index),
                rxrate: text(segment, fields.rxrate, index),
                rssi: int(segment, fields.rssi, index),
                conn_time: text(segment, fields.conn_time, index),
                ip6_addr: optional_text(segment, fields.ip6_addr, index),
                ip6_prefix: optional_text(segment, fields.ip6_prefix, index),
                pap_mac: optional_text(segment, fields.pap_mac, index),
                is_re: optional_text(segment, fields.is_re, index),
                guest_network: optional_text(segment, fields.guest_network, index),
                wireless_auth: optional_text(segment, fields.wireless_auth, index),
            });
        }
        Ok(Snapshot {
            layout,
            reported_count: reported,
            clients,
        })
    }
}

/// Synthetic segment builder shared by the unit tests, the fuzz runner and the
/// golden fixtures. It writes through the same field table the parser reads.
pub mod builder {
    use super::*;

    #[derive(Clone, Debug)]
    pub struct SegmentBuilder {
        layout: Layout,
        bytes: Vec<u8>,
    }

    impl SegmentBuilder {
        pub fn new(layout: Layout) -> Self {
            Self {
                layout,
                bytes: vec![0; layout.size()],
            }
        }

        pub fn layout(&self) -> Layout {
            self.layout
        }

        fn write(&mut self, field: Field, index: usize, value: &[u8]) -> &mut Self {
            let start = field.offset + field.width * index;
            let length = value.len().min(field.width);
            self.bytes[start..start + field.width].fill(0);
            self.bytes[start..start + length].copy_from_slice(&value[..length]);
            self
        }

        fn write_optional(
            &mut self,
            field: Option<Field>,
            index: usize,
            value: &[u8],
        ) -> &mut Self {
            if let Some(field) = field {
                self.write(field, index, value);
            }
            self
        }

        pub fn ip(&mut self, index: usize, ip: [u8; 4]) -> &mut Self {
            self.write(self.layout.fields().ip_addr, index, &ip)
        }

        pub fn mac(&mut self, index: usize, mac: [u8; 6]) -> &mut Self {
            self.write(self.layout.fields().mac_addr, index, &mac)
        }

        pub fn user_define(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write(self.layout.fields().user_define, index, value)
        }

        pub fn device_name(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write(self.layout.fields().device_name, index, value)
        }

        pub fn vendor_name(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write(self.layout.fields().vendor_name, index, value)
        }

        pub fn apple_model(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write(self.layout.fields().apple_model, index, value)
        }

        pub fn online(&mut self, index: usize, value: u8) -> &mut Self {
            self.write(self.layout.fields().online, index, &[value])
        }

        pub fn client_type(&mut self, index: usize, value: u8) -> &mut Self {
            self.write(self.layout.fields().client_type, index, &[value])
        }

        pub fn ip_method(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write(self.layout.fields().ip_method, index, value)
        }

        pub fn op_mode(&mut self, index: usize, value: u8) -> &mut Self {
            self.write(self.layout.fields().op_mode, index, &[value])
        }

        pub fn device_flag(&mut self, index: usize, value: u8) -> &mut Self {
            self.write(self.layout.fields().device_flag, index, &[value])
        }

        pub fn wireless(&mut self, index: usize, value: u8) -> &mut Self {
            self.write(self.layout.fields().wireless, index, &[value])
        }

        pub fn ssid(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write(self.layout.fields().ssid, index, value)
        }

        pub fn txrate(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write(self.layout.fields().txrate, index, value)
        }

        pub fn rxrate(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write(self.layout.fields().rxrate, index, value)
        }

        pub fn rssi(&mut self, index: usize, value: i32) -> &mut Self {
            self.write(self.layout.fields().rssi, index, &value.to_ne_bytes())
        }

        pub fn conn_time(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write(self.layout.fields().conn_time, index, value)
        }

        pub fn ip6_addr(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write_optional(self.layout.fields().ip6_addr, index, value)
        }

        pub fn ip6_prefix(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write_optional(self.layout.fields().ip6_prefix, index, value)
        }

        pub fn pap_mac(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write_optional(self.layout.fields().pap_mac, index, value)
        }

        pub fn is_re(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write_optional(self.layout.fields().is_re, index, value)
        }

        pub fn guest_network(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write_optional(self.layout.fields().guest_network, index, value)
        }

        pub fn wireless_auth(&mut self, index: usize, value: &[u8]) -> &mut Self {
            self.write_optional(self.layout.fields().wireless_auth, index, value)
        }

        /// Store `ip_mac_num` in the trailer at the segment end.
        pub fn count(&mut self, value: i32) -> &mut Self {
            let start = self.bytes.len() - TAIL_SIZE;
            self.bytes[start..start + 4].copy_from_slice(&value.to_ne_bytes());
            self
        }

        pub fn build(&self) -> Vec<u8> {
            self.bytes.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::builder::SegmentBuilder;
    use super::*;
    use crate::layout::{LEGACY_TABLE_SIZE, PUBLIC_TABLE_SIZE};

    #[test]
    fn c_field_stops_at_nul_and_never_past_width() {
        assert_eq!(c_field(b"OffLine"), b"OffLine");
        assert_eq!(c_field(b"ab\0cd"), b"ab");
        assert_eq!(c_field(b""), b"");
    }

    #[test]
    fn unterminated_fields_are_bounded() {
        let mut builder = SegmentBuilder::new(Layout::Legacy);
        builder
            .count(2)
            .ip_method(0, b"OffLine")
            .ip_method(1, b"DHCP")
            .vendor_name(0, &[b'V'; 200])
            .vendor_name(1, b"Next")
            .user_define(0, &[b'U'; 16]);
        let snapshot = Snapshot::parse("GT-AX11000", &builder.build()).unwrap();
        assert_eq!(snapshot.layout, Layout::Legacy);
        assert_eq!(snapshot.clients[0].ip_method, b"OffLine");
        assert_eq!(snapshot.clients[1].ip_method, b"DHCP");
        assert_eq!(snapshot.clients[0].vendor_name.len(), 128);
        assert_eq!(snapshot.clients[1].vendor_name, b"Next");
        assert_eq!(snapshot.clients[0].user_define.len(), 16);
        assert!(snapshot.clients[0].ip6_addr.is_none());
    }

    #[test]
    fn count_is_clamped_and_read_from_the_segment_end() {
        for (reported, expected) in [
            (0, 0),
            (1, 1),
            (255, 255),
            (256, 255),
            (1_000, 255),
            (-1, 0),
            (i32::MIN, 0),
        ] {
            let bytes = SegmentBuilder::new(Layout::Legacy).count(reported).build();
            let snapshot = Snapshot::parse("GT-AX11000", &bytes).unwrap();
            assert_eq!(snapshot.reported_count, reported);
            assert_eq!(snapshot.clients.len(), expected);
        }
        let bytes = SegmentBuilder::new(Layout::Public).count(3).build();
        let snapshot = Snapshot::parse("GT-AX11000", &bytes).unwrap();
        assert_eq!(snapshot.layout, Layout::Public);
        assert_eq!(snapshot.clients.len(), 3);
        assert_eq!(snapshot.clients[0].ip6_addr, Some(Vec::new()));
    }

    #[test]
    fn wrong_segment_sizes_fail_closed() {
        assert!(matches!(
            Snapshot::parse("GT-AX11000", &vec![0; LEGACY_TABLE_SIZE - 1]),
            Err(SnapshotError::UnsupportedLayout(_))
        ));
        assert!(matches!(
            Snapshot::parse("RT-AX88U", &vec![0; LEGACY_TABLE_SIZE]),
            Err(SnapshotError::UnsupportedLayout(_))
        ));
        assert!(matches!(
            Snapshot::parse("GT-AX11000", &[]),
            Err(SnapshotError::UnsupportedLayout(_))
        ));
        assert!(Snapshot::parse("RT-AX88U", &vec![0; PUBLIC_TABLE_SIZE]).is_ok());
    }

    #[test]
    fn legacy_rssi_is_reinterpreted_like_the_c_cast() {
        let bytes = SegmentBuilder::new(Layout::Legacy)
            .count(1)
            .rssi(0, -47)
            .build();
        let snapshot = Snapshot::parse("GT-AX11000", &bytes).unwrap();
        assert_eq!(snapshot.clients[0].rssi, -47);
    }
}
