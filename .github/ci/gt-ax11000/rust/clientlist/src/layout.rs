//! Shared-memory layouts of the networkmap client table.
//!
//! Two layouts exist for `CLIENT_DETAIL_INFO_TABLE` (`networkmap.h:250-334`
//! at `6be5bc84b50`, `MAX_NR_CLIENT_LIST == 255`):
//!
//! * the legacy layout written by the closed prebuilt GT-AX11000 daemon
//!   (`release/src/router/networkmap/prebuild/GT-AX11000/networkmap`), 174,964
//!   bytes, decoded by `networkmap-shm-abi.patch` as
//!   `GT_AX11000_NETWORKMAP_TABLE`;
//! * the public header layout the overlay httpd compiles against
//!   (`RTCONFIG_IPV6=y`, no `RTCONFIG_MULTILAN_CFG`, `RTCONFIG_MLO`,
//!   `RTCONFIG_LANTIQ`, `RTCONFIG_FBWIFI`/`CAPTIVE_PORTAL` subunit or BWDPI
//!   arrays), 173,436 bytes.
//!
//! Both share the first nine arrays; every later offset differs. The structs
//! below are `#[repr(C)]` descriptions whose sizes and offsets are asserted at
//! compile time; parsing never dereferences them, it slices a byte copy of the
//! segment with the asserted offsets. The trailer is read from the segment end
//! in either layout.

use core::mem::{offset_of, size_of};

pub const MAX_NR_CLIENT_LIST: usize = 255;
pub const LEGACY_TABLE_SIZE: usize = 174_964;
pub const PUBLIC_TABLE_SIZE: usize = 173_436;
/// Model whose shipped daemon writes the legacy layout.
pub const LEGACY_PRODUCT_ID: &str = "GT-AX11000";

/// `FLAG_*` bits of `device_flag` (`networkmap.h:193-202`).
pub const FLAG_HTTP: u8 = 0;
pub const FLAG_PRINTER: u8 = 1;
pub const FLAG_ITUNE: u8 = 2;
pub const FLAG_EXIST: u8 = 3;
pub const FLAG_VENDOR: u8 = 4;
pub const FLAG_ASUS: u8 = 5;
pub const FLAG_AIBOARD: u8 = 6;

/// Fixed trailer shared by both layouts (`NETWORKMAP_SHM_TAIL`): four ints and
/// `delete_mac[13]`, padded to 32 bytes and always at the end of the segment.
#[repr(C)]
pub struct Tail {
    pub ip_mac_num: i32,
    pub detail_info_num: i32,
    pub asus_device_num: i32,
    pub commit_no: i32,
    pub delete_mac: [u8; 13],
}

pub const TAIL_SIZE: usize = size_of::<Tail>();
const _: () = assert!(TAIL_SIZE == 32);
const _: () = assert!(offset_of!(Tail, delete_mac) == 16);

/// `GT_AX11000_NETWORKMAP_TABLE` from `networkmap-shm-abi.patch`.
#[repr(C)]
pub struct LegacyTable {
    pub ip_addr: [[u8; 4]; MAX_NR_CLIENT_LIST],
    pub mac_addr: [[u8; 6]; MAX_NR_CLIENT_LIST],
    pub user_define: [[u8; 16]; MAX_NR_CLIENT_LIST],
    pub vendor_name: [[u8; 128]; MAX_NR_CLIENT_LIST],
    pub device_name: [[u8; 32]; MAX_NR_CLIENT_LIST],
    pub apple_model: [[u8; 16]; MAX_NR_CLIENT_LIST],
    pub device_type: [[u8; 32]; MAX_NR_CLIENT_LIST],
    pub vendor_class: [[u8; 32]; MAX_NR_CLIENT_LIST],
    pub os_type: [u8; MAX_NR_CLIENT_LIST],
    pub sdn_idx: [u8; MAX_NR_CLIENT_LIST],
    pub online: [u8; MAX_NR_CLIENT_LIST],
    pub client_type: [u8; MAX_NR_CLIENT_LIST],
    pub ip_method: [[u8; 7]; MAX_NR_CLIENT_LIST],
    pub op_mode: [u8; MAX_NR_CLIENT_LIST],
    pub device_flag: [u8; MAX_NR_CLIENT_LIST],
    pub wireless: [u8; MAX_NR_CLIENT_LIST],
    pub is_wireless: [u8; MAX_NR_CLIENT_LIST],
    pub conn_ts: [i32; MAX_NR_CLIENT_LIST],
    pub offline_time: [i32; MAX_NR_CLIENT_LIST],
    pub ssid: [[u8; 32]; MAX_NR_CLIENT_LIST],
    pub txrate: [[u8; 7]; MAX_NR_CLIENT_LIST],
    pub rxrate: [[u8; 10]; MAX_NR_CLIENT_LIST],
    /// `unsigned int` in the daemon; formatted through `(int)` in C.
    pub rssi: [u32; MAX_NR_CLIENT_LIST],
    pub conn_time: [[u8; 12]; MAX_NR_CLIENT_LIST],
    pub bwdpi_host: [[u8; 32]; MAX_NR_CLIENT_LIST],
    pub bwdpi_vendor: [[u8; 100]; MAX_NR_CLIENT_LIST],
    pub bwdpi_type: [[u8; 100]; MAX_NR_CLIENT_LIST],
    pub bwdpi_device: [[u8; 100]; MAX_NR_CLIENT_LIST],
    pub tail: Tail,
}

const _: () = assert!(size_of::<LegacyTable>() == LEGACY_TABLE_SIZE);
const _: () = assert!(offset_of!(LegacyTable, ip_addr) == 0);
const _: () = assert!(offset_of!(LegacyTable, mac_addr) == 1_020);
const _: () = assert!(offset_of!(LegacyTable, user_define) == 2_550);
const _: () = assert!(offset_of!(LegacyTable, vendor_name) == 6_630);
const _: () = assert!(offset_of!(LegacyTable, device_name) == 39_270);
const _: () = assert!(offset_of!(LegacyTable, apple_model) == 47_430);
const _: () = assert!(offset_of!(LegacyTable, device_type) == 51_510);
const _: () = assert!(offset_of!(LegacyTable, vendor_class) == 59_670);
const _: () = assert!(offset_of!(LegacyTable, os_type) == 67_830);
const _: () = assert!(offset_of!(LegacyTable, sdn_idx) == 68_085);
const _: () = assert!(offset_of!(LegacyTable, online) == 68_340);
const _: () = assert!(offset_of!(LegacyTable, client_type) == 68_595);
const _: () = assert!(offset_of!(LegacyTable, ip_method) == 68_850);
const _: () = assert!(offset_of!(LegacyTable, op_mode) == 70_635);
const _: () = assert!(offset_of!(LegacyTable, device_flag) == 70_890);
const _: () = assert!(offset_of!(LegacyTable, wireless) == 71_145);
const _: () = assert!(offset_of!(LegacyTable, is_wireless) == 71_400);
const _: () = assert!(offset_of!(LegacyTable, conn_ts) == 71_656);
const _: () = assert!(offset_of!(LegacyTable, offline_time) == 72_676);
const _: () = assert!(offset_of!(LegacyTable, ssid) == 73_696);
const _: () = assert!(offset_of!(LegacyTable, txrate) == 81_856);
const _: () = assert!(offset_of!(LegacyTable, rxrate) == 83_641);
const _: () = assert!(offset_of!(LegacyTable, rssi) == 86_192);
const _: () = assert!(offset_of!(LegacyTable, conn_time) == 87_212);
const _: () = assert!(offset_of!(LegacyTable, bwdpi_host) == 90_272);
const _: () = assert!(offset_of!(LegacyTable, bwdpi_vendor) == 98_432);
const _: () = assert!(offset_of!(LegacyTable, bwdpi_type) == 123_932);
const _: () = assert!(offset_of!(LegacyTable, bwdpi_device) == 149_432);
const _: () = assert!(offset_of!(LegacyTable, tail) == 174_932);
const _: () = assert!(offset_of!(LegacyTable, tail) == LEGACY_TABLE_SIZE - TAIL_SIZE);

/// `CLIENT_DETAIL_INFO_TABLE` as compiled by the overlay httpd.
#[repr(C)]
pub struct PublicTable {
    pub ip_addr: [[u8; 4]; MAX_NR_CLIENT_LIST],
    pub mac_addr: [[u8; 6]; MAX_NR_CLIENT_LIST],
    pub user_define: [[u8; 16]; MAX_NR_CLIENT_LIST],
    pub vendor_name: [[u8; 128]; MAX_NR_CLIENT_LIST],
    pub device_name: [[u8; 32]; MAX_NR_CLIENT_LIST],
    pub apple_model: [[u8; 16]; MAX_NR_CLIENT_LIST],
    pub device_type: [[u8; 32]; MAX_NR_CLIENT_LIST],
    pub vendor_class: [[u8; 32]; MAX_NR_CLIENT_LIST],
    pub os_type: [u8; MAX_NR_CLIENT_LIST],
    pub ip6_addr: [[u8; 40]; MAX_NR_CLIENT_LIST],
    pub ip6_prefix: [[u8; 50]; MAX_NR_CLIENT_LIST],
    pub online: [u8; MAX_NR_CLIENT_LIST],
    pub client_type: [u8; MAX_NR_CLIENT_LIST],
    pub ip_method: [[u8; 7]; MAX_NR_CLIENT_LIST],
    pub op_mode: [u8; MAX_NR_CLIENT_LIST],
    pub dhcp_flag: [u8; MAX_NR_CLIENT_LIST],
    pub device_flag: [u8; MAX_NR_CLIENT_LIST],
    pub wireless: [u8; MAX_NR_CLIENT_LIST],
    pub is_wireless: [u8; MAX_NR_CLIENT_LIST],
    pub conn_ts: [i32; MAX_NR_CLIENT_LIST],
    pub offline_time: [i32; MAX_NR_CLIENT_LIST],
    pub pap_mac: [[u8; 18]; MAX_NR_CLIENT_LIST],
    pub is_re: [[u8; 2]; MAX_NR_CLIENT_LIST],
    pub guest_network: [[u8; 4]; MAX_NR_CLIENT_LIST],
    pub ssid: [[u8; 32]; MAX_NR_CLIENT_LIST],
    pub txrate: [[u8; 7]; MAX_NR_CLIENT_LIST],
    pub rxrate: [[u8; 10]; MAX_NR_CLIENT_LIST],
    pub mac_src: [[u8; 30]; MAX_NR_CLIENT_LIST],
    pub name_src: [[u8; 30]; MAX_NR_CLIENT_LIST],
    pub vendor_src: [[u8; 30]; MAX_NR_CLIENT_LIST],
    pub type_src: [[u8; 30]; MAX_NR_CLIENT_LIST],
    pub online_src: [[u8; 30]; MAX_NR_CLIENT_LIST],
    pub wireless_src: [[u8; 30]; MAX_NR_CLIENT_LIST],
    pub rssi: [i32; MAX_NR_CLIENT_LIST],
    pub conn_time: [[u8; 12]; MAX_NR_CLIENT_LIST],
    pub wireless_auth: [[u8; 32]; MAX_NR_CLIENT_LIST],
    pub tail: Tail,
}

const _: () = assert!(size_of::<PublicTable>() == PUBLIC_TABLE_SIZE);
const _: () = assert!(offset_of!(PublicTable, os_type) == 67_830);
const _: () = assert!(offset_of!(PublicTable, ip6_addr) == 68_085);
const _: () = assert!(offset_of!(PublicTable, ip6_prefix) == 78_285);
const _: () = assert!(offset_of!(PublicTable, online) == 91_035);
const _: () = assert!(offset_of!(PublicTable, conn_ts) == 94_608);
const _: () = assert!(offset_of!(PublicTable, pap_mac) == 96_648);
const _: () = assert!(offset_of!(PublicTable, ssid) == 102_768);
const _: () = assert!(offset_of!(PublicTable, rssi) == 161_164);
const _: () = assert!(offset_of!(PublicTable, wireless_auth) == 165_244);
const _: () = assert!(offset_of!(PublicTable, tail) == 173_404);
const _: () = assert!(offset_of!(PublicTable, tail) == PUBLIC_TABLE_SIZE - TAIL_SIZE);

// The first nine arrays are at identical offsets in both layouts.
const _: () = assert!(offset_of!(PublicTable, vendor_name) == offset_of!(LegacyTable, vendor_name));
const _: () = assert!(offset_of!(PublicTable, apple_model) == offset_of!(LegacyTable, apple_model));
const _: () = assert!(offset_of!(PublicTable, device_name) == offset_of!(LegacyTable, device_name));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Legacy,
    Public,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedLayout {
    pub segment_size: usize,
}

impl Layout {
    /// Select the layout from the model and the kernel-reported segment size,
    /// or fail closed. `productid == "GT-AX11000"` with exactly 174,964 bytes
    /// is the legacy view; exactly 173,436 bytes is the public view; any other
    /// combination is not decoded.
    pub fn select(product_id: &str, segment_size: usize) -> Result<Layout, UnsupportedLayout> {
        if product_id == LEGACY_PRODUCT_ID && segment_size == LEGACY_TABLE_SIZE {
            Ok(Layout::Legacy)
        } else if segment_size == PUBLIC_TABLE_SIZE {
            Ok(Layout::Public)
        } else {
            Err(UnsupportedLayout { segment_size })
        }
    }

    pub const fn size(self) -> usize {
        match self {
            Layout::Legacy => LEGACY_TABLE_SIZE,
            Layout::Public => PUBLIC_TABLE_SIZE,
        }
    }
}

/// Byte offset and width of one array field for a layout; `None` when the
/// layout has no such field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    pub offset: usize,
    pub width: usize,
}

macro_rules! field {
    ($table:ty, $name:ident, $width:expr) => {
        Field {
            offset: offset_of!($table, $name),
            width: $width,
        }
    };
}

/// Per-layout field table used by the snapshot parser.
#[derive(Clone, Copy, Debug)]
pub struct Fields {
    pub ip_addr: Field,
    pub mac_addr: Field,
    pub user_define: Field,
    pub vendor_name: Field,
    pub device_name: Field,
    pub apple_model: Field,
    pub online: Field,
    pub client_type: Field,
    pub ip_method: Field,
    pub op_mode: Field,
    pub device_flag: Field,
    pub wireless: Field,
    pub ssid: Field,
    pub txrate: Field,
    pub rxrate: Field,
    pub rssi: Field,
    pub conn_time: Field,
    pub ip6_addr: Option<Field>,
    pub ip6_prefix: Option<Field>,
    pub pap_mac: Option<Field>,
    pub is_re: Option<Field>,
    pub guest_network: Option<Field>,
    pub wireless_auth: Option<Field>,
}

pub const LEGACY_FIELDS: Fields = Fields {
    ip_addr: field!(LegacyTable, ip_addr, 4),
    mac_addr: field!(LegacyTable, mac_addr, 6),
    user_define: field!(LegacyTable, user_define, 16),
    vendor_name: field!(LegacyTable, vendor_name, 128),
    device_name: field!(LegacyTable, device_name, 32),
    apple_model: field!(LegacyTable, apple_model, 16),
    online: field!(LegacyTable, online, 1),
    client_type: field!(LegacyTable, client_type, 1),
    ip_method: field!(LegacyTable, ip_method, 7),
    op_mode: field!(LegacyTable, op_mode, 1),
    device_flag: field!(LegacyTable, device_flag, 1),
    wireless: field!(LegacyTable, wireless, 1),
    ssid: field!(LegacyTable, ssid, 32),
    txrate: field!(LegacyTable, txrate, 7),
    rxrate: field!(LegacyTable, rxrate, 10),
    rssi: field!(LegacyTable, rssi, 4),
    conn_time: field!(LegacyTable, conn_time, 12),
    ip6_addr: None,
    ip6_prefix: None,
    pap_mac: None,
    is_re: None,
    guest_network: None,
    wireless_auth: None,
};

pub const PUBLIC_FIELDS: Fields = Fields {
    ip_addr: field!(PublicTable, ip_addr, 4),
    mac_addr: field!(PublicTable, mac_addr, 6),
    user_define: field!(PublicTable, user_define, 16),
    vendor_name: field!(PublicTable, vendor_name, 128),
    device_name: field!(PublicTable, device_name, 32),
    apple_model: field!(PublicTable, apple_model, 16),
    online: field!(PublicTable, online, 1),
    client_type: field!(PublicTable, client_type, 1),
    ip_method: field!(PublicTable, ip_method, 7),
    op_mode: field!(PublicTable, op_mode, 1),
    device_flag: field!(PublicTable, device_flag, 1),
    wireless: field!(PublicTable, wireless, 1),
    ssid: field!(PublicTable, ssid, 32),
    txrate: field!(PublicTable, txrate, 7),
    rxrate: field!(PublicTable, rxrate, 10),
    rssi: field!(PublicTable, rssi, 4),
    conn_time: field!(PublicTable, conn_time, 12),
    ip6_addr: Some(field!(PublicTable, ip6_addr, 40)),
    ip6_prefix: Some(field!(PublicTable, ip6_prefix, 50)),
    pap_mac: Some(field!(PublicTable, pap_mac, 18)),
    is_re: Some(field!(PublicTable, is_re, 2)),
    guest_network: Some(field!(PublicTable, guest_network, 4)),
    wireless_auth: Some(field!(PublicTable, wireless_auth, 32)),
};

impl Layout {
    pub const fn fields(self) -> &'static Fields {
        match self {
            Layout::Legacy => &LEGACY_FIELDS,
            Layout::Public => &PUBLIC_FIELDS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_is_exact_and_fails_closed() {
        assert_eq!(Layout::select("GT-AX11000", 174_964), Ok(Layout::Legacy));
        assert_eq!(Layout::select("GT-AX11000", 173_436), Ok(Layout::Public));
        assert_eq!(Layout::select("RT-AX88U", 173_436), Ok(Layout::Public));
        assert_eq!(
            Layout::select("RT-AX88U", 174_964),
            Err(UnsupportedLayout {
                segment_size: 174_964
            })
        );
        assert_eq!(
            Layout::select("GT-AX11000", 174_960),
            Err(UnsupportedLayout {
                segment_size: 174_960
            })
        );
        assert!(Layout::select("GT-AX11000", 0).is_err());
        assert!(Layout::select("", 108_656).is_err());
    }

    #[test]
    fn field_tables_stay_inside_their_layout() {
        for (layout, fields) in [
            (Layout::Legacy, &LEGACY_FIELDS),
            (Layout::Public, &PUBLIC_FIELDS),
        ] {
            let end = layout.size() - TAIL_SIZE;
            for field in [
                fields.ip_addr,
                fields.mac_addr,
                fields.user_define,
                fields.vendor_name,
                fields.device_name,
                fields.apple_model,
                fields.online,
                fields.client_type,
                fields.ip_method,
                fields.op_mode,
                fields.device_flag,
                fields.wireless,
                fields.ssid,
                fields.txrate,
                fields.rxrate,
                fields.rssi,
                fields.conn_time,
            ]
            .into_iter()
            .chain(fields.ip6_addr)
            .chain(fields.ip6_prefix)
            .chain(fields.pap_mac)
            .chain(fields.is_re)
            .chain(fields.guest_network)
            .chain(fields.wireless_auth)
            {
                assert!(field.offset + field.width * MAX_NR_CLIENT_LIST <= end);
            }
        }
    }
}
