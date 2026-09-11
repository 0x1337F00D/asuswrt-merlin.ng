//! Hand-constructed wire fixtures for the legacy ASUS infosvr discovery PDU.
//!
//! Every offset is taken from the `#pragma pack(1)` structures in the vendor
//! header `release/src/router/shared/iboxcom.h` and from the request handling
//! in `release/src/router/infosvr/common.c`, `packet.c` and `storage.c`
//! (WAVESERVER defined, WCLIENT and BTN_SETUP undefined, RTCONFIG_AMAS and
//! RTCONFIG_ROG set, which is what main.rs assumes for the GT-AX11000 build).
//! The live probe `tests/infosvr-live.py` exercises the same layouts against
//! the router. The AiMesh group ID travels in the FIND_CAP reply only; the
//! GETINFO_EX2 reply carries just the transaction ID and the disk status.
//!
//! "Derived" fixtures and assertions follow the C struct layout and the C
//! control flow byte for byte. "Inferred" ones cover behaviour the C sources
//! leave to chance (a static, never cleared response buffer; unchecked
//! copies; `strtoul` leniency) and lock in the choice made by the Rust port.

use infosvr::{
    build_response, decode_group_id, parse_mac, parse_request, DeviceState, Request, PDU_LEN,
};
use std::net::Ipv4Addr;
use std::ops::Range;

// iboxcom.h constants shared by every fixture.
const NET_SERVICE_ID_LPT_EMU: u8 = 11;
const NET_SERVICE_ID_IBOX_INFO: u8 = 12;
const NET_PACKET_TYPE_BASE: u8 = 20;
const NET_PACKET_TYPE_CMD: u8 = 21;
const NET_PACKET_TYPE_RES: u8 = 22;
const NET_CMD_ID_GETINFO: u16 = 31;
const NET_CMD_ID_GETINFO_MANU: u16 = 52;
const NET_CMD_ID_GETINFO_EX2: u16 = 53;
const NET_CMD_ID_FIND_CAP: u16 = 54;
const INFO_TYPE_GROUPID: u8 = 1;
const INFO_TYPE_PRODUCT_NAME: u8 = 2;
const INFO_TYPE_MAC: u8 = 3;

// sizeof(IBOX_COMM_PKT_HDR_EX): 8-byte header, 6-byte MAC, 32-byte password.
const HDR_EX_LEN: usize = 46;
// sizeof(IBOX_COMM_PKT_HDR_EX_JSON): 8-byte header, JSON[500].
const HDR_EX_JSON_LEN: usize = 508;

const DEVICE_MAC: [u8; 6] = [0x04, 0x42, 0x1a, 0x0b, 0x0c, 0x0d];
const LABEL_MAC: [u8; 6] = [0x04, 0x42, 0x1a, 0x0b, 0x0c, 0x10];
const TRANSACTION: [u8; 4] = [0x13, 0x37, 0xc0, 0xde];

// gen_vsie_id() output as fed to str2hex(): 40 hex digits, ID_LEN (20) bytes.
const GROUP_ID_HEX: &str = "9A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D";
const GROUP_ID: [u8; 20] = [
    0x9a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
    0x0a, 0x1b, 0x2c, 0x3d,
];

/// `WS_INFO_T` (iboxcom.h) exactly as read from /tmp/waveserver.info.
const WAVE_INFO: [u8; 16] = [
    b'W', b'S', 0x01, 0x00, // Name[4] = "WS" + major + minor
    0x02, 0x00, // Channel = 2 (file byte order, copied verbatim)
    0x44, 0xac, // SampleRate = 44100
    0x82, // u.SampleSize: s16 | cflag
    0x00, // Compress
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved[6]
];

/// Zero-pads a hand-written prefix to INFO_PDU_LENGTH. Both the C daemon
/// (`memset(ginfo, 0, ...)`, `memset(st, 0, ...)`) and its clients pack into
/// a zeroed buffer.
const fn pdu(prefix: &[u8]) -> [u8; PDU_LEN] {
    put([0; PDU_LEN], 0, prefix)
}

/// Copies `bytes` into `packet` at the C struct field offset `offset`.
const fn put(mut packet: [u8; PDU_LEN], offset: usize, bytes: &[u8]) -> [u8; PDU_LEN] {
    let mut index = 0;
    while index < bytes.len() {
        packet[offset + index] = bytes[index];
        index += 1;
    }
    packet
}

/// Bytes that are never valid UTF-8 and never NUL: 0xff and lone
/// continuation bytes.
const fn invalid_utf8<const N: usize>() -> [u8; N] {
    let mut bytes = [0xff; N];
    let mut index = 1;
    while index < N {
        bytes[index] = 0x80 | (index as u8 & 0x3f);
        index += 2;
    }
    bytes
}

// ---------------------------------------------------------------------------
// Request fixtures (client -> daemon)
// ---------------------------------------------------------------------------

/// `IBOX_COMM_PKT_HDR` as packed by `PackGetInfo()` (packet.c). Derived.
#[rustfmt::skip]
const GETINFO_REQUEST: [u8; PDU_LEN] = pdu(&[
    NET_SERVICE_ID_IBOX_INFO, // ServiceID
    NET_PACKET_TYPE_CMD,      // PacketType
    0x1f, 0x00,               // OpCode = NET_CMD_ID_GETINFO (31), little-endian WORD
    0x00, 0x00, 0x00, 0x00,   // Info = 0 (PackGetInfo never sets a transaction)
                              // IBOX_COMM_PKT_HDR_EX_JSON.JSON[500] follows and stays zero
]);

/// GETINFO whose `JSON[500]` body (offset 8) is binary garbage without a NUL.
/// common.c only `strlcpy`s and JSON-parses it; the result is discarded.
/// Derived: the body has no influence on the reply.
const GETINFO_BINARY_JSON_REQUEST: [u8; PDU_LEN] = put(GETINFO_REQUEST, 8, &invalid_utf8::<500>());

/// `IBOX_COMM_PKT_HDR` for NET_CMD_ID_GETINFO_MANU (52); no body is read.
const GETINFO_MANU_REQUEST: [u8; PDU_LEN] = pdu(&[
    NET_SERVICE_ID_IBOX_INFO,
    NET_PACKET_TYPE_CMD,
    0x34,
    0x00, // OpCode = NET_CMD_ID_GETINFO_MANU
]);

/// `IBOX_COMM_PKT_HDR` for NET_CMD_ID_FIND_CAP (54) as sent by AiMesh nodes.
const FIND_CAP_REQUEST: [u8; PDU_LEN] = pdu(&[
    NET_SERVICE_ID_IBOX_INFO,
    NET_PACKET_TYPE_CMD,
    0x36,
    0x00, // OpCode = NET_CMD_ID_FIND_CAP
]);

/// `IBOX_COMM_PKT_HDR_EX` as packed by `PackCmdHdr()` for
/// NET_CMD_ID_GETINFO_EX2 with the all-FF target used by infosvr-live.py.
/// Derived; common.c answers this target, the port answers it too.
#[rustfmt::skip]
const GETINFO_EX2_BROADCAST_REQUEST: [u8; PDU_LEN] = pdu(&[
    NET_SERVICE_ID_IBOX_INFO,           // ServiceID
    NET_PACKET_TYPE_CMD,                // PacketType
    0x35, 0x00,                         // OpCode = NET_CMD_ID_GETINFO_EX2 (53)
    0x13, 0x37, 0xc0, 0xde,             // Info = transaction ID, opaque, echoed verbatim
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // MacAddress[6] = broadcast target
    b'a', b'd', b'm', b'i', b'n', 0x00, // Password[32]: NUL-terminated, ignored
                                        // (the check is commented out in common.c)
]);

/// GETINFO_EX2 addressed to the router's own `lan_hwaddr`. Inferred:
/// common.c drops exactly this case (`memcmp(MacAddress, mac, 6) == 0` logs
/// "Mac Error") and answers every other target; the port instead answers
/// own, broadcast and all-zero targets only.
const GETINFO_EX2_UNICAST_REQUEST: [u8; PDU_LEN] =
    put(GETINFO_EX2_BROADCAST_REQUEST, 8, &DEVICE_MAC);

/// GETINFO_EX2 with an all-zero target (clients that never learnt the MAC).
const GETINFO_EX2_UNSPECIFIED_REQUEST: [u8; PDU_LEN] =
    put(GETINFO_EX2_BROADCAST_REQUEST, 8, &[0; 6]);

/// GETINFO_EX2 addressed to a neighbour: only the last octet differs.
/// Inferred: common.c would answer it; the port keeps silent.
const GETINFO_EX2_FOREIGN_REQUEST: [u8; PDU_LEN] = put(
    GETINFO_EX2_BROADCAST_REQUEST,
    8,
    &[0x04, 0x42, 0x1a, 0x0b, 0x0c, 0x0e],
);

/// GETINFO_EX2 whose `Password[32]` (offset 14) is non-UTF-8 and unterminated.
/// Derived: the password is never read.
const GETINFO_EX2_BINARY_PASSWORD_REQUEST: [u8; PDU_LEN] =
    put(GETINFO_EX2_BROADCAST_REQUEST, 14, &invalid_utf8::<32>());

/// Wrong magic: NET_SERVICE_ID_LPT_EMU, the printer-emulation service.
const LPT_EMU_REQUEST: [u8; PDU_LEN] = put(GETINFO_REQUEST, 0, &[NET_SERVICE_ID_LPT_EMU]);

/// Wrong packet type: a response header reflected back at the daemon.
const REFLECTED_RESPONSE_REQUEST: [u8; PDU_LEN] = put(GETINFO_REQUEST, 1, &[NET_PACKET_TYPE_RES]);

/// OpCode written big-endian; decodes as 0x1f00, an undefined command.
const BIG_ENDIAN_OPCODE_REQUEST: [u8; PDU_LEN] = put(GETINFO_REQUEST, 2, &[0x00, 0x1f]);

/// enum NET_CMD_ID members the read-only port must never answer.
const REJECTED_OPCODES: [(&str, u16); 11] = [
    ("NET_CMD_ID_BASE", 30),
    ("NET_CMD_ID_GETINFO_EX", 32),
    ("NET_CMD_ID_GETINFO_SITES", 33),
    ("NET_CMD_ID_SETINFO", 34),
    ("NET_CMD_ID_SETSYSTEM", 35),
    ("NET_CMD_ID_GETINFO_PROF", 36),
    ("NET_CMD_ID_SETINFO_PROF", 37),
    ("NET_CMD_ID_CHECK_PASS", 38),
    ("NET_CMD_ID_MANU_BASE", 50),
    ("NET_CMD_ID_MANU_CMD", 51),
    ("NET_CMD_ID_MAXIMUM", 55),
];

// ---------------------------------------------------------------------------
// Response fixtures (daemon -> client)
// ---------------------------------------------------------------------------

fn fixture_state() -> DeviceState {
    DeviceState {
        printer_info: "EPSON L3150".into(),
        ssid: "GT-AX11000-Lab".into(),
        netmask: "255.255.255.0".into(),
        product_id: "GT-AX11000".into(),
        firmware_version: "3004.388.8".into(),
        mac: DEVICE_MAC,
        label_mac: LABEL_MAC,
        sw_mode: 1,
        wave_info: Some(WAVE_INFO),
        disk_status: "ef53:1234!$".into(),
        // WEBDAV | AMAS | AAE_BASIC | SWCTRL | MASTER
        extend_capabilities: 0x00d9,
        enable_webdav: true,
        webdav_mode: 2,
        webdav_http_port: 8082,
        webdav_https_port: 443,
        enable_ddns: true,
        ddns_hostname: "lab.asuscomm.com".into(),
        wan_ip: Ipv4Addr::new(203, 0, 113, 7),
        is_not_default: true,
        app_http_port: 8081,
        app_api_level: 2,
        enable_aae: true,
        aae_device_id: "0123456789abcdef".into(),
        ai_home_api_level: 23,
        cfg_group: Some(GROUP_ID),
    }
}

/// The 4-byte `IBOX_COMM_PKT_RES` prefix of every reply.
const fn response_header(opcode: u16) -> [u8; 4] {
    let [low, high] = opcode.to_le_bytes();
    [NET_SERVICE_ID_IBOX_INFO, NET_PACKET_TYPE_RES, low, high]
}

/// `IBOX_COMM_PKT_RES` + `PKT_GET_INFO` + `WS_INFO_T` + `STORAGE_INFO_T` for
/// `fixture_state()`. Offsets derived from iboxcom.h with WAVESERVER defined
/// (common.c). Inferred: `Info` (4..8) and the tail (478..512) are zero; the
/// C daemon reuses a static `pdubuf_res` and leaks whatever the previous
/// reply left there.
const GETINFO_RESPONSE: [u8; PDU_LEN] = {
    let mut p = pdu(&response_header(NET_CMD_ID_GETINFO));
    p = put(p, 8, b"EPSON L3150\0"); // PKT_GET_INFO.PrinterInfo[128]
    p = put(p, 136, b"GT-AX11000-Lab\0"); // .SSID[32]
    p = put(p, 168, b"255.255.255.0\0"); // .NetMask[32]
    p = put(p, 200, b"GT-AX11000\0"); // .ProductID[32]
    p = put(p, 232, b"3004.388.8\0"); // .FirmwareVersion[16]
                                      // 248: .OperationMode = 0 (only set under WCLIENT)
    p = put(p, 249, &DEVICE_MAC); // .MacAddress[6]
    p = put(p, 255, &[1]); // .sw_mode = router
    p = put(p, 256, &WAVE_INFO); // WS_INFO_T (0x100, see iboxcom.h)
    p = put(p, 272, &[0x82, 0x80]); // STORAGE_INFO_T.MagicWord = le16(EXTEND_MAGIC)
    p = put(p, 274, &[0xd9, 0x00]); // .ExtendCap = le16(0x00d9)
    p = put(p, 276, &[1]); // .u.wt.EnableWebDav
    p = put(p, 277, &[2]); // .u.wt.HttpType = EXTEND_WEBDAV_TYPE_BOTH
    p = put(p, 278, &[0x1f, 0x92]); // .u.wt.HttpPort = htons(8082)
    p = put(p, 280, &[1]); // .u.wt.EnableDDNS
    p = put(p, 281, b"lab.asuscomm.com\0"); // .u.wt.HostName[64]
    p = put(p, 345, &[0x07, 0x71, 0x00, 0xcb]); // .u.wt.WANIPAddr = le32(203.0.113.7)
                                                // 349: .u.wt.WANState = 0 (never set by storage.c)
    p = put(p, 350, &[1]); // .u.wt.isNotDefault = x_Setting
    p = put(p, 351, &[0x01, 0xbb]); // .u.wt.HttpsPort = htons(443)
                                    // 353..369: .u.dev.hw (HWCTRL_INFO_T) = 0
                                    // 369: .u.dev.sw.ROGAPILevel = 0
    p = put(p, 370, &[23]); // .u.dev.sw.AiHOMEAPILevel = EXTEND_AIHOME_API_LEVEL
                            // 371..404: .u.dev.sw.AiProtectionAPILevel, Reserved[13], union padding = 0
    p = put(p, 404, &[0x91, 0x1f]); // .AppHttpPort = le16(8081)
    p = put(p, 406, &[2]); // .AppAPILevel = EXTEND_API_LEVEL (RTCONFIG_ROG)
    p = put(p, 407, &[1]); // .EnableAAE
    p = put(p, 408, b"0123456789abcdef\0"); // .AAEDeviceID[64]
    p = put(p, 472, &LABEL_MAC); // .Label_MacAddress[6]
    p // 478..512: unused tail of INFO_PDU_LENGTH
};

/// GETINFO as the C daemon emits it when the USB printer reports a Latin-1
/// model name: `PrinterInfo` is copied byte for byte (`sprintf`), so 0xdc
/// ('Ü' in ISO-8859-1) reaches the wire without any UTF-8 lead byte.
/// Derived layout; the port cannot produce it (see the non-UTF-8 tests).
const GETINFO_RESPONSE_LATIN1_PRINTER: [u8; PDU_LEN] =
    put(GETINFO_RESPONSE, 8, b"EPSON L3150 \xdcbersicht\0");

/// NET_CMD_ID_GETINFO_MANU: same layout without SSID and without WS_INFO_T.
/// Derived: `ginfo` is zeroed and SSID is never copied. Inferred: the
/// WS_INFO_T bytes are zero (the C daemon leaves the previous GETINFO's
/// wave info in its static buffer).
const GETINFO_MANU_RESPONSE: [u8; PDU_LEN] = {
    let mut p = put(
        GETINFO_RESPONSE,
        0,
        &response_header(NET_CMD_ID_GETINFO_MANU),
    );
    p = put(p, 136, &[0; 32]); // .SSID[32] is not filled for manufacturing
    p = put(p, 256, &[0; 16]); // WS_INFO_T is not read for manufacturing
    p
};

/// NET_CMD_ID_GETINFO_EX2: the header `Info` echoes the request transaction
/// and `PKT_GET_INFO.PrinterInfo` carries "<fstype>:<free MiB>!$". Derived:
/// common.c copies the request MAC into `IBOX_COMM_PKT_RES_EX.MacAddress`
/// (8..14) and then zeroes the whole PKT_GET_INFO (8..256), wiping it again.
/// Inferred: bytes 256..512 are zero (static buffer leak in C).
const GETINFO_EX2_RESPONSE: [u8; PDU_LEN] = {
    let mut p = pdu(&response_header(NET_CMD_ID_GETINFO_EX2));
    p = put(p, 4, &TRANSACTION); // IBOX_COMM_PKT_RES.Info
    p = put(p, 8, b"ef53:1234!$\0"); // PKT_GET_INFO.PrinterInfo[128]
    p
};

/// NET_CMD_ID_FIND_CAP: `STORAGE_INFO_FINDCAP_T` at offset 8 with the TLVs
/// written by `storage_setbuf()` in storage.c; group ID present. Derived.
const FIND_CAP_RESPONSE: [u8; PDU_LEN] = {
    let mut p = pdu(&response_header(NET_CMD_ID_FIND_CAP));
    p = put(p, 8, &[0x82, 0x80]); // STORAGE_INFO_FINDCAP_T.MagicWord
    p = put(p, 10, &[0xd9, 0x00]); // .ExtendCap
    p = put(p, 12, &[INFO_TYPE_GROUPID, 20]); // .Info[]: type, len
    p = put(p, 14, &GROUP_ID); // cfg_group_g[20]
    p = put(p, 34, &[INFO_TYPE_PRODUCT_NAME, 10]); // type, strlen(productid)
    p = put(p, 36, b"GT-AX11000"); // productid_g, no NUL
    p = put(p, 46, &[INFO_TYPE_MAC, 6]); // type, len
    p = put(p, 48, &DEVICE_MAC); // mac[6]
    p // 54..512: zero, read as the (0, 0) terminator by infosvr-live.py
};

/// FIND_CAP when `gen_vsie_id()` failed (`cfg_groupid_is_null`): the group
/// TLV is skipped and the product name TLV starts the list. Derived.
const FIND_CAP_RESPONSE_WITHOUT_GROUP: [u8; PDU_LEN] = {
    let mut p = pdu(&response_header(NET_CMD_ID_FIND_CAP));
    p = put(p, 8, &[0x82, 0x80, 0xd9, 0x00]); // MagicWord, ExtendCap
    p = put(p, 12, &[INFO_TYPE_PRODUCT_NAME, 10]);
    p = put(p, 14, b"GT-AX11000");
    p = put(p, 24, &[INFO_TYPE_MAC, 6]);
    p = put(p, 26, &DEVICE_MAC);
    p
};

/// FIND_CAP from a hypothetical peer whose group TLV is one byte short of
/// ID_LEN. Hand-built: no C path emits it; infosvr-live.py must skip it.
const FIND_CAP_RESPONSE_SHORT_GROUP: [u8; PDU_LEN] = {
    let mut p = pdu(&response_header(NET_CMD_ID_FIND_CAP));
    p = put(p, 8, &[0x82, 0x80, 0xd9, 0x00]);
    p = put(p, 12, &[INFO_TYPE_GROUPID, 19]); // len 19, not 20
    p = put(p, 14, &GROUP_ID); // 20 bytes: the last one becomes the next type
    p = put(p, 33, &[INFO_TYPE_PRODUCT_NAME, 10]);
    p = put(p, 35, b"GT-AX11000");
    p = put(p, 45, &[INFO_TYPE_MAC, 6]);
    p = put(p, 47, &DEVICE_MAC);
    p
};

/// FIND_CAP from a hypothetical peer whose group TLV is one byte longer
/// than ID_LEN. Hand-built like the short one; the walk stays in bounds.
const FIND_CAP_RESPONSE_LONG_GROUP: [u8; PDU_LEN] = {
    let mut p = pdu(&response_header(NET_CMD_ID_FIND_CAP));
    p = put(p, 8, &[0x82, 0x80, 0xd9, 0x00]);
    p = put(p, 12, &[INFO_TYPE_GROUPID, 21]); // len 21, not 20
    p = put(p, 14, &GROUP_ID); // 14..34
    p = put(p, 34, &[0x3d]); // the 21st group byte
    p = put(p, 35, &[INFO_TYPE_PRODUCT_NAME, 10]);
    p = put(p, 37, b"GT-AX11000");
    p = put(p, 47, &[INFO_TYPE_MAC, 6]);
    p = put(p, 49, &DEVICE_MAC);
    p
};

/// FIND_CAP whose second TLV claims 255 bytes at offset 271 and therefore
/// ends at 526, past INFO_PDU_LENGTH. Hand-built: `storage_setbuf()` packs
/// into a 256-byte scratch buffer, so no C reply can carry it.
const FIND_CAP_RESPONSE_TLV_OVERRUN: [u8; PDU_LEN] = {
    let mut p = pdu(&response_header(NET_CMD_ID_FIND_CAP));
    p = put(p, 8, &[0x82, 0x80, 0xd9, 0x00]);
    p = put(p, 12, &[INFO_TYPE_PRODUCT_NAME, 255]);
    p = put(p, 14, &[b'p'; 255]); // 14..269
    p = put(p, 269, &[INFO_TYPE_PRODUCT_NAME, 255]); // value would be 271..526
    p = put(p, 271, &[b'q'; PDU_LEN - 271]);
    p
};

// ---------------------------------------------------------------------------
// Client-side unpackers (test doubles for packet.c / infosvr-live.py)
// ---------------------------------------------------------------------------

/// One `STORAGE_INFO_FINDCAP_T.Info[]` entry: (type, value).
type Tlv = (u8, Vec<u8>);
/// Assigns one fixed-width string field of `DeviceState`.
type FieldSetter = fn(&mut DeviceState, String);

/// `strnlen` view of a fixed-width BYTE[] field.
fn c_string(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    &field[..end]
}

/// Mirrors `UnpackResHdrNoCheck()` (packet.c): header magic plus the
/// NET_RES_ERR_* status carried in the high byte of OpCode.
fn unpack_response_header(packet: &[u8]) -> Option<u16> {
    if packet.len() != PDU_LEN
        || packet[0] != NET_SERVICE_ID_IBOX_INFO
        || packet[1] != NET_PACKET_TYPE_RES
    {
        return None;
    }
    let opcode = u16::from_le_bytes([packet[2], packet[3]]);
    if opcode & 0xff00 != 0 {
        return None;
    }
    Some(opcode)
}

/// Mirrors `UnpackGetInfo()` plus the STORAGE_INFO_T view AiCloud clients
/// read, mapped back onto `DeviceState`. Fields that are not on the GETINFO
/// wire (`disk_status`, `cfg_group`) take their defaults. Returns None when
/// a string field is not UTF-8, which `DeviceState` cannot represent.
fn unpack_get_info(packet: &[u8; PDU_LEN]) -> Option<DeviceState> {
    let text = |range: Range<usize>| String::from_utf8(c_string(&packet[range]).to_vec()).ok();
    let wave_info: [u8; 16] = packet[256..272].try_into().unwrap();
    assert_eq!(&packet[272..274], &[0x82, 0x80], "STORAGE_INFO_T.MagicWord");
    assert_eq!(packet[248], 0, "PKT_GET_INFO.OperationMode");
    Some(DeviceState {
        printer_info: text(8..136)?,
        ssid: text(136..168)?,
        netmask: text(168..200)?,
        product_id: text(200..232)?,
        firmware_version: text(232..248)?,
        mac: packet[249..255].try_into().unwrap(),
        label_mac: packet[472..478].try_into().unwrap(),
        sw_mode: packet[255],
        wave_info: (wave_info != [0; 16]).then_some(wave_info),
        extend_capabilities: u16::from_le_bytes([packet[274], packet[275]]),
        enable_webdav: packet[276] != 0,
        webdav_mode: packet[277],
        webdav_http_port: u16::from_be_bytes([packet[278], packet[279]]),
        enable_ddns: packet[280] != 0,
        ddns_hostname: text(281..345)?,
        wan_ip: Ipv4Addr::from(u32::from_le_bytes(packet[345..349].try_into().unwrap())),
        is_not_default: packet[350] != 0,
        webdav_https_port: u16::from_be_bytes([packet[351], packet[352]]),
        ai_home_api_level: packet[370],
        app_http_port: u16::from_le_bytes([packet[404], packet[405]]),
        app_api_level: packet[406],
        enable_aae: packet[407] != 0,
        aae_device_id: text(408..472)?,
        ..DeviceState::default()
    })
}

/// Mirrors the TLV walk in `infosvr-live.py::find_group_id`, returning every
/// TLV up to the (0, 0) terminator, or None where the probe reports
/// FIND_CAP_TLV_BOUNDS.
fn unpack_find_cap(packet: &[u8; PDU_LEN]) -> Option<(u16, Vec<Tlv>)> {
    assert_eq!(
        &packet[8..10],
        &[0x82, 0x80],
        "STORAGE_INFO_FINDCAP_T.MagicWord"
    );
    let extend_cap = u16::from_le_bytes([packet[10], packet[11]]);
    let mut tlvs = Vec::new();
    let mut cursor = 12;
    while cursor + 2 <= PDU_LEN {
        let kind = packet[cursor];
        let value_len = usize::from(packet[cursor + 1]);
        cursor += 2;
        let end = cursor + value_len;
        if end > PDU_LEN {
            return None;
        }
        if kind == 0 && value_len == 0 {
            break;
        }
        tlvs.push((kind, packet[cursor..end].to_vec()));
        cursor = end;
    }
    Some((extend_cap, tlvs))
}

/// The probe's acceptance rule: the first type-1 TLV of exactly 20 bytes.
fn probe_group_id(packet: &[u8; PDU_LEN]) -> Option<[u8; 20]> {
    unpack_find_cap(packet)?
        .1
        .into_iter()
        .find(|(kind, value)| *kind == INFO_TYPE_GROUPID && value.len() == 20)
        .map(|(_, value)| value.try_into().unwrap())
}

/// Reports the first differing offset instead of dumping 512 bytes twice.
#[track_caller]
fn assert_pdu_eq(actual: &[u8; PDU_LEN], expected: &[u8; PDU_LEN]) {
    if let Some(offset) = (0..PDU_LEN).find(|&offset| actual[offset] != expected[offset]) {
        let end = (offset + 8).min(PDU_LEN);
        panic!(
            "PDU differs at offset {offset}: actual {:02x?}, expected {:02x?}",
            &actual[offset..end],
            &expected[offset..end]
        );
    }
}

// ---------------------------------------------------------------------------
// Decode: request fixtures
// ---------------------------------------------------------------------------

#[test]
fn decodes_every_read_only_request_fixture() {
    let extended = Request::GetInfoEx2 {
        transaction: TRANSACTION,
    };
    let fixtures = [
        (&GETINFO_REQUEST, Request::GetInfo),
        (&GETINFO_BINARY_JSON_REQUEST, Request::GetInfo),
        (&GETINFO_MANU_REQUEST, Request::GetInfoManufacturing),
        (&FIND_CAP_REQUEST, Request::FindCapabilities),
        (&GETINFO_EX2_BROADCAST_REQUEST, extended),
        (&GETINFO_EX2_UNICAST_REQUEST, extended),
        (&GETINFO_EX2_UNSPECIFIED_REQUEST, extended),
        (&GETINFO_EX2_BINARY_PASSWORD_REQUEST, extended),
    ];
    for (packet, expected) in fixtures {
        assert_eq!(parse_request(packet, DEVICE_MAC), Some(expected));
    }
}

#[test]
fn opaque_body_fixtures_are_really_not_utf8() {
    let json = &GETINFO_BINARY_JSON_REQUEST[8..HDR_EX_JSON_LEN];
    assert!(std::str::from_utf8(json).is_err());
    // No NUL anywhere in JSON[500]: strlcpy in common.c must stop at the
    // field width, not at a terminator.
    assert!(json.iter().all(|byte| *byte != 0));
    assert_eq!(&GETINFO_BINARY_JSON_REQUEST[HDR_EX_JSON_LEN..], &[0; 4]);
    let password = &GETINFO_EX2_BINARY_PASSWORD_REQUEST[14..HDR_EX_LEN];
    assert!(std::str::from_utf8(password).is_err());
    assert!(password.iter().all(|byte| *byte != 0));
}

#[test]
fn extended_target_mac_gates_the_request_per_octet() {
    assert_eq!(
        parse_request(&GETINFO_EX2_FOREIGN_REQUEST, DEVICE_MAC),
        None
    );
    for octet in 0..6 {
        let mut packet = GETINFO_EX2_UNICAST_REQUEST;
        packet[8 + octet] ^= 0x01;
        assert_eq!(parse_request(&packet, DEVICE_MAC), None, "octet {octet}");
        // A unicast target is exact: the same packet is accepted only by the
        // router whose lan_hwaddr it names.
        let mut mac = DEVICE_MAC;
        mac[octet] ^= 0x01;
        assert!(parse_request(&packet, mac).is_some(), "octet {octet}");
    }
    // Broadcast and unspecified targets do not depend on the device MAC,
    // including the boundary MACs a router could plausibly carry.
    for device_mac in [[0x5e; 6], [0; 6], [0xff; 6]] {
        assert!(parse_request(&GETINFO_EX2_BROADCAST_REQUEST, device_mac).is_some());
        assert!(parse_request(&GETINFO_EX2_UNSPECIFIED_REQUEST, device_mac).is_some());
    }
}

#[test]
fn extended_transaction_is_copied_verbatim() {
    for transaction in [[0; 4], [0xff; 4], [0x00, 0x00, 0x00, 0x01], TRANSACTION] {
        let packet = put(GETINFO_EX2_BROADCAST_REQUEST, 4, &transaction);
        assert_eq!(
            parse_request(&packet, DEVICE_MAC),
            Some(Request::GetInfoEx2 { transaction })
        );
    }
}

#[test]
fn header_only_requests_ignore_the_extended_fields() {
    // GETINFO, GETINFO_MANU and FIND_CAP never dereference
    // IBOX_COMM_PKT_HDR_EX, so a transaction, target MAC or password there
    // changes nothing (common.c takes the non-extended branch).
    let mut packet = FIND_CAP_REQUEST;
    packet[4..8].copy_from_slice(&TRANSACTION);
    packet[8..14].copy_from_slice(&[0x02; 6]);
    packet[14..HDR_EX_LEN].copy_from_slice(&invalid_utf8::<32>());
    assert_eq!(
        parse_request(&packet, DEVICE_MAC),
        Some(Request::FindCapabilities)
    );
    let response = build_response(Request::FindCapabilities, &fixture_state());
    assert_eq!(&response[4..8], &[0; 4]);
    assert_pdu_eq(&response, &FIND_CAP_RESPONSE);

    let mut packet = GETINFO_MANU_REQUEST;
    packet[8..14].copy_from_slice(&DEVICE_MAC);
    assert_eq!(
        parse_request(&packet, DEVICE_MAC),
        Some(Request::GetInfoManufacturing)
    );
}

// ---------------------------------------------------------------------------
// Decode: reject paths
// ---------------------------------------------------------------------------

#[test]
fn rejects_wrong_service_id_and_packet_type() {
    assert_eq!(parse_request(&LPT_EMU_REQUEST, DEVICE_MAC), None);
    assert_eq!(parse_request(&REFLECTED_RESPONSE_REQUEST, DEVICE_MAC), None);
    for service_id in [0x00, NET_SERVICE_ID_IBOX_INFO + 1, 0xff] {
        let packet = put(GETINFO_REQUEST, 0, &[service_id]);
        assert_eq!(parse_request(&packet, DEVICE_MAC), None, "{service_id}");
    }
    for packet_type in [0x00, NET_PACKET_TYPE_BASE, NET_PACKET_TYPE_RES, 0xff] {
        let packet = put(GETINFO_EX2_BROADCAST_REQUEST, 1, &[packet_type]);
        assert_eq!(parse_request(&packet, DEVICE_MAC), None, "{packet_type}");
    }
    // The daemon's own replies must never be mistaken for commands.
    for response in [
        &GETINFO_RESPONSE,
        &GETINFO_RESPONSE_LATIN1_PRINTER,
        &GETINFO_MANU_RESPONSE,
        &GETINFO_EX2_RESPONSE,
        &FIND_CAP_RESPONSE,
        &FIND_CAP_RESPONSE_WITHOUT_GROUP,
    ] {
        assert_eq!(parse_request(response, DEVICE_MAC), None);
    }
}

#[test]
fn rejects_big_endian_and_mutating_opcodes() {
    assert_eq!(parse_request(&BIG_ENDIAN_OPCODE_REQUEST, DEVICE_MAC), None);
    for (name, opcode) in REJECTED_OPCODES {
        let packet = put(GETINFO_EX2_BROADCAST_REQUEST, 2, &opcode.to_le_bytes());
        assert_eq!(parse_request(&packet, DEVICE_MAC), None, "{name}");
    }
    // NET_RES_ERR_* flags in the high byte never form a valid command.
    for opcode in [
        NET_CMD_ID_GETINFO | 0x0100,
        NET_CMD_ID_GETINFO | 0x0200,
        NET_CMD_ID_FIND_CAP | 0x0100,
    ] {
        let packet = put(GETINFO_REQUEST, 2, &opcode.to_le_bytes());
        assert_eq!(parse_request(&packet, DEVICE_MAC), None, "{opcode:#06x}");
    }
}

#[test]
fn rejects_truncated_and_oversized_datagrams() {
    // Truncated: shorter than INFO_PDU_LENGTH, including a complete HDR_EX
    // and a complete HDR_EX_JSON. infosvr.c drops these too (`iRcv !=
    // INFO_PDU_LENGTH`).
    for length in [0, 1, 4, 8, 14, HDR_EX_LEN, HDR_EX_JSON_LEN, PDU_LEN - 1] {
        assert_eq!(
            parse_request(&GETINFO_EX2_BROADCAST_REQUEST[..length], DEVICE_MAC),
            None,
            "{length}"
        );
        assert_eq!(parse_request(&GETINFO_REQUEST[..length], DEVICE_MAC), None);
    }
    // Oversized. Inferred: the C daemon's recvfrom silently truncates to 512
    // bytes and would answer; main.rs receives PDU_LEN + 1 bytes and drops
    // these, which is what infosvr-live.py (INVALID_LEN_513) expects.
    for extra in [1, 2, 512, 1024] {
        let mut packet = GETINFO_REQUEST.to_vec();
        packet.extend(std::iter::repeat_n(0, extra));
        assert_eq!(parse_request(&packet, DEVICE_MAC), None, "{extra}");
        let mut packet = GETINFO_EX2_BROADCAST_REQUEST.to_vec();
        packet.extend(std::iter::repeat_n(0xff, extra));
        assert_eq!(parse_request(&packet, DEVICE_MAC), None, "{extra}");
    }
}

// ---------------------------------------------------------------------------
// Encode: response fixtures
// ---------------------------------------------------------------------------

#[test]
fn getinfo_response_matches_the_c_struct_layout() {
    let state = fixture_state();
    let request = parse_request(&GETINFO_REQUEST, state.mac).unwrap();
    assert_pdu_eq(&build_response(request, &state), &GETINFO_RESPONSE);
    assert_eq!(
        unpack_response_header(&GETINFO_RESPONSE),
        Some(NET_CMD_ID_GETINFO)
    );
    // sizeof(IBOX_COMM_PKT_RES) + sizeof(PKT_GET_INFO) + sizeof(WS_INFO_T)
    // + sizeof(STORAGE_INFO_T) = 8 + 248 + 16 + 206 = 478.
    assert!(GETINFO_RESPONSE[478..].iter().all(|byte| *byte == 0));
}

#[test]
fn manufacturing_response_omits_ssid_and_wave_info() {
    let state = fixture_state();
    let request = parse_request(&GETINFO_MANU_REQUEST, state.mac).unwrap();
    assert_pdu_eq(&build_response(request, &state), &GETINFO_MANU_RESPONSE);
    assert_eq!(
        unpack_response_header(&GETINFO_MANU_RESPONSE),
        Some(NET_CMD_ID_GETINFO_MANU)
    );
}

#[test]
fn extended_response_echoes_transaction_and_disk_status() {
    let state = fixture_state();
    for request in [
        &GETINFO_EX2_BROADCAST_REQUEST,
        &GETINFO_EX2_UNICAST_REQUEST,
        &GETINFO_EX2_UNSPECIFIED_REQUEST,
        &GETINFO_EX2_BINARY_PASSWORD_REQUEST,
    ] {
        let request = parse_request(request, state.mac).unwrap();
        assert_pdu_eq(&build_response(request, &state), &GETINFO_EX2_RESPONSE);
    }
    assert_eq!(
        unpack_response_header(&GETINFO_EX2_RESPONSE),
        Some(NET_CMD_ID_GETINFO_EX2)
    );
    // The request MAC copied into IBOX_COMM_PKT_RES_EX.MacAddress is wiped
    // by the PKT_GET_INFO memset, and nothing from STORAGE_INFO_T leaks.
    assert_eq!(&GETINFO_EX2_RESPONSE[8..14], b"ef53:1");
    assert!(GETINFO_EX2_RESPONSE[20..].iter().all(|byte| *byte == 0));
}

#[test]
fn find_capabilities_with_and_without_group_id() {
    let mut state = fixture_state();
    let request = parse_request(&FIND_CAP_REQUEST, state.mac).unwrap();
    assert_pdu_eq(&build_response(request, &state), &FIND_CAP_RESPONSE);
    assert_eq!(
        unpack_response_header(&FIND_CAP_RESPONSE),
        Some(NET_CMD_ID_FIND_CAP)
    );

    state.cfg_group = None;
    assert_pdu_eq(
        &build_response(request, &state),
        &FIND_CAP_RESPONSE_WITHOUT_GROUP,
    );
}

#[test]
fn wave_info_is_absent_when_waveserver_is_down() {
    let mut state = fixture_state();
    state.wave_info = None;
    let response = build_response(Request::GetInfo, &state);
    assert_pdu_eq(&response, &put(GETINFO_RESPONSE, 256, &[0; 16]));
}

#[test]
fn field_byte_orders_follow_the_c_conversions() {
    let mut state = fixture_state();
    state.webdav_http_port = 0x1234; // htons()
    state.webdav_https_port = 0x5678; // htons()
    state.app_http_port = 0x9abc; // __cpu_to_le16()
    state.wan_ip = Ipv4Addr::new(0x01, 0x02, 0x03, 0x04); // __cpu_to_le32(inet_network())
    state.extend_capabilities = 0x0201; // __cpu_to_le16()
    let response = build_response(Request::GetInfo, &state);
    assert_eq!(&response[278..280], &[0x12, 0x34]);
    assert_eq!(&response[351..353], &[0x56, 0x78]);
    assert_eq!(&response[404..406], &[0xbc, 0x9a]);
    assert_eq!(&response[345..349], &[0x04, 0x03, 0x02, 0x01]);
    assert_eq!(&response[274..276], &[0x01, 0x02]);
    assert_eq!(&response[272..274], &[0x82, 0x80]);

    let response = build_response(Request::FindCapabilities, &state);
    assert_eq!(&response[8..12], &[0x82, 0x80, 0x01, 0x02]);
}

#[test]
fn boundary_macs_and_flags_are_encoded_verbatim() {
    for (mac, label_mac) in [([0; 6], [0xff; 6]), ([0xff; 6], [0; 6])] {
        let mut state = fixture_state();
        state.mac = mac;
        state.label_mac = label_mac;
        state.sw_mode = 0xff;
        state.webdav_mode = 0xff;
        state.ai_home_api_level = 0xff;
        state.app_api_level = 0xff;
        let response = build_response(Request::GetInfo, &state);
        let mut expected = put(GETINFO_RESPONSE, 249, &mac);
        expected = put(expected, 255, &[0xff]);
        expected = put(expected, 277, &[0xff]);
        expected = put(expected, 370, &[0xff]);
        expected = put(expected, 406, &[0xff]);
        expected = put(expected, 472, &label_mac);
        assert_pdu_eq(&response, &expected);

        let response = build_response(Request::FindCapabilities, &state);
        assert_eq!(&response[46..48], &[INFO_TYPE_MAC, 6]);
        assert_eq!(&response[48..54], &mac);
    }
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn getinfo_round_trips_through_the_client_unpacker() {
    let state = fixture_state();
    let mut decoded = unpack_get_info(&build_response(Request::GetInfo, &state)).unwrap();
    decoded.disk_status = state.disk_status.clone();
    decoded.cfg_group = state.cfg_group;
    assert_eq!(decoded, state);

    let mut decoded =
        unpack_get_info(&build_response(Request::GetInfoManufacturing, &state)).unwrap();
    decoded.disk_status = state.disk_status.clone();
    decoded.cfg_group = state.cfg_group;
    decoded.ssid = state.ssid.clone();
    decoded.wave_info = state.wave_info;
    assert_eq!(decoded, state);

    // The hand-written fixture decodes to the same state, so the fixture and
    // the encoder agree independently of each other.
    let mut decoded = unpack_get_info(&GETINFO_RESPONSE).unwrap();
    decoded.disk_status = state.disk_status.clone();
    decoded.cfg_group = state.cfg_group;
    assert_eq!(decoded, state);
}

#[test]
fn find_capabilities_round_trips_through_the_live_probe_walker() {
    let state = fixture_state();
    let (extend_cap, tlvs) =
        unpack_find_cap(&build_response(Request::FindCapabilities, &state)).unwrap();
    assert_eq!(extend_cap, state.extend_capabilities);
    assert_eq!(
        tlvs,
        vec![
            (INFO_TYPE_GROUPID, GROUP_ID.to_vec()),
            (
                INFO_TYPE_PRODUCT_NAME,
                state.product_id.clone().into_bytes()
            ),
            (INFO_TYPE_MAC, state.mac.to_vec()),
        ]
    );
    assert_eq!(decode_group_id(GROUP_ID_HEX), Some(GROUP_ID));
    assert_eq!(probe_group_id(&FIND_CAP_RESPONSE), Some(GROUP_ID));

    let (_, tlvs) = unpack_find_cap(&FIND_CAP_RESPONSE_WITHOUT_GROUP).unwrap();
    assert_eq!(tlvs.len(), 2);
    assert!(tlvs.iter().all(|(kind, _)| *kind != INFO_TYPE_GROUPID));
    assert_eq!(probe_group_id(&FIND_CAP_RESPONSE_WITHOUT_GROUP), None);
}

#[test]
fn extended_round_trip_preserves_transaction_through_encode() {
    for transaction in [[0; 4], [0xff; 4], [0x80, 0x00, 0x00, 0x7f]] {
        let request = put(GETINFO_EX2_BROADCAST_REQUEST, 4, &transaction);
        let parsed = parse_request(&request, DEVICE_MAC).unwrap();
        let response = build_response(parsed, &fixture_state());
        assert_eq!(
            unpack_response_header(&response),
            Some(NET_CMD_ID_GETINFO_EX2)
        );
        assert_eq!(&response[4..8], &transaction);
        assert_eq!(c_string(&response[8..136]), b"ef53:1234!$");
    }
}

/// The exact sequence infosvr-live.py runs against the router.
#[test]
fn discovery_sequence_mirrors_the_live_probe() {
    let state = fixture_state();
    let respond =
        |packet: &[u8]| parse_request(packet, state.mac).map(|r| build_response(r, &state));

    let getinfo = respond(&GETINFO_REQUEST).expect("GETINFO_TIMEOUT");
    assert_eq!(unpack_response_header(&getinfo), Some(NET_CMD_ID_GETINFO));

    assert!(respond(&put(GETINFO_REQUEST, 2, &[0xff, 0xff])).is_none());
    assert!(respond(&GETINFO_REQUEST[..511]).is_none());
    let mut oversized = GETINFO_REQUEST.to_vec();
    oversized.push(0);
    assert!(respond(&oversized).is_none());

    let extended = respond(&GETINFO_EX2_BROADCAST_REQUEST).expect("GETINFO_EX2_TIMEOUT");
    assert_eq!(
        unpack_response_header(&extended),
        Some(NET_CMD_ID_GETINFO_EX2)
    );
    assert_eq!(&extended[4..8], &TRANSACTION);

    let first = respond(&FIND_CAP_REQUEST).expect("FIND_CAP_1_TIMEOUT");
    let second = respond(&FIND_CAP_REQUEST).expect("FIND_CAP_2_TIMEOUT");
    let first_group = probe_group_id(&first).expect("FIND_CAP_GROUP_ID_MISSING");
    let second_group = probe_group_id(&second).expect("FIND_CAP_GROUP_ID_MISSING");
    assert_eq!(first_group, second_group);
}

// ---------------------------------------------------------------------------
// Boundaries
// ---------------------------------------------------------------------------

#[test]
fn fixed_width_strings_keep_a_terminator_at_capacity() {
    // (field, offset, width) from PKT_GET_INFO and STORAGE_INFO_T. Derived
    // for HostName, which storage.c fills with snprintf(sizeof). Inferred
    // for the rest: the C daemon uses strcpy/sprintf into those fields and
    // would overrun them; the port truncates to width - 1 and terminates.
    let fields: [(FieldSetter, usize, usize); 7] = [
        (|s, v| s.printer_info = v, 8, 128),
        (|s, v| s.ssid = v, 136, 32),
        (|s, v| s.netmask = v, 168, 32),
        (|s, v| s.product_id = v, 200, 32),
        (|s, v| s.firmware_version = v, 232, 16),
        (|s, v| s.ddns_hostname = v, 281, 64),
        (|s, v| s.aae_device_id = v, 408, 64),
    ];
    for (set, offset, width) in fields {
        for length in [width - 1, width, width + 1, 4 * width] {
            let mut state = fixture_state();
            set(&mut state, "x".repeat(length));
            let response = build_response(Request::GetInfo, &state);
            let end = offset + width;
            assert_eq!(&response[offset..end - 1], vec![b'x'; width - 1].as_slice());
            assert_eq!(response[end - 1], 0, "offset {offset} length {length}");
            // The neighbouring field is untouched by the overflowing copy.
            assert_eq!(response[end], GETINFO_RESPONSE[end], "offset {offset}");
        }
        // An empty value leaves the whole field zero, as memset did in C.
        let mut state = fixture_state();
        set(&mut state, String::new());
        let response = build_response(Request::GetInfo, &state);
        assert_eq!(&response[offset..offset + width], vec![0; width].as_slice());
    }
}

#[test]
fn ex2_disk_status_is_bounded_by_printer_info() {
    // common.c builds "<fstype>:<free MiB>!$" in prinfo[128] with sprintf and
    // memcpy(strlen()) into PrinterInfo[128]; the port keeps the terminator.
    let mut state = fixture_state();
    for disk_status in ["ef53:1234!$", ":-1!$", "0:0!$", "4d44:1048575!$"] {
        state.disk_status = disk_status.into();
        let response = build_response(
            Request::GetInfoEx2 {
                transaction: TRANSACTION,
            },
            &state,
        );
        assert_eq!(c_string(&response[8..136]), disk_status.as_bytes());
        assert_pdu_eq(
            &response,
            &put(
                put(GETINFO_EX2_RESPONSE, 8, &[0; 128]),
                8,
                disk_status.as_bytes(),
            ),
        );
    }
    state.disk_status = "f".repeat(200);
    let response = build_response(
        Request::GetInfoEx2 {
            transaction: TRANSACTION,
        },
        &state,
    );
    assert_eq!(&response[8..135], vec![b'f'; 127].as_slice());
    assert!(response[135..].iter().all(|byte| *byte == 0));
}

#[test]
fn strings_truncate_at_byte_boundaries_without_utf8_repair() {
    // Sixteen 2-byte characters fill SSID[32]; the copy keeps 31 bytes, so
    // the wire carries a dangling lead byte exactly like strncpy would.
    let mut state = fixture_state();
    state.ssid = "é".repeat(16);
    let response = build_response(Request::GetInfo, &state);
    assert_eq!(&response[136..167], &state.ssid.as_bytes()[..31]);
    assert_eq!(response[166], 0xc3);
    assert_eq!(response[167], 0);
    assert!(std::str::from_utf8(&response[136..167]).is_err());
    assert_eq!(unpack_get_info(&response), None);

    // Embedded NUL ends the C string early. Inferred: strcpy would stop at
    // the NUL and leave zeros; the port copies the remaining bytes as well.
    // No reader looks past the first NUL and no NVRAM value contains one.
    state.ssid = "ab\0cd".into();
    let response = build_response(Request::GetInfo, &state);
    assert_eq!(&response[136..142], b"ab\0cd\0");
    assert_eq!(c_string(&response[136..168]), b"ab");
    assert_eq!(unpack_get_info(&response).unwrap().ssid, "ab");
}

#[test]
fn non_utf8_wire_strings_are_a_c_only_shape() {
    // The C daemon copies whatever bytes NVRAM holds; a Latin-1 printer name
    // is legal on the wire and every C client reads it with strlen-style
    // views, as c_string does here.
    assert_eq!(
        c_string(&GETINFO_RESPONSE_LATIN1_PRINTER[8..136]),
        b"EPSON L3150 \xdcbersicht"
    );
    assert!(std::str::from_utf8(&GETINFO_RESPONSE_LATIN1_PRINTER[8..136]).is_err());
    assert_eq!(unpack_get_info(&GETINFO_RESPONSE_LATIN1_PRINTER), None);
    // Everything after PrinterInfo is untouched by the substitution.
    assert_eq!(
        &GETINFO_RESPONSE_LATIN1_PRINTER[136..],
        &GETINFO_RESPONSE[136..]
    );

    // Inferred: main.rs converts NVRAM lossily to UTF-8, so the port emits
    // the same name UTF-8 encoded: 0xdc becomes 0xc3 0x9c and the rest of
    // the field shifts by one byte. Valid non-ASCII passes through verbatim.
    let mut state = fixture_state();
    state.printer_info = "EPSON L3150 Übersicht".into();
    let response = build_response(Request::GetInfo, &state);
    assert_eq!(&response[8..20], &GETINFO_RESPONSE_LATIN1_PRINTER[8..20]);
    assert_eq!(&response[20..22], &[0xc3, 0x9c]);
    assert_eq!(
        c_string(&response[8..136]),
        "EPSON L3150 Übersicht".as_bytes()
    );
    assert_eq!(&response[136..], &GETINFO_RESPONSE[136..]);
    assert_eq!(
        unpack_get_info(&response).unwrap().printer_info,
        state.printer_info
    );

    // A U+FFFD replacement character, which is what to_string_lossy yields
    // for the Latin-1 byte, is three bytes and still terminates in-field.
    state.ssid = "\u{fffd}".repeat(11);
    let response = build_response(Request::GetInfo, &state);
    assert_eq!(&response[136..166], &state.ssid.as_bytes()[..30]);
    assert_eq!(&response[166..168], &[0xef, 0]);
}

#[test]
fn find_capabilities_tlv_lengths_are_bounded() {
    let mut state = fixture_state();

    // storage_setbuf() stores strlen() in one byte; 255 is the largest value.
    state.product_id = "p".repeat(255);
    let response = build_response(Request::FindCapabilities, &state);
    assert_eq!(&response[34..36], &[INFO_TYPE_PRODUCT_NAME, 255]);
    assert_eq!(&response[36..291], vec![b'p'; 255].as_slice());
    assert_eq!(&response[291..293], &[INFO_TYPE_MAC, 6]);
    assert_eq!(&response[293..299], &DEVICE_MAC);
    assert_eq!(unpack_find_cap(&response).unwrap().1.len(), 3);

    // Inferred: C would overflow its 256-byte scratch buffer; the port clamps.
    state.product_id = "p".repeat(300);
    let clamped = build_response(Request::FindCapabilities, &state);
    assert_pdu_eq(&clamped, &response);

    // Inferred: C skips the copy but still advances two bytes for an empty
    // name; the port emits an explicit zero-length TLV instead.
    state.product_id = String::new();
    let response = build_response(Request::FindCapabilities, &state);
    assert_eq!(&response[34..36], &[INFO_TYPE_PRODUCT_NAME, 0]);
    assert_eq!(&response[36..38], &[INFO_TYPE_MAC, 6]);
    assert_eq!(
        unpack_find_cap(&response).unwrap().1,
        vec![
            (INFO_TYPE_GROUPID, GROUP_ID.to_vec()),
            (INFO_TYPE_PRODUCT_NAME, Vec::new()),
            (INFO_TYPE_MAC, DEVICE_MAC.to_vec()),
        ]
    );

    // Product names are raw bytes on the wire: non-ASCII UTF-8 is copied
    // without a terminator and read back byte for byte.
    state.product_id = "GT-AX11000 Übersicht".into();
    let response = build_response(Request::FindCapabilities, &state);
    assert_eq!(&response[34..36], &[INFO_TYPE_PRODUCT_NAME, 21]);
    assert_eq!(&response[36..57], state.product_id.as_bytes());
    assert_eq!(&response[57..59], &[INFO_TYPE_MAC, 6]);

    // Group IDs are exactly ID_LEN (20) bytes and are copied verbatim.
    state.product_id = "GT-AX11000".into();
    for group in [[0; 20], [0xff; 20], GROUP_ID] {
        state.cfg_group = Some(group);
        let response = build_response(Request::FindCapabilities, &state);
        assert_eq!(&response[12..14], &[INFO_TYPE_GROUPID, 20]);
        assert_eq!(&response[14..34], &group);
        assert_eq!(response[34], INFO_TYPE_PRODUCT_NAME);
        assert_eq!(probe_group_id(&response), Some(group));
    }
}

#[test]
fn live_probe_walker_rejects_malformed_group_tlvs() {
    // A 19-byte group TLV is walked over (the trailing group byte becomes
    // the next type) and the probe reports FIND_CAP_GROUP_ID_MISSING.
    let (_, tlvs) = unpack_find_cap(&FIND_CAP_RESPONSE_SHORT_GROUP).unwrap();
    assert_eq!(tlvs[0], (INFO_TYPE_GROUPID, GROUP_ID[..19].to_vec()));
    assert_eq!(tlvs.len(), 3);
    assert_eq!(probe_group_id(&FIND_CAP_RESPONSE_SHORT_GROUP), None);

    // A 21-byte group TLV is likewise skipped by the probe's exact-length
    // rule even though the walk itself stays in bounds.
    let (_, tlvs) = unpack_find_cap(&FIND_CAP_RESPONSE_LONG_GROUP).unwrap();
    assert_eq!(
        tlvs,
        vec![
            (INFO_TYPE_GROUPID, [GROUP_ID.as_slice(), &[0x3d]].concat()),
            (INFO_TYPE_PRODUCT_NAME, b"GT-AX11000".to_vec()),
            (INFO_TYPE_MAC, DEVICE_MAC.to_vec()),
        ]
    );
    assert_eq!(probe_group_id(&FIND_CAP_RESPONSE_LONG_GROUP), None);

    // A TLV that runs past INFO_PDU_LENGTH is FIND_CAP_TLV_BOUNDS.
    assert_eq!(unpack_find_cap(&FIND_CAP_RESPONSE_TLV_OVERRUN), None);
    assert_eq!(probe_group_id(&FIND_CAP_RESPONSE_TLV_OVERRUN), None);

    // The port can never reach that state: even the longest product name
    // plus group and MAC TLVs end at 299 (12 + 22 + 257 + 8).
    let mut state = fixture_state();
    state.product_id = "p".repeat(255);
    let response = build_response(Request::FindCapabilities, &state);
    assert!(unpack_find_cap(&response).is_some());
    assert!(response[299..].iter().all(|byte| *byte == 0));
}

#[test]
fn mac_text_boundaries() {
    assert_eq!(parse_mac("04:42:1a:0b:0c:0d"), Some(DEVICE_MAC));
    assert_eq!(parse_mac("04:42:1A:0B:0C:0D"), Some(DEVICE_MAC));
    assert_eq!(parse_mac("00:00:00:00:00:00"), Some([0; 6]));
    assert_eq!(parse_mac("ff:ff:ff:ff:ff:ff"), Some([0xff; 6]));
    // Inferred: ether_atoe() in shared/shutils.c is strtoul-based and would
    // accept signs, whitespace and short octets; the port requires exactly
    // six two-digit hexadecimal octets.
    for rejected in [
        "",
        "04:42:1a:0b:0c",
        "04:42:1a:0b:0c:0d:0e",
        "04:42:1a:0b:0c:0d:",
        ":04:42:1a:0b:0c:0d",
        "4:42:1a:0b:0c:0d",
        "004:42:1a:0b:0c:0d",
        "04-42-1a-0b-0c-0d",
        "04:42:1a:0b:0c:0g",
        "04:42:1a:0b:0c: d",
        "+4:42:1a:0b:0c:0d",
        "-4:42:1a:0b:0c:0d",
        "０4:42:1a:0b:0c:0d",
        "04:42:1a:0b:0c:0d\n",
    ] {
        assert_eq!(parse_mac(rejected), None, "{rejected:?}");
    }
}

#[test]
fn group_id_text_boundaries() {
    assert_eq!(decode_group_id(GROUP_ID_HEX), Some(GROUP_ID));
    assert_eq!(
        decode_group_id(&GROUP_ID_HEX.to_ascii_lowercase()),
        Some(GROUP_ID)
    );
    assert_eq!(decode_group_id(&"0".repeat(40)), Some([0; 20]));
    assert_eq!(decode_group_id(&"F".repeat(40)), Some([0xff; 20]));
    // str2hex() lives in the prebuilt libamas-utils.so, so its leniency is
    // unknown; the port accepts exactly 40 hexadecimal digits.
    let rejected = [
        String::new(),
        "0".repeat(39),
        "0".repeat(41),
        "0".repeat(80),
        format!("{}g", "0".repeat(39)),
        format!("{} ", "0".repeat(39)),
        format!("{}\n", "0".repeat(39)),
        "+0".repeat(20),
        "-0".repeat(20),
        // 40 bytes but not 40 ASCII digits: a 2-byte character at the end
        // and twenty 2-byte characters respectively.
        format!("{}é", "0".repeat(38)),
        "é".repeat(20),
        "０".repeat(13) + "0",
    ];
    for value in &rejected {
        assert_eq!(decode_group_id(value), None, "{value:?}");
    }
}
