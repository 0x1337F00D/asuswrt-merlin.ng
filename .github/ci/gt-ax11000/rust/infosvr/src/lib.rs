//! Memory-safe encoder and parser for the legacy ASUS infosvr discovery PDU.

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

pub const PDU_LEN: usize = 512;
pub const SERVER_PORT: u16 = 9999;

const SERVICE_IBOX_INFO: u8 = 12;
const PACKET_COMMAND: u8 = 21;
const PACKET_RESPONSE: u8 = 22;

const CMD_GETINFO: u16 = 31;
const CMD_GETINFO_MANUFACTURING: u16 = 52;
const CMD_GETINFO_EX2: u16 = 53;
const CMD_FIND_CAP: u16 = 54;

const RESPONSE_HEADER_LEN: usize = 8;
const INFO_LEN: usize = 248;
const WAVE_INFO_LEN: usize = 16;
const STORAGE_OFFSET: usize = RESPONSE_HEADER_LEN + INFO_LEN + WAVE_INFO_LEN;
const STORAGE_LEN: usize = 206;

const EXTEND_MAGIC: u16 = 0x8082;
const EXTEND_CAP_WEBDAV: u16 = 0x0001;
const EXTEND_CAP_AMAS: u16 = 0x0008;
const EXTEND_CAP_AAE_BASIC: u16 = 0x0010;
const EXTEND_CAP_SWCTRL: u16 = 0x0040;
const EXTEND_CAP_MASTER: u16 = 0x0080;
const EXTEND_CAP_AMAS_BDL: u16 = 0x0100;
const EXTEND_CAP_ISPCTRL_LOGIN: u16 = 0x0200;

const INFO_TYPE_GROUP_ID: u8 = 1;
const INFO_TYPE_PRODUCT_NAME: u8 = 2;
const INFO_TYPE_MAC: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceState {
    pub printer_info: String,
    pub ssid: String,
    pub netmask: String,
    pub product_id: String,
    pub firmware_version: String,
    pub mac: [u8; 6],
    pub label_mac: [u8; 6],
    pub sw_mode: u8,
    pub wave_info: Option<[u8; WAVE_INFO_LEN]>,
    pub disk_status: String,
    pub extend_capabilities: u16,
    pub enable_webdav: bool,
    pub webdav_mode: u8,
    pub webdav_http_port: u16,
    pub webdav_https_port: u16,
    pub enable_ddns: bool,
    pub ddns_hostname: String,
    pub wan_ip: Ipv4Addr,
    pub is_not_default: bool,
    pub app_http_port: u16,
    pub app_api_level: u8,
    pub enable_aae: bool,
    pub aae_device_id: String,
    pub ai_home_api_level: u8,
    pub cfg_group: Option<[u8; 20]>,
}

impl Default for DeviceState {
    fn default() -> Self {
        Self {
            printer_info: String::new(),
            ssid: String::new(),
            netmask: "255.255.255.0".into(),
            product_id: String::new(),
            firmware_version: String::new(),
            mac: [0; 6],
            label_mac: [0; 6],
            sw_mode: 0,
            wave_info: None,
            disk_status: "0:0!$".into(),
            extend_capabilities: EXTEND_CAP_SWCTRL,
            enable_webdav: false,
            webdav_mode: 0,
            webdav_http_port: 0,
            webdav_https_port: 0,
            enable_ddns: false,
            ddns_hostname: String::new(),
            wan_ip: Ipv4Addr::UNSPECIFIED,
            is_not_default: false,
            app_http_port: 0,
            app_api_level: 1,
            enable_aae: false,
            aae_device_id: String::new(),
            ai_home_api_level: 1,
            cfg_group: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    GetInfo,
    GetInfoManufacturing,
    GetInfoEx2 { transaction: [u8; 4] },
    FindCapabilities,
}

impl Request {
    fn opcode(self) -> u16 {
        match self {
            Self::GetInfo => CMD_GETINFO,
            Self::GetInfoManufacturing => CMD_GETINFO_MANUFACTURING,
            Self::GetInfoEx2 { .. } => CMD_GETINFO_EX2,
            Self::FindCapabilities => CMD_FIND_CAP,
        }
    }
}

/// Parses only the read-only discovery subset. All configuration,
/// authentication and manufacturing command opcodes are rejected.
pub fn parse_request(packet: &[u8], device_mac: [u8; 6]) -> Option<Request> {
    if packet.len() != PDU_LEN || packet[0] != SERVICE_IBOX_INFO || packet[1] != PACKET_COMMAND {
        return None;
    }

    let opcode = u16::from_le_bytes([packet[2], packet[3]]);
    match opcode {
        CMD_GETINFO => Some(Request::GetInfo),
        CMD_GETINFO_MANUFACTURING => Some(Request::GetInfoManufacturing),
        CMD_FIND_CAP => Some(Request::FindCapabilities),
        CMD_GETINFO_EX2 => {
            let target: [u8; 6] = packet.get(8..14)?.try_into().ok()?;
            let broadcast = [0xff; 6];
            let unspecified = [0; 6];
            if target != device_mac && target != broadcast && target != unspecified {
                return None;
            }
            Some(Request::GetInfoEx2 {
                transaction: packet.get(4..8)?.try_into().ok()?,
            })
        }
        _ => None,
    }
}

pub fn build_response(request: Request, state: &DeviceState) -> [u8; PDU_LEN] {
    let mut response = [0_u8; PDU_LEN];
    response[0] = SERVICE_IBOX_INFO;
    response[1] = PACKET_RESPONSE;
    response[2..4].copy_from_slice(&request.opcode().to_le_bytes());

    if let Request::GetInfoEx2 { transaction } = request {
        response[4..8].copy_from_slice(&transaction);
    }

    match request {
        Request::GetInfo => {
            encode_device_info(&mut response, state, true);
            if let Some(wave_info) = state.wave_info {
                response[RESPONSE_HEADER_LEN + INFO_LEN..STORAGE_OFFSET]
                    .copy_from_slice(&wave_info);
            }
            encode_storage(&mut response, state);
        }
        Request::GetInfoManufacturing => {
            encode_device_info(&mut response, state, false);
            encode_storage(&mut response, state);
        }
        Request::GetInfoEx2 { .. } => {
            put_c_string(
                &mut response[RESPONSE_HEADER_LEN..RESPONSE_HEADER_LEN + 128],
                &state.disk_status,
            );
        }
        Request::FindCapabilities => encode_find_capabilities(&mut response, state),
    }

    response
}

fn encode_device_info(response: &mut [u8; PDU_LEN], state: &DeviceState, include_ssid: bool) {
    let mut offset = RESPONSE_HEADER_LEN;
    put_c_string(&mut response[offset..offset + 128], &state.printer_info);
    offset += 128;
    if include_ssid {
        put_c_string(&mut response[offset..offset + 32], &state.ssid);
    }
    offset += 32;
    put_c_string(&mut response[offset..offset + 32], &state.netmask);
    offset += 32;
    put_c_string(&mut response[offset..offset + 32], &state.product_id);
    offset += 32;
    put_c_string(&mut response[offset..offset + 16], &state.firmware_version);
    offset += 16;

    // OperationMode remains zero for compatibility with the non-WCLIENT build.
    offset += 1;
    response[offset..offset + 6].copy_from_slice(&state.mac);
    offset += 6;
    response[offset] = state.sw_mode;
}

fn encode_storage(response: &mut [u8; PDU_LEN], state: &DeviceState) {
    debug_assert_eq!(STORAGE_OFFSET + STORAGE_LEN, 478);
    let storage = &mut response[STORAGE_OFFSET..STORAGE_OFFSET + STORAGE_LEN];

    storage[0..2].copy_from_slice(&EXTEND_MAGIC.to_le_bytes());
    storage[2..4].copy_from_slice(&state.extend_capabilities.to_le_bytes());

    // Packed WEBDAV_INFO_T at the beginning of the 128-byte union.
    let union = &mut storage[4..132];
    union[0] = u8::from(state.enable_webdav);
    union[1] = state.webdav_mode;
    union[2..4].copy_from_slice(&state.webdav_http_port.to_be_bytes());
    union[4] = u8::from(state.enable_ddns);
    put_c_string(&mut union[5..69], &state.ddns_hostname);
    union[69..73].copy_from_slice(&u32::from(state.wan_ip).to_le_bytes());
    union[74] = u8::from(state.is_not_default);
    union[75..77].copy_from_slice(&state.webdav_https_port.to_be_bytes());

    // DEVICE_INFO_T: WEBDAV (77), HWCTRL (16), then SWCTRL.
    union[94] = state.ai_home_api_level;

    storage[132..134].copy_from_slice(&state.app_http_port.to_le_bytes());
    storage[134] = state.app_api_level;
    storage[135] = u8::from(state.enable_aae);
    put_c_string(&mut storage[136..200], &state.aae_device_id);
    storage[200..206].copy_from_slice(&state.label_mac);
}

fn encode_find_capabilities(response: &mut [u8; PDU_LEN], state: &DeviceState) {
    response[8..10].copy_from_slice(&EXTEND_MAGIC.to_le_bytes());
    response[10..12].copy_from_slice(&state.extend_capabilities.to_le_bytes());

    let mut cursor = 12;
    if let Some(group) = state.cfg_group {
        cursor = append_tlv(response, cursor, INFO_TYPE_GROUP_ID, &group);
    }
    cursor = append_tlv(
        response,
        cursor,
        INFO_TYPE_PRODUCT_NAME,
        state.product_id.as_bytes(),
    );
    let _ = append_tlv(response, cursor, INFO_TYPE_MAC, &state.mac);
}

fn append_tlv(response: &mut [u8; PDU_LEN], cursor: usize, kind: u8, value: &[u8]) -> usize {
    let value_len = value.len().min(u8::MAX as usize);
    let end = cursor.saturating_add(2).saturating_add(value_len);
    if end > response.len() {
        return cursor;
    }
    response[cursor] = kind;
    response[cursor + 1] = value_len as u8;
    response[cursor + 2..end].copy_from_slice(&value[..value_len]);
    end
}

fn put_c_string(destination: &mut [u8], value: &str) {
    if destination.is_empty() {
        return;
    }
    let source = value.as_bytes();
    let length = source.len().min(destination.len() - 1);
    destination[..length].copy_from_slice(&source[..length]);
    destination[length] = 0;
}

pub fn calculate_capabilities(
    webdav: bool,
    aae: bool,
    amas: bool,
    amas_bundle: bool,
    master: bool,
    isp_control: bool,
) -> u16 {
    let mut capabilities = EXTEND_CAP_SWCTRL;
    if webdav {
        capabilities |= EXTEND_CAP_WEBDAV;
    }
    if aae {
        capabilities |= EXTEND_CAP_AAE_BASIC;
    }
    if amas {
        capabilities |= EXTEND_CAP_AMAS;
    }
    if amas_bundle {
        capabilities |= EXTEND_CAP_AMAS_BDL;
    }
    if master {
        capabilities |= EXTEND_CAP_MASTER;
    }
    if isp_control {
        capabilities |= EXTEND_CAP_ISPCTRL_LOGIN;
    }
    capabilities
}

pub fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let mut mac = [0_u8; 6];
    let mut parts = value.split(':');
    for byte in &mut mac {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(mac)
}

pub fn decode_group_id(value: &str) -> Option<[u8; 20]> {
    if value.len() != 40 || !value.is_ascii() {
        return None;
    }
    let mut group = [0_u8; 20];
    for (index, byte) in group.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16).ok()?;
    }
    Some(group)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(opcode: u16) -> [u8; PDU_LEN] {
        let mut packet = [0_u8; PDU_LEN];
        packet[0] = SERVICE_IBOX_INFO;
        packet[1] = PACKET_COMMAND;
        packet[2..4].copy_from_slice(&opcode.to_le_bytes());
        packet
    }

    fn state() -> DeviceState {
        DeviceState {
            printer_info: "ASUS Printer".into(),
            ssid: "test-ssid".into(),
            netmask: "255.255.255.0".into(),
            product_id: "GT-AX11000".into(),
            firmware_version: "3006.102.8".into(),
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            label_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            sw_mode: 1,
            extend_capabilities: calculate_capabilities(true, true, true, false, true, false),
            cfg_group: Some([0x42; 20]),
            ..DeviceState::default()
        }
    }

    #[test]
    fn accepts_read_only_commands_and_rejects_mutating_commands() {
        let state = state();
        assert_eq!(
            parse_request(&request(CMD_GETINFO), state.mac),
            Some(Request::GetInfo)
        );
        assert_eq!(parse_request(&request(34), state.mac), None);
        assert_eq!(parse_request(&request(51), state.mac), None);
    }

    #[test]
    fn rejects_every_unimplemented_opcode() {
        let state = state();
        for opcode in u16::MIN..=u16::MAX {
            if matches!(
                opcode,
                CMD_GETINFO | CMD_GETINFO_MANUFACTURING | CMD_GETINFO_EX2 | CMD_FIND_CAP
            ) {
                continue;
            }
            assert_eq!(parse_request(&request(opcode), state.mac), None);
        }
    }

    #[test]
    fn rejects_wrong_size_and_header() {
        let state = state();
        assert_eq!(parse_request(&[], state.mac), None);
        assert_eq!(parse_request(&request(CMD_GETINFO)[..511], state.mac), None);
        let mut oversized = request(CMD_GETINFO).to_vec();
        oversized.push(0);
        assert_eq!(parse_request(&oversized, state.mac), None);
        let mut packet = request(CMD_GETINFO);
        packet[0] = 0;
        assert_eq!(parse_request(&packet, state.mac), None);
    }

    #[test]
    fn extended_request_validates_target_mac() {
        let state = state();
        let mut packet = request(CMD_GETINFO_EX2);
        packet[4..8].copy_from_slice(&[1, 2, 3, 4]);
        packet[8..14].copy_from_slice(&state.mac);
        assert_eq!(
            parse_request(&packet, state.mac),
            Some(Request::GetInfoEx2 {
                transaction: [1, 2, 3, 4]
            })
        );
        packet[8..14].copy_from_slice(&[1, 1, 1, 1, 1, 1]);
        assert_eq!(parse_request(&packet, state.mac), None);
    }

    #[test]
    fn getinfo_response_preserves_wire_offsets() {
        let state = state();
        let response = build_response(Request::GetInfo, &state);
        assert_eq!(response.len(), PDU_LEN);
        assert_eq!(&response[2..4], &CMD_GETINFO.to_le_bytes());
        assert_eq!(&response[136..145], b"test-ssid");
        assert_eq!(&response[200..210], b"GT-AX11000");
        assert_eq!(&response[249..255], &state.mac);
        assert_eq!(response[255], 1);
        assert_eq!(&response[STORAGE_OFFSET..STORAGE_OFFSET + 2], &[0x82, 0x80]);
        assert_eq!(
            &response[STORAGE_OFFSET + 200..STORAGE_OFFSET + 206],
            &state.label_mac
        );
    }

    #[test]
    fn strings_are_truncated_and_terminated() {
        let mut state = state();
        state.ssid = "x".repeat(100);
        let response = build_response(Request::GetInfo, &state);
        assert_eq!(&response[136..167], vec![b'x'; 31].as_slice());
        assert_eq!(response[167], 0);
    }

    #[test]
    fn find_capabilities_tlvs_are_bounded() {
        let state = state();
        let response = build_response(Request::FindCapabilities, &state);
        assert_eq!(&response[8..10], &[0x82, 0x80]);
        assert_eq!(response[12], INFO_TYPE_GROUP_ID);
        assert_eq!(response[13], 20);
        assert_eq!(&response[14..34], &[0x42; 20]);
        assert_eq!(response[34], INFO_TYPE_PRODUCT_NAME);
    }

    #[test]
    fn parser_never_panics_for_short_inputs() {
        let state = state();
        let packet = request(CMD_GETINFO);
        for length in 0..PDU_LEN {
            assert_eq!(parse_request(&packet[..length], state.mac), None);
        }
    }

    #[test]
    fn parses_mac_and_group_id_strictly() {
        assert_eq!(
            parse_mac("00:11:22:33:44:55"),
            Some([0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(parse_mac("00:11:22:33:44"), None);
        assert_eq!(decode_group_id(&"ab".repeat(20)), Some([0xab; 20]));
        assert_eq!(decode_group_id("ab"), None);
    }
}
