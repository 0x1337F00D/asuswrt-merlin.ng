//! The client data model built from a shared-memory snapshot and the typed
//! NVRAM/AiMesh inputs.
//!
//! `ClientList::build()` reproduces `get_client_detail_info()` (web.c
//! 10347-10791 at `6be5bc84b50`, as shifted by the overlay patches) for the
//! GT-AX11000 build flags: `RTCONFIG_AMAS=y`, `RTCONFIG_IPV6=y`, no
//! `RTCONFIG_PERMISSION_MANAGEMENT`, `RTCONFIG_MULTILAN_CFG`, `RTCONFIG_MLO`
//! or `RTCONFIG_STA_AP_BAND_BIND`.

use crate::amas::ReDetail;
use crate::json::{Object, Value};
use crate::layout::{FLAG_AIBOARD, FLAG_ASUS, FLAG_HTTP, FLAG_ITUNE, FLAG_PRINTER};
use crate::nvram::{self, CustomClient, InternetAccess, KeyedList, LocalTime, MultifilterInputs};
use crate::snapshot::{RawClient, Snapshot};

/// `LINE_SIZE` bound of the sanitised name buffer in C; the source buffer is
/// 32 bytes, so 31 bytes survive `strlcpy()`.
const NAME_SOURCE_LIMIT: usize = 31;

/// Inputs of one live client-list build.
pub struct BuildInputs<'a> {
    pub lan_ipaddr: &'a str,
    pub login_ip_str: &'a str,
    pub rog_clientlist: &'a str,
    pub custom_clientlist: &'a str,
    pub qos_rulelist: &'a str,
    pub wtf_rulelist: &'a str,
    pub multifilter: MultifilterInputs<'a>,
    /// `is_amas_support()`
    pub amas_support: bool,
    pub now: LocalTime,
    /// Parsed `/tmp/clientlist.json` (empty when unavailable).
    pub re_details: &'a KeyedList<ReDetail>,
    /// `is_re_node(mac, 1)`; only consulted when `amas_support` is set.
    pub is_re_node: &'a dyn Fn(&str) -> bool,
}

/// `internetState` keeps the C type quirk: the default is the JSON string
/// `"1"`, a MULTIFILTER match replaces it with a JSON integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternetState {
    Default,
    Int(i32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    pub client_type: String,
    pub default_type: String,
    pub name: String,
    pub nick_name: String,
    pub ip: String,
    pub ip6: String,
    pub ip6_prefix: String,
    pub mac: String,
    pub mac_repeat: usize,
    pub is_gateway: bool,
    pub is_asus: bool,
    pub is_web_server: bool,
    pub is_printer: bool,
    pub is_itunes: bool,
    pub is_aiboard: bool,
    pub dpi_device: String,
    pub vendor: String,
    pub is_wl: u8,
    pub is_gn: String,
    pub is_online: String,
    pub ssid: String,
    pub is_login: bool,
    pub op_mode: u8,
    pub rssi: String,
    pub cur_tx: String,
    pub cur_rx: String,
    pub wl_connect_time: String,
    pub wl_auth: String,
    pub ip_method: String,
    pub rog: bool,
    pub callback: String,
    pub keeparp: String,
    pub qos_level: String,
    pub wtfast: String,
    pub internet_mode: String,
    pub internet_state: InternetState,
    pub amesh_is_re: bool,
    pub amesh_pap_mac: Option<String>,
    /// `amesh_bind_mac`/`amesh_bind_band` are emitted under
    /// `is_amas_support()`.
    pub amesh_bind: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientList {
    /// MAC → client with json-c replace-in-place semantics for duplicates.
    pub clients: KeyedList<Client>,
    /// `maclist`: every appended MAC in discovery order, duplicates kept.
    pub maclist: Vec<String>,
}

/// `web.c:10469-10485`: only ASCII alphanumerics, space, `-`, `_`, `(` and
/// `)` survive; every other byte (including UTF-8 sequences) becomes a space.
pub fn sanitize_name(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(NAME_SOURCE_LIMIT)
        .map(|byte| match byte {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b' ' | b'-' | b'_' | b'(' | b')' => {
                char::from(*byte)
            }
            _ => ' ',
        })
        .collect()
}

pub fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub fn format_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// `isMAC()` (web.c:5265-5283).
pub fn is_mac(text: &str) -> bool {
    let mut digits = 0_i32;
    let mut separators = 0_i32;
    for byte in text.bytes() {
        if byte.is_ascii_hexdigit() {
            digits += 1;
        } else if byte == b':' {
            if digits == 0 || digits / 2 - 1 != separators {
                break;
            }
            separators += 1;
        } else {
            separators = -1;
        }
    }
    digits == 12 && separators == 5
}

fn flag(device_flag: u8, bit: u8) -> bool {
    device_flag & (1 << bit) != 0
}

impl Client {
    fn from_raw(
        raw: &RawClient,
        mac: String,
        mac_repeat: usize,
        inputs: &BuildInputs<'_>,
    ) -> Client {
        let source = if raw.user_define.first().is_some_and(|byte| *byte != 0) {
            &raw.user_define
        } else {
            &raw.device_name
        };
        let ip = format_ip(raw.ip_addr);
        let client_type = raw.client_type.to_string();
        Client {
            default_type: client_type.clone(),
            client_type,
            name: sanitize_name(source),
            nick_name: String::new(),
            is_gateway: inputs.lan_ipaddr == ip,
            is_login: inputs.login_ip_str == ip,
            ip,
            ip6: raw.ip6_addr.as_deref().map(lossy).unwrap_or_default(),
            ip6_prefix: raw.ip6_prefix.as_deref().map(lossy).unwrap_or_default(),
            mac,
            mac_repeat,
            is_asus: flag(raw.device_flag, FLAG_ASUS),
            is_web_server: flag(raw.device_flag, FLAG_HTTP),
            is_printer: flag(raw.device_flag, FLAG_PRINTER),
            is_itunes: flag(raw.device_flag, FLAG_ITUNE),
            is_aiboard: flag(raw.device_flag, FLAG_AIBOARD),
            dpi_device: lossy(&raw.apple_model),
            vendor: lossy(&raw.vendor_name),
            is_wl: raw.wireless,
            is_gn: raw.guest_network.as_deref().map(lossy).unwrap_or_default(),
            is_online: if inputs.amas_support {
                raw.online.to_string()
            } else {
                "1".to_owned()
            },
            ssid: lossy(&raw.ssid),
            op_mode: raw.op_mode,
            rssi: raw.rssi.to_string(),
            cur_tx: lossy(&raw.txrate),
            cur_rx: lossy(&raw.rxrate),
            wl_connect_time: lossy(&raw.conn_time),
            wl_auth: raw.wireless_auth.as_deref().map(lossy).unwrap_or_default(),
            ip_method: lossy(&raw.ip_method),
            rog: false,
            callback: String::new(),
            keeparp: String::new(),
            qos_level: String::new(),
            wtfast: "0".to_owned(),
            internet_mode: "allow".to_owned(),
            internet_state: InternetState::Default,
            amesh_is_re: false,
            amesh_pap_mac: None,
            amesh_bind: inputs.amas_support,
        }
    }

    fn apply_custom(&mut self, custom: &CustomClient) {
        let custom_type = custom.client_type.to_string();
        if custom_type != "0" {
            self.client_type = custom_type;
        }
        self.nick_name = custom.name.clone();
        self.callback = custom.callback.clone();
        self.keeparp = custom.keeparp.clone();
    }

    fn apply_internet_access(&mut self, access: &InternetAccess) {
        self.internet_mode = access.mode.to_owned();
        self.internet_state = InternetState::Int(access.state);
    }

    /// Per-client JSON object in the exact C emission order (web.c
    /// 10620-10760 as patched by the overlay).
    pub fn to_object(&self) -> Object {
        let yes_no = |value: bool| if value { "1" } else { "0" };
        let mut object = Object::with_capacity(48);
        object.push("type", Value::string(&self.client_type));
        object.push("defaultType", Value::string(&self.default_type));
        object.push("name", Value::string(&self.name));
        object.push("nickName", Value::string(&self.nick_name));
        object.push("ip", Value::string(&self.ip));
        object.push("ip6", Value::string(&self.ip6));
        object.push("ip6_prefix", Value::string(&self.ip6_prefix));
        object.push("mac", Value::string(&self.mac));
        object.push("from", Value::string("networkmapd"));
        object.push("macRepeat", Value::String(self.mac_repeat.to_string()));
        object.push("isGateway", Value::string(yes_no(self.is_gateway)));
        object.push("isASUS", Value::string(yes_no(self.is_asus)));
        object.push("isWebServer", Value::string(yes_no(self.is_web_server)));
        object.push("isPrinter", Value::string(yes_no(self.is_printer)));
        object.push("isITunes", Value::string(yes_no(self.is_itunes)));
        object.push("isAiBoard", Value::string(yes_no(self.is_aiboard)));
        object.push("dpiType", Value::string(""));
        object.push("dpiDevice", Value::string(&self.dpi_device));
        object.push("vendor", Value::string(&self.vendor));
        object.push("isWL", Value::String(self.is_wl.to_string()));
        object.push("isGN", Value::string(&self.is_gn));
        object.push("isOnline", Value::string(&self.is_online));
        object.push("ssid", Value::string(&self.ssid));
        object.push("isLogin", Value::string(yes_no(self.is_login)));
        object.push("opMode", Value::String(self.op_mode.to_string()));
        object.push("rssi", Value::string(&self.rssi));
        object.push("curTx", Value::string(&self.cur_tx));
        object.push("curRx", Value::string(&self.cur_rx));
        object.push("totalTx", Value::string(""));
        object.push("totalRx", Value::string(""));
        object.push("wlConnectTime", Value::string(&self.wl_connect_time));
        object.push("wlAuth", Value::string(&self.wl_auth));
        object.push("ipMethod", Value::string(&self.ip_method));
        object.push("ROG", Value::string(yes_no(self.rog)));
        object.push("group", Value::string(""));
        object.push("callback", Value::string(&self.callback));
        object.push("keeparp", Value::string(&self.keeparp));
        object.push("qosLevel", Value::string(&self.qos_level));
        object.push("wtfast", Value::string(&self.wtfast));
        object.push("internetMode", Value::string(&self.internet_mode));
        object.push(
            "internetState",
            match self.internet_state {
                InternetState::Default => Value::string("1"),
                InternetState::Int(state) => Value::int(i64::from(state)),
            },
        );
        if self.amesh_is_re {
            object.push("amesh_isRe", Value::string("1"));
        }
        if let Some(pap_mac) = &self.amesh_pap_mac {
            object.push("amesh_isReClient", Value::string("1"));
            object.push("amesh_papMac", Value::string(pap_mac));
        }
        if self.amesh_bind {
            object.push("amesh_bind_mac", Value::string(""));
            object.push("amesh_bind_band", Value::string("0"));
        }
        object
    }
}

impl ClientList {
    /// Build the live list from a decoded snapshot.
    pub fn build(snapshot: &Snapshot, inputs: &BuildInputs<'_>) -> ClientList {
        let custom = nvram::parse_custom_clientlist(inputs.custom_clientlist);
        let qos = nvram::parse_qos_rulelist(inputs.qos_rulelist);
        let wtf = nvram::parse_wtf_rulelist(inputs.wtf_rulelist);
        let multifilter = nvram::parse_multifilter(inputs.multifilter, inputs.now);
        let mut list = ClientList::default();

        for raw in &snapshot.clients {
            let mac = format_mac(raw.mac_addr);
            if inputs.amas_support && (inputs.is_re_node)(&mac) {
                continue;
            }
            let mac_repeat = list.maclist.iter().filter(|entry| **entry == mac).count();
            let mut client = Client::from_raw(raw, mac.clone(), mac_repeat, inputs);

            if inputs.rog_clientlist.contains(&mac) {
                client.rog = true;
                client.client_type = "36".to_owned();
                client.default_type = "36".to_owned();
            }
            if let Some(custom) = custom.get(&mac) {
                client.apply_custom(custom);
            }
            if let Some(level) = qos.get(&mac) {
                client.qos_level = level.clone();
            }
            if let Some(status) = wtf.get(&mac) {
                client.wtfast = status.to_string();
            }
            if let Some(access) = multifilter.get(&mac) {
                client.apply_internet_access(access);
            }

            if inputs.amas_support {
                if raw.is_re.as_deref() == Some(b"1") {
                    client.amesh_is_re = true;
                }
                if let Some(pap_mac) = raw
                    .pap_mac
                    .as_deref()
                    .map(lossy)
                    .filter(|value| is_mac(value))
                {
                    if client.is_wl != 0 {
                        let key = format!("{mac}_{}_{pap_mac}", client.is_wl);
                        if let Some(detail) = inputs.re_details.get(&key) {
                            client.rssi = detail.rssi.clone();
                        }
                    }
                    client.amesh_pap_mac = Some(pap_mac);
                }
                if client.is_online == "1" {
                    list.maclist.push(mac.clone());
                }
            } else {
                list.maclist.push(mac.clone());
            }
            list.clients.set(&mac, client);
        }
        list
    }

    /// Top-level document of `ej_get_clientlist()`/`get_clientlist_ex()`:
    /// every client keyed by MAC, then `maclist`, then `ClientAPILevel`.
    pub fn to_document(&self) -> Object {
        let mut document = Object::with_capacity(self.clients.len() + 2);
        for (mac, client) in self.clients.iter() {
            document.push(mac, Value::Object(client.to_object()));
        }
        document.set(
            "maclist",
            Value::Array(self.maclist.iter().map(|mac| Value::string(mac)).collect()),
        );
        document.set("ClientAPILevel", Value::string(crate::CLIENT_API_LEVEL));
        document
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizer_matches_the_c_character_class() {
        assert_eq!(sanitize_name(b"My-PC_(1) ok"), "My-PC_(1) ok");
        assert_eq!(sanitize_name("Caf\u{e9}!".as_bytes()), "Caf   ");
        assert_eq!(sanitize_name(b"a\tb\"c"), "a b c");
        assert_eq!(sanitize_name(&[b'x'; 40]).len(), 31);
    }

    #[test]
    fn is_mac_matches_web_c() {
        assert!(is_mac("AA:BB:CC:DD:EE:FF"));
        assert!(is_mac("aa:bb:cc:dd:ee:ff"));
        assert!(!is_mac(""));
        assert!(!is_mac("AA:BB:CC:DD:EE"));
        assert!(!is_mac("AABBCCDDEEFF"));
        assert!(!is_mac("AA:BB:CC:DD:EE:FG"));
        assert!(!is_mac("AA-BB-CC-DD-EE-FF"));
    }

    #[test]
    fn mac_and_ip_formatting() {
        assert_eq!(
            format_mac([0xaa, 0x0b, 0xcc, 0xdd, 0xee, 0x0f]),
            "AA:0B:CC:DD:EE:0F"
        );
        assert_eq!(format_ip([192, 168, 50, 1]), "192.168.50.1");
    }
}
