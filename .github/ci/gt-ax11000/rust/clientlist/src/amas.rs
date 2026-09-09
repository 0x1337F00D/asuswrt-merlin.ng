//! AiMesh inputs: RE client details from `/tmp/clientlist.json` and the
//! CAP/RE node types the DB view derives `amesh_isRe` from.

use crate::json::{self, Value};
use crate::nvram::KeyedList;

/// Maximum accepted size of `/tmp/clientlist.json`.
pub const MAX_RE_CLIENT_FILE: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReDetail {
    pub is_wl: u8,
    pub rssi: String,
    pub pap_mac: String,
}

/// Map an AiMesh band label (`2G`, `5G_1`, `5G1`, `6G`...) to the `isWL`
/// number used by `get_amas_re_client_detail_info()` (web.c:9951-10034).
pub fn band_is_wl(band: &str) -> u8 {
    let prefix = band.split('_').next().unwrap_or("");
    match prefix {
        "2G" => 1,
        "5G" => 2,
        "5G1" => 3,
        "6G" => 4,
        "6G1" => 5,
        _ => 0,
    }
}

/// `get_amas_re_client_detail_info()`: the document is
/// `{papMac: {band: {clientMac: {"rssi": ...}}}}`; each client with an
/// `rssi` value is keyed `<clientMac>_<isWL>_<papMac>`. Anything malformed
/// yields no details, as the json-c reader would.
pub fn parse_re_client_details(document: &[u8]) -> KeyedList<ReDetail> {
    let mut list = KeyedList::new();
    let Ok(Value::Object(paps)) = json::parse(document) else {
        return list;
    };
    for (pap_mac, bands) in paps.iter() {
        let Some(bands) = bands.as_object() else {
            continue;
        };
        for (band, clients) in bands.iter() {
            let Some(clients) = clients.as_object() else {
                continue;
            };
            let is_wl = band_is_wl(band);
            for (client_mac, detail) in clients.iter() {
                let Some(rssi) = detail.as_object().and_then(|detail| detail.get("rssi")) else {
                    continue;
                };
                let key = format!("{client_mac}_{is_wl}_{pap_mac}");
                list.set(
                    &key,
                    ReDetail {
                        is_wl,
                        rssi: rssi.c_string(),
                        pap_mac: pap_mac.to_owned(),
                    },
                );
            }
        }
    }
    list
}

/// AiMesh node types as passed from C: `MAC>CAP<MAC>RE<...` built from the
/// `get_amas_info()` result (web.c:9744-9950 sets `type` to `CAP` for index 0
/// and `RE` otherwise). The value is the type string.
pub fn parse_node_types(value: &str) -> KeyedList<String> {
    let mut list = KeyedList::new();
    if value.is_empty() {
        return list;
    }
    for record in value.split('<') {
        let mut fields = record.split('>');
        let (Some(mac), Some(node_type)) = (fields.next(), fields.next()) else {
            continue;
        };
        if mac.is_empty() {
            continue;
        }
        list.set(mac, node_type.to_owned());
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_details_are_keyed_by_mac_band_and_pap() {
        let document = br#"{"AA:BB:CC:DD:EE:F0":{"2G_1":{"AA:BB:CC:DD:EE:01":{"rssi":-40}},"5G":{"AA:BB:CC:DD:EE:02":{"rssi":"-55","x":1},"AA:BB:CC:DD:EE:03":{}},"wired":{"AA:BB:CC:DD:EE:04":{"rssi":0}},"_5G":{"AA:BB:CC:DD:EE:05":{"rssi":1}}},"bad":1}"#;
        let list = parse_re_client_details(document);
        assert_eq!(list.len(), 4);
        let one = list.get("AA:BB:CC:DD:EE:01_1_AA:BB:CC:DD:EE:F0").unwrap();
        assert_eq!(one.rssi, "-40");
        assert_eq!(one.is_wl, 1);
        assert_eq!(one.pap_mac, "AA:BB:CC:DD:EE:F0");
        assert_eq!(
            list.get("AA:BB:CC:DD:EE:02_2_AA:BB:CC:DD:EE:F0")
                .unwrap()
                .rssi,
            "-55"
        );
        assert!(list.contains_key("AA:BB:CC:DD:EE:04_0_AA:BB:CC:DD:EE:F0"));
        assert!(list.contains_key("AA:BB:CC:DD:EE:05_0_AA:BB:CC:DD:EE:F0"));
        assert!(parse_re_client_details(b"[]").is_empty());
        assert!(parse_re_client_details(b"{").is_empty());
    }

    #[test]
    fn band_prefixes() {
        assert_eq!(band_is_wl("2G"), 1);
        assert_eq!(band_is_wl("5G_3"), 2);
        assert_eq!(band_is_wl("5G1_2"), 3);
        assert_eq!(band_is_wl("6G"), 4);
        assert_eq!(band_is_wl("6G1"), 5);
        assert_eq!(band_is_wl(""), 0);
        assert_eq!(band_is_wl("_2G"), 0);
    }

    #[test]
    fn node_types() {
        let list = parse_node_types("AA:BB:CC:DD:EE:F0>CAP<AA:BB:CC:DD:EE:F1>RE<>x<broken");
        assert_eq!(list.len(), 2);
        assert_eq!(
            list.get("AA:BB:CC:DD:EE:F1").map(String::as_str),
            Some("RE")
        );
        assert!(parse_node_types("").is_empty());
    }
}
