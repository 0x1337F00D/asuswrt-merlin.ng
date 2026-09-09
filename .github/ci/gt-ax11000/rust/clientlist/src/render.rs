//! JSON renderers for every httpd client-list consumer.
//!
//! Each function names the C handler it replaces (web.c at `6be5bc84b50`,
//! vendor line numbers). Output is bounded by [`MAX_OUTPUT`]; an oversized
//! document is an error, never a truncated JSON text.

use crate::amas;
use crate::json::{self, Object, Value};
use crate::model::ClientList;
use crate::nvram::{self, c_atoi, KeyedList};

/// Upper bound of any rendered document (255 clients with maximal escaped
/// fields stay well below this; the persistent DB is limited to 256 KiB by
/// the daemon).
pub const MAX_OUTPUT: usize = 1024 * 1024;
/// Upper bound of `/jffs/nmp_cl_json.js` (`NCL_LIMIT` is 262,144 bytes).
pub const MAX_DATABASE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// The document would exceed [`MAX_OUTPUT`] or the caller's buffer.
    Oversized,
    Serialize,
}

pub fn document_to_string(document: &Object, capacity: usize) -> Result<String, RenderError> {
    let text =
        json::to_string(&Value::Object(document.clone())).map_err(|_| RenderError::Serialize)?;
    if text.len() > MAX_OUTPUT || text.len() > capacity {
        return Err(RenderError::Oversized);
    }
    Ok(text)
}

fn value_to_string(value: &Value, capacity: usize) -> Result<String, RenderError> {
    let text = json::to_string(value).map_err(|_| RenderError::Serialize)?;
    if text.len() > MAX_OUTPUT || text.len() > capacity {
        return Err(RenderError::Oversized);
    }
    Ok(text)
}

/// `{"maclist": [], "ClientAPILevel":"7"}` exactly as `ej_get_clientlist()`
/// writes it when networkmap is not running (web.c:10812).
pub fn empty_document() -> String {
    format!(
        "{{\"maclist\": [], \"ClientAPILevel\":\"{}\"}}",
        crate::CLIENT_API_LEVEL
    )
}

/// `ej_get_clientlist()`/`get_clientlist_ex()` live document.
pub fn render_live(list: &ClientList, capacity: usize) -> Result<String, RenderError> {
    document_to_string(&list.to_document(), capacity)
}

/// `get_client_name()` (web.c:43306-43339): scan the top-level objects of a
/// rendered/cached document for `ip`; the last match wins, `nickName` is
/// preferred over `name`, and the IP itself is the fallback.
pub fn name_for_ip(document: &[u8], ip: &str) -> Option<String> {
    let Ok(Value::Object(clients)) = json::parse(document) else {
        return None;
    };
    let mut name = None;
    for (_, client) in clients.iter() {
        let Some(client) = client.as_object() else {
            continue;
        };
        let Some(client_ip) = client.get("ip") else {
            continue;
        };
        if client_ip.c_string() != ip {
            continue;
        }
        let mut chosen = ip.to_owned();
        if let Some(value) = client
            .get("name")
            .map(Value::c_string)
            .filter(|value| !value.is_empty())
        {
            chosen = value;
        }
        if let Some(value) = client
            .get("nickName")
            .map(Value::c_string)
            .filter(|value| !value.is_empty())
        {
            chosen = value;
        }
        name = Some(chosen);
    }
    name
}

/// `get_sdn_client_num()` (web.c:41876-41900): count online clients per
/// `sdn_idx`; `isOnline` must be a string other than `"0"`.
pub fn sdn_client_counts(document: &[u8], counts: &mut [i32]) -> bool {
    let Ok(Value::Object(clients)) = json::parse(document) else {
        return false;
    };
    for (_, client) in clients.iter() {
        let Some(client) = client.as_object() else {
            continue;
        };
        let (Some(sdn_idx), Some(is_online)) = (client.get("sdn_idx"), client.get("isOnline"))
        else {
            continue;
        };
        let Some(is_online) = is_online.as_str() else {
            continue;
        };
        if is_online == "0" {
            continue;
        }
        let index = c_atoi(&sdn_idx.c_string());
        if index >= 0 {
            if let Some(slot) = counts.get_mut(index as usize) {
                *slot = slot.saturating_add(1);
            }
        }
    }
    true
}

pub struct DatabaseInputs<'a> {
    pub rog_clientlist: &'a str,
    pub custom_clientlist: &'a str,
    /// `MAC>CAP<MAC>RE` from `get_amas_info()`; empty when unavailable.
    pub amas_node_types: &'a str,
    /// `is_re_node(mac, 1)`
    pub is_re_node: &'a dyn Fn(&str) -> bool,
}

/// Parse `/jffs/nmp_cl_json.js`; `None` when json-c would fail too.
pub fn parse_database(document: &[u8]) -> Option<Object> {
    if document.len() > MAX_DATABASE {
        return None;
    }
    match json::parse(document) {
        Ok(Value::Object(database)) => Some(database),
        _ => None,
    }
}

/// `ej_get_clientlist_from_json_database()` (web.c:1954-2119) for
/// `RTCONFIG_AMAS=y` without `RTCONFIG_MULTILAN_CFG`/`RTCONFIG_MLO`/
/// `RTCONFIG_STA_AP_BAND_BIND`. `database` is `None` when the file is
/// missing or unparseable, which yields the empty document.
pub fn render_database(
    database: Option<Object>,
    inputs: &DatabaseInputs<'_>,
    capacity: usize,
) -> Result<String, RenderError> {
    let mut maclist = Vec::new();
    let Some(mut clients) = database else {
        let mut document = Object::new();
        document.set("maclist", Value::Array(Vec::new()));
        document.set_str("ClientAPILevel", crate::CLIENT_API_LEVEL);
        return document_to_string(&document, capacity);
    };
    let custom = nvram::parse_custom_clientlist(inputs.custom_clientlist);
    let node_types = amas::parse_node_types(inputs.amas_node_types);

    for (key, value) in clients.iter_mut() {
        if (inputs.is_re_node)(key) {
            continue;
        }
        maclist.push(key.to_owned());
        // json-c would dereference a non-object here; leave it untouched.
        let Some(client) = value.as_object_mut() else {
            continue;
        };
        client.set_str("nickName", "");
        client.set_str("defaultType", "0");
        if let Some(client_type) = client.get("type").map(Value::c_string) {
            client.set_str("defaultType", &client_type);
            client.set_str("type", &client_type);
        }
        if let Some(online) = client.get("online").map(Value::c_string) {
            client.set_str("online", &online);
        }
        client.set_str("from", "nmpClient");
        if inputs.rog_clientlist.contains(key) {
            client.set_str("ROG", "1");
            client.set_str("type", "36");
            client.set_str("defaultType", "36");
        } else {
            client.set_str("ROG", "0");
        }
        if let Some(entry) = custom.get(key) {
            client.set_str("type", &entry.client_type.to_string());
            client.set_str("nickName", &entry.name);
        }
        if let Some(node_type) = node_types.get(key) {
            client.set_str("amesh_isRe", if node_type == "RE" { "1" } else { "0" });
        }
        client.set_str("amesh_bind_mac", "");
        client.set_str("amesh_bind_band", "0");
    }

    for (key, entry) in custom.iter() {
        if clients.contains_key(key) {
            continue;
        }
        maclist.push(key.to_owned());
        let mut client = Object::with_capacity(7);
        client.set_str("type", "0");
        client.set_str("mac", key);
        client.set_str("name", key);
        client.set_str("vendor", "");
        client.set_str("nickName", "");
        client.set_str("defaultType", "0");
        client.set_str("type", &entry.client_type.to_string());
        client.set_str("nickName", &entry.name);
        client.set_str("from", "customList");
        clients.set(key, Value::Object(client));
    }

    clients.set(
        "maclist",
        Value::Array(maclist.iter().map(|mac| Value::string(mac)).collect()),
    );
    clients.set_str("ClientAPILevel", crate::CLIENT_API_LEVEL);
    document_to_string(&clients, capacity)
}

fn custom_names(custom_clientlist: &str) -> KeyedList<String> {
    let mut names = KeyedList::new();
    for (mac, entry) in nvram::parse_custom_clientlist(custom_clientlist).iter() {
        names.set(mac, entry.name.clone());
    }
    names
}

/// `ej_get_all_basic_clientlist()` (web.c:2121-2161): `[[mac, name], ...]`
/// over the persistent DB, the custom name taking precedence; a record
/// without `name` yields `null` like json-c.
pub fn render_all_basic(
    database: &Object,
    custom_clientlist: &str,
    capacity: usize,
) -> Result<String, RenderError> {
    let names = custom_names(custom_clientlist);
    let pairs = database
        .iter()
        .map(|(mac, record)| {
            let name = match names.get(mac) {
                Some(name) => Value::string(name),
                None => record
                    .as_object()
                    .and_then(|record| record.get("name"))
                    .cloned()
                    .unwrap_or(Value::Null),
            };
            Value::Array(vec![Value::string(mac), name])
        })
        .collect();
    value_to_string(&Value::Array(pairs), capacity)
}

/// `get_basic_clientlist_info()` (web.c:2265-2360). `live` is `None` when
/// networkmap is not running or the segment cannot be decoded; `database` is
/// only consulted for `opt == 3`.
pub fn render_basic(
    live: Option<&ClientList>,
    database: Option<&Object>,
    opt: i32,
    capacity: usize,
) -> Result<String, RenderError> {
    let pair = |mac: &str, name: &str| Value::Array(vec![Value::string(mac), Value::string(name)]);
    match opt {
        0..=2 => {
            let mut wired = Vec::new();
            let mut wireless = Vec::new();
            if let Some(list) = live {
                for (mac, client) in list.clients.iter() {
                    if client.is_wl > 0 {
                        wireless.push(pair(mac, &client.name));
                    } else {
                        wired.push(pair(mac, &client.name));
                    }
                }
            }
            match opt {
                0 => value_to_string(&Value::Array(wired), capacity),
                1 => value_to_string(&Value::Array(wireless), capacity),
                _ => Ok(format!(
                    "{{\"wireless\":\"{}\", \"wire\":\"{}\"}}",
                    wireless.len(),
                    wired.len()
                )),
            }
        }
        3 => {
            let mut pairs = Vec::new();
            if let (Some(database), Some(list)) = (database, live) {
                for (mac, record) in database.iter() {
                    if list.clients.get(mac).is_some_and(|client| client.is_wl > 0) {
                        continue;
                    }
                    let name = record
                        .as_object()
                        .and_then(|record| record.get("name"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    pairs.push(Value::Array(vec![Value::string(mac), name]));
                }
            }
            value_to_string(&Value::Array(pairs), capacity)
        }
        _ => Ok(String::new()),
    }
}

/// `search_device_name_in_clientlist()` (web.c:2940-2975): MACs of DB
/// records whose custom name (preferred) or DB name equals `name` under
/// `strcasecmp()`.
pub fn search_device_name(database: &Object, custom_clientlist: &str, name: &str) -> Vec<String> {
    let names = custom_names(custom_clientlist);
    let mut matches = Vec::new();
    for (mac, record) in database.iter() {
        let candidate = match names.get(mac) {
            Some(custom) => Some(custom.clone()),
            None => record
                .as_object()
                .and_then(|record| record.get("name"))
                .map(Value::c_string),
        };
        if candidate.is_some_and(|candidate| candidate.eq_ignore_ascii_case(name)) {
            matches.push(mac.to_owned());
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_document_matches_web_c_literal() {
        assert_eq!(
            empty_document(),
            "{\"maclist\": [], \"ClientAPILevel\":\"7\"}"
        );
    }

    #[test]
    fn name_lookup_prefers_nickname_and_last_match() {
        let document = br#"{"A":{"ip":"10.0.0.2","name":"pc","nickName":"Paul"},"B":{"ip":"10.0.0.3","name":"","nickName":""},"C":{"ip":"10.0.0.2","name":"second"},"maclist":["A"],"ClientAPILevel":"7"}"#;
        assert_eq!(name_for_ip(document, "10.0.0.2").as_deref(), Some("second"));
        assert_eq!(
            name_for_ip(document, "10.0.0.3").as_deref(),
            Some("10.0.0.3")
        );
        assert_eq!(name_for_ip(document, "10.0.0.9"), None);
        assert_eq!(name_for_ip(b"[]", "10.0.0.2"), None);
    }

    #[test]
    fn sdn_counts_follow_get_sdn_client_num() {
        let document = br#"{"A":{"sdn_idx":"1","isOnline":"1"},"B":{"sdn_idx":"1","isOnline":"0"},"C":{"sdn_idx":"2","isOnline":1},"D":{"sdn_idx":"99","isOnline":"1"},"E":{"isOnline":"1"},"maclist":[]}"#;
        let mut counts = [0; 4];
        assert!(sdn_client_counts(document, &mut counts));
        assert_eq!(counts, [0, 1, 0, 0]);
        assert!(!sdn_client_counts(b"null", &mut counts));
    }

    #[test]
    fn search_is_case_insensitive_and_prefers_custom_names() {
        let database = parse_database(
            br#"{"A":{"name":"Laptop"},"B":{"name":"laptop"},"C":{"name":"Other"},"D":1}"#,
        )
        .unwrap();
        let custom = "<Custom>C>0>0>0>0<Renamed>A>0>0>0>0";
        assert_eq!(search_device_name(&database, custom, "LAPTOP"), ["B"]);
        assert_eq!(search_device_name(&database, custom, "custom"), ["C"]);
        assert_eq!(search_device_name(&database, "", "laptop"), ["A", "B"]);
        assert!(search_device_name(&database, "", "nothing").is_empty());
    }

    #[test]
    fn oversized_output_is_rejected() {
        let database = parse_database(br#"{"A":{"name":"x"}}"#).unwrap();
        assert_eq!(
            render_all_basic(&database, "", 4),
            Err(RenderError::Oversized)
        );
    }
}
