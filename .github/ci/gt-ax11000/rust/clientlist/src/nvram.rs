//! Typed parsers for the NVRAM lists that enrich the client view.
//!
//! Every parser mirrors one json-c based helper in `httpd/web.c` at
//! `6be5bc84b50` (vendor line numbers): `get_custom_clientlist_info()`
//! (9304-9350), `get_qos_rulelist_info()` (9352-9374),
//! `get_wtf_rulelist_info()` (9376-9398), `check_internetState()` (9400-9478)
//! and `get_multifilter_info()` (9480-9588). The C code splits with
//! `strsep()`/`vstrsep()`, so empty fields are kept and a record with more
//! fields than pointers is accepted with the surplus ignored.

/// A key → value list with json-c `json_object_object_add()` semantics: a
/// repeated key replaces the earlier value at its original position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyedList<T> {
    entries: Vec<(String, T)>,
}

impl<T> Default for KeyedList<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T> KeyedList<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn set(&mut self, key: &str, value: T) {
        match self.entries.iter_mut().find(|(name, _)| name == key) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((key.to_owned(), value)),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &T)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }
}

/// C `atoi()`/`strtol(..., 10)` prefix semantics with saturation instead of
/// undefined overflow; also `json_object_get_int()` on a json-c string
/// (`json_parse_int64()` clamps to the `int` range).
pub fn c_atoi(text: &str) -> i32 {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
    {
        index += 1;
    }
    let mut negative = false;
    if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
        negative = bytes[index] == b'-';
        index += 1;
    }
    let mut value: i64 = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        value = value
            .saturating_mul(10)
            .saturating_add(i64::from(bytes[index] - b'0'));
        if value > i64::from(i32::MAX) + 1 {
            value = i64::from(i32::MAX) + 1;
        }
        index += 1;
    }
    if negative {
        value = -value;
    }
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// `strsep()` record iteration: an empty NVRAM value yields no records, any
/// other value yields every separator-delimited field including empty ones.
fn records(value: &str, separator: char) -> impl Iterator<Item = &str> {
    value.split(separator).filter(move |_| !value.is_empty())
}

/// `vstrsep(record, ">", ...)` with `pointers` output pointers: returns the
/// fields actually assigned (at most `pointers`).
fn vstrsep(record: &str, pointers: usize) -> Vec<&str> {
    record.split('>').take(pointers).collect()
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CustomClient {
    pub name: String,
    pub group: String,
    pub client_type: i32,
    pub callback: String,
    pub keeparp: String,
    pub groupname: String,
    pub age: String,
    pub groupid: String,
}

/// `get_custom_clientlist_info()`: `<name>mac>group>type>callback>keeparp`
/// with optional `>groupname>age>groupid`; 6 to 9 fields are accepted, fewer
/// are skipped, surplus fields are ignored, `type` is `atoi()`-converted and
/// the map key is the MAC field verbatim.
pub fn parse_custom_clientlist(value: &str) -> KeyedList<CustomClient> {
    let mut list = KeyedList::new();
    for record in records(value, '<') {
        let fields = vstrsep(record, 9);
        if fields.len() < 6 {
            continue;
        }
        let field = |index: usize| fields.get(index).copied().unwrap_or("");
        list.set(
            field(1),
            CustomClient {
                name: field(0).to_owned(),
                group: field(2).to_owned(),
                client_type: c_atoi(field(3)),
                callback: field(4).to_owned(),
                keeparp: field(5).to_owned(),
                groupname: field(6).to_owned(),
                age: field(7).to_owned(),
                groupid: field(8).to_owned(),
            },
        );
    }
    list
}

/// `get_qos_rulelist_info()`: `<desc>mac>port>proto>transferred>prio`; the
/// priority string is kept for records with at least six fields and a
/// non-empty MAC.
pub fn parse_qos_rulelist(value: &str) -> KeyedList<String> {
    let mut list = KeyedList::new();
    for record in records(value, '<') {
        let fields = vstrsep(record, 6);
        if fields.len() != 6 || fields[1].is_empty() {
            continue;
        }
        list.set(fields[1], fields[5].to_owned());
    }
    list
}

/// `get_wtf_rulelist_info()`: `<status>mac>server1>server2>game`; the status
/// is `atoi()`-converted for records with at least five fields and a
/// non-empty MAC.
pub fn parse_wtf_rulelist(value: &str) -> KeyedList<i32> {
    let mut list = KeyedList::new();
    for record in records(value, '<') {
        let fields = vstrsep(record, 5);
        if fields.len() != 5 || fields[1].is_empty() {
            continue;
        }
        list.set(fields[1], c_atoi(fields[0]));
    }
    list
}

/// Wall-clock inputs of `check_internetState()`: `tm_wday` (0 = Sunday) and
/// `tm_hour` from `localtime()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalTime {
    pub weekday: i32,
    pub hour: i32,
}

fn digits(record: &str, start: usize, count: usize) -> i32 {
    // strncpy(time_item, p + start, count) reads at most `count` bytes and
    // stops at the terminator; a record shorter than `start` gives 0.
    let bytes = record.as_bytes();
    if start >= bytes.len() {
        return 0;
    }
    let end = bytes.len().min(start + count);
    std::str::from_utf8(&bytes[start..end]).map_or(0, c_atoi)
}

/// `check_internetState()` (`RTCONFIG_PC_SCHED_V3` is not set for the
/// GT-AX11000): true when one `<`-separated `WWHHhh` entry other than `T`
/// covers the current weekday/hour. Empty entries are evaluated too and
/// match every time, exactly as in C.
pub fn schedule_allows(time_list: &str, now: LocalTime) -> bool {
    let system_week = if now.weekday == 0 { 7 } else { now.weekday };
    let system_hour = now.hour;
    for entry in records(time_list, '<') {
        if entry == "T" {
            continue;
        }
        let week_start = digits(entry, 0, 1);
        let mut week_end = digits(entry, 1, 1);
        let hour_start = digits(entry, 2, 2);
        let hour_end = digits(entry, 4, 2);
        if (week_start == 0 && week_end == 0 && hour_start == 0 && hour_end == 0)
            || week_start > week_end
        {
            week_end = 7;
        }
        if week_start == 0 && week_end == 7 && hour_start == 0 && hour_end == 0 {
            return true;
        } else if week_start == system_week && week_end == system_week {
            if hour_start <= system_hour && hour_end > system_hour {
                return true;
            }
        } else if week_start == system_week && week_end > system_week {
            if hour_start <= system_hour {
                return true;
            }
        } else if week_start < system_week && week_end > system_week {
            return true;
        } else if week_start < system_week && week_end >= system_week {
            if hour_end > system_hour {
                return true;
            }
        } else if week_start == 0
            && week_end == 0
            && system_week == 7
            && hour_start <= system_hour
            && hour_end > system_hour
        {
            return true;
        }
    }
    false
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MultifilterInputs<'a> {
    /// `nvram_get_int("MULTIFILTER_ALL")`
    pub all: i32,
    /// `MULTIFILTER_MAC`
    pub mac: &'a str,
    /// `MULTIFILTER_ENABLE`
    pub enable: &'a str,
    /// `MULTIFILTER_MACFILTER_DAYTIME`
    pub daytime: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternetAccess {
    pub mode: &'static str,
    pub state: i32,
}

/// `get_multifilter_info()` without `RTCONFIG_PERMISSION_MANAGEMENT`: the
/// three `>`-separated lists are matched by index; mode is `allow`/`time`/
/// `block` from the enable value, state is 1 unless blocked or outside the
/// schedule (a daytime of `<` is always blocked).
pub fn parse_multifilter(
    inputs: MultifilterInputs<'_>,
    now: LocalTime,
) -> KeyedList<InternetAccess> {
    let mut list = KeyedList::new();
    if inputs.all == 0 || inputs.mac.is_empty() {
        return list;
    }
    let macs: Vec<&str> = inputs.mac.split('>').collect();
    let enables: Vec<&str> = records(inputs.enable, '>').collect();
    let daytimes: Vec<&str> = records(inputs.daytime, '>').collect();
    for (index, mac) in macs.iter().enumerate() {
        let mut mode = "allow";
        let mut state = 1;
        let status = enables.get(index).map_or(0, |value| c_atoi(value));
        if status == 1 {
            mode = "time";
            if let Some(daytime) = daytimes.get(index) {
                state = if *daytime == "<" {
                    0
                } else {
                    i32::from(schedule_allows(daytime, now))
                };
            }
        } else if status == 2 {
            mode = "block";
            state = 0;
        }
        list.set(mac, InternetAccess { mode, state });
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atoi_prefix_and_saturation() {
        assert_eq!(c_atoi("31"), 31);
        assert_eq!(c_atoi("  -7x"), -7);
        assert_eq!(c_atoi("abc"), 0);
        assert_eq!(c_atoi(""), 0);
        assert_eq!(c_atoi("99999999999999999999"), i32::MAX);
        assert_eq!(c_atoi("-99999999999999999999"), i32::MIN);
    }

    #[test]
    fn custom_clientlist_accepts_six_to_nine_fields_and_replaces_duplicates() {
        // web.c:9304-9350: 6-field legacy writer and 9-field writer.
        let value = "<Laptop>AA:BB:CC:DD:EE:01>0>2>0>0<TV>AA:BB:CC:DD:EE:02>1>7>1>0>Living>3>9<bad>AA:BB:CC:DD:EE:03>0<Laptop2>AA:BB:CC:DD:EE:01>0>0>0>0";
        let list = parse_custom_clientlist(value);
        assert_eq!(list.len(), 2);
        let first = list.get("AA:BB:CC:DD:EE:01").unwrap();
        assert_eq!(first.name, "Laptop2");
        assert_eq!(first.client_type, 0);
        let second = list.get("AA:BB:CC:DD:EE:02").unwrap();
        assert_eq!(second.client_type, 7);
        assert_eq!(second.groupname, "Living");
        assert_eq!(second.groupid, "9");
        assert_eq!(list.iter().next().unwrap().0, "AA:BB:CC:DD:EE:01");
    }

    #[test]
    fn custom_clientlist_empty_and_malformed() {
        assert!(parse_custom_clientlist("").is_empty());
        assert!(parse_custom_clientlist("<").is_empty());
        assert!(parse_custom_clientlist("<a>b>c>d>e").is_empty());
        assert!(parse_custom_clientlist(">>>>>>>>>>>>").len() == 1);
        let ten = parse_custom_clientlist("<n>m>g>t>c>k>gn>a>gi>extra");
        assert_eq!(ten.get("m").unwrap().groupid, "gi");
    }

    #[test]
    fn qos_and_wtf_rulelists() {
        let qos = parse_qos_rulelist(
            "<desc>AA:BB:CC:DD:EE:01>>>>2<x>>1>2>3>4<seven>AA:BB:CC:DD:EE:02>a>b>c>0>extra",
        );
        assert_eq!(qos.get("AA:BB:CC:DD:EE:01").map(String::as_str), Some("2"));
        assert_eq!(qos.get("AA:BB:CC:DD:EE:02").map(String::as_str), Some("0"));
        assert_eq!(qos.len(), 2);
        let wtf = parse_wtf_rulelist("<1>AA:BB:CC:DD:EE:01>s1>s2>g<0>>a>b>c<2>AA:BB:CC:DD:EE:02>x");
        assert_eq!(wtf.get("AA:BB:CC:DD:EE:01"), Some(&1));
        assert_eq!(wtf.len(), 1);
    }

    #[test]
    fn schedule_rules_follow_check_internet_state() {
        let monday_ten = LocalTime {
            weekday: 1,
            hour: 10,
        };
        assert!(schedule_allows("T<000000", monday_ten));
        assert!(schedule_allows("<", monday_ten));
        assert!(!schedule_allows("T", monday_ten));
        assert!(schedule_allows("110812", monday_ten));
        assert!(!schedule_allows("111208", monday_ten));
        assert!(schedule_allows("120800", monday_ten));
        assert!(schedule_allows("030000", monday_ten));
        assert!(schedule_allows(
            "670024",
            LocalTime {
                weekday: 0,
                hour: 1
            }
        ));
        assert!(!schedule_allows(
            "650000",
            LocalTime {
                weekday: 0,
                hour: 1
            }
        ));
        assert!(schedule_allows(
            "000002",
            LocalTime {
                weekday: 0,
                hour: 1
            }
        ));
        assert!(!schedule_allows(
            "000002",
            LocalTime {
                weekday: 0,
                hour: 5
            }
        ));
        assert!(!schedule_allows("11", monday_ten));
    }

    #[test]
    fn multifilter_derives_mode_and_state() {
        let now = LocalTime {
            weekday: 3,
            hour: 12,
        };
        let inputs = MultifilterInputs {
            all: 1,
            mac: "AA:BB:CC:DD:EE:01>AA:BB:CC:DD:EE:02>AA:BB:CC:DD:EE:03>AA:BB:CC:DD:EE:04",
            enable: "1>2>0>1",
            daytime: "<>T<330000>T<x",
        };
        let list = parse_multifilter(inputs, now);
        assert_eq!(
            list.get("AA:BB:CC:DD:EE:01"),
            Some(&InternetAccess {
                mode: "time",
                state: 0
            })
        );
        assert_eq!(
            list.get("AA:BB:CC:DD:EE:02"),
            Some(&InternetAccess {
                mode: "block",
                state: 0
            })
        );
        assert_eq!(
            list.get("AA:BB:CC:DD:EE:03"),
            Some(&InternetAccess {
                mode: "allow",
                state: 1
            })
        );
        assert_eq!(
            list.get("AA:BB:CC:DD:EE:04"),
            Some(&InternetAccess {
                mode: "time",
                state: 1
            })
        );
        assert!(parse_multifilter(MultifilterInputs { all: 0, ..inputs }, now).is_empty());
        assert!(parse_multifilter(MultifilterInputs { mac: "", ..inputs }, now).is_empty());
        let no_enable = parse_multifilter(
            MultifilterInputs {
                enable: "",
                ..inputs
            },
            now,
        );
        assert_eq!(no_enable.get("AA:BB:CC:DD:EE:02").unwrap().mode, "allow");
    }
}
