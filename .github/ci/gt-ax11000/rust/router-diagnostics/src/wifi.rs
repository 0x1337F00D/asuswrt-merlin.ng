//! Strict parsers for observation only. No disconnect/steering/configuration API.
use std::net::Ipv4Addr;

pub fn mac(value: &str) -> Option<String> {
    if value.len() != 17 {
        return None;
    }
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|p| p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    let first = u8::from_str_radix(parts[0], 16).ok()?;
    if first & 1 != 0 || parts.iter().all(|p| *p == "00") {
        return None;
    }
    Some(value.to_ascii_uppercase())
}

pub fn associated(text: &str, target: &str) -> Option<bool> {
    if text.len() > 16384 {
        return None;
    }
    let mut present = false;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 2 || fields[0] != "assoclist" {
            return None;
        }
        present |= mac(fields[1])? == target;
    }
    Some(present)
}

pub fn arp_matches(text: &str, ip: Ipv4Addr, target: &str) -> bool {
    if !ip.is_private() {
        return false;
    }
    let mut matches = 0;
    for line in text.lines().skip(1) {
        let f: Vec<_> = line.split_ascii_whitespace().collect();
        if f.len() == 6 && f[0] == ip.to_string() {
            if f[1] != "0x1"
                || f[2] != "0x2"
                || f[5] != "br0"
                || mac(f[3]).as_deref() != Some(target)
            {
                return false;
            }
            matches += 1;
        }
    }
    matches == 1
}

#[derive(Debug, Default, PartialEq)]
pub struct Station {
    pub rssi: Option<i16>,
    pub power_save: Option<bool>,
    pub retries: Option<u64>,
    pub exhausted: Option<u64>,
    pub age_seconds: Option<u64>,
    pub channel: Option<String>,
}

pub fn retry_delta(
    previous: Option<(usize, u64, u64)>,
    current: Option<(usize, u64, u64)>,
) -> Option<u64> {
    let (previous, current) = (previous?, current?);
    if previous.0 != current.0 || previous.1 > current.1 {
        return None;
    }
    current.2.checked_sub(previous.2)
}

pub fn station(text: &str, target: &str) -> Option<Station> {
    if text.len() > 16384 || !text.starts_with("[VER 8] STA ") {
        return None;
    }
    let header = text
        .lines()
        .next()?
        .strip_prefix("[VER 8] STA ")?
        .strip_suffix(':')?;
    if mac(header)?.as_str() != target {
        return None;
    }
    let mut result = Station::default();
    for line in text.lines().map(str::trim) {
        if let Some(v) = line.strip_prefix("smoothed rssi: ") {
            result.rssi = v.parse::<i16>().ok().filter(|n| (-127..=-1).contains(n));
        } else if line.starts_with("flags ") {
            result.power_save = Some(line.split_ascii_whitespace().any(|s| s == "PS"));
        } else if let Some(v) = line.strip_prefix("tx pkts retries: ") {
            result.retries = v.parse().ok();
        } else if let Some(v) = line.strip_prefix("tx pkts retry exhausted: ") {
            result.exhausted = v.parse().ok();
        } else if let Some(v) = line
            .strip_prefix("in network ")
            .and_then(|s| s.strip_suffix(" seconds"))
        {
            result.age_seconds = v.parse().ok();
        } else if let Some(v) = line
            .strip_prefix("chanspec ")
            .and_then(|s| s.split_ascii_whitespace().next())
        {
            if v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit() || b == b'/') {
                result.channel = Some(v.to_owned());
            }
        }
    }
    Some(result)
}

/// Only this station's association/authentication events; no raw syslog in WebUI.
pub fn event(line: &str, target: &str) -> Option<String> {
    let (_, payload) = line.split_once("wlceventd:")?;
    let fields: Vec<_> = payload.split_ascii_whitespace().collect();
    let pos = fields
        .iter()
        .position(|s| mac(s.trim_end_matches(',')).as_deref() == Some(target))?;
    let kind = *fields.get(pos.checked_sub(1)?)?;
    if !matches!(
        kind,
        "Auth" | "Assoc" | "ReAssoc" | "Disassoc" | "Deauth_ind"
    ) {
        return None;
    }
    let radio = fields.get(pos.checked_sub(2)?)?.trim_end_matches(':');
    if !matches!(radio, "eth6" | "eth7" | "eth8") {
        return None;
    }
    let timestamp = line.split_once(" wlceventd:")?.0;
    if timestamp.len() > 32
        || !timestamp
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b':' | b'-'))
    {
        return None;
    }
    Some(format!("{timestamp} {radio} {kind}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    const MAC: &str = "02:11:22:33:44:55";
    #[test]
    fn counter_reset_or_roam_is_not_a_retry_spike() {
        assert_eq!(retry_delta(Some((0, 10, 20)), Some((0, 11, 24))), Some(4));
        assert_eq!(retry_delta(Some((0, 10, 20)), Some((1, 11, 24))), None);
        assert_eq!(retry_delta(Some((0, 10, 20)), Some((0, 1, 24))), None);
        assert_eq!(retry_delta(Some((0, 10, 20)), Some((0, 11, 1))), None);
        assert_eq!(retry_delta(Some((0, 10, 20)), None), None);
    }
    #[test]
    fn target_validation() {
        for bad in [
            "ff:ff:ff:ff:ff:ff",
            "01:11:22:33:44:55",
            "00:00:00:00:00:00",
            "02:11:22:33:44:55;id",
            "02:11:22:33:44:5",
        ] {
            assert_eq!(mac(bad), None);
        }
        assert_eq!(mac(MAC).as_deref(), Some(MAC));
    }
    #[test]
    fn unknown_is_not_disconnected() {
        assert_eq!(associated("", MAC), Some(false));
        assert_eq!(associated("wl: Unsupported", MAC), None);
        assert_eq!(associated("assoclist 02:11:22:33:44:55\n", MAC), Some(true));
        assert_eq!(associated("assoclist 02:11:22:33:44:55 extra", MAC), None);
    }
    #[test]
    fn arp_requires_exact_lan_peer() {
        let text = format!("header\n192.168.0.236 0x1 0x2 {MAC} * br0\n");
        assert!(arp_matches(&text, "192.168.0.236".parse().unwrap(), MAC));
        assert!(!arp_matches(
            &text.replace("br0", "eth0"),
            "192.168.0.236".parse().unwrap(),
            MAC
        ));
        assert!(!arp_matches(
            &text.replace("0x2", "0x0"),
            "192.168.0.236".parse().unwrap(),
            MAC
        ));
        assert!(!arp_matches(&text, "1.1.1.1".parse().unwrap(), MAC));
    }
    #[test]
    fn station_v8_and_missing_fields() {
        let input = format!("[VER 8] STA {MAC}:\n chanspec 64/160 (0xef32)\n flags 0x1: WME PS HE_CAP\n in network 10 seconds\n smoothed rssi: -80\n tx pkts retries: 12\n tx pkts retry exhausted: 0\n");
        let s = station(&input, MAC).unwrap();
        assert_eq!(s.rssi, Some(-80));
        assert_eq!(s.power_save, Some(true));
        assert_eq!(s.channel.as_deref(), Some("64/160"));
        assert_eq!(s.retries, Some(12));
        assert_eq!(station(&input.replace("VER 8", "VER 9"), MAC), None);
        assert_eq!(station(&input.replace("-80", "0"), MAC).unwrap().rssi, None);
        assert_eq!(
            station(&format!("[VER 8] STA {MAC}:\n"), MAC)
                .unwrap()
                .power_save,
            None
        );
    }
    #[test]
    fn events_are_filtered_and_reduced() {
        let line = format!("Sep  9 13:01:08 wlceventd: wlceventd_proc_event(722): eth6: Assoc {MAC}, status: Successful (0), rssi:-84");
        assert_eq!(
            event(&line, MAC).as_deref(),
            Some("Sep  9 13:01:08 eth6 Assoc")
        );
        assert_eq!(event(&line.replace("eth6", "evil"), MAC), None);
        assert_eq!(event(&line.replace(MAC, "02:00:00:00:00:01"), MAC), None);
    }
}
