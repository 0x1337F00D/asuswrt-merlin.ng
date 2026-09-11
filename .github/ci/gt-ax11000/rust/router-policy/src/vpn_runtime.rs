//! Read-only W9 audit of a complete, explicitly sampled vendor configuration.
//! Unlike the original profile ABI, this checks *every* configured IPv4
//! kill-switch source. It does not claim IPv6 leak prevention, routing-table
//! correctness, or atomicity across a changing firewall/NVRAM snapshot.

use crate::firewall::{
    validate_effective_vpn_client_policy, VpnClientKind, VpnClientProfile, VpnClientRequirements,
};
use crate::PolicyError;
use std::collections::HashSet;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeProfile {
    pub kind: VpnClientKind,
    pub unit: u8,
    pub interface: String,
    pub enabled: bool,
    pub running: bool,
    pub firewall: bool,
    pub enforce: bool,
    pub redirect: u8,
}

fn flag(value: &str) -> Result<bool, PolicyError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(PolicyError::InvalidValue("runtime flag")),
    }
}

/// Exactly ten rows, with no credentials:
/// KIND:UNIT:INTERFACE:ENABLED:RUNNING:FW:ENFORCE:RGW.
/// ENABLED is the vendor kill-switch enable predicate (not simply RUNNING).
/// RUNNING means the expected tunnel interface exists. A manually started
/// client still needs inbound protection even if autostart is disabled.
pub fn parse_snapshot(input: &str) -> Result<Vec<RuntimeProfile>, PolicyError> {
    if input.len() > 2048 {
        return Err(PolicyError::TooLong);
    }
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for line in input.lines() {
        let fields: Vec<_> = line.split(':').collect();
        let [kind, unit, interface, enabled, running, firewall, enforce, redirect] =
            fields.as_slice()
        else {
            return Err(PolicyError::InvalidFormat);
        };
        let checked = VpnClientProfile::parse(&format!("{kind}:{unit}:{interface}:fw"))?;
        let valid_interface = match checked.kind {
            VpnClientKind::OpenVpn => {
                *interface == format!("tun{}", 10 + checked.unit)
                    || *interface == format!("tap{}", 10 + checked.unit)
            }
            VpnClientKind::WireGuard => *interface == format!("wgc{}", checked.unit),
        };
        if !valid_interface {
            return Err(PolicyError::InvalidValue("vendor tunnel interface"));
        }
        if !seen.insert((checked.kind, checked.unit)) {
            return Err(PolicyError::Duplicate("runtime profile"));
        }
        let redirect = match *redirect {
            "0" => 0,
            "1" => 1,
            "2" => 2,
            "3" => 3,
            _ => return Err(PolicyError::InvalidValue("redirect mode")),
        };
        if checked.kind == VpnClientKind::WireGuard && redirect != 2 {
            return Err(PolicyError::InvalidValue("WireGuard redirect mode"));
        }
        result.push(RuntimeProfile {
            kind: checked.kind,
            unit: checked.unit,
            interface: checked.interface,
            enabled: flag(enabled)?,
            running: flag(running)?,
            firewall: flag(firewall)?,
            enforce: flag(enforce)?,
            redirect,
        });
    }
    // Unit bounds, duplicates, and family checks above make length sufficient.
    if result.len() != 10 {
        return Err(PolicyError::Missing("complete ten-profile snapshot"));
    }
    Ok(result)
}

fn selector(value: &str) -> Result<String, PolicyError> {
    let (address, prefix) = value.split_once('/').unwrap_or((value, "32"));
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| PolicyError::InvalidValue("VPN Director source"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| PolicyError::InvalidValue("VPN Director prefix"))?;
    if address.is_unspecified() || !(1..=32).contains(&prefix) {
        return Err(PolicyError::InvalidValue("VPN Director source"));
    }
    // `ip rule show` normalizes network prefixes and removes host /32.
    let mask = u32::MAX << (32 - prefix);
    let network = Ipv4Addr::from(u32::from(address) & mask);
    Ok(if prefix == 32 {
        network.to_string()
    } else {
        format!("{network}/{prefix}")
    })
}

#[derive(Clone, Debug)]
struct DirectorRule {
    enabled: bool,
    target: String,
    source: Option<String>,
    destination: Option<String>,
}

fn director_rules(input: &str) -> Result<Vec<DirectorRule>, PolicyError> {
    // The vendor uses an 8000-byte buffer: never validate a truncated list.
    if input.len() >= 8000 {
        return Err(PolicyError::TooLong);
    }
    let mut rules = Vec::new();
    for entry in input.split('<').filter(|entry| !entry.is_empty()) {
        let fields: Vec<_> = entry.split('>').collect();
        let [enabled, description, source, destination, target] = fields.as_slice() else {
            return Err(PolicyError::InvalidFormat);
        };
        if description.chars().any(char::is_control) || entry.len() >= 128 {
            return Err(PolicyError::InvalidValue("VPN Director entry"));
        }
        if *target != "WAN"
            && !(1..=5)
                .any(|unit| *target == format!("OVPN{unit}") || *target == format!("WGC{unit}"))
        {
            return Err(PolicyError::InvalidValue("VPN Director target"));
        }
        let source = match *source {
            "" | "0.0.0.0" => None,
            value => Some(selector(value)?),
        };
        let destination = match *destination {
            "" | "0.0.0.0" => None,
            value => Some(selector(value)?),
        };
        rules.push(DirectorRule {
            enabled: flag(enabled)?,
            target: (*target).to_owned(),
            source,
            destination,
        });
        if rules.len() > 200 {
            return Err(PolicyError::TooLong);
        }
    }
    Ok(rules)
}

/// A familiar priority/table name is not evidence that an exception was
/// configured. Bind every early WAN/VPN routing exception to the snapshot.
/// Server peer exceptions at priority 90 are deliberately unverified here:
/// validating those would require a separate server configuration snapshot.
fn authorized_early_route(
    priority: u32,
    words: &[&str],
    director: &[DirectorRule],
    profiles: &[RuntimeProfile],
) -> bool {
    if priority == 0 && words == ["from", "all", "lookup", "local"] {
        return true;
    }
    if (12210..12220).contains(&priority) && words.last() == Some(&"prohibit") {
        return true; // Shapes were already checked by the effective-rule parser.
    }
    if (10001..=10005).contains(&priority) {
        return profiles.iter().any(|profile| {
            profile.kind == VpnClientKind::OpenVpn
                && profile.running
                && matches!(profile.redirect, 0 | 1)
                && priority == 10000 + u32::from(profile.unit)
                && words
                    == [
                        "from",
                        "all",
                        "lookup",
                        format!("ovpnc{}", profile.unit).as_str(),
                    ]
        });
    }
    if !(10010..12210).contains(&priority) {
        return false;
    }
    let ["from", source, rest @ ..] = words else {
        return false;
    };
    let source = if *source == "all" {
        None
    } else {
        match selector(source) {
            Ok(value) => Some(value),
            Err(_) => return false,
        }
    };
    let (destination, rest) = match rest {
        ["to", destination, rest @ ..] => match selector(destination) {
            Ok(value) => (Some(value), rest),
            Err(_) => return false,
        },
        _ => (None, rest),
    };
    let ["lookup", table] = rest else {
        return false;
    };
    let (target, expected_table) = if priority < 10210 {
        ("WAN".to_owned(), "main".to_owned())
    } else if priority < 11210 {
        let unit = (priority - 10210) / 200 + 1;
        (format!("OVPN{unit}"), format!("ovpnc{unit}"))
    } else {
        let unit = (priority - 11210) / 200 + 1;
        (format!("WGC{unit}"), format!("wgc{unit}"))
    };
    *table == expected_table
        && director.iter().any(|rule| {
            rule.enabled
                && rule.target == target
                && rule.source == source
                && rule.destination == destination
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditCoverage {
    pub inbound_profiles: usize,
    pub kill_switch_profiles: usize,
    pub kill_switch_sources: usize,
}

/// Validate stable snapshots only. The caller must re-sample configuration
/// and effective rules and reject changes before interpreting this result.
/// Empty policy lists and disabled profiles create no invented requirements.
pub fn audit(
    snapshot: &str,
    director: &str,
    ipv4: &str,
    ipv6: Option<&str>,
    routes: &str,
    lan_interface: &str,
) -> Result<AuditCoverage, PolicyError> {
    let profiles = parse_snapshot(snapshot)?;
    let director = director_rules(director)?;
    let mut requirements = Vec::new();
    let mut expected = Vec::new();
    let mut coverage = AuditCoverage {
        inbound_profiles: 0,
        kill_switch_profiles: 0,
        kill_switch_sources: 0,
    };
    for profile in &profiles {
        let fw = profile.running && profile.firewall;
        let mut sources = HashSet::new();
        if profile.enabled && profile.enforce {
            match profile.redirect {
                1 => {
                    sources.insert(format!("from all iif {lan_interface} prohibit"));
                }
                2 => {
                    let target = match profile.kind {
                        VpnClientKind::OpenVpn => format!("OVPN{}", profile.unit),
                        VpnClientKind::WireGuard => format!("WGC{}", profile.unit),
                    };
                    for rule in &director {
                        if rule.enabled && rule.target == target {
                            // Destination-only routing cannot provide the vendor's
                            // source-wide kill switch. Do not certify it as safe.
                            let source = rule.source.as_ref().ok_or(PolicyError::Invariant(
                                "destination-only VPN rule has no vendor kill switch",
                            ))?;
                            sources.insert(format!("from {source} prohibit"));
                        }
                    }
                }
                _ => {
                    return Err(PolicyError::Invariant(
                        "enforce selected in a mode without a vendor kill switch",
                    ));
                }
            }
        }
        let ks = !sources.is_empty();
        if fw || ks {
            requirements.push(VpnClientProfile::new(
                profile.kind,
                profile.unit,
                &profile.interface,
                fw,
                ks,
            )?);
        }
        coverage.inbound_profiles += usize::from(fw);
        coverage.kill_switch_profiles += usize::from(ks);
        coverage.kill_switch_sources += sources.len();
        let priority = match profile.kind {
            VpnClientKind::OpenVpn => 12210,
            VpnClientKind::WireGuard => 12215,
        } + u32::from(profile.unit)
            - 1;
        expected.extend(sources.into_iter().map(|rule| (priority, rule)));
    }
    if requirements.is_empty() {
        return Ok(coverage); // Explicitly no VPN requirements, not “VPN secure”.
    }
    validate_effective_vpn_client_policy(
        ipv4,
        ipv6,
        ipv6.is_some(),
        Some(routes),
        &VpnClientRequirements {
            profiles: requirements,
            lan_interface: lan_interface.to_owned(),
        },
    )?;
    let mut installed = HashSet::new();
    let highest_slot = expected
        .iter()
        .map(|(priority, _)| *priority)
        .max()
        .unwrap_or(0);
    for line in routes.lines() {
        let (priority, words) = line.split_once(':').ok_or(PolicyError::InvalidFormat)?;
        let priority = priority
            .parse::<u32>()
            .map_err(|_| PolicyError::InvalidFormat)?;
        let words: Vec<_> = words.split_ascii_whitespace().collect();
        if priority < highest_slot
            && !authorized_early_route(priority, &words, &director, &profiles)
        {
            return Err(PolicyError::Invariant(
                "unconfigured early routing exception",
            ));
        }
        let normalized = match words.as_slice() {
            ["from", source, "prohibit"] => format!("from {} prohibit", selector(source)?),
            _ => words.join(" "),
        };
        installed.insert((priority, normalized));
    }
    if !expected.iter().all(|rule| installed.contains(rule)) {
        return Err(PolicyError::Missing(
            "complete per-source kill-switch coverage",
        ));
    }
    Ok(coverage)
}

#[cfg(test)]
mod tests {
    use super::*;
    const FILTER: &str = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -j DROP\n-A FORWARD -j DROP\nCOMMIT\n";
    const ROUTES: &str =
        "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n";
    fn snapshot(first: &str) -> String {
        let mut rows = vec![first.to_owned()];
        for unit in 2..=5 {
            rows.push(format!("openvpn:{unit}:tun{}:0:0:1:0:0", 10 + unit));
        }
        for unit in 1..=5 {
            rows.push(format!("wireguard:{unit}:wgc{unit}:0:0:1:0:2"));
        }
        rows.join("\n")
    }
    #[test]
    fn inactive_saved_enforce_does_not_disable_the_network() {
        let result = audit(
            &snapshot("openvpn:1:tun11:0:0:1:1:2"),
            "",
            FILTER,
            None,
            ROUTES,
            "br0",
        )
        .unwrap();
        assert_eq!(result.kill_switch_profiles, 0);
        assert_eq!(result.inbound_profiles, 0);
    }
    #[test]
    fn enabled_empty_director_is_not_an_imaginary_global_kill_switch() {
        assert_eq!(
            audit(
                &snapshot("openvpn:1:tun11:1:0:1:1:2"),
                "",
                FILTER,
                None,
                ROUTES,
                "br0"
            )
            .unwrap()
            .kill_switch_sources,
            0
        );
    }
    #[test]
    fn every_source_is_required_and_networks_are_normalized() {
        let snapshot = snapshot("openvpn:1:tun11:1:0:1:1:2");
        let director =
            "<1>one>192.0.2.5>>OVPN1<1>two>198.51.100.42/24>>OVPN1<0>off>203.0.113.1>>OVPN1";
        let one = format!("{ROUTES}12210: from 192.0.2.5 prohibit\n");
        assert!(audit(&snapshot, director, FILTER, None, &one, "br0").is_err());
        let all = format!("{one}12210: from 198.51.100.0/24 prohibit\n");
        assert_eq!(
            audit(&snapshot, director, FILTER, None, &all, "br0")
                .unwrap()
                .kill_switch_sources,
            2
        );
        assert!(audit(
            &snapshot,
            director,
            FILTER,
            None,
            &all.replace("12210", "12211"),
            "br0"
        )
        .is_err());
    }
    #[test]
    fn wrong_global_scope_and_unsupported_modes_fail() {
        let snapshot = snapshot("openvpn:1:tun11:1:0:1:1:1");
        let wrong = format!("{ROUTES}12210: from 192.0.2.5 prohibit\n");
        assert!(audit(&snapshot, "", FILTER, None, &wrong, "br0").is_err());
        let global = format!("{ROUTES}12210: from all iif br0 prohibit\n");
        assert!(audit(&snapshot, "", FILTER, None, &global, "br0").is_ok());
        assert!(audit(
            &snapshot.replace(":1:1", ":1:3"),
            "",
            FILTER,
            None,
            &global,
            "br0"
        )
        .is_err());
    }
    #[test]
    fn destination_only_cannot_be_certified() {
        assert!(audit(
            &snapshot("openvpn:1:tun11:1:0:1:1:2"),
            "<1>web>>192.0.2.1>OVPN1",
            FILTER,
            None,
            ROUTES,
            "br0"
        )
        .is_err());
    }
    #[test]
    fn familiar_vendor_wan_priority_cannot_hide_an_unconfigured_bypass() {
        let snapshot = snapshot("openvpn:1:tun11:1:0:1:1:2");
        let director = "<1>vpn>192.0.2.5>>OVPN1";
        let routes = format!("{ROUTES}10010: from 192.0.2.5 to 198.51.100.1 lookup main\n12210: from 192.0.2.5 prohibit\n");
        assert!(audit(&snapshot, director, FILTER, None, &routes, "br0").is_err());
        let configured = format!("{director}<1>exception>192.0.2.5>198.51.100.1>WAN");
        assert!(audit(&snapshot, &configured, FILTER, None, &routes, "br0").is_ok());
        assert!(audit(
            &snapshot,
            &configured,
            FILTER,
            None,
            &routes.replace("to 198.51.100.1", "to 198.51.100.2"),
            "br0"
        )
        .is_err());
    }
    #[test]
    fn every_wireguard_unit_gets_its_own_sources() {
        for unit in 1..=5 {
            let snapshot = snapshot("openvpn:1:tun11:0:0:1:1:2").replace(
                &format!("wireguard:{unit}:wgc{unit}:0:0:1:0:2"),
                &format!("wireguard:{unit}:wgc{unit}:1:0:1:1:2"),
            );
            let director = format!("<1>wg>192.0.2.1>>WGC{unit}<1>wg2>192.0.2.2>>WGC{unit}");
            let routes = format!(
                "{ROUTES}{}: from 192.0.2.1 prohibit\n{}: from 192.0.2.2 prohibit\n",
                12214 + unit,
                12214 + unit
            );
            assert_eq!(
                audit(&snapshot, &director, FILTER, None, &routes, "br0")
                    .unwrap()
                    .kill_switch_sources,
                2
            );
            assert!(audit(
                &snapshot,
                &director,
                FILTER,
                None,
                &routes.replace("192.0.2.2", "192.0.2.3"),
                "br0"
            )
            .is_err());
        }
    }
    #[test]
    fn snapshot_must_be_complete_unique_and_typed() {
        let valid = snapshot("openvpn:1:tun11:0:0:1:1:2");
        assert!(parse_snapshot(&valid).is_ok());
        for bad in [
            valid.replace("wireguard:5", "wireguard:4"),
            valid.replace("tun11", "tun99"),
            valid.replace(":0:", ":-1:"),
            valid.lines().skip(1).collect::<Vec<_>>().join("\n"),
            format!("{valid}\n{valid}"),
        ] {
            assert!(parse_snapshot(&bad).is_err());
        }
        assert!(director_rules(&"x".repeat(8000)).is_err());
        for bad in [
            "<1>x>192.0.2.1>>OVPN1;id",
            "<1>x>bad>>OVPN1",
            "<yes>x>192.0.2.1>>OVPN1",
            "<1>x\ny>192.0.2.1>>OVPN1",
        ] {
            assert!(director_rules(bad).is_err());
        }
    }
}
