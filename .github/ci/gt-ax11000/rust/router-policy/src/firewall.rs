use crate::{valid_identifier, PolicyError};
use std::collections::HashSet;

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_RULES: usize = 512;
const MAX_EFFECTIVE_RULESET_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    fn parse(value: &str) -> Result<Self, PolicyError> {
        match value {
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            _ => Err(PolicyError::InvalidValue("address family")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FilterChain {
    Input,
    Forward,
}

impl FilterChain {
    fn parse(value: &str) -> Result<Self, PolicyError> {
        match value {
            "input" => Ok(Self::Input),
            "forward" => Ok(Self::Forward),
            _ => Err(PolicyError::InvalidValue("filter chain")),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum FirewallRule {
    TerminalDrop {
        family: AddressFamily,
        chain: FilterChain,
    },
    WanAdminDeny {
        family: AddressFamily,
        wan_interface: String,
        tcp_port: u16,
    },
    VpnKillSwitch {
        family: AddressFamily,
        wan_interface: String,
        vpn_interface: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirewallManifest {
    rules: Vec<FirewallRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirewallRequirements {
    pub wan_interfaces: Vec<String>,
    pub admin_tcp_ports: Vec<u16>,
    pub vpn_interfaces: Vec<String>,
    pub vpn_kill_switch: bool,
}

impl FirewallManifest {
    /// Parse a small canonical manifest produced from the effective firewall.
    ///
    /// Accepted records are:
    /// `terminal FAMILY CHAIN drop`,
    /// `wan-admin FAMILY WAN_IF TCP_PORT deny`, and
    /// `vpn-killswitch FAMILY WAN_IF VPN_IF deny`.
    pub fn parse(input: &str) -> Result<Self, PolicyError> {
        if input.len() > MAX_MANIFEST_BYTES {
            return Err(PolicyError::TooLong);
        }
        if !input.is_ascii() {
            return Err(PolicyError::NonAscii);
        }

        let mut rules = Vec::new();
        let mut unique = HashSet::new();
        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.len() > 256 || rules.len() == MAX_RULES {
                return Err(PolicyError::TooLong);
            }
            let words: Vec<_> = line.split_ascii_whitespace().collect();
            let rule = match words.as_slice() {
                ["terminal", family, chain, "drop"] => FirewallRule::TerminalDrop {
                    family: AddressFamily::parse(family)?,
                    chain: FilterChain::parse(chain)?,
                },
                ["wan-admin", family, interface, port, "deny"] => {
                    validate_interface(interface)?;
                    FirewallRule::WanAdminDeny {
                        family: AddressFamily::parse(family)?,
                        wan_interface: (*interface).to_owned(),
                        tcp_port: parse_port(port)?,
                    }
                }
                ["vpn-killswitch", family, wan, vpn, "deny"] => {
                    validate_interface(wan)?;
                    validate_interface(vpn)?;
                    if wan == vpn {
                        return Err(PolicyError::InvalidValue("VPN interface"));
                    }
                    FirewallRule::VpnKillSwitch {
                        family: AddressFamily::parse(family)?,
                        wan_interface: (*wan).to_owned(),
                        vpn_interface: (*vpn).to_owned(),
                    }
                }
                _ => return Err(PolicyError::InvalidFormat),
            };
            if !unique.insert(rule.clone()) {
                return Err(PolicyError::Duplicate("firewall rule"));
            }
            rules.push(rule);
        }
        if rules.is_empty() {
            return Err(PolicyError::Empty);
        }
        Ok(Self { rules })
    }

    pub fn rules(&self) -> &[FirewallRule] {
        &self.rules
    }

    /// Derive only the terminal-DROP facts from effective `iptables-save`
    /// output. The last appended INPUT and FORWARD rule must be an exact,
    /// unconditional DROP. A preceding DROP is not sufficient because a later
    /// rule could otherwise remain reachable.
    pub fn from_effective_filter_saves(
        ipv4: &str,
        ipv6: Option<&str>,
    ) -> Result<Self, PolicyError> {
        let mut rules = terminal_drop_rules(ipv4, AddressFamily::Ipv4)?;
        if let Some(ipv6) = ipv6 {
            rules.extend(terminal_drop_rules(ipv6, AddressFamily::Ipv6)?);
        }
        Ok(Self { rules })
    }

    pub fn validate_terminal_drops(&self, require_ipv6: bool) -> Result<(), PolicyError> {
        for family in [AddressFamily::Ipv4]
            .into_iter()
            .chain(require_ipv6.then_some(AddressFamily::Ipv6))
        {
            for chain in [FilterChain::Input, FilterChain::Forward] {
                if !self
                    .rules
                    .contains(&FirewallRule::TerminalDrop { family, chain })
                {
                    return Err(PolicyError::Invariant("effective terminal DROP"));
                }
            }
        }
        Ok(())
    }

    /// Enforce terminal DROP, WAN admin denial, and optional VPN kill-switch
    /// coverage for both IPv4 and IPv6. Missing coverage fails closed.
    pub fn validate(&self, requirements: &FirewallRequirements) -> Result<(), PolicyError> {
        requirements.validate()?;
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            for chain in [FilterChain::Input, FilterChain::Forward] {
                if !self
                    .rules
                    .contains(&FirewallRule::TerminalDrop { family, chain })
                {
                    return Err(PolicyError::Invariant("IPv4/IPv6 terminal DROP"));
                }
            }
            for wan in &requirements.wan_interfaces {
                for port in &requirements.admin_tcp_ports {
                    if !self.rules.contains(&FirewallRule::WanAdminDeny {
                        family,
                        wan_interface: wan.clone(),
                        tcp_port: *port,
                    }) {
                        return Err(PolicyError::Invariant("WAN admin deny"));
                    }
                }
                if requirements.vpn_kill_switch {
                    for vpn in &requirements.vpn_interfaces {
                        if !self.rules.contains(&FirewallRule::VpnKillSwitch {
                            family,
                            wan_interface: wan.clone(),
                            vpn_interface: vpn.clone(),
                        }) {
                            return Err(PolicyError::Invariant("VPN kill switch"));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn terminal_drop_rules(
    input: &str,
    family: AddressFamily,
) -> Result<Vec<FirewallRule>, PolicyError> {
    if input.len() > MAX_EFFECTIVE_RULESET_BYTES {
        return Err(PolicyError::TooLong);
    }
    if !input.is_ascii() {
        return Err(PolicyError::NonAscii);
    }

    let mut in_filter = false;
    let mut committed = false;
    let mut last_input = None;
    let mut last_forward = None;
    for line in input.lines() {
        let line = line.trim();
        if line == "*filter" {
            if in_filter || committed {
                return Err(PolicyError::InvalidFormat);
            }
            in_filter = true;
            continue;
        }
        if !in_filter {
            continue;
        }
        if line == "COMMIT" {
            committed = true;
            in_filter = false;
            continue;
        }
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        match words.as_slice() {
            ["-A", "INPUT", rest @ ..] => last_input = Some(*rest == ["-j", "DROP"]),
            ["-A", "FORWARD", rest @ ..] => last_forward = Some(*rest == ["-j", "DROP"]),
            _ => {}
        }
    }
    if in_filter || !committed {
        return Err(PolicyError::InvalidFormat);
    }
    if last_input != Some(true) || last_forward != Some(true) {
        return Err(PolicyError::Invariant("effective terminal DROP"));
    }
    Ok(vec![
        FirewallRule::TerminalDrop {
            family,
            chain: FilterChain::Input,
        },
        FirewallRule::TerminalDrop {
            family,
            chain: FilterChain::Forward,
        },
    ])
}

impl FirewallRequirements {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.wan_interfaces.is_empty() {
            return Err(PolicyError::Missing("WAN interface"));
        }
        if self.admin_tcp_ports.is_empty() {
            return Err(PolicyError::Missing("admin TCP port"));
        }
        if self.vpn_kill_switch && self.vpn_interfaces.is_empty() {
            return Err(PolicyError::Missing("VPN interface"));
        }
        for interface in self.wan_interfaces.iter().chain(&self.vpn_interfaces) {
            validate_interface(interface)?;
        }
        if self.admin_tcp_ports.contains(&0) {
            return Err(PolicyError::InvalidValue("admin TCP port"));
        }
        if has_duplicate(&self.wan_interfaces)
            || has_duplicate(&self.vpn_interfaces)
            || has_duplicate(&self.admin_tcp_ports)
        {
            return Err(PolicyError::Duplicate("firewall requirement"));
        }
        Ok(())
    }
}

fn has_duplicate<T: Eq + std::hash::Hash>(items: &[T]) -> bool {
    let mut seen = HashSet::new();
    items.iter().any(|item| !seen.insert(item))
}

fn validate_interface(value: &str) -> Result<(), PolicyError> {
    if valid_identifier(value, 15) {
        Ok(())
    } else {
        Err(PolicyError::InvalidValue("interface"))
    }
}

fn parse_port(value: &str) -> Result<u16, PolicyError> {
    let port = value
        .parse::<u16>()
        .map_err(|_| PolicyError::InvalidValue("TCP port"))?;
    if port == 0 {
        Err(PolicyError::InvalidValue("TCP port"))
    } else {
        Ok(port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPLETE: &str = "\
terminal ipv4 input drop
terminal ipv4 forward drop
terminal ipv6 input drop
terminal ipv6 forward drop
wan-admin ipv4 eth0 22 deny
wan-admin ipv6 eth0 22 deny
wan-admin ipv4 eth0 443 deny
wan-admin ipv6 eth0 443 deny
vpn-killswitch ipv4 eth0 wg0 deny
vpn-killswitch ipv6 eth0 wg0 deny
";

    fn requirements() -> FirewallRequirements {
        FirewallRequirements {
            wan_interfaces: vec!["eth0".into()],
            admin_tcp_ports: vec![22, 443],
            vpn_interfaces: vec!["wg0".into()],
            vpn_kill_switch: true,
        }
    }

    #[test]
    fn complete_manifest_is_accepted() {
        FirewallManifest::parse(COMPLETE)
            .unwrap()
            .validate(&requirements())
            .unwrap();
    }

    #[test]
    fn each_required_rule_fails_closed_when_missing() {
        for required in COMPLETE.lines().filter(|line| !line.is_empty()) {
            let candidate = COMPLETE
                .lines()
                .filter(|line| *line != required)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                FirewallManifest::parse(&candidate)
                    .unwrap()
                    .validate(&requirements())
                    .is_err(),
                "missing rule was accepted: {required}"
            );
        }
    }

    #[test]
    fn malformed_and_permissive_verdicts_are_rejected() {
        for value in [
            "terminal ipv4 input accept",
            "wan-admin ipv4 eth0 443 accept",
            "vpn-killswitch ipv6 eth0 wg0 log",
            "terminal ipv4 output drop",
            "wan-admin ipv4 bad;if 443 deny",
            "wan-admin ipv4 eth0 0 deny",
            "unknown ipv4 input drop",
        ] {
            assert!(FirewallManifest::parse(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn duplicate_rules_and_requirements_are_rejected() {
        assert_eq!(
            FirewallManifest::parse("terminal ipv4 input drop\nterminal ipv4 input drop"),
            Err(PolicyError::Duplicate("firewall rule"))
        );
        let mut duplicate = requirements();
        duplicate.admin_tcp_ports.push(22);
        assert!(FirewallManifest::parse(COMPLETE)
            .unwrap()
            .validate(&duplicate)
            .is_err());
    }

    #[test]
    fn kill_switch_may_only_be_omitted_explicitly() {
        let no_killswitch = COMPLETE
            .lines()
            .filter(|line| !line.starts_with("vpn-killswitch"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut req = requirements();
        req.vpn_kill_switch = false;
        FirewallManifest::parse(&no_killswitch)
            .unwrap()
            .validate(&req)
            .unwrap();
    }

    #[test]
    fn effective_ruleset_requires_the_last_input_and_forward_rules_to_drop() {
        let rules = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j DROP\n-A FORWARD -m state --state ESTABLISHED -j ACCEPT\n-A FORWARD -j DROP\nCOMMIT\n";
        FirewallManifest::from_effective_filter_saves(rules, Some(rules))
            .unwrap()
            .validate_terminal_drops(true)
            .unwrap();

        for invalid in [
            "*filter\n-A INPUT -j DROP\n-A INPUT -j ACCEPT\n-A FORWARD -j DROP\nCOMMIT\n",
            "*filter\n-A INPUT -j DROP\n-A FORWARD -j DROP\n-A FORWARD -j ACCEPT\nCOMMIT\n",
            "*filter\n-A INPUT -j DROP\nCOMMIT\n",
            "*filter\n-A INPUT -j DROP\n-A FORWARD -j DROP\n",
            "*nat\n-A INPUT -j DROP\n-A FORWARD -j DROP\nCOMMIT\n",
            "*filter\n-A INPUT -j DROP --comment late\n-A FORWARD -j DROP\nCOMMIT\n",
        ] {
            assert!(
                FirewallManifest::from_effective_filter_saves(invalid, None).is_err(),
                "accepted invalid effective ruleset: {invalid:?}"
            );
        }
    }

    #[test]
    fn ipv6_terminal_drop_is_required_only_when_ipv6_is_enabled() {
        let rules = "*filter\n-A INPUT -j DROP\n-A FORWARD -j DROP\nCOMMIT\n";
        let ipv4_only = FirewallManifest::from_effective_filter_saves(rules, None).unwrap();
        ipv4_only.validate_terminal_drops(false).unwrap();
        assert!(ipv4_only.validate_terminal_drops(true).is_err());
    }
}
