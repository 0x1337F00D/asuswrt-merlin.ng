use crate::{valid_identifier, PolicyError};
use std::collections::{HashMap, HashSet};

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_RULES: usize = 512;
const MAX_EFFECTIVE_RULESET_BYTES: usize = 128 * 1024;
pub const WAN_ADMIN_GUARD_CHAIN: &str = "CODEX_WAN_GUARD";

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
    /// unconditional DROP, either directly or through a logging-only chain
    /// whose final verdict is DROP. A preceding DROP is not sufficient because
    /// a later rule could otherwise remain reachable.
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

/// Validate the complete runtime contract installed after all vendor, VPN and
/// user firewall hooks. Besides terminal INPUT/FORWARD DROP, the very first
/// INPUT rule must divert packets from the active WAN interface into a small
/// generated chain that drops every local administration port before any
/// vendor ACCEPT rule can run.
pub fn validate_effective_firewall_policy(
    ipv4: &str,
    ipv6: Option<&str>,
    require_ipv6: bool,
    wan_ipv4_interface: &str,
    wan_ipv6_interface: Option<&str>,
    admin_tcp_ports: &[u16],
) -> Result<(), PolicyError> {
    validate_interface(wan_ipv4_interface)?;
    if admin_tcp_ports.is_empty() || admin_tcp_ports.contains(&0) || has_duplicate(admin_tcp_ports)
    {
        return Err(PolicyError::InvalidValue("WAN administration port"));
    }

    FirewallManifest::from_effective_filter_saves(ipv4, ipv6)?
        .validate_terminal_drops(require_ipv6)?;
    validate_wan_admin_guard(ipv4, wan_ipv4_interface, admin_tcp_ports)?;
    if require_ipv6 {
        let wan_ipv6_interface =
            wan_ipv6_interface.ok_or(PolicyError::Missing("IPv6 WAN interface"))?;
        validate_interface(wan_ipv6_interface)?;
        validate_wan_admin_guard(
            ipv6.ok_or(PolicyError::Missing("IPv6 ruleset"))?,
            wan_ipv6_interface,
            admin_tcp_ports,
        )?;
    }
    Ok(())
}

fn validate_wan_admin_guard(
    input: &str,
    wan_interface: &str,
    required_ports: &[u16],
) -> Result<(), PolicyError> {
    if input.len() > MAX_EFFECTIVE_RULESET_BYTES || !input.is_ascii() {
        return Err(PolicyError::TooLong);
    }

    let mut in_filter = false;
    let mut committed = false;
    let mut first_input = None::<Vec<String>>;
    let mut guard_rules = Vec::<Vec<String>>::new();
    for line in input.lines().map(str::trim) {
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
        let words = line.split_ascii_whitespace().collect::<Vec<_>>();
        if let ["-A", chain, rest @ ..] = words.as_slice() {
            if *chain == "INPUT" && first_input.is_none() {
                first_input = Some(rest.iter().map(|word| (*word).to_owned()).collect());
            } else if *chain == WAN_ADMIN_GUARD_CHAIN {
                guard_rules.push(rest.iter().map(|word| (*word).to_owned()).collect());
            }
        }
    }
    if in_filter || !committed {
        return Err(PolicyError::InvalidFormat);
    }

    let valid_hook = first_input.as_deref().is_some_and(|rule| {
        rule.len() == 4
            && rule[0] == "-i"
            && rule[1] == wan_interface
            && rule[2] == "-j"
            && rule[3] == WAN_ADMIN_GUARD_CHAIN
    });
    if !valid_hook {
        return Err(PolicyError::Invariant("WAN guard must be first INPUT rule"));
    }
    let Some((last, drops)) = guard_rules.split_last() else {
        return Err(PolicyError::Missing("WAN administration guard"));
    };
    if last.as_slice() != ["-j", "RETURN"] {
        return Err(PolicyError::Invariant("WAN guard terminal RETURN"));
    }

    let mut denied = HashSet::new();
    for rule in drops {
        let [protocol_flag, protocol, match_flag, matcher, port_flag, port, jump_flag, verdict] =
            rule.as_slice()
        else {
            return Err(PolicyError::Invariant("WAN guard rule"));
        };
        if protocol_flag != "-p"
            || protocol != "tcp"
            || match_flag != "-m"
            || matcher != "tcp"
            || port_flag != "--dport"
            || jump_flag != "-j"
            || verdict != "DROP"
        {
            return Err(PolicyError::Invariant("WAN guard rule"));
        }
        let port = parse_port(port)?;
        if !denied.insert(port) {
            return Err(PolicyError::Duplicate("WAN administration deny"));
        }
    }
    if required_ports.iter().all(|port| denied.contains(port)) {
        Ok(())
    } else {
        Err(PolicyError::Invariant("WAN administration deny"))
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
    let mut last_input = None::<String>;
    let mut last_forward = None::<String>;
    let mut user_chain_rules = HashMap::<String, Vec<Vec<String>>>::new();
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
        if let ["-A", chain, rest @ ..] = words.as_slice() {
            if *chain == "INPUT" || *chain == "FORWARD" {
                let target = match rest {
                    ["-j", target] => Some((*target).to_owned()),
                    _ => None,
                };
                if *chain == "INPUT" {
                    last_input = target;
                } else {
                    last_forward = target;
                }
            } else {
                user_chain_rules
                    .entry((*chain).to_owned())
                    .or_default()
                    .push(rest.iter().map(|word| (*word).to_owned()).collect());
            }
        }
    }
    if in_filter || !committed {
        return Err(PolicyError::InvalidFormat);
    }
    if !last_target_is_drop(last_input.as_deref(), &user_chain_rules)
        || !last_target_is_drop(last_forward.as_deref(), &user_chain_rules)
    {
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

fn last_target_is_drop(
    target: Option<&str>,
    user_chain_rules: &HashMap<String, Vec<Vec<String>>>,
) -> bool {
    let Some(target) = target else {
        return false;
    };
    if target == "DROP" {
        return true;
    }
    let Some(rules) = user_chain_rules.get(target) else {
        return false;
    };
    let Some((last, preceding)) = rules.split_last() else {
        return false;
    };
    if last.as_slice() != ["-j", "DROP"] {
        return false;
    }
    preceding.iter().all(|rule| {
        if rule.iter().any(|word| word == "-g" || word == "--goto") {
            return false;
        }
        let jumps = rule
            .windows(2)
            .filter_map(|words| (words[0] == "-j").then_some(words[1].as_str()))
            .collect::<Vec<_>>();
        jumps.as_slice() == ["LOG"]
    })
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
    fn vendor_logging_drop_chain_is_semantically_terminal() {
        let rules = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:logdrop - [0:0]\n-A INPUT -j logdrop\n-A FORWARD -j logdrop\n-A logdrop -m state --state NEW -j LOG --log-prefix DROP\n-A logdrop -j DROP\nCOMMIT\n";
        FirewallManifest::from_effective_filter_saves(rules, Some(rules))
            .unwrap()
            .validate_terminal_drops(true)
            .unwrap();

        for unsafe_chain in [
            "-A logdrop -j ACCEPT\n-A logdrop -j DROP",
            "-A logdrop -j RETURN\n-A logdrop -j DROP",
            "-A logdrop -g acceptor -j LOG\n-A logdrop -j DROP",
            "-A logdrop -j LOG\n-A logdrop -j ACCEPT",
            "-A logdrop -j DROP\n-A logdrop -j LOG",
        ] {
            let candidate = format!(
                "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:logdrop - [0:0]\n-A INPUT -j logdrop\n-A FORWARD -j logdrop\n{unsafe_chain}\nCOMMIT\n"
            );
            assert!(
                FirewallManifest::from_effective_filter_saves(&candidate, None).is_err(),
                "accepted unsafe logging chain: {unsafe_chain:?}"
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

    #[test]
    fn effective_policy_requires_first_rule_wan_admin_guard() {
        let rules = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:CODEX_WAN_GUARD - [0:0]\n-A INPUT -i eth0 -j CODEX_WAN_GUARD\n-A INPUT -i br0 -j ACCEPT\n-A INPUT -j DROP\n-A FORWARD -j DROP\n-A CODEX_WAN_GUARD -p tcp -m tcp --dport 22 -j DROP\n-A CODEX_WAN_GUARD -p tcp -m tcp --dport 443 -j DROP\n-A CODEX_WAN_GUARD -j RETURN\nCOMMIT\n";
        validate_effective_firewall_policy(
            rules,
            Some(rules),
            true,
            "eth0",
            Some("eth0"),
            &[22, 443],
        )
        .unwrap();

        for invalid in [
            rules.replace(
                "-A INPUT -i eth0 -j CODEX_WAN_GUARD\n-A INPUT -i br0 -j ACCEPT",
                "-A INPUT -i br0 -j ACCEPT\n-A INPUT -i eth0 -j CODEX_WAN_GUARD",
            ),
            rules.replace("-A CODEX_WAN_GUARD -p tcp -m tcp --dport 443 -j DROP\n", ""),
            rules.replace("--dport 443 -j DROP", "--dport 443 -j ACCEPT"),
            rules.replace(
                "-A CODEX_WAN_GUARD -j RETURN",
                "-A CODEX_WAN_GUARD -j ACCEPT",
            ),
        ] {
            assert!(
                validate_effective_firewall_policy(
                    &invalid,
                    None,
                    false,
                    "eth0",
                    None,
                    &[22, 443],
                )
                .is_err(),
                "accepted unsafe WAN guard: {invalid:?}"
            );
        }
    }
}
