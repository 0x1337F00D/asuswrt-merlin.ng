use crate::{valid_identifier, PolicyError};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_RULES: usize = 512;
const MAX_EFFECTIVE_RULESET_BYTES: usize = 128 * 1024;
const MAX_POLICY_ROUTES_BYTES: usize = 64 * 1024;
const MAX_VPN_CLIENT_PROFILE_BYTES: usize = 64;
pub const WAN_ADMIN_GUARD_CHAIN: &str = "CODEX_WAN_GUARD";

// Vendor client bounds and the VPN Director `ip rule` priority ladder, from
// release/src/router/libovpn/openvpn_config.h at 6be5bc84b50: OVPN_CLIENT_MAX
// (:5), WG_CLIENT_MAX (:6), OVPN_CLIENT_BASE (:11) and VPNDIR_PRIO_* (:95-104;
// the allocation table is amvpn_routing.c:153-183). The ladder resolves to
// 10000 (ALL), 10010 (WAN), 10210 (OPENVPN), 11210 (WIREGUARD), 12210
// (KS_OPENVPN), 12215 (KS_WIREGUARD) and 12220 (KS_SDN).
pub const OVPN_CLIENT_MAX: u8 = 5;
pub const WG_CLIENT_MAX: u8 = 5;
const OVPN_CLIENT_BASE: u8 = 10;
const VPNDIR_PRIO_MAX_RULES: u32 = 200;
const VPNDIR_PRIO_ALL: u32 = 10_000;
const VPNDIR_PRIO_WAN: u32 = VPNDIR_PRIO_ALL + OVPN_CLIENT_MAX as u32 + WG_CLIENT_MAX as u32;
const VPNDIR_PRIO_OPENVPN: u32 = VPNDIR_PRIO_WAN + VPNDIR_PRIO_MAX_RULES;
const VPNDIR_PRIO_WIREGUARD: u32 =
    VPNDIR_PRIO_OPENVPN + VPNDIR_PRIO_MAX_RULES * OVPN_CLIENT_MAX as u32;
const VPNDIR_PRIO_KS_OPENVPN: u32 =
    VPNDIR_PRIO_WIREGUARD + VPNDIR_PRIO_MAX_RULES * WG_CLIENT_MAX as u32;
const VPNDIR_PRIO_KS_WIREGUARD: u32 = VPNDIR_PRIO_KS_OPENVPN + OVPN_CLIENT_MAX as u32;
const VPNDIR_PRIO_KS_SDN: u32 = VPNDIR_PRIO_KS_WIREGUARD + WG_CLIENT_MAX as u32;
// `ip rule ... lookup main pref 90` for VPN server peers: the PPTP peer
// address (rc/vpn.c:330) and WireGuard server allowed IPs (rc/wireguard.c:
// 1294), both IP_RULE_PREF_VPNS (shared/shared.h:5725).
const IP_RULE_PREF_VPNS: u32 = 90;
// Deepest user-chain nesting followed while proving that the rules before a
// client-chain hook cannot admit tunnel traffic.
const MAX_HOOK_CHAIN_DEPTH: usize = 8;
const MAX_VPN_CLIENT_PROFILES: usize = (OVPN_CLIENT_MAX + WG_CLIENT_MAX) as usize;

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

/// Vendor VPN client family. Each one owns an INPUT-side and a FORWARD-side
/// chain that rc/firewall.c hooks unconditionally: `-A INPUT -j WGCI` and
/// `-A INPUT -j OVPNCI` (firewall.c:5332, :5343; IPv6 :5336, :5347) and
/// `-A FORWARD -j WGCF` and `-A FORWARD -j OVPNCF` (firewall.c:6172, :6180;
/// IPv6 :6175, :6183). The dual-WAN generator `filter_setting2` emits the
/// same hooks (INPUT :7129, :7140; IPv6 :7133, :7144; FORWARD :8050, :8058;
/// IPv6 :8053, :8061).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VpnClientKind {
    OpenVpn,
    WireGuard,
}

impl VpnClientKind {
    fn parse(value: &str) -> Result<Self, PolicyError> {
        match value {
            "openvpn" => Ok(Self::OpenVpn),
            "wireguard" => Ok(Self::WireGuard),
            _ => Err(PolicyError::InvalidValue("VPN client kind")),
        }
    }

    fn client_max(self) -> u8 {
        match self {
            Self::OpenVpn => OVPN_CLIENT_MAX,
            Self::WireGuard => WG_CLIENT_MAX,
        }
    }

    fn input_chain(self) -> &'static str {
        match self {
            Self::OpenVpn => "OVPNCI",
            Self::WireGuard => "WGCI",
        }
    }

    fn forward_chain(self) -> &'static str {
        match self {
            Self::OpenVpn => "OVPNCF",
            Self::WireGuard => "WGCF",
        }
    }

    /// Tunnel interface the vendor assigns to client `unit`: `tun1N` for the
    /// default `vpn_clientN_if=tun` (libovpn/openvpn_control.c:845-846 with
    /// OVPN_CLIENT_BASE) and `wgcN` (rc/wireguard.c:171).
    pub fn vendor_interface(self, unit: u8) -> String {
        match self {
            Self::OpenVpn => format!("tun{}", u16::from(OVPN_CLIENT_BASE) + u16::from(unit)),
            Self::WireGuard => format!("wgc{unit}"),
        }
    }

    /// `ip rule` priority slot of the client's kill-switch entries
    /// (libovpn/amvpn_routing.c:892 and :962).
    fn kill_switch_priority(self, unit: u8) -> u32 {
        let base = match self {
            Self::OpenVpn => VPNDIR_PRIO_KS_OPENVPN,
            Self::WireGuard => VPNDIR_PRIO_KS_WIREGUARD,
        };
        base + u32::from(unit) - 1
    }
}

/// One vendor VPN client profile (`vpn_clientN_*` or `wgcN_*` NVRAM prefix)
/// together with the per-profile requirements read from it: `inbound_block`
/// mirrors `vpn_clientN_fw`/`wgcN_fw` and `kill_switch` mirrors
/// `vpn_clientN_enforce`/`wgcN_enforce` (shared/defaults.c:5311, :5449).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VpnClientProfile {
    pub kind: VpnClientKind,
    pub unit: u8,
    pub interface: String,
    pub inbound_block: bool,
    /// Require the vendor `enforce` kill-switch route (`ks`). Its scope is
    /// exactly what `amvpn_set_killswitch_rules` installs
    /// (libovpn/amvpn_routing.c:874-1019):
    ///
    /// - OpenVPN `rgw=1` (`OVPN_RGW_ALL`) installs one `from all iif LAN
    ///   prohibit` (:903), which covers every LAN source.
    /// - OpenVPN `rgw=2` (`OVPN_RGW_POLICY`, :923) and every WireGuard
    ///   profile (:987, WireGuard is always policy-routed, :215) install one
    ///   `from SRC prohibit` per *enabled* VPN Director source. The VPN
    ///   Director configuration is not an input here, so one such entry at
    ///   the slot proves that some source is enforced, not that every
    ///   enabled source is.
    /// - OpenVPN `rgw=0` (`OVPN_RGW_NONE`) and `rgw=3`
    ///   (`OVPN_RGW_POLICY_STRICT`) install no kill-switch rule at all: the
    ///   installer only handles `OVPN_RGW_ALL` and `OVPN_RGW_POLICY`
    ///   (:902-929, enum openvpn_config.h:58-63). Request `ks` only for
    ///   `rgw` in {1, 2}; for the other modes the requirement always fails.
    /// - The rules are IPv4 only (`ip rule`, never `ip -6 rule`), so even
    ///   with `require_ipv6` the fact says nothing about IPv6 LAN traffic.
    pub kill_switch: bool,
}

impl VpnClientProfile {
    pub fn new(
        kind: VpnClientKind,
        unit: u8,
        interface: &str,
        inbound_block: bool,
        kill_switch: bool,
    ) -> Result<Self, PolicyError> {
        if unit == 0 || unit > kind.client_max() {
            return Err(PolicyError::InvalidValue("VPN client unit"));
        }
        validate_interface(interface)?;
        if !inbound_block && !kill_switch {
            return Err(PolicyError::Missing("VPN client requirement"));
        }
        Ok(Self {
            kind,
            unit,
            interface: interface.to_owned(),
            inbound_block,
            kill_switch,
        })
    }

    /// Parse `KIND:UNIT[:INTERFACE]:FLAGS`, where KIND is `openvpn` or
    /// `wireguard`, FLAGS is `fw`, `ks` or `fw+ks`, and an omitted INTERFACE
    /// selects [`VpnClientKind::vendor_interface`].
    pub fn parse(value: &str) -> Result<Self, PolicyError> {
        if value.len() > MAX_VPN_CLIENT_PROFILE_BYTES {
            return Err(PolicyError::TooLong);
        }
        if !value.is_ascii() {
            return Err(PolicyError::NonAscii);
        }
        let fields: Vec<_> = value.split(':').collect();
        let (kind, unit, interface, flags) = match fields.as_slice() {
            [kind, unit, flags] => (*kind, *unit, None, *flags),
            [kind, unit, interface, flags] => (*kind, *unit, Some(*interface), *flags),
            _ => return Err(PolicyError::InvalidFormat),
        };
        // A flag word in the interface slot is a misplaced flag, not a name.
        if matches!(interface, Some("fw" | "ks" | "fw+ks")) {
            return Err(PolicyError::InvalidFormat);
        }
        let kind = VpnClientKind::parse(kind)?;
        if unit.is_empty()
            || unit.len() > 2
            || unit.starts_with('0')
            || !unit.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(PolicyError::InvalidValue("VPN client unit"));
        }
        let unit = unit
            .parse::<u8>()
            .map_err(|_| PolicyError::InvalidValue("VPN client unit"))?;
        let (inbound_block, kill_switch) = match flags {
            "fw" => (true, false),
            "ks" => (false, true),
            "fw+ks" => (true, true),
            _ => return Err(PolicyError::InvalidValue("VPN client flags")),
        };
        let interface = interface.map_or_else(|| kind.vendor_interface(unit), str::to_owned);
        Self::new(kind, unit, &interface, inbound_block, kill_switch)
    }
}

/// Per-profile VPN client expectations checked by
/// [`FirewallManifest::validate_vpn_clients`]. `lan_interface` is
/// `lan_ifname`, the ingress interface of the vendor's global kill-switch
/// route (amvpn_routing.c:903).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VpnClientRequirements {
    pub profiles: Vec<VpnClientProfile>,
    pub lan_interface: String,
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
    /// The vendor client chains for `kind` are hooked from INPUT and FORWARD
    /// behind rules that cannot admit `vpn_interface` traffic, and carry the
    /// `fw=1` rules for `vpn_interface` ahead of anything that could match
    /// it, without their `fw=0` counterparts (see `vpn_client_inbound_block`).
    VpnClientInboundBlock {
        family: AddressFamily,
        kind: VpnClientKind,
        vpn_interface: String,
    },
    /// Every `ip rule` entry at the client's VPN Director kill-switch
    /// priority is an exact vendor `prohibit` shape, at least one exists, and
    /// every entry numbered below it is a known vendor shape that cannot
    /// shadow the slot (see [`FirewallManifest::add_effective_policy_routes`]).
    VpnKillSwitchRoute { kind: VpnClientKind, unit: u8 },
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

    /// Derive the terminal-DROP facts plus, per family and profile, whether
    /// the vendor client chains carry the profile's inbound-block rules. The
    /// derivation is a pure function of `iptables-save` text; it neither
    /// requires nor rejects profiles whose rules are absent, so the same
    /// manifest can be checked against differently toggled requirements.
    pub fn from_effective_filter_saves_with_vpn_clients(
        ipv4: &str,
        ipv6: Option<&str>,
        profiles: &[VpnClientProfile],
    ) -> Result<Self, PolicyError> {
        let mut rules = Vec::new();
        let mut derive = |input: &str, family: AddressFamily| -> Result<(), PolicyError> {
            let table = parse_filter_table(input)?;
            rules.extend(terminal_drop_facts(&table, family)?);
            for profile in profiles {
                let rule = FirewallRule::VpnClientInboundBlock {
                    family,
                    kind: profile.kind,
                    vpn_interface: profile.interface.clone(),
                };
                if vpn_client_inbound_block(&table, profile) && !rules.contains(&rule) {
                    rules.push(rule);
                }
            }
            Ok(())
        };
        derive(ipv4, AddressFamily::Ipv4)?;
        if let Some(ipv6) = ipv6 {
            derive(ipv6, AddressFamily::Ipv6)?;
        }
        Ok(Self { rules })
    }

    /// Add [`FirewallRule::VpnKillSwitchRoute`] facts derived from `ip rule
    /// show` output. The vendor installs the `enforce` kill switch as policy
    /// routes, never as netfilter rules, so it is invisible to
    /// `iptables-save` (libovpn/amvpn_routing.c:874-1019): `from all iif LAN
    /// priority P prohibit` for redirect-all OpenVPN clients (:903) and
    /// `from SRC priority P prohibit` per enabled VPN Director source (:923
    /// OpenVPN, :987 WireGuard), with P the client's VPNDIR_PRIO_KS_* slot
    /// (:892, :962). Only those printed shapes are recognised at the slot;
    /// any other entry sharing a profile's priority makes that slot
    /// ambiguous and no fact is derived for it.
    ///
    /// Policy routing stops at the first rule whose `lookup` finds a route,
    /// so any rule numbered below P can shadow the `prohibit`. The vendor
    /// deliberately places its own rules below the slot; exactly those
    /// shapes are accepted there (see `vendor_route_below_kill_switch`) and
    /// any other entry with a priority below P makes the slot ambiguous.
    /// Rules above P are irrelevant, including the kernel's `32766: from all
    /// lookup main` and `32767: from all lookup default`. A line that is not
    /// `PRIORITY:<rule>` cannot be placed on the ladder, so it withholds
    /// every fact. The vendor only ever adds IPv4 routes; see
    /// [`VpnClientProfile::kill_switch`] for what the fact does and does not
    /// prove.
    pub fn add_effective_policy_routes(
        &mut self,
        policy_routes: &str,
        lan_interface: &str,
        profiles: &[VpnClientProfile],
    ) -> Result<(), PolicyError> {
        validate_interface(lan_interface)?;
        if policy_routes.len() > MAX_POLICY_ROUTES_BYTES {
            return Err(PolicyError::TooLong);
        }
        if !policy_routes.is_ascii() {
            return Err(PolicyError::NonAscii);
        }

        let mut entries = Vec::<(u32, Vec<&str>)>::new();
        for line in policy_routes.lines().map(str::trim) {
            if line.is_empty() {
                continue;
            }
            let Some((priority, rule)) = line.split_once(':') else {
                return Ok(());
            };
            if priority.is_empty() || !priority.bytes().all(|byte| byte.is_ascii_digit()) {
                return Ok(());
            }
            let Ok(priority) = priority.parse::<u32>() else {
                return Ok(());
            };
            entries.push((priority, rule.split_ascii_whitespace().collect()));
        }

        for profile in profiles {
            let slot = profile.kind.kill_switch_priority(profile.unit);
            let rule = FirewallRule::VpnKillSwitchRoute {
                kind: profile.kind,
                unit: profile.unit,
            };
            let mut present = false;
            let mut unshadowed = true;
            for (priority, words) in &entries {
                if *priority == slot {
                    if kill_switch_prohibit(profile.kind, words, lan_interface) {
                        present = true;
                    } else {
                        unshadowed = false;
                    }
                } else if *priority < slot
                    && !vendor_route_below_kill_switch(*priority, words, lan_interface)
                {
                    unshadowed = false;
                }
            }
            if present && unshadowed && !self.rules.contains(&rule) {
                self.rules.push(rule);
            }
        }
        Ok(())
    }

    /// Enforce every per-profile requirement: inbound-block coverage for
    /// IPv4 (and IPv6 when required) and the kill-switch route slot. Missing
    /// coverage fails closed. The kill-switch fact is IPv4 only and, for
    /// policy-routed profiles, proves one enforced VPN Director source
    /// rather than all of them; profiles whose `rgw` mode installs no vendor
    /// rule (`OVPN_RGW_NONE`, `OVPN_RGW_POLICY_STRICT`) can never satisfy
    /// `ks` (see [`VpnClientProfile::kill_switch`]).
    pub fn validate_vpn_clients(
        &self,
        requirements: &VpnClientRequirements,
        require_ipv6: bool,
    ) -> Result<(), PolicyError> {
        requirements.validate()?;
        for profile in &requirements.profiles {
            if profile.inbound_block {
                for family in [AddressFamily::Ipv4]
                    .into_iter()
                    .chain(require_ipv6.then_some(AddressFamily::Ipv6))
                {
                    if !self.rules.contains(&FirewallRule::VpnClientInboundBlock {
                        family,
                        kind: profile.kind,
                        vpn_interface: profile.interface.clone(),
                    }) {
                        return Err(PolicyError::Invariant("VPN client inbound block"));
                    }
                }
            }
            if profile.kill_switch
                && !self.rules.contains(&FirewallRule::VpnKillSwitchRoute {
                    kind: profile.kind,
                    unit: profile.unit,
                })
            {
                return Err(PolicyError::Invariant("VPN kill switch route"));
            }
        }
        Ok(())
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

/// [`validate_effective_firewall_policy`] plus, only when `vpn_clients` is
/// given, [`validate_effective_vpn_client_policy`]. Passing `None` keeps
/// the behaviour of the plain policy check unchanged.
#[allow(clippy::too_many_arguments)]
pub fn validate_effective_firewall_policy_with_vpn_clients(
    ipv4: &str,
    ipv6: Option<&str>,
    require_ipv6: bool,
    wan_ipv4_interface: &str,
    wan_ipv6_interface: Option<&str>,
    admin_tcp_ports: &[u16],
    policy_routes: Option<&str>,
    vpn_clients: Option<&VpnClientRequirements>,
) -> Result<(), PolicyError> {
    validate_effective_firewall_policy(
        ipv4,
        ipv6,
        require_ipv6,
        wan_ipv4_interface,
        wan_ipv6_interface,
        admin_tcp_ports,
    )?;
    if let Some(requirements) = vpn_clients {
        validate_effective_vpn_client_policy(
            ipv4,
            ipv6,
            require_ipv6,
            policy_routes,
            requirements,
        )?;
    }
    Ok(())
}

/// Validate the per-profile VPN client contract on top of the terminal DROP
/// invariant. `policy_routes` is `ip rule show` output and is mandatory as
/// soon as any profile requires the kill switch.
pub fn validate_effective_vpn_client_policy(
    ipv4: &str,
    ipv6: Option<&str>,
    require_ipv6: bool,
    policy_routes: Option<&str>,
    requirements: &VpnClientRequirements,
) -> Result<(), PolicyError> {
    requirements.validate()?;
    if require_ipv6 && ipv6.is_none() {
        return Err(PolicyError::Missing("IPv6 ruleset"));
    }
    let mut manifest = FirewallManifest::from_effective_filter_saves_with_vpn_clients(
        ipv4,
        ipv6,
        &requirements.profiles,
    )?;
    if requirements
        .profiles
        .iter()
        .any(|profile| profile.kill_switch)
    {
        let policy_routes = policy_routes.ok_or(PolicyError::Missing("policy routes"))?;
        manifest.add_effective_policy_routes(
            policy_routes,
            &requirements.lan_interface,
            &requirements.profiles,
        )?;
    }
    manifest.validate_terminal_drops(require_ipv6)?;
    manifest.validate_vpn_clients(requirements, require_ipv6)
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

/// The `*filter` table of one `iptables-save` dump: the builtin INPUT and
/// FORWARD rule lists and every other chain's rules, in dump order. A chain
/// that is declared (`:NAME - [0:0]`) but carries no rule is present with an
/// empty rule list.
struct FilterTable {
    input: Vec<Vec<String>>,
    forward: Vec<Vec<String>>,
    user_chains: HashMap<String, Vec<Vec<String>>>,
}

fn parse_filter_table(input: &str) -> Result<FilterTable, PolicyError> {
    if input.len() > MAX_EFFECTIVE_RULESET_BYTES {
        return Err(PolicyError::TooLong);
    }
    if !input.is_ascii() {
        return Err(PolicyError::NonAscii);
    }

    let mut in_filter = false;
    let mut committed = false;
    let mut table = FilterTable {
        input: Vec::new(),
        forward: Vec::new(),
        user_chains: HashMap::new(),
    };
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
            [declaration, ..] if declaration.len() > 1 && declaration.starts_with(':') => {
                let chain = &declaration[1..];
                if chain != "INPUT" && chain != "FORWARD" {
                    table.user_chains.entry(chain.to_owned()).or_default();
                }
            }
            ["-A", chain, rest @ ..] => {
                let rule = rest.iter().map(|word| (*word).to_owned()).collect();
                match *chain {
                    "INPUT" => table.input.push(rule),
                    "FORWARD" => table.forward.push(rule),
                    _ => table
                        .user_chains
                        .entry((*chain).to_owned())
                        .or_default()
                        .push(rule),
                }
            }
            _ => {}
        }
    }
    if in_filter || !committed {
        return Err(PolicyError::InvalidFormat);
    }
    Ok(table)
}

fn terminal_drop_rules(
    input: &str,
    family: AddressFamily,
) -> Result<Vec<FirewallRule>, PolicyError> {
    terminal_drop_facts(&parse_filter_table(input)?, family)
}

fn terminal_drop_facts(
    table: &FilterTable,
    family: AddressFamily,
) -> Result<Vec<FirewallRule>, PolicyError> {
    fn last_target(rules: &[Vec<String>]) -> Option<&str> {
        rules.last().and_then(|rule| match rule.as_slice() {
            [jump, target] if jump == "-j" => Some(target.as_str()),
            _ => None,
        })
    }
    if !last_target_is_drop(last_target(&table.input), &table.user_chains)
        || !last_target_is_drop(last_target(&table.forward), &table.user_chains)
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

/// Recognise the vendor `fw=1` ("Inbound Firewall: Block") rule set for one
/// client profile, exactly as its firewall script installs it:
/// `-I OVPNCF -i IF -j DROP`, `-I OVPNCF -o IF -j ACCEPT` and
/// `-I OVPNCI -i IF -j DROP` (libovpn/openvpn_setup.c:965-967; ip6tables
/// :982-984) or `-I WGCI -i IF -j DROP`, `-I WGCF -i IF -j DROP` and
/// `-I WGCF -o IF -j ACCEPT` (rc/wireguard.c:697-699; ip6tables :700-702).
/// Both chains must be hooked from their builtin chain (firewall.c:5332,
/// :5343, :6172, :6180; dual-WAN `filter_setting2` :7129, :7140, :8050,
/// :8058). The `fw=0` counterpart of either DROP (the same generator lines
/// with `-j ACCEPT`) must be absent from its chain: with both present the
/// effective verdict depends on insertion order, which is ambiguous and
/// therefore not recognised.
///
/// The rules must also be reachable. Every rule ahead of the hook in the
/// builtin chain must be provably unable to admit `IF` traffic
/// (`hook_reachable`), and every rule ahead of the client rules inside the
/// client chain must be scoped to another interface or be non-terminating
/// (`client_chain_blocks`). The vendor inserts with `-I`, so in dump order
/// a client's rules sit at the top of its chain, preceded only by the rules
/// of clients started later (which carry their own `-i`/`-o` interface) and
/// the WireGuard TCPMSS clamp (wireguard.c:708). Anything else ahead of them
/// is ambiguous and yields no fact.
fn vpn_client_inbound_block(table: &FilterTable, profile: &VpnClientProfile) -> bool {
    let kind = profile.kind;
    let interface = profile.interface.as_str();
    let has = |rules: &[Vec<String>], expected: [&str; 4]| {
        rules.iter().any(|rule| rule.as_slice() == expected)
    };
    let (Some(input_chain), Some(forward_chain)) = (
        table.user_chains.get(kind.input_chain()),
        table.user_chains.get(kind.forward_chain()),
    ) else {
        return false;
    };
    if has(input_chain, ["-i", interface, "-j", "ACCEPT"])
        || has(forward_chain, ["-i", interface, "-j", "ACCEPT"])
    {
        return false;
    }
    hook_reachable(
        table,
        &table.input,
        kind.input_chain(),
        interface,
        FilterChain::Input,
    ) && hook_reachable(
        table,
        &table.forward,
        kind.forward_chain(),
        interface,
        FilterChain::Forward,
    ) && client_chain_blocks(input_chain, interface, FilterChain::Input)
        && client_chain_blocks(forward_chain, interface, FilterChain::Forward)
}

/// The client chain carries `-i IF -j DROP` (and, for the FORWARD side,
/// `-o IF -j ACCEPT`) before any rule that could match `IF` traffic. A
/// preceding rule is tolerated only when it is scoped to another interface
/// (a positive `-i OTHER`, or a positive `-o OTHER` on the FORWARD side,
/// which is the shape of every other client's rules: openvpn_setup.c:965-
/// 967, wireguard.c:697-699) or when its only target is non-terminating
/// (`LOG`, or the `TCPMSS` clamp of wireguard.c:708). Rules after the
/// client's own rules cannot reach `IF` packets and are ignored.
fn client_chain_blocks(rules: &[Vec<String>], interface: &str, chain: FilterChain) -> bool {
    let drop = ["-i", interface, "-j", "DROP"];
    let accept = ["-o", interface, "-j", "ACCEPT"];
    let allow_egress = chain == FilterChain::Forward;
    let mut need_drop = true;
    let mut need_accept = allow_egress;
    for rule in rules {
        if !need_drop && !need_accept {
            break;
        }
        if need_drop && rule.as_slice() == drop {
            need_drop = false;
        } else if need_accept && rule.as_slice() == accept {
            need_accept = false;
        } else if !scoped_to_other_interface(rule, interface, allow_egress)
            && !non_terminating(rule)
        {
            return false;
        }
    }
    !need_drop && !need_accept
}

/// The builtin chain reaches `-j HOOK` before any rule that could admit
/// `interface` traffic. Rules ahead of the hook are accepted only in these
/// shapes, which the vendor emits there (rc/firewall.c `filter_setting`
/// INPUT :5002-5327 and FORWARD :5407-6166; `filter_setting2` :6801-7104 and
/// :7204-8043):
///
/// - a positive `-i OTHER` that cannot match `interface` (`-i lo`, `-i br0`,
///   `-i eth0 -j CODEX_WAN_GUARD`, `-i pptp+`, ...);
/// - `-m state --state RELATED,ESTABLISHED -j T` in either order (:5002,
///   :5488), which cannot admit a new inbound flow whatever `T` is;
/// - a single non-terminating target, `LOG` or `TCPMSS` (:5427);
/// - a single terminal denial, `DROP` or `REJECT` (:5003, :5574), which
///   only tightens the verdict;
/// - a single jump into a user chain every rule of which is one of these
///   shapes or `-j RETURN`, such as the empty or restricted server chains
///   `WGSI`/`OVPNSI` (:5331, :5342) and `WGSF`/`OVPNSF` (:5523, :5530);
///   inside the vendor client FORWARD chains a positive `-o OTHER` also
///   counts, since another client's `-o wgcN -j ACCEPT` sits there
///   (wireguard.c:699) ahead of the OpenVPN hook (:6172 before :6180).
///
/// Following the `last_target_is_drop` precedent, any `-g`/`--goto`, any
/// rule with more or fewer than one `-j`, and every other target (`ACCEPT`,
/// `RETURN` in the builtin chain, unknown extensions) make the hook
/// ambiguous.
fn hook_reachable(
    table: &FilterTable,
    builtin: &[Vec<String>],
    hook: &str,
    interface: &str,
    chain: FilterChain,
) -> bool {
    let Some(position) = builtin
        .iter()
        .position(|rule| rule.as_slice() == ["-j", hook])
    else {
        return false;
    };
    builtin[..position]
        .iter()
        .all(|rule| harmless_before_hook(table, rule, interface, chain, None, 0))
}

fn harmless_before_hook(
    table: &FilterTable,
    rule: &[String],
    interface: &str,
    chain: FilterChain,
    user_chain: Option<&str>,
    depth: usize,
) -> bool {
    let Some(jumps) = jump_targets(rule) else {
        return false;
    };
    let allow_egress = chain == FilterChain::Forward
        && user_chain.is_some_and(|name| {
            name == VpnClientKind::OpenVpn.forward_chain()
                || name == VpnClientKind::WireGuard.forward_chain()
        });
    if scoped_to_other_interface(rule, interface, allow_egress) || established_only(rule) {
        return true;
    }
    let [target] = jumps.as_slice() else {
        return false;
    };
    match *target {
        "LOG" | "TCPMSS" | "DROP" | "REJECT" => true,
        "RETURN" => user_chain.is_some(),
        target => {
            depth < MAX_HOOK_CHAIN_DEPTH
                && table.user_chains.get(target).is_some_and(|rules| {
                    rules.iter().all(|rule| {
                        harmless_before_hook(table, rule, interface, chain, Some(target), depth + 1)
                    })
                })
        }
    }
}

/// The rule carries a positive interface match that cannot select
/// `interface`: `-i OTHER` always, `-o OTHER` only where `allow_egress`.
/// A positive `-i` that does select `interface` disqualifies the rule even
/// when an `-o OTHER` is present. Negated matches (`! -i X`) never count.
fn scoped_to_other_interface(rule: &[String], interface: &str, allow_egress: bool) -> bool {
    let excludes = |flag: &str| {
        positive_option(rule, flag)
            .is_some_and(|pattern| !interface_pattern_matches(pattern, interface))
    };
    let ingress = positive_option(rule, "-i");
    if ingress.is_some_and(|pattern| interface_pattern_matches(pattern, interface)) {
        return false;
    }
    ingress.is_some() || (allow_egress && excludes("-o"))
}

/// Exactly `-m state --state RELATED,ESTABLISHED -j T` (or the
/// `ESTABLISHED,RELATED` and `-m conntrack --ctstate` spellings): a match
/// that only ever sees packets of flows conntrack already admitted.
fn established_only(rule: &[String]) -> bool {
    let words: Vec<&str> = rule.iter().map(String::as_str).collect();
    matches!(
        words.as_slice(),
        ["-m", "state", "--state", states, "-j", _]
            | ["-m", "conntrack", "--ctstate", states, "-j", _]
            if *states == "RELATED,ESTABLISHED" || *states == "ESTABLISHED,RELATED"
    )
}

/// The rule's only target is one that never ends rule traversal.
fn non_terminating(rule: &[String]) -> bool {
    jump_targets(rule)
        .is_some_and(|jumps| jumps.as_slice() == ["LOG"] || jumps.as_slice() == ["TCPMSS"])
}

/// Every `-j` target of the rule in order, or `None` when the rule uses
/// `-g`/`--goto` (as in `last_target_is_drop`).
fn jump_targets(rule: &[String]) -> Option<Vec<&str>> {
    if rule.iter().any(|word| word == "-g" || word == "--goto") {
        return None;
    }
    Some(
        rule.windows(2)
            .filter_map(|words| (words[0] == "-j").then_some(words[1].as_str()))
            .collect(),
    )
}

/// The value of the first `flag` in the rule that is not negated by a
/// preceding `!`.
fn positive_option<'a>(rule: &'a [String], flag: &str) -> Option<&'a str> {
    rule.iter().enumerate().find_map(|(index, word)| {
        if word != flag || (index > 0 && rule[index - 1] == "!") {
            return None;
        }
        rule.get(index + 1).map(String::as_str)
    })
}

/// iptables interface matching: an exact name, or a `PREFIX+` wildcard
/// that selects every interface whose name starts with `PREFIX`.
fn interface_pattern_matches(pattern: &str, interface: &str) -> bool {
    match pattern.strip_suffix('+') {
        Some(prefix) => interface.starts_with(prefix),
        None => pattern == interface,
    }
}

/// An `ip rule show` line at a client's kill-switch slot in the exact shape
/// `amvpn_set_killswitch_rules` prints there: `from all iif LAN prohibit`
/// for redirect-all OpenVPN clients (amvpn_routing.c:903) or `from SRC
/// prohibit` per VPN Director source (:923 OpenVPN, :987 WireGuard).
/// WireGuard clients are always policy-routed (:215), so their slots never
/// carry the `iif` form.
fn kill_switch_prohibit(kind: VpnClientKind, words: &[&str], lan_interface: &str) -> bool {
    match words {
        ["from", "all", "iif", interface, "prohibit"] => {
            kind == VpnClientKind::OpenVpn && *interface == lan_interface
        }
        ["from", source, "prohibit"] => valid_ipv4_selector(source),
        _ => false,
    }
}

/// An `ip rule show` line numbered below a kill-switch slot that the vendor
/// itself installs there, and so cannot shadow the slot in a way the vendor
/// did not intend. Exactly these shapes are accepted:
///
/// - `0: from all lookup local`, the kernel default;
/// - `90: from all to ADDR lookup main` for a VPN server peer
///   (IP_RULE_PREF_VPNS: the PPTP peer address, rc/vpn.c:330, and WireGuard
///   server allowed IPs, rc/wireguard.c:1294);
/// - `1000N: from all lookup ovpncN` for OpenVPN client N in redirect-all
///   mode (amvpn_routing.c:230, VPNDIR_PRIO_ALL + unit);
/// - VPN Director rules (`_write_routing_rules`, amvpn_routing.c:275-281,
///   :297-308, :355): `from SRC [to DST] lookup T` or `from all to DST
///   lookup T`, where the priority range fixes `T`: 10010-10209 `main`
///   (WAN), 10210 + 200*(N-1) `ovpncN` and 11210 + 200*(N-1) `wgcN`. A
///   rule with neither source nor destination is not accepted: `from all
///   lookup main` there would send everything to the WAN ahead of the
///   kill switch;
/// - kill-switch entries of lower-numbered clients in 12210-12219
///   (`kill_switch_prohibit`), which only deny more.
///
/// Everything else below the slot is ambiguous, including `from all lookup
/// main` at any other priority, VPN Fusion and multi-WAN rules
/// (shared/shared.h:5718-5763) and the SDN slot 12220 (above every slot,
/// so irrelevant anyway).
fn vendor_route_below_kill_switch(priority: u32, words: &[&str], lan_interface: &str) -> bool {
    match (priority, words) {
        (0, ["from", "all", "lookup", "local"]) => true,
        (IP_RULE_PREF_VPNS, ["from", "all", "to", peer, "lookup", "main"]) => {
            valid_ipv4_selector(peer)
        }
        (priority, ["from", "all", "lookup", table])
            if priority > VPNDIR_PRIO_ALL
                && priority <= VPNDIR_PRIO_ALL + u32::from(OVPN_CLIENT_MAX) =>
        {
            *table == format!("ovpnc{}", priority - VPNDIR_PRIO_ALL)
        }
        (priority, _) if (VPNDIR_PRIO_WAN..VPNDIR_PRIO_KS_OPENVPN).contains(&priority) => {
            vpn_director_route(priority, words)
        }
        (priority, _) if (VPNDIR_PRIO_KS_OPENVPN..VPNDIR_PRIO_KS_WIREGUARD).contains(&priority) => {
            kill_switch_prohibit(VpnClientKind::OpenVpn, words, lan_interface)
        }
        (priority, _) if (VPNDIR_PRIO_KS_WIREGUARD..VPNDIR_PRIO_KS_SDN).contains(&priority) => {
            kill_switch_prohibit(VpnClientKind::WireGuard, words, lan_interface)
        }
        _ => false,
    }
}

/// A VPN Director rule as `ip rule show` prints `ip rule add [from SRC] [to
/// DST] table T priority P` (amvpn_routing.c:355): the table must be the
/// one the priority range is reserved for and at least one selector must
/// be present.
fn vpn_director_route(priority: u32, words: &[&str]) -> bool {
    let ["from", source, rest @ ..] = words else {
        return false;
    };
    let (destination, rest) = match rest {
        ["to", destination, rest @ ..] => (Some(*destination), rest),
        _ => (None, rest),
    };
    let ["lookup", table] = rest else {
        return false;
    };
    let selected_source = *source != "all";
    if (selected_source && !valid_ipv4_selector(source))
        || destination.is_some_and(|destination| !valid_ipv4_selector(destination))
        || (!selected_source && destination.is_none())
    {
        return false;
    }
    let expected = if priority < VPNDIR_PRIO_OPENVPN {
        "main".to_owned()
    } else if priority < VPNDIR_PRIO_WIREGUARD {
        format!(
            "ovpnc{}",
            (priority - VPNDIR_PRIO_OPENVPN) / VPNDIR_PRIO_MAX_RULES + 1
        )
    } else {
        format!(
            "wgc{}",
            (priority - VPNDIR_PRIO_WIREGUARD) / VPNDIR_PRIO_MAX_RULES + 1
        )
    };
    *table == expected
}

/// A VPN Director source or destination as `ip rule show` prints it: a host
/// address or an address with a 1-32 bit prefix. The vendor never installs
/// `0.0.0.0` (amvpn_routing.c:315, :350, :921, :985).
fn valid_ipv4_selector(value: &str) -> bool {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let Ok(address) = address.parse::<Ipv4Addr>() else {
        return false;
    };
    if address.is_unspecified() {
        return false;
    }
    prefix.is_none_or(|prefix| {
        !prefix.is_empty()
            && prefix.len() <= 2
            && prefix.bytes().all(|byte| byte.is_ascii_digit())
            && prefix
                .parse::<u8>()
                .is_ok_and(|length| (1..=32).contains(&length))
    })
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

impl VpnClientRequirements {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.profiles.is_empty() {
            return Err(PolicyError::Missing("VPN client profile"));
        }
        if self.profiles.len() > MAX_VPN_CLIENT_PROFILES {
            return Err(PolicyError::TooLong);
        }
        validate_interface(&self.lan_interface)?;
        let mut units = HashSet::new();
        let mut interfaces = HashSet::new();
        for profile in &self.profiles {
            // Public fields may have bypassed the constructor.
            VpnClientProfile::new(
                profile.kind,
                profile.unit,
                &profile.interface,
                profile.inbound_block,
                profile.kill_switch,
            )?;
            if profile.interface == self.lan_interface {
                return Err(PolicyError::InvalidValue("VPN interface"));
            }
            if !units.insert((profile.kind, profile.unit))
                || !interfaces.insert(profile.interface.as_str())
            {
                return Err(PolicyError::Duplicate("VPN client profile"));
            }
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

    #[test]
    fn vpn_client_profiles_parse_only_vendor_units_and_explicit_flags() {
        let profile = VpnClientProfile::parse("openvpn:1:fw+ks").unwrap();
        assert_eq!(profile.kind, VpnClientKind::OpenVpn);
        assert_eq!(profile.unit, 1);
        assert_eq!(profile.interface, "tun11");
        assert!(profile.inbound_block && profile.kill_switch);
        assert_eq!(
            VpnClientProfile::parse("wireguard:5:ks").unwrap(),
            VpnClientProfile::new(VpnClientKind::WireGuard, 5, "wgc5", false, true).unwrap()
        );
        assert_eq!(
            VpnClientProfile::parse("openvpn:2:tap12:fw")
                .unwrap()
                .interface,
            "tap12"
        );
        assert_eq!(VpnClientKind::OpenVpn.vendor_interface(5), "tun15");
        assert_eq!(VpnClientKind::WireGuard.vendor_interface(255), "wgc255");
        assert_eq!(VpnClientKind::OpenVpn.kill_switch_priority(1), 12_210);
        assert_eq!(VpnClientKind::OpenVpn.kill_switch_priority(5), 12_214);
        assert_eq!(VpnClientKind::WireGuard.kill_switch_priority(1), 12_215);
        assert_eq!(VpnClientKind::WireGuard.kill_switch_priority(5), 12_219);

        for invalid in [
            "openvpn:0:fw",
            "openvpn:6:fw",
            "wireguard:6:ks",
            "openvpn:+1:fw",
            "openvpn:01:fw",
            "openvpn:1:",
            "openvpn:1:none",
            "openvpn:1:fw:ks",
            "openvpn:1:tun11",
            "openvpn:1:bad;if:fw",
            "openvpn:1:-tun11:fw",
            "ipsec:1:fw",
            "OpenVPN:1:fw",
            "openvpn:1:fw,ks",
            "",
        ] {
            assert!(
                VpnClientProfile::parse(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert_eq!(
            VpnClientProfile::new(VpnClientKind::OpenVpn, 1, "tun11", false, false),
            Err(PolicyError::Missing("VPN client requirement"))
        );
    }

    #[test]
    fn vpn_client_requirements_reject_conflicting_profiles() {
        let openvpn = VpnClientProfile::parse("openvpn:1:fw").unwrap();
        let wireguard = VpnClientProfile::parse("wireguard:1:fw").unwrap();
        let valid = VpnClientRequirements {
            profiles: vec![openvpn.clone(), wireguard.clone()],
            lan_interface: "br0".into(),
        };
        valid.validate().unwrap();

        let mut tampered = openvpn.clone();
        tampered.unit = 9;
        let mut same_interface = wireguard.clone();
        same_interface.interface = "tun11".into();
        for (profiles, lan_interface) in [
            (vec![], "br0"),
            (vec![openvpn.clone(), openvpn.clone()], "br0"),
            (vec![openvpn.clone(), same_interface], "br0"),
            (vec![tampered], "br0"),
            (vec![openvpn.clone()], "tun11"),
            (vec![openvpn.clone()], "br 0"),
            (vec![openvpn.clone()], ""),
        ] {
            let requirements = VpnClientRequirements {
                profiles,
                lan_interface: lan_interface.into(),
            };
            assert!(
                requirements.validate().is_err(),
                "accepted {requirements:?}"
            );
        }
        let too_many = VpnClientRequirements {
            profiles: (1..=5)
                .flat_map(|unit| {
                    [
                        VpnClientProfile::new(
                            VpnClientKind::OpenVpn,
                            unit,
                            &format!("tun1{unit}"),
                            true,
                            false,
                        )
                        .unwrap(),
                        VpnClientProfile::new(
                            VpnClientKind::WireGuard,
                            unit,
                            &format!("wgc{unit}"),
                            true,
                            false,
                        )
                        .unwrap(),
                    ]
                })
                .chain([
                    VpnClientProfile::new(VpnClientKind::OpenVpn, 1, "tap11", true, false).unwrap(),
                ])
                .collect(),
            lan_interface: "br0".into(),
        };
        assert_eq!(too_many.validate(), Err(PolicyError::TooLong));
    }

    #[test]
    fn policy_routes_only_yield_facts_for_exact_prohibit_slots() {
        let profiles = [
            VpnClientProfile::parse("openvpn:1:ks").unwrap(),
            VpnClientProfile::parse("wireguard:2:ks").unwrap(),
        ];
        let derive = |routes: &str| {
            let mut manifest = FirewallManifest { rules: Vec::new() };
            manifest
                .add_effective_policy_routes(routes, "br0", &profiles)
                .unwrap();
            manifest.rules
        };
        let openvpn = FirewallRule::VpnKillSwitchRoute {
            kind: VpnClientKind::OpenVpn,
            unit: 1,
        };
        let wireguard = FirewallRule::VpnKillSwitchRoute {
            kind: VpnClientKind::WireGuard,
            unit: 2,
        };

        assert_eq!(
            derive("0:\tfrom all lookup local\n12210:\tfrom all iif br0 prohibit\n12216:\tfrom 192.168.50.20 prohibit\n32766:\tfrom all lookup main\n"),
            vec![openvpn.clone(), wireguard.clone()]
        );
        assert_eq!(
            derive("12210:\tfrom 10.0.0.0/8 prohibit\n12210:\tfrom 192.168.50.7 prohibit\n"),
            vec![openvpn.clone()]
        );
        assert_eq!(
            derive("12210: from all iif br0 prohibit"),
            vec![openvpn.clone()]
        );
        assert_eq!(
            derive("12210:\tfrom all iif br0 prohibit\n12210:\tfrom all iif br0 prohibit\n"),
            vec![openvpn]
        );

        for unrecognised in [
            "",
            "12210:\tfrom all iif br1 prohibit\n",
            "12210:\tfrom all iif br0 lookup ovpnc1\n",
            "12210:\tfrom all iif br0 [detached] prohibit\n",
            "12210:\tfrom all iif br0 prohibit\n12210:\tfrom all lookup main\n",
            "12210:\tfrom all prohibit\n",
            "12210:\tfrom 0.0.0.0 prohibit\n",
            "12210:\tfrom 192.168.50.0/0 prohibit\n",
            "12210:\tfrom 192.168.50.0/33 prohibit\n",
            "12210:\tfrom 192.168.50.0/024 prohibit\n",
            "12210:\tfrom fd00::1 prohibit\n",
            "12210:\tnot from 192.168.50.7 prohibit\n",
            "12210:\tfrom 192.168.50.7 unreachable\n",
            "12210:\tfrom 192.168.50.7 blackhole\n",
            "12209:\tfrom all iif br0 prohibit\n",
            "12215:\tfrom all iif br0 prohibit\n",
            "12220:\tfrom all iif br0 prohibit\n",
            "12210 from all iif br0 prohibit\n",
            "+12210:\tfrom all iif br0 prohibit\n",
            "from all iif br0 prohibit\n",
        ] {
            assert!(
                derive(unrecognised).is_empty(),
                "derived a kill switch from {unrecognised:?}"
            );
        }

        let mut manifest = FirewallManifest { rules: Vec::new() };
        assert_eq!(
            manifest.add_effective_policy_routes(
                "12210:\tfrom all iif br0 prohibit\u{e9}",
                "br0",
                &profiles
            ),
            Err(PolicyError::NonAscii)
        );
        assert!(manifest
            .add_effective_policy_routes("", "br 0", &profiles)
            .is_err());
        assert_eq!(
            manifest.add_effective_policy_routes(
                &"x".repeat(MAX_POLICY_ROUTES_BYTES + 1),
                "br0",
                &profiles
            ),
            Err(PolicyError::TooLong)
        );
    }

    #[test]
    fn policy_routes_below_the_slot_must_be_vendor_shapes() {
        let profiles = [
            VpnClientProfile::parse("openvpn:1:ks").unwrap(),
            VpnClientProfile::parse("wireguard:2:ks").unwrap(),
        ];
        let derive = |routes: &str| {
            let mut manifest = FirewallManifest { rules: Vec::new() };
            manifest
                .add_effective_policy_routes(routes, "br0", &profiles)
                .unwrap();
            manifest.rules
        };
        let openvpn = FirewallRule::VpnKillSwitchRoute {
            kind: VpnClientKind::OpenVpn,
            unit: 1,
        };
        let wireguard = FirewallRule::VpnKillSwitchRoute {
            kind: VpnClientKind::WireGuard,
            unit: 2,
        };
        let both = vec![openvpn.clone(), wireguard.clone()];

        // Every vendor shape that may sit below the slots, all at once (see
        // `vendor_route_below_kill_switch`), with the kernel defaults above.
        let ladder = "\
0:\tfrom all lookup local
90:\tfrom all to 10.8.0.2 lookup main
90:\tfrom all to 10.6.0.0/24 lookup main
10001:\tfrom all lookup ovpnc1
10005:\tfrom all lookup ovpnc5
10010:\tfrom 192.168.50.30 lookup main
10011:\tfrom all to 203.0.113.0/24 lookup main
10012:\tfrom 192.168.50.31 to 203.0.113.7 lookup main
10210:\tfrom 192.168.50.0/24 lookup ovpnc1
10409:\tfrom 192.168.50.10 to 8.8.8.8 lookup ovpnc1
10410:\tfrom 192.168.50.11 lookup ovpnc2
11010:\tfrom all to 9.9.9.9 lookup ovpnc5
11210:\tfrom 192.168.50.20 lookup wgc1
11410:\tfrom all to 1.1.1.1 lookup wgc2
12209:\tfrom 192.168.50.21 lookup wgc5
12210:\tfrom all iif br0 prohibit
12211:\tfrom 192.168.50.40 prohibit
12215:\tfrom 192.168.50.41 prohibit
12216:\tfrom 192.168.50.20 prohibit
12220:\tfrom all iif br1 prohibit
32766:\tfrom all lookup main
32767:\tfrom all lookup default
";
        assert_eq!(derive(ladder), both);

        let slots = "12210:\tfrom all iif br0 prohibit\n12216:\tfrom 192.168.50.20 prohibit\n";
        // Rules above a slot never shadow it.
        for above in [
            "12217:\tfrom all lookup main\n",
            "12220:\tfrom all iif br0 prohibit\n",
            "20000:\tfrom all iif br0 lookup main\n",
        ] {
            assert_eq!(derive(&format!("{slots}{above}")), both, "{above:?}");
        }

        // Anything below both slots that is not a vendor shape shadows them:
        // no fact for either profile, wherever the line sits in the text.
        for shadow in [
            "5:\tfrom all lookup main\n",
            "100:\tfrom all iif br0 lookup main\n",
            "0:\tfrom all lookup main\n",
            "1:\tfrom all lookup local\n",
            "90:\tfrom all lookup main\n",
            "90:\tfrom 10.8.0.2 lookup main\n",
            "90:\tfrom all to 0.0.0.0/0 lookup main\n",
            "90:\tfrom all to 10.8.0.2 lookup ovpnc1\n",
            "999:\tfrom all iif br0 lookup main\n",
            "1000:\tfrom all iif br0 lookup 1001\n",
            "5000:\tfrom all fwmark 0x100/0xf00 lookup wan0\n",
            "10000:\tfrom all lookup ovpnc1\n",
            "10002:\tfrom all lookup ovpnc1\n",
            "10001:\tfrom all lookup main\n",
            "10001:\tfrom all lookup wgc1\n",
            "10001:\tfrom all iif br0 lookup ovpnc1\n",
            "10010:\tfrom all lookup main\n",
            "10010:\tfrom 192.168.50.30 lookup ovpnc1\n",
            "10210:\tfrom all lookup ovpnc1\n",
            "10210:\tfrom 192.168.50.0/24 lookup ovpnc2\n",
            "10210:\tfrom 192.168.50.0/24 lookup main\n",
            "10210:\tfrom 0.0.0.0 lookup ovpnc1\n",
            "10210:\tfrom 192.168.50.0/24 to 0.0.0.0/0 lookup ovpnc1\n",
            "10210:\tfrom 192.168.50.0/24 iif br0 lookup ovpnc1\n",
            "11210:\tfrom 192.168.50.20 lookup ovpnc1\n",
            "11410:\tfrom 192.168.50.20 lookup wgc1\n",
            "12209:\tfrom all iif br0 prohibit\n",
            "12209:\tfrom all lookup main\n",
        ] {
            for routes in [format!("{shadow}{slots}"), format!("{slots}{shadow}")] {
                assert!(derive(&routes).is_empty(), "{shadow:?}");
            }
        }
        // Between the two slots only the WireGuard slot can be shadowed, and
        // only an OpenVPN slot may carry the `iif` form.
        for shadow in [
            "12211:\tfrom all lookup main\n",
            "12213:\tfrom all iif br1 prohibit\n",
            "12215:\tfrom all iif br0 prohibit\n",
            "12215:\tfrom all lookup main\n",
        ] {
            assert_eq!(
                derive(&format!("{slots}{shadow}")),
                vec![openvpn.clone()],
                "{shadow:?}"
            );
        }
        // A line that cannot be placed on the ladder withholds every fact.
        for garbage in [
            "garbage\n",
            "12210 from all iif br0 prohibit\n",
            "99999999999:\tfrom all lookup main\n",
        ] {
            assert!(
                derive(&format!("{slots}{garbage}")).is_empty(),
                "{garbage:?}"
            );
        }
    }
}
