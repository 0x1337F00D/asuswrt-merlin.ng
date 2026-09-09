//! Synthetic effective-rule fixtures for the vendor OpenVPN and WireGuard
//! client firewall state and the VPN Director kill switch (DEBTS SEC-2).
//!
//! SYNTHETIC FROM SOURCE, NOT CAPTURED: every rule below is transcribed from
//! the generators in the vendor tree at 6be5bc84b50 (line numbers cited per
//! rule) and laid out the way `iptables-save`, `ip6tables-save` and
//! `ip rule show` would print them. Nothing here was captured from a router.
//! Real GT-AX11000 captures for each OpenVPN client mode (`rgw` none/all/
//! policy, `fw` on/off, `enforce` on/off) and each WireGuard client mode are
//! still owed and must confirm these layouts before the check is relied on.
//!
//! Sources:
//! - rc/firewall.c: chain declarations (:4544-4554), the INPUT hooks
//!   `-A INPUT -j WGSI/WGCI/OVPNSI/OVPNCI` (:5331-5347) and the FORWARD hooks
//!   `-A FORWARD -j WGCF/OVPNCF` (:6172-6183) of `filter_setting`. The
//!   dual-WAN generator `filter_setting2` emits the same hooks (INPUT
//!   :7128-7144, FORWARD :8050-8061) behind the same preamble. The rules the
//!   vendor places ahead of the hooks (INPUT :5002-5058, FORWARD :5427-5754;
//!   :6801-6843 and :7238-7553 in `filter_setting2`) are reproduced in
//!   `logging_filter_save`: the client rules only count when nothing ahead
//!   of them can admit tunnel traffic.
//! - libovpn/openvpn_setup.c `ovpn_setup_client_fw()` (:948-1000): the
//!   per-client script inserts `-I OVPNCF -i IF -j DROP|ACCEPT` (:965),
//!   `-I OVPNCF -o IF -j ACCEPT` (:966), `-I OVPNCI -i IF -j DROP|ACCEPT`
//!   (:967), mangle MARK rules (:976-977) and the ip6tables twins (:982-984,
//!   :990-991). The DROP/ACCEPT choice is `vpn_clientN_fw`.
//! - rc/wireguard.c `_wg_client_nf_add()` (:675-721): `-I WGCI -i IF -j
//!   DROP|ACCEPT` (:697), `-I WGCF -i IF -j DROP|ACCEPT` (:698), `-I WGCF -o
//!   IF -j ACCEPT` (:699), ip6tables twins (:700-702), TCPMSS clamps
//!   (:708-709) and mangle MARK rules (:712-715). The choice is `wgcN_fw`.
//! - libovpn/amvpn_routing.c `amvpn_set_killswitch_rules()` (:874-1019): the
//!   `enforce` kill switch is policy routing only. OpenVPN redirect-all adds
//!   `ip rule add from all iif lan_ifname priority P prohibit` (:903);
//!   OpenVPN policy mode (:923) and WireGuard (:987) add `ip rule add from
//!   SRC priority P prohibit` per enabled VPN Director source. P is
//!   VPNDIR_PRIO_KS_OPENVPN + unit - 1 (:892) or VPNDIR_PRIO_KS_WIREGUARD +
//!   unit - 1 (:962); with libovpn/openvpn_config.h:95-104 that is 12210-12214
//!   and 12215-12219. Nothing is added to iptables.
//! - The overlay's `CODEX_WAN_GUARD` first-INPUT hook comes from
//!   patches/runtime-hardening-2026.patch, which the base policy requires.
//!
//! Client insertion order matters for the chain dumps: each script line runs
//! `iptables -I`, so later lines appear earlier in the chain.

use router_policy::firewall::{
    validate_effective_firewall_policy, validate_effective_firewall_policy_with_vpn_clients,
    validate_effective_vpn_client_policy, AddressFamily, FilterChain, FirewallManifest,
    FirewallRule, VpnClientKind, VpnClientProfile, VpnClientRequirements,
};
use router_policy::PolicyError;

const WAN: &str = "eth0";
const LAN: &str = "br0";
const ADMIN_PORTS: [u16; 2] = [22, 443];

#[test]
fn runtime_derivation_checks_manual_tunnels_even_without_autostart() {
    let mut snapshot = String::new();
    for unit in 1..=5 {
        snapshot.push_str(&format!(
            "openvpn:{unit}:tun{}:0:{}:1:0:2\n",
            10 + unit,
            u8::from(unit == 1)
        ));
        snapshot.push_str(&format!("wireguard:{unit}:wgc{unit}:0:0:1:0:2\n"));
    }
    let v4 = filter_save(OPENVPN1_BLOCK);
    let routes =
        "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n";
    let result =
        router_policy::vpn_runtime::audit(&snapshot, "", &v4, Some(&v4), routes, LAN).unwrap();
    assert_eq!(result.inbound_profiles, 1);
    assert_eq!(result.kill_switch_profiles, 0);
    assert!(router_policy::vpn_runtime::audit(
        &snapshot,
        "",
        &filter_save(OPENVPN1_ALLOW),
        Some(&v4),
        routes,
        LAN
    )
    .is_err());
    assert!(router_policy::vpn_runtime::audit(
        &snapshot,
        "",
        &v4,
        Some(&filter_save("")),
        routes,
        LAN
    )
    .is_err());
}

/// The vendor mangle table entries the client scripts add (openvpn_setup.c
/// :976-977, wireguard.c:712-713). They live outside `*filter` and must be
/// ignored by the policy.
const MANGLE_OPENVPN1: &str = "\
*mangle
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -i tun11 -j MARK --or-mark 0x1
-A POSTROUTING -o tun11 -j MARK --or-mark 0x1
COMMIT
";

/// Build one `iptables-save`/`ip6tables-save` filter table in the vendor
/// layout with `client_rules` spliced in after the FORWARD chain. The INPUT
/// chain starts with the overlay guard and ends with the vendor terminal
/// DROP; both VPN client chains are declared (firewall.c:4547-4548,
/// :4553-4554) and hooked (firewall.c:5331-5343, :6172, :6180; dual-WAN
/// :7128-7140, :8050, :8058).
fn filter_save(client_rules: &str) -> String {
    format!(
        "\
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:CODEX_WAN_GUARD - [0:0]
:WGSI - [0:0]
:WGSF - [0:0]
:WGCI - [0:0]
:WGCF - [0:0]
:OVPNSI - [0:0]
:OVPNSF - [0:0]
:OVPNCI - [0:0]
:OVPNCF - [0:0]
-A INPUT -i {WAN} -j CODEX_WAN_GUARD
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i {LAN} -m state --state NEW -j ACCEPT
-A INPUT -j WGSI
-A INPUT -j WGCI
-A INPUT -j OVPNSI
-A INPUT -j OVPNCI
-A INPUT -j DROP
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -j WGCF
-A FORWARD -j OVPNCF
-A FORWARD -i {LAN} -o {WAN} -j ACCEPT
-A FORWARD -j DROP
{client_rules}\
-A CODEX_WAN_GUARD -p tcp -m tcp --dport 22 -j DROP
-A CODEX_WAN_GUARD -p tcp -m tcp --dport 443 -j DROP
-A CODEX_WAN_GUARD -j RETURN
COMMIT
"
    )
}

/// OpenVPN client 1 (`tun11`) with `vpn_client1_fw=1`: openvpn_setup.c:967
/// (OVPNCI DROP), :966 (OVPNCF `-o` ACCEPT) and :965 (OVPNCF `-i` DROP),
/// shown in insertion order. Identical text for ip6tables (:982-984).
const OPENVPN1_BLOCK: &str = "\
-A OVPNCI -i tun11 -j DROP
-A OVPNCF -o tun11 -j ACCEPT
-A OVPNCF -i tun11 -j DROP
";

/// OpenVPN client 1 with `vpn_client1_fw=0`: the same generator lines with
/// their ACCEPT branch. Not an inbound block.
const OPENVPN1_ALLOW: &str = "\
-A OVPNCI -i tun11 -j ACCEPT
-A OVPNCF -o tun11 -j ACCEPT
-A OVPNCF -i tun11 -j ACCEPT
";

/// WireGuard client 2 (`wgc2`) with `wgc2_fw=1`: wireguard.c:697 (WGCI
/// DROP), then WGCF in insertion order :708 (TCPMSS clamp), :699 (`-o`
/// ACCEPT), :698 (`-i` DROP). ip6tables twins are :700-702 and :709.
const WIREGUARD2_BLOCK: &str = "\
-A WGCI -i wgc2 -j DROP
-A WGCF -o wgc2 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
-A WGCF -o wgc2 -j ACCEPT
-A WGCF -i wgc2 -j DROP
";

/// OpenVPN client 2 (`tun12`) started after client 1: its `-I` lines
/// (openvpn_setup.c:965-967) land above client 1's in both chains. With
/// `vpn_client2_fw=0` they are the ACCEPT branch.
const OPENVPN2_ALLOW_ABOVE_OPENVPN1_BLOCK: &str = "\
-A OVPNCI -i tun12 -j ACCEPT
-A OVPNCI -i tun11 -j DROP
-A OVPNCF -o tun12 -j ACCEPT
-A OVPNCF -i tun12 -j ACCEPT
-A OVPNCF -o tun11 -j ACCEPT
-A OVPNCF -i tun11 -j DROP
";

/// The same two clients with `vpn_client2_fw=1`.
const OPENVPN2_BLOCK_ABOVE_OPENVPN1_BLOCK: &str = "\
-A OVPNCI -i tun12 -j DROP
-A OVPNCI -i tun11 -j DROP
-A OVPNCF -o tun12 -j ACCEPT
-A OVPNCF -i tun12 -j DROP
-A OVPNCF -o tun11 -j ACCEPT
-A OVPNCF -i tun11 -j DROP
";

/// The vendor filter table with logging enabled (`fw_log_x`, firewall.c
/// :9085-9090 selects the `logaccept` chain of :6039-6041 and the `logdrop`
/// chain of :6049-6051) and the complete preamble `filter_setting` emits
/// ahead of the client hooks: INPUT :5002 (established), :5003 (invalid),
/// :5029 (`! -i lo`), :5045 (LAN), :5058 (`lo`), :5331-5343 (server and
/// client hooks); FORWARD :5427 (TCPMSS), :5488 (established), :5523/:5530
/// (server hooks), :5580 (WAN egress from non-LAN), :5610 (LAN to LAN),
/// :5620 (invalid), :5754 (`SECURITY`, whose chain is :6024-6036),
/// :6172/:6180 (client hooks). Every one of these rules is scoped to another
/// interface, limited to established flows, non-terminating, a denial, or a
/// jump into a chain made only of those.
fn logging_filter_save(client_rules: &str) -> String {
    format!(
        "\
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:CODEX_WAN_GUARD - [0:0]
:SECURITY - [0:0]
:WGSI - [0:0]
:WGSF - [0:0]
:WGCI - [0:0]
:WGCF - [0:0]
:OVPNSI - [0:0]
:OVPNSF - [0:0]
:OVPNCI - [0:0]
:OVPNCF - [0:0]
:logaccept - [0:0]
:logdrop - [0:0]
-A INPUT -i {WAN} -j CODEX_WAN_GUARD
-A INPUT -m state --state RELATED,ESTABLISHED -j logaccept
-A INPUT -m state --state INVALID -j logdrop
-A INPUT ! -i lo -p tcp -m tcp --dport 5152 -j logdrop
-A INPUT -i {LAN} -m state --state NEW -j ACCEPT
-A INPUT -i lo -m state --state NEW -j ACCEPT
-A INPUT -j WGSI
-A INPUT -j WGCI
-A INPUT -j OVPNSI
-A INPUT -j OVPNCI
-A INPUT -j logdrop
-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
-A FORWARD -m state --state ESTABLISHED,RELATED -j logaccept
-A FORWARD -j WGSF
-A FORWARD -j OVPNSF
-A FORWARD -o {WAN} ! -i {LAN} -j logdrop
-A FORWARD -i {LAN} -o {LAN} -j logaccept
-A FORWARD -m state --state INVALID -j logdrop
-A FORWARD -i {WAN} -j SECURITY
-A FORWARD -j WGCF
-A FORWARD -j OVPNCF
-A FORWARD -i {LAN} -o {WAN} -j logaccept
-A FORWARD -j logdrop
{client_rules}\
-A SECURITY -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 1/sec -j RETURN
-A SECURITY -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j logdrop
-A SECURITY -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK RST -m limit --limit 1/sec -j RETURN
-A SECURITY -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK RST -j logdrop
-A SECURITY -p icmp -m icmp --icmp-type 8 -m limit --limit 1/sec -j RETURN
-A SECURITY -p icmp -m icmp --icmp-type 8 -j logdrop
-A SECURITY -j RETURN
-A CODEX_WAN_GUARD -p tcp -m tcp --dport 22 -j DROP
-A CODEX_WAN_GUARD -p tcp -m tcp --dport 443 -j DROP
-A CODEX_WAN_GUARD -j RETURN
-A logaccept -m state --state NEW -j LOG --log-prefix \"ACCEPT \" --log-tcp-sequence --log-tcp-options --log-ip-options
-A logaccept -j ACCEPT
-A logdrop -m state --state NEW -j LOG --log-prefix \"DROP \" --log-tcp-sequence --log-tcp-options --log-ip-options
-A logdrop -j DROP
COMMIT
"
    )
}

/// `ip rule show` with OpenVPN client 1 in redirect-all mode and
/// `vpn_client1_enforce=1`: amvpn_routing.c:903 at priority 12210 (:892).
const ROUTES_OPENVPN1_ALL: &str = "\
0:\tfrom all lookup local
12210:\tfrom all iif br0 prohibit
32766:\tfrom all lookup main
32767:\tfrom all lookup default
";

/// OpenVPN client 1 in VPN Director mode with two enabled sources routed to
/// OVPN1: amvpn_routing.c:923 once per source, both at priority 12210.
const ROUTES_OPENVPN1_POLICY: &str = "\
0:\tfrom all lookup local
12210:\tfrom 192.168.50.0/24 prohibit
12210:\tfrom 192.168.51.10 prohibit
32766:\tfrom all lookup main
32767:\tfrom all lookup default
";

/// WireGuard client 2 with `wgc2_enforce=1` and one VPN Director source:
/// amvpn_routing.c:987 at priority 12216 (:962).
const ROUTES_WIREGUARD2: &str = "\
0:\tfrom all lookup local
12216:\tfrom 192.168.50.20 prohibit
32766:\tfrom all lookup main
32767:\tfrom all lookup default
";

/// Both clients enforcing at once.
const ROUTES_BOTH: &str = "\
0:\tfrom all lookup local
12210:\tfrom all iif br0 prohibit
12216:\tfrom 192.168.50.20 prohibit
32766:\tfrom all lookup main
32767:\tfrom all lookup default
";

/// No client enforces: amvpn_set_killswitch_rules() returns before adding
/// anything (amvpn_routing.c:899, :968) and only the kernel defaults remain.
const ROUTES_NONE: &str = "\
0:\tfrom all lookup local
32766:\tfrom all lookup main
32767:\tfrom all lookup default
";

fn profile(spec: &str) -> VpnClientProfile {
    VpnClientProfile::parse(spec).unwrap()
}

fn requirements(specs: &[&str]) -> VpnClientRequirements {
    VpnClientRequirements {
        profiles: specs.iter().map(|spec| profile(spec)).collect(),
        lan_interface: LAN.into(),
    }
}

fn check(
    ipv4: &str,
    ipv6: Option<&str>,
    routes: Option<&str>,
    specs: &[&str],
) -> Result<(), PolicyError> {
    validate_effective_firewall_policy_with_vpn_clients(
        ipv4,
        ipv6,
        ipv6.is_some(),
        WAN,
        ipv6.map(|_| WAN),
        &ADMIN_PORTS,
        routes,
        Some(&requirements(specs)),
    )
}

#[test]
fn openvpn_client_1_with_inbound_block_and_kill_switch_is_accepted() {
    let ipv4 = format!("{MANGLE_OPENVPN1}{}", filter_save(OPENVPN1_BLOCK));
    let ipv6 = filter_save(OPENVPN1_BLOCK);
    for routes in [ROUTES_OPENVPN1_ALL, ROUTES_OPENVPN1_POLICY] {
        check(&ipv4, Some(&ipv6), Some(routes), &["openvpn:1:fw+ks"]).unwrap();
        check(&ipv4, None, Some(routes), &["openvpn:1:tun11:fw+ks"]).unwrap();
        check(&ipv4, Some(&ipv6), Some(routes), &["openvpn:1:ks"]).unwrap();
    }
    check(&ipv4, Some(&ipv6), None, &["openvpn:1:fw"]).unwrap();
    check(&ipv4, Some(&ipv6), Some(ROUTES_NONE), &["openvpn:1:fw"]).unwrap();
}

#[test]
fn wireguard_client_2_with_inbound_block_and_kill_switch_is_accepted() {
    let rules = filter_save(WIREGUARD2_BLOCK);
    check(
        &rules,
        Some(&rules),
        Some(ROUTES_WIREGUARD2),
        &["wireguard:2:fw+ks"],
    )
    .unwrap();
    check(
        &rules,
        None,
        Some(ROUTES_WIREGUARD2),
        &["wireguard:2:wgc2:ks"],
    )
    .unwrap();
    check(&rules, Some(&rules), None, &["wireguard:2:fw"]).unwrap();
}

#[test]
fn both_clients_are_checked_independently() {
    let both = format!("{OPENVPN1_BLOCK}{WIREGUARD2_BLOCK}");
    let rules = filter_save(&both);
    check(
        &rules,
        Some(&rules),
        Some(ROUTES_BOTH),
        &["openvpn:1:fw+ks", "wireguard:2:fw+ks"],
    )
    .unwrap();

    let manifest = FirewallManifest::from_effective_filter_saves_with_vpn_clients(
        &rules,
        Some(&rules),
        &requirements(&["openvpn:1:fw+ks", "wireguard:2:fw+ks", "openvpn:3:fw"]).profiles,
    )
    .unwrap();
    let mut expected = Vec::new();
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        for chain in [FilterChain::Input, FilterChain::Forward] {
            expected.push(FirewallRule::TerminalDrop { family, chain });
        }
        expected.push(FirewallRule::VpnClientInboundBlock {
            family,
            kind: VpnClientKind::OpenVpn,
            vpn_interface: "tun11".into(),
        });
        expected.push(FirewallRule::VpnClientInboundBlock {
            family,
            kind: VpnClientKind::WireGuard,
            vpn_interface: "wgc2".into(),
        });
    }
    assert_eq!(manifest.rules(), expected.as_slice());

    // One client's coverage never satisfies the other's requirement.
    assert_eq!(
        check(
            &rules,
            Some(&rules),
            Some(ROUTES_OPENVPN1_ALL),
            &["openvpn:1:ks", "wireguard:2:ks"]
        ),
        Err(PolicyError::Invariant("VPN kill switch route"))
    );
    assert_eq!(
        check(
            &rules,
            Some(&rules),
            Some(ROUTES_WIREGUARD2),
            &["openvpn:1:ks", "wireguard:2:ks"]
        ),
        Err(PolicyError::Invariant("VPN kill switch route"))
    );
    let openvpn_only = filter_save(OPENVPN1_BLOCK);
    assert_eq!(
        check(
            &openvpn_only,
            None,
            Some(ROUTES_BOTH),
            &["openvpn:1:fw", "wireguard:2:fw"]
        ),
        Err(PolicyError::Invariant("VPN client inbound block"))
    );
    // A client on another unit or interface is not covered either.
    for other in [
        "openvpn:2:fw",
        "openvpn:1:tap11:fw",
        "wireguard:1:fw",
        "openvpn:2:ks",
        "wireguard:3:ks",
    ] {
        assert!(
            check(&rules, Some(&rules), Some(ROUTES_BOTH), &[other]).is_err(),
            "{other}"
        );
    }
}

#[test]
fn no_client_rules_fail_every_requirement_but_keep_the_base_policy() {
    let rules = filter_save("");
    validate_effective_firewall_policy(&rules, Some(&rules), true, WAN, Some(WAN), &ADMIN_PORTS)
        .unwrap();
    check(&rules, Some(&rules), Some(ROUTES_NONE), &[]).unwrap_err();
    assert_eq!(
        check(&rules, Some(&rules), Some(ROUTES_NONE), &["openvpn:1:fw"]),
        Err(PolicyError::Invariant("VPN client inbound block"))
    );
    assert_eq!(
        check(&rules, Some(&rules), Some(ROUTES_NONE), &["wireguard:2:fw"]),
        Err(PolicyError::Invariant("VPN client inbound block"))
    );
    assert_eq!(
        check(&rules, Some(&rules), Some(ROUTES_NONE), &["openvpn:1:ks"]),
        Err(PolicyError::Invariant("VPN kill switch route"))
    );
    assert_eq!(
        check(&rules, Some(&rules), Some(ROUTES_NONE), &["wireguard:2:ks"]),
        Err(PolicyError::Invariant("VPN kill switch route"))
    );
}

#[test]
fn kill_switch_requirements_need_policy_routes_and_ipv6_needs_its_ruleset() {
    let rules = filter_save(OPENVPN1_BLOCK);
    assert_eq!(
        check(&rules, None, None, &["openvpn:1:ks"]),
        Err(PolicyError::Missing("policy routes"))
    );
    assert_eq!(
        validate_effective_vpn_client_policy(
            &rules,
            None,
            true,
            None,
            &requirements(&["openvpn:1:fw"])
        ),
        Err(PolicyError::Missing("IPv6 ruleset"))
    );
    // IPv6 rules that lack the client's ip6tables twins fail only when IPv6
    // is required.
    let ipv6_without_client = filter_save("");
    validate_effective_vpn_client_policy(
        &rules,
        Some(&ipv6_without_client),
        false,
        None,
        &requirements(&["openvpn:1:fw"]),
    )
    .unwrap();
    assert_eq!(
        validate_effective_vpn_client_policy(
            &rules,
            Some(&ipv6_without_client),
            true,
            None,
            &requirements(&["openvpn:1:fw"]),
        ),
        Err(PolicyError::Invariant("VPN client inbound block"))
    );
}

#[test]
fn decoys_that_resemble_client_rules_are_not_recognised() {
    let base = filter_save(OPENVPN1_BLOCK);
    let iptables_decoys: [(&str, String); 7] = [
        // vpn_client1_fw=0: the ACCEPT branch of openvpn_setup.c:965-967.
        ("fw=0 accept rules", filter_save(OPENVPN1_ALLOW)),
        // Both branches present: the verdict depends on insertion order.
        (
            "mixed accept and drop",
            filter_save(&format!("{OPENVPN1_BLOCK}{OPENVPN1_ALLOW}")),
        ),
        // Server-side chain (openvpn_control.c:1050 shape) with the client interface.
        (
            "server chain",
            filter_save("-A OVPNSF -o tun11 -j DROP\n-A OVPNSF -i tun11 -j DROP\n"),
        ),
        // Only the FORWARD-side rules; the INPUT-side DROP (:967) is missing.
        (
            "no OVPNCI drop",
            filter_save("-A OVPNCF -o tun11 -j ACCEPT\n-A OVPNCF -i tun11 -j DROP\n"),
        ),
        // Only the INPUT-side rule; the FORWARD-side rules (:965-966) are missing.
        (
            "no OVPNCF rules",
            filter_save("-A OVPNCI -i tun11 -j DROP\n"),
        ),
        // The chain hooks are gone, so the chains are unreachable.
        (
            "unhooked chains",
            base.replace("-A FORWARD -j OVPNCF\n", "")
                .replace("-A INPUT -j OVPNCI\n", ""),
        ),
        // Extra match options on the DROP change its scope.
        (
            "narrowed drop",
            base.replace(
                "-A OVPNCF -i tun11 -j DROP",
                "-A OVPNCF -i tun11 -p tcp -j DROP",
            ),
        ),
    ];
    for (name, decoy) in &iptables_decoys {
        validate_effective_firewall_policy(decoy, Some(decoy), true, WAN, Some(WAN), &ADMIN_PORTS)
            .unwrap_or_else(|error| panic!("{name}: base policy must still hold: {error}"));
        assert_eq!(
            check(
                decoy,
                Some(decoy),
                Some(ROUTES_OPENVPN1_ALL),
                &["openvpn:1:fw"]
            ),
            Err(PolicyError::Invariant("VPN client inbound block")),
            "{name}"
        );
    }
    // Hooking only one of the two chains is not enough either.
    for hook in ["-A FORWARD -j OVPNCF\n", "-A INPUT -j OVPNCI\n"] {
        let decoy = base.replace(hook, "");
        assert!(
            check(&decoy, None, None, &["openvpn:1:fw"]).is_err(),
            "{hook:?}"
        );
    }

    let route_decoys = [
        // VPN Director routing rule for the client, not its kill switch.
        "0:\tfrom all lookup local\n12210:\tfrom all iif br0 lookup ovpnc1\n32766:\tfrom all lookup main\n",
        // Kill switch for another LAN bridge.
        "0:\tfrom all lookup local\n12210:\tfrom all iif br1 prohibit\n32766:\tfrom all lookup main\n",
        // The SDN slot (VPNDIR_PRIO_KS_SDN = 12220) and the WireGuard 1 slot.
        "0:\tfrom all lookup local\n12220:\tfrom all iif br0 prohibit\n32766:\tfrom all lookup main\n",
        "0:\tfrom all lookup local\n12215:\tfrom all iif br0 prohibit\n32766:\tfrom all lookup main\n",
        // Exact shape but the priority slot also carries a lookup rule.
        "0:\tfrom all lookup local\n12210:\tfrom all iif br0 prohibit\n12210:\tfrom all lookup main\n32766:\tfrom all lookup main\n",
        // Interface no longer present.
        "0:\tfrom all lookup local\n12210:\tfrom all iif br0 [detached] prohibit\n32766:\tfrom all lookup main\n",
        // The source the vendor never installs.
        "0:\tfrom all lookup local\n12210:\tfrom 0.0.0.0 prohibit\n32766:\tfrom all lookup main\n",
        // Other reject actions.
        "0:\tfrom all lookup local\n12210:\tfrom all iif br0 unreachable\n32766:\tfrom all lookup main\n",
        "0:\tfrom all lookup local\n12210:\tfrom all iif br0 blackhole\n32766:\tfrom all lookup main\n",
        ROUTES_WIREGUARD2,
        ROUTES_NONE,
    ];
    for decoy in route_decoys {
        assert_eq!(
            check(&base, Some(&base), Some(decoy), &["openvpn:1:ks"]),
            Err(PolicyError::Invariant("VPN kill switch route")),
            "{decoy:?}"
        );
    }
}

#[test]
fn base_policy_behaviour_is_identical_without_vpn_requirements() {
    let complete = filter_save(&format!("{OPENVPN1_BLOCK}{WIREGUARD2_BLOCK}"));
    let candidates = [
        complete.clone(),
        filter_save(""),
        filter_save(OPENVPN1_ALLOW),
        complete.replace("-A FORWARD -j DROP\n", ""),
        complete.replace("-A INPUT -i eth0 -j CODEX_WAN_GUARD\n", ""),
        complete.replace("--dport 443 -j DROP", "--dport 443 -j ACCEPT"),
        complete.replace("COMMIT\n", ""),
        String::new(),
    ];
    for ipv4 in &candidates {
        for (ipv6, require_ipv6) in [
            (None, false),
            (Some(ipv4.as_str()), true),
            (Some(ipv4.as_str()), false),
        ] {
            let expected = validate_effective_firewall_policy(
                ipv4,
                ipv6,
                require_ipv6,
                WAN,
                ipv6.map(|_| WAN),
                &ADMIN_PORTS,
            );
            for routes in [None, Some(ROUTES_BOTH)] {
                assert_eq!(
                    validate_effective_firewall_policy_with_vpn_clients(
                        ipv4,
                        ipv6,
                        require_ipv6,
                        WAN,
                        ipv6.map(|_| WAN),
                        &ADMIN_PORTS,
                        routes,
                        None,
                    ),
                    expected
                );
            }
        }
    }
}

#[test]
fn vendor_preambles_and_later_clients_keep_the_block_reachable() {
    // The full vendor preamble with logging chains ahead of every hook.
    let openvpn_only = logging_filter_save(OPENVPN1_BLOCK);
    check(
        &openvpn_only,
        Some(&openvpn_only),
        Some(ROUTES_OPENVPN1_ALL),
        &["openvpn:1:fw+ks"],
    )
    .unwrap();
    let both = logging_filter_save(&format!("{OPENVPN1_BLOCK}{WIREGUARD2_BLOCK}"));
    check(
        &both,
        Some(&both),
        Some(ROUTES_BOTH),
        &["openvpn:1:fw+ks", "wireguard:2:fw+ks"],
    )
    .unwrap();

    // A client started later sits above this one in both chains; its own
    // interface keeps it out of the way whatever its `fw` setting is.
    let later_allow = filter_save(OPENVPN2_ALLOW_ABOVE_OPENVPN1_BLOCK);
    check(&later_allow, Some(&later_allow), None, &["openvpn:1:fw"]).unwrap();
    assert_eq!(
        check(&later_allow, Some(&later_allow), None, &["openvpn:2:fw"]),
        Err(PolicyError::Invariant("VPN client inbound block"))
    );
    let later_block = filter_save(OPENVPN2_BLOCK_ABOVE_OPENVPN1_BLOCK);
    check(
        &later_block,
        Some(&later_block),
        None,
        &["openvpn:1:fw", "openvpn:2:fw"],
    )
    .unwrap();
}

#[test]
fn unreachable_client_rules_are_not_recognised() {
    let base = filter_save(OPENVPN1_BLOCK);
    // A rule ahead of the client's own rules inside its chains.
    let ahead = |rule: &str| filter_save(&format!("{rule}\n{OPENVPN1_BLOCK}"));
    // A rule ahead of the client-chain hook inside a builtin chain.
    let before_hook = |chain: &str, hook: &str, rule: &str| {
        base.replace(
            &format!("-A {chain} -j {hook}\n"),
            &format!("-A {chain} {rule}\n-A {chain} -j {hook}\n"),
        )
    };
    let decoys = [
        ("OVPNCI unconditional ACCEPT", ahead("-A OVPNCI -j ACCEPT")),
        ("OVPNCI unconditional RETURN", ahead("-A OVPNCI -j RETURN")),
        (
            "OVPNCI NEW ACCEPT",
            ahead("-A OVPNCI -i tun11 -m state --state NEW -j ACCEPT"),
        ),
        ("OVPNCI tcp ACCEPT", ahead("-A OVPNCI -i tun11 -p tcp -j ACCEPT")),
        ("OVPNCI RETURN", ahead("-A OVPNCI -i tun11 -j RETURN")),
        ("OVPNCI jump", ahead("-A OVPNCI -i tun11 -j SOMECHAIN")),
        ("OVPNCI negated ACCEPT", ahead("-A OVPNCI ! -i tun12 -j ACCEPT")),
        ("OVPNCI wildcard ACCEPT", ahead("-A OVPNCI -i tun+ -j ACCEPT")),
        (
            "OVPNCI LOG then ACCEPT",
            ahead("-A OVPNCI -j LOG\n-A OVPNCI -j ACCEPT"),
        ),
        ("OVPNCF unconditional ACCEPT", ahead("-A OVPNCF -j ACCEPT")),
        (
            "OVPNCF NEW ACCEPT",
            ahead("-A OVPNCF -i tun11 -m state --state NEW -j ACCEPT"),
        ),
        ("OVPNCF RETURN", ahead("-A OVPNCF -i tun11 -j RETURN")),
        (
            "OVPNCF ingress to other egress",
            ahead("-A OVPNCF -i tun11 -o tun12 -j ACCEPT"),
        ),
        (
            "OVPNCF duplicate egress ACCEPT",
            ahead("-A OVPNCF -o tun11 -j ACCEPT"),
        ),
        (
            "INPUT tunnel ACCEPT",
            before_hook("INPUT", "OVPNCI", "-i tun11 -j ACCEPT"),
        ),
        (
            "INPUT unconditional ACCEPT",
            before_hook("INPUT", "OVPNCI", "-j ACCEPT"),
        ),
        ("INPUT RETURN", before_hook("INPUT", "OVPNCI", "-j RETURN")),
        (
            "INPUT port ACCEPT",
            before_hook("INPUT", "OVPNCI", "-p udp -m udp --dport 1194 -j ACCEPT"),
        ),
        (
            "INPUT NEW ACCEPT",
            before_hook("INPUT", "OVPNCI", "-m state --state NEW -j ACCEPT"),
        ),
        (
            "INPUT negated LAN ACCEPT",
            before_hook("INPUT", "OVPNCI", "! -i br0 -j ACCEPT"),
        ),
        (
            "INPUT wildcard ACCEPT",
            before_hook("INPUT", "OVPNCI", "-i tun+ -j ACCEPT"),
        ),
        (
            "INPUT any-interface ACCEPT",
            before_hook("INPUT", "OVPNCI", "-i + -j ACCEPT"),
        ),
        (
            "INPUT accepting ICMP chain",
            filter_save(&format!(
                "{OPENVPN1_BLOCK}-A INPUT_ICMP -p icmp --icmp-type 8 -j RETURN\n-A INPUT_ICMP -p icmp -j ACCEPT\n"
            ))
            .replace(
                "-A INPUT -j OVPNCI\n",
                "-A INPUT -p icmp -j INPUT_ICMP\n-A INPUT -j OVPNCI\n",
            ),
        ),
        (
            "INPUT accepting server chain",
            filter_save(&format!(
                "{OPENVPN1_BLOCK}-A OVPNSI -p udp -m udp --dport 1194 -j ACCEPT\n"
            )),
        ),
        (
            "INPUT accepting sibling client chain",
            filter_save(&format!("{OPENVPN1_BLOCK}-A WGCI -j ACCEPT\n")),
        ),
        (
            "INPUT goto hook",
            base.replace("-A INPUT -j OVPNCI", "-A INPUT -g OVPNCI"),
        ),
        (
            "FORWARD egress ACCEPT",
            before_hook("FORWARD", "WGCF", "-o eth0 -j ACCEPT"),
        ),
        (
            "FORWARD LAN egress ACCEPT",
            before_hook("FORWARD", "WGCF", "-o br0 -j ACCEPT"),
        ),
        (
            "FORWARD DNAT ACCEPT",
            before_hook("FORWARD", "WGCF", "-m conntrack --ctstate DNAT -j ACCEPT"),
        ),
        (
            "FORWARD accepting sibling client chain",
            filter_save(&format!("{OPENVPN1_BLOCK}-A WGCF -j ACCEPT\n")),
        ),
        (
            "FORWARD goto hook",
            base.replace("-A FORWARD -j OVPNCF", "-A FORWARD -g OVPNCF"),
        ),
    ];
    for (name, decoy) in &decoys {
        validate_effective_firewall_policy(decoy, Some(decoy), true, WAN, Some(WAN), &ADMIN_PORTS)
            .unwrap_or_else(|error| panic!("{name}: base policy must still hold: {error}"));
        assert_eq!(
            check(
                decoy,
                Some(decoy),
                Some(ROUTES_OPENVPN1_ALL),
                &["openvpn:1:fw"]
            ),
            Err(PolicyError::Invariant("VPN client inbound block")),
            "{name}"
        );
    }
}
