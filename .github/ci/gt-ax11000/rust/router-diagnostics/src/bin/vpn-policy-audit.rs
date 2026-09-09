#![forbid(unsafe_code)]
//! W9 hardware audit. Intentionally observation-only until active client modes
//! have hardware fixtures: failure MUST NOT disable the household's forwarding.
use router_diagnostics::{capture, read_bounded};
use router_policy::vpn_runtime::audit;
use std::io;
use std::path::Path;
use std::time::Duration;

fn command(program: &str, args: &[&str], limit: usize) -> io::Result<String> {
    let (ok, result) = capture(program, args, limit, Duration::from_secs(2))?;
    if !ok {
        return Err(io::Error::other("diagnostic command failed"));
    }
    Ok(result)
}
fn nvram(key: &str) -> io::Result<String> {
    Ok(command("/bin/nvram", &["get", key], 128)?
        .trim_end_matches('\n')
        .to_owned())
}
fn number(prefix: &str, name: &str, fallback: &str) -> io::Result<String> {
    let value = nvram(&format!("{prefix}{name}"))?;
    Ok(if value.is_empty() {
        fallback.to_owned()
    } else {
        value
    })
}
#[derive(Eq, PartialEq)]
struct Snapshot {
    profiles: String,
    director: String,
    lan: String,
    ipv6: bool,
}
fn configuration() -> io::Result<Snapshot> {
    let enabled = nvram("vpn_clientx_eas")?;
    if enabled
        .bytes()
        .any(|byte| !matches!(byte, b'1'..=b'5' | b',' | b' '))
    {
        return Err(io::Error::other("unsupported OpenVPN enable list"));
    }
    let enabled: Vec<_> = enabled
        .split([',', ' '])
        .filter(|v| !v.is_empty())
        .collect();
    if enabled.iter().any(|unit| unit.len() != 1) {
        return Err(io::Error::other("ambiguous OpenVPN enable list"));
    }
    let mut profiles = String::new();
    for kind in ["openvpn", "wireguard"] {
        for unit in 1..=5 {
            let (prefix, interface, enabled, redirect) = if kind == "openvpn" {
                let prefix = format!("vpn_client{unit}_");
                let if_kind = number(&prefix, "if", "tun")?;
                if !matches!(if_kind.as_str(), "tun" | "tap") {
                    return Err(io::Error::other("unsupported OpenVPN interface"));
                }
                let redirect = number(&prefix, "rgw", "0")?;
                (
                    prefix,
                    format!("{if_kind}{}", 10 + unit),
                    u8::from(enabled.contains(&unit.to_string().as_str())).to_string(),
                    redirect,
                )
            } else {
                let prefix = format!("wgc{unit}_");
                let enabled = number(&prefix, "enable", "0")?;
                (prefix, format!("wgc{unit}"), enabled, "2".to_owned())
            };
            let running = u8::from(Path::new(&format!("/sys/class/net/{interface}")).exists());
            let fw = number(&prefix, "fw", "0")?;
            let enforce = number(&prefix, "enforce", "0")?;
            profiles.push_str(&format!(
                "{kind}:{unit}:{interface}:{enabled}:{running}:{fw}:{enforce}:{redirect}\n"
            ));
        }
    }
    let director = match read_bounded(Path::new("/jffs/openvpn/vpndirector_rulelist"), 7999) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    let ipv6 = !matches!(nvram("ipv6_service")?.as_str(), "" | "disabled");
    Ok(Snapshot {
        profiles,
        director,
        lan: nvram("lan_ifname")?,
        ipv6,
    })
}
fn normalize_save(input: &str) -> String {
    input
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            if line.starts_with(':') {
                line.split_ascii_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().skip(1).collect::<Vec<_>>() == ["--self-test"] {
        router_diagnostics::verify_open_flags()?;
        println!("OPEN_FLAGS_SELFTEST=PASS native O_NOFOLLOW rejected symlink with ELOOP");
        return Ok(());
    }
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--check-live"] {
        return Err("usage: vpn-policy-audit --check-live (read-only; no enforcement)".into());
    }
    let before = configuration()?;
    let v4 = command("/usr/sbin/iptables-save", &["-t", "filter"], 128 * 1024)?;
    let v6 = if before.ipv6 {
        Some(command(
            "/usr/sbin/ip6tables-save",
            &["-t", "filter"],
            128 * 1024,
        )?)
    } else {
        None
    };
    let routes = command("/usr/sbin/ip", &["rule", "show"], 64 * 1024)?;
    let result = audit(
        &before.profiles,
        &before.director,
        &v4,
        v6.as_deref(),
        &routes,
        &before.lan,
    );
    // Counters/timestamps change during normal traffic; compare rule structure.
    if before != configuration()?
        || normalize_save(&v4)
            != normalize_save(&command(
                "/usr/sbin/iptables-save",
                &["-t", "filter"],
                128 * 1024,
            )?)
        || routes != command("/usr/sbin/ip", &["rule", "show"], 64 * 1024)?
        || (before.ipv6
            && normalize_save(v6.as_deref().unwrap_or(""))
                != normalize_save(&command(
                    "/usr/sbin/ip6tables-save",
                    &["-t", "filter"],
                    128 * 1024,
                )?))
    {
        return Err("INCONCLUSIVE: configuration/rules changed during audit".into());
    }
    let coverage = result?;
    println!("W9_AUDIT=PASS inbound_profiles={} ipv4_kill_switch_profiles={} ipv4_sources={} enforcement=observation_only ipv6_kill_switch=not_proven", coverage.inbound_profiles, coverage.kill_switch_profiles, coverage.kill_switch_sources);
    if coverage.inbound_profiles == 0 && coverage.kill_switch_profiles == 0 {
        println!("COVERAGE=no_active_requirements; this is not an active VPN hardware test");
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("W9_AUDIT=UNVERIFIED {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_volatile_save_metadata_is_ignored() {
        let one = "# Generated now\n*filter\n:INPUT DROP [1:20]\n-A INPUT -j DROP\nCOMMIT";
        let two = one.replace("now", "later").replace("1:20", "2:40");
        assert_eq!(normalize_save(one), normalize_save(&two));
        assert_ne!(
            normalize_save(one),
            normalize_save(&two.replace("-j DROP", "-j ACCEPT"))
        );
    }
}
