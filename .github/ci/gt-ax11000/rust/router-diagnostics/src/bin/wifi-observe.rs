#![forbid(unsafe_code)]
//! Finite, opt-in read-only correlation. No radio/NVRAM/service writes.
use router_diagnostics::{
    capture,
    health::{parse_ping, sample_json, Sample},
    wifi,
};
use router_vpn_audit::read_bounded;
use std::{
    collections::VecDeque,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::Ipv4Addr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const RADIOS: [&str; 3] = ["eth6", "eth7", "eth8"];
const OUTPUT: &str = "/tmp/var/wwwext/link-health";
const LOCK: &str = "/tmp/link-health-wifi-runtime";

fn command(program: &str, args: &[&str], cap: usize) -> Option<String> {
    capture(program, args, cap, Duration::from_millis(350))
        .ok()
        .filter(|v| v.0)
        .map(|v| v.1)
}
fn nvram(key: &str) -> Option<String> {
    command("/bin/nvram", &["get", key], 64).map(|s| s.trim().to_owned())
}
fn integer<T: ToString>(n: Option<T>) -> String {
    n.map_or("null".into(), |v| v.to_string())
}
fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn write_snapshot(data: &str) -> io::Result<()> {
    let tmp = format!("{OUTPUT}/.wifi-{}", std::process::id());
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)?;
    let result = f
        .write_all(data.as_bytes())
        .and_then(|_| fs::rename(&tmp, format!("{OUTPUT}/wifi.json")));
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
struct Lock;
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(format!("{LOCK}/pid"));
        let _ = fs::remove_file(format!("{LOCK}/stop"));
        let _ = fs::remove_dir(LOCK);
    }
}
fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (mac, ip, count) = match args.as_slice() {
        [flag, mac, ipflag, ip, countflag, count]
            if flag == "--mac" && ipflag == "--ip" && countflag == "--samples" =>
        {
            (
                wifi::mac(mac).ok_or_else(|| io::Error::other("invalid unicast MAC"))?,
                ip.parse::<Ipv4Addr>()
                    .ok()
                    .filter(|ip| ip.is_private())
                    .ok_or_else(|| io::Error::other("private LAN IPv4 required"))?,
                count
                    .parse::<u32>()
                    .ok()
                    .filter(|n| (1..=1800).contains(n))
                    .ok_or_else(|| io::Error::other("sample count 1..1800 required"))?,
            )
        }
        _ => {
            return Err(io::Error::other(
                "usage: wifi-observe --mac XX:XX:XX:XX:XX:XX --ip LAN-IP --samples 1..1800",
            ))
        }
    };
    if nvram("productid").as_deref() != Some("GT-AX11000")
        || nvram("location_code").as_deref() != Some("ALL")
    {
        return Err(io::Error::other("this experiment requires GT-AX11000 with ALL already selected; no settings are changed"));
    }
    for (i, radio) in RADIOS.iter().enumerate() {
        if nvram(&format!("wl{i}_ifname")).as_deref() != Some(radio) {
            return Err(io::Error::other("unexpected radio mapping"));
        }
    }
    if !fs::symlink_metadata(OUTPUT)?.is_dir() {
        return Err(io::Error::other(
            "existing private add-on output directory required",
        ));
    }
    fs::DirBuilder::new().mode(0o700).create(LOCK)?;
    let _lock = Lock;
    let mut pidfile = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(format!("{LOCK}/pid"))?;
    writeln!(pidfile, "{}", std::process::id())?;
    let started = Instant::now();
    let mut next = started;
    let mut points = VecDeque::new();
    let mut events: VecDeque<String> = VecDeque::new();
    let mut previous: Option<(usize, u64, u64)> = None;
    let mut bsd = false;
    let mut roamast = false;
    for seq in 1..=count {
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
        if Path::new(&format!("{LOCK}/stop")).exists() {
            break;
        }
        let begin = Instant::now();
        let now = epoch();
        let lag = begin.saturating_duration_since(next).as_millis();
        if seq == 1 || seq % 10 == 0 {
            // Keep ALL as an invariant; never silently change/reinterpret it.
            if nvram("location_code").as_deref() != Some("ALL") {
                return Err(io::Error::other(
                    "ALL no longer confirmed; observation stopped",
                ));
            }
            bsd = command("/bin/pidof", &["bsd"], 128).is_some_and(|s| !s.trim().is_empty());
            roamast =
                command("/bin/pidof", &["roamast"], 128).is_some_and(|s| !s.trim().is_empty());
        }
        let mut bands = Vec::new();
        let mut known = true;
        for (i, radio) in RADIOS.iter().enumerate() {
            match command("/usr/sbin/wl", &["-i", radio, "assoclist"], 16384)
                .and_then(|s| wifi::associated(&s, &mac))
            {
                Some(true) => bands.push(i),
                Some(false) => {}
                None => known = false,
            }
        }
        let band = if known && bands.len() == 1 {
            bands.first().copied()
        } else {
            None
        };
        let station = band
            .and_then(|i| command("/usr/sbin/wl", &["-i", RADIOS[i], "sta_info", &mac], 16384))
            .and_then(|s| wifi::station(&s, &mac));
        let arp_ok = read_bounded(Path::new("/proc/net/arp"), 65536)
            .ok()
            .is_some_and(|s| wifi::arp_matches(&s, ip, &mac));
        let sample = if arp_ok {
            capture(
                "/bin/ping",
                &[
                    "-c",
                    "1",
                    "-W",
                    "1",
                    "-w",
                    "1",
                    "-s",
                    "16",
                    "-I",
                    "br0",
                    &ip.to_string(),
                ],
                4096,
                Duration::from_millis(1250),
            )
            .map_or(Sample::Unknown, |(ok, s)| parse_ping(ok, &s))
        } else {
            Sample::Unknown
        };
        // No daemon scan or active RF scan. Syslog tail is bounded and filtered
        // down to this MAC; raw logs and other clients never enter wifi.json.
        if let Some(log) = command("/usr/bin/tail", &["-n", "80", "/tmp/syslog.log"], 32768) {
            for event in log.lines().filter_map(|line| wifi::event(line, &mac)) {
                if !events.contains(&event) {
                    if events.len() == 30 {
                        events.pop_front();
                    }
                    events.push_back(event);
                }
            }
        }
        let current = station
            .as_ref()
            .and_then(|s| Some((band?, s.age_seconds?, s.retries?)));
        let retry_delta = wifi::retry_delta(previous, current);
        previous = current;
        let state = if !known {
            "unknown"
        } else if bands.len() > 1 {
            "overlap"
        } else if bands.is_empty() {
            "not-associated"
        } else if station.is_none() {
            "unknown"
        } else {
            "associated"
        };
        let detail = station.unwrap_or_default();
        let row = format!("{{\"epoch_ms\":{now},\"lag_ms\":{lag},\"span_ms\":{},\"state\":\"{state}\",\"band\":{},\"rssi\":{},\"power_save\":{},\"retry_delta\":{},\"ping_ms\":{},\"arp_match\":{arp_ok},\"channel\":{}}}",begin.elapsed().as_millis(),integer(band),integer(detail.rssi),integer(detail.power_save),integer(retry_delta),sample_json(sample),detail.channel.map_or("null".into(),|s|format!("\"{s}\"")));
        if points.len() == 60 {
            points.pop_front();
        }
        points.push_back(row);
        let json = format!("{{\"schema\":1,\"sequence\":{seq},\"epoch_ms\":{now},\"target_ip\":\"{ip}\",\"finished\":{},\"all_profile\":true,\"bsd_running\":{bsd},\"roamast_running\":{roamast},\"points\":[{}],\"events\":[{}]}}\n",seq==count,points.iter().cloned().collect::<Vec<_>>().join(","),events.iter().map(|e|format!("\"{e}\"")).collect::<Vec<_>>().join(","));
        write_snapshot(&json)?;
        next += Duration::from_secs(1);
        if next < Instant::now() {
            next = Instant::now() + Duration::from_millis(100);
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("wifi-observe: {error}");
        std::process::exit(1);
    }
}
