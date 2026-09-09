#![forbid(unsafe_code)]
//! Three one-packet probes/sec; fixed WAN IP targets; capped RAM history.
//! No sockets listening, no configuration/firewall writes, no flash history.
use router_diagnostics::{
    capture,
    health::{number, parse_ping, sample_json, Point, Sample, Window},
};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const OUTPUT: &str = "/tmp/var/wwwext/link-health";
const STATE: &str = "/tmp/link-health-runtime";
const INTERVAL: Duration = Duration::from_secs(1);

fn wan_interface() -> io::Result<String> {
    let (ok, value) = capture(
        "/bin/nvram",
        &["get", "wan0_ifname"],
        32,
        Duration::from_secs(1),
    )?;
    let value = value.trim().to_owned();
    if !ok
        || value.is_empty()
        || value.len() > 15
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
    {
        return Err(io::Error::other("invalid WAN interface"));
    }
    Ok(value)
}
fn gateway(interface: &str) -> Option<Ipv4Addr> {
    let routes = fs::read_to_string("/proc/net/route").ok()?;
    for line in routes.lines().skip(1) {
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        if words.len() >= 8
            && words[0] == interface
            && words[1] == "00000000"
            && words[7] == "00000000"
        {
            let gateway = u32::from_str_radix(words[2], 16).ok()?;
            let address = Ipv4Addr::from(gateway.to_le_bytes());
            if !address.is_unspecified() {
                return Some(address);
            }
        }
    }
    None
}
fn atomic_write(directory: &str, name: &str, data: &str) -> io::Result<()> {
    let temporary = Path::new(directory).join(format!(".{name}.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = file
        .write_all(data.as_bytes())
        .and_then(|_| fs::rename(&temporary, Path::new(directory).join(name)));
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
type Work = (u64, Option<Ipv4Addr>, String);
fn worker(index: usize, requests: Receiver<Work>, results: SyncSender<(u64, usize, Sample)>) {
    while let Ok((round, target, interface)) = requests.recv() {
        let sample = target.map_or(Sample::Unknown, |target| {
            match capture(
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
                    &interface,
                    &target.to_string(),
                ],
                4096,
                Duration::from_millis(1250),
            ) {
                Ok((ok, data)) => parse_ping(ok, &data),
                Err(_) => Sample::Unknown,
            }
        });
        if results.send((round, index, sample)).is_err() {
            break;
        }
    }
}
fn snapshot(
    window: &Window,
    sequence: u64,
    epoch_ms: u64,
    targets: &[Option<Ipv4Addr>; 3],
    interface: &str,
    monitor_uptime_ms: u64,
) -> String {
    let mut data = format!("{{\"schema\":1,\"sequence\":{sequence},\"epoch_ms\":{epoch_ms},\"monitor_uptime_ms\":{monitor_uptime_ms},\"interface\":\"{interface}\",\"interval_ms\":1000,\"window_samples\":{},\"targets\":[", window.points.len());
    for (index, address) in targets.iter().enumerate() {
        if index > 0 {
            data.push(',');
        }
        let stats = window.stats(index);
        let target = address.map_or("null".to_owned(), |address| format!("\"{address}\""));
        let latest = window
            .points
            .back()
            .map(|p| p.samples[index])
            .unwrap_or(Sample::Unknown);
        data.push_str(&format!("{{\"ip\":{target},\"last_ms\":{},\"replies\":{},\"misses\":{},\"unknown\":{},\"mean_ms\":{},\"p95_ms\":{},\"max_ms\":{},\"rtt_variation_ms\":{},\"max_miss_streak\":{}}}", sample_json(latest), stats.replies, stats.misses, stats.unknown, number(stats.mean_ms), number(stats.p95_ms), number(stats.max_ms), number(stats.rtt_variation_ms), stats.max_miss_streak));
    }
    data.push_str("],\"events\":[");
    let events: Vec<_> = window
        .points
        .iter()
        .filter(|point| {
            point.lag_ms > 250
                || point.samples.iter().any(|s| {
                    matches!(s, Sample::Miss) || matches!(s, Sample::Reply(value) if *value > 100.0)
                })
        })
        .rev()
        .take(30)
        .collect();
    for (index, point) in events.iter().enumerate() {
        if index > 0 {
            data.push(',');
        }
        data.push_str(&format!(
            "{{\"epoch_ms\":{},\"lag_ms\":{},\"rtt\":[{},{},{}]}}",
            point.epoch_ms,
            point.lag_ms,
            sample_json(point.samples[0]),
            sample_json(point.samples[1]),
            sample_json(point.samples[2])
        ));
    }
    data.push_str("]}\n");
    data
}
struct Lock;
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(format!("{STATE}/stop"));
        let _ = fs::remove_file(format!("{STATE}/pid"));
        let _ = fs::remove_dir(STATE);
    }
}
fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let count = match args.as_slice() {
        [flag] if flag == "--run" => u64::MAX,
        [flag, count] if flag == "--samples" => count
            .parse::<u64>()
            .ok()
            .filter(|n| (1..=3600).contains(n))
            .ok_or_else(|| io::Error::other("invalid sample count"))?,
        _ => {
            return Err(io::Error::other(
                "usage: link-health --run | --samples 1..3600",
            ))
        }
    };
    // Refuse an existing/symlink lock. A stale lock requires explicit inspection.
    fs::DirBuilder::new().mode(0o700).create(STATE)?;
    let _lock = Lock;
    atomic_write(STATE, "pid", &format!("{}\n", std::process::id()))?;
    if !fs::symlink_metadata(OUTPUT)?.is_dir() {
        return Err(io::Error::other(
            "installer must create the private RAM output directory",
        ));
    }
    let mut interface = wan_interface()?;
    let mut targets = [
        gateway(&interface),
        Some(Ipv4Addr::new(1, 1, 1, 1)),
        Some(Ipv4Addr::new(8, 8, 8, 8)),
    ];
    let (results_tx, results_rx) = mpsc::sync_channel(12);
    let mut workers = Vec::new();
    for index in 0..3 {
        let (tx, rx) = mpsc::sync_channel(1);
        let results = results_tx.clone();
        std::thread::spawn(move || worker(index, rx, results));
        workers.push(tx);
    }
    drop(results_tx);
    let start = Instant::now();
    let mut next = start;
    let mut window = Window::default();
    for round in 0..count {
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
        if Path::new(&format!("{STATE}/stop")).exists() {
            break;
        }
        let now = Instant::now();
        let lag_ms = now.saturating_duration_since(next).as_millis() as u64;
        if round > 0 && round % 30 == 0 {
            if let Ok(new_interface) = wan_interface() {
                if interface != new_interface {
                    window = Window::default();
                }
                interface = new_interface;
            }
            let refreshed = [gateway(&interface), targets[1], targets[2]];
            if targets != refreshed {
                window = Window::default();
            }
            targets = refreshed;
        }
        let epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        for (index, sender) in workers.iter().enumerate() {
            let _ = sender.try_send((round, targets[index], interface.clone()));
        }
        let mut samples = [Sample::Unknown; 3];
        let mut received = [false; 3];
        let deadline = now + Duration::from_millis(1400);
        while !received.iter().all(|seen| *seen) {
            match results_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok((id, index, sample)) if id == round => {
                    samples[index] = sample;
                    received[index] = true;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        // Delayed scheduling may itself explain stutter. Do not convert it to
        // fake Internet loss; the UI displays the sampling gap separately.
        if lag_ms > 250 {
            samples = [Sample::Unknown; 3];
        }
        window.push(Point {
            epoch_ms,
            uptime_ms: start.elapsed().as_millis() as u64,
            lag_ms,
            samples,
        });
        atomic_write(
            OUTPUT,
            "status.json",
            &snapshot(
                &window,
                round + 1,
                epoch_ms,
                &targets,
                &interface,
                start.elapsed().as_millis() as u64,
            ),
        )?;
        next += INTERVAL;
        if Instant::now().saturating_duration_since(next) > INTERVAL {
            next = Instant::now(); // No catch-up burst after a suspended router.
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("link-health: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_snapshot_is_valid_json_shaped_and_does_not_invent_zero_latency() {
        let data = snapshot(&Window::default(), 0, 0, &[None; 3], "eth0", 0);
        assert!(data.contains("\"last_ms\":null"));
        assert!(data.contains("\"mean_ms\":null"));
        assert!(!data.contains("NaN"));
        assert!(data.ends_with("]}\n"));
    }
}
