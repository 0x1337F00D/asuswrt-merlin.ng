#![forbid(unsafe_code)]
//! Explicitly approved, one-shot vendor trial. Never installed/autostarted.
use router_vpn_audit::{capture, read_bounded};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // An unreaped child cannot have its PID reused. Never killall/process scan.
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn stop(child: &mut OwnedChild) -> io::Result<ExitStatus> {
    if let Some(status) = child.0.try_wait()? {
        return Ok(status);
    }
    // Keep the child unreaped until the targeted signal command completes.
    let _ = capture(
        "/bin/kill",
        &["-TERM", &child.0.id().to_string()],
        128,
        Duration::from_millis(200),
    );
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.0.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= until {
            child.0.kill()?;
            return child.0.wait();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}
fn read_command(program: &str, args: &[&str]) -> io::Result<String> {
    let (ok, text) = capture(program, args, 65536, Duration::from_millis(700))?;
    if ok {
        Ok(text)
    } else {
        Err(io::Error::other("preflight command failed"))
    }
}
fn config(key: &str) -> io::Result<String> {
    read_command("/bin/nvram", &["get", key]).map(|s| s.trim().to_owned())
}
fn require_no_bsd() -> io::Result<()> {
    let (ok, pids) = capture("/bin/pidof", &["bsd"], 128, Duration::from_millis(300))?;
    if ok || !pids.trim().is_empty() {
        return Err(io::Error::other("bsd already present; refusing trial"));
    }
    Ok(())
}
fn monitor(
    mut child: OwnedChild,
    duration: Duration,
    dir: &Path,
) -> io::Result<(ExitStatus, bool)> {
    let until = Instant::now() + duration;
    let mut maps_saved = false;
    loop {
        if let Some(status) = child.0.try_wait()? {
            return Ok((status, false));
        }
        if !maps_saved {
            if let Ok(maps) = read_bounded(
                &PathBuf::from(format!("/proc/{}/maps", child.0.id())),
                65536,
            ) {
                if maps.contains("/usr/sbin/bsd") {
                    private_file(&dir.join("maps"))?.write_all(maps.as_bytes())?;
                    maps_saved = true;
                }
            }
        }
        if Instant::now() >= until || dir.join("stop").exists() {
            return Ok((stop(&mut child)?, true));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn snapshot() -> io::Result<String> {
    let mut text = String::new();
    for key in [
        "location_code",
        "smart_connect_x",
        "roamast_disable",
        "bsd_role",
        "bsd_ifnames",
        "bsd_primary",
        "bsd_helper",
        "bsd_hport",
        "bsd_pport",
        "bsd_scheme",
        "bsd_msglevel",
        "bsd_dbg",
    ] {
        text.push_str(&format!("{key}={}\n", config(key)?));
    }
    for radio in ["eth6", "eth7", "eth8"] {
        for query in ["macmode", "mac"] {
            text.push_str(&format!(
                "{radio} {query}: {}\n",
                read_command("/usr/sbin/wl", &["-i", radio, query])?.trim()
            ));
        }
    }
    Ok(text)
}
struct Lock;
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_dir("/tmp/bsd-approved-trial-lock");
    }
}
fn run() -> io::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let adapted = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--approved-30-seconds"] => false,
        ["--approved-adapter-30-seconds"] => true,
        _ => {
            return Err(io::Error::other(
                "explicit approved trial mode required; no persistent operation",
            ))
        }
    };
    if config("productid")? != "GT-AX11000"
        || config("location_code")? != "ALL"
        || config("smart_connect_x")? != "1"
    {
        return Err(io::Error::other(
            "model/ALL/configured Smart Connect precondition failed",
        ));
    }
    for (i, radio) in ["eth6", "eth7", "eth8"].iter().enumerate() {
        if config(&format!("wl{i}_ifname"))? != *radio {
            return Err(io::Error::other("radio mapping changed"));
        }
    }
    if read_bounded(Path::new("/proc/sys/kernel/core_pattern"), 128)?.trim() != "core" {
        return Err(io::Error::other(
            "core destination is not private working directory",
        ));
    }
    let hash = read_command("/usr/sbin/openssl", &["dgst", "-sha256", "/usr/sbin/bsd"])?;
    if !hash
        .trim()
        .ends_with("af4f653e017e8daf27058bcb2b28d2f80acbae034456c668ad7613c48b818f84")
    {
        return Err(io::Error::other("vendor bsd hash mismatch"));
    }
    const ADAPTER: &str = "/tmp/bsd-maclist-v3-20260909.so";
    if adapted {
        for (path, expected) in [
            (
                ADAPTER,
                "7a4e67e5856d3329c873b6ac87115dc340f736ef6d605b5246d368233ab4b025",
            ),
            (
                "/usr/lib/libshared.so",
                "2b6d17e434666325e693ebe5924ce031bedc4493e9824146820a34da0b36ac9f",
            ),
        ] {
            if !read_command("/usr/sbin/openssl", &["dgst", "-sha256", path])?
                .trim()
                .ends_with(expected)
            {
                return Err(io::Error::other(
                    "trial adapter/libshared provenance mismatch",
                ));
            }
        }
        // The adapter only repairs argument layout. The old C list parser is
        // not yet hardened; this first trial deliberately excludes active ACLs
        // and AiMesh repeater handling, without changing any configuration.
        if config("re_mode")? != "0" {
            return Err(io::Error::other("repeater mode excluded from this trial"));
        }
        for key in ["wl0_macmode", "wl1_macmode", "wl2_macmode"] {
            if config(key)? != "disabled" {
                return Err(io::Error::other(
                    "active MAC filters excluded from this trial",
                ));
            }
        }
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create("/tmp/bsd-approved-trial-lock")?;
    let _lock = Lock;
    require_no_bsd()?;
    let dir = PathBuf::from(format!("/tmp/bsd-approved-trial-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let before = snapshot()?;
    private_file(&dir.join("before"))?.write_all(before.as_bytes())?;
    let stdout = private_file(&dir.join("vendor.log"))?;
    let stderr = stdout.try_clone()?;
    // Scope limits to this child only. No global core sysctl or NVRAM write.
    // Fixed shell program, no interpolated values. Optional adapter is confined
    // to this one child and must match the exact locally reviewed binary.
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "ulimit -c 32768 && ulimit -f 32768 && exec /usr/sbin/bsd -F",
        ])
        .current_dir(&dir)
        .env("LD_DEBUG", "files")
        .env_remove("LD_PRELOAD")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    if adapted {
        command.env("LD_PRELOAD", ADAPTER);
    }
    let child = command.spawn()?;
    let pid = child.id();
    let owned = OwnedChild(child);
    private_file(&dir.join("child.pid"))?.write_all(pid.to_string().as_bytes())?;
    println!(
        "TRIAL_STARTED pid={pid} directory={} deadline=30s plus at most 2s TERM grace",
        dir.display()
    );
    io::stdout().flush()?;
    let (status, stopped) = monitor(owned, Duration::from_secs(30), &dir)?;
    let after = snapshot()?;
    private_file(&dir.join("after"))?.write_all(after.as_bytes())?;
    let result = format!(
        "code={:?} signal={:?} supervisor_stopped={stopped} observed_config_and_acl_unchanged={}\n",
        status.code(),
        status.signal(),
        before == after
    );
    private_file(&dir.join("result"))?.write_all(result.as_bytes())?;
    print!("{result}");
    require_no_bsd()?;
    if before != after {
        return Err(io::Error::other(
            "observed state changed: inspect before/after; no blind NVRAM/ACL restoration",
        ));
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("bsd-trial: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_owned_child_is_reaped_without_touching_neighbor() {
        let mut neighbor = OwnedChild(Command::new("/bin/sleep").arg("20").spawn().unwrap());
        let mut target = OwnedChild(Command::new("/bin/sleep").arg("20").spawn().unwrap());
        assert_eq!(stop(&mut target).unwrap().signal(), Some(15));
        assert!(neighbor.0.try_wait().unwrap().is_none());
    }
    #[test]
    fn exited_child_preserves_its_status() {
        let mut child = OwnedChild(
            Command::new("/bin/sh")
                .args(["-c", "exit 7"])
                .spawn()
                .unwrap(),
        );
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(stop(&mut child).unwrap().code(), Some(7));
    }
    #[test]
    fn term_ignoring_child_has_hard_kill_fallback() {
        let mut child = OwnedChild(
            Command::new("/bin/sh")
                .args(["-c", "trap '' TERM; exec /bin/sleep 20"])
                .spawn()
                .unwrap(),
        );
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        assert_eq!(stop(&mut child).unwrap().signal(), Some(9));
        assert!(start.elapsed() < Duration::from_secs(4));
    }
}
