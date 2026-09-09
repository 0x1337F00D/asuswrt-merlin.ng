#![forbid(unsafe_code)]
//! Bounded, read-only diagnostic subprocesses. No shell, listener or NVRAM writes.
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "../../linux_open_flags.rs"]
mod linux_open_flags;
use linux_open_flags::{O_NOFOLLOW, O_NONBLOCK};

pub fn capture(
    program: &str,
    args: &[&str],
    limit: usize,
    timeout: Duration,
) -> io::Result<(bool, String)> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing stdout"))?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(5)),
            result => {
                // Always reap, including timeout/error. Never leave a probe alive.
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(result.err().unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "diagnostic command deadline")
                }));
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| io::Error::other("diagnostic reader failed"))??;
    if bytes.len() > limit {
        return Err(io::Error::other("diagnostic output exceeds limit"));
    }
    let value =
        String::from_utf8(bytes).map_err(|_| io::Error::other("non-UTF8 diagnostic output"))?;
    Ok((status.success(), value))
}

pub mod health;

pub fn read_bounded(path: &std::path::Path, limit: usize) -> io::Result<String> {
    // Reject special files and symlinks; do not block on a FIFO masquerading as data.
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::other("expected regular diagnostic input"));
    }
    // Close metadata/open symlink and FIFO races using target-verified flags.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("expected regular diagnostic input"));
    }
    let mut data = String::new();
    file.take(limit as u64 + 1).read_to_string(&mut data)?;
    if data.len() > limit {
        return Err(io::Error::other("diagnostic input exceeds limit"));
    }
    Ok(data)
}

/// Must also run on native ARM/QEMU: host-only tests missed the historical
/// x86 O_NOFOLLOW constant in the ARM firmware. This exercises open itself,
/// not just the preparatory symlink_metadata check.
pub fn verify_open_flags() -> io::Result<()> {
    use std::os::unix::fs::{symlink, DirBuilderExt};
    let dir = std::path::PathBuf::from(format!("/tmp/router-open-flags-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let result = (|| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("plain"))?;
        symlink("plain", dir.join("link"))?;
        let regular = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_NONBLOCK)
            .open(dir.join("plain"))?;
        drop(regular);
        let linked = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_NONBLOCK)
            .open(dir.join("link"));
        if !matches!(linked, Err(ref error) if error.raw_os_error() == Some(40)) {
            return Err(io::Error::other("target O_NOFOLLOW did not produce ELOOP"));
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(dir.join("link"));
    let _ = std::fs::remove_file(dir.join("plain"));
    let _ = std::fs::remove_dir(dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_open_flags_really_reject_symlinks() {
        verify_open_flags().unwrap();
    }
    #[test]
    fn processes_have_deadlines_output_limits_and_no_shell_expansion() {
        let short = Duration::from_millis(40);
        assert!(capture("/bin/sleep", &["1"], 100, short).is_err());
        assert!(capture("/bin/echo", &["123456"], 3, short).is_err());
        assert_eq!(
            capture("/bin/echo", &["$(echo unsafe);x"], 100, short)
                .unwrap()
                .1,
            "$(echo unsafe);x\n"
        );
    }
}
