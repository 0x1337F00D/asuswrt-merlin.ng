//! Running the `-S PROG` hook.
//!
//! On this firmware `PROG` is `/sbin/ntpd_synced`, a symlink to `rc` whose
//! `ntpd_synced_main()` acts only when it is invoked as `ntpd_synced step`.
//! The argument vector and the four environment variables below therefore
//! have to match what busybox's ntpd produced, byte for byte.

use crate::clock::ScriptAction;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

/// The four variables busybox exported before running the hook.
#[derive(Clone, Copy, Debug)]
pub struct Environment {
    /// Local stratum.
    pub stratum: u8,
    /// Kernel frequency drift in parts per million.
    pub freq_drift_ppm: i64,
    /// Current poll interval in seconds.
    pub poll_interval: u32,
    /// Offset that triggered the run, in seconds.
    pub offset: f64,
}

impl Environment {
    /// The variables as `(name, value)` pairs, formatted as busybox did.
    #[must_use]
    pub fn variables(&self) -> [(&'static str, String); 4] {
        [
            ("stratum", self.stratum.to_string()),
            ("freq_drift_ppm", self.freq_drift_ppm.to_string()),
            ("poll_interval", self.poll_interval.to_string()),
            // busybox formatted this with "%f", which is six decimals.
            ("offset", format!("{:.6}", self.offset)),
        ]
    }
}

/// Spawns `script action` without waiting for it.
///
/// The program is executed directly with a two-element argument vector: there
/// is no shell anywhere on this path, so neither the action word nor the
/// environment values can be reinterpreted as syntax. Waiting is deliberately
/// avoided because `ntpd_synced` restarts DDNS and OpenVPN and can take
/// seconds; `SIGCHLD` is set to `SIG_IGN` by the daemon so no zombie is left.
///
/// # Errors
/// Returns the spawn error; the caller logs and carries on.
pub fn run(script: &Path, action: ScriptAction, environment: &Environment) -> io::Result<u32> {
    let mut command = Command::new(script);
    command
        .arg(action.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (name, value) in environment.variables() {
        command.env(name, value);
    }
    command.spawn().map(|child| child.id())
}
