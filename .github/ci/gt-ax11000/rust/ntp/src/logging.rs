//! Logging.
//!
//! `rc` already writes "Started ntpd" through `logmessage()`, so this daemon
//! only reports what busybox reported: peer timeouts, refused replies and the
//! clock corrections it makes. Messages go to `/dev/log` in the same RFC 3164
//! shape `syslog(3)` produces, which is what `logmessage()` in `rc` uses, and
//! fall back to stderr while the daemon is still in the foreground.

use std::io::Write;
use std::os::unix::net::UnixDatagram;

/// `LOG_USER` facility, as `syslog.h` numbers it.
const FACILITY_USER: u8 = 1;
/// `LOG_NOTICE`.
const SEVERITY_NOTICE: u8 = 5;
/// `LOG_WARNING`.
const SEVERITY_WARNING: u8 = 4;
/// `LOG_DEBUG`.
const SEVERITY_DEBUG: u8 = 7;

/// Sends messages to the system log, and to stderr when in the foreground.
pub struct Logger {
    socket: Option<UnixDatagram>,
    verbose: u8,
    stderr: bool,
}

impl Logger {
    /// Opens `/dev/log`. A missing socket is not an error: the daemon starts
    /// before `syslogd` on a cold boot and must still discipline the clock.
    #[must_use]
    pub fn new(verbose: u8, stderr: bool) -> Self {
        let socket = UnixDatagram::unbound().ok().and_then(|socket| {
            socket.connect("/dev/log").ok()?;
            Some(socket)
        });
        Self {
            socket,
            verbose,
            stderr,
        }
    }

    /// A normal operational message.
    pub fn notice(&self, message: &str) {
        self.emit(SEVERITY_NOTICE, message);
    }

    /// Something went wrong but the daemon carries on.
    pub fn warning(&self, message: &str) {
        self.emit(SEVERITY_WARNING, message);
    }

    /// Only emitted at `-d` level `level` or higher.
    pub fn debug(&self, level: u8, message: &str) {
        if self.verbose >= level {
            self.emit(SEVERITY_DEBUG, message);
        }
    }

    fn emit(&self, severity: u8, message: &str) {
        // Control characters would let a hostile host name forge log lines.
        let sanitised: String = message
            .chars()
            .map(|character| {
                if character.is_control() {
                    '?'
                } else {
                    character
                }
            })
            .take(768)
            .collect();
        if let Some(socket) = &self.socket {
            let priority = FACILITY_USER * 8 + severity;
            let _ = socket.send(format!("<{priority}>ntp: {sanitised}").as_bytes());
        }
        if self.stderr {
            let _ = writeln!(std::io::stderr(), "ntp: {sanitised}");
        }
    }
}
