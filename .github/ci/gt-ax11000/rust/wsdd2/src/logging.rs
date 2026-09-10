//! Logging.
//!
//! The vendor logged through `openlog`/`syslog` when daemonised and to stderr
//! otherwise (`wsdd.h:41-61`).  Messages go to `/dev/log` in the same RFC 3164
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
    llmnr_level: u8,
    wsd_level: u8,
    stderr: bool,
}

/// Which debug level gates a message, matching the vendor's `DEBUG(x, L, ...)`
/// and `DEBUG(x, W, ...)` split (`wsdd.h:51`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Channel {
    /// Gated by `-L`.
    Llmnr,
    /// Gated by `-W`.
    Wsd,
}

impl Logger {
    /// Opens `/dev/log`.  A missing socket is not an error: this daemon can
    /// start before `syslogd` and must still answer discovery.
    #[must_use]
    pub fn new(llmnr_level: u8, wsd_level: u8, stderr: bool) -> Self {
        let socket = UnixDatagram::unbound().ok().and_then(|socket| {
            socket.connect("/dev/log").ok()?;
            Some(socket)
        });
        Self {
            socket,
            llmnr_level,
            wsd_level,
            stderr,
        }
    }

    /// A logger with no destination at all, for tests.
    #[cfg(test)]
    #[must_use]
    pub fn discard() -> Self {
        Self {
            socket: None,
            llmnr_level: 0,
            wsd_level: 0,
            stderr: false,
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

    /// Only emitted at `-L`/`-W` level `level` or higher.
    pub fn debug(&self, channel: Channel, level: u8, message: &str) {
        let configured = match channel {
            Channel::Llmnr => self.llmnr_level,
            Channel::Wsd => self.wsd_level,
        };
        if configured >= level {
            self.emit(SEVERITY_DEBUG, message);
        }
    }

    fn emit(&self, severity: u8, message: &str) {
        // Control characters would let a hostile name or message id forge log
        // lines, and every logged value comes off the network.
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
            let _ = socket.send(format!("<{priority}>wsdd2: {sanitised}").as_bytes());
        }
        if self.stderr {
            let _ = writeln!(std::io::stderr(), "wsdd2: {sanitised}");
        }
    }
}
