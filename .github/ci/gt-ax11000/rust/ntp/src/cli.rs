//! Command-line parsing.
//!
//! The contract that must not drift is `start_ntpd()` in
//! `release/src/router/rc/ntpd.c`:
//!
//! ```text
//! /usr/sbin/ntp -t -S /sbin/ntpd_synced -p <server0> [-p <server1>]
//!               [-l -I <lan_ifname>]
//! ```
//!
//! Unknown options are a hard error. Silently ignoring an option would let a
//! future firmware change believe it had configured something it had not.

use std::fmt;
use std::net::Ipv6Addr;
use std::path::PathBuf;

/// Largest number of `-p` peers accepted; `rc` configures at most two.
pub const MAX_PEERS: usize = 8;

/// Longest interface name Linux accepts, minus the NUL.
pub const MAX_INTERFACE_LEN: usize = 15;

/// The parsed command line.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Options {
    /// `-p PEER`, repeatable, in the order given.
    pub peers: Vec<String>,
    /// `-p PEER` values this daemon will not use. `rc/ntpd.c` passes
    /// `nvram_safe_get("ntp_server0")` straight from a free-text UI field that
    /// has no validator, so one unusable value must not stop the daemon from
    /// starting with the other; the caller logs each of these instead.
    pub rejected_peers: Vec<String>,
    /// `-S PROG`, run after a step, a stratum change and every 11 minutes.
    pub script: Option<PathBuf>,
    /// `-I IFACE`, binds the server socket to one interface; implies `-l`.
    pub interface: Option<String>,
    /// `-l`, answer NTP requests as a server.
    pub listen: bool,
    /// `-t`, trust the network: drop the root-distance fitness test.
    pub trust_network: bool,
    /// `-n`, stay in the foreground.
    pub foreground: bool,
    /// `-q`, exit as soon as the clock has been set once.
    pub quit_after_set: bool,
    /// `-w`, query peers but never touch the clock; implies `-n`.
    pub watch_only: bool,
    /// `-N`, raise the scheduling priority.
    pub high_priority: bool,
    /// `-d`, repeated for more detail.
    pub verbose: u8,
}

/// Why a command line was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArgumentError {
    /// An option this daemon does not implement.
    Unknown(String),
    /// An option that takes a value was given none.
    MissingValue(&'static str),
    /// A positional argument; there are none in this contract.
    Unexpected(String),
    /// More `-p` peers than the daemon will track.
    TooManyPeers,
    /// A peer host name that cannot be resolved safely.
    InvalidPeer(String),
    /// An interface name Linux would not accept.
    InvalidInterface(String),
    /// A `-S` path that is empty or not absolute.
    InvalidScript(String),
    /// No `-p PEER` was given. Unlike busybox, `-l` alone is refused: a
    /// server with no upstream would have to publish stratum 1 from an
    /// undisciplined clock.
    NoPeers,
}

impl fmt::Display for ArgumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(option) => write!(formatter, "unknown option: {option}"),
            Self::MissingValue(option) => write!(formatter, "option {option} needs a value"),
            Self::Unexpected(value) => write!(formatter, "unexpected argument: {value}"),
            Self::TooManyPeers => write!(formatter, "at most {MAX_PEERS} -p peers are supported"),
            Self::InvalidPeer(peer) => write!(formatter, "invalid peer: {peer}"),
            Self::InvalidInterface(name) => write!(formatter, "invalid interface: {name}"),
            Self::InvalidScript(path) => write!(formatter, "invalid -S program: {path}"),
            Self::NoPeers => formatter.write_str("no -p PEER was given"),
        }
    }
}

/// One-line usage text, printed on any argument error.
pub const USAGE: &str = concat!(
    "usage: ntp [-dnqNwt] [-l [-I IFACE]] [-S PROG] -p PEER [-p PEER ...]\n",
    "       ntp --self-test\n",
    "  -p PEER  query PEER (host name or address)\n",
    "  -S PROG  run PROG after a step, a stratum change and every 11 min\n",
    "  -t       trust the network: skip the root-distance fitness test\n",
    "  -l       answer NTP client requests\n",
    "  -I IFACE bind the server socket to IFACE (implies -l)\n",
    "  -n       do not daemonise    -q  exit once the clock is set\n",
    "  -w       query only, never set the clock (implies -n)\n",
    "  -N       raise scheduling priority    -d  verbose (repeatable)\n",
);

/// True when a host name is safe to hand to the resolver and to log.
///
/// busybox handed whatever `-p` carried straight to `host2sockaddr()`. This
/// daemon keeps a charset, because the value is logged and reaches a resolver,
/// but it accepts the two forms a person actually types into the free-text
/// `ntp_server0` field and that are safe to pass on: surrounding whitespace,
/// which the caller trims, and a bracketed IPv6 literal, which is the only
/// notation in which `host:port` can express an IPv6 address at all.
#[must_use]
pub fn peer_is_valid(peer: &str) -> bool {
    if peer.is_empty() || peer.len() > 255 {
        return false;
    }
    if let Some(literal) = peer
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        // Only if the brackets really do hold an address: `[$(reboot)]` must
        // not become a name the resolver or a log line ever sees.
        return literal.parse::<Ipv6Addr>().is_ok();
    }
    peer.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

/// True when a name can be used with `SO_BINDTODEVICE`.
#[must_use]
pub fn interface_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_INTERFACE_LEN
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

/// True when a `-S` value is an absolute path with no control characters.
#[must_use]
pub fn script_is_valid(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 255
        && !path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
}

/// Parses the arguments after `argv[0]`.
///
/// # Errors
/// Returns the first [`ArgumentError`] found; nothing is applied partially.
pub fn parse<I>(arguments: I) -> Result<Options, ArgumentError>
where
    I: IntoIterator<Item = String>,
{
    let mut options = Options::default();
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-p" => {
                let peer = arguments.next().ok_or(ArgumentError::MissingValue("-p"))?;
                // A stray space around a host name is a configuration typo in
                // a free-text field, not an attack, and busybox's resolver
                // would have been handed it verbatim.
                let peer = peer.trim().to_owned();
                if !peer_is_valid(&peer) {
                    // Not fatal here: a second `-p` may still be usable, and
                    // `rc` has already logged "Started ntpd" by this point, so
                    // exiting would leave the router with no time source and
                    // no visible reason.
                    if options.rejected_peers.len() < MAX_PEERS {
                        options.rejected_peers.push(peer);
                    }
                    continue;
                }
                if options.peers.len() >= MAX_PEERS {
                    return Err(ArgumentError::TooManyPeers);
                }
                options.peers.push(peer);
            }
            "-S" => {
                let script = arguments.next().ok_or(ArgumentError::MissingValue("-S"))?;
                if !script_is_valid(&script) {
                    return Err(ArgumentError::InvalidScript(script));
                }
                options.script = Some(PathBuf::from(script));
            }
            "-I" => {
                let name = arguments.next().ok_or(ArgumentError::MissingValue("-I"))?;
                if !interface_is_valid(&name) {
                    return Err(ArgumentError::InvalidInterface(name));
                }
                options.interface = Some(name);
                // busybox declares "-I implies -l" through opt_complementary.
                options.listen = true;
            }
            "-l" => options.listen = true,
            "-t" => options.trust_network = true,
            "-n" => options.foreground = true,
            "-q" => options.quit_after_set = true,
            "-w" => {
                options.watch_only = true;
                // busybox declares "-w implies -n" through opt_complementary.
                options.foreground = true;
            }
            "-N" => options.high_priority = true,
            "-d" => options.verbose = options.verbose.saturating_add(1),
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(ArgumentError::Unknown(other.to_owned()))
            }
            other => return Err(ArgumentError::Unexpected(other.to_owned())),
        }
    }
    if options.peers.is_empty() {
        // Every `-p` was unusable: there is nothing left to query, so this is
        // still a startup error. One usable peer is enough to run.
        if let Some(peer) = options.rejected_peers.first() {
            return Err(ArgumentError::InvalidPeer(peer.clone()));
        }
        return Err(ArgumentError::NoPeers);
    }
    Ok(options)
}
