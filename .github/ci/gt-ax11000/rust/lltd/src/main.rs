//! `lld2d`, the GT-AX11000 Link Layer Topology Discovery responder.
//!
//! This binary replaces the closed `release/src/router/lltd.arm/lld2d.hnd`
//! that ASUS installs at `/usr/sbin/lld2d`. `rc/services.c` `start_lltd()`
//! runs `eval("lld2d", "br0")` after `chdir("/usr/sbin")`, and `stop_lltd()`
//! calls `killall_tk("lld2d")`, so the name and the single interface argument
//! are part of the contract.
//!
//! All protocol work happens in the `lltd` library, which forbids `unsafe`
//! entirely. Every syscall lives in [`sys`].

#![forbid(unsafe_op_in_unsafe_fn)]

mod sys;

use lltd::device::Device;
use lltd::responder::{Dropped, Responder};
use lltd::wire::{ETHERTYPE_LLTD, MAX_FRAME_LEN};
use std::fs;
use std::io;
use std::process::ExitCode;

/// Longest interface name accepted, one below `IFNAMSIZ`.
const MAX_INTERFACE_LEN: usize = 15;

/// How long the loop waits for a frame before refreshing its properties.
const POLL_TIMEOUT_MS: i32 = 1_000;

/// How often the IPv4 address and uptime are re-read.
const REFRESH_INTERVAL_MS: u64 = 5_000;

/// Fallback machine name. `get_machine_name` in the blob defaults the NVRAM
/// variable `lld2d_hostname` to exactly this string when it is unset.
const DEFAULT_NAME: &str = "ASUS_ROUTER";

/// Where the pid is recorded, matching the blob's `/var/run/%s-%.10s.pid`.
const PID_DIRECTORY: &str = "/var/run";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match Options::parse(arguments.iter().map(String::as_str)) {
        Ok(Options::SelfTest) => match self_test() {
            Ok(()) => {
                println!("lltd-rs: runtime self-test passed");
                ExitCode::SUCCESS
            }
            Err(failure) => {
                eprintln!("lltd-rs: self-test failed: {failure}");
                ExitCode::FAILURE
            }
        },
        Ok(Options::Run(settings)) => match run(&settings) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("lltd-rs: {error}");
                ExitCode::FAILURE
            }
        },
        Err(message) => {
            eprintln!("lltd-rs: {message}");
            eprintln!("usage: lld2d [-d] [-t TRACELEVEL] INTERFACE [WIRELESS-IF]");
            ExitCode::FAILURE
        }
    }
}

/// What the command line asked for.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Options {
    /// Exercise the parser and responder without a socket, then exit.
    SelfTest,
    /// Run the responder on one interface.
    Run(Settings),
}

/// The accepted invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Settings {
    interface: String,
    foreground: bool,
}

impl Options {
    /// Parses the blob's command line: an optional `-d`, an optional
    /// `-t TRACELEVEL`, the mandatory interface and an optional wireless
    /// interface that this port accepts and ignores.
    ///
    /// The blob assumes `eth1` when no interface is given. This port refuses
    /// instead: a responder that silently binds an interface nobody asked for
    /// is worse than one that does not start.
    fn parse<'a>(arguments: impl Iterator<Item = &'a str>) -> Result<Self, String> {
        let mut foreground = false;
        let mut positional: Vec<&str> = Vec::new();
        let mut expect_trace_level = false;
        for argument in arguments.take(8) {
            if expect_trace_level {
                expect_trace_level = false;
                continue;
            }
            match argument {
                "--self-test" => return Ok(Self::SelfTest),
                "-d" => foreground = true,
                "-t" => expect_trace_level = true,
                other if other.starts_with('-') => {
                    return Err(format!("unknown option: {other}"));
                }
                other => positional.push(other),
            }
        }
        if expect_trace_level {
            return Err("-t needs a TRACELEVEL".into());
        }
        let Some(interface) = positional.first() else {
            return Err("no INTERFACE argument".into());
        };
        if positional.len() > 2 {
            return Err("too many interface arguments".into());
        }
        if !interface_name_ok(interface) {
            return Err(format!("invalid network interface: {interface:?}"));
        }
        Ok(Self::Run(Settings {
            interface: (*interface).to_string(),
            foreground,
        }))
    }
}

/// Accepts only the shapes `if_nametoindex` can be handed safely.
fn interface_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_INTERFACE_LEN
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

/// Runs the responder until a signal arrives.
fn run(settings: &Settings) -> io::Result<()> {
    let interface = settings.interface.as_str();
    let station = sys::hardware_address(interface)?;
    let index = sys::interface_index(interface)?;
    let socket = sys::bind_packet_socket(interface, ETHERTYPE_LLTD)?;

    if !settings.foreground {
        sys::daemonize()?;
    }
    sys::install_signal_handlers();
    write_pid_file(interface);

    let now = sys::monotonic_millis();
    let mut responder = Responder::new(
        Device::new(
            station,
            sys::ipv4_address(interface),
            &machine_name(),
            &machine_name(),
            uptime_micros(),
        ),
        now,
    );
    let mut last_refresh = now;
    let mut frame = vec![0_u8; MAX_FRAME_LEN];

    loop {
        if sys::take_pending_signal() != 0 {
            return Ok(());
        }
        match sys::wait_readable(&socket, POLL_TIMEOUT_MS) {
            Ok(false) => {}
            Ok(true) => {
                let received = match sys::receive(&socket, &mut frame) {
                    Ok(received) => received,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                };
                let now = sys::monotonic_millis();
                let Some(bytes) = frame.get(..received) else {
                    continue;
                };
                // Every refusal is a silent drop: telling an unauthenticated
                // sender why its frame was rejected is itself a reply.
                if let Ok(reply) = responder.handle(bytes, now) {
                    // A send failure is a link condition, not a reason to
                    // abandon the responder.
                    let _ = sys::send(&socket, index, &reply);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        let now = sys::monotonic_millis();
        if now.saturating_sub(last_refresh) >= REFRESH_INTERVAL_MS {
            last_refresh = now;
            responder.refresh(sys::ipv4_address(interface), uptime_micros());
        }
    }
}

/// Writes `/var/run/lld2d-<interface>.pid`, the file the blob's
/// `osl_write_pidfile` creates with the format `/var/run/%s-%.10s.pid`.
///
/// Best effort: `stop_lltd()` on this platform uses `killall_tk("lld2d")` and
/// never reads the file, so a read-only `/var/run` must not stop the daemon.
fn write_pid_file(interface: &str) {
    let short: String = interface.chars().take(10).collect();
    let path = format!("{PID_DIRECTORY}/lld2d-{short}.pid");
    let _ = fs::write(path, format!("{}\n", std::process::id()));
}

/// The name advertised in the Machine Name and Friendly Name properties.
///
/// The blob reads the NVRAM variable `lld2d_hostname`, defaulting it to
/// `ASUS_ROUTER`, and separately overwrites the NVRAM variable
/// `friendly_name` with the fixed string "802.11 Broadcom Reference" every
/// time the property is fetched. This port neither reads nor writes NVRAM: it
/// takes the kernel hostname, which `rc` sets from `lan_hostname`, truncated
/// at the first dot exactly as `get_machine_name` truncates `uname()`.
fn machine_name() -> String {
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let hostname = hostname.trim();
    let hostname = hostname.split('.').next().unwrap_or_default();
    if hostname.is_empty() || hostname == "(none)" || hostname == "localhost" {
        return DEFAULT_NAME.to_string();
    }
    hostname.to_string()
}

/// Microseconds since boot, matching the 1 MHz Performance Counter Frequency
/// this responder advertises. `get_uptime` in the blob reads the same file.
fn uptime_micros() -> u64 {
    let Ok(contents) = fs::read_to_string("/proc/uptime") else {
        return 0;
    };
    let Some(field) = contents.split_ascii_whitespace().next() else {
        return 0;
    };
    parse_uptime_field(field)
}

/// Converts the first field of `/proc/uptime` into microseconds.
///
/// The kernel always prints two fractional digits, but the conversion accepts
/// any count and never over- or underflows: digits past the sixth are
/// discarded and a short fraction is scaled up.
fn parse_uptime_field(field: &str) -> u64 {
    let mut parts = field.split('.');
    let seconds: u64 = parts.next().unwrap_or_default().parse().unwrap_or(0);
    let written = parts.next().unwrap_or_default();
    let mut fraction: u64 = 0;
    let mut digits: u32 = 0;
    for character in written.chars().take(6) {
        let Some(digit) = character.to_digit(10) else {
            break;
        };
        fraction = fraction.saturating_mul(10).saturating_add(u64::from(digit));
        digits = digits.saturating_add(1);
    }
    let scale = 10_u64.pow(6_u32.saturating_sub(digits).min(6));
    seconds
        .saturating_mul(1_000_000)
        .saturating_add(fraction.saturating_mul(scale).min(999_999))
}

/// Exercises the parser, the responder and the emission policy with no
/// socket, no privileges and no clock dependency, then reports success.
///
/// This is what `CI/tests/verify-rust-firmware.sh` runs under QEMU: a raw
/// socket needs `CAP_NET_RAW`, which the CI runner does not have, so the
/// deterministic path has to avoid one entirely.
fn self_test() -> Result<(), String> {
    let station = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mapper = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let device = Device::new(
        station,
        Some([192, 168, 50, 1]),
        "GT-AX11000",
        "GT-AX11000",
        1_000_000,
    );
    let mut responder = Responder::new(device, 0);

    let discover = fixture(&mapper, lltd::wire::Opcode::Discover, 0, &[0, 5, 0, 0]);
    let reply = responder
        .handle(&discover, 0)
        .map_err(|reason| format!("a conforming Discover was dropped: {reason:?}"))?;
    if reply.len() > lltd::responder::MAX_RESPONSE_LEN {
        return Err(format!("the Hello is {} bytes", reply.len()));
    }
    if reply.get(17) != Some(&lltd::wire::Opcode::Hello.to_byte()) {
        return Err("the reply is not a Hello".into());
    }
    if responder.handle(&discover, 1) != Err(Dropped::DuplicateGeneration) {
        return Err("a repeated generation was answered twice".into());
    }

    let mut truncated = discover.clone();
    truncated.truncate(31);
    if responder.handle(&truncated, 2).is_ok() {
        return Err("a truncated frame was answered".into());
    }
    let mut wrong_ethertype = discover.clone();
    if let Some(slot) = wrong_ethertype.get_mut(12..14) {
        slot.copy_from_slice(&[0x08, 0x00]);
    }
    if responder.handle(&wrong_ethertype, 3).is_ok() {
        return Err("a non-LLTD EtherType was answered".into());
    }
    let mut unknown = discover.clone();
    if let Some(slot) = unknown.get_mut(17..18) {
        slot.copy_from_slice(&[0xFF]);
    }
    if responder.handle(&unknown, 4).is_ok() {
        return Err("an unknown opcode was answered".into());
    }

    // The budget is spent only by real replies: the three refusals above must
    // have left it untouched.
    if responder.tokens() != lltd::limit::DEFAULT_BURST.saturating_sub(1) {
        return Err(format!(
            "the emission budget is {} after one reply",
            responder.tokens()
        ));
    }
    Ok(())
}

/// Builds a well-formed request frame for the self-test.
fn fixture(mapper: &[u8; 6], opcode: lltd::wire::Opcode, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame =
        lltd::wire::base_header(&lltd::wire::BROADCAST, mapper, opcode, sequence).to_vec();
    frame.extend_from_slice(payload);
    frame.resize(60, 0);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vendor_command_line_is_accepted() {
        assert_eq!(
            Options::parse(["br0"].into_iter()),
            Ok(Options::Run(Settings {
                interface: "br0".into(),
                foreground: false,
            }))
        );
        assert_eq!(
            Options::parse(["-d", "-t", "0x2f", "br0", "eth6"].into_iter()),
            Ok(Options::Run(Settings {
                interface: "br0".into(),
                foreground: true,
            }))
        );
        assert_eq!(
            Options::parse(["--self-test"].into_iter()),
            Ok(Options::SelfTest)
        );
    }

    #[test]
    fn a_missing_or_unsafe_interface_is_refused_rather_than_guessed() {
        // The blob assumes "eth1" when no interface is named.
        assert!(Options::parse(std::iter::empty()).is_err());
        assert!(Options::parse(["br0;reboot"].into_iter()).is_err());
        assert!(Options::parse(["0123456789abcdef"].into_iter()).is_err());
        assert!(Options::parse(["-d"].into_iter()).is_err());
        assert!(Options::parse(["-t"].into_iter()).is_err());
        assert!(Options::parse(["-q", "br0"].into_iter()).is_err());
        assert!(Options::parse(["br0", "eth6", "eth7"].into_iter()).is_err());
    }

    #[test]
    fn interface_names_are_restricted_to_what_the_kernel_accepts() {
        assert!(interface_name_ok("br0"));
        assert!(interface_name_ok("eth0.100"));
        assert!(!interface_name_ok(""));
        assert!(!interface_name_ok("br0 "));
        assert!(!interface_name_ok("../../etc"));
    }

    #[test]
    fn the_self_test_passes() {
        self_test().expect("the built-in self-test");
    }

    #[test]
    fn the_machine_name_is_never_empty() {
        assert!(!machine_name().is_empty());
    }

    #[test]
    fn the_uptime_is_read_as_microseconds() {
        // /proc/uptime exists on every Linux host the tests run on.
        assert!(uptime_micros() > 0);
        assert_eq!(parse_uptime_field("12345.67"), 12_345_670_000);
        assert_eq!(parse_uptime_field("7"), 7_000_000);
        assert_eq!(parse_uptime_field("7.5"), 7_500_000);
        assert_eq!(parse_uptime_field("7.999999999"), 7_999_999);
        assert_eq!(parse_uptime_field(""), 0);
        assert_eq!(parse_uptime_field("not-a-number"), 0);
        assert_eq!(parse_uptime_field(&"9".repeat(40)), 0);
    }
}
