//! A dependency-free SNTP/NTPv4 client and LAN server for the GT-AX11000.
//!
//! This library half is pure, allocation-light and free of `unsafe`: it holds
//! the wire format, the reply/request validation, the clock-discipline state
//! machine and the command-line contract. The daemon half (`src/main.rs`)
//! keeps every system call in one small module.
//!
//! It replaces the busybox `ntpd` applet that was installed as
//! `/usr/sbin/ntp`. The observable contract that must not change is the one
//! `release/src/router/rc/ntpd.c` depends on: the argument vector, the process
//! name `ntp`, and running `/sbin/ntpd_synced step` when the clock is stepped.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cli;
pub mod client;
pub mod clock;
pub mod packet;
pub mod script;
pub mod server;

use clock::Discipline;
use packet::{Leap, Mode, Timestamp};

/// Marker printed by the `--self-test` path, asserted by the firmware
/// verifier under QEMU.
pub const SELF_TEST_MARKER: &str = "ntp-rs: runtime self-test passed";

/// Runs a deterministic, side-effect-free check of the packet and discipline
/// paths. It touches no socket, no clock and no file, so it is safe to run on
/// the target as a smoke test.
///
/// # Errors
/// Returns a description of the first check that did not hold.
pub fn self_test() -> Result<(), String> {
    let nonce = Timestamp {
        seconds: 0x1234_5678,
        fraction: 0x9abc_def0,
    };
    let query = client::build_query(nonce);
    let decoded = packet::Packet::decode(&query).map_err(|error| error.to_string())?;
    if decoded.mode != Mode::Client || decoded.version != 4 || decoded.transmit != nonce {
        return Err("query packet does not round-trip".to_owned());
    }

    // A stratum-2 reply that puts the local clock two seconds behind.
    let sent_at = 3_913_056_000.0_f64;
    let reply = packet::Packet {
        leap: Leap::NoWarning,
        version: 4,
        mode: Mode::Server,
        stratum: 2,
        poll: 6,
        precision: -20,
        root_delay: 0.01,
        root_dispersion: 0.01,
        reference_id: *b"TEST",
        reference: Timestamp::from_secs_f64(sent_at + 2.0),
        origin: nonce,
        receive: Timestamp::from_secs_f64(sent_at + 2.0),
        transmit: Timestamp::from_secs_f64(sent_at + 2.0),
    }
    .encode();
    let sample = client::evaluate_reply(&reply, client::Query { nonce, sent_at }, sent_at, 0.002)
        .map_err(|rejection| rejection.to_string())?;
    if (sample.offset - 2.0).abs() > 1e-3 {
        return Err(format!("unexpected offset {}", sample.offset));
    }

    // The same bytes with a mismatched origin timestamp must be refused.
    let spoofed = client::Query {
        nonce: Timestamp {
            seconds: 1,
            fraction: 1,
        },
        sent_at,
    };
    if client::evaluate_reply(&reply, spoofed, sent_at, 0.002).is_ok() {
        return Err("spoofed reply was accepted".to_owned());
    }

    let mut discipline = Discipline::new();
    let _ = discipline.update(2.0, sent_at, 2, Leap::NoWarning);
    let outcome = discipline.update(3.0, sent_at + 64.0, 2, Leap::NoWarning);
    if outcome.action != clock::ClockAction::Step(3.0) {
        return Err("a three-second offset did not step the clock".to_owned());
    }

    // Mode 6 and mode 7 have no handler at all.
    let state = server::ServerState {
        leap: Leap::NoWarning,
        stratum: 3,
        poll: 6,
        precision: clock::PRECISION_EXP,
        root_delay: 0.0,
        root_dispersion: 0.0,
        reference_id: *b"TEST",
        reference: Timestamp::from_secs_f64(sent_at),
    };
    for mode in [Mode::Control, Mode::Private] {
        let mut request = query;
        request[0] = (4 << 3) | mode_bits(mode);
        if server::build_reply(&request, &state, Timestamp::default(), Timestamp::default()).is_ok()
        {
            return Err(format!("{mode:?} request produced a reply"));
        }
    }
    Ok(())
}

fn mode_bits(mode: Mode) -> u8 {
    match mode {
        Mode::Reserved => 0,
        Mode::SymmetricActive => 1,
        Mode::SymmetricPassive => 2,
        Mode::Client => 3,
        Mode::Server => 4,
        Mode::Broadcast => 5,
        Mode::Control => 6,
        Mode::Private => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runtime_self_test_passes_on_the_host() {
        self_test().expect("self-test");
    }

    #[test]
    fn every_datagram_length_decodes_or_is_refused_without_panicking() {
        // The daemon is built with `panic = "abort"`, so a panic anywhere on
        // the parsing path would be a remote kill. Walk every length up to a
        // full datagram plus a few oversized ones.
        for length in (0..=128_usize).chain([256, 512, 1500, 4096]) {
            let bytes: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
            let _ = packet::Packet::decode(&bytes);
            let query = client::Query {
                nonce: Timestamp::default(),
                sent_at: 0.0,
            };
            let _ = client::evaluate_reply(&bytes, query, 0.0, 0.002);
            let state = server::ServerState {
                leap: Leap::NoWarning,
                stratum: 3,
                poll: 6,
                precision: clock::PRECISION_EXP,
                root_delay: 0.0,
                root_dispersion: 0.0,
                reference_id: *b"TEST",
                reference: Timestamp::default(),
            };
            let _ = server::build_reply(&bytes, &state, Timestamp::default(), Timestamp::default());
        }
    }
}
