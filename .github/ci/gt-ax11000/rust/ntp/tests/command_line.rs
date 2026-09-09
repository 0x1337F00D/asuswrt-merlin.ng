//! The command-line contract with `release/src/router/rc/ntpd.c`.
//!
//! `start_ntpd()` builds exactly one of the vectors exercised here. If any of
//! these stops parsing, the daemon fails to start on a real boot and the
//! router never gets the time.

use ntp::cli::{parse, ArgumentError, Options, MAX_PEERS};
use std::path::PathBuf;

fn argv(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|value| (*value).to_owned()).collect()
}

/// The base vector `start_ntpd()` always builds, with the default server.
#[test]
fn parses_the_default_rc_argument_vector() {
    let options = parse(argv(&[
        "-t",
        "-S",
        "/sbin/ntpd_synced",
        "-p",
        "pool.ntp.org",
    ]))
    .expect("rc's default vector must parse");
    assert_eq!(
        options,
        Options {
            peers: vec!["pool.ntp.org".to_owned()],
            script: Some(PathBuf::from("/sbin/ntpd_synced")),
            interface: None,
            listen: false,
            trust_network: true,
            foreground: false,
            quit_after_set: false,
            watch_only: false,
            high_priority: false,
            verbose: 0,
        }
    );
}

/// `ntp_server0` and `ntp_server1` both set: a second `-p` is appended.
#[test]
fn parses_two_configured_servers() {
    let options = parse(argv(&[
        "-t",
        "-S",
        "/sbin/ntpd_synced",
        "-p",
        "time.example.net",
        "-p",
        "192.0.2.53",
    ]))
    .expect("two servers must parse");
    assert_eq!(options.peers, ["time.example.net", "192.0.2.53"]);
    assert!(options.trust_network);
}

/// `ntpd_enable=1`: server mode on the LAN bridge.
#[test]
fn parses_the_lan_server_vector() {
    let options = parse(argv(&[
        "-t",
        "-S",
        "/sbin/ntpd_synced",
        "-p",
        "time.example.net",
        "-p",
        "192.0.2.53",
        "-l",
        "-I",
        "br0",
    ]))
    .expect("the server vector must parse");
    assert!(options.listen);
    assert_eq!(options.interface.as_deref(), Some("br0"));
    assert_eq!(options.peers.len(), 2);
    assert_eq!(options.script, Some(PathBuf::from("/sbin/ntpd_synced")));
}

#[test]
fn minus_i_implies_minus_l_and_minus_w_implies_minus_n() {
    let listening = parse(argv(&["-p", "pool.ntp.org", "-I", "br0"])).expect("parses");
    assert!(listening.listen, "-I implies -l, as busybox declared");
    let watching = parse(argv(&["-p", "pool.ntp.org", "-w"])).expect("parses");
    assert!(watching.foreground, "-w implies -n, as busybox declared");
    assert!(watching.watch_only);
}

#[test]
fn rejects_every_option_this_daemon_does_not_implement() {
    // busybox accepted and silently ignored -4/-6/-a/-A/-b/-g/-L, and had an
    // -x it never implemented. Accepting them here would let a future rc
    // change believe it had configured something.
    for option in [
        "-x",
        "-4",
        "-6",
        "-a",
        "-A",
        "-b",
        "-g",
        "-L",
        "-c",
        "-f",
        "-k",
        "-u",
        "--help",
        "--version",
        "-D",
    ] {
        let result = parse(argv(&["-p", "pool.ntp.org", option]));
        assert!(
            matches!(result, Err(ArgumentError::Unknown(ref found)) if found == option),
            "{option} gave {result:?}"
        );
    }
}

#[test]
fn rejects_positional_arguments() {
    assert!(matches!(
        parse(argv(&["-p", "pool.ntp.org", "extra"])),
        Err(ArgumentError::Unexpected(_))
    ));
}

#[test]
fn rejects_options_whose_value_is_missing() {
    for option in ["-p", "-S", "-I"] {
        assert!(
            matches!(
                parse(argv(&["-p", "pool.ntp.org", option])),
                Err(ArgumentError::MissingValue(found)) if found == option
            ),
            "{option}"
        );
    }
}

#[test]
fn rejects_peer_names_that_are_not_host_names() {
    for peer in [
        "",
        "pool.ntp.org;reboot",
        "pool.ntp.org rm -rf /",
        "pool\nntp.org",
        "pool.ntp.org\0",
    ] {
        assert!(
            matches!(
                parse(argv(&["-p", peer])),
                Err(ArgumentError::InvalidPeer(_))
            ),
            "{peer:?} was accepted"
        );
    }
    for peer in [
        "pool.ntp.org",
        "192.0.2.53",
        "2001:db8::1",
        "time-a_b.example",
    ] {
        assert!(parse(argv(&["-p", peer])).is_ok(), "{peer:?} was rejected");
    }
}

#[test]
fn rejects_interface_names_linux_would_not_accept() {
    for name in ["", "this-name-is-far-too-long", "br0;reboot", "br 0"] {
        assert!(
            matches!(
                parse(argv(&["-p", "pool.ntp.org", "-I", name])),
                Err(ArgumentError::InvalidInterface(_))
            ),
            "{name:?} was accepted"
        );
    }
}

#[test]
fn rejects_relative_or_control_laden_script_paths() {
    for script in ["ntpd_synced", "", "/sbin/ntpd_synced\n", "../../bin/sh"] {
        assert!(
            matches!(
                parse(argv(&["-p", "pool.ntp.org", "-S", script])),
                Err(ArgumentError::InvalidScript(_))
            ),
            "{script:?} was accepted"
        );
    }
}

#[test]
fn requires_at_least_one_peer_and_bounds_how_many() {
    assert_eq!(parse(argv(&[])), Err(ArgumentError::NoPeers));
    assert_eq!(
        parse(argv(&["-l", "-I", "br0"])),
        Err(ArgumentError::NoPeers),
        "-l alone would publish stratum 1 from an undisciplined clock"
    );
    let mut many = Vec::new();
    for index in 0..=MAX_PEERS {
        many.push("-p".to_owned());
        many.push(format!("peer{index}.example"));
    }
    assert_eq!(parse(many), Err(ArgumentError::TooManyPeers));
}

#[test]
fn repeated_verbosity_accumulates_without_overflowing() {
    let mut arguments = argv(&["-p", "pool.ntp.org"]);
    for _ in 0..300 {
        arguments.push("-d".to_owned());
    }
    assert_eq!(parse(arguments).expect("parses").verbose, u8::MAX);
}
