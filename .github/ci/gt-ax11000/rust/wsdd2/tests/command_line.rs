//! The command-line contract `release/src/router/rc/usb.c` depends on.

use wsdd2::cli::{self, Outcome};
use wsdd2::config;
use wsdd2::wsd::BootInfo;

fn run(arguments: &[&str]) -> Box<wsdd2::cli::Options> {
    match cli::parse(arguments) {
        Outcome::Run(options) => options,
        other => panic!("expected a run, got {other:?}"),
    }
}

#[test]
fn the_exact_argument_vector_rc_builds_is_accepted() {
    // rc/usb.c:6045-6053, with the boot string from rc/usb.c:6065.
    let options = run(&[
        "-d",
        "-w",
        "-i",
        "br0",
        "-b",
        "sku:GT-AX11000,serial:04d9f5aabbcc",
    ]);
    assert!(options.daemon);
    assert!(options.protocols.wsd);
    assert!(
        !options.protocols.llmnr,
        "-w must select WS-Discovery only, as wsdd2.c:895 did"
    );
    assert_eq!(options.interface.as_deref(), Some("br0"));
    assert_eq!(options.boot.sku, "GT-AX11000");
    assert_eq!(options.boot.serial, "04d9f5aabbcc");
    // Untouched keys keep the ASUSWRT defaults from wsd.c:180-192.
    assert_eq!(options.boot.vendor, "ASUS");
    assert_eq!(options.boot.model, "Asuswrt-Merlin");
    assert_eq!(options.boot.presentation_url, "http://router.asus.com");
    // Neither -4/-6 nor -u/-t was given, so both are selected (wsdd2.c:845).
    assert!(options.families.v4 && options.families.v6);
    assert!(options.transports.udp && options.transports.tcp);
}

#[test]
fn clustered_and_attached_option_arguments_work_like_getopt() {
    let clustered = run(&["-dw", "-ibr0"]);
    assert!(clustered.daemon && clustered.protocols.wsd);
    assert_eq!(clustered.interface.as_deref(), Some("br0"));
    let separated = run(&["-d", "-w", "-i", "br0"]);
    assert_eq!(clustered, separated);
}

#[test]
fn every_vendor_selector_is_honoured() {
    assert!(
        run(&["-4"]).families
            == wsdd2::cli::Families {
                v4: true,
                v6: false
            }
    );
    assert!(
        run(&["-6"]).families
            == wsdd2::cli::Families {
                v4: false,
                v6: true
            }
    );
    assert!(run(&["-46"]).families == wsdd2::cli::Families { v4: true, v6: true });
    assert!(
        run(&["-u"]).transports
            == wsdd2::cli::Transports {
                udp: true,
                tcp: false
            }
    );
    assert!(
        run(&["-t"]).transports
            == wsdd2::cli::Transports {
                udp: false,
                tcp: true
            }
    );
    assert!(
        run(&["-l"]).protocols
            == wsdd2::cli::Protocols {
                llmnr: true,
                wsd: false
            }
    );
    assert_eq!(run(&["-LLL"]).llmnr_debug, 3);
    assert_eq!(run(&["-WW"]).wsd_debug, 2);
    assert_eq!(run(&["-H", "router"]).hostname.as_deref(), Some("router"));
    assert_eq!(run(&["-N", "GTAX"]).netbios_name.as_deref(), Some("GTAX"));
    assert_eq!(run(&["-G", "HOME"]).workgroup.as_deref(), Some("HOME"));
}

#[test]
fn the_any_interface_spellings_select_every_interface() {
    // wsdd2.c:795-804.
    assert_eq!(run(&["-i", "any"]).interface, None);
    assert_eq!(run(&["-i", ""]).interface, None);
    assert_eq!(run(&[]).interface, None);
}

#[test]
fn help_is_requested_and_never_confused_with_a_run() {
    assert_eq!(cli::parse(["-h"]), Outcome::Help);
    assert_eq!(cli::parse(["-dh"]), Outcome::Help);
    assert!(cli::usage("wsdd2").starts_with("WSDD and LLMNR daemon\nUsage: wsdd2 [options]\n"));
}

#[test]
fn the_self_test_takes_no_other_argument() {
    assert_eq!(cli::parse(["--self-test"]), Outcome::SelfTest);
    assert!(matches!(
        cli::parse(["--self-test", "-d"]),
        Outcome::Reject(_)
    ));
}

#[test]
fn a_missing_option_argument_is_refused() {
    for letter in ["i", "H", "N", "G", "b"] {
        match cli::parse([format!("-{letter}")]) {
            Outcome::Reject(reason) => {
                assert!(reason.contains("requires an argument"), "{reason}");
            }
            other => panic!("expected a rejection for -{letter}, got {other:?}"),
        }
    }
}

#[test]
fn options_the_vendor_never_accepted_are_refused() {
    // -A and -B are printed by the vendor's own help (wsdd2.c:723-724) but
    // are absent from its getopt string (wsdd2.c:781), so it rejected them.
    for argument in ["-A", "-B", "-x", "-Z", "--verbose", "-", "positional"] {
        assert!(
            matches!(cli::parse([argument]), Outcome::Reject(_)),
            "accepted {argument}"
        );
    }
}

#[test]
fn a_hostile_option_argument_cannot_reach_a_log_line_or_a_terminal() {
    match cli::parse(["-i", "br0\u{1b}[2J\nfake"]) {
        Outcome::Reject(reason) => {
            assert!(!reason.contains('\u{1b}'));
            assert!(!reason.contains('\n'));
        }
        other => panic!("expected a rejection, got {other:?}"),
    }
    let long = "a".repeat(cli::MAX_OPTION_VALUE + 1);
    assert!(matches!(cli::parse(["-i", &long]), Outcome::Reject(_)));
}

#[test]
fn illegal_interface_names_are_refused() {
    for name in ["br0/../x", "a b", "a:b", "verylonginterfacename", ".", ".."] {
        assert!(
            !cli::interface_name_is_legal(name),
            "accepted interface {name}"
        );
        assert!(matches!(cli::parse(["-i", name]), Outcome::Reject(_)));
    }
    for name in ["br0", "eth0", "wl0.1", "vlan4094"] {
        assert!(cli::interface_name_is_legal(name), "refused {name}");
    }
}

#[test]
fn the_boot_information_grammar_matches_the_vendor_key_set() {
    let mut boot = BootInfo::default();
    cli::apply_boot_info(
        &mut boot,
        "vendor:ACME,model:Router,serial:1,sku:X,vendorurl:http://a,modelurl:http://b,presentationurl:http://c",
    )
    .expect("all seven keys");
    assert_eq!(boot.vendor, "ACME");
    assert_eq!(boot.presentation_url, "http://c");

    for bad in [
        "unknown:1",
        "sku",
        "sku:",
        ":1",
        &format!("sku:{}", "a".repeat(cli::MAX_BOOT_VALUE + 1)),
        "sku:a\u{1b}b",
    ] {
        let mut boot = BootInfo::default();
        assert!(
            cli::apply_boot_info(&mut boot, bad).is_err(),
            "accepted {bad}"
        );
    }
}

#[test]
fn an_endpoint_uuid_is_read_only_in_the_canonical_form() {
    // /proc/sys/kernel/random/boot_id and /etc/machine-id shapes.
    assert_eq!(
        config::parse_endpoint_uuid(b"c1b2a3d4-e5f6-4708-8910-a1b2c3d4e5f6\n").as_deref(),
        Some("c1b2a3d4-e5f6-4708-8910-a1b2c3d4e5f6")
    );
    for bad in [
        &b""[..],
        b"not-a-uuid",
        b"C1B2A3D4-E5F6-4708-8910-A1B2C3D4E5F6",
        b"c1b2a3d4e5f6470889 0a1b2c3d4e5f6",
        b"c1b2a3d4-e5f6-4708-8910-a1b2c3d4e5f",
        b"c1b2a3d4-e5f6-4708-8910-a1b2c3d4e5f67",
        b"c1b2a3d4-e5f6-4708-8910-g1b2c3d4e5f6",
        &[0xff, 0xfe][..],
    ] {
        assert_eq!(config::parse_endpoint_uuid(bad), None, "{bad:?}");
    }
}

#[test]
fn a_uuid_is_formatted_in_the_canonical_shape() {
    let bytes = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x4c, 0xde, 0x81, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let text = config::format_uuid(bytes);
    assert_eq!(text, "01234567-89ab-4cde-8123-456789abcdef");
    assert_eq!(
        config::parse_endpoint_uuid(text.as_bytes()).as_deref(),
        Some(text.as_str())
    );
}

#[test]
fn smb_conf_parameters_are_read_the_way_the_vendor_read_them() {
    let contents =
        b"[global]\n\tnetbios name = GT-AX11000\n\tworkgroup = HOME\n\tsecurity = user\n";
    assert_eq!(
        config::smb_parameter(contents, "netbios name").as_deref(),
        Some("GT-AX11000")
    );
    assert_eq!(
        config::smb_parameter(contents, "workgroup").as_deref(),
        Some("HOME")
    );
    assert_eq!(config::smb_parameter(contents, "netbios aliases"), None);
    assert_eq!(config::smb_parameter(b"", "workgroup"), None);
    // A value that could reach a reply must be printable and bounded.
    assert_eq!(
        config::smb_parameter(b"workgroup = ho\x00me\n", "workgroup"),
        None
    );
    let long = format!("workgroup = {}\n", "a".repeat(config::MAX_SMB_VALUE + 1));
    assert_eq!(config::smb_parameter(long.as_bytes(), "workgroup"), None);
}

#[test]
fn a_host_name_is_cut_at_the_first_dot() {
    // wsdd2.c:742-744.
    assert_eq!(
        config::short_hostname("GT-AX11000.lan").as_deref(),
        Some("GT-AX11000")
    );
    assert_eq!(config::short_hostname("router").as_deref(), Some("router"));
    assert_eq!(config::short_hostname(""), None);
    assert_eq!(config::short_hostname(".lan"), None);
    assert_eq!(config::short_hostname("a b"), None);
}
