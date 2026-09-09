#![forbid(unsafe_op_in_unsafe_fn)]

//! Bounded, fail-closed validation for every value that the vendor
//! `shared/wlif_utils_ax.c` used to interpolate into a `system()`/`popen()`
//! command string.
//!
//! The crate performs no I/O, no allocation across its C ABI and never
//! retains a caller pointer.  It is deliberately independent of
//! `router-policy`/`router-security` so that the archive linked into
//! `libshared.so` — a library that roughly sixty packages and seventeen
//! prebuilt vendor blobs load — carries only these validators.
//!
//! Two classes of value are distinguished:
//!
//! * *identifiers* (interface names, control-interface prefixes, CLI verbs,
//!   WPS PINs, DPP blobs) are restricted to a strict ASCII charset, may not
//!   start with `-` so that they cannot be mistaken for a `wpa_cli` /
//!   `hostapd_cli` option, and can never carry a shell metacharacter;
//! * *opaque credentials* (SSID, passphrase/PSK) are validated only for
//!   length, NUL, control characters and encoding.  They are never allowed
//!   into a command line at all: the callers pass them as a single `execvp`
//!   argument, so no shell ever sees them.

use core::ffi::{c_char, c_int, c_ulong, CStr};

/// `IFNAMSIZ - 1`: the longest interface name the kernel accepts.
pub const MAX_INTERFACE_NAME: usize = 15;
/// Longest `hostapd_cli`/`wpa_cli` verb or enumerated argument accepted.
pub const MAX_CLI_TOKEN: usize = 64;
/// Longest space-separated list of CLI tokens accepted.
pub const MAX_CLI_WORD_LIST: usize = 128;
/// Longest NVRAM prefix accepted for a control-interface directory.
pub const MAX_CONTROL_PREFIX: usize = 16;
/// 802.11 SSID element maximum.
pub const MAX_SSID: usize = 32;
/// 802.11i passphrase bounds.
pub const MIN_PASSPHRASE: usize = 8;
/// 802.11i passphrase bounds.
pub const MAX_PASSPHRASE: usize = 63;
/// Length of a hex-encoded 256-bit PSK.
pub const PSK_HEX_LEN: usize = 64;
/// Longest DPP connector / key blob accepted.
pub const MAX_DPP_VALUE: usize = 1024;
/// Highest `wpa_supplicant` network id accepted.
pub const MAX_NETWORK_ID: u64 = 255;
/// `sizeof(struct sockaddr_un.sun_path)`: the control socket path bound.
pub const MAX_CONTROL_PATH: usize = 108;

const CONTROL_PATH_PREFIX: &[u8] = b"/var/run/";
const CONTROL_PATH_SUFFIX: &[u8] = b"_wpa_supplicant";
const CONTROL_DIR_SUFFIX: &[u8] = b"wpa_supplicant/";

/// Characters a POSIX shell would treat as syntax rather than data.
///
/// The rewritten call sites never build a shell command line, so this is a
/// second, explicit barrier rather than the only one.
#[must_use]
pub fn is_shell_metacharacter(byte: u8) -> bool {
    matches!(
        byte,
        b'|' | b'&'
            | b';'
            | b'<'
            | b'>'
            | b'('
            | b')'
            | b'$'
            | b'`'
            | b'\\'
            | b'"'
            | b'\''
            | b' '
            | b'\t'
            | b'\n'
            | b'\r'
            | b'*'
            | b'?'
            | b'['
            | b']'
            | b'#'
            | b'~'
            | b'='
            | b'%'
            | b'{'
            | b'}'
            | b'!'
    )
}

/// ASCII C0 controls, DEL and NUL.
#[must_use]
pub fn is_control(byte: u8) -> bool {
    byte < 0x20 || byte == 0x7f
}

/// A Linux network interface name usable as an `-i` argument and as one
/// filename component of a control-socket path.
///
/// Accepts `eth0`, `wl0.1`, `wds0.0.1`; rejects anything empty, over-long,
/// non-ASCII, option-like, path-like or carrying a shell metacharacter.
#[must_use]
pub fn interface_name_ok(value: &[u8]) -> bool {
    value.len() <= MAX_INTERFACE_NAME
        && value.first().is_some_and(u8::is_ascii_alphanumeric)
        && value
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

/// An NVRAM interface prefix such as `wl0_`, used to build the vendor
/// control-interface directory name.
#[must_use]
pub fn control_prefix_ok(value: &[u8]) -> bool {
    value.len() <= MAX_CONTROL_PREFIX
        && value.first().is_some_and(u8::is_ascii_alphanumeric)
        && value
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// A `hostapd_cli`/`wpa_cli` verb or enumerated argument (`wps_pbc`,
/// `set_network`, `WPA2PSK`, `CCMP`, a decimal counter, ...), or the vendor
/// program name itself.
///
/// A leading `-` is refused so that a value can never be read as an option,
/// and `/` is refused so that it can never name a different program or a
/// path: every path this file passes is a compiled-in literal or is built by
/// [`supplicant_control_path`]/[`supplicant_control_dir`].
#[must_use]
pub fn cli_token_ok(value: &[u8]) -> bool {
    value.len() <= MAX_CLI_TOKEN
        && value.first().is_some_and(|&byte| byte != b'-')
        && value
            .iter()
            .all(|&byte| byte.is_ascii_graphic() && byte != b'/' && !is_shell_metacharacter(byte))
}

/// A space-separated list of CLI tokens, as produced by the vendor
/// `wpa_supp_key_mgmt_conv_fn`/`hapd_mfp_conv_fn` helpers (`WPA-PSK SAE`,
/// `CCMP TKIP`, `RSN`, `2`, ...).
///
/// `wpa_cli` joins its trailing arguments with a single space before it
/// writes the control-interface line, so the whole list travels as one
/// `execvp` argument.  Leading, trailing and repeated separators are
/// refused so that an empty token can never appear.
#[must_use]
pub fn cli_word_list_ok(value: &[u8]) -> bool {
    value.len() <= MAX_CLI_WORD_LIST
        && !value.is_empty()
        && value.split(|&byte| byte == b' ').all(cli_token_ok)
}

/// A WPS device PIN: four or eight ASCII digits and nothing else.
#[must_use]
pub fn wps_pin_ok(value: &[u8]) -> bool {
    matches!(value.len(), 4 | 8) && value.iter().all(u8::is_ascii_digit)
}

/// Validate a UTF-8 encoding, rejecting overlong forms, surrogates and any
/// scalar value above `U+10FFFF`.
///
/// This is written out rather than delegated to `core::str::from_utf8` so
/// that the archive linked into `libshared.so` references nothing from the
/// Rust standard library beyond `strlen`; `core` is shipped as a single
/// object, so one call would pull the whole panic/backtrace runtime (about
/// 1.1 MiB of stripped ARM text) into a library that every firmware process
/// loads.
#[must_use]
pub fn utf8_ok(value: &[u8]) -> bool {
    let mut index = 0;
    while let Some(&first) = value.get(index) {
        let (width, low, high) = match first {
            0x00..=0x7f => (1, 0, 0),
            0xc2..=0xdf => (2, 0x80, 0xbf),
            0xe0 => (3, 0xa0, 0xbf),
            0xe1..=0xec | 0xee..=0xef => (3, 0x80, 0xbf),
            0xed => (3, 0x80, 0x9f),
            0xf0 => (4, 0x90, 0xbf),
            0xf1..=0xf3 => (4, 0x80, 0xbf),
            0xf4 => (4, 0x80, 0x8f),
            _ => return false,
        };
        for offset in 1..width {
            let Some(&byte) = value.get(index + offset) else {
                return false;
            };
            let (low, high) = if offset == 1 {
                (low, high)
            } else {
                (0x80, 0xbf)
            };
            if byte < low || byte > high {
                return false;
            }
        }
        index += width;
    }
    true
}

/// An SSID handed to a CLI helper as one opaque `execvp` argument.
///
/// The GT-AX11000 profile builds with `UTF8_SSID=y`, so a valid UTF-8
/// encoding is required; NUL, newline and every other control character are
/// refused.  Shell metacharacters are deliberately *allowed*: an SSID may
/// legitimately contain them, and no shell ever sees this value.
#[must_use]
pub fn ssid_ok(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SSID
        && !value.iter().copied().any(is_control)
        && utf8_ok(value)
}

/// A WPA passphrase (8..=63 printable ASCII) or a hex-encoded PSK (exactly
/// 64 hex digits), handed to a CLI helper as one opaque `execvp` argument.
#[must_use]
pub fn passphrase_ok(value: &[u8]) -> bool {
    if value.len() == PSK_HEX_LEN && value.iter().all(u8::is_ascii_hexdigit) {
        return true;
    }
    (MIN_PASSPHRASE..=MAX_PASSPHRASE).contains(&value.len())
        && value.iter().all(|&byte| (0x20..=0x7e).contains(&byte))
}

/// A DPP connector, C-sign key, net-access key or protocol key as stored in
/// NVRAM: base64 or base64url with padding and the JWS separator, and
/// nothing else.  A leading `-` is refused so that the value can never be
/// mistaken for a `wpa_cli` option.
#[must_use]
pub fn dpp_value_ok(value: &[u8]) -> bool {
    value.len() <= MAX_DPP_VALUE
        && value.first().is_some_and(|&byte| byte != b'-')
        && value.iter().all(|&byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'.' | b'_' | b'-' | b'=')
        })
}

/// A `wpa_supplicant` network identifier.
#[must_use]
pub fn network_id_ok(value: u64) -> bool {
    value <= MAX_NETWORK_ID
}

fn write_out(out: &mut [u8], parts: &[&[u8]]) -> Option<usize> {
    let length = parts.iter().map(|part| part.len()).sum::<usize>();
    if length == 0 || length >= MAX_CONTROL_PATH || length >= out.len() {
        return None;
    }
    let mut cursor = 0;
    for part in parts {
        for &byte in *part {
            *out.get_mut(cursor)? = byte;
            cursor += 1;
        }
    }
    *out.get_mut(cursor)? = 0;
    Some(cursor)
}

/// Build `/var/run/<nvifname>_wpa_supplicant` into `out` as a NUL-terminated
/// string, returning the length without the NUL.
#[must_use]
pub fn supplicant_control_path(nvifname: &[u8], out: &mut [u8]) -> Option<usize> {
    if !interface_name_ok(nvifname) {
        return None;
    }
    write_out(out, &[CONTROL_PATH_PREFIX, nvifname, CONTROL_PATH_SUFFIX])
}

/// Build `/var/run/<prefix>wpa_supplicant/` into `out` as a NUL-terminated
/// string, returning the length without the NUL.
#[must_use]
pub fn supplicant_control_dir(prefix: &[u8], out: &mut [u8]) -> Option<usize> {
    if !control_prefix_ok(prefix) {
        return None;
    }
    write_out(out, &[CONTROL_PATH_PREFIX, prefix, CONTROL_DIR_SUFFIX])
}

/// # Safety
///
/// `value` must be null or address a NUL-terminated string for this call.
unsafe fn bytes<'a>(value: *const c_char) -> Option<&'a [u8]> {
    if value.is_null() {
        return None;
    }
    // SAFETY: The ABI contract requires a readable NUL-terminated string.
    Some(unsafe { CStr::from_ptr(value) }.to_bytes())
}

macro_rules! c_predicate {
    ($(#[$meta:meta])* $name:ident => $inner:path) => {
        $(#[$meta])*
        ///
        /// # Safety
        ///
        /// `value` must be null or address a NUL-terminated string for the
        /// duration of this call.
        #[no_mangle]
        pub unsafe extern "C" fn $name(value: *const c_char) -> c_int {
            // SAFETY: forwarded ABI contract of this function.
            match unsafe { bytes(value) } {
                Some(value) => c_int::from($inner(value)),
                None => 0,
            }
        }
    };
}

c_predicate!(
    /// Accept one Linux interface name. Returns `1` when accepted.
    rust_wlif_ifname_ok => interface_name_ok
);
c_predicate!(
    /// Accept one NVRAM control-interface prefix. Returns `1` when accepted.
    rust_wlif_ctrl_prefix_ok => control_prefix_ok
);
c_predicate!(
    /// Accept one CLI verb or enumerated argument. Returns `1` when accepted.
    rust_wlif_cli_token_ok => cli_token_ok
);
c_predicate!(
    /// Accept one space-separated list of CLI tokens. Returns `1` when
    /// accepted.
    rust_wlif_cli_word_list_ok => cli_word_list_ok
);
c_predicate!(
    /// Accept one opaque SSID. Returns `1` when accepted.
    rust_wlif_ssid_ok => ssid_ok
);
c_predicate!(
    /// Accept one opaque passphrase or hex PSK. Returns `1` when accepted.
    rust_wlif_passphrase_ok => passphrase_ok
);
c_predicate!(
    /// Accept one WPS device PIN. Returns `1` when accepted.
    rust_wlif_wps_pin_ok => wps_pin_ok
);
c_predicate!(
    /// Accept one DPP connector or key blob. Returns `1` when accepted.
    rust_wlif_dpp_value_ok => dpp_value_ok
);

/// Accept one `wpa_supplicant` network identifier. Returns `1` when accepted.
#[no_mangle]
// `c_ulong` is 32-bit on the armv7 firmware target and 64-bit on the test
// host, so the widening conversion is only redundant when tests run.
#[allow(clippy::useless_conversion)]
pub extern "C" fn rust_wlif_network_id_ok(value: c_ulong) -> c_int {
    c_int::from(network_id_ok(u64::from(value)))
}

/// # Safety
///
/// `out` must address `out_len` writable bytes and the inputs must be null or
/// NUL-terminated strings for the duration of this call.
unsafe fn build_path(
    out: *mut c_char,
    out_len: usize,
    value: *const c_char,
    builder: fn(&[u8], &mut [u8]) -> Option<usize>,
) -> c_int {
    if out.is_null() || out_len == 0 {
        return 0;
    }
    // SAFETY: the caller guarantees `out_len` writable bytes at `out`.
    let buffer = unsafe { core::slice::from_raw_parts_mut(out.cast::<u8>(), out_len) };
    let Some(first) = buffer.first_mut() else {
        return 0;
    };
    *first = 0;
    // SAFETY: forwarded ABI contract of this function.
    let Some(value) = (unsafe { bytes(value) }) else {
        return 0;
    };
    match builder(value, buffer) {
        Some(_) => 1,
        None => {
            if let Some(first) = buffer.first_mut() {
                *first = 0;
            }
            0
        }
    }
}

/// Write `/var/run/<nvifname>_wpa_supplicant` into `out`.
///
/// Returns `1` on success. On rejection `out` is left as an empty string.
///
/// # Safety
///
/// `out` must address `out_len` writable bytes, and `nvifname` must be null
/// or a NUL-terminated string for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn rust_wlif_supplicant_ctrl_path(
    out: *mut c_char,
    out_len: usize,
    nvifname: *const c_char,
) -> c_int {
    // SAFETY: forwarded ABI contract of this function.
    unsafe { build_path(out, out_len, nvifname, supplicant_control_path) }
}

/// Write `/var/run/<prefix>wpa_supplicant/` into `out`.
///
/// Returns `1` on success. On rejection `out` is left as an empty string.
///
/// # Safety
///
/// `out` must address `out_len` writable bytes, and `prefix` must be null or
/// a NUL-terminated string for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn rust_wlif_supplicant_ctrl_dir(
    out: *mut c_char,
    out_len: usize,
    prefix: *const c_char,
) -> c_int {
    // SAFETY: forwarded ABI contract of this function.
    unsafe { build_path(out, out_len, prefix, supplicant_control_dir) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTILE: [&[u8]; 18] = [
        b"eth0;reboot",
        b"eth0 reboot",
        b"eth0|reboot",
        b"eth0&reboot",
        b"eth0`id`",
        b"eth0$(id)",
        b"eth0${x}",
        b"eth0>out",
        b"eth0<in",
        b"eth0\nreboot",
        b"eth0\rreboot",
        b"eth0\treboot",
        b"eth0*",
        b"eth0?",
        b"eth0'",
        b"eth0\"",
        b"eth0\\",
        b"eth0#",
    ];

    #[test]
    fn interface_names_accept_vendor_shapes_only() {
        for value in [
            &b"eth0"[..],
            b"wl0",
            b"wl0.1",
            b"wds0.0.1",
            b"br0",
            b"eth12345678901",
        ] {
            assert!(interface_name_ok(value), "rejected {value:?}");
        }
        for value in [
            &b""[..],
            b"eth1234567890123",
            b"-i",
            b".",
            b"..",
            b"../../etc/passwd",
            b"eth0/../x",
            b"\xff\xfe",
        ] {
            assert!(!interface_name_ok(value), "accepted {value:?}");
        }
        for value in HOSTILE {
            assert!(!interface_name_ok(value), "accepted {value:?}");
        }
    }

    #[test]
    fn interface_names_reject_every_embedded_control_byte() {
        for byte in 0u8..=0xff {
            let value = [b'w', b'l', byte];
            let accepted = interface_name_ok(&value);
            assert_eq!(
                accepted,
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'),
                "byte {byte:#04x}"
            );
            if is_control(byte) {
                assert!(!accepted, "accepted control byte {byte:#04x}");
            }
        }
    }

    #[test]
    fn control_prefixes_are_bounded_and_path_safe() {
        for value in [&b"wl0_"[..], b"wl1_", b"wl0.1_"] {
            assert!(control_prefix_ok(value), "rejected {value:?}");
        }
        for value in [
            &b""[..],
            b"/var/run",
            b"wl0_/../..",
            b"-p",
            b"wl0_wl0_wl0_wl0_w",
            b"\xc3\x28",
        ] {
            assert!(!control_prefix_ok(value), "accepted {value:?}");
        }
        for value in HOSTILE {
            assert!(!control_prefix_ok(value), "accepted {value:?}");
        }
    }

    #[test]
    fn cli_tokens_reject_options_metacharacters_and_over_length() {
        for value in [
            &b"wps_pbc"[..],
            b"wps_cancel",
            b"set_network",
            b"WPA2PSK",
            b"CCMP",
            b"0",
            b"255",
        ] {
            assert!(cli_token_ok(value), "rejected {value:?}");
        }
        for value in [
            &b""[..],
            b"-i",
            b"--help",
            b"/usr/sbin/wpa_cli",
            b"../../tmp/x",
            b"\xff",
            b"a\0b",
        ] {
            assert!(!cli_token_ok(value), "accepted {value:?}");
        }
        for value in HOSTILE {
            assert!(!cli_token_ok(value), "accepted {value:?}");
        }
        assert!(cli_token_ok(&[b'a'; MAX_CLI_TOKEN]));
        assert!(!cli_token_ok(&[b'a'; MAX_CLI_TOKEN + 1]));
    }

    #[test]
    fn cli_word_lists_reject_empty_tokens_and_metacharacters() {
        for value in [
            &b"WPA-PSK"[..],
            b"WPA-PSK SAE",
            b"CCMP TKIP",
            b"RSN WPA",
            b"2",
        ] {
            assert!(cli_word_list_ok(value), "rejected {value:?}");
        }
        for value in [
            &b""[..],
            b" WPA-PSK",
            b"WPA-PSK ",
            b"WPA-PSK  SAE",
            b"WPA-PSK\tSAE",
            b"WPA-PSK;reboot SAE",
            b"WPA-PSK -i",
            b"WPA-PSK\nSAE",
        ] {
            assert!(!cli_word_list_ok(value), "accepted {value:?}");
        }
        assert!(!cli_word_list_ok(&[b'a'; MAX_CLI_WORD_LIST + 1]));
    }

    #[test]
    fn wps_pins_are_exactly_four_or_eight_digits() {
        assert!(wps_pin_ok(b"12345670"));
        assert!(wps_pin_ok(b"1234"));
        for value in [
            &b""[..],
            b"123",
            b"12345",
            b"1234567",
            b"123456789",
            b"1234567 ",
            b"1234567;",
            b"1234\n567",
            b"abcdefgh",
            b"1234\x00567",
        ] {
            assert!(!wps_pin_ok(value), "accepted {value:?}");
        }
    }

    #[test]
    fn utf8_validation_matches_the_standard_library() {
        let mut buffer = [0_u8; 4];
        for first in 0..=0xff_u8 {
            buffer[0] = first;
            assert_eq!(
                utf8_ok(&buffer[..1]),
                core::str::from_utf8(&buffer[..1]).is_ok(),
                "one byte {first:#04x}"
            );
            for second in 0..=0xff_u8 {
                buffer[1] = second;
                assert_eq!(
                    utf8_ok(&buffer[..2]),
                    core::str::from_utf8(&buffer[..2]).is_ok(),
                    "two bytes {first:#04x} {second:#04x}"
                );
                for third in [0x00_u8, 0x7f, 0x80, 0x9f, 0xa0, 0xbf, 0xc0, 0xff] {
                    buffer[2] = third;
                    assert_eq!(
                        utf8_ok(&buffer[..3]),
                        core::str::from_utf8(&buffer[..3]).is_ok(),
                        "three bytes {first:#04x} {second:#04x} {third:#04x}"
                    );
                    for fourth in [0x00_u8, 0x7f, 0x80, 0x8f, 0x90, 0xbf, 0xc0, 0xff] {
                        buffer[3] = fourth;
                        assert_eq!(
                            utf8_ok(&buffer[..4]),
                            core::str::from_utf8(&buffer[..4]).is_ok(),
                            "four bytes {first:#04x} {second:#04x} {third:#04x} {fourth:#04x}"
                        );
                    }
                }
            }
        }
        assert!(utf8_ok(b""));
        assert!(utf8_ok("caf\u{e9} \u{1f600}".as_bytes()));
    }

    #[test]
    fn ssids_are_opaque_but_bounded_and_control_free() {
        for value in [&b"ASUS_11000"[..], b"My Net; rm -rf /", b"caf\xc3\xa9"] {
            assert!(ssid_ok(value), "rejected {value:?}");
        }
        assert!(ssid_ok(&[b'a'; MAX_SSID]));
        for value in [
            &b""[..],
            b"net\nwork",
            b"net\rwork",
            b"net\twork",
            b"net\x7fwork",
            b"net\x01work",
            b"\xff\xfe",
        ] {
            assert!(!ssid_ok(value), "accepted {value:?}");
        }
        assert!(!ssid_ok(&[b'a'; MAX_SSID + 1]));
    }

    #[test]
    fn passphrases_accept_spec_lengths_and_hex_psks() {
        assert!(passphrase_ok(b"12345678"));
        assert!(passphrase_ok(&[b'p'; MAX_PASSPHRASE]));
        assert!(passphrase_ok(&[b'a'; PSK_HEX_LEN]));
        assert!(passphrase_ok(b"pass;phrase with spaces"));
        for value in [
            &b""[..],
            b"1234567",
            b"pass\nword",
            b"pass\0word",
            b"pass\x7fword",
            b"caf\xc3\xa9pass",
        ] {
            assert!(!passphrase_ok(value), "accepted {value:?}");
        }
        assert!(!passphrase_ok(&[b'p'; MAX_PASSPHRASE + 1]));
        assert!(!passphrase_ok(&[b'z'; PSK_HEX_LEN]));
    }

    #[test]
    fn dpp_values_are_base64_shaped_and_bounded() {
        assert!(dpp_value_ok(b"eyJhbGciOiJFUzI1NiJ9.eyJ4Ijoi_-A"));
        assert!(dpp_value_ok(&[b'A'; MAX_DPP_VALUE]));
        for value in [&b""[..], b"-A", b"key with space", b"key\nnext"] {
            assert!(!dpp_value_ok(value), "accepted {value:?}");
        }
        for value in HOSTILE {
            assert!(!dpp_value_ok(value), "accepted {value:?}");
        }
        assert!(!dpp_value_ok(&[b'A'; MAX_DPP_VALUE + 1]));
    }

    #[test]
    fn network_ids_are_bounded() {
        assert!(network_id_ok(0));
        assert!(network_id_ok(MAX_NETWORK_ID));
        assert!(!network_id_ok(MAX_NETWORK_ID + 1));
        assert!(!network_id_ok(u64::MAX));
    }

    #[test]
    fn control_paths_are_built_only_from_accepted_names() {
        let mut out = [0u8; 128];
        let length = supplicant_control_path(b"wl0.1", &mut out).unwrap();
        assert_eq!(&out[..length], b"/var/run/wl0.1_wpa_supplicant");
        assert_eq!(out[length], 0);

        let length = supplicant_control_dir(b"wl0_", &mut out).unwrap();
        assert_eq!(&out[..length], b"/var/run/wl0_wpa_supplicant/");
        assert_eq!(out[length], 0);

        for value in [&b""[..], b"../../tmp", b"wl0;id", b"\xff"] {
            assert!(supplicant_control_path(value, &mut out).is_none());
            assert!(supplicant_control_dir(value, &mut out).is_none());
        }
    }

    #[test]
    fn control_paths_fail_closed_on_a_short_buffer() {
        let mut small = [0u8; 8];
        assert!(supplicant_control_path(b"wl0", &mut small).is_none());
        assert!(supplicant_control_dir(b"wl0_", &mut small).is_none());

        let mut exact = [0u8; b"/var/run/wl0_wpa_supplicant".len()];
        assert!(supplicant_control_path(b"wl0", &mut exact).is_none());

        let mut room = [0u8; b"/var/run/wl0_wpa_supplicant".len() + 1];
        assert_eq!(supplicant_control_path(b"wl0", &mut room), Some(27));
    }

    #[test]
    fn c_abi_rejects_null_and_reports_one_for_accepted_values() {
        // SAFETY: every pointer below is either null or a NUL-terminated
        // literal that outlives the call.
        unsafe {
            assert_eq!(rust_wlif_ifname_ok(core::ptr::null()), 0);
            assert_eq!(rust_wlif_ifname_ok(c"wl0.1".as_ptr()), 1);
            assert_eq!(rust_wlif_ifname_ok(c"wl0;id".as_ptr()), 0);
            assert_eq!(rust_wlif_cli_token_ok(c"wps_pbc".as_ptr()), 1);
            assert_eq!(rust_wlif_cli_token_ok(c"-i".as_ptr()), 0);
            assert_eq!(rust_wlif_ctrl_prefix_ok(c"wl0_".as_ptr()), 1);
            assert_eq!(rust_wlif_ssid_ok(c"ASUS".as_ptr()), 1);
            assert_eq!(rust_wlif_passphrase_ok(c"12345678".as_ptr()), 1);
            assert_eq!(rust_wlif_wps_pin_ok(c"12345670".as_ptr()), 1);
            assert_eq!(rust_wlif_dpp_value_ok(c"AAAA".as_ptr()), 1);
            assert_eq!(rust_wlif_network_id_ok(0), 1);
            assert_eq!(rust_wlif_network_id_ok(256), 0);

            let mut out = [c_char::default(); 64];
            assert_eq!(
                rust_wlif_supplicant_ctrl_path(out.as_mut_ptr(), out.len(), c"wl0".as_ptr()),
                1
            );
            assert_eq!(
                rust_wlif_supplicant_ctrl_path(out.as_mut_ptr(), out.len(), c"wl0;id".as_ptr()),
                0
            );
            assert_eq!(out[0], 0);
            assert_eq!(
                rust_wlif_supplicant_ctrl_path(core::ptr::null_mut(), 64, c"wl0".as_ptr()),
                0
            );
            assert_eq!(
                rust_wlif_supplicant_ctrl_dir(out.as_mut_ptr(), out.len(), c"wl0_".as_ptr()),
                1
            );
        }
    }
}
