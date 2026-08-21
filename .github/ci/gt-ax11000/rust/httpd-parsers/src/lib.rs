#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_int, CStr};
use core::{ptr, slice};
use router_policy::testlab::{TestlabRequest, TESTLAB_CONFIRMATION};
use router_policy::wlan::{Authentication, Cipher, ProtectedManagementFrames, WlanSecurityTuple};

const INVALID_INPUT: c_int = -1;
const EMBEDDED_NUL: c_int = -2;
const MAX_QUERY_LENGTH: usize = 65_535;
const MAX_QUERY_PAIRS: usize = 1_024;

/// `libovpn.so` is consumed by both `httpd` and `rc`. Each executable exports
/// this same narrow ABI from an already-linked, consumer-specific Rust archive,
/// so `httpd` does not need a second Rust runtime archive.
///
/// # Safety
///
/// Every non-null pointer must address a NUL-terminated string for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_openvpn_import_option_allowed(
    name: *const c_char,
    arg1: *const c_char,
    arg2: *const c_char,
    arg3: *const c_char,
) -> c_int {
    if name.is_null() || !arg3.is_null() {
        return 0;
    }
    // SAFETY: The ABI contract requires a readable NUL-terminated string.
    let Ok(name) = unsafe { CStr::from_ptr(name) }.to_str() else {
        return 0;
    };

    let mut args = Vec::with_capacity(2);
    for argument in [arg1, arg2] {
        if argument.is_null() {
            break;
        }
        // SAFETY: The ABI contract requires readable NUL-terminated strings.
        let Ok(argument) = unsafe { CStr::from_ptr(argument) }.to_str() else {
            return 0;
        };
        args.push(argument);
    }
    if arg1.is_null() && !arg2.is_null() {
        return 0;
    }

    router_policy::vpn::openvpn_import_directive_allowed(name, &args).into()
}

/// Validate the full OpenVPN custom field before libovpn appends it to a
/// generated configuration.
///
/// # Safety
///
/// `config` must address a NUL-terminated string for this call.
#[no_mangle]
pub unsafe extern "C" fn rust_openvpn_custom_config_allowed(config: *const c_char) -> c_int {
    if config.is_null() {
        return 0;
    }
    // SAFETY: The ABI contract requires a readable NUL-terminated string.
    unsafe { CStr::from_ptr(config) }
        .to_str()
        .is_ok_and(router_policy::vpn::openvpn_custom_config_allowed)
        .into()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decoded_octet(input: &[u8], offset: usize, plus_as_space: bool) -> Option<(u8, usize)> {
    if input[offset] == b'+' && plus_as_space {
        return Some((b' ', 1));
    }

    if input[offset] != b'%' || offset + 2 >= input.len() {
        return Some((input[offset], 1));
    }

    match (hex_value(input[offset + 1]), hex_value(input[offset + 2])) {
        (Some(high), Some(low)) => Some(((high << 4) | low, 3)),
        _ => Some((input[offset], 1)),
    }
}

fn url_decode_in_place(input: &mut [u8], plus_as_space: bool) -> Result<usize, ()> {
    let mut read = 0;
    while read < input.len() {
        let (decoded, consumed) = decoded_octet(input, read, plus_as_space).ok_or(())?;
        if decoded == 0 {
            return Err(());
        }
        read += consumed;
    }

    let mut read = 0;
    let mut write = 0;
    while read < input.len() {
        let (decoded, consumed) = decoded_octet(input, read, plus_as_space).ok_or(())?;
        input[write] = decoded;
        read += consumed;
        write += 1;
    }
    Ok(write)
}

/// Decode a URL-encoded byte string in place.
///
/// Valid `%XX` escapes are decoded and malformed escapes remain literal for
/// compatibility with the existing web UI. Encoded NUL is rejected before the
/// buffer is modified so C string consumers cannot observe a truncated value.
///
/// # Safety
///
/// `buffer` must point to a writable allocation of at least `length + 1`
/// bytes. The byte immediately after the input is replaced with a NUL.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_url_decode(
    buffer: *mut c_char,
    length: usize,
    plus_as_space: c_int,
) -> c_int {
    if buffer.is_null() || length > c_int::MAX as usize {
        return INVALID_INPUT;
    }

    // SAFETY: The caller contract requires a writable `length + 1` allocation.
    let bytes = unsafe { slice::from_raw_parts_mut(buffer.cast::<u8>(), length + 1) };
    let decoded_length = match url_decode_in_place(&mut bytes[..length], plus_as_space != 0) {
        Ok(length) => length,
        Err(()) => return EMBEDDED_NUL,
    };
    bytes[decoded_length] = 0;
    decoded_length as c_int
}

/// Return an upper bound for the number of query/form pairs in `query`.
///
/// # Safety
///
/// `query` must reference `length` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_query_capacity(query: *const c_char, length: usize) -> usize {
    if query.is_null() || length == 0 {
        return 1;
    }

    // SAFETY: The caller contract requires `length` readable bytes.
    let bytes = unsafe { slice::from_raw_parts(query.cast::<u8>(), length) };
    bytes
        .iter()
        .filter(|byte| matches!(byte, b'&' | b';'))
        .count()
        .saturating_add(1)
}

fn query_is_valid(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_QUERY_LENGTH
        && bytes
            .iter()
            .filter(|byte| matches!(byte, b'&' | b';'))
            .count()
            .saturating_add(1)
            <= MAX_QUERY_PAIRS
        && bytes
            .split(|byte| matches!(byte, b'&' | b';'))
            .all(field_is_decodable)
}

/// Validate a complete query before any in-place parsing or hash insertion.
/// This makes encoded NUL, overlong requests, and pair-count exhaustion fail
/// the entire request rather than applying a safe prefix.
///
/// # Safety
///
/// `query` must reference `length` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_query_validate(query: *const c_char, length: usize) -> c_int {
    if query.is_null() {
        return 0;
    }
    // SAFETY: The caller contract requires `length` readable bytes.
    let bytes = unsafe { slice::from_raw_parts(query.cast::<u8>(), length) };
    i32::from(query_is_valid(bytes))
}

/// Parse the next `name=value` pair from a mutable query/form string.
///
/// Separators and the first raw `=` are replaced by NUL bytes. Names and values
/// are decoded separately, so encoded delimiters never change the structure of
/// the request. Empty segments and segments without `=` are skipped. A segment
/// containing encoded NUL is rejected without exposing a partial C string.
///
/// Returns `1` for a pair and `0` when no pairs remain. Invalid pointers return
/// `-1`.
///
/// # Safety
///
/// `query` must point to a writable allocation of at least `length + 1` bytes.
/// The other pointers must be valid for their respective output types, and
/// `cursor` must initially be in `0..=length`.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_query_next(
    query: *mut c_char,
    length: usize,
    cursor: *mut usize,
    name_out: *mut *mut c_char,
    value_out: *mut *mut c_char,
) -> c_int {
    if query.is_null()
        || length == usize::MAX
        || cursor.is_null()
        || name_out.is_null()
        || value_out.is_null()
    {
        return INVALID_INPUT;
    }

    // SAFETY: All pointers are checked above and covered by the caller contract.
    let position = unsafe { &mut *cursor };
    if *position > length {
        return INVALID_INPUT;
    }
    // SAFETY: The caller contract requires a writable `length + 1` allocation.
    let bytes = unsafe { slice::from_raw_parts_mut(query.cast::<u8>(), length + 1) };

    while *position < length {
        let start = *position;
        let mut end = start;
        while end < length && !matches!(bytes[end], b'&' | b';') {
            end += 1;
        }
        *position = if end < length { end + 1 } else { length };
        bytes[end] = 0;

        if start == end {
            continue;
        }
        let Some(relative_equal) = bytes[start..end].iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let equal = start + relative_equal;

        // Validate both fields before changing the raw pair. This includes the
        // encoded-NUL check and prevents a rejected pair from becoming visible.
        if !field_is_decodable(&bytes[start..equal]) || !field_is_decodable(&bytes[equal + 1..end])
        {
            continue;
        }

        bytes[equal] = 0;
        let name_length =
            url_decode_in_place(&mut bytes[start..equal], true).expect("field was prevalidated");
        bytes[start + name_length] = 0;
        let value_length =
            url_decode_in_place(&mut bytes[equal + 1..end], true).expect("field was prevalidated");
        bytes[equal + 1 + value_length] = 0;

        // SAFETY: The offsets point inside the caller-owned mutable allocation.
        unsafe {
            ptr::write(name_out, query.add(start));
            ptr::write(value_out, query.add(equal + 1));
        }
        return 1;
    }

    0
}

fn field_is_decodable(field: &[u8]) -> bool {
    let mut offset = 0;
    while offset < field.len() {
        let Some((decoded, consumed)) = decoded_octet(field, offset, true) else {
            return false;
        };
        if decoded == 0 {
            return false;
        }
        offset += consumed;
    }
    true
}

fn multipart_filename_is_safe(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name[0] != b'-'
        && name != b"."
        && name != b".."
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Validate an uploaded certificate/key basename without interpreting a path.
///
/// # Safety
///
/// `name` must reference exactly `length` readable bytes. Embedded NUL bytes
/// are rejected like every other byte outside the strict basename allowlist.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_multipart_filename_validate(
    name: *const c_char,
    length: usize,
) -> c_int {
    if name.is_null() || length == 0 || length > 63 {
        return 0;
    }
    // SAFETY: The caller contract requires `length` readable bytes.
    let bytes = unsafe { slice::from_raw_parts(name.cast::<u8>(), length) };
    i32::from(multipart_filename_is_safe(bytes))
}

fn is_readonly_wireless_identity_key(name: &[u8]) -> bool {
    const GLOBAL_KEYS: [&[u8]; 17] = [
        b"acs_unii4",
        b"location_code",
        b"regulation_domain",
        b"regulation_domain_5G",
        b"regulation_domain_5g",
        b"ui_location_code",
        b"wl_acs_excl_chans",
        b"wl_acs_excl_chans_dfs",
        b"wl_chlist",
        b"wl_country_code",
        b"wl_ifnames",
        b"wl_ifname",
        b"wl_hwaddr",
        b"wl_phytype",
        b"wl_phytypes",
        b"wl_radioids",
        b"wl_txpower",
    ];
    const UNIT_SUFFIXES: [&[u8]; 14] = [
        b"acs_dfs",
        b"acs_excl_chans",
        b"acs_excl_chans_base",
        b"chlist",
        b"country",
        b"country_code",
        b"country_rev",
        b"ifname",
        b"hwaddr",
        b"phytype",
        b"phytypes",
        b"radioids",
        b"reg_mode",
        b"txpower",
    ];

    if GLOBAL_KEYS.contains(&name) {
        return true;
    }
    if let Some(separator) = name.iter().position(|byte| *byte == b':') {
        let (prefix, suffix_with_separator) = name.split_at(separator);
        let suffix = &suffix_with_separator[1..];
        if (prefix == b"0" || prefix == b"1" || prefix == b"2")
            && (suffix == b"ccode" || suffix == b"regrev" || suffix.starts_with(b"maxp"))
        {
            return true;
        }
    }
    if name.starts_with(b"pci/") {
        let suffix = name.rsplit(|byte| *byte == b'/').next().unwrap_or_default();
        if suffix == b"ccode" || suffix == b"regrev" || suffix.starts_with(b"maxp") {
            return true;
        }
    }
    let Some(rest) = name.strip_prefix(b"wl") else {
        return false;
    };
    let digit_count = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if digit_count == 0 || digit_count > 2 || rest.get(digit_count) != Some(&b'_') {
        return false;
    }
    UNIT_SUFFIXES.contains(&&rest[digit_count + 1..])
}

/// Return whether an apply key identifies platform-owned WLAN hardware state
/// or a regulatory value that requires the atomic country-only handler.
///
/// # Safety
///
/// `name` must reference exactly `length` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_wireless_identity_is_readonly(
    name: *const c_char,
    length: usize,
) -> c_int {
    if name.is_null() || length == 0 || length > 128 {
        return 0;
    }
    // SAFETY: The caller contract requires `length` readable bytes.
    let bytes = unsafe { slice::from_raw_parts(name.cast::<u8>(), length) };
    i32::from(is_readonly_wireless_identity_key(bytes))
}

/// Authorize one atomic country-profile change after the exact warning token.
/// No frequency, DFS or power argument exists at this ABI boundary.
///
/// # Safety
///
/// Both pointers must reference their exact readable byte lengths. Inputs are
/// not required to be NUL terminated and embedded NUL bytes are rejected.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_testlab_country_authorize(
    country: *const c_char,
    country_length: usize,
    confirmation: *const c_char,
    confirmation_length: usize,
) -> c_int {
    if country.is_null()
        || confirmation.is_null()
        || country_length == 0
        || country_length > 3
        || confirmation_length != TESTLAB_CONFIRMATION.len()
    {
        return 0;
    }
    // SAFETY: The caller contract requires the exact readable lengths.
    let country = unsafe { slice::from_raw_parts(country.cast::<u8>(), country_length) };
    // SAFETY: The caller contract requires the exact readable lengths.
    let confirmation =
        unsafe { slice::from_raw_parts(confirmation.cast::<u8>(), confirmation_length) };
    let (Ok(country), Ok(confirmation)) = (
        core::str::from_utf8(country),
        core::str::from_utf8(confirmation),
    ) else {
        return 0;
    };
    let request = format!("country={country}");
    i32::from(
        TestlabRequest::parse(&request)
            .and_then(|request| request.authorize(confirmation))
            .is_ok(),
    )
}

fn asus_wlan_security_is_valid(authentication: &str, cipher: &str, pmf: &str, wps: &str) -> bool {
    let authentication = match authentication {
        "psk2" => Authentication::Wpa2Personal,
        "sae" | "wpa3" => Authentication::Wpa3Sae,
        "psk2sae" => Authentication::Wpa2Wpa3Transition,
        "shared" | "psk" | "pskpsk2" => Authentication::Wep,
        "open" => Authentication::Open,
        _ => return false,
    };
    let cipher = match cipher {
        "aes" => Cipher::AesCcmp,
        "tkip" => Cipher::Tkip,
        "tkip+aes" => Cipher::TkipAndAes,
        "" | "none" => Cipher::None,
        _ => return false,
    };
    let pmf = match pmf {
        "0" => ProtectedManagementFrames::Disabled,
        "1" => ProtectedManagementFrames::Optional,
        "2" => ProtectedManagementFrames::Required,
        _ => return false,
    };
    let wps_enabled = match wps {
        "0" => false,
        "1" => true,
        _ => return false,
    };
    WlanSecurityTuple {
        authentication,
        cipher,
        pmf,
        wps_enabled,
    }
    .validate()
    .is_ok()
}

unsafe fn bounded_utf8<'a>(pointer: *const c_char, length: usize) -> Option<&'a str> {
    if pointer.is_null() || length > 32 {
        return None;
    }
    // SAFETY: The caller guarantees exactly `length` readable bytes.
    core::str::from_utf8(unsafe { slice::from_raw_parts(pointer.cast::<u8>(), length) }).ok()
}

/// Validate a complete ASUS WLAN security tuple before any NVRAM member is
/// changed. Regulatory country/channel/power values are deliberately absent.
///
/// # Safety
///
/// Every non-null pointer must reference its exact readable byte length.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_wlan_security_validate(
    authentication: *const c_char,
    authentication_length: usize,
    cipher: *const c_char,
    cipher_length: usize,
    pmf: *const c_char,
    pmf_length: usize,
    wps: *const c_char,
    wps_length: usize,
) -> c_int {
    // SAFETY: This function forwards the caller's exact-length ABI contract.
    let values = unsafe {
        (
            bounded_utf8(authentication, authentication_length),
            bounded_utf8(cipher, cipher_length),
            bounded_utf8(pmf, pmf_length),
            bounded_utf8(wps, wps_length),
        )
    };
    let (Some(authentication), Some(cipher), Some(pmf), Some(wps)) = values else {
        return 0;
    };
    i32::from(asus_wlan_security_is_valid(
        authentication,
        cipher,
        pmf,
        wps,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;
    use std::ffi::CString;

    #[test]
    fn openvpn_import_abi_export_is_fail_closed() {
        let cipher = CString::new("cipher").unwrap();
        let modern = CString::new("AES-256-GCM").unwrap();
        let weak = CString::new("AES-256-CBC").unwrap();

        // SAFETY: Every non-null pointer is backed by a live C string.
        unsafe {
            assert_eq!(
                rust_openvpn_import_option_allowed(
                    cipher.as_ptr(),
                    modern.as_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                ),
                1
            );
            assert_eq!(
                rust_openvpn_import_option_allowed(
                    cipher.as_ptr(),
                    weak.as_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                ),
                0
            );
            assert_eq!(
                rust_openvpn_import_option_allowed(
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                ),
                0
            );
        }
    }

    fn decode(input: &[u8], plus_as_space: bool) -> Result<Vec<u8>, c_int> {
        let mut buffer = input.to_vec();
        buffer.push(0);
        // SAFETY: `buffer` owns `input.len() + 1` writable bytes.
        let result = unsafe {
            rust_httpd_url_decode(
                buffer.as_mut_ptr().cast(),
                input.len(),
                c_int::from(plus_as_space),
            )
        };
        if result < 0 {
            Err(result)
        } else {
            Ok(buffer[..result as usize].to_vec())
        }
    }

    fn parse(input: &str) -> Vec<(String, String)> {
        let mut buffer = input.as_bytes().to_vec();
        buffer.push(0);
        let length = input.len();
        let mut cursor = 0;
        let mut pairs = Vec::new();

        loop {
            let mut name = ptr::null_mut();
            let mut value = ptr::null_mut();
            // SAFETY: All pointers refer to valid local storage and the query
            // buffer is writable with a trailing NUL byte.
            let result = unsafe {
                rust_httpd_query_next(
                    buffer.as_mut_ptr().cast(),
                    length,
                    &mut cursor,
                    &mut name,
                    &mut value,
                )
            };
            assert!(result >= 0);
            if result == 0 {
                break;
            }
            // SAFETY: Successful parsing returns NUL-terminated pointers into
            // `buffer`, which remains alive for these reads.
            let name = unsafe { CStr::from_ptr(name) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: Same argument as for `name`.
            let value = unsafe { CStr::from_ptr(value) }
                .to_string_lossy()
                .into_owned();
            pairs.push((name, value));
        }
        pairs
    }

    #[test]
    fn decodes_percent_and_plus() {
        assert_eq!(
            decode(b"hello+world%21", true),
            Ok(b"hello world!".to_vec())
        );
    }

    #[test]
    fn can_preserve_plus() {
        assert_eq!(decode(b"a+b", false), Ok(b"a+b".to_vec()));
    }

    #[test]
    fn preserves_malformed_percent_escapes() {
        assert_eq!(decode(b"%x1%2", true), Ok(b"%x1%2".to_vec()));
    }

    #[test]
    fn rejects_encoded_nul_before_mutation() {
        let input = b"safe%00hidden";
        assert_eq!(decode(input, true), Err(EMBEDDED_NUL));
    }

    #[test]
    fn rejects_the_entire_query_before_partial_application() {
        assert!(!query_is_valid(b"good=1&bad=%00x&other=2"));
        assert!(query_is_valid(b"good=1&other=2"));
        let too_many = "x=1&".repeat(MAX_QUERY_PAIRS);
        assert!(!query_is_valid(too_many.as_bytes()));
    }

    #[test]
    fn splits_before_decoding_structural_characters() {
        assert_eq!(
            parse("na%3Dme=value%26more&second=x%3By"),
            vec![
                ("na=me".into(), "value&more".into()),
                ("second".into(), "x;y".into())
            ]
        );
    }

    #[test]
    fn accepts_empty_names_values_and_mixed_separators() {
        assert_eq!(
            parse("=empty-name&empty-value=;x=1"),
            vec![
                ("".into(), "empty-name".into()),
                ("empty-value".into(), "".into()),
                ("x".into(), "1".into())
            ]
        );
    }

    #[test]
    fn skips_segments_without_assignments_and_encoded_nul() {
        assert_eq!(
            parse("bare&ok=yes&bad=%00hidden;after=still-here"),
            vec![
                ("ok".into(), "yes".into()),
                ("after".into(), "still-here".into())
            ]
        );
    }

    #[test]
    fn capacity_is_bounded_by_raw_segments() {
        let input = b"a=1&b=2;c=3";
        // SAFETY: `input` contains exactly `input.len()` readable bytes.
        let capacity = unsafe { rust_httpd_query_capacity(input.as_ptr().cast(), input.len()) };
        assert_eq!(capacity, 3);
    }

    #[test]
    fn multipart_filenames_are_strict_basenames() {
        for accepted in [
            b"client-01.p12".as_slice(),
            b"ca.pem".as_slice(),
            b"private_key.crt".as_slice(),
        ] {
            assert!(multipart_filename_is_safe(accepted));
        }
        for rejected in [
            b"".as_slice(),
            b".".as_slice(),
            b"..".as_slice(),
            b"-option.pem".as_slice(),
            b"../ca.pem".as_slice(),
            b"dir/ca.pem".as_slice(),
            b"dir\\ca.pem".as_slice(),
            b"ca;reboot".as_slice(),
            b"ca\0.pem".as_slice(),
        ] {
            assert!(!multipart_filename_is_safe(rejected));
        }
        assert!(!multipart_filename_is_safe(&[b'a'; 64]));
    }

    #[test]
    fn wireless_hardware_identity_keys_are_readonly() {
        for key in [
            b"wl_ifnames".as_slice(),
            b"wl0_ifname".as_slice(),
            b"wl2_hwaddr".as_slice(),
            b"wl10_radioids".as_slice(),
            b"location_code".as_slice(),
            b"ui_location_code".as_slice(),
            b"wl_country_code".as_slice(),
            b"wl0_country_code".as_slice(),
            b"wl1_country_rev".as_slice(),
            b"wl2_chlist".as_slice(),
            b"wl0_txpower".as_slice(),
            b"wl_acs_excl_chans".as_slice(),
            b"wl1_acs_excl_chans_base".as_slice(),
            b"0:ccode".as_slice(),
            b"1:regrev".as_slice(),
            b"2:maxp5ga2".as_slice(),
            b"pci/2/1/maxp2ga0".as_slice(),
            b"pci/2/1/ccode".as_slice(),
            b"regulation_domain".as_slice(),
            b"regulation_domain_5G".as_slice(),
        ] {
            assert!(is_readonly_wireless_identity_key(key));
        }
        for key in [
            b"wl0_ssid".as_slice(),
            b"wl0_auth_mode_x".as_slice(),
            b"wl0_chanspec".as_slice(),
            b"wl_ifname_extra".as_slice(),
            b"wlx_ifname".as_slice(),
            b"lan_ifname".as_slice(),
            b"0:foo".as_slice(),
            b"pci/2/1/macaddr".as_slice(),
        ] {
            assert!(!is_readonly_wireless_identity_key(key));
        }
    }

    #[test]
    fn security_ffi_rejects_null_oversized_and_embedded_nul_inputs() {
        let filename = b"client.p12";
        let embedded_nul = b"client\0.p12";
        let identity = b"wl2_ifname";
        let oversized = [b'a'; 64];

        // SAFETY: Non-null pointers below reference the exact readable lengths
        // supplied to each C-ABI function.
        unsafe {
            assert_eq!(
                rust_httpd_multipart_filename_validate(filename.as_ptr().cast(), filename.len()),
                1
            );
            assert_eq!(
                rust_httpd_multipart_filename_validate(
                    embedded_nul.as_ptr().cast(),
                    embedded_nul.len()
                ),
                0
            );
            assert_eq!(
                rust_httpd_multipart_filename_validate(core::ptr::null(), filename.len()),
                0
            );
            assert_eq!(
                rust_httpd_multipart_filename_validate(oversized.as_ptr().cast(), oversized.len()),
                0
            );
            assert_eq!(
                rust_httpd_wireless_identity_is_readonly(identity.as_ptr().cast(), identity.len()),
                1
            );
            assert_eq!(
                rust_httpd_wireless_identity_is_readonly(core::ptr::null(), identity.len()),
                0
            );
        }
    }

    #[test]
    fn country_profile_ffi_accepts_only_country_or_all_with_exact_consent() {
        for country in [b"DE".as_slice(), b"AU".as_slice(), b"ALL".as_slice()] {
            // SAFETY: Both byte slices remain valid for the exact supplied lengths.
            assert_eq!(
                unsafe {
                    rust_httpd_testlab_country_authorize(
                        country.as_ptr().cast(),
                        country.len(),
                        TESTLAB_CONFIRMATION.as_ptr().cast(),
                        TESTLAB_CONFIRMATION.len(),
                    )
                },
                1
            );
        }
        for country in [b"de".as_slice(), b"A1".as_slice(), b"DE\0".as_slice()] {
            // SAFETY: Both byte slices remain valid for the exact supplied lengths.
            assert_eq!(
                unsafe {
                    rust_httpd_testlab_country_authorize(
                        country.as_ptr().cast(),
                        country.len(),
                        TESTLAB_CONFIRMATION.as_ptr().cast(),
                        TESTLAB_CONFIRMATION.len(),
                    )
                },
                0
            );
        }
        // SAFETY: Non-null pointers remain valid; the deliberately wrong token
        // length is the exact readable length of `wrong`.
        let wrong = b"yes";
        assert_eq!(
            unsafe {
                rust_httpd_testlab_country_authorize(
                    b"DE".as_ptr().cast(),
                    2,
                    wrong.as_ptr().cast(),
                    wrong.len(),
                )
            },
            0
        );
    }

    #[test]
    fn asus_wlan_tuple_is_atomic_fail_closed_and_country_independent() {
        assert!(asus_wlan_security_is_valid("psk2", "aes", "1", "0"));
        assert!(asus_wlan_security_is_valid("sae", "aes", "2", "0"));
        for values in [
            ("sae", "aes", "1", "0"),
            ("sae", "aes", "2", "1"),
            ("psk2", "tkip", "1", "0"),
            ("open", "none", "0", "0"),
            ("unknown", "aes", "2", "0"),
        ] {
            assert!(!asus_wlan_security_is_valid(
                values.0, values.1, values.2, values.3
            ));
        }
        assert!(asus_wlan_security_is_valid("psk2sae", "aes", "1", "0"));
        assert!(!asus_wlan_security_is_valid("psk2", "aes", "1", "1"));

        let live = (b"psk2sae", b"aes", b"1", b"0");
        // SAFETY: Each fixed byte string remains readable for its exact length.
        assert_eq!(
            unsafe {
                rust_httpd_wlan_security_validate(
                    live.0.as_ptr().cast(),
                    live.0.len(),
                    live.1.as_ptr().cast(),
                    live.1.len(),
                    live.2.as_ptr().cast(),
                    live.2.len(),
                    live.3.as_ptr().cast(),
                    live.3.len(),
                )
            },
            1,
            "the deployed psk2sae/aes/PMF-optional tuple must remain applyable"
        );
    }
}
