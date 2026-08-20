#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_int};
use core::{ptr, slice};

const INVALID_INPUT: c_int = -1;
const EMBEDDED_NUL: c_int = -2;
const MAX_QUERY_LENGTH: usize = 65_535;
const MAX_QUERY_PAIRS: usize = 1_024;

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

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;

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
}
