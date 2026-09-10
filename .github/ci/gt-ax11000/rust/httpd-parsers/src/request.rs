//! Request-line and header parsing for the GT-AX11000 web server.
//!
//! The vendor `handle_request()` split the request line with `strsep()` and
//! matched headers with `strncasecmp()` prefixes inside one shared 10,000-byte
//! `char line[]`, advancing a cursor only for the headers it kept.  That
//! design has no bound on the number of headers, no framing checks, no
//! rejection of embedded NUL bytes and reads `Content-Length` with
//! `strtoul(cp, NULL, 0)` (so `0x10` and `010` are accepted) into an `int`.
//!
//! This module keeps the socket I/O in C: the C reader accumulates the raw
//! request block up to and including the terminating empty line and hands the
//! exact bytes here.  Everything from the request line to the last header is
//! parsed by `httparse` behind explicit caps, and only typed, bounded values
//! cross back over the ABI.

use core::ffi::{c_char, c_int, c_long, c_uint};
use core::{ptr, slice};

/// Largest request block (request line plus every header, including the
/// terminating empty line) the C reader may hand over.  The vendor could only
/// ever *store* 10,000 bytes of request line plus kept headers in `line[]`, so
/// this strictly dominates what it was able to represent.
pub const MAX_REQUEST_BLOCK: usize = 32_768;

/// Largest request line, counted up to and including its line feed.
pub const MAX_REQUEST_LINE: usize = 8_192;

/// Largest number of header fields.
pub const MAX_HEADERS: usize = 128;

/// Largest single header field value, before the per-field capacities below.
pub const MAX_HEADER_VALUE: usize = 8_192;

/// Largest `Content-Length`.  The vendor stored the value in an `int` and
/// rejected a negative result, so this is the same reachable range.
pub const MAX_CONTENT_LENGTH: u64 = 2_147_483_647;

/// Largest number of `Content-Length` decimal digits accepted before the
/// value itself is range checked.  Ten digits cannot overflow a `u64`.
const MAX_CONTENT_LENGTH_DIGITS: usize = 10;

/// Fixed capacities of the C result fields, NUL terminator included.
pub const TARGET_CAPACITY: usize = 4_096;
pub const HOST_CAPACITY: usize = 512;
pub const USER_AGENT_CAPACITY: usize = 2_048;
pub const COOKIE_CAPACITY: usize = 8_192;
pub const REFERER_CAPACITY: usize = 1_024;
pub const RANGE_CAPACITY: usize = 256;
pub const IF_NONE_MATCH_CAPACITY: usize = 512;
pub const BOUNDARY_CAPACITY: usize = 512;
pub const ACCEPT_LANGUAGE_CAPACITY: usize = 512;

/// The three methods `handle_request()` dispatches on.  Anything else keeps
/// the vendor's 501 answer instead of a 400, so it must survive parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
    Head,
    Other,
}

impl Method {
    fn as_c_int(self) -> c_int {
        match self {
            Method::Get => METHOD_GET,
            Method::Post => METHOD_POST,
            Method::Head => METHOD_HEAD,
            Method::Other => METHOD_OTHER,
        }
    }
}

/// Every way a request is refused.  Each maps to one distinct negative
/// sentinel on the C side so the caller can pick the vendor's wording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    /// The block ends before the header section is terminated.
    Incomplete,
    /// The request line is malformed, or the version is not HTTP/1.0 or 1.1.
    RequestLine,
    /// A header line has no colon, folds onto the next line, or carries a
    /// byte that is not allowed in a field name or value.
    Header,
    /// A documented cap was exceeded.
    TooLong,
    /// More than `MAX_HEADERS` header fields.
    TooManyHeaders,
    /// A NUL byte appears anywhere in the block.
    EmbeddedNul,
    /// `Content-Length` is duplicated, empty, not plain decimal, or too large.
    ContentLength,
    /// `Transfer-Encoding` is present: this server never framed a body with
    /// it, and accepting it next to `Content-Length` is request smuggling.
    Framing,
    /// The request target is empty, over capacity, or not origin-form.
    Target,
}

impl RequestError {
    fn as_c_int(self) -> c_int {
        match self {
            RequestError::Incomplete => ERR_INCOMPLETE,
            RequestError::RequestLine => ERR_REQUEST_LINE,
            RequestError::Header => ERR_HEADER,
            RequestError::TooLong => ERR_TOO_LONG,
            RequestError::TooManyHeaders => ERR_TOO_MANY_HEADERS,
            RequestError::EmbeddedNul => ERR_EMBEDDED_NUL,
            RequestError::ContentLength => ERR_CONTENT_LENGTH,
            RequestError::Framing => ERR_FRAMING,
            RequestError::Target => ERR_TARGET,
        }
    }
}

/// The typed result of one request block.  Every slice borrows the caller's
/// block; nothing is copied until the value crosses the C ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedRequest<'a> {
    pub method: Method,
    pub minor_version: u8,
    /// Origin-form request target, always starting with `/`.
    pub target: &'a [u8],
    /// Offset of the first `?` inside `target`, or `target.len()` when the
    /// target carries no query.
    pub query_offset: usize,
    pub content_length: Option<u64>,
    pub host: Option<&'a [u8]>,
    pub user_agent: Option<&'a [u8]>,
    pub cookie: Option<&'a [u8]>,
    pub referer: Option<&'a [u8]>,
    pub range: Option<&'a [u8]>,
    pub if_none_match: Option<&'a [u8]>,
    /// Everything after the first `boundary=` in the first header value that
    /// carries one, matching the vendor's `strstr()` on the raw header line.
    pub boundary: Option<&'a [u8]>,
    pub accept_language: Option<&'a [u8]>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn map_httparse_error(error: httparse::Error) -> RequestError {
    match error {
        httparse::Error::HeaderName | httparse::Error::HeaderValue => RequestError::Header,
        httparse::Error::TooManyHeaders => RequestError::TooManyHeaders,
        httparse::Error::NewLine | httparse::Error::Token | httparse::Error::Version => {
            RequestError::RequestLine
        }
        // `Status` is only reachable when parsing a response.
        httparse::Error::Status => RequestError::RequestLine,
    }
}

fn parse_content_length(value: &[u8]) -> Result<u64, RequestError> {
    if value.is_empty() || value.len() > MAX_CONTENT_LENGTH_DIGITS {
        return Err(RequestError::ContentLength);
    }
    let mut total: u64 = 0;
    for &byte in value {
        if !byte.is_ascii_digit() {
            return Err(RequestError::ContentLength);
        }
        // At most ten digits, so this cannot exceed 9_999_999_999.
        total = total * 10 + u64::from(byte - b'0');
    }
    if total > MAX_CONTENT_LENGTH {
        return Err(RequestError::ContentLength);
    }
    Ok(total)
}

fn bounded(value: &[u8], capacity: usize) -> Result<Option<&[u8]>, RequestError> {
    if value.len() >= capacity {
        return Err(RequestError::TooLong);
    }
    Ok(Some(value))
}

/// Parse one complete request block.
///
/// `block` must contain the request line, every header line and the
/// terminating empty line, exactly as they arrived on the socket.
pub fn parse_request(block: &[u8]) -> Result<ParsedRequest<'_>, RequestError> {
    if block.is_empty() {
        return Err(RequestError::Incomplete);
    }
    if block.len() > MAX_REQUEST_BLOCK {
        return Err(RequestError::TooLong);
    }
    if block.contains(&0) {
        return Err(RequestError::EmbeddedNul);
    }
    // `httparse` skips leading empty lines; the vendor answered 400 for them
    // because its first `fgets()` consumed one as the request line.
    if block[0] == b'\r' || block[0] == b'\n' {
        return Err(RequestError::RequestLine);
    }
    let line_feed = block
        .iter()
        .position(|&byte| byte == b'\n')
        .ok_or(RequestError::Incomplete)?;
    if line_feed + 1 > MAX_REQUEST_LINE {
        return Err(RequestError::TooLong);
    }

    let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut storage);
    match request.parse(block).map_err(map_httparse_error)? {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return Err(RequestError::Incomplete),
    }

    let method = match request.method.ok_or(RequestError::RequestLine)? {
        // The vendor dispatched with `strcasecmp()`, so a lowercase method
        // reached the same handler and has to keep doing so.
        name if name.eq_ignore_ascii_case("GET") => Method::Get,
        name if name.eq_ignore_ascii_case("POST") => Method::Post,
        name if name.eq_ignore_ascii_case("HEAD") => Method::Head,
        _ => Method::Other,
    };
    let minor_version = request.version.ok_or(RequestError::RequestLine)?;
    // `httparse` hands the target back as `&str` without validating UTF-8, so
    // it is only ever looked at as bytes here.
    let target = request.path.ok_or(RequestError::RequestLine)?.as_bytes();
    if target.is_empty() || target.len() >= TARGET_CAPACITY {
        return Err(RequestError::Target);
    }
    if target[0] != b'/' {
        return Err(RequestError::Target);
    }
    let query_offset = target
        .iter()
        .position(|&byte| byte == b'?')
        .unwrap_or(target.len());

    let mut parsed = ParsedRequest {
        method,
        minor_version,
        target,
        query_offset,
        content_length: None,
        host: None,
        user_agent: None,
        cookie: None,
        referer: None,
        range: None,
        if_none_match: None,
        boundary: None,
        accept_language: None,
    };
    let mut transfer_encoding = false;

    // The branch order is the vendor's `else if` chain, including the fact
    // that any header value carrying `boundary=` is consumed as the multipart
    // boundary before `Range:` and `If-None-Match:` are ever considered.
    for header in request.headers.iter() {
        let name = header.name;
        let value = header.value;
        if value.len() > MAX_HEADER_VALUE {
            return Err(RequestError::TooLong);
        }
        if name.eq_ignore_ascii_case("Accept-Language") {
            parsed.accept_language = bounded(value, ACCEPT_LANGUAGE_CAPACITY)?;
        } else if name.eq_ignore_ascii_case("User-Agent") {
            parsed.user_agent = bounded(value, USER_AGENT_CAPACITY)?;
        } else if name.eq_ignore_ascii_case("Cookie") {
            parsed.cookie = bounded(value, COOKIE_CAPACITY)?;
        } else if name.eq_ignore_ascii_case("Referer") {
            parsed.referer = bounded(value, REFERER_CAPACITY)?;
        } else if name.eq_ignore_ascii_case("Host") {
            // RFC 7230 allows exactly one; two of them is a routing
            // ambiguity the vendor resolved by taking the last.
            if parsed.host.is_some() {
                return Err(RequestError::Header);
            }
            parsed.host = bounded(value, HOST_CAPACITY)?;
        } else if name.eq_ignore_ascii_case("Content-Length") {
            if parsed.content_length.is_some() {
                return Err(RequestError::ContentLength);
            }
            parsed.content_length = Some(parse_content_length(value)?);
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            transfer_encoding = true;
        } else if let Some(offset) = find(value, b"boundary=") {
            parsed.boundary = bounded(&value[offset + b"boundary=".len()..], BOUNDARY_CAPACITY)?;
        } else if name.eq_ignore_ascii_case("Range") {
            parsed.range = bounded(value, RANGE_CAPACITY)?;
        } else if name.eq_ignore_ascii_case("If-None-Match") {
            parsed.if_none_match = bounded(value, IF_NONE_MATCH_CAPACITY)?;
        }
    }

    if transfer_encoding {
        return Err(RequestError::Framing);
    }

    Ok(parsed)
}

pub const METHOD_GET: c_int = 0;
pub const METHOD_POST: c_int = 1;
pub const METHOD_HEAD: c_int = 2;
pub const METHOD_OTHER: c_int = 3;

pub const HAS_HOST: c_uint = 1 << 0;
pub const HAS_USER_AGENT: c_uint = 1 << 1;
pub const HAS_COOKIE: c_uint = 1 << 2;
pub const HAS_REFERER: c_uint = 1 << 3;
pub const HAS_RANGE: c_uint = 1 << 4;
pub const HAS_IF_NONE_MATCH: c_uint = 1 << 5;
pub const HAS_BOUNDARY: c_uint = 1 << 6;
pub const HAS_ACCEPT_LANGUAGE: c_uint = 1 << 7;
pub const HAS_CONTENT_LENGTH: c_uint = 1 << 8;

pub const PARSE_OK: c_int = 0;
pub const ERR_INVALID_INPUT: c_int = -1;
pub const ERR_INCOMPLETE: c_int = -2;
pub const ERR_REQUEST_LINE: c_int = -3;
pub const ERR_HEADER: c_int = -4;
pub const ERR_TOO_LONG: c_int = -5;
pub const ERR_TOO_MANY_HEADERS: c_int = -6;
pub const ERR_EMBEDDED_NUL: c_int = -7;
pub const ERR_CONTENT_LENGTH: c_int = -8;
pub const ERR_FRAMING: c_int = -9;
pub const ERR_TARGET: c_int = -10;

/// The bounded result `handle_request()` reads.  Layout is pinned by
/// `rust_httpd_request_parse()`, which refuses to write anything unless the
/// caller's `sizeof` matches.
#[repr(C)]
pub struct RustHttpdRequest {
    pub method: c_int,
    pub minor_version: c_int,
    pub present: c_uint,
    pub content_length: c_long,
    pub target_len: usize,
    pub query_offset: usize,
    pub target: [c_char; TARGET_CAPACITY],
    pub host: [c_char; HOST_CAPACITY],
    pub user_agent: [c_char; USER_AGENT_CAPACITY],
    pub cookie: [c_char; COOKIE_CAPACITY],
    pub referer: [c_char; REFERER_CAPACITY],
    pub range: [c_char; RANGE_CAPACITY],
    pub if_none_match: [c_char; IF_NONE_MATCH_CAPACITY],
    pub boundary: [c_char; BOUNDARY_CAPACITY],
    pub accept_language: [c_char; ACCEPT_LANGUAGE_CAPACITY],
}

/// Copy one validated value into a fixed C field.  `parse_request()` has
/// already refused anything that does not fit, so this cannot truncate.
fn copy_field<const N: usize>(output: &mut [c_char; N], value: &[u8]) -> bool {
    if value.len() >= N {
        return false;
    }
    for (target, source) in output.iter_mut().zip(value.iter()) {
        *target = *source as c_char;
    }
    true
}

fn store<const N: usize>(
    output: &mut [c_char; N],
    present: &mut c_uint,
    flag: c_uint,
    value: Option<&[u8]>,
) -> bool {
    let Some(value) = value else {
        return true;
    };
    if !copy_field(output, value) {
        return false;
    }
    *present |= flag;
    true
}

/// Parse one request block into the fixed C result.
///
/// Returns `PARSE_OK` or one of the `ERR_*` sentinels; on any failure
/// `output` is left fully zeroed.
///
/// # Safety
///
/// `block` must reference exactly `length` readable bytes and `output` must
/// be writable for one `RustHttpdRequest`, whose size the caller passes in
/// `output_size`.
#[no_mangle]
pub unsafe extern "C" fn rust_httpd_request_parse(
    block: *const c_char,
    length: usize,
    output: *mut RustHttpdRequest,
    output_size: usize,
) -> c_int {
    if output.is_null() || output_size != core::mem::size_of::<RustHttpdRequest>() {
        return ERR_INVALID_INPUT;
    }
    // SAFETY: The caller contract requires one writable `RustHttpdRequest`,
    // whose size was just confirmed.  Zeroing first makes every failure path
    // hand back an empty result.
    unsafe { ptr::write_bytes(output.cast::<u8>(), 0, output_size) };
    if block.is_null() || length == 0 || length > MAX_REQUEST_BLOCK {
        return ERR_INVALID_INPUT;
    }
    // SAFETY: The caller contract requires exactly `length` readable bytes.
    let bytes = unsafe { slice::from_raw_parts(block.cast::<u8>(), length) };
    let parsed = match parse_request(bytes) {
        Ok(parsed) => parsed,
        Err(error) => return error.as_c_int(),
    };
    // SAFETY: `output` is writable for one value and was just zeroed.
    let result = unsafe { &mut *output };

    let mut present: c_uint = 0;
    let stored = copy_field(&mut result.target, parsed.target)
        && store(&mut result.host, &mut present, HAS_HOST, parsed.host)
        && store(
            &mut result.user_agent,
            &mut present,
            HAS_USER_AGENT,
            parsed.user_agent,
        )
        && store(&mut result.cookie, &mut present, HAS_COOKIE, parsed.cookie)
        && store(
            &mut result.referer,
            &mut present,
            HAS_REFERER,
            parsed.referer,
        )
        && store(&mut result.range, &mut present, HAS_RANGE, parsed.range)
        && store(
            &mut result.if_none_match,
            &mut present,
            HAS_IF_NONE_MATCH,
            parsed.if_none_match,
        )
        && store(
            &mut result.boundary,
            &mut present,
            HAS_BOUNDARY,
            parsed.boundary,
        )
        && store(
            &mut result.accept_language,
            &mut present,
            HAS_ACCEPT_LANGUAGE,
            parsed.accept_language,
        );
    if !stored {
        // Unreachable: `parse_request()` enforces every capacity.  Fail
        // closed anyway and leave nothing behind.
        // SAFETY: `output` is writable for `output_size` bytes.
        unsafe { ptr::write_bytes(output.cast::<u8>(), 0, output_size) };
        return ERR_TOO_LONG;
    }

    if let Some(content_length) = parsed.content_length {
        present |= HAS_CONTENT_LENGTH;
        // `MAX_CONTENT_LENGTH` is `i32::MAX`, so this fits a 32-bit `long`.
        result.content_length = content_length as c_long;
    }
    result.method = parsed.method.as_c_int();
    result.minor_version = c_int::from(parsed.minor_version);
    result.present = present;
    result.target_len = parsed.target.len();
    result.query_offset = parsed.query_offset;
    PARSE_OK
}

/// The `sizeof` the C header must agree on.  Exercised by the C ABI fixture.
#[no_mangle]
pub extern "C" fn rust_httpd_request_struct_size() -> usize {
    core::mem::size_of::<RustHttpdRequest>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(block: &[u8]) -> Result<ParsedRequest<'_>, RequestError> {
        parse_request(block)
    }

    const MINIMAL: &[u8] = b"GET / HTTP/1.1\r\n\r\n";

    #[test]
    fn minimal_get_is_accepted() {
        let request = parse(MINIMAL).expect("minimal GET");
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.minor_version, 1);
        assert_eq!(request.target, b"/");
        assert_eq!(request.query_offset, 1);
        assert_eq!(request.content_length, None);
        assert_eq!(request.host, None);
    }

    #[test]
    fn http_1_0_and_bare_line_feeds_match_the_vendor() {
        let request = parse(b"GET /index.asp HTTP/1.0\n\n").expect("HTTP/1.0");
        assert_eq!(request.minor_version, 0);
        assert_eq!(request.target, b"/index.asp");
    }

    #[test]
    fn lowercase_methods_still_dispatch() {
        for (raw, expected) in [
            (&b"get / HTTP/1.1\r\n\r\n"[..], Method::Get),
            (&b"pOsT / HTTP/1.1\r\n\r\n"[..], Method::Post),
            (&b"head / HTTP/1.1\r\n\r\n"[..], Method::Head),
        ] {
            assert_eq!(parse(raw).expect("method").method, expected);
        }
    }

    #[test]
    fn unknown_methods_parse_so_the_server_can_answer_501() {
        let request = parse(b"OPTIONS / HTTP/1.1\r\n\r\n").expect("OPTIONS");
        assert_eq!(request.method, Method::Other);
    }

    #[test]
    fn query_offset_points_at_the_first_question_mark() {
        let request = parse(b"GET /apply.cgi?a=1?b=2 HTTP/1.1\r\n\r\n").expect("query");
        assert_eq!(request.query_offset, 10);
        assert_eq!(&request.target[request.query_offset..], b"?a=1?b=2");
    }

    #[test]
    fn every_consumed_header_is_returned_trimmed() {
        let block = b"POST /apply.cgi HTTP/1.1\r\n\
            Host:  router.asus.com \r\n\
            User-Agent: \tasusrouter-Android\t\r\n\
            Cookie: asus_token=abc\r\n\
            Referer: http://router.asus.com/Main.asp\r\n\
            Accept-Language: en-US,en;q=0.9\r\n\
            Range: bytes=0-1023\r\n\
            If-None-Match: \"deadbeef\"\r\n\
            Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\r\n\
            Content-Length: 42\r\n\
            Connection: keep-alive\r\n\r\n";
        let request = parse(block).expect("full request");
        assert_eq!(request.method, Method::Post);
        assert_eq!(request.host, Some(&b"router.asus.com"[..]));
        assert_eq!(request.user_agent, Some(&b"asusrouter-Android"[..]));
        assert_eq!(request.cookie, Some(&b"asus_token=abc"[..]));
        assert_eq!(
            request.referer,
            Some(&b"http://router.asus.com/Main.asp"[..])
        );
        assert_eq!(request.accept_language, Some(&b"en-US,en;q=0.9"[..]));
        assert_eq!(request.range, Some(&b"bytes=0-1023"[..]));
        assert_eq!(request.if_none_match, Some(&b"\"deadbeef\""[..]));
        assert_eq!(request.boundary, Some(&b"----WebKitFormBoundary"[..]));
        assert_eq!(request.content_length, Some(42));
    }

    #[test]
    fn boundary_keeps_the_vendor_quoting_and_precedence() {
        // The vendor took everything after the first `boundary=` on the line,
        // quotes included, and never reached its `Range:` branch afterwards.
        let quoted = parse(
            b"POST /u.cgi HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=\"ab\"\r\n\r\n",
        )
        .expect("quoted boundary");
        assert_eq!(quoted.boundary, Some(&b"\"ab\""[..]));

        let shadowed =
            parse(b"GET /f HTTP/1.1\r\nRange: bytes=0-1 boundary=zz\r\n\r\n").expect("shadowed");
        assert_eq!(shadowed.boundary, Some(&b"zz"[..]));
        assert_eq!(shadowed.range, None);
    }

    #[test]
    fn content_length_must_be_plain_decimal() {
        assert_eq!(
            parse(b"POST /a HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
                .expect("zero")
                .content_length,
            Some(0)
        );
        for value in [
            &b"0x10"[..],
            &b"-1"[..],
            &b"+1"[..],
            &b""[..],
            &b"1 2"[..],
            &b"12345678901"[..],
            &b"2147483648"[..],
            &b"4294967295"[..],
        ] {
            let mut block = Vec::from(&b"POST /a HTTP/1.1\r\nContent-Length: "[..]);
            block.extend_from_slice(value);
            block.extend_from_slice(b"\r\n\r\n");
            assert_eq!(
                parse(&block).unwrap_err(),
                RequestError::ContentLength,
                "accepted {value:?}"
            );
        }
        // `010` is plain decimal ten, not octal as `strtoul(cp, NULL, 0)` read it.
        assert_eq!(
            parse(b"POST /a HTTP/1.1\r\nContent-Length: 010\r\n\r\n")
                .expect("leading zero")
                .content_length,
            Some(10)
        );
        assert_eq!(
            parse(b"POST /a HTTP/1.1\r\nContent-Length: 2147483647\r\n\r\n")
                .expect("maximum")
                .content_length,
            Some(MAX_CONTENT_LENGTH)
        );
    }

    #[test]
    fn duplicate_content_length_is_refused() {
        assert_eq!(
            parse(b"POST /a HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n")
                .unwrap_err(),
            RequestError::ContentLength
        );
    }

    #[test]
    fn duplicate_host_is_refused() {
        assert_eq!(
            parse(b"GET /a HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n").unwrap_err(),
            RequestError::Header
        );
    }

    #[test]
    fn transfer_encoding_is_always_refused() {
        for value in [&b"chunked"[..], &b"identity"[..], &b"gzip, chunked"[..]] {
            let mut block =
                Vec::from(&b"POST /a HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: "[..]);
            block.extend_from_slice(value);
            block.extend_from_slice(b"\r\n\r\n");
            assert_eq!(parse(&block).unwrap_err(), RequestError::Framing);
        }
        assert_eq!(
            parse(b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap_err(),
            RequestError::Framing
        );
    }

    #[test]
    fn embedded_nul_is_refused_anywhere() {
        assert_eq!(
            parse(b"GET /a\0b HTTP/1.1\r\n\r\n").unwrap_err(),
            RequestError::EmbeddedNul
        );
        assert_eq!(
            parse(b"GET /a HTTP/1.1\r\nCookie: a\0b\r\n\r\n").unwrap_err(),
            RequestError::EmbeddedNul
        );
        assert_eq!(
            parse(b"GET /a HTTP/1.1\r\n\r\n\0").unwrap_err(),
            RequestError::EmbeddedNul
        );
    }

    #[test]
    fn carriage_return_without_line_feed_is_refused() {
        // `\r` after the version, then a byte that is not `\n`.
        assert_eq!(
            parse(b"GET /a HTTP/1.1\rHost: a\r\n\r\n").unwrap_err(),
            RequestError::RequestLine
        );
        assert_eq!(
            parse(b"GET /a HTTP/1.1\r\nHost: a\r\r\n\r\n").unwrap_err(),
            RequestError::Header
        );
    }

    #[test]
    fn a_header_without_a_colon_is_refused() {
        assert_eq!(
            parse(b"GET /a HTTP/1.1\r\nHost router\r\n\r\n").unwrap_err(),
            RequestError::Header
        );
    }

    #[test]
    fn obsolete_line_folding_is_refused() {
        assert_eq!(
            parse(b"GET /a HTTP/1.1\r\nCookie: a=1\r\n b=2\r\n\r\n").unwrap_err(),
            RequestError::Header
        );
        assert_eq!(
            parse(b"GET /a HTTP/1.1\r\nCookie: a=1\r\n\tb=2\r\n\r\n").unwrap_err(),
            RequestError::Header
        );
    }

    #[test]
    fn control_bytes_in_the_request_line_are_refused() {
        assert_eq!(
            parse(b"GE\x01T /a HTTP/1.1\r\n\r\n").unwrap_err(),
            RequestError::RequestLine
        );
        assert_eq!(
            parse(b"GET /a\tb HTTP/1.1\r\n\r\n").unwrap_err(),
            RequestError::RequestLine
        );
        assert_eq!(
            parse(b"GET /a\x7f HTTP/1.1\r\n\r\n").unwrap_err(),
            RequestError::RequestLine
        );
    }

    #[test]
    fn a_target_that_is_not_absolute_is_refused() {
        for target in [
            &b"http://router/a"[..],
            &b"router:443"[..],
            &b"*"[..],
            &b"a/b"[..],
        ] {
            let mut block = Vec::from(&b"GET "[..]);
            block.extend_from_slice(target);
            block.extend_from_slice(b" HTTP/1.1\r\n\r\n");
            assert_eq!(
                parse(&block).unwrap_err(),
                RequestError::Target,
                "accepted {target:?}"
            );
        }
    }

    #[test]
    fn an_unterminated_block_is_incomplete() {
        assert_eq!(
            parse(b"GET / HTTP/1.1\r\n").unwrap_err(),
            RequestError::Incomplete
        );
        assert_eq!(parse(b"GET / HTT").unwrap_err(), RequestError::Incomplete);
        assert_eq!(parse(b"").unwrap_err(), RequestError::Incomplete);
    }

    #[test]
    fn a_leading_empty_line_is_refused_like_the_vendor() {
        assert_eq!(parse(b"\r\n").unwrap_err(), RequestError::RequestLine);
        assert_eq!(
            parse(b"\r\nGET / HTTP/1.1\r\n\r\n").unwrap_err(),
            RequestError::RequestLine
        );
    }

    #[test]
    fn only_http_1_0_and_1_1_are_accepted() {
        for version in [
            &b"HTTP/1.2"[..],
            &b"HTTP/2.0"[..],
            &b"HTTP/0.9"[..],
            &b"XX"[..],
        ] {
            let mut block = Vec::from(&b"GET / "[..]);
            block.extend_from_slice(version);
            block.extend_from_slice(b"\r\n\r\n");
            assert_eq!(
                parse(&block).unwrap_err(),
                RequestError::RequestLine,
                "accepted {version:?}"
            );
        }
    }

    #[test]
    fn extra_spaces_in_the_request_line_are_refused() {
        assert_eq!(
            parse(b"GET  / HTTP/1.1\r\n\r\n").unwrap_err(),
            RequestError::RequestLine
        );
        assert_eq!(
            parse(b"GET /  HTTP/1.1\r\n\r\n").unwrap_err(),
            RequestError::RequestLine
        );
        assert_eq!(
            parse(b"GET / HTTP/1.1 extra\r\n\r\n").unwrap_err(),
            RequestError::RequestLine
        );
    }

    #[test]
    fn the_request_line_is_capped() {
        let mut block = Vec::from(&b"GET /"[..]);
        block.resize(MAX_REQUEST_LINE, b'a');
        block.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        assert_eq!(parse(&block).unwrap_err(), RequestError::TooLong);
    }

    #[test]
    fn the_target_is_capped_below_the_request_line() {
        let mut block = Vec::from(&b"GET /"[..]);
        block.resize(b"GET ".len() + TARGET_CAPACITY, b'a');
        block.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        assert!(block.len() < MAX_REQUEST_LINE);
        assert_eq!(parse(&block).unwrap_err(), RequestError::Target);
    }

    #[test]
    fn the_header_count_is_capped() {
        let mut block = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for index in 0..=MAX_HEADERS {
            block.extend_from_slice(format!("X-{index}: v\r\n").as_bytes());
        }
        block.extend_from_slice(b"\r\n");
        assert_eq!(parse(&block).unwrap_err(), RequestError::TooManyHeaders);
    }

    #[test]
    fn exactly_the_header_limit_is_accepted() {
        let mut block = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for index in 0..MAX_HEADERS {
            block.extend_from_slice(format!("X-{index}: v\r\n").as_bytes());
        }
        block.extend_from_slice(b"\r\n");
        assert!(parse(&block).is_ok());
    }

    #[test]
    fn a_single_header_value_is_capped() {
        let mut block = Vec::from(&b"GET / HTTP/1.1\r\nX-Pad: "[..]);
        block.resize(block.len() + MAX_HEADER_VALUE + 1, b'a');
        block.extend_from_slice(b"\r\n\r\n");
        assert_eq!(parse(&block).unwrap_err(), RequestError::TooLong);
    }

    #[test]
    fn each_consumed_header_has_its_own_capacity() {
        for (name, capacity) in [
            ("Host", HOST_CAPACITY),
            ("User-Agent", USER_AGENT_CAPACITY),
            ("Referer", REFERER_CAPACITY),
            ("Range", RANGE_CAPACITY),
            ("If-None-Match", IF_NONE_MATCH_CAPACITY),
            ("Accept-Language", ACCEPT_LANGUAGE_CAPACITY),
        ] {
            let mut block = Vec::from(format!("GET / HTTP/1.1\r\n{name}: ").as_bytes());
            let value_start = block.len();
            block.resize(value_start + capacity - 1, b'a');
            block.extend_from_slice(b"\r\n\r\n");
            assert!(parse(&block).is_ok(), "{name} rejected at capacity - 1");

            let mut block = Vec::from(format!("GET / HTTP/1.1\r\n{name}: ").as_bytes());
            let value_start = block.len();
            block.resize(value_start + capacity, b'a');
            block.extend_from_slice(b"\r\n\r\n");
            assert_eq!(
                parse(&block).unwrap_err(),
                RequestError::TooLong,
                "{name} accepted at capacity"
            );
        }
    }

    #[test]
    fn the_whole_block_is_capped() {
        let mut block = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        while block.len() <= MAX_REQUEST_BLOCK {
            block.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaa\r\n");
        }
        block.extend_from_slice(b"\r\n");
        assert_eq!(parse(&block).unwrap_err(), RequestError::TooLong);
    }

    #[test]
    fn later_duplicates_win_for_the_headers_the_vendor_overwrote() {
        let request = parse(
            b"GET / HTTP/1.1\r\nCookie: first\r\nCookie: second\r\nUser-Agent: a\r\nUser-Agent: b\r\n\r\n",
        )
        .expect("duplicates");
        assert_eq!(request.cookie, Some(&b"second"[..]));
        assert_eq!(request.user_agent, Some(&b"b"[..]));
    }

    #[test]
    fn header_names_are_matched_whole_not_by_prefix() {
        let request = parse(
            b"GET / HTTP/1.1\r\nHost-Forwarded: a\r\nCookie-Jar: b\r\nContent-Length-Hint: 9\r\n\r\n",
        )
        .expect("similar names");
        assert_eq!(request.host, None);
        assert_eq!(request.cookie, None);
        assert_eq!(request.content_length, None);
    }

    #[test]
    fn a_high_byte_target_is_kept_like_the_vendor() {
        let request = parse(b"GET /\xc3\xa9 HTTP/1.1\r\n\r\n").expect("high bytes");
        assert_eq!(request.target, b"/\xc3\xa9");
    }

    #[test]
    fn ffi_round_trips_a_full_request() {
        let block = b"POST /apply.cgi?x=1 HTTP/1.1\r\n\
            Host: router.asus.com\r\n\
            Cookie: asus_token=abc\r\n\
            Content-Type: multipart/form-data; boundary=--xyz\r\n\
            Content-Length: 7\r\n\r\n";
        let mut output: RustHttpdRequest = unsafe { core::mem::zeroed() };
        let status = unsafe {
            rust_httpd_request_parse(
                block.as_ptr().cast::<c_char>(),
                block.len(),
                &mut output,
                core::mem::size_of::<RustHttpdRequest>(),
            )
        };
        assert_eq!(status, PARSE_OK);
        assert_eq!(output.method, METHOD_POST);
        assert_eq!(output.minor_version, 1);
        assert_eq!(output.content_length, 7);
        assert_eq!(output.target_len, "/apply.cgi?x=1".len());
        assert_eq!(output.query_offset, "/apply.cgi".len());
        assert_eq!(
            output.present,
            HAS_HOST | HAS_COOKIE | HAS_BOUNDARY | HAS_CONTENT_LENGTH
        );
        let target: Vec<u8> = output.target[..output.target_len]
            .iter()
            .map(|byte| *byte as u8)
            .collect();
        assert_eq!(target, b"/apply.cgi?x=1");
        assert_eq!(output.target[output.target_len], 0);
        assert_eq!(output.boundary[0] as u8, b'-');
        assert_eq!(output.range[0], 0);
    }

    #[test]
    fn ffi_rejects_a_mismatched_struct_size() {
        let mut output: RustHttpdRequest = unsafe { core::mem::zeroed() };
        let status = unsafe {
            rust_httpd_request_parse(
                MINIMAL.as_ptr().cast::<c_char>(),
                MINIMAL.len(),
                &mut output,
                core::mem::size_of::<RustHttpdRequest>() - 1,
            )
        };
        assert_eq!(status, ERR_INVALID_INPUT);
        assert_eq!(
            rust_httpd_request_struct_size(),
            core::mem::size_of::<RustHttpdRequest>()
        );
    }

    #[test]
    fn ffi_zeroes_the_result_on_every_failure() {
        let mut output: RustHttpdRequest = unsafe { core::mem::zeroed() };
        output.method = METHOD_POST;
        output.present = c_uint::MAX;
        output.content_length = 99;
        let block = b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let status = unsafe {
            rust_httpd_request_parse(
                block.as_ptr().cast::<c_char>(),
                block.len(),
                &mut output,
                core::mem::size_of::<RustHttpdRequest>(),
            )
        };
        assert_eq!(status, ERR_FRAMING);
        assert_eq!(output.method, 0);
        assert_eq!(output.present, 0);
        assert_eq!(output.content_length, 0);
        assert_eq!(output.target[0], 0);
    }

    #[test]
    fn ffi_rejects_null_and_oversized_input() {
        let mut output: RustHttpdRequest = unsafe { core::mem::zeroed() };
        let size = core::mem::size_of::<RustHttpdRequest>();
        assert_eq!(
            unsafe { rust_httpd_request_parse(ptr::null(), 4, &mut output, size) },
            ERR_INVALID_INPUT
        );
        assert_eq!(
            unsafe {
                rust_httpd_request_parse(
                    MINIMAL.as_ptr().cast::<c_char>(),
                    MAX_REQUEST_BLOCK + 1,
                    &mut output,
                    size,
                )
            },
            ERR_INVALID_INPUT
        );
        assert_eq!(
            unsafe {
                rust_httpd_request_parse(
                    MINIMAL.as_ptr().cast::<c_char>(),
                    MINIMAL.len(),
                    ptr::null_mut(),
                    size,
                )
            },
            ERR_INVALID_INPUT
        );
    }

    #[test]
    fn every_error_has_a_distinct_sentinel() {
        let sentinels = [
            ERR_INVALID_INPUT,
            ERR_INCOMPLETE,
            ERR_REQUEST_LINE,
            ERR_HEADER,
            ERR_TOO_LONG,
            ERR_TOO_MANY_HEADERS,
            ERR_EMBEDDED_NUL,
            ERR_CONTENT_LENGTH,
            ERR_FRAMING,
            ERR_TARGET,
        ];
        for (index, left) in sentinels.iter().enumerate() {
            assert!(*left < 0);
            for right in &sentinels[index + 1..] {
                assert_ne!(left, right);
            }
        }
    }
}
