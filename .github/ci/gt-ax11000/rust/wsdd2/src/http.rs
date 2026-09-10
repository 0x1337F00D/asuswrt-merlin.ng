//! The tiny HTTP/1.1 framing the WS-Transfer metadata endpoint needs.
//!
//! WS-Discovery advertises `http://<address>:3702/<endpoint-uuid>` in the
//! `wsd:XAddrs` of every match, and a Windows client POSTs a WS-Transfer
//! `Get` there to learn the computer name and workgroup that make the router
//! appear as a named computer in Explorer's Network view.  This module frames
//! that one exchange and nothing else.
//!
//! The vendor equivalent is `wsd_parse_http_header` (`wsd.c:906-1000`).  It
//! is replaced rather than reproduced: it writes `*eol = '\0'` on the result
//! of a `strstr` that is not checked for `NULL` (`wsd.c:915-917`, a null
//! dereference on any request with no CRLF), re-enters its header loop after
//! an unbounded `recv` into the same buffer, and trusts `atoi` of an
//! attacker-supplied `Content-Length`.

/// Largest request this endpoint will hold, headers and body together.
///
/// A WS-Transfer `Get` is a few hundred bytes.  8 KiB is the same cap the XML
/// scanner applies, so a body that fits here can always be handed on.
pub const MAX_REQUEST: usize = 8192;
/// Largest single header line.
pub const MAX_HEADER_LINE: usize = 1024;
/// Largest number of header lines.
pub const MAX_HEADERS: usize = 32;

/// HTTP status codes this endpoint produces (`wsd.c:786-801`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// 200 OK.
    Ok,
    /// 400 Bad Request.
    BadRequest,
    /// 404 Not Found: the request line named another endpoint UUID.
    NotFound,
    /// 405 Method Not Allowed: not a `POST`, or not HTTP/1.x.
    MethodNotAllowed,
    /// 413 Payload Too Large: over [`MAX_REQUEST`].  The vendor answered 500
    /// here (`wsd.c:988`).
    TooLarge,
}

impl Status {
    /// The reason phrase, as it goes on the status line.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Ok => "200 OK",
            Self::BadRequest => "400 Bad Request",
            Self::NotFound => "404 Not Found",
            Self::MethodNotAllowed => "405 Method Not Allowed",
            Self::TooLarge => "413 Payload Too Large",
        }
    }
}

/// What the framer concluded from the bytes read so far.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// The header block is not complete yet; read more.
    Incomplete,
    /// The header block is complete and valid.
    Header {
        /// Offset of the first body byte.
        body_offset: usize,
        /// Declared body length.
        content_length: usize,
    },
    /// The request is refused with this status.
    Failed(Status),
}

/// Parses the header block of a POST to the metadata endpoint.
///
/// `endpoint` is the UUID that must appear in the request target; a request
/// for any other target is a 404, so the endpoint UUID acts as an unguessable
/// path segment on top of everything else.
#[must_use]
pub fn parse_header(buffer: &[u8], endpoint: &str) -> Progress {
    let Some(end) = find(buffer, b"\r\n\r\n") else {
        if buffer.len() >= MAX_REQUEST {
            return Progress::Failed(Status::TooLarge);
        }
        return Progress::Incomplete;
    };
    let Some(head) = buffer.get(..end) else {
        return Progress::Failed(Status::BadRequest);
    };
    let body_offset = match end.checked_add(4) {
        Some(offset) => offset,
        None => return Progress::Failed(Status::BadRequest),
    };

    let mut lines = head.split(|byte| *byte == b'\n');
    let Some(request_line) = lines.next() else {
        return Progress::Failed(Status::BadRequest);
    };
    if let Err(status) = check_request_line(trim_cr(request_line), endpoint) {
        return Progress::Failed(status);
    }

    let mut content_length: Option<usize> = None;
    let mut content_type_seen = false;
    let mut count = 0_usize;
    for line in lines {
        let line = trim_cr(line);
        if line.is_empty() {
            continue;
        }
        count = count.saturating_add(1);
        if count > MAX_HEADERS || line.len() > MAX_HEADER_LINE {
            return Progress::Failed(Status::BadRequest);
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Progress::Failed(Status::BadRequest);
        };
        let (Some(name), Some(value)) = (
            line.get(..colon),
            line.get(colon.saturating_add(1)..).map(trim_spaces),
        ) else {
            return Progress::Failed(Status::BadRequest);
        };
        if name.eq_ignore_ascii_case(b"content-type") {
            content_type_seen = true;
            // The vendor demanded an exact `application/soap+xml`
            // (`wsd.c:949`), which a client that appends the charset
            // parameter -- as Windows does -- never satisfies.  The media
            // type is compared and the parameters are ignored.
            let media = value
                .split(|byte| *byte == b';')
                .next()
                .map(trim_spaces)
                .unwrap_or_default();
            if !media.eq_ignore_ascii_case(b"application/soap+xml") {
                return Progress::Failed(Status::BadRequest);
            }
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                // Two lengths are a request-smuggling primitive, never a
                // legitimate client.
                return Progress::Failed(Status::BadRequest);
            }
            match parse_length(value) {
                Some(length) => content_length = Some(length),
                None => return Progress::Failed(Status::BadRequest),
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            // No chunked decoder exists here, so a body that claims one is
            // refused rather than silently read as if it were identity.
            return Progress::Failed(Status::BadRequest);
        }
    }

    let Some(content_length) = content_length else {
        return Progress::Failed(Status::BadRequest);
    };
    if !content_type_seen || content_length == 0 {
        return Progress::Failed(Status::BadRequest);
    }
    match body_offset.checked_add(content_length) {
        Some(total) if total <= MAX_REQUEST => Progress::Header {
            body_offset,
            content_length,
        },
        _ => Progress::Failed(Status::TooLarge),
    }
}

fn check_request_line(line: &[u8], endpoint: &str) -> Result<(), Status> {
    let mut parts = line.split(|byte| *byte == b' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err(Status::BadRequest);
    }
    if method != b"POST" {
        return Err(Status::MethodNotAllowed);
    }
    if !version.starts_with(b"HTTP/1.") {
        return Err(Status::MethodNotAllowed);
    }
    let Some(path) = target.strip_prefix(b"/".as_slice()) else {
        return Err(Status::NotFound);
    };
    if path != endpoint.as_bytes() {
        return Err(Status::NotFound);
    }
    Ok(())
}

fn parse_length(value: &[u8]) -> Option<usize> {
    if value.is_empty() || value.len() > 7 {
        return None;
    }
    let mut total = 0_usize;
    for byte in value {
        let digit = char::from(*byte).to_digit(10)?;
        total = total
            .checked_mul(10)?
            .checked_add(usize::try_from(digit).ok()?)?;
    }
    if total > MAX_REQUEST {
        return None;
    }
    Some(total)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\r', rest)) => rest,
        _ => line,
    }
}

fn trim_spaces(mut value: &[u8]) -> &[u8] {
    while let Some((first, rest)) = value.split_first() {
        if matches!(first, b' ' | b'\t') {
            value = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = value.split_last() {
        if matches!(last, b' ' | b'\t') {
            value = rest;
        } else {
            break;
        }
    }
    value
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let last = haystack.len().saturating_sub(needle.len());
    (0..=last).find(
        |start| match haystack.get(*start..start.saturating_add(needle.len())) {
            Some(window) => window == needle,
            None => false,
        },
    )
}

/// Builds the response header (`wsd.c:753-770`).
///
/// `date` is pre-formatted by the caller so this stays pure.  The response
/// carries no server-generated cookie, no keep-alive and no field derived
/// from the request.
#[must_use]
pub fn response_header(status: Status, date: &str, length: usize) -> String {
    let mut out = String::from("HTTP/1.1 ");
    out.push_str(status.reason());
    out.push_str("\r\nServer: Asuswrt WSD Server\r\nDate: ");
    out.push_str(date);
    out.push_str("\r\nConnection: close\r\nContent-Type: application/soap+xml\r\nContent-Length: ");
    out.push_str(&length.to_string());
    out.push_str("\r\n\r\n");
    out
}

/// Formats an RFC 1123 date from a Unix timestamp, as `strftime("%a, %d %b
/// %Y %H:%M:%S GMT")` did (`wsd.c:807`).
#[must_use]
pub fn http_date(unix_seconds: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix_seconds / 86_400;
    let seconds_of_day = unix_seconds % 86_400;
    let weekday = DAYS
        .get(usize::try_from(days % 7).unwrap_or(0))
        .copied()
        .unwrap_or("Thu");
    let (year, month, day) = civil_from_days(days);
    let month_name = MONTHS
        .get(usize::from(month).saturating_sub(1))
        .copied()
        .unwrap_or("Jan");
    format!(
        "{weekday}, {day:02} {month_name} {year:04} {:02}:{:02}:{:02} GMT",
        seconds_of_day / 3600,
        (seconds_of_day / 60) % 60,
        seconds_of_day % 60
    )
}

/// Howard Hinnant's civil-from-days, on the proleptic Gregorian calendar.
fn civil_from_days(days_since_epoch: u64) -> (u64, u8, u8) {
    let days = days_since_epoch.saturating_add(719_468);
    let era = days / 146_097;
    let day_of_era = days % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (
        year,
        u8::try_from(month).unwrap_or(1),
        u8::try_from(day).unwrap_or(1),
    )
}
