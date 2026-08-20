#![forbid(unsafe_code)]

//! Pure, fail-closed policy validation for security-sensitive router settings.
//!
//! This crate intentionally has no filesystem, process, socket, FFI, or NVRAM
//! integration.  Callers must first turn untrusted input into the typed values
//! below and may only apply a change after successful validation.

pub mod firewall;
pub mod testlab;
pub mod vpn;
pub mod wlan;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyError {
    Empty,
    TooLong,
    NonAscii,
    InvalidCharacter,
    InvalidFormat,
    InvalidValue(&'static str),
    Duplicate(&'static str),
    UnknownField,
    Missing(&'static str),
    Invariant(&'static str),
    ConfirmationRequired,
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("value is empty"),
            Self::TooLong => formatter.write_str("value exceeds its length limit"),
            Self::NonAscii => formatter.write_str("value must be ASCII"),
            Self::InvalidCharacter => formatter.write_str("value contains an invalid character"),
            Self::InvalidFormat => formatter.write_str("value has an invalid format"),
            Self::InvalidValue(field) => write!(formatter, "invalid value for {field}"),
            Self::Duplicate(field) => write!(formatter, "duplicate {field}"),
            Self::UnknownField => formatter.write_str("unknown field"),
            Self::Missing(field) => write!(formatter, "missing {field}"),
            Self::Invariant(rule) => write!(formatter, "policy invariant failed: {rule}"),
            Self::ConfirmationRequired => formatter.write_str("explicit confirmation required"),
        }
    }
}

impl std::error::Error for PolicyError {}

pub(crate) fn parse_fields<'a, const N: usize>(
    input: &'a str,
    max_len: usize,
    allowed: [&str; N],
) -> Result<Vec<(&'a str, &'a str)>, PolicyError> {
    if input.is_empty() {
        return Err(PolicyError::Empty);
    }
    if input.len() > max_len {
        return Err(PolicyError::TooLong);
    }
    if !input.is_ascii() {
        return Err(PolicyError::NonAscii);
    }

    let mut parsed = Vec::new();
    for field in input.split(';') {
        let (key, value) = field.split_once('=').ok_or(PolicyError::InvalidFormat)?;
        if key.is_empty() || value.is_empty() || !allowed.contains(&key) {
            return Err(if allowed.contains(&key) {
                PolicyError::InvalidFormat
            } else {
                PolicyError::UnknownField
            });
        }
        if parsed.iter().any(|(seen, _)| *seen == key) {
            return Err(PolicyError::Duplicate("field"));
        }
        parsed.push((key, value));
    }
    Ok(parsed)
}

pub(crate) fn field<'a>(fields: &[(&'a str, &'a str)], name: &str) -> Result<&'a str, PolicyError> {
    fields
        .iter()
        .find_map(|(key, value)| (*key == name).then_some(*value))
        .ok_or(PolicyError::Missing("field"))
}

pub(crate) fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.is_ascii()
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}
