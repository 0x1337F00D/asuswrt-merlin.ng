#![forbid(unsafe_code)]

pub const MAX_EVENT_MESSAGE_LEN: usize = 511;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventId(i32);

impl EventId {
    pub fn parse(input: &str) -> Result<Self, EventIdError> {
        let input = input.trim_matches(|character: char| character.is_ascii_whitespace());
        let digits = input
            .strip_prefix("0x")
            .or_else(|| input.strip_prefix("0X"))
            .unwrap_or(input);
        if digits.is_empty() {
            return Err(EventIdError::Empty);
        }
        if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(EventIdError::InvalidDigit);
        }
        let value = u32::from_str_radix(digits, 16).map_err(|_| EventIdError::Overflow)?;
        if value == 0 {
            return Err(EventIdError::Zero);
        }
        let value = i32::try_from(value).map_err(|_| EventIdError::Overflow)?;
        Ok(Self(value))
    }

    pub const fn value(self) -> i32 {
        self.0
    }

    pub const fn class(self) -> EventClass {
        match (self.0 as u32) >> 16 {
            0x1 => EventClass::System,
            0x2 => EventClass::Administration,
            0x3 => EventClass::Protection,
            0x6 => EventClass::Usb,
            0x7 => EventClass::General,
            0x8 => EventClass::AiMesh,
            _ => EventClass::VendorExtension,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventClass {
    System,
    Administration,
    Protection,
    Usb,
    General,
    AiMesh,
    VendorExtension,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventIdError {
    Empty,
    InvalidDigit,
    Zero,
    Overflow,
}

pub fn bounded_message(input: &[u8]) -> &[u8] {
    &input[..input.len().min(MAX_EVENT_MESSAGE_LEN)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_supported_event_classes() {
        let cases = [
            ("10001", EventClass::System),
            ("0x20005", EventClass::Administration),
            ("30010", EventClass::Protection),
            ("60006", EventClass::Usb),
            ("7000B", EventClass::General),
            ("80001", EventClass::AiMesh),
            ("f000", EventClass::VendorExtension),
        ];
        for (input, class) in cases {
            let event = EventId::parse(input).unwrap();
            assert_eq!(event.class(), class);
        }
    }

    #[test]
    fn accepts_legacy_ascii_whitespace() {
        assert_eq!(EventId::parse(" \t10031\n").unwrap().value(), 0x10031);
    }

    #[test]
    fn rejects_partial_and_signed_values() {
        assert_eq!(EventId::parse("10001junk"), Err(EventIdError::InvalidDigit));
        assert_eq!(EventId::parse("-10001"), Err(EventIdError::InvalidDigit));
        assert_eq!(EventId::parse("+10001"), Err(EventIdError::InvalidDigit));
    }

    #[test]
    fn rejects_empty_zero_and_overflow() {
        assert_eq!(EventId::parse(""), Err(EventIdError::Empty));
        assert_eq!(EventId::parse("0x"), Err(EventIdError::Empty));
        assert_eq!(EventId::parse("0"), Err(EventIdError::Zero));
        assert_eq!(EventId::parse("80000000"), Err(EventIdError::Overflow));
        assert_eq!(EventId::parse("100000000"), Err(EventIdError::Overflow));
    }

    #[test]
    fn bounds_message_for_c_terminator() {
        let message = vec![b'x'; 700];
        assert_eq!(bounded_message(&message).len(), 511);
        assert_eq!(bounded_message(b"short"), b"short");
    }
}
