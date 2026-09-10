//! A strict, bounded, namespace-aware XML scanner.
//!
//! It exists only to read the handful of SOAP envelopes WS-Discovery defines,
//! so it is deliberately not a general XML parser: it fails closed on anything
//! it was not written for.  Rejected outright are document type declarations,
//! entity declarations, `CDATA` sections, comments, processing instructions
//! other than a leading XML declaration, and any namespace URI that is not one
//! of the six this protocol uses.
//!
//! Every dimension of the input is capped before any allocation happens:
//! total length, nesting depth, element count, attribute count, name length
//! and text length.  The vendor "parser" it replaces is
//! `release/src/router/wsdd2/wsd.c:353-420` (`wsd_tag_find`, `wsd_req_parse`),
//! a pair of `strstr` calls over a NUL-terminated copy of the datagram with no
//! structural validation at all: it accepts a `<wsa:Action>` that appears
//! anywhere, including inside another element's text, and
//! `strchr(p, '<') < q` compares two pointers that need not be in the same
//! object when the tag is absent.

/// Largest document the scanner will look at, in bytes.
///
/// A Windows WS-Discovery Probe is under 1 KiB; the vendor read datagrams into
/// a 10,000-byte stack buffer (`wsd.c:1029`).  8 KiB leaves generous headroom
/// while keeping the worst case bounded.
pub const MAX_DOCUMENT: usize = 8192;
/// Largest element nesting depth.
pub const MAX_DEPTH: usize = 16;
/// Largest number of elements in one document.
pub const MAX_ELEMENTS: usize = 256;
/// Largest number of attributes on one element.
pub const MAX_ATTRIBUTES: usize = 16;
/// Largest qualified-name length, prefix and colon included.
pub const MAX_NAME: usize = 64;
/// Largest decoded text run, in bytes.
pub const MAX_TEXT: usize = 512;
/// Largest number of live namespace bindings.
pub const MAX_BINDINGS: usize = 32;

/// The SOAP 1.2 envelope namespace (`wsd.c:295`).
pub const SOAP12_NS: &str = "http://www.w3.org/2003/05/soap-envelope";
/// WS-Addressing 2004/08 (`wsd.c:297`).
pub const WSA_NS: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
/// WS-Discovery 2005/04 (`wsd.c:299`).
pub const WSD_NS: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
/// WS-Transfer 2004/09 (`wsd.c:301`).
pub const WXT_NS: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer";
/// WS-Discovery device profile, the namespace of the `Device` type.
pub const WSDP_NS: &str = "http://schemas.xmlsoap.org/ws/2006/02/devprof";
/// Microsoft publication namespace, the namespace of the `Computer` type.
pub const PUB_NS: &str = "http://schemas.microsoft.com/windows/pub/2005/07";

/// One of the namespaces this protocol is defined in.
///
/// Anything else becomes [`Namespace::Foreign`], which no message shape
/// accepts, so an unknown namespace can never be confused with a known one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Namespace {
    /// No prefix and no default binding is in scope.
    None,
    /// `http://www.w3.org/2003/05/soap-envelope`.
    Soap12,
    /// `http://schemas.xmlsoap.org/ws/2004/08/addressing`.
    Addressing,
    /// `http://schemas.xmlsoap.org/ws/2005/04/discovery`.
    Discovery,
    /// `http://schemas.xmlsoap.org/ws/2004/09/transfer`.
    Transfer,
    /// `http://schemas.xmlsoap.org/ws/2006/02/devprof`.
    DeviceProfile,
    /// `http://schemas.microsoft.com/windows/pub/2005/07`.
    Publication,
    /// A syntactically valid URI this daemon has no use for.
    Foreign,
}

impl Namespace {
    fn from_uri(uri: &[u8]) -> Self {
        match uri {
            _ if uri == SOAP12_NS.as_bytes() => Self::Soap12,
            _ if uri == WSA_NS.as_bytes() => Self::Addressing,
            _ if uri == WSD_NS.as_bytes() => Self::Discovery,
            _ if uri == WXT_NS.as_bytes() => Self::Transfer,
            _ if uri == WSDP_NS.as_bytes() => Self::DeviceProfile,
            _ if uri == PUB_NS.as_bytes() => Self::Publication,
            _ => Self::Foreign,
        }
    }
}

/// Why a document was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmlError {
    /// The document is longer than [`MAX_DOCUMENT`].
    TooLong,
    /// A construct this scanner deliberately does not implement: a doctype,
    /// an entity declaration, a CDATA section, a comment or a processing
    /// instruction that is not the leading XML declaration.
    Unsupported,
    /// The document ended in the middle of a construct.
    Truncated,
    /// A byte appeared where the grammar does not allow it.
    Malformed,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// More than [`MAX_ELEMENTS`] elements, [`MAX_ATTRIBUTES`] attributes or
    /// [`MAX_BINDINGS`] namespace bindings.
    TooMany,
    /// A name, attribute value or text run over its cap.
    TooLarge,
    /// An end tag that does not match the open start tag.
    Mismatched,
    /// A prefix with no namespace binding in scope.
    UnboundPrefix,
    /// A character reference or entity reference outside the tiny set that is
    /// implemented: the five predefined entities and printable-ASCII numeric
    /// references.
    BadReference,
    /// A byte sequence that is not valid UTF-8, or a control character.
    NotText,
}

impl core::fmt::Display for XmlError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::TooLong => "document exceeds the size cap",
            Self::Unsupported => "unsupported XML construct",
            Self::Truncated => "document ends inside a construct",
            Self::Malformed => "malformed XML",
            Self::TooDeep => "element nesting exceeds the depth cap",
            Self::TooMany => "element, attribute or namespace count cap exceeded",
            Self::TooLarge => "name or text exceeds its cap",
            Self::Mismatched => "end tag does not match its start tag",
            Self::UnboundPrefix => "namespace prefix is not bound",
            Self::BadReference => "unsupported entity or character reference",
            Self::NotText => "text is not printable UTF-8",
        };
        formatter.write_str(text)
    }
}

/// A qualified element name: a resolved namespace plus a local name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QName<'a> {
    /// The resolved namespace.
    pub namespace: Namespace,
    /// The local part, with the prefix removed.
    pub local: &'a [u8],
}

impl QName<'_> {
    /// True when this name is exactly `namespace:local`.
    #[must_use]
    pub fn is(&self, namespace: Namespace, local: &str) -> bool {
        self.namespace == namespace && self.local == local.as_bytes()
    }
}

/// One scanner event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event<'a> {
    /// An element opened.  A self-closing element produces `Start` and then
    /// `End` so callers never need a separate case for it.
    Start(QName<'a>),
    /// An element closed.
    End(QName<'a>),
    /// A decoded run of character data.  Never empty and never longer than
    /// [`MAX_TEXT`].
    Text(String),
}

struct Binding {
    depth: usize,
    prefix: Vec<u8>,
    namespace: Namespace,
}

/// A pull scanner over one document.
pub struct Scanner<'a> {
    input: &'a [u8],
    position: usize,
    depth: usize,
    elements: usize,
    open: Vec<QName<'a>>,
    bindings: Vec<Binding>,
    pending_end: Option<QName<'a>>,
    root_done: bool,
    finished: bool,
}

impl<'a> Scanner<'a> {
    /// Creates a scanner, checking only the length cap.
    ///
    /// # Errors
    /// [`XmlError::TooLong`] when the document is over [`MAX_DOCUMENT`].
    pub fn new(input: &'a [u8]) -> Result<Self, XmlError> {
        if input.len() > MAX_DOCUMENT {
            return Err(XmlError::TooLong);
        }
        Ok(Self {
            input,
            position: 0,
            depth: 0,
            elements: 0,
            open: Vec::new(),
            bindings: Vec::new(),
            pending_end: None,
            root_done: false,
            finished: false,
        })
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn starts_with(&self, needle: &[u8]) -> bool {
        match self.input.get(self.position..) {
            Some(rest) => rest.starts_with(needle),
            None => false,
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                self.position = self.position.saturating_add(1);
            } else {
                break;
            }
        }
    }

    /// Returns the next event, or `None` at the end of the document.
    ///
    /// # Errors
    /// The first [`XmlError`] the document violates.  After an error the
    /// scanner must not be used again.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Event<'a>>, XmlError> {
        if let Some(name) = self.pending_end.take() {
            return Ok(Some(Event::End(name)));
        }
        if self.finished {
            return Ok(None);
        }
        loop {
            let Some(byte) = self.peek() else {
                self.finished = true;
                if self.depth == 0 {
                    return Ok(None);
                }
                return Err(XmlError::Truncated);
            };
            if byte != b'<' {
                let text = self.scan_text()?;
                // Inter-element whitespace carries no information and is the
                // one thing a pretty-printed envelope adds, so it is dropped
                // before the document shape is checked.
                if text.trim().is_empty() {
                    continue;
                }
                if self.depth == 0 {
                    // Character data outside the root element.
                    return Err(XmlError::Malformed);
                }
                return Ok(Some(Event::Text(text)));
            }
            if self.root_done {
                // Only one root element, and nothing but whitespace after it.
                // Without this, a document could carry a second envelope --
                // or arbitrary trailing bytes -- behind a valid one.
                return Err(XmlError::Malformed);
            }
            if self.starts_with(b"<?xml") {
                self.skip_declaration()?;
                continue;
            }
            if self.starts_with(b"<!") || self.starts_with(b"<?") {
                return Err(XmlError::Unsupported);
            }
            if self.starts_with(b"</") {
                return self.scan_end_tag().map(Some);
            }
            return self.scan_start_tag().map(Some);
        }
    }

    fn skip_declaration(&mut self) -> Result<(), XmlError> {
        if self.position != 0 {
            return Err(XmlError::Unsupported);
        }
        let rest = self.input.get(self.position..).ok_or(XmlError::Truncated)?;
        let end = find(rest, b"?>").ok_or(XmlError::Truncated)?;
        self.position = self
            .position
            .checked_add(end)
            .and_then(|value| value.checked_add(2))
            .ok_or(XmlError::Malformed)?;
        Ok(())
    }

    fn scan_text(&mut self) -> Result<String, XmlError> {
        let start = self.position;
        while let Some(byte) = self.peek() {
            if byte == b'<' {
                break;
            }
            self.position = self.position.saturating_add(1);
        }
        let raw = self
            .input
            .get(start..self.position)
            .ok_or(XmlError::Truncated)?;
        decode_text(raw)
    }

    fn scan_name(&mut self) -> Result<&'a [u8], XmlError> {
        let start = self.position;
        while let Some(byte) = self.peek() {
            if is_name_byte(byte) {
                self.position = self.position.saturating_add(1);
            } else {
                break;
            }
        }
        let name = self
            .input
            .get(start..self.position)
            .ok_or(XmlError::Truncated)?;
        if name.is_empty() {
            return Err(XmlError::Malformed);
        }
        if name.len() > MAX_NAME {
            return Err(XmlError::TooLarge);
        }
        Ok(name)
    }

    fn scan_attribute_value(&mut self) -> Result<&'a [u8], XmlError> {
        let quote = self.peek().ok_or(XmlError::Truncated)?;
        if quote != b'"' && quote != b'\'' {
            return Err(XmlError::Malformed);
        }
        self.position = self.position.saturating_add(1);
        let start = self.position;
        while let Some(byte) = self.peek() {
            if byte == quote {
                let value = self
                    .input
                    .get(start..self.position)
                    .ok_or(XmlError::Truncated)?;
                self.position = self.position.saturating_add(1);
                if value.len() > MAX_TEXT {
                    return Err(XmlError::TooLarge);
                }
                return Ok(value);
            }
            if byte == b'<' {
                return Err(XmlError::Malformed);
            }
            self.position = self.position.saturating_add(1);
        }
        Err(XmlError::Truncated)
    }

    fn scan_start_tag(&mut self) -> Result<Event<'a>, XmlError> {
        self.position = self.position.saturating_add(1);
        let raw_name = self.scan_name()?;
        self.elements = self.elements.saturating_add(1);
        if self.elements > MAX_ELEMENTS {
            return Err(XmlError::TooMany);
        }
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_DEPTH {
            return Err(XmlError::TooDeep);
        }

        // Bindings declared on this element are visible to its own name, so
        // the attributes are scanned before the name is resolved.
        let mut attributes = 0_usize;
        let mut self_closing = false;
        loop {
            self.skip_whitespace();
            match self.peek().ok_or(XmlError::Truncated)? {
                b'>' => {
                    self.position = self.position.saturating_add(1);
                    break;
                }
                b'/' => {
                    self.position = self.position.saturating_add(1);
                    if self.peek() != Some(b'>') {
                        return Err(XmlError::Malformed);
                    }
                    self.position = self.position.saturating_add(1);
                    self_closing = true;
                    break;
                }
                _ => {}
            }
            attributes = attributes.saturating_add(1);
            if attributes > MAX_ATTRIBUTES {
                return Err(XmlError::TooMany);
            }
            let attribute = self.scan_name()?;
            self.skip_whitespace();
            if self.peek() != Some(b'=') {
                return Err(XmlError::Malformed);
            }
            self.position = self.position.saturating_add(1);
            self.skip_whitespace();
            let value = self.scan_attribute_value()?;
            let prefix: Option<&[u8]> = if attribute == b"xmlns" {
                Some(b"")
            } else if let Some(rest) = attribute.strip_prefix(b"xmlns:".as_slice()) {
                if rest.is_empty() {
                    return Err(XmlError::Malformed);
                }
                Some(rest)
            } else {
                None
            };
            if let Some(prefix) = prefix {
                if self.bindings.len() >= MAX_BINDINGS {
                    return Err(XmlError::TooMany);
                }
                self.bindings.push(Binding {
                    depth: self.depth,
                    prefix: prefix.to_vec(),
                    namespace: Namespace::from_uri(value),
                });
            }
        }

        let name = self.resolve(raw_name)?;
        if self_closing {
            self.close_scope();
            self.depth = self.depth.saturating_sub(1);
            if self.depth == 0 {
                self.root_done = true;
            }
            self.pending_end = Some(name);
        } else {
            if self.open.len() >= MAX_DEPTH {
                return Err(XmlError::TooDeep);
            }
            self.open.push(name);
        }
        Ok(Event::Start(name))
    }

    fn scan_end_tag(&mut self) -> Result<Event<'a>, XmlError> {
        self.position = self.position.saturating_add(2);
        let raw_name = self.scan_name()?;
        self.skip_whitespace();
        if self.peek() != Some(b'>') {
            return Err(XmlError::Malformed);
        }
        self.position = self.position.saturating_add(1);
        let name = self.resolve(raw_name)?;
        let expected = self.open.pop().ok_or(XmlError::Mismatched)?;
        if expected != name {
            return Err(XmlError::Mismatched);
        }
        self.close_scope();
        self.depth = self.depth.saturating_sub(1);
        if self.depth == 0 {
            self.root_done = true;
        }
        Ok(Event::End(name))
    }

    /// Resolves a namespace prefix against the bindings that are live right
    /// now.  Callers use it while an [`Event::Text`] is being handled, which
    /// is the only point at which a QName inside character data -- a
    /// `wsd:Types` token -- can be given a meaning.
    #[must_use]
    pub fn resolve_prefix(&self, prefix: &[u8]) -> Option<Namespace> {
        self.bindings
            .iter()
            .rev()
            .find(|binding| binding.prefix == prefix)
            .map(|binding| binding.namespace)
    }

    fn close_scope(&mut self) {
        let depth = self.depth;
        self.bindings.retain(|binding| binding.depth < depth);
    }

    fn resolve(&self, raw_name: &'a [u8]) -> Result<QName<'a>, XmlError> {
        let (prefix, local) = match position_of(raw_name, b':') {
            Some(index) => {
                let prefix = raw_name.get(..index).ok_or(XmlError::Malformed)?;
                let local = raw_name
                    .get(index.saturating_add(1)..)
                    .ok_or(XmlError::Malformed)?;
                if prefix.is_empty() || local.is_empty() || position_of(local, b':').is_some() {
                    return Err(XmlError::Malformed);
                }
                (prefix, local)
            }
            None => (b"".as_slice(), raw_name),
        };
        let namespace = self
            .bindings
            .iter()
            .rev()
            .find(|binding| binding.prefix == prefix)
            .map(|binding| binding.namespace);
        match namespace {
            Some(namespace) => Ok(QName { namespace, local }),
            None if prefix.is_empty() => Ok(QName {
                namespace: Namespace::None,
                local,
            }),
            None => Err(XmlError::UnboundPrefix),
        }
    }
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.')
}

fn position_of(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|byte| *byte == needle)
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

/// Decodes one run of character data.
///
/// Only the five predefined entities and printable-ASCII numeric character
/// references are implemented; everything else is [`XmlError::BadReference`],
/// which means no entity expansion can allocate more than the input does.
/// Tab, carriage return and line feed are the only control characters a run
/// may contain, because a pretty-printed envelope indents its elements; every
/// field accessor trims them and then applies its own stricter character set.
///
/// # Errors
/// [`XmlError::TooLarge`], [`XmlError::BadReference`] or [`XmlError::NotText`].
pub fn decode_text(raw: &[u8]) -> Result<String, XmlError> {
    if raw.len() > MAX_TEXT {
        return Err(XmlError::TooLarge);
    }
    let mut out = String::new();
    let mut index = 0_usize;
    while let Some(byte) = raw.get(index).copied() {
        if byte != b'&' {
            out.push(char::from(byte));
            index = index.saturating_add(1);
            continue;
        }
        let rest = raw.get(index..).ok_or(XmlError::Malformed)?;
        let end = position_of(rest, b';').ok_or(XmlError::BadReference)?;
        let reference = rest.get(1..end).ok_or(XmlError::BadReference)?;
        let decoded = decode_reference(reference)?;
        out.push(char::from(decoded));
        index = index
            .checked_add(end)
            .and_then(|value| value.checked_add(1))
            .ok_or(XmlError::Malformed)?;
    }
    // The raw bytes were pushed one at a time, so validate the result rather
    // than trusting the input: anything above ASCII or any control byte is a
    // refusal.  Every field this daemon reads is a URI or a QName list.
    if out
        .bytes()
        .any(|byte| !(0x20..0x7f).contains(&byte) && !matches!(byte, b'\t' | b'\r' | b'\n'))
    {
        return Err(XmlError::NotText);
    }
    Ok(out)
}

fn decode_reference(reference: &[u8]) -> Result<u8, XmlError> {
    match reference {
        b"amp" => return Ok(b'&'),
        b"lt" => return Ok(b'<'),
        b"gt" => return Ok(b'>'),
        b"quot" => return Ok(b'"'),
        b"apos" => return Ok(b'\''),
        _ => {}
    }
    let digits = reference
        .strip_prefix(b"#".as_slice())
        .ok_or(XmlError::BadReference)?;
    let (digits, radix) = match digits.strip_prefix(b"x".as_slice()) {
        Some(hex) => (hex, 16_u32),
        None => (digits, 10_u32),
    };
    if digits.is_empty() || digits.len() > 4 {
        return Err(XmlError::BadReference);
    }
    let mut value = 0_u32;
    for byte in digits {
        let digit = char::from(*byte)
            .to_digit(radix)
            .ok_or(XmlError::BadReference)?;
        value = value
            .checked_mul(radix)
            .and_then(|scaled| scaled.checked_add(digit))
            .ok_or(XmlError::BadReference)?;
    }
    if !(0x20..0x7f).contains(&value) {
        return Err(XmlError::BadReference);
    }
    u8::try_from(value).map_err(|_| XmlError::BadReference)
}

/// Escapes the five XML metacharacters.
///
/// Nothing this daemon emits actually needs it -- every value that reaches a
/// reply is validated to exclude these bytes first -- but the encoder calls it
/// anyway so a future field cannot silently become an injection point.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::new();
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(character),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(input: &str) -> Result<Vec<Event<'_>>, XmlError> {
        let mut scanner = Scanner::new(input.as_bytes())?;
        let mut out = Vec::new();
        while let Some(event) = scanner.next()? {
            out.push(event);
        }
        Ok(out)
    }

    #[test]
    fn resolves_a_prefix_declared_on_the_element_that_uses_it() {
        let document = "<s:E xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"/>";
        let events = events(document).expect("scan");
        assert_eq!(events.len(), 2);
        match events.first() {
            Some(Event::Start(name)) => assert!(name.is(Namespace::Soap12, "E")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn an_unbound_prefix_is_refused() {
        assert_eq!(events("<a:E/>"), Err(XmlError::UnboundPrefix));
    }

    #[test]
    fn a_foreign_namespace_never_becomes_a_known_one() {
        let document = "<s:E xmlns:s=\"http://example.invalid/\"/>";
        let events = events(document).expect("scan");
        match events.first() {
            Some(Event::Start(name)) => assert_eq!(name.namespace, Namespace::Foreign),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn doctypes_entities_cdata_and_comments_are_refused() {
        for document in [
            "<!DOCTYPE a><a/>",
            "<!ENTITY x \"y\"><a/>",
            "<a><![CDATA[x]]></a>",
            "<!-- hi --><a/>",
        ] {
            assert_eq!(events(document), Err(XmlError::Unsupported), "{document}");
        }
    }

    #[test]
    fn a_processing_instruction_after_the_start_is_refused() {
        assert_eq!(events("<a><?php ?></a>"), Err(XmlError::Unsupported));
    }

    #[test]
    fn nothing_may_follow_the_root_element() {
        // A second envelope, or any trailing bytes, behind a valid document.
        assert_eq!(events("<a/><b/>"), Err(XmlError::Malformed));
        assert_eq!(events("<a></a>junk"), Err(XmlError::Malformed));
        assert_eq!(events("<a/>\n  ").map(|events| events.len()), Ok(2));
    }

    #[test]
    fn depth_is_capped() {
        let mut document = String::new();
        for _ in 0..(MAX_DEPTH + 1) {
            document.push_str("<a>");
        }
        assert_eq!(events(&document), Err(XmlError::TooDeep));
    }

    #[test]
    fn element_count_is_capped() {
        let mut document = String::from("<r>");
        for _ in 0..(MAX_ELEMENTS + 1) {
            document.push_str("<a/>");
        }
        document.push_str("</r>");
        assert_eq!(events(&document), Err(XmlError::TooMany));
    }

    #[test]
    fn oversized_documents_are_refused_before_anything_is_scanned() {
        let document = vec![b'<'; MAX_DOCUMENT + 1];
        assert!(matches!(Scanner::new(&document), Err(XmlError::TooLong)));
    }

    #[test]
    fn mismatched_end_tags_are_refused() {
        assert_eq!(events("<a></b>"), Err(XmlError::Mismatched));
        assert_eq!(events("<a>"), Err(XmlError::Truncated));
        assert_eq!(events("</a>"), Err(XmlError::Mismatched));
    }

    #[test]
    fn only_the_predefined_and_printable_ascii_references_decode() {
        assert_eq!(decode_text(b"a&amp;b"), Ok(String::from("a&b")));
        assert_eq!(decode_text(b"&#65;"), Ok(String::from("A")));
        assert_eq!(decode_text(b"&#x41;"), Ok(String::from("A")));
        assert_eq!(decode_text(b"&#0;"), Err(XmlError::BadReference));
        assert_eq!(decode_text(b"&#xfffd;"), Err(XmlError::BadReference));
        assert_eq!(decode_text(b"&nbsp;"), Err(XmlError::BadReference));
        assert_eq!(decode_text(b"&amp"), Err(XmlError::BadReference));
    }

    #[test]
    fn non_ascii_and_control_bytes_are_refused_as_text() {
        assert_eq!(decode_text(b"caf\xc3\xa9"), Err(XmlError::NotText));
        assert_eq!(decode_text(b"a\x00b"), Err(XmlError::NotText));
        assert_eq!(decode_text(b"a\x7fb"), Err(XmlError::NotText));
        // Indentation is allowed through; the field accessors trim it.
        assert_eq!(decode_text(b"\n\ta\r\n"), Ok(String::from("\n\ta\r\n")));
    }

    #[test]
    fn text_longer_than_the_cap_is_refused() {
        let raw = vec![b'a'; MAX_TEXT + 1];
        assert_eq!(decode_text(&raw), Err(XmlError::TooLarge));
    }

    #[test]
    fn escaping_covers_every_metacharacter() {
        assert_eq!(escape("<&>\"'"), "&lt;&amp;&gt;&quot;&apos;");
    }

    #[test]
    fn no_input_panics_the_scanner() {
        // panic = "abort" makes any panic on this path a remote kill, so walk
        // a wide space of truncations and byte substitutions.
        let seed = b"<?xml version=\"1.0\"?><s:E xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:H><a b=\"c\"/>text&amp;</s:H></s:E>";
        for cut in 0..=seed.len() {
            let slice = seed.get(..cut).unwrap_or_default();
            let _ = events(&String::from_utf8_lossy(slice));
        }
        for index in 0..seed.len() {
            for replacement in [0_u8, b'<', b'>', b'&', b'"', b'/', b':', 0xff] {
                let mut mutated = seed.to_vec();
                if let Some(slot) = mutated.get_mut(index) {
                    *slot = replacement;
                }
                if let Ok(mut scanner) = Scanner::new(&mutated) {
                    while let Ok(Some(_)) = scanner.next() {}
                }
            }
        }
    }
}
