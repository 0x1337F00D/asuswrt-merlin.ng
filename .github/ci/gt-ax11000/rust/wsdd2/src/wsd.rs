//! WS-Discovery message handling.
//!
//! Wire shapes and constants are taken from the vendor implementation this
//! replaces, `release/src/router/wsdd2/wsd.c`; the specific lines are cited on
//! each item.  The parse direction is a complete rewrite: the vendor did no
//! structural validation at all (`wsd.c:353-420`), dispatched on the
//! `wsa:Action` string alone and never looked at the SOAP body, so a datagram
//! whose body said one thing and whose header said another was answered on the
//! header's word.

use crate::xml::{escape, Event, Namespace, QName, Scanner, XmlError};

/// The WS-Discovery UDP and HTTP port (`wsd.h:30`).
pub const WSD_PORT: u16 = 3702;
/// IPv4 discovery group (`wsd.h:32`).
pub const WSD_MCAST_V4: &str = "239.255.255.250";
/// IPv6 discovery group (`wsd.h:33`, lower-cased as `wsdd2.c:86`).
pub const WSD_MCAST_V6: &str = "ff02::c";

/// `WSD_ACT_HELLO` (`wsd.c:303`).
pub const ACT_HELLO: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello";
/// `WSD_ACT_BYE` (`wsd.c:305`).
pub const ACT_BYE: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye";
/// `WSD_ACT_PROBE` (`wsd.c:307`).
pub const ACT_PROBE: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
/// `WSD_ACT_PROBEMATCH` (`wsd.c:309`).
pub const ACT_PROBEMATCHES: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches";
/// `WSD_ACT_RESOLVE` (`wsd.c:311`).
pub const ACT_RESOLVE: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve";
/// `WSD_ACT_RESOLVEMATCH` (`wsd.c:313`).
pub const ACT_RESOLVEMATCHES: &str =
    "http://schemas.xmlsoap.org/ws/2005/04/discovery/ResolveMatches";
/// `WXT_ACT_GET` (`wsd.c:315`).
pub const ACT_GET: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get";
/// `WXT_ACT_GETRESPONSE` (`wsd.c:317`).
pub const ACT_GETRESPONSE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse";
/// `WSD_TO_DISCOVERY` (`wsd.c:319`).
pub const TO_DISCOVERY: &str = "urn:schemas-xmlsoap-org:ws:2005:04:discovery";
/// `WSD_TO_ANONYMOUS` (`wsd.c:321`).
pub const TO_ANONYMOUS: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";

/// Largest `wsa:MessageID` this daemon will echo back in a `wsa:RelatesTo`.
///
/// The message id is the one attacker-controlled string the protocol requires
/// a reply to carry, so it is both length-capped and character-restricted:
/// unreserved plus reserved RFC 3986 URI bytes, minus `&` and `'`, which means
/// escaping can never change its length and it can never open an element.
pub const MAX_MESSAGE_ID: usize = 128;

/// Hard cap on any generated message, in bytes.
///
/// Every reply is assembled from a fixed template plus a bounded message id, a
/// 36-character UUID and an address literal, so this is a backstop rather than
/// a working limit.  A build that somehow exceeded it is dropped rather than
/// sent.
pub const MAX_REPLY: usize = 4096;

/// Hard cap on a reply that leaves as a datagram, in bytes.
///
/// WS-Discovery cannot be made non-amplifying in the strict sense: a
/// conforming `ProbeMatches` carries five namespace declarations, an
/// `AppSequence`, an endpoint reference, a type list and an `XAddrs`, and is
/// larger than the smallest conforming `Probe` that may provoke it.  What is
/// guaranteed instead is that the amplification is *bounded and constant*:
///
/// * the reply is built from a fixed template whose only variable parts are
///   this device's own UUIDs, its own address literal and the echoed message
///   id, which is itself capped at [`MAX_MESSAGE_ID`].  Nothing else the
///   sender writes reaches the reply, so the reply length does not grow with
///   the request length -- a padded request produces a byte-identical reply;
/// * the total never exceeds this cap, so one datagram in can never produce
///   more than one un-fragmented datagram out;
/// * only five prefixes are declared, where the vendor declared seven in
///   every message (`wsd.c:551-558`), which is ~200 bytes less per reply;
/// * a reply is emitted only for a fully validated request whose source
///   address routes back through the bound LAN interface, and only while the
///   per-second budget lasts.
pub const MAX_DATAGRAM_REPLY: usize = 1400;

/// What the sender asked for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Body {
    /// `wsd:Probe`.
    Probe {
        /// True when the probe carried a `wsd:Types` element at all.
        types_present: bool,
        /// True when one of the types named is `wsdp:Device` or
        /// `pub:Computer`, the two this device publishes (`wsd.c:660`).
        types_matched: bool,
    },
    /// `wsd:Resolve`, carrying the endpoint reference address it asks about.
    Resolve {
        /// Text of `wsd:Resolve/wsa:EndpointReference/wsa:Address`.
        address: String,
    },
    /// `wxt:Get`, the metadata request that arrives over HTTP.
    Get,
}

/// A validated WS-Discovery request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// The `wsa:MessageID`, validated and safe to echo verbatim.
    pub message_id: String,
    /// The `wsa:To`, validated against the shape the action requires.
    pub to: String,
    /// The body element and its contents.
    pub body: Body,
}

/// Why a datagram produced no reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The document did not survive the scanner.
    Xml(XmlError),
    /// The root element is not `soap:Envelope` in the SOAP 1.2 namespace.
    NotAnEnvelope,
    /// `soap:Header` and `soap:Body` are not both present exactly once, in
    /// that order, as the only children of the envelope.
    BadEnvelope,
    /// `soap:Body` does not hold exactly one element.
    BadBody,
    /// The body element is not `wsd:Probe`, `wsd:Resolve` or `wxt:Get`.
    UnsupportedBody,
    /// `wsa:Action` is missing.
    NoAction,
    /// `wsa:Action` names a message this daemon does not answer.  `Hello`,
    /// `Bye`, `ProbeMatches` and `ResolveMatches` land here: the vendor
    /// decoded them and then fell through its switch (`wsd.c:1141`).
    UnsupportedAction,
    /// `wsa:Action` and the body element disagree.
    ActionBodyMismatch,
    /// `wsa:MessageID` is missing.
    NoMessageId,
    /// `wsa:MessageID` is too long or holds a byte outside the safe set.
    BadMessageId,
    /// `wsa:To` is missing or is not the value the action requires.
    BadTo,
    /// `wsd:Resolve` carries no endpoint reference address.
    NoResolveAddress,
    /// The same field appeared twice.
    Duplicate,
    /// A field element contained a child element instead of text.
    NotAField,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Xml(error) => write!(formatter, "{error}"),
            Self::NotAnEnvelope => formatter.write_str("not a SOAP 1.2 envelope"),
            Self::BadEnvelope => formatter.write_str("envelope is not Header then Body"),
            Self::BadBody => formatter.write_str("body does not hold exactly one element"),
            Self::UnsupportedBody => formatter.write_str("unsupported body element"),
            Self::NoAction => formatter.write_str("no wsa:Action"),
            Self::UnsupportedAction => formatter.write_str("unsupported wsa:Action"),
            Self::ActionBodyMismatch => formatter.write_str("wsa:Action does not match the body"),
            Self::NoMessageId => formatter.write_str("no wsa:MessageID"),
            Self::BadMessageId => formatter.write_str("unusable wsa:MessageID"),
            Self::BadTo => formatter.write_str("missing or wrong wsa:To"),
            Self::NoResolveAddress => formatter.write_str("resolve carries no address"),
            Self::Duplicate => formatter.write_str("duplicate header field"),
            Self::NotAField => formatter.write_str("header field holds an element"),
        }
    }
}

impl From<XmlError> for Refusal {
    fn from(error: XmlError) -> Self {
        Self::Xml(error)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum BodyKind {
    Probe,
    Resolve,
    Get,
}

impl Request {
    /// Parses and validates one WS-Discovery request.
    ///
    /// Nothing is trusted: the envelope shape, the action, the body element,
    /// the agreement between action and body, the `wsa:To` and the character
    /// set of the message id are all checked before a `Request` exists.
    ///
    /// # Errors
    /// The first [`Refusal`] that applies.  A refusal always means "send
    /// nothing": there is no fault reply on the datagram path.
    pub fn parse(document: &[u8]) -> Result<Self, Refusal> {
        let mut scanner = Scanner::new(document)?;
        let mut path: Vec<QName<'_>> = Vec::new();
        let mut action: Option<String> = None;
        let mut message_id: Option<String> = None;
        let mut to: Option<String> = None;
        let mut body_kind: Option<BodyKind> = None;
        let mut body_elements = 0_usize;
        let mut resolve_address: Option<String> = None;
        let mut types_present = false;
        let mut types_matched = false;
        let mut header_seen = false;
        let mut body_seen = false;

        while let Some(event) = scanner.next()? {
            match event {
                Event::Start(name) => {
                    match path.len() {
                        0 => {
                            if !name.is(Namespace::Soap12, "Envelope") {
                                return Err(Refusal::NotAnEnvelope);
                            }
                        }
                        1 => {
                            if name.is(Namespace::Soap12, "Header") {
                                if header_seen || body_seen {
                                    return Err(Refusal::BadEnvelope);
                                }
                                header_seen = true;
                            } else if name.is(Namespace::Soap12, "Body") {
                                if !header_seen || body_seen {
                                    return Err(Refusal::BadEnvelope);
                                }
                                body_seen = true;
                            } else {
                                return Err(Refusal::BadEnvelope);
                            }
                        }
                        2 if body_seen && in_body(&path) => {
                            body_elements = body_elements.saturating_add(1);
                            if body_elements > 1 {
                                return Err(Refusal::BadBody);
                            }
                            body_kind = Some(if name.is(Namespace::Discovery, "Probe") {
                                BodyKind::Probe
                            } else if name.is(Namespace::Discovery, "Resolve") {
                                BodyKind::Resolve
                            } else if name.is(Namespace::Transfer, "Get") {
                                BodyKind::Get
                            } else {
                                return Err(Refusal::UnsupportedBody);
                            });
                        }
                        _ => {
                            // An empty `wsd:Types` still means "these are the
                            // types I want", so presence is recorded on the
                            // element, not on its text.
                            if body_kind == Some(BodyKind::Probe)
                                && is_probe_types_child(&path, name)
                            {
                                types_present = true;
                            }
                        }
                    }
                    path.push(name);
                }
                Event::End(_) => {
                    path.pop();
                }
                Event::Text(text) => {
                    let trimmed = text.trim();
                    if in_header_field(&path, Namespace::Addressing, "Action") {
                        assign(&mut action, trimmed)?;
                    } else if in_header_field(&path, Namespace::Addressing, "MessageID") {
                        assign(&mut message_id, trimmed)?;
                    } else if in_header_field(&path, Namespace::Addressing, "To") {
                        assign(&mut to, trimmed)?;
                    } else if body_kind == Some(BodyKind::Probe) && is_probe_types(&path) {
                        for token in trimmed.split_ascii_whitespace() {
                            if type_is_ours(&scanner, token) {
                                types_matched = true;
                            }
                        }
                    } else if body_kind == Some(BodyKind::Resolve) && is_resolve_address(&path) {
                        assign(&mut resolve_address, trimmed)?;
                    }
                }
            }
        }

        if !header_seen || !body_seen {
            return Err(Refusal::BadEnvelope);
        }
        let kind = body_kind.ok_or(Refusal::BadBody)?;
        let action = action.ok_or(Refusal::NoAction)?;
        let expected_action = match kind {
            BodyKind::Probe => ACT_PROBE,
            BodyKind::Resolve => ACT_RESOLVE,
            BodyKind::Get => ACT_GET,
        };
        if action != expected_action {
            return Err(if is_known_action(&action) {
                Refusal::ActionBodyMismatch
            } else {
                Refusal::UnsupportedAction
            });
        }
        let raw_message_id = message_id.ok_or(Refusal::NoMessageId)?;
        let message_id = validate_message_id(&raw_message_id).ok_or(Refusal::BadMessageId)?;
        let to = to.ok_or(Refusal::BadTo)?;
        match kind {
            BodyKind::Probe | BodyKind::Resolve => {
                if to != TO_DISCOVERY {
                    return Err(Refusal::BadTo);
                }
            }
            BodyKind::Get => {
                // The transport, not this function, knows the endpoint UUID a
                // Get must be addressed to; it is checked there against the
                // request line of the HTTP POST that carried this body.
                if !to.starts_with("urn:uuid:") {
                    return Err(Refusal::BadTo);
                }
            }
        }

        let body = match kind {
            BodyKind::Probe => Body::Probe {
                types_present,
                types_matched,
            },
            BodyKind::Resolve => Body::Resolve {
                address: resolve_address.ok_or(Refusal::NoResolveAddress)?,
            },
            BodyKind::Get => Body::Get,
        };
        Ok(Self {
            message_id,
            to,
            body,
        })
    }
}

fn assign(slot: &mut Option<String>, value: &str) -> Result<(), Refusal> {
    if slot.is_some() {
        return Err(Refusal::Duplicate);
    }
    *slot = Some(value.to_owned());
    Ok(())
}

fn in_body(path: &[QName<'_>]) -> bool {
    matches!(path.get(1), Some(name) if name.is(Namespace::Soap12, "Body"))
}

fn in_header_field(path: &[QName<'_>], namespace: Namespace, local: &str) -> bool {
    path.len() == 3
        && matches!(path.first(), Some(name) if name.is(Namespace::Soap12, "Envelope"))
        && matches!(path.get(1), Some(name) if name.is(Namespace::Soap12, "Header"))
        && matches!(path.get(2), Some(name) if name.is(namespace, local))
}

fn is_probe_types_child(path: &[QName<'_>], name: QName<'_>) -> bool {
    path.len() == 3
        && in_body(path)
        && matches!(path.get(2), Some(parent) if parent.is(Namespace::Discovery, "Probe"))
        && name.is(Namespace::Discovery, "Types")
}

fn is_probe_types(path: &[QName<'_>]) -> bool {
    path.len() == 4
        && in_body(path)
        && matches!(path.get(2), Some(name) if name.is(Namespace::Discovery, "Probe"))
        && matches!(path.get(3), Some(name) if name.is(Namespace::Discovery, "Types"))
}

fn is_resolve_address(path: &[QName<'_>]) -> bool {
    path.len() == 5
        && in_body(path)
        && matches!(path.get(2), Some(name) if name.is(Namespace::Discovery, "Resolve"))
        && matches!(path.get(3), Some(name) if name.is(Namespace::Addressing, "EndpointReference"))
        && matches!(path.get(4), Some(name) if name.is(Namespace::Addressing, "Address"))
}

/// Resolves one `wsd:Types` QName token against the bindings that are live at
/// the point the text was read, and reports whether it names a type this
/// device publishes.
fn type_is_ours(scanner: &Scanner<'_>, token: &str) -> bool {
    let (prefix, local) = match token.split_once(':') {
        Some((prefix, local)) => (prefix, local),
        None => ("", token),
    };
    if local.is_empty() {
        return false;
    }
    match scanner.resolve_prefix(prefix.as_bytes()) {
        Some(Namespace::DeviceProfile) => local == "Device",
        Some(Namespace::Publication) => local == "Computer",
        _ => false,
    }
}

fn is_known_action(action: &str) -> bool {
    matches!(
        action,
        ACT_HELLO
            | ACT_BYE
            | ACT_PROBE
            | ACT_PROBEMATCHES
            | ACT_RESOLVE
            | ACT_RESOLVEMATCHES
            | ACT_GET
            | ACT_GETRESPONSE
    )
}

/// Accepts a message id only if it is short and made of URI bytes that carry
/// no XML meaning, so echoing it into `wsa:RelatesTo` cannot change the shape
/// of the reply.
#[must_use]
pub fn validate_message_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_MESSAGE_ID {
        return None;
    }
    let safe = trimmed.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b':'
                    | b'/'
                    | b'?'
                    | b'#'
                    | b'['
                    | b']'
                    | b'@'
                    | b'!'
                    | b'$'
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
            )
    });
    if safe {
        Some(trimmed.to_owned())
    } else {
        None
    }
}

/// Everything a reply needs to know about this device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    /// Stable endpoint UUID, 36 lower-case characters (`wsd.c:126`).
    pub endpoint: String,
    /// Per-run sequence UUID (`wsd.c:1006`).
    pub sequence: String,
    /// `InstanceId`, the start time in seconds (`wsd.c:1004`).
    pub instance: u64,
    /// NetBIOS name published in the metadata (`wsd.c:888`).
    pub netbios_name: String,
    /// Workgroup published in the metadata (`wsd.c:889`).
    pub workgroup: String,
    /// `-b` boot information (`wsd.c:180-193`).
    pub boot: BootInfo,
}

/// The `-b key:value` set, with the ASUSWRT defaults from `wsd.c:180-192`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootInfo {
    /// `vendor:`, default `ASUS`.
    pub vendor: String,
    /// `model:`, default `Asuswrt-Merlin`.
    pub model: String,
    /// `serial:`, default `0`.
    pub serial: String,
    /// `sku:`, default `Asus router`.
    pub sku: String,
    /// `vendorurl:`, default `https://www.asus.com`.
    pub vendor_url: String,
    /// `modelurl:`, default `https://www.asuswrt-merlin.net`.
    pub model_url: String,
    /// `presentationurl:`, default `http://router.asus.com`.
    pub presentation_url: String,
}

impl Default for BootInfo {
    fn default() -> Self {
        Self {
            vendor: String::from("ASUS"),
            model: String::from("Asuswrt-Merlin"),
            serial: String::from("0"),
            sku: String::from("Asus router"),
            vendor_url: String::from("https://www.asus.com"),
            model_url: String::from("https://www.asuswrt-merlin.net"),
            presentation_url: String::from("http://router.asus.com"),
        }
    }
}

/// A running message counter; `MessageNumber` in `wsd:AppSequence`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MessageCounter(u32);

impl MessageCounter {
    /// The number the next emitted message will carry.
    ///
    /// A message is built before the reply budget is consulted, so the
    /// counter is only advanced once a message is actually sent: a dropped
    /// reply must not leave a hole in the sequence a client checks.
    #[must_use]
    pub const fn peek(&self) -> u32 {
        self.0.saturating_add(1)
    }

    /// Records that a message was sent, saturating instead of wrapping.  The
    /// vendor used `++msg_no` on an `unsigned int` (`wsd.c:601`).
    pub fn advance(&mut self) -> u32 {
        self.0 = self.0.saturating_add(1);
        self.0
    }
}

/// Namespace prefixes a message may declare.  Only the ones a message uses
/// are emitted, which is the difference between this encoder and the vendor's
/// single seven-prefix template (`wsd.c:551-558`).
const DECL_SOAP: &str = " xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"";
const DECL_WSA: &str = " xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"";
const DECL_WSD: &str = " xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"";
const DECL_WSX: &str = " xmlns:wsx=\"http://schemas.xmlsoap.org/ws/2004/09/mex\"";
const DECL_WSDP: &str = " xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\"";
const DECL_UN0: &str = " xmlns:un0=\"http://schemas.microsoft.com/windows/pnpx/2005/10\"";
const DECL_PUB: &str = " xmlns:pub=\"http://schemas.microsoft.com/windows/pub/2005/07\"";

/// The parts of one outgoing envelope.
struct Envelope<'a> {
    declarations: &'a [&'a str],
    to: &'a str,
    action: &'a str,
    message_id: &'a str,
    identity: &'a Identity,
    number: u32,
    relates_to: Option<&'a str>,
    body: &'a str,
}

fn envelope(parts: &Envelope<'_>) -> Option<String> {
    let Envelope {
        declarations,
        to,
        action,
        message_id,
        identity,
        number,
        relates_to,
        body,
    } = *parts;
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope");
    for declaration in declarations {
        out.push_str(declaration);
    }
    out.push_str("><soap:Header><wsa:To>");
    out.push_str(to);
    out.push_str("</wsa:To><wsa:Action>");
    out.push_str(action);
    out.push_str("</wsa:Action><wsa:MessageID>urn:uuid:");
    out.push_str(message_id);
    out.push_str("</wsa:MessageID><wsd:AppSequence InstanceId=\"");
    out.push_str(&identity.instance.to_string());
    out.push_str("\" SequenceId=\"urn:uuid:");
    out.push_str(&identity.sequence);
    out.push_str("\" MessageNumber=\"");
    out.push_str(&number.to_string());
    out.push_str("\" />");
    if let Some(relates_to) = relates_to {
        out.push_str("<wsa:RelatesTo>");
        out.push_str(&escape(relates_to));
        out.push_str("</wsa:RelatesTo>");
    }
    out.push_str("</soap:Header>");
    out.push_str(body);
    out.push_str("</soap:Envelope>");
    if out.len() > MAX_REPLY {
        return None;
    }
    Some(out)
}

fn announcement_body(element: &str, endpoint: &str) -> String {
    let mut body = String::from("<soap:Body><wsd:");
    body.push_str(element);
    body.push_str("><wsa:EndpointReference><wsa:Address>urn:uuid:");
    body.push_str(endpoint);
    body.push_str("</wsa:Address></wsa:EndpointReference><wsd:Types>wsdp:Device pub:Computer</wsd:Types><wsd:MetadataVersion>2</wsd:MetadataVersion></wsd:");
    body.push_str(element);
    body.push_str("></soap:Body>");
    body
}

fn match_body(element: &str, identity: &Identity, host: &str, port: u16) -> String {
    let plural = format!("{element}es");
    let mut body = String::from("<soap:Body><wsd:");
    body.push_str(&plural);
    body.push_str("><wsd:");
    body.push_str(element);
    body.push_str("><wsa:EndpointReference><wsa:Address>urn:uuid:");
    body.push_str(&identity.endpoint);
    body.push_str("</wsa:Address></wsa:EndpointReference><wsd:Types>wsdp:Device pub:Computer</wsd:Types><wsd:XAddrs>http://");
    body.push_str(&escape(host));
    body.push(':');
    body.push_str(&port.to_string());
    body.push('/');
    body.push_str(&identity.endpoint);
    body.push_str("</wsd:XAddrs><wsd:MetadataVersion>2</wsd:MetadataVersion></wsd:");
    body.push_str(element);
    body.push_str("></wsd:");
    body.push_str(&plural);
    body.push_str("></soap:Body>");
    body
}

/// Builds the multicast `Hello` sent when a socket opens (`wsd.c:625-649`).
#[must_use]
pub fn hello(identity: &Identity, message_id: &str, number: u32) -> Option<String> {
    envelope(&Envelope {
        declarations: &[DECL_SOAP, DECL_WSA, DECL_WSD, DECL_WSDP, DECL_PUB],
        to: TO_DISCOVERY,
        action: ACT_HELLO,
        message_id,
        identity,
        number,
        relates_to: None,
        body: &announcement_body("Hello", &identity.endpoint),
    })
    .filter(|message| message.len() <= MAX_DATAGRAM_REPLY)
}

/// Builds the multicast `Bye` sent when a socket closes (`wsd.c:651-675`).
#[must_use]
pub fn bye(identity: &Identity, message_id: &str, number: u32) -> Option<String> {
    envelope(&Envelope {
        declarations: &[DECL_SOAP, DECL_WSA, DECL_WSD, DECL_WSDP, DECL_PUB],
        to: TO_DISCOVERY,
        action: ACT_BYE,
        message_id,
        identity,
        number,
        relates_to: None,
        body: &announcement_body("Bye", &identity.endpoint),
    })
    .filter(|message| message.len() <= MAX_DATAGRAM_REPLY)
}

/// Builds the unicast `ProbeMatches` answer (`wsd.c:677-710`).
#[must_use]
pub fn probe_matches(
    identity: &Identity,
    message_id: &str,
    number: u32,
    relates_to: &str,
    host: &str,
    port: u16,
) -> Option<String> {
    envelope(&Envelope {
        declarations: &[DECL_SOAP, DECL_WSA, DECL_WSD, DECL_WSDP, DECL_PUB],
        to: TO_ANONYMOUS,
        action: ACT_PROBEMATCHES,
        message_id,
        identity,
        number,
        relates_to: Some(relates_to),
        body: &match_body("ProbeMatch", identity, host, port),
    })
    .filter(|message| message.len() <= MAX_DATAGRAM_REPLY)
}

/// Builds the unicast `ResolveMatches` answer (`wsd.c:712-745`).
#[must_use]
pub fn resolve_matches(
    identity: &Identity,
    message_id: &str,
    number: u32,
    relates_to: &str,
    host: &str,
    port: u16,
) -> Option<String> {
    envelope(&Envelope {
        declarations: &[DECL_SOAP, DECL_WSA, DECL_WSD, DECL_WSDP, DECL_PUB],
        to: TO_ANONYMOUS,
        action: ACT_RESOLVEMATCHES,
        message_id,
        identity,
        number,
        relates_to: Some(relates_to),
        body: &match_body("ResolveMatch", identity, host, port),
    })
    .filter(|message| message.len() <= MAX_DATAGRAM_REPLY)
}

/// Builds the WS-Transfer `GetResponse` metadata document (`wsd.c:828-903`).
///
/// Every interpolated value is escaped: the `-b` boot information and the
/// NetBIOS name and workgroup come from the command line and `/etc/smb.conf`,
/// which are local, but they are not this daemon's own constants.
#[must_use]
pub fn get_response(
    identity: &Identity,
    message_id: &str,
    number: u32,
    relates_to: &str,
) -> Option<String> {
    let boot = &identity.boot;
    let mut body = String::from(
        "<soap:Body><wsx:Metadata><wsx:MetadataSection Dialect=\"http://schemas.xmlsoap.org/ws/2006/02/devprof/ThisDevice\"><wsdp:ThisDevice><wsdp:FriendlyName>Microsoft Publication Service Device Host</wsdp:FriendlyName><wsdp:FirmwareVersion>1.0</wsdp:FirmwareVersion><wsdp:SerialNumber>20050718</wsdp:SerialNumber></wsdp:ThisDevice></wsx:MetadataSection><wsx:MetadataSection Dialect=\"http://schemas.xmlsoap.org/ws/2006/02/devprof/ThisModel\"><wsdp:ThisModel><wsdp:Manufacturer>",
    );
    body.push_str(&escape(&boot.vendor));
    body.push_str("</wsdp:Manufacturer><wsdp:ManufacturerUrl>");
    body.push_str(&escape(&boot.vendor_url));
    body.push_str("</wsdp:ManufacturerUrl><wsdp:ModelName>");
    body.push_str(&escape(&boot.model));
    body.push_str("</wsdp:ModelName><wsdp:ModelNumber>1</wsdp:ModelNumber><wsdp:ModelUrl>");
    body.push_str(&escape(&boot.model_url));
    body.push_str("</wsdp:ModelUrl><wsdp:PresentationUrl>");
    body.push_str(&escape(&boot.presentation_url));
    body.push_str("</wsdp:PresentationUrl><un0:DeviceCategory>Computers</un0:DeviceCategory></wsdp:ThisModel></wsx:MetadataSection><wsx:MetadataSection Dialect=\"http://schemas.xmlsoap.org/ws/2006/02/devprof/Relationship\"><wsdp:Relationship Type=\"http://schemas.xmlsoap.org/ws/2006/02/devprof/host\"><wsdp:Host><wsa:EndpointReference><wsa:Address>urn:uuid:");
    body.push_str(&identity.endpoint);
    body.push_str("</wsa:Address></wsa:EndpointReference><wsdp:Types>pub:Computer</wsdp:Types><wsdp:ServiceId>urn:uuid:");
    body.push_str(&identity.endpoint);
    body.push_str("</wsdp:ServiceId><pub:Computer>");
    body.push_str(&escape(&identity.netbios_name));
    body.push_str("/Workgroup:");
    body.push_str(&escape(&identity.workgroup));
    body.push_str("</pub:Computer></wsdp:Host></wsdp:Relationship></wsx:MetadataSection></wsx:Metadata></soap:Body>");
    envelope(&Envelope {
        declarations: &[
            DECL_SOAP, DECL_WSA, DECL_WSD, DECL_WSX, DECL_WSDP, DECL_UN0, DECL_PUB,
        ],
        to: TO_ANONYMOUS,
        action: ACT_GETRESPONSE,
        message_id,
        identity,
        number,
        relates_to: Some(relates_to),
        body: &body,
    })
}
