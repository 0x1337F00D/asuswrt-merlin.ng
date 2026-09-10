//! Link-Local Multicast Name Resolution (RFC 4795) query handling.
//!
//! The vendor implementation is `release/src/router/wsdd2/llmnr.c`.  Its
//! header checks (`llmnr.c:118-166`) are reproduced exactly; its label loop
//! (`llmnr.c:169-193`) is not, because that loop walks `in_name_p` with no
//! bound against `inlen` at all -- `while (*in_name_p > 0)` reads past the end
//! of a datagram whose question section is not NUL-terminated, and
//! `in_name_p[1] .. in_name_p[4]` (`llmnr.c:205, 213`) then read four more
//! bytes past wherever that stopped.  A 13-byte datagram is enough to reach
//! both.  Here the whole question is parsed inside the received slice.
//!
//! The response is *rebuilt* from the parsed question rather than copied from
//! the request (`llmnr.c:275-277` does `calloc(inlen + answer_len)` and
//! `memcpy(out, in, inlen)`).  That copy is the vendor's amplifier: a 9 KiB
//! datagram whose first question is one valid label is echoed back in full,
//! plus an answer.  Rebuilding makes the reply a function of the question
//! alone, so trailing padding can never be reflected.

/// LLMNR service port (`wsdd2.c:112`).
pub const LLMNR_PORT: u16 = 5355;
/// IPv4 LLMNR group (`wsdd2.c:113`).
pub const LLMNR_MCAST_V4: &str = "224.0.0.252";
/// IPv6 LLMNR group (`wsdd2.c:124`).
pub const LLMNR_MCAST_V6: &str = "ff02::1:3";

/// `DNS_TYPE_A` (`llmnr.c:60`).
pub const TYPE_A: u16 = 0x0001;
/// `DNS_TYPE_AAAA` (`llmnr.c:61`).
pub const TYPE_AAAA: u16 = 0x001c;
/// `DNS_TYPE_ANY` (`llmnr.c:59`).
pub const TYPE_ANY: u16 = 0x00ff;
/// `DNS_CLASS_IN` (`llmnr.c:62`).
pub const CLASS_IN: u16 = 0x0001;

/// Fixed DNS header length.
pub const HEADER_LEN: usize = 12;
/// Longest encoded name, RFC 1035 section 2.3.4.
pub const MAX_NAME_WIRE: usize = 255;
/// Longest single label, RFC 1035 section 2.3.4.
pub const MAX_LABEL: usize = 63;
/// Answer record length for an A record: pointer, type, class, TTL, RDLENGTH
/// and four bytes of address (`llmnr.c:262-268`).
pub const ANSWER_LEN_A: usize = 12 + 4;
/// Answer record length for a AAAA record.
pub const ANSWER_LEN_AAAA: usize = 12 + 16;
/// Largest datagram this daemon will look at.
///
/// The vendor used a 9,217-byte buffer (`llmnr.c:396`, "Ethernet jumbo frame
/// size").  A query can never legitimately exceed a header plus one
/// 255-byte question, so anything larger is refused before it is parsed.
pub const MAX_QUERY: usize = HEADER_LEN + MAX_NAME_WIRE + 4;
/// RR TTL published in an answer, RFC 4795 section 2.8 (`llmnr.c:257`).
pub const ANSWER_TTL: u32 = 30;

/// Why a datagram produced no reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Shorter than a header plus one byte (`llmnr.c:124`), or longer than
    /// [`MAX_QUERY`].
    BadLength,
    /// `QR` set or a non-zero opcode (`llmnr.c:134`).
    NotAQuery,
    /// The conflict bit is set (`llmnr.c:140`).
    ConflictBit,
    /// The truncation bit is set (`llmnr.c:146`).
    TruncationBit,
    /// `QDCOUNT` is not exactly one (`llmnr.c:155`).
    BadQuestionCount,
    /// `ANCOUNT` or `NSCOUNT` is non-zero (`llmnr.c:167`).
    NotEmpty,
    /// A compression pointer appeared; RFC 4795 forbids one in a query and
    /// the vendor refused it too (`llmnr.c:176`).
    Compressed,
    /// A label length or the total name exceeds its RFC 1035 cap.
    NameTooLong,
    /// The question section runs off the end of the datagram.
    Truncated,
    /// A label byte is not a printable, non-dot ASCII character.
    NotAName,
    /// `QTYPE` is not A, AAAA or ANY (`llmnr.c:207`).
    BadType,
    /// `QCLASS` is not IN (`llmnr.c:214`).
    BadClass,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::BadLength => "datagram length is outside the legal range",
            Self::NotAQuery => "not a standard query",
            Self::ConflictBit => "conflict bit set in query",
            Self::TruncationBit => "truncation bit set in query",
            Self::BadQuestionCount => "exactly one question is required",
            Self::NotEmpty => "answer or authority records present in a query",
            Self::Compressed => "message compression is not supported",
            Self::NameTooLong => "name or label exceeds its cap",
            Self::Truncated => "question section runs past the datagram",
            Self::NotAName => "label holds a byte that is not a name character",
            Self::BadType => "record type is not ANY, A or AAAA",
            Self::BadClass => "record class is not IN",
        };
        formatter.write_str(text)
    }
}

/// A validated LLMNR query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query {
    /// Transaction ID.  The protocol requires it to be echoed, and it is the
    /// only byte pair of the request that reaches the reply unexamined.
    pub id: u16,
    /// The encoded question name, labels included, terminating NUL excluded.
    /// It is re-emitted verbatim, which is safe because every byte was
    /// validated as a name character.
    pub name_wire: Vec<u8>,
    /// The dotted, lower-cased name, for the authority check.
    pub name: String,
    /// `QTYPE`.
    pub qtype: u16,
    /// `QCLASS`, always [`CLASS_IN`].
    pub qclass: u16,
}

impl Query {
    /// Parses one LLMNR query.
    ///
    /// # Errors
    /// The first [`Refusal`] that applies.
    pub fn parse(datagram: &[u8]) -> Result<Self, Refusal> {
        if datagram.len() <= HEADER_LEN || datagram.len() > MAX_QUERY {
            return Err(Refusal::BadLength);
        }
        let flags = *datagram.get(2).ok_or(Refusal::BadLength)?;
        if flags & 0xf8 != 0 {
            return Err(Refusal::NotAQuery);
        }
        if flags & 0x04 != 0 {
            return Err(Refusal::ConflictBit);
        }
        if flags & 0x02 != 0 {
            return Err(Refusal::TruncationBit);
        }
        if be16(datagram, 4)? != 1 {
            return Err(Refusal::BadQuestionCount);
        }
        if be16(datagram, 6)? != 0 || be16(datagram, 8)? != 0 {
            return Err(Refusal::NotEmpty);
        }

        let mut cursor = HEADER_LEN;
        let mut name = String::new();
        let mut wire_len = 0_usize;
        loop {
            let length = *datagram.get(cursor).ok_or(Refusal::Truncated)?;
            if length >= 0xc0 {
                return Err(Refusal::Compressed);
            }
            if length as usize > MAX_LABEL {
                return Err(Refusal::NameTooLong);
            }
            cursor = cursor.checked_add(1).ok_or(Refusal::Truncated)?;
            if length == 0 {
                break;
            }
            let end = cursor
                .checked_add(usize::from(length))
                .ok_or(Refusal::Truncated)?;
            let label = datagram.get(cursor..end).ok_or(Refusal::Truncated)?;
            for byte in label {
                // A label may not carry a dot (it would change the name once
                // joined), a control byte, or anything outside ASCII.
                if !(0x21..0x7f).contains(byte) || *byte == b'.' {
                    return Err(Refusal::NotAName);
                }
            }
            wire_len = wire_len
                .checked_add(usize::from(length))
                .and_then(|value| value.checked_add(1))
                .ok_or(Refusal::NameTooLong)?;
            if wire_len.saturating_add(1) > MAX_NAME_WIRE {
                return Err(Refusal::NameTooLong);
            }
            if !name.is_empty() {
                name.push('.');
            }
            for byte in label {
                name.push(char::from(byte.to_ascii_lowercase()));
            }
            cursor = end;
        }

        let name_wire = datagram
            .get(HEADER_LEN..cursor.saturating_sub(1))
            .ok_or(Refusal::Truncated)?
            .to_vec();
        let qtype = be16(datagram, cursor)?;
        let qclass = be16(datagram, cursor.checked_add(2).ok_or(Refusal::Truncated)?)?;
        if qtype != TYPE_ANY && qtype != TYPE_A && qtype != TYPE_AAAA {
            return Err(Refusal::BadType);
        }
        if qclass != CLASS_IN {
            return Err(Refusal::BadClass);
        }
        Ok(Self {
            id: be16(datagram, 0)?,
            name_wire,
            name,
            qtype,
            qclass,
        })
    }

    /// Length of the question section as it will be re-emitted.
    #[must_use]
    pub fn question_len(&self) -> usize {
        self.name_wire.len().saturating_add(5)
    }
}

fn be16(datagram: &[u8], offset: usize) -> Result<u16, Refusal> {
    let high = *datagram.get(offset).ok_or(Refusal::Truncated)?;
    let low = *datagram
        .get(offset.checked_add(1).ok_or(Refusal::Truncated)?)
        .ok_or(Refusal::Truncated)?;
    Ok((u16::from(high) << 8) | u16::from(low))
}

/// The address a reply may carry, or `None` for a reply with no answer.
///
/// RFC 4795 section 2.3: a responder answers a query for a record type it
/// cannot supply on this transport with an empty answer section rather than
/// with silence, which is what the vendor did too (`llmnr.c:243-246`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Answer {
    /// No record: the query asked for a family this transport cannot answer.
    None,
    /// An `A` record.
    V4([u8; 4]),
    /// A `AAAA` record.
    V6([u8; 16]),
}

/// Chooses the answer for a query that arrived over `is_v6`, mirroring
/// `llmnr.c:239-253`: a mismatch between the asked-for family and the
/// transport family yields an empty answer section.
#[must_use]
pub fn choose_answer(qtype: u16, v4: Option<[u8; 4]>, v6: Option<[u8; 16]>, is_v6: bool) -> Answer {
    if is_v6 {
        if qtype == TYPE_A {
            return Answer::None;
        }
        match v6 {
            Some(address) => Answer::V6(address),
            None => Answer::None,
        }
    } else {
        if qtype == TYPE_AAAA {
            return Answer::None;
        }
        match v4 {
            Some(address) => Answer::V4(address),
            None => Answer::None,
        }
    }
}

/// Builds the response for a parsed query.
///
/// The output is `header || question || answer?` and nothing else: no part of
/// the request beyond the transaction ID and the validated question reaches
/// it, and `ARCOUNT` is forced to zero even when the query carried additional
/// records (the vendor echoed both the count and the records).
#[must_use]
pub fn build_response(query: &Query, answer: Answer) -> Vec<u8> {
    let answer_len = match answer {
        Answer::None => 0,
        Answer::V4(_) => ANSWER_LEN_A,
        Answer::V6(_) => ANSWER_LEN_AAAA,
    };
    let mut out = Vec::with_capacity(
        HEADER_LEN
            .saturating_add(query.question_len())
            .saturating_add(answer_len),
    );
    out.extend_from_slice(&query.id.to_be_bytes());
    // QR = 1, opcode 0, C/TC/T clear, RCODE 0 (`llmnr.c:285-286`).
    out.push(0x80);
    out.push(0x00);
    out.extend_from_slice(&1_u16.to_be_bytes());
    let ancount: u16 = if matches!(answer, Answer::None) { 0 } else { 1 };
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());

    out.extend_from_slice(&query.name_wire);
    out.push(0);
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&query.qclass.to_be_bytes());

    match answer {
        Answer::None => {}
        Answer::V4(address) => {
            push_answer(&mut out, TYPE_A, &address);
        }
        Answer::V6(address) => {
            push_answer(&mut out, TYPE_AAAA, &address);
        }
    }
    out
}

fn push_answer(out: &mut Vec<u8>, rtype: u16, rdata: &[u8]) {
    // Pointer to the name in the question section, offset 12 (`llmnr.c:243`).
    out.push(0xc0);
    out.push(0x0c);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ANSWER_TTL.to_be_bytes());
    let length = u16::try_from(rdata.len()).unwrap_or(0);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(rdata);
}

/// True when one of the configured names matches, case-insensitively.
///
/// `llmnr.c:219-237`: the NetBIOS name, the host name and the two
/// space-separated alias lists, compared with `strncasecmp` on the whole
/// dotted name.
#[must_use]
pub fn is_authoritative(name: &str, names: &[&str], alias_lists: &[&str]) -> bool {
    if name.is_empty() {
        return false;
    }
    if names
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
    {
        return true;
    }
    alias_lists.iter().any(|list| {
        list.split(' ')
            .any(|alias| !alias.is_empty() && alias.eq_ignore_ascii_case(name))
    })
}
