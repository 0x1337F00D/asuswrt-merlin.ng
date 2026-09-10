//! Byte-level LLMNR fixtures.
//!
//! Every header rule is the one `release/src/router/wsdd2/llmnr.c:118-216`
//! applied.  The question parser is new, because the vendor's walked past the
//! end of the datagram; the cases that reach that bug are pinned here.

use wsdd2::llmnr::{
    self, Answer, Query, Refusal, ANSWER_LEN_A, ANSWER_LEN_AAAA, CLASS_IN, HEADER_LEN, MAX_QUERY,
    TYPE_A, TYPE_AAAA, TYPE_ANY,
};

const V4: [u8; 4] = [192, 168, 1, 1];
const V6: [u8; 16] = [
    0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55,
];

fn query(name: &[u8], qtype: u16) -> Vec<u8> {
    wsdd2::llmnr_query(name, qtype, CLASS_IN, 0)
}

fn header(flags: u8, qdcount: u16, ancount: u16, nscount: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xbeef_u16.to_be_bytes());
    out.push(flags);
    out.push(0);
    out.extend_from_slice(&qdcount.to_be_bytes());
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&nscount.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.push(3);
    out.extend_from_slice(b"abc");
    out.push(0);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

#[test]
fn a_type_a_query_produces_one_a_record() {
    let datagram = query(b"gt-ax11000", TYPE_A);
    let parsed = Query::parse(&datagram).expect("parse");
    assert_eq!(parsed.id, 0xbeef);
    assert_eq!(parsed.name, "gt-ax11000");
    assert_eq!(parsed.qtype, TYPE_A);
    assert_eq!(parsed.qclass, CLASS_IN);

    let response = llmnr::build_response(&parsed, Answer::V4(V4));
    assert_eq!(response.len(), datagram.len() + ANSWER_LEN_A);
    // QR set, everything else clear.
    assert_eq!(response.get(2), Some(&0x80));
    assert_eq!(response.get(3), Some(&0x00));
    // QDCOUNT 1, ANCOUNT 1, NSCOUNT 0, ARCOUNT 0.
    assert_eq!(
        response.get(4..12),
        Some([0, 1, 0, 1, 0, 0, 0, 0].as_slice())
    );
    // The question is echoed verbatim, then the compressed answer.
    assert_eq!(
        response.get(HEADER_LEN..datagram.len()),
        datagram.get(HEADER_LEN..)
    );
    assert_eq!(
        response.get(datagram.len()..),
        Some([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 168, 1, 1].as_slice())
    );
}

#[test]
fn a_type_aaaa_query_over_ipv6_produces_one_aaaa_record() {
    let datagram = query(b"gt-ax11000", TYPE_AAAA);
    let parsed = Query::parse(&datagram).expect("parse");
    let answer = llmnr::choose_answer(parsed.qtype, None, Some(V6), true);
    assert_eq!(answer, Answer::V6(V6));
    let response = llmnr::build_response(&parsed, answer);
    assert_eq!(response.len(), datagram.len() + ANSWER_LEN_AAAA);
    assert_eq!(
        response.get(datagram.len()..datagram.len() + 4),
        Some([0xc0, 0x0c, 0x00, 0x1c].as_slice())
    );
}

#[test]
fn a_type_any_query_is_answered_with_the_transport_family() {
    let parsed = Query::parse(&query(b"host", TYPE_ANY)).expect("parse");
    assert_eq!(
        llmnr::choose_answer(parsed.qtype, Some(V4), Some(V6), false),
        Answer::V4(V4)
    );
    assert_eq!(
        llmnr::choose_answer(parsed.qtype, Some(V4), Some(V6), true),
        Answer::V6(V6)
    );
}

#[test]
fn a_family_mismatch_is_answered_with_an_empty_answer_section() {
    // RFC 4795 section 2.3, reproduced from llmnr.c:239-246.
    let parsed = Query::parse(&query(b"host", TYPE_A)).expect("parse");
    let answer = llmnr::choose_answer(parsed.qtype, Some(V4), Some(V6), true);
    assert_eq!(answer, Answer::None);
    let response = llmnr::build_response(&parsed, answer);
    assert_eq!(response.get(6..8), Some([0, 0].as_slice()));
    assert_eq!(response.len(), HEADER_LEN + parsed.question_len());
}

#[test]
fn every_header_rule_the_vendor_applied_is_applied() {
    assert_eq!(
        Query::parse(&header(0x80, 1, 0, 0)),
        Err(Refusal::NotAQuery)
    );
    assert_eq!(
        Query::parse(&header(0x08, 1, 0, 0)),
        Err(Refusal::NotAQuery)
    );
    assert_eq!(
        Query::parse(&header(0x04, 1, 0, 0)),
        Err(Refusal::ConflictBit)
    );
    assert_eq!(
        Query::parse(&header(0x02, 1, 0, 0)),
        Err(Refusal::TruncationBit)
    );
    for count in [0_u16, 2, u16::MAX] {
        assert_eq!(
            Query::parse(&header(0, count, 0, 0)),
            Err(Refusal::BadQuestionCount)
        );
    }
    assert_eq!(Query::parse(&header(0, 1, 1, 0)), Err(Refusal::NotEmpty));
    assert_eq!(Query::parse(&header(0, 1, 0, 1)), Err(Refusal::NotEmpty));
    assert_eq!(
        Query::parse(&header(0, 1, 0, 0)).map(|q| q.name),
        Ok(String::from("abc"))
    );
}

#[test]
fn a_wrong_type_or_class_is_refused() {
    for qtype in [0_u16, 2, 12, 16, 252, 0x0100, u16::MAX] {
        assert_eq!(
            Query::parse(&query(b"host", qtype)),
            Err(Refusal::BadType),
            "{qtype}"
        );
    }
    for qclass in [0_u16, 2, 3, 4, 255, u16::MAX] {
        let datagram = wsdd2::llmnr_query(b"host", TYPE_A, qclass, 0);
        assert_eq!(Query::parse(&datagram), Err(Refusal::BadClass), "{qclass}");
    }
}

#[test]
fn a_compression_pointer_is_refused() {
    let mut datagram = query(b"host", TYPE_A);
    if let Some(slot) = datagram.get_mut(HEADER_LEN) {
        *slot = 0xc0;
    }
    assert_eq!(Query::parse(&datagram), Err(Refusal::Compressed));
}

#[test]
fn an_unterminated_question_is_refused_instead_of_read_past_the_end() {
    // This is the vendor's out-of-bounds read: llmnr.c:172 loops on
    // `*in_name_p` with no bound against inlen, so a question whose last
    // label length runs to the end of the datagram walks off it, and
    // llmnr.c:205 then reads four more bytes from wherever it stopped.
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&0xbeef_u16.to_be_bytes());
    datagram.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    datagram.push(63);
    datagram.extend_from_slice(&[b'a'; 8]);
    assert_eq!(Query::parse(&datagram), Err(Refusal::Truncated));

    // The 13-byte minimum the vendor accepted, with a label that claims one
    // byte that is not there.
    let mut minimal = Vec::new();
    minimal.extend_from_slice(&0xbeef_u16.to_be_bytes());
    minimal.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    minimal.push(1);
    assert_eq!(minimal.len(), 13);
    assert_eq!(Query::parse(&minimal), Err(Refusal::Truncated));
}

#[test]
fn a_question_with_no_type_or_class_is_refused() {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&0xbeef_u16.to_be_bytes());
    datagram.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    datagram.push(1);
    datagram.push(b'a');
    datagram.push(0);
    datagram.push(0);
    assert_eq!(Query::parse(&datagram), Err(Refusal::Truncated));
}

#[test]
fn oversized_and_undersized_datagrams_are_refused() {
    for length in 0..=HEADER_LEN {
        let datagram = vec![0_u8; length];
        assert_eq!(Query::parse(&datagram), Err(Refusal::BadLength));
    }
    let oversized = vec![0_u8; MAX_QUERY + 1];
    assert_eq!(Query::parse(&oversized), Err(Refusal::BadLength));
    // The vendor's buffer was 9,217 bytes (llmnr.c:396) and it echoed every
    // received byte back (llmnr.c:275-277).
    let jumbo = wsdd2::llmnr_query(b"gt-ax11000", TYPE_A, CLASS_IN, 9_000);
    assert_eq!(Query::parse(&jumbo), Err(Refusal::BadLength));
}

#[test]
fn a_name_longer_than_rfc_1035_allows_is_refused() {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&0xbeef_u16.to_be_bytes());
    datagram.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for _ in 0..8 {
        datagram.push(63);
        datagram.extend_from_slice(&[b'a'; 63]);
    }
    datagram.push(0);
    datagram.extend_from_slice(&TYPE_A.to_be_bytes());
    datagram.extend_from_slice(&CLASS_IN.to_be_bytes());
    assert!(matches!(
        Query::parse(&datagram),
        Err(Refusal::NameTooLong) | Err(Refusal::BadLength)
    ));
}

#[test]
fn a_label_with_a_control_byte_or_a_dot_is_refused() {
    for byte in [0_u8, b'.', 0x1f, 0x7f, 0x80, 0xff] {
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&0xbeef_u16.to_be_bytes());
        datagram.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        datagram.push(2);
        datagram.push(b'a');
        datagram.push(byte);
        datagram.push(0);
        datagram.extend_from_slice(&TYPE_A.to_be_bytes());
        datagram.extend_from_slice(&CLASS_IN.to_be_bytes());
        assert_eq!(Query::parse(&datagram), Err(Refusal::NotAName), "{byte:#x}");
    }
}

#[test]
fn a_multi_label_name_joins_with_dots_and_lower_cases() {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&0xbeef_u16.to_be_bytes());
    datagram.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    datagram.push(2);
    datagram.extend_from_slice(b"GT");
    datagram.push(5);
    datagram.extend_from_slice(b"LOCAL");
    datagram.push(0);
    datagram.extend_from_slice(&TYPE_A.to_be_bytes());
    datagram.extend_from_slice(&CLASS_IN.to_be_bytes());
    let parsed = Query::parse(&datagram).expect("parse");
    assert_eq!(parsed.name, "gt.local");
}

#[test]
fn the_authority_check_matches_the_vendor_name_set() {
    // llmnr.c:219-237: netbios name, host name, then the two space-separated
    // alias lists, all case-insensitive.
    assert!(llmnr::is_authoritative(
        "gt-ax11000",
        &["GT-AX11000", "router"],
        &[]
    ));
    assert!(llmnr::is_authoritative(
        "router",
        &["GT-AX11000", "router"],
        &[]
    ));
    assert!(llmnr::is_authoritative(
        "nas",
        &["GT-AX11000"],
        &["media nas", ""]
    ));
    assert!(!llmnr::is_authoritative(
        "nas2",
        &["GT-AX11000"],
        &["media nas"]
    ));
    assert!(!llmnr::is_authoritative("", &["GT-AX11000"], &[""]));
    assert!(!llmnr::is_authoritative(
        "gt-ax11000.local",
        &["GT-AX11000"],
        &[]
    ));
}

#[test]
fn no_datagram_panics_the_parser() {
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    for length in 0..=MAX_QUERY {
        let bytes: Vec<u8> = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        if let Ok(parsed) = Query::parse(&bytes) {
            let response = llmnr::build_response(&parsed, Answer::V4(V4));
            assert!(response.len() <= bytes.len() + ANSWER_LEN_A);
        }
    }

    let seed = query(b"gt-ax11000", TYPE_A);
    for index in 0..seed.len() {
        for replacement in [0_u8, 1, 0x3f, 0xc0, 0xff] {
            let mut mutated = seed.clone();
            if let Some(slot) = mutated.get_mut(index) {
                *slot = replacement;
            }
            let _ = Query::parse(&mutated);
        }
        for cut in 0..seed.len() {
            let _ = Query::parse(seed.get(..cut).unwrap_or_default());
        }
    }
}
