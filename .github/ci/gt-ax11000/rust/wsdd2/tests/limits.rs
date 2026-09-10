//! Reply size, reply budget and HTTP framing limits.

use wsdd2::budget::{Budget, REPLIES_PER_SECOND};
use wsdd2::http::{self, Progress, Status};
use wsdd2::llmnr::{
    self, Answer, Query, ANSWER_LEN_A, ANSWER_LEN_AAAA, CLASS_IN, HEADER_LEN, TYPE_A,
};
use wsdd2::wsd::{self, Identity, Request};
use wsdd2::{answer, ReplyContext};

const ENDPOINT: &str = "d1d0f0c8-6d18-4c3b-9c55-1d2a0e7b3f44";

fn identity() -> Identity {
    Identity {
        endpoint: String::from(ENDPOINT),
        sequence: String::from("0b6a8f52-1a3c-4d5e-8f70-2b9c4d6e8a10"),
        instance: 1_757_400_000,
        netbios_name: String::from("GT-AX11000"),
        workgroup: String::from("WORKGROUP"),
        boot: wsd::BootInfo::default(),
    }
}

fn reply_for(document: &str) -> Option<String> {
    let identity = identity();
    let request = Request::parse(document.as_bytes()).ok()?;
    answer(
        &request,
        &ReplyContext {
            identity: &identity,
            message_id: "6f2c1b90-5e44-4a1d-b7c2-8f0d9e3a1c56",
            number: 1,
            host: "192.168.1.1",
            port: wsd::WSD_PORT,
        },
    )
}

/// A probe padded with `extra` harmless header elements.
fn padded_probe(extra: usize) -> String {
    let base = wsdd2::probe_fixture("wsdp:Device");
    let mut padding = String::new();
    for _ in 0..extra {
        padding.push_str("<wsd:Pad>0123456789</wsd:Pad>");
    }
    base.replace("</soap:Header>", &format!("{padding}</soap:Header>"))
}

#[test]
fn a_datagram_reply_never_exceeds_the_hard_cap() {
    let reply = reply_for(&wsdd2::probe_fixture("wsdp:Device")).expect("a reply");
    assert!(reply.len() <= wsd::MAX_DATAGRAM_REPLY, "{}", reply.len());
    let identity = identity();
    for message in [
        wsd::hello(&identity, "6f2c1b90-5e44-4a1d-b7c2-8f0d9e3a1c56", 1),
        wsd::bye(&identity, "6f2c1b90-5e44-4a1d-b7c2-8f0d9e3a1c56", 2),
    ] {
        assert!(message.expect("announcement").len() <= wsd::MAX_DATAGRAM_REPLY);
    }
}

#[test]
fn a_datagram_reply_does_not_grow_with_the_request() {
    // The anti-amplification property WS-Discovery permits: the reply is a
    // function of this device's own identity and the echoed message id only,
    // so padding the request cannot buy an attacker a single extra byte.
    let small = reply_for(&padded_probe(0)).expect("a reply");
    let large = reply_for(&padded_probe(120)).expect("a reply");
    assert!(padded_probe(120).len() > padded_probe(0).len() * 5);
    assert_eq!(small, large);
}

#[test]
fn the_only_request_bytes_in_a_reply_are_the_message_id() {
    let base = reply_for(&wsdd2::probe_fixture("wsdp:Device")).expect("a reply");
    let long_id = format!("urn:uuid:{}", "a".repeat(64));
    let document = wsdd2::probe_fixture("wsdp:Device")
        .replace("urn:uuid:11112222-3333-4444-5555-666677778888", &long_id);
    let with_long_id = reply_for(&document).expect("a reply");
    let growth = with_long_id
        .len()
        .checked_sub(base.len())
        .expect("the longer id cannot shrink the reply");
    assert_eq!(
        growth,
        long_id.len() - "urn:uuid:11112222-3333-4444-5555-666677778888".len()
    );
    // Which is itself bounded, so the whole reply is bounded.
    assert!(long_id.len() <= wsd::MAX_MESSAGE_ID);
    assert!(with_long_id.len() <= wsd::MAX_DATAGRAM_REPLY);
}

#[test]
fn an_llmnr_reply_is_never_larger_than_the_question_plus_one_record() {
    // The vendor copied the entire received datagram into the response
    // (llmnr.c:275-277) with a 9,217-byte receive buffer, so a padded query
    // was reflected in full.  Here the response is rebuilt from the parsed
    // question, so it is bounded by the question, not by the datagram.
    for padding in [0_usize, 1, 16, 200] {
        let datagram = wsdd2::llmnr_query(b"gt-ax11000", TYPE_A, CLASS_IN, padding);
        let query = Query::parse(&datagram).expect("parse");
        let response = llmnr::build_response(&query, Answer::V4([192, 168, 1, 1]));
        assert_eq!(
            response.len(),
            HEADER_LEN + query.question_len() + ANSWER_LEN_A
        );
        assert!(response.len() <= datagram.len() + ANSWER_LEN_AAAA);
        if padding > ANSWER_LEN_A {
            assert!(
                response.len() < datagram.len(),
                "a padded query must produce a smaller response"
            );
        }
    }
}

#[test]
fn an_llmnr_response_carries_no_additional_records_from_the_query() {
    // The vendor overwrote only bytes 2, 3, 6 and 7 of its copy
    // (llmnr.c:285-296), so ARCOUNT and every additional record the query
    // carried were echoed back.
    let mut datagram = wsdd2::llmnr_query(b"gt-ax11000", TYPE_A, CLASS_IN, 0);
    if let Some(slot) = datagram.get_mut(11) {
        *slot = 4;
    }
    datagram.extend_from_slice(&[0xde; 40]);
    let query = Query::parse(&datagram).expect("parse");
    let response = llmnr::build_response(&query, Answer::V4([192, 168, 1, 1]));
    assert_eq!(response.get(10..12), Some([0, 0].as_slice()));
    assert!(!response.windows(4).any(|window| window == [0xde; 4]));
}

#[test]
fn an_invalid_datagram_never_consumes_the_budget() {
    // A limiter charged before validation protects the attacker: a flood of
    // malformed datagrams, which cost nothing to make, would spend the share
    // a real client needs.  Everything that fails to parse must leave the
    // budget untouched, so drive the same sequence the daemon does.
    let identity = identity();
    let mut budget = Budget::default();
    let now = 1_757_400_000.0_f64;

    let hostile: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"<".to_vec(),
        b"not xml at all".to_vec(),
        vec![0xff; 64],
        vec![b'<'; wsdd2::xml::MAX_DOCUMENT + 1],
        wsdd2::probe_fixture("wsdp:Device").as_bytes()[..100].to_vec(),
        wsdd2::probe_fixture("wprt:PrintDeviceType").into_bytes(),
        wsdd2::resolve_fixture("urn:uuid:00000000-0000-0000-0000-000000000000").into_bytes(),
    ];
    for datagram in &hostile {
        if let Ok(request) = Request::parse(datagram) {
            let reply = answer(
                &request,
                &ReplyContext {
                    identity: &identity,
                    message_id: "6f2c1b90-5e44-4a1d-b7c2-8f0d9e3a1c56",
                    number: 1,
                    host: "192.168.1.1",
                    port: wsd::WSD_PORT,
                },
            );
            if reply.is_some() {
                assert!(budget.allow(now));
            }
        }
    }
    assert_eq!(
        budget.used(),
        0,
        "a refused or unanswered datagram charged the budget"
    );

    // A valid probe does charge it, and only once per reply.
    let valid = wsdd2::probe_fixture("wsdp:Device");
    for _ in 0..3 {
        let request = Request::parse(valid.as_bytes()).expect("parse");
        let reply = answer(
            &request,
            &ReplyContext {
                identity: &identity,
                message_id: "6f2c1b90-5e44-4a1d-b7c2-8f0d9e3a1c56",
                number: 1,
                host: "192.168.1.1",
                port: wsd::WSD_PORT,
            },
        );
        assert!(reply.is_some());
        assert!(budget.allow(now));
    }
    assert_eq!(budget.used(), 3);
}

#[test]
fn the_budget_is_exhausted_and_then_refilled_by_the_window() {
    let mut budget = Budget::default();
    let now = 1_757_400_000.0_f64;
    for index in 0..REPLIES_PER_SECOND {
        assert!(budget.allow(now), "denied reply {index}");
    }
    assert!(!budget.allow(now));
    assert!(!budget.allow(now + 0.999));
    assert!(budget.allow(now + 1.0));
    assert_eq!(budget.used(), 1);
}

#[test]
fn a_clock_that_misbehaves_closes_the_budget_rather_than_opening_it() {
    let mut budget = Budget::default();
    assert!(!budget.allow(f64::NAN));
    assert!(!budget.allow(f64::INFINITY));
    let now = 1_757_400_000.0_f64;
    assert!(budget.allow(now));
    // A backwards step restarts the window; it never grants extra replies.
    assert!(budget.allow(now - 100.0));
    assert_eq!(budget.used(), 1);
}

#[test]
fn the_metadata_endpoint_frames_only_a_post_to_the_endpoint_uuid() {
    let good = format!(
        "POST /{ENDPOINT} HTTP/1.1\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: 4\r\n\r\nbody"
    );
    assert_eq!(
        http::parse_header(good.as_bytes(), ENDPOINT),
        Progress::Header {
            body_offset: good.len() - 4,
            content_length: 4
        }
    );

    let cases: [(&str, Status); 8] = [
        ("GET /ENDPOINT HTTP/1.1\r\nContent-Type: application/soap+xml\r\nContent-Length: 4\r\n\r\n", Status::MethodNotAllowed),
        ("POST /ENDPOINT HTTP/2\r\nContent-Type: application/soap+xml\r\nContent-Length: 4\r\n\r\n", Status::MethodNotAllowed),
        ("POST /other HTTP/1.1\r\nContent-Type: application/soap+xml\r\nContent-Length: 4\r\n\r\n", Status::NotFound),
        ("POST ENDPOINT HTTP/1.1\r\nContent-Type: application/soap+xml\r\nContent-Length: 4\r\n\r\n", Status::NotFound),
        ("POST /ENDPOINT HTTP/1.1\r\nContent-Type: text/xml\r\nContent-Length: 4\r\n\r\n", Status::BadRequest),
        ("POST /ENDPOINT HTTP/1.1\r\nContent-Type: application/soap+xml\r\n\r\n", Status::BadRequest),
        ("POST /ENDPOINT HTTP/1.1\r\nContent-Type: application/soap+xml\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n", Status::BadRequest),
        ("POST /ENDPOINT HTTP/1.1\r\nContent-Type: application/soap+xml\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n", Status::BadRequest),
    ];
    for (template, status) in cases {
        let request = template.replace("ENDPOINT", ENDPOINT);
        assert_eq!(
            http::parse_header(request.as_bytes(), ENDPOINT),
            Progress::Failed(status),
            "{template}"
        );
    }

    let too_long = format!(
        "POST /{ENDPOINT} HTTP/1.1\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\n\r\n",
        http::MAX_REQUEST
    );
    assert_eq!(
        http::parse_header(too_long.as_bytes(), ENDPOINT),
        Progress::Failed(Status::TooLarge)
    );
}

#[test]
fn an_incomplete_header_asks_for_more_until_the_cap() {
    let good = format!(
        "POST /{ENDPOINT} HTTP/1.1\r\nContent-Type: application/soap+xml\r\nContent-Length: 4\r\n\r\nbody"
    );
    for cut in 0..(good.len() - 4) {
        assert_eq!(
            http::parse_header(good.as_bytes().get(..cut).unwrap_or_default(), ENDPOINT),
            Progress::Incomplete,
            "at {cut}"
        );
    }
    let flood = vec![b'A'; http::MAX_REQUEST];
    assert_eq!(
        http::parse_header(&flood, ENDPOINT),
        Progress::Failed(Status::TooLarge)
    );
}

#[test]
fn no_http_input_panics_the_framer() {
    let mut state = 0x1234_5678_9abc_def0_u64;
    for length in (0..=256_usize).chain([1024, 4096, http::MAX_REQUEST]) {
        let bytes: Vec<u8> = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let _ = http::parse_header(&bytes, ENDPOINT);
    }
    let seed = format!(
        "POST /{ENDPOINT} HTTP/1.1\r\nContent-Type: application/soap+xml\r\nContent-Length: 4\r\n\r\nbody"
    );
    for index in 0..seed.len() {
        for replacement in [0_u8, b'\r', b'\n', b':', b' ', 0xff] {
            let mut mutated = seed.clone().into_bytes();
            if let Some(slot) = mutated.get_mut(index) {
                *slot = replacement;
            }
            let _ = http::parse_header(&mutated, ENDPOINT);
        }
    }
}

#[test]
fn the_response_header_is_fixed_and_carries_nothing_from_the_request() {
    let header = http::response_header(Status::Ok, "Wed, 10 Sep 2025 12:00:00 GMT", 1234);
    assert_eq!(
        header,
        "HTTP/1.1 200 OK\r\nServer: Asuswrt WSD Server\r\nDate: Wed, 10 Sep 2025 12:00:00 GMT\r\nConnection: close\r\nContent-Type: application/soap+xml\r\nContent-Length: 1234\r\n\r\n"
    );
}

#[test]
fn the_http_date_matches_strftime() {
    // date -u -d @1757505600 '+%a, %d %b %Y %H:%M:%S GMT'
    assert_eq!(
        http::http_date(1_757_505_600),
        "Wed, 10 Sep 2025 12:00:00 GMT"
    );
    assert_eq!(
        http::http_date(1_789_041_600),
        "Thu, 10 Sep 2026 12:00:00 GMT"
    );
    assert_eq!(http::http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    assert_eq!(
        http::http_date(951_782_400),
        "Tue, 29 Feb 2000 00:00:00 GMT"
    );
    assert_eq!(
        http::http_date(1_709_164_800),
        "Thu, 29 Feb 2024 00:00:00 GMT"
    );
}
