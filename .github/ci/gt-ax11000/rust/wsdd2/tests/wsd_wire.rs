//! Byte-level WS-Discovery fixtures.
//!
//! The message shapes are the ones the vendor emitted and accepted:
//! `release/src/router/wsdd2/wsd.c:384-395` (the two header tags it looked
//! for), `wsd.c:551-577` (the envelope template), `wsd.c:625-745` (the four
//! announcement/match bodies) and `wsd.c:431-468` (the action table).

use wsdd2::wsd::{self, Body, Identity, Refusal, Request};
use wsdd2::xml::{self, XmlError};
use wsdd2::{answer, ReplyContext};

const ENDPOINT: &str = "d1d0f0c8-6d18-4c3b-9c55-1d2a0e7b3f44";
const SEQUENCE: &str = "0b6a8f52-1a3c-4d5e-8f70-2b9c4d6e8a10";
const REPLY_ID: &str = "6f2c1b90-5e44-4a1d-b7c2-8f0d9e3a1c56";
const REQUEST_ID: &str = "urn:uuid:11112222-3333-4444-5555-666677778888";

fn identity() -> Identity {
    Identity {
        endpoint: String::from(ENDPOINT),
        sequence: String::from(SEQUENCE),
        instance: 1_757_400_000,
        netbios_name: String::from("GT-AX11000"),
        workgroup: String::from("WORKGROUP"),
        boot: wsd::BootInfo::default(),
    }
}

fn reply_to(document: &str) -> Option<String> {
    let identity = identity();
    let request = Request::parse(document.as_bytes()).ok()?;
    let context = ReplyContext {
        identity: &identity,
        message_id: REPLY_ID,
        number: 1,
        host: "192.168.1.1",
        port: wsd::WSD_PORT,
    };
    answer(&request, &context)
}

/// A Windows-shaped envelope with the prefixes WSDAPI uses.
fn envelope(action: &str, to: &str, message_id: &str, body: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsa=\"{wsa}\" xmlns:wsd=\"{wsd}\" \
         xmlns:wsdp=\"{wsdp}\" xmlns:wxt=\"{wxt}\" xmlns:pub=\"{pub}\">\
         <soap:Header><wsa:To>{to}</wsa:To><wsa:Action>{action}</wsa:Action>\
         <wsa:MessageID>{message_id}</wsa:MessageID></soap:Header>\
         <soap:Body>{body}</soap:Body></soap:Envelope>",
        soap = xml::SOAP12_NS,
        wsa = xml::WSA_NS,
        wsd = xml::WSD_NS,
        wsdp = xml::WSDP_NS,
        wxt = xml::WXT_NS,
        pub = xml::PUB_NS,
    )
}

#[test]
fn a_probe_for_the_device_type_is_answered_with_probematches() {
    let reply = reply_to(&wsdd2::probe_fixture("wsdp:Device")).expect("a reply");
    assert!(reply.contains(&format!(
        "<wsa:Action>{}</wsa:Action>",
        wsd::ACT_PROBEMATCHES
    )));
    assert!(reply.contains(&format!("<wsa:To>{}</wsa:To>", wsd::TO_ANONYMOUS)));
    assert!(reply.contains(&format!("<wsa:RelatesTo>{REQUEST_ID}</wsa:RelatesTo>")));
    assert!(reply.contains("<wsd:Types>wsdp:Device pub:Computer</wsd:Types>"));
    assert!(reply.contains(&format!(
        "<wsd:XAddrs>http://192.168.1.1:3702/{ENDPOINT}</wsd:XAddrs>"
    )));
    assert!(reply.contains("<wsd:MetadataVersion>2</wsd:MetadataVersion>"));
    assert!(reply.contains(&format!(
        "<wsd:AppSequence InstanceId=\"1757400000\" SequenceId=\"urn:uuid:{SEQUENCE}\" MessageNumber=\"1\" />"
    )));
}

#[test]
fn a_probe_for_the_computer_type_is_answered_too() {
    assert!(reply_to(&wsdd2::probe_fixture("pub:Computer")).is_some());
}

#[test]
fn a_probe_with_no_types_element_matches_everything() {
    let document = envelope(
        wsd::ACT_PROBE,
        wsd::TO_DISCOVERY,
        REQUEST_ID,
        "<wsd:Probe />",
    );
    assert!(reply_to(&document).is_some());
}

#[test]
fn a_probe_for_a_type_this_device_does_not_publish_is_not_answered() {
    // The vendor never read wsd:Types at all (wsd.c:1136 dispatches on the
    // action alone), so it answered printer and scanner probes with a
    // computer record.
    for types in [
        "wprt:PrintDeviceType",
        "wsdp:Device2",
        "Device",
        "wsdp:device",
        ":",
        "",
    ] {
        let document = wsdd2::probe_fixture(types);
        assert!(
            reply_to(&document).is_none(),
            "answered a probe for {types:?}"
        );
    }
}

#[test]
fn a_type_token_bound_to_a_foreign_namespace_does_not_match() {
    let document = format!(
        "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsa=\"{wsa}\" \
         xmlns:wsd=\"{wsd}\" xmlns:wsdp=\"http://example.invalid/devprof\">\
         <soap:Header><wsa:To>{to}</wsa:To><wsa:Action>{action}</wsa:Action>\
         <wsa:MessageID>{REQUEST_ID}</wsa:MessageID></soap:Header>\
         <soap:Body><wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe></soap:Body>\
         </soap:Envelope>",
        soap = xml::SOAP12_NS,
        wsa = xml::WSA_NS,
        wsd = xml::WSD_NS,
        to = wsd::TO_DISCOVERY,
        action = wsd::ACT_PROBE,
    );
    assert!(reply_to(&document).is_none());
}

#[test]
fn a_resolve_for_this_endpoint_is_answered_and_one_for_another_is_not() {
    let mine = wsdd2::resolve_fixture(&format!("urn:uuid:{ENDPOINT}"));
    let reply = reply_to(&mine).expect("a reply");
    assert!(reply.contains(&format!(
        "<wsa:Action>{}</wsa:Action>",
        wsd::ACT_RESOLVEMATCHES
    )));
    assert!(reply.contains("<wsd:ResolveMatches><wsd:ResolveMatch>"));

    // The vendor declared struct wsd_req_info.resolve.endpoint (wsd.h:57-59),
    // never filled it in, and answered every Resolve with its own address.
    for address in [
        "urn:uuid:00000000-0000-0000-0000-000000000000",
        "urn:uuid:",
        ENDPOINT,
        "http://192.168.1.1/",
        "",
    ] {
        assert!(
            reply_to(&wsdd2::resolve_fixture(address)).is_none(),
            "answered a resolve for {address:?}"
        );
    }
}

#[test]
fn an_endpoint_address_matches_case_insensitively() {
    let upper = ENDPOINT.to_ascii_uppercase();
    assert!(reply_to(&wsdd2::resolve_fixture(&format!("urn:uuid:{upper}"))).is_some());
}

#[test]
fn a_get_produces_the_metadata_document() {
    let reply = reply_to(&wsdd2::get_fixture(ENDPOINT)).expect("a reply");
    assert!(reply.contains(&format!(
        "<wsa:Action>{}</wsa:Action>",
        wsd::ACT_GETRESPONSE
    )));
    assert!(reply.contains("<pub:Computer>GT-AX11000/Workgroup:WORKGROUP</pub:Computer>"));
    assert!(reply.contains("<wsdp:Manufacturer>ASUS</wsdp:Manufacturer>"));
    assert!(reply.contains("<un0:DeviceCategory>Computers</un0:DeviceCategory>"));
    assert!(reply.contains(&format!(
        "<wsdp:ServiceId>urn:uuid:{ENDPOINT}</wsdp:ServiceId>"
    )));
    assert!(reply.len() <= wsd::MAX_REPLY);
}

#[test]
fn hello_and_bye_carry_the_endpoint_and_both_types() {
    let identity = identity();
    let hello = wsd::hello(&identity, REPLY_ID, 1).expect("hello");
    let bye = wsd::bye(&identity, REPLY_ID, 2).expect("bye");
    assert!(hello.contains(&format!("<wsa:Action>{}</wsa:Action>", wsd::ACT_HELLO)));
    assert!(hello.contains(&format!("<wsa:To>{}</wsa:To>", wsd::TO_DISCOVERY)));
    assert!(hello.contains("<wsd:Hello><wsa:EndpointReference>"));
    assert!(hello.contains("<wsd:Types>wsdp:Device pub:Computer</wsd:Types>"));
    assert!(!hello.contains("<wsa:RelatesTo>"));
    assert!(bye.contains(&format!("<wsa:Action>{}</wsa:Action>", wsd::ACT_BYE)));
    assert!(bye.contains("<wsd:Bye><wsa:EndpointReference>"));
    assert!(bye.contains("MessageNumber=\"2\""));
}

#[test]
fn an_action_that_disagrees_with_the_body_is_refused() {
    let document = envelope(
        wsd::ACT_RESOLVE,
        wsd::TO_DISCOVERY,
        REQUEST_ID,
        "<wsd:Probe />",
    );
    assert_eq!(
        Request::parse(document.as_bytes()),
        Err(Refusal::ActionBodyMismatch)
    );
}

#[test]
fn the_announcement_and_match_actions_are_never_answered() {
    // The vendor decoded Hello, Bye, ProbeMatches, ResolveMatches and
    // GetResponse into its enum (wsd.c:431-468) and then fell through the
    // dispatch switch (wsd.c:1141).  Here they never reach a body at all.
    for action in [
        wsd::ACT_HELLO,
        wsd::ACT_BYE,
        wsd::ACT_PROBEMATCHES,
        wsd::ACT_RESOLVEMATCHES,
        wsd::ACT_GETRESPONSE,
    ] {
        let document = envelope(action, wsd::TO_DISCOVERY, REQUEST_ID, "<wsd:Probe />");
        assert_eq!(
            Request::parse(document.as_bytes()),
            Err(Refusal::ActionBodyMismatch),
            "{action}"
        );
    }
    let document = envelope(
        "http://example.invalid/Attack",
        wsd::TO_DISCOVERY,
        REQUEST_ID,
        "<wsd:Probe />",
    );
    assert_eq!(
        Request::parse(document.as_bytes()),
        Err(Refusal::UnsupportedAction)
    );
}

#[test]
fn the_wsa_to_of_a_probe_must_be_the_discovery_urn() {
    for to in [
        "urn:schemas-xmlsoap-org:ws:2005:04:discovery/",
        "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
        "urn:uuid:d1d0f0c8-6d18-4c3b-9c55-1d2a0e7b3f44",
        "",
    ] {
        let document = envelope(wsd::ACT_PROBE, to, REQUEST_ID, "<wsd:Probe />");
        assert_eq!(
            Request::parse(document.as_bytes()),
            Err(Refusal::BadTo),
            "{to}"
        );
    }
}

#[test]
fn a_message_id_that_could_change_the_reply_is_refused() {
    for message_id in [
        "urn:uuid:</wsa:RelatesTo><wsa:Action>evil",
        "urn:uuid:&amp;",
        "urn:uuid:x'y",
        "urn:uuid:x\"y",
        "",
    ] {
        let document = envelope(
            wsd::ACT_PROBE,
            wsd::TO_DISCOVERY,
            message_id,
            "<wsd:Probe />",
        );
        let outcome = Request::parse(document.as_bytes());
        assert!(
            matches!(
                outcome,
                Err(Refusal::BadMessageId) | Err(Refusal::NoMessageId) | Err(Refusal::Xml(_))
            ),
            "{message_id:?} produced {outcome:?}"
        );
    }
    let oversized = format!("urn:uuid:{}", "a".repeat(wsd::MAX_MESSAGE_ID));
    let document = envelope(
        wsd::ACT_PROBE,
        wsd::TO_DISCOVERY,
        &oversized,
        "<wsd:Probe />",
    );
    assert_eq!(
        Request::parse(document.as_bytes()),
        Err(Refusal::BadMessageId)
    );
}

#[test]
fn a_message_id_is_echoed_verbatim_and_only_once() {
    let document = envelope(
        wsd::ACT_PROBE,
        wsd::TO_DISCOVERY,
        "urn:uuid:AbCd-1234_%20~",
        "<wsd:Probe />",
    );
    let reply = reply_to(&document).expect("a reply");
    assert!(reply.contains("<wsa:RelatesTo>urn:uuid:AbCd-1234_%20~</wsa:RelatesTo>"));
    assert_eq!(reply.matches("urn:uuid:AbCd-1234_%20~").count(), 1);
}

#[test]
fn a_duplicated_header_field_is_refused() {
    let document = format!(
        "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsa=\"{wsa}\" xmlns:wsd=\"{wsd}\">\
         <soap:Header><wsa:To>{to}</wsa:To><wsa:Action>{action}</wsa:Action>\
         <wsa:Action>{action}</wsa:Action><wsa:MessageID>{REQUEST_ID}</wsa:MessageID></soap:Header>\
         <soap:Body><wsd:Probe /></soap:Body></soap:Envelope>",
        soap = xml::SOAP12_NS,
        wsa = xml::WSA_NS,
        wsd = xml::WSD_NS,
        to = wsd::TO_DISCOVERY,
        action = wsd::ACT_PROBE,
    );
    assert_eq!(Request::parse(document.as_bytes()), Err(Refusal::Duplicate));
}

#[test]
fn the_envelope_must_be_soap_twelve_with_a_header_then_a_body() {
    let soap11 = wsdd2::probe_fixture("wsdp:Device")
        .replace(xml::SOAP12_NS, "http://schemas.xmlsoap.org/soap/envelope/");
    assert_eq!(
        Request::parse(soap11.as_bytes()),
        Err(Refusal::NotAnEnvelope)
    );

    let body_first = format!(
        "<soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsa=\"{wsa}\" xmlns:wsd=\"{wsd}\">\
         <soap:Body><wsd:Probe /></soap:Body>\
         <soap:Header><wsa:To>{to}</wsa:To><wsa:Action>{action}</wsa:Action>\
         <wsa:MessageID>{REQUEST_ID}</wsa:MessageID></soap:Header></soap:Envelope>",
        soap = xml::SOAP12_NS,
        wsa = xml::WSA_NS,
        wsd = xml::WSD_NS,
        to = wsd::TO_DISCOVERY,
        action = wsd::ACT_PROBE,
    );
    assert_eq!(
        Request::parse(body_first.as_bytes()),
        Err(Refusal::BadEnvelope)
    );

    let two_bodies = format!(
        "<soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsa=\"{wsa}\" xmlns:wsd=\"{wsd}\">\
         <soap:Header><wsa:To>{to}</wsa:To><wsa:Action>{action}</wsa:Action>\
         <wsa:MessageID>{REQUEST_ID}</wsa:MessageID></soap:Header>\
         <soap:Body><wsd:Probe /><wsd:Resolve /></soap:Body></soap:Envelope>",
        soap = xml::SOAP12_NS,
        wsa = xml::WSA_NS,
        wsd = xml::WSD_NS,
        to = wsd::TO_DISCOVERY,
        action = wsd::ACT_PROBE,
    );
    assert_eq!(Request::parse(two_bodies.as_bytes()), Err(Refusal::BadBody));
}

#[test]
fn a_probe_hidden_in_a_text_node_is_not_a_probe() {
    // The vendor's wsd_tag_find was two strstr calls over the datagram
    // (wsd.c:353-377), so a Probe action quoted inside any element -- or
    // inside an unrelated namespace -- was dispatched as a real one.
    let document = format!(
        "<soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsa=\"{wsa}\" xmlns:wsd=\"{wsd}\">\
         <soap:Header><wsa:To>{to}</wsa:To>\
         <wsa:MessageID>{REQUEST_ID}</wsa:MessageID>\
         <wsd:Note>&lt;wsa:Action&gt;{action}&lt;/wsa:Action&gt;</wsd:Note></soap:Header>\
         <soap:Body><wsd:Probe /></soap:Body></soap:Envelope>",
        soap = xml::SOAP12_NS,
        wsa = xml::WSA_NS,
        wsd = xml::WSD_NS,
        to = wsd::TO_DISCOVERY,
        action = wsd::ACT_PROBE,
    );
    assert_eq!(Request::parse(document.as_bytes()), Err(Refusal::NoAction));
}

#[test]
fn truncated_oversized_and_deeply_nested_documents_are_refused() {
    let seed = wsdd2::probe_fixture("wsdp:Device");
    for cut in 1..seed.len() {
        let slice = seed.as_bytes().get(..cut).unwrap_or_default();
        assert!(
            Request::parse(slice).is_err(),
            "accepted a {cut}-byte prefix"
        );
    }

    let oversized = vec![b'a'; xml::MAX_DOCUMENT + 1];
    assert_eq!(
        Request::parse(&oversized),
        Err(Refusal::Xml(XmlError::TooLong))
    );

    let mut nested = format!(
        "<soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsd=\"{wsd}\"><soap:Header>",
        soap = xml::SOAP12_NS,
        wsd = xml::WSD_NS,
    );
    for _ in 0..xml::MAX_DEPTH {
        nested.push_str("<wsd:a>");
    }
    assert_eq!(
        Request::parse(nested.as_bytes()),
        Err(Refusal::Xml(XmlError::TooDeep))
    );
}

#[test]
fn a_non_utf8_datagram_is_refused_without_panicking() {
    let mut document = wsdd2::probe_fixture("wsdp:Device").into_bytes();
    document.extend_from_slice(&[0xff, 0xfe, 0x00, 0x80]);
    assert!(Request::parse(&document).is_err());

    for index in 0..document.len() {
        for replacement in [0x00_u8, 0x80, 0xc3, 0xff, b'<', b'>', b'&'] {
            let mut mutated = document.clone();
            if let Some(slot) = mutated.get_mut(index) {
                *slot = replacement;
            }
            let _ = Request::parse(&mutated);
        }
    }
}

#[test]
fn every_datagram_length_of_random_bytes_is_refused_without_panicking() {
    // panic = "abort": a panic anywhere on this path is a remote kill.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for length in (0..=512_usize).chain([1024, 4096, xml::MAX_DOCUMENT]) {
        let bytes: Vec<u8> = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        assert!(Request::parse(&bytes).is_err());
    }
}

#[test]
fn a_body_element_from_the_wrong_namespace_is_refused() {
    let document = format!(
        "<soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsa=\"{wsa}\" xmlns:d=\"http://example.invalid/\">\
         <soap:Header><wsa:To>{to}</wsa:To><wsa:Action>{action}</wsa:Action>\
         <wsa:MessageID>{REQUEST_ID}</wsa:MessageID></soap:Header>\
         <soap:Body><d:Probe /></soap:Body></soap:Envelope>",
        soap = xml::SOAP12_NS,
        wsa = xml::WSA_NS,
        to = wsd::TO_DISCOVERY,
        action = wsd::ACT_PROBE,
    );
    assert_eq!(
        Request::parse(document.as_bytes()),
        Err(Refusal::UnsupportedBody)
    );
}

#[test]
fn the_parsed_body_reports_what_the_probe_asked_for() {
    let request = Request::parse(wsdd2::probe_fixture("wsdp:Device").as_bytes()).expect("parse");
    assert_eq!(
        request.body,
        Body::Probe {
            types_present: true,
            types_matched: true
        }
    );
    assert_eq!(request.message_id, REQUEST_ID);
    assert_eq!(request.to, wsd::TO_DISCOVERY);
}
