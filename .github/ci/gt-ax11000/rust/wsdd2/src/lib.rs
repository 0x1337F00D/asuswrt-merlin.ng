//! A dependency-free WS-Discovery and LLMNR responder for the GT-AX11000.
//!
//! This library half is pure and free of `unsafe`: it holds the strict XML
//! scanner, the WS-Discovery and LLMNR wire formats, the HTTP framing of the
//! metadata endpoint, the reply budget and the command-line contract.  The
//! daemon half (`src/main.rs`) keeps every system call in `src/sys.rs`.
//!
//! It replaces `release/src/router/wsdd2`, the NETGEAR/Samba `wsdd2` the
//! firmware builds for `RTCONFIG_SAMBASRV`.  The observable contract that must
//! not change is the one `release/src/router/rc/usb.c:6038-6076` depends on:
//! the argument vector `-d -w -i <lan_ifname> -b sku:<id>,serial:<mac>`, the
//! installed path `/usr/sbin/wsdd2`, and the process name `wsdd2`, which
//! `pids("wsdd2")` and `killall_tk("wsdd2")` match.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod budget;
pub mod cli;
pub mod config;
pub mod http;
pub mod llmnr;
pub mod wsd;
pub mod xml;

use wsd::{Body, Identity, Request};

/// Marker printed by `--self-test`, asserted by the firmware verifier under
/// QEMU.
pub const SELF_TEST_MARKER: &str = "wsdd2-rs: runtime self-test passed";

/// Everything a reply needs that is not part of the request.
#[derive(Clone, Copy, Debug)]
pub struct ReplyContext<'a> {
    /// This device's stable identity.
    pub identity: &'a Identity,
    /// A fresh UUID for the reply's own `wsa:MessageID`.
    pub message_id: &'a str,
    /// `MessageNumber` for the `wsd:AppSequence`.
    pub number: u32,
    /// Host part of the advertised `wsd:XAddrs`: the local address the
    /// requester can reach, or the host name for IPv6 (`wsd.c:234-249`).
    pub host: &'a str,
    /// Port of the advertised `wsd:XAddrs`.
    pub port: u16,
}

/// Builds the reply for a validated request, or `None` when the request is
/// well-formed but not addressed to this device.
///
/// The two `None` cases are the reflection surface the vendor left open:
///
/// * a `Probe` whose `wsd:Types` names no type this device publishes.  The
///   vendor never read `wsd:Types` at all (`wsd.c:1136`) and answered every
///   probe on the segment, including probes for printers and scanners;
/// * a `Resolve` for another device's endpoint.  The vendor declared a
///   `resolve.endpoint` field (`wsd.h:57-59`), never filled it in, and
///   answered every `Resolve` with its own address.
#[must_use]
pub fn answer(request: &Request, context: &ReplyContext<'_>) -> Option<String> {
    match &request.body {
        Body::Probe {
            types_present,
            types_matched,
        } => {
            if *types_present && !*types_matched {
                return None;
            }
            wsd::probe_matches(
                context.identity,
                context.message_id,
                context.number,
                &request.message_id,
                context.host,
                context.port,
            )
        }
        Body::Resolve { address } => {
            if !endpoint_matches(address, &context.identity.endpoint) {
                return None;
            }
            wsd::resolve_matches(
                context.identity,
                context.message_id,
                context.number,
                &request.message_id,
                context.host,
                context.port,
            )
        }
        Body::Get => wsd::get_response(
            context.identity,
            context.message_id,
            context.number,
            &request.message_id,
        ),
    }
}

/// True when an endpoint reference address names this device.
#[must_use]
pub fn endpoint_matches(address: &str, endpoint: &str) -> bool {
    match address.trim().strip_prefix("urn:uuid:") {
        Some(uuid) => uuid.eq_ignore_ascii_case(endpoint),
        None => false,
    }
}

/// A deterministic, side-effect-free check of every parsing and encoding path.
///
/// It opens no socket and touches no file, so it is safe to run on the target
/// as a smoke test.
///
/// # Errors
/// Returns a description of the first check that did not hold.
pub fn self_test() -> Result<(), String> {
    let identity = Identity {
        endpoint: String::from("d1d0f0c8-6d18-4c3b-9c55-1d2a0e7b3f44"),
        sequence: String::from("0b6a8f52-1a3c-4d5e-8f70-2b9c4d6e8a10"),
        instance: 1_757_400_000,
        netbios_name: String::from("GT-AX11000"),
        workgroup: String::from("WORKGROUP"),
        boot: wsd::BootInfo::default(),
    };
    let context = ReplyContext {
        identity: &identity,
        message_id: "6f2c1b90-5e44-4a1d-b7c2-8f0d9e3a1c56",
        number: 1,
        host: "192.168.1.1",
        port: wsd::WSD_PORT,
    };

    let probe = probe_fixture("wsdp:Device");
    let request = Request::parse(probe.as_bytes()).map_err(|refusal| refusal.to_string())?;
    let reply = answer(&request, &context).ok_or("a wsdp:Device probe was not answered")?;
    for expected in [
        wsd::ACT_PROBEMATCHES,
        "<wsd:Types>wsdp:Device pub:Computer</wsd:Types>",
        "<wsd:XAddrs>http://192.168.1.1:3702/d1d0f0c8-6d18-4c3b-9c55-1d2a0e7b3f44</wsd:XAddrs>",
        "<wsa:RelatesTo>urn:uuid:11112222-3333-4444-5555-666677778888</wsa:RelatesTo>",
    ] {
        if !reply.contains(expected) {
            return Err(format!("ProbeMatches is missing {expected}"));
        }
    }
    if reply.len() > wsd::MAX_DATAGRAM_REPLY {
        return Err(String::from("ProbeMatches exceeded the reply cap"));
    }

    // A probe for a printer type must go unanswered.
    let foreign = probe_fixture("wprt:PrintDeviceType");
    match Request::parse(foreign.as_bytes()) {
        Ok(request) => {
            if answer(&request, &context).is_some() {
                return Err(String::from("a foreign-type probe was answered"));
            }
        }
        Err(_) => return Err(String::from("a foreign-type probe did not parse")),
    }

    // A resolve for someone else's endpoint must go unanswered.
    let other = resolve_fixture("urn:uuid:00000000-0000-0000-0000-000000000000");
    let request = Request::parse(other.as_bytes()).map_err(|refusal| refusal.to_string())?;
    if answer(&request, &context).is_some() {
        return Err(String::from("a resolve for another endpoint was answered"));
    }
    let mine = resolve_fixture("urn:uuid:d1d0f0c8-6d18-4c3b-9c55-1d2a0e7b3f44");
    let request = Request::parse(mine.as_bytes()).map_err(|refusal| refusal.to_string())?;
    if answer(&request, &context).is_none() {
        return Err(String::from("a resolve for this endpoint was not answered"));
    }

    // The body and the action must agree.
    let mismatched = probe_fixture("wsdp:Device").replace(wsd::ACT_PROBE, wsd::ACT_RESOLVE);
    if Request::parse(mismatched.as_bytes()) != Err(wsd::Refusal::ActionBodyMismatch) {
        return Err(String::from("an action/body mismatch was accepted"));
    }

    // LLMNR: a query for the NetBIOS name is answered, and the answer is a
    // function of the question alone.
    let query_bytes = llmnr_query(b"gt-ax11000", llmnr::TYPE_A, llmnr::CLASS_IN, 0);
    let query = llmnr::Query::parse(&query_bytes).map_err(|refusal| refusal.to_string())?;
    if !llmnr::is_authoritative(&query.name, &["GT-AX11000"], &[]) {
        return Err(String::from("the LLMNR authority check failed"));
    }
    let response = llmnr::build_response(
        &query,
        llmnr::choose_answer(query.qtype, Some([192, 168, 1, 1]), None, false),
    );
    if response.len() != query_bytes.len() + llmnr::ANSWER_LEN_A {
        return Err(String::from("the LLMNR answer is not exactly one A record"));
    }
    let padded = llmnr_query(b"gt-ax11000", llmnr::TYPE_A, llmnr::CLASS_IN, 128);
    match llmnr::Query::parse(&padded) {
        Ok(padded_query) => {
            let padded_response = llmnr::build_response(
                &padded_query,
                llmnr::choose_answer(padded_query.qtype, Some([192, 168, 1, 1]), None, false),
            );
            if padded_response != response {
                return Err(String::from("LLMNR padding changed the response"));
            }
        }
        Err(refusal) => return Err(format!("a padded LLMNR query was refused: {refusal}")),
    }
    if llmnr::Query::parse(query_bytes.get(..10).unwrap_or_default())
        != Err(llmnr::Refusal::BadLength)
    {
        return Err(String::from("a truncated LLMNR query was accepted"));
    }

    // The HTTP endpoint accepts only a POST to the endpoint UUID.
    let head = format!(
        "POST /{} HTTP/1.1\r\nHost: x\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: 5\r\n\r\nhello",
        identity.endpoint
    );
    match http::parse_header(head.as_bytes(), &identity.endpoint) {
        http::Progress::Header {
            content_length: 5, ..
        } => {}
        other => return Err(format!("the metadata POST was not framed: {other:?}")),
    }
    let wrong = head.replace(&identity.endpoint, "00000000-0000-0000-0000-000000000000");
    if http::parse_header(wrong.as_bytes(), &identity.endpoint)
        != http::Progress::Failed(http::Status::NotFound)
    {
        return Err(String::from("a POST to another endpoint was accepted"));
    }
    Ok(())
}

/// A Windows-shaped `Probe` carrying one `wsd:Types` token.
#[must_use]
pub fn probe_fixture(types: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsa=\"{wsa}\" xmlns:wsd=\"{wsd}\" xmlns:wsdp=\"{wsdp}\" xmlns:pub=\"{pub_ns}\">\
         <soap:Header><wsa:To>{to}</wsa:To><wsa:Action>{action}</wsa:Action>\
         <wsa:MessageID>urn:uuid:11112222-3333-4444-5555-666677778888</wsa:MessageID>\
         </soap:Header><soap:Body><wsd:Probe><wsd:Types>{types}</wsd:Types></wsd:Probe></soap:Body>\
         </soap:Envelope>",
        soap = xml::SOAP12_NS,
        wsa = xml::WSA_NS,
        wsd = xml::WSD_NS,
        wsdp = xml::WSDP_NS,
        pub_ns = xml::PUB_NS,
        to = wsd::TO_DISCOVERY,
        action = wsd::ACT_PROBE,
    )
}

/// A Windows-shaped `Resolve` for one endpoint reference address.
#[must_use]
pub fn resolve_fixture(address: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsa=\"{wsa}\" xmlns:wsd=\"{wsd}\">\
         <soap:Header><wsa:To>{to}</wsa:To><wsa:Action>{action}</wsa:Action>\
         <wsa:MessageID>urn:uuid:11112222-3333-4444-5555-666677778888</wsa:MessageID>\
         </soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference>\
         <wsa:Address>{address}</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body>\
         </soap:Envelope>",
        soap = xml::SOAP12_NS,
        wsa = xml::WSA_NS,
        wsd = xml::WSD_NS,
        to = wsd::TO_DISCOVERY,
        action = wsd::ACT_RESOLVE,
    )
}

/// A Windows-shaped WS-Transfer `Get` body.
#[must_use]
pub fn get_fixture(endpoint: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsa=\"{wsa}\" xmlns:wxt=\"{wxt}\">\
         <soap:Header><wsa:To>urn:uuid:{endpoint}</wsa:To><wsa:Action>{action}</wsa:Action>\
         <wsa:MessageID>urn:uuid:11112222-3333-4444-5555-666677778888</wsa:MessageID>\
         </soap:Header><soap:Body><wxt:Get /></soap:Body></soap:Envelope>",
        soap = xml::SOAP12_NS,
        wsa = xml::WSA_NS,
        wxt = xml::WXT_NS,
        action = wsd::ACT_GET,
    )
}

/// Builds an LLMNR query datagram for one single-label name, optionally
/// followed by `padding` bytes of junk that a conforming responder must not
/// reflect.
#[must_use]
pub fn llmnr_query(label: &[u8], qtype: u16, qclass: u16, padding: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xbeef_u16.to_be_bytes());
    out.push(0x00);
    out.push(0x00);
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    let length = u8::try_from(label.len()).unwrap_or(0);
    out.push(length);
    out.extend_from_slice(label);
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());
    out.extend(core::iter::repeat_n(0x41_u8, padding));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runtime_self_test_passes_on_the_host() {
        self_test().expect("self-test");
    }
}
