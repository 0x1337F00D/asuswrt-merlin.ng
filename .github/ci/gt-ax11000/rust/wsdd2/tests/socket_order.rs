//! Interface admission must happen before each listener acquires its port.
//! Only ephemeral loopback sockets are opened; an invalid interface name is
//! refused in userspace, before SO_BINDTODEVICE or multicast membership calls.

#[allow(dead_code)]
#[path = "../src/sys.rs"]
mod sys;

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};

const INVALID_INTERFACE: &str = "br\0invalid";

#[test]
fn tcp_v4_device_admission_precedes_port_bind() {
    check_tcp("127.0.0.1:0");
}

#[test]
fn tcp_v6_device_admission_precedes_port_bind() {
    check_tcp("[::1]:0");
}

fn check_tcp(address: &str) {
    let held = TcpListener::bind(address).expect("hold ephemeral loopback TCP port");
    let local = held.local_addr().unwrap();
    let error = sys::bind_tcp(local.port(), local.is_ipv6(), Some(INVALID_INTERFACE))
        .expect_err("invalid interface must win over occupied port");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{local}");
}

#[test]
fn multicast_v4_device_admission_precedes_port_bind() {
    check_multicast("127.0.0.1:0");
}

#[test]
fn multicast_v6_device_admission_precedes_port_bind() {
    check_multicast("[::1]:0");
}

fn check_multicast(address: &str) {
    let held = UdpSocket::bind(address).expect("hold ephemeral loopback UDP port");
    let local = held.local_addr().unwrap();
    let result = if local.is_ipv6() {
        sys::bind_multicast_v6(
            "ff02::c".parse::<Ipv6Addr>().unwrap(),
            local.port(),
            Some(INVALID_INTERFACE),
            0,
        )
    } else {
        sys::bind_multicast_v4(
            Ipv4Addr::new(239, 255, 255, 250),
            local.port(),
            Some(INVALID_INTERFACE),
            0,
        )
    };
    let error = result.expect_err("invalid interface must win over occupied port");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{local}");
}
