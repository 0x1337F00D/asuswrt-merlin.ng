//! `/usr/sbin/wsdd2`: the WS-Discovery and LLMNR responder this firmware runs
//! in place of the NETGEAR/Samba `wsdd2`.
//!
//! `release/src/router/rc/usb.c:6038-6076` starts it as
//! `/usr/sbin/wsdd2 -d -w -i <lan_ifname> -b sku:<productid>,serial:<mac>`
//! through `_eval(argv, NULL, 0, &pid)`, and `stop_wsdd()` matches the process
//! with `pids("wsdd2")` / `killall_tk("wsdd2")`.  The binary is therefore
//! named `wsdd2`, daemonises itself the way the vendor did, and speaks the
//! same messages on the same ports.
//!
//! Note what that argument vector means: `-w` selects WS-Discovery only, so
//! LLMNR is not served on this firmware at all.  It is implemented here
//! because `-l` and the default (neither `-l` nor `-w`) still select it.

#![forbid(unsafe_op_in_unsafe_fn)]

mod logging;
mod sys;

use logging::{Channel, Logger};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use sys::Readiness;
use wsdd2::budget::Budget;
use wsdd2::cli::{self, Options, Outcome};
use wsdd2::config;
use wsdd2::http::{self, Progress, Status};
use wsdd2::llmnr;
use wsdd2::wsd::{self, Identity, Request};
use wsdd2::{answer, ReplyContext, SELF_TEST_MARKER};

/// Preferred source of the stable endpoint UUID (`wsd.c:128`).
const MACHINE_ID_PATH: &str = "/etc/machine-id";
/// Fallback source of the endpoint UUID (`wsd.c:132`).
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
/// Where the vendor read the NetBIOS name and workgroup (`wsdd2.c:634`).
const SMB_CONF_PATH: &str = "/etc/smb.conf";
/// The kernel entropy pool, opened once and held for the life of the daemon.
const URANDOM_PATH: &str = "/dev/urandom";

/// How long the main loop blocks in `poll` before it re-checks for a signal.
const POLL_TIMEOUT_MS: i32 = 500;
/// Datagrams taken off one socket in a single readable wakeup.
///
/// Draining until `WouldBlock` puts no bound on receive-side work: a LAN
/// device that sends faster than the loop can read would keep the daemon
/// inside that one socket forever.  The socket stays readable, so `poll`
/// returns at once and nothing is lost.
const MAX_DATAGRAMS_PER_WAKEUP: usize = 32;
/// Metadata connections accepted in a single readable wakeup.
const MAX_CONNECTIONS_PER_WAKEUP: usize = 2;
/// Per-read timeout on a metadata connection.
const TCP_READ_TIMEOUT: Duration = Duration::from_millis(1_000);
/// Total time one metadata connection may occupy the daemon.
const TCP_DEADLINE: Duration = Duration::from_millis(2_000);
/// Largest WS-Discovery datagram accepted: one byte more than the scanner's
/// cap, so an oversized datagram is detected rather than silently truncated.
const WSD_BUFFER: usize = wsdd2::xml::MAX_DOCUMENT + 1;
/// Largest LLMNR datagram accepted, one byte over the protocol maximum.
const LLMNR_BUFFER: usize = llmnr::MAX_QUERY + 1;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let program = std::env::args()
        .next()
        .unwrap_or_else(|| String::from("wsdd2"));
    let program = program.rsplit('/').next().unwrap_or("wsdd2").to_owned();

    let options = match cli::parse(&arguments) {
        Outcome::Run(options) => *options,
        Outcome::Help => {
            print!("{}", cli::usage(&program));
            return ExitCode::SUCCESS;
        }
        Outcome::SelfTest => {
            return match wsdd2::self_test() {
                Ok(()) => {
                    println!("{SELF_TEST_MARKER}");
                    ExitCode::SUCCESS
                }
                Err(reason) => {
                    eprintln!("wsdd2: self-test failed: {reason}");
                    ExitCode::FAILURE
                }
            };
        }
        Outcome::Reject(reason) => {
            eprintln!("wsdd2: {reason}");
            eprint!("{}", cli::usage(&program));
            return ExitCode::FAILURE;
        }
    };

    let (identity, names) = match build_identity(&options) {
        Ok(built) => built,
        Err(reason) => {
            eprintln!("wsdd2: {reason}");
            return ExitCode::FAILURE;
        }
    };

    if options.daemon {
        if let Err(error) = sys::daemonize() {
            eprintln!("wsdd2: cannot daemonise: {error}");
            return ExitCode::FAILURE;
        }
    }
    sys::install_signal_handlers();

    let logger = Logger::new(options.llmnr_debug, options.wsd_debug, !options.daemon);
    logger.notice("starting.");
    let mut counter = wsd::MessageCounter::default();
    let mut random = Random::new();
    let mut status = ExitCode::SUCCESS;
    loop {
        match serve(
            &options,
            &identity,
            &names,
            &logger,
            &mut counter,
            &mut random,
        ) {
            Ok(Exit::Restart) => {
                logger.notice("restarting service.");
                continue;
            }
            Ok(Exit::Terminate) => break,
            Err(reason) => {
                logger.warning(&format!("terminating: {reason}"));
                status = ExitCode::FAILURE;
                break;
            }
        }
    }
    logger.notice("terminating.");
    status
}

/// Why the service loop returned.
enum Exit {
    /// `SIGHUP`: close everything, announce `Bye`, then re-open and say
    /// `Hello` again (`wsdd2.c:1090-1093`).
    Restart,
    /// `SIGINT` or `SIGTERM`.
    Terminate,
}

/// The names this daemon answers to.
struct Names {
    hostname: String,
    netbios_name: String,
    host_aliases: String,
    netbios_aliases: String,
}

/// Reads `/etc/smb.conf`, the host name and the endpoint UUID.
///
/// `wsdd2.c:734-757` (`init_sysinfo`) is the model.  The one behavioural
/// difference is that a missing or unusable endpoint UUID is fatal here,
/// where the vendor started, failed inside `wsd_init` and then ran with no
/// WS-Discovery endpoint at all while `rc` believed the service was up.
fn build_identity(options: &Options) -> Result<(Identity, Names), String> {
    let hostname = options
        .hostname
        .clone()
        .or_else(|| sys::hostname().and_then(|raw| config::short_hostname(&raw)))
        .ok_or("cannot determine a usable host name")?;
    let smb_conf = std::fs::read(SMB_CONF_PATH).unwrap_or_default();
    let netbios_name = options
        .netbios_name
        .clone()
        .or_else(|| config::smb_parameter(&smb_conf, "netbios name"))
        .unwrap_or_else(|| hostname.clone());
    let workgroup = options
        .workgroup
        .clone()
        .or_else(|| config::smb_parameter(&smb_conf, "workgroup"))
        .unwrap_or_else(|| String::from("WORKGROUP"));
    let host_aliases =
        config::smb_parameter(&smb_conf, "additional dns hostnames").unwrap_or_default();
    let netbios_aliases = config::smb_parameter(&smb_conf, "netbios aliases").unwrap_or_default();

    let endpoint = read_endpoint_uuid().ok_or(
        "cannot read a usable UUID from /etc/machine-id or /proc/sys/kernel/random/boot_id",
    )?;
    let mut random = Random::new();
    let names = Names {
        hostname,
        netbios_name: netbios_name.clone(),
        host_aliases,
        netbios_aliases,
    };
    let identity = Identity {
        endpoint,
        sequence: random.uuid(),
        instance: sys::now_unix_seconds(),
        netbios_name,
        workgroup,
        boot: options.boot.clone(),
    };
    Ok((identity, names))
}

fn read_endpoint_uuid() -> Option<String> {
    for path in [MACHINE_ID_PATH, BOOT_ID_PATH] {
        if let Ok(contents) = std::fs::read(path) {
            if let Some(uuid) = config::parse_endpoint_uuid(&contents) {
                return Some(uuid);
            }
        }
    }
    None
}

/// One open service socket.
enum Endpoint {
    /// A WS-Discovery multicast socket and the group it announces on.
    Discovery {
        socket: UdpSocket,
        group: SocketAddr,
        v6: bool,
    },
    /// The WS-Transfer metadata listener.
    Metadata { listener: TcpListener },
    /// An LLMNR multicast socket.
    Llmnr { socket: UdpSocket, v6: bool },
}

impl Endpoint {
    fn descriptor(&self) -> RawFd {
        match self {
            Self::Discovery { socket, .. } | Self::Llmnr { socket, .. } => socket.as_raw_fd(),
            Self::Metadata { listener } => listener.as_raw_fd(),
        }
    }
}

/// Opens every endpoint, announces `Hello`, runs until a signal, then
/// announces `Bye`.
fn serve(
    options: &Options,
    identity: &Identity,
    names: &Names,
    logger: &Logger,
    counter: &mut wsd::MessageCounter,
    random: &mut Random,
) -> Result<Exit, String> {
    let interface = options.interface.as_deref();
    let index = match interface {
        Some(name) => sys::if_index(name)
            .map_err(|error| format!("bad interface '{}': {error}", cli::sanitise(name)))?,
        None => 0,
    };

    let mut endpoints = open_endpoints(options, interface, index, logger);
    if endpoints.is_empty() {
        return Err(String::from("no service endpoint could be opened"));
    }

    let probe_v4 = if options.families.v4 {
        sys::route_probe_socket(false, interface).ok()
    } else {
        None
    };
    let probe_v6 = if options.families.v6 {
        sys::route_probe_socket(true, interface).ok()
    } else {
        None
    };

    let mut state = State {
        identity,
        names,
        logger,
        counter,
        random,
        probe_v4,
        probe_v6,
        wsd_budget: Budget::default(),
        llmnr_budget: Budget::default(),
    };

    for endpoint in &endpoints {
        if let Endpoint::Discovery { socket, group, .. } = endpoint {
            state.announce(socket, *group, true);
        }
    }

    let exit = loop {
        let descriptors: Vec<RawFd> = endpoints
            .iter()
            .map(Endpoint::descriptor)
            .collect::<Vec<_>>();
        let readiness = match sys::poll_readable(&descriptors, POLL_TIMEOUT_MS) {
            Ok(readiness) => readiness,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Vec::new(),
            Err(error) => {
                logger.warning(&format!("poll failed: {error}"));
                break Exit::Terminate;
            }
        };
        match sys::take_pending_signal() {
            0 => {}
            libc_hup if libc_hup == libc::SIGHUP => break Exit::Restart,
            _ => break Exit::Terminate,
        }
        let mut failed: Vec<usize> = Vec::new();
        for (position, endpoint) in endpoints.iter().enumerate() {
            match readiness.get(position) {
                Some(Readiness::Readable) => state.service(endpoint),
                Some(Readiness::Errored) => {
                    logger.warning("a service socket failed; dropping it");
                    failed.push(position);
                }
                _ => {}
            }
        }
        if !failed.is_empty() {
            let mut position = 0_usize;
            endpoints.retain(|_| {
                let keep = !failed.contains(&position);
                position = position.saturating_add(1);
                keep
            });
            if endpoints.is_empty() {
                break Exit::Terminate;
            }
        }
    };

    for endpoint in &endpoints {
        if let Endpoint::Discovery { socket, group, .. } = endpoint {
            state.announce(socket, *group, false);
        }
    }
    Ok(exit)
}

fn open_endpoints(
    options: &Options,
    interface: Option<&str>,
    index: u32,
    logger: &Logger,
) -> Vec<Endpoint> {
    let mut endpoints = Vec::new();
    let open_multicast = |group: IpAddr, port: u16, label: &str| -> Option<UdpSocket> {
        let opened = match group {
            IpAddr::V4(group) => sys::bind_multicast_v4(group, port, interface, index),
            IpAddr::V6(group) => sys::bind_multicast_v6(group, port, interface, index),
        };
        match opened {
            Ok(socket) => match socket.set_nonblocking(true) {
                Ok(()) => Some(socket),
                Err(error) => {
                    logger.warning(&format!("{label}: cannot set non-blocking: {error}"));
                    None
                }
            },
            Err(error) => {
                logger.warning(&format!("{label}: {error}"));
                None
            }
        }
    };

    if options.protocols.wsd && options.transports.udp {
        if options.families.v4 {
            if let Ok(group) = wsd::WSD_MCAST_V4.parse::<Ipv4Addr>() {
                if let Some(socket) =
                    open_multicast(IpAddr::V4(group), wsd::WSD_PORT, "wsdd-mcast-v4")
                {
                    endpoints.push(Endpoint::Discovery {
                        socket,
                        group: SocketAddr::new(IpAddr::V4(group), wsd::WSD_PORT),
                        v6: false,
                    });
                }
            }
        }
        if options.families.v6 {
            if let Ok(group) = wsd::WSD_MCAST_V6.parse::<Ipv6Addr>() {
                if let Some(socket) =
                    open_multicast(IpAddr::V6(group), wsd::WSD_PORT, "wsdd-mcast-v6")
                {
                    endpoints.push(Endpoint::Discovery {
                        socket,
                        group: SocketAddr::new(IpAddr::V6(group), wsd::WSD_PORT),
                        v6: true,
                    });
                }
            }
        }
    }
    if options.protocols.wsd && options.transports.tcp {
        for v6 in [false, true] {
            if (v6 && !options.families.v6) || (!v6 && !options.families.v4) {
                continue;
            }
            match sys::bind_tcp(wsd::WSD_PORT, v6, interface) {
                Ok(listener) => match listener.set_nonblocking(true) {
                    Ok(()) => endpoints.push(Endpoint::Metadata { listener }),
                    Err(error) => {
                        logger.warning(&format!("wsdd-http: cannot set non-blocking: {error}"));
                    }
                },
                Err(error) => logger.warning(&format!("wsdd-http: {error}")),
            }
        }
    }
    if options.protocols.llmnr && options.transports.udp {
        if options.families.v4 {
            if let Ok(group) = llmnr::LLMNR_MCAST_V4.parse::<Ipv4Addr>() {
                if let Some(socket) =
                    open_multicast(IpAddr::V4(group), llmnr::LLMNR_PORT, "llmnr-mcast-v4")
                {
                    endpoints.push(Endpoint::Llmnr { socket, v6: false });
                }
            }
        }
        if options.families.v6 {
            if let Ok(group) = llmnr::LLMNR_MCAST_V6.parse::<Ipv6Addr>() {
                if let Some(socket) =
                    open_multicast(IpAddr::V6(group), llmnr::LLMNR_PORT, "llmnr-mcast-v6")
                {
                    endpoints.push(Endpoint::Llmnr { socket, v6: true });
                }
            }
        }
    }
    endpoints
}

/// Everything the request handlers mutate.
struct State<'a> {
    identity: &'a Identity,
    names: &'a Names,
    logger: &'a Logger,
    counter: &'a mut wsd::MessageCounter,
    random: &'a mut Random,
    probe_v4: Option<UdpSocket>,
    probe_v6: Option<UdpSocket>,
    wsd_budget: Budget,
    llmnr_budget: Budget,
}

impl State<'_> {
    fn service(&mut self, endpoint: &Endpoint) {
        match endpoint {
            Endpoint::Discovery { socket, v6, .. } => self.serve_discovery(socket, *v6),
            Endpoint::Llmnr { socket, v6 } => self.serve_llmnr(socket, *v6),
            Endpoint::Metadata { listener } => self.serve_metadata(listener),
        }
    }

    /// Announces `Hello` (`wsd.c:625`) or `Bye` (`wsd.c:651`) on one group.
    fn announce(&mut self, socket: &UdpSocket, group: SocketAddr, hello: bool) {
        let message_id = self.random.uuid();
        let number = self.counter.peek();
        let built = if hello {
            wsd::hello(self.identity, &message_id, number)
        } else {
            wsd::bye(self.identity, &message_id, number)
        };
        let Some(message) = built else {
            self.logger
                .warning("an announcement exceeded the reply cap");
            return;
        };
        match socket.send_to(message.as_bytes(), group) {
            Ok(_) => {
                self.counter.advance();
            }
            Err(error) => self
                .logger
                .warning(&format!("cannot announce on {group}: {error}")),
        }
    }

    fn serve_discovery(&mut self, socket: &UdpSocket, v6: bool) {
        let mut buffer = [0_u8; WSD_BUFFER];
        for _ in 0..MAX_DATAGRAMS_PER_WAKEUP {
            let (length, peer) = match socket.recv_from(&mut buffer) {
                Ok(received) => received,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.logger
                        .warning(&format!("wsdd receive failed: {error}"));
                    return;
                }
            };
            let Some(datagram) = buffer.get(..length) else {
                continue;
            };
            if length > wsdd2::xml::MAX_DOCUMENT {
                self.logger.debug(
                    Channel::Wsd,
                    1,
                    &format!("dropped an oversized datagram from {}", peer.ip()),
                );
                continue;
            }
            let request = match Request::parse(datagram) {
                Ok(request) => request,
                Err(refusal) => {
                    // No budget is charged: a malformed datagram must not be
                    // able to spend a legitimate client's share.
                    self.logger.debug(
                        Channel::Wsd,
                        1,
                        &format!("refused a datagram from {}: {refusal}", peer.ip()),
                    );
                    continue;
                }
            };
            let Some(host) = self.advertised_host(peer, v6) else {
                self.logger.debug(
                    Channel::Wsd,
                    1,
                    &format!("no local address faces {}", peer.ip()),
                );
                continue;
            };
            let message_id = self.random.uuid();
            let context = ReplyContext {
                identity: self.identity,
                message_id: &message_id,
                number: self.counter.peek(),
                host: &host,
                port: wsd::WSD_PORT,
            };
            let Some(message) = answer(&request, &context) else {
                self.logger
                    .debug(Channel::Wsd, 2, &format!("nothing to say to {}", peer.ip()));
                continue;
            };
            if !self.wsd_budget.allow(sys::now_unix()) {
                self.logger
                    .debug(Channel::Wsd, 1, "reply budget exhausted; dropping a probe");
                continue;
            }
            match socket.send_to(message.as_bytes(), peer) {
                Ok(_) => {
                    self.counter.advance();
                }
                Err(error) => self
                    .logger
                    .warning(&format!("cannot answer {}: {error}", peer.ip())),
            }
        }
    }

    fn serve_llmnr(&mut self, socket: &UdpSocket, v6: bool) {
        let mut buffer = [0_u8; LLMNR_BUFFER];
        for _ in 0..MAX_DATAGRAMS_PER_WAKEUP {
            let (length, peer) = match socket.recv_from(&mut buffer) {
                Ok(received) => received,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.logger
                        .warning(&format!("llmnr receive failed: {error}"));
                    return;
                }
            };
            let Some(datagram) = buffer.get(..length) else {
                continue;
            };
            let query = match llmnr::Query::parse(datagram) {
                Ok(query) => query,
                Err(refusal) => {
                    self.logger.debug(
                        Channel::Llmnr,
                        1,
                        &format!("refused a query from {}: {refusal}", peer.ip()),
                    );
                    continue;
                }
            };
            if !llmnr::is_authoritative(
                &query.name,
                &[&self.names.netbios_name, &self.names.hostname],
                &[&self.names.host_aliases, &self.names.netbios_aliases],
            ) {
                self.logger.debug(
                    Channel::Llmnr,
                    2,
                    &format!("not authoritative for {}", cli::sanitise(&query.name)),
                );
                continue;
            }
            let Some(local) = self.local_address(peer, v6) else {
                continue;
            };
            let (v4_address, v6_address) = match local {
                IpAddr::V4(address) => (Some(address.octets()), None),
                IpAddr::V6(address) => (None, Some(address.octets())),
            };
            let answer = llmnr::choose_answer(query.qtype, v4_address, v6_address, v6);
            let response = llmnr::build_response(&query, answer);
            if !self.llmnr_budget.allow(sys::now_unix()) {
                self.logger.debug(
                    Channel::Llmnr,
                    1,
                    "reply budget exhausted; dropping a query",
                );
                continue;
            }
            if let Err(error) = socket.send_to(&response, peer) {
                self.logger
                    .warning(&format!("cannot answer {}: {error}", peer.ip()));
            }
        }
    }

    fn serve_metadata(&mut self, listener: &TcpListener) {
        for _ in 0..MAX_CONNECTIONS_PER_WAKEUP {
            let (stream, peer) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.logger.warning(&format!("accept failed: {error}"));
                    return;
                }
            };
            self.handle_metadata(stream, peer);
        }
    }

    fn handle_metadata(&mut self, mut stream: TcpStream, peer: SocketAddr) {
        let deadline = Instant::now().checked_add(TCP_DEADLINE);
        let _ = stream.set_read_timeout(Some(TCP_READ_TIMEOUT));
        let _ = stream.set_write_timeout(Some(TCP_READ_TIMEOUT));
        let mut buffer: Vec<u8> = Vec::new();
        let mut chunk = [0_u8; 1024];

        let framing = loop {
            match http::parse_header(&buffer, &self.identity.endpoint) {
                Progress::Incomplete => {}
                other => break other,
            }
            if !before(deadline) {
                return;
            }
            match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(read) => match chunk.get(..read) {
                    Some(bytes) => buffer.extend_from_slice(bytes),
                    None => return,
                },
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
            if buffer.len() > http::MAX_REQUEST {
                self.refuse_metadata(&mut stream, Status::TooLarge);
                return;
            }
        };

        let (body_offset, content_length) = match framing {
            Progress::Header {
                body_offset,
                content_length,
            } => (body_offset, content_length),
            Progress::Failed(status) => {
                self.logger.debug(
                    Channel::Wsd,
                    1,
                    &format!("refused a metadata request from {}", peer.ip()),
                );
                self.refuse_metadata(&mut stream, status);
                return;
            }
            Progress::Incomplete => return,
        };

        let Some(total) = body_offset.checked_add(content_length) else {
            return;
        };
        while buffer.len() < total {
            if !before(deadline) {
                return;
            }
            match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(read) => match chunk.get(..read) {
                    Some(bytes) => buffer.extend_from_slice(bytes),
                    None => return,
                },
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
            if buffer.len() > http::MAX_REQUEST {
                self.refuse_metadata(&mut stream, Status::TooLarge);
                return;
            }
        }

        let Some(body) = buffer.get(body_offset..total) else {
            return;
        };
        let request = match Request::parse(body) {
            Ok(request) => request,
            Err(refusal) => {
                self.logger.debug(
                    Channel::Wsd,
                    1,
                    &format!("refused a metadata body from {}: {refusal}", peer.ip()),
                );
                self.refuse_metadata(&mut stream, Status::BadRequest);
                return;
            }
        };
        if request.body != wsd::Body::Get
            || !wsdd2::endpoint_matches(&request.to, &self.identity.endpoint)
        {
            self.refuse_metadata(&mut stream, Status::BadRequest);
            return;
        }
        let message_id = self.random.uuid();
        let context = ReplyContext {
            identity: self.identity,
            message_id: &message_id,
            number: self.counter.peek(),
            host: "",
            port: wsd::WSD_PORT,
        };
        let Some(message) = answer(&request, &context) else {
            self.refuse_metadata(&mut stream, Status::BadRequest);
            return;
        };
        if !self.wsd_budget.allow(sys::now_unix()) {
            self.logger.debug(
                Channel::Wsd,
                1,
                "reply budget exhausted; dropping a metadata request",
            );
            return;
        }
        let header = http::response_header(Status::Ok, &self.date(), message.len());
        if stream.write_all(header.as_bytes()).is_ok()
            && stream.write_all(message.as_bytes()).is_ok()
        {
            self.counter.advance();
        }
        let _ = stream.flush();
    }

    /// Sends a status line with an empty body.
    ///
    /// The vendor answered a refused request with the status line *and* a
    /// ~700-byte SOAP fault whose text echoed its own internal error string
    /// (`wsd.c:1114-1119`).  That is a larger reply to a worse request, so no
    /// fault body is generated here.
    fn refuse_metadata(&mut self, stream: &mut TcpStream, status: Status) {
        if !self.wsd_budget.allow(sys::now_unix()) {
            return;
        }
        let header = http::response_header(status, &self.date(), 0);
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.flush();
    }

    fn date(&self) -> String {
        http::http_date(sys::now_unix_seconds())
    }

    /// The local address the kernel would use to reach `peer`, or `None` when
    /// no route through the bound interface exists.
    fn local_address(&self, peer: SocketAddr, v6: bool) -> Option<IpAddr> {
        let probe = if v6 {
            self.probe_v6.as_ref()
        } else {
            self.probe_v4.as_ref()
        }?;
        if peer.is_ipv6() != v6 {
            return None;
        }
        probe.connect(peer).ok()?;
        let local = probe.local_addr().ok()?.ip();
        match local {
            IpAddr::V4(address) if address.is_unspecified() => None,
            IpAddr::V6(address) if address.is_unspecified() => None,
            address => Some(address),
        }
    }

    /// The host part of the advertised `wsd:XAddrs`.
    ///
    /// `ip2uri` (`wsdd2.c:234-249`) publishes a literal IPv4 address but
    /// substitutes the host name for an IPv6 address, because Windows 7 did
    /// not accept the `[x::x]` form.  That is reproduced.
    fn advertised_host(&self, peer: SocketAddr, v6: bool) -> Option<String> {
        let local = self.local_address(peer, v6)?;
        match local {
            IpAddr::V4(address) => Some(address.to_string()),
            IpAddr::V6(_) => {
                if self.names.hostname.is_empty() {
                    None
                } else {
                    Some(self.names.hostname.clone())
                }
            }
        }
    }
}

fn before(deadline: Option<Instant>) -> bool {
    match deadline {
        Some(deadline) => Instant::now() < deadline,
        None => false,
    }
}

/// Source of the UUIDs this daemon publishes.
///
/// The vendor seeded `srand48` from the endpoint UUID and the wall clock
/// (`wsd.c:89-106`), so its sequence identifier and every message id were
/// derivable by anyone who had seen one `Hello`.  These come from
/// `/dev/urandom` through a file held open for the life of the daemon; the
/// xorshift fallback exists only for the window before `/dev` is mounted on a
/// cold boot.
struct Random {
    urandom: Option<File>,
    state: u64,
}

impl Random {
    fn new() -> Self {
        Self {
            urandom: File::open(URANDOM_PATH).ok(),
            state: sys::now_unix_seconds()
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(std::process::id().into())
                | 1,
        }
    }

    fn uuid(&mut self) -> String {
        let mut bytes = [0_u8; 16];
        let filled = match &self.urandom {
            Some(file) => {
                let mut handle = file;
                handle.read_exact(&mut bytes).is_ok()
            }
            None => false,
        };
        if !filled {
            for chunk in bytes.chunks_mut(8) {
                let value = self.next_u64().to_le_bytes();
                for (slot, byte) in chunk.iter_mut().zip(value.iter()) {
                    *slot = *byte;
                }
            }
        }
        // RFC 4122 version 4, variant 1.
        if let Some(slot) = bytes.get_mut(6) {
            *slot = (*slot & 0x0f) | 0x40;
        }
        if let Some(slot) = bytes.get_mut(8) {
            *slot = (*slot & 0x3f) | 0x80;
        }
        config::format_uuid(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value | 1;
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_uuids_are_canonical_distinct_and_version_four() {
        let mut random = Random::new();
        let first = random.uuid();
        let second = random.uuid();
        assert_ne!(first, second);
        for uuid in [&first, &second] {
            assert_eq!(
                config::parse_endpoint_uuid(uuid.as_bytes()).as_deref(),
                Some(uuid.as_str())
            );
            assert_eq!(uuid.as_bytes().get(14), Some(&b'4'));
            assert!(matches!(
                uuid.as_bytes().get(19),
                Some(b'8' | b'9' | b'a' | b'b')
            ));
        }
    }

    #[test]
    fn the_xorshift_fallback_still_produces_usable_uuids() {
        // The window before /dev is mounted on a cold boot.
        let mut random = Random {
            urandom: None,
            state: 0x9e37_79b9_7f4a_7c15,
        };
        let first = random.uuid();
        let second = random.uuid();
        assert_ne!(first, second);
        assert_eq!(
            config::parse_endpoint_uuid(first.as_bytes()).as_deref(),
            Some(first.as_str())
        );
    }

    #[test]
    fn a_discarding_logger_swallows_every_channel() {
        let logger = Logger::discard();
        logger.notice("notice");
        logger.warning("warning\u{1b}[2J");
        logger.debug(Channel::Wsd, 1, "debug");
        logger.debug(Channel::Llmnr, 1, "debug");
    }

    #[test]
    fn a_deadline_that_has_passed_stops_a_metadata_read() {
        assert!(!before(None));
        assert!(!before(Instant::now().checked_sub(Duration::from_secs(1))));
        assert!(before(Instant::now().checked_add(Duration::from_secs(1))));
    }
}
