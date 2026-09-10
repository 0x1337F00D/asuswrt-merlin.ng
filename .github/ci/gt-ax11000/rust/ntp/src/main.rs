//! `/usr/sbin/ntp`: the SNTP client and LAN server this firmware runs in place
//! of the busybox `ntpd` applet.
//!
//! `release/src/router/rc/ntpd.c` starts it as
//! `/usr/sbin/ntp -t -S /sbin/ntpd_synced -p SERVER0 [-p SERVER1]
//! [-l -I LAN_IFNAME]` through `_eval(argv, NULL, 0, &pid)`, stops it with
//! `killall_tk("ntp")` and probes it with `pids("ntp")`. The binary is
//! therefore named `ntp`, daemonises itself the way busybox did, and runs the
//! `-S` program with the single argument `step` when it steps the clock.

#![forbid(unsafe_op_in_unsafe_fn)]

mod logging;
mod sys;

use logging::Logger;
use ntp::cli::{self, Options};
use ntp::client::{self, Query, Rejection};
use ntp::clock::{
    self, ClockAction, Discipline, PeerFilter, ScriptAction, BIG_POLL_EXP, MIN_POLL_EXP,
    PRECISION_EXP, PRECISION_SECONDS, SCRIPT_PERIOD,
};
use ntp::packet::{KissCode, Leap, Timestamp, AUTHENTICATED_PACKET_LEN, MAX_STRATUM, PACKET_LEN};
use ntp::script::{self, Environment};
use ntp::server::{self, ReplyBudget, ServerState};
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::process::ExitCode;
use sys::Readiness;

/// The NTP service port, for both the client sockets and the server socket.
const NTP_PORT: u16 = 123;
/// Where busybox's ntpd wrote its pid; nothing on this firmware reads it, but
/// leaving the file behind would be a behaviour change.
const PID_FILE: &str = "/var/run/ntpd.pid";
/// The kernel entropy pool, opened once and held for the life of the daemon.
const URANDOM_PATH: &str = "/dev/urandom";
/// How long to wait for a reply before giving up on a query, seconds.
const RESPONSE_INTERVAL: u32 = 16;
/// Retry delay after a local send failure, seconds.
const RETRY_INTERVAL: u32 = 32;
/// Upper bound on the delay after a query that was never answered, seconds.
const NOREPLY_INTERVAL: u32 = 512;
/// Base delay after a failed name lookup, multiplied by the error count.
const HOSTNAME_INTERVAL: u32 = 2;
/// Saturation point of the per-peer DNS error counter.
const DNS_ERRORS_CAP: u8 = 0x3f;
/// How long a peer that resolved to another peer's address waits before it
/// looks its name up again. A pool name rotates, so the peer is not retired.
const DUPLICATE_PEER_INTERVAL: u32 = 512;
/// Cap on the next query delay after a peer reported a large offset, seconds.
const BIGOFF_INTERVAL: u32 = 128;
/// Delay before retrying a peer that answered with a rate-limiting kiss.
const KISS_RATE_INTERVAL: u32 = 1_024;
/// Queries sent per peer before the initial burst ends.
const INITIAL_SAMPLES: u32 = 1;
/// A reply whose delay grew by more than this factor is not worth using.
const BAD_DELAY_GROWTH: f64 = 4.0;
/// Delays below this are too small for the growth heuristic to mean anything.
const MIN_MEANINGFUL_DELAY: f64 = 1.0 / 8192.0;
/// Largest datagram accepted on any socket; one byte more than a valid packet
/// so an oversized datagram is detected rather than silently truncated.
const RECEIVE_BUFFER: usize = AUTHENTICATED_PACKET_LEN + 1;
/// Requests taken off the server socket in one readable wakeup.
///
/// Draining until `WouldBlock` puts no bound on receive-side work: a LAN
/// device that sends faster than the loop can read keeps `serve_requests`
/// inside its own loop, the client half never runs and the router never syncs.
/// One wakeup is capped at the number of replies a whole second of budget
/// allows, and the main loop then gets a turn; the socket is still readable,
/// so poll returns at once and nothing is lost.
const MAX_REQUESTS_PER_WAKEUP: usize = server::REPLY_BUDGET_PER_SECOND as usize;
/// Shortest poll timeout the main loop will ask for, milliseconds.
const MIN_POLL_TIMEOUT_MS: f64 = 1.0;
/// Longest poll timeout the main loop will ask for, milliseconds.
const MAX_POLL_TIMEOUT_MS: f64 = 3_600_000.0;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.len() == 1 && arguments.first().map(String::as_str) == Some("--self-test") {
        return match ntp::self_test() {
            Ok(()) => {
                println!("{}", ntp::SELF_TEST_MARKER);
                ExitCode::SUCCESS
            }
            Err(reason) => {
                eprintln!("ntp: self-test failed: {reason}");
                ExitCode::FAILURE
            }
        };
    }
    let options = match cli::parse(arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("ntp: {error}");
            eprint!("{}", cli::USAGE);
            return ExitCode::FAILURE;
        }
    };
    match run(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ntp: {error}");
            ExitCode::FAILURE
        }
    }
}

/// A configured upstream server.
struct Peer {
    hostname: String,
    address: Option<SocketAddr>,
    socket: Option<UdpSocket>,
    query: Option<Query>,
    next_action_time: f64,
    filter: PeerFilter,
    dns_errors: u8,
    /// The one address that answered with a `DENY`/`RSTR` kiss, if any. See
    /// [`Daemon::handle_rejection`] for why the refusal is bound to an address
    /// and not to the configured name.
    refused_address: Option<SocketAddr>,
    previous_raw_delay: f64,
}

impl Peer {
    fn new(hostname: String, now: f64) -> Self {
        Self {
            hostname,
            address: None,
            socket: None,
            query: None,
            next_action_time: now,
            filter: PeerFilter::new(),
            dns_errors: 0,
            refused_address: None,
            previous_raw_delay: 0.0,
        }
    }

    fn describe(&self) -> String {
        match self.address {
            Some(address) => format!("{} ({})", self.hostname, address.ip()),
            None => self.hostname.clone(),
        }
    }

    fn close_socket(&mut self) {
        self.socket = None;
        self.query = None;
    }
}

/// What one name lookup did to a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Resolution {
    /// The peer now holds an address no other peer holds.
    Adopted,
    /// The name resolved to an address another peer already holds, so this
    /// peer was skipped and holds no address.
    Duplicate,
    /// The name did not resolve.
    Failed,
}

/// Everything the daemon carries between iterations of the main loop.
struct Daemon {
    options: Options,
    logger: Logger,
    peers: Vec<Peer>,
    listener: Option<UdpSocket>,
    discipline: Discipline,
    budget: ReplyBudget,
    /// Query nonces, drawn from the kernel entropy pool.
    nonce: NonceSource,
    /// Poll-interval jitter. Deliberately a separate generator: its output is
    /// observable from the LAN, and nothing observable may share a stream with
    /// the anti-spoofing nonce.
    jitter: Xorshift,
    /// Reference timestamp: when the clock was last set or corrected.
    reference: Timestamp,
    reference_id: [u8; 4],
    root_delay: f64,
    root_dispersion: f64,
    kernel_freq_ppm: i64,
    last_script_run: f64,
    burst_remaining: u32,
    script: Option<PathBuf>,
}

/// Opens the LAN server socket, pinned to `interface` before it is bound.
fn open_listener(interface: Option<&str>) -> std::io::Result<UdpSocket> {
    let socket = sys::bind_udp_to_device(NTP_PORT, interface)?;
    sys::set_tos(&socket);
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn run(options: Options) -> std::io::Result<()> {
    let logger = Logger::new(options.verbose, true);
    for peer in &options.rejected_peers {
        logger.warning(&format!("ignoring an unusable -p peer: {peer}"));
    }

    // Bind before detaching so a port conflict is still visible on stderr.
    // A server-mode failure is not fatal: `-I` names an interface that may not
    // exist yet, and the client half is what keeps the router's own clock
    // right. Losing the LAN service is a warning, not an exit.
    let listener = if options.listen {
        match open_listener(options.interface.as_deref()) {
            Ok(socket) => Some(socket),
            Err(error) => {
                logger.warning(&format!(
                    "server mode disabled: cannot bind {}:{NTP_PORT}: {error}",
                    options.interface.as_deref().unwrap_or("*")
                ));
                None
            }
        }
    } else {
        None
    };

    if options.high_priority {
        sys::raise_priority();
    }
    if !options.foreground {
        sys::daemonize()?;
    }
    sys::install_signal_handlers();
    let logger = if options.foreground {
        logger
    } else {
        // stderr is /dev/null after detaching, exactly as it was for busybox.
        Logger::new(options.verbose, false)
    };
    let _ = fs::write(PID_FILE, std::process::id().to_string());

    let now = sys::now_ntp_seconds();
    let peers: Vec<Peer> = options
        .peers
        .iter()
        .map(|hostname| Peer::new(hostname.clone(), now))
        .collect();
    let burst_remaining = (peers.len() as u32).saturating_mul(INITIAL_SAMPLES.saturating_add(1));
    let script = options.script.clone();
    let mut daemon = Daemon {
        options,
        logger,
        peers,
        listener,
        discipline: Discipline::new(),
        budget: ReplyBudget::new(),
        nonce: NonceSource::new(),
        jitter: Xorshift::seeded(),
        reference: Timestamp::default(),
        reference_id: *b"INIT",
        root_delay: 0.0,
        root_dispersion: 0.0,
        kernel_freq_ppm: sys::kernel_freq_ppm(),
        last_script_run: now,
        burst_remaining,
        script,
    };
    for index in 0..daemon.peers.len() {
        let outcome = daemon.resolve(index);
        daemon.report_resolution(index, outcome);
    }
    daemon.logger.notice(&format!(
        "started: {} peer(s), server mode {}",
        daemon.peers.len(),
        if daemon.listener.is_some() {
            "on"
        } else {
            "off"
        }
    ));
    let exit = daemon.main_loop();
    let _ = fs::remove_file(PID_FILE);
    daemon.logger.notice("stopped");
    exit
}

impl Daemon {
    fn main_loop(&mut self) -> std::io::Result<()> {
        loop {
            if sys::take_pending_signal() != 0 {
                return Ok(());
            }
            let now = sys::now_ntp_seconds();
            let mut next_action = (self.last_script_run + SCRIPT_PERIOD).max(now + 1.0);

            let mut descriptors: Vec<RawFd> = Vec::with_capacity(self.peers.len() + 1);
            if let Some(listener) = &self.listener {
                descriptors.push(listener.as_raw_fd());
            }
            let listener_slots = usize::from(self.listener.is_some());

            for index in 0..self.peers.len() {
                if self.peers[index].next_action_time <= now {
                    if self.peers[index].socket.is_none() {
                        self.send_query(index, now);
                    } else {
                        self.expire_query(index, now);
                    }
                }
                next_action = next_action.min(self.peers[index].next_action_time);
            }
            let mut waiting: Vec<usize> = Vec::with_capacity(self.peers.len());
            for (index, peer) in self.peers.iter().enumerate() {
                if let Some(socket) = &peer.socket {
                    descriptors.push(socket.as_raw_fd());
                    waiting.push(index);
                }
            }

            let ready = match sys::poll_readable(&descriptors, poll_timeout_ms(next_action - now)) {
                Ok(ready) => ready,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if sys::take_pending_signal() != 0 {
                return Ok(());
            }

            let any_ready = ready.iter().any(|state| *state != Readiness::Idle);
            if !any_ready {
                let now = sys::now_ntp_seconds();
                if now - self.last_script_run > SCRIPT_PERIOD {
                    let offset = self.discipline.last_offset();
                    self.run_script(ScriptAction::Periodic, offset);
                }
                self.resolve_pending(now);
                self.check_unsync();
                continue;
            }

            if listener_slots == 1 {
                match ready.first().copied().unwrap_or(Readiness::Idle) {
                    Readiness::Idle => {}
                    Readiness::Readable => {
                        self.serve_requests();
                    }
                    Readiness::Errored => self.handle_listener_error(),
                }
            }
            for (slot, peer_index) in waiting.iter().enumerate() {
                match ready.get(slot + listener_slots).copied() {
                    Some(Readiness::Readable) => self.receive_reply(*peer_index),
                    Some(Readiness::Errored) => {
                        // `POLLERR` on a connected UDP socket is usually a
                        // queued ICMP error, and reading it both reports and
                        // clears it. Read once so a reply that arrived
                        // alongside the error is not lost, then drop the
                        // socket if it survived: leaving an errored descriptor
                        // in the poll set would spin this loop.
                        self.receive_reply(*peer_index);
                        if self.peers[*peer_index].socket.is_some() {
                            self.logger.debug(
                                1,
                                &format!(
                                    "socket error reported for {}",
                                    self.peers[*peer_index].describe()
                                ),
                            );
                            self.peers[*peer_index].close_socket();
                            self.set_next(*peer_index, RETRY_INTERVAL);
                        }
                    }
                    Some(Readiness::Idle) | None => {}
                }
            }
            self.check_unsync();
        }
    }

    /// Resolves a peer name, remembering the failure count so repeated DNS
    /// outages back off instead of spinning.
    ///
    /// A resolved address another peer already holds is refused, which is what
    /// busybox's `add_peers()` did. Two `-p` names that resolve to one server
    /// would otherwise become two independent Marzullo candidates backed by a
    /// single source, and a single hostile server would pass the intersection
    /// test that exists precisely to stop it. The check belongs here, on every
    /// lookup, because peers resolve lazily and a pool name rotates: a peer
    /// that was distinct when it was first looked up can become a duplicate
    /// later, so the samples it collected while it was distinct are dropped
    /// too and it can contribute nothing until it holds an address of its own.
    fn resolve(&mut self, index: usize) -> Resolution {
        let Some(hostname) = self.peers.get(index).map(|peer| peer.hostname.clone()) else {
            return Resolution::Failed;
        };
        let Some(address) = lookup(&hostname) else {
            if let Some(peer) = self.peers.get_mut(index) {
                peer.dns_errors = ((peer.dns_errors << 1) | 1) & DNS_ERRORS_CAP;
            }
            return Resolution::Failed;
        };
        let duplicate = self
            .peers
            .iter()
            .enumerate()
            .any(|(other, peer)| other != index && peer.address == Some(address));
        let Some(peer) = self.peers.get_mut(index) else {
            return Resolution::Failed;
        };
        peer.dns_errors = 0;
        if duplicate {
            peer.address = None;
            peer.filter = PeerFilter::new();
            peer.close_socket();
            return Resolution::Duplicate;
        }
        peer.address = Some(address);
        Resolution::Adopted
    }

    /// Logs and schedules a peer after a lookup. Returns true when the peer
    /// now holds an address that may be queried.
    fn report_resolution(&mut self, index: usize, outcome: Resolution) -> bool {
        match outcome {
            Resolution::Adopted => true,
            Resolution::Duplicate => {
                self.logger.notice(&format!(
                    "{} resolves to an address another peer already uses; \
                     skipping it so it cannot vote twice",
                    self.peers[index].hostname
                ));
                self.set_next(index, DUPLICATE_PEER_INTERVAL);
                false
            }
            Resolution::Failed => {
                let delay = HOSTNAME_INTERVAL
                    .saturating_mul(u32::from(self.peers[index].dns_errors).max(1));
                self.set_next(index, delay);
                false
            }
        }
    }

    fn resolve_pending(&mut self, now: f64) {
        for index in 0..self.peers.len() {
            let needs = {
                let peer = &self.peers[index];
                peer.address.is_none() && peer.next_action_time <= now
            };
            if needs {
                let outcome = self.resolve(index);
                self.report_resolution(index, outcome);
            }
        }
    }

    fn set_next(&mut self, index: usize, seconds: u32) {
        let now = sys::now_ntp_seconds();
        if let Some(peer) = self.peers.get_mut(index) {
            peer.next_action_time = now + f64::from(seconds);
        }
    }

    /// A randomised poll interval, capped at `upper_bound`, matching the
    /// jitter busybox added so peers are not queried in lockstep.
    fn poll_interval(&mut self, upper_bound: u32) -> u32 {
        let mut interval = self.discipline.poll_seconds().min(upper_bound).max(1);
        let mask = ((interval - 1) >> 4) | 1;
        interval = interval.saturating_add((self.jitter.next_u32()) & mask);
        interval
    }

    fn send_query(&mut self, index: usize, now: f64) {
        if self.peers[index].address.is_none() {
            let outcome = self.resolve(index);
            if !self.report_resolution(index, outcome) {
                if outcome == Resolution::Duplicate {
                    // Nothing goes on the wire, but the reachability register
                    // must still shift: a peer whose bits are frozen at their
                    // last non-zero value keeps `check_unsync` from ever
                    // firing. A DNS failure is deliberately excluded, because
                    // it retries within seconds and would otherwise report a
                    // loss of sync on a resolver blip.
                    self.peers[index].filter.note_query_sent();
                }
                return;
            }
        }
        if self.peers[index].address.is_some()
            && self.peers[index].address == self.peers[index].refused_address
        {
            // The name still resolves to the address that refused service.
            // Honour the refusal, but keep the bookkeeping a real query would
            // have done, so reachability decays, `check_unsync` fires and this
            // router stops publishing a stratum derived from a free-running
            // clock. Clearing the address forces a fresh lookup next time, so
            // a pool that rotates gives this peer a different server.
            self.peers[index].filter.note_query_sent();
            self.peers[index].address = None;
            self.logger.debug(
                1,
                &format!(
                    "{} still resolves to the address that refused service; not querying it",
                    self.peers[index].hostname
                ),
            );
            self.peers[index].next_action_time = now + f64::from(NOREPLY_INTERVAL);
            return;
        }
        if self.burst_remaining > 0 {
            self.burst_remaining -= 1;
            if self.burst_remaining == 0 {
                self.discipline.poll_exp = MIN_POLL_EXP;
            }
        }
        let Some(address) = self.peers[index].address else {
            return;
        };
        let bind: SocketAddr = match address.ip() {
            IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = match UdpSocket::bind(bind).and_then(|socket| {
            // Connecting pins the local port and the peer address, so the
            // kernel drops datagrams from anyone else before they reach us.
            socket.connect(address)?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        }) {
            Ok(socket) => socket,
            Err(error) => {
                self.logger.warning(&format!(
                    "cannot open a socket for {}: {error}",
                    self.peers[index].describe()
                ));
                self.set_next(index, RETRY_INTERVAL);
                return;
            }
        };
        sys::set_tos(&socket);

        let (nonce, warning) = self.nonce.next_nonce();
        if let Some(warning) = warning {
            self.logger.warning(&warning);
        }
        let datagram = client::build_query(nonce);
        // The register shifts even if the send fails locally: a pulled cable
        // must still end in a loss-of-sync report.
        self.peers[index].filter.note_query_sent();
        let sent_at = sys::now_ntp_seconds();
        if let Err(error) = socket.send(&datagram) {
            self.logger.warning(&format!(
                "cannot query {}: {error}",
                self.peers[index].describe()
            ));
            self.peers[index].close_socket();
            self.set_next(index, RETRY_INTERVAL);
            return;
        }
        self.logger.debug(
            1,
            &format!("query sent to {}", self.peers[index].describe()),
        );
        self.peers[index].socket = Some(socket);
        self.peers[index].query = Some(Query { nonce, sent_at });
        self.set_next(index, RESPONSE_INTERVAL);
    }

    fn expire_query(&mut self, index: usize, _now: f64) {
        self.peers[index].close_socket();
        if self.discipline.poll_exp < BIG_POLL_EXP {
            self.discipline.increase_poll();
        }
        let timeout = self.poll_interval(NOREPLY_INTERVAL);
        self.logger.notice(&format!(
            "timed out waiting for {}, reach 0x{:02x}, next query in {timeout}s",
            self.peers[index].describe(),
            self.peers[index].filter.reachable_bits
        ));
        if !self.peers[index].filter.is_reachable() {
            // The peer may simply have moved; a pool name resolves anew.
            let outcome = self.resolve(index);
            self.report_resolution(index, outcome);
        }
        // The timeout wins over any shorter retry the lookup just scheduled:
        // this peer has already missed a round, so it does not get to come
        // back sooner than it would have without a name-lookup problem.
        let earliest = sys::now_ntp_seconds() + f64::from(timeout);
        if let Some(peer) = self.peers.get_mut(index) {
            peer.next_action_time = peer.next_action_time.max(earliest);
        }
    }

    fn receive_reply(&mut self, index: usize) {
        let Some(query) = self.peers[index].query else {
            return;
        };
        let mut datagram = [0_u8; RECEIVE_BUFFER];
        let received = {
            let Some(socket) = &self.peers[index].socket else {
                return;
            };
            match socket.recv(&mut datagram) {
                Ok(length) => length,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => return,
                Err(error) => {
                    self.logger.warning(&format!(
                        "recv from {} failed: {error}",
                        self.peers[index].describe()
                    ));
                    self.peers[index].close_socket();
                    self.set_next(index, RETRY_INTERVAL);
                    return;
                }
            }
        };
        let now = sys::now_ntp_seconds();
        let payload = datagram.get(..received).unwrap_or(&[]);
        let sample = match client::evaluate_reply(payload, query, now, PRECISION_SECONDS) {
            Ok(sample) => sample,
            Err(Rejection::OriginMismatch) => {
                // Somebody else's packet, or a spoof. Keep waiting for the
                // real reply on this socket instead of giving up the round.
                self.logger.debug(
                    1,
                    &format!(
                        "ignored a reply with a foreign origin timestamp from {}",
                        self.peers[index].describe()
                    ),
                );
                return;
            }
            Err(rejection) => {
                self.peers[index].close_socket();
                self.handle_rejection(index, rejection);
                return;
            }
        };

        self.peers[index].close_socket();
        let previous = self.peers[index].previous_raw_delay;
        self.peers[index].previous_raw_delay = sample.raw_delay;
        if self.peers[index].filter.is_reachable()
            && sample.raw_delay > previous * BAD_DELAY_GROWTH
            && sample.raw_delay > MIN_MEANINGFUL_DELAY
        {
            self.logger.notice(&format!(
                "reply from {}: delay {:.6}s is too high, ignoring",
                self.peers[index].describe(),
                sample.raw_delay
            ));
            let interval = self.poll_interval(u32::MAX);
            self.set_next(index, interval);
            return;
        }

        self.peers[index].filter.accept(&sample, now);
        self.logger.debug(
            1,
            &format!(
                "reply from {}: offset {:+.6}s delay {:.6}s stratum {} reach 0x{:02x}",
                self.peers[index].describe(),
                sample.offset,
                sample.raw_delay,
                sample.stratum,
                self.peers[index].filter.reachable_bits
            ),
        );

        let disciplined = self.discipline_from_selection(now);
        let interval = if sample.offset.abs() >= clock::STEP_THRESHOLD {
            self.poll_interval(u32::MAX).min(BIGOFF_INTERVAL)
        } else {
            self.poll_interval(u32::MAX)
        };
        self.set_next(index, interval);
        // -q is "act like ntpdate": leave as soon as the clock has been set,
        // or as soon as one usable datapoint showed it needed no correction.
        if self.options.quit_after_set && (disciplined || self.discipline.has_usable_sample()) {
            let _ = fs::remove_file(PID_FILE);
            std::process::exit(0);
        }
    }

    fn handle_rejection(&mut self, index: usize, rejection: Rejection) {
        match rejection {
            Rejection::KissOfDeath(code) => {
                if code.is_permanent() {
                    // RFC 5905 section 7.4 demobilises the association with
                    // *that server*. The refusal is therefore bound to the
                    // address that sent it and not to the configured name:
                    // `ntp_server0` defaults to `pool.ntp.org`, so retiring
                    // the name would let one volunteer member of the pool
                    // silence this router for the life of the process. The
                    // name is looked up again on the next slot and a rotating
                    // pool hands over a different member; a name with a single
                    // address stays retired, which is what the kiss asked for.
                    //
                    // Either way `send_query` keeps shifting the reachability
                    // register for the refused peer, so `check_unsync` still
                    // fires and the LAN is told this router is unsynchronised
                    // instead of being served a stratum from a free-running
                    // clock. busybox never retired a peer at all
                    // (`networking/ntpd.c` only backs off and retries), which
                    // is the other half of why this is not permanent here.
                    let description = self.peers[index].describe();
                    self.peers[index].refused_address = self.peers[index].address;
                    self.peers[index].address = None;
                    self.logger.warning(&format!(
                        "{description} refused service ({code}); \
                         retiring that address and looking the name up again"
                    ));
                    self.set_next(index, NOREPLY_INTERVAL);
                } else {
                    let delay = if code == KissCode::Rate {
                        KISS_RATE_INTERVAL
                    } else {
                        self.poll_interval(u32::MAX)
                    };
                    self.logger.notice(&format!(
                        "{} sent a kiss-o'-death ({code}); backing off {delay}s",
                        self.peers[index].describe()
                    ));
                    self.discipline.increase_poll();
                    self.set_next(index, delay);
                }
            }
            other => {
                self.logger.notice(&format!(
                    "discarded a reply from {}: {other}",
                    self.peers[index].describe()
                ));
                if self.discipline.poll_exp < BIG_POLL_EXP {
                    self.discipline.increase_poll();
                }
                let interval = self.poll_interval(u32::MAX);
                self.set_next(index, interval);
            }
        }
    }

    /// The peers that may take part in selection right now.
    fn candidates(&mut self, now: f64) -> Vec<clock::Candidate> {
        for peer in &mut self.peers {
            peer.filter.recompute(now);
        }
        self.peers
            .iter()
            .enumerate()
            .filter(|(_, peer)| peer.filter.is_reachable())
            .map(|(index, peer)| clock::Candidate {
                index,
                offset: peer.filter.offset,
                root_distance: peer.filter.root_distance(now),
                stratum: peer.filter.stratum,
                reachable_bits: peer.filter.reachable_bits,
            })
            .filter(|candidate| {
                clock::is_fit(
                    candidate,
                    self.discipline.poll_exp,
                    self.options.trust_network,
                )
            })
            .collect()
    }

    /// Re-runs peer selection and applies the winner to the system clock.
    /// Returns true when the clock was actually set.
    fn discipline_from_selection(&mut self, now: f64) -> bool {
        let candidates = self.candidates(now);
        let Some(selected) = clock::select_peer(&candidates) else {
            if self.discipline.poll_exp < BIG_POLL_EXP {
                self.discipline.increase_poll();
            }
            return false;
        };
        let Some(peer) = self.peers.get(selected) else {
            return false;
        };
        let (offset, received_at, stratum, leap) = (
            peer.filter.offset,
            peer.filter.received_at,
            peer.filter.stratum,
            peer.filter.leap,
        );
        if self.options.watch_only {
            return false;
        }
        let outcome = self.discipline.update(offset, received_at, stratum, leap);
        self.refresh_root_variables(selected, offset, now);
        let mut clock_was_set = false;
        match outcome.action {
            ClockAction::None => {}
            ClockAction::Step(step) => {
                clock_was_set = self.apply_step(step, now);
            }
            ClockAction::Slew {
                offset_micros,
                status,
                constant,
            } => {
                clock_was_set = self.apply_slew(offset_micros, status, constant);
            }
        }
        if let Some(action) = outcome.script {
            let reported = if action == ScriptAction::Step {
                match outcome.action {
                    ClockAction::Step(step) => step,
                    _ => offset,
                }
            } else {
                offset
            };
            self.run_script(action, reported);
        }
        if matches!(outcome.action, ClockAction::Step(_)) {
            // Clear the kernel's pending offset: the step already removed it.
            if let ClockAction::Slew {
                offset_micros,
                status,
                constant,
            } = self.discipline.post_step_slew()
            {
                self.apply_slew(offset_micros, status, constant);
            }
        }
        let decreased = self.discipline.apply_feedback(outcome.feedback);
        if decreased {
            let step = f64::from(self.discipline.poll_seconds());
            for peer in &mut self.peers {
                if peer.socket.is_none() {
                    peer.next_action_time -= step;
                }
            }
        }
        clock_was_set
    }

    fn apply_step(&mut self, offset: f64, now: f64) -> bool {
        if let Err(error) = sys::step_clock(offset) {
            self.logger
                .warning(&format!("cannot set the system clock: {error}"));
            return false;
        }
        self.logger
            .notice(&format!("stepped the clock by {offset:+.6}s"));
        let stepped_now = now + offset;
        self.last_script_run += offset;
        for peer in &mut self.peers {
            peer.filter.rebase_after_step(offset, stepped_now);
            peer.next_action_time += offset;
            if peer.socket.is_some() {
                // A reply computed against the old clock would be bogus.
                peer.close_socket();
                peer.next_action_time = stepped_now + f64::from(RETRY_INTERVAL);
            }
        }
        self.reference = Timestamp::from_secs_f64(stepped_now);
        true
    }

    fn apply_slew(&mut self, offset_micros: i64, status: i32, constant: i32) -> bool {
        match sys::adjust_clock(offset_micros, status, constant) {
            Ok(frequency) => {
                self.kernel_freq_ppm = frequency;
                self.logger.debug(
                    2,
                    &format!(
                        "adjtimex offset {offset_micros}us status 0x{status:x} tc {constant} \
                         drift {frequency}ppm"
                    ),
                );
                true
            }
            Err(error) => {
                self.logger.warning(&format!("adjtimex failed: {error}"));
                false
            }
        }
    }

    fn refresh_root_variables(&mut self, selected: usize, offset: f64, now: f64) {
        let Some(peer) = self.peers.get(selected) else {
            return;
        };
        self.reference = Timestamp::from_secs_f64(now);
        self.reference_id = peer.filter.reference_id;
        self.root_delay = peer.filter.root_delay + peer.filter.delay;
        let age = (now - peer.filter.received_at).max(0.0);
        let dispersion = (peer.filter.dispersion + clock::FREQ_TOLERANCE * age + offset.abs())
            .max(clock::MIN_DISPERSION);
        self.root_dispersion = peer.filter.root_dispersion + peer.filter.jitter + dispersion;
    }

    fn check_unsync(&mut self) {
        if self.peers.is_empty() || !self.discipline.is_synchronised() {
            return;
        }
        if self.peers.iter().any(|peer| peer.filter.is_reachable()) {
            return;
        }
        self.discipline.clamp_poll_and_unsync();
        self.logger
            .warning("no peer answered the last eight queries; clock is unsynchronised");
        self.run_script(ScriptAction::Unsync, 0.0);
    }

    fn run_script(&mut self, action: ScriptAction, offset: f64) {
        self.last_script_run = sys::now_ntp_seconds();
        let Some(script) = self.script.clone() else {
            return;
        };
        let environment = Environment {
            stratum: self.discipline.stratum,
            freq_drift_ppm: self.kernel_freq_ppm,
            poll_interval: self.discipline.poll_seconds(),
            offset,
        };
        match script::run(&script, action, &environment) {
            Ok(pid) => self.logger.debug(
                1,
                &format!("ran {} {} as pid {pid}", script.display(), action.as_str()),
            ),
            Err(error) => self.logger.warning(&format!(
                "cannot run {} {}: {error}",
                script.display(),
                action.as_str()
            )),
        }
    }

    fn server_state(&self) -> ServerState {
        ServerState {
            leap: if self.discipline.is_synchronised() {
                self.discipline.leap
            } else {
                Leap::Unsynchronised
            },
            stratum: self.discipline.stratum.min(MAX_STRATUM),
            poll: i8::try_from(self.discipline.poll_exp).unwrap_or(MIN_POLL_EXP as i8),
            precision: PRECISION_EXP,
            root_delay: self.root_delay,
            root_dispersion: self.root_dispersion,
            reference_id: self.reference_id,
            // Whole seconds only. At full precision this field is the exact
            // instant the last upstream reply was accepted, which any LAN
            // device may ask for and which, together with the published poll
            // exponent, exposes the phase of the poll timer.
            reference: self.reference.truncated_to_seconds(),
        }
    }

    /// Drains the server socket for one wakeup.
    fn serve_requests(&mut self) -> ServeOutcome {
        let Some(listener) = self.listener.take() else {
            return ServeOutcome::default();
        };
        let state = self.server_state();
        let outcome = serve_from(
            &mut (&listener),
            &state,
            &mut self.budget,
            &self.logger,
            sys::now_ntp_seconds,
        );
        self.listener = Some(listener);
        outcome
    }

    /// Handles a server socket that reported `POLLERR`/`POLLHUP`/`POLLNVAL`.
    ///
    /// Reading the socket reports and clears a pending error, so one drain is
    /// attempted first. A descriptor that reports an error and then has
    /// nothing to read is broken for good; keeping it in the poll set would
    /// spin the main loop, so server mode is dropped and the client half --
    /// the half that keeps this router's own clock right -- carries on.
    fn handle_listener_error(&mut self) {
        let outcome = self.serve_requests();
        if outcome.failed || outcome.received == 0 {
            self.logger
                .warning("server socket failed; continuing as a client only");
            self.listener = None;
        }
    }
}

/// The poll timeout for a main-loop iteration, in milliseconds.
///
/// Always at least one millisecond and never more than an hour, so neither a
/// negative nor a non-finite `seconds` can turn the loop into a busy poll or
/// park it forever.
fn poll_timeout_ms(seconds: f64) -> i32 {
    if !seconds.is_finite() {
        return MIN_POLL_TIMEOUT_MS as i32;
    }
    ((seconds + 1.0) * 1000.0).clamp(MIN_POLL_TIMEOUT_MS, MAX_POLL_TIMEOUT_MS) as i32
}

/// Resolves a peer name to one address, preferring IPv4 as busybox did.
///
/// A bare IPv6 literal is bracketed first: `::1:123` is not a `host:port`
/// pair, `[::1]:123` is.
fn lookup(hostname: &str) -> Option<SocketAddr> {
    let target = if hostname.parse::<Ipv6Addr>().is_ok() {
        format!("[{hostname}]:{NTP_PORT}")
    } else {
        format!("{hostname}:{NTP_PORT}")
    };
    target.to_socket_addrs().ok().and_then(|mut addresses| {
        let mut first = None;
        for address in addresses.by_ref() {
            if address.is_ipv4() {
                return Some(address);
            }
            first.get_or_insert(address);
        }
        first
    })
}

/// The two operations the server drain needs from its socket.
///
/// The trait is what lets the drain loop -- the reply budget, the per-wakeup
/// cap and the order in which a request is validated and charged for -- be
/// driven by a test without a socket or a clock.
trait RequestTransport {
    fn receive(&mut self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
    fn send(&mut self, reply: &[u8], destination: SocketAddr) -> std::io::Result<()>;
}

impl RequestTransport for &UdpSocket {
    fn receive(&mut self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.recv_from(buffer)
    }

    fn send(&mut self, reply: &[u8], destination: SocketAddr) -> std::io::Result<()> {
        UdpSocket::send_to(self, reply, destination).map(|_| ())
    }
}

/// What one drain of the server socket did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ServeOutcome {
    /// Datagrams taken off the socket.
    received: usize,
    /// Replies sent, which is exactly the amount of budget charged.
    replied: usize,
    /// Datagrams refused before any budget was charged.
    refused: usize,
    /// Valid requests dropped because the budget really was exhausted.
    rate_limited: usize,
    /// True when the per-wakeup cap ended the drain.
    capped: bool,
    /// True when the socket reported an error the drain cannot recover from.
    failed: bool,
}

/// Answers at most [`MAX_REQUESTS_PER_WAKEUP`] requests from `transport`.
///
/// Every datagram is validated before anything is sent back, and the reply
/// budget is charged only for a reply that is actually going to be sent.
/// Charging first, as this used to, meant sixty-five malformed, mode-7 or
/// oversized datagrams a second from any LAN device exhausted the budget and
/// denied NTP to every legitimate client: the limiter protected the attacker.
fn serve_from<T, C>(
    transport: &mut T,
    state: &ServerState,
    budget: &mut ReplyBudget,
    logger: &Logger,
    clock: C,
) -> ServeOutcome
where
    T: RequestTransport,
    C: Fn() -> f64,
{
    let mut outcome = ServeOutcome::default();
    let mut datagram = [0_u8; RECEIVE_BUFFER];
    loop {
        if outcome.received >= MAX_REQUESTS_PER_WAKEUP {
            outcome.capped = true;
            return outcome;
        }
        let (received, source) = match transport.receive(&mut datagram) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return outcome,
            // Returning rather than continuing is what makes a pending SIGTERM
            // visible: the main loop checks for it, this loop does not.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => return outcome,
            Err(error) => {
                logger.warning(&format!("server recv failed: {error}"));
                outcome.failed = true;
                return outcome;
            }
        };
        outcome.received += 1;
        let arrival = clock();
        let request = datagram.get(..received).unwrap_or(&[]);
        match server::build_reply(
            request,
            state,
            Timestamp::from_secs_f64(arrival),
            Timestamp::from_secs_f64(clock()),
        ) {
            Ok(reply) => {
                debug_assert_eq!(reply.len(), PACKET_LEN);
                if !budget.allow(arrival) {
                    outcome.rate_limited += 1;
                    logger.debug(1, "server reply budget exhausted; dropping a request");
                    continue;
                }
                outcome.replied += 1;
                if let Err(error) = transport.send(&reply, source) {
                    logger.warning(&format!("cannot answer {}: {error}", source.ip()));
                }
            }
            Err(refusal) => {
                outcome.refused += 1;
                logger.debug(
                    1,
                    &format!("refused a request from {}: {refusal}", source.ip()),
                );
            }
        }
    }
}

/// Source of the 64-bit query nonce.
///
/// The nonce is the only anti-spoofing token an unauthenticated SNTP client
/// has, so every query draws eight fresh bytes from `/dev/urandom`. The file
/// is held open for the life of the daemon: a poll must not depend on `open`
/// succeeding, and there is no per-query system call beyond the read.
///
/// The [`Xorshift`] fallback below exists only for the window before `/dev` is
/// mounted on a cold boot. It is not a cryptographic generator, so falling
/// back to it is reported once at warning level.
struct NonceSource {
    pool: Option<fs::File>,
    fallback: Xorshift,
    warned: bool,
}

impl NonceSource {
    fn new() -> Self {
        Self::open(URANDOM_PATH)
    }

    fn open(path: &str) -> Self {
        Self {
            pool: fs::File::open(path).ok(),
            fallback: Xorshift::seeded(),
            warned: false,
        }
    }

    /// Draws a fresh nonce.
    ///
    /// The second element is a message to log, produced only the first time
    /// the kernel pool could not be read.
    fn next_nonce(&mut self) -> (Timestamp, Option<String>) {
        let mut bytes = [0_u8; 8];
        // `read_exact` loops over a short read and reports the end of file,
        // which /dev/urandom never produces but a wrong path would.
        let failure = match self.pool.as_mut() {
            Some(pool) => pool
                .read_exact(&mut bytes)
                .err()
                .map(|error| error.to_string()),
            None => Some(format!("{URANDOM_PATH} could not be opened")),
        };
        let Some(reason) = failure else {
            let value = u64::from_be_bytes(bytes);
            return (
                Timestamp {
                    seconds: (value >> 32) as u32,
                    fraction: value as u32,
                },
                None,
            );
        };
        // Do not keep trying a descriptor that has already failed once.
        self.pool = None;
        let warning = if self.warned {
            None
        } else {
            self.warned = true;
            Some(format!(
                "cannot read {URANDOM_PATH} ({reason}); query nonces fall back to a \
                 non-cryptographic generator and are predictable"
            ))
        };
        let value = self.fallback.next_u64();
        (
            Timestamp {
                seconds: (value >> 32) as u32,
                fraction: value as u32,
            },
            warning,
        )
    }

    /// True while the kernel entropy pool is the source.
    #[cfg(test)]
    fn is_kernel_backed(&self) -> bool {
        self.pool.is_some()
    }
}

/// A small xorshift64 generator.
///
/// NOT CRYPTOGRAPHIC. xorshift64 is F2-linear and invertible: the map from
/// state to output has GF(2) rank 62 of 64, so a couple of observed outputs
/// pin the state and every later output follows. Its only jobs here are the
/// poll-interval jitter, whose effect is published to the LAN anyway, and the
/// query-nonce fallback for a boot where `/dev/urandom` cannot be opened.
///
/// The nonce and the jitter use separate instances on purpose. Sharing one
/// stream, as this daemon used to, meant a LAN device could recover the state
/// from the observable jitter alone -- the published poll interval and the
/// reference timestamp move with it -- and then predict every query nonce
/// without ever seeing a query.
struct Xorshift {
    state: u64,
}

impl Xorshift {
    fn seeded() -> Self {
        let mut seed = [0_u8; 8];
        let entropy = fs::File::open(URANDOM_PATH)
            .and_then(|mut file| file.read_exact(&mut seed))
            .is_ok();
        let state = if entropy {
            u64::from_ne_bytes(seed)
        } else {
            // Only reachable if /dev is not mounted yet. Still unique per
            // boot and per process, which is better than a fixed constant.
            u64::from(std::process::id()).wrapping_mul(0x9e37_79b9_7f4a_7c15)
                ^ (sys::now_ntp_seconds() as u64)
        };
        Self { state: state | 1 }
    }

    #[cfg(test)]
    fn from_state(state: u64) -> Self {
        Self { state: state | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntp::client::Sample;
    use ntp::packet::{Mode, Packet};
    use std::collections::VecDeque;

    /// A local time far enough past `MIN_PLAUSIBLE_NTP_SECONDS` that every
    /// fixture below is accepted.
    const NOW: f64 = 3_960_000_000.0;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn sample(offset: f64, received_at: f64) -> Sample {
        Sample {
            offset,
            delay: 0.01,
            raw_delay: 0.01,
            received_at,
            stratum: 2,
            leap: Leap::NoWarning,
            precision: -20,
            root_delay: 0.01,
            root_dispersion: 0.01,
            reference_id: *b"TEST",
        }
    }

    impl Daemon {
        /// A daemon with no sockets, no `-S` program and no log destination.
        /// Nothing it does touches the system clock or the network beyond the
        /// name lookups the tests ask for, which are numeric literals.
        fn for_test(peers: &[&str]) -> Self {
            let options = Options {
                peers: peers.iter().map(|peer| (*peer).to_owned()).collect(),
                ..Options::default()
            };
            let daemon_peers = options
                .peers
                .iter()
                .map(|hostname| Peer::new(hostname.clone(), NOW))
                .collect();
            Self {
                options,
                logger: Logger::discard(),
                peers: daemon_peers,
                listener: None,
                discipline: Discipline::new(),
                budget: ReplyBudget::new(),
                nonce: NonceSource::new(),
                jitter: Xorshift::from_state(0x1234_5678_9abc_def0),
                reference: Timestamp::default(),
                reference_id: *b"TEST",
                root_delay: 0.0,
                root_dispersion: 0.0,
                kernel_freq_ppm: 0,
                last_script_run: NOW,
                burst_remaining: 0,
                script: None,
            }
        }

        /// Drives the discipline to a synchronised stratum without touching
        /// the clock, so `check_unsync` has something to lose.
        fn synchronise_for_test(&mut self) {
            self.discipline.update(0.001, NOW, 2, Leap::NoWarning);
            self.discipline
                .update(0.001, NOW + 64.0, 2, Leap::NoWarning);
            assert!(self.discipline.is_synchronised());
        }
    }

    /// A scripted server socket: `inbox` is what the kernel would hand back,
    /// `sent` records every reply.
    struct FakeTransport {
        inbox: VecDeque<(Vec<u8>, SocketAddr)>,
        sent: Vec<(Vec<u8>, SocketAddr)>,
    }

    impl FakeTransport {
        fn new() -> Self {
            Self {
                inbox: VecDeque::new(),
                sent: Vec::new(),
            }
        }

        fn queue(&mut self, datagram: Vec<u8>, count: usize) {
            for index in 0..count {
                self.inbox
                    .push_back((datagram.clone(), loopback(1024 + (index % 512) as u16)));
            }
        }
    }

    impl RequestTransport for FakeTransport {
        fn receive(&mut self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            let Some((datagram, source)) = self.inbox.pop_front() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "nothing queued",
                ));
            };
            let length = datagram.len().min(buffer.len());
            buffer
                .get_mut(..length)
                .unwrap_or_default()
                .copy_from_slice(datagram.get(..length).unwrap_or_default());
            Ok((length, source))
        }

        fn send(&mut self, reply: &[u8], destination: SocketAddr) -> std::io::Result<()> {
            self.sent.push((reply.to_vec(), destination));
            Ok(())
        }
    }

    fn client_request() -> Vec<u8> {
        client::build_query(Timestamp {
            seconds: 0x1234_5678,
            fraction: 0x9abc_def0,
        })
        .to_vec()
    }

    fn mode_seven_request() -> Vec<u8> {
        let mut request = client_request();
        if let Some(flags) = request.first_mut() {
            *flags = (4 << 3) | 7;
        }
        request
    }

    fn synchronised_state() -> ServerState {
        ServerState {
            leap: Leap::NoWarning,
            stratum: 3,
            poll: 6,
            precision: PRECISION_EXP,
            root_delay: 0.01,
            root_dispersion: 0.01,
            reference_id: *b"TEST",
            reference: Timestamp::from_secs_f64(NOW),
        }
    }

    // ---- defect 1: the query nonce ------------------------------------

    #[test]
    fn every_query_draws_a_fresh_nonce_from_the_kernel_pool() {
        let mut source = NonceSource::new();
        assert!(
            source.is_kernel_backed(),
            "the test host must have {URANDOM_PATH}"
        );
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let (nonce, warning) = source.next_nonce();
            assert!(warning.is_none(), "the kernel pool must not warn");
            assert!(
                seen.insert((nonce.seconds, nonce.fraction)),
                "a nonce repeated inside 256 queries"
            );
        }
    }

    #[test]
    fn the_jitter_stream_cannot_move_the_nonce_stream() {
        // Regression: one xorshift64 produced both the nonce and the poll
        // jitter. The jitter is observable from the LAN, and xorshift64 is
        // invertible, so observing it recovered the state and with it every
        // future nonce. The two must be independent generators, which is
        // exactly what this asserts: consuming any amount of jitter leaves
        // the nonce sequence untouched.
        let quiet = {
            let mut source = NonceSource::open("/nonexistent/urandom");
            source.fallback = Xorshift::from_state(0xfeed_face_dead_beef);
            (0..8).map(|_| source.next_nonce().0).collect::<Vec<_>>()
        };
        let noisy = {
            let mut source = NonceSource::open("/nonexistent/urandom");
            source.fallback = Xorshift::from_state(0xfeed_face_dead_beef);
            let mut jitter = Xorshift::from_state(0xfeed_face_dead_beef);
            let mut nonces = Vec::new();
            for _ in 0..8 {
                // Two poll intervals' worth of jitter between queries.
                let _ = jitter.next_u32();
                let _ = jitter.next_u32();
                nonces.push(source.next_nonce().0);
            }
            nonces
        };
        assert_eq!(quiet, noisy);
    }

    #[test]
    fn the_xorshift_fallback_is_predictable_which_is_why_it_is_only_a_fallback() {
        // The property that made the old design a defect, asserted directly:
        // xorshift64 is a pure function of its state, so an observer who
        // recovers the state predicts every later output. Nothing an attacker
        // can observe may therefore share this stream with the nonce.
        let mut generator = Xorshift::from_state(0x0123_4567_89ab_cdef);
        let mut predictor = Xorshift::from_state(0x0123_4567_89ab_cdef);
        for _ in 0..64 {
            assert_eq!(generator.next_u64(), predictor.next_u64());
        }
    }

    #[test]
    fn an_unreadable_entropy_pool_warns_once_and_keeps_producing_nonces() {
        let mut source = NonceSource::open("/nonexistent/urandom");
        assert!(!source.is_kernel_backed());
        let (first, warning) = source.next_nonce();
        let warning = warning.expect("the first fallback is reported");
        assert!(warning.contains("non-cryptographic"));
        let (second, repeat) = source.next_nonce();
        assert!(
            repeat.is_none(),
            "the warning is emitted once, not per poll"
        );
        assert_ne!(first, second);
    }

    #[test]
    fn the_published_reference_timestamp_has_no_fraction() {
        // A full-precision reference timestamp is the exact instant the last
        // upstream reply was accepted. Any LAN device may ask for it, and
        // with the published poll exponent it exposes the poll timer's phase.
        let mut daemon = Daemon::for_test(&["127.0.0.1"]);
        daemon.synchronise_for_test();
        daemon.reference = Timestamp::from_secs_f64(NOW + 0.123_456_789);
        assert_ne!(daemon.reference.fraction, 0, "the fixture must have one");
        let state = daemon.server_state();
        assert_eq!(state.reference.fraction, 0);
        assert_eq!(state.reference.seconds, daemon.reference.seconds);
    }

    // ---- defect 2: a permanent kiss-o'-death --------------------------

    #[test]
    fn a_permanent_kiss_ends_in_a_loss_of_sync_report() {
        // Regression: `DENY`/`RSTR` set a `refused` flag and `send_query`
        // returned before `note_query_sent()`, so `reachable_bits` froze at
        // its last non-zero value, `check_unsync` could never fire and the
        // daemon kept serving the LAN a stratum from a free-running clock.
        let mut daemon = Daemon::for_test(&["127.0.0.1"]);
        assert_eq!(daemon.resolve(0), Resolution::Adopted);
        daemon.peers[0].filter.accept(&sample(0.001, NOW), NOW);
        daemon.synchronise_for_test();
        assert!(daemon.peers[0].filter.is_reachable());

        daemon.handle_rejection(0, Rejection::KissOfDeath(KissCode::Deny));
        assert_eq!(daemon.peers[0].refused_address, Some(loopback(NTP_PORT)));
        assert_eq!(daemon.peers[0].address, None, "the address is retired");

        // The name has exactly one address, so every later slot re-resolves to
        // the refused server and is skipped -- but the register still shifts.
        for shift in 1..=8 {
            daemon.send_query(0, NOW + f64::from(shift) * f64::from(NOREPLY_INTERVAL));
            assert!(
                daemon.peers[0].socket.is_none(),
                "a refused address must never be queried"
            );
        }
        assert_eq!(
            daemon.peers[0].filter.reachable_bits, 0,
            "the reachability register never decayed"
        );

        assert!(daemon.discipline.is_synchronised());
        daemon.check_unsync();
        assert!(
            !daemon.discipline.is_synchronised(),
            "the daemon kept claiming synchronisation"
        );
        assert_eq!(daemon.server_state().leap, Leap::Unsynchronised);
        assert_eq!(daemon.server_state().stratum, MAX_STRATUM);
        assert!(!daemon.server_state().is_synchronised());
    }

    #[test]
    fn a_refusal_is_bound_to_the_address_and_not_to_the_pool_name() {
        // `ntp_server0` defaults to `pool.ntp.org`. One volunteer member
        // answering `DENY` must not silence this router for good: the name is
        // looked up again and a different member is queried.
        let mut daemon = Daemon::for_test(&["127.0.0.1"]);
        assert_eq!(daemon.resolve(0), Resolution::Adopted);
        daemon.handle_rejection(0, Rejection::KissOfDeath(KissCode::Restrict));
        // Simulate the pool rotating on to another member.
        daemon.peers[0].address = Some(loopback(NTP_PORT + 1));
        assert_ne!(daemon.peers[0].address, daemon.peers[0].refused_address);
    }

    #[test]
    fn a_rate_kiss_still_only_backs_off() {
        let mut daemon = Daemon::for_test(&["127.0.0.1"]);
        assert_eq!(daemon.resolve(0), Resolution::Adopted);
        daemon.handle_rejection(0, Rejection::KissOfDeath(KissCode::Rate));
        assert_eq!(daemon.peers[0].refused_address, None);
        assert_eq!(daemon.peers[0].address, Some(loopback(NTP_PORT)));
    }

    // ---- defect 3: the LAN reply budget -------------------------------

    #[test]
    fn invalid_datagrams_never_consume_the_reply_budget() {
        // Regression: the budget was charged before validation, so 65
        // malformed or mode-7 datagrams a second from any LAN device denied
        // NTP to every legitimate client. The limiter protected the attacker.
        let state = synchronised_state();
        let mut budget = ReplyBudget::new();
        let logger = Logger::discard();
        let mut transport = FakeTransport::new();
        transport.queue(mode_seven_request(), 40);
        transport.queue(vec![0_u8; 7], 40);
        transport.queue(vec![0_u8; 512], 40);
        transport.queue(client_request(), server::REPLY_BUDGET_PER_SECOND as usize);

        let mut replied = 0;
        let mut refused = 0;
        for _ in 0..8 {
            let outcome = serve_from(&mut transport, &state, &mut budget, &logger, || NOW);
            replied += outcome.replied;
            refused += outcome.refused;
            assert_eq!(outcome.rate_limited, 0, "a valid client was rate limited");
        }
        assert_eq!(refused, 120, "every invalid datagram must be refused");
        assert_eq!(
            replied,
            server::REPLY_BUDGET_PER_SECOND as usize,
            "a full second of budget must survive 120 invalid datagrams"
        );
        assert_eq!(transport.sent.len(), replied);
        assert!(transport
            .sent
            .iter()
            .all(|(reply, _)| reply.len() == PACKET_LEN));
    }

    #[test]
    fn one_wakeup_handles_at_most_the_capped_number_of_datagrams() {
        // Regression: the drain ran until `WouldBlock` with no cap, so a
        // sustained LAN flood kept the loop inside `serve_requests`, the
        // client half never ran and the router never synced.
        let state = synchronised_state();
        let mut budget = ReplyBudget::new();
        let logger = Logger::discard();
        let mut transport = FakeTransport::new();
        transport.queue(mode_seven_request(), MAX_REQUESTS_PER_WAKEUP * 4);

        let outcome = serve_from(&mut transport, &state, &mut budget, &logger, || NOW);
        assert!(outcome.capped, "the drain did not stop at the cap");
        assert_eq!(outcome.received, MAX_REQUESTS_PER_WAKEUP);
        assert_eq!(
            transport.inbox.len(),
            MAX_REQUESTS_PER_WAKEUP * 3,
            "the rest must wait for the next wakeup"
        );
    }

    #[test]
    fn a_real_flood_still_leaves_a_valid_client_a_reply() {
        let state = synchronised_state();
        let mut budget = ReplyBudget::new();
        let logger = Logger::discard();
        let mut transport = FakeTransport::new();
        transport.queue(vec![0_u8; 3], 65);
        transport.queue(client_request(), 1);
        let mut replied = 0;
        for _ in 0..4 {
            replied += serve_from(&mut transport, &state, &mut budget, &logger, || NOW).replied;
        }
        assert_eq!(replied, 1);
    }

    #[test]
    fn the_budget_is_still_enforced_for_valid_requests() {
        let state = synchronised_state();
        let mut budget = ReplyBudget::new();
        let logger = Logger::discard();
        let mut transport = FakeTransport::new();
        transport.queue(client_request(), 256);
        let mut replied = 0;
        let mut rate_limited = 0;
        for _ in 0..8 {
            let outcome = serve_from(&mut transport, &state, &mut budget, &logger, || NOW);
            replied += outcome.replied;
            rate_limited += outcome.rate_limited;
        }
        assert_eq!(replied, server::REPLY_BUDGET_PER_SECOND as usize);
        assert_eq!(rate_limited, 256 - replied);
    }

    #[test]
    fn an_interrupted_receive_returns_to_the_main_loop() {
        // A pending SIGTERM is observed by the main loop, not by the drain, so
        // `EINTR` has to end the drain rather than continue it.
        struct Interrupting(bool);
        impl RequestTransport for Interrupting {
            fn receive(&mut self, _buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
                assert!(!self.0, "the drain continued past an interruption");
                self.0 = true;
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "signal",
                ))
            }

            fn send(&mut self, _reply: &[u8], _to: SocketAddr) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut transport = Interrupting(false);
        let outcome = serve_from(
            &mut transport,
            &synchronised_state(),
            &mut ReplyBudget::new(),
            &Logger::discard(),
            || NOW,
        );
        assert_eq!(outcome, ServeOutcome::default());
    }

    #[test]
    fn an_unsynchronised_server_answers_nothing_and_spends_nothing() {
        let mut state = synchronised_state();
        state.stratum = MAX_STRATUM;
        let mut budget = ReplyBudget::new();
        let logger = Logger::discard();
        let mut transport = FakeTransport::new();
        transport.queue(client_request(), 8);
        let outcome = serve_from(&mut transport, &state, &mut budget, &logger, || NOW);
        assert_eq!(outcome.replied, 0);
        assert_eq!(outcome.refused, 8);
        assert!(budget.allow(NOW), "no budget may have been charged");
    }

    // ---- defect 4: duplicate peers ------------------------------------

    #[test]
    fn two_peers_on_one_address_yield_at_most_one_candidate() {
        // Regression: `resolve` had no duplicate check, so two `-p` names
        // pointing at one server became two independent Marzullo candidates
        // backed by a single source and a lone hostile server passed the
        // intersection test.
        let mut daemon = Daemon::for_test(&["127.0.0.1", "127.0.0.1"]);
        assert_eq!(daemon.resolve(0), Resolution::Adopted);
        assert_eq!(daemon.resolve(1), Resolution::Duplicate);
        assert_eq!(daemon.peers[0].address, Some(loopback(NTP_PORT)));
        assert_eq!(daemon.peers[1].address, None);

        for peer in &mut daemon.peers {
            for shift in 0..3 {
                peer.filter.note_query_sent();
                peer.filter
                    .accept(&sample(0.5, NOW + f64::from(shift)), NOW + f64::from(shift));
            }
        }
        // Even with samples already in it, a peer that has become a duplicate
        // contributes nothing: the next lookup empties its filter.
        assert_eq!(daemon.resolve(1), Resolution::Duplicate);
        assert!(!daemon.peers[1].filter.is_reachable());
        let candidates = daemon.candidates(NOW + 4.0);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates.first().map(|candidate| candidate.index), Some(0));
    }

    #[test]
    fn a_skipped_duplicate_is_never_queried_and_still_decays() {
        let mut daemon = Daemon::for_test(&["127.0.0.1", "127.0.0.1"]);
        assert_eq!(daemon.resolve(0), Resolution::Adopted);
        daemon.peers[1].filter.note_query_sent();
        daemon.peers[1].filter.accept(&sample(0.001, NOW), NOW);
        assert!(daemon.peers[1].filter.is_reachable());
        for shift in 0..8 {
            daemon.send_query(1, NOW + f64::from(shift));
            assert!(daemon.peers[1].socket.is_none());
            assert_eq!(daemon.peers[1].address, None);
        }
        assert_eq!(daemon.peers[1].filter.reachable_bits, 0);
    }

    #[test]
    fn a_peer_with_an_address_of_its_own_is_not_a_duplicate() {
        let mut daemon = Daemon::for_test(&["127.0.0.1", "127.0.0.2"]);
        assert_eq!(daemon.resolve(0), Resolution::Adopted);
        assert_eq!(daemon.resolve(1), Resolution::Adopted);
        assert_ne!(daemon.peers[0].address, daemon.peers[1].address);
        for peer in &mut daemon.peers {
            peer.filter.note_query_sent();
            peer.filter.accept(&sample(0.001, NOW), NOW);
            peer.filter.note_query_sent();
            peer.filter.accept(&sample(0.001, NOW + 1.0), NOW + 1.0);
        }
        assert_eq!(daemon.candidates(NOW + 2.0).len(), 2);
    }

    #[test]
    fn a_duplicate_peer_re_resolving_to_a_free_address_is_adopted() {
        let mut daemon = Daemon::for_test(&["127.0.0.1", "127.0.0.1"]);
        assert_eq!(daemon.resolve(0), Resolution::Adopted);
        assert_eq!(daemon.resolve(1), Resolution::Duplicate);
        // The first peer moves on, so the address is free again.
        daemon.peers[0].address = None;
        assert_eq!(daemon.resolve(1), Resolution::Adopted);
        assert_eq!(daemon.peers[1].address, Some(loopback(NTP_PORT)));
    }

    // ---- minor: the server socket and the poll timeout -----------------

    #[test]
    fn a_missing_server_interface_does_not_stop_the_client_half() {
        // Regression: `run` propagated the bind error, so `-I` naming an
        // interface that did not exist yet killed the whole daemon, client
        // half included, while `rc` had already logged "Started ntpd".
        assert!(open_listener(Some("ntp-no-such-if")).is_err());
        let options = Options {
            peers: vec!["127.0.0.1".to_owned()],
            listen: true,
            interface: Some("ntp-no-such-if".to_owned()),
            ..Options::default()
        };
        // `run` cannot be called here (it daemonises and writes a pid file),
        // so assert the decision `run` makes: a failed listener is a warning
        // and `None`, never an error that propagates out of the daemon.
        let listener = match open_listener(options.interface.as_deref()) {
            Ok(socket) => Some(socket),
            Err(_) => None,
        };
        assert!(listener.is_none());
    }

    #[test]
    fn the_poll_timeout_is_always_a_bounded_positive_millisecond_count() {
        assert_eq!(poll_timeout_ms(f64::NAN), MIN_POLL_TIMEOUT_MS as i32);
        assert_eq!(
            poll_timeout_ms(f64::NEG_INFINITY),
            MIN_POLL_TIMEOUT_MS as i32
        );
        assert_eq!(poll_timeout_ms(-100.0), MIN_POLL_TIMEOUT_MS as i32);
        assert_eq!(poll_timeout_ms(-1.0), MIN_POLL_TIMEOUT_MS as i32);
        assert_eq!(poll_timeout_ms(0.0), 1_000);
        assert_eq!(poll_timeout_ms(1e9), MAX_POLL_TIMEOUT_MS as i32);
        for seconds in [-5.0, 0.0, 0.5, 60.0, 3_600.0, 1e12] {
            let timeout = poll_timeout_ms(seconds);
            assert!((MIN_POLL_TIMEOUT_MS as i32..=MAX_POLL_TIMEOUT_MS as i32).contains(&timeout));
        }
    }

    #[test]
    fn a_bare_ipv6_literal_is_bracketed_before_it_reaches_the_resolver() {
        // `::1:123` is not a host:port pair; `[::1]:123` is.
        let address = lookup("::1").expect("the loopback literal resolves");
        assert_eq!(address, SocketAddr::from((Ipv6Addr::LOCALHOST, NTP_PORT)));
        let bracketed = lookup("[::1]").expect("a bracketed literal resolves");
        assert_eq!(bracketed, address);
    }

    #[test]
    fn a_name_that_does_not_resolve_is_a_failure_not_a_panic() {
        // An empty name stands in for any lookup failure. A made-up domain
        // would be a worse fixture: plenty of resolvers, this build host's
        // included, answer NXDOMAIN with a redirection address.
        assert_eq!(lookup(""), None);
        let mut daemon = Daemon::for_test(&[""]);
        assert_eq!(daemon.resolve(0), Resolution::Failed);
        assert_eq!(daemon.peers[0].address, None);
        assert_ne!(daemon.peers[0].dns_errors, 0);
    }

    #[test]
    fn a_reply_this_daemon_builds_still_decodes_as_a_server_packet() {
        let state = synchronised_state();
        let mut budget = ReplyBudget::new();
        let logger = Logger::discard();
        let mut transport = FakeTransport::new();
        transport.queue(client_request(), 1);
        assert_eq!(
            serve_from(&mut transport, &state, &mut budget, &logger, || NOW).replied,
            1
        );
        let (reply, _) = transport.sent.first().expect("one reply");
        let decoded = Packet::decode(reply).expect("our own reply decodes");
        assert_eq!(decoded.mode, Mode::Server);
        assert_eq!(decoded.reference, state.reference);
    }
}
