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
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::process::ExitCode;

/// The NTP service port, for both the client sockets and the server socket.
const NTP_PORT: u16 = 123;
/// Where busybox's ntpd wrote its pid; nothing on this firmware reads it, but
/// leaving the file behind would be a behaviour change.
const PID_FILE: &str = "/var/run/ntpd.pid";
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
    /// Set by a `DENY`/`RSTR` kiss: the peer is never queried again.
    refused: bool,
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
            refused: false,
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

/// Everything the daemon carries between iterations of the main loop.
struct Daemon {
    options: Options,
    logger: Logger,
    peers: Vec<Peer>,
    listener: Option<UdpSocket>,
    discipline: Discipline,
    budget: ReplyBudget,
    random: Random,
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

fn run(options: Options) -> std::io::Result<()> {
    let logger = Logger::new(options.verbose, true);

    // Bind before detaching so a port conflict is still visible on stderr.
    let listener = if options.listen {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, NTP_PORT))?;
        if let Some(interface) = &options.interface {
            sys::bind_to_device(&socket, interface)?;
        }
        sys::set_tos(&socket);
        socket.set_nonblocking(true)?;
        Some(socket)
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
        random: Random::new(),
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
        daemon.resolve(index);
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

            let timeout_seconds = (next_action - now).clamp(0.0, 3600.0) + 1.0;
            let ready = match sys::poll_readable(&descriptors, (timeout_seconds * 1000.0) as i32) {
                Ok(ready) => ready,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if sys::take_pending_signal() != 0 {
                return Ok(());
            }

            let any_ready = ready.iter().any(|flag| *flag);
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

            if listener_slots == 1 && ready.first().copied().unwrap_or(false) {
                self.serve_requests();
            }
            for (slot, peer_index) in waiting.iter().enumerate() {
                if ready.get(slot + listener_slots).copied().unwrap_or(false) {
                    self.receive_reply(*peer_index);
                }
            }
            self.check_unsync();
        }
    }

    /// Resolves a peer name, remembering the failure count so repeated DNS
    /// outages back off instead of spinning.
    fn resolve(&mut self, index: usize) -> bool {
        let Some(peer) = self.peers.get_mut(index) else {
            return false;
        };
        let target = format!("{}:{NTP_PORT}", peer.hostname);
        let resolved = target.to_socket_addrs().ok().and_then(|mut addresses| {
            let mut first = None;
            for address in addresses.by_ref() {
                if address.is_ipv4() {
                    return Some(address);
                }
                first.get_or_insert(address);
            }
            first
        });
        match resolved {
            Some(address) => {
                peer.address = Some(address);
                peer.dns_errors = 0;
                true
            }
            None => {
                peer.dns_errors = ((peer.dns_errors << 1) | 1) & DNS_ERRORS_CAP;
                false
            }
        }
    }

    fn resolve_pending(&mut self, now: f64) {
        for index in 0..self.peers.len() {
            let needs = {
                let peer = &self.peers[index];
                !peer.refused && peer.address.is_none() && peer.next_action_time <= now
            };
            if needs && !self.resolve(index) {
                let delay = HOSTNAME_INTERVAL
                    .saturating_mul(u32::from(self.peers[index].dns_errors).max(1));
                self.set_next(index, delay);
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
        interval = interval.saturating_add((self.random.next_u32()) & mask);
        interval
    }

    fn send_query(&mut self, index: usize, now: f64) {
        if self.peers[index].refused {
            self.peers[index].next_action_time = now + f64::from(NOREPLY_INTERVAL);
            return;
        }
        if self.peers[index].address.is_none() && !self.resolve(index) {
            let delay =
                HOSTNAME_INTERVAL.saturating_mul(u32::from(self.peers[index].dns_errors).max(1));
            self.set_next(index, delay);
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
            IpAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
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

        let nonce = Timestamp {
            seconds: self.random.next_u32(),
            fraction: self.random.next_u32(),
        };
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
            self.resolve(index);
        }
        self.set_next(index, timeout);
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
                    self.peers[index].refused = true;
                    self.logger.warning(&format!(
                        "{} refused service ({code}); not querying it again",
                        self.peers[index].describe()
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

    /// Re-runs peer selection and applies the winner to the system clock.
    /// Returns true when the clock was actually set.
    fn discipline_from_selection(&mut self, now: f64) -> bool {
        for peer in &mut self.peers {
            peer.filter.recompute(now);
        }
        let candidates: Vec<clock::Candidate> = self
            .peers
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
            .collect();
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
            reference: self.reference,
        }
    }

    /// Drains the server socket. Every datagram is validated before anything
    /// is sent back, and a reply is always exactly 48 bytes.
    fn serve_requests(&mut self) {
        let state = self.server_state();
        let mut datagram = [0_u8; RECEIVE_BUFFER];
        loop {
            let Some(listener) = &self.listener else {
                return;
            };
            let (received, source) = match listener.recv_from(&mut datagram) {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.logger.warning(&format!("server recv failed: {error}"));
                    return;
                }
            };
            let arrival = sys::now_ntp_seconds();
            if !self.budget.allow(arrival) {
                self.logger
                    .debug(1, "server reply budget exhausted; dropping a request");
                continue;
            }
            let request = datagram.get(..received).unwrap_or(&[]);
            let reply = server::build_reply(
                request,
                &state,
                Timestamp::from_secs_f64(arrival),
                Timestamp::from_secs_f64(sys::now_ntp_seconds()),
            );
            match reply {
                Ok(reply) => {
                    debug_assert_eq!(reply.len(), PACKET_LEN);
                    let Some(listener) = &self.listener else {
                        return;
                    };
                    if let Err(error) = listener.send_to(&reply, source) {
                        self.logger
                            .warning(&format!("cannot answer {}: {error}", source.ip()));
                    }
                }
                Err(refusal) => self.logger.debug(
                    1,
                    &format!("refused a request from {}: {refusal}", source.ip()),
                ),
            }
        }
    }
}

/// A small xorshift generator seeded from `/dev/urandom`.
///
/// It produces the query nonce, which is the only anti-spoofing token an
/// unauthenticated SNTP client has, and the poll-interval jitter.
struct Random {
    state: u64,
}

impl Random {
    fn new() -> Self {
        let mut seed = [0_u8; 8];
        let entropy = fs::File::open("/dev/urandom")
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
