//! The only module of this crate that contains `unsafe`.
//!
//! Every function wraps one libc call, validates its arguments in safe Rust
//! first and converts the result into an `io::Result`.  Nothing here keeps a
//! raw pointer beyond the call it is passed to, and every descriptor is owned
//! by an `OwnedFd` from the instant it exists, so no error path leaks one.

use std::ffi::CString;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

/// Set by the signal handler; read by the main loop.
static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Returns and clears the signal number recorded by the handler.
pub fn take_pending_signal() -> i32 {
    PENDING_SIGNAL.swap(0, Ordering::Relaxed)
}

extern "C" fn record_signal(number: libc::c_int) {
    // Async-signal-safe: a single relaxed atomic store and nothing else.
    PENDING_SIGNAL.store(number, Ordering::Relaxed);
}

/// Installs the dispositions the vendor installed (`wsdd2.c:875-880`):
/// `SIGINT`, `SIGHUP` and `SIGTERM` are recorded, and `SIGPIPE` is ignored so
/// a client that closes the metadata connection early cannot kill the daemon.
///
/// `killall_tk("wsdd2")` sends `SIGTERM` and then `SIGKILL`; the second cannot
/// be caught, which is why the loop must exit on the first.
pub fn install_signal_handlers() {
    for number in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: `record_signal` has the C ABI and the signature signal(2)
        // requires, and its body performs only an atomic store, so it is
        // async-signal-safe.
        unsafe {
            libc::signal(number, record_signal as libc::sighandler_t);
        }
    }
    // SAFETY: SIG_IGN is a valid disposition for SIGPIPE and takes no
    // pointer arguments.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// Detaches from the controlling terminal the way `-d` did
/// (`wsdd2.c:854-872`): fork, let the parent exit, `chdir("/")`, point the
/// three standard descriptors at `/dev/null`, then `setsid`.
///
/// `rc` starts this daemon through `_eval(argv, NULL, 0, &pid)`, which forks
/// and returns without waiting, so the process that survives is this child.
/// It is named `wsdd2`, which is what `pids("wsdd2")` matches.
///
/// # Errors
/// Returns the `fork` error.
pub fn daemonize() -> io::Result<()> {
    // SAFETY: the process is single-threaded at this point (no thread has
    // been spawned), so fork(2) leaves the child with a consistent runtime.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child > 0 {
        // SAFETY: _exit does not run destructors or atexit handlers, which is
        // what the parent of a daemon must do.
        unsafe { libc::_exit(0) };
    }
    let root = CString::new("/").map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the path is NUL-terminated and lives across the call.
    unsafe {
        libc::chdir(root.as_ptr());
    }
    redirect_standard_descriptors();
    // SAFETY: setsid takes no arguments and only detaches this process.
    unsafe { libc::setsid() };
    Ok(())
}

fn redirect_standard_descriptors() {
    let Ok(devnull) = CString::new("/dev/null") else {
        return;
    };
    // SAFETY: the path is NUL-terminated and lives across the call; O_RDWR
    // with no O_CREAT needs no mode argument.
    let fd = unsafe { libc::open(devnull.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return;
    }
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: `fd` is a descriptor this function just opened and `target`
        // is one of the three standard descriptor numbers.
        unsafe {
            libc::dup2(fd, target);
        }
    }
    if fd > libc::STDERR_FILENO {
        // SAFETY: `fd` is owned here and is not used again.
        unsafe {
            libc::close(fd);
        }
    }
}

/// Current real time as seconds since the Unix epoch.
pub fn now_unix() -> f64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a live, fully initialised `timespec` owned by this
    // frame; clock_gettime writes exactly one of them and reads no pointer.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut value) };
    if result != 0 {
        return 0.0;
    }
    value.tv_sec as f64 + value.tv_nsec as f64 / 1e9
}

/// Current real time as whole seconds since the Unix epoch.
pub fn now_unix_seconds() -> u64 {
    let seconds = now_unix();
    if seconds.is_finite() && seconds > 0.0 {
        seconds as u64
    } else {
        0
    }
}

/// This host's name, as `gethostname` returned it (`wsdd2.c:740`).
pub fn hostname() -> Option<String> {
    const LIMIT: usize = 256;
    let mut buffer = vec![0_u8; LIMIT];
    // SAFETY: `buffer` owns `LIMIT` initialised bytes for the whole call and
    // the length passed is one less, so the result is always NUL-terminated
    // inside the allocation.
    let result = unsafe {
        libc::gethostname(
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            LIMIT.saturating_sub(1),
        )
    };
    if result != 0 {
        return None;
    }
    let end = buffer.iter().position(|byte| *byte == 0).unwrap_or(0);
    let text = buffer.get(..end)?;
    core::str::from_utf8(text).ok().map(str::to_owned)
}

/// Resolves an interface name to its index.
///
/// # Errors
/// `NotFound` when the interface does not exist, `InvalidInput` for a name
/// with a NUL.
pub fn if_index(name: &str) -> io::Result<u32> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
    // SAFETY: `name` outlives the call and is NUL-terminated; the function
    // reads it and returns a scalar.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no such interface"));
    }
    Ok(index)
}

/// Pins a socket to one network interface.
///
/// This is the same `SO_BINDTODEVICE` pattern the `infosvr` and `ntp` ports
/// use.  It is what keeps both service ports on the LAN bridge and off the
/// WAN, and it is applied *before* `bind`, so the port is never reachable
/// anywhere else, not even for the window between the two calls.
///
/// # Errors
/// Returns the `setsockopt` error, or `InvalidInput` for a name with a NUL.
pub fn bind_to_device(socket: &impl AsRawFd, interface: &str) -> io::Result<()> {
    let name = CString::new(interface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
    // SAFETY: `name` outlives the call and its pointer addresses exactly
    // `as_bytes_with_nul().len()` initialised bytes; the descriptor is owned
    // by the caller for the duration of the borrow.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    check(result)
}

fn set_int_option(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `value` is a live, initialised `c_int` owned by this frame and
    // its length is passed exactly; the descriptor is owned by the caller.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    check(result)
}

fn check(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Creates a socket and applies every option that must precede `bind`:
/// address reuse, IPv6-only for the v6 family, and the interface pin.
///
/// # Errors
/// Returns the first `socket` or `setsockopt` error.  The descriptor is owned
/// from creation, so a failure closes it.
fn new_socket(
    domain: libc::c_int,
    kind: libc::c_int,
    protocol: libc::c_int,
    interface: Option<&str>,
) -> io::Result<OwnedFd> {
    // SAFETY: socket(2) takes three scalars, reads no pointer and returns an
    // owned descriptor or -1.
    let descriptor = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `descriptor` was just returned by socket(2), is not negative and
    // is not owned by anything else, so `OwnedFd` may take it.  Every early
    // return from here on closes it through that ownership.
    let owned = unsafe { OwnedFd::from_raw_fd(descriptor) };
    set_int_option(&owned, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    if domain == libc::AF_INET6 {
        set_int_option(&owned, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
    }
    if let Some(interface) = interface {
        bind_to_device(&owned, interface)?;
    }
    Ok(owned)
}

fn bind_any(socket: &impl AsRawFd, domain: libc::c_int, port: u16) -> io::Result<()> {
    if domain == libc::AF_INET6 {
        // SAFETY: `sockaddr_in6` is plain-old-data; an all-zero value is the
        // documented starting point and every field used is set explicitly.
        let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        address.sin6_port = port.to_be();
        // SAFETY: `address` is a live, fully initialised `sockaddr_in6` owned
        // by this frame and the length passed is exactly its size.
        let result = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                std::ptr::addr_of!(address).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };
        return check(result);
    }
    // SAFETY: as above, for the IPv4 address structure.
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    address.sin_family = libc::AF_INET as libc::sa_family_t;
    address.sin_port = port.to_be();
    address.sin_addr.s_addr = libc::INADDR_ANY.to_be();
    // SAFETY: `address` is a live, fully initialised `sockaddr_in` owned by
    // this frame and the length passed is exactly its size.
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            std::ptr::addr_of!(address).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    check(result)
}

/// Opens the IPv4 multicast socket for one group.
///
/// Order: create, reuse-address, `SO_BINDTODEVICE`, multicast egress
/// interface, loopback off, `bind`, then join the group.  Only the join
/// follows the bind, which is what the vendor did (`wsdd2.c:466-478`) and
/// cannot widen reachability -- the socket is already pinned to the device.
///
/// # Errors
/// Returns the first failing system call.
pub fn bind_multicast_v4(
    group: Ipv4Addr,
    port: u16,
    interface: Option<&str>,
    index: u32,
) -> io::Result<UdpSocket> {
    let owned = new_socket(
        libc::AF_INET,
        libc::SOCK_DGRAM,
        libc::IPPROTO_UDP,
        interface,
    )?;
    let request = mreqn(group, index);
    // SAFETY: `request` is a live, fully initialised `ip_mreqn` owned by this
    // frame and its length is passed exactly.
    let result = unsafe {
        libc::setsockopt(
            owned.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            std::ptr::addr_of!(request).cast(),
            std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
        )
    };
    check(result)?;
    set_int_option(&owned, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, 0)?;
    bind_any(&owned, libc::AF_INET, port)?;
    // SAFETY: as for IP_MULTICAST_IF above; the same initialised structure.
    let result = unsafe {
        libc::setsockopt(
            owned.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_ADD_MEMBERSHIP,
            std::ptr::addr_of!(request).cast(),
            std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
        )
    };
    check(result)?;
    Ok(UdpSocket::from(owned))
}

fn mreqn(group: Ipv4Addr, index: u32) -> libc::ip_mreqn {
    libc::ip_mreqn {
        imr_multiaddr: libc::in_addr {
            s_addr: u32::from(group).to_be(),
        },
        imr_address: libc::in_addr {
            s_addr: libc::INADDR_ANY.to_be(),
        },
        imr_ifindex: index as libc::c_int,
    }
}

/// Opens the IPv6 multicast socket for one group.  See [`bind_multicast_v4`]
/// for the ordering rationale.
///
/// # Errors
/// Returns the first failing system call.
pub fn bind_multicast_v6(
    group: Ipv6Addr,
    port: u16,
    interface: Option<&str>,
    index: u32,
) -> io::Result<UdpSocket> {
    let owned = new_socket(
        libc::AF_INET6,
        libc::SOCK_DGRAM,
        libc::IPPROTO_UDP,
        interface,
    )?;
    set_int_option(
        &owned,
        libc::IPPROTO_IPV6,
        libc::IPV6_MULTICAST_IF,
        index as libc::c_int,
    )?;
    set_int_option(&owned, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, 0)?;
    bind_any(&owned, libc::AF_INET6, port)?;
    let request = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr {
            s6_addr: group.octets(),
        },
        ipv6mr_interface: index,
    };
    // SAFETY: `request` is a live, fully initialised `ipv6_mreq` owned by this
    // frame and its length is passed exactly.
    let result = unsafe {
        libc::setsockopt(
            owned.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_ADD_MEMBERSHIP,
            std::ptr::addr_of!(request).cast(),
            std::mem::size_of::<libc::ipv6_mreq>() as libc::socklen_t,
        )
    };
    check(result)?;
    Ok(UdpSocket::from(owned))
}

/// Opens the TCP metadata listener, pinned to the interface before `bind`.
///
/// # Errors
/// Returns the first failing system call.
pub fn bind_tcp(port: u16, v6: bool, interface: Option<&str>) -> io::Result<TcpListener> {
    let domain = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let owned = new_socket(domain, libc::SOCK_STREAM, libc::IPPROTO_TCP, interface)?;
    bind_any(&owned, domain, port)?;
    // SAFETY: the descriptor is owned and the backlog is a plain scalar.
    let result = unsafe { libc::listen(owned.as_raw_fd(), 8) };
    check(result)?;
    Ok(TcpListener::from(owned))
}

/// Opens an unbound UDP socket pinned to the interface, used only to ask the
/// kernel which local address it would use to reach a given peer.
///
/// This replaces the vendor's `connected_if` (`wsdd2.c:164-232`), which
/// compared every `getifaddrs` entry's address and netmask against the sender
/// by hand.  A `connect` on an unbound datagram socket performs the same route
/// lookup the reply itself will take, so the advertised address is the one the
/// requester can actually reach -- and because the socket is pinned to the LAN
/// interface, a request whose source address is not routed through that
/// interface fails the lookup and is never answered.
///
/// # Errors
/// Returns the first failing system call.
pub fn route_probe_socket(v6: bool, interface: Option<&str>) -> io::Result<UdpSocket> {
    let domain = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let owned = new_socket(domain, libc::SOCK_DGRAM, libc::IPPROTO_UDP, interface)?;
    Ok(UdpSocket::from(owned))
}

/// What one descriptor reported in a [`poll_readable`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readiness {
    /// Nothing happened before the timeout expired.
    Idle,
    /// `POLLIN`: something is queued.
    Readable,
    /// `POLLERR`, `POLLHUP` or `POLLNVAL`: the descriptor is in an error
    /// state.  Reporting this as readable would spin the main loop forever,
    /// because the condition is level-triggered and no read clears it.
    Errored,
}

/// Waits for readability on `descriptors` for at most `timeout_ms`.
///
/// # Errors
/// Returns the `poll` error; `EINTR` is reported so the caller can service a
/// signal and loop.  A negative timeout is `InvalidInput`: poll(2) reads it as
/// "block forever", and clamping it to zero would turn a caller's arithmetic
/// mistake into a busy loop, so neither is done silently.
pub fn poll_readable(descriptors: &[RawFd], timeout_ms: i32) -> io::Result<Vec<Readiness>> {
    if timeout_ms < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "poll timeout must not be negative",
        ));
    }
    let mut entries: Vec<libc::pollfd> = descriptors
        .iter()
        .map(|descriptor| libc::pollfd {
            fd: *descriptor,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let count = entries.len();
    // SAFETY: `entries` owns `count` initialised `pollfd` values and stays
    // borrowed for the whole call; the length passed matches the allocation.
    let result = unsafe { libc::poll(entries.as_mut_ptr(), count as libc::nfds_t, timeout_ms) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(entries
        .iter()
        .map(|entry| {
            if entry.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                Readiness::Errored
            } else if entry.revents & libc::POLLIN != 0 {
                Readiness::Readable
            } else {
                Readiness::Idle
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_negative_poll_timeout_is_refused() {
        let error = poll_readable(&[], -1).expect_err("negative timeout");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn polling_no_descriptors_times_out() {
        assert_eq!(poll_readable(&[], 0).expect("poll"), Vec::new());
    }

    #[test]
    fn a_missing_interface_has_no_index() {
        let error = if_index("wsdd2-no-such-if").expect_err("missing interface");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn an_interface_name_with_a_nul_is_refused_before_any_syscall() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let error = bind_to_device(&socket, "br\09").expect_err("NUL in name");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn the_route_probe_reports_the_local_address_for_a_peer() {
        let probe = route_probe_socket(false, None).expect("probe socket");
        probe.connect("127.0.0.1:9").expect("connect");
        let local = probe.local_addr().expect("local address");
        assert_eq!(local.ip(), std::net::IpAddr::from(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn the_clock_reads_a_plausible_time() {
        assert!(now_unix_seconds() > 1_700_000_000);
    }
}
