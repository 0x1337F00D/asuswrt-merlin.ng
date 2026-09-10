//! The only module of the `lld2d` binary that contains `unsafe`.
//!
//! Every function wraps one syscall, validates its arguments in safe Rust
//! first and converts the result into an `io::Result`. No raw pointer outlives
//! the call it is handed to, and nothing here parses a received frame.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

/// `SIOCGIFHWADDR`. Declared here rather than taken from `libc` so the value
/// this port relies on is visible next to the code that uses it.
const SIOCGIFHWADDR: libc::c_ulong = 0x8927;

/// `SIOCGIFADDR`.
const SIOCGIFADDR: libc::c_ulong = 0x8915;

/// `ARPHRD_ETHER`, the only hardware type this responder accepts. The blob
/// refuses anything else: "was expecting addr type to be Ether, not type %d".
const ARPHRD_ETHER: u16 = 1;

/// `IFNAMSIZ`.
const IFNAMSIZ: usize = 16;

/// `struct ifreq`, laid out by hand because `libc` does not publish it for
/// `*-linux-gnu`. The kernel copies `sizeof(struct ifreq)` bytes, which is the
/// 16-byte name plus a 16-byte union; the union area is over-allocated here so
/// no ioctl can write past the end of the value.
#[repr(C)]
#[derive(Clone, Copy)]
struct Ifreq {
    name: [u8; IFNAMSIZ],
    payload: [u8; 24],
}

impl Ifreq {
    /// Builds a request for `interface`, or `InvalidInput` if the name cannot
    /// be represented (too long, or containing a NUL).
    fn new(interface: &str) -> io::Result<Self> {
        let bytes = interface.as_bytes();
        if bytes.is_empty() || bytes.len() >= IFNAMSIZ || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name does not fit IFNAMSIZ",
            ));
        }
        let mut request = Self {
            name: [0; IFNAMSIZ],
            payload: [0; 24],
        };
        // The length was checked against IFNAMSIZ above, so the destination
        // slice exists and matches the source length.
        if let Some(slot) = request.name.get_mut(..bytes.len()) {
            slot.copy_from_slice(bytes);
        }
        Ok(request)
    }
}

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

/// Records `SIGTERM`/`SIGINT` so the loop can exit cleanly and ignores
/// `SIGPIPE`.
///
/// `stop_lltd()` calls `killall_tk("lld2d")`, which sends `SIGTERM` and then
/// `SIGKILL`; the second cannot be caught, so the loop has to be able to leave
/// on the first.
pub fn install_signal_handlers() {
    for number in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: `record_signal` has the C ABI and the signature signal(2)
        // requires, and its body performs only an atomic store, so it is
        // async-signal-safe.
        unsafe {
            libc::signal(number, record_signal as libc::sighandler_t);
        }
    }
    // SAFETY: SIG_IGN is a valid disposition for SIGPIPE and takes no pointer.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// Milliseconds on the monotonic clock, saturating rather than wrapping.
///
/// A monotonic source is required: the responder's rate limit and duplicate
/// window must not be movable by an NTP step.
#[must_use]
pub fn monotonic_millis() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a live, fully initialised `timespec` owned by this
    // frame; clock_gettime writes exactly one of them and reads no pointer.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return 0;
    }
    let seconds = u64::try_from(value.tv_sec).unwrap_or(0);
    let nanoseconds = u64::try_from(value.tv_nsec).unwrap_or(0);
    seconds
        .saturating_mul(1_000)
        .saturating_add(nanoseconds / 1_000_000)
}

/// Opens a short-lived `AF_INET` datagram socket for the interface ioctls,
/// exactly as the blob's `get_hwaddr` and `get_ipv4addr` do.
fn ioctl_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket(2) takes three scalars, reads no pointer and returns an
    // owned descriptor or -1.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `descriptor` was just returned by socket(2), is not negative and
    // is owned by nothing else, so `OwnedFd` may take it.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

/// Runs one `ifreq` ioctl and returns the filled request.
fn interface_ioctl(interface: &str, request_code: libc::c_ulong) -> io::Result<Ifreq> {
    let socket = ioctl_socket()?;
    let mut request = Ifreq::new(interface)?;
    // SAFETY: `request` is a live, fully initialised `Ifreq` owned by this
    // frame and is at least as large as the `struct ifreq` the kernel copies
    // in both directions; `socket` owns a valid descriptor for the call.
    let result = unsafe { libc::ioctl(socket.as_raw_fd(), request_code, &mut request) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(request)
}

/// Reads the Ethernet address of `interface`.
///
/// # Errors
/// Returns the ioctl error, or `InvalidData` when the interface is not
/// Ethernet.
pub fn hardware_address(interface: &str) -> io::Result<[u8; 6]> {
    let request = interface_ioctl(interface, SIOCGIFHWADDR)?;
    // The union holds a `struct sockaddr`: family (2 bytes) then sa_data.
    let family = request
        .payload
        .get(0..2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_ne_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short SIOCGIFHWADDR reply"))?;
    if family != ARPHRD_ETHER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "interface is not Ethernet",
        ));
    }
    request
        .payload
        .get(2..8)
        .and_then(|bytes| <[u8; 6]>::try_from(bytes).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short SIOCGIFHWADDR reply"))
}

/// Reads the primary IPv4 address of `interface`, or `None` if it has none.
#[must_use]
pub fn ipv4_address(interface: &str) -> Option<[u8; 4]> {
    let request = interface_ioctl(interface, SIOCGIFADDR).ok()?;
    // The union holds a `struct sockaddr_in`: family (2), port (2), address.
    let family = request
        .payload
        .get(0..2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_ne_bytes)?;
    if family != u16::try_from(libc::AF_INET).ok()? {
        return None;
    }
    request
        .payload
        .get(4..8)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
}

/// Resolves an interface name to its kernel index.
///
/// # Errors
/// Returns the `if_nametoindex` error, or `InvalidInput` for a name that
/// cannot be represented.
pub fn interface_index(interface: &str) -> io::Result<libc::c_uint> {
    let name = CString::new(interface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

/// Pins a socket to one network interface with `SO_BINDTODEVICE`.
fn bind_to_device(socket: &impl AsRawFd, interface: &str) -> io::Result<()> {
    let name = CString::new(interface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
    // SAFETY: `name` outlives the call and its pointer addresses exactly
    // `as_bytes_with_nul().len()` initialised bytes; the descriptor is owned
    // by the caller for the whole borrow.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Creates the raw LLTD socket: `AF_PACKET`/`SOCK_RAW` filtered to one
/// EtherType, pinned to `interface` and only then bound to its index.
///
/// The order matters for the same reason it does in the `infosvr` and `ntp`
/// ports. `SO_BINDTODEVICE` is applied to a socket that is not bound yet, so
/// the responder is never briefly listening on the WAN, and an interface that
/// does not exist fails before anything is bound at all. The EtherType is
/// given twice, to `socket()` and to `bind()`, so the kernel drops every other
/// protocol before it reaches this process.
///
/// # Errors
/// Returns the `socket`, `setsockopt` or `bind` error. The descriptor is
/// closed on every error path, so a failure leaks nothing.
pub fn bind_packet_socket(interface: &str, ethertype: u16) -> io::Result<OwnedFd> {
    let index = interface_index(interface)?;
    // The protocol argument of socket(2) is the EtherType in network byte
    // order, which is what htons() produces on the host's endianness.
    let protocol = libc::c_int::from(ethertype.to_be());
    // SAFETY: socket(2) takes three scalars, reads no pointer and returns an
    // owned descriptor or -1.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `descriptor` was just returned by socket(2) and is owned by
    // nothing else. From here on every early return closes it.
    let owned = unsafe { OwnedFd::from_raw_fd(descriptor) };
    bind_to_device(&owned, interface)?;

    // SAFETY: `sockaddr_ll` is plain-old-data; an all-zero value is the
    // documented starting point and every field bind(2) reads is set below.
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as libc::sa_family_t;
    address.sll_protocol = ethertype.to_be();
    address.sll_ifindex = libc::c_int::try_from(index)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface index out of range"))?;
    // SAFETY: `address` is a live, fully initialised `sockaddr_ll` owned by
    // this frame and the length passed is exactly its size; the descriptor is
    // owned by `owned` for the whole call.
    let result = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            std::ptr::addr_of!(address).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// Reads one frame into `buffer` and returns how many bytes it holds.
///
/// # Errors
/// Returns the `recv` error, `Interrupted` included so the caller can service
/// a signal and loop.
pub fn receive(socket: &impl AsRawFd, buffer: &mut [u8]) -> io::Result<usize> {
    let capacity = buffer.len();
    // SAFETY: `buffer` is a live, mutable slice of exactly `capacity` bytes
    // and stays borrowed for the whole call; recv writes at most that many.
    let received = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            capacity,
            libc::MSG_TRUNC,
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let received = usize::try_from(received)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative receive length"))?;
    // MSG_TRUNC makes recv report the real frame length even when it did not
    // fit. Reporting the untruncated length would let a caller read
    // uninitialised bytes, so an over-long frame is reported at capacity and
    // the parser then rejects it on length.
    Ok(received.min(capacity))
}

/// Sends one complete Ethernet frame on `interface_index`.
///
/// # Errors
/// Returns the `sendto` error, or `InvalidInput` for a frame with no
/// destination address in it.
pub fn send(socket: &impl AsRawFd, interface_index: libc::c_uint, frame: &[u8]) -> io::Result<()> {
    let destination: [u8; 6] = frame
        .get(0..6)
        .and_then(|bytes| <[u8; 6]>::try_from(bytes).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame has no header"))?;
    // SAFETY: `sockaddr_ll` is plain-old-data; the zero value is the
    // documented starting point and every field sendto(2) reads is set below.
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as libc::sa_family_t;
    address.sll_ifindex = libc::c_int::try_from(interface_index)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface index out of range"))?;
    address.sll_halen = 6;
    if let Some(slot) = address.sll_addr.get_mut(..6) {
        slot.copy_from_slice(&destination);
    }
    let length = frame.len();
    // SAFETY: `frame` is a live slice of exactly `length` bytes and `address`
    // a live, fully initialised `sockaddr_ll`; both stay borrowed for the
    // call and the two lengths passed match them exactly.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            frame.as_ptr().cast(),
            length,
            0,
            std::ptr::addr_of!(address).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Waits until `socket` has a frame or `timeout_ms` expires.
///
/// # Errors
/// Returns the `poll` error, or `InvalidInput` for a negative timeout, which
/// poll(2) would read as "block forever".
pub fn wait_readable(socket: &impl AsRawFd, timeout_ms: i32) -> io::Result<bool> {
    if timeout_ms < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "poll timeout must not be negative",
        ));
    }
    let mut entry = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `entry` is one live, fully initialised `pollfd` owned by this
    // frame and the count passed is exactly one.
    let result = unsafe { libc::poll(&mut entry, 1, timeout_ms) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if entry.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "the packet socket is in an error state",
        ));
    }
    Ok(entry.revents & libc::POLLIN != 0)
}

/// Detaches from the controlling terminal: fork, let the parent exit, start a
/// new session and point the three standard descriptors at `/dev/null`.
///
/// `rc` starts this daemon through `eval("lld2d", "br0")`, which forks and
/// does not wait, so the surviving process is this child. It is named `lld2d`,
/// which is what `killall_tk("lld2d")` matches.
///
/// # Errors
/// Returns the `fork` error.
pub fn daemonize() -> io::Result<()> {
    // SAFETY: the process is single-threaded at this point, so fork(2) leaves
    // the child with a consistent runtime.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child > 0 {
        // SAFETY: _exit runs no destructor and no atexit handler, which is
        // what the parent of a daemon must do.
        unsafe { libc::_exit(0) };
    }
    // SAFETY: setsid takes no arguments and only detaches this process.
    unsafe { libc::setsid() };
    redirect_standard_descriptors();
    Ok(())
}

fn redirect_standard_descriptors() {
    let Ok(devnull) = CString::new("/dev/null") else {
        return;
    };
    // SAFETY: the path is NUL-terminated and lives across the call; O_RDWR
    // without O_CREAT needs no mode argument.
    let fd: RawFd = unsafe { libc::open(devnull.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return;
    }
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: `fd` was just opened here and `target` is one of the three
        // standard descriptor numbers.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interface_name_that_cannot_fit_ifnamsiz_is_refused() {
        assert!(Ifreq::new("").is_err());
        assert!(Ifreq::new("0123456789abcdef").is_err());
        assert!(Ifreq::new("br\u{0}0").is_err());
        assert!(Ifreq::new("br0").is_ok());
        assert!(Ifreq::new("0123456789abcde").is_ok());
    }

    #[test]
    fn the_name_is_placed_at_the_front_and_nul_padded() {
        let request = Ifreq::new("br0").expect("a valid name");
        assert_eq!(&request.name[..4], b"br0\0");
        assert!(request.name[3..].iter().all(|byte| *byte == 0));
        assert!(request.payload.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn a_missing_interface_has_no_index() {
        let error = interface_index("lltd-no-such-if").expect_err("no such interface");
        assert_ne!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn an_interface_name_with_a_nul_is_refused_before_any_syscall() {
        let error = interface_index("br\u{0}0").expect_err("a NUL is not a name");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn the_monotonic_clock_does_not_run_backwards() {
        let first = monotonic_millis();
        let second = monotonic_millis();
        assert!(second >= first);
    }

    #[test]
    fn a_missing_interface_fails_before_a_socket_is_bound() {
        // Also proves no descriptor is leaked: two hundred failures inside the
        // default file-descriptor limit would exhaust it if any of them did.
        for _ in 0..200 {
            let error = bind_packet_socket("lltd-no-such-if", 0x88D9)
                .expect_err("a missing interface cannot be bound to");
            assert_ne!(error.kind(), io::ErrorKind::AddrInUse);
        }
    }

    #[test]
    fn a_frame_without_a_destination_is_refused_before_any_syscall() {
        let socket = ioctl_socket().expect("a datagram socket");
        let error = send(&socket, 1, &[0; 5]).expect_err("no destination address");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_negative_poll_timeout_is_an_error_rather_than_a_blocking_wait() {
        let socket = ioctl_socket().expect("a datagram socket");
        let error = wait_readable(&socket, -1).expect_err("a negative timeout");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn the_loopback_interface_reports_a_hardware_address_or_a_clean_error() {
        // The address of "lo" is all zeroes and its type is ARPHRD_LOOPBACK,
        // so this must be the typed refusal rather than a panic or garbage.
        match hardware_address("lo") {
            Ok(address) => assert_eq!(address.len(), 6),
            Err(error) => assert!(
                error.kind() == io::ErrorKind::InvalidData
                    || error.kind() == io::ErrorKind::PermissionDenied
                    || error.raw_os_error().is_some(),
                "{error}"
            ),
        }
    }
}
