//! The only module of this crate that contains `unsafe`.
//!
//! Every function here wraps one libc call, validates its arguments in safe
//! Rust first and converts the result into an `io::Result`. Nothing in this
//! module keeps a raw pointer beyond the call it is passed to.

use std::ffi::CString;
use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

use ntp::packet::NTP_TO_UNIX_EPOCH;

/// Set by the signal handler; read by the main loop.
static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Eight unpredictable bytes, only after the kernel random pool is ready.
/// Linux 4.1 may expose /dev/urandom before initialization. GRND_NONBLOCK
/// returns EAGAIN in that window instead of supplying weak bytes or blocking
/// the daemon. Calling syscall directly avoids a GLIBC_2.25 getrandom symbol
/// requirement on the firmware's libc. ENOSYS also fails closed.
pub fn secure_random_bytes() -> io::Result<[u8; 8]> {
    read_random_bytes_with(|buffer| {
        // SAFETY: buffer is an exclusive live slice for exactly the length
        // passed. The kernel writes at most that length and retains nothing.
        // SYS_getrandom and GRND_NONBLOCK are target-specific libc constants;
        // syscall itself is available on the original firmware's glibc.
        let result = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                buffer.as_mut_ptr(),
                buffer.len(),
                libc::GRND_NONBLOCK,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    })
}

/// Safe short-read/error handling shared with injected syscall tests.
fn read_random_bytes_with(
    mut read: impl FnMut(&mut [u8]) -> io::Result<usize>,
) -> io::Result<[u8; 8]> {
    let mut bytes = [0_u8; 8];
    let mut filled = 0;
    while filled < bytes.len() {
        let remaining = &mut bytes[filled..];
        // In particular EAGAIN, ENOSYS and EINTR return immediately. The
        // daemon's next bounded query slot retries without busy looping.
        let received = read(remaining)?;
        if received == 0 || received > remaining.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete getrandom result",
            ));
        }
        filled += received;
    }
    Ok(bytes)
}

/// Returns and clears the signal number recorded by the handler.
pub fn take_pending_signal() -> i32 {
    PENDING_SIGNAL.swap(0, Ordering::Relaxed)
}

extern "C" fn record_signal(number: libc::c_int) {
    // Async-signal-safe: a single relaxed atomic store and nothing else.
    PENDING_SIGNAL.store(number, Ordering::Relaxed);
}

/// Installs the handlers busybox's ntpd installed: record `SIGTERM`/`SIGINT`
/// so the loop can exit cleanly, and ignore `SIGPIPE`/`SIGCHLD` so a `-S`
/// script that is never waited for leaves no zombie.
///
/// `killall_tk("ntp")` sends `SIGTERM` and then `SIGKILL`; the second one
/// cannot be caught, which is why the loop must be able to exit on the first.
pub fn install_signal_handlers() {
    for number in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: `record_signal` has the C ABI and signature signal(2)
        // requires, and its body performs only an atomic store, so it is
        // async-signal-safe.
        unsafe {
            libc::signal(number, record_signal as libc::sighandler_t);
        }
    }
    for number in [libc::SIGPIPE, libc::SIGCHLD] {
        // SAFETY: SIG_IGN is a valid disposition for both signals and takes
        // no pointer arguments.
        unsafe {
            libc::signal(number, libc::SIG_IGN);
        }
    }
}

/// Current real time as seconds since the NTP era-0 epoch (1900-01-01).
pub fn now_ntp_seconds() -> f64 {
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
    value.tv_sec as f64 + value.tv_nsec as f64 / 1e9 + NTP_TO_UNIX_EPOCH as f64
}

/// Steps the system clock by `offset` seconds.
///
/// # Errors
/// Returns the `clock_gettime`/`clock_settime` error.
pub fn step_clock(offset: f64) -> io::Result<()> {
    if !offset.is_finite() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "offset is not finite",
        ));
    }
    let mut current = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: as in `now_ntp_seconds`, a single owned `timespec` is written.
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut current) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let target = current.tv_sec as f64 + current.tv_nsec as f64 / 1e9 + offset;
    if !target.is_finite() || target <= 0.0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stepped time is out of range",
        ));
    }
    let seconds = target.floor();
    if seconds >= libc::time_t::MAX as f64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stepped time is out of range",
        ));
    }
    let updated = libc::timespec {
        tv_sec: seconds as libc::time_t,
        tv_nsec: ((target - seconds) * 1e9).clamp(0.0, 999_999_999.0) as libc::c_long,
    };
    // SAFETY: `updated` is a fully initialised `timespec` that outlives the
    // call, and its fields were range-checked above.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &updated) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Hands one PLL update to the kernel and returns the resulting frequency
/// offset in ppm (`timex.freq / 65536`).
///
/// # Errors
/// Returns the `adjtimex` error. A negative return is an error; a non-zero
/// non-negative return is a clock state, not a failure.
pub fn adjust_clock(offset_micros: i64, status: i32, constant: i32) -> io::Result<i64> {
    // SAFETY: `timex` is a plain-old-data struct; an all-zero value is the
    // documented way to build one before setting the modes of interest.
    let mut timex: libc::timex = unsafe { std::mem::zeroed() };
    timex.modes = libc::ADJ_OFFSET | libc::ADJ_STATUS | libc::ADJ_TIMECONST;
    timex.offset = clamp_to_long(offset_micros);
    timex.status = status;
    timex.constant = clamp_to_long(i64::from(constant));
    // SAFETY: `timex` is a live, fully initialised value owned by this frame;
    // adjtimex reads and writes exactly that one struct.
    let result = unsafe { libc::adjtimex(&mut timex) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(long_to_i64(timex.freq) / 65_536)
}

/// Reads the kernel frequency offset in ppm without changing anything.
pub fn kernel_freq_ppm() -> i64 {
    // SAFETY: see `adjust_clock`; `modes == 0` is a pure query.
    let mut timex: libc::timex = unsafe { std::mem::zeroed() };
    timex.modes = 0;
    // SAFETY: one live, initialised struct is passed and written.
    if unsafe { libc::adjtimex(&mut timex) } < 0 {
        return 0;
    }
    long_to_i64(timex.freq) / 65_536
}

/// Widens a `c_long`, which is 32 bits on armv7 and 64 bits on the test host.
#[cfg(target_pointer_width = "32")]
fn long_to_i64(value: libc::c_long) -> i64 {
    i64::from(value)
}

/// Widens a `c_long`, which is 32 bits on armv7 and 64 bits on the test host.
#[cfg(target_pointer_width = "64")]
fn long_to_i64(value: libc::c_long) -> i64 {
    value
}

#[cfg(target_pointer_width = "32")]
fn clamp_to_long(value: i64) -> libc::c_long {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as libc::c_long
}

#[cfg(target_pointer_width = "64")]
fn clamp_to_long(value: i64) -> libc::c_long {
    value as libc::c_long
}

/// Binds a socket to one network interface.
///
/// This is the same `SO_BINDTODEVICE` pattern the `infosvr` port uses; it is
/// what keeps server mode on the LAN bridge and off the WAN.
///
/// # Errors
/// Returns the `setsockopt` error, or `InvalidInput` for a name with a NUL.
pub fn bind_to_device(socket: &impl AsRawFd, interface: &str) -> io::Result<()> {
    let name = CString::new(interface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
    // SAFETY: `name` outlives the call and its pointer addresses exactly
    // `as_bytes_with_nul().len()` initialised bytes; the file descriptor is
    // owned by the caller and valid for the duration of the borrow.
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

/// Creates a UDP socket, pins it to `interface` and only then binds it to
/// `port` on every address that interface carries.
///
/// The order is the point. `UdpSocket::bind` followed by `SO_BINDTODEVICE`
/// leaves the socket bound on *every* interface -- the WAN included -- for the
/// window between the two calls, and leaves it bound there for good if the
/// second call fails. Setting the device on a socket that is not bound yet
/// means the port is never reachable anywhere but the named interface, and an
/// interface that does not exist fails before anything is bound at all.
///
/// # Errors
/// Returns the `socket`, `setsockopt` or `bind` error, or `InvalidInput` for
/// an interface name containing a NUL. The descriptor is closed on every
/// error path, so a failure leaks nothing.
pub fn bind_udp_to_device(port: u16, interface: Option<&str>) -> io::Result<UdpSocket> {
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
    // is not owned by anything else, so `OwnedFd` may take it. From here on
    // every early return closes it through that ownership.
    let owned = unsafe { OwnedFd::from_raw_fd(descriptor) };
    if let Some(interface) = interface {
        bind_to_device(&owned, interface)?;
    }
    // SAFETY: `sockaddr_in` is plain-old-data; an all-zero value is the
    // documented starting point and every field used below is set explicitly.
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    address.sin_family = libc::AF_INET as libc::sa_family_t;
    address.sin_port = port.to_be();
    address.sin_addr.s_addr = libc::INADDR_ANY.to_be();
    // SAFETY: `address` is a live, fully initialised `sockaddr_in` owned by
    // this frame and the length passed is exactly its size; the descriptor is
    // owned by `owned` for the whole call.
    let result = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            std::ptr::addr_of!(address).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(UdpSocket::from(owned))
}

/// `IPTOS_DSCP_AF21`, the DSCP class busybox's ntpd marked its packets with.
pub const IPTOS_DSCP_AF21: libc::c_int = 0x48;

/// Marks a socket's outgoing packets with `IPTOS_DSCP_AF21`. Best effort: a
/// failure only costs queueing priority.
pub fn set_tos(socket: &impl AsRawFd) {
    let value: libc::c_int = IPTOS_DSCP_AF21;
    // SAFETY: `value` is a live, initialised `c_int` and its length is passed
    // exactly; the descriptor is owned by the caller.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_TOS,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// What one descriptor reported in a [`poll_readable`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readiness {
    /// Nothing happened before the timeout expired.
    Idle,
    /// `POLLIN`: a datagram is queued and `recv` will return it.
    Readable,
    /// `POLLERR`, `POLLHUP` or `POLLNVAL`: the descriptor is in an error
    /// state. Reporting this as readable would make a caller that keeps the
    /// descriptor in its poll set spin at full speed forever, because the
    /// condition is level-triggered and no read clears it, so the caller has
    /// to be told the difference and act on it.
    Errored,
}

/// Waits for readability on `descriptors` for at most `timeout_ms`.
///
/// Returns one [`Readiness`] per descriptor, in the order they were given.
///
/// # Errors
/// Returns the `poll` error; `EINTR` is reported so the caller can service a
/// signal and loop. A negative `timeout_ms` is `InvalidInput`: poll(2) reads it
/// as "block forever", and clamping it to zero instead would turn a caller's
/// arithmetic mistake into a busy loop, so neither is done silently.
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

/// Detaches from the controlling terminal exactly as busybox's
/// `bb_daemonize_or_rexec(DAEMON_DEVNULL_STDIO)` did: fork, let the parent
/// exit, start a new session and point the three standard descriptors at
/// `/dev/null`.
///
/// `rc` starts this daemon through `_eval(argv, NULL, 0, &pid)`, which forks
/// and returns immediately without waiting, so the process that survives is
/// this child. It is named `ntp`, which is what `pids("ntp")` matches.
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

/// Raises the scheduling priority for `-N`. Best effort.
pub fn raise_priority() {
    // SAFETY: setpriority takes only scalars and affects this process alone.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, -15);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unready_unsupported_and_interrupted_getrandom_fail_without_retrying() {
        for errno in [libc::EAGAIN, libc::ENOSYS, libc::EINTR, libc::EPERM] {
            let mut calls = 0;
            let result = read_random_bytes_with(|_| {
                calls += 1;
                Err(io::Error::from_raw_os_error(errno))
            });
            assert_eq!(result.unwrap_err().raw_os_error(), Some(errno));
            assert_eq!(calls, 1, "entropy errors must not spin or block the daemon");
        }
    }

    #[test]
    fn getrandom_short_reads_fill_all_eight_bytes_before_returning() {
        let mut calls = 0;
        let bytes = read_random_bytes_with(|buffer| {
            calls += 1;
            let count = buffer.len().min(3);
            buffer[..count].fill(calls);
            Ok(count)
        })
        .unwrap();
        assert_eq!(bytes, [1, 1, 1, 2, 2, 2, 3, 3]);
        assert_eq!(calls, 3);
    }

    #[test]
    fn failed_partial_getrandom_never_exposes_partial_entropy() {
        let mut calls = 0;
        let result = read_random_bytes_with(|buffer| {
            calls += 1;
            if calls == 1 {
                buffer[0] = 42;
                Ok(1)
            } else {
                Err(io::Error::from_raw_os_error(libc::EAGAIN))
            }
        });
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EAGAIN));
        assert_eq!(calls, 2);
        assert!(read_random_bytes_with(|_| Ok(0)).is_err());
        assert!(read_random_bytes_with(|buffer| Ok(buffer.len() + 1)).is_err());
    }
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    /// A free UDP port on the loopback interface, held open by the returned
    /// socket so nothing else can take it while the test runs.
    fn held_port() -> (UdpSocket, u16) {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a loopback port");
        let port = socket.local_addr().expect("a local address").port();
        (socket, port)
    }

    #[test]
    fn the_device_is_pinned_before_the_port_is_bound() {
        // Regression: the daemon used to call `UdpSocket::bind` first and
        // `SO_BINDTODEVICE` afterwards, so the socket existed on every
        // interface -- the WAN included -- until the second call returned.
        //
        // The order is observable: with the port already taken, binding first
        // fails with `AddrInUse`, while pinning first fails on the interface
        // and never reaches the bind at all.
        let (_holder, port) = held_port();
        let error = bind_udp_to_device(port, Some("ntp-no-such-if"))
            .expect_err("a missing interface cannot be bound to");
        assert_ne!(
            error.kind(),
            io::ErrorKind::AddrInUse,
            "the port was bound before the interface was pinned: {error}"
        );
    }

    #[test]
    fn a_failed_bind_leaks_no_descriptor() {
        // Every error path has to drop the raw descriptor. Two hundred
        // failures inside the default file-descriptor limit would exhaust it
        // if any of them leaked.
        for _ in 0..200 {
            assert!(bind_udp_to_device(0, Some("ntp-no-such-if")).is_err());
        }
        let socket = bind_udp_to_device(0, None).expect("descriptors are still available");
        assert!(socket.local_addr().expect("a local address").is_ipv4());
    }

    #[test]
    fn an_unpinned_socket_binds_the_requested_port() {
        let socket = bind_udp_to_device(0, None).expect("an unpinned socket binds");
        let address = socket.local_addr().expect("a local address");
        assert!(address.is_ipv4());
        assert_ne!(address.port(), 0);
    }

    #[test]
    fn an_interface_name_with_a_nul_is_refused() {
        let error = bind_udp_to_device(0, Some("br\u{0}0")).expect_err("a NUL is not a name");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn readable_and_errored_descriptors_are_told_apart() {
        // Regression: `poll_readable` reported any non-zero `revents` as
        // readable, so a hung-up descriptor looked like data forever and spun
        // the main loop.
        let (mut writer, reader) = UnixStream::pair().expect("a socket pair");
        writer
            .write_all(b"x")
            .expect("a byte fits in the pipe buffer");
        let ready = poll_readable(&[reader.as_raw_fd()], 0).expect("poll");
        assert_eq!(ready, vec![Readiness::Readable]);

        let (writer, reader) = UnixStream::pair().expect("a socket pair");
        drop(writer);
        let ready = poll_readable(&[reader.as_raw_fd()], 0).expect("poll");
        assert_eq!(ready, vec![Readiness::Errored]);
    }

    #[test]
    fn an_idle_descriptor_is_neither_readable_nor_errored() {
        let (_writer, reader) = UnixStream::pair().expect("a socket pair");
        let ready = poll_readable(&[reader.as_raw_fd()], 0).expect("poll");
        assert_eq!(ready, vec![Readiness::Idle]);
    }

    #[test]
    fn a_negative_timeout_is_an_error_rather_than_a_busy_poll() {
        // Regression: the timeout was clamped with `max(0)`, which turned a
        // negative value into a zero-timeout poll and spun the main loop.
        let (_writer, reader) = UnixStream::pair().expect("a socket pair");
        let error = poll_readable(&[reader.as_raw_fd()], -1).expect_err("a negative timeout");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn polling_no_descriptors_returns_no_flags() {
        assert!(poll_readable(&[], 0).expect("poll").is_empty());
    }
}
