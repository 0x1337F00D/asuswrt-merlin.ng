//! The only module of this crate that contains `unsafe`.
//!
//! Every function here wraps one libc call, validates its arguments in safe
//! Rust first and converts the result into an `io::Result`. Nothing in this
//! module keeps a raw pointer beyond the call it is passed to.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

use ntp::packet::NTP_TO_UNIX_EPOCH;

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

/// Waits for readability on `descriptors` for at most `timeout_ms`.
///
/// Returns the descriptors that became ready, as a parallel vector of flags.
///
/// # Errors
/// Returns the `poll` error; `EINTR` is reported so the caller can service a
/// signal and loop.
pub fn poll_readable(descriptors: &[RawFd], timeout_ms: i32) -> io::Result<Vec<bool>> {
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
    let result = unsafe {
        libc::poll(
            entries.as_mut_ptr(),
            count as libc::nfds_t,
            timeout_ms.max(0),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(entries.iter().map(|entry| entry.revents != 0).collect())
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
