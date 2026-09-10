//! Private C bridge. Handles are owned by the caller until the matching free.
//! Calls on a handle must be serialised. Socket descriptors remain C-owned.
#![deny(unsafe_op_in_unsafe_fn)]

use crate::transport::Socket;
use crate::{Configuration, MAX_CERT_BYTES, MAX_KEY_BYTES};
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{BorrowedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

struct Connection {
    tls: rustls::ServerConnection,
    fd: RawFd,
}

fn fail(error: io::Error) -> libc::ssize_t {
    // SAFETY: glibc supplies this thread's live errno slot.
    unsafe {
        *libc::__errno_location() = error.raw_os_error().unwrap_or(match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => libc::ETIMEDOUT,
            io::ErrorKind::InvalidInput => libc::EINVAL,
            _ => libc::EPROTO,
        });
    }
    -1
}

unsafe fn credential(path: *const libc::c_char, limit: usize) -> io::Result<Vec<u8>> {
    if path.is_null() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: the private C API requires a valid NUL-terminated path.
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    if bytes.len() > 4096 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // Opening a mistakenly configured FIFO must not block before metadata
    // validation. O_NONBLOCK has no effect on ordinary certificate files.
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(Path::new(std::ffi::OsStr::from_bytes(bytes)))?;
    if !file.metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(bytes)
}

/// Respect existing socket timeout when shorter than our five-second cap.
fn timeout(fd: RawFd, option: libc::c_int) -> io::Result<Duration> {
    let mut value: libc::timeval = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: live timeval and matching writable length, scalar descriptor.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::timeval).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if value.tv_sec < 0 || value.tv_usec < 0 || value.tv_usec >= 1_000_000 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let configured = Duration::from_secs(value.tv_sec as u64)
        .saturating_add(Duration::from_micros(value.tv_usec as u64));
    let cap = Duration::from_secs(5);
    Ok(if configured.is_zero() {
        cap
    } else {
        configured.min(cap)
    })
}

#[no_mangle]
pub unsafe extern "C" fn rs_mssl_config_new(
    cert: *const libc::c_char,
    key: *const libc::c_char,
    ciphers: *const libc::c_char,
) -> *mut Configuration {
    let result = (|| {
        if !ciphers.is_null() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let cert = unsafe { credential(cert, MAX_CERT_BYTES) }?;
        let key = unsafe { credential(key, MAX_KEY_BYTES) }?;
        Configuration::new(&cert, &key, None)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    })();
    match result {
        Ok(config) => Box::into_raw(Box::new(config)),
        Err(error) => {
            fail(error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_mssl_config_free(config: *mut Configuration) {
    if !config.is_null() {
        // SAFETY: caller transfers a live unique handle from config_new once.
        drop(unsafe { Box::from_raw(config) });
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_mssl_key_match(
    cert: *const libc::c_char,
    key: *const libc::c_char,
) -> libc::c_int {
    match (unsafe { credential(cert, MAX_CERT_BYTES) }, unsafe {
        credential(key, MAX_KEY_BYTES)
    }) {
        (Ok(cert), Ok(key)) => crate::certificate_key_match(&cert, &key).into(),
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_mssl_accept(
    config: *const Configuration,
    fd: RawFd,
) -> *mut libc::c_void {
    let result = (|| {
        if config.is_null() || fd < 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: C keeps config and fd alive throughout this call.
        let config = unsafe { &*config };
        let mut tls = config
            .connection()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let deadline = timeout(fd, libc::SO_RCVTIMEO)?.min(timeout(fd, libc::SO_SNDTIMEO)?);
        let mut socket = Socket::new(unsafe { BorrowedFd::borrow_raw(fd) }, deadline)?;
        tls.complete_io(&mut socket)?;
        if tls.is_handshaking() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(Connection { tls, fd })
    })();
    match result {
        Ok(connection) => Box::into_raw(Box::new(connection)).cast(),
        Err(error) => {
            fail(error);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_mssl_read(
    handle: *mut libc::c_void,
    bytes: *mut u8,
    len: usize,
) -> libc::ssize_t {
    if handle.is_null() || len > isize::MAX as usize || (len != 0 && bytes.is_null()) {
        return fail(io::ErrorKind::InvalidInput.into());
    }
    if len == 0 {
        return 0;
    }
    // SAFETY: C owns this unique connection and a writable buffer of len.
    let connection = unsafe { &mut *handle.cast::<Connection>() };
    let bytes = unsafe { std::slice::from_raw_parts_mut(bytes, len) };
    let result = (|| {
        let mut socket = Socket::new(
            unsafe { BorrowedFd::borrow_raw(connection.fd) },
            timeout(connection.fd, libc::SO_RCVTIMEO)?,
        )?;
        rustls::Stream::new(&mut connection.tls, &mut socket).read(bytes)
    })();
    match result {
        Ok(n) => n as libc::ssize_t,
        Err(error) => fail(error),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_mssl_write(
    handle: *mut libc::c_void,
    bytes: *const u8,
    len: usize,
) -> libc::ssize_t {
    if handle.is_null() || len > isize::MAX as usize || (len != 0 && bytes.is_null()) {
        return fail(io::ErrorKind::InvalidInput.into());
    }
    if len == 0 {
        return 0;
    }
    // SAFETY: C owns this unique connection and a readable buffer of len.
    let connection = unsafe { &mut *handle.cast::<Connection>() };
    let bytes = unsafe { std::slice::from_raw_parts(bytes, len) };
    let result = (|| {
        let mut socket = Socket::new(
            unsafe { BorrowedFd::borrow_raw(connection.fd) },
            timeout(connection.fd, libc::SO_SNDTIMEO)?,
        )?;
        let mut stream = rustls::Stream::new(&mut connection.tls, &mut socket);
        stream.write_all(bytes)?;
        stream.flush()
    })();
    match result {
        Ok(()) => len as libc::ssize_t,
        Err(error) => fail(error),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_mssl_close(handle: *mut libc::c_void) {
    if handle.is_null() {
        return;
    }
    // SAFETY: caller transfers its unique handle exactly once. FD stays owned
    // by httpd, matching SSL_free (which did not close SSL_set_fd's socket).
    let mut connection = unsafe { Box::from_raw(handle.cast::<Connection>()) };
    connection.tls.send_close_notify();
    if let Ok(mut socket) = Socket::new(
        unsafe { BorrowedFd::borrow_raw(connection.fd) },
        Duration::from_millis(200),
    ) {
        while connection.tls.wants_write() {
            match connection.tls.write_tls(&mut socket) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }
}
