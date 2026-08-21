#[cfg(target_arch = "arm")]
use nt_event::bounded_message;
use nt_event::EventId;
use std::env;
use std::ffi::OsString;
#[cfg(target_arch = "arm")]
use std::ffi::{c_char, c_int, c_long};
use std::io;
use std::os::unix::ffi::OsStrExt;

#[cfg(target_arch = "arm")]
const MESSAGE_CAPACITY: usize = 512;

#[cfg(target_arch = "arm")]
#[repr(C)]
struct NotifyEvent {
    event: c_int,
    message: [c_char; MESSAGE_CAPACITY],
    timestamp: c_long,
    action: c_int,
    period: c_int,
    guarantee: c_int,
}

#[cfg(target_arch = "arm")]
const _: [(); 532] = [(); std::mem::size_of::<NotifyEvent>()];
#[cfg(target_arch = "arm")]
const _: [(); 4] = [(); std::mem::align_of::<NotifyEvent>()];

#[cfg(target_arch = "arm")]
#[link(name = "nt")]
extern "C" {
    fn initial_nt_event() -> *mut NotifyEvent;
    fn send_trigger_event(event: *mut NotifyEvent) -> c_int;
    fn nt_event_free(event: *mut NotifyEvent);
}

#[cfg(target_arch = "arm")]
#[link(name = "sqlite3")]
extern "C" {}

fn parse_arguments(
    mut arguments: impl Iterator<Item = OsString>,
) -> io::Result<(EventId, OsString)> {
    let program = arguments
        .next()
        .unwrap_or_else(|| OsString::from("Notify_Event2NC"));
    let Some(event) = arguments.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "usage: {} \"EVENT ID\" [\"Message\"]",
                program.to_string_lossy()
            ),
        ));
    };
    let message = arguments.next().unwrap_or_default();
    if arguments.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many arguments",
        ));
    }
    let event = event
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "event ID is not UTF-8"))?;
    let event = EventId::parse(event).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid event ID: {error:?}"),
        )
    })?;
    Ok((event, message))
}

#[cfg(target_arch = "arm")]
fn send(event: EventId, message: &[u8]) -> io::Result<()> {
    // SAFETY: libnt owns the returned allocation and documents this exact
    // fixed-layout structure in nt_common.h. Null is checked before access.
    let notification = unsafe { initial_nt_event() };
    if notification.is_null() {
        return Err(io::Error::other("libnt could not allocate an event"));
    }

    // SAFETY: `notification` is a live, uniquely owned libnt allocation until
    // `nt_event_free`. The bounded copy leaves the final byte NUL-initialized.
    let result = unsafe {
        (*notification).event = event.value();
        (*notification).message.fill(0);
        let message = bounded_message(message);
        std::ptr::copy_nonoverlapping(
            message.as_ptr().cast::<c_char>(),
            (*notification).message.as_mut_ptr(),
            message.len(),
        );
        let result = send_trigger_event(notification);
        nt_event_free(notification);
        result
    };
    if result < 0 {
        Err(io::Error::other(format!(
            "libnt rejected event 0x{:X}",
            event.value()
        )))
    } else {
        Ok(())
    }
}

#[cfg(not(target_arch = "arm"))]
fn send(_event: EventId, _message: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "notification transport is only available in the ARM firmware",
    ))
}

fn run() -> io::Result<()> {
    let (event, message) = parse_arguments(env::args_os())?;
    send(event, message.as_os_str().as_bytes())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Notify_Event2NC: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_optional_message() {
        let (event, message) = parse_arguments(
            ["Notify_Event2NC", "10001", "network down"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap();
        assert_eq!(event.value(), 0x10001);
        assert_eq!(message, "network down");
    }

    #[test]
    fn defaults_to_empty_message() {
        let (_, message) =
            parse_arguments(["Notify_Event2NC", "10001"].into_iter().map(OsString::from)).unwrap();
        assert!(message.is_empty());
    }

    #[test]
    fn rejects_missing_or_extra_arguments() {
        assert!(parse_arguments(["Notify_Event2NC"].into_iter().map(OsString::from)).is_err());
        assert!(parse_arguments(
            ["Notify_Event2NC", "10001", "message", "extra"]
                .into_iter()
                .map(OsString::from)
        )
        .is_err());
    }

    #[cfg(target_arch = "arm")]
    #[test]
    fn arm_abi_matches_public_header() {
        assert_eq!(std::mem::size_of::<NotifyEvent>(), 532);
        assert_eq!(std::mem::align_of::<NotifyEvent>(), 4);
    }
}
