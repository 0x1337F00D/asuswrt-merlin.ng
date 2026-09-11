//! Fail-closed ABI compatibility for the proprietary-free Network Map.
//!
//! ASUS ships the GT-AX11000 Network Map only as a prebuilt executable with a
//! hard `DT_NEEDED` reference to `libbwdpi.so`, even when BWDPI is disabled at
//! build time.  The executable needs two symbols, but guards all DPI lookups
//! with `check_bwdpi_nvram_setting()`.  This local library always reports the
//! removed engine as disabled and returns an empty bounded device record if a
//! future caller nevertheless invokes the lookup.

use std::ffi::{c_char, c_int};

#[repr(C)]
pub struct BwdpiDevice {
    hostname: [c_char; 32],
    vendor_name: [c_char; 100],
    type_name: [c_char; 100],
    device_name: [c_char; 100],
}

#[no_mangle]
pub extern "C" fn check_bwdpi_nvram_setting() -> c_int {
    0
}

/// # Safety
///
/// `device`, when non-null, must point to one writable `BwdpiDevice` supplied
/// by the C caller. The MAC and IP pointers are intentionally never read.
#[no_mangle]
pub unsafe extern "C" fn bwdpi_client_info(
    _mac: *mut c_char,
    _ip_address: *mut c_char,
    device: *mut BwdpiDevice,
) -> c_int {
    if let Some(device) = unsafe { device.as_mut() } {
        // A zero-filled record is the only non-proprietary result this ABI can
        // represent. Return zero, matching the prebuilt caller's no-data path.
        unsafe { std::ptr::write_bytes(device, 0, 1) };
    }
    0
}

/// Build/runtime marker used by image gates to distinguish this two-symbol
/// local shim from the removed proprietary library.
#[no_mangle]
pub extern "C" fn rust_bwdpi_compat_v1() -> c_int {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_is_always_disabled_and_lookup_is_zeroed() {
        let mut device = BwdpiDevice {
            hostname: [1; 32],
            vendor_name: [1; 100],
            type_name: [1; 100],
            device_name: [1; 100],
        };

        assert_eq!(check_bwdpi_nvram_setting(), 0);
        // SAFETY: `device` is a valid writable instance for the call.
        assert_eq!(
            unsafe { bwdpi_client_info(std::ptr::null_mut(), std::ptr::null_mut(), &mut device) },
            0
        );
        assert!(device.hostname.iter().all(|byte| *byte == 0));
        assert!(device.vendor_name.iter().all(|byte| *byte == 0));
        assert!(device.type_name.iter().all(|byte| *byte == 0));
        assert!(device.device_name.iter().all(|byte| *byte == 0));
        assert_eq!(rust_bwdpi_compat_v1(), 1);
    }

    #[test]
    fn null_output_is_a_bounded_noop() {
        // SAFETY: Null is explicitly accepted as an absent output buffer.
        assert_eq!(
            unsafe {
                bwdpi_client_info(
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
    }
}
