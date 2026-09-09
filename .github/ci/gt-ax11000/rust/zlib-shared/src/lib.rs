//! `libz.so.1` for the GT-AX11000 rootfs, built from zlib-rs.
//!
//! Every firmware package that links `-lz` resolves against the vendor
//! `zlib/libz.so` at build time and against `/usr/lib/libz.so.1` at run time.
//! This crate provides the run-time object.  The vendor `zlib` package is
//! still built and staged, because it owns `zlib.h`/`zconf.h`, the link-time
//! `libz.so` every consumer compiles against, and the `libz.a` archive.
//!
//! Two link arguments make the result a drop-in replacement, and both come
//! from the firmware Makefile (`zlib-install`) rather than from a `build.rs`,
//! so this crate stays build-system-free like every other component here:
//!
//! * `-Wl,-soname,libz.so.1` — consumers record `NEEDED libz.so.1` from the
//!   vendor link-time object, so the replacement must answer to that name.
//! * `-Wl,--version-script=libz.map` — [`libz.map`] next to this file
//!   reproduces the vendor `zlib/zlib.map`: the same `ZLIB_1.2.*` nodes with
//!   the same members, so an already-linked consumer that references
//!   `inflateReset2@ZLIB_1.2.3.4` still resolves, and the zlib-rs-only
//!   extensions the vendor never published stay hidden.
//!
//! # Why this is a `staticlib` and not a `cdylib`
//!
//! A `cdylib` cannot carry a versioned symbol table on this toolchain.  For
//! every `cdylib`, `rustc` unconditionally appends its own *anonymous*
//! version script (`-Wl,--version-script=<tmp>/list`, containing
//! `{ global: ...; local: *; };`) to limit the exported set, and there is no
//! stable switch to suppress it.  GNU `ld` 2.28.1 then refuses the
//! combination:
//!
//! ```text
//! ld: unable to find version dependency `ZLIB_1.2.0.2'
//! ld: anonymous version tag cannot be combined with other version tags
//! ```
//!
//! The alternative — shipping an unversioned `libz.so.1` — would make every
//! consumer that references `inflate@ZLIB_1.2.0` fall back to the base
//! definition and make `ld.so` print `no version information available` for
//! each of them.  So the crate is compiled to a static archive and the
//! Makefile performs the final `$(CC) -shared` link, which owns the SONAME
//! and the version script outright.  `--whole-archive` pulls the complete
//! archive in (a shared object has no undefined reference that would
//! otherwise select the objects) and `--gc-sections` drops what is
//! unreachable from the exported set.
//!
//! The C allocator is selected so memory behaviour matches a plain zlib with
//! `zalloc == Z_NULL`.  `gzprintf` is deliberately not enabled: it needs a
//! nightly compiler and no firmware consumer calls `gzprintf`/`gzvprintf`.
//!
//! The crate itself contains no unsafe code; the exported C entry points are
//! exercised through `tests/c_abi_roundtrip.rs`, the C ABI smoke fixture and
//! the installed-library checks in `tests/verify-rust-firmware.sh`.
//!
//! [`libz.map`]: ../../../zlib-shared/libz.map
#![forbid(unsafe_code)]

pub use libz_rs_sys as ffi;

/// Version string the C ABI reports through `zlibVersion()`.  The firmware
/// verifier greps the installed `libz.so.1` for this marker to prove the
/// vendor object was replaced.
pub const ZLIB_RS_VERSION: &str = "1.3.0-zlib-rs-0.6.7";

/// C `z_stream` is 14 machine words on an ILP32 ABI (`armv7`) and 112 bytes
/// on LP64 (the host used for `cargo test`).  `inflateInit_`/`deflateInit_`
/// reject a caller whose `sizeof(z_stream)` differs, so a layout drift would
/// turn every consumer into `Z_VERSION_ERROR` at run time.  `gz_header` is
/// the other struct crossing the boundary (`deflateSetHeader`,
/// `inflateGetHeader`): 13 machine words on ILP32, 80 bytes on LP64.
///
/// Assert both at compile time for whichever target is being built, which
/// includes the cross-compiled `armv7-unknown-linux-gnueabi` check in CI.
const _: () = {
    let ilp32 = core::mem::size_of::<usize>() == 4;
    assert!(core::mem::size_of::<ffi::z_stream>() == if ilp32 { 56 } else { 112 });
    assert!(core::mem::size_of::<ffi::gz_header>() == if ilp32 { 52 } else { 80 });
};
