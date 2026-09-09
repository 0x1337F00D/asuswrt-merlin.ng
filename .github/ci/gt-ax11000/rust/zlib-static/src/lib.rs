//! Static, C-ABI compatible zlib for isolated firmware consumers.
//!
//! This crate re-exports [`libz_rs_sys`] with the symbol set a C caller
//! expects (`inflate*`, `deflate*`, `crc32`, `adler32`, `gz*`) and packages it
//! as a static archive.  The first consumer is the vendor `wget`, which needs
//! the streaming `inflate` API for HTTP `Content-Encoding: gzip` bodies and the
//! `gzdopen`/`gzwrite`/`gzclose` trio for WARC output.  Linking the archive
//! into one executable keeps every other zlib user on the vendor `libz.so.1`
//! until the shared-library replacement (SONAME, `ZLIB_*` symbol versions and
//! the internal symbols exported by the vendor version script) is done.
//!
//! The C allocator is selected so memory behaviour matches a plain zlib with
//! `zalloc == Z_NULL`.  `gzprintf` is deliberately not enabled: it needs a
//! nightly compiler and no firmware consumer uses it.
//!
//! The crate itself contains no unsafe code; the exported C entry points are
//! exercised through `tests/c_abi_roundtrip.rs` and the C ABI smoke fixture.
#![forbid(unsafe_code)]

pub use libz_rs_sys as ffi;

/// Version string the C ABI reports through `zlibVersion()`.  The firmware
/// verifier greps the installed `wget` for this marker.
pub const ZLIB_RS_VERSION: &str = "1.3.0-zlib-rs-0.6.7";
