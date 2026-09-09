//! Exercises the exported C entry points exactly the way `wget` uses them:
//! streaming `inflate` of a gzip member (retr.c) and `gzdopen`/`gzwrite`/
//! `gzclose` with a level suffix (warc.c), plus the version marker.

use std::ffi::{c_char, c_int, CStr, CString};
use std::io::Read;
use std::os::fd::IntoRawFd;

use zlib_static::ffi;

const Z_OK: c_int = 0;
const Z_STREAM_END: c_int = 1;
const Z_NO_FLUSH: c_int = 0;
const Z_FINISH: c_int = 4;
const Z_DEFLATED: c_int = 8;
const Z_DEFAULT_STRATEGY: c_int = 0;
const MAX_WBITS: c_int = 15;
const GZIP_WINDOW: c_int = 16 + MAX_WBITS;

fn version() -> &'static CStr {
    // SAFETY: zlibVersion returns a pointer to a static NUL-terminated string.
    unsafe { CStr::from_ptr(ffi::zlibVersion()) }
}

fn stream_size() -> c_int {
    c_int::try_from(std::mem::size_of::<ffi::z_stream>()).unwrap()
}

fn gzip_compress(input: &[u8]) -> Vec<u8> {
    // SAFETY: z_stream is a plain C struct; zeroed is the documented initial
    // state (zalloc/zfree/opaque == Z_NULL).
    let mut stream: ffi::z_stream = unsafe { std::mem::zeroed() };
    let mut out = vec![0u8; input.len() + 64];
    // SAFETY: every pointer is valid for the whole call sequence below.
    unsafe {
        assert_eq!(
            ffi::deflateInit2_(
                &mut stream,
                9,
                Z_DEFLATED,
                GZIP_WINDOW,
                8,
                Z_DEFAULT_STRATEGY,
                version().as_ptr(),
                stream_size(),
            ),
            Z_OK
        );
        stream.next_in = input.as_ptr().cast_mut();
        stream.avail_in = input.len() as _;
        stream.next_out = out.as_mut_ptr();
        stream.avail_out = out.len() as _;
        assert_eq!(ffi::deflate(&mut stream, Z_FINISH), Z_STREAM_END);
        assert_eq!(ffi::deflateEnd(&mut stream), Z_OK);
    }
    out.truncate(stream.total_out as usize);
    out
}

/// Streaming decode in tiny input slices, mirroring wget's retr.c loop.
fn gzip_inflate_chunked(compressed: &[u8], chunk: usize) -> (Vec<u8>, c_int) {
    // SAFETY: see gzip_compress.
    let mut stream: ffi::z_stream = unsafe { std::mem::zeroed() };
    // Large enough for every payload in this file; wget grows its own buffer.
    let mut out = vec![0u8; 64 * 1024];
    let mut produced = 0usize;
    let mut status = Z_OK;
    // SAFETY: pointers are valid and the loop keeps avail_* consistent.
    unsafe {
        assert_eq!(
            ffi::inflateInit2_(&mut stream, GZIP_WINDOW, version().as_ptr(), stream_size()),
            Z_OK
        );
        for piece in compressed.chunks(chunk) {
            stream.next_in = piece.as_ptr().cast_mut();
            stream.avail_in = piece.len() as _;
            while stream.avail_in > 0 && status == Z_OK {
                stream.next_out = out.as_mut_ptr().add(produced);
                stream.avail_out = (out.len() - produced) as _;
                status = ffi::inflate(&mut stream, Z_NO_FLUSH);
                produced = stream.total_out as usize;
            }
        }
        assert_eq!(ffi::inflateEnd(&mut stream), Z_OK);
    }
    out.truncate(produced);
    (out, status)
}

#[test]
fn zlib_version_marker_matches_crate_constant() {
    assert_eq!(version().to_str().unwrap(), zlib_static::ZLIB_RS_VERSION);
}

#[test]
fn gzip_member_round_trips_through_streaming_inflate() {
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let compressed = gzip_compress(&payload);
    assert_eq!(&compressed[..2], &[0x1f, 0x8b], "gzip magic");
    for chunk in [1usize, 7, 64, compressed.len()] {
        let (decoded, status) = gzip_inflate_chunked(&compressed, chunk);
        assert_eq!(status, Z_STREAM_END, "chunk size {chunk}");
        assert_eq!(decoded, payload, "chunk size {chunk}");
    }
}

#[test]
fn truncated_gzip_member_is_reported_not_completed() {
    let compressed = gzip_compress(b"the body is cut off before the trailer");
    let (decoded, status) = gzip_inflate_chunked(&compressed[..compressed.len() - 8], 5);
    assert_eq!(status, Z_OK, "stream must not claim completion");
    assert!(decoded.len() <= 40);
}

#[test]
fn gzdopen_with_level_suffix_writes_a_readable_gzip_file() {
    let dir = std::env::temp_dir().join(format!("zlib-static-gz-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("warc.gz");
    let file = std::fs::File::create(&path).unwrap();
    let fd = file.into_raw_fd();
    let mode = CString::new("wb9").unwrap();
    let body = b"WARC/1.0\r\nWARC-Type: warcinfo\r\n\r\n";
    // SAFETY: fd is an owned open descriptor handed to gzdopen, which takes
    // ownership and closes it in gzclose; body is a valid buffer.
    unsafe {
        let gz = ffi::gzdopen(fd, mode.as_ptr());
        assert!(!gz.is_null(), "gzdopen(\"wb9\") must succeed");
        assert_eq!(
            ffi::gzwrite(gz, body.as_ptr().cast(), body.len() as _),
            body.len() as c_int
        );
        assert_eq!(ffi::gzclose(gz), Z_OK);
    }
    let mut raw = Vec::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_end(&mut raw)
        .unwrap();
    assert_eq!(&raw[..2], &[0x1f, 0x8b]);
    let (decoded, status) = gzip_inflate_chunked(&raw, 3);
    assert_eq!(status, Z_STREAM_END);
    assert_eq!(decoded, body);
    // Read it back through the gz* API as well.
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    let rmode = CString::new("rb").unwrap();
    let mut buf = vec![0u8; 128];
    // SAFETY: valid C strings and an owned buffer.
    unsafe {
        let gz = ffi::gzopen(cpath.as_ptr(), rmode.as_ptr());
        assert!(!gz.is_null());
        let n = ffi::gzread(gz, buf.as_mut_ptr().cast(), buf.len() as _);
        assert_eq!(n as usize, body.len());
        assert_eq!(ffi::gzclose(gz), Z_OK);
    }
    assert_eq!(&buf[..body.len()], body);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn gzdopen_rejects_an_invalid_descriptor() {
    let mode = CString::new("wb").unwrap();
    // SAFETY: -1 is never a valid descriptor; gzdopen must fail closed.
    let gz = unsafe { ffi::gzdopen(-1, mode.as_ptr()) };
    assert!(gz.is_null());
    let _: *const c_char = std::ptr::null();
}
