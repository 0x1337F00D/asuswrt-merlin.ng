//! Exercises the C entry points the shared object publishes, in the shapes the
//! firmware consumers use them: the streaming `deflate`/`inflate` pair
//! (`rc`, `libxml2`, `curl`), the one-shot `compress`/`uncompress` pair
//! (`tor`, `libpng`), the checksums (`mtd-utils`, `minidlna`) and the `gz*`
//! file API (`rsyslog`, `wget`'s WARC writer).

use std::ffi::{c_int, c_uint, c_ulong, CStr, CString};
use std::io::Read;

use zlib_shared::ffi;

const Z_OK: c_int = 0;
const Z_STREAM_END: c_int = 1;
const Z_NO_FLUSH: c_int = 0;
const Z_FINISH: c_int = 4;
const Z_DEFLATED: c_int = 8;
const Z_DEFAULT_COMPRESSION: c_int = -1;
const Z_DEFAULT_STRATEGY: c_int = 0;
const Z_BUF_ERROR: c_int = -5;
const MAX_WBITS: c_int = 15;
const GZIP_WINDOW: c_int = 16 + MAX_WBITS;

fn version() -> &'static CStr {
    // SAFETY: zlibVersion returns a pointer to a static NUL-terminated string.
    unsafe { CStr::from_ptr(ffi::zlibVersion()) }
}

fn stream_size() -> c_int {
    c_int::try_from(std::mem::size_of::<ffi::z_stream>()).unwrap()
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7) % 251) as u8).collect()
}

/// `deflateInit2_` + `deflate(Z_FINISH)`, the shape every streaming producer
/// in the tree uses.
fn deflate_all(input: &[u8], window_bits: c_int) -> Vec<u8> {
    // SAFETY: z_stream is a plain C struct; all-zero is the documented initial
    // state (zalloc/zfree/opaque == Z_NULL).
    let mut stream: ffi::z_stream = unsafe { std::mem::zeroed() };
    let mut out = vec![0u8; input.len() + 128];
    // SAFETY: every pointer stays valid for the whole call sequence.
    unsafe {
        assert_eq!(
            ffi::deflateInit2_(
                &mut stream,
                Z_DEFAULT_COMPRESSION,
                Z_DEFLATED,
                window_bits,
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

/// Streaming decode in small slices, the shape of a slow network read.
fn inflate_chunked(compressed: &[u8], chunk: usize, window_bits: c_int) -> (Vec<u8>, c_int) {
    // SAFETY: see deflate_all.
    let mut stream: ffi::z_stream = unsafe { std::mem::zeroed() };
    let mut out = vec![0u8; 256 * 1024];
    let mut produced = 0usize;
    let mut status = Z_OK;
    // SAFETY: pointers are valid and the loop keeps avail_* consistent.
    unsafe {
        assert_eq!(
            ffi::inflateInit2_(&mut stream, window_bits, version().as_ptr(), stream_size()),
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
    assert_eq!(version().to_str().unwrap(), zlib_shared::ZLIB_RS_VERSION);
    // Consumers only ever compare the major component with ZLIB_VERSION.
    assert_eq!(version().to_bytes()[0], b'1');
}

#[test]
fn streaming_round_trip_for_zlib_raw_and_gzip_wrappers() {
    let body = payload(40_000);
    for window_bits in [MAX_WBITS, -MAX_WBITS, GZIP_WINDOW] {
        let compressed = deflate_all(&body, window_bits);
        assert!(compressed.len() < body.len());
        for chunk in [1usize, 13, 4096, compressed.len()] {
            let (decoded, status) = inflate_chunked(&compressed, chunk, window_bits);
            assert_eq!(status, Z_STREAM_END, "wbits {window_bits} chunk {chunk}");
            assert_eq!(decoded, body, "wbits {window_bits} chunk {chunk}");
        }
    }
}

#[test]
fn truncated_stream_is_reported_not_completed() {
    let compressed = deflate_all(b"the trailer is cut off", GZIP_WINDOW);
    let (_, status) = inflate_chunked(&compressed[..compressed.len() - 8], 3, GZIP_WINDOW);
    assert_eq!(status, Z_OK, "a truncated member must not claim completion");
}

#[test]
fn one_shot_compress_and_uncompress_round_trip() {
    let body = payload(9_001);
    // SAFETY: bound/len pairs describe live buffers for the whole call.
    unsafe {
        let bound = ffi::compressBound(body.len() as c_ulong);
        assert!(bound >= body.len() as c_ulong);
        let mut packed = vec![0u8; bound as usize];
        let mut packed_len = bound;
        assert_eq!(
            ffi::compress(
                packed.as_mut_ptr(),
                &mut packed_len,
                body.as_ptr(),
                body.len() as c_ulong,
            ),
            Z_OK
        );
        packed.truncate(packed_len as usize);

        let mut round = vec![0u8; body.len()];
        let mut round_len = round.len() as c_ulong;
        assert_eq!(
            ffi::uncompress(
                round.as_mut_ptr(),
                &mut round_len,
                packed.as_ptr(),
                packed.len() as c_ulong,
            ),
            Z_OK
        );
        assert_eq!(round_len as usize, body.len());
        assert_eq!(round, body);

        // uncompress2 reports how much input it consumed (ZLIB_1.2.9).
        let mut source_len = packed.len() as c_ulong;
        let mut round2 = vec![0u8; body.len()];
        let mut round2_len = round2.len() as c_ulong;
        assert_eq!(
            ffi::uncompress2(
                round2.as_mut_ptr(),
                &mut round2_len,
                packed.as_ptr(),
                &mut source_len,
            ),
            Z_OK
        );
        assert_eq!(source_len as usize, packed.len());
        assert_eq!(round2, body);

        // A short output buffer must fail closed, not truncate silently.
        let mut tiny = [0u8; 8];
        let mut tiny_len = tiny.len() as c_ulong;
        assert_eq!(
            ffi::uncompress(
                tiny.as_mut_ptr(),
                &mut tiny_len,
                packed.as_ptr(),
                packed.len() as c_ulong,
            ),
            Z_BUF_ERROR
        );
    }
}

#[test]
fn checksums_match_the_published_zlib_values() {
    let quick = b"123456789";
    // SAFETY: both pointers describe the live slice above.
    unsafe {
        // Well-known check values for the ASCII digits 1..9.
        assert_eq!(
            ffi::crc32(0, quick.as_ptr(), quick.len() as c_uint),
            0xcbf4_3926
        );
        assert_eq!(
            ffi::adler32(1, quick.as_ptr(), quick.len() as c_uint),
            0x091e_01de
        );
        // The size_t-taking ZLIB_1.2.9 variants must agree.
        assert_eq!(
            ffi::crc32_z(0, quick.as_ptr(), quick.len()),
            ffi::crc32(0, quick.as_ptr(), quick.len() as c_uint)
        );
        assert_eq!(
            ffi::adler32_z(1, quick.as_ptr(), quick.len()),
            ffi::adler32(1, quick.as_ptr(), quick.len() as c_uint)
        );
        // Empty input returns the seed, and NULL returns the initial value.
        assert_eq!(ffi::crc32(0, std::ptr::null(), 0), 0);
        assert_eq!(ffi::adler32(0, std::ptr::null(), 0), 1);

        // combine() of two halves equals the checksum of the whole.
        let body = payload(5_000);
        let (head, tail) = body.split_at(1_777);
        let whole = ffi::crc32(0, body.as_ptr(), body.len() as c_uint);
        let a = ffi::crc32(0, head.as_ptr(), head.len() as c_uint);
        let b = ffi::crc32(0, tail.as_ptr(), tail.len() as c_uint);
        assert_eq!(ffi::crc32_combine(a, b, tail.len() as ffi::z_off_t), whole);
        assert_eq!(
            ffi::crc32_combine64(a, b, tail.len() as ffi::z_off64_t),
            whole
        );

        let whole = ffi::adler32(1, body.as_ptr(), body.len() as c_uint);
        let a = ffi::adler32(1, head.as_ptr(), head.len() as c_uint);
        let b = ffi::adler32(1, tail.as_ptr(), tail.len() as c_uint);
        assert_eq!(
            ffi::adler32_combine(a, b, tail.len() as ffi::z_off_t),
            whole
        );
        assert_eq!(
            ffi::adler32_combine64(a, b, tail.len() as ffi::z_off64_t),
            whole
        );
    }
}

#[test]
fn crc32_combine_op_matches_the_direct_combination() {
    let body = payload(3_333);
    let (head, tail) = body.split_at(1_111);
    // SAFETY: both slices are live for the duration of the calls.
    unsafe {
        let whole = ffi::crc32(0, body.as_ptr(), body.len() as c_uint);
        let a = ffi::crc32(0, head.as_ptr(), head.len() as c_uint);
        let b = ffi::crc32(0, tail.as_ptr(), tail.len() as c_uint);
        // ZLIB_1.2.12: precompute the operator, then apply it.
        let op = ffi::crc32_combine_gen(tail.len() as ffi::z_off_t);
        assert_eq!(ffi::crc32_combine_op(a, b, op), whole);
        let op64 = ffi::crc32_combine_gen64(tail.len() as ffi::z_off64_t);
        assert_eq!(ffi::crc32_combine_op(a, b, op64), whole);
    }
}

#[test]
fn gzip_file_api_round_trips_through_a_real_file() {
    let dir = std::env::temp_dir().join(format!("zlib-shared-gz-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("payload.gz");
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    let body = payload(12_345);

    // SAFETY: valid C strings, and every buffer outlives its call.
    unsafe {
        let wmode = CString::new("wb6").unwrap();
        let gz = ffi::gzopen(cpath.as_ptr(), wmode.as_ptr());
        assert!(!gz.is_null(), "gzopen for writing");
        assert_eq!(ffi::gzbuffer(gz, 8192), Z_OK);
        assert_eq!(
            ffi::gzwrite(gz, body.as_ptr().cast(), body.len() as c_uint),
            body.len() as c_int
        );
        assert_eq!(ffi::gzclose_w(gz), Z_OK);
    }

    let mut raw = Vec::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_end(&mut raw)
        .unwrap();
    assert_eq!(&raw[..2], &[0x1f, 0x8b], "gzip magic");
    let (decoded, status) = inflate_chunked(&raw, 7, GZIP_WINDOW);
    assert_eq!(status, Z_STREAM_END);
    assert_eq!(decoded, body);

    // SAFETY: same reasoning; buf is owned and large enough.
    unsafe {
        let rmode = CString::new("rb").unwrap();
        let gz = ffi::gzopen(cpath.as_ptr(), rmode.as_ptr());
        assert!(!gz.is_null(), "gzopen for reading");
        assert_eq!(ffi::gzdirect(gz), 0, "the file is a real gzip member");
        let mut buf = vec![0u8; body.len()];
        let n = ffi::gzfread(buf.as_mut_ptr().cast(), 1, buf.len(), gz);
        assert_eq!(n, buf.len());
        assert_eq!(buf, body);
        assert_eq!(ffi::gzeof(gz), 0, "EOF is only latched after a short read");
        let mut spare = [0u8; 4];
        assert_eq!(ffi::gzread(gz, spare.as_mut_ptr().cast(), 4), 0);
        assert_eq!(ffi::gzeof(gz), 1);
        let mut errnum: c_int = 1;
        let message = ffi::gzerror(gz, &mut errnum);
        assert_eq!(errnum, Z_OK);
        assert!(!message.is_null());
        assert_eq!(ffi::gztell(gz), body.len() as ffi::z_off_t);
        assert_eq!(ffi::gzrewind(gz), Z_OK);
        assert_eq!(ffi::gztell64(gz), 0);
        assert_eq!(ffi::gzgetc(gz), c_int::from(body[0]));
        assert_eq!(
            ffi::gzungetc(c_int::from(body[0]), gz),
            c_int::from(body[0])
        );
        assert_eq!(ffi::gzgetc_(gz), c_int::from(body[0]));
        assert_eq!(ffi::gzseek(gz, 0, 0 /* SEEK_SET */), 0);
        assert_eq!(ffi::gzclose_r(gz), Z_OK);
    }

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn gzopen_of_a_missing_path_fails_closed() {
    let path = CString::new("/nonexistent/gt-ax11000/zlib-shared.gz").unwrap();
    let mode = CString::new("rb").unwrap();
    // SAFETY: both arguments are valid NUL-terminated strings.
    let gz = unsafe { ffi::gzopen(path.as_ptr(), mode.as_ptr()) };
    assert!(gz.is_null());
}

#[test]
fn gzip_header_round_trips_through_deflate_and_inflate() {
    let body = b"header round trip";
    let name = CString::new("payload.bin").unwrap();
    let mut compressed = vec![0u8; 256];
    let produced;
    // SAFETY: the header and its name buffer outlive the deflate calls.
    unsafe {
        let mut stream: ffi::z_stream = std::mem::zeroed();
        assert_eq!(
            ffi::deflateInit2_(
                &mut stream,
                Z_DEFAULT_COMPRESSION,
                Z_DEFLATED,
                GZIP_WINDOW,
                8,
                Z_DEFAULT_STRATEGY,
                version().as_ptr(),
                stream_size(),
            ),
            Z_OK
        );
        let mut header: ffi::gz_header = std::mem::zeroed();
        header.name = name.as_ptr().cast::<u8>().cast_mut();
        header.time = 0;
        header.os = 3;
        assert_eq!(ffi::deflateSetHeader(&mut stream, &mut header), Z_OK);
        stream.next_in = body.as_ptr().cast_mut();
        stream.avail_in = body.len() as _;
        stream.next_out = compressed.as_mut_ptr();
        stream.avail_out = compressed.len() as _;
        assert_eq!(ffi::deflate(&mut stream, Z_FINISH), Z_STREAM_END);
        assert_eq!(ffi::deflateEnd(&mut stream), Z_OK);
        produced = stream.total_out as usize;
    }
    compressed.truncate(produced);

    let mut seen_name = vec![0u8; 64];
    // SAFETY: seen_name stays alive and its capacity is declared to zlib.
    unsafe {
        let mut stream: ffi::z_stream = std::mem::zeroed();
        assert_eq!(
            ffi::inflateInit2_(&mut stream, GZIP_WINDOW, version().as_ptr(), stream_size()),
            Z_OK
        );
        let mut header: ffi::gz_header = std::mem::zeroed();
        header.name = seen_name.as_mut_ptr();
        header.name_max = seen_name.len() as _;
        assert_eq!(ffi::inflateGetHeader(&mut stream, &mut header), Z_OK);
        let mut out = vec![0u8; 128];
        stream.next_in = compressed.as_ptr().cast_mut();
        stream.avail_in = compressed.len() as _;
        stream.next_out = out.as_mut_ptr();
        stream.avail_out = out.len() as _;
        assert_eq!(ffi::inflate(&mut stream, Z_FINISH), Z_STREAM_END);
        assert_eq!(header.done, 1);
        assert_eq!(&out[..body.len()], body);
        assert_eq!(ffi::inflateEnd(&mut stream), Z_OK);
    }
    let seen = CStr::from_bytes_until_nul(&seen_name).unwrap();
    assert_eq!(seen.to_bytes(), name.to_bytes());
}

#[test]
fn dictionary_round_trip_matches_the_deflate_side() {
    let dictionary = b"GT-AX11000 GT-AX11000 GT-AX11000";
    let body = b"GT-AX11000 firmware payload using the shared dictionary";
    let mut compressed = vec![0u8; 256];
    let produced;
    // SAFETY: dictionary and buffers stay alive across the calls.
    unsafe {
        let mut stream: ffi::z_stream = std::mem::zeroed();
        assert_eq!(
            ffi::deflateInit_(
                &mut stream,
                Z_DEFAULT_COMPRESSION,
                version().as_ptr(),
                stream_size(),
            ),
            Z_OK
        );
        assert_eq!(
            ffi::deflateSetDictionary(&mut stream, dictionary.as_ptr(), dictionary.len() as _),
            Z_OK
        );
        let mut seen = vec![0u8; 64];
        let mut seen_len: c_uint = seen.len() as _;
        assert_eq!(
            ffi::deflateGetDictionary(&stream, seen.as_mut_ptr(), &mut seen_len),
            Z_OK
        );
        assert_eq!(&seen[..seen_len as usize], dictionary);
        stream.next_in = body.as_ptr().cast_mut();
        stream.avail_in = body.len() as _;
        stream.next_out = compressed.as_mut_ptr();
        stream.avail_out = compressed.len() as _;
        assert_eq!(ffi::deflate(&mut stream, Z_FINISH), Z_STREAM_END);
        assert_eq!(ffi::deflateEnd(&mut stream), Z_OK);
        produced = stream.total_out as usize;
    }
    compressed.truncate(produced);

    const Z_NEED_DICT: c_int = 2;
    // SAFETY: same reasoning as above.
    unsafe {
        let mut stream: ffi::z_stream = std::mem::zeroed();
        assert_eq!(
            ffi::inflateInit_(&mut stream, version().as_ptr(), stream_size()),
            Z_OK
        );
        let mut out = vec![0u8; 128];
        stream.next_in = compressed.as_ptr().cast_mut();
        stream.avail_in = compressed.len() as _;
        stream.next_out = out.as_mut_ptr();
        stream.avail_out = out.len() as _;
        assert_eq!(ffi::inflate(&mut stream, Z_NO_FLUSH), Z_NEED_DICT);
        assert_eq!(
            ffi::inflateSetDictionary(&mut stream, dictionary.as_ptr(), dictionary.len() as _),
            Z_OK
        );
        assert_eq!(ffi::inflate(&mut stream, Z_FINISH), Z_STREAM_END);
        assert_eq!(&out[..body.len()], body);
        assert_eq!(ffi::inflateEnd(&mut stream), Z_OK);
    }
}

#[test]
fn compile_flags_describe_this_abi() {
    let flags = ffi::zlibCompileFlags();
    // Bits 0..=1: sizeof(uInt), 2..=3: sizeof(uLong), 4..=5: sizeof(voidpf),
    // 6..=7: sizeof(z_off_t); 0b01 = 32 bit, 0b10 = 64 bit.
    let width = |bits: u32| match (flags >> bits) & 0b11 {
        0 => 2usize,
        1 => 4,
        2 => 8,
        _ => 0,
    };
    assert_eq!(width(0), std::mem::size_of::<c_uint>());
    assert_eq!(width(2), std::mem::size_of::<c_ulong>());
    assert_eq!(width(4), std::mem::size_of::<*const u8>());
    assert_eq!(width(6), std::mem::size_of::<ffi::z_off_t>());
}
