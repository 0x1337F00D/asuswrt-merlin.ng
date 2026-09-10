# TIER1 zlib ABI review and regression gates

All script paths below are relative to `.github/ci/gt-ax11000`.

The replacement remains scoped to the GT-AX11000 image, not every program
ever linked against zlib. No production zlib implementation changed in the
review fixes. The versioned ARM export comparison against the pinned vendor
zlib 1.2.12 had exactly two removals, `gzprintf` and `gzvprintf@ZLIB_1.2.7.1`,
and no additions. Those optional nightly-only APIs remain intentionally
unsupported; a firmware consumer importing either must fail verification.
An unmodified upstream `examplesh` using `gzprintf` does fail, as expected.

## Configured headers and offset widths

Firmware zlib configure enables the `HAVE_UNISTD_H` and `HAVE_STDARG_H`
branches in zconf.h. The former makes `z_off_t` follow `off_t`, not an
unconditional `long`. The checked-in fixture headers are the unconfigured
vendor input; `zlib-header-abi.sh` enables those same two branches without
editing the locked files. `ZLIB_ABI_INCLUDE` can instead select the actual
configured firmware include directory.

The host and ARM C ABI suites run all four macro configurations:

| Consumer configuration | ARM z_off_t | ARM z_off64_t | Callable interfaces |
|---|---:|---:|---|
| Neither large-file macro | 4 | 4 | Native offsets; no explicit *64 calls |
| `_LARGEFILE64_SOURCE=1` | 4 | 8 | Native plus explicit *64 declarations |
| `_FILE_OFFSET_BITS=64` | 8 | 8 | Ordinary names alias *64 via Z_WANT64 |
| Both macros | 8 | 8 | Aliases and explicit *64 declarations |

Thus absence of `_LARGEFILE64_SOURCE` alone is not a demonstrated upstream
ABI defect. zlib.h also declares the *64 interfaces under `Z_WANT64`, using
the configured `z_off_t`. Handwritten declarations bypass that contract and
have been removed from the fixture. An unconfigured header with only
`_FILE_OFFSET_BITS=64` can alias the names while retaining four-byte `long`;
the compile-time fixture assertions now reject that mismatch rather than
calling an eight-byte ABI with half an argument.

The matrix checks streaming and one-shot compression, checksums, native
combine functions and gz file I/O. When the header exposes them it also
checks both *64 combine APIs and CRC operations above the 32-bit length
boundary. Known polynomial powers are normal-path assertions. Failure
diagnostics only report values and mappings: they do not call the failed
checksum routine again, inspect function bytes, or confuse PLT addresses
with implementation identity. The old nm dump was diagnostic, not an
assertion; the address claim and dump have been removed.

## Complete installed direct-consumer import checks

`verify-rust-firmware.sh` retains the shared-object identity, SONAME,
representative export, version-node and hidden-internal gates, and calls
`tests/zlib-consumer-abi.py` for every regular ELF file under the image.
For every object with `DT_NEEDED libz.so.1`, the checker verifies every
attributed zlib import against the replacement's exact symbol/version.
Having the requested version node somewhere in the library is not enough.

Versioned imports use the version-needs provider **index**, so equally
named versions belonging to two libraries do not confuse attribution.
Unversioned ELF imports do not identify their provider: an independent
88-function vendor ABI inventory (`tests/zlib-vendor-exports.txt`) identifies
zlib names, including the intentionally unsupported printf APIs. The
inventory must not be derived from the replacement at verification time,
or removing an export could hide its consumers too. Unversioned imports
require a base/default export; versioned imports require the exact version.
The checker includes weak zlib imports conservatively and fails on ELF or
readelf errors instead of silently dropping a consumer. It does not follow
rootfs symlinks onto the host filesystem.

This is not a complete dynamic-loader emulator: `dlsym` strings, runtime
plugins not present in the image, external software, symbol interposition,
and unknown unversioned extensions are outside its guarantees.

`tests/test-zlib-consumer-abi.py`, wired into the existing host C ABI smoke
step, builds real ELF controls proving rejection of a missing unversioned
export, missing member in an existing node, wrong symbol version while
both nodes exist, both printf omissions when imported, and an unknown
versioned API assigned to libz. Additional tests cover corrupt ELF,
symlink handling and equal version names with distinct provider indices.

## Locally reproduced evidence

Review and fix tests used Rust 1.85.1, Broadcom GCC 5.5/binutils 2.28.1,
ARM QEMU, and the extracted GT-AX11000 glibc 2.26 rootfs. All outputs were
on tmpfs with swap off; no router, network daemon, firmware flash or clock
change was involved.

- Host Rust zlib-shared integration tests: 11 passed.
- ARM configured-header matrix: all four passed, reporting widths exactly
  as above, z_stream 56 and gz_header 52. The same matrix also passed using
  the actual configured vendor include directory rather than HAVE_* flags
  on the fixture input headers.
- Complete extracted-rootfs scan: 31 zlib symbol/version imports across
  ten installed direct consumers satisfied by the fresh replacement.
- Installed libpng16 ran the vendor pngtest under ARM QEMU: passed.
  Loader tracing confirmed the fresh replacement was loaded. Compressed
  byte differences from vendor zlib are expected, not a round-trip failure.
- Historical negative control: forcing the diagnostic at d92c1c18ff9
  timed out; the bc942804a33 argument-order fix returned the intended
  failure. Substituting vendor libz in the fixture fails the Rust-version
  marker, so the positive run is not silently testing system zlib.

No full candidate firmware or hardware behavior is certified by these
tests. The independent review evidence remains distinct from hosted-build
claims and from release approval.
