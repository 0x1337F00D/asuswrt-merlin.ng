# GT-AX11000 Rust components

This workspace contains memory-safe replacements that are copied into the
ephemeral Asuswrt-Merlin CI source tree. Upstream sources stay unchanged.

The first component is `infosvr`. It preserves the read-only 512-byte ASUS
discovery protocol used by the GT-AX11000 while deliberately rejecting legacy
configuration and manufacturing opcodes. NVRAM access is read-only.

The second component is `rstats`. It preserves the 30-second bandwidth
sampling, signal interface, ISP-meter integration, JavaScript output and the
existing ARM binary formats. History V0 files are migrated to V1, and speed
archives now correctly accept any valid count from zero through 35 records.

The third component is `httpd-parsers`, a Rust static library used by the
existing C web server. It parses URL-encoded query/form and multipart filename
boundaries, rejects encoded NUL bytes, protects WLAN identity/regulatory and
raw calibration keys, authorizes only a country-profile test-lab request, and
validates complete WLAN authentication/cipher/PMF/WPS tuples. The HTTP state
machine, CGI hash table and request handlers remain in C.

The fourth component is `wanduck-transition`. It owns the pure, duplicated
dual-WAN failover/failback transition logic while PHY probes, NVRAM access,
restart actions and logging stay in the existing C daemon. Its typed state
model covers link edges, physical reconnection, data limits, modem PIN/scan
states and disconnect-counter policy.

The fifth component is `nt-event`. ASUS does not publish the GT-AX11000 source
for `nt_center`, `nt_monitor` or `libnt`, so this deliberately replaces only
the source-reconstructable `Notify_Event2NC` input boundary. It strictly parses
the hexadecimal event identifier, bounds the message to the public 512-byte
ABI and then hands the typed event to the unchanged proprietary `libnt`
transport.

The sixth component is `router-security`, the shell-free security boundary
linked into `rc`. It owns the narrow apply/NVRAM allowlist, strict IPsec
identity and basename validation, atomic WireGuard endpoint replacement, and
bounded parsing of effective IPv4/IPv6 firewall rules exported to private
temporary files. Keeping these policy and filesystem operations separate
leaves `wanduck-transition` as a pure WAN state machine.

The seventh component is `router-policy`, a dependency-free typed policy
library. Its country-only test-lab and WLAN modules are enforced through
`httpd-parsers`; its effective terminal-DROP invariant is enforced through
`router-security`. WAN-admin coverage is wired into the running firewall. The
per-profile OpenVPN/WireGuard inbound-block and policy-route kill-switch
validator is typed, fuzzed and exercised through its C ABI, but is not yet
wired into the running firewall.

The eighth component is `zlib-static`, a static C-ABI zlib built from
`zlib-rs` (`libz-rs-sys` with `export-symbols`, `gz` and the C allocator).
It is linked into exactly one isolated consumer, the vendor `wget`, which uses
streaming `inflate` for HTTP gzip bodies and `gzdopen`/`gzwrite`/`gzclose` for
WARC output. Every other zlib user keeps the vendor `libz.so.1`; replacing the
shared library needs the `libz.so.1` SONAME, the `ZLIB_1.2.*` symbol versions
from the vendor version script and the internal symbols it exports
(`inflate_fast`, `inflate_table`, `z_errmsg`, `zcalloc`, `zcfree`, ...), which
`zlib-rs` does not provide. `gzprintf` is not enabled (nightly only, unused).
The crate forbids unsafe code; `tests/c_abi_roundtrip.rs` and the C ABI smoke
fixture `tests/c-abi/zlib.c` exercise the exported entry points the way wget
calls them, and `verify-rust-firmware.sh` checks that the installed `wget` has
no `libz.so` dependency, carries the `1.3.0-zlib-rs-` marker and starts under
QEMU.

The ninth component is `clientlist`, the GT-AX11000 Web UI client list. It
replaces the json-c based readers of `httpd/web.c` (`get_client_detail_info`,
`ej_get_clientlist`, `get_clientlist_ex`, `get_client_name`,
`get_sdn_client_num`, `ej_get_clientlist_from_json_database`,
`ej_get_all_basic_clientlist`, `get_basic_clientlist_info` and
`search_device_name_in_clientlist`). `layout.rs` carries `#[repr(C)]`
descriptions of the closed daemon's 174,964-byte legacy table and the public
173,436-byte table with compile-time size and offset assertions; the legacy
view is selected only for `productid` `GT-AX11000` with exactly that segment
size, the public view only for exactly its size, and anything else fails
closed. `shm.rs` takes the vendor `file_lock("networkmap")` (`fcntl`
`F_SETLKW`), attaches the existing segment read-only without ever creating
it, copies it whole and detaches; parsing works on the copy, reads every
string inside its own field width, takes the trailer from the segment end
and clamps the count to 0..=255. The typed model is enriched from
`custom_clientlist`, `qos_rulelist`, `wtf_rulelist`, the `MULTIFILTER_*`
set (including the weekday/hour schedule check), `rog_clientlist` and the
AiMesh RE details, and rendered with `serde_json` through an
insertion-ordered value that keeps json-c's replace-in-place key order. The
C side keeps the `networkmap` process gate, the `nmp_wl_offline_check`
flag, the `delete_mac` trailer write and the AiMesh `is_re_node`/
`get_amas_info` lookups (passed as a callback and a text list); output goes
into a caller-provided 1 MiB buffer, atomic `/tmp/nmp_cache.js` writes are
done in Rust and no `json_object` crosses the boundary. The crate's FFI is
re-exported by `httpd-parsers`, so `httpd` still links one Rust archive.
`serde`/`serde_json` are the only new dependencies (the vendored
`serde_derive`/`syn` tree is a `cfg(any())` placeholder of `serde_core` that
is never compiled).

The tenth component is `wlif-policy`, the only Rust archive linked into
`libshared.so`. The vendor `shared/wlif_utils_ax.c` is compiled into that
library for this profile (`shared/Makefile` adds `wlif_utils_ax.o` when
`RTCONFIG_HND_ROUTER_AX=y`, and the HND-94908 GT-AX11000 sets it) and used to
build 25 `system()`/`popen()` command strings from interface names, SSIDs,
PSKs, WPS PINs and DPP blobs. The overlay rewrites every one of them to a
fixed `argv[]` run through the vendor `_eval()`, or through a local
pipe-capturing `execvp` for the two that read output, and routes each
interpolated value through this crate first. Identifiers (interface names,
control-interface prefixes, CLI verbs, DPP blobs, PINs) get a strict ASCII
charset, may not start with `-` and may not contain `/` or a shell
metacharacter; SSIDs and passphrases stay opaque byte strings that are only
bounded and checked for NUL, control characters and encoding, and are never
placed on a command line at all. Control-socket paths are built by the crate,
not by the caller. Everything fails closed with the error value the vendor
function already returned.

`wlif-policy` deliberately does not reuse `router-policy`/`router-security`:
`librouter_security.a` is already linked into `rc`, its code is one LTO
object, and pulling it into `libshared.so` would duplicate every `rust_*`
symbol and add unrelated filesystem code to a library that roughly sixty
packages and seventeen prebuilt vendor blobs load. The crate also references
nothing from the Rust standard library except `strlen` - the UTF-8 validator
is written out rather than calling `core::str::from_utf8`, because `core`
ships as a single object and one call pulls the whole panic/backtrace runtime
in. Measured with the Broadcom `arm-buildroot-linux-gnueabi` linker, a shared
object built from the archive is 9,664 bytes stripped (6,129 bytes of text)
against 1,130,592 bytes for the same code calling `core::str::from_utf8`, and
it needs no shared library beyond `libc` and `libgcc_s`. `libshared.a` keeps
the plain object list: nothing in the tree links it.

`infosvr` security boundary:

- the packet parser requires an exact 512-byte PDU and accepts only the four
  read-only discovery opcodes;
- all fixed-width protocol strings are bounded and NUL-terminated;
- the protocol library forbids unsafe Rust;
- the daemon's reviewed FFI boundary is limited to read-only NVRAM/feature
  helpers and Linux `SO_BINDTODEVICE`;
- disk statistics use `Command` with a validated argument and never a shell;
- `infosvr` never writes or commits NVRAM.

`rstats` has a different, explicitly reviewed boundary because traffic-meter
compatibility requires NVRAM writes. Its parser and binary codecs forbid unsafe
Rust; the daemon limits unsafe code to the existing NVRAM/network classifier
ABI and POSIX process/signal/time calls. gzip is invoked with a fixed absolute
program and fixed arguments, never through a shell, and decompressed output is
hard-limited before it reaches a codec. State and JavaScript files use atomic
replacement.

`httpd-parsers` exposes small, bounded C-ABI functions. It performs no
allocation across the ABI and never retains a caller pointer. Unit tests cover
malformed escapes, encoded delimiters, empty fields, mixed separators,
parameter smuggling, raw regulatory/calibration writes, exact country consent,
and fail-closed WLAN security combinations.

`wanduck-transition` accepts and returns fixed-layout C structs, performs no
I/O or allocation, and leaves unknown legacy states to the existing C fallback.
Its tests exercise transition priority and retry-counter invariants without
requiring router hardware.

`router-security` rejects null pointers, invalid UTF-8, unknown apply keys,
path-like IPsec names and malformed WireGuard endpoints. WireGuard updates
reject symlinks and oversized files, write a new mode-0600 file, sync it and
atomically rename it over the old configuration. Effective firewall snapshots
also reject symlinks, non-ASCII or oversized input and require INPUT/FORWARD to
end in unconditional DROP rules before forwarding is enabled. It never invokes
a shell.

`wlif-policy` forbids allocation and I/O, keeps no caller pointer and returns
`1`/`0` across its C ABI. Its unit tests cover every accepted vendor shape,
the exact length limits, option-like and path-like names, NUL, newline and
every other control byte, shell metacharacters, non-UTF-8 SSIDs, non-hex
64-character PSKs, short output buffers and null pointers; the UTF-8
validator is checked against `core::str::from_utf8` over every one- and
two-byte sequence and a boundary set of three- and four-byte ones.

`nt-event` rejects empty, signed, overflowing and partially parsed event IDs.
The ARM-only FFI is limited to the documented `initial_nt_event`,
`send_trigger_event` and `nt_event_free` functions, with a null check before
the event allocation is accessed.

Host tests:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
bash ../tests/security-overlay-check.sh /path/to/patched/source
```

The structured fuzz runner covers the HTTP query/URL and multipart
boundaries, NVRAM-facing WLAN/test-lab policy, OpenVPN/IPsec/WireGuard
parsers, the wireless-interface identifier/credential policy, infosvr PDUs,
rstats codecs, the wanduck transition machine and the client-list parsers
(synthetic legacy/public shared-memory segments with random counts and
unterminated fields, the NVRAM list/schedule parsers, the
AiMesh details file, the cache check and the persistent-database transform).
It is deterministic and keeps Cargo state and artifacts in tmpfs:

```sh
ASUSWRT_REQUIRE_TMPFS=1 \
RUST_FUZZ_ITERATIONS=250000 \
bash ../tests/rust-fuzz-smoke.sh
```

Three fixed seeds are always run, along with explicit maximum-length,
pair-count, encoded-NUL, codec-record, protocol-opcode and client-count/
segment-size boundary cases.

The C ABI smoke suite compiles strict C11 fixtures against the release Rust
archives and executes the same entry points used by `httpd`, `rc`, `wanduck`
and `libshared`; `tests/c-abi/clientlist.c` creates a real SysV segment with
a private key, fills the legacy GT-AX11000 layout and checks the rendered
document, the cache and database views and the NULL/small-buffer/wrong-size/
missing-segment failure codes. This catches layout, symbol, ownership and
non-mutation regressions without claiming to replace full firmware-consumer
or hardware tests:

```sh
ASUSWRT_REQUIRE_TMPFS=1 \
bash ../tests/c-abi-smoke.sh
```

The CI additionally checks the ARM target and exhaustively verifies that all
unimplemented 16-bit opcodes are rejected.

All firmware Rust code uses the `armv7-unknown-linux-gnueabi` standard library
and is compiled with `-Ctarget-cpu=cortex-a9`. The generic
`arm-unknown-linux-gnueabi` standard library contains deprecated ARMv6 CP15
barriers which the GT-AX11000's ARMv8 compatibility kernel deliberately does
not emulate. A CPU flag alone cannot repair instructions in Rust's precompiled
standard library. The ARMv7 soft-float target matches the Broadcom C toolchain
and uses architectural `dmb` barriers instead.

After the firmware build, `tests/verify-rust-firmware.sh` inspects the three
standalone Rust programs and the `httpd`/`rc` consumers. It rejects obsolete
CP15 barriers, hard-float or non-ARMv7 output, and then executes safe startup
paths for `infosvr`, `Notify_Event2NC` and `rstats` under `qemu-arm` using the
generated firmware root filesystem.

The firmware Makefiles cross-compile with the existing Broadcom
`arm-buildroot-linux-gnueabi` linker and install the results as
`/usr/sbin/infosvr` and `/bin/rstats`.

Rust sources are not added to `release/src/router` in the fork. The build
script copies this directory to the ephemeral build tree and
`rust-components.patch` only changes the temporary component Makefiles and
selected parser call sites. This keeps upstream merges independent of the
ports.
