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
existing C web server. It parses URL-encoded query and form pairs in place,
decodes names and values only after their raw structural delimiters have been
identified, and rejects encoded NUL bytes. The HTTP state machine, CGI hash
table and request handlers remain in C to keep this migration narrowly scoped.

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

`httpd-parsers` exposes three small C-ABI functions. It performs no allocation
across the ABI and never retains a caller pointer. Unit tests cover malformed
escapes, encoded delimiters, empty fields, mixed separators and parameter
smuggling through encoded NUL.

`wanduck-transition` accepts and returns fixed-layout C structs, performs no
I/O or allocation, and leaves unknown legacy states to the existing C fallback.
Its tests exercise transition priority and retry-counter invariants without
requiring router hardware.

`nt-event` rejects empty, signed, overflowing and partially parsed event IDs.
The ARM-only FFI is limited to the documented `initial_nt_event`,
`send_trigger_event` and `nt_event_free` functions, with a null check before
the event allocation is accessed.

Host tests:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The CI additionally checks the ARM target and exhaustively verifies that all
unimplemented 16-bit opcodes are rejected.

The firmware Makefiles cross-compile with the existing Broadcom
`arm-buildroot-linux-gnueabi` linker and install the results as
`/usr/sbin/infosvr` and `/bin/rstats`.

Rust sources are not added to `release/src/router` in the fork. The build
script copies this directory to the ephemeral build tree and
`rust-components.patch` only changes the temporary component Makefiles and
selected parser call sites. This keeps upstream merges independent of the
ports.
