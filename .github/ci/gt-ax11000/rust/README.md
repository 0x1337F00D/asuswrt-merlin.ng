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
`router-security`. WAN-admin and complete VPN kill-switch manifest coverage is
typed and tested but is not yet wired into the running firewall.

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
