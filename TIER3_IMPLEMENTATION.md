# Tier 3 implementation / candidate alpha3

Base: b2bae581786. Work branch: codex/tier3-implementation.
No router access, changes, install, reboot or load tests in this work.
Independent subagent review waived by user; this is self-review.

## Implemented

- WLAN CLI resolver restricted to /usr/sbin; compiler-macro regression checks
  the old /opt fallback as a counterexample. Runtime suite passes.
- LLTD inactive packet-socket setup already existed. New isolated-copy test
  checks that enabling the protocol early breaks the existing unit test.
- wsdd2 rejects malformed HTTP versions, header names/control bytes, bare
  CR/LF and duplicate Content-Type. Regression failed before the correction.
- A safe DeadlineStream gives metadata reads and writes a shared two-second
  budget. Timeout-setting failures propagate. The fixed per-call-timeout
  mutation fails the regression. The daemon remains synchronous.
- mssl-server uses rustls 0.23.44 / ring 0.17.14 with exact vendored lock.
  CertifiedKey::keys_match compares keys; no custom cryptography.
- Small Rust/C boundary preserves seven public mssl symbols and glibc FILE
  cookies. Client calls return ENOTSUP. Explicit cipher expressions fail.
  TLS 1.2/1.3 only, tickets and early data disabled.
- Caller retains fd ownership. Socket I/O has absolute deadlines and uses
  MSG_DONTWAIT/MSG_NOSIGNAL, respecting shorter socket timeouts. Default cap
  five seconds; shutdown cap 200 ms. Credential files are bounded and must
  be regular; FIFO opens cannot block. Connections retain their config.
- Conditional GT-AX11000 Makefile overlay and fifteen consumer entries added.
- PEM preambles are delegated to the upstream parser, not guessed from the
  first byte; the regression fails on alpha2 and passes after correction.
- Rust source copying and local/CI state hashes exclude only workspace
  /target, not vendored cc/src/target. Both old rules fail regression probes.
- Final shared-object gate checks the seven API exports, soft-float ABI,
  non-executable stack, RELRO, no text relocations, dependency allowlist and
  a 1 MiB linked-size review budget.

## Evidence

Native workspace tests and clippy passed. Native FILE tests cover HTTP,
repeated connections, config destruction and fd ownership. ARMv7 release
cross-build and nine Rust tests passed on QEMU cortex-a7 / Broadcom glibc,
including RSA/EC TLS 1.2/1.3 handshakes. Preliminary stripped libmssl.so:
858268 bytes, no libssl/libcrypto DT_NEEDED. Attributes include VFPv3/NEON,
but no hard-float argument ABI. Final image ISA/link checks remain required.

Historical Claude measurements (2026-09-10; archives, NOT shipped sizes):

| Probe | Release static archive |
| --- | ---: |
| rustls + ring 0.17.14 | 7,113,828 bytes |
| rustls + aws-lc-rs 1.18.1 | 8,714,690 bytes |

## Outstanding

Alpha2 (d4f3886eaa1) full clean RAM build failed at mssl: rsync omitted
vendored cc/src/target/llvm.rs; Cargo checksum validation stopped the build.
No alpha2 image was published. Alpha3 is reserved for the corrections.
All vendored files match a fresh locked cargo vendor output byte-for-byte.
Package-level blob and mssl dry-runs pass; final-image membership is pending.
Full alpha3 firmware build/extraction remains pending.
No browser/login/settings parity, Windows discovery, mobile room-transition,
cold-boot entropy or factory-reset restore claim. WAN multicast isolation of
infosvr remains unproven. wsdd2 metadata processing is still synchronous;
at most two accepted connections can occupy a wakeup for two seconds each.

Alpha3 is a candidate, not approved for installation.
