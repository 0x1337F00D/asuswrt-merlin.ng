# Tier 3 implementation / candidate alpha2

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

Full firmware build/extraction and blob make-n triage remain pending.
No browser/login/settings parity, Windows discovery, mobile room-transition,
cold-boot entropy or factory-reset restore claim. WAN multicast isolation of
infosvr remains unproven. wsdd2 metadata processing is still synchronous;
its per-read timeout can exceed its nominal total deadline.

Alpha2 is a candidate, not approved for installation.
