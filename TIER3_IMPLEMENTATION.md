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

## Final artifact and evidence

Firmware source commit: d0cd472a96ca3e3293e9a0f6d34ece030121bfe2.
Image: GT-AX11000_3006_102.9_alpha3_ubi.w, 78,118,932 bytes (74.50 MiB).
SHA-256: e1c841fa3438f5b922a306df96c0907bedfc342d3c3fec3e1dfaddfa03e5b3a7.
Clean build: 2725 seconds, package jobs=1, kernel cache reuse=0, ccache off,
all build/output/temp paths on tmpfs, swap off. No new parallel build mode.

598 native Rust test cases and workspace clippy passed on an actual copy
made by the build's overlay-copy function. 121 wsdd2/TLS ARM tests passed
under QEMU. Full C-ABI suite passed, including six native TLS FILE tests.
Fuzz smoke passed 250000 iterations for each of three seeds. Workflow tests
17/17; trial tests 35/35. Vendor files match fresh locked cargo vendor output.

The image was independently UBI-extracted. All 2717 regular-file hashes,
entry types/modes/symlinks and hardlink groups match staging; the only exact
packaging transformation is the vendor's empty 0755 /bootfs mountpoint.
All 15 Rust consumer hashes, 25 dictionaries/5078 entries and 31 Web symlinks
pass. Sixteen ARMv7 consumer ELF checks, the separate zlib gate and eight
QEMU runtime paths pass. No proprietary QoS/DPI payload is present according
to the existing rootfs gate. These are offline checks, not router tests.

Installed libmssl.so: 997540 bytes; the initial 858268-byte probe
was not the final production link. The seven public mssl functions,
dependency allowlist, soft-float ABI, NX stack, RELRO and size gate pass.
Twelve additional tests dynamically link the **extracted** libmssl.so on
QEMU: RSA/EC, TLS 1.2/1.3, fragmented HTTP, repeated connections, live config
destruction and caller-owned descriptor closing. Eight PEM/DER credential
combinations pass separately on the native adapter.

Installed libshared.so: 637000 bytes, all reference vendor exports retained,
11 Rust FFI exports and no unintended std/backtrace exports.

Initial checks: Native workspace tests and clippy passed. Native FILE tests cover HTTP,
repeated connections, config destruction and fd ownership. ARMv7 release
cross-build and nine Rust tests passed on QEMU cortex-a7 / Broadcom glibc,
including RSA/EC TLS 1.2/1.3 handshakes. Preliminary stripped libmssl.so:
858268 bytes, no libssl/libcrypto DT_NEEDED. Attributes include VFPv3/NEON,
but no hard-float argument ABI. Final measurements are given above.

Historical Claude measurements (2026-09-10; archives, NOT shipped sizes):

| Probe | Release static archive |
| --- | ---: |
| rustls + ring 0.17.14 | 7,113,828 bytes |
| rustls + aws-lc-rs 1.18.1 | 8,714,690 bytes |

## Input provenance and verification follow-up

Alpha2 (d4f3886eaa1) full clean RAM build failed at mssl: rsync omitted
vendored cc/src/target/llvm.rs; Cargo checksum validation stopped the build.
No alpha2 image was published. Alpha3 is reserved for the corrections.
The local invocation omitted ASUSWRT_ENFORCE_INPUT_LOCK=1, so the original
BUILD-STATE.txt honestly says input_lock_status=not-enforced. It was not
rewritten. Retrospective checks establish:

- The actual build's staged pre-Rust patch snapshot SHA-256 is exactly
  0e82e2936b83cbe7100013c511392c9f01293507c02bd9a8887fdec0804a1fa6,
  matching inputs.lock; the independent clean patch replay also verifies.
- Upstream and toolchain HEADs match the lock. The actual copied Rust source
  hashes to fee9845df4a41c747738b441c2b5dc1d65e0a2846820ed9a32c7a88e174150c2,
  matching the recorded build state.
- This is after-the-fact verification, not a claim that the automatic
  pre-build gate ran. The default is now enforced, with an executable
  regression test. Only build/verification/docs changed after the firmware
  source commit; no firmware Rust source or patch changed.
- The ELF verifier now refuses Python optimization, which otherwise removes
  assert checks. The old verifier accepted an x86 /bin/true under -O; the
  new regression requires refusal. The normal image ELF gate passes again.

Package dry-runs pass in both overlay modes; all three selected vendor
packages are present in the extracted image. See TIER3_BLOB_ANALYSIS.md.

## Outstanding / not approved for installation

Static ELF inventory finds libmssl linked by httpd and awsiot, but only
httpd imports mssl API functions. awsiot's Makefile adds an unused -lmssl;
no client-entry-point imports were found. Do not call it the only DT_NEEDED
consumer just because it is the only API caller.

wtfslhd has missing libssl.so.1.0.0/libcrypto.so.1.0.0 filenames. Its hash is
identical to the reference image, which has the same missing dependencies.
This is an existing optional-feature compatibility debt, not a new TLS
regression; no obsolete OpenSSL libraries were added to work around it.

Before future deployment, check the actual configured certificate/key with
the candidate. Tested credentials are RSA-2048 and EC P-256; do not assume
compatibility for all custom algorithms. Existing httpd logic regenerates
unusable credentials; that vendor behavior was not changed here.

No browser/login/settings parity, Windows discovery, mobile room-transition,
cold-boot entropy or factory-reset restore claim. WAN multicast isolation of
infosvr remains unproven. wsdd2 metadata processing is still synchronous;
at most two accepted connections can occupy a wakeup for two seconds each.

Alpha3 is a candidate, not approved for installation.
