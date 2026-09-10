# TIER 1 review fixes

Base reviewed: `7c6446acfe0245fd7dfa919178c1f38458ab9122`.
Implementation branch: `codex/tier1-review-fixes`.

This follow-up addresses the independent NTP, wlif and zlib reviews. It does
not imply approval to install a new image. The running router is unchanged.

## Build-path closure

`rust-components-relink` explicitly enters `shared-install` before its other
consumers. The original shared Makefile's `install: all` rebuilds the Rust
archive and links the shared object. Repack then promotes the staged
`shared/usr/lib/libshared.so`; all eleven consumers participate in freshness,
hash and CI rootfs equivalence checks.

`tests/test_shared_repack.py` executes the actual promotion shell recipe on a
synthetic staging directory and checks that the build manifest and both CI
exclusion sets agree. No real firmware filesystem is used in this test.

## Size and dependency claim

The reported 9,672-byte stripped wlif result was an isolated linkage of the
validator entry points. It is not a measurement of the full vendor
`libshared.so`. The earlier actual vendor link required explicitly naming
`-ldl -lpthread -lrt`; therefore the isolated result must not be advertised as
proof of zero additional dependencies in the final firmware. Retain the
bounded validator implementation and measure the final ELF separately.

## NTP corrections

- Malformed unauthenticated packets leave the real upstream query pending.
- Discipline updates are staged; failed step/slew writes neither publish
  successful synchronization nor dispatch a false successful-step hook.
- Elapsed holdover expiration bounds stale reachability even when DNS fails
  after a permanent refusal, or when local socket/entropy operations fail.
- Initial queries use the short BusyBox-style burst rather than waiting a
  steady-state minute for the second sample.
- Periodic housekeeping executes independently of whether poll timed out.
- Nonces use raw nonblocking getrandom, fail closed on error/unready entropy,
  and recover on subsequent query slots; no predictable fallback is used.

Permanent tests inject clock-write results rather than changing the host
clock, and use loopback-only sockets and synthetic syscall outcomes.

## WLAN command boundary

The private runner preserves raw wait status, including signal termination;
does not invoke the vendor argv logger; and executes only fixed command names
from the vendor directory list, without a shell fallback. It closes unrelated
child descriptors and resets signal state. Normal child execution/output is
bounded by a monotonic 30-second deadline and a fixed capture buffer; timeout
or overflow clears captured output. SIGKILL cannot guarantee an instantaneous
exit from an uninterruptible kernel wait, and privileged concurrent child
reapers remain a platform-integration consideration.

PSK validation is conditional on PSK/SAE modes, so open, enterprise and DPP-only
provisioning do not require a nonexistent WPA passphrase. Runtime fixtures use
the actual patched C helpers; credential fixtures execute actual patched
functions against the real Rust validation archive.

Credentials remain visible to sufficiently privileged process inspection as
argv; replacing the proprietary CLI with direct control-socket calls would be
a separate interface change. Removing debug_logeval does not claim to hide
credentials from root.

## zlib verification

The production library is unchanged. Configured-header tests cover four
large-file macro combinations; the firmware gate checks every attributed
symbol/version import from direct installed libz consumers. Compiled negative
controls ensure missing exports and wrong versions fail the gate. This is not
a claim of universal drop-in support for omitted gzprintf/gzvprintf or dlsym
users. See [TIER1_ZLIB_ABI.md](TIER1_ZLIB_ABI.md).

## Remaining release gates

- Complete firmware build, final ELF dependency closure and image extraction.
- Actual NTP kernel step/slew and service-readiness lifecycle, including wrong
  RTC boot, upstream and DNS loss/recovery, LAN binding and long-run drift.
- Actual WPS start/cancel and credential read-back, plus supported backhaul
  provisioning modes. Host fake programs cannot establish vendor CLI parity.
- Measured final firmware size and CPU/latency behavior; the separate size
  profile commit `2bfe424fa65adb07c8fd07144d376639ae26fecc` is not part of this
  reviewed base and must be integrated/tested explicitly in a combined image.

These gates require a later controlled build/device trial. No test in this
follow-up changes host time, router time, NVRAM, radio configuration or boot
selection.

## Verified evidence (2026-09-10)

- Final workspace: 358 tests pass, including 105 NTP tests; workspace fmt and
  Clippy with warnings denied pass. Logs `/tmp/gt-tier1-fix-workspace.log` and
  `/tmp/gt-tier1-fix-clippy.log`.
- Fuzz smoke: 250,000 iterations for each of three seeds, 750,000 total,
  pass (`/tmp/gt-tier1-fix-fuzz.log`). This is bounded smoke fuzzing, not a
  claim of exhaustive exploration or coverage-guided campaign completeness.
- Combined host C ABI suite, actual-C WLAN credential flow and all nine
  zlib-audit negative/parser controls pass (`/tmp/gt-tier1-fix-cabi.log`).
- ARM GCC 5.5/QEMU C ABI suite and four configured zlib header variants pass;
  all ten direct installed consumers' 31 zlib imports resolve. NTP ARM
  release build and QEMU self-test pass, importing syscall@GLIBC_2.4 and no
  getrandom symbol. The actual WLAN helper compiles with GCC 5.5, warnings
  denied; that is not an on-router WPS run.
- Actual private WLAN runner fixtures pass raw exit/signal status, opaque
  argv, timeout, overflow clearing, child reaping, sparse FD closure and
  rejection of an executable text file without shell fallback.
- All 30 patches replay on exact upstream `6be5bc84b50`; canonical diff hash
  matches the updated lock:
  `12cb6ccf4ab00de00b78010195f435ca48c944e66aee8ed3bf26fbb23fbff5de`.
  Final log `/tmp/gt-tier1-fix-locked-replay.log`. The hash is computed before
  Rust overlay copying, as in CI; trying to rehash the populated sparse tree
  afterward is invalid and was discarded during verification.
- Security, firewall-capture, network-hardening and rust-fast gates pass.
  Shared promotion tests 3/3, workflow tests 17/17, trial controller 34/34,
  input lock 8/8, build-stage failure 5/5, compiler-cache frontend 2/2 and
  Make bootstrap 3/3 pass. Workflow YAML parses; git diff whitespace check
  passes. Sparse security replay explicitly skips absent wpa_supplicant
  Makefile checks; no full-source compilation is inferred from that gate.
- Builds, fixtures and logs stayed in tmpfs with swap disabled. Original
  worktrees and router were not modified. No GitHub push or hosted CI run was
  performed; local equivalents do not imply a new hosted green run.

## NTP limitations retained as explicit debt

The scoped fixes do not establish full BusyBox behavior equivalence. The
inherited rc hook only marks readiness after a step, so already-small offsets
need a separately designed readiness transition. Published root dispersion
does not grow between updates; the inherited upstream refid is forwarded.
Synchronous DNS can stall the event loop, realtime-based scheduling is sensitive
to external clock changes, and the IPv4 listener lacks per-packet source
selection for multi-address LANs. NTP-era rollover in 2036 is not solved here.
These are known limitations, not passing hardware results or security guarantees.
