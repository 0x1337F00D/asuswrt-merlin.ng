# Tier 1 re-review and Tier 2 boundary fixes

Review base: `210da6e7b2e1cd0182aeadffd8234d3d86283332`.
Pinned upstream: `6be5bc84b50ea37be7b5d4307c5042771c3cf95b`.
Date: 2026-09-10. Local validation only; **not firmware or hardware approval**.

## Boundaries, not a second implementation of C control flow

| Area | Corrected boundary | Regression evidence |
| --- | --- | --- |
| HTTP | The C transport returns an explicit complete/empty/incomplete/I/O-error/too-large result. Only a complete block reaches the pure Rust parser. No fabricated CRLF. Rust requires the parser's consumed length to equal the supplied block. | Tests extract the actual patched C reader and ABI, including every incomplete prefix at EOF/EIO, capacity edges, trailing bytes and preservation of body bytes. |
| LLTD | Full receive length is retained separately from the bounded buffer. Packet sockets start with protocol zero and become active only when bound. An exclusive prepared reply must be admitted before transmission; tokens and generation state commit only after successful send. | Oversized prefixes, socket-setup ordering, refused/dropped/failed transmissions, successful-send expiry and duplicate suppression. Independent cross-review of vendor AF_PACKET receive/send semantics. |
| wsdd2 | Separate private-field UDP discovery and HTTP metadata request types and encoders. The actual UDP send boundary independently checks response size. | UDP Get rejection and Probe response through the real loopback handler, final-send oversized rejection, 32-hex machine IDs, duplicate/nested simple XML fields and lexical closing-name mismatch. |
| wsdd2 budget | Monotonic elapsed Duration from a process-local Instant, not wall-clock time. | Backwards-time regression and bounded admission tests. |
| WLAN process execution | Rust validates domain values; a narrow C wrapper transports bounded results. A fresh standalone supervisor owns the CLI process. Only that supervisor signals its child, and it retains the child's PID with WNOWAIT until capture and cleanup finish. | Actual patched source compiled by the runtime fixture: raw wait status, injection-like literal argv, overflow, deadlines, exited leaders with pipe-holding descendants, foreign reapers, ignored/blocked signals, closed standard FDs, atfork callbacks and malformed helper replies. |

The WLAN wrapper uses fixed-path `posix_spawn`, not caller `fork`
callbacks, and gives the supervisor its own process group. The supervisor
executes only the four existing hostapd_cli/wpa_cli tool names, never a shell.
The existing Rust policy crate is unchanged; process management is not
reimplemented as a large unsafe Rust subsystem.

Target testing caught a real glibc 2.26 incompatibility: spawn's
`dup2(fd, fd)` retained CLOEXEC when standard FDs were closed. The result-pipe
write descriptor is now normalized above stderr before spawning.

`/usr/sbin/wlif-exec` is a fourteenth fresh artifact. Shared builds and
installs it, the repacker promotes it before deleting package staging,
and manifests, freshness checks, workflow hashes and cache exclusions all
include it. Final-rootfs checks require a regular non-symlink mode-0755 ARM
executable; it is not set-id. This changes the delivered file set and requires
a new complete firmware validation, not just a library replacement.

## Verified locally

- 564 workspace tests, workspace formatting, all-target Clippy with warnings
  denied, and ARMv7 workspace/all-target compile checking.
- 250,000 deterministic fuzz iterations with seed 11400714819323198485.
  This is a regression smoke test, not coverage-guided fuzzing or proof of
  absence of vulnerabilities.
- C ABI smoke suite, including the actual HTTP reader and existing client
  list, WLAN credentials/policy, router-security, wanduck and zlib fixtures.
- Independent LLTD review and ARM/QEMU LLTD self-test. HTTP reader/ABI also
  tested with GCC 5.5 and ARM/QEMU against the existing router rootfs.
- Five repack tests, including fresh/missing/stale helper and symlink
  rejection, plus the rust-fast static integration gate.
- All 33 patches replayed on a fresh pinned source; canonical patched diff
  SHA-256 matches `inputs.lock`:
  `b22547162a2b837780150ced1372ceeb98cdeed9b11905d24310ae3db419ba7b`.
  Security-overlay, firewall-capture and network-hardening gates passed.
- Actual patched WLAN wrapper and supervisor passed host and GCC 5.5
  ARM/QEMU tests, including 48 calls with a concurrent foreign child reaper.
  QEMU uses native exec launch bridges rather than globally enabling binfmt;
  the native fixture launcher establishes subreaping because QEMU does not
  implement that prctl. Both process implementations execute as ARM binaries.
  This is not native firmware execution.
- The isolated ARM C supervisor at -O2 measured 13,776 bytes before strip,
  9,732 bytes stripped; its only DT_NEEDED is libc.so.6. These are fixture
  compiler measurements, not the final vendor Makefile link or image size.

No native ARM hardware execution, full image link/rootfs validation or hosted
CI run is implied by these results.

## Remaining release gates and limits

1. Build a complete frozen candidate in RAM; check actual libshared symbol
   resolution, helper dependencies/size, all fourteen fresh artifacts and
   rootfs content. The previous isolated 9.6-KiB Rust archive claim is not a
   measurement of this changed whole-image link.
2. Run a protected hardware trial and real WPS/AP/supplicant operations,
   NTP rc/kernel lifecycle, HTTP clients and Windows discovery behavior.
   No router operation was performed for this review.
3. LLTD remains a deliberately reduced responder: Windows topology links
   and attacker-selected frame emission are not restored. A successful
   send syscall means kernel acceptance, not proven radio/wire delivery.
4. The supervisor handles ordinary CLI exits, timeouts and descendants
   retaining stdout in its process group. Direct privileged termination or
   SIGSTOP of the supervisor, descendants escaping the group, and
   uninterruptible kernel tasks are not containment guarantees.
5. On an exceptional broken/malformed helper transport the wrapper does
   only a nonblocking reap, to avoid killing a reused PID or waiting forever.
   A helper that exits later may need the caller's normal child reaper.
   This residual lifecycle debt is explicit; it is not a claim that arbitrary
   helper crashes have perfect cleanup. Normal success and complete error
   responses wait for the helper to exit.
6. No blanket release approval for Tier 1: the previous zlib consumer ABI,
   vendor library dependencies, NTP behavior and size/link gates still apply.
