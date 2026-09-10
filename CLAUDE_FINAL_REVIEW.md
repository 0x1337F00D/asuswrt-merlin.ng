# Claude final-state reconciliation — 2026-09-10

Compared Claude's `3c4e56eb387` and its uncommitted socket-order test with our
`f201a5dd608` plus the clean-build USB DAG and final libshared link fixes.
The supplied narrative describes older intermediate states as well as the
final state; neither a successful old CI image nor its test count approves
this combined candidate.

## Release procedure

All compilation, temporary files and test targets remain on tmpfs, with swap
disabled. A fresh full build must pass input-lock, artifact freshness, ARM ABI,
library consumer, web payload and full-link checks before any flashing.
The first router boot is one-shot into slot 1 with slot 2 retained as fallback;
permanent promotion is withheld during initial testing. A hung unreachable
router still requires a reboot/power cycle to execute that fallback.

Current router baseline at this review: Second / BOOT_SET_PART2_IMAGE,
3.0.0.6 / 102.9 / alpha1. The existing health suite passed on 2026-09-10:
services, WAN, DNS, all radios, malformed HTTP rejection, firewall terminal
drops, crash-log scan and short PID stability. Kernel log already contains
bridge own-source-address warnings and CFG80211 WLC_SCB_AUTHORIZE warnings;
these are baseline findings, not evidence of a new candidate regression.

## Historical findings to preserve, not silently mark resolved

- Claude's long SIGCHLD-mask and multithreaded fork concerns refer to the old
  in-process runner. Our separate supervisor keeps that logic out of the
  hosting root daemon. Its documented exceptional transport/reaping limits
  remain; isolated native tests are not all possible WLAN workflows.
- Other-model WiFi7/WiFi8 credential paths and WISP fallback behavior need
  separate enablement review. This GT-AX11000 build is not approval for them.
- NTP holdover/root-dispersion, persistent clock-write failure in one-shot
  mode, and cold-boot entropy availability need lifecycle testing on hardware.
- LLTD intentionally omits topology/Emit functionality. Names/TLV encoding
  differences from the blob and real Windows discovery behavior need further
  compatibility review. Our typed truncated-datagram result already prevents
  the prefix-parsing problem described in Claude's older receive implementation.
- HTTP's vendor authentication/referer hooks are prebuilt. Their compatibility
  with parsed strings must be checked on the actual firmware, especially login,
  settings apply and client lists. An overlay-less vendor build is not promised.
- infosvr inherits the LAN/WAN firewall boundary on its listener; the default
  INPUT DROP is critical. Factory-debug behavior is a separately documented
  vendor dependency, not a normal UI toggle or permission to weaken the firewall.
  Its source-subnet filter does not prove the incoming interface. WSDD's vendor
  startup supplies the LAN interface; manual startup without -i is unpinned.
- Claude's rustls/ring/aws-lc static-archive measurements establish a possible
  future experiment, not a shipped TLS replacement or a final linked size.
  A real server handshake, certificate/key handling and ISA review remain gates.

## Status

Independent Tier 1/2 reviews and targeted salvage completed. Preserved our
strict HTTP header-block framing and LLTD send-confirmed state lifecycle;
added the short-path read guard, Rust/C 32/64-bit offsets and flag checks,
LLTD Quick Discovery/broadcast rules, measured amplification assertions, and
four behavioral WSDD socket-order regressions with failing mutation controls.
Host workspace: 584 tests, zero failures; formatting and all-target Clippy
with warnings denied passed. Targeted HTTP/LLTD ARM and C-reader checks passed.
All 34 trial-controller tests passed. Corrected libshared passed the optional
original-vendor export comparison; the old bloated link was correctly rejected.
New canonical patch hash:
`0e16c07f82c3524d4ed55ece67d5ae2f1b835f051844e6f1aa443ae7578c52e2`.

No combined image has been built or installed yet. Full image extraction and
hardware checks remain mandatory; these results are not release approval.
