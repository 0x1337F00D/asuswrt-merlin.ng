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
- infosvr inherits the LAN/WAN firewall boundary on its listener. Actual live
  INPUT policy is ACCEPT with a terminal DROP, but an earlier interface-unbound
  UDP multicast accept (except port1900) includes port9999. Standard WAN NEW
  unicast reaches DROP; full WAN multicast isolation has not been proved.
  This is a pre-existing vendor finding, not a newly fixed boundary.
  Factory-debug behavior is a separately documented
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

The initial combined build failed as described below. The corrected clean
123e6fb4621 build subsequently completed; see the verified candidate evidence.

## Full-build follow-up: PNG configuration dependency

The 0b671 candidate failed before publication at qrencode: CMake generated
`qrencode: PNG::PNG-NOTFOUND` because its supplied libpng path did not yet
exist. FindPNG only assigns an imported location after EXISTS succeeds.
Independent out-of-tree cross configuration/build with the same arguments and
completed PNG staging passed on GCC5.5/CMake3.28.3, with PNG enabled.
Explicit zlib -> libpng -> qrencode package and configure-Makefile ordering
now has clean/cached -j2/-j8 regression coverage; all four scenarios pass and
all four fail on the old graph. An already poisoned CMake cache must not be
reused. The next clean installation candidate uses package jobs1, matching
the existing CI/default release contract. Aggressive package parallelism is
not approved by these incomplete clean builds.

## Verified candidate evidence — 2026-09-10

Clean RAM-only build 123e6fb4621 passed with top/package jobs1, swap disabled.
Canonical patch hash: 7834411d0354ed2efee6263b489e909cdde4cfa5f64b0c8a055752b24c65f74c.
Filesystem-only firmware: 77463572 bytes, SHA256
fb0936818724e40be51f67109375ac4d9176fcdec964f1b7df74435fff2f1856.
Actual UBI extraction, staging equivalence, consumer hashes,25 dictionaries,
31 Web symlinks, vendor exports,15 ARM consumers,8 QEMU runtime paths,
QR PNG generation and wget/WLAN reference gates passed. WLAN reference uses
a synthetic driver, not a physical roaming/steering proof.
On the one-shot First/PART2-persistent boot, native health and rendered guard
checks passed; WiFi/LAN/VPN aggregate configuration digests were unchanged.
Client-list native probe:10 samples,9 live clients,max1.508ms,105 database
entries,2328KiB RSS. Browser login/UI rendering remains untested this turn.
Initial soak passed31/31 samples over919.99seconds, with stable service PIDs,
WAN/DNS/radios and no detected crash markers. Host ping910/910,0loss,
min/avg/max1.956/4.527/68.914ms. This is not a mobile-room-transition test.
Explicit fallback reboot proved Second/PART2, four original binary hashes,
healthy services and unchanged configuration digests. A second candidate boot
passed health, exact image guard and config checks. Guard-mediated permanent
promotion completed2026-09-10T13:41:49Z: First/BOOT_SET_PART1_IMAGE,
PROMOTED_UI_NVRAM_PART1; post-promotion health passed. Slot2 remains intact.
Read-only24h observation is the next phase. The verified encrypted backup does
not prove a factory-reset restore, and physical UI/roaming coverage is limited.
