# Technical debt and TODOs

This file tracks known limitations of the GT-AX11000 overlay. A successful
compile is not sufficient evidence for releasing or flashing a candidate.

## Current router state and latest hardware-tested candidate

- The known baseline is active and persistently selected on partition 2:
  `BOOT_SET_PART2_IMAGE`, version `3.0.0.6/102.8/4`. The latest partition-1
  candidate is not promoted.
- The corrected partition-1 candidate is
  `GT-AX11000_3006_102.8_4_ubi.w`, SHA-256
  `d8ace55818c5b9577875d9e01b2ae5934218d5f51aeb91b33ebd4f1795bd2080`
  (79,822,868 bytes), built and repacked entirely in `/tmp` tmpfs from upstream
  `088512a1296e361d65e5429e7d8d61ef3fdf4c86`. The full fast build took 682
  seconds. Its 103 Rust tests, 21 trial/guard tests, 750,000 post-build
  structured fuzz cases, C ABI, five ARM consumers, three QEMU runtime paths,
  1,105 Web files and 31 symlinks passed.
- A real one-shot partition-1 run passed twice through the strict health gate.
  WAN, local DNS, all three radios, terminal IPv4/IPv6 DROP rules, malformed
  HTTP input, stable service PIDs, all Rust self-tests and the live `infosvr`
  protocol suite passed. Under the persisted `ALL` profile, temporary explicit
  start requests proved that the new firmware suppresses proprietary `roamast`
  and Smart Connect `bsd`; neither process appeared and the fatal-signal count
  stayed zero. Client DNS and HTTPS also passed. The router was explicitly
  returned to the known-good persistent partition 2 after the short soak.
- The preceding candidate
  `40a6b942fe0774716e04f93059803e3baadb008810214ef2a055d7dc3a5bed5c`
  remains rejected. Overnight evidence contained 213 signal-11
  crashes from proprietary `roamast`; a clean baseline boot additionally
  exposed two signal-11 crashes from proprietary Smart Connect `bsd`. The
  existing health gate missed ASUS' kernel wording `potentially unexpected
  fatal signal 11`.
- Immediate reversible mitigation on the router: the previous values were
  saved under `/data/candidate-failure-20260822T1101CEST`, then
  `roamast_disable=1` and `smart_connect_x=0` were committed. All three bands
  retain identical SSID/auth/cipher/key settings. A clean reboot now has zero
  fatal signals, both faulty daemons remain stopped, and the strict full health
  gate plus client DNS/HTTPS pass.
- The health script and persistent guard now reject the kernel's fatal-signal
  wording. The guard has fixed asymmetric roles (candidate partition 1,
  baseline partition 2), so a baseline boot can no longer re-arm a rejected
  candidate. The radio-service quarantine is now built and hardware-tested.
  The candidate is deliberately not promoted permanently until a substantially
  longer monitored soak passes.

## Release blockers

- [x] Complete a clean RAM-only build of all nine overlays and pass the
  firmware/rootfs manifest gates.
- [x] Run the newly rebuilt radio-service-quarantine candidate through the
  one-shot partition-1 trial controller,
  verify LAN, WAN, all three radios, firewall, VPN, `infosvr`, `rstats`,
  `wanduck`, and `nt_center`, then verify the automatic return to the known
  baseline image.
- [x] Audit the retained router configuration for weak pre-existing WPA/WPS,
  VPN, WAN-management, and firewall settings. Secure defaults do not rewrite
  settings restored from NVRAM.
- [x] Do not publish the branch or trigger GitHub Actions until the local image
  and hardware trial pass.
- [x] Rebuild the complete AUTODICT Web payload and verify matching pages and
  all dictionaries in a new one-shot partition-1 trial.
- [ ] Exercise an ordinary WLAN Apply and the isolated country endpoint in an
  authenticated browser session. Static/runtime markers and persisted NVRAM
  values passed, but Windows browser automation was unavailable during the
  final hardware trial.
- [x] Build from current upstream `088512a1296e361d65e5429e7d8d61ef3fdf4c86`,
  which includes miniupnpd 2.3.11 and its 2026 heap-overflow fix; no candidate
  from the older `d2701f4e238c` base may be promoted.

## Security debt

### Current unpromoted 2026 hardening work

- [x] Backport the applicable upstream hostap/wpa security fixes to both
  duplicated Broadcom 2.9 trees: constant-time SAE/EAP-pwd processing
  (2022-1), PMKSA network-context and AKMP matching (2026-2), and exact RADIUS
  Message-Authenticator length validation (2026-5). The resulting `hostapd`
  and `wpa_supplicant` ARM/EABI5 targets build successfully.
- [x] Enforce generated OpenVPN configurations with AEAD-only data ciphers,
  SHA-256, TLS 1.2 or newer, disabled compression and server-certificate role
  verification. Retained NVRAM and complete custom blocks pass bounded Rust
  policy before they can affect generated configuration.
- [x] Install and semantically verify an IPv4/IPv6 `CODEX_WAN_GUARD` after VPN
  and custom firewall hooks but before forwarding is enabled. It protects
  disabled WAN HTTP(S), SSH and Telnet exposure with fixed-argv commands and
  Rust inspection of the effective saved ruleset.
- [x] Rebuild the affected `rc`, `libovpn`, `hostapd` and `wpa_supplicant`
  targets and verify the intended ARM symbols and hardening markers.
- [x] Replace the territory-dependent test-lab dropdown with the 212 country
  codes reported as common to all three GT-AX11000 Broadcom radios, plus
  exactly one synthetic `ALL`. Map `ALL` to the driver's real world locale
  `#a` and bind the lab-only 500% driver request and ACS/DFS flags atomically
  to that profile. The value is not measured RF output and may be clamped by
  immutable board calibration and driver limits.
- [x] Build and manifest-check a complete firmware containing the new
  eleven-patch series in tmpfs. Candidate SHA-256:
  `30d6f62c373d5949216b0dab81df265de8939b6dc23e2fed8ce70ea213403db3`.
  The five Rust consumers, 1,105 Web files, 31 Web symlinks and 25 matching
  5,078-entry dictionaries passed their final image gates.
- [x] One-shot-test the rebuilt candidate with the `ALL`-profile proprietary
  radio-service quarantine on the fallback-protected
  partition and verify OpenVPN, IPv4/IPv6 WAN guard, all three radios and
  rollback before promotion. The last promoted image above predates these
  changes and must not be represented as containing them.
- [ ] Migrate an OpenVPN server to `tls-crypt-v2` (or `tls-crypt`) in a
  controlled compatibility test and re-export every affected client profile.
  Enabling it silently would strand existing clients, so it is intentionally
  not forced by this overlay.

- [x] Replace or explicitly disable security-sensitive compatibility stubs that
  reported false EULA, privacy, or security-update success. Unsupported
  operations now fail closed and configuration changes produce syslog entries.
- [x] Integrate country-only test-lab authorization, atomic WLAN security
  tuples, and effective IPv4/IPv6 terminal-DROP checks into runtime call sites.
- [x] Integrate typed WAN-admin requirements into effective-rule inspection.
  The first WAN INPUT jump and the exact IPv4/IPv6 management-port DROP rules
  are now verified after VPN/custom hooks, together with the terminal INPUT
  and FORWARD policy (including `logdrop -> LOG; DROP`).
- [ ] Integrate per-profile VPN kill-switch requirements into semantic
  effective-rule inspection. This still needs representative real-router
  ruleset fixtures for each OpenVPN and WireGuard client mode.
- [x] Move imported OpenVPN custom-directive validation from ad-hoc C into a
  bounded Rust allowlist. Weak ciphers/digests, compression, scripts, routes,
  pull filters, unknown directives and malformed numeric values fail closed.
- [ ] Verify the emergency firewall failure path on hardware: forwarding must
  stay disabled, WAN INPUT must be dropped for IPv4 and IPv6, and custom
  `firewall-start` scripts must not run after a failed ruleset apply.
- [x] Add a build-time security-overlay gate covering authenticated routing,
  country-only mutation, raw calibration-key denial, firewall ordering,
  OpenVPN imports, IPsec cleanup, WireGuard and WPS argv execution.
- [x] Add executable Rust policy fixtures for OpenVPN compression, legacy
  ciphers/digests, script/route/`pull-filter` injection, malformed bounds and
  complete custom blocks.
- [x] Add strict C11-to-Rust ABI fixtures for HTTP URL/query/multipart parsing,
  test-lab/WLAN tuples, OpenVPN custom blocks, IPsec multipart names,
  WireGuard endpoint updates and the `wanduck` transition struct. These catch
  symbol, layout, ownership and output-mutation regressions.
- [ ] Add end-to-end fixtures around the actual vendor consumers for OpenVPN
  profile generation, PKCS#12 cleanup, WireGuard endpoint updates and WPS
  interface names; the direct ABI fixtures do not exercise surrounding C
  control flow or generated files.
- [ ] Replace the remaining shell-formatted command execution in
  `shared/wlif_utils_ax.c`. Several paths interpolate interface, SSID, PSK or
  DPP-derived values into `system`/`popen`; use bounded validation plus fixed
  `argv` execution and ensure credentials never enter a shell command line or
  log. Rust policy can validate inputs, but cannot make an unsafe C shell
  boundary safe by itself.
- [ ] Re-audit every remaining `system`, `popen`, shell-script generation, and
  NVRAM-to-command path. Prefer fixed argv execution and typed Rust parsers.
- [ ] Review proprietary prebuilt objects/libraries borrowed from other ASUS
  models. A successful ARM link does not prove runtime ABI compatibility.

## Wireless test-lab debt

- [x] Make country selection—including explicit `ALL`—the only test-lab
  mutation. Direct per-radio country, channel-list, DFS, TX percentage,
  `maxp*`, `ccode`, and `regrev` apply keys are read-only.
- [x] Apply normal countries with a 100% request and the synthetic `ALL`
  profile with a 500% driver request consistently to all three radios, without
  writing raw `maxp*` values. Clear legacy channel/exclusion overrides so they
  cannot outlive the profile. Treat either percentage as a requested scalar,
  never as measured or guaranteed RF output.
- [ ] Verify on GT-AX11000 hardware that each radio reports the selected
  country, expected channel set, DFS state, and calibrated power after reboot.
- [x] Add a UI read-back panel that shows effective driver country, channel
  list, channel specification, DFS state, and power for all three radios before
  and after applying a test-lab profile.
- [x] Store the versioned warning acknowledgement once in NVRAM. Normal Apply
  and the atomic country-profile endpoint share the same persisted key; the UI
  renders it checked and disabled on later page loads.
- [ ] Export/import the test-lab profile separately from the normal NVRAM
  backup so that a factory reset does not silently re-enable it.

## Rust component debt

- [x] Keep every firmware Rust recipe dependent on current sources/manifests;
  Cargo may reuse fingerprints, but Make must never silently reuse a stale
  final binary from a broad cache restore. Firmware recipes are forced targets;
  Cargo performs the incremental fingerprint decision.
- [ ] Add packet fixtures and router captures for `infosvr`, including AiMesh
  group-ID and `GETINFO_EX2` compatibility.
- [x] Gate the `rstats` ISP-meter behavior with the model build configuration;
  GT-AX11000 does not enable the legacy ISP-meter feature.
- [x] Expand fuzz/property tests for HTTP query and multipart parsing, NVRAM
  apply validation, VPN profile parsing, and the WAN state machine.
- [ ] Measure memory, CPU, startup time, and crash/restart behavior of all five
  Rust ports on the router.

## Build and CI debt

- [ ] Fix the fast-resume path so unchanged kernel configuration does not force
  repeated kernel rebuilds.
- [x] Record worktree preparation, source adaptation, vendor build and
  post-build gate timings separately in `BUILD-STATE.txt`, in addition to the
  end-to-end duration.
- [x] Add an idempotent `rust-ui-httpd-relink` path that rebuilds only `httpd`
  and `www`, promotes exact artifacts into the flat rootfs, removes package
  staging duplicates, and repacks without rebuilding kernel or drivers.
- [ ] Make local ccache optional without a failed pilot attempt, or provision a
  checksummed RAM-local ccache binary. Never write the cache to SSD.
- [ ] Keep top-level orchestration at `-j1`; only enable package-graph `-j2`
  after repeated reproducible clean builds. Recursive jobs must share the GNU
  jobserver instead of spawning independent pools.
- [ ] Make one code path own patch application. When CI supplies a prepared
  worktree, record and verify the actual source diff hash instead of trusting
  only the intended patch list.
- [x] Pin the GitHub overlay checkout to the exact `GITHUB_SHA`; bind the Rust
  cache to the overlay, upstream, toolchain and Rust identities. Restored Cargo
  fingerprints are safe because every firmware consumer recipe is forced and
  Cargo revalidates the current sources before Make consumes an artifact.
- [ ] Confirm the GitHub-hosted public runner pilot (no self-hosted runner),
  including peak disk use, runtime, cache effectiveness, and artifact upload.

## Trial and recovery debt

- [x] Default the trial controller to dry-run and require an exact risk
  acknowledgement for execution.
- [x] Recover toward the baseline after expected failures, unexpected
  exceptions, interrupts, and evidence-store failures; recovery logging must
  never block rollback.
- [ ] Add an out-of-band power controller if fully automatic recovery from an
  SSH-unreachable candidate is required. Without one, the one-shot state makes
  the next reboot return to baseline, but cannot physically power-cycle the
  router.
- [ ] Periodically restore the encrypted settings/JFFS backup onto a reset test
  device and document the exact recovery time and any excluded secrets.
- [x] Add a persistent, fail-safe promotion-hold marker for host-driven soaks;
  the guard must keep partition 2 selected without rebooting the running
  candidate or permitting an automatic 120-second promotion.

## Known build annoyances

- The vendor build emits many obsolete Autoconf warnings and performs
  error-prone compile probes inside clean recipes; final artifact and manifest
  gates remain authoritative.
- The vendor `wget/Makefile` rule touches generated Autotools inputs immediately
  before `configure`. On WSL this triggered one false "newly created file is
  older" clock error; an unchanged fast retry passed. Add a deterministic
  timestamp barrier without changing firmware contents.
- The proprietary Web compressor prints `Segmentation fault` for some
  long-column JavaScript inputs and continues. The complete generated payload,
  dictionary cardinality, path set and hashes pass afterward, but this tool
  should be replaced or wrapped with an explicit per-input output check so a
  future partial result cannot be mistaken for success.
- The build expects a `repo` command even though this overlay uses Git; the
  missing-command message is currently non-fatal noise.
- Proprietary components prevent complete source-level verification, so binary
  ABI checks and hardware tests are mandatory.

## Rejected candidate: mixed AUTODICT Web payload

The 2026-08-21 Partition 1 candidate is rejected. Its fast UI repack promoted a
new `Advanced_WAdvanced_Content.asp` while retaining older language
dictionaries, so numeric AUTODICT identifiers rendered as unrelated labels
such as `game` and `English`. Normal settings also shared control flow with the
experimental country selector. The router was returned to the known-good,
persistent Partition 2 baseline.

Release gates now require `www-install` to produce a complete nested Web tree;
the repack atomically replaces the entire `/www` payload and refuses to reuse a
flat/stale tree. The test-lab selector has no form name, the vendor region input
is disabled, and country application is isolated from ordinary wireless form
submission. Do not promote another candidate until the generated dictionaries,
pages and rollback trial have passed on hardware. An authenticated browser
exercise of ordinary Apply and the isolated country endpoint remains an
explicit follow-up gate for changing regulatory profiles, rather than an
image-boot blocker.

## Fixed during hardware promotion

- Web payload identity manifests are stored under immutable
  `/usr/share/codex`; `/etc` is a volatile `/tmp/etc` link on this platform and
  cannot carry reboot-persistent firmware identity.
