# Technical debt and TODOs

This file tracks known limitations of the GT-AX11000 overlay. A successful
compile is not sufficient evidence for releasing or flashing a candidate.

## Current validated candidate

- Image: `GT-AX11000_3006_102.8_2_ubi.w`
- SHA-256: `3856d5e0ea8f759b09adb645b0a8d11f6b1584bbbd8e58377d60adb496cdfe76`
- Upstream: `d2701f4e238c2f423849fc78368223d883efbf44`
- Source state: `f9a98b7d245859d8886327df5aea7dd523bb6cad07ca70cc020064637dd919ae`
- Built entirely in `/tmp` tmpfs with all eight overlays. The security-overlay
  gate, firmware/rootfs manifests, 94 host Rust tests, Clippy, ARMv7 checks,
  five consumer ABI/library checks, and three QEMU runtime paths passed.
- The one-shot partition-2 hardware trial passed on 2026-08-21: expected
  candidate/fallback boot states and version, services, WAN, local DNS, all
  three radios, malformed HTTP request, IPv4/IPv6 terminal DROP rules, clean
  kernel log, stable service PIDs, `rstats`, `infosvr`, and `Notify_Event2NC`.
- An unauthenticated country-profile POST did not change the SHA-256 snapshot
  of country, regrev, channel-list, power, or raw calibration NVRAM values.
- The explicit second reboot returned to partition 1, persistent partition-1
  state and `3.0.0.4/388.11/0`; baseline services, WAN/DNS, radios and
  forwarding passed. The candidate is validated for continued development,
  not promoted as a permanent router image.

## Release blockers

- [x] Complete a clean RAM-only build of all seven overlays and pass the
  firmware/rootfs manifest gates.
- [x] Run the candidate through the one-shot partition-2 trial controller,
  verify LAN, WAN, all three radios, firewall, VPN, `infosvr`, `rstats`,
  `wanduck`, and `nt_center`, then verify the automatic return to the known
  baseline image.
- [x] Audit the retained router configuration for weak pre-existing WPA/WPS,
  VPN, WAN-management, and firewall settings. Secure defaults do not rewrite
  settings restored from NVRAM.
- [x] Do not publish the branch or trigger GitHub Actions until the local image
  and hardware trial pass.

## Security debt

- [x] Replace or explicitly disable security-sensitive compatibility stubs that
  reported false EULA, privacy, or security-update success. Unsupported
  operations now fail closed and configuration changes produce syslog entries.
- [x] Integrate country-only test-lab authorization, atomic WLAN security
  tuples, and effective IPv4/IPv6 terminal-DROP checks into runtime call sites.
- [ ] Integrate the remaining typed `router-policy` WAN-admin and VPN
  kill-switch requirements into effective-rule inspection. The VPN profile
  models are still preparatory; OpenVPN import hardening remains in reviewed C.
- [ ] Verify the emergency firewall failure path on hardware: forwarding must
  stay disabled, WAN INPUT must be dropped for IPv4 and IPv6, and custom
  `firewall-start` scripts must not run after a failed ruleset apply.
- [x] Add a build-time security-overlay gate covering authenticated routing,
  country-only mutation, raw calibration-key denial, firewall ordering,
  OpenVPN imports, IPsec cleanup, WireGuard and WPS argv execution.
- [ ] Add executable fixture tests for OpenVPN imports (compression, legacy
  ciphers/digests, route and `pull-filter` injection), IPsec multipart names,
  PKCS#12 cleanup, WireGuard endpoint updates, and WPS interface names.
- [ ] Re-audit every remaining `system`, `popen`, shell-script generation, and
  NVRAM-to-command path. Prefer fixed argv execution and typed Rust parsers.
- [ ] Review proprietary prebuilt objects/libraries borrowed from other ASUS
  models. A successful ARM link does not prove runtime ABI compatibility.

## Wireless test-lab debt

- [x] Make country selection—including explicit `ALL`—the only test-lab
  mutation. Direct per-radio country, channel-list, DFS, TX percentage,
  `maxp*`, `ccode`, and `regrev` apply keys are read-only.
- [x] Apply the selected country profile and 100% of its driver/board-calibrated
  cap consistently to all three radios, without writing raw `maxp*` values;
  clear legacy channel/exclusion overrides so they cannot outlive the profile.
- [ ] Verify on GT-AX11000 hardware that each radio reports the selected
  country, expected channel set, DFS state, and calibrated power after reboot.
- [x] Add a UI read-back panel that shows effective driver country, channel
  list, channel specification, DFS state, and power for all three radios before
  and after applying a test-lab profile.
- [ ] Export/import the test-lab profile separately from the normal NVRAM
  backup so that a factory reset does not silently re-enable it.

## Rust component debt

- [x] Keep every firmware Rust recipe dependent on current sources/manifests;
  Cargo may reuse fingerprints, but Make must never silently reuse a stale
  final binary from a broad cache restore. Firmware recipes are forced targets;
  Cargo performs the incremental fingerprint decision.
- [ ] Add packet fixtures and router captures for `infosvr`, including AiMesh
  group-ID and `GETINFO_EX2` compatibility.
- [ ] Gate the `rstats` ISP-meter behavior with the model build configuration;
  GT-AX11000 does not enable the legacy ISP-meter feature.
- [ ] Expand fuzz/property tests for HTTP query and multipart parsing, NVRAM
  apply validation, VPN profile parsing, and the WAN state machine.
- [ ] Measure memory, CPU, startup time, and crash/restart behavior of all five
  Rust ports on the router.

## Build and CI debt

- [ ] Fix the fast-resume path so unchanged kernel configuration does not force
  repeated kernel rebuilds. Record per-phase timing in the build metadata.
- [ ] Make local ccache optional without a failed pilot attempt, or provision a
  checksummed RAM-local ccache binary. Never write the cache to SSD.
- [ ] Keep top-level orchestration at `-j1`; only enable package-graph `-j2`
  after repeated reproducible clean builds. Recursive jobs must share the GNU
  jobserver instead of spawning independent pools.
- [ ] Make one code path own patch application. When CI supplies a prepared
  worktree, record and verify the actual source diff hash instead of trusting
  only the intended patch list.
- [ ] Pin the GitHub overlay checkout to `GITHUB_SHA`, and key any Rust cache by
  overlay SHA, upstream SHA, toolchain SHA, and Rust version without a broad
  fallback that can inject stale final artifacts.
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

## Known build annoyances

- The vendor build emits many obsolete Autoconf warnings and performs
  error-prone compile probes inside clean recipes; final artifact and manifest
  gates remain authoritative.
- The vendor `wget/Makefile` rule touches generated Autotools inputs immediately
  before `configure`. On WSL this triggered one false "newly created file is
  older" clock error; an unchanged fast retry passed. Add a deterministic
  timestamp barrier without changing firmware contents.
- The build expects a `repo` command even though this overlay uses Git; the
  missing-command message is currently non-fatal noise.
- Proprietary components prevent complete source-level verification, so binary
  ABI checks and hardware tests are mandatory.
