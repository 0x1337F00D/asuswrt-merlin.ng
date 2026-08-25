# Technical debt and TODOs

This file tracks known limitations of the GT-AX11000 overlay. A successful
compile is not sufficient evidence for releasing or flashing a candidate.

## Current router state and latest hardware-tested candidate

- The known baseline is active and persistently selected on partition 2:
  `BOOT_SET_PART2_IMAGE`, version `3.0.0.6/102.8/4`. The latest partition-1
  candidate is not promoted.
- The newest local client-view/local-QoS candidate is
  `GT-AX11000_3006_102.8_4_ubi.w`, SHA-256
  `ebfdaeb58bddbb26f6f5424aabb3f211771c444c0953984e324293bc9c3b115d`
  (75,759,636 bytes). It was repacked entirely on `/tmp` tmpfs on 2026-08-25
  and passed a fallback-protected one-shot partition-1 hardware trial on the
  same day. Both IPv4 and IPv6 installed `CODEX_WAN_GUARD` as the first WAN
  INPUT jump with all seven management-port drops and a terminal RETURN;
  forwarding, local DNS and HTTPS remained healthy and no guard exhaustion or
  ruleset-validation error was logged. The router was explicitly returned to
  the known persistent partition-2 baseline after the trial; the tested image
  remains intact on partition 1 but is not promoted.
- In that trial, the closed ASUS `networkmap` process loaded the local Rust ABI
  provider and survived both boot and a `SIGUSR1` rescan with a stable PID. Its
  174,964-byte LAN shared-memory segment reported 10 live clients and the
  persistent JSON database retained 105 records. The shipped
  `/www/client_function.js` contained both malformed-response array guards.
  No Trend Micro process or mobile EULA page was present.
- Candidate `531a3a5c9326f3688a7300b00e6d0bf764ddef9e374353bcfe3ba939b153192d`
  passed its short one-shot Internet/firewall test: both first-rule WAN guards,
  forwarding, DNS and HTTPS were healthy. It is nevertheless rejected because
  the prebuilt `networkmap` has an unconditional `DT_NEEDED libbwdpi.so`; after
  removal of the proprietary library the process could not start, so the live
  client view remained unavailable. The replacement candidate supplies only a
  three-symbol fail-closed Rust ABI library and gates its SONAME, exports and
  absence of proprietary strings.
- Candidate `a5c33ad4f63983eff1a3a04213c63ff58972ee20bbbce3a08a129607739bc16d`
  is rejected. Its one-shot partition-1 run stayed alive for roughly eight
  hours, but the post-hook WAN guard hit an iptables update race, entered the
  intentional fail-closed path and left forwarding disabled. This explains
  the overnight Internet outage; there was no kernel crash. A later reboot
  consumed the one-shot selection and restored the known partition-2 baseline.
  The replacement retries only fixed-argv guard operations for a bounded
  sub-second interval, removes stale duplicate hooks and logs the exact failed
  family/stage while retaining fail-closed behavior for persistent errors.
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
- [x] One-shot-test candidate `ebfdaeb5...115d` and require successful
  `CODEX_WAN_GUARD` installation in both `iptables-save` outputs, enabled IPv4
  forwarding, client DNS/HTTPS, a stable `networkmap` PID and non-empty live
  client data, and no guard retry exhaustion during boot. The live Network Map
  backend exposed 10 clients through the exact shared-memory segment consumed
  by `httpd`; browser rendering still needs the authenticated UI check above.
- [ ] Repeat WAN/firewall restarts under load and run a longer monitored soak
  before any permanent promotion. Require both guard families, forwarding,
  DNS/HTTPS and the Network Map PID to remain healthy after every restart.
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

## Local client view and QoS debt

- [x] Disable the GT-AX11000 `BWDPI`/Trend Micro feature set at profile and
  kernel configuration level. Adaptive QoS, Traffic Analyzer and proprietary
  application classification must not be exposed as working local features.
- [x] Preserve the dashboard's existing `bwdpi_status("traffic", ...)` hook
  contract with a bounded local implementation backed by `/proc/net/arp` and
  `/proc/net/nf_conntrack`. Conntrack records are parsed in Rust; the C bridge
  uses fixed buffers, bounded client state and no shell execution.
- [x] Restrict accepted QoS modes to local Traditional QoS and Bandwidth
  Limiter values. Reject the removed proprietary Adaptive QoS mode in the Web
  apply path and migrate a persisted unsupported mode to Traditional QoS once
  during boot without deleting bandwidth or client rules.
- [x] Make the dashboard client list tolerate an unavailable icon hook,
  malformed hook responses and individual stale Network Map records without
  discarding every valid client. Fix the JSON-C ownership error which could
  double-free a never-online custom client in
  `get_clientlist_from_json_database()`.
- [x] Fix the actually shipped legacy client page and HTTP backend as well as
  the optional dashboard module. Empty or structurally incomplete
  `/tmp/nmp_cache.js` snapshots no longer override live Network Map data;
  generated cache objects include `maclist` and `ClientAPILevel`; metadata is
  type-checked before dereference; missing client strings and malformed records
  are skipped instead of aborting the complete view.
- [x] Confirm on the running router that `networkmap` and its persistent JSON
  database are alive while the generated Web snapshot incorrectly contains an
  empty `maclist`; a normal `SIGUSR1` Network Map refresh repopulates the live
  neighbor scan without rebooting or writing NVRAM.
- [x] Confirm the replacement image's complete live Network Map backend on
  GT-AX11000 hardware: the Rust ABI provider exports only the three gated
  compatibility symbols, `networkmap` survives a rescan, shared memory reports
  10 live clients, and the persistent database retains 105 historical records.
- [ ] Exercise the Network Map/client-list traffic view and both retained QoS
  modes on GT-AX11000 hardware. Verify monotonically increasing per-client
  counters, shaping, reboot persistence and bounded memory/CPU under a full
  conntrack table before promotion.
- [ ] Add IPv6 neighbor resolution and fixtures for IPv6-only clients. The
  initial local compatibility hook maps IPv4 conntrack addresses through the
  ARP table and therefore cannot attribute an IPv6-only client to a MAC.
- [ ] Decide whether a transparent local L7 classifier is worth the attack
  surface and CPU cost. The current replacement intentionally provides local
  L3/L4 accounting, HTB/fq_codel shaping and per-client limits, but does not
  claim proprietary application/category recognition.
- [x] Remove the shipped Trend Micro mobile EULA, proprietary engine/service
  binaries and `libbwdpi`/`libshn`/`libtdts` libraries, and disable the hidden
  Adaptive-QoS radio in the GT-AX11000 page. Both browser and authenticated
  server apply paths normalize/reject every QoS mode except Traditional (0)
  and Bandwidth Limiter (2); bandwidth values pass a bounded Rust decimal
  policy before NVRAM mutation.
- [ ] Replace the remaining prebuilt ASUS Network Map consumers. The closed
  `networkmap` executable requires the `libbwdpi.so` SONAME even with BWDPI
  disabled; a local Rust ABI provider now exports only a constant-disabled
  feature probe, a zeroing no-data lookup and a build marker. No proprietary
  process or implementation is present, but `networkmap`, `arpstorm`,
  `asusdiscovery`, and `find_cap` remain vendor binaries. The retained
  `usr/networkmap/nmp_bwdpi_type.js` is a 2.4-KiB static JSON keyword-to-device-
  type mapping, not executable DPI code; rename or replace it during a future
  Rust Network Map port.

## Build and CI debt

- [x] Replace moving upstream/toolchain inputs with exact commits in
  `inputs.lock`; validate its schema, the complete ordered patch set and the
  actual binary source-diff hash before a release build.
- [x] Make the scheduled upstream sync create/update a draft
  `upstream-sync/<sha>` pull request instead of merging `main`, and run separate
  required `Rust`, `Security overlay` and `Firmware` checks for vendor,
  overlay, workflow and lock changes.
- [x] Protect GitHub `main` with separate active rulesets: Rust, Security
  overlay and Firmware checks from GitHub Actions are mandatory without a
  bypass; deletion and force-push are blocked. A second rule requires a PR,
  one review, code-owner review and resolved threads. The sole-maintainer
  bypass is limited to PRs and cannot bypass build gates. A no-content direct
  update probe was rejected with HTTP 422 for both the missing checks and the
  missing PR.
- [ ] Fix the fast-resume path so unchanged kernel configuration does not force
  repeated kernel rebuilds. The vendor `bin`/`setprofile` path currently
  deletes or retimestamps `.config`, and `prek` runs `oldnoconfig`, which
  retimestamps generated headers. Reuse must be gated by a successful full
  contract and a kernel-artifact fingerprint; preserving `.config` alone was
  tested and is insufficient.
- [ ] Continue converting serial-order assumptions into explicit package-DAG
  edges. Clean parallel trials have already exposed and fixed `hub-ctrl ->
  libusb10`, `email-3.1.3/Makefile -> nt_center + sqlite`, `aws-iot ->
  nvram/libwebapi/wlcsm/cfg_mnt`, and `usbmuxd-1.1.1 ->
  libimobiledevice-1.3.0`; retain a clean CI build as the promotion gate
  because more hidden vendor staging dependencies may remain.
- [x] Constrain `asusnatnl`/pjproject 1.12 to one shared job token. Its pjnath
  makefile declares test binaries as depending on library files for which it
  has no file-producing rule and relies on serial target order; parallelizing
  that legacy subgraph races `pjnath-test` ahead of `libpjnath`.
- [x] Fail the post-build gate if the flat rootfs contains Trend/BWDPI service
  binaries or libraries, or if the local QoS/client-view replacement and its
  fail-soft dashboard code are absent. This gate runs locally and in Actions
  before an image can be published.
- [x] Record worktree preparation, source adaptation, vendor build and
  post-build gate timings separately in `BUILD-STATE.txt`, in addition to the
  end-to-end duration.
- [x] Add an idempotent `rust-ui-httpd-relink` path that rebuilds only `httpd`
  and `www`, promotes exact artifacts into the flat rootfs, removes package
  staging duplicates, and repacks without rebuilding kernel or drivers.
- [ ] Auto-disable local ccache before source preparation when no executable is
  available, or provision a checksummed RAM-local ccache binary. The current
  wrapper discovers the missing host command only after source adaptation;
  never write the cache to SSD.
- [x] Keep top-level orchestration at `-j1` and provide an opt-in GNU Make 4.4
  package DAG with one shared jobserver, an explicit serial foundation and a
  transitive `.WAIT` barrier. A 16-token build completed with a reference-
  equivalent rootfs, but was 5.4% slower overall, so the default remains one.
- [ ] Add phase-local timing around kernel, package foundation, parallel package
  remainder and image assembly; then benchmark only a small `2/4/8` token
  sweep. Do not spend full builds testing every package combination.
- [x] Make one code path own patch application. CI applies the canonical
  `patches/series` exactly once to its prepared source tree; `build.sh` then
  verifies the complete actual source diff (including added files) against
  `inputs.lock` instead of trusting only the intended patch list.
- [x] Pin the GitHub overlay checkout to the exact `GITHUB_SHA`; bind the Rust
  cache to the overlay, upstream, toolchain and Rust identities. Restored Cargo
  fingerprints are safe because every firmware consumer recipe is forced and
  Cargo revalidates the current sources before Make consumes an artifact.
- [x] Confirm the standard GitHub-hosted `ubuntu-24.04` public-runner pilot;
  no self-hosted runner is configured. The first full run completed in about
  39.5 minutes, retained at least 76 GiB free, peaked at 8.2 GiB source plus
  1.2 GiB toolchains, restored 92 MiB Rust and 410 MiB compiler caches, reached
  98.7% ccache hits for cacheable calls and uploaded a 72.4 MB artifact. The
  final locked run passed the separate Rust, Security overlay and Firmware
  jobs and uploaded artifact digest
  `sha256:6d5dfd7876e1276ba6306b4a444c90476182435820292a92a7b8f39ecb9fa283`.

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
