# Technical debt and TODOs

This file tracks known limitations of the GT-AX11000 overlay. A successful
compile is not sufficient evidence for releasing or flashing a candidate.

## Current router state and latest hardware-tested candidate

- As verified on **2026-09-09**, the live, permanently selected image is
  partition **1**, `BOOT_SET_PART1_IMAGE`, `3.0.0.6/102.9/alpha1`, from commit
  `dc4452af234` and hosted run `34243633067`. Image SHA-256:
  `46a16a7c1fa42d5aef1a02b41747556f4fab827eb525eae71af512a14778432f`.
  The verified `102.8/4` image on partition 2 remains the rollback image.
  See “Fixed during hardware promotion” below for final guard/boot evidence.
- The 2026-09-09 W9 and latency work does **not** flash another firmware.
  Rust `vpn-policy-audit` and `link-health` are separately tested diagnostics;
  they neither reboot the router nor change NVRAM/radio/firewall settings.
  Connection sampling and its panel are isolated on
  `codex/gt-ax11000-connection-diagnostics`; the firmware/security branch
  retains only the observation-only `router-vpn-audit` crate. This Git split
  neither uninstalls nor changes the already installed router add-on.

### Historical baseline: 2026-09-07 (superseded by the state above)

- The current hardware-tested and persistently selected image is on partition
  2: `BOOT_SET_PART2_IMAGE`, version `3.0.0.6/102.8/4`. The exact candidate is
  `GT-AX11000_3006_102.8_4_ubi.w`, SHA-256
  `01d7bde5aafd628265bb6075ff629c3e336fd14d6a7cbc934c49e6a12860e7ba`
  (74,711,060 bytes), built and tested from tmpfs on 2026-09-07. Partition 1
  remains unchanged as the known rollback image.
- The candidate first booted from partition 2 through
  `BOOT_SET_PART2_IMAGE_ONCE`, which correctly consumed to the partition-1
  fallback before promotion. Two complete router-health gates and a 15-minute
  soak passed: WAN, local DNS, all three radios, IPv4/IPv6 terminal drops,
  OpenVPN, malformed HTTP requests, all Rust runtime self-tests, and the PIDs
  of `httpd`, `dnsmasq`, `wanduck`, `infosvr`, `rstats`, `nt_monitor`,
  `networkmap`, `openvpn`, and all three `hostapd` instances stayed healthy.
  The fresh kernel log contained no fault, oops, panic, illegal instruction,
  or fatal signal.
- Proprietary `asd` is absent as both process and rootfs artifact on the live
  candidate. The Network Map cache exposed nine online clients with three
  wireless classifications, survived an explicit refresh with stable
  `networkmap` and `httpd` PIDs, and the three radios retained the atomic `ALL`
  profile (`#a`, 500 driver request) and WPA2/SAE, AES, and PMF settings. The
  known TV-box addresses `.37` and `.100` were not associated or present in
  the neighbor/cache tables during that trial, so that recorded gate did not
  exercise the device-specific path. The user subsequently confirmed the
  TV-box connectivity issue resolved; it is no longer an active blocker.
- The read-only live `infosvr` suite passed exact GETINFO, GETINFO_EX2 and
  FIND_CAP transactions and rejected invalid opcodes and 511/513-byte PDUs.
  Local gates additionally passed the immutable input lock, all Rust workspace
  tests, Clippy with warnings denied, ARMv7 cross-check, C ABI fixtures,
  750,000 deterministic fuzz iterations, six ARM/EABI5 consumer inspections,
  and three QEMU runtime paths.
- Before the current promotion, the known baseline was active and persistently
  selected on partition 1. It was retained unchanged while partition 2 was
  exercised as a one-shot slot and remains available for manual rollback.
- The 2026-09-07 baseline check found two signal-11 crashes from proprietary
  ASUS `asd` during the current boot. The GT-AX11000 overlay now sets `ASD=n`,
  and the final-rootfs gate rejects both `/usr/bin/asd` and `libasd.so`.
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
- On 2026-09-07 the overlay was re-locked from upstream
  `088512a1296e361d65e5429e7d8d61ef3fdf4c86` to
  `6be5bc84b50ea37be7b5d4307c5042771c3cf95b` (3006.102.9 alpha1: OpenSSL 3.5,
  OpenVPN 2.7.7, tzdata 2026c). Only `gt-ax11000-wsl.patch` needed
  regenerating (its `release/src/router/Makefile` and `libcap-ng/configure`
  hunks had drifted); the other 19 patches apply unchanged. `inputs.lock` now
  records `patched_diff_sha256`
  `0477c9575c580ff905b27261f4e53a25469289c9206d8c0543ae3d959891684e`, which two
  independent sparse `--no-cone` replays of the 20-patch series over the 76
  patched paths and the workflow's own `input_lock.py diff-hash` reproduced;
  `HEAD:release` still equals `6be5bc84b50:release`
  (`aa9d4e00acf0566f2f1ccb87a897e5264bf37dbb`). No firmware has been built or
  flashed from the new lock; every candidate and measurement above predates it.

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
- [x] Verify on hardware that the `ASD=n` image boots without new fatal-signal
  records and that removing `asd` does not regress ordinary router services.
- [x] Build from current upstream `088512a1296e361d65e5429e7d8d61ef3fdf4c86`,
  which includes miniupnpd 2.3.11 and its 2026 heap-overflow fix; no candidate
  from the older `d2701f4e238c` base may be promoted.
- [ ] One-shot-test a candidate from the re-locked upstream
  `6be5bc84b50ea37be7b5d4307c5042771c3cf95b` on hardware. The build half is
  done: hosted run 34234225299 (2026-09-08, push of `d701b63eb87`) passed
  every job (`Rust`, `Security overlay`, `Trial controller`, `Firmware`) and
  produced `GT-AX11000_3006_102.9_alpha1_ubi.w`
  (`e6de3eea7bb6df67352bc72d9cba5e3889c4b4785e7523f94a4bc3d6a9ddf04f`) from a
  clean vendor-cache miss in 2790 s with `ccache_status=enabled` and all seven
  Rust consumers hash-verified, so the OpenSSL 3.5 / `openssl11-compat` link
  order works under the serial `make_jobs=1` contract and the post-build
  gates. Still open: OpenVPN 2.7.7 runtime parsing of the hardened directive
  set, the parallel DAG ordering of `openssl11-compat` (not exercised, the CI
  contract is serial), and the hardware one-shot itself; no candidate from
  the new lock has been flashed.

## Security debt

### 2026-09-09 CI and branch isolation

- [x] Keep W9's read-only VPN audit on the security branch as
  `router-vpn-audit`; move the connection collector/UI/install scripts and
  browser tests to `codex/gt-ax11000-connection-diagnostics`. No history rewrite
  or router mutation is needed.
- [x] Stop duplicate expensive firmware jobs on development pushes. Pushes
  retain Rust/security/trial checks; PR merge results, `main`, manual dispatch
  and schedule retain full firmware gates and exact cache attestation.
  The skipped push job has a distinct check name and cannot satisfy the
  required `Firmware` status while a PR merge build is still pending.
  The fifteen-case Node policy/sync test and actionlint 1.7.12 pass locally.
- [x] Fix the observed daily sync failure in run `34323809832`:
  `gh repo clone` already creates `upstream` for forks, so use idempotent
  set-url/add pinned to the lock. Make overlay/patch paths absolute for the
  later `git -C` replay. Regression tests execute the real shell for absent,
  pre-existing and repeated remotes without network access. This fix reaches
  scheduled runs only after the reviewed workflow is merged into `main`.
- [x] Local split gate: 164 Rust tests, fmt, Clippy with warnings denied,
  ARMv7 cross-check, 8 input-lock tests, 23 trial tests, unchanged patched diff
  `dad85e447...9f168`, security/network/relink checks and both C capture harness
  variants pass. Hosted firmware completion for the new tip is tracked
  separately; these checks are not a deployment claim.

### 2026-09-09 W9 hardening follow-up (not yet flashed)

- [x] Fix the architecture-specific file-open flags: ARM EABI `O_NOFOLLOW`
  is `0100000`, not the host x86-64 `0400000`. Share target-selected constants
  between `router-vpn-audit` and `router-security`; include `O_NONBLOCK` before
  rejecting special files. Host, QEMU and native-router C ABI fixtures verify
  symlink/FIFO rejection. Add the ARM execution gate to hosted CI.
- [x] Protect the firewall capture **write and read** transaction with a
  private 0700 directory. Rust's read-side symlink check alone cannot secure
  the earlier C `_eval` redirection to a predictable public `/tmp` path.
  `private-firewall-capture.patch` is appended to the canonical patch series;
  upstream stays pinned to `6be5bc84b50`, new patched diff lock:
  `dad85e447250b612dae51176a1e74fb726673d459a0a7281939b78cb0959f168`.
  Both IPv6 compile variants and failure cleanup paths pass the C harness.
- [ ] Build/validate/deploy a new full firmware containing those fixes to
  `rc`. Live firmware remains the previously promoted `102.9 alpha1`; native
  ABI testing is not a firmware replacement. No restart was done during the
  call-drop investigation.

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
- [x] Implement bounded, fail-closed per-profile OpenVPN/WireGuard inbound-rule
  and policy-route kill-switch inspection in Rust, expose it through an
  additive C ABI, and cover the vendor-derived shapes plus adversarial decoys
  with unit, integration and C-ABI fixtures.
- [x] W9 follow-up: derive complete, typed runtime profile requirements and
  require **all** enabled Director sources, not one arbitrary prohibit rule
  per profile. Bind early routing exceptions to configured selectors; reject
  unsupported enforce/destination-only cases. Include inactive/empty/manual
  tunnel cases and all five WireGuard unit slots in regression tests.
  `vpn-policy-audit --check-live` now exercises this on native router ARM code
  and rechecks configuration/rules for concurrent changes. The actual router
  had zero active VPN-client requirements: that pass is explicitly not an
  active VPN leak-protection test.
- [ ] W9 remains open for **live enforcement**: capture active OpenVPN and
  WireGuard hardware fixtures for each relevant mode, validate server-peer
  exceptions and VPN table content, resolve IPv6 kill-switch semantics, and
  design scoped failure/recovery before changing the running firewall call
  site. The new audit is observation-only and does not disable forwarding.
  The old additive C ABI remains compatible and unchanged.
- [x] Move imported OpenVPN custom-directive validation from ad-hoc C into a
  bounded Rust allowlist. Weak ciphers/digests, compression, scripts, routes,
  pull filters, unknown directives and malformed numeric values fail closed.
- [ ] Verify the emergency firewall failure path on hardware: forwarding must
  stay disabled, WAN INPUT must be dropped for IPv4 and IPv6, and custom
  `firewall-start` scripts must not run after a failed ruleset apply.
- [x] Add a build-time security-overlay gate covering authenticated routing,
  country-only mutation, raw calibration-key denial, firewall ordering,
  OpenVPN imports, IPsec cleanup, WireGuard and WPS argv execution.
  - 2026-09-07: the firewall ordering check now fails on a missing
    `custom`/`guard`/`validate`/`enable_ip_forward` anchor instead of comparing
    empty line numbers. Verified against the patched replay tree at
    `6be5bc84b50` (`security overlay invariants verified`, exit 0).
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
  - Audit SEC-6a (2026-09-07, source scan at `6be5bc84b50`, no build or
    hardware run): `shared/wlif_utils_ax.c` has 25 `system`/`popen` sites with
    non-literal command strings. 17 sit in `wl_wlif_apply_creds_to_supplicant`,
    which interpolates the `<ifname>_ssid`, `<ifname>_wpa_psk` and DPP
    connector/C-sign NVRAM values into `wpa_cli ... set_network` shell lines and
    prints every complete command through `dprintf`; that function is guarded
    by `WIFI7_SDK_20250506 || WIFI8_SDK_20251126` and is therefore not compiled
    for the HND-94908 GT-AX11000 profile. The remaining eight are
    `get_wpacli_status` (`popen`), `wl_wlif_update_hapd_bh_creds`,
    `wl_wlif_parse_hapd_config` and the WPS PBC/stop handlers under
    `CONFIG_HOSTAPD`, `wl_wlif_wpa_supplicant_update_ap_scan` and
    `wl_wlif_select_bhsta_from_bsslist` under `MULTIAP`, and one WiFi 7 MLO site
    that is compiled out. Whether `CONFIG_HOSTAPD` and `MULTIAP` are active
    for this profile was not established, so the item stays open.
- [ ] Re-audit every remaining `system`, `popen`, shell-script generation, and
  NVRAM-to-command path. Prefer fixed argv execution and typed Rust parsers.
  - Audit SEC-6a inventory (2026-09-07, `rc`, `shared`, `httpd`, `libdisk`,
    `libwebapi`, `rstats` and `infosvr` sources at `6be5bc84b50`): 2,080
    `system`/`doSystem`/`popen` call-site lines, 653 of them passing
    non-literal command strings. Concentrations by file and enclosing function:
    `rc/sysdeps/init-broadcom.c` 111 (`set_wan_tag` 44, `init_switch_pre` 44,
    `vlan_forwarding` 10; switch/VLAN setup from NVRAM), `rc/services.c` 39
    (`radiusd_updateDB`, `start_spcmd`, `start_wps`, `start_amas_lldpd`),
    `shared/aura_rgb.c` 37, `rc/ate.c` 27, `shared/wlif_utils_ax.c` 25 (above),
    `rc/watchdog.c` 24, `httpd/web.c` 24 (`ej_netdev`, `sys_script`,
    `ej_dump`, `apply_cgi`, `do_upgrade_cgi`, `get_ipsec_conn_info`, ...),
    `rc/rc_ipsec.c`, `rc/rc.c`, `rc/firewall_sdn.c` and `rc/ai_service.c` 17
    each, `rc/wan.c` and `rc/sysdeps/wps-broadcom.c` 15 each. The existing
    overlay patches replace only the `wps-broadcom.c` (`stop_wps_method`,
    `start_wps_enr`, `hapd_cli_run`) and `services.c` `start_wps` paths and add
    `validate_wlan_security_request` in `web.c`. The scan does not decide which
    sites are compiled for this profile or reachable from the authenticated
    Web boundary; that classification is the remaining work.
- [ ] Review proprietary prebuilt objects/libraries borrowed from other ASUS
  models. A successful ARM link does not prove runtime ABI compatibility.
  - Audit SEC-7a (2026-09-07, tree at `6be5bc84b50`): 41 packages ship a
    `prebuild/GT-AX11000/` directory out of 49 with per-model prebuilt trees;
    the router Makefile copies the `httpd`, `rc` and `shared` sets by
    `BUILD_NAME`. Exactly four objects are borrowed from other models, and all
    four are wired by the overlay's own `gt-ax11000-wsl.patch`:
    `httpd/prebuild/GT-AXE11000/web-broadcom.o` (added unconditionally to the
    `httpd` objects), `rc/prebuild/RT-BE86U/tpvpn.o` (fallback under
    `RTCONFIG_TPVPN=y`, which `config_base` enables),
    `shared/prebuild/RT-BE86U/uu_utils.o` and
    `nmp-api/networkmap/prebuild/RT-BE86U/libnmpapi.so` (fallbacks when no
    GT-AX11000 copy exists). The audit's extracted copies match the vendor
    blobs by SHA-256. No symbol-level or struct-layout comparison against the
    GT-AX11000 headers was recorded; the only runtime evidence remains the
    hardware trials above, so the item stays open.

## Wireless test-lab debt

- [x] Fix connection-panel timeout/authentication confusion and add finite,
  read-only Rust Wi-Fi correlation on the diagnostics branch. The native
  600-round test exited automatically; no WLAN restart or NVRAM changes.
  The moving **MacBook** (previously misidentified as a tablet) lost 44/144
  local probes; a captured weak-signal slice stayed on 5 GHz-1 at reported
  -87 dBm with 23 reverse-probe misses. See
  `.github/ci/gt-ax11000/diagnostics/WIFI_STEERING_REVIEW.md` for original-source
  comparison, blob hashes, synthetic-test limitations and release gates.
- [ ] Repair steering under ALL without reintroducing historical bsd/roamast
  crashes. The quarantine demonstrably suppresses configured Smart Connect;
  the 2026-09-09 approved native test now **reproduced the real bsd crash**:
  legacy bsd/roamast pass `(idx, buffer, size)`, but current libshared expects
  `(idx, vidx, buffer, size)` and writes through 0x1000. A corrected fixture
  reproduces it; the process-scoped ABI adapter survived a native 30-second
  trial and stopped cleanly. The model-limited source candidate is in
  `diagnostics/compat/gt-ax11000-maclist-abi.patch`, not the firmware series.
  Full rebuild, native roamast validation, active movement test and soak remain.
  Do not remove quarantine on the strength of this short startup test alone.
- [ ] Harden `retrieve_static_maclist_from_nvram` independently of the ABI fix:
  current C append loops do not enforce capacity and memset uses sizeof(int)
  rather than the passed buffer size. Preserve allow/deny/AiMesh semantics;
  do not silently turn parse/overflow errors into an empty permissive ACL.
- [ ] Retain a bounded whole Wi-Fi experiment in private RAM; the current
  panel ring contains only the last 60 rounds. Distinguish failed pidof
  capture from confirmed process absence before using service status as a gate.

- [x] Retire the unmerged `codex/gt-ax11000-testlab-ui` branch at `e8ba9d2832e`.
  No code salvage: per-radio controls, the ALL restriction and the temporary
  IPv6 chain conflict with the current country-only policy. Exact contents
  remain recoverable through `archive/gt-ax11000-testlab-ui-20260909`.
  See `.github/ci/gt-ax11000/TESTLAB_BRANCH_REVIEW.md` for the comparison,
  rollback weaknesses and recovery commands; CI rejects accidental re-entry.

- [x] Isolate the connection sampler, panel, installer, browser tests and
  call-drop investigation on `codex/gt-ax11000-connection-diagnostics`.
  Its `diagnostics/README.md` retains the 2026-09-09 native pilot evidence,
  footprint and installation/rollback instructions. Keep future diagnosis
  changes out of the firmware/security PR. No router operation is part of
  this branch split.

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
- [x] Add byte-level wire fixtures for the Rust `infosvr` port, including the
  AiMesh group-ID TLV and `GETINFO_EX2`. `rust/infosvr/tests/wire_fixtures.rs`
  holds 27 const-built fixtures whose offsets were re-derived from the
  `#pragma pack(1)` structs in `shared/iboxcom.h` and from `infosvr/common.c`,
  `storage.c`, `packet.c` and `infosvr.c` at `6be5bc84b50`: GETINFO,
  `GETINFO_EX2` (transaction ID plus `<fstype>:<free MiB>!$`), FIND_CAP with
  the group ID present, truncated and absent, and rejected opcodes and
  511/513-byte PDUs. NVRAM parsing became stricter on the way: `parse_mac`
  rejects `+0`-style octets and `decode_group_id` requires 40 hex digits.
  Verified locally on 2026-09-07 with `cargo +1.85.1 test --workspace
  --locked` (138 passed), Clippy with warnings denied and the ARMv7 check.
- [ ] Add router captures for `infosvr`. Only the read-only `infosvr-live.py`
  transactions have been exercised on hardware; no packet capture backs the
  fixtures, and the port's `ui_sw_mode` and WebDAV `HostName` handling differ
  from `shared.h`/`storage.c` in cases the fixtures do not cover.
- [x] Gate the `rstats` ISP-meter behavior with the model build configuration;
  GT-AX11000 does not enable the legacy ISP-meter feature.
- [x] Expand fuzz/property tests for HTTP query and multipart parsing, NVRAM
  apply validation, VPN profile parsing, and the WAN state machine.
- [ ] Measure memory, CPU, startup time, and crash/restart behavior of all five
  Rust ports on the router.

### Rust library ports (zlib-rs first, then client list, httparse, rustls-ffi)

- [x] Build `wget` against a static zlib-rs archive as the isolated first zlib
  consumer. `rust/zlib-static` packages `libz-rs-sys 0.6.7` (`std`,
  `c-allocator`, `export-symbols`, `gz`; no `gzprintf`) as `libzlib_static.a`;
  `zlib-rs-wget.patch` replaces wget's `ZLIB_LIBS="-L$(TOP)/zlib -lz"` with the
  archive plus `-lpthread -ldl -lm`, keeps the vendor `zlib` package for its
  headers and for every other consumer, and forces a wget relink when the
  archive is newer. Dependencies are vendored (`rust/vendor`, 6.7 MiB) with
  the crates.io mapping in `rust/.cargo/config.toml` and, for the package
  Makefiles, `release/src/router/.cargo/config.toml`. Verified on 2026-09-09:
  host and armv7 archives build with `--locked --offline`; a C11 fixture and
  `tests/c_abi_roundtrip.rs` run wget's exact call pattern (byte-wise
  streaming `inflate`, `gzdopen("wb9")`, invalid descriptor rejected); a
  cross-linked test program with the Broadcom gcc 5.5 toolchain has no
  `libz.so` dependency and reports `1.3.0-zlib-rs-0.6.7`; the full patch
  series replays on `6be5bc84b50` and re-locks to
  `6b4d567a3ffac0fd574e537abee1c30a3677be044029dbc111a363c9a133426a`. No
  firmware build, hosted run or hardware test has exercised the new wget yet.
- [ ] Prove the zlib-rs wget on a hosted build and on hardware: the firmware
  verifier now requires `usr/sbin/wget` without a `libz.so` dependency, with
  the `1.3.0-zlib-rs-` marker and a clean `wget --version` under QEMU; still
  owed are a gzip-encoded HTTP download and a `--warc-file` write on the
  router, and the image-size delta of the static archive.
- [ ] Replace `libz.so.1` for the remaining direct zlib users. The local 102.8
  reference rootfs has seven direct zlib symbol users (wget, Tor and the media
  libraries among them); OpenVPN links `libz` but imports no zlib function, so
  it gains nothing from the swap. A drop-in library must carry the `libz.so.1`
  SONAME, the `ZLIB_1.2.0`..`ZLIB_1.2.3.5` symbol versions from the vendor
  `zlib.map`, and the internal symbols that map exports but zlib-rs lacks
  (`deflate_copyright`, `inflate_copyright`, `inflate_fast`, `inflate_table`,
  `z_errmsg`, `zcalloc`, `zcfree`, `gz_error`, `gz_intmax`, `gzvprintf`);
  `crc32_combine_gen*`/`crc32_combine_op` are exported by zlib-rs but were not
  visible in the host archive and need a link check. `libbz2` is deferred: no
  dynamic user was found in the examined rootfs.
- [x] Port the selected client-list read/render paths to Rust (size- and layout-checked
  shared-memory snapshot, own data model, bounded JSON string; no
  `json_object*` across the boundary; `serde_json` for parsing and output).
  `rust/clientlist` decodes the legacy 174,964-byte GT-AX11000 layout only
  for `productid` `GT-AX11000` and the public 173,436-byte layout only at
  exactly that size (anything else fails closed), takes the vendor
  `file_lock("networkmap")`, attaches the existing segment read-only without
  the `IPC_CREAT` size race, copies it, reads every string inside its field
  width, clamps the count to 0..=255 and renders the live list, the
  `/tmp/nmp_cache.js` read/write, the name-for-IP lookup, the SDN count,
  the persistent-database view, the basic/all-basic lists and the name
  search; `clientlist-rust.patch` replaces the nine json-c readers in
  `web.c` with bounded-buffer calls into the single httpd Rust archive.
  Evidence on 2026-09-09, host only: 42 unit tests, 8 golden documents
  derived by hand from `web.c`, a SysV-segment FFI test, the C11 fixture
  `tests/c-abi/clientlist.c` against a real segment, the fuzz smoke with the
  new parsers, Clippy with warnings denied, the ARMv7 check, an armv7
  `libhttpd_parsers.a` linked into the fixture with the Broadcom gcc 5.5
  toolchain (link only), a full 23-patch replay re-locked to
  `965f35b2733c928f362bea650b83c06e79e9c257e79e41c08fbea60b3ac69b71` and the
  three overlay checks. No firmware build, hosted run or hardware test has
  exercised the Rust client list yet.
- [ ] Prove the Rust client list on a hosted build and on hardware: `httpd`
  must compile and link the changed `web.c` against the archive, the legacy
  and dashboard client pages must render a non-empty `maclist`, the cache
  and database views, `get_client_name()` in the login-lock and port-forward
  reports and the `INTERNETCTRL` report state must be exercised, and the
  per-request 1 MiB buffer and the copy of the 175 KiB segment need a
  memory/CPU measurement under a full 255-client table.
- [ ] Remaining client-list C: `ej_get_clientlist_reportstate` keeps its
  json-c shape and parses the Rust text locally; `search_device_name_in_
  clientlist` fills the caller's json-c array; `get_amas_info`/`is_re_node`
  (cfg_mnt shared memory) stay in C and reach Rust as a text list and a
  callback; `do_del_client_data_cgi`/`deleteOfflineClient` still edit
  `/jffs/nmp_cl_json.js` with json-c and write `delete_mac` through the C
  trailer helper; `miniupnpc/upnpc.c` (`RTCONFIG_JFFS2USERICON`, not built)
  still reads the public layout. Documented deltas: compact JSON instead of
  json-c's spaced output, `/` unescaped, the non-AiMesh build variant
  (`FLAG_EXIST` filter), the VLAN/captive-portal segments and the
  `RTCONFIG_DISABLE_NETWORKMAP` gate are not modelled because the GT-AX11000
  profile does not compile them.
- [ ] Then `httparse` for the HTTP request line/header boundary and
  `rustls-ffi` for HTTPS; the latter needs a crypto-backend decision (the
  default is `aws-lc-rs`) and ARM build, ABI and consumer tests before use.

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
  `get_clientlist_from_json_database()`. Superseded on 2026-09-09: that
  handler, the borrowed-object `json_object_put` in
  `get_client_detail_info` and the array/name ownership defects in
  `ej_get_all_basic_clientlist`/`get_basic_clientlist_info` are gone with
  the Rust client list (`clientlist-rust.patch`).
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
- [x] Decode the exact 174,964-byte legacy GT-AX11000 Network Map ABI only when
  both model and segment size match. The compatibility view restores the real
  online, radio, type, rate, RSSI and timing offsets while newer/public layouts
  continue through their normal structure; a compile-time size assertion and
  security-overlay checks prevent silent drift. Since 2026-09-09 the reader
  is `rust/clientlist/src/layout.rs` (const-asserted sizes and offsets of
  both layouts, strict selection, fail-closed otherwise) and the overlay
  checks assert on the Rust source; only the `delete_mac` trailer helper
  remains in `web.c`.
- [x] Hardware-check that the legacy client page receives a non-empty
  `maclist`, preserves wired/wireless classification and does not restart
  `httpd` or `networkmap` during repeated refreshes.
- [x] Confirm the replacement image's complete live Network Map backend on
  GT-AX11000 hardware: the Rust ABI provider exports only the three gated
  compatibility symbols, `networkmap` survives a rescan, shared memory reports
  10 live clients, and the persistent database retains 105 historical records.
- [ ] Repeat the authenticated browser rendering check on the promoted
  `102.9 alpha1` image. Its live backend is healthy (14 current JSON objects,
  106 persistent objects, a stable `networkmap` PID, and the expected
  `update_clients.asp`/render hooks), but the Windows Computer-Use bridge could
  not attach from the WSL-bound promotion task. No empty-backend condition was
  reproduced.
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
  Rust Network Map port. The httpd side of the Network Map (every client-list
  reader of the shared-memory table and of `/jffs/nmp_cl_json.js`) is Rust
  since 2026-09-09; the producer daemon itself is still the vendor binary.

## Build and CI debt

- [x] Replace moving upstream/toolchain inputs with exact commits in
  `inputs.lock`; validate its schema, the complete ordered patch set and the
  actual binary source-diff hash before a release build.
- [x] Make the scheduled upstream sync create/update a draft
  `upstream-sync/<sha>` pull request instead of merging `main`, and run separate
  required `Rust`, `Security overlay` and `Firmware` checks for vendor,
  overlay, workflow and lock changes.
  - 2026-09-07: a conflicting merge now aborts, creates or updates one
    `upstream-sync conflict <sha>` issue listing the conflicting paths and
    fails the run; an upstream already contained in `main` only refreshes a
    stale lock; an unchanged lock exits without a PR. The push uses
    `SYNC_UPSTREAM_TOKEN` when provisioned, because PRs opened with
    `GITHUB_TOKEN` receive no checks; the PR body states which case applies.
    Verified by YAML parse, `bash -n` and a local git replay with a stub `gh`;
    no Actions run and no token has been provisioned yet.
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
- [x] Auto-disable local ccache before source preparation when no executable is
  available. `build.sh` probes `command -v ccache` right after validating
  `ASUSWRT_CCACHE`, before the GNU Make bootstrap, the tmpfs checks and the
  worktree/source adaptation; a missing executable warns, sets
  `CCACHE_ENABLED=0`, records
  `ccache_status=auto-disabled-missing-executable` next to `ccache_enabled` in
  `BUILD-STATE.txt`, and both values pass through to the inner build shell.
  `ASUSWRT_CCACHE_STATUS` is internal: only the worktree re-exec may carry the
  auto-disable reason, and a stray `enabled` can never be reported while
  `ASUSWRT_CCACHE=0`. CI compares the recorded status with the `ccache=1`
  build contract right after the build and fails closed on a mismatch.
  Nothing is written to the cache in that case. The alternative of a
  checksummed RAM-local ccache binary was not pursued.
  Verified on 2026-09-08 by running the extracted block for the cases
  (`ccache=1` without an executable, `ccache=0`, stray status, inner
  passthrough, fake `ccache` on `PATH`) plus `bash -n`; no firmware build.
- [x] Keep top-level orchestration at `-j1` and provide an opt-in GNU Make 4.4
  package DAG with one shared jobserver, an explicit serial foundation and a
  transitive `.WAIT` barrier. A 16-token build completed with a reference-
  equivalent rootfs, but was 5.4% slower overall, so the default remains one.
- [x] Add phase-local timing around kernel, package foundation, parallel package
  remainder and image assembly. `BUILD-STATE.txt` now records
  `vendor_prebuild_seconds`, `kernel_build_seconds`, `kernel_modules_seconds`,
  `router_foundation_seconds`, `router_packages_seconds`,
  `image_assembly_seconds`, `rust_relink_seconds` and
  `firmware_repack_seconds`. The first six are inferred after the fact from
  artifact timestamps (`.pre_kernelbuild`, `vmlinux`, the newest installed
  `.ko`, the newest serial-foundation library, the runtime libraries that
  `make -C router reinstall` copies into `fs.install/lib` after the last
  package install, and the firmware image) relative to the build-start marker;
  the last two come from the inner build log. The vendor `image` link is not a
  boundary: it is recreated before `make buildimage`, which contains the
  kernel, package and image phases. Known folds: host tools/DTBs/CFE into
  `kernel_modules`, `clean-build`/`kernel_header` into `router_foundation`,
  package installs/`rootprep` into `router_packages`,
  `libcreduction`/`strips`/`buildFS`/manifests into `image_assembly`; a
  kernel-cache hit or `rust-fast` reports 0 for the skipped phases. Verified
  on 2026-09-08 with a synthetic-tree harness and `bash -n`, then observed on
  hosted run 34234225299 (clean, serial): `vendor_prebuild` 656 s,
  `kernel_build` 47 s, `kernel_modules` 34 s, `router_foundation` 1589 s,
  `router_packages` 55 s, `image_assembly` 120 s, `firmware_repack` 138 s of
  `vendor_build` 2660 s. The foundation/packages split is not credible on a
  serial clean build: a foundation product is evidently re-touched late in
  the package phase, so nearly the whole router build lands in
  `router_foundation`. Treat the two fields as one until the boundary is
  re-derived from a real build log (see the next item).
- [ ] Benchmark only a small `2/4/8` token sweep with the new phase fields. Do
  not spend full builds testing every package combination. The
  `PARALLEL_BUILD_BASELINE.md` numbers were measured at
  `088512a1296e361d65e5429e7d8d61ef3fdf4c86`; no A/B run exists at the new lock.
- [x] Give every parallel `sha256sum` batch of the rootfs equivalence manifest
  its own output file before the final sort, so writes above `PIPE_BUF` can no
  longer interleave in one shared stdout. The interleaving did not reproduce
  in three runs of the old script on the local host; the fix rests on the
  documented pipe semantics and repeated deterministic output of the new one.
- [x] Derive the expected AUTODICT dictionary set from the payload's own
  `www/Lang_Hdr.txt` (`LANG_<code>=` lines minus `LANG_select*`) instead of a
  hardcoded count of 25, compare names and count exactly, and make the sentinel
  lookups fail closed inside command substitution. Verified against fixtures
  and the vendor `LnxDictPrep`, which appends to an existing `Lang_Hdr.txt`;
  CI builds from a fresh install directory, so the exact-set check holds there.
- [x] Compute every cache key component (`overlay_sha`, `vendor_state_sha`,
  `build_contract_sha`) before the first cache restore, bind the `rust-fast`
  same-Rust equivalence gate to the seven manifested consumers (`infosvr`,
  `rstats`, `Notify_Event2NC`, `httpd`, `rc`, `networkmap`, `libbwdpi.so`)
  while a changed Rust state may alter only the five relinked binaries
  (`networkmap` and `libbwdpi.so` are not rebuilt by `rust-fast`, so the
  freshness gate and the rootfs exclusions cover just those five), give the
  firmware job its own Rust cache key, pin `upload-artifact` to v4.6.2 and skip
  the upload on a cancelled run. Verified on 2026-09-07 by YAML parse and
  review only; `actionlint` is unavailable and no Actions run has executed the
  changed workflow.
- [x] Implement closure of the `bwdpi-compat`/wget staleness gap on the vendor-cache-hit path. An
  exact vendor cache hit selects `rust-fast`, which relinks only the five
  consumers and never runs `networkmap-install`, while the vendor cache key
  excludes `rust/`. A change confined to `rust/bwdpi-compat` therefore ships
  the cached `libbwdpi.so` and CI stays green (the rootfs equivalence gate
  sees it unchanged because nothing rebuilt it). Pre-existing before the
  2026-09-08 consumer split, which only documents it. Either hash
  `rust/bwdpi-compat` separately in "Snapshot cached relink state" and fail
  closed, or make `rust-fast` also run `networkmap-rust-compat-rebuild` and
  treat all seven consumers as relinked. Since 2026-09-09 the same gap covers
  `wget`, the eighth manifested consumer: a change confined to
  `rust/zlib-static` was carried from the cached tree by `rust-fast`.
  Integration now invokes `networkmap-install`, `wget` and `wget-install`,
  promotes their exact staging payloads and applies freshness/equivalence
  gates to all eight consumers. Host syntax/fixture checks pass; an actual
  hosted cache-hit run must still confirm the end-to-end path.
- [x] Let Dependabot propose weekly pinned-SHA bumps for GitHub Actions and
  lockfile-only Cargo bumps for `rust/`; each lands as a normal PR through the
  same checks. Since 2026-09-09 the workspace carries its crates.io
  dependencies vendored under `rust/vendor` with the mapping in
  `rust/.cargo/config.toml`, so the `--offline` firmware build needs no fetch
  step; a lockfile-only Dependabot bump must regenerate `rust/vendor`, and the
  `Rust` job's `cargo vendor` comparison fails closed until it does.
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
- [x] Run the trial controller's fake-transport unit tests as a separate
  `Trial controller` job in Actions on the exact overlay commit. It never
  contacts a router and is deliberately not a firmware gate. The exact job
  invocation passed locally on 2026-09-07 (22 tests) and on GitHub run
  `34243633067` for commit `dc4452af234`.
- [x] Bind the persistent hardware guard to the promoted image identity
  (`3.0.0.6/102.9/alpha1`) and its immutable Web manifest hashes. A new
  read-only `check` action runs the same complete health predicate without
  changing boot state; a source test rejects future boot-state or state-file
  mutation in that action.

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
- On 2026-09-08, GitHub-hosted run `34243633067` was fully green and produced
  the exact commit-`dc4452af234` GT-AX11000 image with SHA-256
  `46a16a7c1fa42d5aef1a02b41747556f4fab827eb525eae71af512a14778432f`.
  The router booted it on partition 1 as `3.0.0.6/102.9/alpha1`; repeated
  hardware gates passed Rust self-tests, WAN/DNS, all radios, Web malformed-
  request survival, IPv4/IPv6 terminal drops, kernel-fault scanning, daemon
  PID stability and the live `infosvr` protocol fixtures. The seven installed
  Rust-consumer hashes exactly matched the artifact manifest.
- The final persistence reboot exercised the complete guard state machine:
  `arm` selected the untouched `102.8/4` partition 2 for one fallback boot,
  the delayed health gate passed, and `promote` restored partition 1 as the
  permanent boot target. Partition 2 remains available as the known-good
  rollback image.

## 2026-09-09 combined Rust/client-list/Wi-Fi integration

- Preserved Claude's interrupted client-list WIP in a checkpoint; reviewed
  the zlib-rs/wget commits and merged the connection-diagnostics branch into
  `codex/gt-ax11000-rust-wifi-integration`. Neither source worktree was reset.
- Corrected GT-AX11000's `retrieve_static_maclist_from_nvram` to the three-
  argument ABI actually used by the unchanged vendor `bsd` and `roamast`
  objects. Only the `bsd` ALL-profile quarantine is removed. `roamast`
  remains quarantined pending its own native trial; country/power/radio
  settings remain untouched. The native adapter probe succeeded earlier,
  but it is not shipped; the new libshared must pass the vendor-daemon QEMU
  regression without an adapter and a subsequent hardware soak.
- Client-list hardening added during review: 100 ms bounded record-lock
  acquisition, persistent bounded lock descriptors that preserve nested C
  lock ownership, no-follow/nonblocking regular-file cache reads, exclusive
  atomic cache writes, depth/width/input/output JSON bounds, and inline-HTML
  `<`, `>` and `&` escaping. No claim that remaining C writers or json-c
  consumers have been replaced. Known model-variant limitations above remain.
- Gates passed: complete Rust host tests and warnings-as-errors Clippy;
  C-to-Rust fixtures on host AND ARM under QEMU, including live SysV memory,
  contended record-lock deadline, FIFO/symlink cache rejection and zlib;
  750,000 deterministic fuzz-smoke iterations across three seeds; Node panel/
  CI fixtures; input-lock tests; 31 trial/deployment utility tests. Vendored
  crates compare byte-for-byte to a fresh locked crates.io vendor operation.
  These fuzz-smoke runs are not coverage-guided fuzzing or a hardware proof.
- Combined 24-patch replay on `6be5bc84b50` gives patched-diff SHA-256
  `5c02e6b4f5d849f680b95c530015ff3b59bb833b75676b64c333c513ffa7354a`.
  Security/network overlays and the private firewall capture fixtures pass.
- Full clean build is in progress in tmpfs, swap disabled. The first attempt
  stopped at a local ccache host `libhiredis` dependency: the vendor Makefile
  overwrites LD_LIBRARY_PATH. Added that existing host library to the RAM-only
  toolchain view; no firmware/source/security gate was weakened. A fresh
  locked-source retry is running. Firmware/native verification is PENDING.
- The firmware verifier now includes actual ARM wget gzip HTTP and gzip WARC
  consumers with independent Python gzip generation/verification, rather
  than assuming stripped static function names survive in the image.
- Before any flash, a fresh encrypted settings/JFFS/data backup was copied
  off-router to persistent private storage and independently decrypted/
  verified: 4,552 settings, 18 essential comparisons, 329 JFFS/26 data members.
  This is not a factory-reset hardware restore test. The deployment guard
  renderer binds explicit candidate/fallback roles and exact candidate binary
  hashes; tests prove baseline never re-arms candidate, hold prevents promotion
  and failed health selects fallback in both slot orientations. Not deployed
  yet; partition 1 remains the current known-good baseline.
