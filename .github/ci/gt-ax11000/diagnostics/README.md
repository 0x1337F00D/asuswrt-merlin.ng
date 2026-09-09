# Lightweight connection diagnostics and W9 audit

Development branch: `codex/gt-ax11000-connection-diagnostics`. The security/CI
branch contains neither the collector nor the panel/installer. The dependency
is one-way: this optional collector reuses `router-vpn-audit` helpers, while
the W9 audit remains independently buildable and tested on the security branch.
The dedicated **Connection diagnostics** push workflow tests this add-on only;
it does not start a firmware build, contact the router or install anything.

Still open: correlate a real POCO F3/Samsung tablet call interruption, confirm
authenticated rendering on the user's device, and consider opt-in Wi-Fi/DNS
correlation and longer bounded RAM retention. Weak-signal roaming is a
hypothesis, not proof of a driver or WAN fault; do not auto-restart networking.

This is a separately installable, locally tested add-on, **not a new firmware
image**. It leaves the upstream source, NVRAM, radio settings, routes, firewall,
existing network daemons and boot-partition selection unchanged.

## Panel and footprint

Open `/ext/link-health/index.asp` after normal router login. The existing httpd
handles `**.asp*` and `**.json` with `do_auth`; there is no extra web listener.
The add-on's static JS contains no credentials/telemetry. No measurement calls
go from the browser to an external host. Keep the page in the foreground on
the affected Wi-Fi device to collect the browser-to-router timing leg.

The Rust collector sends **one 16-byte-payload ICMP probe per target per second**
to the WAN gateway, `1.1.1.1` and `8.8.8.8`, explicitly bound to `wan0_ifname`.
These diagnostic probes bypass a default VPN path; they contain no user traffic
but the destinations see the WAN public IP. Each probe is a fixed-argv BusyBox
command with a hard deadline, bounded output, and child reaping. No raw-socket
FFI, shell command interpolation, DNS traffic, telemetry service or Rust
third-party crate is added.

Maximum history: 600 rounds, kept in process memory. A small snapshot is
atomically replaced under `/tmp/var/wwwext/link-health/status.json`; only the
last 30 anomalous points are exposed. Writes during measurement are RAM-only.
Sampler delays and command/parser failures are **unknown**, not packet loss.
Browser background/suspend gaps are also not labeled network outages. The UI
checks advancing sequence numbers so an old snapshot cannot remain “live”.

RTT variation means mean absolute differences between consecutive successful
ping RTTs, not RTP jitter. ICMP loss can reflect rate limiting/filtering, not
an actual Internet outage. DNS, VPN payload traffic, application servers and
sub-second loss between probes remain outside coverage. A browser HTTP delay
also includes browser scheduling and httpd work, not just Wi-Fi latency.

## Build and control

Use the locked vendor ARMv7 soft-float 5.3/glibc 2.22 toolchain. All generated
outputs, Cargo targets and TMPDIR must reside on tmpfs:

```sh
export DIAGNOSTICS_LINKER=/path/to/locked/toolchain/usr/bin/arm-buildroot-linux-gnueabi-gcc
export DIAGNOSTICS_STRIP=/path/to/locked/toolchain/usr/bin/arm-buildroot-linux-gnueabi-strip
export DIAGNOSTICS_OUTPUT=/tmp/fresh-diagnostic-package
export CARGO_TARGET_DIR=/tmp/asuswrt-diagnostics-target
bash .github/ci/gt-ax11000/diagnostics/build.sh
```

Transfer that exact package through authenticated SSH and verify its hashes
with the router's `openssl dgst -sha256` (stock BusyBox has no `sha256sum`).
`control.sh start|stop|status|audit` supports a RAM pilot without installation.
Stopping uses a cooperative RAM marker, never `killall` or a network restart.
An unexpected stale lock is intentionally not deleted without inspecting its
owner. History disappears on reboot or collector restart.

Optional first persistent installation uses `install.sh` with the previously
inspected `EXPECTED_SERVICES_SHA256`. It refuses existing add-on/symlink targets,
checks every package file, backs up `services-start` privately, and adds one
background startup line using a compare-before-replace check. It does not
reboot. There is no automatic firmware flash or WAN/firewall failover.

To stop measurement, run `/jffs/addons/link-health/control.sh stop`. To disable
startup permanently, remove just the line ending `# link-health-bootstrap`
from `/jffs/scripts/services-start`, preserving all other edits. The original
hook is `/jffs/addons/link-health/services-start.before`; do not restore the
whole backup over newer unrelated modifications.

## W9 boundary

`vpn-policy-audit --check-live` reads a complete ten-profile, credential-free
snapshot, the vendor `/jffs/openvpn/vpndirector_rulelist`, effective IPv4/IPv6
filter saves and IPv4 policy rules. It re-reads configuration and normalized
rules and rejects observed changes during the audit. This detects races but
is **not an atomic kernel/NVRAM transaction**.

Compared with the old additive ABI, the new typed audit:

- requires every enabled VPN Director source, not one arbitrary rule per slot;
- distinguishes redirect-all from source-policy mode and all ten unit slots;
- binds early WAN/VPN routing exceptions to actual configured selectors;
- checks inbound protection for existing manually started tunnel interfaces;
- does not invent global kill switches for stopped/disabled profiles or empty
  Director lists;
- reports unsupported enforce modes and destination-only rules as unverified.

It remains **observation-only**. Per-profile audit failure is not wired to the
firewall's forwarding switch. C ABI signatures remain unchanged; this audit is
explicitly not a release certificate for VPN security.
No active-requirement coverage is reported as such. Active OpenVPN/WireGuard
hardware fixtures, server-peer route exceptions (priority 90), actual VPN
routing-table content, IPv6 kill-switch semantics, and a targeted, safe
enforcement/recovery design are still required before replacing the current
live guard. Do not wire audit failure straight to a global forwarding shutdown.

## Evidence: 2026-09-09

- Native ARM binaries ran on GT-AX11000 `102.9 alpha1` without rebooting.
- The full security C ABI fixture ran both under QEMU with the locked vendor
  sysroot and **natively on the router**, including WireGuard/snapshot symlink
  rejection and prompt FIFO rejection. A real bug was fixed: ARM EABI
  `O_NOFOLLOW` is octal `0100000`, not the x86-64 `0400000` value previously
  compiled into `router-security`. Both readers also now use `O_NONBLOCK` to
  avoid blocking on a FIFO before checking metadata. The shared values are
  verified against target libc headers and an ARM gate is added to CI.
- `private-firewall-capture.patch` separately moves the C caller's capture
  transaction into a private `mkdtemp` directory; a compiled harness checks
  both IPv6 build variants, success, capture/policy failures, ENOSPC and cleanup.
  **These changes to firmware `rc` have not been flashed.** They require a
  fresh green firmware build and later deployment, not a live binary swap.
- Read-only W9 live audit passed with **zero active VPN-client requirements**;
  no active VPN kill-switch hardware test was performed.
- The first RAM pilot used approximately 1.6–1.8 MiB RSS. Over 286 seconds,
  `/proc/PID/stat` accumulated 127 ticks including reaped ping children,
  approximately 0.44% of one CPU core at Linux USER_HZ=100.
- Gateway + both external targets returned every probe through the first
  fifteen minutes, including history rollover at 600 samples. RSS stabilized
  around 1.7 MiB. This is a short clean observation, not proof that intermittent
  WAN failures never occur.
- Anonymous requests to the page, status and ping endpoints returned only the
  login redirect body. Authenticated rendering on the user's device is still
  unconfirmed. Real Chromium headless-shell rendering **with local fixtures**
  and DOM tests for stale data, login responses, background gaps and text-only
  rendering passed. Full Chromium's CLI render timed out in this environment;
  the headless-shell path is the verified one.
- The add-on was installed to `/jffs/addons/link-health` and its cooperative
  stop/start worked. Only one startup line was added; no router/network service
  was restarted. Pre-install hook SHA-256:
  `822f5a7fec8b15529d08527708e2c8be5cbc2a767a57965e384a37683365c0c2`;
  installed hook: `5cad1274664f82abe443a13dd180e876de5d7646c1aedd7235634f711fe4f54b`.
  First installation exposed the lack of BusyBox `mktemp`; the installer now
  uses an exclusive 0700 staging directory. The incomplete first copy was kept
  privately as `/jffs/addons/link-health.incomplete-20260909` for recovery.
  Firmware reboot-persistence itself was deliberately not retested by reboot.

## Next Wi-Fi investigation

On this boot there were no observed WAN link-downs, kernel crashes or service
PID changes. The affected Galaxy Tab S9 Ultra had repeated band changes and
reassociations at roughly -85 to -87 dBm on 5 GHz. A later 2.4-GHz station
snapshot showed about -78 dBm, retransmissions, WPA3-SAE/AES and no decrypt
failures. This supports weak coverage/roaming as a working hypothesis, not a
proved client/driver bug. The POCO F3 was not associated during inspection.

Correlate an actual call glitch with the two measurement legs first. A
controlled 80-MHz/non-DFS test on 5 GHz-1 and comparison near the router are
reasonable next experiments, with one change at a time and an agreed brief
Wi-Fi interruption. **Neither was applied.** No QoS, DTIM, TWT, country or power
change was made. A stronger AP transmit setting does not improve the phone's
return-path transmit power.

Reference context (not proof of this incident):
[ASUS DFS explanation](https://www.asus.com/support/faq/1045936/) and
[Cisco voice WLAN coverage guidance](https://www.cisco.com/c/en/us/products/collateral/wireless-mobility/wireless-lan-wlan/wireless-vocera-dep-guide-og.html).
