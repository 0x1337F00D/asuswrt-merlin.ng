# ALL-profile steering: reference review and release boundary

2026-09-09. Diagnostics branch only; no driver, country, power, NVRAM, service
startup, firmware or radio change in this work. ALL is the requested invariant.

## Three workstreams

| Workstream | Current result | Not claimed |
| --- | --- | --- |
| Browser error handling | Own timeout is no longer called a login failure; tested and hot-deployed | HTTP timing alone proves RF loss |
| Rust Wi-Fi correlation | Native finite run, bounded one-client telemetry, filtered events, real process presence | Full trace retention, atomic radio snapshots, or a steering fix |
| Steering under ALL | Original source/blob review and isolated initialization probe | Historical crash reproduced, quarantine safe to remove, or new roaming controller ready |

The moving MacBook lost 44/144 local pings. A saved simultaneous radio slice
stayed on eth7 (5 GHz-1, 64/160) as smoothed receive RSSI dropped to -87 dBm,
with 23 missing reverse probes. Twenty missing reverse probes had no PS flag.
A later slice returned to roughly -57 dBm and 60/60 short replies. Neither
snapshot recorded a band transition. This supports a weak, sticky association;
it does not identify one faulty line of driver code or guarantee that 2.4 GHz
would have been adequate. Smoothed RSSI can be stale without incoming frames.

## Original reference, not an invented replacement

Reviewed upstream `6be5bc84b50ea37be7b5d4307c5042771c3cf95b` using `git show`:

- `release/src/router/rc/services.c`, `start_bsd`: ordinary Broadcom startup
  stops the previous instance, checks configured Smart Connect (conditional
  on build flags), and executes `/usr/sbin/bsd`. It has **no ALL exclusion**.
- `start_roamast`: respects existing disable/setup/mode conditions, then
  build-specific forcing or configured per-radio low-RSSI thresholds. It also
  has no ALL exclusion in original upstream code.
- Our `wireless-service-testlab-stability.patch` adds ALL exclusions to both
  startup paths and to `watchdog.c:roamast_check`. This is a real behavioral
  deviation: a configured Smart Connect checkbox does not imply a live bsd.
  Live configuration was smart_connect_x=1, but no bsd; roamast_disable=1 and
  no roamast. The panel now exposes process presence so this is not hidden.
- `release/src/router/bsd/Makefile` copies `prebuilt/$(BUILD_NAME)/bsd` when C
  sources are absent, as here. rc links `roamast.o`/`roamast-broadcom.o` from
  vendor prebuilts; `/sbin/roamast` is an rc applet. Startup source is not the
  complete proprietary steering implementation.
- `release/src/router/rc/roamast.h` defines normal sensitivity as three RSSI
  observations, 15-second idle period, 20-Kbps idle rate and five-second normal
  polling. Other build/sensitivity modes differ. These definitions are a
  reference, not proof of the compiled blob's runtime choices or a recommendation
  to copy thresholds into a disconnect loop.
- Original libshared `wl_ioctl`/`wl_iovar_getbuf` and interface-name mapping
  were inspected. No demonstrated memory-safety bug was found in that review.

The live driver reported `#a (#a/0)` on all three radios. No country was changed.
Client 11v capability alone does not prove that the AP's BTM path is enabled
or compatible; no BTM, forced deauth, active RF scan or new controller was run.

## Historical crashes: evidence and limits

The 2026-08-22 retained evidence records 213 roamast SIGSEGVs and two bsd
SIGSEGVs. This justified containment, but is not a proof that ALL itself is
the root cause. Historical register dumps have similar offsets/register
patterns; without process maps/core dumps, ASLR prevents confidently naming
the shared function from those addresses. No fabricated symbol attribution.

The installed bsd is byte-identical to the vendor blob:
`af4f653e017e8daf27058bcb2b28d2f80acbae034456c668ad7613c48b818f84`.
The matching current rootfs supplies libshared
`2b6d17e434666325e693ebe5924ce031bedc4493e9824146820a34da0b36ac9f`
and libc `ba92e7b4d99da8c0f92205dd3d017cc93999744366c7cc31744c96b50edc7970`.
The older full-tree fs.install has different libshared and must not stand in
for current firmware. `bsd -H` was checked offline before its read-only native
help invocation; no live daemon startup was performed.

`tests/wifi-vendor-reference.sh` copies an explicitly supplied, hash-checked
rootfs to private tmpfs and runs the real bsd with a synthetic NVRAM/ioctl
fixture, isolated network/PID/mount namespaces and private /tmp and /run.
It has an eight-second deadline, a hard-kill fallback, core dumps disabled
and a bounded log. The host shell, not QEMU, is PID 1 so guest SIGSEGVs work.
The actual libshared wrapper/error paths run; unsupported hardware ioctls
fail rather than returning fabricated real station records. Never preload
the fixture on the router. No proprietary binaries enter Git.

Initial missing synthetic sw_mode caused an artificial NULL conversion crash;
supplying the real key fixed the fixture. That was **not** reproduction of the
historical router crash. With the completed fixture and current libraries,
bsd survived until the timeout with all three interfaces examined. This
tests initialization/error paths only, not real-driver station polling,
event handling, steering correctness, long-term stability or regression parity.

## Remaining gates before changing live steering

1. Capture a reproducible crash with exact ELF/library provenance, maps and
   bounded private RAM diagnostics. Do not globally enable unbounded core dumps.
2. Compare the implicated wrapper/ABI and original semantics; prefer a narrow
   demonstrated fix over a wholesale steering rewrite. Preserve normal-country
   behavior and keep ALL; do not globally falsify NVRAM for unrelated services.
3. Replay malformed driver replies, incomplete/duplicate station reports,
   counter resets, delayed/missing events and association races. Unknown input
   must never trigger a client disconnect.
4. If a Rust controller is ultimately needed: observation-only first, existing
   protocol mechanisms, client allowlist, sustained observations, qualified
   target evidence, cooldown and failure backoff. No forced deauthentication
   based solely on one RSSI value; no untested private-driver ABI.
5. Agree a short interruption window before native steering trials. An
   automatic controller stop does **not** guarantee immediate client reconnect;
   do not promise interruption-free rollback or reboot the router implicitly.
6. Repeat stationary and move-away/return active-client probes under ALL,
   compare loss bursts and band changes, then soak with no SIGSEGVs or PID
   churn before removing quarantine or merging into firmware.

Additional measurement debt: whole-test bounded private RAM retention, explicit
process-query failure vs process-absence state, and authenticated live browser
verification of the new section on the user's affected device. Repeated existing
`WLC_SCB_AUTHORIZE sta_flags_mask not set` kernel log lines were observed but not
temporally tied to this movement test; do not label them its cause without evidence.
