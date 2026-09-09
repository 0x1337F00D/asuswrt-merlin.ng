# ALL-profile steering: reference review and release boundary

2026-09-09. Diagnostics branch only; no persistent driver, country, power, NVRAM,
startup or firmware change. After explicit user approval, two bounded native
bsd trials ran, both now stopped. ALL is the requested invariant.

## Three workstreams

| Workstream | Current result | Not claimed |
| --- | --- | --- |
| Browser error handling | Own timeout is no longer called a login failure; tested and hot-deployed | HTTP timing alone proves RF loss |
| Rust Wi-Fi correlation | Native finite run, bounded one-client telemetry, filtered events, real process presence | Full trace retention, atomic radio snapshots, or a steering fix |
| Steering under ALL | Native crash localized to a 3-vs-4 argument ABI break; isolated regression and corrected 30-second native start passed | Permanent firmware fix deployed, successful band handover, roamast native validation, or long soak |

## Confirmed ABI defect and bounded correction, 14:44–15:01 CEST

The approved original-binary trial crashed once, with no restart loop. The
private 442368-byte core SHA-256 is
`b63ae42ff00cd1fe6fb5f3be3f4c425c8be324d5d46f10e11efbb451143606d8`.
It and process maps remain in RAM at `/tmp/bsd-approved-trial-26264` on the
router; the verified local copy is `/tmp/bsd-native-evidence-20260909/core`.
Do not commit/upload raw cores or logs: process memory can contain private data.

GDB with the exact installed libshared resolves PC `0xf7690e00` to
`retrieve_static_maclist_from_nvram+612`, specifically `str r3,[r10]` with
`r10=0x1000`. The source initializes `maclist->count` here.

| Consumer/provider | Proven argument layout |
| --- | --- |
| Pinned bsd, call at `0x245dc` | r0=radio index, r1=buffer, r2=4096 (three arguments) |
| Pinned roamast-broadcom.o, relocation at `0x2b0` | Same legacy three-argument call |
| Current libshared, broadcom.c:2451 | `(idx, vidx, buffer, size)` (four arguments) |

The new callee treats the legacy size 4096 as the buffer pointer and writes
through address 0x1000. This is a concrete ABI mismatch, not evidence that
the ALL country profile is intrinsically incompatible. The earlier ALL
quarantine contained crashes but did not repair their cause.

Corrected offline fixture: successful WLC_GET_MACMODE (105) is required to
reach this call. The earlier unsupported-ioctl fixture skipped it and thus
missed the real bug. With MACMODE success and the real configured scheme 2,
the original blob now predictably SIGSEGVs; with the small process-local
`compat/bsd-maclist-v3.c` adapter it survives until the test deadline. The
adapter only inserts `vidx=0`; it does not replace parsing, driver logic or
regulatory settings. Bad/mixed ABI inputs abort instead of returning a fake
empty access list. Host C tests check all three indices, buffer canaries and
five invalid inputs.

The corrected native trial at 14:59:09 ran the full 30 seconds, then handled
SIGTERM and exited 0. No new core/fatal signal. Result directory:
`/tmp/bsd-approved-trial-15237`. Before/after selected NVRAM and all three
driver MAC lists/modes were identical. httpd/WAN collector remained
1362/25987; external ICMP answered; the MacBook remained associated. No
roamast start, forced deauthentication, WLAN restart or router reboot occurred.
Global core_pattern stayed `core`; normal shells still have core limit 0.
Only the test child had a bounded core/file-size allowance.
The later WAN window retained 600/600 replies for each target, but contained
two shared RTT spikes of about 200–220 and 340–360 ms after the adapted child
had stopped. Thus no packet-loss outage was recorded, but this is not a claim
of jitter-free service or a fix for every observed connectivity symptom.

The adapter and Rust supervisor are RAM-only, not added to the installed
add-on or firmware. `bsd-trial` is an explicit opt-in development binary,
not included by the diagnostic package installer. Its owned-child tests
cover natural exit, targeted SIGTERM without touching a neighbor, and a
hard-kill fallback. Its Drop guard handles ordinary errors; it does not
claim survival of kernel failure or SIGKILL of the supervisor itself.

`compat/gt-ax11000-maclist-abi.patch` is the preferred permanent-source
candidate: restore the known three-argument export only for GTAX11000,
keep `vidx=0` for those legacy consumers, and leave other models' four-argument
interface untouched. It replays over locked upstream 6be5bc84b50. The actual
rootfs symbol scan finds only bsd and rc importing this symbol (libshared
exports it). **This patch is not in inputs.lock or the firmware build series,
and the source-patched full library/image has not been built or flashed.**

Remaining safety gates: full library/image compilation and exact export/caller
checks, roamast-specific regression (native trial not performed), active
MAC-filter and AiMesh semantics, active move-away/return handover test, and
longer bounded soak. The old C parser also ignores buffer capacity when
appending and uses `sizeof(maclist_buf_size)` in memset; those separate
hardening debts are not fixed by ABI adaptation. Native adapter testing was
deliberately restricted to existing disabled MAC filters and re_mode=0.

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
or compatible; no manual BTM, forced deauth or active RF scan was requested.

## Historical crashes: evidence and limits

Before the 14:44 native reproduction above, the 2026-08-22 retained evidence recorded 213 roamast SIGSEGVs and two bsd
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
help invocation; this describes the initial read-only stage before the approved
native trials above.

`tests/wifi-vendor-reference.sh` copies an explicitly supplied, hash-checked
rootfs to private tmpfs and runs the real bsd with a synthetic NVRAM/ioctl
fixture, isolated network/PID/mount namespaces and private /tmp and /run.
It has an eight-second deadline, a hard-kill fallback, core dumps disabled
and a bounded log. The host shell, not QEMU, is PID 1 so guest SIGSEGVs work.
The actual libshared wrapper/error paths run; unsupported hardware ioctls
fail rather than returning fabricated real station records. Never preload
the fixture on the router. No proprietary binaries enter Git.

During the initial incomplete fixture, missing synthetic sw_mode caused an artificial NULL conversion crash;
supplying the real key fixed the fixture. That was **not** reproduction of the
historical router crash. With the completed fixture and current libraries,
bsd survived until the timeout with all three interfaces examined. That earlier
result only covered initialization/error paths, not real-driver station polling,
event handling, steering correctness, long-term stability or regression parity.

## Remaining gates before changing live steering

1. Native bsd crash capture with exact ELF/library provenance, maps and bounded
   private RAM core is complete. Preserve these privately; do not enable global
   unbounded core dumps or assume roamast's whole runtime is already tested.
2. Integrate/build/test the demonstrated legacy-ABI fix. Preserve normal-country
   behavior and keep ALL; do not globally falsify NVRAM for unrelated services.
3. Replay malformed driver replies, incomplete/duplicate station reports,
   counter resets, delayed/missing events and association races. Unknown input
   must never trigger a client disconnect.
4. If a Rust controller is ultimately needed: observation-only first, existing
   protocol mechanisms, client allowlist, sustained observations, qualified
   target evidence, cooldown and failure backoff. No forced deauthentication
   based solely on one RSSI value; no untested private-driver ABI.
5. A short native start window was approved and used; coordinate the longer
   active movement test before proceeding. An
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
