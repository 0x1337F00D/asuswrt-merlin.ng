# Extracted-image QEMU test laboratory

## Goal and boundary

Run the actual ARM executables/shared libraries extracted from a reviewed
candidate in an explicitly requested local lab, not just independently compiled
host unit tests. Never contact the router. The historical image evidence below
belongs to the Tier3 alpha4 candidate; adding this suite does not build, install
or validate a new firmware image.

## CI method and firmware compatibility

The standalone `.github/workflows/qemu-lab-host.yml` runs **20 host harness
regressions only** on GitHub-hosted Ubuntu for relevant pull requests/pushes and
manual dispatch. It uses Python's standard library and synthetic files/short
subprocesses: no QEMU installation, compiler, firmware, artifact download,
privileged namespace setup, router access, secrets or self-hosted runner. Its
read-only checkout is pinned to the event SHA; the five-minute job is separate
from the existing firmware build and has no build dependency.

Reusable method: first test the harness verdicts themselves (known pass, explicit
failure, timeout, crash, unsafe manifest/archive, absent isolation and missing
guest markers). Then execute reviewed image consumers locally with positive and
negative protocol controls, preserving exact hashes and failed-attempt logs.
Finally require both user-mode and real-kernel-VM reports in the combined gate.
Host-green proves the harness checks, not that a firmware consumer passed.
Missing parent fixtures fail explicitly; a Python "file not found" error is
not accepted as evidence that a namespace safety guard ran.

This CI branch is based on main `a3caa67111ddb3a0a2c032067de464eba75c8627`, whose
firmware consumers are older than the separately tested Tier3 alpha4 image.
Those historical image passes are **not main-image evidence**. Extracted-image
QEMU stays local/on-demand until the corresponding firmware consumers land and
a matching image/manifest is available. Do not weaken required self-tests or
substitute the historical manifest to make older main binaries appear green.
Manual dispatch of the hosted workflow also runs only the host tests.

The hosted job has no firmware-path input and never executes fetched artifacts
from untrusted refs. A future on-demand artifact job must be separately reviewed
for artifact provenance, isolation and authorization; it must reuse a built
candidate rather than require another full firmware build. No hosted image or
hardware pass is claimed by this workflow.

[QEMU user mode](https://www.qemu.org/docs/master/user/main.html) translates
system calls to the host kernel. It does not boot the vendor Linux kernel,
emulate Broadcom radios, reproduce switch offload or prove flash/recovery.
Namespaces limit accidental network interaction, not malicious binary access
to all host files: only run our reviewed artifacts. QEMU -L is not a chroot.
Do not supply real router NVRAM, private keys or untrusted firmware.

## Implemented first layer

Runner: `.github/ci/gt-ax11000/tests/qemu-lab/run.py`.

- Verify the complete supplied Rust-consumer manifest against extracted files
  before execution; reject missing, tampered, duplicate and escaping paths.
- Require tmpfs workspace and disabled swap. Generated probes, synthetic keys,
  logs and models stay there. No package installation or router credentials.
- Fresh user/network/mount/PID namespaces per scenario, private /proc and
  /run, read-only bind mount of the extracted rootfs, and disposable veth
  links. No host interface is added to the lab. Namespace
  creation failure is a failed test, never an automatic non-isolated fallback.
- Per-scenario wall deadline, process-group cleanup, no core dumps, 16 MiB
  per-file limit; repeat count bounded 1..100. JSON + JUnit and individual logs.
- Emulator/compiler and manifest hashes recorded. Explicit pass/fail/timeout;
  missing capabilities do not silently skip a required test.
- infosvr from the image: test-only LD_PRELOAD model supplies LAN IP/netmask,
  product ID, SSID and capabilities; writes abort. It is not installed into
  the image and does not intercept sockets, TLS or firewall behavior.
- Single/multiple interface infosvr LAN response and spoofed-source WAN
  unicast/multicast rejection, with source port 9999 checked.
- Extracted wsdd2/lld2d positive LAN and negative WAN discovery controls;
  slow TCP clients must not block discovery or shutdown.
- Extracted wsdd2: 120 rounds/1440 connection attempts and six SIGHUPs per
  repeat, descriptor ceiling/reclamation and process survival. Admission
  refusals counted explicitly. RSS is QEMU process RSS, not router RAM usage.
- Extracted libmssl: RSA/EC x TLS1.2/1.3 x three repeated sessions, byte-wise
  HTTP fragmentation, stdio response, config and descriptor lifetime. Extra
  idle/partial-record/plaintext/disconnect tests check short socket deadlines.
  A C-side socket-timeout readback checks the emulator ABI first.
- Deterministic malformed ingress (fixed seeds, truncations, mutations and
  boundary lengths through 16384 bytes) for image infosvr/wsdd2; malformed
  HTTP lengths/headers, positive controls before/after, fd reclamation.
  Last input, seed and stderr retained. Counts are **sent datagrams**, not a
  claim every packet was processed or that coverage-guided fuzzing was used.
  The infosvr veth uses MTU 20000 to reach large datagram boundaries without
  IP fragmentation; this is deliberately not the physical LAN's MTU.
- An intentional ARM SIGSEGV proves crash detection with independent waitpid
  verification; it is a harness control, not a firmware crash. QEMU runs
  below namespace PID 1 so init's special signal semantics cannot swallow its
  fatal signal. Crashes, failures and timeouts are distinct failing verdicts.
- Twenty host regressions for the runners, archive, guest verdict and download
  locks, including refusal of Python -O; the standalone hosted workflow runs
  both host test files. The image suite itself is local/on-demand, not a new
  recurring GitHub firmware build or a claimed completed hosted image test.

## Reproduce

Requires Linux user/network/mount/PID namespaces, iproute2, util-linux,
Python >=3.11, openssl, and the existing Broadcom ARM soft-float compiler.
The compiler's original symlink name must be retained (argv[0] selects it).
Set the toolchain's host LD_LIBRARY_PATH if its wrapper requires it.

1. Use the existing verified image-extraction procedure and its matching
   RUST-CONSUMERS.sha256. Do not pair a different image with a stale manifest.
2. Run `python3 .github/ci/gt-ax11000/tests/qemu-lab/fetch-emulator.py`.
   It fetches the locked Debian package, verifies SHA/length BEFORE extraction,
   and prints the extracted **runtime directory**; append `/usr/bin/qemu-arm`.
   No sudo, apt sources or system installation.
3. Run from the repository:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 .github/ci/gt-ax11000/tests/qemu-lab/test_runner.py
PYTHONDONTWRITEBYTECODE=1 python3 .github/ci/gt-ax11000/tests/qemu-lab/test_system.py
PYTHONDONTWRITEBYTECODE=1 python3 .github/ci/gt-ax11000/tests/qemu-lab/run.py \
  --rootfs /absolute/path/to/extracted/rootfs \
  --manifest /absolute/path/to/RUST-CONSUMERS.sha256 \
  --qemu /absolute/path/to/qemu-arm \
  --tls-qemu /absolute/path/to/qemu-arm-with-working-timeout-readback \
  --cc /absolute/path/to/arm-buildroot-linux-gnueabi-gcc \
  --repeat 3 --seed 4908 --packets 10000
```

This runs the user-mode layer only. The combined gate below additionally
requires the system VM (including IPv6). Preserve report.json, junit.xml and
logs, including failed first attempts. Do not adjust timeouts just to obtain
green results. Diagnose emulator vs fixture vs firmware using independent
socket probes and syscall traces; do not preload replacements for the code
being tested. The NVRAM model deliberately narrows only the hardware boundary.

## Findings that motivated capability checks

- QEMU 8.2.2 lacks the required IP_MULTICAST_IF emulation.
- QEMU 10.0.11 returns zero-length SO_RCVTIMEO readback in our C probe. Its
  [getsockopt translation](https://raw.githubusercontent.com/qemu/qemu/v10.0.11/linux-user/syscall.c)
  zeroes the length when the destination pointer is non-null. The image TLS
  adapter then observes zero/default rather than the configured short timeout.
  This is not evidence that the router kernel returns the same invalid result.
  The new test must pass using a working emulator, not bypass this check.
- The pinned Debian 11.1.1 binary reproduces the same zero-length result.
  QEMU 8.2.2 passes the same short-deadline cases against the same libmssl.
  Current validated setup therefore uses 11.1.1 for discovery and explicitly
  passes `--tls-qemu` for 8.2.2. Both executable hashes/versions are recorded.
  Omitting the override on affected versions keeps TLS red; there is no
  automatic retry with an older emulator and no socket-emulation preload.
  A future unified emulator must first pass both capability families. The
  downloader pins the network emulator only; supply the existing validated
  TLS emulator explicitly, and retain its provenance with the report.
- QEMU 11.1.1 also refuses `setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_IF)`
  with ENOPROTOOPT (syscall trace: level 41, option 17). Consequently the
  image wsdd2 cannot open its IPv6 discovery socket in that emulator.
  `wsdd-ipv6.py` remains an opt-in diagnostic reproducer, **not a passed test**.
  IPv6 discovery is assigned explicitly to the real-kernel VM below. It is
  required by the combined gate; it is not silently skipped or retried.

## Implemented second layer: generic ARM system VM

`system.py` constructs a small newc initramfs in RAM and boots pinned Debian
Linux 6.1.0-53-arm64 (6.1.187-1) on QEMU `virt-8.2`, Cortex-A53, TCG, one
vCPU and 512 MiB. In the historical Tier3 validation, ARM32 compatibility executed
three **unchanged extracted alpha4 binaries**, wsdd2/ntp/lld2d, with their image
loader/glibc and self-tests. Re-running against another candidate requires its
matching image consumers and manifest; this suite does not supply those binaries.
The minimal static test PID 1 is not router rc, and the rootfs is not booted.

- Real-kernel socket timeout ABI, socketpair read/write, intentional child
  SIGSEGV detection; required markers, panic/failure rejection, 90s boot ceiling.
- Real image wsdd2 over IPv6 loopback: valid discovery before and after 250
  malformed datagrams and SIGHUP, request-ID-correlated replies, normal exit.
- Load the guest kernel's real cfg80211/mac80211/mac80211_hwsim module chain;
  require two virtual radio phy devices. **Only module loading/enumeration is
  covered: no association, WPA handshake, radio traffic or roaming test yet.**
- No QEMU NIC, host network, disks, shared filesystem, USB or hardware
  passthrough. Logs capped at 16 MiB; core files disabled. JSON/JUnit records
  kernel/initramfs/emulator/consumer/library and fixture hashes.

Reproduce package setup (Linux x86-64 host; tested on Ubuntu noble):

```sh
python3 .github/ci/gt-ax11000/tests/qemu-lab/fetch-emulator.py \
  --lock .github/ci/gt-ax11000/tests/qemu-lab/system-kernel.lock.json
python3 .github/ci/gt-ax11000/tests/qemu-lab/fetch-emulator.py \
  --lock .github/ci/gt-ax11000/tests/qemu-lab/system-emulator.lock.json
# Substitute the first returned runtime directory; this writes only its RAM copy:
/usr/sbin/depmod -b /absolute/path/to/kernel-runtime 6.1.0-53-arm64
```

The second lock contains QEMU and its extra libfdt/libslirp packages. The host
still supplies ordinary system libraries; this is not a hermetic container.
Set LD_LIBRARY_PATH to its `runtime/usr/lib/x86_64-linux-gnu` plus the existing
Broadcom compiler's `lib` and `usr/lib`. Each download is length/SHA checked
before any package in the set is extracted; no maintainer scripts are run.
The kernel package is from the official
[Debian security archive](https://packages.debian.org/bookworm/arm64/linux-image-6.1.0-53-arm64/download).

## One combined pre-installation gate

```sh
PYTHONDONTWRITEBYTECODE=1 python3 .github/ci/gt-ax11000/tests/qemu-lab/preinstall.py \
  --rootfs /absolute/path/to/extracted/rootfs \
  --manifest /absolute/path/to/RUST-CONSUMERS.sha256 \
  --cc /absolute/path/to/arm-buildroot-linux-gnueabi-gcc \
  --qemu /absolute/path/to/network-runtime/usr/bin/qemu-arm \
  --tls-qemu /absolute/path/to/validated-tls-qemu-arm \
  --kernel-root /absolute/path/to/kernel-runtime \
  --qemu-system /absolute/path/to/system-runtime/usr/bin/qemu-system-aarch64 \
  --repeat 3 --packets 10000 --seed 4908
```

Exit zero requires **both** layers, with linked child reports and their hashes.
Missing tooling/capabilities/reports fail; no automatic installation follows.
Independent scripts remain usable for diagnosis. A green offline gate is
necessary evidence for a candidate, **not sufficient deployment approval**.
The gate is currently run locally/on-demand, not automatically by the flash tool.

## Broadcom kernel attempt: not a successful boot

The actual vendor tree is Linux 4.1.51 ARM64 with ARM32 COMPAT. A separate
RAM-only copy was configured toward virt, serial, networking and hwsim.
`kernel-virt.patch` and `kernel-config.sh` preserve this **failed portability
experiment**, not a supported build recipe. They are outside the firmware
patch series and must never be applied to a router image build.

The vendor top-level product configuration and external driver Kconfig prevent
a plain generic configuration. After separating those lab-only and repairing
copied external fltr/sch_cake links, compilation reached generic networking.
First an unguarded Broadcom pktc_flags access required a lab-only guard; then
net/core/dev.c still required FkBuff_t/pNBuff_t/skb_xlate_dp/fkb_mark. These are
pervasive Broadcom packet-path dependencies, not missing virt device settings.
The attempt stopped there: no invented successful driver stubs, no claimed
vendor kernel image, no changes to the production build sources.

QEMU [virt](https://www.qemu.org/docs/master/system/arm/virt.html) is a generic
board, not BCM4908. [mac80211_hwsim](https://wireless.docs.kernel.org/en/latest/en/users/drivers/mac80211_hwsim.html)
simulates mac80211 radios, not Broadcom's proprietary radio/firmware stack.
Even a future adapted vendor kernel would not establish RF/DFS/offload parity.

## Next layers (planned, NOT implemented)

1. Generalize the NVRAM model into typed scenario snapshots; reject/log unknown
   required keys. Extend to complete httpd/client-list requests with modeled
   shared-memory Network Map data, auth sessions and write transactions.
   Do not execute full rc or substitute successful vendor calls indiscriminately.
2. Add deterministic network delay/loss/reordering, IPv6 WAN-isolation, interface
   down/up/address changes and slow-reader backpressure. The malformed ingress
   corpus and IPv6 loopback lifecycle are now implemented as described above.
   Preserve LAN positive controls and fixed seeds; repeated success alone does
   not establish robustness to loss or client protocol diversity.
3. Run NTP against a local fake upstream and a clock-write model; test startup,
   KoD, DNS transitions and signals without changing the host clock.
4. Extend the working generic VM with real iptables/routing/VPN tunnel traffic,
   fail-closed kill-switch cases, memory pressure and hwsim hostapd/supplicant
   association/WPA tests. No forwarding/VPN/WPA coverage is claimed today.
   Add ASan/UBSan builds and coverage-guided native/ARM fuzzers for suitable
   parser boundaries; release-image traffic mutation alone is not a sanitizer.
5. Add on-demand CI consuming an already built artifact, emulator cache keyed
   by checksum and uploaded JUnit/logs. Do not spawn another full firmware build.

Hardware remains mandatory for Broadcom Wi-Fi/DFS/roaming, actual credentials,
switch/Runner offload, WAN topology and bootloader/fallback behavior. There is
no spare test router: only promising offline-passing versions should reach the
production router, in an explicitly authorized maintenance window with backup,
one-shot boot/fallback and stop criteria. No guarantee of catching every crash.
