# QEMU laboratory validation and CI scope — 2026-09-11

## CI integration: host-only evidence

This isolated CI change is based on main
`a3caa67111ddb3a0a2c032067de464eba75c8627`. Its standalone GitHub-hosted workflow
runs the 12 runner and 8 system/package/combined-verdict host regressions, using
synthetic fixtures only. All 20 pass locally in this worktree. Hosted execution
has not yet occurred at the time of preparation; no GitHub image-QEMU or hardware
pass is claimed.

The image results below are **historical Tier3 alpha4 evidence**, not validation
of main's older firmware consumers. No candidate firmware was built or executed
for this CI integration. Image QEMU remains local/on-demand until the relevant
consumers land and a reviewed image with its matching manifest is available.
The report paths are machine-local historical evidence, not CI artifacts shipped
by this PR. The manual hosted dispatch also runs only the 20 host regressions.

## Expanded combined offline gate — historical Tier3 alpha4 result

**PASS**, unchanged alpha4. No router access or installation; all compilation,
downloads and runtime test output were in tmpfs with swap disabled. Sources
and evidence are copied to durable storage only after verification.

- Combined report: `/tmp/gt-preinstall-lab-211rci7g/report.json`.
- User-mode report: `/tmp/gt-qemu-lab-jarxlsw2/report.json`: **24/24 pass**
  (21 scenario groups in three repetitions plus model/probe compilation and
  intentional ARM SIGSEGV detection). 82.626 seconds including orchestration.
- System report: `/tmp/gt-system-lab-rkh8b6gi/report.json`: **PASS**,
  3.669 seconds including packaging/compiler/orchestration. Both layers together
  about **86 seconds**, excluding initial package downloads/extraction.
- At the time of that Tier3 experiment, 20 host harness regressions (12 runner +
  8 system/package/combined verdict) and all 19 existing workflow regressions
  passed locally. No hosted image execution occurred. The separate CI change
  described above adds the reusable host gate, not a replay of this image run.

The repeated real-image tests cover 60 TLS cases, 60000 **sent** deterministic
mutated/boundary UDP datagrams across infosvr/wsdd2 (seeds 4908/4909/4910),
malformed metadata HTTP requests and 4320 wsdd2 connection attempts. 4317
connections established, three refused; 18 reloads, fd baseline/peak/final
7/15/7 in each resource round. QEMU RSS increased 64 KiB per round; this is
host emulator memory, not measured router memory or proof of no long-term leak.
No unexpected crash was detected in those tested paths. UDP sends do not prove
every packet was processed; kernel drops and service rate limits remain possible.

The system VM runs the image's unchanged wsdd2, ntp and lld2d self-tests using
its ARM32 loader/glibc under a real generic ARM64 kernel. It also tests wsdd2
IPv6 discovery before/after 250 malformed datagrams and reload, requires a
fresh matching request ID, and checks normal shutdown. A child SIGSEGV is
deliberately generated and independently detected. Five kernel modules load;
two mac80211_hwsim phy devices appear. **No WPA association/traffic test yet.**
VM: one vCPU, 512 MiB, no NIC/disks/shared host filesystem.

Kernel 6.1.0-53-arm64 package 6.1.187-1, SHA-256 of the kernel:
`4909442ce8c53a14239e29b0074ca7190733795ecce56b43b0ec8741fa9734da`.
Exact emulator/kernel package locks and verified extractor are in the suite.
Both layers produce JSON/JUnit; the combined gate links and hashes their reports.

### Failed attempts retained, not relabeled as successful

- `/tmp/gt-qemu-lab-i0r0wlxn`: the new IPv6 user-mode probe failed three times.
  Trace identifies ENOPROTOOPT for IPV6_MULTICAST_IF in QEMU 11.1.1, before the
  daemon can open its discovery socket. The same unchanged image passes in
  the generic system VM. IPv6 therefore belongs to that explicit required
  layer; the user-mode reproducer remains available and known to fail.
- `/tmp/gt-qemu-lab-28hwhwtk`: actual service groups passed, but the intentional
  crash control hung after the SIGSEGV message because QEMU was run directly
  as namespace PID 1. It now runs as a child of a small Python namespace init,
  like the other daemon scenarios. waitpid independently verifies SIGSEGV;
  the final control finishes in 0.785s, reports expected crash/observed crash.
  No timeout threshold was widened and no hardware firmware change was made.
- Earlier malformed infosvr fixture used loopback and failed its valid
  broadcast-response control. It was corrected to disposable veth/raw-LAN
  ingress, with explicit MTU 20000 test-only boundary handling.
- The isolated Broadcom 4.1.51 generic-port build **failed** on unseparated
  vendor network dependencies (FkBuff_t, pNBuff_t, skb_xlate_dp, fkb_mark).
  Log: `/tmp/gt-kernel-lab-build-network.log`. Lab-only patch/config retained;
  no vendor-kernel boot, Broadcom RF/DFS, switch offload or flash test is claimed.

### Remaining release risk

Full httpd/client-list flows, real VPN/firewall forwarding, NTP lifecycle/clock,
memory-pressure/sanitizer fuzzing, WPA/roaming and the actual Broadcom kernel
are not covered by this new gate. Existing separate source/ABI tests are not
substitutes for those integration scenarios. Offline green cannot guarantee
absence of crashes. Only promising candidates proceed to the production router
in a separately authorized, recoverable maintenance window.

Durable expanded suite/evidence:
`/home/paul/.local/share/gt-ax11000-builds/qemu-lab-expanded-alpha4-20260911`.

## Initial first-layer validation — historical result

Image: unchanged alpha4, source 4d093a18788, SHA-256
2ec09b692e1beab94e1c042c25c3e6504c4476957b132a445f5c452ed9f709ed.
No router access, installation, NVRAM change or firmware rebuild.

## Passed

- Ten runner unit tests, including tampered/missing/duplicate/escaping
  manifest entries, timeout/nonzero propagation, namespace refusal and -O.
- Existing 19 workflow tests at the time of this initial Tier3 experiment.
  Those historical checks do not establish a hosted run of the new standalone
  workflow or validate main's older image consumers.
- Three complete image rounds: 18 scenario groups plus fixture compilation,
  all pass in `/tmp/gt-qemu-lab-s9_0iyba/report.json` and junit.xml.
- 60 TLS cases: 36 RSA/EC TLS1.2/1.3 fragmented-HTTP/lifetime sessions and
  24 idle/partial-record/plaintext/disconnect rejection/deadline cases.
- infosvr single/multiple-interface LAN positive, spoofed WAN negative cases
  use the actual ARM executable, with only NVRAM/SSID/capabilities modeled.
- wsdd2/lld2d discovery isolation and wsdd2 slow-client response/shutdown pass.
- wsdd2 stress: 4320 attempts, 4317 established, 3 refused; 360 rounds and
  18 SIGHUP reloads. Each repetition fd baseline/peak/final = 7/15/7.
  QEMU RSS growth was 64 KiB each run; this is NOT a router-memory benchmark.

## Emulator evidence and limitations

The suite initially failed TLS deadline probes with QEMU 10.0.11 and again
with the pinned 11.1.1 package. An independent C getsockopt readback returns
size=0/value=0 after setting 200ms. The 10.0.11 translation source explains
the inverted pointer condition; see QEMU_TEST_PLAN.md. Logs were retained.

The same exact image library and TLS probe pass under existing QEMU 8.2.2.
Network cases require newer multicast emulation and pass under 11.1.1.
The successful run explicitly supplies --tls-qemu; both versions/hashes are
recorded. This is not an automatic fallback or a passing claim for the
defective emulator's timeout implementation. No firmware TLS code was patched.

After that full run, runner-only fixture provenance hashing and explicit -O
refusal were added; their unit tests pass. The firmware and scenario logic
are unchanged. Plan and results distinguish simulated hardware boundaries
from actual guest code and from still-unimplemented full-system tests.

Durable suite and evidence:
`/home/paul/.local/share/gt-ax11000-builds/qemu-lab-alpha4-20260911`.
See QEMU_TEST_PLAN.md for commands and next layers. No independent agent
review or hardware validation is claimed.
