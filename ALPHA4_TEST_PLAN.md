# Alpha4: evening installation and validation plan

## Current authorization

Build and offline tests only. Do not flash, reboot, change boot selection,
read private router keys, modify NVRAM or run load tests before the user
starts the evening test session. No automatic scheduled installation.
Keep the country/profile, Wi-Fi, QoS, VPN and firewall settings unchanged
through the comparison. Alpha4 does not introduce WLAN tuning or blob ports.

## Changes to exercise

- infosvr receives only on configured interfaces, bound before UDP port
  activation. Replies retain source port 9999. Same-subnet source addresses
  alone no longer authorize ingress from another interface.
- wsdd2: up to eight nonblocking TCP metadata connections, 8 KiB request cap,
  64 KiB response cap, two-second absolute lifetime, bounded I/O per loop.
  When TCP is pending, the loop polls at 25 ms; idle behavior remains 500 ms.
  Discovery has no worker queue/threads. Slow readers cannot block the loop.
  Sequence numbers reserve on admission; failed sends may leave harmless gaps.
- Existing TLS credentials survive unsupported keys and initialization errors.
  HTTPS fails closed instead of replacing keys; explicit regeneration and
  missing factory credentials retain vendor generation behavior.
- awsiot no longer links unused mssl in this model's Rust overlay; OpenSSL
  remains for awsiot's actual transport. Vendor mode is unchanged.
- Input lock is mandatory by default; alpha4 wrapper explicitly enforces it.

## 1. Preflight — stop on any failure

Use a wired administration computer, leave its SSH session open, and have
physical power access. A one-shot boot selection does NOT reboot a hung
router automatically; fallback may require the user to power-cycle it.

1. Confirm user approval now, image SHA-256/version/source commit and saved
   artifact manifests. Do not select alpha3 or rely on filenames alone.
2. Read actual model, running firmware, uptime, current boot slot and both
   slot identities with the already validated trial controller. Do not guess
   bcm_bootstate numeric values from old notes.
3. Take/verify a fresh private backup: supported settings export, JFFS scripts
   and configuration, VPN credentials/certificates, DHCP reservations and
   current known-good firmware. Verify archive readability and checksums;
   export sensitive data only to the existing private backup location.
4. Record baseline PIDs/restart counts, free memory, kernel/OOM logs, client
   list, WAN/DNS/IPv4/IPv6, VPN routing and kill-switch expectations. Observe
   idle LAN ping for at least five minutes without traffic saturation.
5. Preflight the actual HTTPS certificate/key with the candidate mssl on QEMU
   in private tmpfs, or a separately approved RAM-only router probe. Use
   mssl_cert_key_match AND mssl_init; never print key bytes. Record only
   pass/fail and public certificate fingerprint. No key replacement fallback.
   Also read the existing https_crt_gen flag: an already requested explicit
   regeneration retains its vendor semantics and must not be overlooked.
6. If unsupported: STOP before flash. Decide separately whether to retain
   the old TLS image or explicitly issue compatible credentials. Do not
   silently regenerate a certificate to make this candidate boot.

## 2. One-shot installation, not immediate permanent promotion

Use the existing manifest-bound trial controller with alpha4's
FIRMWARE-VERSION.json and exact binary/Web hashes. Verify the inactive slot
and retain the known-good slot. Check image write/verification evidence
before selecting one-shot boot. Do not use raw guessed flash commands.

Important: controller.py is a complete smoke-and-fallback cycle. On success
it intentionally reboots a second time back to the baseline; it has no
"remain on candidate for 30 minutes" switch. Do not run it expecting a
long soak. First prove that cycle, then separately authorize the additional
candidate boot for the held soak using the documented persistent guard.
The hold-promotion marker must be in place BEFORE that candidate boot, and
any old guard must be backed up and correctly rendered for alpha4's actual
slot/manifests. See .github/ci/gt-ax11000/trial/README.md; do not install the
unrendered template or assume an old alpha1 guard will accept alpha4.

After boot, verify actual alpha4 identity before running tests. A reachable
ping alone is not a successful trial. Hold promotion until all required
checks below pass. If the router becomes unreachable, stop automatic writes;
use the agreed power-cycle fallback and confirm original settings afterwards.

## 3. Functional checks (wired first)

| Check | How | Pass / stop criterion |
| --- | --- | --- |
| HTTPS | Two browsers, login/logout, trusted or explicitly inspected certificate; TLS 1.2/1.3 requests | Expected fingerprint and page content, no HTTP fallback; TLS 1.0/1.1 refused |
| Concurrency | Six simultaneous bounded HTTPS GETs, then normal login | No stalls beyond socket deadlines, no httpd restart, no descriptor growth |
| Settings | Read existing settings; save one reversible non-network UI preference only after approval; reload/login again | Value persists, no unrelated NVRAM change, no unexpected service restart |
| Client UI | index.asp and device-map/clients.asp plus JSON endpoint | Active/stored clients visible, valid text/dictionaries, no duplicate malformed records |
| DHCP/DNS | Existing TV box LAN/WLAN identities, phone/tablet/laptop; short DNS and HTTPS tests | Expected reservations, gateway/DNS and Internet reachability |
| VPN | Existing tunnel status/routes, DNS; controlled disconnect only with separate approval | Configured kill switch prevents fallback traffic; no route/DNS leak |
| Discovery | Existing read-only infosvr-live.py on LAN; Windows Network/metadata query; LLTD-capable client | LAN discovery works; no new restarts or logs |
| wsdd2 slow clients | Two silent TCP/3702 connections for <=2 s while querying discovery | Discovery stays responsive; sockets reclaimed; no sustained RSS/fd growth |
| Wi-Fi | Existing ALL profile unchanged; stationary ping then timed room transitions on MacBook and tablet | Record loss/RTT alongside band/RSSI; compare to baseline, do not claim a roaming fix |

Do not change real certificates merely to test reload on the live router.
RSA→EC rotation, bad replacement and descriptor lifetime have synthetic
offline coverage. Test a real replacement only if separately backed up and
explicitly authorized. Keep recovery SSH/wired access throughout.

## 4. Isolation / firewall evidence

Capture current IPv4/IPv6 INPUT rules and service socket/interface bindings.
The vendor's broad multicast ACCEPT is not proof that discovery is isolated.
The new infosvr device binding is defense in depth, not a firewall rewrite.

From an authorized, controlled WAN-side segment, probe UDP/9999 and UDP/TCP
3702 and (if enabled) UDP/5355 using unicast AND multicast. Record ingress
interface/counters and absence of replies, then positive-control LAN replies.
Include a spoofed LAN-source probe only in an isolated lab segment, never
on the public ISP link. LLTD is Ethernet 0x88d9, not an IP port: test on the
WAN Ethernet segment with a LAN positive control. Do not flush firewall rules.

If no controlled WAN-side sender exists, mark hardware WAN isolation NOT
TESTED. Host veth tests establish Linux socket behavior, not Broadcom switch,
bridge/multicast handling or all dynamic rules on the actual router.

## 5. Observation and rollback

Observe at least 30 minutes of normal use, including a call, then optionally
overnight. Capture bounded summaries: min/mean/p95/max RTT and losses, process
PID/start time, fd count, RSS, kernel errors/OOM, WAN reconnects. Compare to
baseline; browser HTTP timing is not pure Wi-Fi RTT. No saturation test yet.

Stop/promote nothing for repeated reboots, crashes/OOM, lost WAN/DNS/VPN,
missing clients, unexpected certificate changes, unauthorized WAN replies
or sustained memory/fd growth. Preserve logs in private storage and return to
the known-good slot using the validated controller/fallback procedure.

Permanent promotion is a separate explicit decision after functional checks.
A successful short soak does not establish crash freedom or factory-reset
restore capability. WTFast remains an existing broken optional feature
(unchanged old OpenSSL dependencies); do not reinstall obsolete crypto.

## Read-only command examples for the evening session

On the wired computer in the saved artifact directory:

```sh
sha256sum -c SHA256SUMS
ping -c 300 192.168.0.1
```

In the authenticated router SSH session (save output privately):

```sh
nvram get firmver
nvram get buildno
nvram get extendno
nvram get https_lanport
nvram get https_crt_gen
uptime
free
pidof httpd dnsmasq wanduck infosvr wsdd2
ip route show
ip -6 route show
iptables-save
ip6tables-save
```

For repeated PID/fd/RSS snapshots, inspect /proc/PID/status and /proc/PID/fd
for those recorded PIDs; a changed PID means restart, not successful memory
reclamation. Keep logs local because rules/routes can reveal private network
details. Do not run `nvram show`, `nvram commit`, firewall flushes or service
restarts as part of a read-only baseline. Certificate and browser requests
must use the actual configured HTTPS port/name, not an assumed 443/8443.
