# Alpha4 build and offline verification

Firmware source commit: `4d093a1878826084bea7c525d5fde5472c484e67`.
Branch: `codex/tier3-implementation`. Router untouched; no installation,
boot selection, NVRAM change, private-key extraction or router load test.
Independent agent review was not requested for this iteration; self-review.

## Changes

- infosvr: permanent per-interface ingress binding BEFORE UDP port activation;
  no outbound unbind. LAN source-IP checks retained. Replies still use port
  9999. Uses the already vendored libc 0.2.189, not a new downloaded dependency.
- wsdd2: eight-slot nonblocking metadata pool instead of synchronous reads;
  8 KiB requests, 64 KiB reply ceiling, two-second absolute connection budget,
  bounded operations per iteration. UDP discovery and signals keep progressing.
  Syslog transport is nonblocking. No threads, async runtime or new crates.
- httpd: existing certificates/keys survive unsupported credentials and TLS
  initialization errors; HTTPS fails closed. Explicit user regeneration and
  empty factory configuration retain certificate generation behavior.
- awsiot: unused mssl link omitted only in this model's Rust overlay;
  actual OpenSSL transport remains. No global OpenSSL replacement.
- Alpha4 local wrapper enforces the input lock before Rust overlay copying.

## Completed source/native checks

- 603 native workspace Rust cases and clippy with warnings denied.
- 125 wsdd2/mssl ARM release cases under QEMU with the Broadcom soft-float
  toolchain, plus whole-workspace ARM cross-check with warnings denied.
- C ABI suite, including seven TLS adapter cases: RSA/EC, six simultaneous
  connections per identity, TLS 1.2/1.3, fragmented HTTP, failed/mismatched
  rotation preserving the previous identity, timeout and descriptor ownership.
- Fuzz smoke: 250000 iterations for each of three seeds (750000 total).
- 35 fake-transport trial/backup/controller tests. No router calls.
- Source overlay, network hardening, private firewall capture, relink/repack,
  version/input-lock/copy/gate checks; 18 workflow tests after trigger fix.
- Executed extracted httpd start_ssl with synthetic C stubs in four lifecycle
  cases; the alpha3 function fails the credential-preservation negative control.

## Linux namespace tests (not router hardware)

- Real native infosvr: positive LAN reply with source port 9999; spoofed
  LAN-source WAN unicast/multicast silent. Single- and multiple-interface
  startup pass. The alpha3 binary FAILS this same WAN-isolation test.
- Real native wsdd2: UDP discovery and termination remain responsive with
  two silent TCP clients; alpha3 times out in the same regression test.
- Real native wsdd2 and lld2d: artificial WAN-side probes get no reply;
  LAN-side probes produce WS-Discovery/LLTD responses. IPv4/Ethernet only.
- wsdd2 host resource run: 120 rounds, 1440 connections, six SIGHUP reloads;
  fd baseline/peak/final 8/16/8, RSS 2580→2640 KiB. No sustained descriptor
  leak in this run. An initial stricter stress invocation hit a client connect
  timeout while exceeding the listen backlog; the bounded retry run records
  refusals rather than confusing overload admission with daemon failure.

Tests require fresh network/mount namespaces and use disposable veth links;
they cannot be directed at the production router by changing a target IP.
The namespace guards and additional CI tests were tightened after the firmware
source freeze; no firmware Rust source or patch changed afterwards.

## Input provenance

Pre-Rust patched-diff SHA-256:
`6873b4232b9322ade0ebbabcb77de6d6d00487d3d6146b1b0f2ed1d68c71c9ed`.
Input lock SHA-256:
`5320cf19274a61a5e1bcceaa8e284b3375dc54863f2b8d7fd4f02a41fd49afae`.
The actual build's lock-state file says `input_lock_status=verified`.
All compilation, caches, intermediates and output are in tmpfs, swap off.
Clean mode, package jobs=1, ccache off; no new parallel build variant.

## Image and CI status

Full clean RAM build completed successfully in 2753 seconds (45m53s).
Artifact: `GT-AX11000_3006_102.9_alpha4_ubi.w`, 78118932 bytes.
SHA-256: `2ec09b692e1beab94e1c042c25c3e6504c4476957b132a445f5c452ed9f709ed`.
Durable artifact directory: `/home/paul/.local/share/gt-ax11000-builds/tier3-alpha4-4d093a18788`.

Final extracted-image checks pass: WFI/UBI structure, staging equivalence
(only expected empty /bootfs mountpoint), version alpha4, 15 Rust hashes,
Web payload/31 symlinks/25 dictionaries, proprietary-QoS exclusion, 16 ARM
consumer gates, libz ABI and runtime tests, preserved libshared exports.
Twelve dynamic TLS/stdio cases pass against the extracted libmssl under ARM
emulation. Scanning all 581 dynamically dependent ELF files confirms httpd
is the only mssl API/link consumer; awsiot no longer links mssl.

The extracted libmssl.so is 997540 bytes and identical to alpha3
(`6677cd0c54f85911e966a127e98c5e62f7b3fce5dceb2319131e3607a52d0bcc`).
wsdd2 shrank from 411280 to 407184 bytes; httpd, infosvr, awsiot and libshared
sizes are unchanged. Total firmware size is unchanged.

Additional extracted ARM wsdd2/lld2d network tests initially FAILED under
QEMU 8.2.2: strace showed IP_MULTICAST_IF returning ENOPROTOOPT, so wsdd2
correctly did not activate that UDP endpoint. This socket option exists in
the target Linux 4.1 source but is not emulated by QEMU 8.2.2. With QEMU
10.0.11, the exact same image binaries pass both LAN/WAN isolation controls;
wsdd2 discovery with silent TCP peers takes 0.002s and shutdown 0.032s.
No firmware change or isolation bypass was used to make the test pass.
The emulator was extracted into tmpfs, not installed on the host. Package
SHA-256: `6b6fea55551fbcc1eb30e146ad5abdfbb49f8fa8c5998016242126de4d7f80df`.
Provenance: [Debian qemu-user package](https://packages.debian.org/trixie/amd64/qemu-user/download).
Original failure logs and successful retests are retained as evidence.

Post-push GitHub CI is pending; local results are not GitHub run evidence.

The Tier-3 branch was absent from the workflow's push triggers, explaining
why its previous push had no runs. The branch trigger is now included and
tested. Only Rust/security/trial gates should run after push, not an additional
GitHub firmware build. No push while the local build is running.

## Open checks and decisions

- Actual router credentials must be preflighted before flash; unsupported
  credentials stop HTTPS rather than being silently replaced. Authenticated
  browser/login/save behavior is not established by synthetic HTTP exchanges.
- WAN IPv6 and Broadcom switch/bridge/offload behavior, dynamic firewall rules,
  Wi-Fi room transitions and actual VPN routing/kill switch require hardware.
  The broad vendor multicast ACCEPT rules were NOT globally rewritten.
- No claim of fairness under indefinite LAN saturation: eight held metadata
  connections can temporarily deny new metadata clients, while discovery
  continues. Protocol/rate limits remain; a per-client admission policy is
  a separate compatibility decision, not an untested extra in alpha4.
- WTFast's unchanged optional binary has missing old OpenSSL dependencies
  already in the reference. Decision for alpha4: do not restore obsolete
  crypto or claim this feature fixed. Feature removal/replacement is deferred
  to a separately tested UI/profile change; no blob replacement is included.
- No hardware/browser test, certificate replacement, permanent promotion or
  factory-reset restore is approved by these offline results.

Evening procedure: [ALPHA4_TEST_PLAN.md](ALPHA4_TEST_PLAN.md).
