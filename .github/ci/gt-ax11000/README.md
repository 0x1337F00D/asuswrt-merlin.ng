# GT-AX11000 CI overlay

This directory contains the complete local build overlay for the GT-AX11000.
The upstream Asuswrt-Merlin source tree remains unchanged in Git. CI checks out
the exact upstream and toolchain commits recorded in `inputs.lock`, applies the
canonical `patches/series` only in the ephemeral runner workspace, verifies the
actual binary Git diff against its locked SHA-256, and uploads the firmware plus
build metadata and log as a short-lived artifact. Moving `main` or `master`
heads are never release inputs. The diff is staged in a temporary index and
uses full object IDs, so its hash is independent of the clone's object count
and local `core.abbrev` setting.

The scheduled upstream workflow never changes `main`. It merges a new
`RMerl/main` into `upstream-sync/<sha>`, recomputes the locked patched-source
diff and opens or updates a draft pull request. The separate `Rust`,
`Security overlay` and `Firmware` checks must pass before review and merge.

Local builds can set `ASUSWRT_REQUIRE_TMPFS=1` to fail closed unless the source
repository, build worktree, firmware output, temporary directory, build home,
Cargo directories, generated host tools and optional compiler cache all reside
on `tmpfs`. This protects the local SSD. GitHub Actions stays on the hosted
runner filesystem because the full checkout and clean worktree exceed the RAM
budget of the standard hosted runner; no self-hosted runner is required.

The SDK top-level build stays at `-j1`. For HND routers, an ephemeral patch
orders the unsafe router prerequisites into three phases: `clean-build`, then
the headers/filesystem, then a package DAG. The package DAG has a serial
foundation for OpenSSL, `shared`, NVRAM, `libdisk` and Netfilter staging, a GNU
Make 4.4 `.WAIT` barrier and a parallel remainder. Explicit edges and local
serialization cover the races found in `libdisk`, `calc_nvram`, `libwebapi`
and `mapd`; the traceroute dependency list is also compatible with GNU Make
4.4.1. The build bootstraps that checksum-pinned Make release into RAM.

`ROUTER_PACKAGE_JOBS=N` is an explicit experimental mode and defaults to one.
When `N` is greater than one, `PARALLEL_BUILD` is cleared so recursive packages
share one GNU jobserver. StrongSwan and Samba no longer start private eight-job
pools. A 16-token reference run completed and produced the same rootfs graph as
the serial reference, but took 719 instead of 682 seconds on the local
16-thread host. Three genuinely clean hosted four-token runs then exposed
different implicit-order failures in Netfilter, `lldpd`, and `hub-ctrl`/libusb.
Required CI therefore remains at the faster stable serial default. Full-DAG
parallelism stays available only as a manual experiment until a positive safe
package whitelist passes repeated clean-build and extracted-rootfs equivalence
gates. Reusable, contract-bound build state is the supported CI speedup.
The durable comparison is recorded in `PARALLEL_BUILD_BASELINE.md`.

CI keeps a 2 GiB `ccache` for the HND cross-compilers. The cache is keyed by toolchain,
upstream source, and overlay revisions. It also keeps one exact kernel cache,
containing the complete kernel tree and installed profile modules. Reuse has no
fallback key: the successful-build state file must match the upstream, full
patch/preparation state, profile, toolchain and pinned GNU Make contract, and
the expected kernel image, configs, DTBs and modules must all exist. A mismatch
fails closed. Locally, this reduced the same no-ccache four-token build from
17:30 to 9:28 (46%); the extracted filesystems retained all 2,812 files, 546
links and modes, with only embedded build time, generated image version and
unordered `modules.dep` differences.
CI verifies the complete patched-source diff immediately before restoring the
kernel archive. On an exact hit the redundant in-script full-tree diff is
disabled because the restored tracked kernel build outputs are expected to
change that diff; the cache contract and explicit artifact checks still fail
closed, and the pre-restore lock attestation is embedded in build metadata.

The hosted runner already reaches roughly 99% cache hits for cacheable C/C++
compilations, so restoring only the kernel did not reduce its critical path.
CI therefore also stores the exact completed vendor build tree. Its key binds
the upstream and toolchain revisions, runner image, Rust target, complete patch
series, input lock, repack rules and build driver, but deliberately excludes
Rust source. A hit selects `rust-fast`: the current Rust tree is synchronized,
all five firmware consumers are rebuilt and checksum-bound into the rootfs, and
the image is repacked and verified. Patch, profile, toolchain, runner-image or
upstream changes miss the cache and take the normal clean path. The weekly
scheduled build and a manual `force_clean` dispatch never restore generated
vendor state. A lookup-only probe lets a successful clean gate seed a missing
exact cache without trying to overwrite an existing immutable key. Restore and
save are separate actions so this policy cannot accidentally overlay a
forced-clean workspace.

The cached `httpd` path is intentionally a relink, not a recursive package
install. It requires every C object from the completed clean build, records
their hashes, links only those objects against the current Rust archive and
fails if any object changes. When the Rust state itself is unchanged, CI also
requires all five stripped firmware consumers to remain byte-identical across
the fast cycle. This gate caught an earlier generic `httpd-install` shortcut
that silently rebuilt C objects outside the full router target context; that
result is excluded from performance claims.

Cache schema v2 also binds the hosted runner image and a centralized effective
build contract (top-level jobs, preparation jobs, router-package jobs, ccache,
direct-toolchain mode and clean profile selection). On an exact vendor hit CI
fetches only the locked upstream commit/tree metadata and restores the already
gated release tree; it does not materialize 5.6 GiB merely to overwrite it.
The independent security-overlay job still proves the complete patched diff.
It hydrates only the exact files named by the patch series plus the single
unmodified configuration file inspected by the hardening gate, instead of a
second multi-gigabyte vendor checkout.
Before and after every fast build, normalized, diffable manifests cover the
entire final rootfs—contents, paths, types, modes, symlinks and hardlink
groups—with only the validated generated `rom/etc/image_version` excluded.
Rust changes may
additionally exclude exactly the five consumers already covered by freshness,
manifest, ISA and QEMU gates.

The cache contains the expensive compiled vendor prerequisite tree. The common
`rust-repack.mk` finalizer is deliberately consumed live rather than treated as
a cache prerequisite: it always reruns, and the complete rootfs gate rejects
any unexplained path, mode, link or content change. Finalizer-only correctness
fixes therefore do not force another clean compile.

## Fast Rust iteration

A clean build is still the release gate after an upstream, patch, toolchain or
board-profile change. Pure changes below `rust/` use the shorter cycle:

```sh
ASUSWRT_DEV_BUILD_MODE=rust-fast \
ASUSWRT_FORCE_PROFILE=0 \
ASUSWRT_REQUIRE_TMPFS=1 \
RUST_HOST_TARGET_DIR=/tmp/asuswrt-rust-host-target \
RUST_TARGET_DIR=/tmp/asuswrt-rust-target-armv7 \
bash .github/ci/gt-ax11000/dev-cycle.sh
```

The prepared vendor-tree state is keyed only by upstream, the patch series and
the source-mutating preparation functions. Rust has a separate state identifier and is synchronized on
every run with `rsync --delete`. Consequently, editing one Rust source no longer
resets roughly half a million vendor files or reruns Autotools. After one
successful full build, `rust-fast` rebuilds and installs only the five Rust
consumers, reruns rootfs assembly and repacks the existing kernel. It refuses
an upstream, patch, profile or preparation-state mismatch. Cargo is still
invoked for every firmware consumer; its fingerprints decide what is reused.
The build then requires fresh installs of `infosvr`, `rstats`,
`Notify_Event2NC`, `httpd` and `rc`, creates checksums for them, produces exactly
one fresh firmware image and runs the ARM ISA/QEMU verifier.
The prerequisite full-build contract also binds the generated SDK/router/kernel
configuration, toolchain identity, pinned Rust compiler, ARM target and CPU
flags. The repack compares the exact SHA-256 values of all five post-strip
package artifacts with the completed rootfs, so a copied stale binary fails the
cycle even if its timestamp is new.

Clean, fast and Rust-fast builds all finish through the same manifest-bound
repack. `www-install` must leave a fresh nested staging tree; the finalizer then
replaces the complete Web payload, records every regular-file hash and every
symbolic-link target, and embeds both manifests in immutable
`/usr/share/codex`. (`/etc` is a volatile `/tmp/etc` link on this platform.) Host verification
checks the exact path counts, all 25 equal-length language dictionaries,
numeric AUTODICT bounds and fixed English/German semantic sentinels before an
image can be published. The persistent router guard rechecks the embedded
manifests before it may promote a trial slot.

For a change confined to the authenticated HTTP boundary or its Web page, the
platform makefile also exposes `rust-ui-httpd-relink`. It preserves the HND
platform exports, rebuilds only `httpd` and the complete AUTODICT Web payload,
and then uses the same idempotent firmware repack. Compressed ASP pages and all
language dictionaries are one inseparable generated set: the repack refuses a
missing nested staging tree and atomically replaces the old flat `/www` tree
with the complete new set. It also promotes only the five known consumer
artifacts and removes their package staging roots, preventing `/httpd`, `/rc`
or `/www/www` duplicates.

The local loop intentionally leaves router installation outside the build
script. A candidate is transferred only to router RAM, checked with
`firmware_check`, written to the inactive partition, armed with the matching
`BOOT_SET_PART*_IMAGE_ONCE` state, tested, and rebooted back to the previous
partition. Promotion or boot-partition commit is never part of an automated
test cycle.

After the one-shot candidate has booted, the two bounded live gates are:

```sh
sh -s -- Second BOOT_SET_PART1_IMAGE 3.0.0.6 102.8 2 \
  < .github/ci/gt-ax11000/tests/router-health.sh
python3 .github/ci/gt-ax11000/tests/infosvr-live.py 192.168.0.1
```

The second argument is an expected, already-consumed fallback state observed
after boot; it is never written by the health script. The first command is
intended to be provided as standard input to the
configured SSH transport. In addition to the running partition it verifies
that the consumed one-shot state already points the next reboot back to the
known-good partition and that supervised service PIDs remain stable throughout
the gate. The second sends only read-only discovery PDUs and
checks exact sizes, rejected malformed inputs, transaction preservation and a
stable AiMesh group ID. Neither test prints SSIDs, MAC addresses, keys or packet
contents.
