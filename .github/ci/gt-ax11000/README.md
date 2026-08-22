# GT-AX11000 CI overlay

This directory contains the complete local build overlay for the GT-AX11000.
The upstream Asuswrt-Merlin source tree remains unchanged in Git. CI checks out
the exact upstream and toolchain commits recorded in `inputs.lock`, applies the
canonical `patches/series` only in the ephemeral runner workspace, verifies the
actual binary Git diff against its locked SHA-256, and uploads the firmware plus
build metadata and log as a short-lived artifact. Moving `main` or `master`
heads are never release inputs.

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
the headers/filesystem plus foundational OpenSSL and Netfilter libraries, then
the package graph. The package graph defaults to one top-level job and retains
the proven package-internal `PARALLEL_BUILD`; pilots with two top-level jobs
found undeclared OpenSSL, Netfilter and `libdisk` staging dependencies.

`ROUTER_PACKAGE_JOBS=2` remains an explicit experimental mode. In that mode
`PARALLEL_BUILD` is cleared so recursive packages share the two-job GNU Make
jobserver rather than creating nested worker pools. It is intentionally not
enabled in GitHub Actions until the upstream graph has complete dependencies.
StrongSwan now follows the selected strategy instead of always starting a
private eight-job pool.

CI prepares independent Autotools packages with up to four workers and keeps a
2 GiB `ccache` for the HND cross-compilers. The cache is keyed by toolchain,
upstream source, and overlay revisions; the multi-gigabyte build tree itself is
never cached.

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
