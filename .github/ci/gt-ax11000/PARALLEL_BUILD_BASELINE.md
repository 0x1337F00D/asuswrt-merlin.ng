# GT-AX11000 parallel-build reference

This is the durable A/B reference for the first package-DAG pilot. Both builds
used upstream `088512a1296e361d65e5429e7d8d61ef3fdf4c86`, profile `94908HND`,
kernel configuration SHA-256
`ccc88a96d4c5e9f20865eed2fc255231b639b46e71b71a6432c368f0608ee1ba`,
Rust 1.85.1 and the same local toolchain state.

| Build | Router tokens | Vendor time | End-to-end | Result |
|---|---:|---:|---:|---|
| Stable v4 | 1 | 678 s | 682 s | reference |
| Package DAG v6 | 16 | 716 s | 719 s | successful, reference-equivalent |

The 16-token run is a correctness proof for the current coarse DAG, not a
performance default. It was 37 seconds (5.4%) slower end-to-end. The kernel is
rebuilt before package parallelism can help, and 16 package tokens add enough
scheduling and memory-pressure overhead to erase the package-phase gain.

## Rootfs comparison

Both root filesystems contain 2,812 regular files, 546 symbolic links and 3,065
non-link mode entries. Every path, symlink target and mode is identical. Of the
2,812 regular files, 2,807 are byte-identical. The five explained differences
are:

- `bin/busybox`: identical size, sections and symbols; only three copies of the
  embedded build timestamp differ (15 bytes total).
- `usr/lib/libshared.so`: identical size, sections and symbols; only its
  embedded build timestamp differs (6 bytes total).
- `rom/etc/motd` and `rom/etc/image_version`: generated build-time metadata.
- `lib/modules/4.1.51/modules.dep`: all 185 modules have exactly the same
  dependency sets; only dependency ordering differs.

Reference manifest digests:

```text
ROOTFS-CONTENT.sha256  b0ddeb8459817aff7687870f4da0c137279a06eea2d5d74d68b4df6819765b35
ROOTFS-MODES.manifest  920a950f53ff4950527ab4b1ab0d6ed1a436c4afac229c2a5f2a653ec6bf7e51
ROOTFS-SYMLINKS        9d0e8e4f2d706ab8f1b2fb526db0dd26f5d1b27328fb2cb5be9a25c0bf4efe9a
```

## Four-token kernel-reuse validation

The hosted-runner candidate uses four shared router tokens and an exact kernel
cache. A local no-ccache seed build completed in 17:30; the identical
contract-verified reuse build completed in 9:28, a 46% wall-time reduction.
The cache restores the complete SDK kernel directory and the installed
`94908HND` modules. It is accepted only with an exact successful-build state
file and explicit image, config, DTB and module checks. There are no prefix or
partial restore keys.

Both extracted root filesystems contain 2,812 files and 546 links, with
identical paths, link targets and modes. Kernel modules are byte-identical.
Only five generated outputs differ: the BusyBox and `libshared` embedded build
times, `motd`, `image_version`, and ordering in `modules.dep`.

The four-token run also exposed and fixed a real hidden edge: `openssl`
already invokes `$(OPENSSL)`, so listing both as parallel foundation targets
could compile `openssl-1.1` twice and race on `.d.tmp` files. The foundation
now contains only the public `openssl` target.

The first genuinely clean hosted run exposed a second hidden ordering
assumption that retained local stage files had masked: Netfilter configure
tests could overlap the shared OpenSSL/Netfilter staging producers and fail to
link their probe executables. `router-foundation` is therefore explicitly
`.NOTPARALLEL`; only the much larger package remainder receives the shared
four-token jobserver. This keeps the high-value parallel region while making
the common stage a deterministic prefix.

The next hosted run exposed the same implicit-order problem inside a package:
`lldpd` listed its staged libraries and generated Autoconf `Makefile` as peer
prerequisites, allowing configure to link before those libraries existed.
Every top-level package target now preserves its declared prerequisite order;
independent package targets still run concurrently. This generalizes the fix
without serializing the large package remainder.

A third hosted run then reached `hub-ctrl`, whose top-level target has no
declared edge to its required `libusb10` producer. Together these independent
failures prove that the vendor `obj-y` sequence itself carries undocumented
ordering. Since the local four-token candidate was also slower than the serial
reference, required hosted CI now uses `ROUTER_PACKAGE_JOBS=1`. Parallel mode
remains an opt-in research path; a future version must use a positive safe
whitelist rather than treating the full vendor list as a DAG.

The hosted GitHub Actions serial cold run and exact kernel-cache reuse run now
provide the auditable reference. CI metadata records runner CPU count, router
tokens and all cache-hit states.

The hosted serial cold run completed successfully with every firmware and
runtime gate green and saved a 528 MiB exact kernel archive. Its first reuse
attempt restored and contract-validated that archive, then exposed a redundant
verification mismatch: restored tracked kernel outputs necessarily change the
Git diff after the overlay had already been verified. CI now keeps the
authoritative pre-restore lock attestation and skips only that duplicate
full-tree diff on an exact hit; kernel contract and artifact validation remain
mandatory.

The subsequent reuse build exposed one missing distinction in the vendor
patch: protecting `kernel/.config` had also suppressed recreation of the
Broadcom `SRCBASE/.config` profile symlink. That symlink is not a reusable
kernel output and is now rebuilt on every invocation; only the actual kernel
configuration remains protected. The changed patch contract intentionally
uses a new exact cache key.

The final hosted comparison showed that kernel-only reuse does not shorten the
four-vCPU runner's critical path: the cold reference already served 21,430 of
21,608 cacheable compiler calls (99.18%) from `ccache`. Required CI therefore
adds an exact completed-vendor-tree cache and uses the already gated
`rust-fast` relink/repack path for cache-compatible Rust-only changes. This
removes Clean/Configure/Link work from the common iteration without enabling
the unsafe package DAG. Scheduled and manually forced clean runs remain the
release reference.

## Exact vendor-tree cache pilot

The corrected clean seed in GitHub Actions run 45 compiled the firmware in
41:35 and completed the firmware job in 45:30. Rust, security-overlay, ARM ISA,
QEMU runtime, manifest, input-lock and artifact gates all passed. Saving the
roughly 2.2 GiB compressed exact vendor state added 27 seconds after artifact
upload. The cache remains within the hosted repository cache budget and no
self-hosted runner is involved.

An earlier five-minute fast-path pilot was deliberately rejected: extracted
images showed that four Rust consumers matched, while `httpd` had been
recompiled with a smaller link context. The generic recursive install target
was replaced by `httpd-rust-install`, which only relinks the complete cached C
object set with the current Rust archive. CI now hashes that object set before
and after the relink and, for an unchanged Rust state, demands byte-identical
post-strip binaries for all five consumers. Only a cache-hit run passing those
new gates is a valid fast-path reference.

The extracted pilot also exposed three empty `rom/rom`, `rom/rom/modules` and
`rom/rom/scripts` directories that existed only after the repeated repack.
They are legacy optional-payload containers created by `fsbuild`; the common
finalizer now removes them only when empty. Cache schema v2 compares a
timestamp/ownership-normalized archive of the entire final rootfs before and
after every fast build, including paths, types, modes and link structure. The
generated and separately validated `rom/etc/image_version` is the sole normal
exclusion when Rust itself is unchanged.
