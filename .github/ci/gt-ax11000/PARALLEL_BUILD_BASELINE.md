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

## Bounded next experiment

First add phase timing and a full-contract-bound kernel artifact fingerprint.
Then run only `ROUTER_PACKAGE_JOBS=2`, `4` and `8` against this reference,
stopping as soon as elapsed time stops improving. Any candidate must pass the
same path, symlink, mode and normalized-content comparison before it can become
the default.
