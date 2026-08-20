# GT-AX11000 CI overlay

This directory contains the complete local build overlay for the GT-AX11000.
The upstream Asuswrt-Merlin source tree remains unchanged in Git. CI checks out
the current `RMerl/asuswrt-merlin.ng` `main` branch, applies the patch series only in
the ephemeral runner workspace, and uploads the firmware plus build log as a
short-lived artifact.

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
