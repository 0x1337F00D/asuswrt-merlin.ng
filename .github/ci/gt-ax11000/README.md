# GT-AX11000 CI overlay

This directory contains the complete local build overlay for the GT-AX11000.
The upstream Asuswrt-Merlin source tree remains unchanged in Git. CI checks out
the current `RMerl/asuswrt-merlin.ng` `main` branch, applies both patches only in
the ephemeral runner workspace, and uploads the firmware plus build log as a
short-lived artifact.

The top-level build stays at `-j1` because the router Makefile has unordered
clean/build prerequisites. Kernel, module, and supported package builds still
use their existing internal `PARALLEL_BUILD` setting.

CI prepares independent Autotools packages with up to four workers and keeps a
2 GiB `ccache` for the HND cross-compilers. The cache is keyed by toolchain,
upstream source, and overlay revisions; the multi-gigabyte build tree itself is
never cached.

The experimental phased router build is opt-in through
`ASUSWRT_ROUTER_PHASED_BUILD=1`. It runs `clean-build`, then
`kernel_header version fsbuild`, and finally the package graph with the worker
limit from `ASUSWRT_ROUTER_PACKAGE_JOBS`. The package phase clears
`PARALLEL_BUILD`, so recursive package builds share its GNU make jobserver.
Keep the top-level `ASUSWRT_MAKE_JOBS` at `1`; start package testing at `2`.
