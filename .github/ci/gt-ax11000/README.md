# GT-AX11000 CI overlay

This directory contains the complete local build overlay for the GT-AX11000.
The upstream Asuswrt-Merlin source tree remains unchanged in Git. CI checks out
the current `RMerl/asuswrt-merlin.ng` `main` branch, applies the patches only in
the ephemeral runner workspace, and uploads the firmware plus build log as a
short-lived artifact.

`advanced-testlab-ui.patch` adds a GT-AX11000-only Advanced Wireless page for
temporary test-lab controls. It exposes all chanspecs reported by the active
Broadcom regulatory domain for all three radios, applies them only to the live
driver, and restores the configured chanspec automatically after ten minutes.
It never writes or commits NVRAM. Country, territory, regrev, and TX-power
values are diagnostic-only; `ALL`, `#a`, or power values above 100 block radio
changes. A separate temporary IPv6 FORWARD chain can be enabled without
changing WAN DHCP or persistent firewall configuration.

The top-level build stays at `-j1` because the router Makefile has unordered
clean/build prerequisites. Kernel, module, and supported package builds still
use their existing internal `PARALLEL_BUILD` setting.

CI prepares independent Autotools packages with up to four workers and keeps a
2 GiB `ccache` for the HND cross-compilers. The cache is keyed by toolchain,
upstream source, and overlay revisions; the multi-gigabyte build tree itself is
never cached.
