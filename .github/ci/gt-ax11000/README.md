# GT-AX11000 CI overlay

This directory contains the complete local build overlay for the GT-AX11000.
The upstream Asuswrt-Merlin source tree remains unchanged in Git. CI checks out
the current `RMerl/asuswrt-merlin.ng` `main` branch, applies both patches only in
the ephemeral runner workspace, and uploads the firmware plus build log as a
short-lived artifact.

The top-level build stays at `-j1` because the router Makefile has unordered
clean/build prerequisites. Kernel, module, and supported package builds still
use their existing internal `PARALLEL_BUILD` setting.
