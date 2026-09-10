# Firmware iterations

The deployed fb093681 image is legacy alpha1. The next candidate is alpha2,
reserved by the committed `firmware-iteration` file. Increment this integer
before building each new candidate; never reuse a number for changed sources.
Rebuilding the identical candidate keeps its number for reproducibility.
Local and CI builds use the same committed reservation, not independent counters
or GitHub run numbers. Concurrent release branches must reserve distinct numbers
before publishing; this file is not a distributed automatic allocator.

build.sh generates an isolated version.conf using the upstream-supported
ASUSWRTVERSIONCONFDIR include. No upstream version file is modified. The iteration
and generator are included in prepared-source identity: changing the number
invalidates fast/relink reuse and requires a full build. Output filenames and
the generated RT_EXTENDNO header must agree before publication. The build emits
FIRMWARE-VERSION.json and records firmware_suffix in BUILD-STATE.txt.

Pass that candidate's FIRMWARE-VERSION.json to render_guard.py --version-file.
No implicit alpha1 default is accepted; the rendered guard checks actual runtime
NVRAM version plus exact binary/web hashes. Never rewrite NVRAM merely to rename
an installed image. Original hashes remain the authoritative artifact identity.

Tests cover strict number parsing, changed upstream layouts, GNU Make recursive
version propagation and guard injection rejection. A full alpha2 build and
hardware check remain required; the running alpha1 router is unchanged.
