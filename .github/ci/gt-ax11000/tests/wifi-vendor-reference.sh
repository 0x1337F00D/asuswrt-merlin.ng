#!/usr/bin/env bash
# Offline, synthetic initialization probe; NOT a steering/hardware safety gate.
set -euo pipefail
umask 077
: "${WIFI_REFERENCE_ROOTFS:?Set the extracted W9 firmware rootfs, not the older build staging tree}"
: "${WIFI_REFERENCE_QEMU:?Set an existing qemu-arm binary}"
: "${DIAGNOSTICS_LINKER:?Set the pinned ARM compiler}"
export TMPDIR=${TMPDIR:-/tmp}
[[ $(findmnt -n -o FSTYPE -T "$TMPDIR") == tmpfs ]]
root=$(realpath "$WIFI_REFERENCE_ROOTFS")
qemu=$(realpath "$WIFI_REFERENCE_QEMU")
tests=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
check() { [[ $(sha256sum "$root/$1" | cut -d ' ' -f 1) == "$2" ]]; }
# Exact files verified against the installed router on 2026-09-09. No blobs
# are downloaded, modified, committed, or executed on the physical router.
check usr/sbin/bsd af4f653e017e8daf27058bcb2b28d2f80acbae034456c668ad7613c48b818f84
check usr/lib/libshared.so 2b6d17e434666325e693ebe5924ce031bedc4493e9824146820a34da0b36ac9f
check lib/libc.so.6 ba92e7b4d99da8c0f92205dd3d017cc93999744366c7cc31744c96b50edc7970
[[ $(findmnt -n -o FSTYPE -T /dev/shm) == tmpfs ]]
# Keep executables outside the /tmp mount hidden inside the child namespace.
trial=$(mktemp -d /dev/shm/wifi-vendor-reference.XXXXXX)
mkdir "$trial/usr"
cp -a "$root/lib" "$trial/lib"
cp -a "$root/usr/lib" "$trial/usr/lib"
cp "$root/usr/sbin/bsd" "$trial/bsd"
cp "$qemu" "$trial/qemu-arm"
chmod 700 "$trial/bsd" "$trial/qemu-arm"
"$DIAGNOSTICS_LINKER" -Wall -Wextra -Werror -fPIC -shared \
    "$tests/wifi-vendor-fixture.c" -o "$trial/fixture.so"
set +e
(
    ulimit -c 0
    ulimit -f 4096
    # The shell, not qemu, must be PID 1 so guest fatal signals work normally.
    # Private /run and /tmp; no network interfaces/routes to the real router.
    timeout -k 2 8 unshare --user --map-root-user --net --mount --pid --fork --kill-child \
      /bin/sh -c '
        mount -t tmpfs tmpfs /tmp && mount -t tmpfs tmpfs /run && cd /tmp || exit 70
        "$1/qemu-arm" -L "$1" -E "LD_LIBRARY_PATH=$1/lib:$1/usr/lib" \
          -E "LD_PRELOAD=$1/fixture.so" "$1/bsd" -F
        result=$?; exit "$result"
      ' sh "$trial"
) > "$trial/initialization.log" 2>&1
result=$?
set -e
[[ $result == 124 ]] || { echo "Fixture exited with $result; inspect $trial/initialization.log" >&2; exit 1; }
! rg -qi 'segmentation fault|uncaught target signal|core dumped' "$trial/initialization.log"
rg -q 'Tri-Band Smart Connect' "$trial/initialization.log"
for radio in eth6 eth7 eth8; do rg -q "fixture wl_ioctl $radio 14" "$trial/initialization.log"; done
echo "BSD_FIXTURE_INITIALIZATION_ONLY=PASS log=$trial/initialization.log"
echo "No real station/steering/driver test; historical crashes remain unreproduced."
