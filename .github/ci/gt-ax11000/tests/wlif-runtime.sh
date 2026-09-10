#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixture_dir="$(mktemp -d /tmp/gt-wlif-runtime.XXXXXX)"
# Extract the actual new source files; no copy of the process algorithm.
git -C "$fixture_dir" apply --unsafe-paths \
  --include='release/src/router/shared/wlif_process.h' \
  --include='release/src/router/shared/wlif_process.c' \
  --include='release/src/router/shared/wlif_exec.c' \
  "$root/../patches/wlif-shell-hardening.patch"
source_dir="$fixture_dir/release/src/router/shared"
compiler="${WLIF_RUNTIME_CC:-cc}"
binary_suffix=""
fixture_flags=()
if [ -n "${WLIF_RUNTIME_QEMU:-}" ]; then
  : "${WLIF_RUNTIME_SYSROOT:?QEMU tests require an explicit ARM sysroot}"
  binary_suffix=".arm"
  fixture_flags=(-DWLIF_FIXTURE_UNDER_QEMU)
fi
"$compiler" -std=gnu11 -Wall -Wextra -Werror -O2 \
  -DWLIF_CLI_TIMEOUT_MS=200 -DWLIF_CLI_DIRS="\"$fixture_dir\"" \
  "$source_dir/wlif_exec.c" -o "$fixture_dir/wlif-exec$binary_suffix"
"$compiler" -std=gnu11 -Wall -Wextra -Werror -O2 -pthread \
  "${fixture_flags[@]}" \
  -D_GNU_SOURCE -DWLIF_CLI_TIMEOUT_MS=200 \
  -DWLIF_HELPER_PATH="\"$fixture_dir/wlif-exec\"" \
  -DWLIF_TEST_DIR="\"$fixture_dir\"" -I"$source_dir" \
  "$source_dir/wlif_process.c" "$root/wlif-runtime.c" \
  -o "$fixture_dir/hostapd_cli$binary_suffix"
if [ -n "$binary_suffix" ]; then
  # Native launch bridges affect exec mechanics only; no global binfmt or
  # privileged setup. Both process implementations run as ARM executables.
  for program in wlif-exec hostapd_cli; do
    "${WLIF_RUNTIME_HOST_CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -O2 \
      -D_GNU_SOURCE -I"$source_dir" \
      -DWLIF_FIXTURE_QEMU="\"$WLIF_RUNTIME_QEMU\"" \
      -DWLIF_FIXTURE_SYSROOT="\"$WLIF_RUNTIME_SYSROOT\"" \
      "$root/wlif-runtime.c" -o "$fixture_dir/$program"
  done
  echo "ARM runtime uses native exec bridges (no binfmt); not native firmware execution"
fi
if [ "${WLIF_RUNTIME_COMPILE_ONLY:-0}" != 1 ]; then
  "$fixture_dir/hostapd_cli"
fi
echo "Fixture retained in $fixture_dir"
