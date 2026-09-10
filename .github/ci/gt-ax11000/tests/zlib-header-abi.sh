#!/usr/bin/env bash
# Compile/run against the configured Linux zlib header for each supported
# consumer macro combination. Optional QEMU arguments select the ARM run.
set -euo pipefail
if [[ $# != 3 && $# != 5 ]]; then
    echo "usage: $0 CC LIBRARY_DIR OUTPUT_DIR [QEMU SYSROOT]" >&2
    exit 2
fi
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cc=$1
library_dir=$(readlink -f "$2")
output_dir=$(readlink -f "$3")
include=${ZLIB_ABI_INCLUDE:-$root/c-abi/include}
for variant in native large64 offset64 both; do
    flags=()
    case $variant in large64|both) flags+=(-D_LARGEFILE64_SOURCE=1);; esac
    case $variant in offset64|both) flags+=(-D_FILE_OFFSET_BITS=64);; esac
    # ./configure enables these two branches in firmware zconf.h. Enabling
    # their original HAVE_* guards is equivalent, while keeping the locked
    # input header untouched. ZLIB_ABI_INCLUDE may point at the actual build.
    "$cc" -std=c11 -D_POSIX_C_SOURCE=200809L \
        -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 "${flags[@]}" \
        -Wall -Wextra -Werror -O2 -I"$include" "$root/c-abi/zlib-shared.c" \
        -L"$library_dir" -lz -o "$output_dir/zlib-shared-$variant"
    echo "zlib configured-header variant: $variant"
    if [[ $# == 5 ]]; then
        timeout 30 "$4" -L "$5" -E "LD_LIBRARY_PATH=$library_dir" \
            "$output_dir/zlib-shared-$variant"
    else
        LD_LIBRARY_PATH="$library_dir" timeout 30 "$output_dir/zlib-shared-$variant"
    fi
done
