#!/usr/bin/env bash
# Execute the C caller against ARM Rust, not just a cross-compilation check.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/asuswrt-arm-security-target}
export RUSTFLAGS='-Dwarnings -Ctarget-cpu=cortex-a9'
ARM_CC=${ARM_CC:-arm-linux-gnueabi-gcc}
ARM_QEMU=${ARM_QEMU:-qemu-arm}
ARM_SYSROOT=${ARM_SYSROOT:-/usr/arm-linux-gnueabi}
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/arm-security-abi.XXXXXX")
# Cargo resolves the vendored crates.io mapping from the working directory.
cd "$root/rust"
cargo +1.85.1 build --manifest-path "$root/rust/Cargo.toml" --release \
    --locked --offline --target armv7-unknown-linux-gnueabi \
    -p router-security -p httpd-parsers -p zlib-static
"$ARM_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror -O2 \
    "$root/tests/c-abi/router-security.c" \
    "$CARGO_TARGET_DIR/armv7-unknown-linux-gnueabi/release/librouter_security.a" \
    -ldl -lpthread -lm -lrt -lutil -o "$fixture_dir/router-security"
timeout 20 "$ARM_QEMU" -L "$ARM_SYSROOT" "$fixture_dir/router-security" "$fixture_dir"
for fixture in clientlist zlib; do
    archive=libhttpd_parsers.a
    [[ $fixture != zlib ]] || archive=libzlib_static.a
    "$ARM_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror -O2 \
        -I"$root/tests/c-abi/include" "$root/tests/c-abi/$fixture.c" \
        "$CARGO_TARGET_DIR/armv7-unknown-linux-gnueabi/release/$archive" \
        -ldl -lpthread -lm -lrt -lutil -o "$fixture_dir/$fixture"
    timeout 20 "$ARM_QEMU" -L "$ARM_SYSROOT" "$fixture_dir/$fixture" "$fixture_dir"
done
echo "ARM_SECURITY_ABI=PASS fixture_dir=$fixture_dir (includes symlink and FIFO rejection)"
