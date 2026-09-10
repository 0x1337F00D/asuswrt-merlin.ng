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
    -p router-security -p httpd-parsers -p zlib-static -p zlib-shared
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
# The rootfs libz.so.1, linked exactly as release/src/router/Makefile links it
# and executed on ARM.  Everything in the firmware that links -lz resolves
# these symbols at run time, so the version script and the export set have to
# hold up in a real dynamic link, not only in a cross-compilation check.
"$ARM_CC" -shared -static-libgcc -o "$fixture_dir/libz.so.1" \
    -Wl,-soname,libz.so.1 \
    -Wl,--version-script="$root/rust/zlib-shared/libz.map" \
    -Wl,--gc-sections -Wl,--no-undefined \
    -Wl,--whole-archive \
    "$CARGO_TARGET_DIR/armv7-unknown-linux-gnueabi/release/libzlib_shared.a" \
    -Wl,--no-whole-archive -lpthread -ldl -lm
# -lz resolves the SONAME-less development name, which the rootfs gets from
# the vendor zlib package; provide it here so the fixture links the object
# under test rather than a sysroot copy.
ln -sf libz.so.1 "$fixture_dir/libz.so"
# The plain and the 64-bit combine entry points must not share an address:
# the plain one has to sign-extend its 32-bit length into the register pair
# the implementation reads, so an alias silently feeds it a garbage high word.
"${ARM_CC%-gcc}-nm" -D --defined-only "$fixture_dir/libz.so.1" \
    | grep -E ' (crc32_combine|crc32_combine64|adler32_combine|adler32_combine64)$' \
    | sort | sed 's/^/libz.so.1 dynsym: /'
"$ARM_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror -O2 \
    -I"$root/tests/c-abi/include" "$root/tests/c-abi/zlib-shared.c" \
    -L"$fixture_dir" -lz -o "$fixture_dir/zlib-shared"
timeout 60 "$ARM_QEMU" -L "$ARM_SYSROOT" -E "LD_LIBRARY_PATH=$fixture_dir" \
    "$fixture_dir/zlib-shared"
echo "ARM_SECURITY_ABI=PASS fixture_dir=$fixture_dir (includes symlink and FIFO rejection)"
