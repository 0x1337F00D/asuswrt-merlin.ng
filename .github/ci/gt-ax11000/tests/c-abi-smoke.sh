#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_ROOT/../rust/Cargo.toml"
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-1.85.1}"
TARGET_DIR="${RUST_C_ABI_TARGET_DIR:-/tmp/asuswrt-rust-c-abi-target}"
FIXTURE_DIR="${RUST_C_ABI_FIXTURE_DIR:-/tmp/asuswrt-rust-c-abi-fixtures}"
CARGO_DIR="${RUST_C_ABI_CARGO_HOME:-/tmp/asuswrt-rust-c-abi-cargo}"

if [ "${ASUSWRT_REQUIRE_TMPFS:-0}" = "1" ]; then
	for path in "$TARGET_DIR" "$FIXTURE_DIR" "$CARGO_DIR"; do
		candidate="$path"
		while [ ! -e "$candidate" ] && [ "$candidate" != / ]; do
			candidate="$(dirname "$candidate")"
		done
		[ "$(findmnt -n -o FSTYPE -T "$candidate")" = tmpfs ] || {
			echo "C ABI output path is not tmpfs: $path" >&2
			exit 1
		}
	done
fi

mkdir -p "$TARGET_DIR" "$FIXTURE_DIR" "$CARGO_DIR"
export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_HOME="$CARGO_DIR"

# Cargo resolves the vendored crates.io mapping from the working directory.
cd "$(dirname "$MANIFEST")"
cargo +"$RUST_TOOLCHAIN" build --manifest-path "$MANIFEST" --release \
	--locked --offline -p httpd-parsers -p router-security -p wanduck-transition \
	-p zlib-static -p zlib-shared

common=(-std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror -O2)
libraries=(-ldl -lpthread -lm -lrt -lutil)
cc "${common[@]}" "$SCRIPT_ROOT/c-abi/httpd.c" \
	"$TARGET_DIR/release/libhttpd_parsers.a" "${libraries[@]}" \
	-o "$FIXTURE_DIR/httpd"
# The client list is exported by the same archive httpd links; the fixture
# creates a private SysV segment and needs a writable directory for the
# vendor-style lock and cache files.
cc "${common[@]}" "$SCRIPT_ROOT/c-abi/clientlist.c" \
	"$TARGET_DIR/release/libhttpd_parsers.a" "${libraries[@]}" \
	-o "$FIXTURE_DIR/clientlist"
cc "${common[@]}" "$SCRIPT_ROOT/c-abi/router-security.c" \
	"$TARGET_DIR/release/librouter_security.a" "${libraries[@]}" \
	-o "$FIXTURE_DIR/router-security"
cc "${common[@]}" "$SCRIPT_ROOT/c-abi/wanduck.c" \
	"$TARGET_DIR/release/libwanduck_transition.a" "${libraries[@]}" \
	-o "$FIXTURE_DIR/wanduck"
# The vendor zlib.h/zconf.h (locked upstream copy) is what wget compiles
# against; the fixture links the same archive the firmware wget links.
cc "${common[@]}" -I"$SCRIPT_ROOT/c-abi/include" "$SCRIPT_ROOT/c-abi/zlib.c" \
	"$TARGET_DIR/release/libzlib_static.a" "${libraries[@]}" \
	-o "$FIXTURE_DIR/zlib"
# The rootfs libz.so.1 is linked from the zlib-shared archive with the same
# arguments release/src/router/Makefile uses, so this fixture exercises the
# real shared object: SONAME, version script, --whole-archive, --gc-sections.
# Everything else in the firmware resolves those symbols at run time, so a
# missing export or a broken ZLIB_* node has to fail here.
cc -shared -static-libgcc -o "$FIXTURE_DIR/libz.so.1" \
	-Wl,-soname,libz.so.1 \
	-Wl,--version-script="$SCRIPT_ROOT/../rust/zlib-shared/libz.map" \
	-Wl,--gc-sections -Wl,--no-undefined \
	-Wl,--whole-archive "$TARGET_DIR/release/libzlib_shared.a" \
	-Wl,--no-whole-archive -lpthread -ldl -lm
readelf -d "$FIXTURE_DIR/libz.so.1" | grep -q 'SONAME.*\[libz\.so\.1\]'
for node in ZLIB_1.2.0 ZLIB_1.2.0.2 ZLIB_1.2.0.8 ZLIB_1.2.2 ZLIB_1.2.2.3 \
	ZLIB_1.2.2.4 ZLIB_1.2.3.3 ZLIB_1.2.3.4 ZLIB_1.2.3.5 ZLIB_1.2.5.1 \
	ZLIB_1.2.5.2 ZLIB_1.2.7.1 ZLIB_1.2.9 ZLIB_1.2.12; do
	readelf -V "$FIXTURE_DIR/libz.so.1" | grep -q "Name: $node$" || {
		echo "libz.so.1 does not define version node $node" >&2
		exit 1
	}
done
cc "${common[@]}" -I"$SCRIPT_ROOT/c-abi/include" \
	"$SCRIPT_ROOT/c-abi/zlib-shared.c" -L"$FIXTURE_DIR" -lz \
	-o "$FIXTURE_DIR/zlib-shared"
readelf -d "$FIXTURE_DIR/zlib-shared" | grep -q 'Shared library: \[libz\.so\.1\]'

"$FIXTURE_DIR/httpd"
"$FIXTURE_DIR/clientlist" "$FIXTURE_DIR"
"$FIXTURE_DIR/router-security" "$FIXTURE_DIR"
"$FIXTURE_DIR/wanduck"
"$FIXTURE_DIR/zlib"
LD_LIBRARY_PATH="$FIXTURE_DIR" "$FIXTURE_DIR/zlib-shared"
echo "RESULT=PASS"
