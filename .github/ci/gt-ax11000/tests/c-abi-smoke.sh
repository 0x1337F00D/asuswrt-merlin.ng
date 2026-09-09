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
	-p zlib-static

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

"$FIXTURE_DIR/httpd"
"$FIXTURE_DIR/clientlist" "$FIXTURE_DIR"
"$FIXTURE_DIR/router-security" "$FIXTURE_DIR"
"$FIXTURE_DIR/wanduck"
"$FIXTURE_DIR/zlib"
echo "RESULT=PASS"
