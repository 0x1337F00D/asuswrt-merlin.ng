#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_ROOT/../rust/Cargo.toml"
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-1.85.1}"
ITERATIONS="${RUST_FUZZ_ITERATIONS:-250000}"
TARGET_DIR="${RUST_FUZZ_TARGET_DIR:-/tmp/asuswrt-router-fuzz-target}"
CARGO_DIR="${RUST_FUZZ_CARGO_HOME:-/tmp/asuswrt-router-fuzz-cargo}"

if ! [[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]]; then
	echo "RUST_FUZZ_ITERATIONS must be a positive integer" >&2
	exit 2
fi

if [ "${ASUSWRT_REQUIRE_TMPFS:-0}" = "1" ]; then
	for path in "$TARGET_DIR" "$CARGO_DIR" "${TMPDIR:-/tmp}"; do
		candidate="$path"
		while [ ! -e "$candidate" ] && [ "$candidate" != / ]; do
			candidate="$(dirname "$candidate")"
		done
		if [ "$(findmnt -n -o FSTYPE -T "$candidate")" != tmpfs ]; then
			echo "fuzz output path is not tmpfs: $path" >&2
			exit 1
		fi
	done
fi

mkdir -p "$TARGET_DIR" "$CARGO_DIR"
export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_HOME="$CARGO_DIR"

# Cargo resolves the vendored crates.io mapping from the working directory.
cd "$(dirname "$MANIFEST")"

for seed in 1 11400714819323198485 18446744073709551615; do
	cargo +"$RUST_TOOLCHAIN" run \
		--manifest-path "$MANIFEST" \
		--release --locked --offline -p router-fuzz -- \
		"$ITERATIONS" "$seed"
done

echo "RESULT=PASS"
