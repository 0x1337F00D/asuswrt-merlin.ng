#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$SCRIPT_ROOT/rust"
BUILD_SCRIPT="$SCRIPT_ROOT/build.sh"
VERIFY_SCRIPT="$SCRIPT_ROOT/tests/verify-rust-firmware.sh"
RUST_TOOLCHAIN="1.85.1"
DEFAULT_RUST_TARGET="armv7-unknown-linux-gnueabi"
RUST_TARGET="${RUST_TARGET:-$DEFAULT_RUST_TARGET}"

if [ "$RUST_TARGET" != "$DEFAULT_RUST_TARGET" ]; then
	echo "Rust firmware cycle requires target $DEFAULT_RUST_TARGET (got $RUST_TARGET)" >&2
	exit 2
fi

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Missing required command: $1" >&2
		exit 1
	fi
}

for command_name in bash cargo rustc find file readlink sha256sum; do
	require_cmd "$command_name"
done

host_target_dir="${RUST_HOST_TARGET_DIR:-${TMPDIR:-/tmp}/asuswrt-rust-host-target}"
mkdir -p "$host_target_dir"
if [ "${ASUSWRT_REQUIRE_TMPFS:-0}" = "1" ]; then
	require_cmd findmnt
	if [ "$(findmnt -n -o FSTYPE -T "$host_target_dir")" != "tmpfs" ]; then
		echo "RAM-only Rust cycle requires host Cargo target on tmpfs: $host_target_dir" >&2
		exit 1
	fi
fi
export CARGO_TARGET_DIR="$host_target_dir"

if [ ! -f "$RUST_ROOT/Cargo.toml" ]; then
	echo "Rust workspace not found: $RUST_ROOT" >&2
	exit 1
fi
if [ ! -x "$BUILD_SCRIPT" ] && [ ! -f "$BUILD_SCRIPT" ]; then
	echo "Build script not found: $BUILD_SCRIPT" >&2
	exit 1
fi
if [ ! -x "$VERIFY_SCRIPT" ] && [ ! -f "$VERIFY_SCRIPT" ]; then
	echo "Firmware verification script not found: $VERIFY_SCRIPT" >&2
	exit 1
fi

rustc +"$RUST_TOOLCHAIN" --version --verbose >/dev/null
cargo +"$RUST_TOOLCHAIN" --version >/dev/null

echo "Checking Rust workspace with toolchain $RUST_TOOLCHAIN"
cd "$RUST_ROOT"
cargo +"$RUST_TOOLCHAIN" fmt \
	--manifest-path "$RUST_ROOT/Cargo.toml" \
	--all -- --check
cargo +"$RUST_TOOLCHAIN" test \
	--manifest-path "$RUST_ROOT/Cargo.toml" \
	--workspace --locked --offline
cargo +"$RUST_TOOLCHAIN" clippy \
	--manifest-path "$RUST_ROOT/Cargo.toml" \
	--workspace --all-targets --locked --offline -- -D warnings

echo "Checking ARM target $RUST_TARGET"
ARM_RUSTFLAGS="${RUSTFLAGS:-} -Dwarnings -Ctarget-cpu=cortex-a9"
RUSTFLAGS="$ARM_RUSTFLAGS" cargo +"$RUST_TOOLCHAIN" check \
	--manifest-path "$RUST_ROOT/Cargo.toml" \
	--workspace --locked --offline --target "$RUST_TARGET"

# The Makefile overlay consumes RUST_TARGET and RUST_CPU_FLAGS from the
# environment. Preserve caller-provided values, but never fall back to the
# obsolete generic ARM target for a firmware iteration.
export RUST_TARGET
export RUST_CPU_FLAGS="${RUST_CPU_FLAGS:--Ctarget-cpu=cortex-a9}"
export ASUSWRT_BUILD_MODE="${ASUSWRT_DEV_BUILD_MODE:-rust-fast}"
export ASUSWRT_FORCE_PROFILE=0

echo "Building firmware in Rust fast-iteration mode"
bash "$BUILD_SCRIPT" gt-ax11000

source_repo="${ASUSWRT_SOURCE_REPO:-$SCRIPT_ROOT/../asuswrt-merlin.ng}"
worktree_base="${ASUSWRT_WORKTREE_BASE:-$SCRIPT_ROOT}"
worktree_dir="${ASUSWRT_WORKTREE_DIR:-$worktree_base/gt-ax11000}"
if [ -n "${ASUSWRT_SOURCE_ROOT:-}" ]; then
	if [ "${ASUSWRT_BUILD_WORKTREE:-0}" = "1" ]; then
		build_root="$ASUSWRT_SOURCE_ROOT"
	else
		build_root="$worktree_dir"
	fi
elif [ "${ASUSWRT_BUILD_WORKTREE:-0}" = "1" ]; then
	build_root="$source_repo"
else
	build_root="$worktree_dir"
fi

targets_root="$build_root/release/src-rt-5.02axhnd/targets"
if [ ! -d "$targets_root" ]; then
	echo "Firmware targets directory not found: $targets_root" >&2
	exit 1
fi

infosvr_path="$(find "$targets_root" -type f -path '*/fs/usr/sbin/infosvr' -print -quit)"
if [ -z "$infosvr_path" ]; then
	echo "Fresh infosvr rootfs artifact not found below: $targets_root" >&2
	exit 1
fi
rootfs="${infosvr_path%/usr/sbin/infosvr}"

toolchains_root="${AM_TOOLCHAINS:-$HOME/am-toolchains}"
toolchain_bin="${ASUSWRT_TOOLCHAIN_BIN:-$toolchains_root/brcm-arm-hnd/crosstools-arm-gcc-5.5-linux-4.1-glibc-2.26-binutils-2.28.1/bin}"
if [ ! -d "$toolchain_bin" ]; then
	echo "ARM toolchain bin directory not found: $toolchain_bin" >&2
	exit 1
fi

qemu_arm="${QEMU_ARM:-}"
if [ -z "$qemu_arm" ]; then
	qemu_arm="$(command -v qemu-arm || true)"
fi
if [ -z "$qemu_arm" ]; then
	echo "Missing qemu-arm; set QEMU_ARM or install qemu-user" >&2
	exit 1
fi

echo "Verifying firmware rootfs: $rootfs"
bash "$VERIFY_SCRIPT" "$rootfs" "$toolchain_bin" "$qemu_arm"

echo "Rust iteration cycle completed successfully"
