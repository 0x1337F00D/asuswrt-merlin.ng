#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
	echo "usage: $0 ROOTFS TOOLCHAIN_BIN QEMU_ARM" >&2
	exit 2
fi

rootfs=$(readlink -f "$1")
toolchain_bin=$(readlink -f "$2")
qemu_arm=$(readlink -f "$3")
objdump="$toolchain_bin/arm-buildroot-linux-gnueabi-objdump"
readelf="$toolchain_bin/arm-buildroot-linux-gnueabi-readelf"

for tool in "$objdump" "$readelf" "$qemu_arm" file grep mktemp; do
	if [ ! -x "$tool" ] && ! command -v "$tool" >/dev/null 2>&1; then
		echo "required tool is unavailable: $tool" >&2
		exit 1
	fi
done

artifacts=(
	"bin/rstats"
	"usr/sbin/infosvr"
	"usr/sbin/Notify_Event2NC"
	"usr/sbin/httpd"
	"sbin/rc"
)

temporary=$(mktemp -d "${TMPDIR:-/tmp}/gtax-rust-verify.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT

for relative in "${artifacts[@]}"; do
	binary="$rootfs/$relative"
	if [ ! -x "$binary" ]; then
		echo "missing executable: $relative" >&2
		exit 1
	fi

	identity=$(file -b "$binary")
	case "$identity" in
		*"ELF 32-bit LSB"*"ARM"*"EABI5"*) ;;
		*) echo "unexpected ELF identity for $relative: $identity" >&2; exit 1 ;;
	esac

	"$readelf" -h "$binary" > "$temporary/header"
	"$readelf" -A "$binary" > "$temporary/attributes"
	"$readelf" -l "$binary" > "$temporary/program-headers"
	grep -q 'Machine:.*ARM' "$temporary/header"
	grep -q 'Flags:.*soft-float ABI' "$temporary/header"
	grep -q 'Tag_CPU_arch: v7' "$temporary/attributes"
	if grep -q 'Tag_ABI_VFP_args' "$temporary/attributes"; then
		echo "hard-float ABI is forbidden: $relative" >&2
		exit 1
	fi
	grep -q '/lib/ld-linux.so.3' "$temporary/program-headers"

	while IFS= read -r library; do
		if ! find "$rootfs/lib" "$rootfs/usr/lib" \( -type f -o -type l \) \
			-name "$library" -print -quit 2>/dev/null | grep -q .; then
			echo "missing runtime library for $relative: $library" >&2
			exit 1
		fi
	done < <("$readelf" -d "$binary" \
		| sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p')

	"$objdump" -d "$binary" > "$temporary/disassembly"
	if grep -Eiq 'mcr[a-z]*[[:space:]]+15,.*cr7,.*cr10,.*\{5\}' "$temporary/disassembly"; then
		echo "obsolete ARMv6 CP15 barrier found in $relative" >&2
		exit 1
	fi
done

run_expected_exit() {
	local expected=$1
	shift
	set +e
	"$@" > "$temporary/qemu.stdout" 2> "$temporary/qemu.stderr"
	local status=$?
	set -e
	if [ "$status" -ne "$expected" ]; then
		echo "unexpected QEMU exit $status (expected $expected): $*" >&2
		sed -n '1,40p' "$temporary/qemu.stderr" >&2
		exit 1
	fi
}

qemu=("$qemu_arm" -cpu cortex-a7 -L "$rootfs")
run_expected_exit 1 "${qemu[@]}" "$rootfs/usr/sbin/infosvr"
run_expected_exit 2 "${qemu[@]}" "$rootfs/usr/sbin/Notify_Event2NC"
run_expected_exit 0 "${qemu[@]}" "$rootfs/bin/rstats" --self-test
grep -q 'runtime self-test passed' "$temporary/qemu.stdout"

echo "verified ${#artifacts[@]} ARMv7 soft-float consumers and 3 QEMU runtime paths"
