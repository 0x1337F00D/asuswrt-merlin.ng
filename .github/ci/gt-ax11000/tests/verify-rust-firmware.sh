#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0

if [ "$#" -ne 3 ]; then
	echo "usage: $0 ROOTFS TOOLCHAIN_BIN QEMU_ARM" >&2
	exit 2
fi

rootfs=$(readlink -f "$1")
toolchain_bin=$(readlink -f "$2")
qemu_arm=$(readlink -f "$3")
objdump="$toolchain_bin/arm-buildroot-linux-gnueabi-objdump"
readelf="$toolchain_bin/arm-buildroot-linux-gnueabi-readelf"

for tool in "$objdump" "$readelf" "$qemu_arm" file grep mktemp python3; do
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
	"usr/sbin/networkmap"
	"sbin/rc"
	"usr/sbin/ntp"
	"usr/sbin/wget"
	"usr/sbin/hostapd"
	"usr/sbin/wpa_supplicant-2.7"
)

# Installed 0755 by networkmap-install, so it reaches the same ISA checks, but
# it is a library: no interpreter, and it is loaded by the closed networkmap.
shared_objects=(
	"usr/lib/libbwdpi.so"
	"usr/lib/libshared.so"
)

temporary=$(mktemp -d "${TMPDIR:-/tmp}/gtax-rust-verify.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT

for relative in "${artifacts[@]}" "${shared_objects[@]}"; do
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
	# Shared objects carry no PT_INTERP.  The ELF type cannot decide this:
	# binutils 2.28 labels a position-independent executable and a shared
	# library identically as DYN, so the interpreter is required for
	# everything that is not on the shared-object list.
	case " ${shared_objects[*]} " in
	*" $relative "*)
		if [ ! -f "$binary" ] || [ -L "$binary" ]; then
			echo "shared object must be a regular non-symlink: $relative" >&2
			exit 1
		fi
		grep -q 'Type:.*DYN' "$temporary/header"
		if grep -q 'INTERP' "$temporary/program-headers"; then
			echo "shared object must not have PT_INTERP: $relative" >&2
			exit 1
		fi
		;;
	*) grep -q '/lib/ld-linux.so.3' "$temporary/program-headers" ;;
	esac

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

# The staged libshared must contain the Rust policy called by the hardened
# wlif wrappers. A fresh filename alone cannot distinguish a stale C-only
# library from the relinked archive. Require only definitions actually called
# by the C wrapper: unused policy helpers may be removed by --gc-sections.
"$readelf" --dyn-syms -W "$rootfs/usr/lib/libshared.so" | awk '
	$4 == "FUNC" && $5 ~ /^(GLOBAL|WEAK)$/ && $7 != "UND" {sub(/@.*/, "", $8); print $8}
' > "$temporary/shared-exports"
for symbol in rust_wlif_ifname_ok \
	rust_wlif_cli_token_ok rust_wlif_cli_word_list_ok rust_wlif_ssid_ok \
	rust_wlif_passphrase_ok rust_wlif_dpp_value_ok \
	rust_wlif_network_id_ok rust_wlif_supplicant_ctrl_path rust_wlif_supplicant_ctrl_dir; do
	if ! grep -qxF "$symbol" "$temporary/shared-exports"; then
		echo "usr/lib/libshared.so does not define $symbol" >&2
		exit 1
	fi
done

# usr/lib/libz.so.1 is the zlib-rs replacement for the vendor libz.  It must
# be a real ARMv7 soft-float shared object carrying the vendor SONAME and the
# vendor ZLIB_* version nodes, and it must not publish the internal symbols
# the vendor version script keeps local.
libz="$rootfs/usr/lib/libz.so.1"
if [ ! -f "$libz" ] || [ -L "$libz" ]; then
	echo "missing or symlinked shared library: usr/lib/libz.so.1" >&2
	exit 1
fi
identity=$(file -b "$libz")
case "$identity" in
	*"ELF 32-bit LSB"*"ARM"*"EABI5"*) ;;
	*) echo "unexpected ELF identity for usr/lib/libz.so.1: $identity" >&2; exit 1 ;;
esac
"$readelf" -h "$libz" > "$temporary/libz-header"
"$readelf" -A "$libz" > "$temporary/libz-attributes"
"$readelf" -d "$libz" > "$temporary/libz-dynamic"
"$readelf" -V "$libz" > "$temporary/libz-versions"
grep -q 'Machine:.*ARM' "$temporary/libz-header"
grep -q 'Flags:.*soft-float ABI' "$temporary/libz-header"
grep -q 'Tag_CPU_arch: v7' "$temporary/libz-attributes"
if grep -q 'Tag_ABI_VFP_args' "$temporary/libz-attributes"; then
	echo "hard-float ABI is forbidden: usr/lib/libz.so.1" >&2
	exit 1
fi
if ! grep -q 'SONAME.*\[libz\.so\.1\]' "$temporary/libz-dynamic"; then
	echo "usr/lib/libz.so.1 does not carry SONAME libz.so.1" >&2
	exit 1
fi
# zlibVersion() of the replacement; the vendor library reports "1.2.12".
if ! grep -aq '1\.3\.0-zlib-rs-' "$libz"; then
	echo "usr/lib/libz.so.1 is not the zlib-rs build" >&2
	exit 1
fi
while IFS= read -r library; do
	if ! find "$rootfs/lib" "$rootfs/usr/lib" \( -type f -o -type l \) \
		-name "$library" -print -quit 2>/dev/null | grep -q .; then
		echo "missing runtime library for usr/lib/libz.so.1: $library" >&2
		exit 1
	fi
done < <(sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' "$temporary/libz-dynamic")

# The complete node list of the vendor release/src/router/zlib/zlib.map.  A
# missing node breaks every consumer that recorded a versioned reference.
for node in ZLIB_1.2.0 ZLIB_1.2.0.2 ZLIB_1.2.0.8 ZLIB_1.2.2 ZLIB_1.2.2.3 \
	ZLIB_1.2.2.4 ZLIB_1.2.3.3 ZLIB_1.2.3.4 ZLIB_1.2.3.5 ZLIB_1.2.5.1 \
	ZLIB_1.2.5.2 ZLIB_1.2.7.1 ZLIB_1.2.9 ZLIB_1.2.12; do
	if ! grep -q "Name: $node$" "$temporary/libz-versions"; then
		echo "usr/lib/libz.so.1 does not define version node $node" >&2
		exit 1
	fi
done

# Defined dynamic exports, rendered as "name" or "name@@VERSION".
"$readelf" --dyn-syms -W "$libz" | awk '
	$4 ~ /^(FUNC|OBJECT|NOTYPE|IFUNC)$/ && $5 ~ /^(GLOBAL|WEAK)$/ && $7 != "UND" {print $8}
' | sort -u > "$temporary/libz-exports"
for expected in \
	deflate inflate compress uncompress crc32 adler32 zlibVersion \
	gzopen gzread gzwrite gzclose \
	compressBound@@ZLIB_1.2.0 inflateBackInit_@@ZLIB_1.2.0 \
	zlibCompileFlags@@ZLIB_1.2.0.2 deflatePrime@@ZLIB_1.2.0.8 \
	inflateGetHeader@@ZLIB_1.2.2 gzdirect@@ZLIB_1.2.2.3 \
	inflatePrime@@ZLIB_1.2.2.4 gzopen64@@ZLIB_1.2.3.3 \
	inflateReset2@@ZLIB_1.2.3.4 gzbuffer@@ZLIB_1.2.3.5 \
	deflatePending@@ZLIB_1.2.5.1 gzgetc_@@ZLIB_1.2.5.2 \
	inflateGetDictionary@@ZLIB_1.2.7.1 uncompress2@@ZLIB_1.2.9 \
	crc32_combine_gen@@ZLIB_1.2.12; do
	if ! grep -qxF -- "$expected" "$temporary/libz-exports"; then
		echo "usr/lib/libz.so.1 does not export $expected" >&2
		exit 1
	fi
done
# The vendor version script keeps these local; so must the replacement.  The
# zlib-rs-only extensions must not widen the published ABI either.
for forbidden in deflate_copyright inflate_copyright inflate_fast \
	inflate_table zcalloc zcfree z_errmsg gz_error gz_intmax \
	rust_eh_personality rust_begin_unwind rust_panic \
	compress_z compress2_z compressBound_z deflateBound_z deflateUsed \
	uncompress_z uncompress2_z; do
	if grep -qE "^$forbidden(@|$)" "$temporary/libz-exports"; then
		echo "usr/lib/libz.so.1 exports the internal symbol $forbidden" >&2
		exit 1
	fi
done

# Check every imported zlib symbol and its exact requested version against
# this object, using an independent vendor inventory for unversioned names.
python3 "$(dirname "$0")/zlib-consumer-abi.py" "$rootfs" "$readelf"

# The WLAN daemons must use the locked OpenSSL major, including on a cold
# vendor-cache miss. A header-only fix must not leave a stale 1.1 consumer.
for relative in usr/sbin/hostapd usr/sbin/wpa_supplicant-2.7; do
	"$readelf" -d "$rootfs/$relative" > "$temporary/wifi-dynamic"
	grep -Fq 'Shared library: [libcrypto.so.3]' "$temporary/wifi-dynamic"
	grep -Fq 'Shared library: [libssl.so.3]' "$temporary/wifi-dynamic"
done

# wget is the isolated zlib-rs consumer: it must carry the Rust zlib in its
# own image and must not load the shared libz.so.1 that every other package
# resolves at run time.
wget="$rootfs/usr/sbin/wget"
"$readelf" -d "$wget" > "$temporary/wget-dynamic"
if grep -q 'Shared library: \[libz\.so' "$temporary/wget-dynamic"; then
	echo "wget still depends on the vendor libz.so.1" >&2
	exit 1
fi
if ! grep -aq '1\.3\.0-zlib-rs-' "$wget"; then
	echo "wget does not carry the zlib-rs version marker" >&2
	exit 1
fi
# Production binaries are stripped; static function names need not survive.
# Prove inflate/gzwrite through the actual consumer instead of symbol guesses.
python3 "$(dirname "$0")/wget-zlib-runtime.py" "$rootfs" "$qemu_arm"

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
# The NTP daemon exercises its packet, discipline and refusal paths without a
# socket or a clock write, then exits 0. With no arguments it must refuse to
# start rather than silently do nothing.
run_expected_exit 0 "${qemu[@]}" "$rootfs/usr/sbin/ntp" --self-test
grep -q '^ntp-rs: runtime self-test passed$' "$temporary/qemu.stdout"
run_expected_exit 1 "${qemu[@]}" "$rootfs/usr/sbin/ntp"
grep -q 'no -p PEER was given' "$temporary/qemu.stderr"
run_expected_exit 0 "${qemu[@]}" "$rootfs/usr/sbin/wget" --no-config --version
grep -q '^GNU Wget 1\.24\.5' "$temporary/qemu.stdout"
# hostapd deliberately exits 1 after printing its version; the baseline and
# rebuilt consumer were both checked. Neither invocation starts a radio.
run_expected_exit 1 "${qemu[@]}" "$rootfs/usr/sbin/hostapd" -v
grep -q '^hostapd v2\.9' "$temporary/qemu.stderr"
run_expected_exit 0 "${qemu[@]}" "$rootfs/usr/sbin/wpa_supplicant-2.7" -v
grep -q '^wpa_supplicant v2\.9' "$temporary/qemu.stdout"

echo "verified $((${#artifacts[@]} + ${#shared_objects[@]})) ARMv7 soft-float consumers, the zlib-rs libz.so.1 and the QEMU runtime checks"
