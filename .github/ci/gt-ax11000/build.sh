#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_REPO="${ASUSWRT_SOURCE_REPO:-$SCRIPT_ROOT/../asuswrt-merlin.ng}"
ROOT="${ASUSWRT_SOURCE_ROOT:-$SOURCE_REPO}"
DEVICE="${1:-}"
RUST_OVERLAY="$SCRIPT_ROOT/rust"
RUST_REPACK_MAKEFILE="$SCRIPT_ROOT/rust-repack.mk"
INPUT_LOCK="$SCRIPT_ROOT/inputs.lock"
INPUT_LOCK_TOOL="$SCRIPT_ROOT/tools/input_lock.py"
PATCH_SERIES="$SCRIPT_ROOT/patches/series"
SECURITY_OVERLAY_TEST="$SCRIPT_ROOT/tests/security-overlay-check.sh"
NETWORK_HARDENING_TEST="$SCRIPT_ROOT/tests/network-hardening-check.sh"
NO_PROPRIETARY_QOS_ROOTFS_TEST="$SCRIPT_ROOT/tests/no-proprietary-qos-rootfs.sh"
WEB_PAYLOAD_TEST="$SCRIPT_ROOT/tests/verify-web-payload.sh"
WEB_SYMLINK_TEST="$SCRIPT_ROOT/tests/verify-web-symlinks.sh"
SOURCE_PREP_VERSION=1
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-1.85.1}"
RUST_TARGET="${RUST_TARGET:-armv7-unknown-linux-gnueabi}"
RUST_CPU_FLAGS="${RUST_CPU_FLAGS:--Ctarget-cpu=cortex-a9}"

usage() {
	cat <<EOF
Usage: ./build.sh <device_name>

Supported devices:
  gt-ax11000

Environment overrides:
  AM_TOOLCHAINS=/path/to/am-toolchains        default: \$HOME/am-toolchains
  ASUSWRT_SOURCE_REPO=/path/to/source         default: ../asuswrt-merlin.ng
  ASUSWRT_BUILD_MODE=clean|fast|rust-fast     default: clean
  ASUSWRT_FORCE_PROFILE=0|1                    default: 0; use 1 only after profile changes
  ASUSWRT_HOSTTOOLS=/tmp/path                 default: /tmp/asuswrt-hosttools
  ASUSWRT_GNU_MAKE_ROOT=/tmp/path             default: /tmp/asuswrt-host-make-4.4.1
  ASUSWRT_MAKE_JOBS=1                         safety-enforced top-level orchestration
  ROUTER_PACKAGE_JOBS=N                       shared package-DAG job tokens; default: 1
  ASUSWRT_PREPARE_JOBS=N                      parallel Autotools preparation, default: 4
  ASUSWRT_CCACHE=0|1                          cache HND cross-compiler output, default: 0
                                              (auto-disabled when no ccache executable exists)
  ASUSWRT_CCACHE_DIR=/path                    default: /tmp/asuswrt-ccache
  ASUSWRT_CCACHE_MAXSIZE=size                 default: 2G
  ASUSWRT_KERNEL_CACHE_RESTORE=0|1            trust an exact successful CI kernel cache
  ASUSWRT_DIRECT_TOOLCHAIN=0|1                use /opt symlink instead of unshare (CI)
  ASUSWRT_REQUIRE_TMPFS=0|1                   reject non-tmpfs build paths, default: 0
  ASUSWRT_WORKTREE_BASE=/path/to/worktrees    default: this directory
  ASUSWRT_OUTPUT_DIR=/path/to/output          default: ./output/<device>

rust-fast is an incremental Rust-only relink/repack path. It refuses to run
without an exact prepared-source state and a prior successful full build.
EOF
}

if [ -z "$DEVICE" ] || [ "$DEVICE" = "-h" ] || [ "$DEVICE" = "--help" ]; then
	usage
	exit 0
fi

case "${DEVICE,,}" in
	gt-ax11000|gtax11000|ax11000)
		BUILD_NAME="GT-AX11000"
		MAKE_TARGET="gt-ax11000"
		SDK_PATH="release/src-rt-5.02axhnd"
		PROFILE="94908HND"
		IMAGE_GLOB="GT-AX11000*.w"
		TOOLCHAIN_GROUP="brcm-arm-hnd"
		;;
	*)
		echo "Unsupported device: $DEVICE" >&2
		usage >&2
		exit 2
		;;
esac

TOOLCHAINS="${AM_TOOLCHAINS:-$HOME/am-toolchains}"
TOOLCHAIN_SRC="$TOOLCHAINS/$TOOLCHAIN_GROUP"
HOSTTOOLS="${ASUSWRT_HOSTTOOLS:-/tmp/asuswrt-hosttools}"
GNU_MAKE_VERSION=4.4.1
GNU_MAKE_SHA256=dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3
GNU_MAKE_URL="https://ftp.gnu.org/gnu/make/make-$GNU_MAKE_VERSION.tar.gz"
GNU_MAKE_ROOT="${ASUSWRT_GNU_MAKE_ROOT:-/tmp/asuswrt-host-make-$GNU_MAKE_VERSION}"
GNU_MAKE_BINDIR="$GNU_MAKE_ROOT/bin"
GNU_MAKE_BIN="$GNU_MAKE_BINDIR/make"
APT_CACHE="${ASUSWRT_APT_CACHE:-/tmp/asuswrt-apt}"
FAKEBIN="${ASUSWRT_FAKEBIN:-/tmp/asuswrt-fakebin}"
PATCH_FILES=()
while IFS= read -r patch_name; do
	patch_name="${patch_name%%#*}"
	patch_name="${patch_name//[[:space:]]/}"
	[ -n "$patch_name" ] || continue
	case "$patch_name" in
		*/*|.*) echo "Unsafe patch-series entry: $patch_name" >&2; exit 1 ;;
	esac
	PATCH_FILES+=("$SCRIPT_ROOT/patches/$patch_name")
done < "$PATCH_SERIES"
[ "${#PATCH_FILES[@]}" -gt 0 ] || { echo "Patch series is empty" >&2; exit 1; }
MAKE_JOBS="${ASUSWRT_MAKE_JOBS:-1}"
ROUTER_PACKAGE_JOBS="${ROUTER_PACKAGE_JOBS:-1}"
PREPARE_JOBS="${ASUSWRT_PREPARE_JOBS:-4}"
CCACHE_ENABLED="${ASUSWRT_CCACHE:-0}"
CCACHE_DIR="${ASUSWRT_CCACHE_DIR:-/tmp/asuswrt-ccache}"
CCACHE_MAXSIZE="${ASUSWRT_CCACHE_MAXSIZE:-2G}"
KERNEL_CACHE_RESTORE="${ASUSWRT_KERNEL_CACHE_RESTORE:-0}"
TOOLCHAIN_VIEW="${ASUSWRT_TOOLCHAIN_VIEW:-/tmp/asuswrt-toolchain-view/$TOOLCHAIN_GROUP}"
TOOLCHAIN_MOUNT_SRC="$TOOLCHAIN_SRC"
CCACHE_PATH_VALUE=""
DIRECT_TOOLCHAIN="${ASUSWRT_DIRECT_TOOLCHAIN:-0}"
REQUIRE_TMPFS="${ASUSWRT_REQUIRE_TMPFS:-0}"
BUILD_MODE="${ASUSWRT_BUILD_MODE:-clean}"
BUILD_MODE="${BUILD_MODE,,}"
FORCE_PROFILE="${ASUSWRT_FORCE_PROFILE:-}"
WORKTREE_BASE="${ASUSWRT_WORKTREE_BASE:-$SCRIPT_ROOT}"
WORKTREE_DIR="${ASUSWRT_WORKTREE_DIR:-$WORKTREE_BASE/$MAKE_TARGET}"
OUTPUT_DIR="${ASUSWRT_OUTPUT_DIR:-$SCRIPT_ROOT/output/$MAKE_TARGET}"
SDK_DIR="$ROOT/$SDK_PATH"
LOG_FILE="$SDK_DIR/output-${MAKE_TARGET}-wsl.log"
RUST_CONSUMER_MANIFEST="$ROOT/.asuswrt-rust-consumers-expected"
WEB_PAYLOAD_MANIFEST="$ROOT/.asuswrt-web-payload-expected"
WEB_SYMLINK_MANIFEST="$ROOT/.asuswrt-web-symlinks-expected"
OUTER_USER="$(id -un)"
BUILD_STARTED_EPOCH="${ASUSWRT_BUILD_STARTED_EPOCH:-$(date +%s)}"
WORKTREE_PREP_SECONDS="${ASUSWRT_WORKTREE_PREP_SECONDS:-0}"
ENFORCE_INPUT_LOCK="${ASUSWRT_ENFORCE_INPUT_LOCK:-0}"
INPUT_LOCK_STATE_FILE="$OUTPUT_DIR/.asuswrt-input-lock-state"
KERNEL_CACHE_STATE_FILE="$ROOT/.asuswrt-kernel-cache-state"
KERNEL_CACHE_REUSE=0

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Missing required command: $1" >&2
		exit 1
	fi
}

path_fstype() {
	local candidate="$1"

	while [ ! -e "$candidate" ]; do
		if [ "$candidate" = "/" ]; then
			break
		fi
		candidate="$(dirname "$candidate")"
	done
	findmnt -n -o FSTYPE -T "$candidate"
}

require_tmpfs_path() {
	local label="$1"
	local path="$2"
	local fstype

	fstype="$(path_fstype "$path")"
	if [ "$fstype" != "tmpfs" ]; then
		echo "RAM-only build requires $label on tmpfs: $path (found $fstype)" >&2
		exit 1
	fi
	printf 'RAM-only check: %-20s tmpfs (%s)\n' "$label" "$path"
}

verify_locked_inputs() {
	mkdir -p "$OUTPUT_DIR"
	if [ "$ENFORCE_INPUT_LOCK" != "1" ]; then
		printf '%s\n' \
			"input_lock_status=not-enforced" \
			"input_lock_sha256=$(sha256sum "$INPUT_LOCK" | awk '{print $1}')" \
			> "$INPUT_LOCK_STATE_FILE"
		return
	fi
	require_cmd python3
	python3 "$INPUT_LOCK_TOOL" verify \
		--lock "$INPUT_LOCK" \
		--series "$PATCH_SERIES" \
		--patch-root "$SCRIPT_ROOT/patches" \
		--source "$ROOT" \
		--toolchains "$TOOLCHAINS" \
		--rust-toolchain "$RUST_TOOLCHAIN" \
		--rust-target "$RUST_TARGET" \
		--rust-target-cpu "${RUST_CPU_FLAGS#-Ctarget-cpu=}" \
		> "$INPUT_LOCK_STATE_FILE"
	printf '%s\n' "input_lock_status=verified" >> "$INPUT_LOCK_STATE_FILE"
}

verify_ram_only_paths() {
	require_cmd findmnt
	require_tmpfs_path "source repository" "$SOURCE_REPO"
	require_tmpfs_path "source root" "$ROOT"
	require_tmpfs_path "build worktree" "$WORKTREE_DIR"
	require_tmpfs_path "firmware output" "$OUTPUT_DIR"
	require_tmpfs_path "temporary files" "${TMPDIR:-/tmp}"
	require_tmpfs_path "Cargo home" "${CARGO_HOME:-$HOME/.cargo}"
	require_tmpfs_path "host tools" "$HOSTTOOLS"
	require_tmpfs_path "GNU Make host tool" "$GNU_MAKE_ROOT"
	require_tmpfs_path "APT cache" "$APT_CACHE"
	require_tmpfs_path "generated helper bin" "$FAKEBIN"
	if [ -n "${RUST_TARGET_DIR:-}" ]; then
		require_tmpfs_path "Rust target" "$RUST_TARGET_DIR"
	fi
	if [ "$CCACHE_ENABLED" = "1" ]; then
		require_tmpfs_path "ccache" "$CCACHE_DIR"
		require_tmpfs_path "ccache toolchain view" "$TOOLCHAIN_VIEW"
	fi
}

ensure_gnu_make() {
	local archive="${TMPDIR:-/tmp}/make-$GNU_MAKE_VERSION.tar.gz"
	local build_root
	local source_root
	local actual_sha256

	if [ -x "$GNU_MAKE_BIN" ] &&
		[ "$($GNU_MAKE_BIN --version | sed -n '1s/^GNU Make //p')" = "$GNU_MAKE_VERSION" ]; then
		echo "Reusing GNU Make $GNU_MAKE_VERSION from $GNU_MAKE_BIN"
		return
	fi
	if [ -e "$GNU_MAKE_ROOT" ]; then
		echo "Existing GNU Make root is incomplete or has the wrong version: $GNU_MAKE_ROOT" >&2
		exit 1
	fi

	require_cmd curl
	require_cmd tar
	if [ ! -f "$archive" ]; then
		# Download to a partial file so an interrupted transfer never masquerades
		# as a complete archive on the next run; the checksum below stays pinned.
		curl --fail --location --silent --show-error \
			--retry 3 --retry-all-errors --connect-timeout 20 --max-time 300 \
			"$GNU_MAKE_URL" --output "$archive.part"
		mv -f "$archive.part" "$archive"
	fi
	actual_sha256="$(sha256sum "$archive" | awk '{print $1}')"
	if [ "$actual_sha256" != "$GNU_MAKE_SHA256" ]; then
		echo "GNU Make archive checksum mismatch: $actual_sha256" >&2
		# Never leave the rejected archive behind: the next run would skip the
		# download and fail on the same bytes forever.
		rm -f -- "$archive"
		exit 1
	fi

	build_root="$(mktemp -d --tmpdir asuswrt-make-build.XXXXXX)"
	source_root="$build_root/source"
	mkdir -p "$source_root"
	tar -xzf "$archive" -C "$source_root" --strip-components=1
	(
		cd "$source_root"
		./configure --prefix="$build_root/install" \
			--disable-dependency-tracking --without-guile >/dev/null
		/usr/bin/make -j"$(nproc)" >/dev/null
		/usr/bin/make install >/dev/null
	)
	mv "$build_root/install" "$GNU_MAKE_ROOT"
	if [ "$($GNU_MAKE_BIN --version | sed -n '1s/^GNU Make //p')" != "$GNU_MAKE_VERSION" ]; then
		echo "Built GNU Make failed its version check" >&2
		exit 1
	fi
	echo "Built checksum-verified GNU Make $GNU_MAKE_VERSION in RAM"
}

prepare_ccache_toolchain_view() {
	local bin_dir
	local ccache_bin
	local compiler
	local smoke_compiler=""
	local smoke_ld_library_path
	local smoke_object
	local smoke_source
	local wrapped=0
	local -a compiler_paths=()
	local -a library_paths=()

	require_cmd ccache
	ccache_bin="$(command -v ccache)"

	if [ -e "$TOOLCHAIN_VIEW" ] || [ -L "$TOOLCHAIN_VIEW" ]; then
		smoke_compiler="$(find "$TOOLCHAIN_VIEW" -type l \
			\( -name '*-gcc' -o -name '*-g++' -o -name '*-cc' -o -name '*-c++' \) \
			-print -quit)"
		if [ -z "$smoke_compiler" ] || [ "$(readlink -f "$smoke_compiler")" != "$(readlink -f "$ccache_bin")" ]; then
			echo "Existing ccache toolchain view is incomplete or uses another ccache: $TOOLCHAIN_VIEW" >&2
			exit 1
		fi
		while IFS= read -r bin_dir; do
			compiler_paths+=("$bin_dir")
		done < <(
			find "$TOOLCHAIN_SRC" \( -type f -o -type l \) \
				\( -name '*-gcc' -o -name '*-g++' -o -name '*-cc' -o -name '*-c++' \) \
				-printf '%h\n' | sort -u
		)
		if [ "${#compiler_paths[@]}" -eq 0 ]; then
			echo "No HND cross-compilers found for reused ccache view" >&2
			exit 1
		fi
		# A prior view can predate host-runtime libraries added to the RAM copy.
		# Merge only missing immutable toolchain files while preserving the ccache
		# compiler symlinks already installed in the view.
		cp -aln "$TOOLCHAIN_SRC/." "$TOOLCHAIN_VIEW/"
		CCACHE_PATH_VALUE="$(IFS=:; echo "${compiler_paths[*]}")"
		TOOLCHAIN_MOUNT_SRC="$TOOLCHAIN_VIEW"
		mkdir -p "$CCACHE_DIR"
		CCACHE_DIR="$CCACHE_DIR" ccache --set-config="max_size=$CCACHE_MAXSIZE"
		echo "Reusing ccache compiler frontends in $TOOLCHAIN_VIEW"
		return
	fi
	mkdir -p "$TOOLCHAIN_VIEW"
	cp -al "$TOOLCHAIN_SRC/." "$TOOLCHAIN_VIEW/"

	while IFS= read -r -d '' compiler; do
		rm -f -- "$compiler"
		ln -s "$ccache_bin" "$compiler"
		if [ -z "$smoke_compiler" ]; then
			smoke_compiler="$compiler"
		fi
		wrapped=$((wrapped + 1))
	done < <(
		find "$TOOLCHAIN_VIEW" \( -type f -o -type l \) \
			\( -name '*-gcc' -o -name '*-g++' -o -name '*-cc' -o -name '*-c++' \) \
			-print0
	)

	while IFS= read -r bin_dir; do
		compiler_paths+=("$bin_dir")
	done < <(
		find "$TOOLCHAIN_SRC" \( -type f -o -type l \) \
			\( -name '*-gcc' -o -name '*-g++' -o -name '*-cc' -o -name '*-c++' \) \
			-printf '%h\n' | sort -u
	)
	while IFS= read -r bin_dir; do
		library_paths+=("$bin_dir")
	done < <(find "$TOOLCHAIN_SRC" -type d -path '*/usr/lib' -print | sort -u)

	if [ "$wrapped" -eq 0 ] || [ "${#compiler_paths[@]}" -eq 0 ]; then
		echo "No HND cross-compilers found for ccache" >&2
		exit 1
	fi

	CCACHE_PATH_VALUE="$(IFS=:; echo "${compiler_paths[*]}")"
	smoke_ld_library_path="$(IFS=:; echo "${library_paths[*]}")"
	TOOLCHAIN_MOUNT_SRC="$TOOLCHAIN_VIEW"
	mkdir -p "$CCACHE_DIR"
	CCACHE_DIR="$CCACHE_DIR" ccache --set-config="max_size=$CCACHE_MAXSIZE"
	CCACHE_DIR="$CCACHE_DIR" ccache --zero-stats
	smoke_source="$(mktemp --tmpdir asuswrt-ccache-smoke.XXXXXX.c)"
	smoke_object="${smoke_source%.c}.o"
	printf 'int main(void) { return 0; }\n' > "$smoke_source"
	CCACHE_DIR="$CCACHE_DIR" CCACHE_PATH="$CCACHE_PATH_VALUE" \
		LD_LIBRARY_PATH="$smoke_ld_library_path:${LD_LIBRARY_PATH:-}" \
		"$smoke_compiler" -c -o "$smoke_object" "$smoke_source"
	CCACHE_DIR="$CCACHE_DIR" CCACHE_PATH="$CCACHE_PATH_VALUE" \
		LD_LIBRARY_PATH="$smoke_ld_library_path:${LD_LIBRARY_PATH:-}" \
		"$smoke_compiler" -c -o "$smoke_object" "$smoke_source"
	rm -f -- "$smoke_source" "$smoke_object"
	echo "Prepared $wrapped ccache compiler frontends in $TOOLCHAIN_VIEW"
}

compute_source_state_id() {
	{
		git -C "$SOURCE_REPO" rev-parse HEAD
		printf '%s\n' "$SOURCE_PREP_VERSION"
		# Hash the source-mutating preparation implementation itself. This keeps
		# unrelated build-driver edits cheap while invalidating prepared trees
		# automatically whenever their generated source state could change.
		declare -f prepare_gt_ax11000_tree normalize_source_timestamps \
			normalize_autotools_timestamps refresh_profile_cookie
		for patch_file in "${PATCH_FILES[@]}"; do
			sha256sum "$patch_file" | awk '{print $1}'
		done
	} | sha256sum | awk '{print $1}'
}

hash_file_or_missing() {
	local path="$1"

	if [ -f "$path" ]; then
		sha256sum "$path" | awk '{print $1}'
	else
		printf 'missing'
	fi
}

fresh_build_mtime() {
	local path="$1"
	local mtime

	# Report an artifact's modification epoch only when this build refreshed
	# it: a reused kernel cache or rust-fast leaves older artifacts in place.
	# Symlinks report themselves so a dangling link cannot abort the scan.
	if [ ! -e "$path" ] && [ ! -L "$path" ]; then
		return
	fi
	mtime="$(stat -c '%Y' "$path")"
	if [ "$mtime" -ge "$build_started_epoch" ]; then
		printf '%s' "$mtime"
	fi
}

newest_fresh_build_mtime() {
	local newest=""
	local mtime
	local path

	for path in "$@"; do
		mtime="$(fresh_build_mtime "$path")"
		if [ -n "$mtime" ] && { [ -z "$newest" ] || [ "$mtime" -gt "$newest" ]; }; then
			newest="$mtime"
		fi
	done
	printf '%s' "$newest"
}

vendor_phase_seconds() {
	local name="$1"
	local boundary="$2"

	# Phases are sequential under the -j1 top-level orchestration, so each one
	# spans from the previous observed boundary. An unobserved phase reports 0
	# and its span folds into the next observed one.
	if [ -n "$boundary" ] && [ "$boundary" -ge "$vendor_phase_prev" ]; then
		printf -v "$name" '%s' "$((boundary - vendor_phase_prev))"
		vendor_phase_prev="$boundary"
	else
		printf -v "$name" '0'
	fi
}

log_stage_seconds() {
	local value

	value="$(sed -n "s/^$1=//p" "$LOG_FILE" 2>/dev/null | tail -n 1 || true)"
	if [[ "$value" =~ ^[0-9]+$ ]]; then
		printf '%s' "$value"
	else
		printf '0'
	fi
}

compute_vendor_phase_timings() {
	local kernel_dir="$SDK_DIR/kernel/linux-4.1"
	local router_dir="$ROOT/release/src/router"
	local install_dir="$SDK_DIR/targets/$PROFILE/fs.install"
	local image_path="${1:-}"
	local kernel_prepared=""
	local kernel_linked=""
	local modules_installed=""
	local foundation_built=""
	local router_installed=""
	local image_built=""
	# Build products of the serial router foundation (fast-parallel-build.patch)
	# whose newest member marks the .WAIT barrier before the package remainder.
	local -a foundation_artifacts=(
		"$router_dir"/openssl*/libssl.so*
		"$router_dir"/shared/libshared.so
		"$router_dir"/libdisk/libdisk.so
		"$router_dir"/libnfnetlink-*/src/.libs/libnfnetlink.so
		"$router_dir"/libmnl-*/src/.libs/libmnl.so
		"$router_dir"/libnetfilter_conntrack-*/src/.libs/libnetfilter_conntrack.so
		"$router_dir"/libnetfilter_cttimeout-*/src/.libs/libnetfilter_cttimeout.so
	)
	# Toolchain runtime libraries that `make -C router reinstall` copies with
	# fresh timestamps (install -D) after every package install, still inside
	# the vendor `make buildimage` and before libcreduction, strips, buildFS and
	# the image tools run. Neither libcreduction (it only adds libraries that
	# are still missing) nor the manifest-bound repack rewrites them.
	local -a router_install_artifacts=(
		"$install_dir"/lib/libc.so.6
		"$install_dir"/lib/libpthread.so.0
		"$install_dir"/lib/libdl.so.2
		"$install_dir"/lib/libgcc_s.so.1
		"$install_dir"/lib/aarch64/libc.so.6
		"$install_dir"/lib/aarch64/libnss_files.so.2
	)

	# Sub-phase boundaries are observed from artifact timestamps after the fact
	# instead of instrumenting the vendor Makefiles. The inner build shell
	# already logs the Rust relink and manifest-bound repack stage durations.
	rust_relink_seconds="$(log_stage_seconds RUST_RELINK_SECONDS)"
	firmware_repack_seconds="$(log_stage_seconds FIRMWARE_REPACK_SECONDS)"
	vendor_prebuild_seconds=0
	kernel_build_seconds=0
	kernel_modules_seconds=0
	router_foundation_seconds=0
	router_packages_seconds=0
	image_assembly_seconds=0
	if [ "$BUILD_MODE" = "rust-fast" ]; then
		return
	fi

	kernel_prepared="$(fresh_build_mtime "$kernel_dir/.pre_kernelbuild")"
	kernel_linked="$(fresh_build_mtime "$kernel_dir/vmlinux")"
	# A build that failed before modules_install has no modules directory yet;
	# that must not abort the driver under pipefail before the failure report.
	modules_installed="$(
		find "$SDK_DIR/targets/$PROFILE/modules" -type f -name '*.ko' \
			-newer "$build_started_marker" -printf '%T@\n' 2>/dev/null \
			| sort -n | tail -n 1 | cut -d. -f1 || true
	)"
	foundation_built="$(newest_fresh_build_mtime "${foundation_artifacts[@]}")"
	# The vendor `image` link is not a usable boundary: the top-level recipe
	# recreates it before `make buildimage`, which then runs the kernel, the
	# router packages and the image assembly. The last router step observable
	# after the package remainder is the reinstall of the runtime libraries.
	router_installed="$(newest_fresh_build_mtime "${router_install_artifacts[@]}")"
	if [ -n "$image_path" ]; then
		image_built="$(fresh_build_mtime "$image_path")"
	fi

	vendor_phase_prev="$build_started_epoch"
	vendor_phase_seconds vendor_prebuild_seconds "$kernel_prepared"
	vendor_phase_seconds kernel_build_seconds "$kernel_linked"
	vendor_phase_seconds kernel_modules_seconds "$modules_installed"
	vendor_phase_seconds router_foundation_seconds "$foundation_built"
	vendor_phase_seconds router_packages_seconds "$router_installed"
	vendor_phase_seconds image_assembly_seconds "$image_built"
	# The image span ends after the common repack, which is timed separately.
	if [ "$image_assembly_seconds" -ge "$firmware_repack_seconds" ]; then
		image_assembly_seconds=$((image_assembly_seconds - firmware_repack_seconds))
	fi
}

compute_toolchain_state_id() {
	if [ -n "${ASUSWRT_TOOLCHAINS_STATE:-}" ]; then
		printf '%s\n' "$ASUSWRT_TOOLCHAINS_STATE"
		return
	fi

	# A local extracted toolchain has no Git object identity. Hash its stable
	# tree metadata plus the actual compiler/linker executables; callers with a
	# repository revision (CI) pass ASUSWRT_TOOLCHAINS_STATE explicitly.
	{
		find "$TOOLCHAINS/$TOOLCHAIN_GROUP" "$TOOLCHAINS/brcm-arm-sdk" \
			\( -type f -o -type l \) -printf '%P\0%s\0%T@\0' 2>/dev/null \
			| sort -z | sha256sum
		find "$TOOLCHAINS/$TOOLCHAIN_GROUP" "$TOOLCHAINS/brcm-arm-sdk" \
			-type f \( -name '*-gcc' -o -name '*-g++' -o -name '*-ld' \) \
			-print0 2>/dev/null | sort -z | xargs -0r sha256sum
	} | sha256sum | awk '{print $1}'
}

compute_full_build_contract_id() {
	{
		printf 'source=%s\n' "$ASUSWRT_SOURCE_STATE_ID"
		printf 'profile=%s\n' "$PROFILE"
		printf 'sdk_config=%s\n' "$(hash_file_or_missing "$SDK_DIR/.config")"
		printf 'router_config=%s\n' "$(hash_file_or_missing "$ROOT/release/src/router/.config")"
		printf 'kernel_config=%s\n' "$(hash_file_or_missing "$SDK_DIR/kernel/linux-4.1/.config")"
		printf 'toolchains=%s\n' "$(compute_toolchain_state_id)"
		printf 'rust_toolchain=%s\n' "$RUST_TOOLCHAIN"
		rustc +"$RUST_TOOLCHAIN" --version --verbose
		printf 'rust_target=%s\n' "$RUST_TARGET"
		printf 'rust_cpu_flags=%s\n' "$RUST_CPU_FLAGS"
	} | sha256sum | awk '{print $1}'
}

compute_kernel_cache_contract_id() {
	{
		printf 'format=1\n'
		printf 'source=%s\n' "$ASUSWRT_SOURCE_STATE_ID"
		printf 'profile=%s\n' "$PROFILE"
		printf 'sdk_path=%s\n' "$SDK_PATH"
		printf 'toolchains=%s\n' "$(compute_toolchain_state_id)"
		printf 'gnu_make=%s\n' "$GNU_MAKE_SHA256"
	} | sha256sum | awk '{print $1}'
}

compute_rust_state_id() {
	(
		cd "$RUST_OVERLAY"
		find . -type f -not -path '*/target/*' -print0 \
			| sort -z | xargs -0 sha256sum
	) \
		| sha256sum | awk '{print $1}'
}

install_rust_components() {
	local destination="$ROOT/release/src/router/rust-components"

	if [ ! -f "$RUST_OVERLAY/Cargo.lock" ]; then
		echo "Rust overlay not found: $RUST_OVERLAY" >&2
		exit 1
	fi
	mkdir -p "$destination"
	rsync --archive --delete --exclude target/ "$RUST_OVERLAY/" "$destination/"
	if [ -n "${ASUSWRT_RUST_STATE_ID:-}" ]; then
		printf '%s\n' "$ASUSWRT_RUST_STATE_ID" > "$ROOT/.asuswrt-rust-state"
	fi
}

prepare_source_worktree() {
	local head
	local old_head
	local patch_file
	local state_file
	local state_id

	require_cmd git

	if ! git -C "$SOURCE_REPO" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		echo "Source repository not found: $SOURCE_REPO" >&2
		exit 1
	fi
	# The source repository is an object store: only its committed HEAD is used
	# to create/update the detached build worktree. Its primary checkout may be
	# intentionally empty to save RAM and is therefore not a build input.
	for patch_file in "${PATCH_FILES[@]}"; do
		if [ ! -f "$patch_file" ]; then
			echo "Patch file not found: $patch_file" >&2
			exit 1
		fi
	done

	head="$(git -C "$SOURCE_REPO" rev-parse HEAD)"
	state_id="$(compute_source_state_id)"
	ASUSWRT_RUST_STATE_ID="$(compute_rust_state_id)"
	state_file="$WORKTREE_DIR/.asuswrt-build-state"
	ASUSWRT_SOURCE_STATE_ID="$state_id"
	ASUSWRT_FAST_REUSE_HIT=0
	mkdir -p "$(dirname "$WORKTREE_DIR")"

	if git -C "$WORKTREE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		old_head="$(git -C "$WORKTREE_DIR" rev-parse HEAD 2>/dev/null || true)"
		if [ "$BUILD_MODE" != "clean" ] &&
			[ "$old_head" = "$head" ] &&
			[ -f "$state_file" ] &&
			[ "$(cat "$state_file")" = "$state_id" ]; then
			echo "Reusing prepared fast worktree in $WORKTREE_DIR"
			ASUSWRT_FAST_REUSE_HIT=1
			return
		fi

		git -C "$WORKTREE_DIR" reset --hard >/dev/null
		# Any fast-state miss means that upstream, patches or preparation logic
		# changed. Keep incremental objects only for an exact state hit.
		git -C "$WORKTREE_DIR" clean -fdx >/dev/null
		git -C "$WORKTREE_DIR" checkout --detach "$head" >/dev/null
	else
		rm -rf "$WORKTREE_DIR"
		git -C "$SOURCE_REPO" worktree add --detach "$WORKTREE_DIR" "$head" >/dev/null
	fi

	git -C "$WORKTREE_DIR" reset --hard "$head" >/dev/null
	if [ "$BUILD_MODE" != "fast" ]; then
		git -C "$WORKTREE_DIR" clean -fdx >/dev/null
	fi

	for patch_file in "${PATCH_FILES[@]}"; do
		echo "Applying local overlay: $(basename "$patch_file")"
		git -C "$WORKTREE_DIR" apply --recount --3way "$patch_file"
	done
}

normalize_source_timestamps() {
	if [ "$KERNEL_CACHE_REUSE" = "1" ]; then
		find "$ROOT" -path "$SDK_DIR/kernel/linux-4.1" -prune -o \
			-type f -exec touch -c {} +
	else
		find "$ROOT" -type f -exec touch -c {} +
	fi
}

normalize_autotools_timestamps() {
	find "$ROOT/release/src/router" -type f \
		\( -name configure -o \
		-name configure.ac -o \
		-name configure.in -o \
		-name aclocal.m4 -o \
		-name Makefile.am -o \
		-name Makefile.in -o \
		-name config.status \) \
		-exec touch -c {} + 2>/dev/null
}

refresh_profile_cookie() {
	printf '%s\n' "$PROFILE" > "$SDK_DIR/.last_profile"
	touch "$SDK_DIR/.last_profile"
}

ensure_hosttools() {
	local missing=0
	local cmd

	for cmd in bison flex autopoint makeinfo gperf libtool autoreconf aclocal; do
		if [ ! -x "$HOSTTOOLS/usr/bin/$cmd" ]; then
			missing=1
			break
		fi
	done

	if [ ! -f "$HOSTTOOLS/usr/share/aclocal/ax_code_coverage.m4" ]; then
		missing=1
	fi

	if [ "$missing" -eq 1 ]; then
		mkdir -p "$HOSTTOOLS" "$APT_CACHE"
		(
			cd "$APT_CACHE"
			apt-get download \
				autoconf \
				autoconf-archive \
				automake \
				autopoint \
				bison \
				flex \
				gperf \
				libtext-unidecode-perl \
				libtool-bin \
				texinfo
			for deb in *.deb; do
				dpkg-deb -x "$deb" "$HOSTTOOLS"
			done
		)
	fi

	mkdir -p "$HOSTTOOLS/usr/share/texinfo/Text"
	if [ -f "$HOSTTOOLS/usr/share/perl5/Text/Unidecode.pm" ] && [ ! -e "$HOSTTOOLS/usr/share/texinfo/Text/Unidecode.pm" ]; then
		ln -s ../../perl5/Text/Unidecode.pm "$HOSTTOOLS/usr/share/texinfo/Text/Unidecode.pm"
	fi

	cat > "$HOSTTOOLS/usr/bin/yacc" <<EOF
#!/bin/sh
exec "$HOSTTOOLS/usr/bin/bison" -y "\$@"
EOF
	chmod +x "$HOSTTOOLS/usr/bin/yacc"
}

prepare_gt_ax11000_tree() {
	local strongswan="$ROOT/release/src/router/strongswan"
	local lib_prefix_src="$ROOT/release/src/router/libgpg-error-1.10/m4/lib-prefix.m4"
	local lib_prefix_dst="$strongswan/m4/config/lib-prefix.m4"
	local libnl="$SDK_DIR/bcmdrivers/broadcom/net/wl/impl51/main/components/opensource/router_tools/libnl"
	local zlib="$ROOT/release/src/router/zlib"
	local pkg
	local pid
	local prepare_failed=0
	local -a prepare_pids=()
	local autoreconf_pkgs=(
		haveged
		inadyn
		ipset-7.6
		jq-1.7.1
		jq-1.7.1/modules/oniguruma
		libogg
		lighttpd-1.4.39
		lldpd-0.9.8
		nano
		nettle
		onig-6.9.9
		openvpn
		pcre-8.31
		tor
		wget
	)
	local autoreconf_env=(
		PATH="$HOSTTOOLS/usr/bin:$PATH"
		ACLOCAL_PATH="$HOSTTOOLS/usr/share/aclocal"
		BISON_PKGDATADIR="$HOSTTOOLS/usr/share/bison"
		gettext_datadir="$HOSTTOOLS/usr/share/gettext"
		M4=/usr/bin/m4
		M4PATH="$HOSTTOOLS/usr/share/flex/m4"
	)

	if [ -d "$SDK_DIR/hostTools/squashfs_4.2" ]; then
		make -C "$SDK_DIR/hostTools/squashfs_4.2" EXTRA_CFLAGS="-std=gnu89" >/dev/null
	fi

	if [ -f "$lib_prefix_src" ] && [ ! -f "$lib_prefix_dst" ]; then
		mkdir -p "$(dirname "$lib_prefix_dst")"
		cp "$lib_prefix_src" "$lib_prefix_dst"
	fi

	if [ -d "$strongswan" ]; then
		(
			cd "$strongswan"
			env "${autoreconf_env[@]}" autoreconf -i >/dev/null
		)

		(
			cd "$strongswan/src/starter"
			sed -e 's:@GPERF_LEN_TYPE@:size_t:' keywords.h.in > keywords.h
			"$HOSTTOOLS/usr/bin/gperf" -m 10 -C -G -D -t --output-file=keywords.c keywords.txt
		)

		(
			cd "$strongswan/src/stroke"
			sed -e 's:@GPERF_LEN_TYPE@:size_t:' stroke_keywords.h.in > stroke_keywords.h
			"$HOSTTOOLS/usr/bin/gperf" -m 10 -D -C -G -t --output-file=stroke_keywords.c stroke_keywords.txt
		)
	fi

	if [ -d "$libnl" ]; then
		(
			cd "$libnl"
			env "${autoreconf_env[@]}" autoreconf -fi >/dev/null
		)
	fi

	echo "Preparing independent Autotools packages with up to $PREPARE_JOBS workers"
	for pkg in "${autoreconf_pkgs[@]}"; do
		if [ -f "$ROOT/release/src/router/$pkg/configure.ac" ] || [ -f "$ROOT/release/src/router/$pkg/configure.in" ]; then
			(
				cd "$ROOT/release/src/router/$pkg"
				echo "Preparing Autotools package: $pkg"
				env "${autoreconf_env[@]}" autoreconf -fi >/dev/null
			) &
			prepare_pids+=("$!")

			if [ "${#prepare_pids[@]}" -ge "$PREPARE_JOBS" ]; then
				for pid in "${prepare_pids[@]}"; do
					if ! wait "$pid"; then
						prepare_failed=1
					fi
				done
				prepare_pids=()
				if [ "$prepare_failed" -ne 0 ]; then
					return 1
				fi
			fi
		fi
	done
	for pid in "${prepare_pids[@]}"; do
		if ! wait "$pid"; then
			prepare_failed=1
		fi
	done
	if [ "$prepare_failed" -ne 0 ]; then
		return 1
	fi

	if [ -d "$zlib" ] && grep -q "Please use ./configure first" "$zlib/Makefile" 2>/dev/null; then
		rm -f "$zlib/stamp-h1"
	fi
}

for cmd in apt-get cargo cmp dpkg-deb make md5sum rsync rustc sha256sum; do
	require_cmd "$cmd"
done

case "$DIRECT_TOOLCHAIN" in
	0)
		require_cmd mount
		require_cmd unshare
		;;
	1)
		require_cmd readlink
		require_cmd sudo
		;;
	*)
		echo "ASUSWRT_DIRECT_TOOLCHAIN must be 0 or 1" >&2
		exit 2
		;;
esac

case "$BUILD_MODE" in
	clean|fast|rust-fast)
		;;
	*)
		echo "ASUSWRT_BUILD_MODE must be clean, fast or rust-fast" >&2
		exit 2
		;;
esac

if ! [[ "$MAKE_JOBS" =~ ^[0-9]+$ ]] || [ "$MAKE_JOBS" -lt 1 ]; then
	echo "ASUSWRT_MAKE_JOBS must be a positive integer" >&2
	exit 2
fi

if [ "$MAKE_JOBS" -ne 1 ]; then
	echo "ASUSWRT_MAKE_JOBS must remain 1: the vendor top-level graph has destructive unordered prerequisites" >&2
	exit 2
fi

if ! [[ "$ROUTER_PACKAGE_JOBS" =~ ^[0-9]+$ ]] || [ "$ROUTER_PACKAGE_JOBS" -lt 1 ]; then
	echo "ROUTER_PACKAGE_JOBS must be a positive integer" >&2
	exit 2
fi

if [ "$ROUTER_PACKAGE_JOBS" -gt "$(nproc)" ]; then
	echo "ROUTER_PACKAGE_JOBS cannot exceed the available $(nproc) CPU threads" >&2
	exit 2
fi

if [ "$ROUTER_PACKAGE_JOBS" -gt 1 ]; then
	echo "Experimental parallel router DAG enabled with $ROUTER_PACKAGE_JOBS shared job tokens"
fi

if ! [[ "$PREPARE_JOBS" =~ ^[0-9]+$ ]] || [ "$PREPARE_JOBS" -lt 1 ]; then
	echo "ASUSWRT_PREPARE_JOBS must be a positive integer" >&2
	exit 2
fi

case "$CCACHE_ENABLED" in
	0|1)
		;;
	*)
		echo "ASUSWRT_CCACHE must be 0 or 1" >&2
		exit 2
		;;
esac

# Discover a missing ccache executable here, before the GNU Make bootstrap
# and source adaptation, instead of failing minutes later inside the toolchain
# view wrapper. Disabling keeps the cache RAM-only: nothing is written at all.
# ASUSWRT_CCACHE_STATUS is internal: the worktree re-exec below passes the
# downgrade reason to the inner driver. It is never trusted to claim more than
# CCACHE_ENABLED allows, so a stray value cannot report an enabled cache.
CCACHE_STATUS=disabled
if [ "$CCACHE_ENABLED" = "1" ]; then
	if command -v ccache >/dev/null 2>&1; then
		CCACHE_STATUS=enabled
	else
		echo "Warning: ASUSWRT_CCACHE=1 but no ccache executable is available; continuing without the HND compiler cache" >&2
		CCACHE_ENABLED=0
		CCACHE_STATUS=auto-disabled-missing-executable
	fi
elif [ -n "${ASUSWRT_BUILD_WORKTREE:-}" ] &&
	[ "${ASUSWRT_CCACHE_STATUS:-}" = "auto-disabled-missing-executable" ]; then
	CCACHE_STATUS=auto-disabled-missing-executable
fi

case "$KERNEL_CACHE_RESTORE" in
	0|1)
		;;
	*)
		echo "ASUSWRT_KERNEL_CACHE_RESTORE must be 0 or 1" >&2
		exit 2
		;;
esac

if [ -z "$FORCE_PROFILE" ]; then
	FORCE_PROFILE=0
fi

case "$FORCE_PROFILE" in
	0|1)
		;;
	*)
		echo "ASUSWRT_FORCE_PROFILE must be 0 or 1" >&2
		exit 2
		;;
esac

case "$REQUIRE_TMPFS" in
	0|1)
		;;
	*)
		echo "ASUSWRT_REQUIRE_TMPFS must be 0 or 1" >&2
		exit 2
		;;
esac

ensure_gnu_make
export PATH="$GNU_MAKE_BINDIR:$PATH"

if [ "$REQUIRE_TMPFS" = "1" ]; then
	verify_ram_only_paths
fi

if [ -z "${ASUSWRT_SOURCE_STATE_ID:-}" ]; then
	ASUSWRT_SOURCE_STATE_ID="$(compute_source_state_id)"
fi
if [ -z "${ASUSWRT_RUST_STATE_ID:-}" ]; then
	ASUSWRT_RUST_STATE_ID="$(compute_rust_state_id)"
fi

if [ -z "${ASUSWRT_BUILD_WORKTREE:-}" ]; then
	if [ "$BUILD_MODE" != "clean" ]; then
		echo "Preparing reusable $BUILD_MODE source worktree in $WORKTREE_DIR"
	else
		echo "Preparing clean source worktree in $WORKTREE_DIR"
	fi
	worktree_prepare_started=$SECONDS
	prepare_source_worktree
	WORKTREE_PREP_SECONDS=$((SECONDS - worktree_prepare_started))
	if [ "$BUILD_MODE" = "rust-fast" ] && [ "$ASUSWRT_FAST_REUSE_HIT" != "1" ]; then
		echo "rust-fast requires an exact prepared-source state from a prior full build" >&2
		exit 1
	fi
	exec env \
		ASUSWRT_BUILD_STARTED_EPOCH="$BUILD_STARTED_EPOCH" \
		ASUSWRT_WORKTREE_PREP_SECONDS="$WORKTREE_PREP_SECONDS" \
		ASUSWRT_BUILD_WORKTREE=1 \
		ASUSWRT_BUILD_MODE="$BUILD_MODE" \
		ASUSWRT_CCACHE="$CCACHE_ENABLED" \
		ASUSWRT_CCACHE_STATUS="$CCACHE_STATUS" \
		ASUSWRT_FORCE_PROFILE="$FORCE_PROFILE" \
		ASUSWRT_FAST_REUSE_HIT="$ASUSWRT_FAST_REUSE_HIT" \
		ASUSWRT_SOURCE_STATE_ID="$ASUSWRT_SOURCE_STATE_ID" \
		ASUSWRT_RUST_STATE_ID="$ASUSWRT_RUST_STATE_ID" \
		ASUSWRT_SOURCE_ROOT="$WORKTREE_DIR" \
		ASUSWRT_OUTPUT_DIR="$OUTPUT_DIR" \
		"$SCRIPT_ROOT/build.sh" "$DEVICE"
fi

if [ ! -d "$SDK_DIR" ]; then
	echo "SDK directory not found: $SDK_DIR" >&2
	exit 1
fi

if [ ! -d "$TOOLCHAIN_SRC" ]; then
	echo "Toolchain directory not found: $TOOLCHAIN_SRC" >&2
	echo "Set AM_TOOLCHAINS if your Asuswrt-Merlin toolchains live elsewhere." >&2
	exit 1
fi

if [ ! -f "$RUST_REPACK_MAKEFILE" ]; then
	echo "Manifest-bound repack makefile not found: $RUST_REPACK_MAKEFILE" >&2
	exit 1
fi

if [ "$KERNEL_CACHE_RESTORE" = "1" ]; then
	expected_kernel_cache="$(compute_kernel_cache_contract_id)"
	if [ ! -f "$KERNEL_CACHE_STATE_FILE" ] || [ -L "$KERNEL_CACHE_STATE_FILE" ]; then
		echo "Exact kernel cache hit has no trustworthy state file" >&2
		exit 1
	fi
	actual_kernel_cache="$(cat "$KERNEL_CACHE_STATE_FILE")"
	if [ "$actual_kernel_cache" != "$expected_kernel_cache" ]; then
		echo "Exact kernel cache contract mismatch: expected $expected_kernel_cache, got $actual_kernel_cache" >&2
		exit 1
	fi
	for kernel_artifact in \
		.config vmlinux Module.symvers include/generated/autoconf.h \
		include/config/auto.conf arch/arm64/boot/Image .pre_kernelbuild
	do
		if [ ! -f "$SDK_DIR/kernel/linux-4.1/$kernel_artifact" ]; then
			echo "Exact kernel cache is incomplete: $kernel_artifact" >&2
			exit 1
		fi
	done
	for dtb in 94908.dtb 94908REF.dtb; do
		if [ ! -s "$SDK_DIR/kernel/dts/4908/$dtb" ]; then
			echo "Exact kernel cache is incomplete: kernel/dts/4908/$dtb" >&2
			exit 1
		fi
	done
	if [ -z "$(find "$SDK_DIR/targets/$PROFILE/modules" -type f -name '*.ko' -print -quit 2>/dev/null)" ]; then
		echo "Exact kernel cache has no installed kernel modules" >&2
		exit 1
	fi
	KERNEL_CACHE_REUSE=1
	echo "Reusing exact successful kernel cache $expected_kernel_cache"
fi

source_adapt_started=$SECONDS
echo "Installing Rust component overlay"
verify_locked_inputs
install_rust_components

echo "Verifying security overlay invariants"
bash "$SECURITY_OVERLAY_TEST" "$ROOT"
echo "Verifying network hardening invariants"
bash "$NETWORK_HARDENING_TEST" "$ROOT"

if [ "$BUILD_MODE" != "clean" ]; then
	echo "Skipping full source timestamp normalization in $BUILD_MODE mode"
else
	echo "Normalizing source timestamps in $ROOT"
	normalize_source_timestamps
fi

echo "Preparing WSL host tools in $HOSTTOOLS"
ensure_hosttools

case "$MAKE_TARGET" in
	gt-ax11000)
		if [ "$BUILD_MODE" != "clean" ] && [ "${ASUSWRT_FAST_REUSE_HIT:-0}" = "1" ]; then
			echo "Reusing previously generated $BUILD_NAME source adaptations"
		else
			echo "Preparing $BUILD_NAME source adaptations"
			prepare_gt_ax11000_tree
		fi
		if [ -n "${ASUSWRT_SOURCE_STATE_ID:-}" ]; then
			printf '%s\n' "$ASUSWRT_SOURCE_STATE_ID" > "$ROOT/.asuswrt-build-state"
		fi
		;;
esac

if [ "$BUILD_MODE" = "fast" ] && [ "${ASUSWRT_FAST_REUSE_HIT:-0}" != "1" ]; then
	echo "Normalizing Autotools timestamps for fast rebuild"
	normalize_autotools_timestamps
elif [ "$BUILD_MODE" = "fast" ]; then
	echo "Preserving generated timestamps for reused fast worktree"
fi

if [ "$BUILD_MODE" = "fast" ] && [ "$FORCE_PROFILE" = "1" ]; then
	echo "Refreshing $BUILD_NAME profile cookie for fast rebuild"
	refresh_profile_cookie
fi

full_build_state="$ROOT/.asuswrt-full-build-state"
if [ "$BUILD_MODE" = "rust-fast" ]; then
	full_build_contract="$(compute_full_build_contract_id)"
	if [ "$FORCE_PROFILE" != "0" ]; then
		echo "rust-fast cannot refresh or change the board profile" >&2
		exit 1
	fi
	if [ "${ASUSWRT_FAST_REUSE_HIT:-0}" != "1" ] ||
		[ ! -f "$full_build_state" ] ||
		[ "$(cat "$full_build_state")" != "$full_build_contract" ]; then
		echo "rust-fast requires a successful full build with the exact source, profile, toolchain and Rust target contract" >&2
		exit 1
	fi
fi

if [ "$CCACHE_ENABLED" = "1" ]; then
	echo "Preparing persistent HND compiler cache in $CCACHE_DIR"
	prepare_ccache_toolchain_view
fi
source_adapt_seconds=$((SECONDS - source_adapt_started))

DIRECT_TOOLCHAIN_LINK_CREATED=0
cleanup_direct_toolchain() {
	if [ "$DIRECT_TOOLCHAIN_LINK_CREATED" -eq 1 ]; then
		sudo rm -f /opt/toolchains
	fi
}
trap cleanup_direct_toolchain EXIT

build_shell=(unshare --user --map-root-user --mount --propagation private bash)
if [ "$DIRECT_TOOLCHAIN" = "1" ]; then
	sudo mkdir -p /opt
	if [ -e /opt/toolchains ] || [ -L /opt/toolchains ]; then
		if [ "$(readlink -f /opt/toolchains)" != "$(readlink -f "$TOOLCHAIN_MOUNT_SRC")" ]; then
			echo "/opt/toolchains already exists and points elsewhere" >&2
			exit 1
		fi
	else
		sudo ln -s "$TOOLCHAIN_MOUNT_SRC" /opt/toolchains
		DIRECT_TOOLCHAIN_LINK_CREATED=1
	fi
	build_shell=(bash)
fi

export ROOT SDK_PATH MAKE_TARGET TOOLCHAINS TOOLCHAIN_SRC TOOLCHAIN_MOUNT_SRC HOSTTOOLS FAKEBIN LOG_FILE OUTER_USER
export MAKE_JOBS ROUTER_PACKAGE_JOBS PREPARE_JOBS BUILD_MODE FORCE_PROFILE
export GNU_MAKE_VERSION GNU_MAKE_SHA256 GNU_MAKE_BINDIR GNU_MAKE_BIN
export ASUSWRT_KERNEL_REUSE="$KERNEL_CACHE_REUSE"
export DIRECT_TOOLCHAIN CCACHE_ENABLED CCACHE_DIR CCACHE_MAXSIZE CCACHE_PATH_VALUE
export RUST_REPACK_MAKEFILE RUST_CONSUMER_MANIFEST WEB_PAYLOAD_MANIFEST WEB_SYMLINK_MANIFEST
export RUST_TOOLCHAIN RUST_TARGET RUST_CPU_FLAGS

echo "Building $BUILD_NAME via $SDK_PATH with $MAKE_JOBS jobs ($BUILD_MODE mode)"
mkdir -p "$OUTPUT_DIR"
rm -f -- "$RUST_CONSUMER_MANIFEST" "$WEB_PAYLOAD_MANIFEST" "$WEB_SYMLINK_MANIFEST"
find "$OUTPUT_DIR" -maxdepth 1 -type f \
	\( -name "$IMAGE_GLOB" -o -name "output-${MAKE_TARGET}-wsl.log" -o \
	-name SHA256SUMS -o -name MD5SUMS -o -name RUST-CONSUMERS.sha256 -o \
	-name WEB-PAYLOAD.sha256 -o -name WEB-SYMLINKS.manifest -o \
	-name BUILD-STATE.txt \) -delete
find "$SDK_DIR/image" "$SDK_DIR/targets/$PROFILE" -maxdepth 1 -type f \
	-name "$IMAGE_GLOB" -delete 2>/dev/null || true
build_started_marker="$(mktemp --tmpdir asuswrt-build-start.XXXXXX)"
touch "$build_started_marker"
build_started_epoch="$(stat -c '%Y' "$build_started_marker")"
vendor_build_started=$SECONDS
set +e
"${build_shell[@]}" <<'EOF'
set -euo pipefail

mkdir -p "$FAKEBIN"
if [ "$DIRECT_TOOLCHAIN" = "0" ]; then
	mount -t tmpfs tmpfs /opt
	mkdir -p /opt/toolchains
	mount --bind "$TOOLCHAIN_MOUNT_SRC" /opt/toolchains
fi

cat > "$FAKEBIN/whoami" <<WHOAMI
#!/bin/sh
echo "$OUTER_USER"
WHOAMI

cat > "$FAKEBIN/pkg-config" <<'PKGCONFIG'
#!/bin/sh
exec /usr/bin/pkg-config "$@"
PKGCONFIG

cat > "$FAKEBIN/tar" <<'TARWRAP'
#!/bin/sh
for arg do
	case "$arg" in
		--version|--help|--usage)
			exec /usr/bin/tar "$@"
			;;
	esac
done
if [ "$#" -ge 2 ] && [ "${1#-}" = "$1" ]; then
	case "$1" in
		*x*f*|*f*x*|*x*)
			mode="$1"
			archive="$2"
			shift 2
			exec /usr/bin/tar "$mode" "$archive" --no-same-owner "$@"
			;;
	esac
fi
case "$1" in
	-*x*|--extract)
		exec /usr/bin/tar --no-same-owner "$@"
		;;
esac
exec /usr/bin/tar "$@"
TARWRAP

chmod +x "$FAKEBIN/whoami" "$FAKEBIN/pkg-config" "$FAKEBIN/tar"

export TOOLCHAIN_BASE=/opt/toolchains
export ACLOCAL_PATH="$HOSTTOOLS/usr/share/aclocal"
export BISON_PKGDATADIR="$HOSTTOOLS/usr/share/bison"
export gettext_datadir="$HOSTTOOLS/usr/share/gettext"
export M4=/usr/bin/m4
export M4PATH="$HOSTTOOLS/usr/share/flex/m4"
export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig
if [ "$CCACHE_ENABLED" = "1" ]; then
	export CCACHE_PATH="$CCACHE_PATH_VALUE"
	export CCACHE_BASEDIR="$ROOT"
	export CCACHE_COMPILERCHECK=content
	export CCACHE_NOHASHDIR=true
	export CCACHE_UMASK=002
fi
export LD_LIBRARY_PATH="/opt/toolchains/crosstools-arm-gcc-5.5-linux-4.1-glibc-2.26-binutils-2.28.1/lib:/opt/toolchains/crosstools-aarch64-gcc-5.5-linux-4.1-glibc-2.26-binutils-2.28.1/lib:/opt/toolchains/crosstools-arm-gcc-5.3-linux-4.1-glibc-2.22-binutils-2.25/lib:/opt/toolchains/crosstools-arm-gcc-5.5-linux-4.1-glibc-2.26-binutils-2.28.1/usr/lib:/opt/toolchains/crosstools-arm-gcc-5.3-linux-4.1-glibc-2.22-binutils-2.25/usr/lib:$HOSTTOOLS/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
export PATH="$GNU_MAKE_BINDIR:$HOME/.cargo/bin:$FAKEBIN:$HOSTTOOLS/usr/bin:/opt/toolchains/crosstools-arm-gcc-5.5-linux-4.1-glibc-2.26-binutils-2.28.1/usr/bin:/opt/toolchains/crosstools-aarch64-gcc-5.5-linux-4.1-glibc-2.26-binutils-2.28.1/usr/bin:$TOOLCHAINS/brcm-arm-sdk/hndtools-armeabi-2011.09/bin:$TOOLCHAINS/brcm-arm-sdk/hndtools-armeabi-2013.11/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

cd "$ROOT/$SDK_PATH"
make_args=()
if [ "${FORCE_PROFILE:-0}" = "1" ]; then
	make_args+=(FORCE=1)
fi
make_rc=1
if [ "$BUILD_MODE" = "rust-fast" ]; then
	: > "$LOG_FILE"
	{
		echo "Rust-only relink and firmware repack"
		stage_started=$SECONDS
		make -j1 -f Makefile -f "$RUST_REPACK_MAKEFILE" \
			SHELL=/bin/bash "HOSTCFLAGS+=-fcommon" rust-components-relink
		echo "RUST_RELINK_SECONDS=$((SECONDS - stage_started))"
		stage_started=$SECONDS
		make -j1 -f Makefile -f "$RUST_REPACK_MAKEFILE" \
			SHELL=/bin/bash rust-firmware-repack
		echo "FIRMWARE_REPACK_SECONDS=$((SECONDS - stage_started))"
	} 2>&1 | tee "$LOG_FILE"
	make_rc=${PIPESTATUS[0]}
else
for attempt in 1 2; do
	set +e
	if [ "$attempt" -eq 1 ]; then
		make -j"$MAKE_JOBS" SHELL=/bin/bash "HOSTCFLAGS+=-fcommon" "${make_args[@]}" "$MAKE_TARGET" 2>&1 | tee "$LOG_FILE"
	else
		make -j"$MAKE_JOBS" SHELL=/bin/bash "HOSTCFLAGS+=-fcommon" "${make_args[@]}" "$MAKE_TARGET" 2>&1 | tee -a "$LOG_FILE"
	fi
	make_rc=${PIPESTATUS[0]}
	set -e
	if [ "$make_rc" -eq 0 ]; then
		break
	fi
	if [ "$attempt" -eq 1 ] && /usr/bin/grep -Fq "Please run the same make command again" "$LOG_FILE"; then
		echo "OpenSSL regenerated its makefiles; retrying the same build command once." | tee -a "$LOG_FILE"
		continue
	fi
	break
done
if [ "$make_rc" -eq 0 ]; then
	set +e
	{
		echo "Finalizing firmware through the common manifest-bound repack"
		stage_started=$SECONDS
		make -j1 -f Makefile -f "$RUST_REPACK_MAKEFILE" \
			SHELL=/bin/bash rust-firmware-repack
		echo "FIRMWARE_REPACK_SECONDS=$((SECONDS - stage_started))"
	} 2>&1 | tee -a "$LOG_FILE"
	make_rc=${PIPESTATUS[0]}
	set -e
fi
fi
exit "$make_rc"
EOF
build_rc=$?
set -e
vendor_build_seconds=$((SECONDS - vendor_build_started))
post_build_gate_started=$SECONDS

mapfile -d '' built_images < <(
	find "$SDK_DIR/image" "$SDK_DIR/targets/$PROFILE" -maxdepth 1 -type f \
		-name "$IMAGE_GLOB" -newer "$build_started_marker" -print0 2>/dev/null
)
compute_vendor_phase_timings "${built_images[0]:-}"

if [ "$build_rc" -eq 0 ] && [ "${#built_images[@]}" -ne 1 ]; then
	echo "Build produced ${#built_images[@]} fresh firmware images; expected exactly one" >&2
	build_rc=1
fi

rt_tables_link="$SDK_DIR/targets/$PROFILE/fs/tmp/etc/iproute2/rt_tables"
if [ "$build_rc" -eq 0 ] && { [ ! -L "$rt_tables_link" ] || [ "$(readlink "$rt_tables_link")" != "/var/iproute2/rt_tables" ]; }; then
	echo "Required rootfs link is missing or incorrect: $rt_tables_link" >&2
	build_rc=1
fi

rootfs_dir="$SDK_DIR/targets/$PROFILE/fs"
dict_enum_file=$(find "$SDK_DIR" -type f -path '*/src/image/dictenum.txt' -print -quit)
# The five Rust-built binaries are what rust-components-relink (rust-repack.mk)
# reinstalls in rust-fast mode. The closed networkmap and its Rust libbwdpi.so
# provider are only built by networkmap-install, which a full build runs and
# rust-fast does not: there they are carried from the cached tree with their
# old timestamps and are bound only by the manifest hash check below.
rust_relinked_consumers=(
	usr/sbin/infosvr
	bin/rstats
	usr/sbin/Notify_Event2NC
	usr/sbin/httpd
	sbin/rc
)
rust_consumers=(
	"${rust_relinked_consumers[@]}"
	usr/sbin/networkmap
	usr/lib/libbwdpi.so
)
fresh_consumers=("${rust_consumers[@]}")
if [ "$BUILD_MODE" = "rust-fast" ]; then
	fresh_consumers=("${rust_relinked_consumers[@]}")
fi
if [ "$build_rc" -eq 0 ]; then
	for consumer in "${fresh_consumers[@]}"; do
		if [ ! -f "$rootfs_dir/$consumer" ] || [ ! "$rootfs_dir/$consumer" -nt "$build_started_marker" ]; then
			echo "Rust consumer was not freshly installed by this build: $rootfs_dir/$consumer" >&2
			build_rc=1
		fi
	done
fi

if [ "$build_rc" -eq 0 ]; then
	if ! bash "$NO_PROPRIETARY_QOS_ROOTFS_TEST" "$rootfs_dir"; then
		echo "Rootfs contains proprietary QoS artifacts or lacks the local replacement" >&2
		build_rc=1
	fi
fi

if [ "$build_rc" -eq 0 ]; then
	if [ ! -s "$RUST_CONSUMER_MANIFEST" ]; then
		echo "Rust repack did not publish an expected consumer manifest" >&2
		build_rc=1
	elif ! (cd "$rootfs_dir" && sha256sum --check --strict "$RUST_CONSUMER_MANIFEST"); then
		echo "Repacked rootfs does not contain the exact freshly linked Rust consumers" >&2
		build_rc=1
	fi
	if [ ! -s "$WEB_PAYLOAD_MANIFEST" ]; then
		echo "Rust repack did not publish the complete AUTODICT Web manifest" >&2
		build_rc=1
	elif [ -e "$rootfs_dir/www/www" ]; then
		echo "Repacked rootfs contains a forbidden nested /www/www tree" >&2
		build_rc=1
	elif ! cmp -s "$WEB_PAYLOAD_MANIFEST" "$rootfs_dir/usr/share/codex/web-payload.sha256"; then
		echo "Rootfs does not embed the exact generated AUTODICT Web manifest" >&2
		build_rc=1
	elif ! cmp -s "$WEB_SYMLINK_MANIFEST" "$rootfs_dir/usr/share/codex/web-symlinks.manifest"; then
		echo "Rootfs does not embed the exact generated Web symlink manifest" >&2
		build_rc=1
	elif ! (cd "$rootfs_dir" && sha256sum --check --strict "$WEB_PAYLOAD_MANIFEST"); then
		echo "Repacked rootfs Web pages and dictionaries do not match the generated set" >&2
		build_rc=1
	elif [ -z "$dict_enum_file" ] || \
		! bash "$WEB_PAYLOAD_TEST" "$rootfs_dir" "$dict_enum_file" "$WEB_PAYLOAD_MANIFEST"; then
		echo "Repacked AUTODICT Web payload failed semantic validation" >&2
		build_rc=1
	elif ! bash "$WEB_SYMLINK_TEST" "$rootfs_dir" "$WEB_SYMLINK_MANIFEST"; then
		echo "Repacked Web symlink set failed validation" >&2
		build_rc=1
	fi
fi

rm -f -- "$build_started_marker"

echo
echo "Build outputs:"
find "$SDK_DIR/image" "$SDK_DIR/targets/$PROFILE" -maxdepth 1 -type f -name "$IMAGE_GLOB" -printf '%s %p\n' 2>/dev/null | sort -n

echo
echo "SHA256:"
find "$SDK_DIR/image" "$SDK_DIR/targets/$PROFILE" -maxdepth 1 -type f -name "$IMAGE_GLOB" -print0 2>/dev/null | xargs -0r sha256sum

echo
if [ "$build_rc" -eq 0 ]; then
	cp -f -- "${built_images[0]}" "$OUTPUT_DIR/"
	cp -f "$LOG_FILE" "$OUTPUT_DIR/" 2>/dev/null || true
	output_image="$OUTPUT_DIR/$(basename "${built_images[0]}")"
	(
		cd "$OUTPUT_DIR"
		sha256sum "$(basename "$output_image")"
	) > "$OUTPUT_DIR/SHA256SUMS"
	(
		cd "$OUTPUT_DIR"
		md5sum "$(basename "$output_image")"
	) > "$OUTPUT_DIR/MD5SUMS"
	(
		cd "$rootfs_dir"
		sha256sum "${rust_consumers[@]}"
	) > "$OUTPUT_DIR/RUST-CONSUMERS.sha256"
	cp -f "$WEB_PAYLOAD_MANIFEST" "$OUTPUT_DIR/WEB-PAYLOAD.sha256"
	cp -f "$WEB_SYMLINK_MANIFEST" "$OUTPUT_DIR/WEB-SYMLINKS.manifest"
	{
		echo "upstream_sha=$(git -C "$SOURCE_REPO" rev-parse HEAD)"
		echo "source_state=${ASUSWRT_SOURCE_STATE_ID:-unknown}"
		echo "rust_state=${ASUSWRT_RUST_STATE_ID:-unknown}"
		echo "full_build_contract=$(compute_full_build_contract_id)"
		echo "toolchain_state=$(compute_toolchain_state_id)"
		echo "profile=$PROFILE"
		echo "sdk_config_sha256=$(hash_file_or_missing "$SDK_DIR/.config")"
		echo "router_config_sha256=$(hash_file_or_missing "$ROOT/release/src/router/.config")"
		echo "kernel_config_sha256=$(hash_file_or_missing "$SDK_DIR/kernel/linux-4.1/.config")"
		echo "rust_toolchain=$RUST_TOOLCHAIN"
		echo "rust_target=$RUST_TARGET"
		echo "rust_cpu_flags=$RUST_CPU_FLAGS"
		echo "gnu_make_version=$GNU_MAKE_VERSION"
		echo "gnu_make_sha256=$GNU_MAKE_SHA256"
		echo "router_package_jobs=$ROUTER_PACKAGE_JOBS"
		echo "kernel_cache_reuse=$KERNEL_CACHE_REUSE"
		echo "ccache_enabled=$CCACHE_ENABLED"
		echo "ccache_status=$CCACHE_STATUS"
		echo "build_mode=$BUILD_MODE"
		echo "force_profile=$FORCE_PROFILE"
		echo "firmware_sha256=$(sha256sum "$output_image" | awk '{print $1}')"
		echo "rust_consumers_manifest_sha256=$(sha256sum "$RUST_CONSUMER_MANIFEST" | awk '{print $1}')"
		echo "web_payload_manifest_sha256=$(sha256sum "$WEB_PAYLOAD_MANIFEST" | awk '{print $1}')"
		echo "web_symlinks_manifest_sha256=$(sha256sum "$WEB_SYMLINK_MANIFEST" | awk '{print $1}')"
		cat "$INPUT_LOCK_STATE_FILE"
		echo "worktree_prepare_seconds=$WORKTREE_PREP_SECONDS"
		echo "source_adapt_seconds=$source_adapt_seconds"
		echo "vendor_build_seconds=$vendor_build_seconds"
		echo "vendor_prebuild_seconds=$vendor_prebuild_seconds"
		echo "kernel_build_seconds=$kernel_build_seconds"
		echo "kernel_modules_seconds=$kernel_modules_seconds"
		echo "router_foundation_seconds=$router_foundation_seconds"
		echo "router_packages_seconds=$router_packages_seconds"
		echo "image_assembly_seconds=$image_assembly_seconds"
		echo "rust_relink_seconds=$rust_relink_seconds"
		echo "firmware_repack_seconds=$firmware_repack_seconds"
		echo "post_build_gate_seconds=$((SECONDS - post_build_gate_started))"
		echo "duration_seconds=$(($(date +%s) - BUILD_STARTED_EPOCH))"
	} > "$OUTPUT_DIR/BUILD-STATE.txt"
	if [ "$BUILD_MODE" != "rust-fast" ]; then
		compute_full_build_contract_id > "$full_build_state"
		kernel_cache_state_new="$(mktemp --tmpdir asuswrt-kernel-cache-state.XXXXXX)"
		compute_kernel_cache_contract_id > "$kernel_cache_state_new"
		mv -f "$kernel_cache_state_new" "$KERNEL_CACHE_STATE_FILE"
	fi
	echo "Copied outputs to: $OUTPUT_DIR"
else
	cp -f "$LOG_FILE" "$OUTPUT_DIR/" 2>/dev/null || true
	echo "Build failed; no firmware image was published to: $OUTPUT_DIR"
fi

echo
echo "Log: $LOG_FILE"

exit "$build_rc"
