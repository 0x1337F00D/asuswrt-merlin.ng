#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_REPO="${ASUSWRT_SOURCE_REPO:-$SCRIPT_ROOT/../asuswrt-merlin.ng}"
ROOT="${ASUSWRT_SOURCE_ROOT:-$SOURCE_REPO}"
DEVICE="${1:-}"
RUST_OVERLAY="$SCRIPT_ROOT/rust"

usage() {
	cat <<EOF
Usage: ./build.sh <device_name>

Supported devices:
  gt-ax11000

Environment overrides:
  AM_TOOLCHAINS=/path/to/am-toolchains        default: \$HOME/am-toolchains
  ASUSWRT_SOURCE_REPO=/path/to/source         default: ../asuswrt-merlin.ng
  ASUSWRT_BUILD_MODE=clean|fast               default: clean
  ASUSWRT_FORCE_PROFILE=0|1                    default: 1 in fast mode, otherwise 0
  ASUSWRT_HOSTTOOLS=/tmp/path                 default: /tmp/asuswrt-hosttools
  ASUSWRT_MAKE_JOBS=1                         safety-enforced top-level orchestration
  ROUTER_PACKAGE_JOBS=1                       safe package graph; >1 is experimental
  ASUSWRT_PREPARE_JOBS=N                      parallel Autotools preparation, default: 4
  ASUSWRT_CCACHE=0|1                          cache HND cross-compiler output, default: 0
  ASUSWRT_CCACHE_DIR=/path                    default: /tmp/asuswrt-ccache
  ASUSWRT_CCACHE_MAXSIZE=size                 default: 2G
  ASUSWRT_DIRECT_TOOLCHAIN=0|1                use /opt symlink instead of unshare (CI)
  ASUSWRT_REQUIRE_TMPFS=0|1                   reject non-tmpfs build paths, default: 0
  ASUSWRT_WORKTREE_BASE=/path/to/worktrees    default: this directory
  ASUSWRT_OUTPUT_DIR=/path/to/output          default: ./output/<device>
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
APT_CACHE="${ASUSWRT_APT_CACHE:-/tmp/asuswrt-apt}"
FAKEBIN="${ASUSWRT_FAKEBIN:-/tmp/asuswrt-fakebin}"
PATCH_FILES=(
	"$SCRIPT_ROOT/patches/local-features.patch"
	"$SCRIPT_ROOT/patches/${MAKE_TARGET}-wsl.patch"
	"$SCRIPT_ROOT/patches/fast-parallel-build.patch"
	"$SCRIPT_ROOT/patches/rust-components.patch"
	"$SCRIPT_ROOT/patches/security-hardening.patch"
	"$SCRIPT_ROOT/patches/wps-shell-hardening.patch"
)
MAKE_JOBS="${ASUSWRT_MAKE_JOBS:-1}"
ROUTER_PACKAGE_JOBS="${ROUTER_PACKAGE_JOBS:-1}"
PREPARE_JOBS="${ASUSWRT_PREPARE_JOBS:-4}"
CCACHE_ENABLED="${ASUSWRT_CCACHE:-0}"
CCACHE_DIR="${ASUSWRT_CCACHE_DIR:-/tmp/asuswrt-ccache}"
CCACHE_MAXSIZE="${ASUSWRT_CCACHE_MAXSIZE:-2G}"
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
OUTER_USER="$(id -un)"

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

verify_ram_only_paths() {
	require_cmd findmnt
	require_tmpfs_path "source repository" "$SOURCE_REPO"
	require_tmpfs_path "source root" "$ROOT"
	require_tmpfs_path "build worktree" "$WORKTREE_DIR"
	require_tmpfs_path "firmware output" "$OUTPUT_DIR"
	require_tmpfs_path "temporary files" "${TMPDIR:-/tmp}"
	require_tmpfs_path "build home" "$HOME"
	require_tmpfs_path "Cargo home" "${CARGO_HOME:-$HOME/.cargo}"
	require_tmpfs_path "host tools" "$HOSTTOOLS"
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
		echo "ASUSWRT_TOOLCHAIN_VIEW already exists: $TOOLCHAIN_VIEW" >&2
		exit 1
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
		sha256sum "$SCRIPT_ROOT/build.sh" "${PATCH_FILES[@]}"
		find "$RUST_OVERLAY" -type f -not -path '*/target/*' -print0 \
			| sort -z | xargs -0 sha256sum
	} | sha256sum | awk '{print $1}'
}

install_rust_components() {
	local destination="$ROOT/release/src/router/rust-components"

	if [ ! -f "$RUST_OVERLAY/Cargo.lock" ]; then
		echo "Rust overlay not found: $RUST_OVERLAY" >&2
		exit 1
	fi
	mkdir -p "$destination"
	rsync --archive --delete --exclude target/ "$RUST_OVERLAY/" "$destination/"
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
	for patch_file in "${PATCH_FILES[@]}"; do
		if [ ! -f "$patch_file" ]; then
			echo "Patch file not found: $patch_file" >&2
			exit 1
		fi
	done

	head="$(git -C "$SOURCE_REPO" rev-parse HEAD)"
	state_id="$(compute_source_state_id)"
	state_file="$WORKTREE_DIR/.asuswrt-build-state"
	ASUSWRT_SOURCE_STATE_ID="$state_id"
	ASUSWRT_FAST_REUSE_HIT=0
	mkdir -p "$(dirname "$WORKTREE_DIR")"

	if git -C "$WORKTREE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		old_head="$(git -C "$WORKTREE_DIR" rev-parse HEAD 2>/dev/null || true)"
		if [ "$BUILD_MODE" = "fast" ] &&
			[ "$old_head" = "$head" ] &&
			[ -f "$state_file" ] &&
			[ "$(cat "$state_file")" = "$state_id" ]; then
			echo "Reusing prepared fast worktree in $WORKTREE_DIR"
			ASUSWRT_FAST_REUSE_HIT=1
			return
		fi

		git -C "$WORKTREE_DIR" reset --hard >/dev/null
		if [ "$BUILD_MODE" != "fast" ] || [ "$old_head" != "$head" ]; then
			git -C "$WORKTREE_DIR" clean -fdx >/dev/null
		fi
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
	find "$ROOT" -type f -exec touch -c {} +
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

for cmd in apt-get cargo dpkg-deb make rsync rustc sha256sum; do
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
	clean|fast)
		;;
	*)
		echo "ASUSWRT_BUILD_MODE must be clean or fast" >&2
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

if ! [[ "$ROUTER_PACKAGE_JOBS" =~ ^[0-9]+$ ]] || [ "$ROUTER_PACKAGE_JOBS" -ne 1 ]; then
	echo "ROUTER_PACKAGE_JOBS must remain 1 until repeated clean builds prove the vendor package graph race-free" >&2
	exit 2
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

if [ -z "$FORCE_PROFILE" ]; then
	if [ "$BUILD_MODE" = "fast" ]; then
		FORCE_PROFILE=1
	else
		FORCE_PROFILE=0
	fi
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

if [ "$REQUIRE_TMPFS" = "1" ]; then
	verify_ram_only_paths
fi

if [ -z "${ASUSWRT_BUILD_WORKTREE:-}" ]; then
	if [ "$BUILD_MODE" = "fast" ]; then
		echo "Preparing fast reusable source worktree in $WORKTREE_DIR"
	else
		echo "Preparing clean source worktree in $WORKTREE_DIR"
	fi
	prepare_source_worktree
	exec env \
		ASUSWRT_BUILD_WORKTREE=1 \
		ASUSWRT_BUILD_MODE="$BUILD_MODE" \
		ASUSWRT_FORCE_PROFILE="$FORCE_PROFILE" \
		ASUSWRT_FAST_REUSE_HIT="$ASUSWRT_FAST_REUSE_HIT" \
		ASUSWRT_SOURCE_STATE_ID="$ASUSWRT_SOURCE_STATE_ID" \
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

echo "Installing Rust component overlay"
install_rust_components

if [ "$BUILD_MODE" = "fast" ]; then
	echo "Skipping full source timestamp normalization in fast mode"
else
	echo "Normalizing source timestamps in $ROOT"
	normalize_source_timestamps
fi

echo "Preparing WSL host tools in $HOSTTOOLS"
ensure_hosttools

case "$MAKE_TARGET" in
	gt-ax11000)
		if [ "$BUILD_MODE" = "fast" ] && [ "${ASUSWRT_FAST_REUSE_HIT:-0}" = "1" ]; then
			echo "Reusing previously generated $BUILD_NAME source adaptations"
		else
			echo "Preparing $BUILD_NAME source adaptations"
			prepare_gt_ax11000_tree
			if [ "$BUILD_MODE" = "fast" ] && [ -n "${ASUSWRT_SOURCE_STATE_ID:-}" ]; then
				printf '%s\n' "$ASUSWRT_SOURCE_STATE_ID" > "$ROOT/.asuswrt-build-state"
			fi
		fi
		;;
esac

if [ "$BUILD_MODE" = "fast" ]; then
	echo "Normalizing Autotools timestamps for fast rebuild"
	normalize_autotools_timestamps
fi

if [ "$BUILD_MODE" = "fast" ] && [ "$FORCE_PROFILE" = "1" ]; then
	echo "Refreshing $BUILD_NAME profile cookie for fast rebuild"
	refresh_profile_cookie
fi

if [ "$CCACHE_ENABLED" = "1" ]; then
	echo "Preparing persistent HND compiler cache in $CCACHE_DIR"
	prepare_ccache_toolchain_view
fi

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
export DIRECT_TOOLCHAIN CCACHE_ENABLED CCACHE_DIR CCACHE_MAXSIZE CCACHE_PATH_VALUE

echo "Building $BUILD_NAME via $SDK_PATH with $MAKE_JOBS jobs ($BUILD_MODE mode)"
mkdir -p "$OUTPUT_DIR"
find "$OUTPUT_DIR" -maxdepth 1 -type f \
	\( -name "$IMAGE_GLOB" -o -name "output-${MAKE_TARGET}-wsl.log" \) -delete
find "$SDK_DIR/image" "$SDK_DIR/targets/$PROFILE" -maxdepth 1 -type f \
	-name "$IMAGE_GLOB" -delete 2>/dev/null || true
build_started_marker="$(mktemp --tmpdir asuswrt-build-start.XXXXXX)"
touch "$build_started_marker"
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
export LD_LIBRARY_PATH="/opt/toolchains/crosstools-arm-gcc-5.5-linux-4.1-glibc-2.26-binutils-2.28.1/usr/lib:/opt/toolchains/crosstools-arm-gcc-5.3-linux-4.1-glibc-2.22-binutils-2.25/usr/lib:${LD_LIBRARY_PATH:-}"
export PATH="$HOME/.cargo/bin:$FAKEBIN:$HOSTTOOLS/usr/bin:/opt/toolchains/crosstools-arm-gcc-5.5-linux-4.1-glibc-2.26-binutils-2.28.1/usr/bin:/opt/toolchains/crosstools-aarch64-gcc-5.5-linux-4.1-glibc-2.26-binutils-2.28.1/usr/bin:$TOOLCHAINS/brcm-arm-sdk/hndtools-armeabi-2011.09/bin:$TOOLCHAINS/brcm-arm-sdk/hndtools-armeabi-2013.11/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

cd "$ROOT/$SDK_PATH"
make_args=()
if [ "${FORCE_PROFILE:-0}" = "1" ]; then
	make_args+=(FORCE=1)
fi
make_rc=1
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
exit "$make_rc"
EOF
build_rc=$?
set -e

mapfile -d '' built_images < <(
	find "$SDK_DIR/image" "$SDK_DIR/targets/$PROFILE" -maxdepth 1 -type f \
		-name "$IMAGE_GLOB" -newer "$build_started_marker" -print0 2>/dev/null
)

if [ "$build_rc" -eq 0 ] && [ "${#built_images[@]}" -ne 1 ]; then
	echo "Build produced ${#built_images[@]} fresh firmware images; expected exactly one" >&2
	build_rc=1
fi

rt_tables_link="$SDK_DIR/targets/$PROFILE/fs/tmp/etc/iproute2/rt_tables"
if [ "$build_rc" -eq 0 ] && { [ ! -L "$rt_tables_link" ] || [ "$(readlink "$rt_tables_link")" != "/var/iproute2/rt_tables" ]; }; then
	echo "Required rootfs link is missing or incorrect: $rt_tables_link" >&2
	build_rc=1
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
	echo "Copied outputs to: $OUTPUT_DIR"
else
	cp -f "$LOG_FILE" "$OUTPUT_DIR/" 2>/dev/null || true
	echo "Build failed; no firmware image was published to: $OUTPUT_DIR"
fi

echo
echo "Log: $LOG_FILE"

exit "$build_rc"
