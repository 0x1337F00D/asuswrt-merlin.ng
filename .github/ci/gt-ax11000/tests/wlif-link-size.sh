#!/usr/bin/env bash
# Check the complete, installed GT-AX11000 library, not an isolated Rust link.
# The corrected stripped vendor link measures 637000 bytes. A 1 MiB ceiling
# leaves normal growth room while rejecting the observed 1757492-byte runtime
# inclusion. Keep this fixed profile budget explicit, not an environment knob.
set -euo pipefail
export LC_ALL=C

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	echo "usage: $0 STRIPPED_LIBSHARED READELF [ORIGINAL_VENDOR_LIBSHARED]" >&2
	exit 2
fi
library=$1
readelf=$2
baseline=${3:-}
temporary=$(mktemp -d "${TMPDIR:-/tmp}/wlif-link-size.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT

if [ ! -f "$library" ]; then
	echo "missing libshared: $library" >&2
	exit 1
fi
"$readelf" --dyn-syms -W "$library" > "$temporary/symbols"
# Preserve versions for the optional vendor ABI comparison, including data
# symbols. Undefined imports are not evidence that this library exports an ABI.
awk '$5 ~ /^(GLOBAL|WEAK)$/ && $6 ~ /^(DEFAULT|PROTECTED)$/ && $7 != "UND" && NF >= 8 {print $8}' \
	"$temporary/symbols" | sort -u > "$temporary/exports"
awk '$4 ~ /^(FUNC|IFUNC)$/ && $5 ~ /^(GLOBAL|WEAK)$/ && $6 ~ /^(DEFAULT|PROTECTED)$/ && $7 != "UND" {sub(/@.*/, "", $8); print $8}' \
	"$temporary/symbols" | sort -u > "$temporary/functions"

failed=0
bytes=$(stat -c '%s' "$library")
if [ "$bytes" -gt 1048576 ]; then
	echo "wlif full-link size exceeds 1048576-byte GT profile budget: $bytes" >&2
	failed=1
fi
for symbol in rust_wlif_ifname_ok rust_wlif_ctrl_prefix_ok \
	rust_wlif_cli_token_ok rust_wlif_cli_word_list_ok rust_wlif_ssid_ok \
	rust_wlif_passphrase_ok rust_wlif_dpp_value_ok rust_wlif_wps_pin_ok \
	rust_wlif_network_id_ok rust_wlif_supplicant_ctrl_path rust_wlif_supplicant_ctrl_dir; do
	if ! grep -qxF "$symbol" "$temporary/functions"; then
		echo "wlif full-link missing function export: $symbol" >&2
		failed=1
	fi
done
# These definitions appeared when ARM __aeabi_* references extracted Rust
# compiler_builtins ahead of libgcc_s, then pulled std through its personality.
# Do not hide the runtime exports merely to pass: the full size gate also runs.
if grep -E '^(rust_(eh_personality|begin_unwind|panic)|__rust_(alloc|dealloc|realloc)|_ZN(3std|5gimli|9addr2line|11miniz_oxide|14rustc_demangle))' \
	"$temporary/exports" > "$temporary/runtime"; then
	echo "wlif full-link unexpectedly exports Rust std/backtrace runtime:" >&2
	head -n 8 "$temporary/runtime" >&2
	failed=1
fi
if [ -n "$baseline" ]; then
	"$readelf" --dyn-syms -W "$baseline" > "$temporary/baseline-symbols"
	awk '$5 ~ /^(GLOBAL|WEAK)$/ && $6 ~ /^(DEFAULT|PROTECTED)$/ && $7 != "UND" && NF >= 8 {print $8}' \
		"$temporary/baseline-symbols" | sort -u > "$temporary/baseline-exports"
	comm -23 "$temporary/baseline-exports" "$temporary/exports" > "$temporary/missing"
	if [ -s "$temporary/missing" ]; then
		echo "wlif full-link lost $(wc -l < "$temporary/missing") original vendor exports (first 32):" >&2
		head -n 32 "$temporary/missing" >&2
		failed=1
	fi
fi
if [ "$failed" -ne 0 ]; then exit 1; fi
echo "wlif full-link PASS: $bytes bytes, 11 Rust FFI exports, no std/backtrace exports${baseline:+, vendor exports preserved}"
