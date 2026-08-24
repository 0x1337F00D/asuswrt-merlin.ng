#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
	echo "usage: $0 ROOTFS OUTPUT_DIR [EXCLUDED_RELATIVE_PATH ...]" >&2
	exit 2
fi

rootfs=$(readlink -f "$1")
output=$2
shift 2

if [ ! -d "$rootfs" ]; then
	echo "rootfs directory not found: $rootfs" >&2
	exit 1
fi

declare -A excluded=()
for path in "$@"; do
	if [ -z "$path" ] || [[ "$path" = /* ]] || [[ "$path" = ./* ]] || \
		[[ "$path" = *$'\n'* ]] || [[ "$path" = *$'\t'* ]]; then
		echo "invalid rootfs exclusion: $path" >&2
		exit 2
	fi
	excluded["$path"]=1
done

mkdir -p "$output"
: > "$output/entries.manifest"
: > "$output/content.sha256"
: > "$output/hardlinks.manifest"

declare -A hardlink_groups=()
entry_count=0

# Validate the delimiters used by the text manifests before parsing find's
# batched metadata output. This is one cheap traversal and performs no stat or
# digest subprocess per entry.
while IFS= read -r -d '' entry; do
	relative=${entry#./}
	if [[ -v "excluded[$relative]" ]]; then
		continue
	fi
	if [[ "$relative" = *$'\n'* ]] || [[ "$relative" = *$'\t'* ]]; then
		echo "rootfs path cannot be represented safely: $relative" >&2
		exit 1
	fi
	if [ -L "$rootfs/$relative" ]; then
		target=$(readlink -- "$rootfs/$relative")
		if [[ "$target" = *$'\n'* ]] || [[ "$target" = *$'\t'* ]]; then
			echo "rootfs link target cannot be represented safely: $relative" >&2
			exit 1
		fi
	fi
done < <(cd "$rootfs" && find . -mindepth 1 -print0)

# One find traversal supplies all common metadata. Device nodes are absent in
# the current image; if one appears, record its device number with one stat.
while IFS=$'\t' read -r -d '' type mode links size inode entry target; do
	relative=${entry#./}
	if [[ -v "excluded[$relative]" ]]; then
		continue
	fi
	case "$type" in
		f)
			printf 'f\t%s\t%s\t%s\t%s\n' \
				"$mode" "$links" "$size" "$relative" \
				>> "$output/entries.manifest"
			if [ "$links" -gt 1 ]; then
				hardlink_groups["$inode"]+="$relative"$'\n'
			fi
			;;
		l)
			printf 'l\t%s\t%s\t%s\n' "$mode" "$relative" "$target" \
				>> "$output/entries.manifest"
			;;
		b|c)
			device=$(stat -c '%t:%T' -- "$rootfs/$relative")
			printf '%s\t%s\t%s\t%s\n' "$type" "$mode" "$relative" "$device" \
				>> "$output/entries.manifest"
			;;
		*)
			printf '%s\t%s\t%s\n' "$type" "$mode" "$relative" \
				>> "$output/entries.manifest"
			;;
	esac
	entry_count=$((entry_count + 1))
done < <(
	cd "$rootfs"
	find . -mindepth 1 -printf '%y\t%m\t%n\t%s\t%D:%i\t%p\t%l\0' \
		| LC_ALL=C sort -z -t $'\t' -k6,6
)

find_args=(. -type f)
for path in "${!excluded[@]}"; do
	find_args+=( ! -path "./$path" )
done
(
	cd "$rootfs"
	find "${find_args[@]}" -print0 | LC_ALL=C sort -z \
		| xargs -0 -r -P "$(nproc)" -n 64 sha256sum -- \
		| sed 's/  /\t/' | LC_ALL=C sort -t $'\t' -k2,2
) > "$output/content.sha256"
file_count=$(wc -l < "$output/content.sha256")

for inode in "${!hardlink_groups[@]}"; do
	members=$(printf '%s' "${hardlink_groups[$inode]}" | LC_ALL=C sort)
	member_count=$(printf '%s\n' "$members" | wc -l)
	printf '%s\t%s\n' "$member_count" "$(printf '%s\n' "$members" | paste -sd '|' -)"
done | LC_ALL=C sort > "$output/hardlinks.manifest"

printf 'entries=%s files=%s exclusions=%s\n' \
	"$entry_count" "$file_count" "${#excluded[@]}"
