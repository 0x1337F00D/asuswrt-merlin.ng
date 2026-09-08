#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
	echo "usage: $0 ROOTFS DICT_ENUM FILE_MANIFEST" >&2
	exit 2
fi

rootfs=$(readlink -f "$1")
dict_enum=$(readlink -f "$2")
file_manifest=$(readlink -f "$3")
www="$rootfs/www"
page="$www/Advanced_WAdvanced_Content.asp"

for required in "$page" "$www/index.asp" "$www/EN.dict" "$www/DE.dict"; do
	if [ ! -s "$required" ]; then
		echo "required Web payload file is missing or empty: $required" >&2
		exit 1
	fi
done

expected_files=$(wc -l < "$file_manifest")
actual_files=$(find "$www" -type f | wc -l)
if [ "$expected_files" -eq 0 ] || [ "$actual_files" -ne "$expected_files" ]; then
	echo "Web file count mismatch: rootfs=$actual_files manifest=$expected_files" >&2
	exit 1
fi

# Under RTCONFIG_AUTODICT, LnxDictPrep emits Lang_Hdr.txt next to the
# dictionaries it generates from dictctrl.txt, and httpd builds the language
# selector from its LANG_<code>= lines (skipping LANG_select*) at runtime.  That
# file is therefore the authoritative language list for this payload; derive
# the expected dictionary set from it instead of hardcoding the upstream count.
lang_hdr="$www/Lang_Hdr.txt"
if [ ! -s "$lang_hdr" ]; then
	echo "AUTODICT language header is missing or empty: $lang_hdr" >&2
	exit 1
fi
expected_dicts=$(LC_ALL=C sed 's/^\xef\xbb\xbf//; s/\r$//' "$lang_hdr" |
	awk -F= '/^LANG_/ && !/^LANG_select/ { print substr($1, 6) ".dict" }' | sort -u)
if [ -z "$expected_dicts" ]; then
	echo "AUTODICT language header lists no LANG_ entries: $lang_hdr" >&2
	exit 1
fi
expected_count=$(printf '%s\n' "$expected_dicts" | wc -l)

dict_lines=
dict_count=0
dict_names=
while IFS= read -r -d '' dictionary; do
	lines=$(wc -l < "$dictionary")
	if [ -z "$dict_lines" ]; then
		dict_lines=$lines
	elif [ "$lines" -ne "$dict_lines" ]; then
		echo "AUTODICT line-count mismatch: $dictionary has $lines, expected $dict_lines" >&2
		exit 1
	fi
	dict_count=$((dict_count + 1))
	dict_names="$dict_names${dictionary##*/}"$'\n'
done < <(find "$www" -maxdepth 1 -type f -name '*.dict' -print0 | sort -z)

if [ "$dict_count" -ne "$expected_count" ] || [ "$(printf '%s' "$dict_names" | sort)" != "$expected_dicts" ]; then
	echo "AUTODICT payload must contain exactly the $expected_count language dictionaries listed in Lang_Hdr.txt" >&2
	echo "expected: $(printf '%s' "$expected_dicts" | tr '\n' ' ')" >&2
	echo "actual:   $(printf '%s' "$dict_names" | tr '\n' ' ')" >&2
	exit 1
fi
if [ -z "$dict_lines" ] || [ "$dict_lines" -le 0 ]; then
	echo "AUTODICT payload dictionaries are empty" >&2
	exit 1
fi

mapfile -t tokens < <(grep -Eoh '<#[^#>]*#>' "$page" | sort -u)
if [ "${#tokens[@]}" -eq 0 ]; then
	echo "Advanced wireless page contains no AUTODICT references" >&2
	exit 1
fi

max_id=0
for token in "${tokens[@]}"; do
	if ! [[ "$token" =~ ^\<\#([0-9]+)\#\>$ ]]; then
		echo "unresolved AUTODICT placeholder in Advanced wireless page: $token" >&2
		exit 1
	fi
	id=${BASH_REMATCH[1]}
	if [ "$id" -gt "$max_id" ]; then
		max_id=$id
	fi
done

if [ "$max_id" -ge "$dict_lines" ]; then
	echo "AUTODICT reference $max_id exceeds dictionary range 0..$((dict_lines - 1))" >&2
	exit 1
fi

grep -Fq 'id="regulatory_lab_country"' "$page"
grep -Fq 'regulatory_lab_store_acknowledgement' "$page"

dict_value() {
	local dictionary=$1
	local key=$2
	local id
	local line

	id=$(awk -F= -v key="$key" '$2 == key { print $1; exit }' "$dict_enum")
	if [ -z "$id" ] || ! [[ "$id" =~ ^[0-9]+$ ]]; then
		echo "AUTODICT sentinel key is missing from enum: $key" >&2
		return 1
	fi
	line=$((id + 1))
	sed -n "${line}p" "$dictionary"
}

# dict_value runs in a command substitution, so its failure must be checked
# here rather than relying on set -e inside the subshell.  The third argument
# is a shell pattern matched unquoted.
expect_dict_value() {
	local dictionary=$1
	local key=$2
	local pattern=$3
	local value

	if ! value=$(dict_value "$dictionary" "$key"); then
		echo "AUTODICT sentinel lookup failed for $key in $dictionary" >&2
		exit 1
	fi
	# shellcheck disable=SC2053
	if [[ "$value" != $pattern ]]; then
		echo "AUTODICT sentinel mismatch in $dictionary: $key is '$value', expected '$pattern'" >&2
		exit 1
	fi
}

expect_dict_value "$www/EN.dict" CTL_apply Apply
expect_dict_value "$www/DE.dict" CTL_apply Anwenden
expect_dict_value "$www/EN.dict" WLANConfig11b_x_Region Region
expect_dict_value "$www/DE.dict" WLANConfig11b_x_Region Region
expect_dict_value "$www/EN.dict" Web_Title '*GT-AX11000*'
expect_dict_value "$www/DE.dict" Web_Title '*GT-AX11000*'

echo "Web payload verified: $dict_count dictionaries, $dict_lines entries, max page id $max_id"
