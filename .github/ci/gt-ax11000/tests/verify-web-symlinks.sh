#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: $0 ROOTFS MANIFEST" >&2
	exit 2
fi

rootfs=$(readlink -f "$1")
manifest=$(readlink -f "$2")
expected_count=0

while IFS=$'\t' read -r link target; do
	if [ -z "$link" ] || [ -z "$target" ] || [[ "$link" = /* ]] || [[ "$link" = *$'\n'* ]]; then
		echo "invalid Web symlink manifest entry: $link" >&2
		exit 1
	fi
	path="$rootfs/$link"
	if [ ! -L "$path" ]; then
		echo "expected Web symlink is missing: $path" >&2
		exit 1
	fi
	actual=$(readlink "$path")
	if [ "$actual" != "$target" ]; then
		echo "Web symlink target mismatch: $link -> $actual, expected $target" >&2
		exit 1
	fi
	expected_count=$((expected_count + 1))
done < "$manifest"

actual_count=$(find "$rootfs/www" -type l | wc -l)
if [ "$expected_count" -eq 0 ] || [ "$actual_count" -ne "$expected_count" ]; then
	echo "Web symlink count mismatch: rootfs=$actual_count manifest=$expected_count" >&2
	exit 1
fi

for required in \
	'www/ext	/tmp/var/wwwext' \
	'www/user	/tmp/var/wwwext' \
	'www/proxy.pac	/www/ext/proxy.pac' \
	'www/wpad.dat	/www/ext/proxy.pac'; do
	link=${required%%$'\t'*}
	target=${required#*$'\t'}
	[ -L "$rootfs/$link" ] || {
		echo "required model Web symlink is missing: $link" >&2
		exit 1
	}
	[ "$(readlink "$rootfs/$link")" = "$target" ] || {
		echo "required model Web symlink target mismatch: $link" >&2
		exit 1
	}
done

echo "Web symlinks verified: $actual_count"
