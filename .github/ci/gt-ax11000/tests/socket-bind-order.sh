#!/usr/bin/env bash
# The device pin must precede the bind in every Rust daemon that listens.
#
# This is the property that keeps a service off the WAN: a socket bound to the
# wildcard address before SO_BINDTODEVICE returns exists on every interface for
# the width of that window. `ntp` proves the ordering behaviourally, by holding
# the port first so that binding first would fail with AddrInUse; `lltd` uses
# AF_PACKET and `wsdd2` binds several sockets, and neither ordering is
# observable that cheaply, so their suites did not notice the calls being
# swapped. This checks the source order instead, which is weaker than a
# behavioural test but catches exactly that edit.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rust=${1:-$root/rust}
status=0
for crate in ntp lltd wsdd2; do
	file="$rust/$crate/src/sys.rs"
	if [ ! -f "$file" ]; then
		echo "no sys.rs for $crate" >&2
		exit 1
	fi
	pin=$(grep -n 'bind_to_device(&owned\|bind_to_device(&socket' "$file" | head -1 | cut -d: -f1)
	bind=$(grep -n 'libc::bind(' "$file" | head -1 | cut -d: -f1)
	if [ -z "$pin" ] || [ -z "$bind" ]; then
		echo "$crate: no device pin or no bind found in sys.rs" >&2
		status=1
		continue
	fi
	if [ "$pin" -ge "$bind" ]; then
		echo "$crate: device pin at line $pin is not before bind at line $bind" >&2
		status=1
		continue
	fi
	# A second bind with no pin in front of it would slip through the check
	# above, so require that every bind has a pin somewhere before it.
	binds=$(grep -c 'libc::bind(' "$file")
	pins=$(grep -c 'bind_to_device(&owned\|bind_to_device(&socket' "$file")
	if [ "$pins" -lt "$binds" ]; then
		echo "$crate: $binds binds but only $pins device pins" >&2
		status=1
		continue
	fi
	echo "$crate: device pinned at line $pin, bound at line $bind"
done
if [ "$status" -ne 0 ]; then
	echo "socket bind order check failed" >&2
	exit 1
fi
echo "socket bind order verified"
