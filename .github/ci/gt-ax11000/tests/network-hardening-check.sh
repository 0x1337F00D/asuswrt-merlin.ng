#!/usr/bin/env bash
set -euo pipefail

root="${1:?usage: network-hardening-check.sh ASUSWRT_SOURCE_ROOT}"
overlay_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
web="$root/release/src/router/httpd/web.c"
services="$root/release/src/router/rc/services.c"
firewall="$root/release/src/router/rc/firewall.c"

require_text() {
	local file="$1"
	local expected="$2"
	if ! grep -Fq -- "$expected" "$file"; then
		echo "missing hardening invariant in $file: $expected" >&2
		exit 1
	fi
}

for file in "$web" "$services" "$firewall"; do
	test -f "$file" || { echo "missing source file: $file" >&2; exit 1; }
done

# A normal Advanced-WLAN apply migrates stale WPS state to off before Rust
# validates the exact psk2/sae/transition tuple.  No country field participates.
require_text "$web" 'validate_wlan_security_tuple(root, unit, "0")'
require_text "$web" 'nvram_set("wps_enable", "0");'
require_text "$web" 'nvram_set("wps_enable_x", "0");'
if grep -Eq 'rust_wlan_allow_transition|rust_wlan_allow_wps_wpa2|allow_wps_with_wpa2' \
   "$web" "$overlay_root/patches/runtime-policy.patch" \
   "$overlay_root/rust/httpd-parsers/src/lib.rs"; then
	echo "obsolete WLAN exception ABI remains reachable" >&2
	exit 1
fi
if sed -n '/static int validate_wlan_security_tuple/,/^}/p' "$web" | grep -Eq 'country|ccode|regrev|txpower|chanspec'; then
	echo "regulatory settings leaked into WLAN security policy" >&2
	exit 1
fi

# Existing installations are migrated once in persistent NVRAM, and later WPS
# button/service attempts cannot revive the registrar.
require_text "$services" '#ifdef GTAX11000'
require_text "$services" 'nvram_invmatch("wps_enable", "0")'
require_text "$services" 'nvram_commit();'
if sed -n '/if (nvram_match("wps_enable", "1")/,/) {/p' "$services" | \
   sed -n '/#ifdef GTAX11000/,/#endif/p' | grep -Fq 'amesh_wps_enr'; then
	echo "AiMesh WPS exception remains enabled on GT-AX11000" >&2
	exit 1
fi

# Validation must observe VPN/vendor/custom hook changes before forwarding is
# enabled; any failed apply or semantic ruleset failure stays fail-closed.
ovpn_line=$(grep -nF 'ovpn_run_fw_scripts();' "$firewall" | tail -1 | cut -d: -f1)
custom_line=$(grep -nF 'run_custom_script("firewall-start"' "$firewall" | tail -1 | cut -d: -f1)
validation_line=$(grep -nF '!validate_effective_firewall_policy()' "$firewall" | tail -1 | cut -d: -f1)
forward_line=$(grep -nF $'\t\tenable_ip_forward();' "$firewall" | tail -1 | cut -d: -f1)
if [ -z "$ovpn_line" ] || [ -z "$custom_line" ] || [ -z "$validation_line" ] || \
   [ -z "$forward_line" ] || [ "$ovpn_line" -ge "$custom_line" ] || \
   [ "$custom_line" -ge "$validation_line" ] || [ "$validation_line" -ge "$forward_line" ]; then
	echo "firewall hook/validation/forwarding order is unsafe" >&2
	exit 1
fi
require_text "$firewall" 'firewall_enter_fail_closed();'

echo "network hardening overlay checks passed"
