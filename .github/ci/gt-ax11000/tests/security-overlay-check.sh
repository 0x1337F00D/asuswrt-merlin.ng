#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: $0 PATCHED_SOURCE_ROOT" >&2
	exit 2
fi

root=$(readlink -f "$1")
router="$root/release/src/router"

require_text() {
	local file=$1
	local text=$2
	if ! grep -Fq -- "$text" "$file"; then
		echo "security invariant missing from ${file#"$root"/}: $text" >&2
		exit 1
	fi
}

reject_text() {
	local file=$1
	local text=$2
	if grep -Fq -- "$text" "$file"; then
		echo "forbidden security pattern remains in ${file#"$root"/}: $text" >&2
		exit 1
	fi
}

httpd_stubs="$router/httpd/httpd_compat_stubs.c"
web="$router/httpd/web.c"
rc_stubs="$router/rc/rc_compat_stubs.c"
firewall="$router/rc/firewall.c"
ipsec="$router/rc/rc_ipsec.c"
wireguard="$router/rc/wireguard.c"
wps="$router/rc/sysdeps/wps-broadcom.c"
openvpn="$router/libovpn/openvpn_options.c"
httpd_rust="$router/rust-components/httpd-parsers/src/lib.rs"
security_rust="$router/rust-components/router-security/src/lib.rs"
policy_rust="$router/rust-components/router-policy/src/vpn.rs"
wireless_ui="$router/www/Advanced_WAdvanced_Content.asp"

for file in "$httpd_stubs" "$web" "$rc_stubs" "$firewall" "$ipsec" \
	"$wireguard" "$wps" "$openvpn" "$httpd_rust" "$security_rust" \
	"$policy_rust" "$wireless_ui"; do
	test -f "$file" || { echo "security input is missing: $file" >&2; exit 1; }
done

# Compatibility gaps must fail closed instead of reporting successful work.
require_text "$rc_stubs" 'return rust_validate_apply_input_value(name, value);'
require_text "$rc_stubs" 'errno = ENOTSUP;'
require_text "$httpd_stubs" '{\"statusCode\":\"-1\",\"supported\":false}'
require_text "$httpd_stubs" '{\"supported\":false}'
reject_text "$rc_stubs" 'return system(cmd);'

# The regulatory test lab has exactly one authenticated mutation endpoint.
require_text "$web" '{ "set_regulatory_testlab.cgi*", "application/json", no_cache_IE7, do_html_post_and_get, do_set_regulatory_testlab_cgi, do_auth }'
require_text "$wireless_ui" 'regulatory_lab_prepare_controls();'
require_text "$wireless_ui" 'document.getElementById("regulatory_lab_country")'
require_text "$wireless_ui" '<select id="regulatory_lab_country" class="input_option"></select>'
reject_text "$wireless_ui" 'name="regulatory_lab_country"'
require_text "$wireless_ui" 'document.form.ui_location_code.disabled = true;'
require_text "$wireless_ui" 'nvram_match("rust_regulatory_testlab_ack_v1", "1", "accepted")'
require_text "$wireless_ui" 'acknowledgement.disabled = regulatory_lab_ack_stored;'
require_text "$wireless_ui" 'regulatory_lab_store_acknowledgement()'
require_text "$wireless_ui" '"acknowledge_only": "1"'
require_text "$wireless_ui" 'Länderprofil anwenden'
require_text "$wireless_ui" '(!acknowledgement || !acknowledgement.checked)'
reject_text "$wireless_ui" 'regionControl.value == currentRegion'
reject_text "$wireless_ui" 'Für ein neues Profil bitte ein anderes Land wählen.'
require_text "$wireless_ui" 'aktuelle Leistungseinstellung='
require_text "$httpd_stubs" 'websGetVar(stream, "country", "")'
require_text "$httpd_stubs" 'websGetVar(stream, "confirmation", "")'
require_text "$httpd_stubs" 'websGetVar(stream, "acknowledge_only", "0")'
require_text "$httpd_stubs" '{\"statusCode\":\"0\",\"acknowledged\":true}'
require_text "$httpd_stubs" 'strcmp(acknowledge_only, "0") && strcmp(acknowledge_only, "1")'
reject_text "$httpd_stubs" 'websGetVar(stream, "tx'
reject_text "$httpd_stubs" 'websGetVar(stream, "wl'
reject_text "$httpd_stubs" 'nvram_set("wl0_chlist"'
reject_text "$httpd_stubs" 'nvram_set("0:maxp'
require_text "$httpd_stubs" 'nvram_set("rust_regulatory_testlab_ack_v1", "1");'
require_text "$httpd_stubs" 'nvram_commit();'
for unit in 0 1 2; do
	require_text "$httpd_stubs" "nvram_set(\"${unit}:ccode\", country);"
	require_text "$httpd_stubs" "nvram_set(\"wl${unit}_txpower\", \"100\");"
	require_text "$httpd_stubs" "nvram_unset(\"wl${unit}_chlist\");"
done
for protected in 'b"0:ccode"' 'b"2:maxp5ga2"' 'b"pci/2/1/maxp2ga0"' \
	'b"wl0_txpower"' 'b"wl2_chlist"'; do
	require_text "$httpd_rust" "$protected"
done

# The effective firewall is checked after custom/VPN hooks and forwarding is
# enabled only after that check. Failures install the emergency WAN deny.
require_text "$firewall" 'rust_validate_effective_firewall_files'
require_text "$firewall" 'firewall_enter_fail_closed();'
custom_line=$(grep -nF 'run_custom_script("firewall-start"' "$firewall" | tail -1 | cut -d: -f1)
validation_line=$(grep -nF '!validate_effective_firewall_policy()' "$firewall" | tail -1 | cut -d: -f1)
forward_line=$(grep -nF $'\t\tenable_ip_forward();' "$firewall" | tail -1 | cut -d: -f1)
if ! [ "$custom_line" -lt "$validation_line" ] || ! [ "$validation_line" -lt "$forward_line" ]; then
	echo "firewall validation/forwarding order is unsafe" >&2
	exit 1
fi

# Known authenticated command-injection boundaries remain argv/typed only.
require_text "$ipsec" 'rust_validate_ipsec_filename'
require_text "$ipsec" 'rust_validate_ipsec_identity'
require_text "$ipsec" 'unlink(password_file);'
require_text "$wireguard" 'rust_update_wireguard_endpoint(path, address)'
require_text "$wps" 'argv[argc++] = "/usr/sbin/hostapd_cli";'
reject_text "$wps" 'popen(cmd'

# Imported OpenVPN profiles are checked by the same bounded Rust policy in the
# one existing Rust archive of each libovpn consumer (httpd and rc).
require_text "$openvpn" 'rust_openvpn_import_option_allowed(const char *name,'
require_text "$openvpn" '__attribute__((weak))'
require_text "$openvpn" 'p && p[0] && rust_openvpn_import_option_allowed &&'
require_text "$openvpn" 'rust_openvpn_import_option_allowed(p[0], p[1], p[2], p[3])'
require_text "$openvpn" 'imported_openvpn_option_allowed(p)'
require_text "$httpd_rust" 'pub unsafe extern "C" fn rust_openvpn_import_option_allowed'
require_text "$security_rust" 'pub unsafe extern "C" fn rust_openvpn_import_option_allowed'
require_text "$policy_rust" 'pub enum OpenVpnImportDirective'
require_text "$policy_rust" 'openvpn_import_directive_allowed'
reject_text "$openvpn" 'safe_imported_custom_option'
reject_text "$openvpn" 'safe_modern_cipher_list'
reject_text "$openvpn" 'safe_modern_digest'
require_text "$openvpn" 'OpenVPN import disabled compression'
require_text "$openvpn" 'OpenVPN import ignored unsafe or unsupported directive'

echo "security overlay invariants verified"
