#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: $0 PATCHED_SOURCE_ROOT" >&2
	exit 2
fi

root=$(readlink -f "$1")
router="$root/release/src/router"
router_makefile="$router/Makefile"

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
# The retired test-lab branch must not reintroduce independent radio/power or
# IPv6 mutations alongside the supported country-only endpoint.
reject_text "$web" 'advanced_testlab.cgi'
reject_text "$web" 'ASUS_TESTLAB_V6'
test ! -e "$router/www/Advanced_TestLab_Content.asp" || {
	echo 'retired standalone test-lab page must not ship' >&2
	exit 1
}
rc_stubs="$router/rc/rc_compat_stubs.c"
firewall="$router/rc/firewall.c"
lan="$router/rc/lan.c"
init="$router/rc/init.c"
services="$router/rc/services.c"
watchdog="$router/rc/watchdog.c"
ipsec="$router/rc/rc_ipsec.c"
wireguard="$router/rc/wireguard.c"
wps="$router/rc/sysdeps/wps-broadcom.c"
openvpn="$router/libovpn/openvpn_options.c"
openvpn_setup="$router/libovpn/openvpn_setup.c"
rstats_makefile="$router/rstats/Makefile"
router_config_base="$router/config_base"
target_mak="$root/release/src-rt/target.mak"
src_rt_makefile="$root/release/src-rt/Makefile"
local_traffic="$router/httpd/local_traffic.c"
httpd_rust="$router/rust-components/httpd-parsers/src/lib.rs"
clientlist_rust="$router/rust-components/clientlist/src"
security_rust="$router/rust-components/router-security/src/lib.rs"
policy_rust="$router/rust-components/router-policy/src/vpn.rs"
qos_policy_rust="$router/rust-components/router-policy/src/qos.rs"
wireless_ui="$router/www/Advanced_WAdvanced_Content.asp"
clientlist_ui="$router/www/dashboard/js/clientlist.module.js"
clientlist_shipped="$router/www/client_function.js"
qos_ui="$router/www/QoS_EZQoS.asp"
www_makefile="$router/www/Makefile"
networkmap_makefile="$router/networkmap/Makefile"
router_makefile="$router/Makefile"
cargo_config="$router/.cargo/config.toml"
zlib_static="$router/rust-components/zlib-static/src/lib.rs"
zlib_static_manifest="$router/rust-components/zlib-static/Cargo.toml"
bwdpi_compat="$router/rust-components/bwdpi-compat/src/lib.rs"
wifi_base="$root/release/src-rt-5.02axhnd/bcmdrivers/broadcom/net/wl/impl51/main/components/opensource/router_tools"

for file in "$httpd_stubs" "$web" "$rc_stubs" "$firewall" "$lan" "$init" \
	"$services" "$watchdog" "$ipsec" \
	"$wireguard" "$wps" "$openvpn" "$httpd_rust" "$security_rust" \
	"$policy_rust" "$wireless_ui" "$clientlist_ui" "$clientlist_shipped" "$openvpn_setup" \
	"$rstats_makefile" "$router_config_base" "$target_mak" "$src_rt_makefile" \
	"$local_traffic" "$qos_policy_rust" "$qos_ui" "$www_makefile" \
	"$networkmap_makefile" "$bwdpi_compat" \
	"$router_makefile" "$cargo_config" "$zlib_static" "$zlib_static_manifest" \
	"$clientlist_rust/lib.rs" "$clientlist_rust/layout.rs" \
	"$clientlist_rust/snapshot.rs" "$clientlist_rust/shm.rs" \
	"$clientlist_rust/render.rs" "$clientlist_rust/cache.rs" \
	"$clientlist_rust/ffi.rs" \
	"$wifi_base/hostapd/src/common/sae.c" \
	"$wifi_base/hostapd/src/radius/radius.c" \
	"$wifi_base/hostapd/src/rsn_supp/wpa.c" \
	"$wifi_base/wpa_supplicant/src/common/sae.c" \
	"$wifi_base/wpa_supplicant/src/radius/radius.c" \
	"$wifi_base/wpa_supplicant/src/rsn_supp/wpa.c"; do
	test -f "$file" || { echo "security input is missing: $file" >&2; exit 1; }
done

# GT-AX11000 ships no Trend Micro/BWDPI engine. The compatibility hook is
# backed by bounded local conntrack/ARP counters parsed in Rust, and crafted
# requests cannot re-enable the proprietary adaptive mode.
require_text "$firewall" 'mkdtemp(private_dir)'
require_text "$firewall" '_eval(ipv4_argv, ipv4_output, 0, NULL)'
require_text "$firewall" 'rmdir(private_dir);'
reject_text "$firewall" '"/tmp/firewall-effective-v4.rules"'
reject_text "$firewall" '"/tmp/firewall-effective-v6.rules"'
require_text "$target_mak" 'JFFS2LOG=y BWDPI=n DUMP_OOPS_MSG=n'
require_text "$target_mak" 'OPEN_NAT=y AHS=n ASD=n LIBASC=y FRS_LIVE_UPDATE=n'
require_text "$src_rt_makefile" 'if [ "$(LIBASC)" = "y" ]; then'
require_text "$local_traffic" 'rust_httpd_conntrack_traffic_parse'
require_text "$local_traffic" 'CONNTRACK_LINE_LIMIT 2048'
require_text "$local_traffic" 'fopen("/proc/net/nf_conntrack", "r")'
reject_text "$local_traffic" 'system('
reject_text "$local_traffic" 'popen('
require_text "$web" '{ "bwdpi_status", ej_local_traffic_status}'
require_text "$web" 'rust_httpd_local_qos_mode_allowed'
require_text "$web" 'rust_httpd_local_qos_bandwidth_allowed'
require_text "$web" '"qos_ibw", "qos_obw", "qos_ibw1", "qos_obw1"'
require_text "$init" 'migrate_local_qos_mode();'
require_text "$init" 'rust_local_qos_mode_allowed(mode)'
require_text "$httpd_rust" 'pub unsafe extern "C" fn rust_httpd_conntrack_traffic_parse'
require_text "$httpd_rust" 'pub unsafe extern "C" fn rust_httpd_local_qos_mode_allowed'
require_text "$httpd_rust" 'pub unsafe extern "C" fn rust_httpd_local_qos_bandwidth_allowed'
require_text "$security_rust" 'pub unsafe extern "C" fn rust_local_qos_mode_allowed'
require_text "$qos_policy_rust" 'Mode 1 is deliberately absent'
require_text "$rc_stubs" 'int check_tdts_module_exist(void)'
require_text "$rc_stubs" 'int check_bwdpi_nvram_setting(void)'
require_text "$rc_stubs" 'int check_wrs_switch(void)'
require_text "$rc_stubs" 'int get_fw_mesh_extender(void **output, unsigned int *used_length)'
require_text "$rc_stubs" 'int get_fw_user_list(void **output, unsigned int *used_length)'
require_text "$router_makefile" 'hub-ctrl: libusb10'
require_text "$router_makefile" 'email-3.1.3/Makefile: nt_center sqlite'
require_text "$router_makefile" 'aws-iot: nvram$(BCMEX)$(EX7) libwebapi $(if $(HND_ROUTER),wlcsm) $(if $(RTCONFIG_CFGSYNC),cfg_mnt)'
require_text "$router_makefile" 'usbmuxd-1.1.1: libimobiledevice-1.3.0'
require_text "$router_makefile" '$(MAKE) -j1 -C $@ $(shell if [[ "$(HND_ROUTER)" = "y" ]]'
require_text "$clientlist_ui" 'const safeHookGet = async (name) => {'
require_text "$clientlist_ui" 'if (Array.isArray(fromNetworkmapd.maclist)) {'
require_text "$clientlist_ui" 'Client icons unavailable; continuing without them'
require_text "$clientlist_shipped" 'Array.isArray(originData.fromNetworkmapd[0].maclist)'
require_text "$clientlist_shipped" 'httpApi.hookGet("get_clientlist") || {maclist: []}'
# The Web UI client list is rendered by the Rust clientlist crate from a
# locked, size- and layout-checked copy of the networkmap segment: the
# 174,964-byte legacy view only for productid GT-AX11000, the 173,436-byte
# public view otherwise, anything else fails closed; the trailer is read from
# the segment end and the count is clamped to 0..=255.  C keeps the process
# gates, the wireless offline flag and the delete_mac trailer write; no
# json_object crosses the boundary and the json-c readers are gone.
require_text "$web" '#define CLIENTLIST_JSON_CAPACITY (1024 * 1024)'
require_text "$web" 'rust_httpd_clientlist_render(&inputs, buffer, capacity)'
require_text "$web" 'rust_httpd_clientlist_cache_read(NMP_CACHE_FILE, buffer, CLIENTLIST_JSON_CAPACITY)'
require_text "$web" 'rust_httpd_clientlist_cache_write(NMP_CACHE_FILE, buffer, (size_t)length)'
require_text "$web" 'rust_httpd_clientlist_database_render(&inputs, buffer, CLIENTLIST_JSON_CAPACITY)'
require_text "$web" 'rust_httpd_clientlist_name_for_ip(buffer, (size_t)length, ipaddr, name, name_len)'
require_text "$web" 'rust_httpd_clientlist_basic_render(&inputs, alive, NMP_CL_JSON_FILE, opt,'
require_text "$web" 'rust_httpd_clientlist_all_basic_render(NMP_CL_JSON_FILE, custom_clientlist,'
require_text "$web" 'rust_httpd_clientlist_search_name(NMP_CL_JSON_FILE, custom_clientlist, name,'
require_text "$web" 'nvram_set("nmp_wl_offline_check", "1");'
require_text "$web" 'if(!pids("networkmap")){'
require_text "$web" 'NETWORKMAP_SHM_TAIL'
require_text "$web" 'shm_info.shm_segsz - sizeof(NETWORKMAP_SHM_TAIL)'
require_text "$web" 'networkmap_shm_set_delete_mac(shared_client_info, shm_client_info_id,'
reject_text "$web" 'get_client_detail_info(struct json_object'
reject_text "$web" 'get_client_detail_info(clients'
reject_text "$web" 'get_client_detail_info(*clients'
reject_text "$web" 'GT_AX11000_NETWORKMAP_TABLE'
reject_text "$web" 'check_macrepeat('
reject_text "$web" 'get_amas_re_client_detail_info('
reject_text "$web" 'json_object_from_file(NMP_CACHE_FILE)'
reject_text "$web" 'json_object_to_file(NMP_CACHE_FILE'
reject_text "$web" 'shmget((key_t)shmkey, sizeof(CLIENT_DETAIL_INFO_TABLE), 0666|IPC_CREAT)'
reject_text "$web" 'for(i = 0; i < p_client_info_tab->ip_mac_num; i++)'
reject_text "$web" 'strlcpy(p_client_info_tab->delete_mac, mac_str'
reject_text "$web" 'json_object_put(new_never_online_client);'
require_text "$clientlist_rust/lib.rs" '#![forbid(unsafe_op_in_unsafe_fn)]'
require_text "$clientlist_rust/layout.rs" 'pub const LEGACY_TABLE_SIZE: usize = 174_964;'
require_text "$clientlist_rust/layout.rs" 'pub const PUBLIC_TABLE_SIZE: usize = 173_436;'
require_text "$clientlist_rust/layout.rs" 'pub const LEGACY_PRODUCT_ID: &str = "GT-AX11000";'
require_text "$clientlist_rust/layout.rs" 'const _: () = assert!(size_of::<LegacyTable>() == LEGACY_TABLE_SIZE);'
require_text "$clientlist_rust/layout.rs" 'const _: () = assert!(size_of::<PublicTable>() == PUBLIC_TABLE_SIZE);'
require_text "$clientlist_rust/layout.rs" 'if product_id == LEGACY_PRODUCT_ID && segment_size == LEGACY_TABLE_SIZE {'
require_text "$clientlist_rust/layout.rs" 'Err(UnsupportedLayout { segment_size })'
require_text "$clientlist_rust/snapshot.rs" '(reported as usize).min(MAX_NR_CLIENT_LIST)'
require_text "$clientlist_rust/snapshot.rs" 'let tail = &segment[segment.len() - TAIL_SIZE..];'
require_text "$clientlist_rust/shm.rs" 'libc::shmget(key, 0, 0)'
require_text "$clientlist_rust/shm.rs" 'libc::shmat(id, std::ptr::null(), libc::SHM_RDONLY)'
require_text "$clientlist_rust/shm.rs" 'libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock)'
reject_text "$clientlist_rust/shm.rs" 'libc::F_SETLKW'
require_text "$clientlist_rust/shm.rs" 'const LOCK_WAIT: Duration = Duration::from_millis(100);'
require_text "$clientlist_rust/cache.rs" '.create_new(true)'
require_text "$clientlist_rust/cache.rs" 'libc::O_NOFOLLOW | libc::O_NONBLOCK'
reject_text "$clientlist_rust/shm.rs" 'IPC_CREAT'
require_text "$clientlist_rust/render.rs" 'pub const MAX_OUTPUT: usize = 1024 * 1024;'
require_text "$clientlist_rust/cache.rs" '.is_some_and(|maclist| !maclist.is_empty())'
require_text "$clientlist_rust/ffi.rs" 'pub unsafe extern "C" fn rust_httpd_clientlist_render('
require_text "$httpd_rust" 'pub use clientlist::ffi as clientlist_ffi;'
require_text "$qos_ui" 'const qos_type = (_nvram.qos_type == "2") ? "2" : "0";'
require_text "$qos_ui" 'if (value !== "0" && value !== "2")'
require_text "$qos_ui" 'style="display:none;" type="radio" disabled'
require_text "$www_makefile" 'rm -f $(INSTALLDIR)/www/mobile/pages/tmtos_page.html'
require_text "$networkmap_makefile" '.DEFAULT_GOAL := all'
require_text "$networkmap_makefile" '-cp -f prebuild/$(BUILD_NAME)/networkmap networkmap'
require_text "$networkmap_makefile" 'RUST_BWDPI_COMPAT_MANIFEST := $(RUST_COMPONENTS_DIR)/bwdpi-compat/Cargo.toml'
require_text "$networkmap_makefile" '$(INSTALLDIR)/usr/lib/libbwdpi.so'
require_text "$bwdpi_compat" 'pub extern "C" fn check_bwdpi_nvram_setting() -> c_int'
require_text "$bwdpi_compat" 'pub unsafe extern "C" fn bwdpi_client_info('
require_text "$bwdpi_compat" 'pub extern "C" fn rust_bwdpi_compat_v1() -> c_int'

# wget is the isolated zlib-rs consumer: it links the static Rust archive and
# never the vendor libz; the vendored crates.io mapping must be discoverable
# from every package directory.
require_text "$router_makefile" 'RUST_ZLIB_STATIC_MANIFEST := $(RUST_COMPONENTS_DIR)/zlib-static/Cargo.toml'
require_text "$router_makefile" 'WGET_ZLIB_LIBS := $(RUST_ZLIB_STATIC_LIB) -lpthread -ldl -lm'
require_text "$router_makefile" 'ZLIB_LIBS="$(WGET_ZLIB_LIBS)"'
require_text "$router_makefile" 'wget: openssl zlib $(WGET_ZLIB_DEPS) wget/Makefile'
reject_text "$router_makefile" 'ZLIB_LIBS="-L$(TOP)/zlib -lz "'
require_text "$cargo_config" 'directory = "rust-components/vendor"'
require_text "$zlib_static" '#![forbid(unsafe_code)]'
require_text "$zlib_static_manifest" 'features = ["std", "c-allocator", "export-symbols", "gz"]'
reject_text "$zlib_static_manifest" 'gzprintf'

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
require_text "$wireless_ui" 'Treiberanforderung='
require_text "$wireless_ui" 'regulatory_lab_country_codes = ("AD AF AG'
require_text "$wireless_ui" 'ALL (Testlabor – Broadcom #a)'
country_codes=$(sed -n 's/^var regulatory_lab_country_codes = ("\([A-Z ]*\)").*/\1/p' "$wireless_ui")
country_count=$(wc -w <<<"$country_codes")
unique_country_count=$(tr ' ' '\n' <<<"$country_codes" | sort -u | wc -l)
if [ "$country_count" -lt 180 ] || [ "$country_count" -ne "$unique_country_count" ]; then
	echo "regulatory test-lab country list is incomplete or contains duplicates" >&2
	exit 1
fi
if grep -qw ALL <<<"$country_codes" ||
   [ "$(grep -Fc 'new Option("ALL (Testlabor – Broadcom #a)"' "$wireless_ui")" -ne 1 ]; then
	echo "regulatory test-lab selector must contain exactly one synthetic ALL profile" >&2
	exit 1
fi
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
reject_text "$httpd_stubs" 'nvram_set("wl0_country_code"'
reject_text "$httpd_stubs" 'nvram_set("wl0_txpower"'
require_text "$lan" 'rust_regulatory_profile_kind(country)'
require_text "$lan" 'driver_country = kind == 2 ? "#a" : country;'
require_text "$lan" 'txpower = kind == 2 ? "500" : "100";'
require_text "$lan" 'apply_regulatory_testlab_profile();'
require_text "$init" 'apply_regulatory_testlab_profile();'
require_text "$security_rust" 'pub unsafe extern "C" fn rust_regulatory_profile_kind'
reject_text "$services" 'suspended bsd under regulatory test-lab ALL profile'
require_text "$router/shared/sysdeps/broadcom/broadcom.c" 'void retrieve_static_maclist_from_nvram(int idx,struct maclist *maclist,int maclist_buf_size)'
require_text "$router/shared/sysdeps/broadcom/broadcom.c" 'const int vidx = 0;'
require_text "$services" 'suspended roamast under regulatory test-lab ALL profile'
require_text "$watchdog" 'if (nvram_match("location_code", "ALL"))'
restart_defaults_line=$(grep -nF 'wl_defaults();' "$lan" | tail -1 | cut -d: -f1)
restart_profile_line=$(grep -nF $'\tapply_regulatory_testlab_profile();' "$lan" | tail -1 | cut -d: -f1)
restart_start_line=$(grep -nF $'\tstart_lan_wl();' "$lan" | tail -1 | cut -d: -f1)
if [ -z "$restart_defaults_line" ] || [ -z "$restart_profile_line" ] ||
   [ -z "$restart_start_line" ] ||
   [ "$restart_defaults_line" -ge "$restart_profile_line" ] ||
   [ "$restart_profile_line" -ge "$restart_start_line" ]; then
	echo "regulatory profile must be re-derived after wl_defaults and before start_lan_wl" >&2
	exit 1
fi
for protected in '"0:ccode"' '"2:ccode"' '"wl0_txpower"' '"wl2_chlist"'; do
	require_text "$lan" "$protected"
done
for protected in 'b"0:ccode"' 'b"2:maxp5ga2"' 'b"pci/2/1/maxp2ga0"' \
	'b"wl0_txpower"' 'b"wl2_chlist"'; do
	require_text "$httpd_rust" "$protected"
done

# The effective firewall is checked after custom/VPN hooks and forwarding is
# enabled only after that check. Failures install the emergency WAN deny.
require_text "$firewall" 'rust_validate_effective_firewall_policy_files'
require_text "$firewall" '#define CODEX_WAN_GUARD "CODEX_WAN_GUARD"'
require_text "$firewall" 'install_wan_admin_guard(wan_if)'
require_text "$firewall" '#define WAN_GUARD_COMMAND_ATTEMPTS 10'
require_text "$firewall" 'run_wan_guard_command(tool, "input-hook"'
require_text "$firewall" 'WAN guard %s/%s failed after %u attempts'
require_text "$firewall" 'firewall_enter_fail_closed();'
custom_line=$(grep -nF 'run_custom_script("firewall-start"' "$firewall" | tail -1 | cut -d: -f1)
guard_line=$(grep -nF '!install_wan_admin_guard(wan_if)' "$firewall" | tail -1 | cut -d: -f1)
validation_line=$(grep -nF '!validate_effective_firewall_policy()' "$firewall" | tail -1 | cut -d: -f1)
forward_line=$(grep -nF $'\t\tenable_ip_forward();' "$firewall" | tail -1 | cut -d: -f1)
if [ -z "$custom_line" ] || [ -z "$guard_line" ] || [ -z "$validation_line" ] || \
   [ -z "$forward_line" ]; then
	echo "firewall validation/forwarding anchor missing" >&2
	exit 1
fi
if ! [ "$custom_line" -lt "$guard_line" ] || ! [ "$guard_line" -lt "$validation_line" ] || \
   ! [ "$validation_line" -lt "$forward_line" ]; then
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
require_text "$policy_rust" 'openvpn_custom_config_allowed'
reject_text "$openvpn" 'safe_imported_custom_option'
reject_text "$openvpn" 'safe_modern_cipher_list'
reject_text "$openvpn" 'safe_modern_digest'
require_text "$openvpn" 'OpenVPN import disabled compression'
require_text "$openvpn" 'OpenVPN import ignored unsafe or unsupported directive'
require_text "$openvpn_setup" 'OVPN_HARDENED_DATA_CIPHERS'
require_text "$openvpn_setup" 'rust_openvpn_custom_config_allowed'
require_text "$openvpn_setup" 'allow-compression no'
require_text "$openvpn_setup" 'tls-version-min 1.2'
require_text "$openvpn_setup" 'remote-cert-tls server'
reject_text "$openvpn_setup" 'data-ciphers-fallback AES-128-CBC'

# The legacy ISP-meter writes JFFS state and is not a GT-AX11000 feature.
# Cargo may enable it only for model profiles that explicitly select it.
require_text "$rstats_makefile" 'ifeq ($(RTCONFIG_ISP_METER),y)'
require_text "$rstats_makefile" 'RUST_RSTAT_FEATURES := --features isp-meter'
require_text "$router_config_base" '# RTCONFIG_ISP_METER is not set'

# Security fixes are backported into both duplicate vendor trees.
for wifi_tree in hostapd wpa_supplicant; do
	require_text "$wifi_base/$wifi_tree/src/common/sae.c" 'dragonfly_sqrt(sae->tmp->ec, y, y)'
	require_text "$wifi_base/$wifi_tree/src/radius/radius.c" 'attr->length != sizeof(*attr) + MD5_MAC_LEN'
	require_text "$wifi_base/$wifi_tree/src/rsn_supp/wpa.c" 'sm->network_ctx, sm->key_mgmt'
done

echo "security overlay invariants verified"
