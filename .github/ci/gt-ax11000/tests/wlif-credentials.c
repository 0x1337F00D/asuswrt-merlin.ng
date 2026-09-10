#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#define FALSE false
#define TRUE true
#define WLIF_MIN_BUF 256
#define WLIF_BUF_512 512
#define IFNAMSIZ 16
#define WLIFU_MLO_INVALID -1
#define WLIFU_MLO_MAP_LINKID 0
#define HAPD_KEY_MGMT_SAE "SAE"
#define cprintf(...) ((void)0)
#define dprintf(...) ((void)0)
typedef enum { WPA_CONNECTION_TYPE_WPS, WPA_CONNECTION_TYPE_DPP } wpa_connection_type_t;
extern int rust_wlif_ifname_ok(const char *);
extern int rust_wlif_network_id_ok(unsigned long);
extern int rust_wlif_ssid_ok(const char *);
extern int rust_wlif_passphrase_ok(const char *);
extern int rust_wlif_cli_token_ok(const char *);
extern int rust_wlif_cli_word_list_ok(const char *);
extern int rust_wlif_dpp_value_ok(const char *);
static const char *mode, *psk;
static char sent_psk[128];
static int saved, enabled, psk_set, dpp_set;
static int osifname_to_nvifname(char *name, char *out, size_t len)
{ (void)name; snprintf(out, len, "wl0"); return 0; }
static char *nvram_safe_get(const char *name)
{
	if (strstr(name, "_ssid")) return "test network";
	if (strstr(name, "_wpa_psk")) return (char *)psk;
	if (strstr(name, "_dpp_")) return "ABCD";
	return "";
}
static int find_in_list(const char *list, const char *word)
{ return strstr(list, word) != NULL; }
static int wl_wlif_get_mlo_linkid(char *name, bool any)
{ (void)name; (void)any; return WLIFU_MLO_INVALID; }
static void wpa_supp_key_mgmt_conv_fn(char *name, char *key, void *unused, char *out, int len)
{ (void)name; (void)unused; snprintf(out, len, "%s", !strcmp(key, "akm") ? mode : "CCMP"); }
static void hapd_mfp_conv_fn(char *name, char *key, void *unused, char *out, int len)
{ (void)name; (void)key; (void)unused; snprintf(out, len, "2"); }
static int wl_wlif_run_argv(char *const argv[], char *out, size_t len)
{
	(void)out; (void)len;
	if (!strcmp(argv[3], "save_config")) saved++;
	if (!strcmp(argv[3], "enable_network")) enabled++;
	if (!strcmp(argv[3], "set_network")) {
		if (!strcmp(argv[5], "psk")) {
			psk_set++;
			snprintf(sent_psk, sizeof(sent_psk), "%s", argv[6]);
		}
		if (strstr(argv[5], "dpp_")) dpp_set++;
	}
	return 0;
}
/* INSERT_ACTUAL_VENDOR_FUNCTIONS */
static void run(const char *security, const char *password, wpa_connection_type_t type)
{
	mode = security; psk = password;
	saved = enabled = psk_set = dpp_set = 0;
	wl_wlif_apply_creds_to_supplicant("wl0", 0, type);
}
int main(void)
{
	run("NONE", "", WPA_CONNECTION_TYPE_WPS);
	assert(saved == 1 && enabled == 1 && psk_set == 0);
	run("DPP", "", WPA_CONNECTION_TYPE_DPP);
	assert(saved == 1 && enabled == 1 && psk_set == 0 && dpp_set == 4);
	run("WPA-EAP", "", WPA_CONNECTION_TYPE_WPS);
	assert(saved == 1 && enabled == 1 && psk_set == 0);
	run("WPA-PSK", "", WPA_CONNECTION_TYPE_WPS);
	assert(saved == 0 && enabled == 0 && psk_set == 0);
	run("WPA-PSK SAE", "testpass", WPA_CONNECTION_TYPE_WPS);
	assert(saved == 1 && enabled == 1 && psk_set == 1 && !strcmp(sent_psk, "\"testpass\""));
	run("WPA-PSK", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", WPA_CONNECTION_TYPE_WPS);
	assert(saved == 1 && enabled == 1 && psk_set == 1 && sent_psk[0] == '0');
	puts("wlif credentials: actual C flow + Rust policy, open/DPP/enterprise/PSK/SAE/raw-key passed");
	return 0;
}
