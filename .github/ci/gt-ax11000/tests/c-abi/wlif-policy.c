/* Strict C11 caller for the wireless-interface policy archive that
 * libshared.so links.  It exercises the exact entry points that the
 * rewritten shared/wlif_utils_ax.c call sites use before they hand a value
 * to hostapd_cli/wpa_cli through _eval().
 */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

extern int rust_wlif_ifname_ok(const char *);
extern int rust_wlif_ctrl_prefix_ok(const char *);
extern int rust_wlif_cli_token_ok(const char *);
extern int rust_wlif_cli_word_list_ok(const char *);
extern int rust_wlif_ssid_ok(const char *);
extern int rust_wlif_passphrase_ok(const char *);
extern int rust_wlif_wps_pin_ok(const char *);
extern int rust_wlif_dpp_value_ok(const char *);
extern int rust_wlif_network_id_ok(unsigned long);
extern int rust_wlif_supplicant_ctrl_path(char *, size_t, const char *);
extern int rust_wlif_supplicant_ctrl_dir(char *, size_t, const char *);

/* Every one of these terminates a shell word, so none may ever be accepted
 * inside an identifier that used to be interpolated into a command string.
 */
static const char *const hostile[] = {
	"wl0;reboot",
	"wl0 reboot",
	"wl0|reboot",
	"wl0&reboot",
	"wl0`id`",
	"wl0$(id)",
	"wl0${x}",
	"wl0>/tmp/x",
	"wl0</tmp/x",
	"wl0\nreboot",
	"wl0\rreboot",
	"wl0\treboot",
	"wl0\x01",
	"wl0\x7f",
	"wl0*",
	"wl0?",
	"wl0'",
	"wl0\"",
	"wl0\\",
	"wl0#",
	"-i",
	"../../tmp/x",
	"/var/run/hostapd",
	"",
};

int main(void)
{
	char path[128];
	char small[8];
	size_t index;
	char over_length[4096];

	/* Interface names: the vendor shapes are accepted, everything that
	 * could escape a command line is not.
	 */
	assert(rust_wlif_ifname_ok("eth0") == 1);
	assert(rust_wlif_ifname_ok("wl0.1") == 1);
	assert(rust_wlif_ifname_ok("wds0.0.1") == 1);
	assert(rust_wlif_ifname_ok("eth12345678901") == 1);
	assert(rust_wlif_ifname_ok("eth1234567890123") == 0);
	assert(rust_wlif_ifname_ok(NULL) == 0);
	for (index = 0; index < sizeof(hostile) / sizeof(hostile[0]); index++) {
		assert(rust_wlif_ifname_ok(hostile[index]) == 0);
		assert(rust_wlif_ctrl_prefix_ok(hostile[index]) == 0);
		assert(rust_wlif_cli_token_ok(hostile[index]) == 0);
	}

	/* A NUL truncates the C string, so the bytes after it can never be
	 * smuggled into an argv element.
	 */
	assert(rust_wlif_ifname_ok("wl0\0;reboot") == 1);

	assert(rust_wlif_ctrl_prefix_ok("wl0_") == 1);
	assert(rust_wlif_ctrl_prefix_ok("wl0_wl0_wl0_wl0_w") == 0);

	assert(rust_wlif_cli_token_ok("wps_pbc") == 1);
	assert(rust_wlif_cli_token_ok("wps_cancel") == 1);
	assert(rust_wlif_cli_token_ok("set_network") == 1);
	assert(rust_wlif_cli_token_ok("WPA2PSK") == 1);
	assert(rust_wlif_cli_token_ok("255") == 1);
	assert(rust_wlif_cli_token_ok("--help") == 0);
	assert(rust_wlif_cli_token_ok(NULL) == 0);

	assert(rust_wlif_cli_word_list_ok("WPA-PSK SAE") == 1);
	assert(rust_wlif_cli_word_list_ok("CCMP TKIP") == 1);
	assert(rust_wlif_cli_word_list_ok("2") == 1);
	assert(rust_wlif_cli_word_list_ok("WPA-PSK  SAE") == 0);
	assert(rust_wlif_cli_word_list_ok(" WPA-PSK") == 0);
	assert(rust_wlif_cli_word_list_ok("WPA-PSK ") == 0);
	assert(rust_wlif_cli_word_list_ok("WPA-PSK;reboot SAE") == 0);

	/* Credentials stay opaque: metacharacters are allowed because no shell
	 * ever sees them, but control bytes, over-length and bad encoding are
	 * refused.
	 */
	assert(rust_wlif_ssid_ok("ASUS_11000") == 1);
	assert(rust_wlif_ssid_ok("My Net; rm -rf /") == 1);
	assert(rust_wlif_ssid_ok("caf\xc3\xa9") == 1);
	assert(rust_wlif_ssid_ok("caf\xe9") == 0);
	assert(rust_wlif_ssid_ok("net\nwork") == 0);
	assert(rust_wlif_ssid_ok("") == 0);
	assert(rust_wlif_ssid_ok("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 1);
	assert(rust_wlif_ssid_ok("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);

	assert(rust_wlif_passphrase_ok("12345678") == 1);
	assert(rust_wlif_passphrase_ok("1234567") == 0);
	assert(rust_wlif_passphrase_ok("pass;phrase with spaces") == 1);
	assert(rust_wlif_passphrase_ok("pass\nphrase") == 0);
	assert(rust_wlif_passphrase_ok(
	    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") == 1);
	assert(rust_wlif_passphrase_ok(
	    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg") == 0);

	assert(rust_wlif_wps_pin_ok("12345670") == 1);
	assert(rust_wlif_wps_pin_ok("1234") == 1);
	assert(rust_wlif_wps_pin_ok("1234567") == 0);
	assert(rust_wlif_wps_pin_ok("1234567;") == 0);
	assert(rust_wlif_wps_pin_ok("abcdefgh") == 0);

	assert(rust_wlif_dpp_value_ok("eyJhbGciOiJFUzI1NiJ9.eyJ4Ijoi_-A=") == 1);
	assert(rust_wlif_dpp_value_ok("-Aq") == 0);
	assert(rust_wlif_dpp_value_ok("key with space") == 0);
	memset(over_length, 'A', sizeof(over_length));
	over_length[1024] = '\0';
	assert(rust_wlif_dpp_value_ok(over_length) == 1);
	over_length[1024] = 'A';
	over_length[1025] = '\0';
	assert(rust_wlif_dpp_value_ok(over_length) == 0);

	assert(rust_wlif_network_id_ok(0) == 1);
	assert(rust_wlif_network_id_ok(255) == 1);
	assert(rust_wlif_network_id_ok(256) == 0);

	/* The control paths are built by the policy, never by the caller, and
	 * fail closed into an empty string.
	 */
	memset(path, 'x', sizeof(path));
	assert(rust_wlif_supplicant_ctrl_path(path, sizeof(path), "wl0.1") == 1);
	assert(strcmp(path, "/var/run/wl0.1_wpa_supplicant") == 0);
	memset(path, 'x', sizeof(path));
	assert(rust_wlif_supplicant_ctrl_dir(path, sizeof(path), "wl0_") == 1);
	assert(strcmp(path, "/var/run/wl0_wpa_supplicant/") == 0);

	for (index = 0; index < sizeof(hostile) / sizeof(hostile[0]); index++) {
		memset(path, 'x', sizeof(path));
		assert(rust_wlif_supplicant_ctrl_path(path, sizeof(path),
		    hostile[index]) == 0);
		assert(path[0] == '\0');
		memset(path, 'x', sizeof(path));
		assert(rust_wlif_supplicant_ctrl_dir(path, sizeof(path),
		    hostile[index]) == 0);
		assert(path[0] == '\0');
	}

	memset(small, 'x', sizeof(small));
	assert(rust_wlif_supplicant_ctrl_path(small, sizeof(small), "wl0") == 0);
	assert(small[0] == '\0');
	assert(rust_wlif_supplicant_ctrl_path(NULL, sizeof(path), "wl0") == 0);
	assert(rust_wlif_supplicant_ctrl_path(path, 0, "wl0") == 0);
	assert(rust_wlif_supplicant_ctrl_path(path, sizeof(path), NULL) == 0);

	printf("wlif-policy C ABI fixture passed\n");
	return 0;
}
