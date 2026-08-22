#include <assert.h>
#include <stddef.h>
#include <string.h>

extern int rust_httpd_url_decode(char *, size_t, int);
extern int rust_httpd_query_validate(const char *, size_t);
extern int rust_httpd_multipart_filename_validate(const char *, size_t);
extern int rust_httpd_testlab_country_authorize(const char *, size_t,
    const char *, size_t);
extern int rust_httpd_wlan_security_validate(const char *, size_t,
    const char *, size_t, const char *, size_t, const char *, size_t);
extern int rust_openvpn_import_option_allowed(const char *, const char *,
    const char *, const char *);

int main(void)
{
	char encoded_nul[] = "safe%00suffix";
	char original[sizeof(encoded_nul)];
	const char *confirmation = "ACKNOWLEDGE_REGULATORY_AND_HARDWARE_RISK_V1";

	memcpy(original, encoded_nul, sizeof(original));
	assert(rust_httpd_url_decode(encoded_nul, strlen(encoded_nul), 1) == -2);
	assert(memcmp(encoded_nul, original, sizeof(original)) == 0);
	assert(rust_httpd_query_validate("name=value&x=1", 14) == 1);
	assert(rust_httpd_query_validate("name=%00", 8) == 0);
	assert(rust_httpd_multipart_filename_validate("client.p12", 10) == 1);
	assert(rust_httpd_multipart_filename_validate("../client.p12", 13) == 0);
	assert(rust_httpd_testlab_country_authorize("ALL", 3, confirmation,
	    strlen(confirmation)) == 1);
	assert(rust_httpd_testlab_country_authorize("#a", 2, confirmation,
	    strlen(confirmation)) == 0);
	assert(rust_httpd_wlan_security_validate("psk2", 4, "aes", 3, "2", 1,
	    "0", 1) == 1);
	assert(rust_httpd_wlan_security_validate("psk2", 4, "tkip", 4, "0", 1,
	    "1", 1) == 0);
	assert(rust_openvpn_import_option_allowed("cipher", "AES-256-GCM", NULL,
	    NULL) == 1);
	assert(rust_openvpn_import_option_allowed("script-security", "2", NULL,
	    NULL) == 0);
	return 0;
}
