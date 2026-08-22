#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int rust_openvpn_custom_config_allowed(const char *);
extern int rust_validate_ipsec_identity(const char *);
extern int rust_validate_ipsec_filename(const char *);
extern int rust_update_wireguard_endpoint(const char *, const char *);
extern int rust_regulatory_profile_kind(const char *);

int main(int argc, char **argv)
{
	char path[PATH_MAX];
	char buffer[256] = {0};
	const char config[] = "[Peer]\nEndpoint = old.example:51820\n";
	int fd;
	ssize_t length;

	assert(argc == 2);
	assert(rust_regulatory_profile_kind("DE") == 1);
	assert(rust_regulatory_profile_kind("ALL") == 2);
	assert(rust_regulatory_profile_kind("ZZ") == 0);
	assert(rust_regulatory_profile_kind("#a") == 0);
	assert(snprintf(path, sizeof(path), "%s/wg.conf", argv[1]) > 0);
	fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(fd >= 0);
	assert(write(fd, config, sizeof(config) - 1) == (ssize_t)(sizeof(config) - 1));
	assert(fsync(fd) == 0);
	assert(close(fd) == 0);

	assert(rust_validate_ipsec_identity("vpn.example") == 1);
	assert(rust_validate_ipsec_identity("vpn.example;touch /tmp/pwn") == 0);
	assert(rust_validate_ipsec_filename("client.p12") == 1);
	assert(rust_validate_ipsec_filename("../../client.p12") == 0);
	assert(rust_openvpn_custom_config_allowed(
	    "auth SHA256\ndata-ciphers AES-256-GCM\nremote-cert-tls server\n") == 1);
	assert(rust_openvpn_custom_config_allowed("up /tmp/hook\n") == 0);
	assert(rust_update_wireguard_endpoint(path, "vpn.example") == 1);

	fd = open(path, O_RDONLY);
	assert(fd >= 0);
	length = read(fd, buffer, sizeof(buffer) - 1);
	assert(length > 0);
	assert(close(fd) == 0);
	assert(strstr(buffer, "Endpoint = vpn.example:51820\n") != NULL);
	assert(unlink(path) == 0);
	return 0;
}
