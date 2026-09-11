#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern int rust_openvpn_custom_config_allowed(const char *);
extern int rust_validate_ipsec_identity(const char *);
extern int rust_validate_ipsec_filename(const char *);
extern int rust_update_wireguard_endpoint(const char *, const char *);
extern int rust_regulatory_profile_kind(const char *);
extern int rust_validate_effective_vpn_client_files(const char *, const char *,
	int, const char *, const char *, const char *);

static void write_text_file(const char *path, const char *contents)
{
	int fd;
	size_t length = strlen(contents);

	fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(fd >= 0);
	assert(write(fd, contents, length) == (ssize_t)length);
	assert(fsync(fd) == 0);
	assert(close(fd) == 0);
}

int main(int argc, char **argv)
{
	char path[PATH_MAX];
	char ipv4_path[PATH_MAX];
	char ipv6_path[PATH_MAX];
	char routes_path[PATH_MAX];
	char buffer[256] = {0};
	const char config[] = "[Peer]\nEndpoint = old.example:51820\n";
	const char filter[] =
	    "*filter\n"
	    ":INPUT ACCEPT [0:0]\n"
	    ":FORWARD ACCEPT [0:0]\n"
	    ":OVPNCI - [0:0]\n"
	    ":OVPNCF - [0:0]\n"
	    "-A INPUT -j OVPNCI\n"
	    "-A INPUT -j DROP\n"
	    "-A FORWARD -j OVPNCF\n"
	    "-A FORWARD -j DROP\n"
	    "-A OVPNCI -i tun11 -j DROP\n"
	    "-A OVPNCF -o tun11 -j ACCEPT\n"
	    "-A OVPNCF -i tun11 -j DROP\n"
	    "COMMIT\n";
	const char routes[] =
	    "0:\tfrom all lookup local\n"
	    "12210:\tfrom all iif br0 prohibit\n"
	    "32766:\tfrom all lookup main\n";
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

	assert(snprintf(ipv4_path, sizeof(ipv4_path), "%s/wg-link", argv[1]) > 0);
	assert(symlink(path, ipv4_path) == 0);
	assert(rust_update_wireguard_endpoint(ipv4_path, "vpn.example") == 0);
	assert(unlink(ipv4_path) == 0);

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

	assert(snprintf(ipv4_path, sizeof(ipv4_path), "%s/vpn-filter4", argv[1]) > 0);
	assert(snprintf(ipv6_path, sizeof(ipv6_path), "%s/vpn-filter6", argv[1]) > 0);
	assert(snprintf(routes_path, sizeof(routes_path), "%s/vpn-routes", argv[1]) > 0);
	write_text_file(ipv4_path, filter);
	write_text_file(ipv6_path, filter);
	write_text_file(routes_path, routes);
	assert(rust_validate_effective_vpn_client_files(
	    ipv4_path, ipv6_path, 1, routes_path, "br0", "openvpn:1:fw+ks") == 1);
	assert(rust_validate_effective_vpn_client_files(
	    ipv4_path, ipv6_path, 1, routes_path, "br1", "openvpn:1:fw+ks") == 0);
	assert(rust_validate_effective_vpn_client_files(
	    ipv4_path, ipv6_path, 1, NULL, "br0", "openvpn:1:fw+ks") == 0);
	assert(rust_validate_effective_vpn_client_files(
	    ipv4_path, ipv6_path, 1, NULL, "br0", "openvpn:1:fw") == 1);
	/* Run this on ARM too: Linux ARM EABI's O_NOFOLLOW is not x86's value. */
	assert(symlink(ipv4_path, path) == 0);
	assert(rust_validate_effective_vpn_client_files(
	    path, ipv6_path, 1, routes_path, "br0", "openvpn:1:fw+ks") == 0);
	assert(unlink(path) == 0);
	assert(mkfifo(path, 0600) == 0);
	alarm(2); /* A special input must not block before metadata validation. */
	assert(rust_update_wireguard_endpoint(path, "vpn.example") == 0);
	assert(rust_validate_effective_vpn_client_files(
	    path, ipv6_path, 1, routes_path, "br0", "openvpn:1:fw+ks") == 0);
	alarm(0);
	assert(unlink(path) == 0);
	assert(unlink(ipv4_path) == 0);
	assert(unlink(ipv6_path) == 0);
	assert(unlink(routes_path) == 0);
	return 0;
}
