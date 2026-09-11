/* Test-only read-only model. Never linked or installed in firmware. */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
const char *nvram_get(const char *key) {
    if (!key) return 0;
    if (!strcmp(key, "lan_ipaddr")) return "192.0.2.1";
    if (!strcmp(key, "lan_netmask")) return "255.255.255.0";
    if (!strcmp(key, "productid")) return "GT-AX11000";
    return "";
}
int nvram_set(const char *key, const char *value) {
    (void)key; (void)value; abort();
}
int nvram_unset(const char *key) { (void)key; abort(); }
int nvram_commit(void) { abort(); }
int get_discovery_ssid(char *buffer, int size) {
    if (size < 9) return -1;
    memcpy(buffer, "QEMU-LAB", 9); return 0;
}
uint16_t get_extend_cap(void) { return 0; }
