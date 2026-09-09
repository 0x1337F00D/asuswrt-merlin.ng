/* Offline QEMU fixture ONLY. Never preload this library on a router.
 * Synthetic NVRAM, no real credentials. Run in separate network/PID/mount
 * namespaces with an isolated /tmp. Not a production compatibility shim.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

char *nvram_get(const char *key)
{
    fprintf(stderr, "fixture nvram_get %s\n", key);
    if (!strcmp(key, "location_code")) return "ALL";
    if (!strcmp(key, "bsd_role")) return "3";
    if (!strcmp(key, "smart_connect_x")) return "1";
    if (!strcmp(key, "sw_mode")) return "1";
    if (!strcmp(key, "bsd_ifnames") || !strcmp(key, "wl_ifnames")) return "eth6 eth7 eth8";
    if (!strcmp(key, "bsd_primary")) return "127.0.0.1";
    if (!strcmp(key, "bsd_helper")) return "127.0.0.2";
    if (!strcmp(key, "bsd_msglevel")) return "7";
    if (!strcmp(key, "wl0_ifname")) return "eth6";
    if (!strcmp(key, "wl1_ifname")) return "eth7";
    if (!strcmp(key, "wl2_ifname")) return "eth8";
    if (!strcmp(key, "wl0_vifs")) return "wl0.1";
    if (strstr(key, "_bsd_steering_policy")) return key[2] == '2' ? "0 5 3 -82 0 0 0x28" : "0 5 3 -82 0 0 0x20";
    if (strstr(key, "_bsd_sta_select_policy")) return key[2] == '2' ? "30 -82 0 0 0 1 1 0 0 0 0x28" : "30 -82 0 0 0 1 1 0 0 0 0x20";
    if (!strcmp(key, "wl0_bsd_if_select_policy")) return "eth8 eth7";
    if (!strcmp(key, "wl1_bsd_if_select_policy")) return "eth8 eth6";
    if (!strcmp(key, "wl2_bsd_if_select_policy")) return "eth7 eth6";
    if (strstr(key, "_radio") || strstr(key, "_bss_enabled")) return "1";
    if (strstr(key, "_ssid")) return "offline-fixture";
    if (strstr(key, "_country_code")) return "#a";
    return NULL;
}
int nvram_get_int(const char *key) { char *p = nvram_get(key); return p ? atoi(p) : 0; }
char *nvram_default_get(const char *key) { return nvram_get(key); }
int nvram_set(const char *key, const char *value)
{ (void)value; fprintf(stderr, "fixture ignoring nvram_set %s\n", key); return 0; }
int nvram_unset(const char *key) { (void)key; return 0; }
int nvram_commit(void) { errno = EPERM; return -1; }
int system(const char *s) { (void)s; errno = EPERM; return -1; }
int daemon(int a, int b) { (void)a; (void)b; errno = EPERM; return -1; }
int kill(pid_t pid, int sig) { (void)pid; (void)sig; errno = EPERM; return -1; }
static int fixture_wl_ioctl(char *name, int cmd, void *buf, int len)
{
    fprintf(stderr, "fixture wl_ioctl %s %d\n", name, cmd);
    if (cmd == 14 && len == 4) { *(int *)buf = name[3] - '6'; return 0; }
    if (cmd == 141 && len == 4) { *(int *)buf = name[3] == '6' ? 2 : 1; return 0; }
    if (cmd == 25 && len >= 36) { memset(buf, 0, len); *(int *)buf=15; memcpy((char *)buf+4, "offline-fixture",15); return 0; }
    if (cmd == 23 && len >= 6) { memset(buf,0,len); ((unsigned char *)buf)[0]=2; ((unsigned char *)buf)[5]=name[3]; return 0; }
    return -1;
}

int ioctl(int fd, unsigned long request, ...)
{
    va_list args;
    struct ifreq *ifr;
    (void)fd;
    va_start(args,request); ifr=va_arg(args,struct ifreq *); va_end(args);
    if (request==SIOCDEVPRIVATE) {
        struct fixture_ioc { uint32_t cmd; void *buf; uint32_t len; } *ioc=(void *)ifr->ifr_data;
        int result=fixture_wl_ioctl(ifr->ifr_name, ioc->cmd, ioc->buf, ioc->len);
        if (result) errno=EOPNOTSUPP;
        return result;
    }
    if (request==SIOCETHTOOL) {
        struct ethtool_drvinfo *info=(void *)ifr->ifr_data;
        if (info->cmd==ETHTOOL_GDRVINFO) { strcpy(info->driver,"wl"); return 0; }
    }
    errno=EOPNOTSUPP; return -1;
}
