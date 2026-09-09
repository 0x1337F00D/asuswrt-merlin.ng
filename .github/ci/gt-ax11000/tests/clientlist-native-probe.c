/* Read-only native consumer probe: no NVRAM set/commit, no shared-memory
 * writes, no daemon control, no cache/database writes and no client names
 * printed. The real Rust snapshot uses the vendor's advisory lock. json-c
 * independently checks the returned text; no json_object crosses the FFI.
 * No AiMesh RE nodes are modeled by this standalone single-router probe.
 */
#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <json.h>

struct rust_httpd_clientlist_inputs {
    int shm_key;
    const char *productid, *lan_ipaddr, *login_ip_str, *rog_clientlist;
    const char *custom_clientlist, *qos_rulelist, *wtf_rulelist;
    int multifilter_all;
    const char *multifilter_mac, *multifilter_enable, *multifilter_daytime;
    int amas_support;
    const char *amas_client_list_path, *lock_dir;
    int (*is_re_node)(const char *);
};
struct rust_httpd_clientlist_db_inputs {
    const char *db_path, *rog_clientlist, *custom_clientlist, *amas_node_types;
    int (*is_re_node)(const char *);
};
extern char *nvram_get(const char *);
extern int rust_httpd_clientlist_render(const struct rust_httpd_clientlist_inputs *, char *, size_t);
extern int rust_httpd_clientlist_database_render(const struct rust_httpd_clientlist_db_inputs *, char *, size_t);

static char *value(const char *name)
{
    const char *text = nvram_get(name);
    char *copy = strdup(text ? text : "");
    if (!copy) exit(70);
    return copy;
}

static int validate(const char *text)
{
    struct json_object *root = json_tokener_parse(text), *maclist = NULL;
    int count, i;
    if (!root || !json_object_is_type(root, json_type_object) ||
        !json_object_object_get_ex(root, "maclist", &maclist) ||
        !json_object_is_type(maclist, json_type_array)) {
        if (root) json_object_put(root);
        return -1;
    }
    count = json_object_array_length(maclist);
    for (i = 0; i < count; ++i) {
        struct json_object *entry = json_object_array_get_idx(maclist, i), *client = NULL;
        if (!json_object_is_type(entry, json_type_string) ||
            !json_object_object_get_ex(root, json_object_get_string(entry), &client) ||
            !json_object_is_type(client, json_type_object)) {
            json_object_put(root);
            return -1;
        }
    }
    json_object_put(root);
    return count;
}

int main(void)
{
    const size_t capacity = 1024 * 1024;
    struct rust_httpd_clientlist_inputs in = {0};
    struct rust_httpd_clientlist_db_inputs db = {0};
    struct rusage usage;
    struct timespec start, end;
    char *buffer, *all;
    int round, length, count = 0;
    double maximum_ms = 0;
    in.productid = value("productid");
    if (strcmp(in.productid, "GT-AX11000")) return 2;
    in.shm_key = 1001;
    in.lan_ipaddr = value("lan_ipaddr");
    in.login_ip_str = value("login_ip_str");
    in.rog_clientlist = value("rog_clientlist");
    in.custom_clientlist = value("custom_clientlist");
    in.qos_rulelist = value("qos_rulelist");
    in.wtf_rulelist = value("wtf_rulelist");
    in.multifilter_mac = value("MULTIFILTER_MAC");
    in.multifilter_enable = value("MULTIFILTER_ENABLE");
    in.multifilter_daytime = value("MULTIFILTER_MACFILTER_DAYTIME");
    all = value("MULTIFILTER_ALL");
    in.multifilter_all = atoi(all);
    free(all);
    in.amas_support = 1;
    in.amas_client_list_path = "/tmp/clientlist.json";
    buffer = malloc(capacity);
    if (!buffer) return 70;
    for (round = 0; round < 10; ++round) {
        if (clock_gettime(CLOCK_MONOTONIC, &start)) return 70;
        length = rust_httpd_clientlist_render(&in, buffer, capacity);
        if (clock_gettime(CLOCK_MONOTONIC, &end)) return 70;
        if (length <= 0 || (count = validate(buffer)) <= 0 || count > 255) {
            printf("LIVE=FAIL ffi=%d clients=%d round=%d\n", length, count, round);
            return 1;
        }
        double ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
        if (ms > maximum_ms) maximum_ms = ms;
        usleep(100000);
    }
    printf("LIVE=PASS samples=10 clients=%d bytes=%d max_render_ms=%.3f\n", count, length, maximum_ms);
    db.db_path = "/jffs/nmp_cl_json.js";
    db.rog_clientlist = in.rog_clientlist;
    db.custom_clientlist = in.custom_clientlist;
    length = rust_httpd_clientlist_database_render(&db, buffer, capacity);
    count = length > 0 ? validate(buffer) : -1;
    if (count < 0) return 1;
    printf("DATABASE=PASS clients=%d bytes=%d\n", count, length);
    if (getrusage(RUSAGE_SELF, &usage)) return 70;
    printf("NATIVE_CLIENTLIST=PASS max_rss_kib=%ld writes=advisory-lock-only\n", usage.ru_maxrss);
    free(buffer);
    free((void *)in.productid); free((void *)in.lan_ipaddr); free((void *)in.login_ip_str);
    free((void *)in.rog_clientlist); free((void *)in.custom_clientlist);
    free((void *)in.qos_rulelist); free((void *)in.wtf_rulelist);
    free((void *)in.multifilter_mac); free((void *)in.multifilter_enable); free((void *)in.multifilter_daytime);
    return 0;
}
