/*
 * Strict C11 fixture for the client-list C ABI exported by the single
 * httpd Rust archive (libhttpd_parsers.a re-exports the clientlist crate).
 * It creates a real SysV segment with a private key, fills the legacy
 * GT-AX11000 layout the way the closed networkmap daemon does, renders the
 * document and checks the fail-closed paths.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LEGACY_TABLE_SIZE 174964U
#define PUBLIC_TABLE_SIZE 173436U
#define TAIL_SIZE 32U
#define MAX_NR_CLIENT_LIST 255U

/* Offsets of GT_AX11000_NETWORKMAP_TABLE (networkmap-shm-abi.patch). */
#define OFF_IP_ADDR 0U
#define OFF_MAC_ADDR 1020U
#define OFF_USER_DEFINE 2550U
#define OFF_VENDOR_NAME 6630U
#define OFF_DEVICE_NAME 39270U
#define OFF_APPLE_MODEL 47430U
#define OFF_ONLINE 68340U
#define OFF_TYPE 68595U
#define OFF_IPMETHOD 68850U
#define OFF_DEVICE_FLAG 70890U
#define OFF_WIRELESS 71145U
#define OFF_RSSI 86192U

#define CLIENTLIST_INVALID (-1)
#define CLIENTLIST_UNSUPPORTED_LAYOUT (-3)
#define CLIENTLIST_OVERFLOW (-4)
#define CLIENTLIST_NO_SEGMENT (-5)
#define CLIENTLIST_CACHE_REJECTED (-8)

struct rust_httpd_clientlist_inputs {
	int shm_key;
	const char *productid;
	const char *lan_ipaddr;
	const char *login_ip_str;
	const char *rog_clientlist;
	const char *custom_clientlist;
	const char *qos_rulelist;
	const char *wtf_rulelist;
	int multifilter_all;
	const char *multifilter_mac;
	const char *multifilter_enable;
	const char *multifilter_daytime;
	int amas_support;
	const char *amas_client_list_path;
	const char *lock_dir;
	int (*is_re_node)(const char *mac);
};

struct rust_httpd_clientlist_db_inputs {
	const char *db_path;
	const char *rog_clientlist;
	const char *custom_clientlist;
	const char *amas_node_types;
	int (*is_re_node)(const char *mac);
};

extern int rust_httpd_clientlist_render(
    const struct rust_httpd_clientlist_inputs *inputs, char *buffer,
    size_t capacity);
extern int rust_httpd_clientlist_cache_write(const char *path,
    const char *json, size_t length);
extern int rust_httpd_clientlist_cache_read(const char *path, char *buffer,
    size_t capacity);
extern int rust_httpd_clientlist_name_for_ip(const char *json, size_t length,
    const char *ip, char *name, size_t name_capacity);
extern int rust_httpd_clientlist_sdn_client_count(const char *json,
    size_t length, int *counts, size_t count_capacity);
extern int rust_httpd_clientlist_database_render(
    const struct rust_httpd_clientlist_db_inputs *inputs, char *buffer,
    size_t capacity);
extern int rust_httpd_clientlist_all_basic_render(const char *db_path,
    const char *custom_clientlist, char *buffer, size_t capacity);
extern int rust_httpd_clientlist_basic_render(
    const struct rust_httpd_clientlist_inputs *inputs, int networkmap_alive,
    const char *db_path, int opt, char *buffer, size_t capacity);
extern int rust_httpd_clientlist_search_name(const char *db_path,
    const char *custom_clientlist, const char *name, char *buffer,
    size_t capacity);

static void check_contended_lock(const char *path,
    const struct rust_httpd_clientlist_inputs *inputs, char *buffer, size_t size)
{
	int ready[2], release[2], status;
	char byte = 'x';
	pid_t child;
	struct timespec start, end;
	assert(pipe(ready) == 0 && pipe(release) == 0);
	child = fork();
	assert(child >= 0);
	if(child == 0) {
		int fd = open(path, O_CREAT | O_RDWR, 0600);
		pid_t pid = getpid();
		struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
		assert(fd >= 0 && fcntl(fd, F_SETLK, &lock) == 0);
		assert(write(fd, &pid, sizeof(pid)) == sizeof(pid));
		assert(write(ready[1], &byte, 1) == 1);
		assert(read(release[0], &byte, 1) == 1);
		close(fd);
		_exit(0);
	}
	assert(read(ready[0], &byte, 1) == 1);
	assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
	assert(rust_httpd_clientlist_render(inputs, buffer, size) == -6);
	assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
	assert((end.tv_sec - start.tv_sec) * 1000 +
	    (end.tv_nsec - start.tv_nsec) / 1000000 < 2000);
	assert(write(release[1], &byte, 1) == 1);
	assert(waitpid(child, &status, 0) == child && status == 0);
	close(ready[0]); close(ready[1]); close(release[0]); close(release[1]);
}

static int is_re_node_f1(const char *mac)
{
	return strcmp(mac, "AA:BB:CC:DD:EE:F1") == 0;
}

static void put_field(unsigned char *table, size_t offset, size_t width,
    size_t index, const char *value)
{
	size_t length = strlen(value);

	if (length > width)
		length = width;
	memset(table + offset + width * index, 0, width);
	memcpy(table + offset + width * index, value, length);
}

static void put_byte(unsigned char *table, size_t offset, size_t index,
    unsigned char value)
{
	table[offset + index] = value;
}

static void fill_legacy_table(unsigned char *table)
{
	const unsigned char gateway_mac[6] = { 0x04, 0xd4, 0xc4, 0xaa, 0xbb, 0x01 };
	const unsigned char phone_mac[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02 };
	const unsigned char console_mac[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03 };
	const unsigned char re_mac[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf1 };
	const unsigned char gateway_ip[4] = { 192, 168, 50, 1 };
	const unsigned char phone_ip[4] = { 192, 168, 50, 20 };
	const unsigned char console_ip[4] = { 192, 168, 50, 30 };
	const unsigned char re_ip[4] = { 192, 168, 50, 39 };
	int count = 4;
	int rssi = -47;
	char long_vendor[129];

	memset(table, 0, LEGACY_TABLE_SIZE);
	memset(long_vendor, 'V', sizeof(long_vendor) - 1);
	long_vendor[sizeof(long_vendor) - 1] = '\0';

	memcpy(table + OFF_IP_ADDR, gateway_ip, 4);
	memcpy(table + OFF_MAC_ADDR, gateway_mac, 6);
	put_field(table, OFF_DEVICE_NAME, 32, 0, "GT-AX11000");
	put_field(table, OFF_VENDOR_NAME, 128, 0, "ASUSTek COMPUTER INC.");
	put_byte(table, OFF_ONLINE, 0, 1);
	put_byte(table, OFF_TYPE, 0, 9);
	put_field(table, OFF_IPMETHOD, 7, 0, "Manual");
	put_byte(table, OFF_DEVICE_FLAG, 0, (1 << 5) | (1 << 0));

	memcpy(table + OFF_IP_ADDR + 4, phone_ip, 4);
	memcpy(table + OFF_MAC_ADDR + 6, phone_mac, 6);
	put_field(table, OFF_USER_DEFINE, 16, 1, "Paul's Phone!");
	put_field(table, OFF_VENDOR_NAME, 128, 1, long_vendor);
	put_field(table, OFF_APPLE_MODEL, 16, 1, "iPhone");
	put_byte(table, OFF_ONLINE, 1, 1);
	put_byte(table, OFF_TYPE, 1, 2);
	put_field(table, OFF_IPMETHOD, 7, 1, "DHCP");
	put_byte(table, OFF_WIRELESS, 1, 2);
	memcpy(table + OFF_RSSI + 4, &rssi, sizeof(rssi));

	memcpy(table + OFF_IP_ADDR + 8, console_ip, 4);
	memcpy(table + OFF_MAC_ADDR + 12, console_mac, 6);
	put_field(table, OFF_DEVICE_NAME, 32, 2, "Xbox");
	put_byte(table, OFF_ONLINE, 2, 0);
	put_byte(table, OFF_TYPE, 2, 1);
	put_field(table, OFF_IPMETHOD, 7, 2, "OffLine");
	put_byte(table, OFF_WIRELESS, 2, 1);

	memcpy(table + OFF_IP_ADDR + 12, re_ip, 4);
	memcpy(table + OFF_MAC_ADDR + 18, re_mac, 6);
	put_field(table, OFF_DEVICE_NAME, 32, 3, "RE node");
	put_byte(table, OFF_ONLINE, 3, 1);

	memcpy(table + LEGACY_TABLE_SIZE - TAIL_SIZE, &count, sizeof(count));
}

static int create_segment(key_t key, const unsigned char *bytes, size_t size)
{
	int id = shmget(key, size, IPC_CREAT | IPC_EXCL | 0600);
	void *address;

	assert(id != -1);
	address = shmat(id, NULL, 0);
	assert(address != (void *)-1);
	memcpy(address, bytes, size);
	assert(shmdt(address) == 0);
	return id;
}

static void write_file(const char *path, const char *text)
{
	FILE *file = fopen(path, "w");

	assert(file != NULL);
	assert(fputs(text, file) >= 0);
	assert(fclose(file) == 0);
}

int main(int argc, char **argv)
{
	static unsigned char table[LEGACY_TABLE_SIZE];
	static char buffer[256 * 1024];
	static char copy[256 * 1024];
	char scratch[512], cache_path[600], db_path[600], lock_probe[600];
	char name[8];
	struct rust_httpd_clientlist_inputs inputs;
	struct rust_httpd_clientlist_db_inputs db_inputs;
	key_t key = (key_t)(0x43000000 | (((int)getpid() & 0x000fffff) << 4));
	int legacy_id, small_id, length, copied, counts[4] = { 0, 0, 0, 0 };
	struct stat status;
	const char *sdn_document = "{\"A\":{\"sdn_idx\":\"1\",\"isOnline\":\"1\"}}";

	assert(argc == 2);
	snprintf(scratch, sizeof(scratch), "%s/clientlist-%ld", argv[1],
	    (long)getpid());
	assert(mkdir(scratch, 0700) == 0 || errno == EEXIST);
	snprintf(cache_path, sizeof(cache_path), "%s/nmp_cache.js", scratch);
	snprintf(db_path, sizeof(db_path), "%s/nmp_cl_json.js", scratch);
	snprintf(lock_probe, sizeof(lock_probe), "%s/networkmap.lock", scratch);

	fill_legacy_table(table);
	legacy_id = create_segment(key, table, sizeof(table));
	small_id = create_segment(key + 1, table, 1000);

	memset(&inputs, 0, sizeof(inputs));
	inputs.shm_key = (int)key;
	inputs.productid = "GT-AX11000";
	inputs.lan_ipaddr = "192.168.50.1";
	inputs.login_ip_str = "192.168.50.20";
	inputs.rog_clientlist = "<AA:BB:CC:DD:EE:03";
	inputs.custom_clientlist = "<Pauls iPhone>AA:BB:CC:DD:EE:02>0>5>cb>1";
	inputs.qos_rulelist = "<>AA:BB:CC:DD:EE:02>>>>2";
	inputs.wtf_rulelist = "<1>AA:BB:CC:DD:EE:02>>>";
	inputs.multifilter_all = 1;
	inputs.multifilter_mac = "AA:BB:CC:DD:EE:03";
	inputs.multifilter_enable = "2";
	inputs.multifilter_daytime = "";
	inputs.amas_support = 1;
	inputs.amas_client_list_path = NULL;
	inputs.lock_dir = scratch;
	inputs.is_re_node = is_re_node_f1;
	check_contended_lock(lock_probe, &inputs, buffer, sizeof(buffer));

	/* Live document from the real segment. */
	length = rust_httpd_clientlist_render(&inputs, buffer, sizeof(buffer));
	assert(length > 0);
	assert(buffer[length] == '\0');
	assert((size_t)length == strlen(buffer));
	assert(strstr(buffer, "\"04:D4:C4:AA:BB:01\":{\"type\":\"9\",\"defaultType\":\"9\","
	    "\"name\":\"GT-AX11000\",\"nickName\":\"\",\"ip\":\"192.168.50.1\"") != NULL);
	assert(strstr(buffer, "\"isGateway\":\"1\",\"isASUS\":\"1\",\"isWebServer\":\"1\"") != NULL);
	assert(strstr(buffer, "\"name\":\"Paul s Phone \",\"nickName\":\"Pauls iPhone\"") != NULL);
	assert(strstr(buffer, "\"AA:BB:CC:DD:EE:02\":{\"type\":\"5\",\"defaultType\":\"2\"") != NULL);
	assert(strstr(buffer, "\"rssi\":\"-47\"") != NULL);
	assert(strstr(buffer, "\"qosLevel\":\"2\",\"wtfast\":\"1\"") != NULL);
	assert(strstr(buffer, "\"AA:BB:CC:DD:EE:03\":{\"type\":\"36\",\"defaultType\":\"36\"") != NULL);
	assert(strstr(buffer, "\"ipMethod\":\"OffLine\",\"ROG\":\"1\"") != NULL);
	assert(strstr(buffer, "\"internetMode\":\"block\",\"internetState\":0") != NULL);
	assert(strstr(buffer, "\"vendor\":\"VVVVVVVV") != NULL);
	assert(strstr(buffer, "AA:BB:CC:DD:EE:F1") == NULL);
	assert(strstr(buffer, "\"maclist\":[\"04:D4:C4:AA:BB:01\",\"AA:BB:CC:DD:EE:02\"],"
	    "\"ClientAPILevel\":\"7\"}") != NULL);
	assert(buffer[0] == '{' && buffer[length - 1] == '}');
	/* The vendor lock file is truncated again after the copy. */
	assert(stat(lock_probe, &status) == 0 && status.st_size == 0);

	/* Fail-closed paths: NULL buffer, small buffer, wrong model, wrong size,
	 * no segment. */
	assert(rust_httpd_clientlist_render(&inputs, NULL, sizeof(buffer)) ==
	    CLIENTLIST_INVALID);
	assert(rust_httpd_clientlist_render(NULL, buffer, sizeof(buffer)) ==
	    CLIENTLIST_INVALID);
	assert(rust_httpd_clientlist_render(&inputs, buffer, 100) ==
	    CLIENTLIST_OVERFLOW);
	inputs.productid = "RT-AX88U";
	assert(rust_httpd_clientlist_render(&inputs, buffer, sizeof(buffer)) ==
	    CLIENTLIST_UNSUPPORTED_LAYOUT);
	inputs.productid = "GT-AX11000";
	inputs.shm_key = (int)key + 1;
	assert(rust_httpd_clientlist_render(&inputs, buffer, sizeof(buffer)) ==
	    CLIENTLIST_UNSUPPORTED_LAYOUT);
	inputs.shm_key = (int)key + 2;
	assert(rust_httpd_clientlist_render(&inputs, buffer, sizeof(buffer)) ==
	    CLIENTLIST_NO_SEGMENT);
	inputs.shm_key = (int)key;

	/* Cache write/read and the name lookup over the document. */
	{
		char hostile[700], target[700];
		snprintf(hostile, sizeof(hostile), "%s.%ld.0.tmp", cache_path, (long)getpid());
		snprintf(target, sizeof(target), "%s/untouched", scratch);
		write_file(target, "untouched");
		assert(symlink(target, hostile) == 0);
		assert(rust_httpd_clientlist_cache_write(cache_path, buffer, (size_t)length) == -7);
		assert(lstat(hostile, &status) == 0 && S_ISLNK(status.st_mode));
		assert(stat(target, &status) == 0 && status.st_size == 9);
		assert(unlink(hostile) == 0 && unlink(target) == 0);
		assert(mkfifo(hostile, 0600) == 0);
		assert(rust_httpd_clientlist_cache_read(hostile, copy, sizeof(copy)) < 0);
		assert(unlink(hostile) == 0);
	}
	assert(rust_httpd_clientlist_cache_write(cache_path, buffer,
	    (size_t)length) == 0);
	assert(stat(cache_path, &status) == 0 &&
	    (status.st_mode & 0777) == 0644);
	copied = rust_httpd_clientlist_cache_read(cache_path, copy, sizeof(copy));
	assert(copied == length && memcmp(copy, buffer, (size_t)length) == 0);
	assert(rust_httpd_clientlist_cache_read(cache_path, copy, 16) ==
	    CLIENTLIST_OVERFLOW);
	assert(rust_httpd_clientlist_cache_write(cache_path,
	    "{\"maclist\": [], \"ClientAPILevel\":\"7\"}", 38) ==
	    CLIENTLIST_CACHE_REJECTED);
	assert(rust_httpd_clientlist_name_for_ip(buffer, (size_t)length,
	    "192.168.50.20", name, sizeof(name)) == 1);
	assert(strcmp(name, "Pauls i") == 0);
	assert(rust_httpd_clientlist_name_for_ip(buffer, (size_t)length,
	    "192.168.50.30", name, sizeof(name)) == 1);
	assert(strcmp(name, "Xbox") == 0);
	assert(rust_httpd_clientlist_name_for_ip(buffer, (size_t)length,
	    "10.9.9.9", name, sizeof(name)) == 0);
	assert(name[0] == '\0');
	assert(rust_httpd_clientlist_sdn_client_count(sdn_document,
	    strlen(sdn_document), counts, 4) == 0);
	assert(counts[1] == 1);

	/* Basic lists over the live segment. */
	length = rust_httpd_clientlist_basic_render(&inputs, 1, NULL, 2, buffer,
	    sizeof(buffer));
	assert(length > 0 && strcmp(buffer, "{\"wireless\":\"2\", \"wire\":\"1\"}") == 0);
	length = rust_httpd_clientlist_basic_render(&inputs, 1, NULL, 0, buffer,
	    sizeof(buffer));
	assert(length > 0 && strcmp(buffer, "[[\"04:D4:C4:AA:BB:01\",\"GT-AX11000\"]]") == 0);
	length = rust_httpd_clientlist_basic_render(&inputs, 0, NULL, 1, buffer,
	    sizeof(buffer));
	assert(length == 2 && strcmp(buffer, "[]") == 0);
	assert(rust_httpd_clientlist_basic_render(&inputs, 1, NULL, 4, buffer,
	    sizeof(buffer)) == CLIENTLIST_INVALID);

	/* Persistent database views. */
	write_file(db_path,
	    "{\"AA:BB:CC:DD:EE:01\":{\"name\":\"Phone\",\"type\":2,\"online\":1},"
	    "\"AA:BB:CC:DD:EE:F1\":{\"name\":\"RE\"},"
	    "\"AA:BB:CC:DD:EE:03\":{\"name\":\"Xbox\",\"type\":1}}");
	memset(&db_inputs, 0, sizeof(db_inputs));
	db_inputs.db_path = db_path;
	db_inputs.rog_clientlist = "<AA:BB:CC:DD:EE:03";
	db_inputs.custom_clientlist = "<Printer>AA:BB:CC:DD:EE:09>0>0>0>0";
	db_inputs.amas_node_types = "AA:BB:CC:DD:EE:01>RE";
	db_inputs.is_re_node = is_re_node_f1;
	length = rust_httpd_clientlist_database_render(&db_inputs, buffer,
	    sizeof(buffer));
	assert(length > 0);
	assert(strcmp(buffer,
	    "{\"AA:BB:CC:DD:EE:01\":{\"name\":\"Phone\",\"type\":\"2\",\"online\":\"1\","
	    "\"nickName\":\"\",\"defaultType\":\"2\",\"from\":\"nmpClient\",\"ROG\":\"0\","
	    "\"amesh_isRe\":\"1\",\"amesh_bind_mac\":\"\",\"amesh_bind_band\":\"0\"},"
	    "\"AA:BB:CC:DD:EE:F1\":{\"name\":\"RE\"},"
	    "\"AA:BB:CC:DD:EE:03\":{\"name\":\"Xbox\",\"type\":\"36\",\"nickName\":\"\","
	    "\"defaultType\":\"36\",\"from\":\"nmpClient\",\"ROG\":\"1\","
	    "\"amesh_bind_mac\":\"\",\"amesh_bind_band\":\"0\"},"
	    "\"AA:BB:CC:DD:EE:09\":{\"type\":\"0\",\"mac\":\"AA:BB:CC:DD:EE:09\","
	    "\"name\":\"AA:BB:CC:DD:EE:09\",\"vendor\":\"\",\"nickName\":\"Printer\","
	    "\"defaultType\":\"0\",\"from\":\"customList\"},"
	    "\"maclist\":[\"AA:BB:CC:DD:EE:01\",\"AA:BB:CC:DD:EE:03\",\"AA:BB:CC:DD:EE:09\"],"
	    "\"ClientAPILevel\":\"7\"}") == 0);
	length = rust_httpd_clientlist_all_basic_render(db_path,
	    db_inputs.custom_clientlist, buffer, sizeof(buffer));
	assert(length > 0 && strcmp(buffer,
	    "[[\"AA:BB:CC:DD:EE:01\",\"Phone\"],[\"AA:BB:CC:DD:EE:F1\",\"RE\"],"
	    "[\"AA:BB:CC:DD:EE:03\",\"Xbox\"]]") == 0);
	/* opt 3 skips DB records that are currently wireless clients. */
	length = rust_httpd_clientlist_basic_render(&inputs, 1, db_path, 3,
	    buffer, sizeof(buffer));
	assert(length > 0 && strcmp(buffer,
	    "[[\"AA:BB:CC:DD:EE:01\",\"Phone\"],[\"AA:BB:CC:DD:EE:F1\",\"RE\"]]") == 0);
	length = rust_httpd_clientlist_search_name(db_path, "", "xbox", buffer,
	    sizeof(buffer));
	assert(length == 1 && strcmp(buffer, "AA:BB:CC:DD:EE:03\n") == 0);
	length = rust_httpd_clientlist_search_name(db_path, "", "nobody", buffer,
	    sizeof(buffer));
	assert(length == 0 && buffer[0] == '\0');
	/* A missing database is reported, never invented. */
	db_inputs.db_path = lock_probe;
	length = rust_httpd_clientlist_database_render(&db_inputs, buffer,
	    sizeof(buffer));
	assert(length > 0 && strcmp(buffer,
	    "{\"maclist\":[],\"ClientAPILevel\":\"7\"}") == 0);
	assert(rust_httpd_clientlist_all_basic_render(lock_probe, "", buffer,
	    sizeof(buffer)) < 0);

	assert(shmctl(legacy_id, IPC_RMID, NULL) == 0);
	assert(shmctl(small_id, IPC_RMID, NULL) == 0);
	assert(unlink(cache_path) == 0);
	assert(unlink(db_path) == 0);
	(void)unlink(lock_probe);
	(void)rmdir(scratch);
	printf("clientlist C ABI fixture passed\n");
	return 0;
}
