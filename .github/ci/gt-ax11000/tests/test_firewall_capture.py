#!/usr/bin/env python3
"""Compile the actual patched capture function with side-effect-free stubs.

No iptables commands are executed. All capture artifacts reside in /tmp.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

PREFIX = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static int use_v6, fail_capture, fail_create, valid_policy, captures;
static char captured_dir[256];
static const char *firewall_fail_wan_if = "eth0";
static const char *firewall_admin_ports = "22,443";
#ifdef RTCONFIG_IPV6
static int ipv6_enabled(void) { return use_v6; }
static const char *get_wan6face(void) { return "eth0"; }
#endif
static char *test_mkdtemp(char *path) {
    if (fail_create) { errno = ENOSPC; return NULL; }
    return mkdtemp(path);
}
#define mkdtemp test_mkdtemp
static int _eval(char **argv, const char *output, int ignored, void *unused) {
    struct stat st;
    char *slash;
    int fd;
    (void)ignored; (void)unused;
    assert(!strcmp(argv[0], "iptables-save") || !strcmp(argv[0], "ip6tables-save"));
    assert(output[0] == '>');
    assert(strlen(output + 1) < sizeof(captured_dir));
    strcpy(captured_dir, output + 1);
    slash = strrchr(captured_dir, '/'); assert(slash); *slash = 0;
    assert(strncmp(captured_dir, "/tmp/firewall-effective.", 24) == 0);
    assert(stat(captured_dir, &st) == 0);
    assert(S_ISDIR(st.st_mode) && (st.st_mode & 0777) == 0700);
    captures++;
    if (captures == fail_capture) return 1;
    fd = open(output + 1, O_CREAT | O_EXCL | O_WRONLY, 0644); assert(fd >= 0);
    assert(write(fd, "fixture", 7) == 7); assert(close(fd) == 0);
    return 0;
}
static int rust_validate_effective_firewall_policy_files(const char *v4,
    const char *v6, int required, const char *wan, const char *wan6, const char *ports) {
    struct stat st;
    (void)wan; (void)wan6; (void)ports;
    assert(stat(v4, &st) == 0 && (st.st_mode & 0777) == 0600);
    assert((v6 != NULL) == required);
    if (required) assert(stat(v6, &st) == 0 && (st.st_mode & 0777) == 0600);
    return valid_policy;
}
'''
SUFFIX = r'''
int main(void) {
    int v6, fault, expected, result;
    for (v6 = 0; v6 <= 1; v6++) for (fault = 0; fault <= 4; fault++) {
        use_v6 = v6; fail_capture = (fault == 1 || fault == 2) ? fault : 0;
        fail_create = fault == 3; valid_policy = fault != 4;
        captures = 0; captured_dir[0] = 0;
        expected = fault == 0;
#ifdef RTCONFIG_IPV6
        if (fault == 2 && !v6) expected = 1;
#else
        if (fault == 2) expected = 1;
#endif
        result = validate_effective_firewall_policy();
        assert(result == expected);
        if (captured_dir[0]) assert(access(captured_dir, F_OK) == -1 && errno == ENOENT);
    }
    puts("PRIVATE_FIREWALL_CAPTURE=PASS (success, capture failure, policy failure, ENOSPC, cleanup)");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    source = (args.source / "release/src/router/rc/firewall.c").read_text()
    start = source.index("static int validate_effective_firewall_policy(void)")
    end = source.index("static void firewall_enter_fail_closed(void)", start)
    with tempfile.TemporaryDirectory(prefix="firewall-capture-", dir="/tmp") as directory:
        root = Path(directory)
        cfile = root / "capture.c"
        cfile.write_text(PREFIX + source[start:end] + SUFFIX)
        for defines in ([], ["-DRTCONFIG_IPV6"]):
            binary = root / ("capture6" if defines else "capture4")
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", *defines, str(cfile), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=5)


if __name__ == "__main__":
    main()
