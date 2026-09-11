/* PID 1 for the isolated virt kernel probe; not a router init replacement. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void check(int ok, const char *name) {
    if (!ok) { printf("LAB_FAIL %s errno=%d\n", name, errno); fflush(stdout); reboot(RB_POWER_OFF); _exit(1); }
    printf("LAB_PASS %s\n", name); fflush(stdout);
}

/* Real image daemon over real guest-kernel sockets, with no host networking. */
static void wsdd_ipv6(void) {
    char probe[2048], response[20000], invalid[8193], *message_id;
    struct sockaddr_in6 destination, source;
    struct timeval timeout = {0, 200000};
    socklen_t source_size;
    FILE *input = fopen("/wsd-probe.xml", "rb");
    size_t length;
    int fd, status, attempt, round, answered;
    pid_t daemon;
    check(input != NULL, "ipv6-probe-open");
    length = fread(probe, 1, sizeof(probe), input); fclose(input);
    check(length > 0 && length < sizeof(probe), "ipv6-probe-size");
    message_id = memmem(probe, length, "11112222-3333-4444-5555-666677778888", 36);
    check(message_id != NULL, "ipv6-probe-correlation");
    fd = socket(AF_INET6, SOCK_DGRAM, 0); check(fd >= 0, "ipv6-peer-socket");
    check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), "ipv6-peer-timeout");
    memset(&destination, 0, sizeof(destination)); destination.sin6_family = AF_INET6;
    destination.sin6_port = htons(3702);
    check(inet_pton(AF_INET6, "::1", &destination.sin6_addr) == 1, "ipv6-address");
    daemon = fork();
    if (!daemon) { execl("/bin/wsdd2", "wsdd2", "-w", "-6", "-i", "lo", (char *)NULL); _exit(98); }
    check(daemon > 0, "ipv6-daemon-start");
    for (round = 0; round < 2; round++) {
        message_id[0] = '2' + round; /* A queued pre-reload reply cannot pass. */
        answered = 0;
        /* Bounded readiness/reload window; no widening of service timeouts. */
        for (attempt = 0; attempt < 10; attempt++) {
            ssize_t received;
            check(waitpid(daemon, &status, WNOHANG) == 0, "ipv6-daemon-alive");
            check(sendto(fd, probe, length, 0, (void *)&destination, sizeof(destination)) == (ssize_t)length,
                  "ipv6-probe-send");
            source_size = sizeof(source);
            received = recvfrom(fd, response, sizeof(response), 0, (void *)&source, &source_size);
            if (received > 0 && memmem(response, received, "ProbeMatches", 12) != NULL
                && memmem(response, received, message_id, 36) != NULL
                && source.sin6_port == htons(3702)) { answered = 1; break; }
            usleep(50000);
        }
        check(answered, round ? "ipv6-after-reload" : "ipv6-before-malformed");
        if (!round) {
            static const size_t sizes[] = {0, 1, 512, 8192, 8193};
            unsigned int i, j;
            memset(invalid, 0xff, sizeof(invalid));
            for (i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++)
                for (j = 0; j < 50; j++)
                    if (sendto(fd, invalid, sizes[i], 0, (void *)&destination, sizeof(destination))
                        != (ssize_t)sizes[i]) check(0, "ipv6-malformed-send");
            check(1, "ipv6-250-malformed-sent");
            usleep(200000);
            check(!kill(daemon, SIGHUP), "ipv6-reload-signal");
            usleep(100000);
        }
    }
    close(fd);
    check(!kill(daemon, SIGTERM), "ipv6-terminate");
    for (attempt = 0; attempt < 30; attempt++) {
        if (waitpid(daemon, &status, WNOHANG) == daemon) {
            check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "ipv6-clean-exit");
            return;
        }
        usleep(100000);
    }
    kill(daemon, SIGKILL); waitpid(daemon, &status, 0);
    check(0, "ipv6-shutdown-timeout");
}
int main(void) {
    struct utsname info;
    struct timeval wanted = {0, 200000}, actual = {0, 0};
    socklen_t size = sizeof(actual);
    struct ifreq iface;
    int fd, pair[2], status;
    pid_t child;
    setbuf(stdout, NULL);
    check(getpid() == 1, "pid1");
    check(!mount("proc", "/proc", "proc", 0, NULL), "proc");
    check(!mount("sysfs", "/sys", "sysfs", 0, NULL), "sysfs");
    check(!sethostname("qemu-lab", 8), "hostname");
    check(!uname(&info), "uname");
    printf("LAB_KERNEL %s %s\n", info.release, info.machine);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    check(fd >= 0, "socket");
    memset(&iface, 0, sizeof(iface)); strcpy(iface.ifr_name, "lo");
    iface.ifr_flags = IFF_UP | IFF_LOOPBACK;
    check(!ioctl(fd, SIOCSIFFLAGS, &iface), "loopback-up");
    check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wanted, sizeof(wanted)), "set-timeout");
    check(!getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &actual, &size) && size == sizeof(actual)
          && actual.tv_sec == 0 && actual.tv_usec >= 200000 && actual.tv_usec <= 250000,
          "real-kernel-timeout-abi");
    close(fd);
    check(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair), "socketpair");
    check(write(pair[0], "abc", 3) == 3, "socket-write");
    { char buf[4]; check(read(pair[1], buf, 3) == 3 && !memcmp(buf, "abc", 3), "socket-read"); }
    close(pair[0]); close(pair[1]);
    child = fork(); check(child >= 0, "fork");
    if (!child) { raise(SIGSEGV); _exit(99); }
    check(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV,
          "intentional-child-segv-detected");
    {
        FILE *modules = fopen("/modules.list", "r");
        char path[256];
        check(modules != NULL, "module-list");
        while (fgets(path, sizeof(path), modules)) {
            struct stat st;
            void *bytes;
            FILE *module;
            path[strcspn(path, "\n")] = 0;
            check(!stat(path, &st) && st.st_size > 0 && st.st_size < 16*1024*1024, "module-size");
            module = fopen(path, "rb"); check(module != NULL, "module-open");
            bytes = malloc(st.st_size); check(bytes != NULL, "module-memory");
            check(fread(bytes, 1, st.st_size, module) == (size_t)st.st_size, "module-read");
            fclose(module);
            printf("LAB_MODULE %s\n", path);
            check(syscall(SYS_init_module, bytes, st.st_size, "") == 0, "module-load");
            free(bytes);
        }
        fclose(modules);
    }
    check(access("/sys/class/ieee80211/phy0", F_OK) == 0, "hwsim-phy0-present");
    check(access("/sys/class/ieee80211/phy1", F_OK) == 0, "hwsim-phy1-present");
    {
        const char *programs[] = {"/bin/wsdd2", "/bin/ntp", "/bin/lld2d"};
        unsigned int i;
        for (i = 0; i < sizeof(programs)/sizeof(programs[0]); i++) {
            child = fork(); check(child >= 0, "firmware-fork");
            if (!child) {
                alarm(10);
                execl(programs[i], programs[i], "--self-test", (char *)NULL);
                _exit(98);
            }
            printf("LAB_FIRMWARE %s\n", programs[i]);
            check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                  "firmware-arm-self-test");
        }
    }
    wsdd_ipv6();
    puts("LAB_COMPLETE PASS"); fflush(stdout);
    sync(); reboot(RB_POWER_OFF);
    return 1;
}
