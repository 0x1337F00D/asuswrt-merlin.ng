#include <assert.h>
#include <stdint.h>
#include <string.h>
#ifdef V4_PROVIDER
void retrieve_static_maclist_from_nvram(int idx, int vidx, void *buffer, int size)
{
    assert(idx >= 0 && idx <= 2);
    assert(vidx == 0);
    assert(size == 4096);
    memset(buffer, 0x5a, (size_t)size);
    *(uint32_t *)buffer = 37;
}
#else
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
extern void retrieve_static_maclist_from_nvram(int, void *, int);
int main(void)
{
    uint32_t buffer[1026];
    struct rlimit limit = {0, 0};
    assert(setrlimit(RLIMIT_CORE, &limit) == 0);
    for (int idx = 0; idx < 3; idx++) {
        memset(buffer, 0xa5, sizeof(buffer));
        retrieve_static_maclist_from_nvram(idx, buffer+1, 4096);
        assert(buffer[0] == UINT32_C(0xa5a5a5a5));
        assert(buffer[1] == 37);
        assert(buffer[1024] == UINT32_C(0x5a5a5a5a));
        assert(buffer[1025] == UINT32_C(0xa5a5a5a5));
    }
    for (int bad = 0; bad < 5; bad++) {
        int status;
        pid_t pid = fork();
        assert(pid >= 0);
        if (!pid) {
            retrieve_static_maclist_from_nvram(bad == 0 ? -1 : bad == 1 ? 3 : 0,
                bad == 2 ? NULL : bad == 3 ? (void *)((char *)buffer+1) : (void *)buffer,
                bad == 4 ? 4095 : 4096);
            _exit(99);
        }
        assert(waitpid(pid, &status, 0) == pid);
        assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    }
    puts("MACLIST_ADAPTER_ABI=PASS radios=3 canaries=preserved rejected_inputs=5");
    return 0;
}
#endif
