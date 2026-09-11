#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
extern int mssl_init(char *, char *);
extern void mssl_ctx_free(void);
extern FILE *ssl_server_fopen(int);
int main(int argc, char **argv) {
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    char line[256];
    FILE *stream;
    int listener, fd;
    alarm(10);
    if ((argc != 3 && argc != 4) || !mssl_init(argv[1], argv[2])) return 2;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 1)) return 3;
    if (getsockname(listener, (struct sockaddr *)&address, &length)) return 4;
    printf("%u\n", (unsigned)ntohs(address.sin_port));
    fflush(stdout);
    fd = accept(listener, NULL, NULL);
    if (fd < 0) return 10;
    if (argc == 4) {
        struct timeval deadline = {0, 200000};
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) ||
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline))) return 11;
        {
            struct timeval observed = {0, 0};
            socklen_t observed_size = sizeof(observed);
            if (getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &observed, &observed_size)) return 14;
            fprintf(stderr, "TIMEOUT_ABI size=%u sec=%ld usec=%ld\n",
                    (unsigned)observed_size, (long)observed.tv_sec, (long)observed.tv_usec);
            if (observed_size != sizeof(observed) || observed.tv_sec != 0 || observed.tv_usec != 200000) return 15;
        }
        stream = ssl_server_fopen(fd);
        if (stream) { fclose(stream); return 12; }
        mssl_ctx_free();
        if (close(fd) || close(listener)) return 13;
        return 0;
    }
    stream = ssl_server_fopen(fd);
    if (!stream) return 5;
    mssl_ctx_free();
    if (!fgets(line, sizeof(line), stream) || strcmp(line, "GET / HTTP/1.0\r\n")) return 6;
    if (!fgets(line, sizeof(line), stream) || strcmp(line, "\r\n")) return 7;
    if (fputs("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK", stream) < 0 || fflush(stream)) return 8;
    if (fclose(stream) || close(fd) || close(listener)) return 9;
    return 0;
}
