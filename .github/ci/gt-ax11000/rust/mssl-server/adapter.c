/* glibc stdio glue for the server-only Rust TLS boundary.
 * httpd serialises these calls; FILE cookies are not shared between threads.
 * The socket is always owned by httpd, including failed handshakes and fclose.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>

struct rs_config;
extern struct rs_config *rs_mssl_config_new(const char *, const char *, const char *);
extern void rs_mssl_config_free(struct rs_config *);
extern int rs_mssl_key_match(const char *, const char *);
extern void *rs_mssl_accept(const struct rs_config *, int);
extern ssize_t rs_mssl_read(void *, unsigned char *, size_t);
extern ssize_t rs_mssl_write(void *, const unsigned char *, size_t);
extern void rs_mssl_close(void *);

static struct rs_config *config;

int mssl_init_ex(char *cert, char *key, char *ciphers)
{
    struct rs_config *next = rs_mssl_config_new(cert, key, ciphers);
    if (!next) return 0;
    rs_mssl_config_free(config);
    config = next;
    return 1;
}

int mssl_init(char *cert, char *key) { return mssl_init_ex(cert, key, NULL); }
void mssl_ctx_free(void) { rs_mssl_config_free(config); config = NULL; }
int mssl_cert_key_match(const char *cert, const char *key) { return rs_mssl_key_match(cert, key); }

static ssize_t read_cookie(void *cookie, char *bytes, size_t len)
{ return rs_mssl_read(cookie, (unsigned char *)bytes, len); }
static ssize_t write_cookie(void *cookie, const char *bytes, size_t len)
{
    ssize_t n = rs_mssl_write(cookie, (const unsigned char *)bytes, len);
    /* glibc cookie write reports errors as zero, not a negative count. */
    return n < 0 ? 0 : n;
}
static int seek_cookie(void *cookie, off64_t *offset, int whence)
{ (void)cookie; (void)offset; (void)whence; errno = ESPIPE; return -1; }
static int close_cookie(void *cookie) { rs_mssl_close(cookie); return 0; }

FILE *ssl_server_fopen(int fd)
{
    void *cookie;
    FILE *stream;
    cookie_io_functions_t io = { read_cookie, write_cookie, seek_cookie, close_cookie };
    if (!config) { errno = EINVAL; return NULL; }
    cookie = rs_mssl_accept(config, fd);
    if (!cookie) return NULL;
    stream = fopencookie(cookie, "r+", io);
    if (!stream) {
        int saved = errno;
        rs_mssl_close(cookie);
        errno = saved;
    }
    return stream;
}

FILE *ssl_client_fopen(int fd)
{ (void)fd; errno = ENOTSUP; return NULL; }
FILE *ssl_client_fopen_name(int fd, const char *name)
{ (void)name; return ssl_client_fopen(fd); }
