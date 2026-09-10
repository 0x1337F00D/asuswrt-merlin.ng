/* The runner inserts the actual patched ABI and reader, not copies. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

/* INSERT_ACTUAL_HTTP_REQUEST_ABI */
/* INSERT_ACTUAL_HTTP_REQUEST_READER */

struct input {
    const unsigned char *bytes;
    size_t length;
    size_t position;
    int end_error;
};

static ssize_t input_read(void *opaque, char *buffer, size_t capacity)
{
    struct input *input = opaque;
    size_t count = input->length - input->position;
    if (count == 0) {
        if (input->end_error) {
            errno = input->end_error;
            return -1;
        }
        return 0;
    }
    if (count > capacity)
        count = capacity;
    memcpy(buffer, input->bytes + input->position, count);
    input->position += count;
    return (ssize_t)count;
}

static FILE *input_open(struct input *input)
{
    cookie_io_functions_t functions = { .read = input_read };
    FILE *stream = fopencookie(input, "r", functions);
    assert(stream != NULL);
    return stream;
}

static void incomplete_input_never_publishes_a_block(void)
{
    static const unsigned char complete[] =
        "GET /apply.cgi HTTP/1.1\r\nHost: router\r\n\r\n";
    char block[RUST_HTTPD_REQUEST_BLOCK_MAX];
    for (size_t prefix = 0; prefix < sizeof(complete) - 1; ++prefix) {
        for (int failure = 0; failure < 2; ++failure) {
            struct input input = { complete, prefix, 0, failure ? EIO : 0 };
            FILE *stream = input_open(&input);
            size_t length = (size_t)-1;
            enum request_read_result result =
                read_request_block(stream, block, sizeof(block), &length);
            assert(result == (failure ? REQUEST_READ_IO_ERROR :
                prefix == 0 ? REQUEST_READ_EMPTY : REQUEST_READ_INCOMPLETE));
            assert(length == 0);
            assert(!!ferror(stream) == failure);
            fclose(stream);
        }
    }
}

static void complete_headers_leave_binary_body_in_the_stream(void)
{
    static const unsigned char crlf[] =
        "POST /upload HTTP/1.1\r\nContent-Length: 5\r\n\r\n\0BODY";
    static const unsigned char lf[] =
        "POST /upload HTTP/1.0\nContent-Length: 5\n\n\0BODY";
    const unsigned char *cases[] = { crlf, lf };
    const size_t sizes[] = { sizeof(crlf) - 1, sizeof(lf) - 1 };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        struct input input = { cases[i], sizes[i], 0, EIO };
        FILE *stream = input_open(&input);
        char block[RUST_HTTPD_REQUEST_BLOCK_MAX];
        size_t length = 0;
        rust_httpd_request_t request;
        assert(read_request_block(stream, block, sizeof(block), &length) == REQUEST_READ_COMPLETE);
        assert(length == sizes[i] - 5);
        assert(memcmp(block, cases[i], length) == 0);
        assert(rust_httpd_request_parse(block, length, &request, sizeof(request)) == RUST_HTTPD_PARSE_OK);
        assert(request.content_length == 5);
        unsigned char body[5];
        assert(fread(body, 1, sizeof(body), stream) == sizeof(body));
        assert(memcmp(body, "\0BODY", 5) == 0);
        fclose(stream);
    }
}

static void capacity_is_checked_without_publishing_a_partial_block(void)
{
    static const unsigned char complete[] = "GET / HTTP/1.1\r\n\r\n";
    for (size_t capacity = 0; capacity <= sizeof(complete) - 1; ++capacity) {
        struct input input = { complete, sizeof(complete) - 1, 0, 0 };
        FILE *stream = input_open(&input);
        unsigned char block[sizeof(complete) + 8];
        memset(block, 0xa5, sizeof(block));
        size_t length = 99;
        enum request_read_result result =
            read_request_block(stream, (char *)block, capacity, &length);
        if (capacity == sizeof(complete) - 1) {
            assert(result == REQUEST_READ_COMPLETE);
            assert(length == capacity);
        } else {
            assert(result == REQUEST_READ_TOO_LARGE);
            assert(length == 0);
        }
        for (size_t i = capacity; i < sizeof(block); ++i)
            assert(block[i] == 0xa5);
        fclose(stream);
    }
}

static void complete_transport_does_not_override_parser_validation(void)
{
    static const unsigned char nul[] = "GET / HTTP/1.1\r\nHost: a\0b\r\n\r\n";
    struct input input = { nul, sizeof(nul) - 1, 0, 0 };
    FILE *stream = input_open(&input);
    char block[RUST_HTTPD_REQUEST_BLOCK_MAX];
    size_t length = 0;
    rust_httpd_request_t request;
    assert(read_request_block(stream, block, sizeof(block), &length) == REQUEST_READ_COMPLETE);
    assert(rust_httpd_request_parse(block, length, &request, sizeof(request)) == RUST_HTTPD_ERR_EMBEDDED_NUL);
    fclose(stream);
}

int main(void)
{
    assert(rust_httpd_request_struct_size() == sizeof(rust_httpd_request_t));
    incomplete_input_never_publishes_a_block();
    complete_headers_leave_binary_body_in_the_stream();
    capacity_is_checked_without_publishing_a_partial_block();
    complete_transport_does_not_override_parser_validation();
    puts("httpd actual reader+parser: EOF/EIO, body boundary, capacity and ABI passed");
    return 0;
}
