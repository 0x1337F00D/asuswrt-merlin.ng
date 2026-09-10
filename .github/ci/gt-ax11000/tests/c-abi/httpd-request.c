/*
 * The request-line and header ABI httpd.c calls once per connection.
 * The struct below is the copy in release/src/router/httpd/httpd.h, so a
 * layout drift between the C header and httpd-parsers/src/request.rs fails
 * this fixture instead of corrupting a live request.
 */
#include <assert.h>
#include <stddef.h>
#include <string.h>

#define RUST_HTTPD_REQUEST_BLOCK_MAX		32768
#define RUST_HTTPD_TARGET_CAPACITY		4096
#define RUST_HTTPD_HOST_CAPACITY		512
#define RUST_HTTPD_USER_AGENT_CAPACITY		2048
#define RUST_HTTPD_COOKIE_CAPACITY		8192
#define RUST_HTTPD_REFERER_CAPACITY		1024
#define RUST_HTTPD_RANGE_CAPACITY		256
#define RUST_HTTPD_IF_NONE_MATCH_CAPACITY	512
#define RUST_HTTPD_BOUNDARY_CAPACITY		512
#define RUST_HTTPD_ACCEPT_LANGUAGE_CAPACITY	512

#define RUST_HTTPD_METHOD_GET			0
#define RUST_HTTPD_METHOD_POST			1
#define RUST_HTTPD_METHOD_HEAD			2
#define RUST_HTTPD_METHOD_OTHER			3

#define RUST_HTTPD_HAS_HOST			(1u << 0)
#define RUST_HTTPD_HAS_USER_AGENT		(1u << 1)
#define RUST_HTTPD_HAS_COOKIE			(1u << 2)
#define RUST_HTTPD_HAS_REFERER			(1u << 3)
#define RUST_HTTPD_HAS_RANGE			(1u << 4)
#define RUST_HTTPD_HAS_IF_NONE_MATCH		(1u << 5)
#define RUST_HTTPD_HAS_BOUNDARY			(1u << 6)
#define RUST_HTTPD_HAS_ACCEPT_LANGUAGE		(1u << 7)
#define RUST_HTTPD_HAS_CONTENT_LENGTH		(1u << 8)

#define RUST_HTTPD_PARSE_OK			0
#define RUST_HTTPD_ERR_INVALID_INPUT		-1
#define RUST_HTTPD_ERR_INCOMPLETE		-2
#define RUST_HTTPD_ERR_REQUEST_LINE		-3
#define RUST_HTTPD_ERR_HEADER			-4
#define RUST_HTTPD_ERR_TOO_LONG			-5
#define RUST_HTTPD_ERR_TOO_MANY_HEADERS		-6
#define RUST_HTTPD_ERR_EMBEDDED_NUL		-7
#define RUST_HTTPD_ERR_CONTENT_LENGTH		-8
#define RUST_HTTPD_ERR_FRAMING			-9
#define RUST_HTTPD_ERR_TARGET			-10

typedef struct rust_httpd_request {
	int method;
	int minor_version;
	unsigned int present;
	long content_length;
	size_t target_len;
	size_t query_offset;
	char target[RUST_HTTPD_TARGET_CAPACITY];
	char host[RUST_HTTPD_HOST_CAPACITY];
	char user_agent[RUST_HTTPD_USER_AGENT_CAPACITY];
	char cookie[RUST_HTTPD_COOKIE_CAPACITY];
	char referer[RUST_HTTPD_REFERER_CAPACITY];
	char range[RUST_HTTPD_RANGE_CAPACITY];
	char if_none_match[RUST_HTTPD_IF_NONE_MATCH_CAPACITY];
	char boundary[RUST_HTTPD_BOUNDARY_CAPACITY];
	char accept_language[RUST_HTTPD_ACCEPT_LANGUAGE_CAPACITY];
} rust_httpd_request_t;

extern int rust_httpd_request_parse(const char *block, size_t length,
    rust_httpd_request_t *output, size_t output_size);
extern size_t rust_httpd_request_struct_size(void);

static rust_httpd_request_t request;

static int parse(const char *block)
{
	return rust_httpd_request_parse(block, strlen(block), &request,
	    sizeof(request));
}

static void browser_get(void)
{
	assert(parse(
	    "GET /Main_Login.asp?flag=1 HTTP/1.1\r\n"
	    "Host: router.asus.com\r\n"
	    "User-Agent: Mozilla/5.0\r\n"
	    "Accept-Language: en-US,en;q=0.9\r\n"
	    "Cookie: asus_token=0123456789abcdef\r\n"
	    "Referer: http://router.asus.com/Main_Login.asp\r\n"
	    "If-None-Match: \"abc\"\r\n"
	    "Connection: keep-alive\r\n"
	    "\r\n") == RUST_HTTPD_PARSE_OK);
	assert(request.method == RUST_HTTPD_METHOD_GET);
	assert(request.minor_version == 1);
	assert(strcmp(request.target, "/Main_Login.asp?flag=1") == 0);
	assert(request.target_len == strlen("/Main_Login.asp?flag=1"));
	assert(request.query_offset == strlen("/Main_Login.asp"));
	assert(request.target[request.query_offset] == '?');
	assert(strcmp(request.host, "router.asus.com") == 0);
	assert(strcmp(request.user_agent, "Mozilla/5.0") == 0);
	assert(strcmp(request.cookie, "asus_token=0123456789abcdef") == 0);
	assert(strcmp(request.accept_language, "en-US,en;q=0.9") == 0);
	assert(strcmp(request.if_none_match, "\"abc\"") == 0);
	assert((request.present & RUST_HTTPD_HAS_CONTENT_LENGTH) == 0);
	assert((request.present & RUST_HTTPD_HAS_RANGE) == 0);
	assert((request.present & RUST_HTTPD_HAS_BOUNDARY) == 0);
	assert(request.content_length == 0);
}

static void multipart_upload(void)
{
	assert(parse(
	    "POST /upgrade.cgi HTTP/1.1\r\n"
	    "Content-Type: multipart/form-data; boundary=----AsusBoundary\r\n"
	    "Content-Length: 67108864\r\n"
	    "\r\n") == RUST_HTTPD_PARSE_OK);
	assert(request.method == RUST_HTTPD_METHOD_POST);
	assert(request.present & RUST_HTTPD_HAS_BOUNDARY);
	assert(strcmp(request.boundary, "----AsusBoundary") == 0);
	assert(request.present & RUST_HTTPD_HAS_CONTENT_LENGTH);
	assert(request.content_length == 67108864L);
	/* No query: the offset is one past the last target byte. */
	assert(request.query_offset == request.target_len);
}

static void head_and_unknown_methods(void)
{
	assert(parse("HEAD / HTTP/1.0\r\n\r\n") == RUST_HTTPD_PARSE_OK);
	assert(request.method == RUST_HTTPD_METHOD_HEAD);
	assert(request.minor_version == 0);
	/* The vendor answered 501, not 400, so this must still parse. */
	assert(parse("OPTIONS * HTTP/1.1\r\n\r\n") == RUST_HTTPD_ERR_TARGET);
	assert(parse("PROPFIND /a HTTP/1.1\r\n\r\n") == RUST_HTTPD_PARSE_OK);
	assert(request.method == RUST_HTTPD_METHOD_OTHER);
}

static void rejections(void)
{
	assert(parse("GET /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
	    == RUST_HTTPD_ERR_FRAMING);
	assert(parse("POST /a HTTP/1.1\r\nContent-Length: 1\r\n"
	    "Transfer-Encoding: identity\r\n\r\n") == RUST_HTTPD_ERR_FRAMING);
	assert(parse("POST /a HTTP/1.1\r\nContent-Length: 0x10\r\n\r\n")
	    == RUST_HTTPD_ERR_CONTENT_LENGTH);
	assert(parse("POST /a HTTP/1.1\r\nContent-Length: 1\r\n"
	    "Content-Length: 2\r\n\r\n") == RUST_HTTPD_ERR_CONTENT_LENGTH);
	assert(parse("GET /a HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n")
	    == RUST_HTTPD_ERR_HEADER);
	assert(parse("GET /a HTTP/1.1\r\nCookie: a\r\n b\r\n\r\n")
	    == RUST_HTTPD_ERR_HEADER);
	assert(parse("GET /a HTTP/1.1\r\nHost router\r\n\r\n")
	    == RUST_HTTPD_ERR_HEADER);
	assert(parse("GET /a HTTP/1.2\r\n\r\n") == RUST_HTTPD_ERR_REQUEST_LINE);
	assert(parse("GET  /a HTTP/1.1\r\n\r\n") == RUST_HTTPD_ERR_REQUEST_LINE);
	assert(parse("\r\n") == RUST_HTTPD_ERR_REQUEST_LINE);
	assert(parse("GET http://router/a HTTP/1.1\r\n\r\n")
	    == RUST_HTTPD_ERR_TARGET);
	assert(parse("GET /a HTTP/1.1\r\n") == RUST_HTTPD_ERR_INCOMPLETE);

	/* An embedded NUL cannot be expressed with strlen(); pass it by hand. */
	{
		static const char block[] =
		    "GET /a\0b HTTP/1.1\r\n\r\n";
		assert(rust_httpd_request_parse(block, sizeof(block) - 1,
		    &request, sizeof(request)) == RUST_HTTPD_ERR_EMBEDDED_NUL);
	}
}

static void fails_closed(void)
{
	assert(parse("GET /keepme HTTP/1.1\r\nCookie: keep\r\n\r\n")
	    == RUST_HTTPD_PARSE_OK);
	assert(parse("GET /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
	    == RUST_HTTPD_ERR_FRAMING);
	assert(request.method == 0);
	assert(request.present == 0);
	assert(request.content_length == 0);
	assert(request.target_len == 0);
	assert(request.target[0] == '\0');
	assert(request.cookie[0] == '\0');
}

static void abi_guards(void)
{
	assert(rust_httpd_request_struct_size() == sizeof(request));
	assert(rust_httpd_request_parse("GET / HTTP/1.1\r\n\r\n", 18, &request,
	    sizeof(request) - 1) == RUST_HTTPD_ERR_INVALID_INPUT);
	assert(rust_httpd_request_parse(NULL, 4, &request, sizeof(request))
	    == RUST_HTTPD_ERR_INVALID_INPUT);
	assert(rust_httpd_request_parse("GET / HTTP/1.1\r\n\r\n", 0, &request,
	    sizeof(request)) == RUST_HTTPD_ERR_INVALID_INPUT);
	assert(rust_httpd_request_parse("GET / HTTP/1.1\r\n\r\n",
	    (size_t) RUST_HTTPD_REQUEST_BLOCK_MAX + 1, &request,
	    sizeof(request)) == RUST_HTTPD_ERR_INVALID_INPUT);
	assert(rust_httpd_request_parse("GET / HTTP/1.1\r\n\r\n", 18, NULL,
	    sizeof(request)) == RUST_HTTPD_ERR_INVALID_INPUT);
}

int main(void)
{
	browser_get();
	multipart_upload();
	head_and_unknown_methods();
	rejections();
	fails_closed();
	abi_guards();
	return 0;
}
