/* GT-AX11000 zlib-static C ABI fixture: the exact call pattern of the vendor
 * wget (retr.c streaming inflate, warc.c gzdopen/gzwrite/gzclose) against the
 * zlib-rs archive, compiled with strict C11 flags. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zlib.h"

static const char message[] =
	"GT-AX11000 zlib-static fixture: streaming inflate and gz output";

static int fail(const char *what, int code)
{
	fprintf(stderr, "zlib fixture: %s (%d)\n", what, code);
	return 1;
}

int main(void)
{
	char path[] = "/tmp/gtax-zlib-fixture-XXXXXX";
	unsigned char raw[512];
	unsigned char out[512];
	z_stream stream;
	gzFile gz;
	FILE *file;
	size_t raw_size;
	int fd;
	int rc;

	if (strncmp(zlibVersion(), "1.3.0-zlib-rs-", 14) != 0)
		return fail("unexpected zlibVersion", 0);

	fd = mkstemp(path);
	if (fd < 0)
		return fail("mkstemp", fd);
	gz = gzdopen(fd, "wb9");
	if (gz == NULL)
		return fail("gzdopen", 0);
	rc = gzwrite(gz, message, (unsigned)sizeof message);
	if (rc != (int)sizeof message)
		return fail("gzwrite", rc);
	rc = gzclose(gz);
	if (rc != Z_OK)
		return fail("gzclose", rc);

	file = fopen(path, "rb");
	if (file == NULL)
		return fail("fopen", 0);
	raw_size = fread(raw, 1, sizeof raw, file);
	fclose(file);
	unlink(path);
	if (raw_size < 18 || raw[0] != 0x1f || raw[1] != 0x8b)
		return fail("gzip magic", (int)raw_size);

	memset(&stream, 0, sizeof stream);
	rc = inflateInit2(&stream, 16 + MAX_WBITS);
	if (rc != Z_OK)
		return fail("inflateInit2", rc);
	/* Feed one byte at a time, as a slow HTTP body would arrive. */
	for (size_t i = 0; i < raw_size; i++) {
		stream.next_in = raw + i;
		stream.avail_in = 1;
		stream.next_out = out + stream.total_out;
		stream.avail_out = (uInt)(sizeof out - stream.total_out);
		rc = inflate(&stream, Z_NO_FLUSH);
		if (rc != Z_OK && rc != Z_STREAM_END)
			return fail("inflate", rc);
	}
	if (rc != Z_STREAM_END)
		return fail("inflate did not finish", rc);
	if (stream.total_out != sizeof message ||
	    memcmp(out, message, sizeof message) != 0)
		return fail("payload mismatch", (int)stream.total_out);
	rc = inflateEnd(&stream);
	if (rc != Z_OK)
		return fail("inflateEnd", rc);

	if (crc32(0L, (const Bytef *)"hello", 5) != 0x3610a686UL)
		return fail("crc32", 0);
	if (gzdopen(-1, "wb") != NULL)
		return fail("gzdopen accepted an invalid descriptor", 0);

	printf("zlib fixture: %s OK (%zu gzip bytes)\n", zlibVersion(), raw_size);
	return 0;
}
