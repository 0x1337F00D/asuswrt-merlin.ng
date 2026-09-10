/* GT-AX11000 libz.so.1 C ABI fixture.  Unlike zlib.c, which links the static
 * zlib-rs archive the way wget does, this program is linked with -lz against
 * the zlib-rs *shared* object, exactly like rc, curl, libxml2, tor, minidlna
 * and every other firmware package that resolves libz.so.1 at run time.
 *
 * It exercises the streaming deflate/inflate pair, the one-shot
 * compress/uncompress pair, the checksums and the gz* file API.  Compiled
 * against the locked vendor zlib.h, so the call shapes and struct layouts are
 * the ones the firmware really uses. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zlib.h"

/* Declared by zlib.h only under _LARGEFILE64_SOURCE; the fixture calls
 * them directly to isolate a target-specific divergence. */
extern uLong crc32_combine_gen(z_off_t len2);
extern uLong crc32_combine_op(uLong crc1, uLong crc2, uLong op);
extern uLong crc32_combine64(uLong crc1, uLong crc2, z_off64_t len2);

#define PAYLOAD_LEN 40000u

static int fail(const char *what, long code)
{
	fprintf(stderr, "libz.so.1 fixture: %s (%ld)\n", what, code);
	return 1;
}

/* A wrong combine() is the kind of defect that only shows on the target, so
 * report the inputs, both results and the argument width rather than a bare
 * label, and name the shared object that actually answered the call. */
static int fail_combine(const char *what, uLong head, uLong tail,
	uLong got, uLong want)
{
	char line[512];
	FILE *maps;

	fprintf(stderr, "libz.so.1 fixture: %s head=%08lx tail=%08lx "
		"len=%u got=%08lx want=%08lx sizeof(z_off_t)=%u "
		"sizeof(uLong)=%u\n", what, (unsigned long)head,
		(unsigned long)tail, (unsigned)(PAYLOAD_LEN - 1777u),
		(unsigned long)got, (unsigned long)want,
		(unsigned)sizeof(z_off_t), (unsigned)sizeof(uLong));
	fprintf(stderr, "libz.so.1 fixture: zlibVersion=%s "
		"zlibCompileFlags=%08lx\n", zlibVersion(),
		(unsigned long)zlibCompileFlags());
	/* Decompose the computation so the target says which step diverges.
	 * On a 32-bit target crc32_combine and crc32_combine64 have different
	 * argument widths, which a host with 64-bit long cannot tell apart. */
	{
		uLong op = crc32_combine_gen((z_off_t)(PAYLOAD_LEN - 1777u));
		/* crc32_combine_op(crc1, crc2, op) is multmodp(op, crc1) ^ crc2,
		 * so passing op last reproduces crc32_combine step by step.
		 * op must never be zero: multmodp loops forever on a zero
		 * multiplier, which is documented in the zlib-rs source. */
		fprintf(stderr, "libz.so.1 fixture: gen=%08lx op(head,tail,gen)="
			"%08lx combine64=%08lx\n", (unsigned long)op,
			(unsigned long)(op == 0 ? 0
				: crc32_combine_op(head, tail, op)),
			(unsigned long)crc32_combine64(head, tail,
				(z_off64_t)(PAYLOAD_LEN - 1777u)));
	}
	maps = fopen("/proc/self/maps", "r");
	if (maps != NULL) {
		while (fgets(line, sizeof line, maps) != NULL) {
			if (strstr(line, "libz.so") != NULL)
				fputs(line, stderr);
		}
		fclose(maps);
	}

	return 1;
}

static void fill(unsigned char *buffer, unsigned length)
{
	for (unsigned i = 0; i < length; i++)
		buffer[i] = (unsigned char)((i * 7u) % 251u);
}

int main(void)
{
	static unsigned char body[PAYLOAD_LEN];
	/* zlib-rs returns a more conservative (larger) compressBound() than
	 * stock zlib -- about 9n/8 rather than n + n/4096 -- so size the
	 * staging buffer generously instead of assuming the vendor bound. */
	static unsigned char packed[2 * PAYLOAD_LEN + 4096];
	static unsigned char round[PAYLOAD_LEN + 16];
	char path[] = "/tmp/gtax-libz-shared-XXXXXX";
	z_stream stream;
	uLongf packed_len;
	uLongf round_len;
	uLong whole;
	uLong combined;
	uLong head_sum;
	uLong tail_sum;
	gzFile gz;
	int fd;
	int rc;

	fill(body, PAYLOAD_LEN);

	/* The replacement must identify itself as zlib-rs and keep the major
	 * version consumers compare against ZLIB_VERSION. */
	if (strncmp(zlibVersion(), "1.3.0-zlib-rs-", 14) != 0)
		return fail("unexpected zlibVersion", 0);
	if (zlibVersion()[0] != ZLIB_VERSION[0])
		return fail("major version mismatch with the vendor header", 0);

	/* Streaming deflate of a gzip member, fed in one shot. */
	memset(&stream, 0, sizeof stream);
	rc = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
			  16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
	if (rc != Z_OK)
		return fail("deflateInit2", rc);
	stream.next_in = body;
	stream.avail_in = PAYLOAD_LEN;
	stream.next_out = packed;
	stream.avail_out = (uInt)sizeof packed;
	rc = deflate(&stream, Z_FINISH);
	if (rc != Z_STREAM_END)
		return fail("deflate", rc);
	packed_len = stream.total_out;
	if (deflateEnd(&stream) != Z_OK)
		return fail("deflateEnd", 0);
	if (packed_len >= PAYLOAD_LEN)
		return fail("gzip member did not compress", (long)packed_len);
	if (packed[0] != 0x1f || packed[1] != 0x8b)
		return fail("gzip magic", 0);

	/* Streaming inflate, one byte at a time, as a slow HTTP body arrives. */
	memset(&stream, 0, sizeof stream);
	rc = inflateInit2(&stream, 16 + MAX_WBITS);
	if (rc != Z_OK)
		return fail("inflateInit2", rc);
	for (uLongf i = 0; i < packed_len; i++) {
		stream.next_in = packed + i;
		stream.avail_in = 1;
		stream.next_out = round + stream.total_out;
		stream.avail_out = (uInt)(sizeof round - stream.total_out);
		rc = inflate(&stream, Z_NO_FLUSH);
		if (rc != Z_OK && rc != Z_STREAM_END)
			return fail("inflate", rc);
	}
	if (rc != Z_STREAM_END)
		return fail("inflate did not finish", rc);
	if (stream.total_out != PAYLOAD_LEN ||
	    memcmp(round, body, PAYLOAD_LEN) != 0)
		return fail("streaming payload mismatch", (long)stream.total_out);
	if (inflateEnd(&stream) != Z_OK)
		return fail("inflateEnd", 0);

	/* One-shot compress/uncompress, the shape libpng and tor use. */
	packed_len = compressBound(PAYLOAD_LEN);
	if (packed_len > sizeof packed)
		return fail("compressBound too large", (long)packed_len);
	rc = compress(packed, &packed_len, body, PAYLOAD_LEN);
	if (rc != Z_OK)
		return fail("compress", rc);
	round_len = sizeof round;
	rc = uncompress(round, &round_len, packed, packed_len);
	if (rc != Z_OK)
		return fail("uncompress", rc);
	if (round_len != PAYLOAD_LEN || memcmp(round, body, PAYLOAD_LEN) != 0)
		return fail("one-shot payload mismatch", (long)round_len);
	round_len = 8;
	if (uncompress(round, &round_len, packed, packed_len) != Z_BUF_ERROR)
		return fail("short uncompress buffer must fail closed", 0);

	/* Checksums, including the combine() helpers behind ZLIB_1.2.2. */
	if (crc32(0, (const Bytef *)"123456789", 9) != 0xcbf43926UL)
		return fail("crc32 check value", 0);
	if (adler32(1, (const Bytef *)"123456789", 9) != 0x091e01deUL)
		return fail("adler32 check value", 0);
	whole = crc32(0, body, PAYLOAD_LEN);
	head_sum = crc32(0, body, 1777);
	tail_sum = crc32(0, body + 1777, PAYLOAD_LEN - 1777);
	combined = crc32_combine(head_sum, tail_sum,
		(z_off_t)(PAYLOAD_LEN - 1777));
	if (combined != whole)
		return fail_combine("crc32_combine", head_sum, tail_sum,
			combined, whole);
	whole = adler32(1, body, PAYLOAD_LEN);
	head_sum = adler32(1, body, 1777);
	tail_sum = adler32(1, body + 1777, PAYLOAD_LEN - 1777);
	combined = adler32_combine(head_sum, tail_sum,
		(z_off_t)(PAYLOAD_LEN - 1777));
	if (combined != whole)
		return fail_combine("adler32_combine", head_sum, tail_sum,
			combined, whole);

	/* gz* file API: write through a descriptor, read back through a path. */
	fd = mkstemp(path);
	if (fd < 0)
		return fail("mkstemp", fd);
	gz = gzdopen(fd, "wb6");
	if (gz == NULL)
		return fail("gzdopen", 0);
	if (gzbuffer(gz, 8192) != Z_OK)
		return fail("gzbuffer", 0);
	if (gzwrite(gz, body, PAYLOAD_LEN) != (int)PAYLOAD_LEN)
		return fail("gzwrite", 0);
	rc = gzclose_w(gz);
	if (rc != Z_OK)
		return fail("gzclose_w", rc);

	gz = gzopen(path, "rb");
	if (gz == NULL)
		return fail("gzopen", 0);
	if (gzdirect(gz) != 0)
		return fail("gzdirect must report a real gzip member", 0);
	memset(round, 0, sizeof round);
	if (gzfread(round, 1, PAYLOAD_LEN, gz) != PAYLOAD_LEN)
		return fail("gzfread", 0);
	if (memcmp(round, body, PAYLOAD_LEN) != 0)
		return fail("gz payload mismatch", 0);
	if (gzread(gz, round, 4) != 0 || gzeof(gz) != 1)
		return fail("gzeof", 0);
	if (gzrewind(gz) != Z_OK || gztell(gz) != 0)
		return fail("gzrewind", 0);
	if (gzgetc(gz) != (int)body[0])
		return fail("gzgetc", 0);
	rc = gzclose_r(gz);
	if (rc != Z_OK)
		return fail("gzclose_r", rc);
	unlink(path);

	printf("libz.so.1 fixture: %s\n", zlibVersion());
	return 0;
}
