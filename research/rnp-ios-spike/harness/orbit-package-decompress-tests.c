#include "ORBITPackageDecompress.h"

#include <bzlib.h>
#include <lzma.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <zstd.h>

static unsigned checks;
static unsigned failures;
#define EXPECT(label, condition) do { ++checks; if (!(condition)) { ++failures; \
    fprintf(stderr, "FAIL: %s\n", label); } } while (0)

typedef struct { uint8_t bytes[128]; size_t length; } sink_buffer;

static bool collect(void *context, const uint8_t *bytes, size_t length) {
    sink_buffer *sink = (sink_buffer *)context;
    if (!sink || length > sizeof(sink->bytes) - sink->length) return false;
    memcpy(sink->bytes + sink->length, bytes, length);
    sink->length += length;
    return true;
}

static size_t make_gzip(const uint8_t *input, size_t input_length,
                        uint8_t *output, size_t capacity) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return 0U;
    stream.next_in = (Bytef *)input;
    stream.avail_in = (uInt)input_length;
    stream.next_out = output;
    stream.avail_out = (uInt)capacity;
    int status = deflate(&stream, Z_FINISH);
    size_t length = status == Z_STREAM_END ? stream.total_out : 0U;
    deflateEnd(&stream);
    return length;
}

static size_t make_bzip(const uint8_t *input, size_t input_length,
                        uint8_t *output, size_t capacity) {
    unsigned int output_length = (unsigned int)capacity;
    if (BZ2_bzBuffToBuffCompress((char *)output, &output_length,
            (char *)input, (unsigned int)input_length, 9, 0, 30) != BZ_OK)
        return 0U;
    return output_length;
}

static size_t make_xz(const uint8_t *input, size_t input_length,
                      uint8_t *output, size_t capacity) {
    size_t output_length = 0U;
    lzma_ret status = lzma_easy_buffer_encode(6U, LZMA_CHECK_CRC64, NULL,
        input, input_length, output, &output_length, capacity);
    return status == LZMA_OK ? output_length : 0U;
}

static size_t make_zstd(const uint8_t *input, size_t input_length,
                        uint8_t *output, size_t capacity) {
    size_t length = ZSTD_compress(output, capacity, input, input_length, 3);
    return ZSTD_isError(length) ? 0U : length;
}

static void check_format(const char *label, orbit_decompress_format format,
                         size_t (*compressor)(const uint8_t *, size_t, uint8_t *, size_t)) {
    static const uint8_t plain[] = "ORBIT bounded streaming decompression";
    uint8_t compressed[256];
    size_t compressed_length = compressor(plain, sizeof(plain), compressed, sizeof(compressed));
    EXPECT("fixture compression succeeds", compressed_length > 0U);
    if (compressed_length == 0U) return;

    sink_buffer sink = {{0}, 0U};
    uint64_t output_length = 0U;
    orbit_decompress_code result = orbit_package_decompress_stream(
        format, compressed, compressed_length, sizeof(sink.bytes),
        collect, &sink, &output_length);
    EXPECT(label, result == ORBIT_DECOMPRESS_OK);
    EXPECT("decoded bytes match", sink.length == sizeof(plain) &&
           memcmp(sink.bytes, plain, sizeof(plain)) == 0);
    EXPECT("reported output length matches", output_length == sizeof(plain));

    sink = (sink_buffer){{0}, 0U};
    result = orbit_package_decompress_stream(
        format, compressed, compressed_length + 1U, sizeof(sink.bytes),
        collect, &sink, &output_length);
    EXPECT("trailing data rejected", result == ORBIT_DECOMPRESS_TRAILING_DATA);

    sink = (sink_buffer){{0}, 0U};
    result = orbit_package_decompress_stream(
        format, compressed, compressed_length - 1U, sizeof(sink.bytes),
        collect, &sink, &output_length);
    EXPECT("truncated stream rejected", result == ORBIT_DECOMPRESS_MALFORMED);

    sink = (sink_buffer){{0}, 0U};
    result = orbit_package_decompress_stream(
        format, compressed, compressed_length, 4U,
        collect, &sink, &output_length);
    EXPECT("output ceiling enforced", result == ORBIT_DECOMPRESS_LIMIT);
}

int main(void) {
    check_format("gzip stream decoded", ORBIT_DECOMPRESS_GZIP, make_gzip);
    check_format("xz stream decoded", ORBIT_DECOMPRESS_XZ, make_xz);
    check_format("bzip2 stream decoded", ORBIT_DECOMPRESS_BZIP2, make_bzip);
    check_format("zstd stream decoded", ORBIT_DECOMPRESS_ZSTD, make_zstd);
    uint64_t output_length = 0U;
    EXPECT("unknown format rejected",
        orbit_package_decompress_stream((orbit_decompress_format)99,
            (const uint8_t *)"x", 1U, 8U, collect, NULL, &output_length)
            == ORBIT_DECOMPRESS_UNSUPPORTED);
    EXPECT("null output length rejected",
        orbit_package_decompress_stream(ORBIT_DECOMPRESS_GZIP,
            (const uint8_t *)"x", 1U, 8U, collect, NULL, NULL)
            == ORBIT_DECOMPRESS_INVALID_ARGUMENT);
    printf("decompress_checks=%u failures=%u\ndecision=%s\n",
           checks, failures, failures == 0U ? "PASS" : "FAIL");
    return failures == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
