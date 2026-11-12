#include "ORBITPackageArchive.h"
#include "ORBITPackageDecompress.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bzlib.h>
#include <lzma.h>
#include <zlib.h>
#include <zstd.h>

static unsigned checks;
static unsigned failures;
#define EXPECT(label, condition) do { ++checks; if (!(condition)) { ++failures; \
    fprintf(stderr, "FAIL: %s\n", label); } } while (0)

static void octal(uint8_t *p, size_t n, uint64_t value) {
    char buffer[32];
    (void)snprintf(buffer, sizeof(buffer), "%0*llo", (int)(n - 1U),
                   (unsigned long long)value);
    memcpy(p, buffer, n - 1U);
    p[n - 1U] = 0U;
}

static void make_tar_header(uint8_t *h, const char *path, uint64_t size, char type) {
    memset(h, 0, 512U);
    memcpy(h, path, strlen(path));
    octal(h + 100U, 8U, 0644U);
    octal(h + 108U, 8U, 0U);
    octal(h + 116U, 8U, 0U);
    octal(h + 124U, 12U, size);
    octal(h + 136U, 12U, 0U);
    memset(h + 148U, ' ', 8U);
    h[156U] = (uint8_t)type;
    memcpy(h + 257U, "ustar", 5U);
    h[262U] = 0U;
    h[263U] = '0'; h[264U] = '0';
    unsigned sum = 0U;
    for (size_t i = 0U; i < 512U; ++i) sum += h[i];
    (void)snprintf((char *)h + 148U, 8U, "%06o", sum);
    h[154U] = 0U; h[155U] = ' ';
}

static size_t make_tar(uint8_t *out, const char *path, char type) {
    memset(out, 0, 1536U);
    make_tar_header(out, path, 0U, type);
    return 1536U;
}

static size_t append_ar_member(uint8_t *out, size_t offset,
                               const char *name, const uint8_t *body,
                               size_t body_length) {
    uint8_t *h = out + offset;
    memset(h, ' ', 60U);
    memcpy(h, name, strlen(name));
    memcpy(h + 48U, "         0", 10U);
    char size_text[16];
    (void)snprintf(size_text, sizeof(size_text), "%-10zu", body_length);
    memcpy(h + 48U, size_text, 10U);
    memcpy(h + 58U, "`\n", 2U);
    if (body_length) memcpy(h + 60U, body, body_length);
    size_t next = offset + 60U + body_length;
    if (((60U + body_length) & 1U) != 0U) out[next++] = '\n';
    return next;
}

static size_t make_deb(uint8_t *out, const char *path, char type) {
    uint8_t tar[1536];
    size_t tar_length = make_tar(tar, path, type);
    memcpy(out, "!<arch>\n", 8U);
    size_t offset = 8U;
    static const uint8_t version[] = "2.0\n";
    offset = append_ar_member(out, offset, "debian-binary", version, 4U);
    offset = append_ar_member(out, offset, "control.tar", tar, tar_length);
    offset = append_ar_member(out, offset, "data.tar", tar, tar_length);
    return offset;
}


static size_t compress_fixture(orbit_decompress_format format,
                               const uint8_t *input, size_t input_length,
                               uint8_t *output, size_t capacity) {
    if (format == ORBIT_DECOMPRESS_GZIP) {
        z_stream stream;
        memset(&stream, 0, sizeof(stream));
        if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, 31, 8,
                         Z_DEFAULT_STRATEGY) != Z_OK) return 0U;
        stream.next_in = (Bytef *)input;
        stream.avail_in = (uInt)input_length;
        stream.next_out = output;
        stream.avail_out = (uInt)capacity;
        int status = deflate(&stream, Z_FINISH);
        size_t length = status == Z_STREAM_END ? stream.total_out : 0U;
        deflateEnd(&stream);
        return length;
    }
    if (format == ORBIT_DECOMPRESS_BZIP2) {
        unsigned int output_length = (unsigned int)capacity;
        if (BZ2_bzBuffToBuffCompress((char *)output, &output_length,
            (char *)input, (unsigned int)input_length, 9, 0, 30) != BZ_OK)
            return 0U;
        return output_length;
    }
    if (format == ORBIT_DECOMPRESS_XZ) {
        size_t output_length = 0U;
        return lzma_easy_buffer_encode(6U, LZMA_CHECK_CRC64, NULL,
            input, input_length, output, &output_length, capacity) == LZMA_OK ?
            output_length : 0U;
    }
    if (format == ORBIT_DECOMPRESS_ZSTD) {
        size_t length = ZSTD_compress(output, capacity, input, input_length, 3);
        return ZSTD_isError(length) ? 0U : length;
    }
    return 0U;
}

static size_t make_deb_compressed(uint8_t *out, const char *path,
                                  orbit_decompress_format format,
                                  const char *suffix) {
    uint8_t tar[1536], compressed[2048];
    size_t tar_length = make_tar(tar, path, '0');
    size_t compressed_length = compress_fixture(format, tar, tar_length,
                                                 compressed, sizeof(compressed));
    if (compressed_length == 0U) return 0U;
    char control_name[32], data_name[32];
    (void)snprintf(control_name, sizeof(control_name), "control.tar%s", suffix);
    (void)snprintf(data_name, sizeof(data_name), "data.tar%s", suffix);
    memcpy(out, "!<arch>\n", 8U);
    size_t offset = 8U;
    static const uint8_t version[] = "2.0\n";
    offset = append_ar_member(out, offset, "debian-binary", version, 4U);
    offset = append_ar_member(out, offset, control_name, compressed, compressed_length);
    offset = append_ar_member(out, offset, data_name, compressed, compressed_length);
    return offset;
}

static size_t make_tar_with_payload(uint8_t *out, const char *path,
                                     const uint8_t *payload, size_t payload_length) {
    size_t padded = ((payload_length + 511U) / 512U) * 512U;
    size_t total = 512U + padded + 1024U;
    memset(out, 0, total);
    make_tar_header(out, path, payload_length, '0');
    if (payload_length != 0U) memcpy(out + 512U, payload, payload_length);
    return total;
}

int main(void) {
    EXPECT("normal package path accepted",
           orbit_package_archive_path_is_safe("usr/lib/orbit/example.dylib"));
    EXPECT("parent traversal rejected",
           !orbit_package_archive_path_is_safe("usr/lib/../../etc/evil"));
    EXPECT("absolute path rejected",
           !orbit_package_archive_path_is_safe("/Library/evil"));
    EXPECT("backslash path rejected",
           !orbit_package_archive_path_is_safe("usr\\..\\evil"));
    EXPECT("empty path segment rejected",
           !orbit_package_archive_path_is_safe("usr//lib/file"));
    EXPECT("dot segment rejected",
           !orbit_package_archive_path_is_safe("usr/./lib/file"));

    orbit_archive_report report;
    uint8_t stream_tar[73728];
    size_t stream_tar_length = make_tar(stream_tar, "Library/ORBIT/stream.dylib", '0');
    const size_t chunk_sizes[] = { 1U, 511U, 512U, 513U, 65519U };
    for (size_t i = 0U; i < sizeof(chunk_sizes) / sizeof(chunk_sizes[0]); ++i) {
        EXPECT("incremental tar parser accepts arbitrary chunk boundary",
            orbit_package_archive_test_inspect_tar_chunks(
                stream_tar, stream_tar_length, chunk_sizes[i], &report) == ORBIT_ARCHIVE_OK);
    }
    EXPECT("incremental parser rejects truncated header",
        orbit_package_archive_test_inspect_tar_chunks(
            stream_tar, stream_tar_length - 1U, 511U, &report) == ORBIT_ARCHIVE_MALFORMED_TAR);
    EXPECT("incremental parser rejects missing end blocks",
        orbit_package_archive_test_inspect_tar_chunks(
            stream_tar, 512U, 37U, &report) == ORBIT_ARCHIVE_MALFORMED_TAR);
    stream_tar[1535U] = 1U;
    EXPECT("incremental parser rejects nonzero trailing data",
        orbit_package_archive_test_inspect_tar_chunks(
            stream_tar, stream_tar_length, 513U, &report) == ORBIT_ARCHIVE_MALFORMED_TAR);
    stream_tar[1535U] = 0U;

    uint8_t payload[70001U];
    memset(payload, 0xA5, sizeof(payload));
    stream_tar_length = make_tar_with_payload(
        stream_tar, "Library/ORBIT/payload.bin", payload, sizeof(payload));
    EXPECT("incremental parser skips payload and padding across chunks",
        orbit_package_archive_test_inspect_tar_chunks(
            stream_tar, stream_tar_length, 65519U, &report) == ORBIT_ARCHIVE_OK);
    EXPECT("incremental parser records exact payload length",
        report.regular_file_bytes == sizeof(payload));

    uint8_t deb[8192];
    size_t length = make_deb(deb, "./Library/ORBIT/example.dylib", '0');
    EXPECT("valid uncompressed deb accepted",
           orbit_package_archive_inspect_deb(deb, length, &report) == ORBIT_ARCHIVE_OK);
    EXPECT("control and data manifest entries counted", report.entries == 2U);
    EXPECT("normalized path remains safe",
           orbit_package_archive_path_is_safe("Library/ORBIT/example.dylib"));
    EXPECT("required deb members present",
           report.saw_debian_binary && report.saw_control_archive && report.saw_data_archive);


    const struct {
        orbit_decompress_format format;
        const char *suffix;
        const char *label;
    } compressed_formats[] = {
        { ORBIT_DECOMPRESS_GZIP, ".gz", "gzip deb inspected" },
        { ORBIT_DECOMPRESS_XZ, ".xz", "xz deb inspected" },
        { ORBIT_DECOMPRESS_BZIP2, ".bz2", "bzip2 deb inspected" },
        { ORBIT_DECOMPRESS_ZSTD, ".zst", "zstd deb inspected" }
    };
    for (size_t i = 0U; i < sizeof(compressed_formats) / sizeof(compressed_formats[0]); ++i) {
        length = make_deb_compressed(deb, "Library/ORBIT/compressed.dylib",
                                     compressed_formats[i].format,
                                     compressed_formats[i].suffix);
        EXPECT("compressed Debian fixture generated", length > 0U);
        EXPECT(compressed_formats[i].label,
               orbit_package_archive_inspect_deb(deb, length, &report) == ORBIT_ARCHIVE_OK);
    }

    length = make_deb(deb, "../escape", '0');
    EXPECT("tar traversal rejected",
           orbit_package_archive_inspect_deb(deb, length, &report) == ORBIT_ARCHIVE_UNSAFE_PATH);
    length = make_deb(deb, "Library/link", '2');
    EXPECT("symlink rejected",
           orbit_package_archive_inspect_deb(deb, length, &report) == ORBIT_ARCHIVE_UNSUPPORTED_ENTRY);
    length = make_deb(deb, "Library/device", '3');
    EXPECT("device node rejected",
           orbit_package_archive_inspect_deb(deb, length, &report) == ORBIT_ARCHIVE_UNSUPPORTED_ENTRY);

    length = make_deb(deb, "Library/file", '0');
    /* Unknown compression suffixes must fail closed. */
    const uint8_t *data_name = (const uint8_t *)"data.tar";
    for (size_t i = 8U; i + 60U <= length; ++i) {
        if (memcmp(deb + i, data_name, 8U) == 0) {
            memcpy(deb + i, "data.tar.zz", 11U);
            break;
        }
    }
    EXPECT("unknown compression extension rejected",
           orbit_package_archive_inspect_deb(deb, length, &report) == ORBIT_ARCHIVE_UNSUPPORTED_COMPRESSION);

    EXPECT("null input rejected",
           orbit_package_archive_inspect_deb(NULL, 0U, &report) == ORBIT_ARCHIVE_INVALID_ARGUMENT);
    printf("archive_checks=%u failures=%u\ndecision=%s\n",
           checks, failures, failures == 0U ? "PASS" : "FAIL");
    return failures == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
