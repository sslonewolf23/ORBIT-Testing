#include "ORBITPackageArchive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    uint8_t deb[8192];
    orbit_archive_report report;
    size_t length = make_deb(deb, "./Library/ORBIT/example.dylib", '0');
    EXPECT("valid uncompressed deb accepted",
           orbit_package_archive_inspect_deb(deb, length, &report) == ORBIT_ARCHIVE_OK);
    EXPECT("manifest entry counted", report.entries == 1U);
    EXPECT("normalized path remains safe",
           orbit_package_archive_path_is_safe("Library/ORBIT/example.dylib"));
    EXPECT("required deb members present",
           report.saw_debian_binary && report.saw_control_archive && report.saw_data_archive);

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
    /* Change data member to a compressed member name: it must not be parsed. */
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
