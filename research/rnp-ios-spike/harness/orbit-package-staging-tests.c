#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include "ORBITPackageArchive.h"
#include "ORBITPackageStaging.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned checks;
static unsigned failures;
#define EXPECT(label, condition) do { ++checks; if (!(condition)) { ++failures; \
    fprintf(stderr, "FAIL: %s\n", label); } } while (0)

static void octal(uint8_t *output, size_t length, uint64_t value) {
    char buffer[32];
    (void)snprintf(buffer, sizeof(buffer), "%0*llo", (int)(length - 1U),
                   (unsigned long long)value);
    memcpy(output, buffer, length - 1U);
    output[length - 1U] = 0U;
}

static void make_tar_header(uint8_t *header, const char *path,
                            uint64_t size, char type, uint32_t mode) {
    memset(header, 0, 512U);
    memcpy(header, path, strlen(path));
    octal(header + 100U, 8U, mode);
    octal(header + 108U, 8U, 0U);
    octal(header + 116U, 8U, 0U);
    octal(header + 124U, 12U, size);
    octal(header + 136U, 12U, 0U);
    memset(header + 148U, ' ', 8U);
    header[156U] = (uint8_t)type;
    memcpy(header + 257U, "ustar", 5U);
    header[262U] = 0U;
    header[263U] = '0';
    header[264U] = '0';
    unsigned checksum = 0U;
    for (size_t i = 0U; i < 512U; ++i) checksum += header[i];
    (void)snprintf((char *)header + 148U, 8U, "%06o", checksum);
    header[154U] = 0U;
    header[155U] = ' ';
}

static size_t make_tar(uint8_t *output, const char *path,
                       const uint8_t *payload, size_t payload_length,
                       uint32_t mode) {
    size_t padded = ((payload_length + 511U) / 512U) * 512U;
    size_t total = 512U + padded + 1024U;
    memset(output, 0, total);
    make_tar_header(output, path, payload_length, '0', mode);
    if (payload_length != 0U)
        memcpy(output + 512U, payload, payload_length);
    return total;
}

static size_t append_ar_member(uint8_t *output, size_t offset,
                               const char *name, const uint8_t *body,
                               size_t body_length) {
    uint8_t *header = output + offset;
    memset(header, ' ', 60U);
    memcpy(header, name, strlen(name));
    char size_text[16];
    (void)snprintf(size_text, sizeof(size_text), "%-10zu", body_length);
    memcpy(header + 48U, size_text, 10U);
    memcpy(header + 58U, "`\n", 2U);
    if (body_length != 0U) memcpy(header + 60U, body, body_length);
    size_t next = offset + 60U + body_length;
    if (((60U + body_length) & 1U) != 0U) output[next++] = '\n';
    return next;
}

static size_t make_deb(uint8_t *output, const uint8_t *payload,
                       size_t payload_length, uint32_t file_mode) {
    uint8_t control_tar[2048], data_tar[4096];
    size_t control_length = make_tar(control_tar, "control", NULL, 0U, 0644U);
    size_t data_length = make_tar(
        data_tar, "Library/ORBIT/staged.bin", payload, payload_length, file_mode);
    memcpy(output, "!<arch>\n", 8U);
    size_t offset = 8U;
    static const uint8_t version[] = "2.0\n";
    offset = append_ar_member(output, offset, "debian-binary", version, 4U);
    offset = append_ar_member(output, offset, "control.tar", control_tar, control_length);
    offset = append_ar_member(output, offset, "data.tar", data_tar, data_length);
    return offset;
}

static bool path_exists_at(int directory_fd, const char *path) {
    struct stat status;
    return fstatat(directory_fd, path, &status, AT_SYMLINK_NOFOLLOW) == 0;
}

int main(void) {
    char temporary_directory[] = "/tmp/orbit-staging-XXXXXX";
    char *base_path = mkdtemp(temporary_directory);
    EXPECT("temporary base directory created", base_path != NULL);
    if (!base_path) return EXIT_FAILURE;

    int base_fd = open(base_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("trusted base directory opened", base_fd >= 0);
    if (base_fd < 0) {
        (void)rmdir(base_path);
        return EXIT_FAILURE;
    }

    static const uint8_t payload[] = "ORBIT staged package bytes";
    uint8_t deb[8192];
    size_t deb_length = make_deb(deb, payload, sizeof(payload), 0644U);
    orbit_package_staging staging;
    orbit_archive_report staged_report;
    orbit_archive_code staged_archive_code = ORBIT_ARCHIVE_INVALID_ARGUMENT;
    EXPECT("archive is fully inspected before private staging",
        orbit_package_staging_extract_deb(
            base_fd, "stage-good", deb, deb_length, &staging,
            &staged_report, &staged_archive_code) == ORBIT_STAGING_OK &&
        staged_archive_code == ORBIT_ARCHIVE_OK &&
        staged_report.entries == 2U && staged_report.saw_data_archive &&
        staged_report.regular_file_bytes == sizeof(payload));

    int library_fd = openat(staging.staging_directory_fd, "Library",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int orbit_fd = library_fd >= 0 ? openat(library_fd, "ORBIT",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    int package_fd = orbit_fd >= 0 ? openat(orbit_fd, "staged.bin",
        O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
    uint8_t actual[sizeof(payload)];
    ssize_t actual_length = package_fd >= 0 ? read(package_fd, actual, sizeof(actual)) : -1;
    struct stat package_status;
    bool mode_ok = package_fd >= 0 && fstat(package_fd, &package_status) == 0 &&
                   (package_status.st_mode & 0777U) == 0644U;
    EXPECT("staged file bytes and safe mode match",
        actual_length == (ssize_t)sizeof(payload) &&
        memcmp(actual, payload, sizeof(payload)) == 0 && mode_ok);
    if (package_fd >= 0) close(package_fd);
    if (orbit_fd >= 0) close(orbit_fd);
    if (library_fd >= 0) close(library_fd);
    EXPECT("staging tree discarded safely",
        orbit_package_staging_discard(&staging) == ORBIT_STAGING_OK);
    EXPECT("discard removed staging directory",
        !path_exists_at(base_fd, "stage-good"));

    deb_length = make_deb(deb, payload, sizeof(payload), 0777U);
    EXPECT("world-writable archive mode is staged in a private tree",
        orbit_package_staging_extract_deb(
            base_fd, "stage-mode", deb, deb_length, &staging,
            &staged_report, &staged_archive_code) == ORBIT_STAGING_OK);
    int mode_library_fd = openat(staging.staging_directory_fd, "Library",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int mode_orbit_fd = mode_library_fd >= 0 ? openat(mode_library_fd, "ORBIT",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    int mode_file_fd = mode_orbit_fd >= 0 ? openat(mode_orbit_fd, "staged.bin",
        O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
    struct stat sanitized_status;
    EXPECT("archive group/other write bits are stripped",
        mode_file_fd >= 0 && fstat(mode_file_fd, &sanitized_status) == 0 &&
        (sanitized_status.st_mode & 0777U) == 0755U);
    if (mode_file_fd >= 0) close(mode_file_fd);
    if (mode_orbit_fd >= 0) close(mode_orbit_fd);
    if (mode_library_fd >= 0) close(mode_library_fd);
    EXPECT("mode-sanitization stage discarded",
        orbit_package_staging_discard(&staging) == ORBIT_STAGING_OK);

    size_t empty_deb_length = make_deb(deb, NULL, 0U, 0644U);
    EXPECT("zero-length file staging directory created",
        orbit_package_staging_begin(base_fd, "stage-empty", &staging) == ORBIT_STAGING_OK);
    EXPECT("zero-length package file is finalized by empty final chunk",
        orbit_package_archive_inspect_deb_with_data(
            deb, empty_deb_length,
            orbit_package_staging_entry_callback, &staging,
            orbit_package_staging_data_callback, &staging,
            &(orbit_archive_report){0}) == ORBIT_ARCHIVE_OK &&
        orbit_package_staging_finish(&staging) == ORBIT_STAGING_OK);
    int empty_library_fd = openat(staging.staging_directory_fd, "Library",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int empty_orbit_fd = empty_library_fd >= 0 ? openat(empty_library_fd, "ORBIT",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    int empty_file_fd = empty_orbit_fd >= 0 ? openat(empty_orbit_fd, "staged.bin",
        O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
    struct stat empty_status;
    EXPECT("zero-length staged file exists",
        empty_file_fd >= 0 && fstat(empty_file_fd, &empty_status) == 0 &&
        empty_status.st_size == 0);
    if (empty_file_fd >= 0) close(empty_file_fd);
    if (empty_orbit_fd >= 0) close(empty_orbit_fd);
    if (empty_library_fd >= 0) close(empty_library_fd);
    EXPECT("zero-length stage discarded",
        orbit_package_staging_discard(&staging) == ORBIT_STAGING_OK);

    EXPECT("group/world-writable staging base is rejected",
        chmod(base_path, 0777) == 0 &&
        orbit_package_staging_begin(base_fd, "stage-untrusted", &staging) ==
            ORBIT_STAGING_INVALID_ARGUMENT &&
        !path_exists_at(base_fd, "stage-untrusted"));
    EXPECT("trusted staging base permissions restored",
        chmod(base_path, 0700) == 0);

    EXPECT("unsafe staging name rejected",
        orbit_package_staging_begin(base_fd, "../outside", &staging) ==
            ORBIT_STAGING_UNSAFE_PATH);

    /* Restore the non-empty archive fixture after the zero-length case. */
    deb_length = make_deb(deb, payload, sizeof(payload), 0644U);

    uint8_t malformed_deb[sizeof(deb)];
    memcpy(malformed_deb, deb, deb_length);
    malformed_deb[deb_length - 1U] = 1U;
    orbit_archive_code malformed_code = ORBIT_ARCHIVE_OK;
    EXPECT("malformed archive is rejected during no-write preflight",
        orbit_package_staging_extract_deb(
            base_fd, "stage-late", malformed_deb, deb_length, &staging,
            &staged_report, &malformed_code) == ORBIT_STAGING_ARCHIVE_ERROR &&
        malformed_code == ORBIT_ARCHIVE_MALFORMED_TAR);
    EXPECT("preflight failure creates no staging directory",
        !path_exists_at(base_fd, "stage-late"));

    EXPECT("symlink staging directory created",
        orbit_package_staging_begin(base_fd, "stage-link", &staging) == ORBIT_STAGING_OK);
    EXPECT("test symlink inserted into private stage",
        symlinkat(base_path, staging.staging_directory_fd, "Library") == 0);
    EXPECT("staging refuses symlink parent traversal",
        orbit_package_archive_inspect_deb_with_data(
            deb, deb_length,
            orbit_package_staging_entry_callback, &staging,
            orbit_package_staging_data_callback, &staging,
            &(orbit_archive_report){0}) == ORBIT_ARCHIVE_CALLBACK_ERROR);
    EXPECT("symlink stage cleanup succeeds",
        orbit_package_staging_discard(&staging) == ORBIT_STAGING_OK);
    EXPECT("no file escaped into staging base",
        !path_exists_at(base_fd, "ORBIT"));

    close(base_fd);
    EXPECT("temporary base directory removed", rmdir(base_path) == 0);
    printf("staging_checks=%u failures=%u\ndecision=%s\n",
           checks, failures, failures == 0U ? "PASS" : "FAIL");
    return failures == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
