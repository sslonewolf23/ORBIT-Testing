#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageInstallTransaction.h"
#include "ORBITPackageOwnershipCodec.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned checks, failures;
#define EXPECT(label, condition) do { ++checks; if (!(condition)) { ++failures; \
    fprintf(stderr, "FAIL: %s\n", label); } } while (0)

static void octal(uint8_t *out, size_t length, uint64_t value) {
    char buffer[32];
    (void)snprintf(buffer, sizeof(buffer), "%0*llo", (int)(length - 1U),
                   (unsigned long long)value);
    memcpy(out, buffer, length - 1U);
    out[length - 1U] = 0U;
}
static size_t make_tar(uint8_t *out, const char *path) {
    memset(out, 0, 1536U);
    memcpy(out, path, strlen(path));
    octal(out + 100U, 8U, 0644U);
    octal(out + 108U, 8U, 0U);
    octal(out + 116U, 8U, 0U);
    octal(out + 124U, 12U, 0U);
    octal(out + 136U, 12U, 0U);
    memset(out + 148U, ' ', 8U);
    out[156U] = '0';
    memcpy(out + 257U, "ustar", 5U);
    out[262U] = 0U; out[263U] = '0'; out[264U] = '0';
    unsigned sum = 0U;
    for (size_t i = 0U; i < 512U; ++i) sum += out[i];
    (void)snprintf((char *)out + 148U, 8U, "%06o", sum);
    out[154U] = 0U; out[155U] = ' ';
    return 1536U;
}
static size_t append_member(uint8_t *out, size_t offset, const char *name,
                            const uint8_t *body, size_t length) {
    uint8_t *header = out + offset;
    memset(header, ' ', 60U);
    memcpy(header, name, strlen(name));
    char size[16];
    (void)snprintf(size, sizeof(size), "%-10zu", length);
    memcpy(header + 48U, size, 10U);
    memcpy(header + 58U, "\`\n", 2U);
    memcpy(header + 60U, body, length);
    size_t next = offset + 60U + length;
    if (((60U + length) & 1U) != 0U) out[next++] = '\n';
    return next;
}
static size_t make_deb(uint8_t *out) {
    uint8_t control[1536], data[1536];
    size_t control_length = make_tar(control, "control");
    size_t data_length = make_tar(data, "Library/ORBIT/staged.bin");
    memcpy(out, "!<arch>\n", 8U);
    size_t offset = 8U;
    static const uint8_t version[] = "2.0\n";
    offset = append_member(out, offset, "debian-binary", version, 4U);
    offset = append_member(out, offset, "control.tar", control, control_length);
    offset = append_member(out, offset, "data.tar", data, data_length);
    return offset;
}
static bool unused_load(void *ctx, uint8_t **p, size_t *n, uint8_t d[32]) {
    (void)ctx; (void)p; (void)n; (void)d; return false;
}
static void unused_release(void *ctx, uint8_t *p) { (void)ctx; free(p); }
static bool unused_store(void *ctx, uint64_t rev, const uint8_t d[32],
                         const uint8_t *p, size_t n, uint8_t next[32]) {
    (void)ctx; (void)rev; (void)d; (void)p; (void)n; (void)next; return false;
}
static orbit_filesystem_code unused_executor(
    void *ctx, const uint8_t id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    orbit_file_journal_action action, const orbit_package_file_change *change) {
    (void)ctx; (void)id; (void)action; (void)change;
    return ORBIT_FILESYSTEM_IO_ERROR;
}
static bool exists_at(int fd, const char *name) {
    struct stat st;
    return fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0;
}
int main(void) {
    char root_template[] = "/tmp/orbit-install-orchestrator-XXXXXX";
    char *root_path = mkdtemp(root_template);
    EXPECT("temporary root created", root_path != NULL);
    if (!root_path) return EXIT_FAILURE;
    int root_fd = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("temporary root opened", root_fd >= 0);
    if (root_fd < 0) return EXIT_FAILURE;
    EXPECT("install root created", mkdirat(root_fd, "install", 0700) == 0);
    EXPECT("stage base created", mkdirat(root_fd, "stage-base", 0700) == 0);
    EXPECT("backup root created", mkdirat(root_fd, "backup", 0700) == 0);
    int install_fd = openat(root_fd, "install", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int stage_base_fd = openat(root_fd, "stage-base", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int backup_fd = openat(root_fd, "backup", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("trusted roots opened", install_fd >= 0 && stage_base_fd >= 0 && backup_fd >= 0);

    orbit_package_record candidate;
    memset(&candidate, 0, sizeof(candidate));
    (void)snprintf(candidate.name, sizeof(candidate.name), "orbit-test");
    (void)snprintf(candidate.version, sizeof(candidate.version), "1.0");
    (void)snprintf(candidate.architecture, sizeof(candidate.architecture), "iphoneos-arm64");

    orbit_package_ownership_record foreign;
    memset(&foreign, 0, sizeof(foreign));
    (void)snprintf(foreign.path, sizeof(foreign.path), "Library/ORBIT/staged.bin");
    (void)snprintf(foreign.package_name, sizeof(foreign.package_name), "other-manager");
    (void)snprintf(foreign.package_version, sizeof(foreign.package_version), "1");
    (void)snprintf(foreign.architecture, sizeof(foreign.architecture), "iphoneos-arm64");
    orbit_package_ownership_snapshot installed = { &foreign, 1U };

    size_t ownership_length = 0U;
    EXPECT("ownership snapshot sizing succeeds",
        orbit_package_ownership_encode(&installed, NULL, 0U, &ownership_length) ==
            ORBIT_OWNERSHIP_CODEC_BUFFER_TOO_SMALL && ownership_length > 0U);
    uint8_t *ownership_bytes = (uint8_t *)malloc(ownership_length);
    EXPECT("ownership snapshot encodes",
        ownership_bytes != NULL &&
        orbit_package_ownership_encode(&installed, ownership_bytes,
            ownership_length, &ownership_length) == ORBIT_OWNERSHIP_CODEC_OK);

    uint8_t deb[8192];
    size_t deb_length = make_deb(deb);
    uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES];
    memset(transaction_id, 0x42, sizeof(transaction_id));
    orbit_package_filesystem_envelope_backend backend = {
        NULL, unused_load, unused_release, unused_store
    };
    orbit_package_staging staging;
    orbit_archive_report report;
    orbit_archive_code archive_code;
    orbit_package_file_plan_code plan_code;
    orbit_filesystem_code journal_code;

    EXPECT("foreign-owned path rejected before staging",
        orbit_package_install_transaction_execute_deb_enveloped(
            &installed, &candidate, deb, deb_length,
            ownership_bytes, ownership_length, transaction_id,
            install_fd, stage_base_fd, backup_fd, "stage-conflict",
            &backend, unused_executor, NULL, &staging, &report,
            &archive_code, &plan_code, &journal_code) ==
                ORBIT_PACKAGE_INSTALL_TRANSACTION_OWNERSHIP_PREFLIGHT_FAILED);
    EXPECT("preflight fully validates archive", archive_code == ORBIT_ARCHIVE_OK);
    EXPECT("ownership conflict creates no staging directory",
        !exists_at(stage_base_fd, "stage-conflict"));
    EXPECT("ownership conflict leaves staging descriptors closed",
        staging.base_directory_fd == -1 && staging.staging_directory_fd == -1);

    free(ownership_bytes);
    if (backup_fd >= 0) close(backup_fd);
    if (stage_base_fd >= 0) close(stage_base_fd);
    if (install_fd >= 0) close(install_fd);
    close(root_fd);
    EXPECT("temporary root removed", rmdir(root_path) == 0);
    printf("orchestrator_checks=%u failures=%u\ndecision=%s\n",
        checks, failures, failures == 0U ? "PASS" : "FAIL");
    return failures == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
