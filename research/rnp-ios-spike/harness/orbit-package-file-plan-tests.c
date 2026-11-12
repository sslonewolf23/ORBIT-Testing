#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageFilePlan.h"
#include "ORBITPackageInstallTransaction.h"

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

static bool write_file_at(int directory_fd, const char *name, const char *value) {
    int fd = openat(directory_fd, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    size_t length = strlen(value), offset = 0U;
    while (offset < length) {
        ssize_t count = write(fd, value + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); return false; }
        offset += (size_t)count;
    }
    bool ok = fsync(fd) == 0 && close(fd) == 0;
    return ok;
}

static orbit_filesystem_code no_op_executor(
    void *context,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    orbit_file_journal_action action,
    const orbit_package_file_change *change) {
    (void)context;
    (void)transaction_id;
    (void)action;
    (void)change;
    return ORBIT_FILESYSTEM_OK;
}

static void fill_record(orbit_package_ownership_record *record,
                        const char *path, const char *name,
                        const char *version, const char *architecture,
                        bool directory) {
    memset(record, 0, sizeof(*record));
    (void)snprintf(record->path, sizeof(record->path), "%s", path);
    (void)snprintf(record->package_name, sizeof(record->package_name), "%s", name);
    (void)snprintf(record->package_version, sizeof(record->package_version), "%s", version);
    (void)snprintf(record->architecture, sizeof(record->architecture), "%s", architecture);
    record->directory = directory;
}

int main(void) {
    char root_template[] = "/tmp/orbit-file-plan-XXXXXX";
    char *root_path = mkdtemp(root_template);
    EXPECT("temporary root created", root_path != NULL);
    if (!root_path) return EXIT_FAILURE;

    int root_fd = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("temporary root opened", root_fd >= 0);
    if (root_fd < 0) return EXIT_FAILURE;
    EXPECT("fixture directories created",
        mkdirat(root_fd, "install", 0700) == 0 &&
        mkdirat(root_fd, "stage", 0700) == 0 &&
        mkdirat(root_fd, "backup", 0700) == 0);

    int install_fd = openat(root_fd, "install", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int stage_fd = openat(root_fd, "stage", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int backup_fd = openat(root_fd, "backup", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("fixture roots opened", install_fd >= 0 && stage_fd >= 0 && backup_fd >= 0);
    EXPECT("package parent directories created",
        mkdirat(install_fd, "Library", 0700) == 0 &&
        mkdirat(stage_fd, "Library", 0700) == 0);
    int install_library = openat(install_fd, "Library", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int stage_library = openat(stage_fd, "Library", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("package parent descriptors opened",
        install_library >= 0 && stage_library >= 0);
    EXPECT("old and staged files created",
        write_file_at(install_library, "old-file", "old") &&
        write_file_at(stage_library, "new-file", "new"));

    orbit_package_record candidate;
    memset(&candidate, 0, sizeof(candidate));
    (void)snprintf(candidate.name, sizeof(candidate.name), "demo.package");
    (void)snprintf(candidate.version, sizeof(candidate.version), "2.0");
    (void)snprintf(candidate.architecture, sizeof(candidate.architecture),
                   "iphoneos-arm64");

    orbit_package_ownership_record installed_records[2];
    fill_record(&installed_records[0], "Library", "demo.package", "1.0",
                "iphoneos-arm64", true);
    fill_record(&installed_records[1], "Library/old-file", "demo.package", "1.0",
                "iphoneos-arm64", false);
    orbit_package_ownership_snapshot installed = {
        installed_records, 2U
    };

    orbit_archive_entry manifest[2];
    memset(manifest, 0, sizeof(manifest));
    (void)snprintf(manifest[0].path, sizeof(manifest[0].path), "Library");
    manifest[0].directory = true;
    (void)snprintf(manifest[1].path, sizeof(manifest[1].path), "Library/new-file");
    manifest[1].size = 3U;

    orbit_package_file_change changes[8];
    orbit_package_ownership_record ownership_output[8];
    orbit_package_ownership_snapshot replacement;
    size_t change_count = 0U;
    orbit_package_file_plan_code result = orbit_package_file_plan_build_install(
        &installed, &candidate, manifest, 2U,
        install_fd, stage_fd, backup_fd,
        changes, 8U, &change_count,
        ownership_output, 8U, &replacement);
    EXPECT("upgrade plan builds", result == ORBIT_PACKAGE_FILE_PLAN_OK);
    EXPECT("upgrade plans obsolete removal and new replacement",
        change_count == 2U &&
        changes[0].operation == ORBIT_FILESYSTEM_REMOVE &&
        changes[1].operation == ORBIT_FILESYSTEM_REPLACE);
    EXPECT("plan stores safe relative parent locators",
        strcmp(changes[0].target_parent_path, "Library") == 0 &&
        changes[0].staged_parent_path[0] == '\0' &&
        strcmp(changes[1].target_parent_path, "Library") == 0 &&
        strcmp(changes[1].staged_parent_path, "Library") == 0);
    EXPECT("replacement ownership is complete and versioned",
        replacement.count == 2U &&
        strcmp(replacement.records[1].path, "Library/new-file") == 0 &&
        strcmp(replacement.records[1].package_version, "2.0") == 0);
    EXPECT("planning did not mutate installed or staged files",
        faccessat(install_library, "old-file", F_OK, AT_SYMLINK_NOFOLLOW) == 0 &&
        faccessat(stage_library, "new-file", F_OK, AT_SYMLINK_NOFOLLOW) == 0 &&
        faccessat(install_library, "new-file", F_OK, AT_SYMLINK_NOFOLLOW) != 0);

    size_t remove_count = 0U;
    orbit_package_ownership_record remove_output[8];
    orbit_package_ownership_snapshot after_remove;
    result = orbit_package_file_plan_build_remove(
        &installed, &candidate, install_fd, backup_fd,
        changes, 8U, &remove_count, remove_output, 8U, &after_remove);
    EXPECT("package removal plan builds", result == ORBIT_PACKAGE_FILE_PLAN_OK);
    EXPECT("removal backs up every owned regular file",
        remove_count == 1U &&
        changes[0].operation == ORBIT_FILESYSTEM_REMOVE &&
        strcmp(changes[0].target_parent_path, "Library") == 0);
    EXPECT("removal drops only the selected package ownership rows",
        after_remove.count == 0U);
    EXPECT("removal planning leaves the installed file untouched",
        faccessat(install_library, "old-file", F_OK, AT_SYMLINK_NOFOLLOW) == 0);

    /* The orchestration entry point must refuse a stale ownership database
     * before it can plan or invoke the authenticated journal backend. */
    const uint8_t stale_ownership[] = { 0x00U };
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 1U };
    orbit_package_filesystem_envelope_backend unused_backend;
    memset(&unused_backend, 0, sizeof(unused_backend));
    orbit_package_file_plan_code orchestration_plan =
        ORBIT_PACKAGE_FILE_PLAN_OK;
    orbit_filesystem_code orchestration_journal = ORBIT_FILESYSTEM_OK;
    orbit_package_install_transaction_code orchestration =
        orbit_package_install_transaction_execute_enveloped(
            &installed, &candidate, manifest, 2U,
            stale_ownership, sizeof(stale_ownership), transaction_id,
            install_fd, stage_fd, backup_fd, &unused_backend,
            no_op_executor, NULL, &orchestration_plan, &orchestration_journal);
    EXPECT("enveloped install rejects stale ownership before execution",
        orchestration == ORBIT_PACKAGE_INSTALL_TRANSACTION_INVALID_ARGUMENT &&
        orchestration_plan == ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT &&
        orchestration_journal == ORBIT_FILESYSTEM_INVALID_ARGUMENT);
    EXPECT("stale ownership rejection leaves installed files untouched",
        faccessat(install_library, "old-file", F_OK, AT_SYMLINK_NOFOLLOW) == 0 &&
        faccessat(stage_library, "new-file", F_OK, AT_SYMLINK_NOFOLLOW) == 0);

    size_t insufficient_count = 99U;
    orbit_package_ownership_snapshot insufficient_snapshot;
    result = orbit_package_file_plan_build_install(
        &installed, &candidate, manifest, 2U,
        install_fd, stage_fd, backup_fd,
        changes, 1U, &insufficient_count,
        ownership_output, 8U, &insufficient_snapshot);
    EXPECT("insufficient plan capacity fails closed",
        result == ORBIT_PACKAGE_FILE_PLAN_LIMIT &&
        insufficient_count == 0U && insufficient_snapshot.count == 0U);

    orbit_archive_entry unsupported[2] = { manifest[0], manifest[1] };
    (void)snprintf(unsupported[1].path, sizeof(unsupported[1].path),
                   "Missing/new-file");
    size_t unsupported_count = 0U;
    result = orbit_package_file_plan_build_install(
        &installed, &candidate, unsupported, 2U,
        install_fd, stage_fd, backup_fd,
        changes, 8U, &unsupported_count,
        ownership_output, 8U, &insufficient_snapshot);
    EXPECT("missing target parent fails closed without a partial plan",
        result == ORBIT_PACKAGE_FILE_PLAN_FILESYSTEM_ERROR &&
        unsupported_count == 0U && insufficient_snapshot.count == 0U);

    close(stage_library);
    close(install_library);
    unlinkat(install_fd, "Library/old-file", 0);
    unlinkat(stage_fd, "Library/new-file", 0);
    unlinkat(install_fd, "Library", AT_REMOVEDIR);
    unlinkat(stage_fd, "Library", AT_REMOVEDIR);
    close(backup_fd);
    close(stage_fd);
    close(install_fd);
    unlinkat(root_fd, "backup", AT_REMOVEDIR);
    unlinkat(root_fd, "stage", AT_REMOVEDIR);
    unlinkat(root_fd, "install", AT_REMOVEDIR);
    close(root_fd);
    rmdir(root_path);

    printf("package_file_plan_checks=%u failures=%u\ndecision=%s\n",
        checks, failures, failures == 0U ? "PASS" : "FAIL");
    return failures == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
