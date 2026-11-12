#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include "ORBITPackageFilesystem.h"

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

static bool write_file_at(int directory_fd, const char *name,
                          const char *contents) {
    int fd = openat(directory_fd, name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t length = strlen(contents);
    size_t offset = 0U;
    while (offset < length) {
        ssize_t amount = write(fd, contents + offset, length - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) { close(fd); return false; }
        offset += (size_t)amount;
    }
    bool sync_ok = fsync(fd) == 0;
    bool close_ok = close(fd) == 0;
    return sync_ok && close_ok;
}

static bool file_equals_at(int directory_fd, const char *name,
                           const char *expected) {
    int fd = openat(directory_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    char buffer[256];
    size_t used = 0U;
    for (;;) {
        ssize_t amount = read(fd, buffer + used, sizeof(buffer) - used);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) { close(fd); return false; }
        if (amount == 0) break;
        used += (size_t)amount;
        if (used == sizeof(buffer)) { close(fd); return false; }
    }
    close(fd);
    return used == strlen(expected) && memcmp(buffer, expected, used) == 0;
}

static bool exists_at(int directory_fd, const char *name) {
    struct stat status;
    return fstatat(directory_fd, name, &status, AT_SYMLINK_NOFOLLOW) == 0;
}

static bool remove_if_present(int directory_fd, const char *name) {
    if (unlinkat(directory_fd, name, 0) == 0) return true;
    return errno == ENOENT;
}

int main(void) {
    char temporary_directory[] = "/tmp/orbit-filesystem-XXXXXX";
    char *base_path = mkdtemp(temporary_directory);
    EXPECT("temporary transaction root created", base_path != NULL);
    if (!base_path) return EXIT_FAILURE;

    int base_fd = open(base_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("transaction root opened", base_fd >= 0);
    if (base_fd < 0) { (void)rmdir(base_path); return EXIT_FAILURE; }

    EXPECT("target directory created", mkdirat(base_fd, "target", 0700) == 0);
    EXPECT("stage directory created", mkdirat(base_fd, "stage", 0700) == 0);
    EXPECT("backup directory created", mkdirat(base_fd, "backup", 0700) == 0);
    int target_fd = openat(base_fd, "target", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int stage_fd = openat(base_fd, "stage", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int backup_fd = openat(base_fd, "backup", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    EXPECT("all transaction directories opened",
        target_fd >= 0 && stage_fd >= 0 && backup_fd >= 0);
    if (target_fd < 0 || stage_fd < 0 || backup_fd < 0) return EXIT_FAILURE;

    orbit_package_file_change change;
    EXPECT("old target created", write_file_at(target_fd, "existing.dylib", "old-bytes"));
    EXPECT("staged replacement created", write_file_at(stage_fd, "existing.new", "new-bytes"));
    EXPECT("replacement change prepared",
        orbit_package_filesystem_prepare_replace(
            target_fd, "existing.dylib", stage_fd, "existing.new",
            backup_fd, "existing.backup", &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("replacement applied atomically",
        orbit_package_filesystem_apply(
            target_fd, stage_fd, backup_fd, &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("replacement target contains new bytes",
        file_equals_at(target_fd, "existing.dylib", "new-bytes"));
    EXPECT("replacement preimage retained in backup",
        file_equals_at(backup_fd, "existing.backup", "old-bytes"));
    EXPECT("replacement rollback restores preimage",
        orbit_package_filesystem_rollback(
            target_fd, stage_fd, backup_fd, &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("rollback restored original target",
        file_equals_at(target_fd, "existing.dylib", "old-bytes"));
    EXPECT("rollback removed backup link", !exists_at(backup_fd, "existing.backup"));
    EXPECT("replacement rollback is idempotent",
        orbit_package_filesystem_rollback(
            target_fd, stage_fd, backup_fd, &change) == ORBIT_FILESYSTEM_OK);

    EXPECT("new staged file created", write_file_at(stage_fd, "new-only", "fresh"));
    EXPECT("new-file change prepared",
        orbit_package_filesystem_prepare_replace(
            target_fd, "new-only", stage_fd, "new-only",
            backup_fd, "new-only.backup", &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("new-file change applied",
        orbit_package_filesystem_apply(
            target_fd, stage_fd, backup_fd, &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("new file appears in target", file_equals_at(target_fd, "new-only", "fresh"));
    EXPECT("new-file rollback removes installed file",
        orbit_package_filesystem_rollback(
            target_fd, stage_fd, backup_fd, &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("new-file rollback leaves no target", !exists_at(target_fd, "new-only"));

    EXPECT("commit target created", write_file_at(target_fd, "commit.dylib", "before"));
    EXPECT("commit stage created", write_file_at(stage_fd, "commit.new", "after"));
    EXPECT("commit change prepared",
        orbit_package_filesystem_prepare_replace(
            target_fd, "commit.dylib", stage_fd, "commit.new",
            backup_fd, "commit.backup", &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("commit replacement applied",
        orbit_package_filesystem_apply(
            target_fd, stage_fd, backup_fd, &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("commit finalization removes preimage",
        orbit_package_filesystem_finalize(
            target_fd, stage_fd, backup_fd, &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("committed target retained", file_equals_at(target_fd, "commit.dylib", "after"));
    EXPECT("committed backup removed", !exists_at(backup_fd, "commit.backup"));
    EXPECT("commit finalization is idempotent",
        orbit_package_filesystem_finalize(
            target_fd, stage_fd, backup_fd, &change) == ORBIT_FILESYSTEM_OK);

    EXPECT("removal target created", write_file_at(target_fd, "remove.dylib", "remove-me"));
    EXPECT("removal change prepared",
        orbit_package_filesystem_prepare_remove(
            target_fd, "remove.dylib", backup_fd, "remove.backup",
            &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("removal applied",
        orbit_package_filesystem_apply(
            target_fd, -1, backup_fd, &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("removed target absent", !exists_at(target_fd, "remove.dylib"));
    EXPECT("removed preimage retained", file_equals_at(backup_fd, "remove.backup", "remove-me"));
    EXPECT("removal rollback restores file",
        orbit_package_filesystem_rollback(
            target_fd, -1, backup_fd, &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("restored removal target matches", file_equals_at(target_fd, "remove.dylib", "remove-me"));

    EXPECT("final removal target created", write_file_at(target_fd, "final-remove", "gone"));
    EXPECT("final removal change prepared",
        orbit_package_filesystem_prepare_remove(
            target_fd, "final-remove", backup_fd, "final-remove.backup",
            &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("final removal applied",
        orbit_package_filesystem_apply(
            target_fd, -1, backup_fd, &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("final removal finalized",
        orbit_package_filesystem_finalize(
            target_fd, -1, backup_fd, &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("final removal backup deleted",
        !exists_at(backup_fd, "final-remove.backup"));

    EXPECT("hard-link target created", write_file_at(target_fd, "hardlinked", "shared"));
    EXPECT("foreign hard link created", linkat(target_fd, "hardlinked", target_fd, "hardlinked-alias", 0) == 0);
    EXPECT("hard-linked target rejected",
        orbit_package_filesystem_prepare_remove(
            target_fd, "hardlinked", backup_fd, "hardlinked.backup",
            &change) == ORBIT_FILESYSTEM_CONFLICT);
    EXPECT("symlink target created", symlinkat("/etc/passwd", target_fd, "symlink-target") == 0);
    EXPECT("symlink target rejected",
        orbit_package_filesystem_prepare_remove(
            target_fd, "symlink-target", backup_fd, "symlink.backup",
            &change) == ORBIT_FILESYSTEM_CONFLICT);
    EXPECT("symlink stage created", symlinkat("/etc/passwd", stage_fd, "symlink-stage") == 0);
    EXPECT("symlink staged source rejected",
        orbit_package_filesystem_prepare_replace(
            target_fd, "symlink-output", stage_fd, "symlink-stage",
            backup_fd, "symlink.backup", &change) == ORBIT_FILESYSTEM_CONFLICT);

    EXPECT("backup collision fixture created", write_file_at(backup_fd, "occupied.backup", "keep"));
    EXPECT("occupied backup path rejected",
        orbit_package_filesystem_prepare_remove(
            target_fd, "remove.dylib", backup_fd, "occupied.backup",
            &change) == ORBIT_FILESYSTEM_CONFLICT);

    EXPECT("foreign replacement fixture created", write_file_at(target_fd, "foreign-change", "original"));
    EXPECT("foreign-change staged fixture created", write_file_at(stage_fd, "foreign-stage", "intended"));
    EXPECT("foreign-change prepared",
        orbit_package_filesystem_prepare_replace(
            target_fd, "foreign-change", stage_fd, "foreign-stage",
            backup_fd, "foreign-backup", &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("foreign-change applied",
        orbit_package_filesystem_apply(
            target_fd, stage_fd, backup_fd, &change) == ORBIT_FILESYSTEM_OK);
    EXPECT("foreign actor replacement fixture",
        remove_if_present(target_fd, "foreign-change") &&
        write_file_at(target_fd, "foreign-change", "foreign"));
    EXPECT("rollback refuses to delete a foreign replacement",
        orbit_package_filesystem_rollback(
            target_fd, stage_fd, backup_fd, &change) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);

    close(backup_fd);
    close(stage_fd);
    close(target_fd);

    /* Remove the known test fixtures without following links. */
    int cleanup_target = openat(base_fd, "target", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int cleanup_stage = openat(base_fd, "stage", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int cleanup_backup = openat(base_fd, "backup", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    const char *target_names[] = {
        "existing.dylib", "commit.dylib", "remove.dylib",
        "hardlinked", "hardlinked-alias", "symlink-target", "foreign-change"
    };
    if (cleanup_target >= 0) {
        for (size_t i = 0U; i < sizeof(target_names) / sizeof(target_names[0]); ++i)
            (void)unlinkat(cleanup_target, target_names[i], 0);
        close(cleanup_target);
    }
    const char *stage_names[] = { "symlink-stage", "foreign-stage" };
    if (cleanup_stage >= 0) {
        for (size_t i = 0U; i < sizeof(stage_names) / sizeof(stage_names[0]); ++i)
            (void)unlinkat(cleanup_stage, stage_names[i], 0);
        close(cleanup_stage);
    }
    const char *backup_names[] = { "foreign-backup", "occupied.backup" };
    if (cleanup_backup >= 0) {
        for (size_t i = 0U; i < sizeof(backup_names) / sizeof(backup_names[0]); ++i)
            (void)unlinkat(cleanup_backup, backup_names[i], 0);
        close(cleanup_backup);
    }
    (void)unlinkat(base_fd, "target", AT_REMOVEDIR);
    (void)unlinkat(base_fd, "stage", AT_REMOVEDIR);
    (void)unlinkat(base_fd, "backup", AT_REMOVEDIR);
    close(base_fd);
    EXPECT("temporary transaction root removed", rmdir(base_path) == 0);

    printf("filesystem_checks=%u failures=%u\ndecision=%s\n",
           checks, failures, failures == 0U ? "PASS" : "FAIL");
    return failures == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
