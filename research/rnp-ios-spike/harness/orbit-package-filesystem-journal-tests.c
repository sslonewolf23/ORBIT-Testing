#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include "ORBITPackageFilesystemJournal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool fail_next_fsync;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (fail_next_fsync) {
        fail_next_fsync = false;
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}

static unsigned checks;
static unsigned failures;
#define EXPECT(label, condition) do { ++checks; if (!(condition)) { ++failures; \
    fprintf(stderr, "FAIL: %s\n", label); } } while (0)

typedef struct {
    orbit_package_filesystem_journal_record *record;
    uint64_t last_revision;
    size_t store_calls;
    size_t fail_store_call;
    bool fail_clear_once;
} memory_journal;

typedef struct {
    int target_fd;
    int stage_fd;
    int backup_fd;
    size_t apply_calls;
    size_t fail_apply_call;
    bool fail_after_apply;
    bool fail_rollback_once;
    bool fail_finalize_once;
} filesystem_executor;

static orbit_file_journal_load_result memory_load(
    void *context, orbit_package_filesystem_journal_record *record,
    uint64_t *last_revision) {
    memory_journal *memory = (memory_journal *)context;
    if (!memory || !record || !last_revision)
        return ORBIT_FILE_JOURNAL_LOAD_ERROR;
    *last_revision = memory->last_revision;
    if (!memory->record) return ORBIT_FILE_JOURNAL_LOAD_EMPTY;
    memcpy(record, memory->record, sizeof(*record));
    return ORBIT_FILE_JOURNAL_LOAD_PRESENT;
}

static bool memory_store(
    void *context, const orbit_package_filesystem_journal_record *record) {
    memory_journal *memory = (memory_journal *)context;
    if (!memory || !record || record->revision != memory->last_revision + 1U)
        return false;
    if (memory->record && memory->record->revision != memory->last_revision)
        return false;
    ++memory->store_calls;
    if (memory->fail_store_call != 0U &&
        memory->store_calls == memory->fail_store_call)
        return false;
    orbit_package_filesystem_journal_record *copy =
        (orbit_package_filesystem_journal_record *)malloc(sizeof(*copy));
    if (!copy) return false;
    memcpy(copy, record, sizeof(*copy));
    free(memory->record);
    memory->record = copy;
    memory->last_revision = record->revision;
    return true;
}

static bool memory_clear(void *context, uint64_t expected_revision) {
    memory_journal *memory = (memory_journal *)context;
    if (!memory || !memory->record ||
        memory->record->revision != expected_revision ||
        memory->last_revision != expected_revision)
        return false;
    if (memory->fail_clear_once) {
        memory->fail_clear_once = false;
        return false;
    }
    free(memory->record);
    memory->record = NULL;
    return true;
}

static bool write_file_at(int directory_fd, const char *name,
                          const char *contents) {
    int fd = openat(directory_fd, name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t length = strlen(contents), offset = 0U;
    while (offset < length) {
        ssize_t amount = write(fd, contents + offset, length - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) { close(fd); return false; }
        offset += (size_t)amount;
    }
    bool synced = fsync(fd) == 0;
    bool closed = close(fd) == 0;
    return synced && closed;
}

static bool file_equals_at(int directory_fd, const char *name,
                           const char *expected) {
    int fd = openat(directory_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    char buffer[128];
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

static orbit_filesystem_code execute_change(
    void *context,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    orbit_file_journal_action action,
    const orbit_package_file_change *change) {
    (void)transaction_id;
    filesystem_executor *executor = (filesystem_executor *)context;
    if (!executor || !change) return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    if (action == ORBIT_FILE_JOURNAL_APPLY) {
        ++executor->apply_calls;
        if (executor->fail_apply_call == executor->apply_calls &&
            !executor->fail_after_apply)
            return ORBIT_FILESYSTEM_IO_ERROR;
        orbit_filesystem_code result = orbit_package_filesystem_apply(
            executor->target_fd, executor->stage_fd,
            executor->backup_fd, change);
        if (result == ORBIT_FILESYSTEM_OK &&
            executor->fail_apply_call == executor->apply_calls &&
            executor->fail_after_apply)
            return ORBIT_FILESYSTEM_IO_ERROR;
        return result;
    }
    if (action == ORBIT_FILE_JOURNAL_ROLLBACK) {
        if (executor->fail_rollback_once) {
            executor->fail_rollback_once = false;
            return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        }
        return orbit_package_filesystem_rollback(
            executor->target_fd, executor->stage_fd,
            executor->backup_fd, change);
    }
    if (action == ORBIT_FILE_JOURNAL_FINALIZE) {
        if (executor->fail_finalize_once) {
            executor->fail_finalize_once = false;
            return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        }
        return orbit_package_filesystem_finalize(
            executor->target_fd, executor->stage_fd,
            executor->backup_fd, change);
    }
    return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
}

static bool prepare_pair(
    int target_fd, int stage_fd, int backup_fd,
    const char *target_a, const char *stage_a, const char *backup_a,
    const char *target_b, const char *backup_b,
    orbit_package_file_change changes[2]) {
    if (orbit_package_filesystem_prepare_replace(
            target_fd, target_a, stage_fd, stage_a, backup_fd, backup_a,
            &changes[0]) != ORBIT_FILESYSTEM_OK)
        return false;
    if (orbit_package_filesystem_prepare_remove(
            target_fd, target_b, backup_fd, backup_b,
            &changes[1]) != ORBIT_FILESYSTEM_OK)
        return false;
    return true;
}

static bool seed_pair(
    int target_fd, int stage_fd,
    const char *target_a, const char *stage_a, const char *target_b) {
    return write_file_at(target_fd, target_a, "old-a") &&
           write_file_at(stage_fd, stage_a, "new-a") &&
           write_file_at(target_fd, target_b, "old-b");
}

static void cleanup_names(int directory_fd, const char *const *names,
                          size_t count) {
    for (size_t i = 0U; i < count; ++i)
        (void)unlinkat(directory_fd, names[i], 0);
}

int main(void) {
    char temporary_directory[] = "/tmp/orbit-file-journal-XXXXXX";
    char *base_path = mkdtemp(temporary_directory);
    EXPECT("temporary journal root created", base_path != NULL);
    if (!base_path) return EXIT_FAILURE;
    int base_fd = open(base_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("journal root opened", base_fd >= 0);
    if (base_fd < 0) { (void)rmdir(base_path); return EXIT_FAILURE; }

    orbit_package_filesystem_lock lock_one = { -1 };
    orbit_package_filesystem_lock lock_two = { -1 };
    EXPECT("group/world-writable transaction root is rejected",
        fchmod(base_fd, 0777) == 0 &&
        orbit_package_filesystem_lock_acquire(base_fd, &lock_one) ==
            ORBIT_FILESYSTEM_CONFLICT);
    EXPECT("private transaction root permissions restored",
        fchmod(base_fd, 0700) == 0);
    EXPECT("exclusive package lock acquired",
        orbit_package_filesystem_lock_acquire(base_fd, &lock_one) ==
            ORBIT_FILESYSTEM_OK);
    EXPECT("second package lock is rejected as busy",
        orbit_package_filesystem_lock_acquire(base_fd, &lock_two) ==
            ORBIT_FILESYSTEM_BUSY);
    EXPECT("first package lock released",
        orbit_package_filesystem_lock_release(&lock_one) == ORBIT_FILESYSTEM_OK);
    EXPECT("package lock can be acquired after release",
        orbit_package_filesystem_lock_acquire(base_fd, &lock_two) ==
            ORBIT_FILESYSTEM_OK);
    EXPECT("second package lock released",
        orbit_package_filesystem_lock_release(&lock_two) == ORBIT_FILESYSTEM_OK);

    uint8_t backup_transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xA1U };
    int transaction_backup_fd = -1;
    EXPECT("transaction backup directory created with private identity",
        orbit_package_filesystem_open_backup_directory(
            base_fd, backup_transaction_id, true,
            &transaction_backup_fd) == ORBIT_FILESYSTEM_OK);
    EXPECT("transaction backup directory descriptor returned",
        transaction_backup_fd >= 0);
    if (transaction_backup_fd >= 0) close(transaction_backup_fd);
    transaction_backup_fd = -1;
    EXPECT("transaction backup directory reopens without creation",
        orbit_package_filesystem_open_backup_directory(
            base_fd, backup_transaction_id, false,
            &transaction_backup_fd) == ORBIT_FILESYSTEM_OK);
    if (transaction_backup_fd >= 0) close(transaction_backup_fd);
    uint8_t empty_transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0U };
    EXPECT("zero transaction ID cannot open a backup directory",
        orbit_package_filesystem_open_backup_directory(
            base_fd, empty_transaction_id, true,
            &transaction_backup_fd) == ORBIT_FILESYSTEM_INVALID_ARGUMENT);
    uint8_t stale_transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xC1U };
    EXPECT("stale backup directory initially created",
        orbit_package_filesystem_open_backup_directory(
            base_fd, stale_transaction_id, true,
            &transaction_backup_fd) == ORBIT_FILESYSTEM_OK);
    EXPECT("stale backup sentinel created",
        transaction_backup_fd >= 0 &&
        write_file_at(transaction_backup_fd, "stale", "unexpected"));
    if (transaction_backup_fd >= 0) close(transaction_backup_fd);
    transaction_backup_fd = -1;
    EXPECT("new transaction refuses nonempty backup directory",
        orbit_package_filesystem_open_backup_directory(
            base_fd, stale_transaction_id, true,
            &transaction_backup_fd) == ORBIT_FILESYSTEM_CONFLICT);
    EXPECT("repeated emptiness inspection still detects stale contents",
        orbit_package_filesystem_open_backup_directory(
            base_fd, stale_transaction_id, true,
            &transaction_backup_fd) == ORBIT_FILESYSTEM_CONFLICT);
    int stale_directory_fd = openat(base_fd,
        "c1000000000000000000000000000000",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (stale_directory_fd >= 0) {
        (void)unlinkat(stale_directory_fd, "stale", 0);
        close(stale_directory_fd);
    }
    (void)unlinkat(base_fd, "c1000000000000000000000000000000", AT_REMOVEDIR);
    uint8_t symlink_transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xB1U };
    EXPECT("transaction backup symlink fixture created",
        symlinkat("target", base_fd,
            "b1000000000000000000000000000000") == 0);
    EXPECT("transaction backup opener refuses symlink directory",
        orbit_package_filesystem_open_backup_directory(
            base_fd, symlink_transaction_id, false,
            &transaction_backup_fd) != ORBIT_FILESYSTEM_OK);
    (void)unlinkat(base_fd, "b1000000000000000000000000000000", 0);

    EXPECT("target directory created", mkdirat(base_fd, "target", 0700) == 0);
    EXPECT("stage directory created", mkdirat(base_fd, "stage", 0700) == 0);
    EXPECT("backup directory created", mkdirat(base_fd, "backup", 0700) == 0);
    int target_fd = openat(base_fd, "target", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int stage_fd = openat(base_fd, "stage", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int backup_fd = openat(base_fd, "backup", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("transaction roots opened",
        target_fd >= 0 && stage_fd >= 0 && backup_fd >= 0);
    if (target_fd < 0 || stage_fd < 0 || backup_fd < 0) return EXIT_FAILURE;

    orbit_package_filesystem_journal_backend backend;
    memory_journal memory;
    memset(&memory, 0, sizeof(memory));
    backend.context = &memory;
    backend.load = memory_load;
    backend.store_atomic = memory_store;
    backend.clear_atomic = memory_clear;

    uint8_t nonempty_cleanup_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xC2U };
    int nonempty_cleanup_fd = -1;
    EXPECT("nonempty cleanup fixture directory created",
        orbit_package_filesystem_open_backup_directory(
            base_fd, nonempty_cleanup_id, true,
            &nonempty_cleanup_fd) == ORBIT_FILESYSTEM_OK);
    EXPECT("nonempty cleanup sentinel created",
        nonempty_cleanup_fd >= 0 &&
        write_file_at(nonempty_cleanup_fd, "preserve", "do-not-delete"));
    if (nonempty_cleanup_fd >= 0) close(nonempty_cleanup_fd);
    EXPECT("empty-journal cleanup still refuses a nonempty backup directory",
        orbit_package_filesystem_journal_cleanup_backup_directory(
            &backend, base_fd, nonempty_cleanup_id) ==
            ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    nonempty_cleanup_fd = openat(base_fd,
        "c2000000000000000000000000000000",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (nonempty_cleanup_fd >= 0) {
        (void)unlinkat(nonempty_cleanup_fd, "preserve", 0);
        close(nonempty_cleanup_fd);
    }
    (void)unlinkat(base_fd, "c2000000000000000000000000000000", AT_REMOVEDIR);

    uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xA1U };
    orbit_package_file_change changes[2];
    EXPECT("successful transaction fixtures created",
        seed_pair(target_fd, stage_fd, "ok-a", "ok-a-stage", "ok-b"));
    EXPECT("successful transaction plan prepared",
        prepare_pair(target_fd, stage_fd, backup_fd,
            "ok-a", "ok-a-stage", "ok-a-backup",
            "ok-b", "ok-b-backup", changes));
    filesystem_executor executor = { target_fd, stage_fd, backup_fd, 0U, 0U, false, false, false };
    EXPECT("complete file transaction applies commits and clears journal",
        orbit_package_filesystem_journal_execute(
            &backend, transaction_id, changes, 2U,
            execute_change, &executor) == ORBIT_FILESYSTEM_OK);
    EXPECT("successful transaction installed first file",
        file_equals_at(target_fd, "ok-a", "new-a"));
    EXPECT("successful transaction removed second file",
        !exists_at(target_fd, "ok-b"));
    EXPECT("successful transaction cleared preimage backups",
        !exists_at(backup_fd, "ok-a-backup") &&
        !exists_at(backup_fd, "ok-b-backup"));
    EXPECT("empty journal recovery is a no-op",
        orbit_package_filesystem_journal_recover(
            &backend, execute_change, &executor) == ORBIT_FILESYSTEM_OK);

    EXPECT("rollback transaction fixtures created",
        seed_pair(target_fd, stage_fd, "rb-a", "rb-a-stage", "rb-b"));
    EXPECT("rollback transaction plan prepared",
        prepare_pair(target_fd, stage_fd, backup_fd,
            "rb-a", "rb-a-stage", "rb-a-backup",
            "rb-b", "rb-b-backup", changes));
    executor.apply_calls = 0U;
    executor.fail_apply_call = 2U;
    executor.fail_after_apply = true;
    executor.fail_rollback_once = true;
    EXPECT("failed apply with rollback interruption retains journal",
        orbit_package_filesystem_journal_execute(
            &backend, transaction_id, changes, 2U,
            execute_change, &executor) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    EXPECT("rollback interruption leaves durable rolling-back phase",
        memory.record != NULL &&
        memory.record->phase == ORBIT_FILE_JOURNAL_ROLLING_BACK);
    executor.fail_apply_call = 0U;
    executor.fail_after_apply = false;
    EXPECT("recovery retries reverse rollback and clears journal",
        orbit_package_filesystem_journal_recover(
            &backend, execute_change, &executor) == ORBIT_FILESYSTEM_OK);
    EXPECT("recovery restored first preimage",
        file_equals_at(target_fd, "rb-a", "old-a"));
    EXPECT("recovery restored second preimage",
        file_equals_at(target_fd, "rb-b", "old-b"));

    EXPECT("commit-store-failure fixtures created",
        seed_pair(target_fd, stage_fd, "st-a", "st-a-stage", "st-b"));
    EXPECT("commit-store-failure plan prepared",
        prepare_pair(target_fd, stage_fd, backup_fd,
            "st-a", "st-a-stage", "st-a-backup",
            "st-b", "st-b-backup", changes));
    executor.apply_calls = 0U;
    executor.fail_rollback_once = false;
    memory.fail_store_call = memory.store_calls + 2U;
    EXPECT("failed COMMITTED journal write leaves APPLYING record",
        orbit_package_filesystem_journal_execute(
            &backend, transaction_id, changes, 2U,
            execute_change, &executor) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    EXPECT("failed commit transition remains recoverable as APPLYING",
        memory.record != NULL &&
        memory.record->phase == ORBIT_FILE_JOURNAL_APPLYING);
    memory.fail_store_call = 0U;
    EXPECT("APPLYING recovery rolls back all file changes",
        orbit_package_filesystem_journal_recover(
            &backend, execute_change, &executor) == ORBIT_FILESYSTEM_OK);
    EXPECT("APPLYING recovery restored both preimages",
        file_equals_at(target_fd, "st-a", "old-a") &&
        file_equals_at(target_fd, "st-b", "old-b"));

    EXPECT("partial-finalization fixtures created",
        seed_pair(target_fd, stage_fd, "pf-a", "pf-a-stage", "pf-b"));
    EXPECT("partial-finalization plan prepared",
        prepare_pair(target_fd, stage_fd, backup_fd,
            "pf-a", "pf-a-stage", "pf-a-backup",
            "pf-b", "pf-b-backup", changes));
    executor.apply_calls = 0U;
    executor.fail_finalize_once = true;
    EXPECT("interrupted committed cleanup retains journal",
        orbit_package_filesystem_journal_execute(
            &backend, transaction_id, changes, 2U,
            execute_change, &executor) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    EXPECT("partial cleanup remains in committed phase",
        memory.record != NULL &&
        memory.record->phase == ORBIT_FILE_JOURNAL_COMMITTED);
    uint8_t guarded_cleanup_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xE1U };
    int guarded_cleanup_fd = -1;
    EXPECT("guarded cleanup fixture directory created",
        orbit_package_filesystem_open_backup_directory(
            base_fd, guarded_cleanup_id, true,
            &guarded_cleanup_fd) == ORBIT_FILESYSTEM_OK);
    if (guarded_cleanup_fd >= 0) close(guarded_cleanup_fd);
    EXPECT("backup cleanup is blocked while any journal is active",
        orbit_package_filesystem_journal_cleanup_backup_directory(
            &backend, base_fd, guarded_cleanup_id) ==
            ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    EXPECT("orphan sweep is blocked while any journal is active",
        orbit_package_filesystem_journal_cleanup_orphan_backup_directories(
            &backend, base_fd) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    EXPECT("committed recovery completes remaining backup cleanup",
        orbit_package_filesystem_journal_recover(
            &backend, execute_change, &executor) == ORBIT_FILESYSTEM_OK);
    EXPECT("empty journal permits guarded empty backup cleanup",
        orbit_package_filesystem_journal_cleanup_backup_directory(
            &backend, base_fd, guarded_cleanup_id) == ORBIT_FILESYSTEM_OK);
    EXPECT("post-tombstone orphan sweep removes empty backup directories",
        orbit_package_filesystem_journal_cleanup_orphan_backup_directories(
            &backend, base_fd) == ORBIT_FILESYSTEM_OK);
    EXPECT("post-tombstone crash-window directory is gone",
        !exists_at(base_fd, "e1000000000000000000000000000000"));
    EXPECT("partial-finalization recovery preserves committed package state",
        file_equals_at(target_fd, "pf-a", "new-a") &&
        !exists_at(target_fd, "pf-b") &&
        !exists_at(backup_fd, "pf-a-backup") &&
        !exists_at(backup_fd, "pf-b-backup"));

    EXPECT("clear-failure fixtures created",
        seed_pair(target_fd, stage_fd, "cl-a", "cl-a-stage", "cl-b"));
    EXPECT("clear-failure plan prepared",
        prepare_pair(target_fd, stage_fd, backup_fd,
            "cl-a", "cl-a-stage", "cl-a-backup",
            "cl-b", "cl-b-backup", changes));
    executor.apply_calls = 0U;
    memory.fail_clear_once = true;
    EXPECT("failed journal clear retains COMMITTED record",
        orbit_package_filesystem_journal_execute(
            &backend, transaction_id, changes, 2U,
            execute_change, &executor) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    EXPECT("clear failure leaves committed phase",
        memory.record != NULL &&
        memory.record->phase == ORBIT_FILE_JOURNAL_COMMITTED);
    EXPECT("committed recovery retries finalization and clears",
        orbit_package_filesystem_journal_recover(
            &backend, execute_change, &executor) == ORBIT_FILESYSTEM_OK);
    EXPECT("committed recovery leaves installed result",
        file_equals_at(target_fd, "cl-a", "new-a") &&
        !exists_at(target_fd, "cl-b"));
    EXPECT("committed recovery removes backup links",
        !exists_at(backup_fd, "cl-a-backup") &&
        !exists_at(backup_fd, "cl-b-backup"));

    EXPECT("standard executor fixtures created",
        write_file_at(target_fd, "std-target", "old-standard") &&
        write_file_at(stage_fd, "std-stage", "new-standard"));
    uint8_t standard_transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xD1U };
    int standard_backup_fd = -1;
    EXPECT("standard transaction backup directory created",
        orbit_package_filesystem_open_backup_directory(
            base_fd, standard_transaction_id, true,
            &standard_backup_fd) == ORBIT_FILESYSTEM_OK);
    orbit_package_file_change standard_change;
    EXPECT("standard executor replacement plan prepared",
        standard_backup_fd >= 0 &&
        orbit_package_filesystem_prepare_replace(
            target_fd, "std-target", stage_fd, "std-stage",
            standard_backup_fd, "std-backup", &standard_change) ==
            ORBIT_FILESYSTEM_OK);
    if (standard_backup_fd >= 0) close(standard_backup_fd);
    EXPECT("standard executor parent locators stored",
        orbit_package_filesystem_set_parent_paths(
            &standard_change, "", "") == ORBIT_FILESYSTEM_OK);
    orbit_package_filesystem_executor_context standard_executor;
    memset(&standard_executor, 0, sizeof(standard_executor));
    standard_executor.install_root_fd = target_fd;
    standard_executor.staging_root_fd = stage_fd;
    standard_executor.backup_base_directory_fd = base_fd;
    memcpy(standard_executor.transaction_id, standard_transaction_id,
           sizeof(standard_transaction_id));
    EXPECT("standard descriptor-resolving executor commits file replacement",
        orbit_package_filesystem_journal_execute(
            &backend, standard_transaction_id, &standard_change, 1U,
            orbit_package_filesystem_journal_execute_change,
            &standard_executor) == ORBIT_FILESYSTEM_OK);
    EXPECT("standard executor installed staged file",
        file_equals_at(target_fd, "std-target", "new-standard"));
    EXPECT("standard executor consumed staged path",
        !exists_at(stage_fd, "std-stage"));
    standard_backup_fd = -1;
    EXPECT("standard executor backup directory reopens",
        orbit_package_filesystem_open_backup_directory(
            base_fd, standard_transaction_id, false,
            &standard_backup_fd) == ORBIT_FILESYSTEM_OK);
    EXPECT("standard executor finalized preimage backup",
        standard_backup_fd >= 0 && !exists_at(standard_backup_fd, "std-backup"));
    if (standard_backup_fd >= 0) close(standard_backup_fd);
    EXPECT("successful transaction permits cleanup after journal is empty",
        orbit_package_filesystem_journal_cleanup_backup_directory(
            &backend, base_fd, standard_transaction_id) ==
            ORBIT_FILESYSTEM_OK);
    EXPECT("successful transaction removes its empty backup directory",
        fstatat(base_fd, "d1000000000000000000000000000000",
                &(struct stat){0}, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);

    uint8_t tombstone_window_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xE2U };
    int tombstone_window_fd = -1;
    EXPECT("simulated tombstone-to-cleanup crash leaves empty transaction directory",
        orbit_package_filesystem_open_backup_directory(
            base_fd, tombstone_window_id, true, &tombstone_window_fd) ==
            ORBIT_FILESYSTEM_OK);
    if (tombstone_window_fd >= 0) close(tombstone_window_fd);
    EXPECT("orphan sweep recovers tombstone-to-cleanup crash window",
        orbit_package_filesystem_journal_cleanup_orphan_backup_directories(
            &backend, base_fd) == ORBIT_FILESYSTEM_OK);
    EXPECT("orphan transaction directory removed after durable empty journal",
        !exists_at(base_fd, "e2000000000000000000000000000000"));

    uint8_t orphan_a_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xA2U };
    uint8_t orphan_b_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xA3U };
    int orphan_a_fd = -1, orphan_b_fd = -1;
    EXPECT("multiple orphan candidate directories created",
        orbit_package_filesystem_open_backup_directory(
            base_fd, orphan_a_id, true, &orphan_a_fd) == ORBIT_FILESYSTEM_OK &&
        orbit_package_filesystem_open_backup_directory(
            base_fd, orphan_b_id, true, &orphan_b_fd) == ORBIT_FILESYSTEM_OK);
    if (orphan_a_fd >= 0) close(orphan_a_fd);
    if (orphan_b_fd >= 0) close(orphan_b_fd);
    EXPECT("noncanonical directory fixture created",
        mkdirat(base_fd, "not-a-transaction-directory", 0700) == 0);
    EXPECT("orphan sweep removes every collected candidate",
        orbit_package_filesystem_journal_cleanup_orphan_backup_directories(
            &backend, base_fd) == ORBIT_FILESYSTEM_OK);
    EXPECT("orphan sweep removes both canonical candidates",
        !exists_at(base_fd, "a2000000000000000000000000000000") &&
        !exists_at(base_fd, "a3000000000000000000000000000000"));
    EXPECT("orphan sweep leaves noncanonical directories untouched",
        exists_at(base_fd, "not-a-transaction-directory"));
    EXPECT("noncanonical fixture removed",
        unlinkat(base_fd, "not-a-transaction-directory", AT_REMOVEDIR) == 0);


    uint8_t nonempty_orphan_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xA4U };
    int nonempty_orphan_fd = -1;
    EXPECT("nonempty orphan candidate created",
        orbit_package_filesystem_open_backup_directory(
            base_fd, nonempty_orphan_id, true,
            &nonempty_orphan_fd) == ORBIT_FILESYSTEM_OK);
    EXPECT("nonempty orphan sentinel created",
        nonempty_orphan_fd >= 0 &&
        write_file_at(nonempty_orphan_fd, "sentinel", "preserve"));
    if (nonempty_orphan_fd >= 0) close(nonempty_orphan_fd);
    EXPECT("orphan sweep refuses nonempty candidate",
        orbit_package_filesystem_journal_cleanup_orphan_backup_directories(
            &backend, base_fd) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    nonempty_orphan_fd = openat(base_fd,
        "a4000000000000000000000000000000",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("nonempty orphan candidate and sentinel are preserved",
        nonempty_orphan_fd >= 0 &&
        file_equals_at(nonempty_orphan_fd, "sentinel", "preserve"));
    if (nonempty_orphan_fd >= 0) {
        (void)unlinkat(nonempty_orphan_fd, "sentinel", 0);
        close(nonempty_orphan_fd);
    }
    (void)unlinkat(base_fd, "a4000000000000000000000000000000", AT_REMOVEDIR);

    EXPECT("canonical symlink orphan fixture created",
        symlinkat("missing-target", base_fd,
            "a5000000000000000000000000000000") == 0);
    EXPECT("orphan sweep refuses symlink candidate",
        orbit_package_filesystem_journal_cleanup_orphan_backup_directories(
            &backend, base_fd) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    struct stat symlink_status;
    EXPECT("symlink candidate remains untouched",
        fstatat(base_fd, "a5000000000000000000000000000000",
                &symlink_status, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISLNK(symlink_status.st_mode));
    (void)unlinkat(base_fd, "a5000000000000000000000000000000", 0);

    const unsigned oversized_candidate_count = 4097U;
    char oversized_name[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES * 2U + 1U];
    unsigned oversized_created = 0U;
    for (unsigned i = 0U; i < oversized_candidate_count; ++i) {
        (void)snprintf(oversized_name, sizeof(oversized_name), "%032x", i + 1U);
        if (mkdirat(base_fd, oversized_name, 0700) != 0) break;
        ++oversized_created;
    }
    EXPECT("all over-limit canonical candidates created",
        oversized_created == oversized_candidate_count);
    EXPECT("orphan sweep rejects more than 4096 candidates",
        oversized_created == oversized_candidate_count &&
        orbit_package_filesystem_journal_cleanup_orphan_backup_directories(
            &backend, base_fd) == ORBIT_FILESYSTEM_LIMIT);
    (void)snprintf(oversized_name, sizeof(oversized_name), "%032x", 1U);
    EXPECT("over-limit sweep deletes no candidates",
        exists_at(base_fd, oversized_name));
    for (unsigned i = 0U; i < oversized_created; ++i) {
        (void)snprintf(oversized_name, sizeof(oversized_name), "%032x", i + 1U);
        (void)unlinkat(base_fd, oversized_name, AT_REMOVEDIR);
    }


    uint8_t fsync_failure_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] = { 0xA6U };
    int fsync_failure_fd = -1;
    EXPECT("fsync failure orphan fixture created",
        orbit_package_filesystem_open_backup_directory(
            base_fd, fsync_failure_id, true,
            &fsync_failure_fd) == ORBIT_FILESYSTEM_OK);
    if (fsync_failure_fd >= 0) close(fsync_failure_fd);
    fail_next_fsync = true;
    EXPECT("orphan sweep reports directory fsync failure",
        orbit_package_filesystem_journal_cleanup_orphan_backup_directories(
            &backend, base_fd) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    EXPECT("fsync failure injection was consumed",
        !fail_next_fsync);
    EXPECT("case-fold duplicate fixture prepared",
        seed_pair(target_fd, stage_fd, "dup-a", "dup-a-stage", "dup-b") &&
        prepare_pair(target_fd, stage_fd, backup_fd,
            "dup-a", "dup-a-stage", "dup-a-backup",
            "dup-b", "dup-b-backup", changes));
    orbit_package_file_change duplicate_changes[2];
    duplicate_changes[0] = changes[0];
    duplicate_changes[1] = changes[0];
    memcpy(duplicate_changes[1].target_name, "DUP-A", 6U);
    EXPECT("case-folded duplicate targets rejected before journaling",
        orbit_package_filesystem_journal_execute(
            &backend, transaction_id, duplicate_changes, 2U,
            execute_change, &executor) == ORBIT_FILESYSTEM_INVALID_ARGUMENT);
    EXPECT("duplicate plan did not create journal", memory.record == NULL);

    duplicate_changes[1] = changes[0];
    (void)strcpy(duplicate_changes[1].target_name, "dup-other-target");
    (void)strcpy(duplicate_changes[1].staged_name, "dup-other-stage");
    EXPECT("duplicate backup locators rejected before journaling",
        orbit_package_filesystem_journal_execute(
            &backend, transaction_id, duplicate_changes, 2U,
            execute_change, &executor) == ORBIT_FILESYSTEM_INVALID_ARGUMENT);
    duplicate_changes[1] = changes[0];
    (void)strcpy(duplicate_changes[1].target_name, "dup-other-target");
    (void)strcpy(duplicate_changes[1].backup_name, "dup-other-backup");
    EXPECT("duplicate staged locators rejected before journaling",
        orbit_package_filesystem_journal_execute(
            &backend, transaction_id, duplicate_changes, 2U,
            execute_change, &executor) == ORBIT_FILESYSTEM_INVALID_ARGUMENT);
    EXPECT("all duplicate plans leave journal empty", memory.record == NULL);

    const char *target_names[] = {
        "ok-a", "ok-b", "rb-a", "rb-b", "st-a", "st-b",
        "cl-a", "cl-b", "pf-a", "pf-b", "dup-a", "dup-b", "std-target"
    };
    const char *stage_names[] = {
        "ok-a-stage", "rb-a-stage", "st-a-stage", "cl-a-stage",
        "pf-a-stage", "dup-a-stage"
    };
    const char *backup_names[] = {
        "ok-a-backup", "ok-b-backup", "rb-a-backup", "rb-b-backup",
        "st-a-backup", "st-b-backup", "cl-a-backup", "cl-b-backup",
        "pf-a-backup", "pf-b-backup",
        "dup-a-backup", "dup-b-backup"
    };
    cleanup_names(target_fd, target_names, sizeof(target_names) / sizeof(target_names[0]));
    cleanup_names(stage_fd, stage_names, sizeof(stage_names) / sizeof(stage_names[0]));
    cleanup_names(backup_fd, backup_names, sizeof(backup_names) / sizeof(backup_names[0]));
    close(backup_fd);
    close(stage_fd);
    close(target_fd);
    (void)unlinkat(base_fd, "target", AT_REMOVEDIR);
    (void)unlinkat(base_fd, "stage", AT_REMOVEDIR);
    (void)unlinkat(base_fd, "backup", AT_REMOVEDIR);
    (void)unlinkat(base_fd, "a1000000000000000000000000000000", AT_REMOVEDIR);
    (void)unlinkat(base_fd, ORBIT_FILESYSTEM_LOCK_NAME, 0);
    close(base_fd);
    int root_remove_result = rmdir(base_path);
    if (root_remove_result != 0) {
        int root_remove_errno = errno;
        fprintf(stderr, "journal test root cleanup: rmdir errno=%d (%s)\\n",
                root_remove_errno, strerror(root_remove_errno));
        DIR *remaining_directory = opendir(base_path);
        if (remaining_directory) {
            struct dirent *entry = NULL;
            while ((entry = readdir(remaining_directory)) != NULL) {
                if (strcmp(entry->d_name, ".") != 0 &&
                    strcmp(entry->d_name, "..") != 0)
                    fprintf(stderr, "journal test root leftover: %s\\n",
                            entry->d_name);
            }
            closedir(remaining_directory);
        } else {
            fprintf(stderr, "journal test root could not be listed: %s\\n",
                    strerror(errno));
        }
        errno = root_remove_errno;
    }
    EXPECT("temporary journal root removed", root_remove_result == 0);

    free(memory.record);
    printf("filesystem_journal_checks=%u failures=%u\ndecision=%s\n",
           checks, failures, failures == 0U ? "PASS" : "FAIL");
    return failures == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
