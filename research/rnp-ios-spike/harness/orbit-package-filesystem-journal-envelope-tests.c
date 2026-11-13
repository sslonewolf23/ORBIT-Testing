#define _POSIX_C_SOURCE 200809L

#include "ORBITPackageFilesystemJournalEnvelope.h"
#include "ORBITPackageInstallTransaction.h"
#include "ORBITPackageOwnershipCodec.h"

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

static const uint8_t ownership_old[] = {
    'O','R','O','W',1U,0U,0U,0U,0U,0U,0U,0U
};
static const uint8_t ownership_new[] = {
    'O','R','O','W',1U,0U,0U,0U,0U,0U,0U,1U,
    0U,9U,'L','i','b','r','a','r','y','/','X',
    0U,5U,'p','k','g','-','x', 0U,1U,'1',
    0U,14U,'i','p','h','o','n','e','o','s','-','a','r','m','6','4', 0U
};

typedef struct {
    uint8_t *payload;
    size_t length;
    uint8_t digest[32];
    bool fail_store_once;
} memory_envelope;

typedef struct {
    int target_fd;
    int stage_fd;
    int backup_fd;
    size_t apply_calls;
    size_t rollback_calls;
    size_t finalize_calls;
    bool fail_apply_once;
    size_t fail_apply_at_call;
    bool fail_rollback_once;
    bool fail_finalize_once;
} envelope_executor;

static uint64_t payload_revision(const uint8_t *payload, size_t length) {
    if (!payload || length < 16U) return 0U;
    uint64_t value = 0U;
    for (size_t i = 8U; i < 16U; ++i)
        value = (value << 8U) | payload[i];
    return value;
}

static void fake_digest(const uint8_t *payload, size_t length, uint8_t digest[32]) {
    uint32_t state = 2166136261U;
    for (size_t i = 0U; i < length; ++i) {
        state ^= payload[i];
        state *= 16777619U;
    }
    for (size_t i = 0U; i < 32U; ++i) {
        state ^= (uint32_t)i + (uint32_t)length;
        state *= 16777619U;
        digest[i] = (uint8_t)(state >> ((i % 4U) * 8U));
    }
}

static bool memory_load(void *context, uint8_t **payload, size_t *length,
                        uint8_t digest[32]) {
    memory_envelope *memory = (memory_envelope *)context;
    if (!memory || !payload || !length || !digest || !memory->payload)
        return false;
    *payload = (uint8_t *)malloc(memory->length);
    if (!*payload) return false;
    memcpy(*payload, memory->payload, memory->length);
    *length = memory->length;
    memcpy(digest, memory->digest, sizeof(memory->digest));
    return true;
}

static void memory_release(void *context, uint8_t *payload) {
    (void)context;
    free(payload);
}

static bool memory_store(void *context, uint64_t expected_revision,
                         const uint8_t expected_digest[32],
                         const uint8_t *next_payload, size_t next_length,
                         uint8_t next_digest[32]) {
    memory_envelope *memory = (memory_envelope *)context;
    if (!memory || !memory->payload || !expected_digest ||
        !next_payload || !next_digest ||
        payload_revision(memory->payload, memory->length) != expected_revision ||
        expected_revision == UINT64_MAX ||
        payload_revision(next_payload, next_length) != expected_revision + 1U ||
        memcmp(memory->digest, expected_digest, 32U) != 0)
        return false;
    if (memory->fail_store_once) {
        memory->fail_store_once = false;
        return false;
    }
    uint8_t *copy = (uint8_t *)malloc(next_length);
    if (!copy) return false;
    memcpy(copy, next_payload, next_length);
    fake_digest(copy, next_length, next_digest);
    free(memory->payload);
    memory->payload = copy;
    memory->length = next_length;
    memcpy(memory->digest, next_digest, 32U);
    return true;
}

static bool memory_initialize(memory_envelope *memory) {
    orbit_package_transaction_envelope initial;
    memset(&initial, 0, sizeof(initial));
    initial.revision = 1U;
    initial.state = ORBIT_TRANSACTION_ENVELOPE_EMPTY;
    initial.phase = ORBIT_TRANSACTION_ENVELOPE_PHASE_NONE;
    initial.committed_ownership = ownership_old;
    initial.committed_ownership_length = sizeof(ownership_old);
    size_t length = 0U;
    if (orbit_package_transaction_envelope_encode(
            &initial, NULL, 0U, &length) !=
        ORBIT_TRANSACTION_ENVELOPE_BUFFER_TOO_SMALL)
        return false;
    memory->payload = (uint8_t *)malloc(length);
    if (!memory->payload) return false;
    if (orbit_package_transaction_envelope_encode(
            &initial, memory->payload, length, &length) !=
        ORBIT_TRANSACTION_ENVELOPE_OK) {
        free(memory->payload);
        memory->payload = NULL;
        return false;
    }
    memory->length = length;
    fake_digest(memory->payload, memory->length, memory->digest);
    return true;
}

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
    bool synced = fsync(fd) == 0;
    bool closed = close(fd) == 0;
    return synced && closed;
}

static bool file_equals_at(int directory_fd, const char *name, const char *value) {
    int fd = openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    char buffer[128];
    size_t used = 0U;
    for (;;) {
        ssize_t count = read(fd, buffer + used, sizeof(buffer) - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { close(fd); return false; }
        if (count == 0) break;
        used += (size_t)count;
        if (used == sizeof(buffer)) { close(fd); return false; }
    }
    close(fd);
    return used == strlen(value) && memcmp(buffer, value, used) == 0;
}

static orbit_filesystem_code execute_change(
    void *context,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    orbit_file_journal_action action,
    const orbit_package_file_change *change) {
    (void)transaction_id;
    envelope_executor *executor = (envelope_executor *)context;
    if (!executor || !change) return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    /* Journal entries store safe relative parent locators, not descriptors.
     * Reopen each parent beneath its trusted root for every apply/rollback/
     * finalize callback so nested package paths are executed at the intended
     * location and recovery does not depend on process-local descriptors. */
    int target_parent_fd = -1;
    int staged_parent_fd = -1;
    orbit_filesystem_code result =
        orbit_package_filesystem_open_parent_directory(
            executor->target_fd, change->target_parent_path,
            &target_parent_fd);
    bool needs_staged = change->operation == ORBIT_FILESYSTEM_REPLACE;
    if (result == ORBIT_FILESYSTEM_OK && needs_staged)
        result = orbit_package_filesystem_open_parent_directory(
            executor->stage_fd, change->staged_parent_path,
            &staged_parent_fd);
    if (result != ORBIT_FILESYSTEM_OK) {
        if (target_parent_fd >= 0) (void)close(target_parent_fd);
        return result;
    }

    if (action == ORBIT_FILE_JOURNAL_APPLY) {
        ++executor->apply_calls;
        if (executor->fail_apply_once ||
            (executor->fail_apply_at_call != 0U &&
             executor->apply_calls == executor->fail_apply_at_call)) {
            executor->fail_apply_once = false;
            executor->fail_apply_at_call = 0U;
            result = ORBIT_FILESYSTEM_IO_ERROR;
        } else {
            result = orbit_package_filesystem_apply(
                target_parent_fd, staged_parent_fd,
                executor->backup_fd, change);
        }
    } else if (action == ORBIT_FILE_JOURNAL_ROLLBACK) {
        ++executor->rollback_calls;
        if (executor->fail_rollback_once) {
            executor->fail_rollback_once = false;
            result = ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        } else {
            result = orbit_package_filesystem_rollback(
                target_parent_fd, staged_parent_fd,
                executor->backup_fd, change);
        }
    } else if (action == ORBIT_FILE_JOURNAL_FINALIZE) {
        ++executor->finalize_calls;
        if (executor->fail_finalize_once) {
            executor->fail_finalize_once = false;
            result = ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        } else {
            result = orbit_package_filesystem_finalize(
                target_parent_fd, staged_parent_fd,
                executor->backup_fd, change);
        }
    } else {
        result = ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    }

    bool staged_closed = staged_parent_fd < 0 ||
        close(staged_parent_fd) == 0;
    bool target_closed = close(target_parent_fd) == 0;
    if ((!staged_closed || !target_closed) &&
        result == ORBIT_FILESYSTEM_OK)
        return ORBIT_FILESYSTEM_IO_ERROR;
    return result;
}

static bool decode_memory(memory_envelope *memory,
                          orbit_package_transaction_envelope *envelope,
                          uint8_t *journal, uint8_t *committed, uint8_t *pending) {
    return orbit_package_transaction_envelope_decode(
        memory->payload, memory->length, journal,
        ORBIT_TRANSACTION_ENVELOPE_MAX_JOURNAL,
        committed, ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP,
        pending, ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP,
        envelope) == ORBIT_TRANSACTION_ENVELOPE_OK;
}

static bool prepare_change(int target_fd, int stage_fd, int backup_fd,
                           const char *target, const char *stage,
                           const char *backup, orbit_package_file_change *change) {
    return orbit_package_filesystem_prepare_replace(
        target_fd, target, stage_fd, stage, backup_fd, backup, change) ==
        ORBIT_FILESYSTEM_OK &&
        orbit_package_filesystem_set_parent_paths(change, "", "") ==
        ORBIT_FILESYSTEM_OK;
}

static bool create_backup_directory(int base_fd, const char *name, int *fd) {
    if (mkdirat(base_fd, name, 0700) != 0) return false;
    *fd = openat(base_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    return *fd >= 0;
}

int main(void) {
    char root_template[] = "/tmp/orbit-envelope-journal-XXXXXX";
    char *root_path = mkdtemp(root_template);
    EXPECT("temporary root created", root_path != NULL);
    if (!root_path) return EXIT_FAILURE;
    int root_fd = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("temporary root opened", root_fd >= 0);
    if (root_fd < 0) { (void)rmdir(root_path); return EXIT_FAILURE; }
    EXPECT("install root created", mkdirat(root_fd, "install", 0700) == 0);
    EXPECT("staging root created", mkdirat(root_fd, "stage", 0700) == 0);
    int install_fd = openat(root_fd, "install", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int stage_fd = openat(root_fd, "stage", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("install and staging roots opened", install_fd >= 0 && stage_fd >= 0);

    memory_envelope memory;
    memset(&memory, 0, sizeof(memory));
    EXPECT("initial authenticated-envelope fixture created", memory_initialize(&memory));
    orbit_package_filesystem_envelope_backend backend = {
        &memory, memory_load, memory_release, memory_store
    };

    uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES];
    memset(transaction_id, 0xA1, sizeof(transaction_id));
    int backup_fd = -1;
    EXPECT("success backup directory created",
        create_backup_directory(root_fd, "backup-success", &backup_fd));
    EXPECT("success fixture files created",
        write_file_at(install_fd, "target-success", "old-success") &&
        write_file_at(stage_fd, "stage-success", "new-success"));
    orbit_package_file_change change;
    EXPECT("success replacement prepared",
        prepare_change(install_fd, stage_fd, backup_fd,
            "target-success", "stage-success", "backup-success-file", &change));
    envelope_executor executor;
    memset(&executor, 0, sizeof(executor));
    executor.target_fd = install_fd;
    executor.stage_fd = stage_fd;
    executor.backup_fd = backup_fd;
    EXPECT("file and ownership commit together",
        orbit_package_filesystem_journal_execute_enveloped(
            &backend, transaction_id, &change, 1U,
            ownership_old, sizeof(ownership_old),
            ownership_new, sizeof(ownership_new),
            execute_change, &executor) == ORBIT_FILESYSTEM_OK);
    EXPECT("successful transaction applied and finalized once",
        executor.apply_calls == 1U && executor.finalize_calls == 1U);
    EXPECT("successful transaction installed target",
        file_equals_at(install_fd, "target-success", "new-success"));
    uint8_t *journal_buffer = (uint8_t *)malloc(ORBIT_TRANSACTION_ENVELOPE_MAX_JOURNAL);
    uint8_t *committed_buffer = (uint8_t *)malloc(ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP);
    uint8_t *pending_buffer = (uint8_t *)malloc(ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP);
    orbit_package_transaction_envelope decoded;
    EXPECT("successful transaction envelope decoded",
        journal_buffer && committed_buffer && pending_buffer &&
        decode_memory(&memory, &decoded, journal_buffer,
                      committed_buffer, pending_buffer));
    EXPECT("successful transaction promoted ownership and cleared journal",
        decoded.state == ORBIT_TRANSACTION_ENVELOPE_EMPTY &&
        decoded.committed_ownership_length == sizeof(ownership_new) &&
        memcmp(decoded.committed_ownership, ownership_new,
               sizeof(ownership_new)) == 0);

    close(backup_fd);
    EXPECT("success backup directory removed",
        unlinkat(root_fd, "backup-success", AT_REMOVEDIR) == 0);

    memset(transaction_id, 0xA2, sizeof(transaction_id));
    EXPECT("rollback backup directory created",
        create_backup_directory(root_fd, "backup-rollback", &backup_fd));
    EXPECT("rollback fixture files created",
        write_file_at(install_fd, "target-rollback", "old-rollback") &&
        write_file_at(stage_fd, "stage-rollback", "new-rollback"));
    EXPECT("rollback replacement prepared",
        prepare_change(install_fd, stage_fd, backup_fd,
            "target-rollback", "stage-rollback", "backup-rollback-file", &change));
    memset(&executor, 0, sizeof(executor));
    executor.target_fd = install_fd;
    executor.stage_fd = stage_fd;
    executor.backup_fd = backup_fd;
    executor.fail_apply_once = true;
    executor.fail_rollback_once = true;
    EXPECT("interrupted rollback leaves recoverable envelope",
        orbit_package_filesystem_journal_execute_enveloped(
            &backend, transaction_id, &change, 1U,
            ownership_new, sizeof(ownership_new),
            ownership_old, sizeof(ownership_old),
            execute_change, &executor) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    EXPECT("rolling-back envelope retains committed and pending snapshots",
        decode_memory(&memory, &decoded, journal_buffer,
                      committed_buffer, pending_buffer) &&
        decoded.state == ORBIT_TRANSACTION_ENVELOPE_ACTIVE &&
        decoded.phase == ORBIT_TRANSACTION_ENVELOPE_ROLLING_BACK &&
        decoded.committed_ownership_length == sizeof(ownership_new) &&
        decoded.pending_ownership_length == sizeof(ownership_old) &&
        memcmp(decoded.committed_ownership, ownership_new,
               sizeof(ownership_new)) == 0);
    EXPECT("recovery completes rollback and discards pending ownership",
        orbit_package_filesystem_journal_recover_enveloped(
            &backend, execute_change, &executor) == ORBIT_FILESYSTEM_OK);
    EXPECT("rollback recovery keeps old committed ownership",
        decode_memory(&memory, &decoded, journal_buffer,
                      committed_buffer, pending_buffer) &&
        decoded.state == ORBIT_TRANSACTION_ENVELOPE_EMPTY &&
        decoded.committed_ownership_length == sizeof(ownership_new) &&
        memcmp(decoded.committed_ownership, ownership_new,
               sizeof(ownership_new)) == 0);
    EXPECT("rollback recovery restored original target",
        file_equals_at(install_fd, "target-rollback", "old-rollback"));

    close(backup_fd);
    EXPECT("rollback backup directory removed",
        unlinkat(root_fd, "backup-rollback", AT_REMOVEDIR) == 0);

    memset(transaction_id, 0xA3, sizeof(transaction_id));
    EXPECT("commit-recovery backup directory created",
        create_backup_directory(root_fd, "backup-commit", &backup_fd));
    EXPECT("commit-recovery fixture files created",
        write_file_at(install_fd, "target-commit", "old-commit") &&
        write_file_at(stage_fd, "stage-commit", "new-commit"));
    EXPECT("commit-recovery replacement prepared",
        prepare_change(install_fd, stage_fd, backup_fd,
            "target-commit", "stage-commit", "backup-commit-file", &change));
    memset(&executor, 0, sizeof(executor));
    executor.target_fd = install_fd;
    executor.stage_fd = stage_fd;
    executor.backup_fd = backup_fd;
    executor.fail_finalize_once = true;
    EXPECT("interrupted committed finalization retains pending ownership",
        orbit_package_filesystem_journal_execute_enveloped(
            &backend, transaction_id, &change, 1U,
            ownership_new, sizeof(ownership_new),
            ownership_old, sizeof(ownership_old),
            execute_change, &executor) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    EXPECT("committed envelope keeps old ownership until finalization",
        decode_memory(&memory, &decoded, journal_buffer,
                      committed_buffer, pending_buffer) &&
        decoded.state == ORBIT_TRANSACTION_ENVELOPE_ACTIVE &&
        decoded.phase == ORBIT_TRANSACTION_ENVELOPE_COMMITTED &&
        memcmp(decoded.committed_ownership, ownership_new,
               sizeof(ownership_new)) == 0 &&
        memcmp(decoded.pending_ownership, ownership_old,
               sizeof(ownership_old)) == 0);
    EXPECT("recovery finalizes and promotes pending ownership",
        orbit_package_filesystem_journal_recover_enveloped(
            &backend, execute_change, &executor) == ORBIT_FILESYSTEM_OK);
    EXPECT("commit recovery promoted ownership only after finalization",
        decode_memory(&memory, &decoded, journal_buffer,
                      committed_buffer, pending_buffer) &&
        decoded.state == ORBIT_TRANSACTION_ENVELOPE_EMPTY &&
        decoded.committed_ownership_length == sizeof(ownership_old) &&
        memcmp(decoded.committed_ownership, ownership_old,
               sizeof(ownership_old)) == 0);
    EXPECT("commit recovery preserves installed file",
        file_equals_at(install_fd, "target-commit", "new-commit"));

    close(backup_fd);
    EXPECT("commit backup directory removed",
        unlinkat(root_fd, "backup-commit", AT_REMOVEDIR) == 0);

    memset(transaction_id, 0xA4, sizeof(transaction_id));
    EXPECT("write-ahead failure backup directory created",
        create_backup_directory(root_fd, "backup-storefail", &backup_fd));
    EXPECT("write-ahead failure fixture files created",
        write_file_at(install_fd, "target-storefail", "old-storefail") &&
        write_file_at(stage_fd, "stage-storefail", "new-storefail"));
    EXPECT("write-ahead failure replacement prepared",
        prepare_change(install_fd, stage_fd, backup_fd,
            "target-storefail", "stage-storefail", "backup-storefail-file", &change));
    memset(&executor, 0, sizeof(executor));
    executor.target_fd = install_fd;
    executor.stage_fd = stage_fd;
    executor.backup_fd = backup_fd;
    memory.fail_store_once = true;
    EXPECT("failed APPLYING envelope store blocks file mutation",
        orbit_package_filesystem_journal_execute_enveloped(
            &backend, transaction_id, &change, 1U,
            ownership_old, sizeof(ownership_old),
            ownership_new, sizeof(ownership_new),
            execute_change, &executor) == ORBIT_FILESYSTEM_RECOVERY_REQUIRED);
    EXPECT("failed write-ahead store did not invoke executor",
        executor.apply_calls == 0U &&
        file_equals_at(install_fd, "target-storefail", "old-storefail") &&
        file_equals_at(stage_fd, "stage-storefail", "new-storefail"));
    close(backup_fd);
    EXPECT("write-ahead failure backup directory removed",
        unlinkat(root_fd, "backup-storefail", AT_REMOVEDIR) == 0);

    /* Full orchestration test: staged manifest -> safe file plan ->
     * authenticated journal -> filesystem apply/finalize -> ownership commit. */
    int install_library = -1, stage_library = -1, backup_install_fd = -1;
    EXPECT("end-to-end install directories created",
        mkdirat(install_fd, "Library", 0700) == 0 &&
        mkdirat(stage_fd, "Library", 0700) == 0 &&
        create_backup_directory(root_fd, "backup-install", &backup_install_fd));
    install_library = openat(install_fd, "Library",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    stage_library = openat(stage_fd, "Library",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    EXPECT("end-to-end package directories opened",
        install_library >= 0 && stage_library >= 0);
    EXPECT("end-to-end staged package file created",
        write_file_at(stage_library, "orbit-demo.dylib", "orbit-package-payload"));

    orbit_package_record candidate;
    memset(&candidate, 0, sizeof(candidate));
    (void)snprintf(candidate.name, sizeof(candidate.name), "org.orbit.demo");
    (void)snprintf(candidate.version, sizeof(candidate.version), "1.0");
    (void)snprintf(candidate.architecture, sizeof(candidate.architecture),
                   "iphoneos-arm64");
    orbit_archive_entry manifest[2];
    memset(manifest, 0, sizeof(manifest));
    (void)snprintf(manifest[0].path, sizeof(manifest[0].path), "Library");
    manifest[0].directory = true;
    (void)snprintf(manifest[1].path, sizeof(manifest[1].path),
                   "Library/orbit-demo.dylib");
    manifest[1].size = strlen("orbit-package-payload");
    orbit_package_ownership_snapshot installed_snapshot = { NULL, 0U };
    memory_envelope install_memory;
    memset(&install_memory, 0, sizeof(install_memory));
    EXPECT("end-to-end authenticated envelope initialized",
        memory_initialize(&install_memory));
    orbit_package_filesystem_envelope_backend install_backend = {
        &install_memory, memory_load, memory_release, memory_store
    };
    envelope_executor install_executor;
    memset(&install_executor, 0, sizeof(install_executor));
    install_executor.target_fd = install_fd;
    install_executor.stage_fd = stage_fd;
    install_executor.backup_fd = backup_install_fd;
    uint8_t install_transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES];
    memset(install_transaction_id, 0xB1, sizeof(install_transaction_id));
    orbit_package_file_plan_code install_plan_result =
        ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT;
    orbit_filesystem_code install_journal_result =
        ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    orbit_package_install_transaction_code install_result =
        orbit_package_install_transaction_execute_enveloped(
            &installed_snapshot, &candidate, manifest, 2U,
            ownership_old, sizeof(ownership_old), install_transaction_id,
            install_fd, stage_fd, backup_install_fd, &install_backend,
            execute_change, &install_executor,
            &install_plan_result, &install_journal_result);
    fprintf(stderr, "DEBUG install_result=%d plan=%d journal=%d apply=%zu rollback=%zu finalize=%zu\\n",
        (int)install_result, (int)install_plan_result,
        (int)install_journal_result, install_executor.apply_calls,
        install_executor.rollback_calls, install_executor.finalize_calls);
    EXPECT("complete package install orchestration succeeds",
        install_result == ORBIT_PACKAGE_INSTALL_TRANSACTION_OK);
    EXPECT("orchestration reports successful plan and journal",
        install_plan_result == ORBIT_PACKAGE_FILE_PLAN_OK &&
        install_journal_result == ORBIT_FILESYSTEM_OK);
    EXPECT("orchestration installs staged package file",
        file_equals_at(install_library, "orbit-demo.dylib",
                       "orbit-package-payload"));
    uint8_t *install_journal_buffer =
        (uint8_t *)malloc(ORBIT_TRANSACTION_ENVELOPE_MAX_JOURNAL);
    uint8_t *install_committed_buffer =
        (uint8_t *)malloc(ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP);
    uint8_t *install_pending_buffer =
        (uint8_t *)malloc(ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP);
    orbit_package_transaction_envelope install_decoded;
    EXPECT("orchestration leaves a clean committed envelope",
        install_journal_buffer && install_committed_buffer &&
        install_pending_buffer &&
        decode_memory(&install_memory, &install_decoded,
            install_journal_buffer, install_committed_buffer,
            install_pending_buffer) &&
        install_decoded.state == ORBIT_TRANSACTION_ENVELOPE_EMPTY);
    orbit_package_ownership_record committed_records[4];
    orbit_package_ownership_snapshot committed_snapshot;
    EXPECT("orchestration persisted complete package ownership",
        orbit_package_ownership_decode(
            install_decoded.committed_ownership,
            install_decoded.committed_ownership_length,
            committed_records, 4U, &committed_snapshot) ==
                ORBIT_OWNERSHIP_CODEC_OK &&
        committed_snapshot.count == 2U &&
        strcmp(committed_snapshot.records[1].path,
               "Library/orbit-demo.dylib") == 0 &&
        strcmp(committed_snapshot.records[1].package_name,
               "org.orbit.demo") == 0);
    EXPECT("orchestration applied and finalized exactly one file",
        install_executor.apply_calls == 1U &&
        install_executor.finalize_calls == 1U);

    /* Continue with a real package removal using the committed snapshot
     * produced above. The same authenticated envelope must atomically
     * promote the post-removal ownership database. */
    memset(install_transaction_id, 0xB3, sizeof(install_transaction_id));
    orbit_package_file_plan_code remove_plan_result =
        ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT;
    orbit_filesystem_code remove_journal_result =
        ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    EXPECT("complete package removal orchestration succeeds",
        orbit_package_remove_transaction_execute_enveloped(
            &committed_snapshot, &candidate,
            install_decoded.committed_ownership,
            install_decoded.committed_ownership_length,
            install_transaction_id, install_fd, backup_install_fd,
            &install_backend, execute_change, &install_executor,
            &remove_plan_result, &remove_journal_result) ==
                ORBIT_PACKAGE_INSTALL_TRANSACTION_OK);
    EXPECT("removal reports successful plan and journal",
        remove_plan_result == ORBIT_PACKAGE_FILE_PLAN_OK &&
        remove_journal_result == ORBIT_FILESYSTEM_OK);
    EXPECT("removal deletes only the package-owned regular file",
        faccessat(install_library, "orbit-demo.dylib",
                  F_OK, AT_SYMLINK_NOFOLLOW) != 0);
    EXPECT("removal atomically commits empty package ownership",
        decode_memory(&install_memory, &install_decoded,
            install_journal_buffer, install_committed_buffer,
            install_pending_buffer) &&
        install_decoded.state == ORBIT_TRANSACTION_ENVELOPE_EMPTY &&
        orbit_package_ownership_decode(
            install_decoded.committed_ownership,
            install_decoded.committed_ownership_length,
            committed_records, 4U, &committed_snapshot) ==
                ORBIT_OWNERSHIP_CODEC_OK &&
        committed_snapshot.count == 0U);
    EXPECT("install then removal applied and finalized both transactions",
        install_executor.apply_calls == 2U &&
        install_executor.finalize_calls == 2U);
    free(install_journal_buffer);
    free(install_committed_buffer);
    free(install_pending_buffer);
    free(install_memory.payload);
    EXPECT("end-to-end backup directory cleaned",
        unlinkat(root_fd, "backup-install", AT_REMOVEDIR) == 0);
    /* A later file failure must roll back earlier mutations and leave the
     * committed ownership database at its pre-install snapshot. */
    EXPECT("rollback fixture package files staged",
        write_file_at(stage_library, "orbit-first.dylib", "first-payload") &&
        write_file_at(stage_library, "orbit-second.dylib", "second-payload"));
    orbit_archive_entry rollback_manifest[3];
    memset(rollback_manifest, 0, sizeof(rollback_manifest));
    rollback_manifest[0] = manifest[0];
    (void)snprintf(rollback_manifest[1].path,
                   sizeof(rollback_manifest[1].path),
                   "Library/orbit-first.dylib");
    rollback_manifest[1].size = strlen("first-payload");
    (void)snprintf(rollback_manifest[2].path,
                   sizeof(rollback_manifest[2].path),
                   "Library/orbit-second.dylib");
    rollback_manifest[2].size = strlen("second-payload");
    int rollback_install_backup_fd = -1;
    EXPECT("end-to-end rollback backup directory created",
        create_backup_directory(root_fd, "backup-install-rollback",
                                &rollback_install_backup_fd));
    memory_envelope rollback_install_memory;
    memset(&rollback_install_memory, 0, sizeof(rollback_install_memory));
    EXPECT("end-to-end rollback envelope initialized",
        memory_initialize(&rollback_install_memory));
    orbit_package_filesystem_envelope_backend rollback_install_backend = {
        &rollback_install_memory, memory_load, memory_release, memory_store
    };
    envelope_executor rollback_install_executor;
    memset(&rollback_install_executor, 0, sizeof(rollback_install_executor));
    rollback_install_executor.target_fd = install_fd;
    rollback_install_executor.stage_fd = stage_fd;
    rollback_install_executor.backup_fd = rollback_install_backup_fd;
    rollback_install_executor.fail_apply_at_call = 2U;
    memset(install_transaction_id, 0xB2, sizeof(install_transaction_id));
    install_plan_result = ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT;
    install_journal_result = ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    EXPECT("failed second file triggers complete install rollback",
        orbit_package_install_transaction_execute_enveloped(
            &installed_snapshot, &candidate, rollback_manifest, 3U,
            ownership_old, sizeof(ownership_old), install_transaction_id,
            install_fd, stage_fd, rollback_install_backup_fd,
            &rollback_install_backend, execute_change,
            &rollback_install_executor,
            &install_plan_result, &install_journal_result) ==
                ORBIT_PACKAGE_INSTALL_TRANSACTION_JOURNAL_FAILED);
    fprintf(stderr,
        "DEBUG rollback apply=%zu rollback=%zu first_target=%d second_target=%d first_stage=%d second_stage=%d\\n",
        rollback_install_executor.apply_calls,
        rollback_install_executor.rollback_calls,
        faccessat(install_library, "orbit-first.dylib", F_OK, AT_SYMLINK_NOFOLLOW),
        faccessat(install_library, "orbit-second.dylib", F_OK, AT_SYMLINK_NOFOLLOW),
        file_equals_at(stage_library, "orbit-first.dylib", "first-payload"),
        file_equals_at(stage_library, "orbit-second.dylib", "second-payload"));
    EXPECT("rollback restored staged files and removed partial installs",
        rollback_install_executor.apply_calls == 2U &&
        rollback_install_executor.rollback_calls >= 1U &&
        faccessat(install_library, "orbit-first.dylib",
                  F_OK, AT_SYMLINK_NOFOLLOW) != 0 &&
        faccessat(install_library, "orbit-second.dylib",
                  F_OK, AT_SYMLINK_NOFOLLOW) != 0 &&
        file_equals_at(stage_library, "orbit-first.dylib", "first-payload") &&
        file_equals_at(stage_library, "orbit-second.dylib", "second-payload"));
    uint8_t *rollback_journal_buffer =
        (uint8_t *)malloc(ORBIT_TRANSACTION_ENVELOPE_MAX_JOURNAL);
    uint8_t *rollback_committed_buffer =
        (uint8_t *)malloc(ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP);
    uint8_t *rollback_pending_buffer =
        (uint8_t *)malloc(ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP);
    orbit_package_transaction_envelope rollback_install_decoded;
    EXPECT("failed install preserves old ownership and clears journal",
        rollback_journal_buffer && rollback_committed_buffer &&
        rollback_pending_buffer &&
        decode_memory(&rollback_install_memory, &rollback_install_decoded,
            rollback_journal_buffer, rollback_committed_buffer,
            rollback_pending_buffer) &&
        rollback_install_decoded.state == ORBIT_TRANSACTION_ENVELOPE_EMPTY &&
        rollback_install_decoded.committed_ownership_length ==
            sizeof(ownership_old) &&
        memcmp(rollback_install_decoded.committed_ownership,
               ownership_old, sizeof(ownership_old)) == 0);
    free(rollback_journal_buffer);
    free(rollback_committed_buffer);
    free(rollback_pending_buffer);
    free(rollback_install_memory.payload);
    close(rollback_install_backup_fd);
    EXPECT("end-to-end rollback backup directory cleaned",
        unlinkat(root_fd, "backup-install-rollback", AT_REMOVEDIR) == 0);
    EXPECT("end-to-end rollback staged fixtures cleaned",
        unlinkat(stage_library, "orbit-first.dylib", 0) == 0 &&
        unlinkat(stage_library, "orbit-second.dylib", 0) == 0);
    close(stage_library);
    close(install_library);
    EXPECT("end-to-end package directories removed",
        unlinkat(install_fd, "Library", AT_REMOVEDIR) == 0 &&
        unlinkat(stage_fd, "Library", AT_REMOVEDIR) == 0);

    EXPECT("success target cleaned", unlinkat(install_fd, "target-success", 0) == 0);
    EXPECT("rollback target cleaned", unlinkat(install_fd, "target-rollback", 0) == 0);
    EXPECT("commit target cleaned", unlinkat(install_fd, "target-commit", 0) == 0);
    EXPECT("write-ahead failure target cleaned", unlinkat(install_fd, "target-storefail", 0) == 0);
    EXPECT("unapplied staged file cleaned", unlinkat(stage_fd, "stage-rollback", 0) == 0);
    EXPECT("write-ahead failure staged file cleaned", unlinkat(stage_fd, "stage-storefail", 0) == 0);
    free(journal_buffer);
    free(committed_buffer);
    free(pending_buffer);
    free(memory.payload);
    close(stage_fd);
    close(install_fd);
    EXPECT("install root removed",
        unlinkat(root_fd, "install", AT_REMOVEDIR) == 0);
    EXPECT("staging root removed",
        unlinkat(root_fd, "stage", AT_REMOVEDIR) == 0);
    close(root_fd);
    EXPECT("temporary root removed", rmdir(root_path) == 0);

    printf("filesystem_journal_envelope_checks=%u failures=%u\ndecision=%s\n",
        checks, failures, failures == 0U ? "PASS" : "FAIL");
    return failures == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
