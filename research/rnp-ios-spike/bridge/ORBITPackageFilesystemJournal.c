#define _POSIX_C_SOURCE 200809L

#include "ORBITPackageFilesystemJournal.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static bool executor_roots_are_valid(
    const orbit_package_filesystem_executor_context *executor,
    bool needs_staging) {
    struct stat install_status, backup_status, staging_status;
    if (fstat(executor->install_root_fd, &install_status) < 0 ||
        fstat(executor->backup_base_directory_fd, &backup_status) < 0)
        return false;
    if (!S_ISDIR(install_status.st_mode) ||
        !S_ISDIR(backup_status.st_mode) ||
        install_status.st_dev != backup_status.st_dev ||
        (install_status.st_dev == backup_status.st_dev &&
         install_status.st_ino == backup_status.st_ino))
        return false;
    if (!needs_staging) return true;
    if (executor->staging_root_fd < 0 ||
        fstat(executor->staging_root_fd, &staging_status) < 0)
        return false;
    return S_ISDIR(staging_status.st_mode) &&
        staging_status.st_dev == install_status.st_dev &&
        !(staging_status.st_dev == install_status.st_dev &&
          staging_status.st_ino == install_status.st_ino) &&
        !(staging_status.st_dev == backup_status.st_dev &&
          staging_status.st_ino == backup_status.st_ino);
}

orbit_filesystem_code orbit_package_filesystem_journal_execute_change(
    void *context,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    orbit_file_journal_action action,
    const orbit_package_file_change *change) {
    orbit_package_filesystem_executor_context *executor =
        (orbit_package_filesystem_executor_context *)context;
    if (!executor || !transaction_id || !change ||
        executor->install_root_fd < 0 || executor->backup_base_directory_fd < 0 ||
        memcmp(executor->transaction_id, transaction_id,
               ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES) != 0)
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    orbit_filesystem_code valid =
        orbit_package_filesystem_validate_change(change);
    if (valid != ORBIT_FILESYSTEM_OK) return valid;
    if (!executor_roots_are_valid(
            executor, change->operation == ORBIT_FILESYSTEM_REPLACE))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    int backup_parent_fd = -1;
    valid = orbit_package_filesystem_open_backup_directory(
        executor->backup_base_directory_fd, transaction_id, false,
        &backup_parent_fd);
    if (valid != ORBIT_FILESYSTEM_OK) return valid;

    int target_parent_fd = -1;
    int staged_parent_fd = -1;
    valid = orbit_package_filesystem_open_parent_directory(
        executor->install_root_fd, change->target_parent_path,
        &target_parent_fd);
    if (valid != ORBIT_FILESYSTEM_OK) {
        close(backup_parent_fd);
        return valid;
    }

    if (change->operation == ORBIT_FILESYSTEM_REPLACE) {
        valid = orbit_package_filesystem_open_parent_directory(
            executor->staging_root_fd, change->staged_parent_path,
            &staged_parent_fd);
        if (valid != ORBIT_FILESYSTEM_OK) {
            close(target_parent_fd);
            close(backup_parent_fd);
            return valid;
        }
    }

    orbit_filesystem_code result;
    if (action == ORBIT_FILE_JOURNAL_APPLY)
        result = orbit_package_filesystem_apply(
            target_parent_fd, staged_parent_fd,
            backup_parent_fd, change);
    else if (action == ORBIT_FILE_JOURNAL_ROLLBACK)
        result = orbit_package_filesystem_rollback(
            target_parent_fd, staged_parent_fd,
            backup_parent_fd, change);
    else if (action == ORBIT_FILE_JOURNAL_FINALIZE)
        result = orbit_package_filesystem_finalize(
            target_parent_fd, staged_parent_fd,
            backup_parent_fd, change);
    else
        result = ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    bool staged_closed = staged_parent_fd < 0 || close(staged_parent_fd) == 0;
    bool target_closed = close(target_parent_fd) == 0;
    bool backup_closed = close(backup_parent_fd) == 0;
    if (!staged_closed || !target_closed || !backup_closed)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    return result;
}

static bool backup_directory_is_empty(int directory_fd) {
    /* openat(".") creates a fresh open-file description. dup()/F_DUPFD would
     * share the directory stream offset with the caller's descriptor. */
    int duplicate = openat(directory_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (duplicate < 0) return false;
    DIR *directory = fdopendir(duplicate);
    if (!directory) {
        close(duplicate);
        return false;
    }
    bool empty = true;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) {
            empty = false;
            break;
        }
    }
    if (errno != 0) empty = false;
    closedir(directory);
    return empty;
}

orbit_filesystem_code orbit_package_filesystem_open_backup_directory(
    int backup_base_directory_fd,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    bool create, int *backup_directory_fd) {
    if (backup_base_directory_fd < 0 || !transaction_id ||
        !backup_directory_fd)
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    *backup_directory_fd = -1;
    uint8_t combined = 0U;
    for (size_t i = 0U; i < ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES; ++i)
        combined |= transaction_id[i];
    if (combined == 0U) return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    struct stat base_status;
    if (fstat(backup_base_directory_fd, &base_status) < 0)
        return ORBIT_FILESYSTEM_IO_ERROR;
    if (!S_ISDIR(base_status.st_mode))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    char name[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES * 2U + 1U];
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0U; i < ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES; ++i) {
        name[i * 2U] = hex[transaction_id[i] >> 4U];
        name[i * 2U + 1U] = hex[transaction_id[i] & 0x0fU];
    }
    name[sizeof(name) - 1U] = '\0';

    if (create && mkdirat(backup_base_directory_fd, name, 0700) < 0 &&
        errno != EEXIST)
        return ORBIT_FILESYSTEM_IO_ERROR;
    if (create && fsync(backup_base_directory_fd) < 0)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;

    int fd = openat(backup_base_directory_fd, name,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ?
        ORBIT_FILESYSTEM_RECOVERY_REQUIRED : ORBIT_FILESYSTEM_IO_ERROR;

    struct stat opened_status, named_status;
    if (fstat(fd, &opened_status) < 0 ||
        fstatat(backup_base_directory_fd, name, &named_status,
                AT_SYMLINK_NOFOLLOW) < 0) {
        close(fd);
        return ORBIT_FILESYSTEM_IO_ERROR;
    }
    if (!S_ISDIR(opened_status.st_mode) || !S_ISDIR(named_status.st_mode) ||
        opened_status.st_dev != named_status.st_dev ||
        opened_status.st_ino != named_status.st_ino ||
        opened_status.st_uid != geteuid() ||
        (opened_status.st_mode & 0077) != 0 ||
        opened_status.st_dev != base_status.st_dev) {
        close(fd);
        return ORBIT_FILESYSTEM_CONFLICT;
    }
    if (create && !backup_directory_is_empty(fd)) {
        close(fd);
        return ORBIT_FILESYSTEM_CONFLICT;
    }
    *backup_directory_fd = fd;
    return ORBIT_FILESYSTEM_OK;
}

static bool transaction_id_is_valid(
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES]) {
    if (!transaction_id) return false;
    uint8_t combined = 0U;
    for (size_t i = 0U; i < ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES; ++i)
        combined |= transaction_id[i];
    return combined != 0U;
}

static int compare_ascii_casefold(const char *left, const char *right) {
    while (*left && *right) {
        unsigned char a = (unsigned char)*left++;
        unsigned char b = (unsigned char)*right++;
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + ('a' - 'A'));
        if (a != b) return a < b ? -1 : 1;
    }
    if (*left) return 1;
    if (*right) return -1;
    return 0;
}

typedef enum {
    CHANGE_KEY_TARGET = 0,
    CHANGE_KEY_BACKUP = 1,
    CHANGE_KEY_STAGED = 2
} change_key_kind;

static int compare_change_key(
    const orbit_package_filesystem_journal_record *record,
    size_t left, size_t right, change_key_kind kind) {
    const orbit_package_file_change *a = &record->changes[left];
    const orbit_package_file_change *b = &record->changes[right];
    if (kind == CHANGE_KEY_BACKUP)
        return compare_ascii_casefold(a->backup_name, b->backup_name);
    if (kind == CHANGE_KEY_STAGED) {
        int parent_order = compare_ascii_casefold(
            a->staged_parent_path, b->staged_parent_path);
        if (parent_order != 0) return parent_order;
        return compare_ascii_casefold(a->staged_name, b->staged_name);
    }
    int parent_order = compare_ascii_casefold(
        a->target_parent_path, b->target_parent_path);
    if (parent_order != 0) return parent_order;
    return compare_ascii_casefold(a->target_name, b->target_name);
}

static void swap_indices(size_t *left, size_t *right) {
    size_t temporary = *left;
    *left = *right;
    *right = temporary;
}

static void sift_index_heap(
    size_t *indices, size_t root, size_t count,
    const orbit_package_filesystem_journal_record *record,
    change_key_kind kind) {
    while (count > 1U && root <= (count - 2U) / 2U) {
        size_t child = root * 2U + 1U;
        if (child + 1U < count &&
            compare_change_key(record, indices[child],
                               indices[child + 1U], kind) < 0)
            ++child;
        if (compare_change_key(record, indices[root],
                               indices[child], kind) >= 0)
            return;
        swap_indices(&indices[root], &indices[child]);
        root = child;
    }
}

static void sort_change_indices(
    size_t *indices, size_t count,
    const orbit_package_filesystem_journal_record *record,
    change_key_kind kind) {
    if (count < 2U) return;
    for (size_t start = count / 2U; start > 0U; --start)
        sift_index_heap(indices, start - 1U, count, record, kind);
    for (size_t end = count; end > 1U; --end) {
        swap_indices(&indices[0], &indices[end - 1U]);
        sift_index_heap(indices, 0U, end - 1U, record, kind);
    }
}

static bool record_is_valid(
    const orbit_package_filesystem_journal_record *record) {
    if (!record || record->version != ORBIT_FILESYSTEM_JOURNAL_VERSION ||
        record->revision == 0U ||
        record->phase < ORBIT_FILE_JOURNAL_APPLYING ||
        record->phase > ORBIT_FILE_JOURNAL_COMMITTED ||
        record->change_count == 0U ||
        record->change_count > ORBIT_FILESYSTEM_JOURNAL_MAX_CHANGES ||
        !transaction_id_is_valid(record->transaction_id))
        return false;

    for (size_t i = 0U; i < record->change_count; ++i) {
        if (orbit_package_filesystem_validate_change(
                &record->changes[i]) != ORBIT_FILESYSTEM_OK)
            return false;
    }

    size_t *indices = (size_t *)malloc(record->change_count * sizeof(*indices));
    if (!indices) return false;

    for (size_t i = 0U; i < record->change_count; ++i) indices[i] = i;
    sort_change_indices(indices, record->change_count, record, CHANGE_KEY_TARGET);
    bool unique = true;
    for (size_t i = 1U; i < record->change_count; ++i) {
        if (compare_change_key(record, indices[i - 1U], indices[i],
                               CHANGE_KEY_TARGET) == 0) {
            unique = false;
            break;
        }
    }

    if (unique) {
        sort_change_indices(indices, record->change_count, record, CHANGE_KEY_BACKUP);
        for (size_t i = 1U; i < record->change_count; ++i) {
            if (compare_change_key(record, indices[i - 1U], indices[i],
                                   CHANGE_KEY_BACKUP) == 0) {
                unique = false;
                break;
            }
        }
    }

    if (unique) {
        size_t staged_count = 0U;
        for (size_t i = 0U; i < record->change_count; ++i) {
            if (record->changes[i].operation == ORBIT_FILESYSTEM_REPLACE)
                indices[staged_count++] = i;
        }
        sort_change_indices(indices, staged_count, record, CHANGE_KEY_STAGED);
        for (size_t i = 1U; i < staged_count; ++i) {
            if (compare_change_key(record, indices[i - 1U], indices[i],
                                   CHANGE_KEY_STAGED) == 0) {
                unique = false;
                break;
            }
        }
    }
    free(indices);
    return unique;
}

static bool backend_is_valid(
    const orbit_package_filesystem_journal_backend *backend) {
    return backend && backend->load && backend->store_atomic &&
           backend->clear_atomic;
}

static orbit_file_journal_load_result load_record(
    const orbit_package_filesystem_journal_backend *backend,
    orbit_package_filesystem_journal_record *record,
    uint64_t *last_revision) {
    if (!backend_is_valid(backend) || !record || !last_revision)
        return ORBIT_FILE_JOURNAL_LOAD_ERROR;
    memset(record, 0, sizeof(*record));
    *last_revision = 0U;
    orbit_file_journal_load_result result =
        backend->load(backend->context, record, last_revision);
    if (result == ORBIT_FILE_JOURNAL_LOAD_PRESENT) {
        if (!record_is_valid(record) || record->revision != *last_revision)
            return ORBIT_FILE_JOURNAL_LOAD_ERROR;
    } else if (result == ORBIT_FILE_JOURNAL_LOAD_EMPTY) {
        if (record->change_count != 0U) return ORBIT_FILE_JOURNAL_LOAD_ERROR;
    } else {
        return ORBIT_FILE_JOURNAL_LOAD_ERROR;
    }
    return result;
}

static bool advance_revision(
    orbit_package_filesystem_journal_record *record) {
    if (!record || record->revision == UINT64_MAX) return false;
    ++record->revision;
    return true;
}

static orbit_filesystem_code rollback_all(
    const orbit_package_filesystem_journal_record *record,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context) {
    for (size_t i = record->change_count; i > 0U; --i) {
        orbit_filesystem_code result = executor(
            executor_context, record->transaction_id,
            ORBIT_FILE_JOURNAL_ROLLBACK, &record->changes[i - 1U]);
        if (result != ORBIT_FILESYSTEM_OK)
            return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }
    return ORBIT_FILESYSTEM_OK;
}

static orbit_filesystem_code finalize_all(
    const orbit_package_filesystem_journal_record *record,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context) {
    for (size_t i = 0U; i < record->change_count; ++i) {
        orbit_filesystem_code result = executor(
            executor_context, record->transaction_id,
            ORBIT_FILE_JOURNAL_FINALIZE, &record->changes[i]);
        if (result != ORBIT_FILESYSTEM_OK)
            return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }
    return ORBIT_FILESYSTEM_OK;
}

orbit_filesystem_code orbit_package_filesystem_journal_execute(
    const orbit_package_filesystem_journal_backend *backend,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    const orbit_package_file_change *changes, size_t change_count,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context) {
    if (!backend_is_valid(backend) || !transaction_id_is_valid(transaction_id) ||
        !changes || change_count == 0U ||
        change_count > ORBIT_FILESYSTEM_JOURNAL_MAX_CHANGES || !executor)
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    orbit_package_filesystem_journal_record *record =
        (orbit_package_filesystem_journal_record *)calloc(1U, sizeof(*record));
    if (!record) return ORBIT_FILESYSTEM_LIMIT;

    uint64_t last_revision = 0U;
    orbit_file_journal_load_result loaded =
        load_record(backend, record, &last_revision);
    if (loaded != ORBIT_FILE_JOURNAL_LOAD_EMPTY) {
        free(record);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }
    if (last_revision == UINT64_MAX) {
        free(record);
        return ORBIT_FILESYSTEM_LIMIT;
    }

    record->version = ORBIT_FILESYSTEM_JOURNAL_VERSION;
    record->phase = ORBIT_FILE_JOURNAL_APPLYING;
    record->revision = last_revision + 1U;
    memcpy(record->transaction_id, transaction_id,
           ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES);
    record->change_count = (uint32_t)change_count;
    memcpy(record->changes, changes, change_count * sizeof(*changes));
    if (!record_is_valid(record)) {
        free(record);
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    }
    if (!backend->store_atomic(backend->context, record)) {
        free(record);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    orbit_filesystem_code apply_result = ORBIT_FILESYSTEM_OK;
    for (size_t i = 0U; i < record->change_count; ++i) {
        apply_result = executor(
            executor_context, record->transaction_id,
            ORBIT_FILE_JOURNAL_APPLY, &record->changes[i]);
        if (apply_result != ORBIT_FILESYSTEM_OK) break;
    }

    if (apply_result != ORBIT_FILESYSTEM_OK) {
        if (!advance_revision(record)) {
            orbit_filesystem_code rollback_result =
                rollback_all(record, executor, executor_context);
            bool cleared = rollback_result == ORBIT_FILESYSTEM_OK &&
                backend->clear_atomic(backend->context, record->revision);
            free(record);
            return cleared ? apply_result : ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        }
        record->phase = ORBIT_FILE_JOURNAL_ROLLING_BACK;
        if (!backend->store_atomic(backend->context, record)) {
            free(record);
            return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        }
        orbit_filesystem_code rollback_result =
            rollback_all(record, executor, executor_context);
        if (rollback_result != ORBIT_FILESYSTEM_OK ||
            !backend->clear_atomic(backend->context, record->revision)) {
            free(record);
            return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        }
        free(record);
        return apply_result;
    }

    if (!advance_revision(record)) {
        free(record);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }
    record->phase = ORBIT_FILE_JOURNAL_COMMITTED;
    if (!backend->store_atomic(backend->context, record)) {
        free(record);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    orbit_filesystem_code finalize_result =
        finalize_all(record, executor, executor_context);
    if (finalize_result != ORBIT_FILESYSTEM_OK ||
        !backend->clear_atomic(backend->context, record->revision)) {
        free(record);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }
    free(record);
    return ORBIT_FILESYSTEM_OK;
}

orbit_filesystem_code orbit_package_filesystem_journal_recover(
    const orbit_package_filesystem_journal_backend *backend,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context) {
    if (!backend_is_valid(backend) || !executor)
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    orbit_package_filesystem_journal_record *record =
        (orbit_package_filesystem_journal_record *)calloc(1U, sizeof(*record));
    if (!record) return ORBIT_FILESYSTEM_LIMIT;
    uint64_t last_revision = 0U;
    orbit_file_journal_load_result loaded =
        load_record(backend, record, &last_revision);
    if (loaded == ORBIT_FILE_JOURNAL_LOAD_EMPTY) {
        free(record);
        return ORBIT_FILESYSTEM_OK;
    }
    if (loaded != ORBIT_FILE_JOURNAL_LOAD_PRESENT) {
        free(record);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    if (record->phase == ORBIT_FILE_JOURNAL_APPLYING) {
        if (!advance_revision(record)) {
            orbit_filesystem_code rollback_result =
                rollback_all(record, executor, executor_context);
            bool cleared = rollback_result == ORBIT_FILESYSTEM_OK &&
                backend->clear_atomic(backend->context, record->revision);
            free(record);
            return cleared ? ORBIT_FILESYSTEM_OK :
                   ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        }
        record->phase = ORBIT_FILE_JOURNAL_ROLLING_BACK;
        if (!backend->store_atomic(backend->context, record)) {
            free(record);
            return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        }
    }

    orbit_filesystem_code result;
    if (record->phase == ORBIT_FILE_JOURNAL_ROLLING_BACK)
        result = rollback_all(record, executor, executor_context);
    else if (record->phase == ORBIT_FILE_JOURNAL_COMMITTED)
        result = finalize_all(record, executor, executor_context);
    else
        result = ORBIT_FILESYSTEM_RECOVERY_REQUIRED;

    if (result == ORBIT_FILESYSTEM_OK &&
        !backend->clear_atomic(backend->context, record->revision))
        result = ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    free(record);
    return result;
}

orbit_filesystem_code orbit_package_filesystem_journal_cleanup_backup_directory(
    const orbit_package_filesystem_journal_backend *backend,
    int backup_base_directory_fd,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES]) {
    if (!backend_is_valid(backend) || backup_base_directory_fd < 0 ||
        !transaction_id_is_valid(transaction_id))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    struct stat base_status;
    if (fstat(backup_base_directory_fd, &base_status) < 0)
        return ORBIT_FILESYSTEM_IO_ERROR;
    if (!S_ISDIR(base_status.st_mode))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    orbit_package_filesystem_journal_record *record =
        (orbit_package_filesystem_journal_record *)calloc(1U, sizeof(*record));
    if (!record) return ORBIT_FILESYSTEM_LIMIT;
    uint64_t last_revision = 0U;
    orbit_file_journal_load_result loaded =
        load_record(backend, record, &last_revision);
    free(record);
    if (loaded != ORBIT_FILE_JOURNAL_LOAD_EMPTY)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;

    char name[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES * 2U + 1U];
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0U; i < ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES; ++i) {
        name[i * 2U] = hex[transaction_id[i] >> 4U];
        name[i * 2U + 1U] = hex[transaction_id[i] & 0x0fU];
    }
    name[sizeof(name) - 1U] = '\0';

    int directory_fd = -1;
    orbit_filesystem_code opened = orbit_package_filesystem_open_backup_directory(
        backup_base_directory_fd, transaction_id, false, &directory_fd);
    if (opened != ORBIT_FILESYSTEM_OK) return opened;
    bool empty = backup_directory_is_empty(directory_fd);
    struct stat opened_status, named_status;
    bool identity_matches =
        fstat(directory_fd, &opened_status) == 0 &&
        fstatat(backup_base_directory_fd, name, &named_status,
                AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISDIR(named_status.st_mode) &&
        opened_status.st_dev == named_status.st_dev &&
        opened_status.st_ino == named_status.st_ino;
    bool closed = close(directory_fd) == 0;
    if (!empty || !identity_matches || !closed)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    if (unlinkat(backup_base_directory_fd, name, AT_REMOVEDIR) < 0)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    return fsync(backup_base_directory_fd) == 0 ?
        ORBIT_FILESYSTEM_OK : ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
}


/* Sweep only canonical transaction directories after the authenticated journal
 * tombstone is durable. A nonempty, malformed, or unsafe candidate stops the
 * sweep: it may contain data whose ownership cannot be established. */
orbit_filesystem_code orbit_package_filesystem_journal_cleanup_orphan_backup_directories(
    const orbit_package_filesystem_journal_backend *backend,
    int backup_base_directory_fd) {
    if (!backend_is_valid(backend) || backup_base_directory_fd < 0)
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    struct stat base_status;
    if (fstat(backup_base_directory_fd, &base_status) < 0)
        return ORBIT_FILESYSTEM_IO_ERROR;
    if (!S_ISDIR(base_status.st_mode))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    orbit_package_filesystem_journal_record *record =
        (orbit_package_filesystem_journal_record *)calloc(1U, sizeof(*record));
    if (!record) return ORBIT_FILESYSTEM_LIMIT;
    uint64_t last_revision = 0U;
    orbit_file_journal_load_result loaded =
        load_record(backend, record, &last_revision);
    free(record);
    if (loaded != ORBIT_FILE_JOURNAL_LOAD_EMPTY)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;

    /* Collect before unlinking: mutating a directory while consuming its
     * readdir stream can skip entries on filesystems with unstable cookies. */
    uint8_t (*candidate_ids)[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES] =
        (uint8_t (*)[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES])calloc(
            4096U, sizeof(*candidate_ids));
    if (!candidate_ids) return ORBIT_FILESYSTEM_LIMIT;

    int scan_fd = openat(backup_base_directory_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (scan_fd < 0) {
        free(candidate_ids);
        return ORBIT_FILESYSTEM_IO_ERROR;
    }
    DIR *directory = fdopendir(scan_fd);
    if (!directory) {
        close(scan_fd);
        free(candidate_ids);
        return ORBIT_FILESYSTEM_IO_ERROR;
    }

    orbit_filesystem_code result = ORBIT_FILESYSTEM_OK;
    size_t candidate_count = 0U;
    struct dirent *entry;
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (!entry) {
            if (errno != 0) result = ORBIT_FILESYSTEM_IO_ERROR;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        if (strlen(entry->d_name) !=
            ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES * 2U)
            continue;

        uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES];
        bool canonical = true;
        for (size_t i = 0U; i < sizeof(transaction_id); ++i) {
            unsigned char high = (unsigned char)entry->d_name[i * 2U];
            unsigned char low = (unsigned char)entry->d_name[i * 2U + 1U];
            unsigned high_value, low_value;
            if (high >= '0' && high <= '9') high_value = high - '0';
            else if (high >= 'a' && high <= 'f') high_value = high - 'a' + 10U;
            else { canonical = false; break; }
            if (low >= '0' && low <= '9') low_value = low - '0';
            else if (low >= 'a' && low <= 'f') low_value = low - 'a' + 10U;
            else { canonical = false; break; }
            transaction_id[i] = (uint8_t)((high_value << 4U) | low_value);
        }
        if (!canonical) continue;
        if (candidate_count == 4096U) {
            result = ORBIT_FILESYSTEM_LIMIT;
            break;
        }
        memcpy(candidate_ids[candidate_count++], transaction_id,
               sizeof(transaction_id));
    }
    if (closedir(directory) != 0 && result == ORBIT_FILESYSTEM_OK)
        result = ORBIT_FILESYSTEM_IO_ERROR;

    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0U; i < candidate_count && result == ORBIT_FILESYSTEM_OK; ++i) {
        char name[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES * 2U + 1U];
        for (size_t j = 0U; j < ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES; ++j) {
            name[j * 2U] = hex[candidate_ids[i][j] >> 4U];
            name[j * 2U + 1U] = hex[candidate_ids[i][j] & 0x0fU];
        }
        name[sizeof(name) - 1U] = '\0';

        int candidate_fd = -1;
        orbit_filesystem_code opened = orbit_package_filesystem_open_backup_directory(
            backup_base_directory_fd, candidate_ids[i], false, &candidate_fd);
        if (opened != ORBIT_FILESYSTEM_OK) {
            result = ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
            break;
        }

        bool empty = backup_directory_is_empty(candidate_fd);
        struct stat opened_status, named_status;
        bool identity_matches =
            fstat(candidate_fd, &opened_status) == 0 &&
            fstatat(backup_base_directory_fd, name, &named_status,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISDIR(named_status.st_mode) &&
            opened_status.st_dev == named_status.st_dev &&
            opened_status.st_ino == named_status.st_ino &&
            opened_status.st_dev == base_status.st_dev;
        bool closed = close(candidate_fd) == 0;
        if (!empty || !identity_matches || !closed) {
            result = ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
            break;
        }
        if (unlinkat(backup_base_directory_fd, name, AT_REMOVEDIR) < 0 ||
            fsync(backup_base_directory_fd) < 0) {
            result = ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
            break;
        }
    }
    free(candidate_ids);
    return result;
}
