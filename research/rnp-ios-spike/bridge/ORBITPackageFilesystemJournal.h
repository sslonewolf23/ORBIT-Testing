#ifndef ORBIT_PACKAGE_FILESYSTEM_JOURNAL_H
#define ORBIT_PACKAGE_FILESYSTEM_JOURNAL_H

#include "ORBITPackageFilesystem.h"

#include <stddef.h>
#include <stdint.h>

#define ORBIT_FILESYSTEM_JOURNAL_VERSION 1U
#define ORBIT_FILESYSTEM_JOURNAL_MAX_CHANGES 4096U
#define ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES 16U

typedef enum {
    ORBIT_FILE_JOURNAL_EMPTY = 0,
    ORBIT_FILE_JOURNAL_APPLYING = 1,
    ORBIT_FILE_JOURNAL_ROLLING_BACK = 2,
    ORBIT_FILE_JOURNAL_COMMITTED = 3
} orbit_file_journal_phase;

typedef struct {
    uint32_t version;
    uint32_t phase;
    uint64_t revision;
    uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES];
    uint32_t change_count;
    orbit_package_file_change changes[ORBIT_FILESYSTEM_JOURNAL_MAX_CHANGES];
} orbit_package_filesystem_journal_record;

typedef enum {
    ORBIT_FILE_JOURNAL_LOAD_EMPTY = 0,
    ORBIT_FILE_JOURNAL_LOAD_PRESENT = 1,
    ORBIT_FILE_JOURNAL_LOAD_ERROR = 2
} orbit_file_journal_load_result;

typedef struct {
    void *context;
    /* load authenticates the record and returns the durable monotonic revision
     * even when no active record exists. */
    orbit_file_journal_load_result (*load)(
        void *context, orbit_package_filesystem_journal_record *record,
        uint64_t *last_revision);
    /* store_atomic must authenticate, atomically replace, and accept only
     * record.revision == last_revision + 1. */
    bool (*store_atomic)(
        void *context, const orbit_package_filesystem_journal_record *record);
    /* clear_atomic removes only the active record at expected_revision while
     * retaining the monotonic revision counter. */
    bool (*clear_atomic)(void *context, uint64_t expected_revision);
} orbit_package_filesystem_journal_backend;

typedef enum {
    ORBIT_FILE_JOURNAL_APPLY = 1,
    ORBIT_FILE_JOURNAL_ROLLBACK = 2,
    ORBIT_FILE_JOURNAL_FINALIZE = 3
} orbit_file_journal_action;

typedef orbit_filesystem_code (*orbit_package_filesystem_journal_executor)(
    void *context,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    orbit_file_journal_action action,
    const orbit_package_file_change *change);

/* Persists the complete file plan before the first mutation. On apply failure,
 * it attempts reverse rollback. If rollback cannot finish, the journal remains. */
orbit_filesystem_code orbit_package_filesystem_journal_execute(
    const orbit_package_filesystem_journal_backend *backend,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    const orbit_package_file_change *changes, size_t change_count,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context);

/* APPLYING/ROLLING_BACK records recover by reverse rollback. COMMITTED records
 * recover by retrying backup finalization. Empty journals are a no-op. */
orbit_filesystem_code orbit_package_filesystem_journal_recover(
    const orbit_package_filesystem_journal_backend *backend,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context);

#endif
