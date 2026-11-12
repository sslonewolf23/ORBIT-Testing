#ifndef ORBIT_PACKAGE_FILESYSTEM_JOURNAL_H
#define ORBIT_PACKAGE_FILESYSTEM_JOURNAL_H

#include "ORBITPackageFilesystem.h"

#include <stddef.h>
#include <stdint.h>

#define ORBIT_FILESYSTEM_JOURNAL_VERSION 2U
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

typedef struct {
    int install_root_fd;
    int staging_root_fd;
    int backup_base_directory_fd;
    uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES];
} orbit_package_filesystem_executor_context;

/* Opens the private backup directory named by the 16-byte transaction ID.
 * create=true creates it with mode 0700; an existing directory is accepted
 * only when it is owned by the effective user, has no group/other access,
 * and is empty (to reject stale transaction contents). */
orbit_filesystem_code orbit_package_filesystem_open_backup_directory(
    int backup_base_directory_fd,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    bool create, int *backup_directory_fd);

/* Standard descriptor-resolving executor for the journal. The backup root
 * must already be opened for the supplied transaction ID. */
orbit_filesystem_code orbit_package_filesystem_journal_execute_change(
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

/* Sweep canonical, empty transaction backup directories left behind if the
 * process crashed after the authenticated journal tombstone but before directory
 * removal. Requires the package filesystem lock. Refuses to proceed if a journal
 * is active, a candidate is unsafe/nonempty, or more than 4096 candidates exist. */
orbit_filesystem_code orbit_package_filesystem_journal_cleanup_orphan_backup_directories(
    const orbit_package_filesystem_journal_backend *backend,
    int backup_base_directory_fd);

/* Remove the transaction-scoped backup directory only after the authenticated
 * journal reports EMPTY and the directory is verified empty. Caller must hold
 * the package filesystem transaction lock across this check and cleanup. */
orbit_filesystem_code orbit_package_filesystem_journal_cleanup_backup_directory(
    const orbit_package_filesystem_journal_backend *backend,
    int backup_base_directory_fd,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES]);

#endif
