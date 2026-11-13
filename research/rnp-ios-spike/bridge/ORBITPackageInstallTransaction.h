#ifndef ORBIT_PACKAGE_INSTALL_TRANSACTION_H
#define ORBIT_PACKAGE_INSTALL_TRANSACTION_H

#include "ORBITPackageFilePlan.h"
#include "ORBITPackageFilesystemJournalEnvelope.h"
#include "ORBITPackageStaging.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ORBIT_PACKAGE_INSTALL_TRANSACTION_OK = 0,
    ORBIT_PACKAGE_INSTALL_TRANSACTION_INVALID_ARGUMENT,
    ORBIT_PACKAGE_INSTALL_TRANSACTION_PLAN_FAILED,
    ORBIT_PACKAGE_INSTALL_TRANSACTION_OWNERSHIP_CODEC_FAILED,
    ORBIT_PACKAGE_INSTALL_TRANSACTION_JOURNAL_FAILED,
    ORBIT_PACKAGE_INSTALL_TRANSACTION_ARCHIVE_PREFLIGHT_FAILED,
    ORBIT_PACKAGE_INSTALL_TRANSACTION_OWNERSHIP_PREFLIGHT_FAILED,
    ORBIT_PACKAGE_INSTALL_TRANSACTION_STAGING_FAILED
} orbit_package_install_transaction_code;

/* End-to-end install/upgrade path for an already staged and fully validated
 * package manifest. The supplied installed snapshot must decode from exactly
 * expected_ownership; this prevents planning from a stale in-memory database.
 *
 * This function builds the file plan, encodes the complete replacement
 * ownership snapshot, then submits both to the authenticated envelope executor.
 * It does not create directories, extract archives, run maintainer scripts, or
 * remove the transaction backup directory. Caller holds ORBIT's cross-process
 * lock and retains it through journal recovery and backup cleanup. */
orbit_package_install_transaction_code
orbit_package_install_transaction_execute_enveloped(
    const orbit_package_ownership_snapshot *installed,
    const orbit_package_record *candidate,
    const orbit_archive_entry *manifest, size_t manifest_count,
    const uint8_t *expected_ownership, size_t expected_ownership_length,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    int install_root_fd, int staging_root_fd, int backup_directory_fd,
    const orbit_package_filesystem_envelope_backend *backend,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context,
    orbit_package_file_plan_code *plan_result,
    orbit_filesystem_code *journal_result);


/* End-to-end .deb install/upgrade orchestration. It first captures the full
 * data.tar manifest without filesystem writes and validates ownership conflicts.
 * Only then does it create a private stage and stream payload bytes. The existing
 * authenticated transaction path applies the already validated manifest.
 *
 * staging_base_fd must be a trusted, owner-controlled directory on the same
 * filesystem as install_root_fd. Caller holds the ORBIT transaction lock across
 * this call and recovery. On return after staging begins, staging_out owns open
 * descriptors and the private tree; caller must retain it through recovery, then
 * explicitly discard it. No maintainer scripts are executed. */
orbit_package_install_transaction_code
orbit_package_install_transaction_execute_deb_enveloped(
    const orbit_package_ownership_snapshot *installed,
    const orbit_package_record *candidate,
    const uint8_t *deb, size_t deb_length,
    const uint8_t *expected_ownership, size_t expected_ownership_length,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    int install_root_fd, int staging_base_fd, int backup_directory_fd,
    const char *staging_name,
    const orbit_package_filesystem_envelope_backend *backend,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context,
    orbit_package_staging *staging_out,
    orbit_archive_report *archive_report,
    orbit_archive_code *archive_result,
    orbit_package_file_plan_code *plan_result,
    orbit_filesystem_code *journal_result);

/* Remove an installed package identity through the same authenticated
 * filesystem/ownership transaction. Only files owned by this exact
 * name+architecture identity are removed; directory rows and other owners
 * remain protected. The package must own at least one regular file. */
orbit_package_install_transaction_code
orbit_package_remove_transaction_execute_enveloped(
    const orbit_package_ownership_snapshot *installed,
    const orbit_package_record *package,
    const uint8_t *expected_ownership, size_t expected_ownership_length,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    int install_root_fd, int backup_directory_fd,
    const orbit_package_filesystem_envelope_backend *backend,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context,
    orbit_package_file_plan_code *plan_result,
    orbit_filesystem_code *journal_result);
#ifdef __cplusplus
}
#endif
#endif
