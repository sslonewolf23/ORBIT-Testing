#include "ORBITPackageInstallTransaction.h"
#include "ORBITPackageOwnershipCodec.h"

#include <stdlib.h>
#include <string.h>

#define ORBIT_INSTALL_PLAN_CHANGE_CAPACITY ORBIT_FILESYSTEM_JOURNAL_MAX_CHANGES

static bool encode_snapshot_alloc(
    const orbit_package_ownership_snapshot *snapshot,
    uint8_t **payload, size_t *payload_length) {
    if (!snapshot || !payload || !payload_length) return false;
    *payload = NULL;
    *payload_length = 0U;
    size_t required = 0U;
    orbit_ownership_codec_code measured =
        orbit_package_ownership_encode(snapshot, NULL, 0U, &required);
    if (measured != ORBIT_OWNERSHIP_CODEC_BUFFER_TOO_SMALL ||
        required == 0U || required > ORBIT_OWNERSHIP_CODEC_MAX_PAYLOAD)
        return false;
    uint8_t *buffer = (uint8_t *)malloc(required);
    if (!buffer) return false;
    orbit_ownership_codec_code encoded =
        orbit_package_ownership_encode(snapshot, buffer, required, &required);
    if (encoded != ORBIT_OWNERSHIP_CODEC_OK) {
        free(buffer);
        return false;
    }
    *payload = buffer;
    *payload_length = required;
    return true;
}

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
    orbit_filesystem_code *journal_result) {
    if (plan_result) *plan_result = ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT;
    if (journal_result) *journal_result = ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    if (!installed || !candidate || !manifest || manifest_count == 0U ||
        !expected_ownership || expected_ownership_length == 0U ||
        !transaction_id || install_root_fd < 0 || staging_root_fd < 0 ||
        backup_directory_fd < 0 || !backend || !executor ||
        !plan_result || !journal_result)
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_INVALID_ARGUMENT;

    uint8_t *installed_payload = NULL;
    size_t installed_payload_length = 0U;
    if (!encode_snapshot_alloc(installed, &installed_payload,
                               &installed_payload_length))
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_OWNERSHIP_CODEC_FAILED;
    bool snapshot_matches =
        installed_payload_length == expected_ownership_length &&
        memcmp(installed_payload, expected_ownership,
               expected_ownership_length) == 0;
    free(installed_payload);
    if (!snapshot_matches)
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_INVALID_ARGUMENT;

    orbit_package_file_change *changes =
        (orbit_package_file_change *)calloc(
            ORBIT_INSTALL_PLAN_CHANGE_CAPACITY, sizeof(*changes));
    orbit_package_ownership_record *ownership_records =
        (orbit_package_ownership_record *)calloc(
            ORBIT_OWNERSHIP_MAX_RECORDS, sizeof(*ownership_records));
    if (!changes || !ownership_records) {
        free(changes);
        free(ownership_records);
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_PLAN_FAILED;
    }

    size_t change_count = 0U;
    orbit_package_ownership_snapshot replacement;
    memset(&replacement, 0, sizeof(replacement));
    orbit_package_file_plan_code planned =
        orbit_package_file_plan_build_install(
            installed, candidate, manifest, manifest_count,
            install_root_fd, staging_root_fd, backup_directory_fd,
            changes, ORBIT_INSTALL_PLAN_CHANGE_CAPACITY, &change_count,
            ownership_records, ORBIT_OWNERSHIP_MAX_RECORDS, &replacement);
    *plan_result = planned;
    if (planned != ORBIT_PACKAGE_FILE_PLAN_OK) {
        free(changes);
        free(ownership_records);
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_PLAN_FAILED;
    }

    uint8_t *replacement_payload = NULL;
    size_t replacement_payload_length = 0U;
    if (!encode_snapshot_alloc(&replacement, &replacement_payload,
                               &replacement_payload_length)) {
        free(changes);
        free(ownership_records);
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_OWNERSHIP_CODEC_FAILED;
    }

    orbit_filesystem_code executed =
        orbit_package_filesystem_journal_execute_enveloped(
            backend, transaction_id, changes, change_count,
            expected_ownership, expected_ownership_length,
            replacement_payload, replacement_payload_length,
            executor, executor_context);
    *journal_result = executed;

    free(replacement_payload);
    free(changes);
    free(ownership_records);
    return executed == ORBIT_FILESYSTEM_OK ?
        ORBIT_PACKAGE_INSTALL_TRANSACTION_OK :
        ORBIT_PACKAGE_INSTALL_TRANSACTION_JOURNAL_FAILED;
}
