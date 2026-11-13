#include "ORBITPackageInstallTransaction.h"
#include "ORBITPackageOwnershipCodec.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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


typedef struct {
    orbit_archive_entry *entries;
    size_t count;
    size_t capacity;
    bool overflow;
} orbit_install_manifest_capture;

static bool capture_install_manifest(void *context,
                                     const orbit_archive_entry *entry) {
    orbit_install_manifest_capture *capture =
        (orbit_install_manifest_capture *)context;
    if (!capture || !entry || capture->overflow ||
        capture->count >= capture->capacity) {
        if (capture) capture->overflow = true;
        return false;
    }
    capture->entries[capture->count++] = *entry;
    return true;
}

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
    orbit_filesystem_code *journal_result) {
    if (plan_result) *plan_result = ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT;
    if (journal_result) *journal_result = ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    if (archive_result) *archive_result = ORBIT_ARCHIVE_INVALID_ARGUMENT;
    if (staging_out) {
        memset(staging_out, 0, sizeof(*staging_out));
        staging_out->base_directory_fd = -1;
        staging_out->staging_directory_fd = -1;
        staging_out->active_file_fd = -1;
    }
    if (!installed || !candidate || !deb || deb_length == 0U ||
        !expected_ownership || expected_ownership_length == 0U ||
        !transaction_id || install_root_fd < 0 || staging_base_fd < 0 ||
        backup_directory_fd < 0 || !staging_name || !backend || !executor ||
        !staging_out || !archive_report || !archive_result ||
        !plan_result || !journal_result)
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_INVALID_ARGUMENT;

    /* Reject stale ownership state before doing any archive extraction. */
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

    struct stat install_status, staging_status;
    if (fstat(install_root_fd, &install_status) < 0 ||
        fstat(staging_base_fd, &staging_status) < 0 ||
        !S_ISDIR(install_status.st_mode) || !S_ISDIR(staging_status.st_mode) ||
        install_status.st_dev != staging_status.st_dev)
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_INVALID_ARGUMENT;

    orbit_install_manifest_capture capture;
    memset(&capture, 0, sizeof(capture));
    capture.capacity = ORBIT_TAR_MAX_ENTRIES;
    capture.entries = (orbit_archive_entry *)calloc(
        capture.capacity, sizeof(*capture.entries));
    if (!capture.entries)
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_ARCHIVE_PREFLIGHT_FAILED;

    orbit_archive_code inspected =
        orbit_package_archive_inspect_deb_with_data_entries(
            deb, deb_length, capture_install_manifest, &capture, archive_report);
    *archive_result = inspected;
    if (inspected != ORBIT_ARCHIVE_OK || capture.overflow ||
        capture.count == 0U) {
        free(capture.entries);
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_ARCHIVE_PREFLIGHT_FAILED;
    }

    /* Validate ownership conflicts before creating the staging directory. */
    orbit_package_ownership_record *ownership_records =
        (orbit_package_ownership_record *)calloc(
            ORBIT_OWNERSHIP_MAX_RECORDS, sizeof(*ownership_records));
    if (!ownership_records) {
        free(capture.entries);
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_OWNERSHIP_PREFLIGHT_FAILED;
    }
    orbit_package_ownership_snapshot replacement;
    memset(&replacement, 0, sizeof(replacement));
    orbit_ownership_code ownership_code =
        orbit_package_ownership_snapshot_install(
            installed, candidate, capture.entries, capture.count,
            ownership_records, ORBIT_OWNERSHIP_MAX_RECORDS, &replacement);
    free(ownership_records);
    if (ownership_code != ORBIT_OWNERSHIP_OK) {
        free(capture.entries);
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_OWNERSHIP_PREFLIGHT_FAILED;
    }

    /* The staging helper repeats full no-write validation before creating files. */
    orbit_staging_code staged = orbit_package_staging_extract_deb(
        staging_base_fd, staging_name, deb, deb_length,
        staging_out, archive_report, archive_result);
    if (staged != ORBIT_STAGING_OK) {
        free(capture.entries);
        return ORBIT_PACKAGE_INSTALL_TRANSACTION_STAGING_FAILED;
    }

    orbit_package_install_transaction_code transaction =
        orbit_package_install_transaction_execute_enveloped(
            installed, candidate, capture.entries, capture.count,
            expected_ownership, expected_ownership_length, transaction_id,
            install_root_fd, staging_out->staging_directory_fd,
            backup_directory_fd, backend, executor, executor_context,
            plan_result, journal_result);
    free(capture.entries);
    /* Keep the private stage available to caller until commit/recovery cleanup. */
    return transaction;
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
    orbit_filesystem_code *journal_result) {
    if (plan_result) *plan_result = ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT;
    if (journal_result) *journal_result = ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    if (!installed || !package || !expected_ownership ||
        expected_ownership_length == 0U || !transaction_id ||
        install_root_fd < 0 || backup_directory_fd < 0 ||
        !backend || !executor || !plan_result || !journal_result)
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
        orbit_package_file_plan_build_remove(
            installed, package, install_root_fd, backup_directory_fd,
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
