#ifndef ORBIT_PACKAGE_FILESYSTEM_JOURNAL_ENVELOPE_H
#define ORBIT_PACKAGE_FILESYSTEM_JOURNAL_ENVELOPE_H

#include "ORBITPackageFilesystemJournal.h"
#include "ORBITPackageTransactionEnvelope.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *context;
    /* load returns a malloc-compatible copy of the authenticated current ORBE
     * payload and the SHA-256 digest of payload || its HMAC tag. */
    bool (*load)(void *context, uint8_t **payload, size_t *payload_length,
                 uint8_t authenticated_file_digest[32]);
    void (*release)(void *context, uint8_t *payload);
    /* One atomic local-file + independent-witness CAS. It must accept only
     * expected_revision/digest and next_revision=expected+1, authenticate the
     * complete next payload, and return its payload||HMAC SHA-256 digest. */
    bool (*store_atomic)(void *context, uint64_t expected_revision,
                         const uint8_t expected_digest[32],
                         const uint8_t *next_payload, size_t next_payload_length,
                         uint8_t next_authenticated_file_digest[32]);
} orbit_package_filesystem_envelope_backend;

/* Execute a file plan and its complete ownership snapshot as one durable
 * transaction. expected_ownership must equal the currently committed snapshot.
 * replacement_ownership is the complete new snapshot, not a delta.
 *
 * The backend must already contain an initialized EMPTY ORBE envelope. The
 * caller must hold ORBIT's cross-process package lock and keep it through
 * backup-directory cleanup. */
orbit_filesystem_code orbit_package_filesystem_journal_execute_enveloped(
    const orbit_package_filesystem_envelope_backend *backend,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    const orbit_package_file_change *changes, size_t change_count,
    const uint8_t *expected_ownership, size_t expected_ownership_length,
    const uint8_t *replacement_ownership, size_t replacement_ownership_length,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context);

/* Recovery rolls back APPLYING/ROLLING_BACK transactions, or finalizes a
 * COMMITTED transaction and promotes its pending ownership snapshot. */
orbit_filesystem_code orbit_package_filesystem_journal_recover_enveloped(
    const orbit_package_filesystem_envelope_backend *backend,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context);

#ifdef __cplusplus
}
#endif
#endif
