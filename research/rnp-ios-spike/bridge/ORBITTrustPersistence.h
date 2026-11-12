#ifndef ORBIT_TRUST_PERSISTENCE_H
#define ORBIT_TRUST_PERSISTENCE_H

#include "ORBITRepositoryTrust.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ORBIT_TRUST_STORE_VERSION 1U
#define ORBIT_TRUST_STORE_MAC_BYTES 32U
#define ORBIT_TRUST_STORE_RECORD_MAX 512U

typedef enum {
    ORBIT_TRUST_BACKEND_OK = 0,
    ORBIT_TRUST_BACKEND_NOT_FOUND = 1,
    ORBIT_TRUST_BACKEND_ERROR = 2
} orbit_trust_store_read_result;

typedef enum {
    ORBIT_TRUST_STORE_OK = 0,
    ORBIT_TRUST_STORE_NOT_FOUND = 1,
    ORBIT_TRUST_STORE_INVALID_ARGUMENT = 2,
    ORBIT_TRUST_STORE_IO_ERROR = 3,
    ORBIT_TRUST_STORE_AUTHENTICATION_FAILED = 4,
    ORBIT_TRUST_STORE_ROLLBACK_DETECTED = 5,
    ORBIT_TRUST_STORE_FORMAT_REJECTED = 6,
    ORBIT_TRUST_STORE_REVISION_EXHAUSTED = 7
} orbit_trust_store_code;

/*
 * Platform adapter contract:
 * - begin/end_transaction must provide an exclusive repository-scoped lock
 *   across each complete read/modify/write operation.
 * - read/advance_counter must expose a durable, atomic, non-rollbackable
 *   monotonic counter bound to this device and repository.
 * - write_record_atomic must replace the complete record atomically.
 * - mac must use a device-protected secret unavailable to repository data.
 * - record and MAC must be protected from backup/synchronization rollback.
 *
 * If the platform cannot provide these guarantees, persistence must remain
 * unavailable and repository trust must fail closed. Do not substitute a
 * plain file, UserDefaults, or an ordinary backup-restorable counter.
 */
typedef struct {
    void *context;
    bool (*begin_transaction)(void *context, const char *repository_id);
    void (*end_transaction)(void *context, const char *repository_id);
    bool (*read_counter)(void *context, const char *repository_id,
                         uint64_t *counter);
    bool (*advance_counter)(void *context, const char *repository_id,
                            uint64_t expected, uint64_t next);
    orbit_trust_store_read_result (*read_record)(void *context, const char *repository_id,
                        uint8_t *record, size_t capacity, size_t *length,
                        uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES]);
    bool (*write_record_atomic)(void *context, const char *repository_id,
                                const uint8_t *record, size_t length,
                                const uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES]);
    bool (*mac_record)(void *context, const char *repository_id,
                       const uint8_t *record, size_t length,
                       uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES]);
} orbit_trust_store_backend;

/* Load an existing trust record, or initialize and persist the caller's
 * pinned bootstrap fingerprint only when the backend explicitly reports that
 * no record exists and its monotonic counter is zero. */
orbit_trust_store_code orbit_repository_trust_load_or_initialize(
    orbit_repository_trust_state *state,
    const char *repository_id,
    const char *bootstrap_primary_fingerprint,
    const orbit_trust_store_backend *backend);

/* Transactional wrappers commit trust changes or reload the last durable
 * state (invalidating memory if reload fails). trust_result reports the
 * cryptographic/policy decision; the return value reports storage status. */
orbit_trust_store_code orbit_repository_trust_authorize_rotation_and_store(
    orbit_repository_trust_state *state,
    const char *repository_id,
    const char *expected_repository,
    const uint8_t *rotation_inrelease,
    size_t rotation_inrelease_length,
    const uint8_t *current_public_key_bundle,
    size_t current_bundle_length,
    const uint8_t *candidate_public_key_bundle,
    size_t candidate_bundle_length,
    uint64_t now_seconds,
    const orbit_trust_store_backend *backend,
    orbit_trust_code *trust_result);

/* Persisted emergency recovery: validate with the separately pinned offline
 * root and commit the immediate, zero-grace replacement before returning. */
orbit_trust_store_code orbit_repository_trust_authorize_recovery_rotation_and_store(
    orbit_repository_trust_state *state,
    const char *repository_id,
    const char *expected_repository,
    const uint8_t *recovery_inrelease,
    size_t recovery_inrelease_length,
    const uint8_t *recovery_public_key_bundle,
    size_t recovery_bundle_length,
    const char *pinned_recovery_primary_fingerprint,
    const uint8_t *candidate_public_key_bundle,
    size_t candidate_bundle_length,
    uint64_t now_seconds,
    const orbit_trust_store_backend *backend,
    orbit_trust_code *trust_result);

/* Production lookup: persist/advance the time floor first, then evaluate
 * the requested primary fingerprint at that exact committed timestamp. */
bool orbit_repository_trust_fingerprint_allowed_and_store(
    orbit_repository_trust_state *state, const char *repository_id,
    const char *primary_fingerprint, uint64_t now_seconds,
    const orbit_trust_store_backend *backend,
    orbit_trust_store_code *store_result);

bool orbit_repository_trust_observe_time_and_store(
    orbit_repository_trust_state *state, const char *repository_id,
    uint64_t now_seconds, const orbit_trust_store_backend *backend,
    orbit_trust_store_code *store_result);

bool orbit_repository_trust_advance_and_store(
    orbit_repository_trust_state *state, const char *repository_id,
    uint64_t now_seconds, const orbit_trust_store_backend *backend,
    orbit_trust_store_code *store_result);

bool orbit_repository_trust_prune_previous_and_store(
    orbit_repository_trust_state *state, const char *repository_id,
    uint64_t now_seconds, const orbit_trust_store_backend *backend,
    orbit_trust_store_code *store_result);

/* Load a MAC-authenticated record whose revision matches the platform
 * monotonic counter, or is exactly one ahead as a recoverable staged commit.
 * A missing record is distinct from corruption and storage I/O failure. */
orbit_trust_store_code orbit_repository_trust_store_load(
    orbit_repository_trust_state *state,
    const char *repository_id,
    const orbit_trust_store_backend *backend);

/* Atomically stage the authenticated next-revision record, then advance the
 * monotonic anchor. Load can finish a valid record exactly one revision ahead
 * after a crash. Older records are always rejected. Repeating the same save
 * is safe. */
orbit_trust_store_code orbit_repository_trust_store_save(
    const orbit_repository_trust_state *state,
    const char *repository_id,
    const orbit_trust_store_backend *backend);

#endif
