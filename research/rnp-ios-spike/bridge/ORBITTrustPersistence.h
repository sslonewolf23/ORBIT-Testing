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
    bool (*read_counter)(void *context, const char *repository_id,
                         uint64_t *counter);
    bool (*advance_counter)(void *context, const char *repository_id,
                            uint64_t expected, uint64_t next);
    bool (*read_record)(void *context, const char *repository_id,
                        uint8_t *record, size_t capacity, size_t *length,
                        uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES]);
    bool (*write_record_atomic)(void *context, const char *repository_id,
                                const uint8_t *record, size_t length,
                                const uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES]);
    bool (*mac_record)(void *context, const char *repository_id,
                       const uint8_t *record, size_t length,
                       uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES]);
} orbit_trust_store_backend;

/* Load only a MAC-authenticated record whose revision exactly matches the
 * platform monotonic counter. A missing record is distinct from corruption. */
orbit_trust_store_code orbit_repository_trust_store_load(
    orbit_repository_trust_state *state,
    const char *repository_id,
    const orbit_trust_store_backend *backend);

/* Advance the monotonic anchor before atomic record replacement. A crash
 * between those operations intentionally makes the record unavailable rather
 * than accepting an older trust snapshot. Repeating the same save is safe. */
orbit_trust_store_code orbit_repository_trust_store_save(
    const orbit_repository_trust_state *state,
    const char *repository_id,
    const orbit_trust_store_backend *backend);

#endif
