#ifndef ORBIT_PACKAGE_TRANSACTION_H
#define ORBIT_PACKAGE_TRANSACTION_H

#include "ORBITPackagesIndex.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ORBIT_TRANSACTION_MAX_OPERATIONS 256U
#define ORBIT_TRANSACTION_ID_BYTES 16U
#define ORBIT_TRANSACTION_JOURNAL_VERSION 1U

typedef enum {
    ORBIT_TRANSACTION_INSTALL = 1,
    ORBIT_TRANSACTION_REMOVE = 2
} orbit_transaction_action;

typedef enum {
    ORBIT_TRANSACTION_OK = 0,
    ORBIT_TRANSACTION_INVALID_ARGUMENT,
    ORBIT_TRANSACTION_BUSY,
    ORBIT_TRANSACTION_JOURNAL_ERROR,
    ORBIT_TRANSACTION_RESOLUTION_ERROR,
    ORBIT_TRANSACTION_APPLY_ERROR,
    ORBIT_TRANSACTION_ROLLBACK_REQUIRED,
    ORBIT_TRANSACTION_RECOVERY_REQUIRED,
    ORBIT_TRANSACTION_LIMIT,
    ORBIT_TRANSACTION_NATIVE_LOCK_ERROR
} orbit_transaction_code;

typedef enum {
    ORBIT_TRANSACTION_PHASE_EMPTY = 0,
    ORBIT_TRANSACTION_PHASE_APPLYING = 1,
    ORBIT_TRANSACTION_PHASE_ROLLING_BACK = 2,
    ORBIT_TRANSACTION_PHASE_COMMITTED = 3
} orbit_transaction_phase;

typedef enum {
    ORBIT_TRANSACTION_STEP_PENDING = 0,
    ORBIT_TRANSACTION_STEP_IN_FLIGHT = 1,
    ORBIT_TRANSACTION_STEP_COMPLETE = 2,
    ORBIT_TRANSACTION_STEP_ROLLED_BACK = 3
} orbit_transaction_step_state;

typedef struct {
    uint32_t version;
    uint32_t phase;
    uint64_t revision;
    uint8_t transaction_id[ORBIT_TRANSACTION_ID_BYTES];
    uint32_t operation_count;
    uint32_t rollback_cursor;
    struct {
        uint32_t action;
        uint32_t state;
        char name[ORBIT_PACKAGE_NAME_CAPACITY];
        char version_string[ORBIT_PACKAGE_VERSION_CAPACITY];
        char architecture[ORBIT_PACKAGE_ARCH_CAPACITY];
    } operations[ORBIT_TRANSACTION_MAX_OPERATIONS];
} orbit_transaction_journal;

/* Backend must authenticate the journal, atomically replace durable storage,
 * and reject revision rollback/replay. load returns NOT_FOUND when no journal
 * exists. A successful store is durable before it returns. */
typedef enum {
    ORBIT_JOURNAL_OK = 0,
    ORBIT_JOURNAL_NOT_FOUND,
    ORBIT_JOURNAL_ERROR
} orbit_journal_status;

typedef struct {
    void *context;
    orbit_journal_status (*load)(void *context,
                                 orbit_transaction_journal *journal);
    bool (*store_atomic)(void *context,
                         const orbit_transaction_journal *journal);
    bool (*clear_atomic)(void *context, uint64_t committed_revision);
} orbit_transaction_journal_backend;

/* Resolve identity from trusted package metadata. The returned record remains
 * valid for the duration of the callback. */
typedef const orbit_package_record *(*orbit_transaction_resolve_fn)(
    void *context, const char *name, const char *version,
    const char *architecture);

/* apply and rollback must be idempotent for a package/action pair. rollback
 * must restore the exact pre-transaction state, including partially applied
 * operations. Backend owns safe extraction, path allowlisting, atomic file
 * replacement, permissions, and durable filesystem synchronization. */
typedef bool (*orbit_transaction_package_fn)(
    void *context, orbit_transaction_action action,
    const orbit_package_record *package);

typedef struct {
    void *context;
    orbit_transaction_resolve_fn resolve;
    orbit_transaction_package_fn apply;
    orbit_transaction_package_fn rollback;
} orbit_transaction_package_backend;

orbit_transaction_code orbit_package_transaction_execute(
    const uint8_t transaction_id[ORBIT_TRANSACTION_ID_BYTES],
    const orbit_package_record *const *packages,
    const orbit_transaction_action *actions,
    size_t operation_count,
    const orbit_transaction_journal_backend *journal_backend,
    const orbit_transaction_package_backend *package_backend);

orbit_transaction_code orbit_package_transaction_recover(
    const orbit_transaction_journal_backend *journal_backend,
    const orbit_transaction_package_backend *package_backend);

#ifdef __cplusplus
}
#endif
#endif
