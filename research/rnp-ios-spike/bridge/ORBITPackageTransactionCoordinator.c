#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageTransactionCoordinator.h"

#include <stdatomic.h>
#include <string.h>

/* A second lockset for the same inode in this process could release the first
 * caller's POSIX record lock when its descriptor closes. Reject concurrent
 * coordinator entry rather than allowing that unsafe descriptor lifecycle. */
static atomic_flag g_native_transaction_gate = ATOMIC_FLAG_INIT;

static orbit_transaction_code native_enter(
    const orbit_transaction_native_lock_context *context,
    orbit_bootstrap_lockset *lockset) {
    if (!context || context->bootstrap_root_descriptor < 0 ||
        !context->profile || !context->observed_admin_relative)
        return ORBIT_TRANSACTION_INVALID_ARGUMENT;
    if (atomic_flag_test_and_set_explicit(
            &g_native_transaction_gate, memory_order_acquire))
        return ORBIT_TRANSACTION_BUSY;

    memset(lockset, 0, sizeof(*lockset));
    lockset->directory_descriptor = -1;
    for (size_t i = 0; i < ORBIT_BOOTSTRAP_LOCKSET_CAPACITY; ++i)
        lockset->locks[i].descriptor = -1;

    orbit_native_lock_code acquired = orbit_bootstrap_lockset_acquire(
        context->bootstrap_root_descriptor, context->profile,
        context->observed_admin_relative, context->expected_owner, lockset);
    if (acquired == ORBIT_NATIVE_LOCK_OK) return ORBIT_TRANSACTION_OK;

    atomic_flag_clear_explicit(&g_native_transaction_gate,
                               memory_order_release);
    if (acquired == ORBIT_NATIVE_LOCK_BUSY) return ORBIT_TRANSACTION_BUSY;
    if (acquired == ORBIT_NATIVE_LOCK_INVALID_ARGUMENT)
        return ORBIT_TRANSACTION_INVALID_ARGUMENT;
    return ORBIT_TRANSACTION_NATIVE_LOCK_ERROR;
}

static orbit_transaction_code native_leave(
    orbit_bootstrap_lockset *lockset,
    orbit_transaction_code transaction_result) {
    orbit_native_lock_code released = orbit_bootstrap_lockset_release(lockset);
    atomic_flag_clear_explicit(&g_native_transaction_gate,
                               memory_order_release);
    /* A release/identity failure is a hard coordination failure even if the
     * package operation itself returned another error. The durable journal
     * remains the source of truth for any required subsequent recovery. */
    return released == ORBIT_NATIVE_LOCK_OK ?
        transaction_result : ORBIT_TRANSACTION_NATIVE_LOCK_ERROR;
}

orbit_transaction_code orbit_package_transaction_execute_coordinated(
    const orbit_transaction_native_lock_context *native_context,
    const uint8_t transaction_id[ORBIT_TRANSACTION_ID_BYTES],
    const orbit_package_record *const *packages,
    const orbit_transaction_action *actions, size_t operation_count,
    const orbit_transaction_journal_backend *journal_backend,
    const orbit_transaction_package_backend *package_backend) {
    if (!transaction_id || !packages || !actions || operation_count == 0U ||
        operation_count > ORBIT_TRANSACTION_MAX_OPERATIONS ||
        !journal_backend || !package_backend)
        return ORBIT_TRANSACTION_INVALID_ARGUMENT;

    orbit_bootstrap_lockset lockset;
    orbit_transaction_code entered = native_enter(native_context, &lockset);
    if (entered != ORBIT_TRANSACTION_OK) return entered;

    orbit_transaction_code result = orbit_package_transaction_execute(
        transaction_id, packages, actions, operation_count,
        journal_backend, package_backend);
    return native_leave(&lockset, result);
}

orbit_transaction_code orbit_package_transaction_recover_coordinated(
    const orbit_transaction_native_lock_context *native_context,
    const orbit_transaction_journal_backend *journal_backend,
    const orbit_transaction_package_backend *package_backend) {
    if (!journal_backend || !package_backend)
        return ORBIT_TRANSACTION_INVALID_ARGUMENT;

    orbit_bootstrap_lockset lockset;
    orbit_transaction_code entered = native_enter(native_context, &lockset);
    if (entered != ORBIT_TRANSACTION_OK) return entered;

    orbit_transaction_code result = orbit_package_transaction_recover(
        journal_backend, package_backend);
    return native_leave(&lockset, result);
}
