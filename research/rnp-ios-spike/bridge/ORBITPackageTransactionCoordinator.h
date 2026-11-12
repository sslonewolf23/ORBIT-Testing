#ifndef ORBIT_PACKAGE_TRANSACTION_COORDINATOR_H
#define ORBIT_PACKAGE_TRANSACTION_COORDINATOR_H

#include "ORBITPackageTransaction.h"
#include "ORBITPackageBootstrapLockset.h"
#include "ORBITAPTConfigResolver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The caller must already hold ORBIT's own cross-process transaction lock and
 * supply a verified bootstrap root descriptor plus the active APT status
 * path resolved beneath that root. This layer serializes all native-lock
 * handles in this process (fcntl locks are process-associated), acquires
 * APT's frontend/dpkg locks, and keeps them held through execute/recovery. */
typedef struct {
    int bootstrap_root_descriptor;
    const orbit_bootstrap_profile *profile;
    /* APT-visible prefix, not necessarily the physical path used to open root fd. */
    const char *bootstrap_root_apt_path;
    /* Exact effective Dir::State::status returned by initialized libapt-pkg. */
    const char *effective_status_path;
    uid_t expected_owner;
} orbit_transaction_native_lock_context;

orbit_transaction_code orbit_package_transaction_execute_coordinated(
    const orbit_transaction_native_lock_context *native_context,
    const uint8_t transaction_id[ORBIT_TRANSACTION_ID_BYTES],
    const orbit_package_record *const *packages,
    const orbit_transaction_action *actions,
    size_t operation_count,
    const orbit_transaction_journal_backend *journal_backend,
    const orbit_transaction_package_backend *package_backend);

orbit_transaction_code orbit_package_transaction_recover_coordinated(
    const orbit_transaction_native_lock_context *native_context,
    const orbit_transaction_journal_backend *journal_backend,
    const orbit_transaction_package_backend *package_backend);

#ifdef __cplusplus
}
#endif
#endif
