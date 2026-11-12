#ifndef ORBIT_TRUST_PERSISTENCE_TESTING_H
#define ORBIT_TRUST_PERSISTENCE_TESTING_H

#include "ORBITTrustPersistence.h"

/* Test-harness-only primitive for storage format, crash, and tamper tests.
 * Production code must use the transactional trust policy wrappers. */
orbit_trust_store_code orbit_repository_trust_store_save_for_testing(
    const orbit_repository_trust_state *state,
    const char *repository_id,
    const orbit_trust_store_backend *backend);

#endif
