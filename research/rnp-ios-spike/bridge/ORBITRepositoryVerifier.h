#ifndef ORBIT_REPOSITORY_VERIFIER_H
#define ORBIT_REPOSITORY_VERIFIER_H

#include "ORBITReleaseMetadata.h"
#include "ORBITTrustPersistence.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ORBIT_REPOSITORY_VERIFY_PAYLOAD_MAX ORBIT_RELEASE_MAX_BYTES

typedef enum {
    ORBIT_REPOSITORY_VERIFY_VALID = 0,
    ORBIT_REPOSITORY_VERIFY_INVALID_ARGUMENT = 1,
    ORBIT_REPOSITORY_VERIFY_TRUST_STORE_ERROR = 2,
    ORBIT_REPOSITORY_VERIFY_SIGNER_NOT_TRUSTED = 3,
    ORBIT_REPOSITORY_VERIFY_SIGNATURE_REJECTED = 4,
    ORBIT_REPOSITORY_VERIFY_RELEASE_METADATA_REJECTED = 5,
    ORBIT_REPOSITORY_VERIFY_REPOSITORY_POLICY_REJECTED = 6,
    ORBIT_REPOSITORY_VERIFY_FRESHNESS_REJECTED = 7,
    ORBIT_REPOSITORY_VERIFY_INDEX_REJECTED = 8,
    ORBIT_REPOSITORY_VERIFY_RESOURCE_LIMIT = 9
} orbit_repository_verify_code;

typedef struct {
    orbit_repository_verify_code code;
    orbit_trust_store_code trust_store_code;
    orbit_rnp_verify_result signature;
    uint64_t release_date;
    uint64_t valid_until;
    size_t authenticated_release_bytes;
    size_t verified_index_bytes;
} orbit_repository_verify_result;

/*
 * Complete fail-closed repository verification path:
 * 1. Load the latest authenticated trust state, advance/persist its clock
 *    floor, and authorize the requested pinned primary fingerprint.
 * 2. Verify the clear-signed InRelease with that exact primary key.
 * 3. Parse only the authenticated cleartext Release payload.
 * 4. Enforce caller-pinned suite, codename, architecture, and component.
 * 5. Enforce Valid-Until or the caller's maximum-age policy.
 * 6. Verify the exact Packages-index path, declared byte length, and SHA-256.
 *
 * The caller must provide the repository's actual Packages-index bytes, not
 * bytes parsed from an unverified cache. This function does not install
 * packages, resolve dependencies, or authorize package execution.
 */
orbit_repository_verify_code orbit_repository_verify_packages_index(
    orbit_repository_trust_state *trust_state,
    const char *repository_id,
    const char *expected_primary_fingerprint,
    const uint8_t *public_key_bundle,
    size_t public_key_bundle_length,
    const uint8_t *inrelease_data,
    size_t inrelease_length,
    const char *expected_suite,
    const char *expected_codename,
    const char *required_architecture,
    const char *required_component,
    const char *relative_index_path,
    const uint8_t *index_data,
    size_t index_length,
    uint64_t now_seconds,
    uint64_t maximum_release_age_seconds,
    uint64_t allowed_future_skew_seconds,
    const orbit_trust_store_backend *trust_backend,
    orbit_repository_verify_result *result);

#ifdef __cplusplus
}
#endif
#endif
