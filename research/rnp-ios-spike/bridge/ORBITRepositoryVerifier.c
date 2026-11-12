#include "ORBITRepositoryVerifier.h"

#include <stdlib.h>
#include <string.h>

#define ORBIT_REPOSITORY_MAX_INRELEASE_BYTES (16U * 1024U * 1024U)

static bool nonempty(const char *value) {
    return value != NULL && value[0] != '\0';
}

static void secure_clear(void *memory, size_t length) {
    volatile uint8_t *p = (volatile uint8_t *)memory;
    while (length-- != 0U) *p++ = 0U;
}

void orbit_repository_verify_result_destroy(orbit_repository_verify_result *result) {
    if(!result)return;
    orbit_packages_index_destroy(&result->packages);
    memset(result,0,sizeof(*result));
}

static orbit_repository_verify_code finish(
    orbit_repository_verify_result *result,
    orbit_repository_verify_code code) {
    result->code = code;
    return code;
}

orbit_repository_verify_code orbit_repository_verify_packages_index(
    orbit_repository_trust_state *trust_state,
    const char *repository_id,
    const char *expected_primary_fingerprint,
    const uint8_t *public_key_bundle,
    size_t public_key_bundle_length,
    const uint8_t *inrelease_data,
    size_t inrelease_length,
    const char *expected_origin,
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
    orbit_repository_verify_result *result) {
    if (result == NULL) return ORBIT_REPOSITORY_VERIFY_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    result->code = ORBIT_REPOSITORY_VERIFY_INVALID_ARGUMENT;
    result->trust_store_code = ORBIT_TRUST_STORE_INVALID_ARGUMENT;
    result->signature.code = ORBIT_RNP_VERIFY_INVALID_ARGUMENT;

    if (trust_state == NULL || !nonempty(repository_id) ||
        !nonempty(expected_primary_fingerprint) ||
        public_key_bundle == NULL || public_key_bundle_length == 0U ||
        inrelease_data == NULL || inrelease_length == 0U ||
        !nonempty(expected_origin) || !nonempty(expected_suite) || !nonempty(expected_codename) ||
        !nonempty(required_architecture) || !nonempty(required_component) ||
        !nonempty(relative_index_path) || index_data == NULL ||
        index_length == 0U || now_seconds == 0U ||
        maximum_release_age_seconds == 0U || trust_backend == NULL) {
        return finish(result, ORBIT_REPOSITORY_VERIFY_INVALID_ARGUMENT);
    }
    if (inrelease_length > ORBIT_REPOSITORY_MAX_INRELEASE_BYTES ||
        public_key_bundle_length > 4U * 1024U * 1024U ||
        index_length > ORBIT_RELEASE_MAX_BYTES) {
        return finish(result, ORBIT_REPOSITORY_VERIFY_RESOURCE_LIMIT);
    }

    bool signer_allowed = orbit_repository_trust_fingerprint_allowed_and_store(
        trust_state, repository_id, expected_primary_fingerprint, now_seconds,
        trust_backend, &result->trust_store_code);
    if (result->trust_store_code != ORBIT_TRUST_STORE_OK) {
        return finish(result, ORBIT_REPOSITORY_VERIFY_TRUST_STORE_ERROR);
    }
    if (!signer_allowed) {
        return finish(result, ORBIT_REPOSITORY_VERIFY_SIGNER_NOT_TRUSTED);
    }

    uint8_t *authenticated_payload =
        (uint8_t *)malloc(ORBIT_REPOSITORY_VERIFY_PAYLOAD_MAX);
    orbit_release_metadata *metadata =
        (orbit_release_metadata *)calloc(1U, sizeof(*metadata));
    if (authenticated_payload == NULL || metadata == NULL) {
        if (authenticated_payload != NULL) {
            secure_clear(authenticated_payload,
                         ORBIT_REPOSITORY_VERIFY_PAYLOAD_MAX);
            free(authenticated_payload);
        }
        free(metadata);
        return finish(result, ORBIT_REPOSITORY_VERIFY_RESOURCE_LIMIT);
    }

    size_t authenticated_length = 0U;
    result->signature.code = orbit_rnp_verify_inrelease_with_payload(
        inrelease_data, inrelease_length, public_key_bundle,
        public_key_bundle_length, expected_primary_fingerprint,
        &result->signature, authenticated_payload,
        ORBIT_REPOSITORY_VERIFY_PAYLOAD_MAX, &authenticated_length);
    if (result->signature.code != ORBIT_RNP_VERIFY_VALID) {
        secure_clear(authenticated_payload,
                     ORBIT_REPOSITORY_VERIFY_PAYLOAD_MAX);
        free(authenticated_payload);
        free(metadata);
        return finish(result, ORBIT_REPOSITORY_VERIFY_SIGNATURE_REJECTED);
    }
    result->authenticated_release_bytes = authenticated_length;

    if (!orbit_release_metadata_parse(authenticated_payload,
                                      authenticated_length, metadata)) {
        secure_clear(authenticated_payload,
                     ORBIT_REPOSITORY_VERIFY_PAYLOAD_MAX);
        free(authenticated_payload);
        free(metadata);
        return finish(result, ORBIT_REPOSITORY_VERIFY_RELEASE_METADATA_REJECTED);
    }
    secure_clear(authenticated_payload, ORBIT_REPOSITORY_VERIFY_PAYLOAD_MAX);
    free(authenticated_payload);

    if (!orbit_release_metadata_matches_repository_policy(
            metadata, expected_origin, expected_suite, expected_codename,
            required_architecture, required_component)) {
        free(metadata);
        return finish(result, ORBIT_REPOSITORY_VERIFY_REPOSITORY_POLICY_REJECTED);
    }

    if (!orbit_release_metadata_timestamps(
            metadata, &result->release_date, &result->valid_until) ||
        !orbit_release_freshness_valid(
            result->release_date, result->valid_until, now_seconds,
            maximum_release_age_seconds, allowed_future_skew_seconds)) {
        free(metadata);
        return finish(result, ORBIT_REPOSITORY_VERIFY_FRESHNESS_REJECTED);
    }

    bool index_valid = orbit_release_verify_index(
        metadata, result->signature.code, relative_index_path,
        index_data, index_length);
    free(metadata);
    if (!index_valid) {
        return finish(result, ORBIT_REPOSITORY_VERIFY_INDEX_REJECTED);
    }

    orbit_packages_index parsed_packages;
    memset(&parsed_packages, 0, sizeof(parsed_packages));
    if (!orbit_packages_index_parse(index_data, index_length, &parsed_packages)) {
        return finish(result, ORBIT_REPOSITORY_VERIFY_PACKAGE_INDEX_MALFORMED);
    }

    for(size_t i=0U;i<parsed_packages.count;++i) {
        const char *architecture=parsed_packages.packages[i].architecture;
        if(strcmp(architecture,required_architecture)!=0&&strcmp(architecture,"all")!=0) {
            orbit_packages_index_destroy(&parsed_packages);
            return finish(result,ORBIT_REPOSITORY_VERIFY_PACKAGE_ARCHITECTURE_REJECTED);
        }
    }

    /* Recheck the pin after the expensive signature and digest work so a
     * concurrent emergency rotation cannot leave a stale authorization. */
    bool still_authorized = orbit_repository_trust_fingerprint_allowed_and_store(
        trust_state, repository_id, expected_primary_fingerprint, now_seconds,
        trust_backend, &result->trust_store_code);
    if (result->trust_store_code != ORBIT_TRUST_STORE_OK) {
        orbit_packages_index_destroy(&parsed_packages);
        return finish(result, ORBIT_REPOSITORY_VERIFY_TRUST_STORE_ERROR);
    }
    if (!still_authorized) {
        orbit_packages_index_destroy(&parsed_packages);
        return finish(result, ORBIT_REPOSITORY_VERIFY_SIGNER_NOT_TRUSTED);
    }

    result->packages = parsed_packages;
    result->package_count = parsed_packages.count;
    parsed_packages.packages = NULL;
    parsed_packages.count = 0U;
    result->verified_index_bytes = index_length;
    return finish(result, ORBIT_REPOSITORY_VERIFY_VALID);
}
