#ifndef ORBIT_RNP_INRELEASE_VERIFIER_H
#define ORBIT_RNP_INRELEASE_VERIFIER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ORBIT_RNP_FINGERPRINT_CAPACITY 96
#define ORBIT_RNP_ERROR_CAPACITY 192
#define ORBIT_RNP_MAX_IMPORTED_PUBLIC_KEYS 32

typedef enum {
    ORBIT_RNP_VERIFY_VALID = 0,
    ORBIT_RNP_VERIFY_INVALID_ARGUMENT = 1,
    ORBIT_RNP_VERIFY_ENGINE_ERROR = 2,
    ORBIT_RNP_VERIFY_KEY_IMPORT_FAILED = 3,
    ORBIT_RNP_VERIFY_DOCUMENT_REJECTED = 4,
    ORBIT_RNP_VERIFY_SIGNATURE_COUNT_REJECTED = 5,
    ORBIT_RNP_VERIFY_SIGNATURE_INVALID = 6,
    ORBIT_RNP_VERIFY_SIGNER_MISMATCH = 7,
    ORBIT_RNP_VERIFY_KEY_REVOKED = 8,
    ORBIT_RNP_VERIFY_KEY_INVALID = 9,
    ORBIT_RNP_VERIFY_KEY_CANNOT_SIGN = 10,
    ORBIT_RNP_VERIFY_SIGNATURE_TIME_INVALID = 11,
    ORBIT_RNP_VERIFY_HASH_ALGORITHM_REJECTED = 12,
    ORBIT_RNP_VERIFY_KEY_ALGORITHM_REJECTED = 13
} orbit_rnp_verify_code;

typedef struct {
    orbit_rnp_verify_code code;
    char primary_fingerprint[ORBIT_RNP_FINGERPRINT_CAPACITY];
    char signing_fingerprint[ORBIT_RNP_FINGERPRINT_CAPACITY];
    char hash_algorithm[16];
    char key_algorithm[16];
    char key_curve[32];
    char error[ORBIT_RNP_ERROR_CAPACITY];
    uint32_t signature_creation_time;
    uint32_t signature_expiration_seconds;
    size_t signature_count;
    size_t public_key_count;
} orbit_rnp_verify_result;

/*
 * Verify a Debian-style clear-signed InRelease document against one supplied
 * public-key bundle and an explicitly pinned PRIMARY key fingerprint.
 *
 * This function establishes cryptographic validity and signer identity only.
 * It does not establish repository policy, key rotation authorization, package
 * hash validity, freshness, or installation safety.
 *
 * key_data may be ASCII-armored or binary OpenPGP public-key data accepted by
 * RNP's GPG key loader. The bundle is limited to 4 MiB and 32 imported public
 * keys. Exactly one signature is required.
 *
 * Returns ORBIT_RNP_VERIFY_VALID only when every check in this bridge passes.
 * All other outcomes are fail-closed.
 */
orbit_rnp_verify_code orbit_rnp_verify_inrelease(
    const uint8_t *inrelease_data,
    size_t inrelease_length,
    const uint8_t *public_key_data,
    size_t public_key_length,
    const char *expected_primary_fingerprint,
    orbit_rnp_verify_result *result
);

/* Same strict verification policy, with an optional bounded copy of the
 * authenticated cleartext payload. If payload is NULL, payload_length must
 * also be NULL. If payload is non-NULL, payload_capacity is required and
 * payload_length receives the exact authenticated payload length on success.
 * Payload is copied only after every signature, signer, key, and time check. */
/* Confirm that a supplied public-key bundle contains the exact, valid,
 * unrevoked Ed25519 primary signing key named by expected_primary_fingerprint. */
bool orbit_rnp_key_bundle_has_primary_fingerprint(
    const uint8_t *public_key_data,
    size_t public_key_length,
    const char *expected_primary_fingerprint
);

orbit_rnp_verify_code orbit_rnp_verify_inrelease_with_payload(
    const uint8_t *inrelease_data,
    size_t inrelease_length,
    const uint8_t *public_key_data,
    size_t public_key_length,
    const char *expected_primary_fingerprint,
    orbit_rnp_verify_result *result,
    uint8_t *payload,
    size_t payload_capacity,
    size_t *payload_length
);

#ifdef __cplusplus
}
#endif

#endif
