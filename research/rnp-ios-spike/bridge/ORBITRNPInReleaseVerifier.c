#include "ORBITRNPInReleaseVerifier.h"
#include "ORBITRNPTimePolicy.h"

#include <rnp/rnp.h>
#include <rnp/rnp_err.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define ORBIT_MAX_INRELEASE_BYTES (16U * 1024U * 1024U)
#define ORBIT_MAX_PUBLIC_KEY_BYTES (4U * 1024U * 1024U)

static void set_error(orbit_rnp_verify_result *result,
                      orbit_rnp_verify_code code,
                      const char *message) {
    if (!result) return;
    result->code = code;
    if (message) {
        (void) snprintf(result->error, sizeof(result->error), "%s", message);
    }
}

static bool normalize_fingerprint(const char *input, char *output, size_t capacity) {
    size_t written = 0;
    if (!input || !output || capacity < 2) return false;

    for (const unsigned char *cursor = (const unsigned char *) input; *cursor; ++cursor) {
        if (*cursor == ' ' || *cursor == ':' || *cursor == '\t' ||
            *cursor == '\r' || *cursor == '\n') {
            continue;
        }
        if (!isxdigit(*cursor) || written + 1 >= capacity) return false;
        output[written++] = (char) toupper(*cursor);
    }
    output[written] = '\0';
    return written == 40 || written == 64;
}

static bool fingerprints_equal(const char *left, const char *right) {
    char normalized_left[ORBIT_RNP_FINGERPRINT_CAPACITY];
    char normalized_right[ORBIT_RNP_FINGERPRINT_CAPACITY];
    return normalize_fingerprint(left, normalized_left, sizeof(normalized_left)) &&
           normalize_fingerprint(right, normalized_right, sizeof(normalized_right)) &&
           strcmp(normalized_left, normalized_right) == 0;
}

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
) {
    rnp_ffi_t ffi = NULL;
    rnp_input_t key_input = NULL;
    rnp_input_t signed_input = NULL;
    rnp_output_t discarded_output = NULL;
    rnp_op_verify_t verify = NULL;
    rnp_key_handle_t signing_key = NULL;
    rnp_key_handle_t primary_key = NULL;
    rnp_signature_handle_t signature_handle = NULL;
    char *signing_fingerprint = NULL;
    char *hash_algorithm = NULL;
    char *key_algorithm = NULL;
    char *key_curve = NULL;
    char *primary_fingerprint = NULL;
    char expected_primary[ORBIT_RNP_FINGERPRINT_CAPACITY] = {0};
    size_t signature_count = 0;
    size_t imported_public_key_count = 0;
    uint32_t signature_created = 0;
    uint32_t key_created = 0;
    uint64_t key_valid_until = 0;
    uint32_t signature_expires = 0;
    bool is_subkey = false;
    bool primary_valid = false;
    bool primary_revoked = false;
    bool key_valid = false;
    bool key_revoked = false;
    bool can_sign = false;
    orbit_rnp_verify_code outcome = ORBIT_RNP_VERIFY_ENGINE_ERROR;

    if (result) memset(result, 0, sizeof(*result));
    if (payload_length) *payload_length = 0;
    if ((!payload && (payload_capacity != 0 || payload_length != NULL)) ||
        (payload && (!payload_length || payload_capacity == 0))) {
        set_error(result, ORBIT_RNP_VERIFY_INVALID_ARGUMENT, "Payload output arguments are inconsistent.");
        return ORBIT_RNP_VERIFY_INVALID_ARGUMENT;
    }
    if (!result || !inrelease_data || inrelease_length == 0 ||
        !public_key_data || public_key_length == 0 ||
        inrelease_length > ORBIT_MAX_INRELEASE_BYTES ||
        public_key_length > ORBIT_MAX_PUBLIC_KEY_BYTES ||
        !expected_primary_fingerprint || expected_primary_fingerprint[0] == '\0') {
        set_error(result, ORBIT_RNP_VERIFY_INVALID_ARGUMENT, "Missing verifier input.");
        return ORBIT_RNP_VERIFY_INVALID_ARGUMENT;
    }

    if (!normalize_fingerprint(expected_primary_fingerprint,
                               expected_primary,
                               sizeof(expected_primary))) {
        set_error(result, ORBIT_RNP_VERIFY_INVALID_ARGUMENT,
                  "Expected primary fingerprint is malformed.");
        return ORBIT_RNP_VERIFY_INVALID_ARGUMENT;
    }

    if (rnp_ffi_create(&ffi, "GPG", "GPG") != RNP_SUCCESS) {
        set_error(result, ORBIT_RNP_VERIFY_ENGINE_ERROR, "RNP initialization failed.");
        goto cleanup;
    }

    if (rnp_input_from_memory(&key_input, public_key_data, public_key_length, true) != RNP_SUCCESS ||
        rnp_load_keys(ffi, "GPG", key_input, RNP_LOAD_SAVE_PUBLIC_KEYS) != RNP_SUCCESS) {
        outcome = ORBIT_RNP_VERIFY_KEY_IMPORT_FAILED;
        set_error(result, outcome, "Trusted public-key material could not be imported.");
        goto cleanup;
    }

    if (rnp_get_public_key_count(ffi, &imported_public_key_count) != RNP_SUCCESS ||
        imported_public_key_count == 0 ||
        imported_public_key_count > ORBIT_RNP_MAX_IMPORTED_PUBLIC_KEYS) {
        outcome = ORBIT_RNP_VERIFY_KEY_IMPORT_FAILED;
        set_error(result, outcome, "Public-key bundle is empty or exceeds the 32-key import limit.");
        goto cleanup;
    }
    result->public_key_count = imported_public_key_count;


    if (rnp_input_from_memory(&signed_input, inrelease_data, inrelease_length, true) != RNP_SUCCESS ||
        (payload ? rnp_output_to_memory(&discarded_output, payload_capacity) :
                   rnp_output_to_null(&discarded_output)) != RNP_SUCCESS ||
        rnp_op_verify_create(&verify, ffi, signed_input, discarded_output) != RNP_SUCCESS) {
        outcome = ORBIT_RNP_VERIFY_DOCUMENT_REJECTED;
        set_error(result, outcome, "InRelease document could not be parsed for verification.");
        goto cleanup;
    }

    if (rnp_op_verify_set_flags(verify, RNP_VERIFY_REQUIRE_ALL_SIGS) != RNP_SUCCESS) {
        outcome = ORBIT_RNP_VERIFY_ENGINE_ERROR;
        set_error(result, outcome, "Could not require all signatures to verify.");
        goto cleanup;
    }

    if (rnp_op_verify_execute(verify) != RNP_SUCCESS ||
        rnp_op_verify_get_signature_count(verify, &signature_count) != RNP_SUCCESS) {
        outcome = ORBIT_RNP_VERIFY_SIGNATURE_INVALID;
        set_error(result, outcome, "RNP rejected the signed InRelease document.");
        goto cleanup;
    }
    result->signature_count = signature_count;

    if (signature_count != 1) {
        outcome = ORBIT_RNP_VERIFY_SIGNATURE_COUNT_REJECTED;
        set_error(result, outcome, "Exactly one signature is required by ORBIT policy.");
        goto cleanup;
    }

    rnp_op_verify_signature_t verified_signature = NULL;
    if (rnp_op_verify_get_signature_at(verify, 0, &verified_signature) != RNP_SUCCESS ||
        !verified_signature ||
        rnp_op_verify_signature_get_status(verified_signature) != RNP_SUCCESS ||
        rnp_op_verify_signature_get_handle(verified_signature, &signature_handle) != RNP_SUCCESS ||
        !signature_handle ||
        rnp_signature_is_valid(signature_handle, 0) != RNP_SUCCESS) {
        outcome = ORBIT_RNP_VERIFY_SIGNATURE_INVALID;
        set_error(result, outcome, "The sole OpenPGP signature is not valid.");
        goto cleanup;
    }

    if (rnp_op_verify_signature_get_hash(verified_signature, &hash_algorithm) != RNP_SUCCESS ||
        !hash_algorithm ||
        (strcasecmp(hash_algorithm, "SHA256") != 0 &&
         strcasecmp(hash_algorithm, "SHA384") != 0 &&
         strcasecmp(hash_algorithm, "SHA512") != 0 &&
         strcasecmp(hash_algorithm, "SHA-256") != 0 &&
         strcasecmp(hash_algorithm, "SHA-384") != 0 &&
         strcasecmp(hash_algorithm, "SHA-512") != 0)) {
        outcome = ORBIT_RNP_VERIFY_HASH_ALGORITHM_REJECTED;
        set_error(result, outcome, "Only SHA-256, SHA-384, and SHA-512 signatures are accepted.");
        goto cleanup;
    }
    (void) snprintf(result->hash_algorithm, sizeof(result->hash_algorithm), "%s", hash_algorithm);

    if (rnp_op_verify_signature_get_times(verified_signature,
                                          &signature_created,
                                          &signature_expires) != RNP_SUCCESS) {
        outcome = ORBIT_RNP_VERIFY_SIGNATURE_TIME_INVALID;
        set_error(result, outcome, "Signature creation or expiration time is unavailable.");
        goto cleanup;
    }
    result->signature_creation_time = signature_created;
    result->signature_expiration_seconds = signature_expires;

    time_t now = time(NULL);
    if (now < 0 ||
        !orbit_rnp_signature_time_policy_valid(signature_created,
                                               signature_expires,
                                               (uint64_t) now)) {
        outcome = ORBIT_RNP_VERIFY_SIGNATURE_TIME_INVALID;
        set_error(result, outcome, "Signature is future-dated or expired.");
        goto cleanup;
    }

    /* RNP 0.18.1 implementation allocates a fresh key-handle wrapper here;
     * release it with rnp_key_handle_destroy during the common cleanup path. */
    if (rnp_op_verify_signature_get_key(verified_signature, &signing_key) != RNP_SUCCESS ||
        !signing_key ||
        rnp_key_get_fprint(signing_key, &signing_fingerprint) != RNP_SUCCESS ||
        !signing_fingerprint) {
        outcome = ORBIT_RNP_VERIFY_SIGNER_MISMATCH;
        set_error(result, outcome, "The signing key fingerprint is unavailable.");
        goto cleanup;
    }
    if (!normalize_fingerprint(signing_fingerprint,
                               result->signing_fingerprint,
                               sizeof(result->signing_fingerprint))) {
        outcome = ORBIT_RNP_VERIFY_SIGNER_MISMATCH;
        set_error(result, outcome, "RNP returned a malformed signing-key fingerprint.");
        goto cleanup;
    }

    if (rnp_key_get_alg(signing_key, &key_algorithm) != RNP_SUCCESS ||
        !key_algorithm ||
        rnp_key_get_curve(signing_key, &key_curve) != RNP_SUCCESS ||
        !key_curve ||
        strcasecmp(key_algorithm, "EDDSA") != 0 ||
        strcasecmp(key_curve, "ed25519") != 0) {
        outcome = ORBIT_RNP_VERIFY_KEY_ALGORITHM_REJECTED;
        set_error(result, outcome, "Only EdDSA keys on the Ed25519 curve are accepted by v1 policy.");
        goto cleanup;
    }
    (void) snprintf(result->key_algorithm, sizeof(result->key_algorithm), "%s", key_algorithm);
    (void) snprintf(result->key_curve, sizeof(result->key_curve), "%s", key_curve);

    if (rnp_key_is_sub(signing_key, &is_subkey) != RNP_SUCCESS) {
        outcome = ORBIT_RNP_VERIFY_KEY_INVALID;
        set_error(result, outcome, "Could not determine whether the signer is a subkey.");
        goto cleanup;
    }

    if (is_subkey) {
        if (rnp_key_get_primary_fprint(signing_key, &primary_fingerprint) != RNP_SUCCESS ||
            !primary_fingerprint) {
            outcome = ORBIT_RNP_VERIFY_KEY_INVALID;
            set_error(result, outcome, "Signing subkey has no readable primary-key fingerprint.");
            goto cleanup;
        }
    } else {
        primary_fingerprint = signing_fingerprint;
    }

    if (!fingerprints_equal(primary_fingerprint, expected_primary)) {
        outcome = ORBIT_RNP_VERIFY_SIGNER_MISMATCH;
        set_error(result, outcome, "Signature was made by a different primary key.");
        goto cleanup;
    }
    if (!normalize_fingerprint(primary_fingerprint,
                               result->primary_fingerprint,
                               sizeof(result->primary_fingerprint))) {
        outcome = ORBIT_RNP_VERIFY_SIGNER_MISMATCH;
        set_error(result, outcome, "RNP returned a malformed primary-key fingerprint.");
        goto cleanup;
    }

    if (is_subkey) {
        if (rnp_locate_key(ffi, "fingerprint", primary_fingerprint, &primary_key) != RNP_SUCCESS ||
            !primary_key ||
            rnp_key_is_valid(primary_key, &primary_valid) != RNP_SUCCESS ||
            rnp_key_is_revoked(primary_key, &primary_revoked) != RNP_SUCCESS ||
            !primary_valid || primary_revoked) {
            outcome = primary_revoked ? ORBIT_RNP_VERIFY_KEY_REVOKED : ORBIT_RNP_VERIFY_KEY_INVALID;
            set_error(result, outcome, "Primary key is missing, invalid, or revoked.");
            goto cleanup;
        }
    } else {
        primary_valid = true;
    }

    if (rnp_key_is_revoked(signing_key, &key_revoked) != RNP_SUCCESS || key_revoked) {
        outcome = ORBIT_RNP_VERIFY_KEY_REVOKED;
        set_error(result, outcome, "Signing key or subkey is revoked.");
        goto cleanup;
    }

    if (rnp_key_is_valid(signing_key, &key_valid) != RNP_SUCCESS || !key_valid) {
        outcome = ORBIT_RNP_VERIFY_KEY_INVALID;
        set_error(result, outcome, "Signing key or its binding is not currently valid.");
        goto cleanup;
    }

    if (rnp_key_get_creation(signing_key, &key_created) != RNP_SUCCESS ||
        rnp_key_valid_till64(signing_key, &key_valid_until) != RNP_SUCCESS ||
        !orbit_rnp_key_time_policy_valid(signature_created,
                                          key_created,
                                          key_valid_until,
                                          (uint64_t) now)) {
        outcome = ORBIT_RNP_VERIFY_SIGNATURE_TIME_INVALID;
        set_error(result, outcome, "Signing key was never valid, expired, or created after the signature.");
        goto cleanup;
    }

    if (rnp_key_allows_usage(signing_key, "sign", &can_sign) != RNP_SUCCESS || !can_sign) {
        outcome = ORBIT_RNP_VERIFY_KEY_CANNOT_SIGN;
        set_error(result, outcome, "The signing key is not authorized for document signatures.");
        goto cleanup;
    }

    if (payload) {
        uint8_t *authenticated = NULL;
        size_t authenticated_length = 0;
        if (rnp_output_memory_get_buf(discarded_output, &authenticated,
                                      &authenticated_length, true) != RNP_SUCCESS ||
            !authenticated || authenticated_length == 0 ||
            authenticated_length > payload_capacity) {
            if (authenticated) rnp_buffer_destroy(authenticated);
            outcome = ORBIT_RNP_VERIFY_DOCUMENT_REJECTED;
            set_error(result, outcome, "Authenticated cleartext payload could not be safely extracted.");
            goto cleanup;
        }
        memcpy(payload, authenticated, authenticated_length);
        *payload_length = authenticated_length;
        rnp_buffer_destroy(authenticated);
    }

    outcome = ORBIT_RNP_VERIFY_VALID;
    set_error(result, outcome, "Cryptographic signature and pinned primary-key identity verified.");

cleanup:
    if (result) result->code = outcome;
    if (primary_fingerprint && primary_fingerprint != signing_fingerprint) {
        rnp_buffer_destroy(primary_fingerprint);
    }
    if (signing_fingerprint) rnp_buffer_destroy(signing_fingerprint);
    if (key_algorithm) rnp_buffer_destroy(key_algorithm);
    if (key_curve) rnp_buffer_destroy(key_curve);
    if (hash_algorithm) rnp_buffer_destroy(hash_algorithm);
    if (signature_handle) rnp_signature_handle_destroy(signature_handle);
    if (signing_key) rnp_key_handle_destroy(signing_key);
    if (primary_key) rnp_key_handle_destroy(primary_key);
    if (verify) rnp_op_verify_destroy(verify);
    if (discarded_output) rnp_output_destroy(discarded_output);
    if (signed_input) rnp_input_destroy(signed_input);
    if (key_input) rnp_input_destroy(key_input);
    if (ffi) rnp_ffi_destroy(ffi);
    return outcome;
}


bool orbit_rnp_key_bundle_has_primary_fingerprint(
    const uint8_t *public_key_data,
    size_t public_key_length,
    const char *expected_primary_fingerprint
) {
    rnp_ffi_t ffi = NULL;
    rnp_input_t key_input = NULL;
    rnp_key_handle_t key = NULL;
    char *fingerprint = NULL;
    char *algorithm = NULL;
    char *curve = NULL;
    char expected[ORBIT_RNP_FINGERPRINT_CAPACITY] = {0};
    size_t key_count = 0;
    uint32_t created = 0;
    uint64_t valid_until = 0;
    bool is_subkey = true;
    bool is_valid = false;
    bool is_revoked = true;
    bool can_sign = false;
    bool accepted = false;
    time_t now = time(NULL);

    if (!public_key_data || public_key_length == 0 ||
        public_key_length > ORBIT_MAX_PUBLIC_KEY_BYTES ||
        !normalize_fingerprint(expected_primary_fingerprint, expected,
                               sizeof(expected)) || now < 0) goto cleanup;
    if (rnp_ffi_create(&ffi, "GPG", "GPG") != RNP_SUCCESS ||
        rnp_input_from_memory(&key_input, public_key_data, public_key_length, true) != RNP_SUCCESS ||
        rnp_load_keys(ffi, "GPG", key_input, RNP_LOAD_SAVE_PUBLIC_KEYS) != RNP_SUCCESS ||
        rnp_get_public_key_count(ffi, &key_count) != RNP_SUCCESS ||
        key_count == 0 || key_count > ORBIT_RNP_MAX_IMPORTED_PUBLIC_KEYS ||
        rnp_locate_key(ffi, "fingerprint", expected, &key) != RNP_SUCCESS ||
        !key ||
        rnp_key_is_sub(key, &is_subkey) != RNP_SUCCESS || is_subkey ||
        rnp_key_get_fprint(key, &fingerprint) != RNP_SUCCESS || !fingerprint ||
        !fingerprints_equal(fingerprint, expected) ||
        rnp_key_get_alg(key, &algorithm) != RNP_SUCCESS || !algorithm ||
        strcasecmp(algorithm, "EDDSA") != 0 ||
        rnp_key_get_curve(key, &curve) != RNP_SUCCESS || !curve ||
        strcasecmp(curve, "ed25519") != 0 ||
        rnp_key_is_valid(key, &is_valid) != RNP_SUCCESS || !is_valid ||
        rnp_key_is_revoked(key, &is_revoked) != RNP_SUCCESS || is_revoked ||
        rnp_key_allows_usage(key, "sign", &can_sign) != RNP_SUCCESS || !can_sign ||
        rnp_key_get_creation(key, &created) != RNP_SUCCESS ||
        rnp_key_valid_till64(key, &valid_until) != RNP_SUCCESS ||
        !orbit_rnp_key_time_policy_valid(created, created, valid_until, (uint64_t)now)) {
        goto cleanup;
    }
    accepted = true;

cleanup:
    if (fingerprint) rnp_buffer_destroy(fingerprint);
    if (algorithm) rnp_buffer_destroy(algorithm);
    if (curve) rnp_buffer_destroy(curve);
    if (key) rnp_key_handle_destroy(key);
    if (key_input) rnp_input_destroy(key_input);
    if (ffi) rnp_ffi_destroy(ffi);
    return accepted;
}

orbit_rnp_verify_code orbit_rnp_verify_inrelease(
    const uint8_t *inrelease_data,
    size_t inrelease_length,
    const uint8_t *public_key_data,
    size_t public_key_length,
    const char *expected_primary_fingerprint,
    orbit_rnp_verify_result *result
) {
    return orbit_rnp_verify_inrelease_with_payload(
        inrelease_data, inrelease_length, public_key_data, public_key_length,
        expected_primary_fingerprint, result, NULL, 0, NULL);
}
