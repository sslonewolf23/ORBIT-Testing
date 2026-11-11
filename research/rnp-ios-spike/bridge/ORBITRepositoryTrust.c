#include "ORBITRepositoryTrust.h"
#include "ORBITReleaseMetadata.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static bool normalize_fingerprint(const char *input, char output[ORBIT_TRUST_FINGERPRINT_CAPACITY]) {
    if (!input || !output) return false;
    size_t length = strlen(input);
    if (length != 40U && length != 64U) return false;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)input[i];
        if (!isxdigit(c)) return false;
        output[i] = (char)toupper(c);
    }
    output[length] = '\0';
    return true;
}

static bool copy_value(char *output, size_t capacity, const char *value, size_t length) {
    if (!output || !value || length == 0 || length >= capacity) return false;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (c < 0x20U || c > 0x7eU) return false;
    }
    memcpy(output, value, length);
    output[length] = '\0';
    return true;
}

static bool valid_repository_id(const char *value) {
    if (!value || !*value) return false;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' || *p == '-'))
            return false;
    }
    return true;
}

bool orbit_trust_rotation_proof_parse(const uint8_t *data, size_t length,
                                      orbit_trust_rotation_proof *proof) {
    if (!data || !proof || length == 0 || length > ORBIT_TRUST_ROTATION_MAX_BYTES ||
        memchr(data, 0, length)) return false;

    orbit_trust_rotation_proof parsed;
    memset(&parsed, 0, sizeof(parsed));
    char activate_text[64] = {0};
    char grace_text[64] = {0};
    bool seen_version = false, seen_repository = false, seen_current = false;
    bool seen_next = false, seen_activate = false, seen_grace = false;
    char *buffer = (char *)data;
    /* Parse without modifying caller-owned authenticated payload. */
    char local[ORBIT_TRUST_ROTATION_MAX_BYTES + 1U];
    memcpy(local, buffer, length);
    local[length] = '\0';
    char *cursor = local;
    bool ok = true;
    while (*cursor && ok) {
        char *end = strchr(cursor, '\n');
        if (end) *end = '\0';
        size_t line_length = strlen(cursor);
        if (line_length && cursor[line_length - 1U] == '\r')
            cursor[--line_length] = '\0';
        if (line_length == 0) {
            ok = false;
        } else {
            char *colon = strchr(cursor, ':');
            if (!colon || colon == cursor || colon[1] != ' ') {
                ok = false;
            } else {
                *colon = '\0';
                const char *value = colon + 2;
                size_t value_length = strlen(value);
                if (strcmp(cursor, "ORBIT-Key-Rotation") == 0) {
                    if (seen_version++ || strcmp(value, "1") != 0) ok = false;
                } else if (strcmp(cursor, "Repository") == 0) {
                    if (seen_repository++ ||
                        !copy_value(parsed.repository, sizeof(parsed.repository), value, value_length) ||
                        !valid_repository_id(parsed.repository)) ok = false;
                } else if (strcmp(cursor, "Current-Fingerprint") == 0) {
                    char raw[ORBIT_TRUST_FINGERPRINT_CAPACITY];
                    if (seen_current++ ||
                        !copy_value(raw, sizeof(raw), value, value_length) ||
                        !normalize_fingerprint(raw, parsed.current_fingerprint)) ok = false;
                } else if (strcmp(cursor, "Next-Fingerprint") == 0) {
                    char raw[ORBIT_TRUST_FINGERPRINT_CAPACITY];
                    if (seen_next++ ||
                        !copy_value(raw, sizeof(raw), value, value_length) ||
                        !normalize_fingerprint(raw, parsed.next_fingerprint)) ok = false;
                } else if (strcmp(cursor, "Activate-At") == 0) {
                    if (seen_activate++ ||
                        !copy_value(activate_text, sizeof(activate_text), value, value_length)) ok = false;
                } else if (strcmp(cursor, "Previous-Key-Valid-Until") == 0) {
                    if (seen_grace++ ||
                        !copy_value(grace_text, sizeof(grace_text), value, value_length)) ok = false;
                } else {
                    ok = false;
                }
            }
        }
        if (!end) break;
        cursor = end + 1;
    }

    if (!seen_version || !seen_repository || !seen_current || !seen_next ||
        !seen_activate || !seen_grace ||
        !orbit_release_parse_timestamp(activate_text, &parsed.activate_at) ||
        !orbit_release_parse_timestamp(grace_text, &parsed.previous_key_valid_until) ||
        strcmp(parsed.current_fingerprint, parsed.next_fingerprint) == 0) ok = false;

    if (ok) *proof = parsed;
    else memset(proof, 0, sizeof(*proof));
    return ok;
}

bool orbit_repository_trust_init(orbit_repository_trust_state *state,
                                 const char *pinned_primary_fingerprint) {
    if (!state || !pinned_primary_fingerprint) return false;
    orbit_repository_trust_state initial;
    memset(&initial, 0, sizeof(initial));
    if (!normalize_fingerprint(pinned_primary_fingerprint, initial.current_fingerprint))
        return false;
    *state = initial;
    return true;
}

static orbit_trust_code schedule_verified_rotation(
    orbit_repository_trust_state *state,
    const char *expected_repository,
    const orbit_trust_rotation_proof *proof,
    const orbit_rnp_verify_result *verified_rotation,
    const uint8_t *candidate_public_key_bundle,
    size_t candidate_bundle_length,
    uint64_t now_seconds) {
    char signer[ORBIT_TRUST_FINGERPRINT_CAPACITY];
    if (!state || !expected_repository || !valid_repository_id(expected_repository) ||
        !proof || !verified_rotation || !candidate_public_key_bundle ||
        candidate_bundle_length == 0) return ORBIT_TRUST_INVALID_ARGUMENT;
    if (state->generation == UINT32_MAX) return ORBIT_TRUST_GENERATION_EXHAUSTED;
    if (state->pending_fingerprint[0] != '\0') return ORBIT_TRUST_ROTATION_ALREADY_PENDING;
    if (verified_rotation->code != ORBIT_RNP_VERIFY_VALID ||
        !normalize_fingerprint(verified_rotation->primary_fingerprint, signer) ||
        strcmp(signer, state->current_fingerprint) != 0 ||
        strcmp(proof->current_fingerprint, state->current_fingerprint) != 0)
        return ORBIT_TRUST_SIGNER_MISMATCH;
    if (strcmp(proof->repository, expected_repository) != 0)
        return ORBIT_TRUST_REPOSITORY_MISMATCH;
    if (strcmp(proof->next_fingerprint, state->current_fingerprint) == 0 ||
        !orbit_rnp_key_bundle_has_primary_fingerprint(candidate_public_key_bundle,
                                                       candidate_bundle_length,
                                                       proof->next_fingerprint))
        return ORBIT_TRUST_CANDIDATE_KEY_REJECTED;
    if (proof->activate_at < now_seconds ||
        proof->activate_at - now_seconds > ORBIT_TRUST_MAX_ACTIVATION_DELAY_SECONDS ||
        proof->previous_key_valid_until < proof->activate_at ||
        proof->previous_key_valid_until - proof->activate_at >
            ORBIT_TRUST_MAX_PREVIOUS_KEY_GRACE_SECONDS)
        return ORBIT_TRUST_ROTATION_WINDOW_REJECTED;

    memcpy(state->pending_fingerprint, proof->next_fingerprint,
           sizeof(state->pending_fingerprint));
    state->pending_activation = proof->activate_at;
    state->previous_valid_until = proof->previous_key_valid_until;
    return ORBIT_TRUST_ACCEPTED;
}


orbit_trust_code orbit_repository_trust_authorize_rotation(
    orbit_repository_trust_state *state,
    const char *expected_repository,
    const uint8_t *rotation_inrelease,
    size_t rotation_inrelease_length,
    const uint8_t *current_public_key_bundle,
    size_t current_bundle_length,
    const uint8_t *candidate_public_key_bundle,
    size_t candidate_bundle_length,
    uint64_t now_seconds) {
    if (!state || !expected_repository || !rotation_inrelease ||
        rotation_inrelease_length == 0 || !current_public_key_bundle ||
        current_bundle_length == 0 || !candidate_public_key_bundle ||
        candidate_bundle_length == 0) return ORBIT_TRUST_INVALID_ARGUMENT;

    uint8_t *authenticated_payload = (uint8_t *)malloc(ORBIT_TRUST_ROTATION_MAX_BYTES);
    if (!authenticated_payload) return ORBIT_TRUST_INVALID_ARGUMENT;
    size_t authenticated_length = 0;
    orbit_rnp_verify_result verification;
    orbit_rnp_verify_code verify_code = orbit_rnp_verify_inrelease_with_payload(
        rotation_inrelease, rotation_inrelease_length,
        current_public_key_bundle, current_bundle_length,
        state->current_fingerprint, &verification,
        authenticated_payload, ORBIT_TRUST_ROTATION_MAX_BYTES,
        &authenticated_length);
    if (verify_code != ORBIT_RNP_VERIFY_VALID) {
        free(authenticated_payload);
        return ORBIT_TRUST_ROTATION_SIGNATURE_REJECTED;
    }

    orbit_trust_rotation_proof proof;
    bool parsed = orbit_trust_rotation_proof_parse(authenticated_payload,
                                                    authenticated_length, &proof);
    memset(authenticated_payload, 0, ORBIT_TRUST_ROTATION_MAX_BYTES);
    free(authenticated_payload);
    if (!parsed) return ORBIT_TRUST_PROOF_MALFORMED;
    return schedule_verified_rotation(state, expected_repository, &proof,
                                      &verification, candidate_public_key_bundle,
                                      candidate_bundle_length, now_seconds);
}

bool orbit_repository_trust_advance(orbit_repository_trust_state *state,
                                    uint64_t now_seconds) {
    if (!state || state->pending_fingerprint[0] == '\0' ||
        now_seconds < state->pending_activation ||
        state->generation == UINT32_MAX) return false;
    memcpy(state->previous_fingerprint, state->current_fingerprint,
           sizeof(state->previous_fingerprint));
    memcpy(state->current_fingerprint, state->pending_fingerprint,
           sizeof(state->current_fingerprint));
    memset(state->pending_fingerprint, 0, sizeof(state->pending_fingerprint));
    state->pending_activation = 0;
    ++state->generation;
    return true;
}

bool orbit_repository_trust_fingerprint_allowed(
    const orbit_repository_trust_state *state,
    const char *primary_fingerprint,
    uint64_t now_seconds) {
    char normalized[ORBIT_TRUST_FINGERPRINT_CAPACITY];
    if (!state || !normalize_fingerprint(primary_fingerprint, normalized)) return false;
    if (strcmp(normalized, state->current_fingerprint) == 0) return true;
    return state->previous_fingerprint[0] != '\0' &&
           strcmp(normalized, state->previous_fingerprint) == 0 &&
           now_seconds <= state->previous_valid_until;
}
