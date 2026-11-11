#ifndef ORBIT_REPOSITORY_TRUST_H
#define ORBIT_REPOSITORY_TRUST_H

#include "ORBITRNPInReleaseVerifier.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ORBIT_TRUST_FINGERPRINT_CAPACITY 65U
#define ORBIT_TRUST_REPOSITORY_CAPACITY 96U
#define ORBIT_TRUST_ROTATION_MAX_BYTES (64U * 1024U)
#define ORBIT_TRUST_MAX_ACTIVATION_DELAY_SECONDS (90ULL * 24ULL * 60ULL * 60ULL)
#define ORBIT_TRUST_MAX_PREVIOUS_KEY_GRACE_SECONDS (30ULL * 24ULL * 60ULL * 60ULL)

typedef struct {
    char repository[ORBIT_TRUST_REPOSITORY_CAPACITY];
    char current_fingerprint[ORBIT_TRUST_FINGERPRINT_CAPACITY];
    char next_fingerprint[ORBIT_TRUST_FINGERPRINT_CAPACITY];
    uint64_t activate_at;
    uint64_t previous_key_valid_until;
} orbit_trust_rotation_proof;

typedef struct {
    char current_fingerprint[ORBIT_TRUST_FINGERPRINT_CAPACITY];
    char previous_fingerprint[ORBIT_TRUST_FINGERPRINT_CAPACITY];
    char pending_fingerprint[ORBIT_TRUST_FINGERPRINT_CAPACITY];
    uint64_t pending_activation;
    uint64_t previous_valid_until;
    uint64_t last_observed_time;
    uint32_t generation;
    uint64_t revision;
} orbit_repository_trust_state;

typedef enum {
    ORBIT_TRUST_ACCEPTED = 0,
    ORBIT_TRUST_INVALID_ARGUMENT = 1,
    ORBIT_TRUST_PROOF_MALFORMED = 2,
    ORBIT_TRUST_SIGNER_MISMATCH = 3,
    ORBIT_TRUST_REPOSITORY_MISMATCH = 4,
    ORBIT_TRUST_CANDIDATE_KEY_REJECTED = 5,
    ORBIT_TRUST_ROTATION_WINDOW_REJECTED = 6,
    ORBIT_TRUST_ROTATION_ALREADY_PENDING = 7,
    ORBIT_TRUST_GENERATION_EXHAUSTED = 8,
    ORBIT_TRUST_ROTATION_SIGNATURE_REJECTED = 9,
    ORBIT_TRUST_PREVIOUS_KEY_GRACE_ACTIVE = 10
} orbit_trust_code;

/* Parse only the dedicated ORBIT rotation statement from authenticated bytes.
 * Caller MUST obtain bytes through orbit_rnp_verify_inrelease_with_payload(). */
bool orbit_trust_rotation_proof_parse(const uint8_t *data, size_t length,
                                      orbit_trust_rotation_proof *proof);

bool orbit_repository_trust_init(orbit_repository_trust_state *state,
                                 const char *pinned_primary_fingerprint);

/* Verify the signed rotation document with the currently pinned key,
 * extract only its authenticated cleartext, parse its proof, and validate
 * the candidate key bundle before scheduling activation. */
orbit_trust_code orbit_repository_trust_authorize_rotation(
    orbit_repository_trust_state *state,
    const char *expected_repository,
    const uint8_t *rotation_inrelease,
    size_t rotation_inrelease_length,
    const uint8_t *current_public_key_bundle,
    size_t current_bundle_length,
    const uint8_t *candidate_public_key_bundle,
    size_t candidate_bundle_length,
    uint64_t now_seconds);

/* Apply a scheduled rotation at/after activation. Previous key remains
 * authorized only until its signed grace deadline. */
bool orbit_repository_trust_advance(orbit_repository_trust_state *state,
                                    uint64_t now_seconds);
/* Persisted callers must advance this floor before making a trust decision.
 * Fingerprint checks accept only the exact last-observed timestamp. */
bool orbit_repository_trust_observe_time(orbit_repository_trust_state *state,
                                         uint64_t now_seconds);

/* Remove the previous key only after its signed grace deadline. This is
 * a persisted trust-state mutation and advances the durable revision. */
bool orbit_repository_trust_prune_previous(orbit_repository_trust_state *state,
                                           uint64_t now_seconds);

bool orbit_repository_trust_fingerprint_allowed(
    const orbit_repository_trust_state *state,
    const char *primary_fingerprint,
    uint64_t now_seconds);

#endif
