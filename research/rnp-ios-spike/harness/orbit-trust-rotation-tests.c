#include "ORBITRepositoryTrust.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned checks = 0, failures = 0;
static void expect(const char *name, bool actual, bool wanted) {
    ++checks;
    if (actual != wanted) {
        fprintf(stderr, "FAIL %s actual=%d expected=%d\n", name, actual, wanted);
        ++failures;
    } else {
        printf("PASS %s\n", name);
    }
}
static uint8_t *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return NULL; }
    long size = ftell(file);
    if (size <= 0 || size > 4 * 1024 * 1024 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file); return NULL;
    }
    uint8_t *data = (uint8_t *)malloc((size_t)size);
    if (!data) { fclose(file); return NULL; }
    if (fread(data, 1, (size_t)size, file) != (size_t)size) {
        free(data); fclose(file); return NULL;
    }
    fclose(file); *length = (size_t)size; return data;
}
static char *read_text(const char *path) {
    size_t length = 0;
    uint8_t *data = read_file(path, &length);
    if (!data) return NULL;
    char *text = (char *)malloc(length + 1U);
    if (!text) { free(data); return NULL; }
    memcpy(text, data, length); text[length] = '\0'; free(data); return text;
}
int main(int argc, char **argv) {
    if (argc != 13) {
        fprintf(stderr, "usage: %s trusted-keyring rotation.InRelease trusted-fpr candidate-keyring candidate-fpr wrong-keyring combined-keyring unauthorized-rotation expired-keyring expired-fpr revoked-keyring revoked-fpr\n", argv[0]);
        return 2;
    }
    size_t trusted_len = 0, rotation_len = 0, candidate_len = 0, wrong_len = 0;
    size_t combined_len = 0, unauthorized_len = 0, expired_len = 0, revoked_len = 0;
    uint8_t *trusted = read_file(argv[1], &trusted_len);
    uint8_t *rotation = read_file(argv[2], &rotation_len);
    char *trusted_fpr = read_text(argv[3]);
    uint8_t *candidate = read_file(argv[4], &candidate_len);
    char *candidate_fpr = read_text(argv[5]);
    uint8_t *wrong_candidate = read_file(argv[6], &wrong_len);
    uint8_t *combined = read_file(argv[7], &combined_len);
    uint8_t *unauthorized = read_file(argv[8], &unauthorized_len);
    uint8_t *expired = read_file(argv[9], &expired_len);
    char *expired_fpr = read_text(argv[10]);
    uint8_t *revoked = read_file(argv[11], &revoked_len);
    char *revoked_fpr = read_text(argv[12]);
    if (!trusted || !rotation || !trusted_fpr || !candidate || !candidate_fpr || !wrong_candidate || !combined || !unauthorized || !expired || !expired_fpr || !revoked || !revoked_fpr) {
        fprintf(stderr, "fixture read failed\n");
        return 2;
    }
    trusted_fpr[strcspn(trusted_fpr, "\r\n")] = '\0';
    candidate_fpr[strcspn(candidate_fpr, "\r\n")] = '\0';
    expired_fpr[strcspn(expired_fpr, "\r\n")] = '\0';
    revoked_fpr[strcspn(revoked_fpr, "\r\n")] = '\0';

    expect("candidate-bundle-exact-primary", orbit_rnp_key_bundle_has_primary_fingerprint(
        candidate, candidate_len, candidate_fpr), true);
    expect("candidate-bundle-rejects-wrong-primary", orbit_rnp_key_bundle_has_primary_fingerprint(
        candidate, candidate_len, trusted_fpr), false);
    expect("expired-candidate-key-rejected", orbit_rnp_key_bundle_has_primary_fingerprint(
        expired, expired_len, expired_fpr), false);
    expect("revoked-candidate-key-rejected", orbit_rnp_key_bundle_has_primary_fingerprint(
        revoked, revoked_len, revoked_fpr), false);
    orbit_rnp_verify_result unauthorized_result;
    orbit_rnp_verify_code unauthorized_code = orbit_rnp_verify_inrelease(
        unauthorized, unauthorized_len, combined, combined_len, trusted_fpr,
        &unauthorized_result);
    expect("unauthorized-new-key-cannot-authorize-rotation",
        unauthorized_code == ORBIT_RNP_VERIFY_SIGNER_MISMATCH, true);
    uint8_t rejected_payload[ORBIT_TRUST_ROTATION_MAX_BYTES];
    memset(rejected_payload, 0x5a, sizeof(rejected_payload));
    size_t rejected_payload_length = 99U;
    orbit_rnp_verify_result rejected_result;
    orbit_rnp_verify_code rejected_code = orbit_rnp_verify_inrelease_with_payload(
        unauthorized, unauthorized_len, combined, combined_len, trusted_fpr,
        &rejected_result, rejected_payload, sizeof(rejected_payload),
        &rejected_payload_length);
    expect("failed-verification-does-not-return-payload",
        rejected_code == ORBIT_RNP_VERIFY_SIGNER_MISMATCH &&
        rejected_payload_length == 0U && rejected_payload[0] == 0U, true);

    uint8_t payload[ORBIT_TRUST_ROTATION_MAX_BYTES];
    size_t payload_length = 0;
    orbit_rnp_verify_result verification;
    orbit_rnp_verify_code code = orbit_rnp_verify_inrelease_with_payload(
        rotation, rotation_len, trusted, trusted_len, trusted_fpr, &verification,
        payload, sizeof(payload), &payload_length);
    expect("old-key-signed-rotation-authenticates", code == ORBIT_RNP_VERIFY_VALID, true);
    expect("authenticated-payload-returned", payload_length > 0, true);

    orbit_trust_rotation_proof proof;
    expect("strict-rotation-proof-parses", orbit_trust_rotation_proof_parse(
        payload, payload_length, &proof), true);
    expect("proof-current-key-matches-pin", strcmp(proof.current_fingerprint, trusted_fpr) == 0, true);
    expect("proof-next-key-matches-candidate", strcmp(proof.next_fingerprint, candidate_fpr) == 0, true);

    orbit_repository_trust_state state;
    expect("initial-pin-created", orbit_repository_trust_init(&state, trusted_fpr), true);
    uint64_t now = (uint64_t)time(NULL);
    expect("old-key-authorized-initially", orbit_repository_trust_fingerprint_allowed(
        &state, trusted_fpr, now), true);
    expect("candidate-not-authorized-before-rotation", orbit_repository_trust_fingerprint_allowed(
        &state, candidate_fpr, now), false);

    expect("legitimate-rotation-scheduled", orbit_repository_trust_authorize_rotation(
        &state, "orbit-official", rotation, rotation_len, trusted, trusted_len,
        candidate, candidate_len, now)
        == ORBIT_TRUST_ACCEPTED, true);
    expect("second-pending-rotation-blocked", orbit_repository_trust_authorize_rotation(
        &state, "orbit-official", rotation, rotation_len, trusted, trusted_len,
        candidate, candidate_len, now)
        == ORBIT_TRUST_ROTATION_ALREADY_PENDING, true);
    expect("candidate-not-active-before-time", orbit_repository_trust_fingerprint_allowed(
        &state, candidate_fpr, proof.activate_at - 1U), false);
    expect("cannot-advance-before-activation", orbit_repository_trust_advance(
        &state, proof.activate_at - 1U), false);
    expect("pending-key-authorized-at-activation", orbit_repository_trust_fingerprint_allowed(
        &state, candidate_fpr, proof.activate_at), true);
    expect("old-key-grace-applies-before-compaction", orbit_repository_trust_fingerprint_allowed(
        &state, trusted_fpr, proof.previous_key_valid_until), true);
    expect("old-key-expires-after-grace-before-compaction", orbit_repository_trust_fingerprint_allowed(
        &state, trusted_fpr, proof.previous_key_valid_until + 1U), false);
    expect("rotation-activates-at-signed-time", orbit_repository_trust_advance(
        &state, proof.activate_at), true);
    expect("generation-increments", state.generation == 1U, true);
    expect("new-key-authorized-after-activation", orbit_repository_trust_fingerprint_allowed(
        &state, candidate_fpr, proof.activate_at), true);
    expect("old-key-allowed-during-grace", orbit_repository_trust_fingerprint_allowed(
        &state, trusted_fpr, proof.previous_key_valid_until), true);
    expect("old-key-rejected-after-grace", orbit_repository_trust_fingerprint_allowed(
        &state, trusted_fpr, proof.previous_key_valid_until + 1U), false);

    orbit_repository_trust_state wrong_state;
    expect("wrong-candidate-state-init", orbit_repository_trust_init(&wrong_state, trusted_fpr), true);
    expect("mismatched-candidate-key-rejected", orbit_repository_trust_authorize_rotation(
        &wrong_state, "orbit-official", rotation, rotation_len, trusted, trusted_len,
        wrong_candidate, wrong_len, now)
        == ORBIT_TRUST_CANDIDATE_KEY_REJECTED, true);
    expect("wrong-repository-rejected", orbit_repository_trust_authorize_rotation(
        &wrong_state, "different-repository", rotation, rotation_len, trusted, trusted_len,
        candidate, candidate_len, now)
        == ORBIT_TRUST_REPOSITORY_MISMATCH, true);

    expect("new-key-cannot-sign-own-rotation", orbit_repository_trust_authorize_rotation(
        &wrong_state, "orbit-official", unauthorized, unauthorized_len, combined, combined_len,
        candidate, candidate_len, now) == ORBIT_TRUST_ROTATION_SIGNATURE_REJECTED, true);

    orbit_trust_rotation_proof malformed;
    const uint8_t bad_proof[] = "ORBIT-Key-Rotation: 1\nRepository: orbit-official\nUnknown: value\n";
    expect("unknown-proof-field-rejected", orbit_trust_rotation_proof_parse(
        bad_proof, sizeof(bad_proof) - 1U, &malformed), false);

    printf("decision=%s checks=%u failures=%u\n", failures ? "FAIL" : "PASS", checks, failures);
    free(trusted); free(rotation); free(trusted_fpr); free(candidate);
    free(candidate_fpr); free(wrong_candidate); free(combined); free(unauthorized);
    free(expired); free(expired_fpr); free(revoked); free(revoked_fpr);
    return failures ? 1 : 0;
}
