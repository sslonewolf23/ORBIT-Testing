#include "ORBITPackageTransactionEnvelope.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
static unsigned failures;

#define EXPECT(label, expression) do { \
    ++checks; \
    if (!(expression)) { \
        ++failures; \
        fprintf(stderr, "FAIL: %s\n", label); \
    } \
} while (0)

static const uint8_t ownership_old[] = {
    'O','R','O','W',1U,0U,0U,0U,0U,0U,0U,0U
};
static const uint8_t ownership_new[] = {
    'O','R','O','W',1U,0U,0U,0U,0U,0U,0U,0U
};
static const uint8_t journal_payload[] = {
    'O','R','J','P',1U,0U,0U,0U,1U,0U,0U,0U,0U,0U,0U,0U,
    0U,0U,0U,0U,0U,0U,0U,0U,0U,0U,0U,0U,0U
};

int main(void) {
    uint8_t encoded[256], journal_out[64], committed_out[64], pending_out[64];
    size_t encoded_length = 0U;
    orbit_package_transaction_envelope empty;
    memset(&empty, 0, sizeof(empty));
    empty.revision = 10U;
    empty.state = ORBIT_TRANSACTION_ENVELOPE_EMPTY;
    empty.phase = ORBIT_TRANSACTION_ENVELOPE_PHASE_NONE;
    empty.committed_ownership = ownership_old;
    empty.committed_ownership_length = sizeof(ownership_old);

    EXPECT("encode initial committed ownership state",
        orbit_package_transaction_envelope_encode(
            &empty, encoded, sizeof(encoded), &encoded_length) ==
            ORBIT_TRANSACTION_ENVELOPE_OK);
    EXPECT("initial envelope has canonical fixed header",
        encoded_length == ORBIT_TRANSACTION_ENVELOPE_HEADER_SIZE +
            sizeof(ownership_old) && memcmp(encoded, "ORBE", 4U) == 0);

    orbit_package_transaction_envelope decoded;
    EXPECT("decode initial envelope",
        orbit_package_transaction_envelope_decode(
            encoded, encoded_length, journal_out, sizeof(journal_out),
            committed_out, sizeof(committed_out), pending_out,
            sizeof(pending_out), &decoded) == ORBIT_TRANSACTION_ENVELOPE_OK);
    EXPECT("decoded initial revision and ownership",
        decoded.revision == 10U && decoded.state == ORBIT_TRANSACTION_ENVELOPE_EMPTY &&
        decoded.committed_ownership_length == sizeof(ownership_old) &&
        memcmp(decoded.committed_ownership, ownership_old, sizeof(ownership_old)) == 0);

    orbit_package_transaction_envelope applying = empty;
    applying.revision = 11U;
    applying.state = ORBIT_TRANSACTION_ENVELOPE_ACTIVE;
    applying.phase = ORBIT_TRANSACTION_ENVELOPE_APPLYING;
    memset(applying.transaction_id, 0xA5, sizeof(applying.transaction_id));
    applying.journal_payload = journal_payload;
    applying.journal_length = sizeof(journal_payload);
    applying.pending_ownership = ownership_new;
    applying.pending_ownership_length = sizeof(ownership_new);
    EXPECT("empty to applying retains committed and stages pending ownership",
        orbit_package_transaction_envelope_validate_transition(
            &empty, &applying) == ORBIT_TRANSACTION_ENVELOPE_OK);

    orbit_package_transaction_envelope rolling = applying;
    rolling.revision = 12U;
    rolling.phase = ORBIT_TRANSACTION_ENVELOPE_ROLLING_BACK;
    EXPECT("applying to rolling back preserves both ownership snapshots",
        orbit_package_transaction_envelope_validate_transition(
            &applying, &rolling) == ORBIT_TRANSACTION_ENVELOPE_OK);

    orbit_package_transaction_envelope rolled_back = empty;
    rolled_back.revision = 13U;
    EXPECT("rollback drops pending ownership and retains committed state",
        orbit_package_transaction_envelope_validate_transition(
            &rolling, &rolled_back) == ORBIT_TRANSACTION_ENVELOPE_OK);

    orbit_package_transaction_envelope committed = applying;
    committed.revision = 12U;
    committed.phase = ORBIT_TRANSACTION_ENVELOPE_COMMITTED;
    EXPECT("applying to committed retains old committed and pending state",
        orbit_package_transaction_envelope_validate_transition(
            &applying, &committed) == ORBIT_TRANSACTION_ENVELOPE_OK);

    orbit_package_transaction_envelope promoted = empty;
    promoted.revision = 13U;
    promoted.committed_ownership = ownership_new;
    promoted.committed_ownership_length = sizeof(ownership_new);
    EXPECT("commit promotes pending snapshot only when active record clears",
        orbit_package_transaction_envelope_validate_transition(
            &committed, &promoted) == ORBIT_TRANSACTION_ENVELOPE_OK);

    orbit_package_transaction_envelope split_brain = promoted;
    split_brain.revision = 14U;
    split_brain.committed_ownership = ownership_old;
    EXPECT("committed transition rejects stale ownership promotion",
        orbit_package_transaction_envelope_validate_transition(
            &committed, &split_brain) ==
            ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION);

    orbit_package_transaction_envelope skipped = committed;
    skipped.revision = 14U;
    skipped.state = ORBIT_TRANSACTION_ENVELOPE_EMPTY;
    skipped.phase = ORBIT_TRANSACTION_ENVELOPE_PHASE_NONE;
    skipped.journal_payload = NULL;
    skipped.journal_length = 0U;
    skipped.pending_ownership = NULL;
    skipped.pending_ownership_length = 0U;
    skipped.committed_ownership = ownership_new;
    EXPECT("committed state cannot skip pending snapshot promotion",
        orbit_package_transaction_envelope_validate_transition(
            &committed, &skipped) ==
            ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION);

    EXPECT("reject revision jump",
        orbit_package_transaction_envelope_validate_transition(
            &empty, &(orbit_package_transaction_envelope){
                .revision = 12U, .state = ORBIT_TRANSACTION_ENVELOPE_ACTIVE,
                .phase = ORBIT_TRANSACTION_ENVELOPE_APPLYING,
                .transaction_id = { [0] = 1U },
                .journal_payload = journal_payload,
                .journal_length = sizeof(journal_payload),
                .committed_ownership = ownership_old,
                .committed_ownership_length = sizeof(ownership_old),
                .pending_ownership = ownership_new,
                .pending_ownership_length = sizeof(ownership_new)
            }) == ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION);

    EXPECT("reject insufficient output capacity",
        orbit_package_transaction_envelope_encode(
            &empty, encoded, 1U, &encoded_length) ==
            ORBIT_TRANSACTION_ENVELOPE_BUFFER_TOO_SMALL);

    EXPECT("reject trailing bytes",
        orbit_package_transaction_envelope_decode(
            encoded, encoded_length + 1U, journal_out, sizeof(journal_out),
            committed_out, sizeof(committed_out), pending_out,
            sizeof(pending_out), &decoded) ==
            ORBIT_TRANSACTION_ENVELOPE_MALFORMED);

    EXPECT("reject nonzero reserved byte",
        orbit_package_transaction_envelope_encode(
            &empty, encoded, sizeof(encoded), &encoded_length) ==
            ORBIT_TRANSACTION_ENVELOPE_OK);
    encoded[7] = 1U;
    EXPECT("reserved byte is canonical zero",
        orbit_package_transaction_envelope_decode(
            encoded, encoded_length, journal_out, sizeof(journal_out),
            committed_out, sizeof(committed_out), pending_out,
            sizeof(pending_out), &decoded) ==
            ORBIT_TRANSACTION_ENVELOPE_MALFORMED);

    EXPECT("reject truncated payload",
        orbit_package_transaction_envelope_decode(
            encoded, encoded_length - 1U, journal_out, sizeof(journal_out),
            committed_out, sizeof(committed_out), pending_out,
            sizeof(pending_out), &decoded) ==
            ORBIT_TRANSACTION_ENVELOPE_MALFORMED);

    printf("transaction_envelope_checks=%u failures=%u\ndecision=%s\n",
        checks, failures, failures == 0U ? "PASS" : "FAIL");
    return failures == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
