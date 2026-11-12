#include "ORBITPackageFilesystemJournalEnvelope.h"
#include "ORBITPackageFilesystemJournalCodec.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    orbit_package_transaction_envelope value;
    uint8_t *journal;
    uint8_t *committed;
    uint8_t *pending;
    uint8_t digest[32];
} loaded_envelope;

static bool backend_valid(const orbit_package_filesystem_envelope_backend *backend) {
    return backend && backend->load && backend->release && backend->store_atomic;
}

static uint32_t read_u32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24U) | ((uint32_t)bytes[1] << 16U) |
           ((uint32_t)bytes[2] << 8U) | (uint32_t)bytes[3];
}

static void loaded_envelope_destroy(loaded_envelope *loaded) {
    if (!loaded) return;
    free(loaded->journal);
    free(loaded->committed);
    free(loaded->pending);
    memset(loaded, 0, sizeof(*loaded));
}

static orbit_filesystem_code loaded_envelope_read(
    const orbit_package_filesystem_envelope_backend *backend,
    loaded_envelope *loaded) {
    if (!backend_valid(backend) || !loaded)
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    memset(loaded, 0, sizeof(*loaded));

    uint8_t *encoded = NULL;
    size_t encoded_length = 0U;
    if (!backend->load(backend->context, &encoded, &encoded_length,
                       loaded->digest) ||
        !encoded || encoded_length < ORBIT_TRANSACTION_ENVELOPE_HEADER_SIZE ||
        encoded_length > ORBIT_TRANSACTION_ENVELOPE_MAX_PAYLOAD) {
        if (encoded) backend->release(backend->context, encoded);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    uint32_t journal_length = read_u32(encoded + 32U);
    uint32_t committed_length = read_u32(encoded + 36U);
    uint32_t pending_length = read_u32(encoded + 40U);
    if (journal_length > ORBIT_TRANSACTION_ENVELOPE_MAX_JOURNAL ||
        committed_length > ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP ||
        pending_length > ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP) {
        backend->release(backend->context, encoded);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    if (journal_length) loaded->journal = (uint8_t *)malloc(journal_length);
    if (committed_length) loaded->committed = (uint8_t *)malloc(committed_length);
    if (pending_length) loaded->pending = (uint8_t *)malloc(pending_length);
    if ((journal_length && !loaded->journal) ||
        (committed_length && !loaded->committed) ||
        (pending_length && !loaded->pending)) {
        backend->release(backend->context, encoded);
        loaded_envelope_destroy(loaded);
        return ORBIT_FILESYSTEM_LIMIT;
    }

    orbit_transaction_envelope_code decoded =
        orbit_package_transaction_envelope_decode(
            encoded, encoded_length,
            loaded->journal, journal_length,
            loaded->committed, committed_length,
            loaded->pending, pending_length, &loaded->value);
    backend->release(backend->context, encoded);
    if (decoded != ORBIT_TRANSACTION_ENVELOPE_OK) {
        loaded_envelope_destroy(loaded);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }
    return ORBIT_FILESYSTEM_OK;
}

static orbit_filesystem_code persist_transition(
    const orbit_package_filesystem_envelope_backend *backend,
    const loaded_envelope *current,
    const orbit_package_transaction_envelope *next,
    uint8_t next_digest[32]) {
    if (orbit_package_transaction_envelope_validate_transition(
            &current->value, next) != ORBIT_TRANSACTION_ENVELOPE_OK)
        return ORBIT_FILESYSTEM_INVALID_STATE;

    size_t encoded_length = 0U;
    orbit_transaction_envelope_code measured =
        orbit_package_transaction_envelope_encode(
            next, NULL, 0U, &encoded_length);
    if (measured != ORBIT_TRANSACTION_ENVELOPE_BUFFER_TOO_SMALL ||
        encoded_length > ORBIT_TRANSACTION_ENVELOPE_MAX_PAYLOAD)
        return ORBIT_FILESYSTEM_INVALID_STATE;

    uint8_t *encoded = (uint8_t *)malloc(encoded_length);
    if (!encoded) return ORBIT_FILESYSTEM_LIMIT;
    orbit_transaction_envelope_code result =
        orbit_package_transaction_envelope_encode(
            next, encoded, encoded_length, &encoded_length);
    if (result != ORBIT_TRANSACTION_ENVELOPE_OK) {
        free(encoded);
        return ORBIT_FILESYSTEM_INVALID_STATE;
    }

    bool stored = backend->store_atomic(
        backend->context, current->value.revision, current->digest,
        encoded, encoded_length, next_digest);
    free(encoded);
    return stored ? ORBIT_FILESYSTEM_OK :
        ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
}

static bool encode_journal_record(
    orbit_package_filesystem_journal_record *record,
    uint8_t **payload, size_t *payload_length) {
    if (!record || !payload || !payload_length) return false;
    *payload = NULL;
    *payload_length = 0U;
    size_t required = 0U;
    orbit_journal_codec_code measured =
        orbit_package_filesystem_journal_encode(record, NULL, 0U, &required);
    if (measured != ORBIT_JOURNAL_CODEC_BUFFER_TOO_SMALL ||
        required > ORBIT_FILESYSTEM_JOURNAL_CODEC_MAX_PAYLOAD)
        return false;
    uint8_t *buffer = (uint8_t *)malloc(required);
    if (!buffer) return false;
    orbit_journal_codec_code encoded =
        orbit_package_filesystem_journal_encode(record, buffer, required, &required);
    if (encoded != ORBIT_JOURNAL_CODEC_OK) {
        free(buffer);
        return false;
    }
    *payload = buffer;
    *payload_length = required;
    return true;
}

static orbit_filesystem_code persist_active_phase(
    const orbit_package_filesystem_envelope_backend *backend,
    loaded_envelope *current,
    orbit_package_filesystem_journal_record *record,
    uint32_t phase) {
    if (!current || current->value.state != ORBIT_TRANSACTION_ENVELOPE_ACTIVE ||
        current->value.revision == UINT64_MAX)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;

    record->phase = phase;
    record->revision = current->value.revision + 1U;
    uint8_t *journal = NULL;
    size_t journal_length = 0U;
    if (!encode_journal_record(record, &journal, &journal_length))
        return ORBIT_FILESYSTEM_INVALID_STATE;

    orbit_package_transaction_envelope next;
    memset(&next, 0, sizeof(next));
    next.revision = current->value.revision + 1U;
    next.state = ORBIT_TRANSACTION_ENVELOPE_ACTIVE;
    next.phase = (uint8_t)phase;
    memcpy(next.transaction_id, current->value.transaction_id,
           sizeof(next.transaction_id));
    next.journal_payload = journal;
    next.journal_length = journal_length;
    next.committed_ownership = current->committed;
    next.committed_ownership_length = current->value.committed_ownership_length;
    next.pending_ownership = current->pending;
    next.pending_ownership_length = current->value.pending_ownership_length;

    uint8_t next_digest[32];
    orbit_filesystem_code stored =
        persist_transition(backend, current, &next, next_digest);
    if (stored != ORBIT_FILESYSTEM_OK) {
        free(journal);
        return stored;
    }

    free(current->journal);
    current->journal = journal;
    current->value = next;
    current->value.journal_payload = current->journal;
    current->value.committed_ownership = current->committed;
    current->value.pending_ownership = current->pending;
    memcpy(current->digest, next_digest, sizeof(current->digest));
    return ORBIT_FILESYSTEM_OK;
}

static orbit_filesystem_code persist_finish(
    const orbit_package_filesystem_envelope_backend *backend,
    loaded_envelope *current,
    bool promote_pending) {
    if (!current || current->value.state != ORBIT_TRANSACTION_ENVELOPE_ACTIVE ||
        current->value.revision == UINT64_MAX)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;

    orbit_package_transaction_envelope next;
    memset(&next, 0, sizeof(next));
    next.revision = current->value.revision + 1U;
    next.state = ORBIT_TRANSACTION_ENVELOPE_EMPTY;
    next.phase = ORBIT_TRANSACTION_ENVELOPE_PHASE_NONE;
    next.committed_ownership = promote_pending ?
        current->pending : current->committed;
    next.committed_ownership_length = promote_pending ?
        current->value.pending_ownership_length :
        current->value.committed_ownership_length;

    uint8_t next_digest[32];
    orbit_filesystem_code stored =
        persist_transition(backend, current, &next, next_digest);
    if (stored != ORBIT_FILESYSTEM_OK) return stored;

    free(current->journal);
    current->journal = NULL;
    if (promote_pending) {
        free(current->committed);
        current->committed = current->pending;
        current->pending = NULL;
        current->value.committed_ownership_length =
            current->value.pending_ownership_length;
    } else {
        free(current->pending);
        current->pending = NULL;
    }
    current->value = next;
    current->value.committed_ownership = current->committed;
    current->value.pending_ownership = NULL;
    current->value.journal_payload = NULL;
    current->value.journal_length = 0U;
    current->value.pending_ownership_length = 0U;
    memcpy(current->digest, next_digest, sizeof(current->digest));
    return ORBIT_FILESYSTEM_OK;
}

static orbit_filesystem_code rollback_record(
    const orbit_package_filesystem_journal_record *record,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context) {
    for (size_t i = record->change_count; i > 0U; --i) {
        orbit_filesystem_code result = executor(
            executor_context, record->transaction_id,
            ORBIT_FILE_JOURNAL_ROLLBACK, &record->changes[i - 1U]);
        if (result != ORBIT_FILESYSTEM_OK) return result;
    }
    return ORBIT_FILESYSTEM_OK;
}

static orbit_filesystem_code finalize_record(
    const orbit_package_filesystem_journal_record *record,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context) {
    for (size_t i = 0U; i < record->change_count; ++i) {
        orbit_filesystem_code result = executor(
            executor_context, record->transaction_id,
            ORBIT_FILE_JOURNAL_FINALIZE, &record->changes[i]);
        if (result != ORBIT_FILESYSTEM_OK) return result;
    }
    return ORBIT_FILESYSTEM_OK;
}

static bool transaction_id_valid(const uint8_t *transaction_id) {
    if (!transaction_id) return false;
    uint8_t combined = 0U;
    for (size_t i = 0U; i < ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES; ++i)
        combined |= transaction_id[i];
    return combined != 0U;
}

orbit_filesystem_code orbit_package_filesystem_journal_execute_enveloped(
    const orbit_package_filesystem_envelope_backend *backend,
    const uint8_t transaction_id[ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES],
    const orbit_package_file_change *changes, size_t change_count,
    const uint8_t *expected_ownership, size_t expected_ownership_length,
    const uint8_t *replacement_ownership, size_t replacement_ownership_length,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context) {
    if (!backend_valid(backend) || !transaction_id_valid(transaction_id) ||
        !changes || change_count == 0U ||
        change_count > ORBIT_FILESYSTEM_JOURNAL_MAX_CHANGES ||
        !expected_ownership || expected_ownership_length < 12U ||
        expected_ownership_length > ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP ||
        !replacement_ownership || replacement_ownership_length < 12U ||
        replacement_ownership_length > ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP ||
        !executor)
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    loaded_envelope current;
    orbit_filesystem_code loaded = loaded_envelope_read(backend, &current);
    if (loaded != ORBIT_FILESYSTEM_OK) return loaded;
    if (current.value.state != ORBIT_TRANSACTION_ENVELOPE_EMPTY ||
        current.value.revision == UINT64_MAX ||
        current.value.committed_ownership_length != expected_ownership_length ||
        memcmp(current.committed, expected_ownership, expected_ownership_length) != 0) {
        loaded_envelope_destroy(&current);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    for (size_t i = 0U; i < change_count; ++i) {
        orbit_filesystem_code valid =
            orbit_package_filesystem_validate_change(&changes[i]);
        if (valid != ORBIT_FILESYSTEM_OK) {
            loaded_envelope_destroy(&current);
            return valid;
        }
    }

    orbit_package_filesystem_journal_record *record =
        (orbit_package_filesystem_journal_record *)calloc(1U, sizeof(*record));
    if (!record) {
        loaded_envelope_destroy(&current);
        return ORBIT_FILESYSTEM_LIMIT;
    }
    record->version = ORBIT_FILESYSTEM_JOURNAL_VERSION;
    record->phase = ORBIT_FILE_JOURNAL_APPLYING;
    record->revision = current.value.revision + 1U;
    memcpy(record->transaction_id, transaction_id,
           ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES);
    record->change_count = (uint32_t)change_count;
    memcpy(record->changes, changes, change_count * sizeof(*changes));

    uint8_t *journal = NULL;
    size_t journal_length = 0U;
    uint8_t *pending = (uint8_t *)malloc(replacement_ownership_length);
    if (!pending) {
        free(record);
        loaded_envelope_destroy(&current);
        return ORBIT_FILESYSTEM_LIMIT;
    }
    memcpy(pending, replacement_ownership, replacement_ownership_length);
    if (!encode_journal_record(record, &journal, &journal_length)) {
        free(pending);
        free(record);
        loaded_envelope_destroy(&current);
        return ORBIT_FILESYSTEM_INVALID_STATE;
    }

    orbit_package_transaction_envelope applying;
    memset(&applying, 0, sizeof(applying));
    applying.revision = current.value.revision + 1U;
    applying.state = ORBIT_TRANSACTION_ENVELOPE_ACTIVE;
    applying.phase = ORBIT_TRANSACTION_ENVELOPE_APPLYING;
    memcpy(applying.transaction_id, transaction_id,
           ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES);
    applying.journal_payload = journal;
    applying.journal_length = journal_length;
    applying.committed_ownership = current.committed;
    applying.committed_ownership_length = current.value.committed_ownership_length;
    applying.pending_ownership = pending;
    applying.pending_ownership_length = replacement_ownership_length;

    uint8_t next_digest[32];
    orbit_filesystem_code stored =
        persist_transition(backend, &current, &applying, next_digest);
    if (stored != ORBIT_FILESYSTEM_OK) {
        free(journal);
        free(pending);
        free(record);
        loaded_envelope_destroy(&current);
        return stored;
    }
    current.journal = journal;
    current.pending = pending;
    current.value = applying;
    current.value.journal_payload = current.journal;
    current.value.committed_ownership = current.committed;
    current.value.pending_ownership = current.pending;
    memcpy(current.digest, next_digest, sizeof(current.digest));

    orbit_filesystem_code apply_result = ORBIT_FILESYSTEM_OK;
    for (size_t i = 0U; i < record->change_count; ++i) {
        apply_result = executor(executor_context, transaction_id,
            ORBIT_FILE_JOURNAL_APPLY, &record->changes[i]);
        if (apply_result != ORBIT_FILESYSTEM_OK) break;
    }

    if (apply_result != ORBIT_FILESYSTEM_OK) {
        orbit_filesystem_code phase_result = persist_active_phase(
            backend, &current, record, ORBIT_FILE_JOURNAL_ROLLING_BACK);
        if (phase_result != ORBIT_FILESYSTEM_OK) {
            free(record);
            loaded_envelope_destroy(&current);
            return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        }
        orbit_filesystem_code rollback_result =
            rollback_record(record, executor, executor_context);
        if (rollback_result == ORBIT_FILESYSTEM_OK)
            rollback_result = persist_finish(backend, &current, false);
        free(record);
        loaded_envelope_destroy(&current);
        return rollback_result == ORBIT_FILESYSTEM_OK ?
            apply_result : ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    orbit_filesystem_code phase_result = persist_active_phase(
        backend, &current, record, ORBIT_FILE_JOURNAL_COMMITTED);
    if (phase_result != ORBIT_FILESYSTEM_OK) {
        free(record);
        loaded_envelope_destroy(&current);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    orbit_filesystem_code finalize_result =
        finalize_record(record, executor, executor_context);
    if (finalize_result == ORBIT_FILESYSTEM_OK)
        finalize_result = persist_finish(backend, &current, true);
    free(record);
    loaded_envelope_destroy(&current);
    return finalize_result;
}

orbit_filesystem_code orbit_package_filesystem_journal_recover_enveloped(
    const orbit_package_filesystem_envelope_backend *backend,
    orbit_package_filesystem_journal_executor executor,
    void *executor_context) {
    if (!backend_valid(backend) || !executor)
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    loaded_envelope current;
    orbit_filesystem_code loaded = loaded_envelope_read(backend, &current);
    if (loaded != ORBIT_FILESYSTEM_OK) return loaded;
    if (current.value.state == ORBIT_TRANSACTION_ENVELOPE_EMPTY) {
        loaded_envelope_destroy(&current);
        return ORBIT_FILESYSTEM_OK;
    }

    orbit_package_filesystem_journal_record *record =
        (orbit_package_filesystem_journal_record *)calloc(1U, sizeof(*record));
    if (!record) {
        loaded_envelope_destroy(&current);
        return ORBIT_FILESYSTEM_LIMIT;
    }
    orbit_journal_codec_code decoded =
        orbit_package_filesystem_journal_decode(
            current.journal, current.value.journal_length,
            current.value.revision, record);
    if (decoded != ORBIT_JOURNAL_CODEC_OK ||
        record->phase != current.value.phase ||
        memcmp(record->transaction_id, current.value.transaction_id,
               ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES) != 0) {
        free(record);
        loaded_envelope_destroy(&current);
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    orbit_filesystem_code result = ORBIT_FILESYSTEM_OK;
    if (record->phase == ORBIT_FILE_JOURNAL_APPLYING) {
        result = persist_active_phase(
            backend, &current, record, ORBIT_FILE_JOURNAL_ROLLING_BACK);
    }
    if (result == ORBIT_FILESYSTEM_OK &&
        record->phase == ORBIT_FILE_JOURNAL_ROLLING_BACK) {
        result = rollback_record(record, executor, executor_context);
        if (result == ORBIT_FILESYSTEM_OK)
            result = persist_finish(backend, &current, false);
    } else if (result == ORBIT_FILESYSTEM_OK &&
               record->phase == ORBIT_FILE_JOURNAL_COMMITTED) {
        result = finalize_record(record, executor, executor_context);
        if (result == ORBIT_FILESYSTEM_OK)
            result = persist_finish(backend, &current, true);
    } else if (result == ORBIT_FILESYSTEM_OK &&
               record->phase == ORBIT_FILE_JOURNAL_APPLYING) {
        result = ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    free(record);
    loaded_envelope_destroy(&current);
    return result;
}
