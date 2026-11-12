#include "ORBITPackageTransactionEnvelope.h"

#include <string.h>

static const uint8_t envelope_magic[4] = { 'O', 'R', 'B', 'E' };

static void write_u32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24U);
    out[1] = (uint8_t)(value >> 16U);
    out[2] = (uint8_t)(value >> 8U);
    out[3] = (uint8_t)value;
}

static uint32_t read_u32(const uint8_t *in) {
    return ((uint32_t)in[0] << 24U) | ((uint32_t)in[1] << 16U) |
           ((uint32_t)in[2] << 8U) | (uint32_t)in[3];
}

static void write_u64(uint8_t *out, uint64_t value) {
    for (size_t i = 0U; i < 8U; ++i)
        out[i] = (uint8_t)(value >> (56U - (unsigned)(i * 8U)));
}

static uint64_t read_u64(const uint8_t *in) {
    uint64_t value = 0U;
    for (size_t i = 0U; i < 8U; ++i)
        value = (value << 8U) | in[i];
    return value;
}

static bool nonzero_id(const uint8_t id[ORBIT_TRANSACTION_ENVELOPE_TRANSACTION_ID_BYTES]) {
    uint8_t value = 0U;
    for (size_t i = 0U; i < ORBIT_TRANSACTION_ENVELOPE_TRANSACTION_ID_BYTES; ++i)
        value |= id[i];
    return value != 0U;
}

static bool bytes_equal(const uint8_t *a, size_t a_length,
                        const uint8_t *b, size_t b_length) {
    return a_length == b_length &&
        (a_length == 0U || (a && b && memcmp(a, b, a_length) == 0));
}

static bool envelope_valid(const orbit_package_transaction_envelope *e) {
    if (!e || e->revision == 0U ||
        !e->committed_ownership ||
        e->committed_ownership_length < 12U ||
        e->committed_ownership_length > ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP ||
        (e->journal_length && !e->journal_payload) ||
        (e->pending_ownership_length && !e->pending_ownership) ||
        e->journal_length > ORBIT_TRANSACTION_ENVELOPE_MAX_JOURNAL ||
        e->pending_ownership_length > ORBIT_TRANSACTION_ENVELOPE_MAX_OWNERSHIP)
        return false;

    if (e->state == ORBIT_TRANSACTION_ENVELOPE_EMPTY) {
        uint8_t id_value = 0U;
        for (size_t i = 0U; i < sizeof(e->transaction_id); ++i)
            id_value |= e->transaction_id[i];
        return e->phase == ORBIT_TRANSACTION_ENVELOPE_PHASE_NONE &&
            id_value == 0U && e->journal_length == 0U &&
            e->pending_ownership_length == 0U;
    }

    return e->state == ORBIT_TRANSACTION_ENVELOPE_ACTIVE &&
        e->phase >= ORBIT_TRANSACTION_ENVELOPE_APPLYING &&
        e->phase <= ORBIT_TRANSACTION_ENVELOPE_COMMITTED &&
        nonzero_id(e->transaction_id) &&
        e->journal_length >= 29U &&
        e->pending_ownership_length >= 12U;
}

orbit_transaction_envelope_code orbit_package_transaction_envelope_encode(
    const orbit_package_transaction_envelope *e,
    uint8_t *output, size_t capacity, size_t *output_length) {
    if (!e || !output_length)
        return ORBIT_TRANSACTION_ENVELOPE_INVALID_ARGUMENT;
    *output_length = 0U;
    if (!envelope_valid(e))
        return ORBIT_TRANSACTION_ENVELOPE_INVALID_STATE;

    size_t required = ORBIT_TRANSACTION_ENVELOPE_HEADER_SIZE;
    if (e->journal_length > SIZE_MAX - required)
        return ORBIT_TRANSACTION_ENVELOPE_LIMIT;
    required += e->journal_length;
    if (e->committed_ownership_length > SIZE_MAX - required)
        return ORBIT_TRANSACTION_ENVELOPE_LIMIT;
    required += e->committed_ownership_length;
    if (e->pending_ownership_length > SIZE_MAX - required)
        return ORBIT_TRANSACTION_ENVELOPE_LIMIT;
    required += e->pending_ownership_length;
    if (required > ORBIT_TRANSACTION_ENVELOPE_MAX_PAYLOAD)
        return ORBIT_TRANSACTION_ENVELOPE_LIMIT;

    *output_length = required;
    if (!output || capacity < required)
        return ORBIT_TRANSACTION_ENVELOPE_BUFFER_TOO_SMALL;

    uint8_t *cursor = output;
    memcpy(cursor, envelope_magic, sizeof(envelope_magic)); cursor += 4U;
    *cursor++ = ORBIT_TRANSACTION_ENVELOPE_VERSION;
    *cursor++ = e->state;
    *cursor++ = e->phase;
    *cursor++ = 0U;
    write_u64(cursor, e->revision); cursor += 8U;
    memcpy(cursor, e->transaction_id, sizeof(e->transaction_id));
    cursor += sizeof(e->transaction_id);
    write_u32(cursor, (uint32_t)e->journal_length); cursor += 4U;
    write_u32(cursor, (uint32_t)e->committed_ownership_length); cursor += 4U;
    write_u32(cursor, (uint32_t)e->pending_ownership_length); cursor += 4U;
    if (e->journal_length) {
        memcpy(cursor, e->journal_payload, e->journal_length);
        cursor += e->journal_length;
    }
    memcpy(cursor, e->committed_ownership, e->committed_ownership_length);
    cursor += e->committed_ownership_length;
    if (e->pending_ownership_length) {
        memcpy(cursor, e->pending_ownership, e->pending_ownership_length);
        cursor += e->pending_ownership_length;
    }
    return (size_t)(cursor - output) == required ?
        ORBIT_TRANSACTION_ENVELOPE_OK : ORBIT_TRANSACTION_ENVELOPE_INVALID_STATE;
}

orbit_transaction_envelope_code orbit_package_transaction_envelope_decode(
    const uint8_t *payload, size_t length,
    uint8_t *journal_buffer, size_t journal_capacity,
    uint8_t *committed_buffer, size_t committed_capacity,
    uint8_t *pending_buffer, size_t pending_capacity,
    orbit_package_transaction_envelope *e) {
    if (!payload || !e)
        return ORBIT_TRANSACTION_ENVELOPE_INVALID_ARGUMENT;
    memset(e, 0, sizeof(*e));
    if (length < ORBIT_TRANSACTION_ENVELOPE_HEADER_SIZE ||
        length > ORBIT_TRANSACTION_ENVELOPE_MAX_PAYLOAD ||
        memcmp(payload, envelope_magic, sizeof(envelope_magic)) != 0 ||
        payload[4] != ORBIT_TRANSACTION_ENVELOPE_VERSION || payload[7] != 0U)
        return ORBIT_TRANSACTION_ENVELOPE_MALFORMED;

    uint8_t state = payload[5], phase = payload[6];
    uint64_t revision = read_u64(payload + 8U);
    uint32_t journal_length = read_u32(payload + 32U);
    uint32_t committed_length = read_u32(payload + 36U);
    uint32_t pending_length = read_u32(payload + 40U);
    size_t expected = ORBIT_TRANSACTION_ENVELOPE_HEADER_SIZE;
    if ((size_t)journal_length > SIZE_MAX - expected)
        return ORBIT_TRANSACTION_ENVELOPE_MALFORMED;
    expected += journal_length;
    if ((size_t)committed_length > SIZE_MAX - expected)
        return ORBIT_TRANSACTION_ENVELOPE_MALFORMED;
    expected += committed_length;
    if ((size_t)pending_length > SIZE_MAX - expected)
        return ORBIT_TRANSACTION_ENVELOPE_MALFORMED;
    expected += pending_length;
    if (expected != length)
        return ORBIT_TRANSACTION_ENVELOPE_MALFORMED;
    if (journal_length > journal_capacity ||
        committed_length > committed_capacity ||
        pending_length > pending_capacity ||
        (journal_length && !journal_buffer) ||
        (committed_length && !committed_buffer) ||
        (pending_length && !pending_buffer))
        return ORBIT_TRANSACTION_ENVELOPE_BUFFER_TOO_SMALL;

    const uint8_t *cursor = payload + ORBIT_TRANSACTION_ENVELOPE_HEADER_SIZE;
    if (journal_length) {
        memcpy(journal_buffer, cursor, journal_length);
        cursor += journal_length;
    }
    if (committed_length) {
        memcpy(committed_buffer, cursor, committed_length);
        cursor += committed_length;
    }
    if (pending_length) memcpy(pending_buffer, cursor, pending_length);

    e->revision = revision;
    e->state = state;
    e->phase = phase;
    memcpy(e->transaction_id, payload + 16U, sizeof(e->transaction_id));
    e->journal_payload = journal_buffer;
    e->journal_length = journal_length;
    e->committed_ownership = committed_buffer;
    e->committed_ownership_length = committed_length;
    e->pending_ownership = pending_buffer;
    e->pending_ownership_length = pending_length;
    return envelope_valid(e) ? ORBIT_TRANSACTION_ENVELOPE_OK :
        ORBIT_TRANSACTION_ENVELOPE_MALFORMED;
}

orbit_transaction_envelope_code orbit_package_transaction_envelope_validate_transition(
    const orbit_package_transaction_envelope *previous,
    const orbit_package_transaction_envelope *next) {
    if (!envelope_valid(previous) || !envelope_valid(next))
        return ORBIT_TRANSACTION_ENVELOPE_INVALID_STATE;
    if (previous->revision == UINT64_MAX ||
        next->revision != previous->revision + 1U)
        return ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION;

    if (previous->state == ORBIT_TRANSACTION_ENVELOPE_EMPTY) {
        if (next->state != ORBIT_TRANSACTION_ENVELOPE_ACTIVE ||
            next->phase != ORBIT_TRANSACTION_ENVELOPE_APPLYING ||
            !bytes_equal(previous->committed_ownership,
                         previous->committed_ownership_length,
                         next->committed_ownership,
                         next->committed_ownership_length))
            return ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION;
        return ORBIT_TRANSACTION_ENVELOPE_OK;
    }

    if (next->state == ORBIT_TRANSACTION_ENVELOPE_ACTIVE) {
        if (!bytes_equal(previous->transaction_id, sizeof(previous->transaction_id),
                         next->transaction_id, sizeof(next->transaction_id)) ||
            !bytes_equal(previous->committed_ownership,
                         previous->committed_ownership_length,
                         next->committed_ownership,
                         next->committed_ownership_length) ||
            !bytes_equal(previous->pending_ownership,
                         previous->pending_ownership_length,
                         next->pending_ownership,
                         next->pending_ownership_length))
            return ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION;

        if (previous->phase == ORBIT_TRANSACTION_ENVELOPE_APPLYING &&
            (next->phase == ORBIT_TRANSACTION_ENVELOPE_ROLLING_BACK ||
             next->phase == ORBIT_TRANSACTION_ENVELOPE_COMMITTED))
            return ORBIT_TRANSACTION_ENVELOPE_OK;
        if (previous->phase == next->phase &&
            (next->phase == ORBIT_TRANSACTION_ENVELOPE_APPLYING ||
             next->phase == ORBIT_TRANSACTION_ENVELOPE_ROLLING_BACK ||
             next->phase == ORBIT_TRANSACTION_ENVELOPE_COMMITTED))
            return ORBIT_TRANSACTION_ENVELOPE_OK;
        return ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION;
    }

    if (next->state != ORBIT_TRANSACTION_ENVELOPE_EMPTY ||
        next->phase != ORBIT_TRANSACTION_ENVELOPE_PHASE_NONE ||
        next->journal_length != 0U || next->pending_ownership_length != 0U)
        return ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION;

    if (previous->phase == ORBIT_TRANSACTION_ENVELOPE_ROLLING_BACK) {
        return bytes_equal(previous->committed_ownership,
                           previous->committed_ownership_length,
                           next->committed_ownership,
                           next->committed_ownership_length) ?
            ORBIT_TRANSACTION_ENVELOPE_OK :
            ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION;
    }
    if (previous->phase == ORBIT_TRANSACTION_ENVELOPE_COMMITTED) {
        return bytes_equal(previous->pending_ownership,
                           previous->pending_ownership_length,
                           next->committed_ownership,
                           next->committed_ownership_length) ?
            ORBIT_TRANSACTION_ENVELOPE_OK :
            ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION;
    }
    return ORBIT_TRANSACTION_ENVELOPE_INVALID_TRANSITION;
}
