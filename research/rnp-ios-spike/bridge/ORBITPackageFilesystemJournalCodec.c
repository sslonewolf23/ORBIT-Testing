#include "ORBITPackageFilesystemJournalCodec.h"

#include <stdbool.h>
#include <string.h>

#define CODEC_HEADER_SIZE 29U
#define CODEC_STRING_COUNT 5U

static const uint8_t codec_magic[4] = { 'O', 'R', 'J', 'P' };

static void write_u16(uint8_t *out, uint16_t value) {
    out[0] = (uint8_t)(value >> 8U);
    out[1] = (uint8_t)value;
}

static void write_u32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24U);
    out[1] = (uint8_t)(value >> 16U);
    out[2] = (uint8_t)(value >> 8U);
    out[3] = (uint8_t)value;
}

static void write_u64(uint8_t *out, uint64_t value) {
    for (size_t i = 0U; i < 8U; ++i)
        out[i] = (uint8_t)(value >> (56U - (unsigned)(i * 8U)));
}

static uint16_t read_u16(const uint8_t *in) {
    return (uint16_t)(((uint16_t)in[0] << 8U) | in[1]);
}

static uint32_t read_u32(const uint8_t *in) {
    return ((uint32_t)in[0] << 24U) | ((uint32_t)in[1] << 16U) |
           ((uint32_t)in[2] << 8U) | (uint32_t)in[3];
}

static uint64_t read_u64(const uint8_t *in) {
    uint64_t value = 0U;
    for (size_t i = 0U; i < 8U; ++i)
        value = (value << 8U) | in[i];
    return value;
}

static bool stored_string_length(const char *value, size_t capacity,
                                 uint16_t *length) {
    if (!value || !length) return false;
    const char *terminator = (const char *)memchr(value, '\0', capacity);
    if (!terminator) return false;
    size_t count = (size_t)(terminator - value);
    if (count > UINT16_MAX) return false;
    for (size_t i = count + 1U; i < capacity; ++i) {
        if (value[i] != '\0') return false;
    }
    *length = (uint16_t)count;
    return true;
}

static bool add_size(size_t *total, size_t amount) {
    if (!total || amount > SIZE_MAX - *total) return false;
    *total += amount;
    return true;
}

static bool change_encoded_size(const orbit_package_file_change *change,
                                size_t *size) {
    const char *strings[CODEC_STRING_COUNT] = {
        change->target_name, change->staged_name, change->backup_name,
        change->target_parent_path, change->staged_parent_path
    };
    const size_t capacities[CODEC_STRING_COUNT] = {
        sizeof(change->target_name), sizeof(change->staged_name),
        sizeof(change->backup_name), sizeof(change->target_parent_path),
        sizeof(change->staged_parent_path)
    };
    size_t result = 4U + 4U + 1U + 8U * 4U;
    for (size_t i = 0U; i < CODEC_STRING_COUNT; ++i) {
        uint16_t length = 0U;
        if (!stored_string_length(strings[i], capacities[i], &length) ||
            !add_size(&result, 2U + length))
            return false;
    }
    *size = result;
    return true;
}

static bool record_is_codec_valid(
    const orbit_package_filesystem_journal_record *record) {
    if (!record || record->version != ORBIT_FILESYSTEM_JOURNAL_VERSION ||
        record->revision == 0U ||
        record->phase < ORBIT_FILE_JOURNAL_APPLYING ||
        record->phase > ORBIT_FILE_JOURNAL_COMMITTED ||
        record->change_count == 0U ||
        record->change_count > ORBIT_FILESYSTEM_JOURNAL_MAX_CHANGES)
        return false;
    uint8_t transaction_id = 0U;
    for (size_t i = 0U; i < ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES; ++i)
        transaction_id |= record->transaction_id[i];
    if (transaction_id == 0U) return false;
    for (size_t i = 0U; i < record->change_count; ++i) {
        if (orbit_package_filesystem_validate_change(&record->changes[i]) !=
            ORBIT_FILESYSTEM_OK)
            return false;
    }
    return true;
}

static void encode_string(uint8_t **cursor, const char *value,
                          size_t capacity) {
    uint16_t length = 0U;
    (void)stored_string_length(value, capacity, &length);
    write_u16(*cursor, length);
    *cursor += 2U;
    if (length > 0U) {
        memcpy(*cursor, value, length);
        *cursor += length;
    }
}

orbit_journal_codec_code orbit_package_filesystem_journal_encode(
    const orbit_package_filesystem_journal_record *record,
    uint8_t *output, size_t output_capacity, size_t *output_length) {
    if (!record || !output_length) return ORBIT_JOURNAL_CODEC_INVALID_ARGUMENT;
    *output_length = 0U;
    if (!record_is_codec_valid(record)) return ORBIT_JOURNAL_CODEC_INVALID_RECORD;

    size_t required = CODEC_HEADER_SIZE;
    for (size_t i = 0U; i < record->change_count; ++i) {
        size_t change_size = 0U;
        if (!change_encoded_size(&record->changes[i], &change_size) ||
            !add_size(&required, change_size) ||
            required > ORBIT_FILESYSTEM_JOURNAL_CODEC_MAX_PAYLOAD)
            return ORBIT_JOURNAL_CODEC_INVALID_RECORD;
    }
    *output_length = required;
    if (!output || output_capacity < required)
        return ORBIT_JOURNAL_CODEC_BUFFER_TOO_SMALL;

    uint8_t *cursor = output;
    memcpy(cursor, codec_magic, sizeof(codec_magic));
    cursor += sizeof(codec_magic);
    *cursor++ = 2U;
    write_u32(cursor, record->phase);
    cursor += 4U;
    memcpy(cursor, record->transaction_id, ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES);
    cursor += ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES;
    write_u32(cursor, record->change_count);
    cursor += 4U;

    for (size_t i = 0U; i < record->change_count; ++i) {
        const orbit_package_file_change *change = &record->changes[i];
        write_u32(cursor, change->version); cursor += 4U;
        write_u32(cursor, change->operation); cursor += 4U;
        encode_string(&cursor, change->target_name, sizeof(change->target_name));
        encode_string(&cursor, change->staged_name, sizeof(change->staged_name));
        encode_string(&cursor, change->backup_name, sizeof(change->backup_name));
        encode_string(&cursor, change->target_parent_path,
                      sizeof(change->target_parent_path));
        encode_string(&cursor, change->staged_parent_path,
                      sizeof(change->staged_parent_path));
        *cursor++ = change->preimage_exists ? 1U : 0U;
        write_u64(cursor, change->preimage_device); cursor += 8U;
        write_u64(cursor, change->preimage_inode); cursor += 8U;
        write_u64(cursor, change->staged_device); cursor += 8U;
        write_u64(cursor, change->staged_inode); cursor += 8U;
    }
    return (size_t)(cursor - output) == required ?
        ORBIT_JOURNAL_CODEC_OK : ORBIT_JOURNAL_CODEC_INVALID_RECORD;
}

static bool decode_string(const uint8_t **cursor, const uint8_t *end,
                          char *output, size_t capacity) {
    if ((size_t)(end - *cursor) < 2U) return false;
    uint16_t length = read_u16(*cursor);
    *cursor += 2U;
    if ((size_t)(end - *cursor) < length || (size_t)length >= capacity)
        return false;
    if (length > 0U && memchr(*cursor, '\0', length) != NULL) return false;
    memcpy(output, *cursor, length);
    output[length] = '\0';
    *cursor += length;
    return true;
}

orbit_journal_codec_code orbit_package_filesystem_journal_decode(
    const uint8_t *payload, size_t payload_length, uint64_t revision,
    orbit_package_filesystem_journal_record *record) {
    if (!payload || !record || revision == 0U)
        return ORBIT_JOURNAL_CODEC_INVALID_ARGUMENT;
    memset(record, 0, sizeof(*record));
    if (payload_length < CODEC_HEADER_SIZE ||
        payload_length > ORBIT_FILESYSTEM_JOURNAL_CODEC_MAX_PAYLOAD ||
        memcmp(payload, codec_magic, sizeof(codec_magic)) != 0 ||
        payload[4] != 2U)
        return ORBIT_JOURNAL_CODEC_MALFORMED;

    const uint8_t *cursor = payload + 5U;
    const uint8_t *end = payload + payload_length;
    record->version = ORBIT_FILESYSTEM_JOURNAL_VERSION;
    record->phase = read_u32(cursor); cursor += 4U;
    memcpy(record->transaction_id, cursor, ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES);
    cursor += ORBIT_FILESYSTEM_TRANSACTION_ID_BYTES;
    record->revision = revision;
    record->change_count = read_u32(cursor); cursor += 4U;
    if (record->phase < ORBIT_FILE_JOURNAL_APPLYING ||
        record->phase > ORBIT_FILE_JOURNAL_COMMITTED ||
        record->change_count == 0U ||
        record->change_count > ORBIT_FILESYSTEM_JOURNAL_MAX_CHANGES)
        return ORBIT_JOURNAL_CODEC_MALFORMED;

    for (size_t i = 0U; i < record->change_count; ++i) {
        orbit_package_file_change *change = &record->changes[i];
        if ((size_t)(end - cursor) < 8U) return ORBIT_JOURNAL_CODEC_MALFORMED;
        change->version = read_u32(cursor); cursor += 4U;
        change->operation = read_u32(cursor); cursor += 4U;
        if (!decode_string(&cursor, end, change->target_name,
                           sizeof(change->target_name)) ||
            !decode_string(&cursor, end, change->staged_name,
                           sizeof(change->staged_name)) ||
            !decode_string(&cursor, end, change->backup_name,
                           sizeof(change->backup_name)) ||
            !decode_string(&cursor, end, change->target_parent_path,
                           sizeof(change->target_parent_path)) ||
            !decode_string(&cursor, end, change->staged_parent_path,
                           sizeof(change->staged_parent_path)) ||
            (size_t)(end - cursor) < 33U)
            return ORBIT_JOURNAL_CODEC_MALFORMED;
        if (*cursor > 1U) return ORBIT_JOURNAL_CODEC_MALFORMED;
        change->preimage_exists = *cursor++ == 1U;
        change->preimage_device = read_u64(cursor); cursor += 8U;
        change->preimage_inode = read_u64(cursor); cursor += 8U;
        change->staged_device = read_u64(cursor); cursor += 8U;
        change->staged_inode = read_u64(cursor); cursor += 8U;
        if (orbit_package_filesystem_validate_change(change) != ORBIT_FILESYSTEM_OK)
            return ORBIT_JOURNAL_CODEC_MALFORMED;
    }
    if (cursor != end || !record_is_codec_valid(record))
        return ORBIT_JOURNAL_CODEC_MALFORMED;
    return ORBIT_JOURNAL_CODEC_OK;
}
