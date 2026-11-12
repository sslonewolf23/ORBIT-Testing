#include "ORBITPackageArchive.h"
#include "ORBITPackageDecompress.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define AR_HEADER_BYTES 60U
#define TAR_BLOCK_BYTES 512U
#define AR_MAGIC "!<arch>\n"
#define AR_TRAILER "`\n"

typedef struct {
    char path[ORBIT_TAR_MAX_PATH + 1U];
    bool directory;
} path_record;

typedef struct {
    path_record records[ORBIT_TAR_MAX_ENTRIES];
    size_t count;
} path_set;

static bool add_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (!out || b > UINT64_MAX - a) return false;
    *out = a + b;
    return true;
}

static bool all_bytes(const uint8_t *p, size_t n, uint8_t value) {
    for (size_t i = 0U; i < n; ++i) if (p[i] != value) return false;
    return true;
}

static bool parse_decimal(const uint8_t *p, size_t n, uint64_t *value) {
    size_t i = 0U;
    uint64_t result = 0U;
    while (i < n && p[i] == ' ') ++i;
    size_t digits = 0U;
    for (; i < n && p[i] >= '0' && p[i] <= '9'; ++i) {
        unsigned d = (unsigned)(p[i] - '0');
        if (result > (UINT64_MAX - d) / 10U) return false;
        result = result * 10U + d;
        ++digits;
    }
    while (i < n && p[i] == ' ') ++i;
    if (digits == 0U || i != n) return false;
    *value = result;
    return true;
}

static bool parse_octal(const uint8_t *p, size_t n, uint64_t *value) {
    size_t i = 0U;
    uint64_t result = 0U;
    while (i < n && (p[i] == ' ' || p[i] == '\0')) ++i;
    size_t digits = 0U;
    for (; i < n && p[i] >= '0' && p[i] <= '7'; ++i) {
        unsigned d = (unsigned)(p[i] - '0');
        if (result > (UINT64_MAX - d) / 8U) return false;
        result = result * 8U + d;
        ++digits;
    }
    while (i < n && (p[i] == ' ' || p[i] == '\0')) ++i;
    if (i != n || digits == 0U) return false;
    *value = result;
    return true;
}

static bool field_string(const uint8_t *p, size_t n, char *out, size_t cap) {
    size_t length = 0U;
    while (length < n && p[length] != ' ' && p[length] != '/') ++length;
    if (length == 0U || length >= cap) return false;
    size_t padding = length;
    if (padding < n && p[padding] == '/') ++padding;
    for (size_t i = padding; i < n; ++i)
        if (p[i] != ' ') return false;
    for (size_t i = 0U; i < length; ++i) {
        unsigned char c = p[i];
        if (c < 0x21U || c > 0x7eU) return false;
    }
    memcpy(out, p, length);
    out[length] = '\0';
    return true;
}

bool orbit_package_archive_path_is_safe(const char *path) {
    if (!path || !path[0] || path[0] == '/' || path[0] == '\\') return false;
    size_t length = strlen(path);
    if (length == 0U || length > ORBIT_TAR_MAX_PATH ||
        path[length - 1U] == '/' || strchr(path, '\\')) return false;
    const char *segment = path;
    for (const char *p = path;; ++p) {
        unsigned char c = (unsigned char)*p;
        if (*p == '/' || *p == '\0') {
            size_t n = (size_t)(p - segment);
            if (n == 0U || (n == 1U && segment[0] == '.') ||
                (n == 2U && segment[0] == '.' && segment[1] == '.')) return false;
            if (*p == '\0') break;
            segment = p + 1;
        } else if (c < 0x21U || c > 0x7eU || c == ':' ) {
            return false;
        }
    }
    return true;
}

static bool tar_string(const uint8_t *p, size_t n, char *out, size_t cap) {
    size_t length = 0U;
    while (length < n && p[length] != 0U) ++length;
    if (length == 0U || length >= cap) return false;
    for (size_t i = 0U; i < length; ++i) {
        unsigned char c = p[i];
        if (c < 0x20U || c > 0x7eU) return false;
    }
    memcpy(out, p, length);
    out[length] = '\0';
    return true;
}

static bool join_tar_path(const uint8_t *header, char *out, size_t cap) {
    char name[256], prefix[156];
    if (!tar_string(header, 100U, name, sizeof(name))) return false;
    size_t prefix_len = 0U;
    while (prefix_len < 155U && header[345U + prefix_len] != 0U) ++prefix_len;
    if (prefix_len == 0U) {
        if (strlen(name) >= cap) return false;
        strcpy(out, name);
        return true;
    }
    if (prefix_len >= sizeof(prefix) ||
        !tar_string(header + 345U, 155U, prefix, sizeof(prefix))) return false;
    size_t need = prefix_len + 1U + strlen(name);
    if (need >= cap) return false;
    memcpy(out, prefix, prefix_len);
    out[prefix_len] = '/';
    strcpy(out + prefix_len + 1U, name);
    return true;
}

static bool tar_checksum_valid(const uint8_t *header) {
    uint64_t stored = 0U;
    if (!parse_octal(header + 148U, 8U, &stored)) return false;
    uint64_t sum = 0U;
    for (size_t i = 0U; i < TAR_BLOCK_BYTES; ++i) {
        uint8_t c = (i >= 148U && i < 156U) ? (uint8_t)' ' : header[i];
        if (!add_u64(sum, c, &sum)) return false;
    }
    return sum == stored;
}

static int compare_path_records(const path_record *a, const path_record *b) {
    return strcmp(a->path, b->path);
}

static void swap_path_records(path_record *a, path_record *b) {
    path_record temporary = *a;
    *a = *b;
    *b = temporary;
}

static void sift_path_heap(path_record *records, size_t root, size_t count) {
    while (count > 1U && root <= (count - 2U) / 2U) {
        size_t child = root * 2U + 1U;
        if (child + 1U < count &&
            compare_path_records(&records[child], &records[child + 1U]) < 0)
            ++child;
        if (compare_path_records(&records[root], &records[child]) >= 0) return;
        swap_path_records(&records[root], &records[child]);
        root = child;
    }
}

static void sort_path_records(path_set *set) {
    if (!set || set->count < 2U) return;
    for (size_t start = set->count / 2U; start > 0U; --start)
        sift_path_heap(set->records, start - 1U, set->count);
    for (size_t end = set->count; end > 1U; --end) {
        swap_path_records(&set->records[0], &set->records[end - 1U]);
        sift_path_heap(set->records, 0U, end - 1U);
    }
}

static size_t path_lower_bound(const path_set *set, const char *path) {
    size_t first = 0U;
    size_t count = set->count;
    while (count != 0U) {
        size_t step = count / 2U;
        size_t index = first + step;
        if (strcmp(set->records[index].path, path) < 0) {
            first = index + 1U;
            count -= step + 1U;
        } else {
            count = step;
        }
    }
    return first;
}

static orbit_archive_code validate_path_set(path_set *set) {
    if (!set) return ORBIT_ARCHIVE_INVALID_ARGUMENT;
    sort_path_records(set);
    for (size_t i = 0U; i < set->count; ++i) {
        const path_record *record = &set->records[i];
        if (i != 0U &&
            strcmp(set->records[i - 1U].path, record->path) == 0)
            return ORBIT_ARCHIVE_DUPLICATE_PATH;
        if (record->directory) continue;

        size_t length = strlen(record->path);
        if (length >= ORBIT_TAR_MAX_PATH) return ORBIT_ARCHIVE_UNSAFE_PATH;
        char descendant_prefix[ORBIT_TAR_MAX_PATH + 2U];
        memcpy(descendant_prefix, record->path, length);
        descendant_prefix[length] = '/';
        descendant_prefix[length + 1U] = '\0';
        size_t descendant = path_lower_bound(set, descendant_prefix);
        if (descendant < set->count &&
            strncmp(set->records[descendant].path, descendant_prefix,
                    length + 1U) == 0)
            return ORBIT_ARCHIVE_UNSAFE_PATH;
    }
    return ORBIT_ARCHIVE_OK;
}

static bool member_compression(const char *name, const char *base,
                               orbit_decompress_format *format, bool *compressed) {
    *compressed = false;
    if (strcmp(name, base) == 0) return true;
    char candidate[32];
    const char *suffixes[] = { ".gz", ".xz", ".bz2", ".zst" };
    const orbit_decompress_format formats[] = {
        ORBIT_DECOMPRESS_GZIP, ORBIT_DECOMPRESS_XZ,
        ORBIT_DECOMPRESS_BZIP2, ORBIT_DECOMPRESS_ZSTD
    };
    for (size_t i = 0U; i < sizeof(suffixes) / sizeof(suffixes[0]); ++i) {
        if (snprintf(candidate, sizeof(candidate), "%s%s", base, suffixes[i]) > 0 &&
            strcmp(name, candidate) == 0) {
            *format = formats[i];
            *compressed = true;
            return true;
        }
    }
    return false;
}

typedef struct {
    path_set *paths;
    orbit_archive_report *report;
    uint8_t header[TAR_BLOCK_BYTES];
    size_t header_used;
    uint64_t payload_remaining;
    uint64_t padding_remaining;
    uint64_t input_bytes;
    unsigned zero_blocks;
    bool ended;
    orbit_archive_code code;
    orbit_archive_entry_callback callback;
    void *callback_context;
    orbit_archive_data_chunk_callback data_callback;
    void *data_context;
    char current_file_path[ORBIT_TAR_MAX_PATH + 1U];
    uint64_t current_file_offset;
} tar_stream;

static bool tar_stream_init(tar_stream *stream, orbit_archive_report *report,
                            orbit_archive_entry_callback callback,
                            void *callback_context,
                            orbit_archive_data_chunk_callback data_callback,
                            void *data_context) {
    if (!stream || !report) return false;
    memset(stream, 0, sizeof(*stream));
    stream->paths = (path_set *)calloc(1U, sizeof(*stream->paths));
    if (!stream->paths) return false;
    stream->report = report;
    stream->callback = callback;
    stream->callback_context = callback_context;
    stream->data_callback = data_callback;
    stream->data_context = data_context;
    stream->code = ORBIT_ARCHIVE_OK;
    return true;
}

static void tar_stream_destroy(tar_stream *stream) {
    if (!stream) return;
    free(stream->paths);
    stream->paths = NULL;
}

static orbit_archive_code tar_stream_header(tar_stream *stream) {
    const uint8_t *h = stream->header;
    if (all_bytes(h, TAR_BLOCK_BYTES, 0U)) {
        ++stream->zero_blocks;
        if (stream->zero_blocks >= 2U) stream->ended = true;
        return ORBIT_ARCHIVE_OK;
    }
    if (stream->zero_blocks != 0U) return ORBIT_ARCHIVE_MALFORMED_TAR;
    if (!tar_checksum_valid(h)) return ORBIT_ARCHIVE_MALFORMED_TAR;
    if (memcmp(h + 257U, "ustar", 5U) != 0 ||
        (h[262U] != '\0' && h[262U] != ' '))
        return ORBIT_ARCHIVE_UNSUPPORTED_ENTRY;

    char path[ORBIT_TAR_MAX_PATH + 1U];
    if (!join_tar_path(h, path, sizeof(path))) return ORBIT_ARCHIVE_UNSAFE_PATH;
    char type = (char)h[156U];
    bool directory = type == '5';
    if (directory && (strcmp(path, ".") == 0 || strcmp(path, "./") == 0)) {
        uint64_t root_size = 0U;
        if (!parse_octal(h + 124U, 12U, &root_size) || root_size != 0U)
            return ORBIT_ARCHIVE_MALFORMED_TAR;
        return ORBIT_ARCHIVE_OK;
    }

    while (strncmp(path, "./", 2U) == 0)
        memmove(path, path + 2U, strlen(path + 2U) + 1U);
    size_t path_length = strlen(path);
    if (directory && path_length > 0U && path[path_length - 1U] == '/')
        path[path_length - 1U] = '\0';
    if (!orbit_package_archive_path_is_safe(path)) return ORBIT_ARCHIVE_UNSAFE_PATH;

    uint64_t file_size = 0U;
    uint64_t mode_value = 0U;
    if (!parse_octal(h + 124U, 12U, &file_size) ||
        !parse_octal(h + 100U, 8U, &mode_value) || mode_value > 07777U)
        return ORBIT_ARCHIVE_MALFORMED_TAR;
    if (!(type == '\0' || type == '0' || directory) ||
        (directory && file_size != 0U) || (mode_value & ~0777ULL) != 0U)
        return ORBIT_ARCHIVE_UNSUPPORTED_ENTRY;
    if (file_size > ORBIT_TAR_MAX_FILE_BYTES ||
        stream->report->entries >= ORBIT_TAR_MAX_ENTRIES)
        return ORBIT_ARCHIVE_LIMIT;

    if (stream->paths->count >= ORBIT_TAR_MAX_ENTRIES)
        return ORBIT_ARCHIVE_LIMIT;
    path_record *record = &stream->paths->records[stream->paths->count++];
    strcpy(record->path, path);
    record->directory = directory;

    if (!directory) {
        uint64_t total = 0U;
        if (!add_u64(stream->report->regular_file_bytes, file_size, &total) ||
            total > ORBIT_TAR_MAX_TOTAL_BYTES)
            return ORBIT_ARCHIVE_LIMIT;
        stream->report->regular_file_bytes = total;
        if (file_size > stream->report->largest_file_bytes)
            stream->report->largest_file_bytes = file_size;
    }
    ++stream->report->entries;
    if (stream->callback) {
        orbit_archive_entry entry;
        memset(&entry, 0, sizeof(entry));
        memcpy(entry.path, path, strlen(path) + 1U);
        entry.size = file_size;
        entry.mode = (uint32_t)mode_value;
        entry.directory = directory;
        if (!stream->callback(stream->callback_context, &entry))
            return ORBIT_ARCHIVE_CALLBACK_ERROR;
    }
    if (!directory && stream->data_callback) {
        memcpy(stream->current_file_path, path, strlen(path) + 1U);
        stream->current_file_offset = 0U;
        if (file_size == 0U &&
            !stream->data_callback(stream->data_context, path, 0U, NULL, 0U, true))
            return ORBIT_ARCHIVE_CALLBACK_ERROR;
    }

    uint64_t padded = file_size;
    if (padded > UINT64_MAX - (TAR_BLOCK_BYTES - 1U))
        return ORBIT_ARCHIVE_LIMIT;
    padded = ((padded + TAR_BLOCK_BYTES - 1U) / TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES;
    stream->payload_remaining = file_size;
    stream->padding_remaining = padded - file_size;
    return ORBIT_ARCHIVE_OK;
}

static bool tar_stream_feed(void *context, const uint8_t *bytes, size_t length) {
    tar_stream *stream = (tar_stream *)context;
    if (!stream || (!bytes && length != 0U) || stream->code != ORBIT_ARCHIVE_OK)
        return false;
    if ((uint64_t)length > UINT64_MAX - stream->input_bytes) {
        stream->code = ORBIT_ARCHIVE_LIMIT;
        return false;
    }
    stream->input_bytes += (uint64_t)length;
    size_t offset = 0U;
    while (offset < length) {
        if (stream->ended) {
            if (!all_bytes(bytes + offset, length - offset, 0U)) {
                stream->code = ORBIT_ARCHIVE_MALFORMED_TAR;
                return false;
            }
            return true;
        }
        if (stream->payload_remaining != 0U) {
            size_t take = stream->payload_remaining < (uint64_t)(length - offset) ?
                (size_t)stream->payload_remaining : length - offset;
            if (stream->data_callback &&
                !stream->data_callback(stream->data_context,
                    stream->current_file_path, stream->current_file_offset,
                    bytes + offset, take, (uint64_t)take == stream->payload_remaining)) {
                stream->code = ORBIT_ARCHIVE_CALLBACK_ERROR;
                return false;
            }
            stream->current_file_offset += (uint64_t)take;
            stream->payload_remaining -= (uint64_t)take;
            offset += take;
            continue;
        }
        if (stream->padding_remaining != 0U) {
            size_t take = stream->padding_remaining < (uint64_t)(length - offset) ?
                (size_t)stream->padding_remaining : length - offset;
            if (!all_bytes(bytes + offset, take, 0U)) {
                stream->code = ORBIT_ARCHIVE_MALFORMED_TAR;
                return false;
            }
            stream->padding_remaining -= (uint64_t)take;
            offset += take;
            continue;
        }
        size_t need = TAR_BLOCK_BYTES - stream->header_used;
        size_t take = need < length - offset ? need : length - offset;
        memcpy(stream->header + stream->header_used, bytes + offset, take);
        stream->header_used += take;
        offset += take;
        if (stream->header_used == TAR_BLOCK_BYTES) {
            stream->code = tar_stream_header(stream);
            stream->header_used = 0U;
            if (stream->code != ORBIT_ARCHIVE_OK) return false;
        }
    }
    return true;
}

static orbit_archive_code tar_stream_finish(tar_stream *stream) {
    if (!stream) return ORBIT_ARCHIVE_INVALID_ARGUMENT;
    if (stream->code != ORBIT_ARCHIVE_OK) return stream->code;
    if (!stream->ended || stream->header_used != 0U ||
        stream->payload_remaining != 0U || stream->padding_remaining != 0U ||
        (stream->input_bytes % TAR_BLOCK_BYTES) != 0U)
        return ORBIT_ARCHIVE_MALFORMED_TAR;
    return validate_path_set(stream->paths);
}

static orbit_archive_code inspect_tar_member(
    const uint8_t *member, size_t member_length, bool compressed,
    orbit_decompress_format format, orbit_archive_report *report,
    orbit_archive_entry_callback callback, void *callback_context,
    orbit_archive_data_chunk_callback data_callback, void *data_context) {
    tar_stream stream;
    if (!tar_stream_init(&stream, report, callback, callback_context,
                         data_callback, data_context)) return ORBIT_ARCHIVE_LIMIT;
    orbit_archive_code result = ORBIT_ARCHIVE_OK;
    if (compressed) {
        uint64_t decoded_length = 0U;
        orbit_decompress_code decode = orbit_package_decompress_stream(
            format, member, member_length, ORBIT_DECOMPRESS_OUTPUT_MAX,
            tar_stream_feed, &stream, &decoded_length);
        if (stream.code != ORBIT_ARCHIVE_OK) {
            result = stream.code;
        } else if (decode == ORBIT_DECOMPRESS_LIMIT) {
            result = ORBIT_ARCHIVE_LIMIT;
        } else if (decode != ORBIT_DECOMPRESS_OK) {
            result = ORBIT_ARCHIVE_MALFORMED_TAR;
        } else if (decoded_length != stream.input_bytes) {
            result = ORBIT_ARCHIVE_MALFORMED_TAR;
        }
    } else if (!tar_stream_feed(&stream, member, member_length)) {
        result = stream.code;
    }
    if (result == ORBIT_ARCHIVE_OK) result = tar_stream_finish(&stream);
    tar_stream_destroy(&stream);
    return result;
}


#ifdef ORBIT_PACKAGE_ARCHIVE_TESTING
orbit_archive_code orbit_package_archive_test_inspect_tar_chunks(
    const uint8_t *tar, size_t tar_length, size_t chunk_size,
    orbit_archive_report *report) {
    if (!report || !tar || tar_length == 0U || chunk_size == 0U)
        return ORBIT_ARCHIVE_INVALID_ARGUMENT;
    memset(report, 0, sizeof(*report));
    tar_stream stream;
    if (!tar_stream_init(&stream, report, NULL, NULL, NULL, NULL))
        return ORBIT_ARCHIVE_LIMIT;
    orbit_archive_code result = ORBIT_ARCHIVE_OK;
    size_t offset = 0U;
    while (offset < tar_length) {
        size_t amount = chunk_size < tar_length - offset ?
            chunk_size : tar_length - offset;
        if (!tar_stream_feed(&stream, tar + offset, amount)) {
            result = stream.code;
            break;
        }
        offset += amount;
    }
    if (result == ORBIT_ARCHIVE_OK) result = tar_stream_finish(&stream);
    tar_stream_destroy(&stream);
    report->code = result;
    return result;
}
#endif

orbit_archive_code orbit_package_archive_inspect_deb_with_data(
    const uint8_t *deb, size_t deb_length,
    orbit_archive_entry_callback entry_callback, void *entry_context,
    orbit_archive_data_chunk_callback data_callback, void *data_context,
    orbit_archive_report *report) {
    if (!report) return ORBIT_ARCHIVE_INVALID_ARGUMENT;
    memset(report, 0, sizeof(*report));
    if (!deb || deb_length == 0U) {
        report->code = ORBIT_ARCHIVE_INVALID_ARGUMENT;
        return report->code;
    }
    if (deb_length > ORBIT_DEB_MAX_BYTES) {
        report->code = ORBIT_ARCHIVE_LIMIT;
        return report->code;
    }
    if (deb_length < 8U || memcmp(deb, AR_MAGIC, 8U) != 0) {
        report->code = ORBIT_ARCHIVE_MALFORMED_AR;
        return report->code;
    }
    size_t offset = 8U;
    const uint8_t *control_tar = NULL;
    size_t control_tar_length = 0U;
    orbit_decompress_format control_format = ORBIT_DECOMPRESS_GZIP;
    bool control_compressed = false;
    const uint8_t *data_tar = NULL;
    size_t data_tar_length = 0U;
    orbit_decompress_format data_format = ORBIT_DECOMPRESS_GZIP;
    bool data_compressed = false;
    unsigned members = 0U;
    while (offset < deb_length) {
        if (deb_length - offset < AR_HEADER_BYTES) {
            report->code = ORBIT_ARCHIVE_MALFORMED_AR; return report->code;
        }
        const uint8_t *h = deb + offset;
        if (memcmp(h + 58U, AR_TRAILER, 2U) != 0) {
            report->code = ORBIT_ARCHIVE_MALFORMED_AR; return report->code;
        }
        char name[32];
        if (!field_string(h, 16U, name, sizeof(name))) {
            report->code = ORBIT_ARCHIVE_MALFORMED_AR; return report->code;
        }
        uint64_t member_size = 0U;
        if (!parse_decimal(h + 48U, 10U, &member_size) ||
            member_size > (uint64_t)(deb_length - offset - AR_HEADER_BYTES)) {
            report->code = ORBIT_ARCHIVE_MALFORMED_AR; return report->code;
        }
        if (++members > ORBIT_DEB_MAX_MEMBERS) {
            report->code = ORBIT_ARCHIVE_LIMIT; return report->code;
        }
        const uint8_t *body = h + AR_HEADER_BYTES;
        if (strcmp(name, "debian-binary") == 0) {
            if (report->saw_debian_binary || member_size != 4U ||
                memcmp(body, "2.0\n", 4U) != 0) {
                report->code = ORBIT_ARCHIVE_MALFORMED_AR; return report->code;
            }
            report->saw_debian_binary = true;
        } else if (strncmp(name, "control.tar", 10U) == 0) {
            if (report->saw_control_archive) {
                report->code = ORBIT_ARCHIVE_DUPLICATE_PATH; return report->code;
            }
            report->saw_control_archive = true;
            if (!member_compression(name, "control.tar", &control_format, &control_compressed)) {
                report->code = ORBIT_ARCHIVE_UNSUPPORTED_COMPRESSION; return report->code;
            }
            control_tar = body;
            control_tar_length = (size_t)member_size;
        } else if (strncmp(name, "data.tar", 8U) == 0) {
            if (report->saw_data_archive) {
                report->code = ORBIT_ARCHIVE_DUPLICATE_PATH; return report->code;
            }
            report->saw_data_archive = true;
            if (!member_compression(name, "data.tar", &data_format, &data_compressed)) {
                report->code = ORBIT_ARCHIVE_UNSUPPORTED_COMPRESSION; return report->code;
            }
            data_tar = body;
            data_tar_length = (size_t)member_size;
        } else {
            report->code = ORBIT_ARCHIVE_UNSUPPORTED_ENTRY; return report->code;
        }
        size_t advance = AR_HEADER_BYTES + (size_t)member_size;
        if ((advance & 1U) != 0U) {
            if (offset + advance >= deb_length || deb[offset + advance] != '\n') {
                report->code = ORBIT_ARCHIVE_MALFORMED_AR; return report->code;
            }
            ++advance;
        }
        offset += advance;
    }
    if (!report->saw_debian_binary || !report->saw_control_archive ||
        !report->saw_data_archive || !control_tar || !data_tar) {
        report->code = ORBIT_ARCHIVE_MISSING_COMPONENT; return report->code;
    }
    report->code = inspect_tar_member(control_tar, control_tar_length,
                                      control_compressed, control_format, report,
                                      NULL, NULL, NULL, NULL);
    if (report->code != ORBIT_ARCHIVE_OK) return report->code;
    report->code = inspect_tar_member(data_tar, data_tar_length,
                                      data_compressed, data_format, report,
                                      entry_callback, entry_context,
                                      data_callback, data_context);
    return report->code;
}

orbit_archive_code orbit_package_archive_inspect_deb_with_data_entries(
    const uint8_t *deb, size_t deb_length, orbit_archive_entry_callback callback,
    void *callback_context, orbit_archive_report *report) {
    return orbit_package_archive_inspect_deb_with_data(
        deb, deb_length, callback, callback_context, NULL, NULL, report);
}

orbit_archive_code orbit_package_archive_inspect_deb(
    const uint8_t *deb, size_t deb_length, orbit_archive_report *report) {
    return orbit_package_archive_inspect_deb_with_data(
        deb, deb_length, NULL, NULL, NULL, NULL, report);
}
