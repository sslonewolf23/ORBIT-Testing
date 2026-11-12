#include "ORBITPackageArchive.h"

#include <ctype.h>
#include <limits.h>
#include <string.h>

#define AR_HEADER_BYTES 60U
#define TAR_BLOCK_BYTES 512U
#define AR_MAGIC "!<arch>\n"
#define AR_TRAILER "`\n"

typedef struct {
    char paths[ORBIT_TAR_MAX_ENTRIES][ORBIT_TAR_MAX_PATH + 1U];
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
    if (i != n) return false;
    *value = digits == 0U ? 0U : result;
    return true;
}

static bool field_string(const uint8_t *p, size_t n, char *out, size_t cap) {
    size_t length = 0U;
    while (length < n && p[length] != ' ' && p[length] != '/') ++length;
    if (length == 0U || length >= cap) return false;
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

static bool path_exists(const path_set *set, const char *path) {
    for (size_t i = 0U; i < set->count; ++i)
        if (strcmp(set->paths[i], path) == 0) return true;
    return false;
}

static orbit_archive_code inspect_tar(const uint8_t *tar, size_t length,
                                      orbit_archive_report *report) {
    if (!tar || length < TAR_BLOCK_BYTES * 2U ||
        (length % TAR_BLOCK_BYTES) != 0U) return ORBIT_ARCHIVE_MALFORMED_TAR;
    path_set *set = (path_set *)0;
    /* Avoid a large stack allocation; the caller's input is bounded and the
       path set is allocated only for this inspection. */
    set = (path_set *)calloc(1U, sizeof(*set));
    if (!set) return ORBIT_ARCHIVE_LIMIT;
    size_t offset = 0U;
    uint64_t total = 0U;
    bool ended = false;
    orbit_archive_code result = ORBIT_ARCHIVE_OK;
    while (offset + TAR_BLOCK_BYTES <= length) {
        const uint8_t *h = tar + offset;
        if (all_bytes(h, TAR_BLOCK_BYTES, 0U)) {
            if (offset + TAR_BLOCK_BYTES * 2U > length ||
                !all_bytes(tar + offset + TAR_BLOCK_BYTES,
                           TAR_BLOCK_BYTES, 0U) ||
                !all_bytes(tar + offset + TAR_BLOCK_BYTES * 2U,
                           length - offset - TAR_BLOCK_BYTES * 2U, 0U)) {
                result = ORBIT_ARCHIVE_MALFORMED_TAR;
            } else {
                ended = true;
            }
            break;
        }
        if (!tar_checksum_valid(h)) { result = ORBIT_ARCHIVE_MALFORMED_TAR; break; }
        if (memcmp(h + 257U, "ustar", 5U) != 0 ||
            (h[262U] != '\0' && h[262U] != ' ')) {
            result = ORBIT_ARCHIVE_UNSUPPORTED_ENTRY; break;
        }
        char path[ORBIT_TAR_MAX_PATH + 1U];
        if (!join_tar_path(h, path, sizeof(path)) ||
            !orbit_package_archive_path_is_safe(path)) {
            result = ORBIT_ARCHIVE_UNSAFE_PATH; break;
        }
        uint64_t file_size = 0U;
        if (!parse_octal(h + 124U, 12U, &file_size)) {
            result = ORBIT_ARCHIVE_MALFORMED_TAR; break;
        }
        char type = (char)h[156U];
        bool directory = type == '5';
        if (!(type == '\0' || type == '0' || directory) ||
            (directory && file_size != 0U)) {
            result = ORBIT_ARCHIVE_UNSUPPORTED_ENTRY; break;
        }
        if (file_size > ORBIT_TAR_MAX_FILE_BYTES ||
            report->entries >= ORBIT_TAR_MAX_ENTRIES) {
            result = ORBIT_ARCHIVE_LIMIT; break;
        }
        if (path_exists(set, path)) { result = ORBIT_ARCHIVE_DUPLICATE_PATH; break; }
        if (set->count >= ORBIT_TAR_MAX_ENTRIES) {
            result = ORBIT_ARCHIVE_LIMIT; break;
        }
        strcpy(set->paths[set->count++], path);
        if (!directory) {
            if (!add_u64(total, file_size, &total) ||
                total > ORBIT_TAR_MAX_TOTAL_BYTES) {
                result = ORBIT_ARCHIVE_LIMIT; break;
            }
            report->regular_file_bytes = total;
            if (file_size > report->largest_file_bytes)
                report->largest_file_bytes = file_size;
        }
        ++report->entries;
        uint64_t padded = file_size;
        if (padded > UINT64_MAX - (TAR_BLOCK_BYTES - 1U)) {
            result = ORBIT_ARCHIVE_LIMIT; break;
        }
        padded = ((padded + TAR_BLOCK_BYTES - 1U) / TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES;
        if (padded > (uint64_t)(length - offset - TAR_BLOCK_BYTES)) {
            result = ORBIT_ARCHIVE_MALFORMED_TAR; break;
        }
        offset += TAR_BLOCK_BYTES + (size_t)padded;
    }
    if (result == ORBIT_ARCHIVE_OK && !ended)
        result = ORBIT_ARCHIVE_MALFORMED_TAR;
    free(set);
    return result;
}

orbit_archive_code orbit_package_archive_inspect_deb(
    const uint8_t *deb, size_t deb_length, orbit_archive_report *report) {
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
    const uint8_t *data_tar = NULL;
    size_t data_tar_length = 0U;
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
            if (strcmp(name, "control.tar") != 0) {
                report->code = ORBIT_ARCHIVE_UNSUPPORTED_COMPRESSION; return report->code;
            }
        } else if (strncmp(name, "data.tar", 8U) == 0) {
            if (report->saw_data_archive) {
                report->code = ORBIT_ARCHIVE_DUPLICATE_PATH; return report->code;
            }
            report->saw_data_archive = true;
            if (strcmp(name, "data.tar") != 0) {
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
        !report->saw_data_archive || !data_tar) {
        report->code = ORBIT_ARCHIVE_MISSING_COMPONENT; return report->code;
    }
    report->code = inspect_tar(data_tar, data_tar_length, report);
    return report->code;
}
