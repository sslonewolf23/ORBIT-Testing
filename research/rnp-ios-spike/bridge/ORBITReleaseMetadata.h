#ifndef ORBIT_RELEASE_METADATA_H
#define ORBIT_RELEASE_METADATA_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ORBIT_RELEASE_MAX_BYTES (4U * 1024U * 1024U)
#define ORBIT_RELEASE_MAX_CHECKSUMS 256U
#define ORBIT_RELEASE_FIELD_CAPACITY 256U
#define ORBIT_RELEASE_PATH_CAPACITY 512U

typedef struct {
    char sha256[65];
    uint64_t size;
    char path[ORBIT_RELEASE_PATH_CAPACITY];
} orbit_release_checksum;

typedef struct {
    char date[ORBIT_RELEASE_FIELD_CAPACITY];
    char valid_until[ORBIT_RELEASE_FIELD_CAPACITY];
    char suite[ORBIT_RELEASE_FIELD_CAPACITY];
    char codename[ORBIT_RELEASE_FIELD_CAPACITY];
    char architectures[ORBIT_RELEASE_FIELD_CAPACITY];
    char components[ORBIT_RELEASE_FIELD_CAPACITY];
    orbit_release_checksum checksums[ORBIT_RELEASE_MAX_CHECKSUMS];
    size_t checksum_count;
} orbit_release_metadata;

/* Strictly parse a bounded Debian Release/InRelease plaintext payload.
 * This parser does not authenticate the input; verify InRelease first. */
bool orbit_release_metadata_parse(const uint8_t *data, size_t length,
                                   orbit_release_metadata *result);

/* Parse RFC 2822-style Debian timestamps with a validated weekday, calendar
 * date, clock, and UTC or numeric +/-HHMM timezone. Rejects pre-epoch dates. */
bool orbit_release_parse_timestamp(const char *value, uint64_t *unix_seconds);

/* Convert parsed Date and optional Valid-Until fields to Unix timestamps.
 * A missing Valid-Until is returned as zero and must be handled by max-age policy. */
bool orbit_release_metadata_timestamps(const orbit_release_metadata *metadata,
                                        uint64_t *date_seconds,
                                        uint64_t *valid_until_seconds);

bool orbit_release_freshness_valid(uint64_t date_seconds,
                                   uint64_t valid_until_seconds,
                                   uint64_t now_seconds,
                                   uint64_t maximum_age_seconds,
                                   uint64_t allowed_future_skew_seconds);
#endif
