#ifndef ORBIT_PACKAGE_OWNERSHIP_CODEC_H
#define ORBIT_PACKAGE_OWNERSHIP_CODEC_H
#include "ORBITPackageOwnership.h"
#include <stddef.h>
#include <stdint.h>
#define ORBIT_OWNERSHIP_CODEC_MAX_PAYLOAD (16U * 1024U * 1024U)
typedef enum {
    ORBIT_OWNERSHIP_CODEC_OK = 0,
    ORBIT_OWNERSHIP_CODEC_INVALID_ARGUMENT,
    ORBIT_OWNERSHIP_CODEC_INVALID_SNAPSHOT,
    ORBIT_OWNERSHIP_CODEC_BUFFER_TOO_SMALL,
    ORBIT_OWNERSHIP_CODEC_MALFORMED,
    ORBIT_OWNERSHIP_CODEC_LIMIT
} orbit_ownership_codec_code;
/* Canonical, versioned encoding. Authenticate these exact bytes and protect
 * the revision in the outer store. Never persist raw C structs or padding. */
orbit_ownership_codec_code orbit_package_ownership_encode(
    const orbit_package_ownership_snapshot *snapshot,
    uint8_t *output, size_t output_capacity, size_t *output_length);
orbit_ownership_codec_code orbit_package_ownership_decode(
    const uint8_t *payload, size_t payload_length,
    orbit_package_ownership_record *records, size_t record_capacity,
    orbit_package_ownership_snapshot *snapshot);
#endif
