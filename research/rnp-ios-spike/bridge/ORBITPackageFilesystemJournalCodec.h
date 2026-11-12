#ifndef ORBIT_PACKAGE_FILESYSTEM_JOURNAL_CODEC_H
#define ORBIT_PACKAGE_FILESYSTEM_JOURNAL_CODEC_H

#include "ORBITPackageFilesystemJournal.h"

#include <stddef.h>
#include <stdint.h>

#define ORBIT_FILESYSTEM_JOURNAL_CODEC_MAX_PAYLOAD (16U * 1024U * 1024U)

typedef enum {
    ORBIT_JOURNAL_CODEC_OK = 0,
    ORBIT_JOURNAL_CODEC_INVALID_ARGUMENT,
    ORBIT_JOURNAL_CODEC_INVALID_RECORD,
    ORBIT_JOURNAL_CODEC_BUFFER_TOO_SMALL,
    ORBIT_JOURNAL_CODEC_MALFORMED
} orbit_journal_codec_code;

/* Canonical payload codec. Revision is authenticated by the outer ORBJ
 * envelope and is supplied separately when decoding. Never persist raw C
 * structs or compiler padding. */
orbit_journal_codec_code orbit_package_filesystem_journal_encode(
    const orbit_package_filesystem_journal_record *record,
    uint8_t *output, size_t output_capacity, size_t *output_length);

orbit_journal_codec_code orbit_package_filesystem_journal_decode(
    const uint8_t *payload, size_t payload_length, uint64_t revision,
    orbit_package_filesystem_journal_record *record);

#endif
