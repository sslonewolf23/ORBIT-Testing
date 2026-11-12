#include "ORBITPackageFilesystemJournalCodec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned failures = 0U;
#define EXPECT(label, condition) do { \
    if (condition) printf("PASS %s\n", label); \
    else { printf("FAIL %s\n", label); ++failures; } \
} while (0)

int main(void) {
    orbit_package_filesystem_journal_record *source =
        (orbit_package_filesystem_journal_record *)calloc(1U, sizeof(*source));
    orbit_package_filesystem_journal_record *decoded =
        (orbit_package_filesystem_journal_record *)calloc(1U, sizeof(*decoded));
    EXPECT("large journal records allocated", source != NULL && decoded != NULL);
    if (!source || !decoded) {
        free(source);
        free(decoded);
        return 1;
    }

    source->version = ORBIT_FILESYSTEM_JOURNAL_VERSION;
    source->phase = ORBIT_FILE_JOURNAL_APPLYING;
    source->revision = 7U;
    source->transaction_id[0] = 0xA7U;
    source->change_count = 1U;
    orbit_package_file_change *change = &source->changes[0];
    change->version = ORBIT_FILESYSTEM_CHANGE_VERSION;
    change->operation = ORBIT_FILESYSTEM_REMOVE;
    memcpy(change->target_name, "old-file", sizeof("old-file"));
    memcpy(change->backup_name, "backup-1", sizeof("backup-1"));
    change->preimage_exists = true;
    change->preimage_device = 11U;
    change->preimage_inode = 22U;

    size_t required = 0U;
    EXPECT("size query reports buffer requirement",
        orbit_package_filesystem_journal_encode(
            source, NULL, 0U, &required) == ORBIT_JOURNAL_CODEC_BUFFER_TOO_SMALL &&
        required > 29U);
    uint8_t *encoded = (uint8_t *)malloc(required);
    EXPECT("canonical payload allocated", encoded != NULL);
    if (!encoded) {
        free(source);
        free(decoded);
        return 1;
    }
    size_t written = 0U;
    EXPECT("canonical payload encoded",
        orbit_package_filesystem_journal_encode(
            source, encoded, required, &written) == ORBIT_JOURNAL_CODEC_OK &&
        written == required);
    EXPECT("canonical payload decoded",
        orbit_package_filesystem_journal_decode(
            encoded, written, source->revision, decoded) == ORBIT_JOURNAL_CODEC_OK);
    EXPECT("round-trip record is byte-identical",
        memcmp(source, decoded, sizeof(*source)) == 0);

    EXPECT("trailing bytes rejected",
        orbit_package_filesystem_journal_decode(
            encoded, written + 1U, source->revision, decoded) ==
            ORBIT_JOURNAL_CODEC_MALFORMED);
    EXPECT("zero revision rejected",
        orbit_package_filesystem_journal_decode(
            encoded, written, 0U, decoded) ==
            ORBIT_JOURNAL_CODEC_INVALID_ARGUMENT);

    encoded[4] = 2U;
    EXPECT("unknown codec version rejected",
        orbit_package_filesystem_journal_decode(
            encoded, written, source->revision, decoded) ==
            ORBIT_JOURNAL_CODEC_MALFORMED);

    free(encoded);
    free(source);
    free(decoded);
    printf("decision=%s failures=%u\n",
           failures == 0U ? "PASS" : "FAIL", failures);
    return failures == 0U ? 0 : 1;
}
