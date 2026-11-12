#ifndef ORBIT_PACKAGE_ARCHIVE_H
#define ORBIT_PACKAGE_ARCHIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ORBIT_DEB_MAX_BYTES (512ULL * 1024ULL * 1024ULL)
#define ORBIT_DEB_MAX_MEMBERS 16U
#define ORBIT_TAR_MAX_ENTRIES 4096U
#define ORBIT_TAR_MAX_PATH 1024U
#define ORBIT_TAR_MAX_FILE_BYTES (256ULL * 1024ULL * 1024ULL)
#define ORBIT_TAR_MAX_TOTAL_BYTES (1024ULL * 1024ULL * 1024ULL)

typedef enum {
    ORBIT_ARCHIVE_OK = 0,
    ORBIT_ARCHIVE_INVALID_ARGUMENT,
    ORBIT_ARCHIVE_LIMIT,
    ORBIT_ARCHIVE_MALFORMED_AR,
    ORBIT_ARCHIVE_MALFORMED_TAR,
    ORBIT_ARCHIVE_UNSAFE_PATH,
    ORBIT_ARCHIVE_DUPLICATE_PATH,
    ORBIT_ARCHIVE_UNSUPPORTED_ENTRY,
    ORBIT_ARCHIVE_UNSUPPORTED_COMPRESSION,
    ORBIT_ARCHIVE_MISSING_COMPONENT,
    ORBIT_ARCHIVE_CALLBACK_ERROR
} orbit_archive_code;

typedef struct {
    char path[ORBIT_TAR_MAX_PATH + 1U];
    uint64_t size;
    uint32_t mode;
    bool directory;
} orbit_archive_entry;

typedef struct {
    size_t entries;
    uint64_t regular_file_bytes;
    uint64_t largest_file_bytes;
    bool saw_debian_binary;
    bool saw_control_archive;
    bool saw_data_archive;
    orbit_archive_code code;
} orbit_archive_report;

typedef bool (*orbit_archive_entry_callback)(
    void *context, const orbit_archive_entry *entry);

typedef bool (*orbit_archive_data_chunk_callback)(
    void *context, const char *path, uint64_t offset,
    const uint8_t *bytes, size_t length, bool final_chunk);

/* Reports data.tar entries only. Callbacks may receive partial results before
 * a later archive error; callers must stage and discard the whole manifest
 * unless this function returns ORBIT_ARCHIVE_OK. */
orbit_archive_code orbit_package_archive_inspect_deb_with_data_entries(
    const uint8_t *deb, size_t deb_length, orbit_archive_entry_callback callback,
    void *callback_context, orbit_archive_report *report);

/* Streams data.tar file bytes to a callback. Path and byte pointers are valid
 * only during the callback. Chunks are provisional until the whole .deb
 * validates; callers must use disposable staging and discard unless OK.
 * Offsets are per file; final_chunk marks the last bytes (including empty files). */
orbit_archive_code orbit_package_archive_inspect_deb_with_data(
    const uint8_t *deb, size_t deb_length,
    orbit_archive_entry_callback entry_callback, void *entry_context,
    orbit_archive_data_chunk_callback data_callback, void *data_context,
    orbit_archive_report *report);

/* Strict inspection only. No extraction, filesystem writes, or script execution.
 * Path collisions are validated using a sorted, bounded manifest. Supports
 * uncompressed, gzip, xz, bzip2, and zstd control/data tar members.
 * Compressed members are decoded in fixed chunks with a 256 MiB expanded
 * output ceiling and a 200:1 expansion-ratio ceiling. */
orbit_archive_code orbit_package_archive_inspect_deb(
    const uint8_t *deb, size_t deb_length, orbit_archive_report *report);

#ifdef ORBIT_PACKAGE_ARCHIVE_TESTING
/* Harness-only entry point for exercising arbitrary decompressor chunk boundaries. */
orbit_archive_code orbit_package_archive_test_inspect_tar_chunks(
    const uint8_t *tar, size_t tar_length, size_t chunk_size,
    orbit_archive_report *report);
#endif

/* Validate a single archive path using the same policy as the tar inspector. */
bool orbit_package_archive_path_is_safe(const char *path);

#endif
