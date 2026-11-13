#ifndef ORBIT_PACKAGE_STAGING_H
#define ORBIT_PACKAGE_STAGING_H

#include "ORBITPackageArchive.h"

#include <stdbool.h>
#include <stdint.h>

#define ORBIT_STAGING_NAME_CAPACITY 64U

typedef enum {
    ORBIT_STAGING_OK = 0,
    ORBIT_STAGING_INVALID_ARGUMENT,
    ORBIT_STAGING_INVALID_STATE,
    ORBIT_STAGING_UNSAFE_PATH,
    ORBIT_STAGING_LIMIT,
    ORBIT_STAGING_IO_ERROR,
    ORBIT_STAGING_ARCHIVE_ERROR
} orbit_staging_code;

typedef struct {
    int base_directory_fd;
    int staging_directory_fd;
    int active_file_fd;
    char staging_name[ORBIT_STAGING_NAME_CAPACITY];
    char active_file_path[ORBIT_TAR_MAX_PATH + 1U];
    uint64_t active_file_size;
    uint64_t active_file_written;
    uint32_t active_file_mode;
    bool complete;
    bool failed;
} orbit_package_staging;

/* staging must be fresh storage or a fully discarded/closed instance.
 * base_directory_fd must identify a trusted directory opened by the caller.
 * The staging directory is created as a new 0700 child and never follows links. */
orbit_staging_code orbit_package_staging_begin(
    int base_directory_fd, const char *staging_name,
    orbit_package_staging *staging);

/* Performs a no-write full-archive inspection first, then creates a fresh
 * private stage and streams the validated archive into it. The caller must
 * complete package-ownership conflict checks before calling this function.
 * Any second-pass or staging failure triggers best-effort stage discard.
 * archive_code receives the parser result when an archive pass fails. */
orbit_staging_code orbit_package_staging_extract_deb(
    int base_directory_fd, const char *staging_name,
    const uint8_t *deb, size_t deb_length,
    orbit_package_staging *staging,
    orbit_archive_report *report,
    orbit_archive_code *archive_code);

/* These callbacks can be passed directly to
 * orbit_package_archive_inspect_deb_with_data(). All writes remain inside the
 * private staging directory. Any archive failure requires discard(). */
bool orbit_package_staging_entry_callback(
    void *context, const orbit_archive_entry *entry);
bool orbit_package_staging_data_callback(
    void *context, const char *path, uint64_t offset,
    const uint8_t *bytes, size_t length, bool final_chunk);

orbit_staging_code orbit_package_staging_finish(
    orbit_package_staging *staging);

/* Recursively removes only the private staging tree using descriptor-relative,
 * no-follow operations. Safe to retry after a partial cleanup failure. */
orbit_staging_code orbit_package_staging_discard(
    orbit_package_staging *staging);

/* Closes descriptors but deliberately leaves a completed staging tree in place. */
orbit_staging_code orbit_package_staging_close(
    orbit_package_staging *staging);

#endif
