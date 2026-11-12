#ifndef ORBIT_PACKAGES_INDEX_H
#define ORBIT_PACKAGES_INDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ORBIT_PACKAGES_INDEX_MAX_BYTES (4U * 1024U * 1024U)
#define ORBIT_PACKAGES_INDEX_MAX_PACKAGES 4096U
#define ORBIT_PACKAGE_NAME_CAPACITY 128U
#define ORBIT_PACKAGE_VERSION_CAPACITY 128U
#define ORBIT_PACKAGE_ARCH_CAPACITY 64U
#define ORBIT_PACKAGE_FILENAME_CAPACITY 512U
#define ORBIT_PACKAGE_DESCRIPTION_CAPACITY 768U

typedef struct {
    char name[ORBIT_PACKAGE_NAME_CAPACITY];
    char version[ORBIT_PACKAGE_VERSION_CAPACITY];
    char architecture[ORBIT_PACKAGE_ARCH_CAPACITY];
    char filename[ORBIT_PACKAGE_FILENAME_CAPACITY];
    char sha256[65];
    char description[ORBIT_PACKAGE_DESCRIPTION_CAPACITY];
    uint64_t size;
} orbit_package_record;

typedef struct {
    orbit_package_record *packages;
    size_t count;
    size_t capacity;
} orbit_packages_index;

/* Parse a bounded Debian Packages control index. The caller must first verify
 * the exact index bytes against an authenticated Release SHA256 entry. */
bool orbit_packages_index_parse(const uint8_t *data, size_t length,
                                orbit_packages_index *result);
void orbit_packages_index_destroy(orbit_packages_index *index);

/* Verify downloaded .deb bytes against the exact Filename/Size/SHA256 record.
 * Call only after the Packages index itself has passed Release verification. */
bool orbit_package_verify_artifact(const orbit_package_record *package,
                                   const uint8_t *artifact_data,
                                   size_t artifact_length);

#endif
