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
#define ORBIT_PACKAGE_RELATION_CAPACITY 2048U

typedef struct {
    char name[ORBIT_PACKAGE_NAME_CAPACITY];
    char version[ORBIT_PACKAGE_VERSION_CAPACITY];
    char architecture[ORBIT_PACKAGE_ARCH_CAPACITY];
    char filename[ORBIT_PACKAGE_FILENAME_CAPACITY];
    char sha256[65];
    char description[ORBIT_PACKAGE_DESCRIPTION_CAPACITY];
    char depends[ORBIT_PACKAGE_RELATION_CAPACITY];
    char pre_depends[ORBIT_PACKAGE_RELATION_CAPACITY];
    char conflicts[ORBIT_PACKAGE_RELATION_CAPACITY];
    char breaks[ORBIT_PACKAGE_RELATION_CAPACITY];
    char provides[ORBIT_PACKAGE_RELATION_CAPACITY];
    char replaces[ORBIT_PACKAGE_RELATION_CAPACITY];
    char multi_arch[32];
    uint64_t size;
} orbit_package_record;

typedef struct {
    orbit_package_record *packages;
    size_t count;
    size_t capacity;
} orbit_packages_index;

/* Parse a bounded Debian Packages control index. The caller must first verify
 * the exact index bytes against an authenticated Release SHA256 entry.
 * result must be zero-initialized or previously released with destroy(). */
bool orbit_packages_index_parse(const uint8_t *data, size_t length,
                                orbit_packages_index *result);
void orbit_packages_index_destroy(orbit_packages_index *index);

typedef struct {
    void *hash_context;
    uint64_t expected_size;
    uint64_t bytes_seen;
    uint8_t expected_digest[32];
    bool active;
} orbit_package_artifact_verifier;

/* Streaming artifact verification for large .deb downloads. Initialize from
 * a record in an authenticated Packages catalog, feed every downloaded byte,
 * then finalize. Any size/hash mismatch fails closed. */
bool orbit_package_artifact_verifier_init(
    orbit_package_artifact_verifier *verifier,
    const orbit_package_record *package);
bool orbit_package_artifact_verifier_update(
    orbit_package_artifact_verifier *verifier,
    const uint8_t *chunk,
    size_t chunk_length);
bool orbit_package_artifact_verifier_finalize(
    orbit_package_artifact_verifier *verifier);
void orbit_package_artifact_verifier_destroy(
    orbit_package_artifact_verifier *verifier);

/* Convenience wrapper for artifacts already resident in memory. */
bool orbit_package_verify_artifact(const orbit_package_record *package,
                                   const uint8_t *artifact_data,
                                   size_t artifact_length);

#endif
