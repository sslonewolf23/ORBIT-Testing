#ifndef ORBIT_PACKAGE_OWNERSHIP_H
#define ORBIT_PACKAGE_OWNERSHIP_H
#include "ORBITPackageArchive.h"
#include "ORBITPackagesIndex.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define ORBIT_OWNERSHIP_MAX_RECORDS 8192U
#define ORBIT_OWNERSHIP_MAX_PACKAGE_ENTRIES ORBIT_TAR_MAX_ENTRIES
typedef struct {
    char path[ORBIT_TAR_MAX_PATH + 1U];
    char package_name[ORBIT_PACKAGE_NAME_CAPACITY];
    char package_version[ORBIT_PACKAGE_VERSION_CAPACITY];
    char architecture[ORBIT_PACKAGE_ARCH_CAPACITY];
    bool directory;
} orbit_package_ownership_record;
typedef enum {
    ORBIT_OWNERSHIP_OK = 0, ORBIT_OWNERSHIP_INVALID_ARGUMENT,
    ORBIT_OWNERSHIP_LIMIT, ORBIT_OWNERSHIP_UNSAFE_PATH,
    ORBIT_OWNERSHIP_DUPLICATE_CANDIDATE, ORBIT_OWNERSHIP_FILE_CONFLICT,
    ORBIT_OWNERSHIP_ANCESTOR_CONFLICT, ORBIT_OWNERSHIP_NOT_OWNER,
    ORBIT_OWNERSHIP_CORRUPT_DATABASE
} orbit_ownership_code;
typedef struct {
    const orbit_package_ownership_record *records;
    size_t count;
} orbit_package_ownership_snapshot;
typedef struct {
    orbit_package_ownership_record *records;
    size_t count;
    size_t capacity;
} orbit_package_ownership_plan;
orbit_ownership_code orbit_package_ownership_plan_install(
    const orbit_package_ownership_snapshot *installed,
    const orbit_package_record *candidate,
    const orbit_archive_entry *entries, size_t entry_count,
    orbit_package_ownership_plan *plan);
orbit_ownership_code orbit_package_ownership_plan_remove(
    const orbit_package_ownership_snapshot *installed,
    const orbit_package_record *package,
    orbit_package_ownership_plan *plan);
void orbit_package_ownership_plan_destroy(orbit_package_ownership_plan *plan);
#ifdef __cplusplus
}
#endif
#endif
