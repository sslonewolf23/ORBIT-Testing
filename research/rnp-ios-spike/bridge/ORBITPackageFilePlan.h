#ifndef ORBIT_PACKAGE_FILE_PLAN_H
#define ORBIT_PACKAGE_FILE_PLAN_H

#include "ORBITPackageFilesystem.h"
#include "ORBITPackageOwnership.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ORBIT_PACKAGE_FILE_PLAN_OK = 0,
    ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT,
    ORBIT_PACKAGE_FILE_PLAN_OWNERSHIP_ERROR,
    ORBIT_PACKAGE_FILE_PLAN_FILESYSTEM_ERROR,
    ORBIT_PACKAGE_FILE_PLAN_LIMIT
} orbit_package_file_plan_code;

/* Build a read-only filesystem removal plan for an installed package identity.
 * Every regular file owned by that identity is backed up for rollback and
 * removed on commit. Directory ownership rows are removed from the replacement
 * snapshot but directories are never recursively deleted (they may be shared).
 * Packages with no owned regular files are currently rejected because the
 * journal format requires at least one filesystem change.
 */
orbit_package_file_plan_code orbit_package_file_plan_build_remove(
    const orbit_package_ownership_snapshot *installed,
    const orbit_package_record *package,
    int install_root_fd, int backup_directory_fd,
    orbit_package_file_change *changes, size_t change_capacity,
    size_t *change_count,
    orbit_package_ownership_record *ownership_output,
    size_t ownership_capacity,
    orbit_package_ownership_snapshot *replacement_ownership);

/* Build a read-only filesystem change plan for an already-staged package.
 * The complete archive manifest is used to create the replacement ownership
 * snapshot. Regular files are mapped to same-relative-path targets and staged
 * files. Obsolete regular files owned by this package identity are removed.
 *
 * This planner never creates directories and never mutates installed files.
 * Every target/staged parent must already exist; unsupported layouts fail
 * closed. The caller must keep all trusted roots and the backup directory
 * stable and hold the package transaction lock through execution/recovery.
 *
 * Changes and ownership_output are caller-owned buffers. No partial plan is
 * returned on failure. Directory manifest entries affect ownership only. */
orbit_package_file_plan_code orbit_package_file_plan_build_install(
    const orbit_package_ownership_snapshot *installed,
    const orbit_package_record *candidate,
    const orbit_archive_entry *manifest, size_t manifest_count,
    int install_root_fd, int staging_root_fd, int backup_directory_fd,
    orbit_package_file_change *changes, size_t change_capacity,
    size_t *change_count,
    orbit_package_ownership_record *ownership_output,
    size_t ownership_capacity,
    orbit_package_ownership_snapshot *replacement_ownership);

#ifdef __cplusplus
}
#endif
#endif
