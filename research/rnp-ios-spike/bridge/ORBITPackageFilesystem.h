#ifndef ORBIT_PACKAGE_FILESYSTEM_H
#define ORBIT_PACKAGE_FILESYSTEM_H

#include <stdbool.h>
#include <stdint.h>

#define ORBIT_FILESYSTEM_COMPONENT_CAPACITY 64U
#define ORBIT_FILESYSTEM_CHANGE_VERSION 2U
#define ORBIT_FILESYSTEM_PARENT_PATH_CAPACITY 1025U
#define ORBIT_FILESYSTEM_LOCK_NAME ".orbit-package-transaction.lock"

typedef enum {
    ORBIT_FILESYSTEM_OK = 0,
    ORBIT_FILESYSTEM_INVALID_ARGUMENT,
    ORBIT_FILESYSTEM_INVALID_STATE,
    ORBIT_FILESYSTEM_UNSAFE_PATH,
    ORBIT_FILESYSTEM_CONFLICT,
    ORBIT_FILESYSTEM_IO_ERROR,
    ORBIT_FILESYSTEM_RECOVERY_REQUIRED,
    ORBIT_FILESYSTEM_BUSY,
    ORBIT_FILESYSTEM_LIMIT
} orbit_filesystem_code;

typedef enum {
    ORBIT_FILESYSTEM_REPLACE = 1,
    ORBIT_FILESYSTEM_REMOVE = 2
} orbit_filesystem_operation;

/* Fixed-size recovery record. Persist this record durably before apply().
 * Parent directory descriptors are supplied separately and are never stored. */
typedef struct {
    uint32_t version;
    uint32_t operation;
    char target_name[ORBIT_FILESYSTEM_COMPONENT_CAPACITY];
    char staged_name[ORBIT_FILESYSTEM_COMPONENT_CAPACITY];
    char backup_name[ORBIT_FILESYSTEM_COMPONENT_CAPACITY];
    char target_parent_path[ORBIT_FILESYSTEM_PARENT_PATH_CAPACITY];
    char staged_parent_path[ORBIT_FILESYSTEM_PARENT_PATH_CAPACITY];
    bool preimage_exists;
    uint64_t preimage_device;
    uint64_t preimage_inode;
    uint64_t staged_device;
    uint64_t staged_inode;
} orbit_package_file_change;

typedef struct {
    int descriptor;
} orbit_package_filesystem_lock;

/* Acquires a nonblocking exclusive advisory lock in an owner-controlled root
 * that is not group/world writable. The caller must hold it across prepare,
 * journal execution/recovery, and cleanup. This coordinates cooperating ORBIT
 * processes only; it cannot exclude privileged or same-owner non-ORBIT writers. */
orbit_filesystem_code orbit_package_filesystem_lock_acquire(
    int trusted_root_fd, orbit_package_filesystem_lock *lock);
orbit_filesystem_code orbit_package_filesystem_lock_release(
    orbit_package_filesystem_lock *lock);

/* Prepare is read-only. The caller must persist the returned change record in
 * its authenticated, monotonic transaction journal before calling apply(). */
orbit_filesystem_code orbit_package_filesystem_validate_change(
    const orbit_package_file_change *change);

orbit_filesystem_code orbit_package_filesystem_prepare_replace(
    int target_parent_fd, const char *target_name,
    int staged_parent_fd, const char *staged_name,
    int backup_parent_fd, const char *backup_name,
    orbit_package_file_change *change);

orbit_filesystem_code orbit_package_filesystem_prepare_remove(
    int target_parent_fd, const char *target_name,
    int backup_parent_fd, const char *backup_name,
    orbit_package_file_change *change);

/* Optional journal locators are relative to the caller's trusted install and
 * staging roots. Empty strings identify the root directory itself. */
orbit_filesystem_code orbit_package_filesystem_set_parent_paths(
    orbit_package_file_change *change,
    const char *target_parent_relative_path,
    const char *staged_parent_relative_path);

/* Opens a relative parent path without following symlinks. Caller owns the
 * returned descriptor and must close it. */
orbit_filesystem_code orbit_package_filesystem_open_parent_directory(
    int trusted_root_fd, const char *relative_path, int *directory_fd);

/* Apply, rollback, and finalize are identity-checked and safe to retry.
 * All parent descriptors must be trusted directory handles on the same volume.
 * The caller must hold the package filesystem transaction lock throughout. */
orbit_filesystem_code orbit_package_filesystem_apply(
    int target_parent_fd, int staged_parent_fd, int backup_parent_fd,
    const orbit_package_file_change *change);

orbit_filesystem_code orbit_package_filesystem_rollback(
    int target_parent_fd, int staged_parent_fd, int backup_parent_fd,
    const orbit_package_file_change *change);

orbit_filesystem_code orbit_package_filesystem_finalize(
    int target_parent_fd, int staged_parent_fd, int backup_parent_fd,
    const orbit_package_file_change *change);

#endif
