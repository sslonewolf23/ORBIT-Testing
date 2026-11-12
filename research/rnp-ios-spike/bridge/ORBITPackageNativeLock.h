#ifndef ORBIT_PACKAGE_NATIVE_LOCK_H
#define ORBIT_PACKAGE_NATIVE_LOCK_H

#include <sys/types.h>
#include <stdint.h>

typedef enum {
    ORBIT_NATIVE_LOCK_OK = 0,
    ORBIT_NATIVE_LOCK_INVALID_ARGUMENT,
    ORBIT_NATIVE_LOCK_BUSY,
    ORBIT_NATIVE_LOCK_CONFLICT,
    ORBIT_NATIVE_LOCK_IO_ERROR
} orbit_native_lock_code;

typedef struct {
    int descriptor;
    dev_t device;
    ino_t inode;
} orbit_package_native_lock;

/* The caller initializes descriptor to -1. parent_fd must be an already-open,
 * trusted directory. The lock file must already exist, be regular, single-link,
 * owned by expected_owner, and not group/world writable. Uses POSIX fcntl
 * record locks, matching dpkg/APT-style cooperating lock users (unlike flock).
 * Acquire all target-native locks in the target package manager's documented
 * order, and hold them alongside ORBIT's own lock through recovery/cleanup.
 *
 * POSIX record locks are process-associated: closing ANY descriptor for this
 * inode in this process can release the lock. Do not independently open/close
 * the same lock inode while held. The ORBIT process-wide lock must serialize
 * same-process callers. Locks are advisory and cannot stop non-cooperating
 * privileged writers. */
orbit_native_lock_code orbit_package_native_lock_acquire_at(
    int parent_fd, const char *lock_name, uid_t expected_owner,
    orbit_package_native_lock *lock);

orbit_native_lock_code orbit_package_native_lock_release_at(
    int parent_fd, const char *lock_name,
    orbit_package_native_lock *lock);

#endif
