#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageBootstrapLockset.h"

#include "ORBITPackageFilesystem.h"

#include <stddef.h>
#include <unistd.h>

static void initialize_locks(orbit_bootstrap_lockset *lockset) {
    for (size_t i = 0; i < ORBIT_BOOTSTRAP_LOCKSET_CAPACITY; ++i) {
        lockset->locks[i].descriptor = -1;
        lockset->locks[i].device = 0;
        lockset->locks[i].inode = 0;
    }
}

orbit_native_lock_code orbit_bootstrap_lockset_acquire(
    int root_fd, const orbit_bootstrap_profile *profile, uid_t expected_owner,
    orbit_bootstrap_lockset *lockset) {
    if (root_fd < 0 || !profile || !lockset ||
        !profile->dpkg_admin_directory_relative ||
        !profile->frontend_lock_leaf || !profile->dpkg_lock_leaf)
        return ORBIT_NATIVE_LOCK_INVALID_ARGUMENT;
    if (lockset->directory_descriptor >= 0 || lockset->count != 0)
        return ORBIT_NATIVE_LOCK_BUSY;

    initialize_locks(lockset);
    int directory_fd = -1;
    if (orbit_package_filesystem_open_parent_directory(
            root_fd, profile->dpkg_admin_directory_relative,
            &directory_fd) != ORBIT_FILESYSTEM_OK)
        return ORBIT_NATIVE_LOCK_IO_ERROR;

    lockset->directory_descriptor = directory_fd;
    orbit_native_lock_code result = orbit_package_native_lock_acquire_at(
        directory_fd, profile->frontend_lock_leaf, expected_owner,
        &lockset->locks[0]);
    if (result != ORBIT_NATIVE_LOCK_OK) goto fail;
    lockset->count = 1;

    result = orbit_package_native_lock_acquire_at(
        directory_fd, profile->dpkg_lock_leaf, expected_owner,
        &lockset->locks[1]);
    if (result != ORBIT_NATIVE_LOCK_OK) goto fail;
    lockset->count = 2;
    return ORBIT_NATIVE_LOCK_OK;

fail:
    while (lockset->count > 0) {
        --lockset->count;
        (void)orbit_package_native_lock_release_at(
            directory_fd,
            lockset->count == 0 ? profile->frontend_lock_leaf :
                                  profile->dpkg_lock_leaf,
            &lockset->locks[lockset->count]);
    }
    (void)close(directory_fd);
    lockset->directory_descriptor = -1;
    initialize_locks(lockset);
    return result;
}

orbit_native_lock_code orbit_bootstrap_lockset_release(
    orbit_bootstrap_lockset *lockset) {
    if (!lockset || lockset->directory_descriptor < 0 ||
        lockset->count == 0 || lockset->count > ORBIT_BOOTSTRAP_LOCKSET_CAPACITY)
        return ORBIT_NATIVE_LOCK_INVALID_ARGUMENT;

    orbit_native_lock_code result = ORBIT_NATIVE_LOCK_OK;
    while (lockset->count > 0) {
        --lockset->count;
        const char *leaf = lockset->count == 0 ? "lock-frontend" : "lock";
        orbit_native_lock_code released =
            orbit_package_native_lock_release_at(
                lockset->directory_descriptor, leaf,
                &lockset->locks[lockset->count]);
        if (released != ORBIT_NATIVE_LOCK_OK)
            result = ORBIT_NATIVE_LOCK_CONFLICT;
    }
    if (close(lockset->directory_descriptor) != 0)
        result = ORBIT_NATIVE_LOCK_IO_ERROR;
    lockset->directory_descriptor = -1;
    initialize_locks(lockset);
    return result;
}
