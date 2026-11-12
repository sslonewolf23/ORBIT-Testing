#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageBootstrapLockset.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void initialize_locks(orbit_bootstrap_lockset *lockset) {
    for (size_t i = 0; i < ORBIT_BOOTSTRAP_LOCKSET_CAPACITY; ++i) {
        lockset->locks[i].descriptor = -1;
        lockset->locks[i].device = 0;
        lockset->locks[i].inode = 0;
    }
}

static int open_admin_directory(int root_fd, const char *relative_path) {
    if (!relative_path || !relative_path[0] || relative_path[0] == '/')
        return -1;
    char path[1025];
    size_t length = strlen(relative_path);
    if (length >= sizeof(path)) return -1;
    memcpy(path, relative_path, length + 1);

    int current = openat(root_fd, ".",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0) return -1;
    char *component = path;
    for (char *cursor = path; ; ++cursor) {
        if (*cursor != '/' && *cursor != '\0') continue;
        char separator = *cursor;
        *cursor = '\0';
        if (!component[0] || strcmp(component, ".") == 0 ||
            strcmp(component, "..") == 0) {
            close(current);
            return -1;
        }
        int next = openat(current, component,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        close(current);
        if (next < 0) return -1;
        current = next;
        if (separator == '\0') break;
        component = cursor + 1;
    }
    return current;
}

orbit_native_lock_code orbit_bootstrap_lockset_acquire(
    int root_fd, const orbit_bootstrap_profile *profile,
    const char *observed_admin_relative, uid_t expected_owner,
    orbit_bootstrap_lockset *lockset) {
    if (root_fd < 0 || !profile || !lockset ||
        !orbit_bootstrap_profile_matches_admin_directory(
            profile, observed_admin_relative) ||
        !profile->dpkg_admin_directory_relative ||
        !profile->frontend_lock_leaf || !profile->dpkg_lock_leaf)
        return ORBIT_NATIVE_LOCK_INVALID_ARGUMENT;
    if (lockset->directory_descriptor >= 0 || lockset->count != 0)
        return ORBIT_NATIVE_LOCK_BUSY;

    initialize_locks(lockset);
    int directory_fd = open_admin_directory(
        root_fd, profile->dpkg_admin_directory_relative);
    if (directory_fd < 0) return ORBIT_NATIVE_LOCK_IO_ERROR;

    lockset->directory_descriptor = directory_fd;
    lockset->profile = profile;
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
        const char *leaf = lockset->count == 0 ?
            profile->frontend_lock_leaf : profile->dpkg_lock_leaf;
        (void)orbit_package_native_lock_release_at(
            directory_fd, leaf, &lockset->locks[lockset->count]);
    }
    (void)close(directory_fd);
    lockset->directory_descriptor = -1;
    lockset->profile = NULL;
    initialize_locks(lockset);
    return result;
}

orbit_native_lock_code orbit_bootstrap_lockset_release(
    orbit_bootstrap_lockset *lockset) {
    if (!lockset || lockset->directory_descriptor < 0 ||
        !lockset->profile || lockset->count == 0 ||
        lockset->count > ORBIT_BOOTSTRAP_LOCKSET_CAPACITY)
        return ORBIT_NATIVE_LOCK_INVALID_ARGUMENT;

    orbit_native_lock_code result = ORBIT_NATIVE_LOCK_OK;
    while (lockset->count > 0) {
        --lockset->count;
        const char *leaf = lockset->count == 0 ?
            lockset->profile->frontend_lock_leaf :
            lockset->profile->dpkg_lock_leaf;
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
    lockset->profile = NULL;
    initialize_locks(lockset);
    return result;
}
