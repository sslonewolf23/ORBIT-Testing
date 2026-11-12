#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageNativeLock.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool valid_leaf(const char *name) {
    return name && name[0] != '\0' && strcmp(name, ".") != 0 &&
           strcmp(name, "..") != 0 && strchr(name, '/') == NULL;
}

orbit_native_lock_code orbit_package_native_lock_acquire_at(
    int parent_fd, const char *lock_name, uid_t expected_owner,
    orbit_package_native_lock *lock) {
    if (parent_fd < 0 || !valid_leaf(lock_name) || !lock)
        return ORBIT_NATIVE_LOCK_INVALID_ARGUMENT;
    if (lock->descriptor >= 0) return ORBIT_NATIVE_LOCK_BUSY;

    struct stat parent_status;
    if (fstat(parent_fd, &parent_status) < 0)
        return ORBIT_NATIVE_LOCK_IO_ERROR;
    if (!S_ISDIR(parent_status.st_mode))
        return ORBIT_NATIVE_LOCK_INVALID_ARGUMENT;

    int fd = openat(parent_fd, lock_name, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return ORBIT_NATIVE_LOCK_IO_ERROR;

    struct stat opened, named;
    if (fstat(fd, &opened) < 0 ||
        fstatat(parent_fd, lock_name, &named, AT_SYMLINK_NOFOLLOW) < 0) {
        close(fd);
        return ORBIT_NATIVE_LOCK_IO_ERROR;
    }
    if (!S_ISREG(opened.st_mode) || !S_ISREG(named.st_mode) ||
        opened.st_dev != named.st_dev || opened.st_ino != named.st_ino ||
        opened.st_dev != parent_status.st_dev ||
        opened.st_uid != expected_owner || opened.st_nlink != 1 ||
        (opened.st_mode & 0022) != 0) {
        close(fd);
        return ORBIT_NATIVE_LOCK_CONFLICT;
    }

    struct flock request;
    memset(&request, 0, sizeof(request));
    request.l_type = F_WRLCK;
    request.l_whence = SEEK_SET;
    request.l_start = 0;
    request.l_len = 0;
    if (fcntl(fd, F_SETLK, &request) < 0) {
        int saved = errno;
        close(fd);
        return (saved == EACCES || saved == EAGAIN) ?
            ORBIT_NATIVE_LOCK_BUSY : ORBIT_NATIVE_LOCK_IO_ERROR;
    }

    struct stat locked, current;
    if (fstat(fd, &locked) < 0 ||
        fstatat(parent_fd, lock_name, &current, AT_SYMLINK_NOFOLLOW) < 0 ||
        locked.st_dev != current.st_dev || locked.st_ino != current.st_ino) {
        request.l_type = F_UNLCK;
        (void)fcntl(fd, F_SETLK, &request);
        close(fd);
        return ORBIT_NATIVE_LOCK_CONFLICT;
    }
    lock->descriptor = fd;
    lock->device = locked.st_dev;
    lock->inode = locked.st_ino;
    return ORBIT_NATIVE_LOCK_OK;
}

orbit_native_lock_code orbit_package_native_lock_release_at(
    int parent_fd, const char *lock_name,
    orbit_package_native_lock *lock) {
    if (parent_fd < 0 || !valid_leaf(lock_name) || !lock ||
        lock->descriptor < 0)
        return ORBIT_NATIVE_LOCK_INVALID_ARGUMENT;

    struct stat opened, named;
    bool same = fstat(lock->descriptor, &opened) == 0 &&
        fstatat(parent_fd, lock_name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        opened.st_dev == lock->device && opened.st_ino == lock->inode &&
        named.st_dev == lock->device && named.st_ino == lock->inode;

    struct flock request;
    memset(&request, 0, sizeof(request));
    request.l_type = F_UNLCK;
    request.l_whence = SEEK_SET;
    request.l_start = 0;
    request.l_len = 0;
    bool unlocked = fcntl(lock->descriptor, F_SETLK, &request) == 0;
    bool closed = close(lock->descriptor) == 0;
    lock->descriptor = -1;
    lock->device = 0;
    lock->inode = 0;
    if (!same) return ORBIT_NATIVE_LOCK_CONFLICT;
    return unlocked && closed ? ORBIT_NATIVE_LOCK_OK :
           ORBIT_NATIVE_LOCK_IO_ERROR;
}
