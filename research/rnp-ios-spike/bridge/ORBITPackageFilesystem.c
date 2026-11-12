#define _POSIX_C_SOURCE 200809L

#include "ORBITPackageFilesystem.h"
#include "ORBITPackageArchive.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>

typedef enum {
    FILE_ID_ERROR = -1,
    FILE_ID_MISSING = 0,
    FILE_ID_MATCH = 1,
    FILE_ID_OTHER = 2
} file_identity_result;

static bool valid_component(const char *name, size_t capacity) {
    if (!name) return false;
    size_t length = strlen(name);
    return length != 0U && length < capacity &&
           strchr(name, '/') == NULL && orbit_package_archive_path_is_safe(name);
}

static bool valid_stored_component(const char *name, size_t capacity) {
    if (!name) return false;
    const char *terminator = (const char *)memchr(name, '\0', capacity);
    if (!terminator || terminator == name) return false;
    size_t length = (size_t)(terminator - name);
    for (size_t i = length + 1U; i < capacity; ++i)
        if (name[i] != '\0') return false;
    return memchr(name, '/', length) == NULL &&
           orbit_package_archive_path_is_safe(name);
}

static bool stored_string_is_empty(const char *value, size_t capacity) {
    if (!value || value[0] != '\0') return false;
    for (size_t i = 1U; i < capacity; ++i)
        if (value[i] != '\0') return false;
    return true;
}

static bool valid_parent_path(const char *path, size_t capacity) {
    if (!path) return false;
    size_t length = strlen(path);
    return length < capacity &&
           (length == 0U || orbit_package_archive_path_is_safe(path));
}

static bool valid_stored_parent_path(const char *path, size_t capacity) {
    if (!path) return false;
    const char *terminator = (const char *)memchr(path, '\0', capacity);
    if (!terminator) return false;
    size_t length = (size_t)(terminator - path);
    for (size_t i = length + 1U; i < capacity; ++i)
        if (path[i] != '\0') return false;
    return length == 0U || orbit_package_archive_path_is_safe(path);
}

static bool same_volume_directories(int first_fd, int second_fd) {
    struct stat first, second;
    return first_fd >= 0 && second_fd >= 0 &&
           fstat(first_fd, &first) == 0 && fstat(second_fd, &second) == 0 &&
           S_ISDIR(first.st_mode) && S_ISDIR(second.st_mode) &&
           first.st_dev == second.st_dev;
}

static bool same_directory_object(int first_fd, int second_fd) {
    struct stat first, second;
    return first_fd >= 0 && second_fd >= 0 &&
           fstat(first_fd, &first) == 0 && fstat(second_fd, &second) == 0 &&
           S_ISDIR(first.st_mode) && S_ISDIR(second.st_mode) &&
           first.st_dev == second.st_dev && first.st_ino == second.st_ino;
}

static bool aliased_component_names(
    int target_fd, const char *target_name,
    int staged_fd, const char *staged_name,
    int backup_fd, const char *backup_name,
    bool has_staged) {
    if (same_directory_object(target_fd, backup_fd) &&
        strcmp(target_name, backup_name) == 0) return true;
    if (!has_staged) return false;
    if (same_directory_object(target_fd, staged_fd) &&
        strcmp(target_name, staged_name) == 0) return true;
    return same_directory_object(staged_fd, backup_fd) &&
           strcmp(staged_name, backup_name) == 0;
}

static bool all_parent_directories_same_volume(
    int target_fd, int staged_fd, int backup_fd, bool needs_staged) {
    if (!same_volume_directories(target_fd, backup_fd)) return false;
    return !needs_staged || same_volume_directories(target_fd, staged_fd);
}

static file_identity_result file_identity_at(
    int directory_fd, const char *name, uint64_t device, uint64_t inode,
    uint64_t *actual_device, uint64_t *actual_inode, nlink_t *links) {
    struct stat status;
    if (fstatat(directory_fd, name, &status, AT_SYMLINK_NOFOLLOW) < 0)
        return errno == ENOENT ? FILE_ID_MISSING : FILE_ID_ERROR;
    if (!S_ISREG(status.st_mode)) return FILE_ID_OTHER;
    if (actual_device) *actual_device = (uint64_t)status.st_dev;
    if (actual_inode) *actual_inode = (uint64_t)status.st_ino;
    if (links) *links = status.st_nlink;
    return (uint64_t)status.st_dev == device &&
           (uint64_t)status.st_ino == inode ? FILE_ID_MATCH : FILE_ID_OTHER;
}

static file_identity_result read_regular_file(
    int directory_fd, const char *name, uint64_t *device,
    uint64_t *inode, nlink_t *links) {
    struct stat status;
    if (fstatat(directory_fd, name, &status, AT_SYMLINK_NOFOLLOW) < 0)
        return errno == ENOENT ? FILE_ID_MISSING : FILE_ID_ERROR;
    if (!S_ISREG(status.st_mode)) return FILE_ID_OTHER;
    if (device) *device = (uint64_t)status.st_dev;
    if (inode) *inode = (uint64_t)status.st_ino;
    if (links) *links = status.st_nlink;
    return FILE_ID_MATCH;
}

static bool backup_is_missing(int backup_parent_fd, const char *backup_name) {
    struct stat status;
    if (fstatat(backup_parent_fd, backup_name, &status,
                AT_SYMLINK_NOFOLLOW) == 0) return false;
    return errno == ENOENT;
}

static orbit_filesystem_code verify_change(
    const orbit_package_file_change *change) {
    if (!change || change->version != ORBIT_FILESYSTEM_CHANGE_VERSION ||
        !valid_stored_component(change->target_name, sizeof(change->target_name)) ||
        !valid_stored_component(change->backup_name, sizeof(change->backup_name)) ||
        !valid_stored_parent_path(change->target_parent_path,
                                  sizeof(change->target_parent_path)))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    if (change->operation == ORBIT_FILESYSTEM_REPLACE) {
        if (!valid_stored_component(change->staged_name, sizeof(change->staged_name)) ||
            !valid_stored_parent_path(change->staged_parent_path,
                                      sizeof(change->staged_parent_path)) ||
            change->staged_inode == 0U)
            return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    } else if (change->operation == ORBIT_FILESYSTEM_REMOVE) {
        if (!stored_string_is_empty(change->staged_name,
                                    sizeof(change->staged_name)) ||
            !valid_stored_parent_path(change->staged_parent_path,
                                      sizeof(change->staged_parent_path)) ||
            change->staged_parent_path[0] != '\0' ||
            !change->preimage_exists || change->preimage_inode == 0U)
            return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    } else {
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    }
    if (change->preimage_exists && change->preimage_inode == 0U)
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    return ORBIT_FILESYSTEM_OK;
}

static orbit_filesystem_code ensure_backup_link(
    int target_parent_fd, int backup_parent_fd,
    const orbit_package_file_change *change) {
    file_identity_result backup = file_identity_at(
        backup_parent_fd, change->backup_name,
        change->preimage_device, change->preimage_inode, NULL, NULL, NULL);
    if (backup == FILE_ID_MATCH) {
        nlink_t existing_links = 0;
        (void)file_identity_at(backup_parent_fd, change->backup_name,
            change->preimage_device, change->preimage_inode,
            NULL, NULL, &existing_links);
        return existing_links == 2 ? ORBIT_FILESYSTEM_OK :
               ORBIT_FILESYSTEM_CONFLICT;
    }
    if (backup != FILE_ID_MISSING)
        return backup == FILE_ID_ERROR ? ORBIT_FILESYSTEM_IO_ERROR :
               ORBIT_FILESYSTEM_RECOVERY_REQUIRED;

    nlink_t target_links = 0;
    file_identity_result target = file_identity_at(
        target_parent_fd, change->target_name,
        change->preimage_device, change->preimage_inode,
        NULL, NULL, &target_links);
    if (target != FILE_ID_MATCH)
        return target == FILE_ID_ERROR ? ORBIT_FILESYSTEM_IO_ERROR :
               ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    if (target_links != 1) return ORBIT_FILESYSTEM_CONFLICT;

    bool created_backup_link =
        linkat(target_parent_fd, change->target_name,
               backup_parent_fd, change->backup_name, 0) == 0;
    if (!created_backup_link && errno != EEXIST)
        return ORBIT_FILESYSTEM_IO_ERROR;
    nlink_t backup_links = 0;
    backup = file_identity_at(
        backup_parent_fd, change->backup_name,
        change->preimage_device, change->preimage_inode,
        NULL, NULL, &backup_links);
    if (backup != FILE_ID_MATCH) {
        if (created_backup_link) {
            (void)unlinkat(backup_parent_fd, change->backup_name, 0);
            (void)fsync(backup_parent_fd);
        }
        return backup == FILE_ID_ERROR ? ORBIT_FILESYSTEM_IO_ERROR :
               ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }
    if (backup_links != 2) {
        if (created_backup_link) {
            (void)unlinkat(backup_parent_fd, change->backup_name, 0);
            (void)fsync(backup_parent_fd);
        }
        return ORBIT_FILESYSTEM_CONFLICT;
    }
    if (fsync(backup_parent_fd) < 0) return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    return ORBIT_FILESYSTEM_OK;
}

static orbit_filesystem_code remove_if_identity(
    int directory_fd, const char *name, uint64_t device, uint64_t inode) {
    nlink_t links = 0;
    file_identity_result identity = file_identity_at(
        directory_fd, name, device, inode, NULL, NULL, &links);
    if (identity == FILE_ID_MISSING) return ORBIT_FILESYSTEM_OK;
    if (identity == FILE_ID_ERROR) return ORBIT_FILESYSTEM_IO_ERROR;
    if (identity != FILE_ID_MATCH) return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    if (links != 1) return ORBIT_FILESYSTEM_CONFLICT;
    if (unlinkat(directory_fd, name, 0) < 0)
        return ORBIT_FILESYSTEM_IO_ERROR;
    return fsync(directory_fd) == 0 ? ORBIT_FILESYSTEM_OK :
           ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
}

static orbit_filesystem_code unlink_backup_while_preimage_remains(
    int backup_parent_fd, const orbit_package_file_change *change) {
    nlink_t links = 0;
    file_identity_result backup = file_identity_at(
        backup_parent_fd, change->backup_name,
        change->preimage_device, change->preimage_inode,
        NULL, NULL, &links);
    if (backup == FILE_ID_ERROR) return ORBIT_FILESYSTEM_IO_ERROR;
    if (backup != FILE_ID_MATCH) return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    if (links != 2) return ORBIT_FILESYSTEM_CONFLICT;
    if (unlinkat(backup_parent_fd, change->backup_name, 0) < 0)
        return ORBIT_FILESYSTEM_IO_ERROR;
    return fsync(backup_parent_fd) == 0 ? ORBIT_FILESYSTEM_OK :
           ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
}

static orbit_filesystem_code restore_backup(
    int target_parent_fd, int backup_parent_fd,
    const orbit_package_file_change *change) {
    nlink_t backup_links = 0;
    file_identity_result backup = file_identity_at(
        backup_parent_fd, change->backup_name,
        change->preimage_device, change->preimage_inode,
        NULL, NULL, &backup_links);
    if (backup != FILE_ID_MATCH)
        return backup == FILE_ID_ERROR ? ORBIT_FILESYSTEM_IO_ERROR :
               ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    if (backup_links != 1) return ORBIT_FILESYSTEM_CONFLICT;
    struct stat target_status;
    if (fstatat(target_parent_fd, change->target_name,
                &target_status, AT_SYMLINK_NOFOLLOW) == 0)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    if (errno != ENOENT) return ORBIT_FILESYSTEM_IO_ERROR;
    if (renameat(backup_parent_fd, change->backup_name,
                 target_parent_fd, change->target_name) < 0)
        return ORBIT_FILESYSTEM_IO_ERROR;
    if (fsync(target_parent_fd) < 0 || fsync(backup_parent_fd) < 0)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    return ORBIT_FILESYSTEM_OK;
}

orbit_filesystem_code orbit_package_filesystem_lock_acquire(
    int trusted_root_fd, orbit_package_filesystem_lock *lock) {
    if (trusted_root_fd < 0 || !lock)
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    lock->descriptor = -1;
    struct stat root_status;
    if (fstat(trusted_root_fd, &root_status) < 0)
        return ORBIT_FILESYSTEM_IO_ERROR;
    if (!S_ISDIR(root_status.st_mode))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    int fd = openat(trusted_root_fd, ORBIT_FILESYSTEM_LOCK_NAME,
        O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return ORBIT_FILESYSTEM_IO_ERROR;
    struct stat lock_status, named_status;
    if (fstat(fd, &lock_status) < 0 ||
        fstatat(trusted_root_fd, ORBIT_FILESYSTEM_LOCK_NAME,
                &named_status, AT_SYMLINK_NOFOLLOW) < 0) {
        close(fd);
        return ORBIT_FILESYSTEM_IO_ERROR;
    }
    if (!S_ISREG(lock_status.st_mode) || !S_ISREG(named_status.st_mode) ||
        lock_status.st_dev != named_status.st_dev ||
        lock_status.st_ino != named_status.st_ino ||
        lock_status.st_dev != root_status.st_dev ||
        lock_status.st_uid != geteuid() ||
        (lock_status.st_mode & 0077) != 0 ||
        lock_status.st_nlink != 1) {
        close(fd);
        return ORBIT_FILESYSTEM_CONFLICT;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        int saved_errno = errno;
        close(fd);
        return (saved_errno == EWOULDBLOCK || saved_errno == EAGAIN) ?
            ORBIT_FILESYSTEM_BUSY : ORBIT_FILESYSTEM_IO_ERROR;
    }
    struct stat locked_status, current_name_status;
    if (fstat(fd, &locked_status) < 0 ||
        fstatat(trusted_root_fd, ORBIT_FILESYSTEM_LOCK_NAME,
                &current_name_status, AT_SYMLINK_NOFOLLOW) < 0 ||
        locked_status.st_dev != current_name_status.st_dev ||
        locked_status.st_ino != current_name_status.st_ino) {
        (void)flock(fd, LOCK_UN);
        close(fd);
        return ORBIT_FILESYSTEM_CONFLICT;
    }
    lock->descriptor = fd;
    return ORBIT_FILESYSTEM_OK;
}

orbit_filesystem_code orbit_package_filesystem_lock_release(
    orbit_package_filesystem_lock *lock) {
    if (!lock || lock->descriptor < 0)
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    int fd = lock->descriptor;
    lock->descriptor = -1;
    bool unlocked = flock(fd, LOCK_UN) == 0;
    bool closed = close(fd) == 0;
    return unlocked && closed ? ORBIT_FILESYSTEM_OK :
           ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
}

orbit_filesystem_code orbit_package_filesystem_validate_change(
    const orbit_package_file_change *change) {
    return verify_change(change);
}

orbit_filesystem_code orbit_package_filesystem_set_parent_paths(
    orbit_package_file_change *change,
    const char *target_parent_relative_path,
    const char *staged_parent_relative_path) {
    orbit_filesystem_code valid = verify_change(change);
    if (valid != ORBIT_FILESYSTEM_OK) return valid;
    if (!valid_parent_path(target_parent_relative_path,
                           ORBIT_FILESYSTEM_PARENT_PATH_CAPACITY))
        return ORBIT_FILESYSTEM_UNSAFE_PATH;
    if (change->operation == ORBIT_FILESYSTEM_REPLACE) {
        if (!valid_parent_path(staged_parent_relative_path,
                               ORBIT_FILESYSTEM_PARENT_PATH_CAPACITY))
            return ORBIT_FILESYSTEM_UNSAFE_PATH;
    } else if (!staged_parent_relative_path ||
               staged_parent_relative_path[0] != '\0') {
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    }
    memset(change->target_parent_path, 0, sizeof(change->target_parent_path));
    memset(change->staged_parent_path, 0, sizeof(change->staged_parent_path));
    memcpy(change->target_parent_path, target_parent_relative_path,
           strlen(target_parent_relative_path) + 1U);
    if (change->operation == ORBIT_FILESYSTEM_REPLACE) {
        memcpy(change->staged_parent_path, staged_parent_relative_path,
               strlen(staged_parent_relative_path) + 1U);
    }
    return ORBIT_FILESYSTEM_OK;
}

orbit_filesystem_code orbit_package_filesystem_open_parent_directory(
    int trusted_root_fd, const char *relative_path, int *directory_fd) {
    if (trusted_root_fd < 0 || !directory_fd ||
        !valid_parent_path(relative_path, ORBIT_FILESYSTEM_PARENT_PATH_CAPACITY))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    *directory_fd = -1;
    struct stat root_status;
    if (fstat(trusted_root_fd, &root_status) < 0)
        return ORBIT_FILESYSTEM_IO_ERROR;
    if (!S_ISDIR(root_status.st_mode))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    int current_fd = fcntl(trusted_root_fd, F_DUPFD_CLOEXEC, 0);
    if (current_fd < 0) return ORBIT_FILESYSTEM_IO_ERROR;
    if (relative_path[0] == '\0') {
        *directory_fd = current_fd;
        return ORBIT_FILESYSTEM_OK;
    }

    char path_copy[ORBIT_FILESYSTEM_PARENT_PATH_CAPACITY];
    memcpy(path_copy, relative_path, strlen(relative_path) + 1U);
    char *segment = path_copy;
    for (;;) {
        char *slash = strchr(segment, '/');
        bool final_segment = slash == NULL;
        if (slash) *slash = '\0';
        int next_fd = openat(current_fd, segment,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next_fd < 0) {
            close(current_fd);
            return ORBIT_FILESYSTEM_IO_ERROR;
        }
        struct stat status;
        if (fstat(next_fd, &status) < 0 || !S_ISDIR(status.st_mode)) {
            close(next_fd);
            close(current_fd);
            return ORBIT_FILESYSTEM_CONFLICT;
        }
        close(current_fd);
        current_fd = next_fd;
        if (final_segment) break;
        segment = slash + 1U;
    }
    *directory_fd = current_fd;
    return ORBIT_FILESYSTEM_OK;
}

orbit_filesystem_code orbit_package_filesystem_prepare_replace(
    int target_parent_fd, const char *target_name,
    int staged_parent_fd, const char *staged_name,
    int backup_parent_fd, const char *backup_name,
    orbit_package_file_change *change) {
    if (!change || !valid_component(target_name, ORBIT_FILESYSTEM_COMPONENT_CAPACITY) ||
        !valid_component(staged_name, ORBIT_FILESYSTEM_COMPONENT_CAPACITY) ||
        !valid_component(backup_name, ORBIT_FILESYSTEM_COMPONENT_CAPACITY) ||
        !all_parent_directories_same_volume(
            target_parent_fd, staged_parent_fd, backup_parent_fd, true) ||
        aliased_component_names(target_parent_fd, target_name,
            staged_parent_fd, staged_name, backup_parent_fd, backup_name, true))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    struct stat target_parent_status;
    if (fstat(target_parent_fd, &target_parent_status) < 0 ||
        !S_ISDIR(target_parent_status.st_mode))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    uint64_t staged_device = 0U, staged_inode = 0U;
    nlink_t staged_links = 0;
    if (read_regular_file(staged_parent_fd, staged_name,
                          &staged_device, &staged_inode, &staged_links) != FILE_ID_MATCH ||
        staged_links != 1 || staged_device != (uint64_t)target_parent_status.st_dev)
        return ORBIT_FILESYSTEM_CONFLICT;
    if (!backup_is_missing(backup_parent_fd, backup_name))
        return ORBIT_FILESYSTEM_CONFLICT;

    uint64_t preimage_device = 0U, preimage_inode = 0U;
    nlink_t preimage_links = 0;
    file_identity_result target = read_regular_file(
        target_parent_fd, target_name,
        &preimage_device, &preimage_inode, &preimage_links);
    if (target == FILE_ID_ERROR) return ORBIT_FILESYSTEM_IO_ERROR;
    if (target == FILE_ID_OTHER || (target == FILE_ID_MATCH &&
        (preimage_links != 1 ||
         preimage_device != (uint64_t)target_parent_status.st_dev)))
        return ORBIT_FILESYSTEM_CONFLICT;

    memset(change, 0, sizeof(*change));
    change->version = ORBIT_FILESYSTEM_CHANGE_VERSION;
    change->operation = ORBIT_FILESYSTEM_REPLACE;
    memcpy(change->target_name, target_name, strlen(target_name) + 1U);
    memcpy(change->staged_name, staged_name, strlen(staged_name) + 1U);
    memcpy(change->backup_name, backup_name, strlen(backup_name) + 1U);
    change->preimage_exists = target == FILE_ID_MATCH;
    change->preimage_device = preimage_device;
    change->preimage_inode = preimage_inode;
    change->staged_device = staged_device;
    change->staged_inode = staged_inode;
    return ORBIT_FILESYSTEM_OK;
}

orbit_filesystem_code orbit_package_filesystem_prepare_remove(
    int target_parent_fd, const char *target_name,
    int backup_parent_fd, const char *backup_name,
    orbit_package_file_change *change) {
    if (!change || !valid_component(target_name, ORBIT_FILESYSTEM_COMPONENT_CAPACITY) ||
        !valid_component(backup_name, ORBIT_FILESYSTEM_COMPONENT_CAPACITY) ||
        !same_volume_directories(target_parent_fd, backup_parent_fd) ||
        aliased_component_names(target_parent_fd, target_name,
            -1, "", backup_parent_fd, backup_name, false))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    struct stat target_parent_status;
    if (fstat(target_parent_fd, &target_parent_status) < 0 ||
        !S_ISDIR(target_parent_status.st_mode))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;
    uint64_t preimage_device = 0U, preimage_inode = 0U;
    nlink_t preimage_links = 0;
    file_identity_result target = read_regular_file(
        target_parent_fd, target_name,
        &preimage_device, &preimage_inode, &preimage_links);
    if (target == FILE_ID_ERROR) return ORBIT_FILESYSTEM_IO_ERROR;
    if (target != FILE_ID_MATCH || preimage_links != 1 ||
        preimage_device != (uint64_t)target_parent_status.st_dev)
        return ORBIT_FILESYSTEM_CONFLICT;
    if (!backup_is_missing(backup_parent_fd, backup_name))
        return ORBIT_FILESYSTEM_CONFLICT;

    memset(change, 0, sizeof(*change));
    change->version = ORBIT_FILESYSTEM_CHANGE_VERSION;
    change->operation = ORBIT_FILESYSTEM_REMOVE;
    memcpy(change->target_name, target_name, strlen(target_name) + 1U);
    memcpy(change->backup_name, backup_name, strlen(backup_name) + 1U);
    change->preimage_exists = true;
    change->preimage_device = preimage_device;
    change->preimage_inode = preimage_inode;
    return ORBIT_FILESYSTEM_OK;
}

orbit_filesystem_code orbit_package_filesystem_apply(
    int target_parent_fd, int staged_parent_fd, int backup_parent_fd,
    const orbit_package_file_change *change) {
    orbit_filesystem_code valid = verify_change(change);
    if (valid != ORBIT_FILESYSTEM_OK) return valid;
    bool needs_staged = change->operation == ORBIT_FILESYSTEM_REPLACE;
    if (!all_parent_directories_same_volume(
            target_parent_fd, staged_parent_fd, backup_parent_fd, needs_staged) ||
        aliased_component_names(target_parent_fd, change->target_name,
            staged_parent_fd, change->staged_name, backup_parent_fd,
            change->backup_name, needs_staged))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    if (change->operation == ORBIT_FILESYSTEM_REMOVE) {
        file_identity_result target = file_identity_at(
            target_parent_fd, change->target_name,
            change->preimage_device, change->preimage_inode, NULL, NULL, NULL);
        nlink_t backup_links = 0;
        file_identity_result backup = file_identity_at(
            backup_parent_fd, change->backup_name,
            change->preimage_device, change->preimage_inode,
            NULL, NULL, &backup_links);
        if (target == FILE_ID_MISSING && backup == FILE_ID_MATCH)
            return backup_links == 1 ? ORBIT_FILESYSTEM_OK :
                   ORBIT_FILESYSTEM_CONFLICT;
        if (target == FILE_ID_MATCH) {
            orbit_filesystem_code linked = ensure_backup_link(
                target_parent_fd, backup_parent_fd, change);
            if (linked != ORBIT_FILESYSTEM_OK) return linked;
            target = file_identity_at(
                target_parent_fd, change->target_name,
                change->preimage_device, change->preimage_inode, NULL, NULL, NULL);
            backup = file_identity_at(
                backup_parent_fd, change->backup_name,
                change->preimage_device, change->preimage_inode, NULL, NULL, NULL);
        }
        if (target == FILE_ID_MATCH && backup == FILE_ID_MATCH) {
            if (unlinkat(target_parent_fd, change->target_name, 0) < 0)
                return ORBIT_FILESYSTEM_IO_ERROR;
            return fsync(target_parent_fd) == 0 ? ORBIT_FILESYSTEM_OK :
                   ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        }
        if (target == FILE_ID_ERROR || backup == FILE_ID_ERROR)
            return ORBIT_FILESYSTEM_IO_ERROR;
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    nlink_t target_new_links = 0, staged_links = 0, backup_links = 0;
    file_identity_result target_new = file_identity_at(
        target_parent_fd, change->target_name,
        change->staged_device, change->staged_inode,
        NULL, NULL, &target_new_links);
    file_identity_result staged = file_identity_at(
        staged_parent_fd, change->staged_name,
        change->staged_device, change->staged_inode,
        NULL, NULL, &staged_links);
    file_identity_result backup = change->preimage_exists ?
        file_identity_at(backup_parent_fd, change->backup_name,
            change->preimage_device, change->preimage_inode,
            NULL, NULL, &backup_links) :
        (backup_is_missing(backup_parent_fd, change->backup_name) ?
            FILE_ID_MISSING : FILE_ID_OTHER);

    if (target_new == FILE_ID_MATCH && staged == FILE_ID_MISSING &&
        ((!change->preimage_exists && backup == FILE_ID_MISSING) ||
         (change->preimage_exists && backup == FILE_ID_MATCH))) {
        if (target_new_links != 1 ||
            (change->preimage_exists && backup_links != 1))
            return ORBIT_FILESYSTEM_CONFLICT;
        return ORBIT_FILESYSTEM_OK;
    }

    if (target_new == FILE_ID_ERROR || staged == FILE_ID_ERROR ||
        backup == FILE_ID_ERROR) return ORBIT_FILESYSTEM_IO_ERROR;

    if (change->preimage_exists) {
        file_identity_result target_old = file_identity_at(
            target_parent_fd, change->target_name,
            change->preimage_device, change->preimage_inode, NULL, NULL, NULL);
        if (target_old == FILE_ID_ERROR) return ORBIT_FILESYSTEM_IO_ERROR;
        if (target_old != FILE_ID_MATCH &&
            !(target_old == FILE_ID_MISSING && backup == FILE_ID_MATCH))
            return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        if (target_old == FILE_ID_MATCH) {
            orbit_filesystem_code linked = ensure_backup_link(
                target_parent_fd, backup_parent_fd, change);
            if (linked != ORBIT_FILESYSTEM_OK) return linked;
        } else if (backup != FILE_ID_MATCH) {
            return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        }
    } else if (target_new != FILE_ID_MISSING || backup != FILE_ID_MISSING) {
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    if (staged != FILE_ID_MATCH)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    if (staged_links != 1) return ORBIT_FILESYSTEM_CONFLICT;

    if (change->preimage_exists) {
        file_identity_result target_before_rename = file_identity_at(
            target_parent_fd, change->target_name,
            change->preimage_device, change->preimage_inode,
            NULL, NULL, NULL);
        nlink_t backup_before_rename_links = 0;
        file_identity_result backup_before_rename = file_identity_at(
            backup_parent_fd, change->backup_name,
            change->preimage_device, change->preimage_inode,
            NULL, NULL, &backup_before_rename_links);
        if (target_before_rename == FILE_ID_ERROR ||
            backup_before_rename == FILE_ID_ERROR)
            return ORBIT_FILESYSTEM_IO_ERROR;
        if (backup_before_rename != FILE_ID_MATCH ||
            !((target_before_rename == FILE_ID_MATCH &&
               backup_before_rename_links == 2) ||
              (target_before_rename == FILE_ID_MISSING &&
               backup_before_rename_links == 1)))
            return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    } else {
        file_identity_result target_before_rename = file_identity_at(
            target_parent_fd, change->target_name,
            change->staged_device, change->staged_inode,
            NULL, NULL, NULL);
        if (target_before_rename != FILE_ID_MISSING)
            return target_before_rename == FILE_ID_ERROR ?
                ORBIT_FILESYSTEM_IO_ERROR : ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    if (renameat(staged_parent_fd, change->staged_name,
                 target_parent_fd, change->target_name) < 0)
        return ORBIT_FILESYSTEM_IO_ERROR;
    if (fsync(target_parent_fd) < 0 || fsync(staged_parent_fd) < 0)
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    return ORBIT_FILESYSTEM_OK;
}

orbit_filesystem_code orbit_package_filesystem_rollback(
    int target_parent_fd, int staged_parent_fd, int backup_parent_fd,
    const orbit_package_file_change *change) {
    orbit_filesystem_code valid = verify_change(change);
    if (valid != ORBIT_FILESYSTEM_OK) return valid;
    bool needs_staged = change->operation == ORBIT_FILESYSTEM_REPLACE;
    if (!all_parent_directories_same_volume(
            target_parent_fd, staged_parent_fd, backup_parent_fd, needs_staged) ||
        aliased_component_names(target_parent_fd, change->target_name,
            staged_parent_fd, change->staged_name, backup_parent_fd,
            change->backup_name, needs_staged))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    if (change->operation == ORBIT_FILESYSTEM_REMOVE) {
        nlink_t target_old_links = 0;
        file_identity_result target_old = file_identity_at(
            target_parent_fd, change->target_name,
            change->preimage_device, change->preimage_inode,
            NULL, NULL, &target_old_links);
        file_identity_result backup = file_identity_at(
            backup_parent_fd, change->backup_name,
            change->preimage_device, change->preimage_inode, NULL, NULL, NULL);
        if (target_old == FILE_ID_MATCH) {
            if (backup == FILE_ID_MATCH)
                return unlink_backup_while_preimage_remains(
                    backup_parent_fd, change);
            if (backup == FILE_ID_MISSING && target_old_links == 1)
                return ORBIT_FILESYSTEM_OK;
            return backup == FILE_ID_ERROR ? ORBIT_FILESYSTEM_IO_ERROR :
                   ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        }
        if (target_old == FILE_ID_MISSING && backup == FILE_ID_MATCH)
            return restore_backup(target_parent_fd, backup_parent_fd, change);
        if (target_old == FILE_ID_ERROR || backup == FILE_ID_ERROR)
            return ORBIT_FILESYSTEM_IO_ERROR;
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }

    file_identity_result target_new = file_identity_at(
        target_parent_fd, change->target_name,
        change->staged_device, change->staged_inode, NULL, NULL, NULL);
    if (target_new == FILE_ID_ERROR) return ORBIT_FILESYSTEM_IO_ERROR;
    if (!change->preimage_exists) {
        if (target_new == FILE_ID_MISSING) return ORBIT_FILESYSTEM_OK;
        if (target_new != FILE_ID_MATCH) return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
        return remove_if_identity(target_parent_fd, change->target_name,
                                  change->staged_device, change->staged_inode);
    }

    nlink_t target_old_links = 0;
    file_identity_result target_old = file_identity_at(
        target_parent_fd, change->target_name,
        change->preimage_device, change->preimage_inode,
        NULL, NULL, &target_old_links);
    file_identity_result backup = file_identity_at(
        backup_parent_fd, change->backup_name,
        change->preimage_device, change->preimage_inode, NULL, NULL, NULL);
    if (target_old == FILE_ID_ERROR || backup == FILE_ID_ERROR)
        return ORBIT_FILESYSTEM_IO_ERROR;

    if (target_new == FILE_ID_MATCH && backup == FILE_ID_MATCH) {
        orbit_filesystem_code removed = remove_if_identity(
            target_parent_fd, change->target_name,
            change->staged_device, change->staged_inode);
        if (removed != ORBIT_FILESYSTEM_OK) return removed;
        return restore_backup(target_parent_fd, backup_parent_fd, change);
    }
    if (target_old == FILE_ID_MATCH) {
        if (backup == FILE_ID_MATCH)
            return unlink_backup_while_preimage_remains(
                backup_parent_fd, change);
        if (backup == FILE_ID_MISSING && target_old_links == 1)
            return ORBIT_FILESYSTEM_OK;
        return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    }
    if (target_new == FILE_ID_MISSING && backup == FILE_ID_MATCH)
        return restore_backup(target_parent_fd, backup_parent_fd, change);
    return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
}

orbit_filesystem_code orbit_package_filesystem_finalize(
    int target_parent_fd, int staged_parent_fd, int backup_parent_fd,
    const orbit_package_file_change *change) {
    orbit_filesystem_code valid = verify_change(change);
    if (valid != ORBIT_FILESYSTEM_OK) return valid;
    bool needs_staged = change->operation == ORBIT_FILESYSTEM_REPLACE;
    if (!all_parent_directories_same_volume(
            target_parent_fd, staged_parent_fd, backup_parent_fd, needs_staged) ||
        aliased_component_names(target_parent_fd, change->target_name,
            staged_parent_fd, change->staged_name, backup_parent_fd,
            change->backup_name, needs_staged))
        return ORBIT_FILESYSTEM_INVALID_ARGUMENT;

    if (change->operation == ORBIT_FILESYSTEM_REMOVE) {
        file_identity_result target = file_identity_at(
            target_parent_fd, change->target_name,
            change->preimage_device, change->preimage_inode, NULL, NULL, NULL);
        file_identity_result backup = file_identity_at(
            backup_parent_fd, change->backup_name,
            change->preimage_device, change->preimage_inode, NULL, NULL, NULL);
        if (target == FILE_ID_MISSING && backup == FILE_ID_MISSING)
            return ORBIT_FILESYSTEM_OK;
        if (target == FILE_ID_MISSING && backup == FILE_ID_MATCH)
            return remove_if_identity(backup_parent_fd, change->backup_name,
                                      change->preimage_device, change->preimage_inode);
        if (target == FILE_ID_ERROR || backup == FILE_ID_ERROR)
            return ORBIT_FILESYSTEM_IO_ERROR;
        return ORBIT_FILESYSTEM_INVALID_STATE;
    }

    nlink_t target_new_links = 0;
    file_identity_result target_new = file_identity_at(
        target_parent_fd, change->target_name,
        change->staged_device, change->staged_inode,
        NULL, NULL, &target_new_links);
    file_identity_result staged = file_identity_at(
        staged_parent_fd, change->staged_name,
        change->staged_device, change->staged_inode, NULL, NULL, NULL);
    file_identity_result backup = change->preimage_exists ?
        file_identity_at(backup_parent_fd, change->backup_name,
            change->preimage_device, change->preimage_inode, NULL, NULL, NULL) :
        (backup_is_missing(backup_parent_fd, change->backup_name) ?
            FILE_ID_MISSING : FILE_ID_OTHER);
    if (target_new == FILE_ID_ERROR || staged == FILE_ID_ERROR ||
        backup == FILE_ID_ERROR) return ORBIT_FILESYSTEM_IO_ERROR;
    if (target_new != FILE_ID_MATCH || staged != FILE_ID_MISSING)
        return ORBIT_FILESYSTEM_INVALID_STATE;
    if (target_new_links != 1) return ORBIT_FILESYSTEM_CONFLICT;
    if (!change->preimage_exists)
        return backup == FILE_ID_MISSING ? ORBIT_FILESYSTEM_OK :
               ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    if (backup == FILE_ID_MISSING) return ORBIT_FILESYSTEM_OK;
    if (backup != FILE_ID_MATCH) return ORBIT_FILESYSTEM_RECOVERY_REQUIRED;
    return remove_if_identity(backup_parent_fd, change->backup_name,
                              change->preimage_device, change->preimage_inode);
}
