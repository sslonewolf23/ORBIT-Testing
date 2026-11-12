#define _POSIX_C_SOURCE 200809L

#include "ORBITPackageStaging.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int duplicate_cloexec(int fd) {
    return fcntl(fd, F_DUPFD_CLOEXEC, 0);
}

static void mark_failed(orbit_package_staging *staging) {
    if (staging) staging->failed = true;
}

static int open_directory_path(int root_fd, const char *path,
                               bool create, uint32_t final_mode) {
    if (root_fd < 0 || !path) { errno = EINVAL; return -1; }
    if (path[0] == '\0') return duplicate_cloexec(root_fd);

    size_t length = strlen(path);
    if (length == 0U || length > ORBIT_TAR_MAX_PATH ||
        !orbit_package_archive_path_is_safe(path)) {
        errno = EINVAL;
        return -1;
    }

    char mutable_path[ORBIT_TAR_MAX_PATH + 1U];
    memcpy(mutable_path, path, length + 1U);
    int current_fd = duplicate_cloexec(root_fd);
    if (current_fd < 0) return -1;

    char *segment = mutable_path;
    for (;;) {
        char *slash = strchr(segment, '/');
        bool final_segment = slash == NULL;
        if (slash) *slash = '\0';
        uint32_t requested_mode =
            final_segment && final_mode != UINT32_MAX ? final_mode : 0755U;

        int next_fd = openat(current_fd, segment,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next_fd < 0 && errno == ENOENT && create) {
            if (mkdirat(current_fd, segment, (mode_t)requested_mode) < 0 &&
                errno != EEXIST) {
                close(current_fd);
                return -1;
            }
            next_fd = openat(current_fd, segment,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (next_fd >= 0 && fchmod(next_fd, (mode_t)requested_mode) < 0) {
                close(next_fd);
                close(current_fd);
                return -1;
            }
            if (next_fd >= 0 && fsync(current_fd) < 0) {
                close(next_fd);
                close(current_fd);
                return -1;
            }
        } else if (next_fd >= 0 && final_segment &&
                   final_mode != UINT32_MAX) {
            if (fchmod(next_fd, (mode_t)final_mode) < 0) {
                close(next_fd);
                close(current_fd);
                return -1;
            }
        }
        if (next_fd < 0) {
            close(current_fd);
            return -1;
        }

        struct stat status;
        if (fstat(next_fd, &status) < 0 || !S_ISDIR(status.st_mode)) {
            close(next_fd);
            close(current_fd);
            errno = ENOTDIR;
            return -1;
        }
        close(current_fd);
        current_fd = next_fd;
        if (final_segment) break;
        segment = slash + 1;
    }
    return current_fd;
}

static int open_parent_directory(orbit_package_staging *staging,
                                 const char *path, char *leaf,
                                 size_t leaf_capacity) {
    size_t length = strlen(path);
    if (length == 0U || length > ORBIT_TAR_MAX_PATH) {
        errno = EINVAL;
        return -1;
    }
    char mutable_path[ORBIT_TAR_MAX_PATH + 1U];
    memcpy(mutable_path, path, length + 1U);
    char *slash = strrchr(mutable_path, '/');
    char *leaf_source = slash ? slash + 1U : mutable_path;
    size_t leaf_length = strlen(leaf_source);
    if (leaf_length == 0U || leaf_length >= leaf_capacity) {
        errno = EINVAL;
        return -1;
    }
    memcpy(leaf, leaf_source, leaf_length + 1U);
    if (!slash) return duplicate_cloexec(staging->staging_directory_fd);
    *slash = '\0';
    return open_directory_path(staging->staging_directory_fd,
                               mutable_path, true, UINT32_MAX);
}

static bool remove_directory_contents(int directory_fd) {
    int scan_fd = openat(directory_fd, ".",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (scan_fd < 0) return false;
    DIR *directory = fdopendir(scan_fd);
    if (!directory) {
        close(scan_fd);
        return false;
    }

    bool success = true;
    struct dirent *item;
    while ((item = readdir(directory)) != NULL) {
        if (strcmp(item->d_name, ".") == 0 ||
            strcmp(item->d_name, "..") == 0) continue;

        struct stat status;
        if (fstatat(directory_fd, item->d_name, &status,
                    AT_SYMLINK_NOFOLLOW) < 0) {
            success = false;
            break;
        }
        if (S_ISDIR(status.st_mode)) {
            int child_fd = openat(directory_fd, item->d_name,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child_fd < 0) {
                success = false;
                break;
            }
            bool child_success = remove_directory_contents(child_fd);
            close(child_fd);
            if (!child_success ||
                unlinkat(directory_fd, item->d_name, AT_REMOVEDIR) < 0) {
                success = false;
                break;
            }
        } else if (unlinkat(directory_fd, item->d_name, 0) < 0) {
            success = false;
            break;
        }
    }
    if (closedir(directory) < 0) success = false;
    return success;
}

orbit_staging_code orbit_package_staging_begin(
    int base_directory_fd, const char *staging_name,
    orbit_package_staging *staging) {
    if (!staging) return ORBIT_STAGING_INVALID_ARGUMENT;
    memset(staging, 0, sizeof(*staging));
    staging->base_directory_fd = -1;
    staging->staging_directory_fd = -1;
    staging->active_file_fd = -1;

    if (base_directory_fd < 0 || !staging_name)
        return ORBIT_STAGING_INVALID_ARGUMENT;
    size_t name_length = strlen(staging_name);
    if (name_length == 0U || name_length >= sizeof(staging->staging_name) ||
        strchr(staging_name, '/') || !orbit_package_archive_path_is_safe(staging_name))
        return ORBIT_STAGING_UNSAFE_PATH;

    struct stat base_status;
    if (fstat(base_directory_fd, &base_status) < 0 ||
        !S_ISDIR(base_status.st_mode))
        return ORBIT_STAGING_INVALID_ARGUMENT;

    int base_copy = duplicate_cloexec(base_directory_fd);
    if (base_copy < 0) return ORBIT_STAGING_IO_ERROR;
    if (mkdirat(base_copy, staging_name, 0700) < 0) {
        close(base_copy);
        return ORBIT_STAGING_IO_ERROR;
    }
    if (fsync(base_copy) < 0) {
        (void)unlinkat(base_copy, staging_name, AT_REMOVEDIR);
        close(base_copy);
        return ORBIT_STAGING_IO_ERROR;
    }
    int root_fd = openat(base_copy, staging_name,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0 || fchmod(root_fd, 0700) < 0 ||
        (root_fd >= 0 && fsync(root_fd) < 0)) {
        if (root_fd >= 0) close(root_fd);
        (void)unlinkat(base_copy, staging_name, AT_REMOVEDIR);
        close(base_copy);
        return ORBIT_STAGING_IO_ERROR;
    }
    staging->base_directory_fd = base_copy;
    staging->staging_directory_fd = root_fd;
    memcpy(staging->staging_name, staging_name, name_length + 1U);
    return ORBIT_STAGING_OK;
}

bool orbit_package_staging_entry_callback(
    void *context, const orbit_archive_entry *entry) {
    orbit_package_staging *staging = (orbit_package_staging *)context;
    if (!staging || !entry || staging->failed || staging->complete ||
        staging->staging_directory_fd < 0 || staging->active_file_fd >= 0) {
        mark_failed(staging);
        return false;
    }
    if (!memchr(entry->path, '\0', sizeof(entry->path)) ||
        !orbit_package_archive_path_is_safe(entry->path) ||
        entry->size > ORBIT_TAR_MAX_FILE_BYTES ||
        (entry->mode & ~0777U) != 0U ||
        (entry->directory && (entry->mode & 0700U) != 0700U) ||
        (entry->directory && (entry->mode & 0100U) == 0U)) {
        mark_failed(staging);
        return false;
    }

    if (entry->directory) {
        int directory_fd = open_directory_path(
            staging->staging_directory_fd, entry->path, true, entry->mode);
        if (directory_fd < 0 || fsync(directory_fd) < 0) {
            if (directory_fd >= 0) close(directory_fd);
            mark_failed(staging);
            return false;
        }
        close(directory_fd);
        return true;
    }

    char leaf[ORBIT_TAR_MAX_PATH + 1U];
    int parent_fd = open_parent_directory(staging, entry->path,
                                          leaf, sizeof(leaf));
    if (parent_fd < 0) {
        mark_failed(staging);
        return false;
    }
    int file_fd = openat(parent_fd, leaf,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (file_fd < 0) {
        close(parent_fd);
        mark_failed(staging);
        return false;
    }

    struct stat file_status;
    bool safe_file = fstat(file_fd, &file_status) == 0 &&
                     S_ISREG(file_status.st_mode) && file_status.st_nlink == 1;
    if (!safe_file || fchmod(file_fd, (mode_t)(entry->mode & 0777U)) < 0 ||
        fsync(parent_fd) < 0) {
        close(file_fd);
        (void)unlinkat(parent_fd, leaf, 0);
        close(parent_fd);
        mark_failed(staging);
        return false;
    }
    close(parent_fd);
    staging->active_file_fd = file_fd;
    staging->active_file_size = entry->size;
    staging->active_file_written = 0U;
    memcpy(staging->active_file_path, entry->path, strlen(entry->path) + 1U);
    return true;
}

bool orbit_package_staging_data_callback(
    void *context, const char *path, uint64_t offset,
    const uint8_t *bytes, size_t length, bool final_chunk) {
    orbit_package_staging *staging = (orbit_package_staging *)context;
    if (!staging || !path || staging->failed || staging->complete ||
        staging->active_file_fd < 0 ||
        strcmp(path, staging->active_file_path) != 0 ||
        offset != staging->active_file_written ||
        (length != 0U && !bytes) || (length == 0U && !final_chunk) ||
        staging->active_file_written > staging->active_file_size ||
        (uint64_t)length > staging->active_file_size - staging->active_file_written) {
        mark_failed(staging);
        return false;
    }

    size_t written = 0U;
    while (written < length) {
        ssize_t amount = write(staging->active_file_fd,
                               bytes + written, length - written);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) {
            mark_failed(staging);
            return false;
        }
        written += (size_t)amount;
    }
    staging->active_file_written += (uint64_t)length;
    bool file_complete = staging->active_file_written == staging->active_file_size;
    if (final_chunk != file_complete) {
        mark_failed(staging);
        return false;
    }
    if (final_chunk) {
        if (fsync(staging->active_file_fd) < 0) {
            mark_failed(staging);
            return false;
        }
        if (close(staging->active_file_fd) < 0) {
            staging->active_file_fd = -1;
            mark_failed(staging);
            return false;
        }
        staging->active_file_fd = -1;
    }
    return true;
}

orbit_staging_code orbit_package_staging_finish(
    orbit_package_staging *staging) {
    if (!staging || staging->staging_directory_fd < 0)
        return ORBIT_STAGING_INVALID_ARGUMENT;
    if (staging->failed || staging->complete || staging->active_file_fd >= 0)
        return ORBIT_STAGING_INVALID_STATE;
    if (fsync(staging->staging_directory_fd) < 0) {
        staging->failed = true;
        return ORBIT_STAGING_IO_ERROR;
    }
    staging->complete = true;
    return ORBIT_STAGING_OK;
}

orbit_staging_code orbit_package_staging_discard(
    orbit_package_staging *staging) {
    if (!staging || staging->base_directory_fd < 0 ||
        staging->staging_name[0] == '\0')
        return ORBIT_STAGING_INVALID_STATE;
    if (staging->active_file_fd >= 0) {
        if (close(staging->active_file_fd) < 0) return ORBIT_STAGING_IO_ERROR;
        staging->active_file_fd = -1;
    }

    if (staging->staging_directory_fd < 0) {
        staging->staging_directory_fd = openat(
            staging->base_directory_fd, staging->staging_name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (staging->staging_directory_fd < 0) {
            if (errno != ENOENT || fsync(staging->base_directory_fd) < 0)
                return ORBIT_STAGING_IO_ERROR;
            staging->staging_name[0] = '\0';
            staging->complete = false;
            staging->failed = false;
            int base_fd = staging->base_directory_fd;
            staging->base_directory_fd = -1;
            return close(base_fd) == 0 ? ORBIT_STAGING_OK : ORBIT_STAGING_IO_ERROR;
        }
    }
    if (!remove_directory_contents(staging->staging_directory_fd))
        return ORBIT_STAGING_IO_ERROR;

    int root_fd = staging->staging_directory_fd;
    staging->staging_directory_fd = -1;
    if (close(root_fd) < 0) return ORBIT_STAGING_IO_ERROR;
    if (unlinkat(staging->base_directory_fd, staging->staging_name,
                 AT_REMOVEDIR) < 0 && errno != ENOENT)
        return ORBIT_STAGING_IO_ERROR;
    if (fsync(staging->base_directory_fd) < 0)
        return ORBIT_STAGING_IO_ERROR;
    staging->staging_name[0] = '\0';
    staging->complete = false;
    staging->failed = false;
    int base_fd = staging->base_directory_fd;
    staging->base_directory_fd = -1;
    if (close(base_fd) < 0) return ORBIT_STAGING_IO_ERROR;
    return ORBIT_STAGING_OK;
}
orbit_staging_code orbit_package_staging_close(
    orbit_package_staging *staging) {
    if (!staging || staging->staging_directory_fd < 0 ||
        staging->base_directory_fd < 0)
        return ORBIT_STAGING_INVALID_ARGUMENT;
    if (!staging->complete || staging->active_file_fd >= 0)
        return ORBIT_STAGING_INVALID_STATE;
    int root_fd = staging->staging_directory_fd;
    staging->staging_directory_fd = -1;
    if (close(root_fd) < 0) return ORBIT_STAGING_IO_ERROR;
    int base_fd = staging->base_directory_fd;
    staging->base_directory_fd = -1;
    if (close(base_fd) < 0) return ORBIT_STAGING_IO_ERROR;
    return ORBIT_STAGING_OK;
}
