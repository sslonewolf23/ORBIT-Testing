#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageFilePlan.h"
#include "ORBITPackageFilesystemJournal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned char fold_ascii(unsigned char value) {
    return value >= 'A' && value <= 'Z' ?
        (unsigned char)(value + ('a' - 'A')) : value;
}

static bool path_equal(const char *left, const char *right) {
    if (!left || !right) return false;
    while (*left && *right) {
        if (fold_ascii((unsigned char)*left) !=
            fold_ascii((unsigned char)*right)) return false;
        ++left;
        ++right;
    }
    return *left == '\0' && *right == '\0';
}

static bool package_identity_matches(
    const orbit_package_ownership_record *record,
    const orbit_package_record *package) {
    return strcmp(record->package_name, package->name) == 0 &&
        strcmp(record->architecture, package->architecture) == 0;
}

static bool manifest_has_path(const orbit_archive_entry *manifest,
                              size_t manifest_count, const char *path,
                              bool *is_directory) {
    for (size_t i = 0U; i < manifest_count; ++i) {
        if (path_equal(manifest[i].path, path)) {
            if (is_directory) *is_directory = manifest[i].directory;
            return true;
        }
    }
    return false;
}

static bool split_path(const char *path, char *parent, size_t parent_capacity,
                       const char **basename) {
    if (!path || !parent || parent_capacity == 0U || !basename)
        return false;
    const char *slash = strrchr(path, '/');
    if (!slash) {
        parent[0] = '\0';
        *basename = path;
        return true;
    }
    size_t parent_length = (size_t)(slash - path);
    if (parent_length >= parent_capacity || slash[1] == '\0') return false;
    memcpy(parent, path, parent_length);
    parent[parent_length] = '\0';
    *basename = slash + 1;
    return true;
}

static bool backup_name_for(size_t index, char output[64]) {
    int count = snprintf(output, 64U, "b%08zu", index);
    return count > 0 && count < 64;
}


/* Find the first missing directory component without following symlinks.
 * The returned path is the topmost missing prefix, so moving that staged
 * subtree also installs every descendant in one recoverable journal action. */
static bool first_missing_directory(
    int install_root_fd, const char *path, bool final_is_directory,
    char missing[ORBIT_TAR_MAX_PATH + 1U], bool *found) {
    if (!path || !missing || !found) return false;
    *found = false;
    size_t length = strlen(path);
    if (length == 0U || length > ORBIT_TAR_MAX_PATH) return false;
    char prefix[ORBIT_TAR_MAX_PATH + 1U];
    size_t prefix_length = 0U;
    const char *cursor = path;
    while (*cursor) {
        const char *slash = strchr(cursor, '/');
        size_t component_length = slash ? (size_t)(slash - cursor) : strlen(cursor);
        if (component_length == 0U) return false;
        if (prefix_length != 0U) prefix[prefix_length++] = '/';
        if (prefix_length + component_length > ORBIT_TAR_MAX_PATH) return false;
        memcpy(prefix + prefix_length, cursor, component_length);
        prefix_length += component_length;
        prefix[prefix_length] = '\0';
        if (!slash && !final_is_directory) break;

        char parent[ORBIT_FILESYSTEM_PARENT_PATH_CAPACITY];
        const char *basename = NULL;
        if (!split_path(prefix, parent, sizeof(parent), &basename)) return false;
        int parent_fd = -1;
        orbit_filesystem_code opened =
            orbit_package_filesystem_open_parent_directory(
                install_root_fd, parent, &parent_fd);
        if (opened != ORBIT_FILESYSTEM_OK) return false;
        struct stat status;
        int stat_result = fstatat(parent_fd, basename, &status, AT_SYMLINK_NOFOLLOW);
        int saved_errno = errno;
        bool closed = close(parent_fd) == 0;
        if (!closed) return false;
        if (stat_result < 0) {
            if (saved_errno != ENOENT) return false;
            memcpy(missing, prefix, prefix_length + 1U);
            *found = true;
            return true;
        }
        if (!S_ISDIR(status.st_mode)) return false;
        cursor = slash + 1;
    }
    return true;
}

static bool path_is_within_directory(const char *path, const char *directory) {
    size_t length = strlen(directory);
    return path_equal(path, directory) ||
        (strncmp(path, directory, length) == 0 && path[length] == '/');
}

static orbit_package_file_plan_code append_create_directory(
    const char *path, int install_root_fd, int staging_root_fd,
    int backup_directory_fd, size_t backup_index,
    orbit_package_file_change *change) {
    char target_parent[ORBIT_FILESYSTEM_PARENT_PATH_CAPACITY];
    const char *basename = NULL;
    char backup_name[64];
    if (!split_path(path, target_parent, sizeof(target_parent), &basename) ||
        !backup_name_for(backup_index, backup_name))
        return ORBIT_PACKAGE_FILE_PLAN_LIMIT;
    int target_parent_fd = -1, staged_parent_fd = -1;
    orbit_filesystem_code result =
        orbit_package_filesystem_open_parent_directory(
            install_root_fd, target_parent, &target_parent_fd);
    if (result == ORBIT_FILESYSTEM_OK)
        result = orbit_package_filesystem_open_parent_directory(
            staging_root_fd, target_parent, &staged_parent_fd);
    if (result == ORBIT_FILESYSTEM_OK)
        result = orbit_package_filesystem_prepare_create_directory(
            target_parent_fd, basename, staged_parent_fd, basename,
            backup_directory_fd, backup_name, change);
    if (result == ORBIT_FILESYSTEM_OK)
        result = orbit_package_filesystem_set_parent_paths(
            change, target_parent, target_parent);
    if (result == ORBIT_FILESYSTEM_OK)
        result = orbit_package_filesystem_validate_change(change);
    bool staged_closed = staged_parent_fd < 0 || close(staged_parent_fd) == 0;
    bool target_closed = target_parent_fd < 0 || close(target_parent_fd) == 0;
    if (!staged_closed || !target_closed || result != ORBIT_FILESYSTEM_OK)
        return result == ORBIT_FILESYSTEM_LIMIT ?
            ORBIT_PACKAGE_FILE_PLAN_LIMIT :
            ORBIT_PACKAGE_FILE_PLAN_FILESYSTEM_ERROR;
    return ORBIT_PACKAGE_FILE_PLAN_OK;
}

static orbit_package_file_plan_code append_remove(
    const orbit_package_ownership_record *record,
    int install_root_fd, int backup_directory_fd, size_t backup_index,
    orbit_package_file_change *change) {
    char parent[ORBIT_FILESYSTEM_PARENT_PATH_CAPACITY];
    const char *basename = NULL;
    char backup_name[64];
    if (!split_path(record->path, parent, sizeof(parent), &basename) ||
        !backup_name_for(backup_index, backup_name))
        return ORBIT_PACKAGE_FILE_PLAN_LIMIT;

    int target_parent_fd = -1;
    orbit_filesystem_code result = orbit_package_filesystem_open_parent_directory(
        install_root_fd, parent, &target_parent_fd);
    if (result == ORBIT_FILESYSTEM_OK)
        result = orbit_package_filesystem_prepare_remove(
            target_parent_fd, basename, backup_directory_fd,
            backup_name, change);
    if (result == ORBIT_FILESYSTEM_OK)
        result = orbit_package_filesystem_set_parent_paths(change, parent, "");
    if (result == ORBIT_FILESYSTEM_OK)
        result = orbit_package_filesystem_validate_change(change);
    bool closed = target_parent_fd < 0 || close(target_parent_fd) == 0;
    if (!closed || result != ORBIT_FILESYSTEM_OK)
        return result == ORBIT_FILESYSTEM_LIMIT ?
            ORBIT_PACKAGE_FILE_PLAN_LIMIT :
            ORBIT_PACKAGE_FILE_PLAN_FILESYSTEM_ERROR;
    return ORBIT_PACKAGE_FILE_PLAN_OK;
}

static orbit_package_file_plan_code append_replace(
    const orbit_archive_entry *entry,
    int install_root_fd, int staging_root_fd, int backup_directory_fd,
    size_t backup_index, orbit_package_file_change *change) {
    char parent[ORBIT_FILESYSTEM_PARENT_PATH_CAPACITY];
    const char *basename = NULL;
    char backup_name[64];
    if (!split_path(entry->path, parent, sizeof(parent), &basename) ||
        !backup_name_for(backup_index, backup_name))
        return ORBIT_PACKAGE_FILE_PLAN_LIMIT;

    int target_parent_fd = -1;
    int staged_parent_fd = -1;
    orbit_filesystem_code result = orbit_package_filesystem_open_parent_directory(
        install_root_fd, parent, &target_parent_fd);
    if (result == ORBIT_FILESYSTEM_OK)
        result = orbit_package_filesystem_open_parent_directory(
            staging_root_fd, parent, &staged_parent_fd);
    if (result == ORBIT_FILESYSTEM_OK)
        result = orbit_package_filesystem_prepare_replace(
            target_parent_fd, basename, staged_parent_fd, basename,
            backup_directory_fd, backup_name, change);
    if (result == ORBIT_FILESYSTEM_OK)
        result = orbit_package_filesystem_set_parent_paths(
            change, parent, parent);
    if (result == ORBIT_FILESYSTEM_OK)
        result = orbit_package_filesystem_validate_change(change);

    bool staged_closed = staged_parent_fd < 0 || close(staged_parent_fd) == 0;
    bool target_closed = target_parent_fd < 0 || close(target_parent_fd) == 0;
    if (!staged_closed || !target_closed || result != ORBIT_FILESYSTEM_OK)
        return result == ORBIT_FILESYSTEM_LIMIT ?
            ORBIT_PACKAGE_FILE_PLAN_LIMIT :
            ORBIT_PACKAGE_FILE_PLAN_FILESYSTEM_ERROR;
    return ORBIT_PACKAGE_FILE_PLAN_OK;
}

orbit_package_file_plan_code orbit_package_file_plan_build_install(
    const orbit_package_ownership_snapshot *installed,
    const orbit_package_record *candidate,
    const orbit_archive_entry *manifest, size_t manifest_count,
    int install_root_fd, int staging_root_fd, int backup_directory_fd,
    orbit_package_file_change *changes, size_t change_capacity,
    size_t *change_count,
    orbit_package_ownership_record *ownership_output,
    size_t ownership_capacity,
    orbit_package_ownership_snapshot *replacement_ownership) {
    if (!installed || !candidate || !manifest || manifest_count == 0U ||
        install_root_fd < 0 || staging_root_fd < 0 ||
        backup_directory_fd < 0 || !changes || !change_count ||
        !ownership_output || !replacement_ownership) {
        return ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT;
    }
    *change_count = 0U;
    memset(replacement_ownership, 0, sizeof(*replacement_ownership));
    if (manifest_count > ORBIT_OWNERSHIP_MAX_PACKAGE_ENTRIES ||
        change_capacity > ORBIT_FILESYSTEM_JOURNAL_MAX_CHANGES) {
        return ORBIT_PACKAGE_FILE_PLAN_LIMIT;
    }

    orbit_ownership_code ownership_result =
        orbit_package_ownership_snapshot_install(
            installed, candidate, manifest, manifest_count,
            ownership_output, ownership_capacity, replacement_ownership);
    if (ownership_result != ORBIT_OWNERSHIP_OK) {
        return ownership_result == ORBIT_OWNERSHIP_LIMIT ?
            ORBIT_PACKAGE_FILE_PLAN_LIMIT :
            ORBIT_PACKAGE_FILE_PLAN_OWNERSHIP_ERROR;
    }


    /* Remove obsolete files from the prior version first. A stale ownership
     * row beneath a physically missing directory fails closed here. */
    for (size_t i = 0U; i < installed->count; ++i) {
        const orbit_package_ownership_record *old = &installed->records[i];
        if (!package_identity_matches(old, candidate) || old->directory)
            continue;
        bool replacement_is_directory = false;
        if (manifest_has_path(manifest, manifest_count, old->path,
                              &replacement_is_directory)) {
            if (replacement_is_directory) {
                *change_count = 0U;
                memset(replacement_ownership, 0, sizeof(*replacement_ownership));
                return ORBIT_PACKAGE_FILE_PLAN_FILESYSTEM_ERROR;
            }
            continue;
        }
        if (*change_count >= change_capacity) {
            *change_count = 0U;
            memset(replacement_ownership, 0, sizeof(*replacement_ownership));
            return ORBIT_PACKAGE_FILE_PLAN_LIMIT;
        }
        orbit_package_file_plan_code planned = append_remove(
            old, install_root_fd, backup_directory_fd, *change_count + 1U,
            &changes[*change_count]);
        if (planned != ORBIT_PACKAGE_FILE_PLAN_OK) {
            *change_count = 0U;
            memset(replacement_ownership, 0, sizeof(*replacement_ownership));
            return planned;
        }
        ++(*change_count);
    }

    /* Discover topmost missing directory prefixes. Each operation moves the
     * complete staged subtree, so descendants are deliberately not scheduled
     * as separate directory or file changes. */
    char **created_directories = (char **)calloc(manifest_count, sizeof(char *));
    if (!created_directories) {
        *change_count = 0U;
        memset(replacement_ownership, 0, sizeof(*replacement_ownership));
        return ORBIT_PACKAGE_FILE_PLAN_LIMIT;
    }
    size_t created_count = 0U;
    for (size_t i = 0U; i < manifest_count; ++i) {
        char missing[ORBIT_TAR_MAX_PATH + 1U];
        bool found = false;
        if (!first_missing_directory(install_root_fd, manifest[i].path,
                                     manifest[i].directory, missing, &found)) {
            for (size_t n = 0U; n < created_count; ++n) free(created_directories[n]);
            free(created_directories);
            *change_count = 0U;
            memset(replacement_ownership, 0, sizeof(*replacement_ownership));
            return ORBIT_PACKAGE_FILE_PLAN_FILESYSTEM_ERROR;
        }
        if (!found) continue;
        bool already_covered = false;
        for (size_t n = 0U; n < created_count; ++n) {
            if (path_is_within_directory(missing, created_directories[n])) {
                already_covered = true;
                break;
            }
        }
        if (already_covered) continue;
        if (*change_count >= change_capacity) {
            for (size_t n = 0U; n < created_count; ++n) free(created_directories[n]);
            free(created_directories);
            *change_count = 0U;
            memset(replacement_ownership, 0, sizeof(*replacement_ownership));
            return ORBIT_PACKAGE_FILE_PLAN_LIMIT;
        }
        orbit_package_file_plan_code planned = append_create_directory(
            missing, install_root_fd, staging_root_fd, backup_directory_fd,
            *change_count + 1U, &changes[*change_count]);
        if (planned != ORBIT_PACKAGE_FILE_PLAN_OK) {
            for (size_t n = 0U; n < created_count; ++n) free(created_directories[n]);
            free(created_directories);
            *change_count = 0U;
            memset(replacement_ownership, 0, sizeof(*replacement_ownership));
            return planned;
        }
        created_directories[created_count] = strdup(missing);
        if (!created_directories[created_count]) {
            for (size_t n = 0U; n < created_count; ++n) free(created_directories[n]);
            free(created_directories);
            *change_count = 0U;
            memset(replacement_ownership, 0, sizeof(*replacement_ownership));
            return ORBIT_PACKAGE_FILE_PLAN_LIMIT;
        }
        ++created_count;
        ++(*change_count);
    }

    for (size_t i = 0U; i < manifest_count; ++i) {
        if (manifest[i].directory) continue;
        bool supplied_by_directory_move = false;
        for (size_t n = 0U; n < created_count; ++n) {
            if (path_is_within_directory(manifest[i].path,
                                         created_directories[n])) {
                supplied_by_directory_move = true;
                break;
            }
        }
        if (supplied_by_directory_move) continue;
        if (*change_count >= change_capacity) {
            for (size_t n = 0U; n < created_count; ++n) free(created_directories[n]);
            free(created_directories);
            *change_count = 0U;
            memset(replacement_ownership, 0, sizeof(*replacement_ownership));
            return ORBIT_PACKAGE_FILE_PLAN_LIMIT;
        }
        orbit_package_file_plan_code planned = append_replace(
            &manifest[i], install_root_fd, staging_root_fd,
            backup_directory_fd, *change_count + 1U,
            &changes[*change_count]);
        if (planned != ORBIT_PACKAGE_FILE_PLAN_OK) {
            for (size_t n = 0U; n < created_count; ++n) free(created_directories[n]);
            free(created_directories);
            *change_count = 0U;
            memset(replacement_ownership, 0, sizeof(*replacement_ownership));
            return planned;
        }
        ++(*change_count);
    }
    for (size_t n = 0U; n < created_count; ++n) free(created_directories[n]);
    free(created_directories);

    if (*change_count == 0U) {
        memset(replacement_ownership, 0, sizeof(*replacement_ownership));
        return ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT;
    }
    return ORBIT_PACKAGE_FILE_PLAN_OK;
}

orbit_package_file_plan_code orbit_package_file_plan_build_remove(
    const orbit_package_ownership_snapshot *installed,
    const orbit_package_record *package,
    int install_root_fd, int backup_directory_fd,
    orbit_package_file_change *changes, size_t change_capacity,
    size_t *change_count,
    orbit_package_ownership_record *ownership_output,
    size_t ownership_capacity,
    orbit_package_ownership_snapshot *replacement_ownership) {
    if (!installed || !package || install_root_fd < 0 ||
        backup_directory_fd < 0 || !changes || !change_count ||
        !ownership_output || !replacement_ownership)
        return ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT;
    *change_count = 0U;
    memset(replacement_ownership, 0, sizeof(*replacement_ownership));
    if (change_capacity > ORBIT_FILESYSTEM_JOURNAL_MAX_CHANGES)
        return ORBIT_PACKAGE_FILE_PLAN_LIMIT;

    orbit_ownership_code ownership_result =
        orbit_package_ownership_snapshot_remove(
            installed, package, ownership_output, ownership_capacity,
            replacement_ownership);
    if (ownership_result != ORBIT_OWNERSHIP_OK)
        return ownership_result == ORBIT_OWNERSHIP_LIMIT ?
            ORBIT_PACKAGE_FILE_PLAN_LIMIT :
            ORBIT_PACKAGE_FILE_PLAN_OWNERSHIP_ERROR;

    for (size_t i = 0U; i < installed->count; ++i) {
        const orbit_package_ownership_record *record = &installed->records[i];
        if (!package_identity_matches(record, package) || record->directory)
            continue;
        if (*change_count >= change_capacity) {
            *change_count = 0U;
            memset(replacement_ownership, 0, sizeof(*replacement_ownership));
            return ORBIT_PACKAGE_FILE_PLAN_LIMIT;
        }
        orbit_package_file_plan_code planned = append_remove(
            record, install_root_fd, backup_directory_fd,
            *change_count + 1U, &changes[*change_count]);
        if (planned != ORBIT_PACKAGE_FILE_PLAN_OK) {
            *change_count = 0U;
            memset(replacement_ownership, 0, sizeof(*replacement_ownership));
            return planned;
        }
        ++(*change_count);
    }

    if (*change_count == 0U) {
        memset(replacement_ownership, 0, sizeof(*replacement_ownership));
        return ORBIT_PACKAGE_FILE_PLAN_INVALID_ARGUMENT;
    }
    return ORBIT_PACKAGE_FILE_PLAN_OK;
}
