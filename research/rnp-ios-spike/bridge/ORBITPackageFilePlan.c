#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageFilePlan.h"

#include <stdio.h>
#include <string.h>
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

    /* Remove obsolete files from the prior version before preparing new files.
     * Directory creation and file-to-directory transitions are intentionally
     * unsupported by this file-only transaction primitive. */
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

    for (size_t i = 0U; i < manifest_count; ++i) {
        if (manifest[i].directory) continue;
        if (*change_count >= change_capacity) {
            *change_count = 0U;
            memset(replacement_ownership, 0, sizeof(*replacement_ownership));
            return ORBIT_PACKAGE_FILE_PLAN_LIMIT;
        }
        orbit_package_file_plan_code planned = append_replace(
            &manifest[i], install_root_fd, staging_root_fd,
            backup_directory_fd, *change_count + 1U,
            &changes[*change_count]);
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
