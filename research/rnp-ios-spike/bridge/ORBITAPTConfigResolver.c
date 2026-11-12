#include "ORBITAPTConfigResolver.h"

#include <string.h>

static int canonical_absolute_path(const char *path) {
    if (!path || path[0] != '/') return 0;
    size_t length = strlen(path);
    if (length == 0U || length >= ORBIT_APT_PATH_CAPACITY) return 0;
    if (length == 1U) return 1;
    if (path[length - 1U] == '/') return 0;

    size_t component_start = 1U;
    for (size_t i = 1U; i <= length; ++i) {
        if (i < length) {
            unsigned char ch = (unsigned char)path[i];
            if (ch < 0x20U || ch == 0x7fU) return 0;
            if (ch != '/') continue;
        }
        size_t component_length = i - component_start;
        if (component_length == 0U ||
            (component_length == 1U && path[component_start] == '.') ||
            (component_length == 2U && path[component_start] == '.' &&
             path[component_start + 1U] == '.'))
            return 0;
        component_start = i + 1U;
    }
    for (size_t i = 0; i < length; ++i) {
        unsigned char ch = (unsigned char)path[i];
        if (ch < 0x20U || ch == 0x7fU) return 0;
    }
    return 1;
}

int orbit_apt_resolve_admin_directory(
    const char *bootstrap_root_apt_path,
    const char *effective_status_path,
    char *admin_relative_out,
    size_t output_capacity) {
    if (!admin_relative_out || output_capacity == 0U ||
        !canonical_absolute_path(bootstrap_root_apt_path) ||
        !canonical_absolute_path(effective_status_path))
        return 0;

    size_t root_length = strlen(bootstrap_root_apt_path);
    size_t status_path_length = strlen(effective_status_path);
    const char *relative_status = NULL;
    if (root_length == 1U && bootstrap_root_apt_path[0] == '/') {
        relative_status = effective_status_path + 1U;
    } else {
        if (status_path_length <= root_length ||
            strncmp(effective_status_path, bootstrap_root_apt_path,
                    root_length) != 0 ||
            effective_status_path[root_length] != '/')
            return 0;
        relative_status = effective_status_path + root_length + 1U;
    }

    size_t relative_length = strlen(relative_status);
    static const char suffix[] = "/status";
    if (relative_length <= sizeof(suffix) - 1U ||
        strcmp(relative_status + relative_length - (sizeof(suffix) - 1U),
               suffix) != 0)
        return 0;

    size_t admin_length = relative_length - (sizeof(suffix) - 1U);
    if (admin_length == 0U || admin_length >= output_capacity ||
        admin_length >= ORBIT_APT_PATH_CAPACITY)
        return 0;

    memcpy(admin_relative_out, relative_status, admin_length);
    admin_relative_out[admin_length] = '\0';
    return 1;
}
