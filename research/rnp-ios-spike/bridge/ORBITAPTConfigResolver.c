#include "ORBITAPTConfigResolver.h"

#include <string.h>

static int canonical_absolute_path(const char *path) {
    if (!path || path[0] != '/') return 0;
    size_t length = strlen(path);
    if (length == 0U || length >= ORBIT_APT_PATH_CAPACITY) return 0;
    if (length > 1U && path[length - 1U] == '/') return 0;

    for (size_t i = 0; i < length; ++i) {
        unsigned char ch = (unsigned char)path[i];
        if (ch < 0x20U || ch == 0x7fU) return 0;
        if (ch == '/') {
            if (i + 1U < length && path[i + 1U] == '/') return 0;
            size_t start = i + 1U;
            size_t end = start;
            while (end < length && path[end] != '/') ++end;
            size_t component_length = end - start;
            if ((component_length == 1U && path[start] == '.') ||
                (component_length == 2U && path[start] == '.' &&
                 path[start + 1U] == '.'))
                return 0;
        }
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
    const char *relative_status = NULL;
    if (root_length == 1U && bootstrap_root_apt_path[0] == '/') {
        relative_status = effective_status_path + 1U;
    } else {
        if (strncmp(effective_status_path, bootstrap_root_apt_path,
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
