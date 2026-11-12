#ifndef ORBIT_APT_CONFIG_RESOLVER_H
#define ORBIT_APT_CONFIG_RESOLVER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ORBIT_APT_PATH_CAPACITY 1024U

/* Resolve the effective Dir::State::status value returned by libapt-pkg
 * after its configuration and package-system initialization. Do not pass a
 * guessed default or a value scraped from apt.conf. bootstrap_root_apt_path
 * is the canonical APT-visible absolute prefix ("/" for rootful or typically
 * "/var/jb" for Procursus rootless); the caller must independently prove that
 * its already-open root descriptor refers to that same bootstrap root.
 *
 * Only canonical absolute status paths beneath that prefix, ending in
 * "/status", are accepted. Output is the relative dpkg admin directory. */
int orbit_apt_resolve_admin_directory(
    const char *bootstrap_root_apt_path,
    const char *effective_status_path,
    char *admin_relative_out,
    size_t output_capacity);

#ifdef __cplusplus
}
#endif
#endif
