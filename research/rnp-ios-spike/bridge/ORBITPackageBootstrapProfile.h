#ifndef ORBIT_PACKAGE_BOOTSTRAP_PROFILE_H
#define ORBIT_PACKAGE_BOOTSTRAP_PROFILE_H

#include <stddef.h>

#define ORBIT_BOOTSTRAP_PATH_CAPACITY 64U

typedef enum {
    ORBIT_BOOTSTRAP_PROCursus_ROOTFUL = 1,
    ORBIT_BOOTSTRAP_PROCursus_ROOTLESS = 2,
    ORBIT_BOOTSTRAP_DOPAMINE_ELLEKIT_ROOTLESS = 3
} orbit_bootstrap_profile_id;

typedef struct {
    orbit_bootstrap_profile_id identifier;
    const char *display_name;
    const char *dpkg_admin_directory_relative;
    const char *frontend_lock_leaf;
    const char *dpkg_lock_leaf;
} orbit_bootstrap_profile;

/* Returns immutable defaults only. The caller must independently establish
 * the trusted bootstrap root descriptor and verify the active APT
 * Dir::State::status setting resolves to this dpkg admin directory. If APT
 * config overrides that location, reject this profile until an explicit
 * validated profile is supplied. Never infer rootful/rootless from a string
 * path alone. Dopamine/ElleKit is a Procursus-rootless profile; ElleKit is
 * tweak injection, not a separate package database or lock protocol. */
const orbit_bootstrap_profile *orbit_bootstrap_profile_get(
    orbit_bootstrap_profile_id identifier);

#endif
