#include "ORBITPackageBootstrapProfile.h"

#include <string.h>

static const orbit_bootstrap_profile profiles[] = {
    {
        ORBIT_BOOTSTRAP_PROCursus_ROOTFUL,
        "Procursus rootful",
        "var/lib/dpkg",
        "lock-frontend",
        "lock"
    },
    {
        ORBIT_BOOTSTRAP_PROCursus_ROOTLESS,
        "Procursus rootless",
        "var/lib/dpkg",
        "lock-frontend",
        "lock"
    },
    {
        ORBIT_BOOTSTRAP_DOPAMINE_ELLEKIT_ROOTLESS,
        "Dopamine / ElleKit (Procursus rootless)",
        "var/lib/dpkg",
        "lock-frontend",
        "lock"
    }
};

const orbit_bootstrap_profile *orbit_bootstrap_profile_get(
    orbit_bootstrap_profile_id identifier) {
    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i) {
        if (profiles[i].identifier == identifier)
            return &profiles[i];
    }
    return 0;
}

int orbit_bootstrap_profile_matches_admin_directory(
    const orbit_bootstrap_profile *profile, const char *observed_admin_relative) {
    return profile && profile->dpkg_admin_directory_relative &&
        observed_admin_relative &&
        strcmp(profile->dpkg_admin_directory_relative,
               observed_admin_relative) == 0;
}
