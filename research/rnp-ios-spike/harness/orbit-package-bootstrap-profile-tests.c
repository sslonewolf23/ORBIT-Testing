#include "ORBITPackageBootstrapProfile.h"

#include <stdio.h>
#include <stdlib.h>

static unsigned passed, failed;
#define EXPECT(label, expression) do { \
    if (expression) { ++passed; printf("PASS: %s\n", label); } \
    else { ++failed; printf("FAIL: %s\n", label); } \
} while (0)

int main(void) {
    const orbit_bootstrap_profile *rootful =
        orbit_bootstrap_profile_get(ORBIT_BOOTSTRAP_PROCursus_ROOTFUL);
    const orbit_bootstrap_profile *rootless =
        orbit_bootstrap_profile_get(ORBIT_BOOTSTRAP_PROCursus_ROOTLESS);
    const orbit_bootstrap_profile *dopamine =
        orbit_bootstrap_profile_get(ORBIT_BOOTSTRAP_DOPAMINE_ELLEKIT_ROOTLESS);

    EXPECT("Procursus rootful profile exists", rootful != NULL);
    EXPECT("Procursus rootless profile exists", rootless != NULL);
    EXPECT("Dopamine/ElleKit rootless profile exists", dopamine != NULL);
    EXPECT("all profiles use verified dpkg lock leaves",
        rootful && rootless && dopamine &&
        rootful->dpkg_admin_directory_relative &&
        rootless->dpkg_admin_directory_relative &&
        dopamine->dpkg_admin_directory_relative &&
        rootful->frontend_lock_leaf && rootless->frontend_lock_leaf &&
        dopamine->frontend_lock_leaf &&
        rootful->dpkg_lock_leaf && rootless->dpkg_lock_leaf &&
        dopamine->dpkg_lock_leaf);
    EXPECT("rootful and rootless resolve same paths under different roots",
        rootful && rootless &&
        rootful->dpkg_admin_directory_relative[0] == 'v' &&
        rootless->dpkg_admin_directory_relative[0] == 'v' &&
        rootful->frontend_lock_leaf[0] == rootless->frontend_lock_leaf[0] &&
        rootful->dpkg_lock_leaf[0] == rootless->dpkg_lock_leaf[0]);
    EXPECT("Dopamine is explicitly Procursus rootless",
        dopamine && dopamine->identifier ==
            ORBIT_BOOTSTRAP_DOPAMINE_ELLEKIT_ROOTLESS &&
        dopamine->dpkg_admin_directory_relative[0] == 'v');
    EXPECT("unknown profile rejected",
        orbit_bootstrap_profile_get((orbit_bootstrap_profile_id)999) == NULL);

    printf("bootstrap_profile_checks_passed=%u\nbootstrap_profile_checks_failed=%u\n",
           passed, failed);
    printf("decision=%s\n", failed == 0 ? "PASS" : "FAIL");
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
