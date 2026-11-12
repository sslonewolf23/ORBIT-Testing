#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageBootstrapLockset.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned passed, failed;
#define EXPECT(label, expression) do { \
    if (expression) { ++passed; printf("PASS: %s\n", label); } \
    else { ++failed; printf("FAIL: %s\n", label); } \
} while (0)

int main(void) {
    char path[] = "/tmp/orbit-bootstrap-lockset-XXXXXX";
    char *dir = mkdtemp(path);
    EXPECT("bootstrap root created", dir != NULL);
    if (!dir) return EXIT_FAILURE;
    int root = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("bootstrap root opened", root >= 0);
    if (root < 0) return EXIT_FAILURE;

    EXPECT("var directory created", mkdirat(root, "var", 0755) == 0);
    int varfd = openat(root, "var", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("var directory opened", varfd >= 0);
    EXPECT("lib directory created", varfd >= 0 && mkdirat(varfd, "lib", 0755) == 0);
    int libfd = varfd >= 0 ? openat(varfd, "lib", O_RDONLY | O_DIRECTORY | O_CLOEXEC) : -1;
    EXPECT("lib directory opened", libfd >= 0);
    EXPECT("dpkg directory created", libfd >= 0 && mkdirat(libfd, "dpkg", 0755) == 0);
    if (libfd >= 0) close(libfd);
    if (varfd >= 0) close(varfd);

    const orbit_bootstrap_profile *profile =
        orbit_bootstrap_profile_get(ORBIT_BOOTSTRAP_DOPAMINE_ELLEKIT_ROOTLESS);
    orbit_bootstrap_lockset lockset = { -1, 0, 0, { { -1, 0, 0 }, { -1, 0, 0 } } };
    EXPECT("Dopamine lockset acquires frontend then dpkg locks",
        profile && orbit_bootstrap_lockset_acquire(
            root, profile, geteuid(), &lockset) == ORBIT_NATIVE_LOCK_OK);
    EXPECT("both native locks held",
        lockset.count == 2 && lockset.locks[0].descriptor >= 0 &&
        lockset.locks[1].descriptor >= 0);
    EXPECT("lockset releases in reverse order",
        orbit_bootstrap_lockset_release(&lockset) == ORBIT_NATIVE_LOCK_OK);
    EXPECT("lockset reset after release",
        lockset.count == 0 && lockset.directory_descriptor == -1);

    const orbit_bootstrap_profile *rootful_profile =
        orbit_bootstrap_profile_get(ORBIT_BOOTSTRAP_PROCursus_ROOTFUL);
    EXPECT("Procursus rootful profile acquires the same relative lock set",
        rootful_profile && orbit_bootstrap_lockset_acquire(
            root, rootful_profile, geteuid(), &lockset) == ORBIT_NATIVE_LOCK_OK);
    EXPECT("Procursus rootful lockset releases",
        orbit_bootstrap_lockset_release(&lockset) == ORBIT_NATIVE_LOCK_OK);

    EXPECT("lock files cleaned",
        unlinkat(root, "var/lib/dpkg/lock-frontend", 0) == 0 &&
        unlinkat(root, "var/lib/dpkg/lock", 0) == 0);
    EXPECT("dpkg directory removed", unlinkat(root, "var/lib/dpkg", AT_REMOVEDIR) == 0);
    EXPECT("lib directory removed", unlinkat(root, "var/lib", AT_REMOVEDIR) == 0);
    EXPECT("var directory removed", unlinkat(root, "var", AT_REMOVEDIR) == 0);
    close(root);
    EXPECT("bootstrap root removed", rmdir(dir) == 0);
    printf("bootstrap_lockset_checks_passed=%u\nbootstrap_lockset_checks_failed=%u\n",
           passed, failed);
    printf("decision=%s\n", failed == 0 ? "PASS" : "FAIL");
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
