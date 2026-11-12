#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageNativeLock.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned passed, failed;
#define EXPECT(label, expr) do { \
    if (expr) { ++passed; printf("PASS: %s\n", label); } \
    else { ++failed; printf("FAIL: %s (errno=%d)\n", label, errno); } \
} while (0)

int main(void) {
    char path[] = "/tmp/orbit-native-lock-XXXXXX";
    char *dir = mkdtemp(path);
    EXPECT("native lock test directory created", dir != NULL);
    if (!dir) return EXIT_FAILURE;
    int root = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    EXPECT("native lock directory opened", root >= 0);
    if (root < 0) return EXIT_FAILURE;

    int fixture = openat(root, "dpkg-lock", O_RDWR | O_CREAT | O_EXCL |
                         O_CLOEXEC, 0600);
    EXPECT("native lock fixture created", fixture >= 0);
    if (fixture >= 0) close(fixture);

    orbit_package_native_lock created = { -1, 0, 0 };
    EXPECT("missing APT-style lock file is created safely",
        orbit_package_native_lock_acquire_at(root, "new-lock", geteuid(),
            &created) == ORBIT_NATIVE_LOCK_OK);
    struct stat created_status;
    EXPECT("created lock file has APT-compatible permissions",
        fstat(created.descriptor, &created_status) == 0 &&
        S_ISREG(created_status.st_mode) && created_status.st_nlink == 1 &&
        (created_status.st_mode & 0777) == 0640);
    EXPECT("created lock released",
        orbit_package_native_lock_release_at(root, "new-lock", &created) ==
            ORBIT_NATIVE_LOCK_OK);
    EXPECT("created lock fixture removed",
        unlinkat(root, "new-lock", 0) == 0);

    orbit_package_native_lock held = { -1, 0, 0 };
    EXPECT("native fcntl lock acquired",
        orbit_package_native_lock_acquire_at(root, "dpkg-lock", geteuid(),
            &held) == ORBIT_NATIVE_LOCK_OK);

    pid_t child = fork();
    EXPECT("cross-process contention child forked", child >= 0);
    if (child == 0) {
        orbit_package_native_lock contender = { -1, 0, 0 };
        orbit_native_lock_code result =
            orbit_package_native_lock_acquire_at(root, "dpkg-lock",
                geteuid(), &contender);
        if (contender.descriptor >= 0)
            (void)orbit_package_native_lock_release_at(root, "dpkg-lock",
                                                       &contender);
        _exit(result == ORBIT_NATIVE_LOCK_BUSY ? 0 : 1);
    }
    int status = 0;
    if (child > 0) (void)waitpid(child, &status, 0);
    EXPECT("independent process cannot acquire held native lock",
        child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);

    EXPECT("duplicate acquisition cannot overwrite held handle",
        orbit_package_native_lock_acquire_at(root, "dpkg-lock", geteuid(),
            &held) == ORBIT_NATIVE_LOCK_BUSY && held.descriptor >= 0);
    EXPECT("native lock released",
        orbit_package_native_lock_release_at(root, "dpkg-lock", &held) ==
            ORBIT_NATIVE_LOCK_OK);

    EXPECT("native lock can be reacquired after release",
        orbit_package_native_lock_acquire_at(root, "dpkg-lock", geteuid(),
            &held) == ORBIT_NATIVE_LOCK_OK);
    EXPECT("native lock second release",
        orbit_package_native_lock_release_at(root, "dpkg-lock", &held) ==
            ORBIT_NATIVE_LOCK_OK);

    EXPECT("symlink fixture created",
        symlinkat("missing", root, "symlink-lock") == 0);
    orbit_package_native_lock invalid = { -1, 0, 0 };
    EXPECT("native lock refuses symlink",
        orbit_package_native_lock_acquire_at(root, "symlink-lock", geteuid(),
            &invalid) != ORBIT_NATIVE_LOCK_OK);
    EXPECT("slash-containing lock name rejected",
        orbit_package_native_lock_acquire_at(root, "subdir/lock", geteuid(),
            &invalid) == ORBIT_NATIVE_LOCK_INVALID_ARGUMENT);
    EXPECT("hardlink fixture created",
        linkat(root, "dpkg-lock", root, "dpkg-lock-alias", 0) == 0);
    EXPECT("multiply-linked native lock is rejected",
        orbit_package_native_lock_acquire_at(root, "dpkg-lock", geteuid(),
            &invalid) == ORBIT_NATIVE_LOCK_CONFLICT);
    EXPECT("hardlink fixture removed",
        unlinkat(root, "dpkg-lock-alias", 0) == 0);
    EXPECT("writable lock parent rejected",
        fchmod(root, 0777) == 0 &&
        orbit_package_native_lock_acquire_at(root, "dpkg-lock", geteuid(),
            &invalid) == ORBIT_NATIVE_LOCK_CONFLICT);
    EXPECT("private lock parent restored", fchmod(root, 0700) == 0);

    EXPECT("fixtures cleaned",
        unlinkat(root, "symlink-lock", 0) == 0 &&
        unlinkat(root, "dpkg-lock", 0) == 0);
    close(root);
    EXPECT("test directory removed", rmdir(dir) == 0);
    printf("native_lock_checks_passed=%u\nnative_lock_checks_failed=%u\n",
           passed, failed);
    printf("decision=%s\n", failed == 0 ? "PASS" : "FAIL");
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
