#ifndef ORBIT_PACKAGE_BOOTSTRAP_LOCKSET_H
#define ORBIT_PACKAGE_BOOTSTRAP_LOCKSET_H

#include "ORBITPackageBootstrapProfile.h"
#include "ORBITPackageNativeLock.h"

#define ORBIT_BOOTSTRAP_LOCKSET_CAPACITY 2U

typedef struct {
    int directory_descriptor;
    const orbit_bootstrap_profile *profile;
    unsigned count;
    orbit_package_native_lock locks[ORBIT_BOOTSTRAP_LOCKSET_CAPACITY];
} orbit_bootstrap_lockset;

/* Initialize with directory_descriptor = -1, count = 0, and each lock
 * descriptor = -1. root_fd must be the already-open, verified bootstrap root:
 * "/" for rootful Procursus or the resolved jbroot directory for rootless.
 * Acquires APT's frontend lock first, then dpkg's database lock, matching
 * Debian APT's debSystem::Lock ordering. Missing lock files are created
 * exactly as APT does (O_CREAT, 0640, F_SETLK). */
orbit_native_lock_code orbit_bootstrap_lockset_acquire(
    int root_fd, const orbit_bootstrap_profile *profile, uid_t expected_owner,
    orbit_bootstrap_lockset *lockset);

/* Releases in reverse acquisition order and closes the dpkg admin directory. */
orbit_native_lock_code orbit_bootstrap_lockset_release(
    orbit_bootstrap_lockset *lockset);

#endif
