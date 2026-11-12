#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageTransactionCoordinator.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    orbit_transaction_journal journal;
    bool present;
    unsigned loads;
    unsigned applies;
    bool native_locks_held_during_apply;
    char dpkg_path[1024];
} fixture;

static unsigned checks, failures;
static void expect(const char *name, bool ok) {
    ++checks;
    if (!ok) { ++failures; fprintf(stderr, "FAIL %s\n", name); }
}
static orbit_journal_status load_journal(void *ctx, orbit_transaction_journal *out) {
    fixture *f = ctx; ++f->loads;
    if (!f->present) return ORBIT_JOURNAL_NOT_FOUND;
    *out = f->journal; return ORBIT_JOURNAL_OK;
}
static bool store_journal(void *ctx, const orbit_transaction_journal *j) {
    fixture *f = ctx;
    if (f->present && j->revision <= f->journal.revision) return false;
    f->journal = *j; f->present = true; return true;
}
static bool clear_journal(void *ctx, uint64_t revision) {
    fixture *f = ctx;
    if (!f->present || f->journal.revision != revision) return false;
    f->present = false; return true;
}
static const orbit_package_record *resolve_package(void *ctx, const char *name,
    const char *version, const char *architecture) {
    static orbit_package_record p; (void)ctx;
    memset(&p, 0, sizeof(p));
    snprintf(p.name, sizeof(p.name), "%s", name);
    snprintf(p.version, sizeof(p.version), "%s", version);
    snprintf(p.architecture, sizeof(p.architecture), "%s", architecture);
    return &p;
}
static bool locks_contend_from_child(const char *path) {
    char lock_path[1200];
    snprintf(lock_path, sizeof(lock_path), "%s/lock-frontend", path);
    pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        int fd = open(lock_path, O_RDWR | O_CLOEXEC);
        if (fd < 0) _exit(2);
        struct flock fl;
        memset(&fl, 0, sizeof(fl));
        fl.l_type = F_WRLCK; fl.l_whence = SEEK_SET;
        int rc = fcntl(fd, F_SETLK, &fl);
        close(fd);
        _exit(rc < 0 ? 0 : 1);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static bool apply_package(void *ctx, orbit_transaction_action action,
                          const orbit_package_record *p) {
    fixture *f = ctx; (void)action; (void)p;
    ++f->applies;
    f->native_locks_held_during_apply = locks_contend_from_child(f->dpkg_path);
    return f->native_locks_held_during_apply;
}
static bool rollback_package(void *ctx, orbit_transaction_action action,
                             const orbit_package_record *p) {
    (void)ctx; (void)action; (void)p; return true;
}
static bool make_dir(const char *path) {
    return mkdir(path, 0755) == 0;
}
int main(void) {
    char root_template[] = "/tmp/orbit-coordinator-XXXXXX";
    char *root = mkdtemp(root_template);
    expect("temporary-bootstrap-root", root != NULL);
    if (!root) return 1;

    char path[1200];
    snprintf(path, sizeof(path), "%s/var", root); expect("mkdir-var", make_dir(path));
    snprintf(path, sizeof(path), "%s/var/lib", root); expect("mkdir-lib", make_dir(path));
    snprintf(path, sizeof(path), "%s/var/lib/dpkg", root); expect("mkdir-dpkg", make_dir(path));

    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    expect("open-verified-root", root_fd >= 0);
    fixture f; memset(&f, 0, sizeof(f));
    snprintf(f.dpkg_path, sizeof(f.dpkg_path), "%s/var/lib/dpkg", root);

    orbit_package_record package; memset(&package, 0, sizeof(package));
    snprintf(package.name, sizeof(package.name), "coordinator-test");
    snprintf(package.version, sizeof(package.version), "1.0");
    snprintf(package.architecture, sizeof(package.architecture), "iphoneos-arm64");
    const orbit_package_record *packages[] = { &package };
    orbit_transaction_action actions[] = { ORBIT_TRANSACTION_INSTALL };
    uint8_t transaction_id[ORBIT_TRANSACTION_ID_BYTES] = { 0x42 };
    orbit_transaction_journal_backend jb = { &f, load_journal, store_journal, clear_journal };
    orbit_transaction_package_backend pb = { &f, resolve_package, apply_package, rollback_package };
    const orbit_bootstrap_profile *profile =
        orbit_bootstrap_profile_get(ORBIT_BOOTSTRAP_PROCursus_ROOTFUL);
    char root_apt_path[1200], status_path[1400];
    snprintf(root_apt_path, sizeof(root_apt_path), "%s", root);
    snprintf(status_path, sizeof(status_path), "%s/var/lib/dpkg/status", root);
    orbit_transaction_native_lock_context nc = {
        root_fd, profile, root_apt_path, status_path, getuid()
    };

    orbit_transaction_code result = orbit_package_transaction_execute_coordinated(
        &nc, transaction_id, packages, actions, 1U, &jb, &pb);
    expect("coordinated-execute-succeeds", result == ORBIT_TRANSACTION_OK);
    expect("native-locks-held-through-package-apply",
           f.applies == 1U && f.native_locks_held_during_apply);
    expect("transaction-journal-cleared", !f.present);

    unsigned before = f.loads;
    snprintf(status_path, sizeof(status_path), "%s/var/lib/other/status", root);
    result = orbit_package_transaction_recover_coordinated(&nc, &jb, &pb);
    expect("apt-admin-override-rejected", result == ORBIT_TRANSACTION_INVALID_ARGUMENT);
    expect("invalid-profile-does-not-touch-journal", f.loads == before);

    snprintf(status_path, sizeof(status_path), "%s/var/lib/dpkg/status", root);
    result = orbit_package_transaction_recover_coordinated(&nc, &jb, &pb);
    expect("coordinated-recovery-succeeds", result == ORBIT_TRANSACTION_OK);

    close(root_fd);
    char cleanup[1400];
    snprintf(cleanup, sizeof(cleanup), "%s/var/lib/dpkg/lock-frontend", root); unlink(cleanup);
    snprintf(cleanup, sizeof(cleanup), "%s/var/lib/dpkg/lock", root); unlink(cleanup);
    snprintf(cleanup, sizeof(cleanup), "%s/var/lib/dpkg", root); rmdir(cleanup);
    snprintf(cleanup, sizeof(cleanup), "%s/var/lib", root); rmdir(cleanup);
    snprintf(cleanup, sizeof(cleanup), "%s/var", root); rmdir(cleanup);
    rmdir(root);

    printf("decision=%s checks=%u failures=%u\n",
           failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
