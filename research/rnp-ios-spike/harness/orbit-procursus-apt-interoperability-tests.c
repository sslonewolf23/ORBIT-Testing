#define _POSIX_C_SOURCE 200809L
#include "ORBITPackageBootstrapLockset.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned checks, failures;
static void expect(const char *label, int ok) {
    ++checks;
    if (!ok) { ++failures; fprintf(stderr, "FAIL: %s\n", label); }
}
static int mkdir_one(const char *path) {
    return mkdir(path, 0755) == 0 || errno == EEXIST;
}
static int write_text(const char *path, const char *value) {
    FILE *f = fopen(path, "w");
    if (!f) return 0;
    int ok = fputs(value, f) >= 0 && fclose(f) == 0;
    return ok;
}
static int run_apt(const char *root, const char *deb, const char *log_path) {
    char opt_root[1400], opt_status[1400], opt_state[1400], opt_cache[1400];
    char opt_lists[1400], opt_logs[1400], opt_source[1400], opt_dpkg_root[1400];
    snprintf(opt_root, sizeof(opt_root), "Dir::Root=%s", root);
    snprintf(opt_dpkg_root, sizeof(opt_dpkg_root), "DPkg::Options::=--root=%s", root);
    snprintf(opt_status, sizeof(opt_status), "Dir::State::status=/var/lib/dpkg/status");
    snprintf(opt_state, sizeof(opt_state), "Dir::State=/var/lib/apt");
    snprintf(opt_cache, sizeof(opt_cache), "Dir::Cache=/var/cache/apt");
    snprintf(opt_lists, sizeof(opt_lists), "Dir::State::lists=/var/lib/apt/lists");
    snprintf(opt_logs, sizeof(opt_logs), "Dir::Log=/var/log/apt");
    snprintf(opt_source, sizeof(opt_source), "Dir::Etc::sourcelist=/etc/apt/sources.list");

    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) _exit(120);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
        execlp("apt-get", "apt-get",
            "-o", opt_root,
            "-o", opt_status,
            "-o", opt_state,
            "-o", opt_cache,
            "-o", opt_lists,
            "-o", opt_logs,
            "-o", opt_source,
            "-o", "Dir::Etc::sourceparts=-",
            "-o", "Dir::Etc::main=-",
            "-o", "APT::Sandbox::User=root",
            "-o", "DPkg::Options::=--root", 
            "-o", opt_dpkg_root,
            "--assume-yes", "--no-install-recommends", "--no-download",
            "install", deb, (char *)NULL);
        _exit(121);
    }
    int status_code = 0;
    if (waitpid(child, &status_code, 0) != child || !WIFEXITED(status_code))
        return -1;
    return WEXITSTATUS(status_code);
}
static void dump_log(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "Unable to read APT diagnostic log: %s\n", path); return; }
    fprintf(stderr, "--- APT diagnostic log: %s ---\n", path);
    char line[1024];
    while (fgets(line, sizeof(line), f)) fputs(line, stderr);
    fclose(f);
    fprintf(stderr, "--- end APT diagnostic log ---\n");
}
static int file_contains(const char *path, const char *needle) {
    char buffer[8192];
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    size_t n = fread(buffer, 1, sizeof(buffer) - 1U, f);
    fclose(f);
    buffer[n] = '\0';
    return strstr(buffer, needle) != NULL;
}
int main(void) {
    char root_template[] = "/tmp/orbit-apt-interop-XXXXXX";
    char *root = mkdtemp(root_template);
    expect("temporary bootstrap root created", root != NULL);
    if (!root) return 1;
    expect("temporary root is traversable by the test package manager",
           chmod(root, 0755) == 0);

    char path[1600], package_dir[1200], deb_path[1200], log_path[1200];
    const char *dirs[] = {
        "/var", "/var/lib", "/var/lib/dpkg", "/var/lib/dpkg/updates",
        "/var/lib/dpkg/info", "/var/lib/dpkg/triggers", "/var/lib/dpkg/parts", "/var/lib/apt",
        "/var/lib/apt/lists", "/var/lib/apt/lists/partial",
        "/var/cache", "/var/cache/apt", "/var/cache/apt/archives",
        "/var/cache/apt/archives/partial", "/var/log", "/var/log/apt",
        "/etc", "/etc/apt", "/tmp-pkg", "/tmp-pkg/DEBIAN",
        "/tmp-pkg/usr", "/tmp-pkg/usr/share",
        "/tmp-pkg/usr/share/orbit-lock-probe"
    };
    for (size_t i = 0; i < sizeof(dirs)/sizeof(dirs[0]); ++i) {
        snprintf(path, sizeof(path), "%s%s", root, dirs[i]);
        expect("bootstrap/package directory created", mkdir_one(path));
    }
    snprintf(path, sizeof(path), "%s/var/lib/dpkg/status", root);
    expect("empty dpkg status created", write_text(path, ""));
    snprintf(path, sizeof(path), "%s/etc/apt/sources.list", root);
    expect("empty source list created", write_text(path, ""));
    snprintf(path, sizeof(path), "%s/tmp-pkg/DEBIAN/control", root);
    expect("local package control created",
        write_text(path, "Package: orbit-lock-probe\nVersion: 1.0\nArchitecture: all\nMaintainer: ORBIT test\nDescription: ORBIT APT lock interoperability fixture\n"));
    snprintf(path, sizeof(path), "%s/tmp-pkg/usr/share/orbit-lock-probe/probe.txt", root);
    expect("local package payload created", write_text(path, "installed\n"));

    snprintf(package_dir, sizeof(package_dir), "%s/tmp-pkg", root);
    snprintf(deb_path, sizeof(deb_path), "%s/var/cache/apt/archives/orbit-lock-probe_1.0_all.deb", root);
    pid_t build = fork();
    if (build == 0) {
        execlp("dpkg-deb", "dpkg-deb", "--build", package_dir, deb_path, (char *)NULL);
        _exit(122);
    }
    int build_status = 0;
    expect("dpkg-deb fixture built",
        build > 0 && waitpid(build, &build_status, 0) == build &&
        WIFEXITED(build_status) && WEXITSTATUS(build_status) == 0);

    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    expect("bootstrap root descriptor opened", root_fd >= 0);
    const orbit_bootstrap_profile *profile =
        orbit_bootstrap_profile_get(ORBIT_BOOTSTRAP_PROCursus_ROOTFUL);
    orbit_bootstrap_lockset lockset;
    memset(&lockset, 0, sizeof(lockset));
    lockset.directory_descriptor = -1;
    for (size_t i = 0; i < ORBIT_BOOTSTRAP_LOCKSET_CAPACITY; ++i)
        lockset.locks[i].descriptor = -1;

    orbit_native_lock_code acquired = orbit_bootstrap_lockset_acquire(
        root_fd, profile, "var/lib/dpkg", getuid(), &lockset);
    expect("ORBIT acquires APT frontend and dpkg locks",
        acquired == ORBIT_NATIVE_LOCK_OK);

    snprintf(log_path, sizeof(log_path), "%s/apt-held-lock.log", root);
    int blocked = run_apt(root, deb_path, log_path);
    expect("real apt-get is blocked while ORBIT holds native locks",
        blocked != 0 && file_contains(log_path, "lock"));
    int reports_contention =
        file_contains(log_path, "Could not get lock") ||
        file_contains(log_path, "Unable to acquire") ||
        file_contains(log_path, "locked");
    expect("APT reports lock contention", reports_contention);
    if (!reports_contention) dump_log(log_path);

    orbit_native_lock_code released = orbit_bootstrap_lockset_release(&lockset);
    expect("ORBIT releases native locks", released == ORBIT_NATIVE_LOCK_OK);

    snprintf(log_path, sizeof(log_path), "%s/apt-released-lock.log", root);
    int installed = run_apt(root, deb_path, log_path);
    expect("real apt-get proceeds after ORBIT releases locks", installed == 0);
    if (installed != 0) dump_log(log_path);
    snprintf(path, sizeof(path), "%s/usr/share/orbit-lock-probe/probe.txt", root);
    int payload_installed = access(path, F_OK) == 0;
    expect("APT and dpkg install fixture into isolated root", payload_installed);
    if (!payload_installed && installed == 0) dump_log(log_path);

    close(root_fd);
    printf("procursus_apt_interop_checks=%u\nprocursus_apt_interop_failures=%u\n",
           checks, failures);
    printf("decision=%s\n", failures ? "FAIL" : "PASS");
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
