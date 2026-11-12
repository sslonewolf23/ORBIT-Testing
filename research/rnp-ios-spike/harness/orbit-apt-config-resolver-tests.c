#include "ORBITAPTConfigResolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures;
static void expect(const char *label, int ok) {
    ++checks;
    if (!ok) { ++failures; fprintf(stderr, "FAIL: %s\n", label); }
}
static int resolves(const char *root, const char *status, const char *expected) {
    char output[ORBIT_APT_PATH_CAPACITY];
    memset(output, 0xA5, sizeof(output));
    if (!orbit_apt_resolve_admin_directory(root, status, output, sizeof(output)))
        return 0;
    return strcmp(output, expected) == 0;
}
int main(void) {
    expect("rootful default status path",
        resolves("/", "/var/lib/dpkg/status", "var/lib/dpkg"));
    expect("Procursus rootless status path",
        resolves("/var/jb", "/var/jb/var/lib/dpkg/status", "var/lib/dpkg"));
    expect("rootless prefix boundary enforced",
        !resolves("/var/jb", "/var/jb2/var/lib/dpkg/status", "var/lib/dpkg"));
    expect("status outside bootstrap root rejected",
        !resolves("/var/jb", "/private/var/lib/dpkg/status", "var/lib/dpkg"));
    expect("status shorter than bootstrap prefix rejected safely",
        !resolves("/var/jb/long-bootstrap-root", "/x", "var/lib/dpkg"));
    expect("custom status directory resolves exactly",
        resolves("/var/jb", "/var/jb/private/dpkg/status", "private/dpkg"));
    expect("non-status filename rejected",
        !resolves("/var/jb", "/var/jb/var/lib/dpkg/available", "var/lib/dpkg"));
    expect("relative status path rejected",
        !resolves("/var/jb", "var/lib/dpkg/status", "var/lib/dpkg"));
    expect("dot-dot traversal rejected",
        !resolves("/var/jb", "/var/jb/var/../lib/dpkg/status", "var/lib/dpkg"));
    expect("duplicate slash rejected",
        !resolves("/var/jb", "/var/jb//var/lib/dpkg/status", "var/lib/dpkg"));
    expect("noncanonical root rejected",
        !resolves("/var/jb/", "/var/jb/var/lib/dpkg/status", "var/lib/dpkg"));
    expect("terminal dot-dot root segment rejected",
        !resolves("/var/jb/..", "/var/jb/../var/lib/dpkg/status", "var/lib/dpkg"));
    expect("terminal dot root segment rejected",
        !resolves("/var/jb/.", "/var/jb/./var/lib/dpkg/status", "var/lib/dpkg"));
    expect("empty admin directory rejected",
        !resolves("/var/jb", "/var/jb/status", ""));
    char small[4];
    expect("undersized output rejected",
        !orbit_apt_resolve_admin_directory(
            "/", "/var/lib/dpkg/status", small, sizeof(small)));
    printf("apt_config_resolver_checks=%u\napt_config_resolver_failures=%u\n",
           checks, failures);
    printf("decision=%s\n", failures ? "FAIL" : "PASS");
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
