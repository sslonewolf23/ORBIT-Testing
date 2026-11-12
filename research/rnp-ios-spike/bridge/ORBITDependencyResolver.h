#ifndef ORBIT_DEPENDENCY_RESOLVER_H
#define ORBIT_DEPENDENCY_RESOLVER_H

#include "ORBITPackagesIndex.h"

#define ORBIT_DEPENDENCY_PLAN_MAX 4096U

typedef enum {
    ORBIT_DEPENDENCY_OK = 0,
    ORBIT_DEPENDENCY_INVALID_ARGUMENT,
    ORBIT_DEPENDENCY_PACKAGE_NOT_FOUND,
    ORBIT_DEPENDENCY_UNSATISFIED,
    ORBIT_DEPENDENCY_CONFLICT,
    ORBIT_DEPENDENCY_CYCLE,
    ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION,
    ORBIT_DEPENDENCY_LIMIT
} orbit_dependency_code;

typedef struct {
    const orbit_package_record **ordered;
    size_t count;
} orbit_dependency_plan;

/* Debian version comparison: -1, 0, +1; false for malformed versions. */
bool orbit_debian_version_compare(const char *left, const char *right,
                                  int *comparison);

/* Builds a dependency-first installation order for one requested package.
 * Installed packages satisfy dependencies but are not added to the plan.
 * Unsupported relationship syntax fails closed. The caller owns plan.ordered. */
orbit_dependency_code orbit_dependency_plan_build(
    const orbit_packages_index *available,
    const orbit_package_record *const *installed,
    size_t installed_count,
    const char *requested_package,
    const char *target_architecture,
    orbit_dependency_plan *plan);

void orbit_dependency_plan_destroy(orbit_dependency_plan *plan);

#endif
