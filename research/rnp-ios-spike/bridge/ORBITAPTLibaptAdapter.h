#ifndef ORBIT_APT_LIBAPT_ADAPTER_H
#define ORBIT_APT_LIBAPT_ADAPTER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Copy the effective Dir::State::status path from an initialized libapt-pkg
 * Configuration object. The object must have completed pkgInitConfig() and
 * pkgInitSystem() using the same config inputs/options as the target APT
 * invocation. The opaque pointer is a const Configuration*. */
int orbit_apt_copy_effective_status_path(
    const void *initialized_apt_configuration,
    char *output,
    size_t output_capacity);

#ifdef __cplusplus
}
#endif
#endif
