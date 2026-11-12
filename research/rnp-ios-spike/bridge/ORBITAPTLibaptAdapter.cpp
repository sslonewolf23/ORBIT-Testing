#include "ORBITAPTLibaptAdapter.h"

#include <apt-pkg/contrib/configuration.h>

#include <cstring>
#include <string>

extern "C" int orbit_apt_copy_effective_status_path(
    const void *initialized_apt_configuration,
    char *output,
    size_t output_capacity) {
    if (!initialized_apt_configuration || !output || output_capacity == 0U)
        return 0;

    try {
        const auto *configuration =
            static_cast<const Configuration *>(initialized_apt_configuration);
        const std::string status_path =
            configuration->FindFile("Dir::State::status");
        if (status_path.empty() || status_path.size() >= output_capacity)
            return 0;
        std::memcpy(output, status_path.data(), status_path.size());
        output[status_path.size()] = '\0';
        return 1;
    } catch (...) {
        return 0;
    }
}
