#include "ORBITPackageArchive.h"
#include "ORBITPackageDecompress.h"

#include <stddef.h>
#include <stdint.h>

#define ORBIT_FUZZ_INPUT_MAX (1024U * 1024U)
#define ORBIT_FUZZ_OUTPUT_MAX (1024U * 1024U)

static bool discard_output(void *context, const uint8_t *bytes, size_t length) {
    (void)context;
    (void)bytes;
    (void)length;
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data || size == 0U || size > ORBIT_FUZZ_INPUT_MAX) return 0;

    orbit_archive_report report;
    (void)orbit_package_archive_inspect_deb(data, size, &report);

    const size_t chunk_sizes[] = { 1U, 511U, 512U, 513U, 4093U };
    size_t chunk_size = chunk_sizes[data[0] % (sizeof(chunk_sizes) / sizeof(chunk_sizes[0]))];
    (void)orbit_package_archive_test_inspect_tar_chunks(
        data, size, chunk_size, &report);

    const orbit_decompress_format formats[] = {
        ORBIT_DECOMPRESS_GZIP,
        ORBIT_DECOMPRESS_XZ,
        ORBIT_DECOMPRESS_BZIP2,
        ORBIT_DECOMPRESS_ZSTD
    };
    for (size_t i = 0U; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        uint64_t output_length = 0U;
        (void)orbit_package_decompress_stream(
            formats[i], data, size, ORBIT_FUZZ_OUTPUT_MAX,
            discard_output, NULL, &output_length);
    }
    return 0;
}
