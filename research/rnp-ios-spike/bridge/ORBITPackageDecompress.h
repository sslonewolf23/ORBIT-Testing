#ifndef ORBIT_PACKAGE_DECOMPRESS_H
#define ORBIT_PACKAGE_DECOMPRESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ORBIT_DECOMPRESS_INPUT_MAX (512ULL * 1024ULL * 1024ULL)
#define ORBIT_DECOMPRESS_OUTPUT_MAX (256ULL * 1024ULL * 1024ULL)
#define ORBIT_DECOMPRESS_CHUNK_BYTES (64U * 1024U)
#define ORBIT_DECOMPRESS_RATIO_MAX 200U
#define ORBIT_DECOMPRESS_MEMORY_MAX (64ULL * 1024ULL * 1024ULL)
#define ORBIT_DECOMPRESS_MAX_STEPS 16384U

typedef enum {
    ORBIT_DECOMPRESS_GZIP = 1,
    ORBIT_DECOMPRESS_XZ,
    ORBIT_DECOMPRESS_BZIP2,
    ORBIT_DECOMPRESS_ZSTD
} orbit_decompress_format;

typedef enum {
    ORBIT_DECOMPRESS_OK = 0,
    ORBIT_DECOMPRESS_INVALID_ARGUMENT,
    ORBIT_DECOMPRESS_LIMIT,
    ORBIT_DECOMPRESS_MALFORMED,
    ORBIT_DECOMPRESS_TRAILING_DATA,
    ORBIT_DECOMPRESS_SINK_ERROR,
    ORBIT_DECOMPRESS_UNSUPPORTED
} orbit_decompress_code;

typedef bool (*orbit_decompress_sink)(void *context,
                                      const uint8_t *bytes,
                                      size_t length);

/* Decodes exactly one compressed stream in bounded output chunks and decoder
 * iterations. Rejects truncation, trailing bytes, and concatenated streams.
 * The sink must consume/copy each chunk before returning. */
orbit_decompress_code orbit_package_decompress_stream(
    orbit_decompress_format format,
    const uint8_t *input,
    size_t input_length,
    uint64_t output_limit,
    orbit_decompress_sink sink,
    void *sink_context,
    uint64_t *output_length);

#endif
