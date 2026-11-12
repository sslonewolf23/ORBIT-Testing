#include "ORBITPackageDecompress.h"

#include <bzlib.h>
#include <lzma.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <zstd.h>

static bool account_output(uint64_t *total, size_t produced,
                           size_t input_length, uint64_t output_limit) {
    if (produced > UINT64_MAX - *total) return false;
    uint64_t next = *total + (uint64_t)produced;
    if (next > output_limit || next > ORBIT_DECOMPRESS_OUTPUT_MAX) return false;
    if (input_length != 0U &&
        next > (uint64_t)input_length * ORBIT_DECOMPRESS_RATIO_MAX) return false;
    *total = next;
    return true;
}

static orbit_decompress_code emit_output(
    uint64_t *total, const uint8_t *buffer, size_t produced,
    size_t input_length, uint64_t output_limit,
    orbit_decompress_sink sink, void *context) {
    if (!account_output(total, produced, input_length, output_limit))
        return ORBIT_DECOMPRESS_LIMIT;
    if (produced != 0U && !sink(context, buffer, produced))
        return ORBIT_DECOMPRESS_SINK_ERROR;
    return ORBIT_DECOMPRESS_OK;
}

static orbit_decompress_code decode_gzip(
    const uint8_t *input, size_t length, uint64_t limit,
    orbit_decompress_sink sink, void *context, uint64_t *total) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, 15 + 16) != Z_OK) return ORBIT_DECOMPRESS_UNSUPPORTED;
    uint8_t *out = (uint8_t *)malloc(ORBIT_DECOMPRESS_CHUNK_BYTES);
    if (!out) { inflateEnd(&stream); return ORBIT_DECOMPRESS_LIMIT; }
    stream.next_in = (Bytef *)input;
    stream.avail_in = (uInt)length;
    orbit_decompress_code result = ORBIT_DECOMPRESS_MALFORMED;
    for (;;) {
        stream.next_out = out;
        stream.avail_out = ORBIT_DECOMPRESS_CHUNK_BYTES;
        int status = inflate(&stream, Z_NO_FLUSH);
        size_t produced = ORBIT_DECOMPRESS_CHUNK_BYTES - stream.avail_out;
        result = emit_output(total, out, produced, length, limit, sink, context);
        if (result != ORBIT_DECOMPRESS_OK) break;
        if (status == Z_STREAM_END) {
            result = stream.avail_in == 0U ? ORBIT_DECOMPRESS_OK :
                     ORBIT_DECOMPRESS_TRAILING_DATA;
            break;
        }
        if (status != Z_OK || (produced == 0U && stream.avail_in == 0U)) {
            result = ORBIT_DECOMPRESS_MALFORMED;
            break;
        }
    }
    free(out);
    inflateEnd(&stream);
    return result;
}

static orbit_decompress_code decode_bzip2(
    const uint8_t *input, size_t length, uint64_t limit,
    orbit_decompress_sink sink, void *context, uint64_t *total) {
    bz_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (BZ2_bzDecompressInit(&stream, 0, 0) != BZ_OK)
        return ORBIT_DECOMPRESS_UNSUPPORTED;
    uint8_t *out = (uint8_t *)malloc(ORBIT_DECOMPRESS_CHUNK_BYTES);
    if (!out) { BZ2_bzDecompressEnd(&stream); return ORBIT_DECOMPRESS_LIMIT; }
    stream.next_in = (char *)input;
    stream.avail_in = (unsigned int)length;
    orbit_decompress_code result = ORBIT_DECOMPRESS_MALFORMED;
    for (;;) {
        stream.next_out = (char *)out;
        stream.avail_out = ORBIT_DECOMPRESS_CHUNK_BYTES;
        int status = BZ2_bzDecompress(&stream);
        size_t produced = ORBIT_DECOMPRESS_CHUNK_BYTES - stream.avail_out;
        result = emit_output(total, out, produced, length, limit, sink, context);
        if (result != ORBIT_DECOMPRESS_OK) break;
        if (status == BZ_STREAM_END) {
            result = stream.avail_in == 0U ? ORBIT_DECOMPRESS_OK :
                     ORBIT_DECOMPRESS_TRAILING_DATA;
            break;
        }
        if (status != BZ_OK || (produced == 0U && stream.avail_in == 0U)) {
            result = ORBIT_DECOMPRESS_MALFORMED;
            break;
        }
    }
    free(out);
    BZ2_bzDecompressEnd(&stream);
    return result;
}

static orbit_decompress_code decode_xz(
    const uint8_t *input, size_t length, uint64_t limit,
    orbit_decompress_sink sink, void *context, uint64_t *total) {
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_ret init = lzma_stream_decoder(&stream, ORBIT_DECOMPRESS_MEMORY_MAX, 0U);
    if (init != LZMA_OK) return ORBIT_DECOMPRESS_UNSUPPORTED;
    uint8_t *out = (uint8_t *)malloc(ORBIT_DECOMPRESS_CHUNK_BYTES);
    if (!out) { lzma_end(&stream); return ORBIT_DECOMPRESS_LIMIT; }
    stream.next_in = input;
    stream.avail_in = length;
    orbit_decompress_code result = ORBIT_DECOMPRESS_MALFORMED;
    for (;;) {
        stream.next_out = out;
        stream.avail_out = ORBIT_DECOMPRESS_CHUNK_BYTES;
        lzma_ret status = lzma_code(&stream, LZMA_FINISH);
        size_t produced = ORBIT_DECOMPRESS_CHUNK_BYTES - stream.avail_out;
        result = emit_output(total, out, produced, length, limit, sink, context);
        if (result != ORBIT_DECOMPRESS_OK) break;
        if (status == LZMA_STREAM_END) {
            result = stream.avail_in == 0U ? ORBIT_DECOMPRESS_OK :
                     ORBIT_DECOMPRESS_TRAILING_DATA;
            break;
        }
        if (status != LZMA_OK || (produced == 0U && stream.avail_in == 0U)) {
            result = ORBIT_DECOMPRESS_MALFORMED;
            break;
        }
    }
    free(out);
    lzma_end(&stream);
    return result;
}

static orbit_decompress_code decode_zstd(
    const uint8_t *input, size_t length, uint64_t limit,
    orbit_decompress_sink sink, void *context, uint64_t *total) {
    ZSTD_DStream *stream = ZSTD_createDStream();
    if (!stream) return ORBIT_DECOMPRESS_LIMIT;
    size_t status = ZSTD_DCtx_setParameter(stream, ZSTD_d_windowLogMax, 26);
    if (ZSTD_isError(status)) { ZSTD_freeDStream(stream); return ORBIT_DECOMPRESS_UNSUPPORTED; }
    status = ZSTD_initDStream(stream);
    if (ZSTD_isError(status)) { ZSTD_freeDStream(stream); return ORBIT_DECOMPRESS_UNSUPPORTED; }
    uint8_t *out = (uint8_t *)malloc(ORBIT_DECOMPRESS_CHUNK_BYTES);
    if (!out) { ZSTD_freeDStream(stream); return ORBIT_DECOMPRESS_LIMIT; }
    ZSTD_inBuffer in = { input, length, 0U };
    orbit_decompress_code result = ORBIT_DECOMPRESS_MALFORMED;
    bool ended = false;
    while (in.pos < in.size || !ended) {
        ZSTD_outBuffer output = { out, ORBIT_DECOMPRESS_CHUNK_BYTES, 0U };
        size_t before = in.pos;
        status = ZSTD_decompressStream(stream, &output, &in);
        result = emit_output(total, out, output.pos, length, limit, sink, context);
        if (result != ORBIT_DECOMPRESS_OK) break;
        if (ZSTD_isError(status)) { result = ORBIT_DECOMPRESS_MALFORMED; break; }
        if (status == 0U) {
            ended = true;
            result = in.pos == in.size ? ORBIT_DECOMPRESS_OK :
                     ORBIT_DECOMPRESS_TRAILING_DATA;
            break;
        }
        if (in.pos == before && output.pos == 0U) {
            result = ORBIT_DECOMPRESS_MALFORMED;
            break;
        }
    }
    free(out);
    ZSTD_freeDStream(stream);
    return result;
}

orbit_decompress_code orbit_package_decompress_stream(
    orbit_decompress_format format, const uint8_t *input, size_t input_length,
    uint64_t output_limit, orbit_decompress_sink sink, void *sink_context,
    uint64_t *output_length) {
    if (output_length) *output_length = 0U;
    if (!input || input_length == 0U || !sink || !output_length ||
        output_limit == 0U) return ORBIT_DECOMPRESS_INVALID_ARGUMENT;
    if (input_length > ORBIT_DECOMPRESS_INPUT_MAX ||
        output_limit > ORBIT_DECOMPRESS_OUTPUT_MAX)
        return ORBIT_DECOMPRESS_LIMIT;
    uint64_t total = 0U;
    orbit_decompress_code result;
    switch (format) {
        case ORBIT_DECOMPRESS_GZIP:
            result = decode_gzip(input, input_length, output_limit, sink, sink_context, &total);
            break;
        case ORBIT_DECOMPRESS_XZ:
            result = decode_xz(input, input_length, output_limit, sink, sink_context, &total);
            break;
        case ORBIT_DECOMPRESS_BZIP2:
            result = decode_bzip2(input, input_length, output_limit, sink, sink_context, &total);
            break;
        case ORBIT_DECOMPRESS_ZSTD:
            result = decode_zstd(input, input_length, output_limit, sink, sink_context, &total);
            break;
        default:
            return ORBIT_DECOMPRESS_UNSUPPORTED;
    }
    *output_length = total;
    return result;
}
