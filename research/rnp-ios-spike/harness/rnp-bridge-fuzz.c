#include "ORBITRNPInReleaseVerifier.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *trusted_key;
static size_t trusted_key_length;
static uint8_t *valid_document;
static size_t valid_document_length;
static char trusted_fingerprint[ORBIT_RNP_FINGERPRINT_CAPACITY];

static int load_bytes(const char *path, uint8_t **out, size_t *length) {
    FILE *file;
    long size;
    uint8_t *buffer;
    if (!path || !out || !length || !(file = fopen(path, "rb"))) return 0;
    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) <= 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }
    buffer = (uint8_t *) malloc((size_t) size);
    if (!buffer) { fclose(file); return 0; }
    if (fread(buffer, 1, (size_t) size, file) != (size_t) size) {
        free(buffer); fclose(file); return 0;
    }
    if (fclose(file) != 0) { free(buffer); return 0; }
    *out = buffer;
    *length = (size_t) size;
    return 1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    const char *key_path = getenv("ORBIT_FUZZ_TRUSTED_KEY");
    const char *document_path = getenv("ORBIT_FUZZ_VALID_DOCUMENT");
    const char *fingerprint_path = getenv("ORBIT_FUZZ_FINGERPRINT");
    FILE *fingerprint_file;
    size_t n;
    (void) argc;
    (void) argv;

    if (!load_bytes(key_path, &trusted_key, &trusted_key_length) ||
        !load_bytes(document_path, &valid_document, &valid_document_length) ||
        !fingerprint_path ||
        !(fingerprint_file = fopen(fingerprint_path, "rb"))) {
        fprintf(stderr, "ORBIT fuzz fixture environment is incomplete.\n");
        return -1;
    }
    n = fread(trusted_fingerprint, 1, sizeof(trusted_fingerprint) - 1U, fingerprint_file);
    if (fclose(fingerprint_file) != 0 || n == 0) {
        fprintf(stderr, "Could not read trusted fingerprint fixture.\n");
        return -1;
    }
    while (n > 0 && (trusted_fingerprint[n - 1] == '\n' ||
                     trusted_fingerprint[n - 1] == '\r' ||
                     trusted_fingerprint[n - 1] == ' ')) {
        trusted_fingerprint[--n] = '\0';
    }
    if (n != 40 && n != 64) {
        fprintf(stderr, "Trusted fingerprint fixture has an unexpected length.\n");
        return -1;
    }
    return 0;
}

/*
 * Each mutation is exercised in both parser positions:
 * 1) fuzz bytes as clear-signed InRelease data with a known trusted key;
 * 2) fuzz bytes as an OpenPGP public-key bundle with a known valid document.
 *
 * The verifier's own 16 MiB / 4 MiB limits remain active. Every return must
 * agree with the structured result code; any mismatch is a harness invariant
 * violation and terminates the fuzz run.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    orbit_rnp_verify_result result;
    orbit_rnp_verify_code code;

    if (!data || size == 0) return 0;

    memset(&result, 0xA5, sizeof(result));
    code = orbit_rnp_verify_inrelease(data, size, trusted_key, trusted_key_length,
                                      trusted_fingerprint, &result);
    if (result.code != code) __builtin_trap();

    memset(&result, 0xA5, sizeof(result));
    code = orbit_rnp_verify_inrelease(valid_document, valid_document_length,
                                      data, size, trusted_fingerprint, &result);
    if (result.code != code) __builtin_trap();

    return 0;
}
