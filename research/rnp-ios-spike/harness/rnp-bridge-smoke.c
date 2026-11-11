#include "ORBITRNPInReleaseVerifier.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_KEY_BYTES (4U * 1024U * 1024U)
#define MAX_INRELEASE_BYTES (16U * 1024U * 1024U)

static int read_bounded_file(const char *path,
                             size_t maximum,
                             uint8_t **data,
                             size_t *length) {
    FILE *file = NULL;
    long file_size = 0;
    uint8_t *buffer = NULL;

    *data = NULL;
    *length = 0;
    file = fopen(path, "rb");
    if (!file) return 0;
    if (fseek(file, 0, SEEK_END) != 0 || (file_size = ftell(file)) < 0 ||
        (unsigned long) file_size > maximum || file_size == 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }

    buffer = (uint8_t *) malloc((size_t) file_size);
    if (!buffer) {
        fclose(file);
        return 0;
    }
    if (fread(buffer, 1, (size_t) file_size, file) != (size_t) file_size) {
        free(buffer);
        fclose(file);
        return 0;
    }
    if (fclose(file) != 0) {
        free(buffer);
        return 0;
    }

    *data = buffer;
    *length = (size_t) file_size;
    return 1;
}

int main(int argc, char **argv) {
    uint8_t *key_data = NULL;
    uint8_t *inrelease_data = NULL;
    size_t key_length = 0;
    size_t inrelease_length = 0;
    orbit_rnp_verify_result result = {0};
    orbit_rnp_verify_code code;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <public-keyring> <InRelease> <expected-primary-fingerprint>\n", argv[0]);
        return 64;
    }
    if (!read_bounded_file(argv[1], MAX_KEY_BYTES, &key_data, &key_length) ||
        !read_bounded_file(argv[2], MAX_INRELEASE_BYTES, &inrelease_data, &inrelease_length)) {
        fprintf(stderr, "input rejected: expected non-empty regular files within configured size limits\n");
        printf("decision=BLOCK\nreason=input_size_or_file_validation_failed\n");
        free(key_data);
        free(inrelease_data);
        return 64;
    }

    code = orbit_rnp_verify_inrelease(inrelease_data,
                                      inrelease_length,
                                      key_data,
                                      key_length,
                                      argv[3],
                                      &result);
    printf("bridge_code=%d\nsignature_count=%zu\npublic_key_count=%zu\n",
           (int) code, result.signature_count, result.public_key_count);
    printf("primary_fingerprint=%s\nsigning_fingerprint=%s\nhash=%s\n",
           result.primary_fingerprint, result.signing_fingerprint, result.hash_algorithm);
    printf("decision=%s\nreason=%s\n",
           code == ORBIT_RNP_VERIFY_VALID ? "ACCEPT" : "BLOCK",
           result.error);

    free(key_data);
    free(inrelease_data);
    return code == ORBIT_RNP_VERIFY_VALID ? 0 : 1;
}
