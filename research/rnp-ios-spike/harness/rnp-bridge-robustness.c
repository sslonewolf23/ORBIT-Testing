#include "ORBITRNPInReleaseVerifier.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, uint8_t **data, size_t *length) {
    FILE *file = fopen(path, "rb");
    long size;
    uint8_t *buffer;
    if (!file) return 0;
    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) <= 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }
    buffer = (uint8_t *) malloc((size_t) size);
    if (!buffer) {
        fclose(file);
        return 0;
    }
    if (fread(buffer, 1, (size_t) size, file) != (size_t) size) {
        free(buffer);
        fclose(file);
        return 0;
    }
    if (fclose(file) != 0) {
        free(buffer);
        return 0;
    }
    *data = buffer;
    *length = (size_t) size;
    return 1;
}

int main(int argc, char **argv) {
    uint8_t *key = NULL, *message = NULL, *malformed_key = NULL;
    size_t key_len = 0, message_len = 0, malformed_key_len = 0;
    orbit_rnp_verify_result result;
    orbit_rnp_verify_code code;
    int failures = 0;

    if (argc != 5) {
        fprintf(stderr, "usage: %s <trusted-keyring> <valid-InRelease> <fingerprint> <truncated-keyring>\n", argv[0]);
        return 64;
    }
    if (!read_file(argv[1], &key, &key_len) ||
        !read_file(argv[2], &message, &message_len) ||
        !read_file(argv[4], &malformed_key, &malformed_key_len)) {
        fprintf(stderr, "could not read robustness fixtures\n");
        free(key); free(message); free(malformed_key);
        return 64;
    }

    /* Repeated valid calls must remain stable and release all per-call RNP state. */
    for (unsigned i = 0; i < 128; ++i) {
        memset(&result, 0xA5, sizeof(result));
        code = orbit_rnp_verify_inrelease(message, message_len, key, key_len,
                                           argv[3], &result);
        if (code != ORBIT_RNP_VERIFY_VALID || result.code != ORBIT_RNP_VERIFY_VALID) {
            fprintf(stderr, "valid iteration %u failed: return=%d result=%d error=%s\n",
                    i, (int) code, (int) result.code, result.error);
            ++failures;
            break;
        }

        /* Alternate malformed input to expose stale success state across calls. */
        memset(&result, 0xA5, sizeof(result));
        code = orbit_rnp_verify_inrelease(message, message_len,
                                           malformed_key, malformed_key_len,
                                           argv[3], &result);
        if (code == ORBIT_RNP_VERIFY_VALID || result.code != code) {
            fprintf(stderr, "malformed-key iteration %u did not fail closed\n", i);
            ++failures;
            break;
        }
    }

    /* Invalid arguments must reset the output and return a structured failure. */
    memset(&result, 0xA5, sizeof(result));
    code = orbit_rnp_verify_inrelease(NULL, message_len, key, key_len, argv[3], &result);
    if (code != ORBIT_RNP_VERIFY_INVALID_ARGUMENT ||
        result.code != ORBIT_RNP_VERIFY_INVALID_ARGUMENT ||
        result.error[0] == '\0' || result.signature_count != 0 ||
        result.public_key_count != 0) {
        fprintf(stderr, "null-message argument contract failed\n");
        ++failures;
    }

    code = orbit_rnp_verify_inrelease(message, message_len, key, key_len, argv[3], NULL);
    if (code != ORBIT_RNP_VERIFY_INVALID_ARGUMENT) {
        fprintf(stderr, "null-result argument contract failed\n");
        ++failures;
    }

    free(key);
    free(message);
    free(malformed_key);
    if (failures) {
        printf("decision=FAIL\nfailures=%d\n", failures);
        return 1;
    }
    printf("decision=PASS\nrepeated_valid_calls=128\ninterleaved_malformed_calls=128\ninvalid_argument_checks=2\n");
    return 0;
}
