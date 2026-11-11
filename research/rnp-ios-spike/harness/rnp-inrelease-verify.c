#include <rnp/rnp.h>
#include <rnp/rnp_err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

#define MAX_IMPORTED_PUBLIC_KEYS 32u

#define CHECK(call, label) do { \
  rnp_result_t result_ = (call); \
  if (result_ != RNP_SUCCESS) { \
    fprintf(stderr, "%s failed: 0x%x\\n", (label), (unsigned)result_); \
    goto cleanup; \
  } \
} while (0)

static void free_buffer(char **value) {
  if (*value) {
    rnp_buffer_destroy(*value);
    *value = NULL;
  }
}

static bool bounded_regular_file(const char *path, uint64_t maximum, bool allow_empty) {
  struct stat info;
  if (stat(path, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0 ||
      (uint64_t)info.st_size > maximum || (!allow_empty && info.st_size == 0)) {
    return false;
  }
  return true;
}

static bool valid_fingerprint(const char *value) {
  size_t length = strlen(value);
  if (length != 40 && length != 64) return false;
  for (size_t i = 0; i < length; ++i) {
    char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F'))) return false;
  }
  return true;
}

static bool allowed_hash(const char *hash) {
  return strcasecmp(hash, "SHA256") == 0 || strcasecmp(hash, "SHA-256") == 0 ||
         strcasecmp(hash, "SHA384") == 0 || strcasecmp(hash, "SHA-384") == 0 ||
         strcasecmp(hash, "SHA512") == 0 || strcasecmp(hash, "SHA-512") == 0;
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s <public-keyring.gpg> <InRelease> <trusted-primary-fingerprint>\\n", argv[0]);
    return 64;
  }

  const char *key_path = argv[1];
  const char *message_path = argv[2];
  const char *trusted_fingerprint = argv[3];
  if (!bounded_regular_file(key_path, 4u * 1024u * 1024u, true) ||
      !bounded_regular_file(message_path, 16u * 1024u * 1024u, false) ||
      !valid_fingerprint(trusted_fingerprint)) {
    fprintf(stderr, "input rejected: keyring <=4 MiB, InRelease 1..16 MiB, valid fingerprint required\\n");
    return 64;
  }

  rnp_ffi_t ffi = NULL;
  rnp_input_t key_input = NULL;
  rnp_input_t message_input = NULL;
  rnp_output_t output = NULL;
  rnp_op_verify_t operation = NULL;
  rnp_key_handle_t signing_key = NULL;
  rnp_key_handle_t primary_key = NULL;
  char *signing_fingerprint = NULL;
  char *primary_fingerprint = NULL;
  char *hash = NULL;
  char *algorithm = NULL;
  char *curve = NULL;
  bool is_subkey = false;
  bool key_valid = false;
  bool key_revoked = false;
  bool signing_allowed = false;
  bool primary_valid = false;
  bool primary_revoked = false;
  size_t signature_count = 0;
  size_t imported_public_key_count = 0;
  int exit_code = 2;
  rnp_result_t execute_result = 0;

  CHECK(rnp_ffi_create(&ffi, "GPG", "GPG"), "ffi_create");
  CHECK(rnp_input_from_path(&key_input, key_path), "key_input");
  CHECK(rnp_load_keys(ffi, "GPG", key_input, RNP_LOAD_SAVE_PUBLIC_KEYS), "load_public_keys");
  CHECK(rnp_get_public_key_count(ffi, &imported_public_key_count), "public_key_count");
  printf("public_key_count=%zu\\n", imported_public_key_count);
  if (imported_public_key_count == 0 || imported_public_key_count > MAX_IMPORTED_PUBLIC_KEYS) {
    fprintf(stderr, "input rejected: public-key bundle exceeds %u keys\\n", MAX_IMPORTED_PUBLIC_KEYS);
    goto cleanup;
  }
  CHECK(rnp_input_from_path(&message_input, message_path), "message_input");
  CHECK(rnp_output_to_null(&output), "output_to_null");
  CHECK(rnp_op_verify_create(&operation, ffi, message_input, output), "verify_create");
  CHECK(rnp_op_verify_set_flags(operation, RNP_VERIFY_REQUIRE_ALL_SIGS), "require_all_signatures");

  execute_result = rnp_op_verify_execute(operation);
  if (rnp_op_verify_get_signature_count(operation, &signature_count) != RNP_SUCCESS) {
    fprintf(stderr, "signature count unavailable; fail closed\\n");
    goto cleanup;
  }
  printf("execute_result=0x%x\\nsignature_count=%zu\\n",
         (unsigned)execute_result, signature_count);
  if (signature_count != 1) {
    printf("decision=BLOCK\\nreason=signature_count_not_exactly_one\\n");
    exit_code = 1;
    goto cleanup;
  }

  rnp_op_verify_signature_t signature = NULL;
  CHECK(rnp_op_verify_get_signature_at(operation, 0, &signature), "get_signature");
  rnp_result_t signature_status = rnp_op_verify_signature_get_status(signature);
  printf("signature_status=0x%x\\n", (unsigned)signature_status);
  if (execute_result != RNP_SUCCESS || signature_status != RNP_SUCCESS) {
    printf("decision=BLOCK\\nreason=signature_not_valid\\n");
    exit_code = 1;
    goto cleanup;
  }

  CHECK(rnp_op_verify_signature_get_key(signature, &signing_key), "get_signing_key");
  CHECK(rnp_key_get_fprint(signing_key, &signing_fingerprint), "signer_fingerprint");
  CHECK(rnp_key_is_sub(signing_key, &is_subkey), "is_subkey");
  if (is_subkey) {
    CHECK(rnp_key_get_primary_fprint(signing_key, &primary_fingerprint), "primary_fingerprint");
    CHECK(rnp_locate_key(ffi, "fingerprint", primary_fingerprint, &primary_key), "locate_primary_key");
    if (!primary_key) {
      fprintf(stderr, "primary key missing from supplied local keyring; fail closed\\n");
      goto cleanup;
    }
    CHECK(rnp_key_is_valid(primary_key, &primary_valid), "primary_key_validity");
    CHECK(rnp_key_is_revoked(primary_key, &primary_revoked), "primary_key_revocation");
  } else {
    primary_valid = true;
  }

  CHECK(rnp_key_is_valid(signing_key, &key_valid), "key_validity");
  CHECK(rnp_key_is_revoked(signing_key, &key_revoked), "key_revocation");
  CHECK(rnp_key_allows_usage(signing_key, "sign", &signing_allowed), "key_signing_usage");
  CHECK(rnp_key_get_alg(signing_key, &algorithm), "key_algorithm");
  CHECK(rnp_key_get_curve(signing_key, &curve), "key_curve");
  CHECK(rnp_op_verify_signature_get_hash(signature, &hash), "signature_hash");

  uint64_t key_valid_until = 0;
  uint32_t key_created = 0;
  uint32_t signature_created = 0;
  uint32_t signature_expires = 0;
  CHECK(rnp_key_valid_till64(signing_key, &key_valid_until), "key_expiration");
  CHECK(rnp_key_get_creation(signing_key, &key_created), "key_creation");
  CHECK(rnp_op_verify_signature_get_times(signature, &signature_created, &signature_expires),
        "signature_times");
  time_t now = time(NULL);
  if (now < 0) {
    fprintf(stderr, "system clock unavailable; fail closed\\n");
    goto cleanup;
  }

  printf("signer_fingerprint=%s\\nprimary_fingerprint=%s\\nsubkey=%s\\n",
         signing_fingerprint, is_subkey ? primary_fingerprint : signing_fingerprint,
         is_subkey ? "true" : "false");
  printf("key_valid=%s\\nkey_valid_until=%llu\\nkey_revoked=%s\\nsigning_allowed=%s\\n",
         key_valid ? "true" : "false", (unsigned long long)key_valid_until,
         key_revoked ? "true" : "false", signing_allowed ? "true" : "false");
  printf("key_created=%u\\nsignature_created=%u\\nsignature_expires=%u\\nhash=%s\\nalgorithm=%s\\ncurve=%s\\n",
         key_created, signature_created, signature_expires, hash, algorithm, curve);

  if (!key_valid || key_revoked || !signing_allowed || !primary_valid || primary_revoked ||
      signature_created < key_created || key_valid_until == 0 ||
      (key_valid_until != UINT64_MAX && (uint64_t)now >= key_valid_until) ||
      (uint64_t)signature_created > (uint64_t)now + 300u ||
      (signature_expires != 0 &&
       (uint64_t)signature_created + (uint64_t)signature_expires <= (uint64_t)now)) {
    printf("decision=BLOCK\\nreason=signing_key_or_signature_lifetime_policy_failed\\n");
    exit_code = 1;
    goto cleanup;
  }
  if (!allowed_hash(hash)) {
    printf("decision=BLOCK\\nreason=hash_not_allowlisted\\n");
    exit_code = 1;
    goto cleanup;
  }
  /* V1 intentionally accepts EdDSA only until other algorithms have dedicated tests. */
  if (strcasecmp(algorithm, "EDDSA") != 0 || strcasecmp(curve, "ed25519") != 0) {
    printf("decision=BLOCK\\nreason=public_key_algorithm_or_curve_not_allowlisted\\n");
    exit_code = 1;
    goto cleanup;
  }

  if (strcasecmp(is_subkey ? primary_fingerprint : signing_fingerprint,
                 trusted_fingerprint) == 0) {
    printf("decision=TRUSTED\\n");
    exit_code = 0;
  } else {
    printf("decision=VALID_BUT_UNTRUSTED\\n");
    exit_code = 3;
  }

cleanup:
  free_buffer(&signing_fingerprint);
  free_buffer(&hash);
  free_buffer(&algorithm);
  free_buffer(&curve);
  free_buffer(&primary_fingerprint);
  if (primary_key) rnp_key_handle_destroy(primary_key);
  if (signing_key) rnp_key_handle_destroy(signing_key);
  if (operation) rnp_op_verify_destroy(operation);
  if (output) rnp_output_destroy(output);
  if (message_input) rnp_input_destroy(message_input);
  if (key_input) rnp_input_destroy(key_input);
  if (ffi) rnp_ffi_destroy(ffi);
  return exit_code;
}
