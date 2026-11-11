#include "rnp-fault-injection.h"
#include <rnp/rnp.h>
#include <rnp/rnp_err.h>

static orbit_fault_point target = ORBIT_FAULT_COUNT;
static unsigned target_occurrence = 0;
static unsigned target_seen = 0;
static int triggered = 0;

void orbit_fault_arm(orbit_fault_point point, unsigned occurrence) {
 target = point; target_occurrence = occurrence; target_seen = 0; triggered = 0;
}
int orbit_fault_was_triggered(void) { return triggered; }
const char *orbit_fault_name(orbit_fault_point p) {
 static const char *names[] = {
  "ffi_create","input_from_memory","load_keys","get_public_key_count",
  "output_to_null","op_verify_create","op_verify_set_flags","op_verify_execute",
  "get_signature_count","get_signature_at","signature_get_status","signature_get_handle",
  "signature_is_valid","signature_get_hash","signature_get_times","signature_get_key",
  "key_get_fprint","key_get_alg","key_get_curve","key_is_sub","key_get_primary_fprint",
  "locate_primary","key_is_valid","key_is_revoked","key_get_creation","key_valid_till64",
  "key_allows_usage"
 };
 return p < ORBIT_FAULT_COUNT ? names[p] : "unknown";
}
static int fail_after_success(orbit_fault_point p, rnp_result_t rc) {
 if (rc != RNP_SUCCESS || target != p) return 0;
 ++target_seen;
 if (target_seen == target_occurrence) { triggered = 1; return 1; }
 return 0;
}
/* The wrapped names are referenced only by this test binary. */
rnp_result_t __real_rnp_ffi_create(rnp_ffi_t *, const char *, const char *);
rnp_result_t __real_rnp_input_from_memory(rnp_input_t *, const uint8_t *, size_t, bool);
rnp_result_t __real_rnp_load_keys(rnp_ffi_t, const char *, rnp_input_t, uint32_t);
rnp_result_t __real_rnp_get_public_key_count(rnp_ffi_t, size_t *);
rnp_result_t __real_rnp_output_to_null(rnp_output_t *);
rnp_result_t __real_rnp_op_verify_create(rnp_op_verify_t *, rnp_ffi_t, rnp_input_t, rnp_output_t);
rnp_result_t __real_rnp_op_verify_set_flags(rnp_op_verify_t, uint32_t);
rnp_result_t __real_rnp_op_verify_execute(rnp_op_verify_t);
rnp_result_t __real_rnp_op_verify_get_signature_count(rnp_op_verify_t, size_t *);
rnp_result_t __real_rnp_op_verify_get_signature_at(rnp_op_verify_t, size_t, rnp_op_verify_signature_t *);
rnp_result_t __real_rnp_op_verify_signature_get_status(rnp_op_verify_signature_t);
rnp_result_t __real_rnp_op_verify_signature_get_handle(rnp_op_verify_signature_t, rnp_signature_handle_t *);
rnp_result_t __real_rnp_signature_is_valid(rnp_signature_handle_t, uint32_t);
rnp_result_t __real_rnp_op_verify_signature_get_hash(rnp_op_verify_signature_t, char **);
rnp_result_t __real_rnp_op_verify_signature_get_times(rnp_op_verify_signature_t, uint32_t *, uint32_t *);
rnp_result_t __real_rnp_op_verify_signature_get_key(rnp_op_verify_signature_t, rnp_key_handle_t *);
rnp_result_t __real_rnp_key_get_fprint(rnp_key_handle_t, char **);
rnp_result_t __real_rnp_key_get_alg(rnp_key_handle_t, char **);
rnp_result_t __real_rnp_key_get_curve(rnp_key_handle_t, char **);
rnp_result_t __real_rnp_key_is_sub(rnp_key_handle_t, bool *);
rnp_result_t __real_rnp_key_get_primary_fprint(rnp_key_handle_t, char **);
rnp_result_t __real_rnp_locate_key(rnp_ffi_t, const char *, const char *, rnp_key_handle_t *);
rnp_result_t __real_rnp_key_is_valid(rnp_key_handle_t, bool *);
rnp_result_t __real_rnp_key_is_revoked(rnp_key_handle_t, bool *);
rnp_result_t __real_rnp_key_get_creation(rnp_key_handle_t, uint32_t *);
rnp_result_t __real_rnp_key_valid_till64(rnp_key_handle_t, uint64_t *);
rnp_result_t __real_rnp_key_allows_usage(rnp_key_handle_t, const char *, bool *);

#define WRAP_RETURN(name, p, params, args) \
 rnp_result_t __wrap_##name params { rnp_result_t rc = __real_##name args; \
 return fail_after_success(p, rc) ? (rnp_result_t)1U : rc; }

WRAP_RETURN(rnp_ffi_create, ORBIT_FAULT_FFI_CREATE,
 (rnp_ffi_t *ffi, const char *pub, const char *sec), (ffi,pub,sec))
WRAP_RETURN(rnp_input_from_memory, ORBIT_FAULT_INPUT_MEMORY,
 (rnp_input_t *in, const uint8_t *buf, size_t len, bool copy), (in,buf,len,copy))
WRAP_RETURN(rnp_load_keys, ORBIT_FAULT_LOAD_KEYS,
 (rnp_ffi_t ffi, const char *format, rnp_input_t in, uint32_t flags), (ffi,format,in,flags))
WRAP_RETURN(rnp_get_public_key_count, ORBIT_FAULT_PUBLIC_KEY_COUNT,
 (rnp_ffi_t ffi, size_t *count), (ffi,count))
WRAP_RETURN(rnp_output_to_null, ORBIT_FAULT_OUTPUT_NULL,
 (rnp_output_t *out), (out))
WRAP_RETURN(rnp_op_verify_create, ORBIT_FAULT_VERIFY_CREATE,
 (rnp_op_verify_t *op, rnp_ffi_t ffi, rnp_input_t in, rnp_output_t out), (op,ffi,in,out))
WRAP_RETURN(rnp_op_verify_set_flags, ORBIT_FAULT_VERIFY_SET_FLAGS,
 (rnp_op_verify_t op, uint32_t flags), (op,flags))
WRAP_RETURN(rnp_op_verify_execute, ORBIT_FAULT_VERIFY_EXECUTE,
 (rnp_op_verify_t op), (op))
WRAP_RETURN(rnp_op_verify_get_signature_count, ORBIT_FAULT_SIGNATURE_COUNT,
 (rnp_op_verify_t op, size_t *count), (op,count))
WRAP_RETURN(rnp_op_verify_get_signature_at, ORBIT_FAULT_SIGNATURE_AT,
 (rnp_op_verify_t op, size_t index, rnp_op_verify_signature_t *sig), (op,index,sig))
WRAP_RETURN(rnp_op_verify_signature_get_status, ORBIT_FAULT_SIGNATURE_STATUS,
 (rnp_op_verify_signature_t sig), (sig))
WRAP_RETURN(rnp_op_verify_signature_get_handle, ORBIT_FAULT_SIGNATURE_HANDLE,
 (rnp_op_verify_signature_t sig, rnp_signature_handle_t *handle), (sig,handle))
WRAP_RETURN(rnp_signature_is_valid, ORBIT_FAULT_SIGNATURE_VALID,
 (rnp_signature_handle_t sig, uint32_t flags), (sig,flags))
WRAP_RETURN(rnp_op_verify_signature_get_hash, ORBIT_FAULT_SIGNATURE_HASH,
 (rnp_op_verify_signature_t sig, char **hash), (sig,hash))
WRAP_RETURN(rnp_op_verify_signature_get_times, ORBIT_FAULT_SIGNATURE_TIMES,
 (rnp_op_verify_signature_t sig, uint32_t *created, uint32_t *expires), (sig,created,expires))
WRAP_RETURN(rnp_op_verify_signature_get_key, ORBIT_FAULT_SIGNATURE_KEY,
 (rnp_op_verify_signature_t sig, rnp_key_handle_t *key), (sig,key))
WRAP_RETURN(rnp_key_get_fprint, ORBIT_FAULT_KEY_FPRINT,
 (rnp_key_handle_t key, char **fp), (key,fp))
WRAP_RETURN(rnp_key_get_alg, ORBIT_FAULT_KEY_ALG,
 (rnp_key_handle_t key, char **alg), (key,alg))
WRAP_RETURN(rnp_key_get_curve, ORBIT_FAULT_KEY_CURVE,
 (rnp_key_handle_t key, char **curve), (key,curve))
WRAP_RETURN(rnp_key_is_sub, ORBIT_FAULT_KEY_IS_SUB,
 (rnp_key_handle_t key, bool *is_sub), (key,is_sub))
WRAP_RETURN(rnp_key_get_primary_fprint, ORBIT_FAULT_PRIMARY_FPRINT,
 (rnp_key_handle_t key, char **fp), (key,fp))
WRAP_RETURN(rnp_locate_key, ORBIT_FAULT_LOCATE_PRIMARY,
 (rnp_ffi_t ffi, const char *type, const char *id, rnp_key_handle_t *key), (ffi,type,id,key))
WRAP_RETURN(rnp_key_is_valid, ORBIT_FAULT_KEY_IS_VALID,
 (rnp_key_handle_t key, bool *valid), (key,valid))
WRAP_RETURN(rnp_key_is_revoked, ORBIT_FAULT_KEY_IS_REVOKED,
 (rnp_key_handle_t key, bool *revoked), (key,revoked))
WRAP_RETURN(rnp_key_get_creation, ORBIT_FAULT_KEY_CREATION,
 (rnp_key_handle_t key, uint32_t *created), (key,created))
WRAP_RETURN(rnp_key_valid_till64, ORBIT_FAULT_KEY_VALID_TILL,
 (rnp_key_handle_t key, uint64_t *until), (key,until))
WRAP_RETURN(rnp_key_allows_usage, ORBIT_FAULT_KEY_ALLOWS_USAGE,
 (rnp_key_handle_t key, const char *usage, bool *allowed), (key,usage,allowed))

