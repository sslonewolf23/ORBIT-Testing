# RNP 0.18.1 verifier ownership audit

Date: 2026-11-11

Scope: `research/rnp-ios-spike/bridge/ORBITRNPInReleaseVerifier.c` against pinned RNP source commit `aad1892e4d8423398a0b973bd0a7e4544c359afc`.

This is a source-level ownership audit, not a formal security review or iOS validation.

## Ownership findings

| Value | RNP contract / source behavior | Verifier cleanup |
|---|---|---|
| `rnp_ffi_t` | Created by `rnp_ffi_create`; released by `rnp_ffi_destroy` | Destroyed when non-NULL |
| `rnp_input_t` key/document inputs | Created by `rnp_input_from_memory`; released by `rnp_input_destroy` | Both released when non-NULL |
| `rnp_output_t` null sink | Created by `rnp_output_to_null`; released by `rnp_output_destroy` | Released when non-NULL |
| `rnp_op_verify_t` | Created by `rnp_op_verify_create`; owns its verification context and borrowed signature contexts | Destroyed after signature/key handles and before input/FFI |
| `rnp_op_verify_signature_t` | Borrowed from verification operation by `rnp_op_verify_get_signature_at` | Not separately destroyed; operation owns its lifetime |
| `rnp_signature_handle_t` | Separately allocated by `rnp_op_verify_signature_get_handle`; API requires `rnp_signature_handle_destroy` | Destroyed when non-NULL |
| `rnp_key_handle_t` from `rnp_op_verify_signature_get_key` | Pinned implementation's `get_signer_handle` allocates a new handle wrapper | Destroyed when non-NULL |
| `rnp_key_handle_t` from `rnp_locate_key` | API documentation explicitly requires `rnp_key_handle_destroy` | Destroyed when non-NULL |
| Fingerprint/hash/algorithm/curve strings | API documentation requires `rnp_buffer_destroy` | Destroyed when non-NULL; primary fingerprint alias is not double-freed |
| Caller input buffers | Borrowed by verifier; memory inputs are configured with copy enabled | Never freed or modified by verifier |

## Error-path review

- All owned handles and allocated strings are initialized to NULL before use.
- All post-initialization failures converge on one cleanup label.
- Cleanup destroys signature/key handles before the verification operation, then destroys inputs and the FFI.
- When the primary signer is not a subkey, `primary_fingerprint` aliases `signing_fingerprint`; pointer identity prevents a double free.
- The result structure is reset before argument validation; invalid inputs return a structured error when a result structure is supplied.
- A failed `rnp_ffi_create` reaches cleanup safely with a NULL FFI.

## Conclusion

No ownership leak, double-free, or borrowed-handle destruction defect was identified in the reviewed paths. The signing-key handle returned by `rnp_op_verify_signature_get_key` is newly allocated in the pinned RNP implementation and is correctly released by the verifier; a source comment now records this subtle ownership rule.

Existing sanitizer and repeated-call tests provide supporting runtime evidence, but do not prove every allocation-failure path. Follow-up work should add controlled fault injection where practical and expand tests for failures at each RNP initialization/verification stage.

## Evidence boundaries

- This audit is limited to the pinned RNP 0.18.1 source and the verifier implementation.
- The latest completed host CI run before this audit was Run #55. The ownership-comment commit still requires a fresh CI run.
- This does not establish iOS/device behavior, repository trust policy, package metadata integrity, or installation safety.
