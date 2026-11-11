# RNP C-FFI Adapter Design Review

**Status: API review plus isolated C verifier draft. No verifier implementation is enabled in the app.**

This document maps the pinned RNP 0.18.1 C API to a future Swift adapter. The main-branch
`UnavailableOpenPGPRepositoryVerifier` must remain the production default until the cross-build,
fixture suite, provenance review, and device tests pass.

## Verification boundary

The adapter must receive the complete raw Debian `InRelease` byte sequence. It must not verify
the Swift parser's extracted `Release` text, a re-serialized form, or normalized line endings.
The existing `ReleaseMetadata.parseInRelease` parser may extract fields for display/index parsing,
but those values remain untrusted until the original complete signed payload has been verified.

RNP's public API provides the required primitives:

- `rnp_ffi_create` / `rnp_ffi_destroy`: create a fresh per-operation FFI context.
- `rnp_input_from_memory`: pass the bounded original `InRelease` bytes.
- `rnp_output_to_null`: discard verified cleartext; do not allocate an unbounded output buffer.
- `rnp_op_verify_create`, `rnp_op_verify_set_flags`, `rnp_op_verify_execute`: execute verification.
- `rnp_op_verify_get_signature_count`, `rnp_op_verify_get_signature_at`,
  `rnp_op_verify_signature_get_status`: enumerate and inspect every signature.
- `rnp_op_verify_signature_get_key`, `rnp_key_get_fprint`,
  `rnp_key_get_primary_fprint`: identify the signing key and its primary key.
- `rnp_op_verify_signature_get_times`, `rnp_op_verify_signature_get_hash`,
  `rnp_key_get_alg`, `rnp_key_allows_usage`: inspect signature time, hash, algorithm and signing use.
- `rnp_key_is_valid`, `rnp_key_is_revoked`, `rnp_key_valid_till64`: check key validity,
  revocation and validity horizon. RNP documents that subkey validity also considers its primary key.

Upstream header reviewed at the pinned source commit:
https://github.com/rnpgp/rnp/blob/aad1892e4d8423398a0b973bd0a7e4544c359afc/include/rnp/rnp.h

## Critical verification semantics

RNP documents that `rnp_op_verify_execute` succeeds by default when at least one signature is
valid. That return value alone is not sufficient for repository trust.

Version-one policy should be deliberately strict:

1. Require exactly one signature in the signed message. Reject zero or multiple signatures until
   multi-signature repository semantics have their own reviewed policy and tests.
2. Set `RNP_VERIFY_REQUIRE_ALL_SIGS` defensively, and still inspect the single signature status.
3. Require signature status `RNP_SUCCESS`; map expired, invalid, unknown, malformed, unsupported,
   and verification errors to distinct fail-closed outcomes.
4. Require the signing key handle and full signing-key fingerprint. If it is a subkey, require the
   primary fingerprint and valid binding to that primary key.
5. Require signing usage, valid key state, non-revoked key/subkey, a signature creation time no
   earlier than the signing key's creation time, acceptable key lifetime, and an explicit
   algorithm/hash allowlist. The current bridge draft applies an initial EdDSA/Ed25519-only key
   policy and SHA-256/384/512 hash policy; compatibility expansion requires separately reviewed
   algorithms and dedicated fixtures. The current experimental harness also rejects keys expired at the
   time of verification; this is a deliberately strict initial policy pending dedicated expiry
   fixtures and review.
6. Enforce a local trust decision separately from cryptographic validity. A valid signature from a
   candidate key that is not trusted may become an explicit warning; it must never become trusted
   merely because RNP verifies it.
7. Do not interpret an unavailable public key as a valid-but-untrusted signature. Without the
   public key, the signature cannot be cryptographically verified and installation must be blocked.

The RNP example uses a key-provider callback that can load keys on demand. Do not implement a
network-backed provider. Load only explicitly imported/candidate keys and locally trusted keys from
a controlled keyring; no automatic keyserver lookup or repository-controlled key import.

## Resource and memory policy

- Reject empty or oversized `InRelease` data before calling RNP. The current draft caps InRelease at 16 MiB and the supplied public-key bundle at 4 MiB.
- Use `rnp_input_from_memory` with a copy or a rigorously scoped immutable buffer lifetime.
- Use `rnp_output_to_null`; do not use `rnp_output_to_memory(..., 0)` because zero means unlimited
  allocation.
- Bound keyring/key import bytes and imported public-key count (maximum 32); reject empty, malformed, or oversized key bundles before signature policy evaluation.
- Create a separate FFI context per verification operation. Do not share mutable FFI/keyring state
  across concurrent repository checks.
- Check every C return code and every returned pointer. Destroy every input/output/operation/key/FFI
  handle and every RNP-allocated buffer on all paths.
- Convert RNP errors into a closed Swift enum; never treat an unknown error as success.

## Proposed Swift result mapping

| RNP outcome | Swift policy result |
| --- | --- |
| One valid signature, allowed key, fingerprint locally trusted | `trustedSigner(fingerprint:)` |
| One valid signature, candidate key available but not trusted | `untrustedSigner(fingerprint:)` |
| No signature / cleartext unsigned | `unsigned` (warning only if verifier itself is available and format is conclusively unsigned) |
| Bad/tampered/expired/revoked/unsupported/ambiguous signature | `invalidSignature` or a more specific blocked reason |
| Missing key, unsupported feature, unavailable backend, parser/FFI error | `unsupported` or `verificationError`; always blocked |

The isolated C bridge draft lives under `research/rnp-ios-spike/bridge/`; it is not linked into the app and has not been compiled or fixture-tested yet. The current `RepositorySignatureVerification` enum may need more specific cases for expired key,
revoked key, unsupported algorithm, malformed signature and ambiguous signatures before production.
Do not collapse these cases into an untrusted-signer warning.

## Required independent fixture suite

Generate fixtures independently with GnuPG and/or Debian tooling, then verify them through RNP:

- valid Debian-style clear-signed InRelease using a trusted signing subkey;
- same valid signature under a key not in the local trust store;
- tampered Release payload and tampered signature armor;
- malformed/truncated armor and malformed cleartext-signature framing;
- expired signature, expired primary key, expired signing subkey;
- revoked primary key and revoked signing subkey;
- wrong signing usage, weak/disallowed hash, unsupported public-key algorithm;
- missing signer key (must not be downgraded to an unsigned/untrusted warning);
- multiple signatures and mixed valid/invalid signatures (must reject under v1 policy);
- dash-escaped lines, CRLF/LF handling and canonical cleartext edge cases.

Record fixture generator versions, public-key fingerprints, exact input hashes and expected result
for each case. Never commit real private keys; generated test-only secret keys should be ephemeral
CI fixtures and never be reused.

## Adoption gates

No RNP package linkage or production verifier activation until:
- device and simulator arm64 builds pass;
- upstream source provenance and all licenses are reviewed (the selected upstream tag is unsigned);
- every fixture passes with no false acceptance;
- trust/keyring persistence and key rotation/revocation policy are implemented and reviewed;
- binary size, memory, performance and concurrency behavior are measured;
- real-device tests pass before any repository installation is enabled.


## Additional import bound

The isolated bridge and host probe now enforce a maximum of 32 imported public keys per supplied key bundle, in addition to the 4 MiB byte limit. This bounds key-import work and avoids treating a byte cap alone as a sufficient resource limit. The check uses RNP's public-key count API after import. This is source-level hardening only; compilation and runtime validation against the pinned build remain outstanding.


## November 11 follow-up: imported-key count bound

The pinned RNP 0.18.1 header exposes `rnp_get_public_key_count`. The isolated bridge and host harness now require at least one and at most 32 imported public keys after loading the bounded public-key bundle. The bridge result reports the imported count for diagnostics. This supplements the existing 4 MiB input cap; it does not replace parser/resource limits inside RNP. The change is source-level only and remains pending compilation and runtime testing.
