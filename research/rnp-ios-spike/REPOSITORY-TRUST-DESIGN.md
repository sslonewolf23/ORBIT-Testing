# ORBIT Repository Trust & Metadata Security Design

Status: **Design proposal — not implemented or production-approved**  
Scope: isolated security planning for ORBIT-Testing. No private ORBIT application code, credentials, or production keys belong here.

## 1. Security boundary

The existing RNP bridge verifies a clear-signed Debian-style InRelease document against a caller-supplied public-key bundle and pinned primary-key fingerprint. It does **not** currently establish repository identity, authorize key rotation, enforce metadata freshness or rollback resistance, authenticate package indexes, or authorize installation.

Keep those responsibilities in a separate repository-policy layer. Do not weaken the cryptographic verifier to make policy decisions.

## 2. Repository identity

A configured repository identity must bind at least:

- Canonical repository base URL (normalized scheme, host, port, and path).
- Suite and codename.
- Allowed components.
- Allowed device/package architectures.
- The enrolled primary-key fingerprint.
- A stable local repository identifier.

Do not treat a matching display name, hostname, TLS certificate, or signing-key user ID as sufficient identity. HTTPS protects transport; the OpenPGP signature and enrolled fingerprint establish metadata authenticity.

Reject unexpected redirects, URL credential components, unsupported schemes, path escapes, and repository metadata that claims a different suite/codename/architecture than the configured policy permits.

## 3. Initial key enrollment

Use explicit user-approved enrollment; do not silently trust the first key returned by a server.

Enrollment should:

1. Fetch candidate public key material as untrusted input.
2. Parse it with strict size/count limits.
3. Display the complete primary fingerprint and repository URL to the user.
4. Require explicit confirmation of that fingerprint.
5. Persist the repository identity, fingerprint, key material, enrollment time, and policy version in protected app storage.
6. Keep the repository in an untrusted state until enrollment is complete.

A repository must never become trusted merely because its signature is mathematically valid. Trust requires a local enrollment decision.

## 4. Key rotation and revocation

The current verifier's exactly-one-signature rule is intentionally strict. Do not simply allow multiple signatures to support rotation.

Design a separate, versioned key-transition statement that binds:

- Repository identity.
- Old primary fingerprint.
- New primary fingerprint and public-key digest.
- Effective time and optional expiry.
- Transition sequence number.
- Policy version.

Require authorization by the currently enrolled key and proof of possession by the new key. Verify both proofs independently with the existing strict verifier, using distinct signed transition payloads if necessary. Persist the accepted transition atomically and reject replayed or skipped sequence numbers unless a documented recovery process authorizes them.

A revoked, expired, or compromised key must not be silently replaced by a key fetched from the same endpoint. Define an explicit recovery path (for example, user-assisted re-enrollment with a clearly displayed new fingerprint). Emergency revocation should immediately disable metadata acceptance and package operations for that repository.

## 5. Metadata freshness and rollback resistance

Parse Release fields strictly and enforce:

- Required Date field with bounded clock skew.
- Valid-Until when present; define a conservative maximum metadata age when absent.
- Reject expired metadata and metadata dated too far in the future.
- Persist the last accepted metadata digest, date, and monotonic repository sequence/version when available.
- Reject older metadata or previously accepted metadata replayed after a newer version.
- Treat device clock uncertainty as a reason to fail closed or require a clearly surfaced recovery action, not to disable expiry checks.

A valid signature does not prove that metadata is current.

## 6. Package-index and package integrity chain

After accepting InRelease:

1. Parse its checksum sections with strict duplicate-field and path validation.
2. Select only configured components and architectures.
3. Download each Packages index using a path constrained to the repository root.
4. Verify its exact byte length and SHA-256 digest against the authenticated Release metadata before parsing it.
5. Parse package records with bounded input sizes and reject duplicate or ambiguous critical fields.
6. Bind each package record to its filename, version, architecture, size, and SHA-256 digest.
7. Verify the downloaded .deb byte length and SHA-256 digest against the authenticated package record before any installation handoff.

Never use an index or package whose digest is missing, ambiguous, mismatched, or sourced from unauthenticated metadata. APT hash verification is a separate layer from the OpenPGP signature check.

## 7. Fail-closed repository states

Model repository state explicitly:

- **Unconfigured** — no repository identity or trust decision.
- **Pending enrollment** — candidate key awaiting user confirmation.
- **Trusted** — enrolled key and all metadata policy checks pass.
- **Update required** — authenticated key transition is available but not yet accepted.
- **Expired** — metadata freshness policy failed.
- **Revoked** — enrolled signing key or repository trust has been revoked.
- **Invalid** — signature, identity, metadata, or digest verification failed.
- **Unavailable** — network or server failure; retain last verified metadata only according to an explicit offline policy.

Only Trusted may supply package metadata to later package-management stages. Cached data must retain its verification timestamp and freshness status; offline mode must never convert stale metadata into trusted-current metadata.

## 8. Required test matrix

### Enrollment and identity
- Valid key + explicit fingerprint confirmation.
- Valid signature from a key not enrolled for that repository.
- Same key presented for a different repository identity.
- Fingerprint mismatch, malformed fingerprint, empty key, oversized key bundle.
- User declines enrollment.
- Redirect, URL credential, path traversal, and unexpected suite/codename.

### Rotation and revocation
- Authorized old-key to new-key transition.
- New-key proof missing or invalid.
- Old-key authorization missing or invalid.
- Wrong repository identity in transition.
- Replayed, expired, future-dated, or out-of-order transition.
- Old key revoked before transition; new key revoked after transition.
- Unsolicited replacement key from repository endpoint.

### Freshness and rollback
- Current metadata; exact expiry boundary; expired metadata.
- Future Date inside and outside allowed skew.
- Missing or malformed Date/Valid-Until.
- Replayed old metadata after a newer accepted version.
- Same timestamp with different digest.
- Device clock rollback/forward and offline stale-cache behavior.

### Index and package integrity
- Valid Packages index digest and size.
- Modified index, truncated index, wrong size, missing hash.
- Duplicate/ambiguous checksum fields and unsafe paths.
- Valid .deb digest and size.
- Modified, truncated, substituted, or wrong-architecture package.
- Package record changed after index authentication.

### State-machine and recovery
- Every failure maps to the correct non-trusted state.
- No failed check leaves a stale Trusted state.
- Trust changes persist atomically across app termination.
- Revocation disables subsequent metadata/package use.
- Recovery never silently enrolls a replacement key.

## 9. Implementation sequence

1. Review and approve this policy design.
2. Implement a platform-independent repository identity and Release metadata parser with deterministic fixtures.
3. Implement metadata freshness and rollback policy as pure, deterministic functions.
4. Add authenticated Packages-index digest validation.
5. Add package-record and .deb digest validation.
6. Design and test explicit key enrollment and key-transition authorization.
7. Run host tests, sanitizer tests, fuzzing, then iOS Simulator tests.
8. Validate persistence and user-confirmation flows on a physical device.
9. Only after independent review, consider app integration. Package installation remains disabled until all required safeguards are complete.

## 10. Non-goals and safety constraints

- This document does not claim any of these features are implemented.
- It does not authorize package installation.
- It does not approve a broadening of accepted OpenPGP algorithms or signature counts.
- It does not replace an independent security review.
- Do not commit real repository private keys, signing secrets, access tokens, or user data.
