# ORBIT repository key rotation research

This is a research-only trust transition layer. It is not wired into the ORBIT
application and does not enable package installation.

## Rotation authorization

A rotation document is a Debian-style clear-signed document whose authenticated
cleartext contains exactly these fields:

```
ORBIT-Key-Rotation: 1
Repository: orbit-official
Current-Fingerprint: <40- or 64-hex primary fingerprint>
Next-Fingerprint: <40- or 64-hex primary fingerprint>
Activate-At: <strict Debian/RFC timestamp>
Previous-Key-Valid-Until: <strict Debian/RFC timestamp>
```

Unknown fields, duplicate fields, missing fields, malformed fingerprints,
invalid calendar timestamps, and a current/next fingerprint collision are
rejected. The repository identifier is compared exactly against the caller's
configured identifier.

## Verification sequence

1. `orbit_repository_trust_authorize_rotation` invokes the RNP verifier using
   the currently pinned primary fingerprint and current trusted public-key
   bundle.
2. RNP must accept exactly one signature under the existing Ed25519/SHA-2,
   signer-identity, key-validity, revocation, and signature-time policy.
3. The verifier returns a bounded copy of cleartext only after all checks pass.
   On every failure, the output buffer is scrubbed and its length remains zero.
4. The rotation parser accepts only the authenticated payload.
5. The proposed public-key bundle is independently inspected. The exact
   replacement primary fingerprint must exist and identify a valid,
   unrevoked Ed25519 key with signing usage.
6. The proof must name the current pin and expected repository identifier.
7. Activation must be between now and 90 days ahead. The previous-key grace
   period must end at or after activation and no more than 30 days later.
8. Only one pending rotation is permitted.

## Runtime trust behavior

Before activation, only the current key is accepted. At the signed activation
time, the new key becomes authorized. The old key remains accepted through
the signed grace deadline, inclusive, then is rejected. The state can be
compacted with `orbit_repository_trust_advance`; the generation counter
increments on that transition.

The caller must persist the trust state atomically and invoke the transition
logic as time advances. Durable storage, rollback resistance, multi-device
synchronization, transparency logging, recovery keys, multi-signature
authorization, and emergency revocation distribution are not implemented.


## Emergency recovery root

An independent offline recovery primary key can authorize an emergency
rotation through `orbit_repository_trust_authorize_recovery_rotation`. Its
fingerprint is enrolled alongside the normal signing fingerprint and stored
inside the authenticated, version-2 trust record. Version-1 records do
not contain this independent pin and are rejected rather than silently
migrated or assigned a guessed recovery root. The recovery API no longer
accepts a caller-selected recovery fingerprint; it always verifies against
the persisted recovery pin. The offline public-key bundle is supplied for
verification, but cannot change that pin.

The recovery document uses the same strict, authenticated rotation statement,
but its activation must be no earlier than the previously persisted time,
no later than the current time, and no more than 24 hours old. Its previous-key
deadline must equal that signed activation time. This is an immediate
transition with zero grace. It
replaces the current signing pin, cancels any pending normal rotation, and
discards any older previous-key grace pin. The compromised current key is accepted only through the signed activation
timestamp; if recovery is processed later, it is rejected immediately.
The persisted wrapper commits the time floor and emergency transition before
returning success.

This research implementation has one independently pinned recovery signer,
not a threshold/multisignature quorum. Recovery-root replacement, recovery-root
revocation, and recovery-root backup custody procedures remain separate design
work. The recovery private key must remain offline; it must never be bundled
with ORBIT or the repository. Enrollment rejects a recovery fingerprint that
matches the normal signing key, and normal rotations cannot promote the
recovery root into a repository signing key.

## Durable trust-state persistence

`ORBITTrustPersistence.h/.c` adds a versioned, fixed-width, canonical record
format bound to the repository identifier. The record contains the active,
previous, and pending primary fingerprints, activation/grace timestamps, key
generation, and a separate mutation revision. The record is authenticated by
a platform-provided MAC callback and its revision must exactly match a
platform-provided monotonic counter.

Every state mutation advances the revision, including scheduling a rotation,
activating it, and pruning an expired previous key. A record cannot be replaced
with different bytes at the same revision. The authenticated next-revision
record is atomically staged before the monotonic counter advances. If the
process crashes after staging but before counter advancement, loading verifies
the MAC and can safely complete exactly one pending counter increment. Records
older than the counter are rejected. Retrying the exact same saved state is
idempotent.

The backend is an explicit security boundary, not a default file-storage
implementation. A production iOS adapter must provide a device-protected MAC
key, atomic record replacement, and a repository-scoped monotonic counter that
cannot be rolled back by restoring backups or app data. Ordinary files,
UserDefaults, and a backup-restorable Keychain counter do not satisfy this
contract. If a suitable monotonic primitive is unavailable, durable trust
must remain disabled until an independently authenticated recovery or remote
witness design is approved.

Only one key transition may be pending. A subsequent rotation is blocked while
the previous key's grace period remains active. After the signed deadline,
`orbit_repository_trust_prune_previous` removes that old pin and advances the
revision before another rotation can be scheduled.

The host persistence harness uses an intentionally non-cryptographic in-memory
MAC solely to exercise API behavior, tamper detection, revision checks, and
crash-window handling. It is not evidence of production cryptographic storage.

The harness also covers explicit missing-versus-I/O-error handling, repository
binding, exclusive-lock contention, same-revision substitution, stale snapshot rejection, failed atomic
writes, interrupted counter advancement and recovery, plus transactional
rollback of in-memory activation and previous-key pruning when storage commits
fail.

The trust state also persists a monotonic observed-time floor. Production callers should use
`orbit_repository_trust_fingerprint_allowed_and_store`, which commits the
current time before evaluating a signer. The lower-level read-only fingerprint
check accepts only that exact persisted timestamp. A backward clock value is rejected
and cannot make an expired previous key valid again. Rotation scheduling,
activation, and pruning also refuse time values below the stored floor.

## End-to-end repository verification

`ORBITRepositoryVerifier.c` provides the fail-closed repository verification
entry point, `orbit_repository_verify_packages_index`. It reloads the latest
authenticated trust record under the repository transaction lock, advances
and commits the monotonic time floor, and authorizes the requested primary
fingerprint before checking the repository document.

The verifier then validates the clear-signed InRelease using that exact pin,
parses only the authenticated cleartext, and enforces exact signed Release
`Origin`, `Suite`, and `Codename` plus complete architecture/component
tokens. It enforces `Valid-Until`, or a caller-provided maximum Release age
when that field is absent, and finally checks the actual Packages-index bytes
against the exact SHA256 path and declared byte count.

The API returns distinct fail-closed outcomes for storage failure, untrusted
signer, invalid signature, malformed Release metadata, repository-policy
mismatch, stale Release metadata, and Packages-index mismatch. Authenticated
cleartext is bounded, scrubbed, and never returned to the caller. After the signed index digest passes, `ORBITPackagesIndex.c` performs a
bounded Debian Packages stanza parse. It requires unique package/architecture
identities and complete Version, Architecture, Filename, Size, and SHA256
artifact fields; unsafe relative paths, duplicate fields, malformed
digests, zero/overflow sizes, and incomplete records are rejected. The index
path is derived from the pinned component and architecture, and each package
record must target that architecture or `all`. The
verified catalog is returned as owned package records in the verification result; callers release it with `orbit_repository_verify_result_destroy`. The parser is data-only and does not install packages.

`orbit_package_verify_artifact` separately checks downloaded `.deb` bytes
against the selected record's exact byte count and SHA-256 using Botan. The
caller must resolve the validated relative Filename beneath the configured
repository origin and must verify the artifact before any future installation.
The current work does not download packages, install them, resolve dependencies,
or authorize package execution.

All persistent trust mutations (bootstrap, normal rotation, emergency
recovery, time-floor updates, activation, and grace pruning) hold the
repository-scoped backend transaction lock across the complete read/modify/
write. The host test backend rejects any storage callback invoked without
that lock. The host fixture now signs a real Packages index and its digest
inside Release metadata.

## Test coverage

The host fixture suite exercises:

- valid old-key-authorized rotation;
- a new key attempting to authorize its own rotation;
- mismatched candidate fingerprint/key bundle;
- expired and revoked candidate keys;
- wrong repository identifier;
- pending-rotation duplication;
- activation and previous-key grace boundaries;
- failed verification not returning cleartext;
- malformed, unknown, and duplicate rotation fields;
- emergency recovery signed by an independent offline root;
- delayed emergency statements, unauthorized recovery signers, wrong repository
  identifiers, and mismatched replacement keys;
- emergency recovery overriding a pending rotation and discarding older grace
  pins;
- persisted emergency rotation, reload, old-key rejection, and failed-commit
  recovery.

The iOS Simulator pipeline cross-compiles and statically links the trust layer.
This is not physical-device validation or production readiness.
