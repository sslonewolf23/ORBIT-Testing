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
binding, same-revision substitution, stale snapshot rejection, failed atomic
writes, interrupted counter advancement and recovery, plus transactional
rollback of in-memory activation and previous-key pruning when storage commits
fail.

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
- malformed/unknown rotation fields.

The iOS Simulator pipeline cross-compiles and statically links the trust layer.
This is not physical-device validation or production readiness.
