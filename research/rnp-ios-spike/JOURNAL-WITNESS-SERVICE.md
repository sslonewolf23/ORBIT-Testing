# ORBIT App Attest journal freshness witness service

## Status

This document is the server contract for the private iOS client. No production
service implementation or deployment is included in this repository. Do not
configure a production endpoint or enable package installation until the
service has been independently reviewed and deployed.

## Security boundary

The service is the independent freshness anchor. It must not trust a revision,
digest, App Attest key identifier, or assertion counter supplied without
verification. It must bind one registered App Attest key to one authenticated
ORBIT installation/account and retain that binding durably. Re-registration
must never create a fresh journal head for an installation that already has
state. Key replacement requires an explicit recovery process that preserves
the old head and audit trail.

All endpoints require TLS. Production clients must use a fixed, reviewed
origin and an explicit transport trust policy. Apply request size limits,
rate limits, audit logging, and strict JSON parsing.

## App Attest registration

1. The client generates a uniformly random 32-byte recovery credential and
   stores it in device-only Keychain storage before network registration.
2. `GET /v1/orbit/journal/attestation-challenge` returns a cryptographically
   random, single-use challenge (base64). Challenge expiry and consumption
   are enforced server-side.
3. The client calls `generateKey`, then `attestKey` with SHA-256(rawChallenge),
   and submits `keyID`, `challenge`, `attestation`, and base64
   `recoveryCredential` to `POST /v1/orbit/journal/register`.
4. The service verifies Apple's App Attest certificate chain against Apple's
   published trust root, validates the nonce extension against the exact
   client-data hash, checks the expected app identifier/team bundle identity,
   verifies the key identifier and public key, and consumes the challenge.
5. The service binds the verified key to the authenticated installation.
   Repeating the exact same registration proof is idempotent; a different
   proof for an already-bound key or installation is rejected.

Never accept a client-provided public key or app identity as a substitute for
the attestation evidence. Keep Apple's trust roots and verification rules
current.

## Recovery credential and App Attest key replacement

At first enrollment the client generates a uniformly random 32-byte recovery credential. It must be displayed/exported once with clear instructions to store it offline; it must not be silently recoverable from server storage. The registration JSON includes `recoveryCredential` as base64. The server stores only HMAC-SHA-256(server pepper, domain || credential); the pepper is a separate deployment secret and must not be stored beside the database.

For replacement, the client generates a new App Attest key and submits the recovery credential plus new key ID to POST /v1/orbit/journal/recovery-challenge. The server derives the verifier, locates the existing installation, and returns a five-minute, single-use challenge bound server-side to the old and new key IDs. The client submits the recovery credential, challenge, and new-key attestation to POST /v1/orbit/journal/recover over TLS. The server verifies the credential in constant time, verifies Apple's attestation for the replacement key, consumes the challenge, and atomically replaces the key binding while preserving the existing revision, digest, tombstone, recovery verifier, and recovery history. The client does not need the old key ID or old Keychain record. A replacement key cannot create a new initial journal head. The old key is retired by the same transaction. Recovery credentials must never be logged.

A database migration does not silently invent credentials for existing installations: records without a verifier are ineligible for self-service recovery. They require an explicit, separately reviewed migration path.

## Assertion verification

For every `head` and `compare-and-swap` request:

- Decode the exact `request` and `assertion` byte strings from base64.
- Look up the registered App Attest public key and last accepted assertion
  counter for the authenticated installation.
- Verify the assertion signature and its authenticator data using Apple's
  App Attest verification procedure.
- Verify the RP ID hash/app identity and that the assertion's client-data
  hash equals SHA-256 of the exact request bytes.
- Require the assertion counter to be strictly greater than the last accepted
  counter; update it atomically with the request result.
- Reject unknown keys, invalid signatures, stale/replayed counters, wrong app
  identity, malformed CBOR, oversized input, and any counter overflow.

The server must serialize assertion-counter updates and journal-head updates
in one database transaction. A valid assertion alone does not authorize a
journal revision transition.

## Journal head storage

Persist one row per authenticated installation:

- installation/account binding;
- App Attest key identifier and public key;
- last accepted assertion counter;
- journal revision (unsigned 64-bit semantics);
- exact 32-byte SHA-256 digest of the complete authenticated ORBJ envelope;
- tombstone flag;
- server-side audit metadata.

A newly enrolled installation begins at revision 0, tombstone=true, digest
32 zero bytes. It may not be reinitialized if a row already exists.

## Signed request formats

The HTTP JSON wrapper contains `keyID`, base64 `request`, and base64
`assertion`. App Attest signs SHA-256 of the raw request bytes, not the JSON
wrapper.

Head request:

- UTF-8 `ORBIT-JOURNAL-HEAD-V1`;
- one NUL byte;
- UTF-8 key identifier.

CAS request:

- UTF-8 `ORBIT-JOURNAL-CAS-V1`;
- one NUL byte;
- UTF-8 key identifier;
- expected head;
- replacement head.

Each head is 41 bytes: 8-byte big-endian revision, 1-byte tombstone flag
(0 or 1), and 32-byte digest.

## Atomic compare-and-swap rules

After verifying the App Attest assertion, compare the expected head with the
stored head byte-for-byte. Accept only these transitions:

1. active `r` -> active `r+1`;
2. active `r` -> tombstone `r`;
3. tombstone `r` -> active `r+1`.

The initial revision-zero tombstone may transition to active revision one.
No other transition is valid. Reject lower revisions, skipped revisions,
same-revision active digest changes, tombstone-to-tombstone rewrites,
active-to-tombstone with a different revision, and any replacement digest
that is not exactly 32 bytes.

Commit the new head and assertion counter in one durable database transaction.
If the server commits but the response is lost, retrying the same request must
be idempotent: the service should recognize the exact replacement head and
return success without accepting a replayed assertion counter as a new
operation. A new App Attest assertion can also retry the same expected /
replacement pair and receive success only if the current head already equals
the requested replacement.

## Responses

- Challenge: HTTP 200, JSON `{"challenge":"<base64>" }`.
- Registration: HTTP 200 or 204 only after successful verification and durable
  binding.
- Head: HTTP 200, JSON
  `{"revision":123,"digest":"<base64-32-bytes>","tombstone":false}`.
- CAS: HTTP 204 only after the atomic transition is durable.

Do not disclose whether a different account's installation exists. Use generic
authorization failures for unbound or unauthorized keys.

## Required service tests

- Valid Apple attestation and wrong app/team/bundle identity.
- Invalid certificate chain, nonce mismatch, challenge replay and expiry.
- Valid assertion, wrong client-data hash, invalid signature, stale counter,
  duplicate counter, and counter overflow.
- Two concurrent CAS operations from the same expected head (exactly one
  transition succeeds).
- Lost response after commit and idempotent retry.
- Revision rollback, skipped revision, same-revision digest mutation, invalid
  tombstone transitions, and unknown installation.
- Database crash/restart, backup restore, stale replica, and failover tests
  proving the head cannot move backward.
- Keychain loss, device restore, account recovery, and key re-registration
  attempts proving a new App Attest key cannot reset an existing head.

The service must fail closed if its durable database or consistency mechanism
is unavailable. A stale replica must never answer a freshness query.


## Reference server implementation

A Go reference service now lives in
`research/rnp-ios-spike/witness-service/`. It provides TLS-only challenge,
registration, head, and compare-and-swap endpoints; SQLite WAL/FULL durability;
App Attest certificate-chain, nonce, RP ID, key-ID, and ECDSA assertion
verification; monotonic assertion counters; and atomic head transitions.
Its setup and known limitations are documented in that directory's README.

This implementation is not yet approved for production. In particular, it
still needs validation-category and bundle-version extension verification,
strict CBOR/resource-limit review, challenge cleanup/rate limiting, current
Apple root rotation handling, production account/recovery policy, and tests
against real Apple-issued development and production attestations. Do not
deploy it as the production trust anchor until those items are reviewed.


## Important gap in the current reference implementation

The protocol contract above requires an authenticated account/installation
binding that survives App Attest key replacement. The Go reference now binds initial enrollment to a client-held recovery credential and includes an atomic key-replacement path that preserves the existing head. The private iOS client now generates, stores, and submits the credential and can request recovery without the old key ID. The device validation host displays the credential once after first enrollment. The complete flow still needs service and physical-device testing before it can be relied upon.

Likewise, the SQLite database is crash-durable but can be rolled back by
restoring an older database snapshot. Production requires an independent
monotonic anchor or a strongly consistent externally protected store. The
current server is a protocol and verification reference, not a production
freshness authority. Package installation must remain disabled until both
gaps are closed and independently reviewed.
