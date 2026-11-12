# ORBIT Recovery Concurrency and Crash-Recovery Audit

Status: source audit and implementation notes; tests are authored but not executed. This document is not a production security certification.

## Scope

Reviewed the App Attest witness request handlers, SQLite transaction setup, DynamoDB monotonic checkpoint adapter, Swift package journal coordinator, authenticated local journal persistence, and descriptor-relative filesystem bridge.

## Concurrency findings

- The witness service configures SQLite with one open connection. This serializes local database transactions within one service process.
- The five request handlers that open SQL transactions now use `BeginTx(r.Context(), nil)`. Client disconnects and request deadlines can therefore cancel in-flight SQL transactions instead of leaving a transaction holding the single connection until an unrelated timeout.
- Assertion counters are advanced with a conditional SQL update requiring the stored counter to be lower than the new App Attest counter.
- Recovery challenges are consumed with a conditional update requiring the challenge digest, old key, new key, unconsumed state, and non-expired timestamp to match. This is the single-use gate when two recovery submissions race.
- Recovery rotates the installation key and writes immutable recovery history inside one SQL transaction. The independent anchor append is conditional on the next sequence and predecessor hash. Competing head/CAS/recovery operations cannot both append different checkpoints at the same sequence.
- The external checkpoint is appended before the SQLite transaction commits. If the process or SQLite commit fails after the external append, the next request reconciles the local database forward from the anchor. It never intentionally moves the anchor backward.

## Crash-recovery invariants

1. An accepted assertion must advance both the App Attest counter and the external checkpoint.
2. An accepted journal head transition must be represented by the external checkpoint before the SQL transaction commits.
3. A failed or ambiguous SQL commit after an anchor append is repaired by reading the anchor and rebuilding/advancing the SQLite cache.
4. A local SQLite state ahead of the anchor is rejected.
5. A missing local SQLite installation may be reconstructed only from the anchor selected by the high-entropy recovery credential; local backup data is never used to seed a missing anchor.
6. Recovery key rotation preserves the journal head, resets the new App Attest key counter, consumes the recovery challenge, and appends a new checkpoint.
7. An anchor outage fails closed. No journal or assertion operation should be accepted using SQLite alone.

## Filesystem transaction recovery model

- The coordinator persists APPLYING before changing installed files.
- Each filesystem operation is designed to be idempotent so recovery can safely roll back every planned change, including changes that may not have started.
- APPLYING and ROLLING_BACK recover by reverse-order rollback.
- COMMITTED recovers by idempotent finalization only; it must never roll back committed package contents.
- The journal is cleared only after rollback or finalization completes. Transaction backup cleanup follows journal clearing and requires the transaction backup directory to be empty.
- A crash after local journal rename but before witness CAS is reconciled by advancing the witness from the one-step-ahead authenticated local envelope. A stale local envelope behind the witness is rejected.
- A crash after witness CAS but before the client receives its response is resolved by reading the witness; matching local and remote heads are idempotent.

## Remaining validation required

The following are test requirements, not claims of completed testing:

- Run concurrent HTTP requests for two different valid assertions against one installation and verify only a contiguous anchor sequence is accepted.
- Race two submissions of the same recovery challenge; exactly one may consume it.
- Race a normal old-key head request against key recovery; the resulting state must be either the old-key checkpoint followed by recovery, or recovery followed by rejection of the old key. No fork is allowed.
- Simulate anchor append success followed by SQLite commit failure, then verify the next request repairs the local row.
- Simulate a lost response after successful DynamoDB PutItem and verify exact-checkpoint retry is idempotent.
- Simulate a conditional-write race between two DynamoDB clients and verify one checkpoint wins.
- Inject process termination after every journal write, backup creation, backup link, rename, unlink, directory fsync, witness CAS, journal clear, and backup-directory cleanup.
- Verify rollback and finalization can be repeated after each interruption without losing the preimage or deleting an unrelated file.
- Exercise the actual DynamoDB adapter against a disposable table; the in-memory anchor tests do not validate AWS conditional-expression behavior or IAM policy.

## Explicit boundaries

- DynamoDB's conditional append protects against ordinary concurrent writers and the documented runtime role is intended to lack update/delete permissions. An administrator able to rewrite or delete table history is outside this database-only rollback model. Latest-checkpoint reads validate the latest checkpoint and its immediate predecessor, not a full historical chain walk on every request.
- SQLite uses one connection and is a cache, not the rollback authority. Multi-process/multi-region service deployment needs a separate concurrency and failover design; SQLite is not a shared multi-node database.
- Rate limiting, abuse monitoring, deployment backup/restore drills, account/installation recovery governance, and production incident procedures remain deployment blockers.
- No AWS table has been provisioned and no witness service has been deployed as part of this audit.
- No test runner, CI workflow, sanitizer, or physical-device test was run during this source audit.
