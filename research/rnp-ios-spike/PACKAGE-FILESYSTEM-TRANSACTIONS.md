# ORBIT atomic package file changes

## File-level transaction primitive

`ORBITPackageFilesystem` provides identity-checked operations for replacing or removing one regular file. It does not install a complete package or modify directories.

A caller supplies already-open target, stage, and backup parent directory descriptors. The change record can also carry relative target/stage parent locators so recovery can reopen them from trusted roots with no-follow traversal. The module rejects cross-volume layouts, symlinks, non-regular files, multiply-linked source/preimage files, unsafe leaf names, and ambiguous same-directory name aliasing.

## Replace protocol

1. `prepare_replace` records the target preimage identity (if present) and staged-file identity. It performs no filesystem mutation.
2. The caller must durably persist the complete `orbit_package_file_change` record in its authenticated, monotonic transaction journal.
3. `apply` creates a hard-link preimage in the private backup directory, fsyncs that directory, then uses `renameat` to atomically replace the target pathname with the staged regular file. It fsyncs the target and stage directories.
4. `rollback` checks device/inode identities before removing the installed file and restoring the preimage. It is safe to retry.
5. After the enclosing package transaction is committed, `finalize` removes the backup link. It is safe to retry.

When the target did not exist, rollback removes only the exact staged inode installed by this operation.

## Remove protocol

1. `prepare_remove` records the target's exact device/inode identity and verifies it is a single-link regular file.
2. The caller persists the change record before mutation.
3. `apply` hard-links the preimage into the backup directory, fsyncs it, unlinks the target, and fsyncs the target directory.
4. `rollback` restores the exact preimage inode from backup; `finalize` deletes the backup after commit.

## Recovery and concurrency

Apply/rollback/finalize infer progress from target, stage, and backup inode identities rather than trusting volatile in-memory flags. Unexpected files, symlinks, inode changes, missing required preimages, or abnormal hard-link counts fail closed with a recovery-required/conflict result.

The caller must hold an exclusive package filesystem transaction lock from preparation through finalization or rollback. All parent descriptors must remain open and refer to the intended directories. Staging, target, and backup must be on the same volume. Hard-link support is required; unsupported filesystems fail closed.

The version-2 fixed-size change record includes target/stage relative parent locators and is a recovery payload, not a self-authenticating journal. The caller must encode and persist it using the authenticated, monotonic journal backend; do not write a raw C struct as an unauthenticated file. The per-file journal now coordinates these records and exposes a descriptor-resolving executor. Its backup directory is named from the transaction ID, opened with no-follow semantics, and accepted only when it is a private directory owned by the effective user. The caller must create that directory before starting a new transaction; recovery reopens the existing directory.

## Per-file write-ahead journal

`ORBITPackageFilesystemJournal` coordinates up to 4,096 file changes as one package file transaction. It stores the entire validated plan before the first mutation, then uses durable phases:

- `APPLYING`: recovery chooses reverse rollback, including operations that may not have started (their rollback is idempotent).
- `ROLLING_BACK`: recovery retries reverse rollback.
- `COMMITTED`: recovery retries backup finalization and then clears the journal.

The record carries each target/stage parent path relative to trusted install/staging roots, plus the exact file identities. The executor resolves those paths with no-follow descriptor traversal and derives the private backup root from the transaction ID. The journal rejects duplicate targets, including ASCII case-folded duplicates.

The backend contract requires authenticated loads, atomic stores, a monotonic revision retained even after clear, and compare-by-revision clearing. It must encode fields canonically; raw C struct persistence is not acceptable. The host harness uses an in-memory backend only. No production iOS persistence adapter is connected yet.

### Durable authenticated journal backend contract

A production backend must persist a **canonical envelope**, not a raw C struct. The envelope should contain a format/version discriminator, a domain-separation label (for example, `ORBIT-FILESYSTEM-JOURNAL`), a fixed-width unsigned revision in network byte order, an explicit active/tombstone state, and—when active—the transaction ID, phase, count, and each change field encoded individually with explicit lengths and fixed-width integer encodings. Reject unknown versions, noncanonical encodings, overlong strings, duplicate fields, trailing bytes, and integer overflow before constructing the in-memory record.

Authenticate the complete envelope with a keyed MAC such as HMAC-SHA-256. The MAC key must be generated per installation, stored using an iOS Keychain accessibility class that prevents migration to another device (and the strongest access-control policy compatible with recovery), and never embedded in the app or journal file. Verify the MAC in constant time before parsing or acting on any journal content. Key loss, authentication failure, or an unavailable key must fail closed and preserve the journal and backups for manual recovery; do not silently initialize a replacement key.

Implement `store_atomic` as a compare-and-swap on the expected prior revision: write a new envelope to a uniquely named temporary file in the same protected directory, fully write it, fsync the file, atomically rename it over the prior envelope, then fsync the containing directory. Enforce `record.revision == last_revision + 1` while holding the same exclusive state lock. Implement `clear_atomic` by atomically replacing the active envelope with an authenticated **tombstone** at the same expected revision; do not simply delete the only copy of the revision. A tombstone lets `load` return EMPTY while preserving the last revision after a normal restart. Temporary files left by a crash must never be treated as authoritative without validating the final envelope and its MAC.

A MAC and a tombstone prevent undetected edits and ordinary stale writes, but **do not by themselves prevent restoration of an older, valid file snapshot**. A real rollback-resistant implementation needs an independent freshness anchor, such as a trustworthy server-side monotonic witness/transparency checkpoint or a platform primitive that actually provides monotonic state. iOS Keychain storage and Secure Enclave key protection alone must not be represented as a generic monotonic counter. Until an independent anchor is implemented and validated, label the backend authenticated but not rollback-resistant, and keep production installation disabled.

The caller must hold the package-wide exclusive transaction lock across preparation, journal execution or recovery, backup-directory creation, and cleanup. After a successful rollback or committed finalization, call the backup cleanup helper only after the backend reports an empty journal; the helper refuses cleanup while any active or unreadable journal exists and removes only a verified empty transaction directory. `ORBITPackageFilesystem` provides a nonblocking advisory lock file helper that rejects symlinks, non-regular files, unexpected ownership/modes, and lock-file replacement during acquisition. This coordinates ORBIT instances only; it does not replace any lock required by the target package manager or prevent non-cooperating privileged processes from modifying the root.

## Limitations

- Regular files only; directory creation/removal and directory-mode rollback are not handled here.
- No ownership database commit, package-level dependency ordering, live-root adapter, or privileged helper.
- File uid/gid, ACLs, extended attributes, flags, and directory metadata are not preserved by this primitive.
- No maintainer scripts are executed.
- Hard-link preimages and rename semantics still require validation on each supported jailbreak filesystem and physical device.
- The host harness is authored and wired under AddressSanitizer/UndefinedBehaviorSanitizer, but has not been run.

Installation remains disabled.


## Canonical journal payload codec

`ORBITPackageFilesystemJournalCodec.h/.c` provides a bounded canonical
binary encoding for the per-file journal record. It deliberately excludes
compiler padding and the revision field (the authenticated outer journal
envelope owns the revision). All integers are unsigned big-endian; strings
are explicit 16-bit byte lengths followed by UTF-8/ASCII bytes without a NUL
terminator; unused in-memory string bytes must be zero.

Payload format v1 is:

- 4-byte magic `ORJP`;
- 1-byte codec version;
- 4-byte phase;
- 16-byte nonzero transaction identifier;
- 4-byte change count;
- each change: version and operation (4 bytes each), five length-prefixed
  strings (target, staged, backup, target parent, staged parent), one boolean
  byte, then four 64-bit device/inode values.

The decoder requires an exact payload length, rejects unknown versions,
invalid booleans, embedded NULs, nonzero in-memory string tails, malformed
changes, and trailing bytes. The outer authenticated envelope supplies the
revision to the decoder. The codec is wired into host verification. A research Swift persistence adapter now consumes the combined ORBE envelope, but it is not yet connected to the production transaction executor or privileged helper.


## Ownership state must share the journal's commit boundary

The ownership planner now exposes complete replacement-snapshot builders for install/upgrade and removal. The canonical ownership codec can encode/decode that snapshot, and both are covered by host CI. They are still in-memory planning/codec components; they are not a persistent ownership database.

The **active file journal, pending ownership snapshot, and committed ownership snapshot must share one authenticated durable state envelope**. The ORBE codec and Swift adapter now provide initial building blocks for that envelope, but the existing file-journal backend is not yet switched over. Do not implement ownership persistence as a second independent file or a second callback that can commit separately from the file journal.

Required backend semantics:

1. The envelope carries the monotonic revision, active file-journal record (when present), the currently committed ownership payload, and the pending replacement ownership payload for the active transaction.
2. Storing an APPLYING or ROLLING_BACK journal atomically updates the active journal and pending payload while preserving the previous committed ownership payload.
3. A rollback completion atomically clears the active transaction and discards its pending ownership payload. The prior committed ownership payload remains authoritative.
4. A COMMITTED journal is durable before backup finalization. Recovery retries finalization while the pending ownership payload remains in the same envelope.
5. Only the atomic transition that clears a successfully finalized COMMITTED journal may promote the pending ownership payload to committed ownership. That transition must also advance/preserve the same monotonic freshness anchor; there must be no crash window where files are committed but ownership can silently revert.
6. Loading an active COMMITTED transaction must expose its pending ownership snapshot as the transaction's intended post-commit state, but ordinary package operations remain blocked until finalization and promotion complete.
7. Authentication, revision compare-and-swap, and the independent anti-rollback freshness anchor cover the entire envelope—not separate journal and ownership records. Key loss, MAC failure, stale revision, or ambiguous state fails closed and preserves backups.

The backend API should express this as one atomic envelope operation with explicit active/pending/committed state. Avoid adding a raw struct pointer to the journal record or relying on a process-local callback to remember the pending snapshot; recovery must reconstruct all required state after process death. The implementation must define ownership of allocated buffers and enforce the existing ownership codec payload bound before writing.

The combined envelope codec and research Swift adapter are implemented, but the current file-journal backend contract and in-memory test backend do not yet persist ownership state through that envelope. Production installation remains disabled.

## Verification status update

The canonical file-journal codec and filesystem-journal host tests are now wired into the host verification workflow and have passed on the feature branch. The earlier statements that these tests had not run are superseded by the successful CI run. This does not mean a production persistence adapter or device crash-recovery path exists.


## Canonical combined transaction envelope (implementation in progress)

`ORBITPackageTransactionEnvelope.h/.c` now defines a version-1 `ORBE` envelope. Its canonical header carries the envelope revision, active/empty state, transaction phase, transaction ID, and explicit lengths for three opaque canonical payloads:

- active per-file journal payload;
- last committed ownership snapshot;
- pending replacement ownership snapshot.

The encoder uses fixed-width big-endian integers, rejects invalid state combinations and payloads over their independent bounds, and never serializes C struct padding. The transition validator enforces consecutive revisions and these rules:

- Begin: retain committed ownership and stage pending ownership before any file mutation.
- Rollback: preserve committed ownership; clear the pending snapshot only when rollback has completed.
- Commit: keep old committed ownership while the journal is COMMITTED and backups are being finalized; promote pending ownership only in the final atomic transition that clears the active journal.
- Reject attempts to promote stale ownership, skip revisions, or clear an APPLYING transaction without first entering rollback or commit.

The host harness covers canonical encode/decode, malformed/truncated/trailing data, revision jumps, rollback preservation, commit promotion, and split-brain rejection. The iOS harness now includes a Swift persistence adapter that uses a device-only Keychain identity, HMAC-SHA-256 over the complete envelope, a same-directory pending-file/atomic-rename protocol, and App Attest assertions against the existing independent freshness-witness service. A pending file is retained when the witness is unavailable so recovery can retry; the adapter never silently recreates missing identity material.

Important integration boundary: the envelope codec/state validator and Swift adapter are new building blocks. The existing per-file journal backend and package transaction coordinator have **not yet been switched over** to this combined backend. The Swift adapter is currently compiled as part of the simulator harness, not wired into a production ORBIT app or privileged filesystem helper. It assumes the caller holds the package-wide cross-process lock, and App Attest enrollment/recovery plus real-device crash testing remain separate prerequisites. The envelope payload digest and server witness format must be kept byte-for-byte consistent during integration. Installation remains disabled.


## Enveloped filesystem journal executor

ORBITPackageFilesystemJournalEnvelope.h/.c now adds a combined
execution/recovery API alongside the original journal API. It loads an
authenticated EMPTY ORBE envelope, verifies the caller's expected committed
ownership bytes, stages the complete replacement ownership snapshot, and
persists APPLYING before invoking the first file executor callback.

The executor then persists one of three durable paths:

- Apply failure: persist ROLLING_BACK, retry reverse rollback, then atomically
  clear the journal and discard pending ownership while preserving committed
  ownership.
- Apply success: persist COMMITTED, finalize every backup, then atomically clear
  the journal and promote pending ownership to committed ownership.
- Process interruption: recovery decodes the journal from the envelope and
  resumes the ROLLING_BACK or COMMITTED path. APPLYING is converted to
  ROLLING_BACK before any recovery mutation.

The backend contract is one authenticated local-envelope + independent-witness
compare-and-swap. The load callback must verify the local HMAC and return the
digest of the complete payload-plus-HMAC file. The store_atomic callback must
compare the expected revision and digest, atomically persist the next envelope,
advance the external freshness witness, and return the new complete-file
digest. A backend failure leaves the previous durable envelope authoritative;
if the local pending-file protocol has an unresolved candidate, its own
recovery gate must resolve it before returning a state to this C layer.

The new host harness exercises successful file/ownership commit, interrupted
rollback with ownership preservation, and interrupted committed finalization
with delayed ownership promotion. The iOS simulator workflow cross-compiles
the new journal executor and its filesystem/codec dependencies.

Integration boundary: the new enveloped executor is available, but the legacy
orbit_package_filesystem_journal_backend is not transparently replaced, and
the package-level ORBITPackageTransactionCoordinator is not yet composed
around this API. The Swift Keychain/App Attest store is a research adapter;
a C callback bridge that implements this backend contract, initial EMPTY
envelope provisioning, real App Attest enrollment, and physical-device
crash-point tests are still required. Installation remains disabled.
