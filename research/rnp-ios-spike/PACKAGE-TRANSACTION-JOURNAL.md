# ORBIT package transaction journal

This is a research transaction coordinator, not a device installer.

## Transaction protocol

1. Validate the complete operation list and reject duplicate package identities.
2. Write a versioned journal before changing package state.
3. Before each package operation, persist `IN_FLIGHT`.
4. Invoke the platform backend's idempotent apply callback.
5. Persist `COMPLETE` only after apply returns success.
6. Persist `COMMITTED` only after every operation is complete.
7. Clear the journal only after the committed marker is durable.

The journal is bounded to 256 operations. Each entry stores action and exact package name, version, and architecture. It does not store untrusted paths or download URLs.

## Crash recovery

Recovery treats every `IN_FLIGHT` and `COMPLETE` entry as potentially applied and rolls it back in reverse order. This intentionally includes an operation that may have partially changed the filesystem before the process died. The rollback callback must therefore be idempotent and restore the exact pre-transaction state.

A `COMMITTED` journal is cleanup-only: recovery clears it and does not undo a completed transaction. Invalid or unauthenticated journal data fails closed. If rollback or journal persistence fails, the journal remains and recovery must be retried; ORBIT must not start another package transaction.

## Required platform backend guarantees

A research Swift Keychain/App Attest persistence adapter and C callback bridge now exist in the simulator harness. The separate per-file enveloped journal executor coordinates file changes with ownership snapshots, but neither it nor the adapter is yet composed with this package-level coordinator or a privileged production helper. Before this coordinator can be used on-device, its backend must provide:

- Authenticated journal storage (MAC or equivalent device-bound integrity protection).
- Atomic, durable journal replacement and clear operations.
- Monotonic revision enforcement to reject replay/rollback of older journal snapshots.
- Exclusive transaction serialization across app processes and concurrent repository operations.
- Safe archive extraction with canonical path validation; reject absolute paths, traversal, symlink escapes, device nodes, and unsupported file types.
- Staging on the same filesystem as the destination, atomic replacement, permission/ownership policy, and filesystem synchronization.
- A durable pre-operation snapshot or equivalent undo data for every file/database mutation.
- Idempotent recovery callbacks that can restore partially applied installs and removals.
- A startup gate that runs recovery before package database reads, repository refreshes that mutate state, or any new install/remove request.

Keychain storage by itself is not proof against restoration of an older device backup. The adapter must meet the monotonic revision contract using a defensible device-bound or externally witnessed mechanism.

## Current scope and limitations

The coordinator supports install and remove actions through one callback interface, dependency-first operation order supplied by the caller, reverse-order rollback, and crash recovery. It does not extract .deb archives, execute maintainer scripts, manipulate the iOS filesystem, preserve actual installed file contents, or integrate with the app. No package operation is authorized merely by constructing a transaction plan.

Maintainer scripts and arbitrary package code remain disabled. A production package manager needs a separately reviewed policy for executable scripts, privilege boundaries, file ownership, shared-file conflicts, backups, and package database migration before any device installation is enabled.

## Verification

`orbit-package-transaction-tests.c` exercises successful commit, mixed install/remove actions, failure rollback, journal write failure after an apply, recovery of an in-flight operation, empty recovery, and corrupt-journal rejection. These tests are wired into the host verification workflow. A successful CI run is still required for the latest combined-envelope changes.


## Ownership integration status

The package ownership layer now builds complete replacement snapshots for install/upgrade and removal, and has a canonical bounded codec. Those pieces are host-tested, but this coordinator still has no ownership-snapshot field or atomic ownership-store operation. Do not treat a successful package-level journal commit as proof that an installed-file ownership database was committed.

The next integration must place the pending ownership snapshot, committed ownership snapshot, and active file journal in one authenticated durable envelope. A rollback must discard only the pending snapshot; a committed transaction may promote it only after file backup finalization succeeds. The envelope's revision and anti-rollback freshness anchor must cover all three pieces together. A separate ownership file or independent commit callback would create a split-brain crash window and is not acceptable.

The current package-level coordinator and per-file filesystem journal are distinct layers. They must be explicitly composed so the package journal cannot report success while file changes or ownership promotion remain incomplete. Production installation remains disabled until this composition, its crash-point tests, and the device persistence adapter are complete.

## Verification status update

The host transaction-coordinator tests are wired into CI and have passed on the feature branch. This confirms the current coordinator's tested behavior only; it does not validate the not-yet-implemented ownership integration or a production persistence backend.
