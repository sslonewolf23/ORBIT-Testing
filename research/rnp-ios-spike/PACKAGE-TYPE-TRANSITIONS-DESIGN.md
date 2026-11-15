# Journaled Package File/Directory Type Transitions

Status: implementation design; no type-transition operation is enabled by this document.

## Scope

The planner currently rejects both owned regular-file-to-directory and owned directory-to-regular-file transitions. Keep that rejection until a dedicated journal operation, codec support, executor behavior, recovery logic, and regression suite land together.

The first implementation is deliberately narrow:

- Only a regular file may transition to a directory, or an empty directory may transition to a regular file.
- The preimage must be owned by the package being replaced, confirmed by the authenticated ownership snapshot.
- The staged replacement must be a regular file or real directory with a captured device/inode identity.
- Symlinks, special files, multiply-linked regular files, non-empty directories, and foreign/unowned destinations are rejected.
- No recursive deletion, path-following, cross-volume copy, or implicit ownership takeover is permitted.

## Journal representation

Add two distinct operation values rather than overloading replace/remove/create-directory:

- `ORBIT_FILESYSTEM_REPLACE_FILE_WITH_DIRECTORY`
- `ORBIT_FILESYSTEM_REPLACE_EMPTY_DIRECTORY_WITH_FILE`

Bump the filesystem change-record version and canonical journal codec version. Do not reinterpret records written with the prior version. The authenticated envelope must continue authenticating the complete canonical payload and monotonic revision.

Each transition record must persist, before the first mutation:

- target leaf and trusted relative target-parent locator;
- staged leaf and trusted relative staged-parent locator;
- transaction-scoped backup leaf;
- preimage device/inode and explicit preimage kind;
- staged device/inode and explicit staged kind.

The operation value fixes the expected kinds; a record cannot choose arbitrary kind combinations. Validation rejects nonzero unused fields and noncanonical strings.

## File -> directory state machine

Let F be the owned preimage regular file, D the staged directory, and B the transaction backup.

| State | Target | Staging | Backup |
|---|---|---|---|
| Prepared | F | D | absent |
| Preimage moved | absent | D | F |
| Applied | D | absent | F |

Apply is restartable: verify identities without following symlinks, move F to B using an atomic no-replace rename, fsync both parents, then move D to target using an atomic no-replace rename and fsync both parents. If the process stops between renames, retry resumes only from the exact recorded state.

Rollback runs after dependent child/file changes have been rolled back. It moves the exact D back to staging, then restores the exact F from B to target. It refuses rollback if the target directory is not the recorded inode, if it is not empty after dependent rollback, or if any destination is occupied unexpectedly.

Finalize is permitted only after the enclosing journal is committed. It verifies D at target and F at B, then removes only the recorded regular-file backup after confirming identity and link-count constraints. It never removes the installed directory.

## Empty directory -> file state machine

Let E be the owned, empty preimage directory, S the staged regular file, and B the transaction backup.

| State | Target | Staging | Backup |
|---|---|---|---|
| Prepared | E | S | absent |
| Preimage moved | absent | S | E |
| Applied | S | absent | E |

Apply moves E to B with atomic no-replace rename, fsyncs both parents, then moves S to target and fsyncs both parents. Before the first rename, E must be opened descriptor-relatively with no-follow semantics and proven empty; its device/inode must match the prepared record.

Rollback moves the exact S back to staging, then restores E from B. The backup directory must still be the recorded empty directory. A newly-created entry, changed inode, symlink, or occupied target causes recovery-required rather than destructive cleanup.

Finalize verifies S at target and E at B, then removes only the empty backup directory with `unlinkat(..., AT_REMOVEDIR)`. It must not recurse.

## Durability and recovery rules

- The complete change list is durably journaled before any rename.
- Every rename uses no-replace semantics; unsupported platforms fail closed rather than falling back to a replacing rename.
- Fsync source and destination parent directories after each rename. Preserve existing file/directory fsync policy and transaction lock lifetime.
- Recovery classifies only the exact three states in the applicable table. Any other combination returns recovery-required and leaves all paths untouched.
- Rollback order remains reverse journal order. Transition records must be ordered so child changes are undone before a parent directory transition.
- The executor must resolve each parent locator at the time that record is executed/recovered, not pre-open all target parents before earlier journal operations can create or move them.
- Backup cleanup occurs only after the authenticated journal tombstone/commit protocol permits it. Orphan cleanup must recognize and safely handle only transaction-owned, empty backups.
- All operations remain descriptor-relative under trusted install, staging, and transaction backup roots protected by the existing exclusive package filesystem lock.

## Required tests before enabling planner output

1. Codec canonical round-trip for both operation values; malformed kind combinations and old versions rejected.
2. File-to-directory apply, repeated apply, rollback from each intermediate state, repeated rollback, finalize, and repeated finalize.
3. Empty-directory-to-file equivalents, including interrupted states.
4. Reject non-empty directory, symlink at every involved leaf, special file, hard-linked file, foreign inode substitution, occupied backup, and occupied staged/target destination.
5. Fault injection after each rename and each fsync boundary; recovery must either finish rollback or return recovery-required without deleting unknown data.
6. Journal-level crash recovery and ownership snapshot atomicity for a transaction containing a type transition plus dependent children.
7. Planner tests prove unowned and unsupported transitions remain rejected and that no partial plan escapes on failure.
8. Host ASan/UBSan/fuzz/fault-injection suites and iOS Simulator cross-compile pass. Device-level persistence/recovery validation is still required before enabling production installation.

## Rollout

Implement in layers: (1) versioned record and codec validation, (2) descriptor-relative filesystem state machine, (3) executor/recovery integration, (4) ownership-aware planner integration, (5) fault-injection and simulator validation. Keep planner rejection active until all five layers are complete.

## Parent-directory identity binding

The current recovery locator resolver opens each relative path component with
`O_DIRECTORY | O_NOFOLLOW`, which prevents symlink traversal but does not prove
that a real directory at that path is the same directory used during prepare.
A same-owner or privileged actor could rename the original parent aside and
substitute a different real directory; a path-only journal could then resolve
successfully against the substitute.

Before enabling type transitions, extend the versioned change record and
canonical codec to bind each target, staging, and backup parent to its captured
directory identity (device and inode). Capture those identities from the
already-open parent descriptors during prepare, authenticate them in the
journal, and verify them immediately after every recovery-time parent open and
before each mutation. Root-relative locators must also bind the trusted root
identity, not merely its textual path. Unused identity fields must be zero and
malformed or mismatched identities must fail closed.

Add regression coverage that renames a validated parent aside and substitutes
a different real directory at the same relative path (not just a symlink).
Recovery must reject the replacement directory and leave both the original
objects and substitute directory untouched. Include equivalent target,
staging, and backup parent cases, plus crash/restart execution. This is a
cross-cutting record/codec/executor change and must be completed before the
type-transition planner is enabled.
