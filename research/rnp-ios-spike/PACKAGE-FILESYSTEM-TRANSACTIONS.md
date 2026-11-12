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

The backend contract requires authenticated loads, atomic stores, a monotonic revision retained even after clear, and compare-by-revision clearing. It must encode fields canonically; raw C struct persistence is not acceptable. The host harness uses an in-memory backend only. No production iOS persistence adapter is connected yet. The caller must hold the package-wide exclusive transaction lock across journal execution or recovery, backup-directory creation, and cleanup.

## Limitations

- Regular files only; directory creation/removal and directory-mode rollback are not handled here.
- No ownership database commit, package-level dependency ordering, live-root adapter, or privileged helper.
- File uid/gid, ACLs, extended attributes, flags, and directory metadata are not preserved by this primitive.
- No maintainer scripts are executed.
- Hard-link preimages and rename semantics still require validation on each supported jailbreak filesystem and physical device.
- The host harness is authored and wired under AddressSanitizer/UndefinedBehaviorSanitizer, but has not been run.

Installation remains disabled.
