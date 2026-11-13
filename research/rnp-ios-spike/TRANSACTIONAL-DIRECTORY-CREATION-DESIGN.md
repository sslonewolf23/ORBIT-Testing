# Transactional Directory Creation Design

Status: design approved for implementation on `work/package-file-plan`. This document does not claim directory creation is implemented.

## Problem

The current package file planner can replace and remove regular files only when every destination parent directory already exists. Archive extraction already creates the package's directory tree inside the private staging root, but the install journal cannot yet create corresponding directories under the live install root.

Creating live directories before journal execution is not acceptable: a crash or later file failure could leave untracked filesystem changes, and recovery would have no durable record explaining whether those directories belong to the transaction.

## Chosen model: staged-directory rename

Do not add an unjournaled `mkdirat()` side effect to the planner or executor. Reuse the private staging tree as the source of each new directory and add an explicit journal operation that moves a pre-created staged directory into the install tree.

For each directory that is missing from the install root:

1. The planner discovers the missing path components from the validated archive manifest.
2. The planner verifies that the corresponding directory exists under the private staging root, is a real directory opened with `O_NOFOLLOW`, and is on the same filesystem as the install and backup roots.
3. A prepared journal record captures the staged directory's device/inode identity and both relative parent locators before any live filesystem mutation.
4. Journal apply renames that exact staged directory into the target parent with no replacement semantics, then fsyncs both parent directories.
5. Rollback verifies the target still names the recorded directory inode and the staged destination is absent, then renames the directory back into staging. It must be idempotent and fail closed on any unexpected inode or path state.
6. Commit finalization verifies the directory is at the target and leaves it in place. It must not recursively delete or chmod the live directory.

## Ordering and recovery invariants

- Directory-creation records precede every file replacement that depends on those directories.
- Parent directories are created shallowest-first. Journal rollback already runs in reverse, so child directories are moved back before their parents.
- Existing install directories are never replaced, chmodded, or removed by this operation.
- The planner must reject a path whose existing component is a symlink or non-directory.
- A file-to-directory or directory-to-file transition remains unsupported until a separate, explicit migration design exists.
- Directory ownership rows are committed in the same ownership snapshot as the file changes. Uninstall must continue to avoid recursive directory deletion.
- A failed apply or recovery mismatch returns a recovery-required/error result; it must never guess that a similarly named directory is safe to move.
- The operation must be encoded in the authenticated journal format. The journal format version must be bumped; old journal records must not be reinterpreted under the new operation enum.
- All operations remain within descriptor-relative trusted roots and the existing cross-process transaction lock.

## Required implementation and regression coverage

1. Add a new directory-create operation and bump the filesystem change/journal codec versions.
2. Add a prepare helper that accepts target/staged parent descriptors and a directory leaf, validates same-volume and inode/type properties, and emits a canonical journal record.
3. Extend journal validation, apply, rollback, finalize, executor dispatch, codec round-trip tests, and recovery tests for the new operation.
4. Extend the package planner to identify missing directory prefixes, deduplicate them case-insensitively, order them parent-first, and append records before file changes.
5. Test successful nested directory creation plus file install, rollback after a later file failure, crash/recovery between each directory rename and dependent file operation, pre-existing directory preservation, symlink/non-directory rejection, and unexpected inode replacement.
6. Test that rollback restores staged directory trees and staged file payloads so retry remains possible.
7. Keep the production install path disabled until host sanitizer tests, iOS simulator compilation, and device-level recovery validation are complete.

## Important limitation

The existing filesystem journal currently models regular-file replace/remove operations and its executor opens target parent directories before each operation. Supporting nested directory creation therefore requires the executor to resolve parent paths only after earlier parent-creation records have applied. The implementation must preserve that sequential behavior and must not pre-open every target parent before the transaction starts.
