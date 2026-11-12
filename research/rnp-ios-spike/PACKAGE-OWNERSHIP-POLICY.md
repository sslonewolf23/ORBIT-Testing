# ORBIT installed-package file ownership policy

## Scope
This module plans ownership changes only. It does not extract archives, mutate files, or persist an installed-package database. Inputs are a validated ownership snapshot and candidate manifest from archive inspection. The archive API exposes a data.tar-only entry callback; the convenience planner stages every callback entry and discards the entire manifest unless the complete Debian archive validates.

## Install and upgrade rules
- Package identity is Debian package name plus architecture; version is retained as audit metadata.
- Regular-file paths are exclusive. A candidate cannot overwrite a path owned by another package.
- Directory paths may be shared by packages.
- A regular file cannot be an ancestor of another path.
- Candidate paths are revalidated using the archive inspector path policy; duplicates and collisions fail closed. Ownership comparisons fold ASCII case conservatively so case-only path aliases cannot collide on a case-insensitive target volume.
- Malformed or duplicate installed ownership records fail closed.
- Bounds: 4,096 candidate paths and 8,192 installed ownership records.

## Removal rules
A removal plan includes paths recorded for the package identity. Shared directories are omitted while another package still references them or owns a descendant path. Unknown packages cannot request a removal plan.

## Integration boundary
The module is not yet connected to persistent package state or the transaction engine. A future installer must atomically commit ownership database changes with filesystem mutations, and remove directories only with descriptor-relative, non-following operations after confirming they are empty. Ownership must be derived from inspected data archive manifests, never package maintainer scripts.

Installation remains disabled. This is not a filesystem mutator.


## Complete snapshot transitions

The module now includes complete-snapshot builders:

- Install/upgrade removes all prior rows for the same package name and architecture, retains unrelated package rows, then adds the candidate manifest rows.
- Removal removes every row for the selected package identity while retaining all other owners, including packages that share directory ownership.
- The complete result is validated before it is returned. The caller supplies the output storage; it must not overlap the installed snapshot's record storage.

Host regression tests cover upgrade replacement of stale paths and preservation of shared-directory ownership on removal. These transition builders do not write persistent state and must not be called as a substitute for the transaction journal.

## Persistence boundary

A canonical ownership codec is available and host-tested. It is serialization only: it provides neither authentication nor anti-rollback protection. The pending and committed snapshots must be carried in the same authenticated, monotonic envelope as the filesystem journal, with promotion occurring only when a COMMITTED file transaction has completed finalization. See [PACKAGE-FILESYSTEM-TRANSACTIONS.md](PACKAGE-FILESYSTEM-TRANSACTIONS.md) for the required crash-consistent state transitions.

No production ownership store or device transaction integration is connected yet. Installation remains disabled.
