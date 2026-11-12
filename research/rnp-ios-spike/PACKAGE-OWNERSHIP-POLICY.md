# ORBIT installed-package file ownership policy

## Scope
This module plans ownership changes only. It does not extract archives, mutate files, or persist an installed-package database. Inputs are a validated ownership snapshot and candidate manifest from archive inspection.

## Install and upgrade rules
- Package identity is Debian package name plus architecture; version is retained as audit metadata.
- Regular-file paths are exclusive. A candidate cannot overwrite a path owned by another package.
- Directory paths may be shared by packages.
- A regular file cannot be an ancestor of another path.
- Candidate paths are revalidated using the archive inspector path policy; duplicates and collisions fail closed.
- Malformed or duplicate installed ownership records fail closed.
- Bounds: 4,096 candidate paths and 8,192 installed ownership records.

## Removal rules
A removal plan includes paths recorded for the package identity. Shared directories are omitted while another package still references them. Unknown packages cannot request a removal plan.

## Integration boundary
The module is not yet connected to persistent package state or the transaction engine. A future installer must atomically commit ownership database changes with filesystem mutations, and remove directories only with descriptor-relative, non-following operations after confirming they are empty. Ownership must be derived from inspected data archive manifests, never package maintainer scripts.

Installation remains disabled. This is not a filesystem mutator.
