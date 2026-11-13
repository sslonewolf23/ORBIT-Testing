# ORBIT package archive inspection boundary

## Scope

The archive inspector is a research-stage, read-only preflight component. It does not itself extract files, invoke package scripts, or mutate an installed package database. A separate private staging module now consumes the inspector only after a complete no-write inspection pass.

It accepts uncompressed `control.tar` and `data.tar`, plus gzip (`.gz`), xz (`.xz`), bzip2 (`.bz2`), and zstd (`.zst`) variants. Both control and data members are inspected. Unsupported suffixes fail closed.

## Decompression policy

- Compressed input: 512 MiB maximum.
- Expanded tar member: 256 MiB maximum.
- Expansion ratio: 200:1 maximum.
- Decoder output chunk: 64 KiB.
- XZ decoder memory: 64 MiB maximum.
- Zstandard decoder window: 64 MiB maximum.
- Exactly one compressed stream is accepted; truncated streams, concatenated streams, and trailing bytes are rejected.

The codec adapters decode incrementally into fixed-size output chunks and feed a stateful ustar parser directly. The parser retains only a 512-byte header buffer, bounded path manifest, and counters; it skips regular-file payload bytes without collecting the expanded tar member. Header parsing, payload skipping, padding, and end-marker validation continue correctly across arbitrary sink chunk boundaries. This is an incremental read-only manifest parser, not an extractor. A data.tar-only callback can stream validated entry records to a caller; callbacks are provisional until the entire .deb passes inspection, so callers must stage and discard all callback output on any later error.

## Accepted tar entries

- Regular files (type NUL or `0`).
- Directories (type `5`) with zero payload size.
- Strict ustar header and checksum.
- Printable ASCII relative paths with no empty or `..` components. Standard leading `./` and root directory entries are normalized safely.

## Rejected entries and formats

- Absolute paths, backslashes, colon characters, control/non-ASCII bytes, and traversal.
- Duplicate manifest paths and file-versus-directory ancestor collisions.
- Symbolic links, hard links, devices, FIFOs, sparse files, PAX, GNU long-name records, and unknown entry types.
- Non-ustar headers, malformed octal fields/checksums, truncated headers or payloads, nonzero payload padding, missing end blocks, and nonzero trailing data.
- Unsupported compression suffixes and malformed compressed streams.

## Resource limits

- Debian container: 512 MiB.
- ar members: 16.
- tar entries across control and data manifests: 4,096.
- path length: 1,024 bytes.
- one regular file: 256 MiB.
- aggregate regular-file payload: 1 GiB.
- expanded compressed tar member: 256 MiB.

The manifest path table is bounded and allocated for inspection only. Parent directories are permitted, but a regular file cannot be an ancestor of another entry.

## Validation and ownership status

The separate ownership planner enforces cross-package path collision policy after archive inspection:

- A candidate cannot replace a regular file owned by another package identity.
- Case-folded path collisions fail closed.
- Regular-file ancestor conflicts are rejected; explicit shared directory ownership is permitted.
- A package upgrade may replace its own prior paths, while unrelated package ownership rows are retained.
- Regression cases live in `harness/orbit-package-ownership-tests.c`.

The archive regression harness also covers duplicate normalized paths, regular-file ancestor collisions, explicit directory parents, absolute paths, backslashes, empty and dot components, parent traversal, colon characters, symlinks, devices, compressed streams, and streaming callback failure. The host workflow is the authoritative execution gate; a source change or queued run is not evidence of a passing test.

## Private staging boundary

`ORBITPackageStaging` creates a new 0700 staging child, creates nested directories relative to trusted directory descriptors, refuses symlink traversal, creates regular files with exclusive/no-follow flags, streams bounded sequential writes, fsyncs file and directory state, and can recursively discard only the staging tree after verifying its directory identity. Archive file modes are sanitized to strip set-id and group/other write permissions; directory staging modes are normalized. The staging API requires the caller to complete ownership conflict checks before invoking extraction. It does not execute maintainer scripts or write into the live install root.

The host staging harness covers normal payloads, empty files, malformed archive preflight with no stage creation, symlink parent refusal, and safe discard. The host workflow is the authoritative execution gate; a source change or queued run is not evidence of a passing test.

## Ownership-first install orchestration

`orbit_package_install_transaction_execute_deb_enveloped` now composes the read-only archive inspector, ownership snapshot validation, private staging, file planner, and authenticated filesystem journal for a complete .deb install attempt.

The orchestration order is deliberately fail-closed:

1. Encode the caller's installed ownership snapshot and require byte-for-byte equality with the committed ownership payload before doing archive work.
2. Verify the install root and staging base are directories on the same filesystem.
3. Inspect the complete .deb and collect the data manifest without creating a staging tree.
4. Build/validate the candidate ownership snapshot. A foreign package manager's ownership conflict aborts before extraction.
5. Extract validated regular-file payloads into a private staging child.
6. Execute the file plan through the authenticated journal, which persists the APPLYING state before live filesystem mutations and supports rollback/recovery.

The caller must hold ORBIT's cross-process transaction lock for the entire operation and through recovery. The caller must retain the staging object until the transaction is committed or recovery has completed, then explicitly discard it. A journal failure does not cause the orchestrator to delete staging data that recovery may still need. The staging base descriptor must refer to a trusted, owner-controlled directory; the caller is responsible for establishing that trust. Maintainer scripts are not executed.

The current file planner requires destination parent directories to exist already in the install root. It does not yet create missing destination directories transactionally; missing parents fail closed. This is a known limitation, not a reason to create directories outside the journal.

The new orchestration regression harness verifies that a candidate colliding with a path owned by another package manager is rejected before a staging directory is created. The separate journal-envelope harness exercises transaction apply, rollback recovery, committed-finalization recovery, write-ahead-store failure, and staged package install/removal flows. The host workflow is the authoritative execution gate; a source change or queued run is not evidence of a passing test.

## Remaining work

1. Complete current host sanitizer and iOS simulator CI runs, including the new orchestration harness.
2. Add a positive-path .deb orchestration test that covers archive inspection through private extraction and journal commit, plus failure injection at staging and journal boundaries.
3. Add transactional destination-directory creation or keep the existing-parent limitation explicit and tested.
4. Tighten staging-base trust checks and exercise mode sanitization, write failures, cleanup interruption, and descriptor/path race conditions.
5. Run broader parser fuzzing and device-specific validation after the production helper and App Attest integration exist.

Installation must remain disabled. These APIs are research-stage components and are not yet integrated into a production package manager or privileged helper. They must not remove, overwrite, or modify files belonging to other package managers.
