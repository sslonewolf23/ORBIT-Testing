# ORBIT package archive inspection boundary

## Scope

The archive inspector is a research-stage, read-only preflight component. It does not extract files, create directories, invoke package scripts, change ownership or permissions, or mutate an installed package database.

It parses the Debian ar container and validates the data archive's ustar manifest. The first implementation intentionally accepts only uncompressed `control.tar` and `data.tar`. Common compressed variants (`.gz`, `.xz`, `.bz2`, `.zst`) return `ORBIT_ARCHIVE_UNSUPPORTED_COMPRESSION`; they are not guessed, partially decoded, or passed through to an extractor.

## Accepted tar entries

- Regular files (type NUL or `0`).
- Directories (type `5`) with zero payload size.
- Strict ustar header and checksum.
- Printable ASCII relative paths with no empty, `.`, or `..` components.

## Rejected entries and formats

- Absolute paths, backslashes, colon characters, control/non-ASCII bytes, and traversal.
- Duplicate manifest paths.
- Symbolic links, hard links, devices, FIFOs, sparse files, PAX, GNU long-name records, and unknown entry types.
- Non-ustar headers, malformed octal fields/checksums, truncated members, missing end blocks, and nonzero trailing data.
- Compressed tar members until a bounded streaming decompressor is implemented.

## Resource limits

- Debian container: 512 MiB.
- ar members: 16.
- tar entries: 100,000.
- path length: 1,024 bytes.
- one regular file: 256 MiB.
- aggregate regular-file payload: 1 GiB.

These are policy ceilings, not a promise that the current implementation can hold or extract an archive of those sizes. The manifest path table is bounded and allocated for inspection only.

## Important remaining work

1. Add bounded streaming decoders for gzip, xz, bzip2, and zstd with strict output, memory, CPU, and trailing-data limits.
2. Inspect both control and data tar manifests and validate their relationship.
3. Add parent/child path collision checks and package ownership collision policy.
4. Build a staging/extraction backend with descriptor-relative path operations, no-follow semantics, same-filesystem staging, fsync, and atomic replacement.
5. Capture exact preimages for rollback and integrate the result with the durable transaction journal.
6. Run the full host suite and fuzz the ar/ustar parser before any device integration.

Installation must remain disabled. This component is not a production extractor.
