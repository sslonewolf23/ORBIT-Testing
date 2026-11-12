# ORBIT package archive inspection boundary

## Scope

The archive inspector is a research-stage, read-only preflight component. It does not extract files, create directories, invoke package scripts, change ownership or permissions, or mutate an installed package database.

It accepts uncompressed `control.tar` and `data.tar`, plus gzip (`.gz`), xz (`.xz`), bzip2 (`.bz2`), and zstd (`.zst`) variants. Both control and data members are inspected. Unsupported suffixes fail closed.

## Decompression policy

- Compressed input: 512 MiB maximum.
- Expanded tar member: 256 MiB maximum.
- Expansion ratio: 200:1 maximum.
- Decoder output chunk: 64 KiB.
- XZ decoder memory: 64 MiB maximum.
- Zstandard decoder window: 64 MiB maximum.
- Exactly one compressed stream is accepted; truncated streams, concatenated streams, and trailing bytes are rejected.

The codec adapters decode incrementally into fixed-size output chunks and feed a stateful ustar parser directly. The parser retains only a 512-byte header buffer, bounded path manifest, and counters; it skips regular-file payload bytes without collecting the expanded tar member. Header parsing, payload skipping, padding, and end-marker validation continue correctly across arbitrary sink chunk boundaries. This is an incremental read-only manifest parser, not an extractor.

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

## Important remaining work

1. Add package ownership collision policy across already-installed packages.
2. Add CPU/time budgets and fuzz the ar, decompressor, and ustar parsers.
3. Build a staging/extraction backend with descriptor-relative path operations, no-follow semantics, same-filesystem staging, fsync, and atomic replacement.
4. Capture exact preimages for rollback and integrate the result with the durable transaction journal.

Installation must remain disabled. This component is not a production extractor.
