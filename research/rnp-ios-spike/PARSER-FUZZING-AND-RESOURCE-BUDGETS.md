# ORBIT parser fuzzing and resource budgets

## Production parser bounds

The package archive path validator no longer performs a full pairwise path comparison while streaming each tar header. It stages at most 4,096 bounded path records, sorts them once with an in-place heapsort, rejects adjacent duplicates, and uses binary lower-bound searches to detect regular files that would be ancestors of another entry. This keeps collision validation at bounded sort/search complexity rather than quadratic scans over every path pair.

The decompression layer applies these ceilings before or during decoding:

- compressed input: 512 MiB maximum
- expanded output: 256 MiB maximum
- expansion ratio: 200:1 maximum
- output callback chunk: 64 KiB
- XZ decoder memory cap: 64 MiB; Zstandard maximum window: 64 MiB
- decoder iterations: 16,384 maximum per stream
- exactly one stream: truncated, concatenated, or trailing data is rejected

The iteration ceiling is a deterministic loop bound, not a wall-clock guarantee for an individual codec call; total compressed input and expanded output are independently capped. The host fuzz runner additionally applies a two-second per-input timeout and a 1 GiB process RSS limit.

## Fuzz target

`harness/orbit-package-parser-fuzz.c` is an LLVM libFuzzer entry point. Each bounded input is exercised against:

- Debian ar/.deb container inspection
- incremental ustar parsing at varied chunk boundaries
- gzip, xz, bzip2, and zstd streaming decoders

The target caps each fuzz input and each decoder output at 1 MiB. It discards decoded output rather than retaining attacker-controlled expanded data. The host workflow builds the target with AddressSanitizer and UndefinedBehaviorSanitizer and runs it for 45 seconds using a dictionary plus valid minimal .deb and compressed-stream seeds. Fuzzer corpus and crash artifacts are uploaded with the host evidence.

## Validation status

The deterministic edge-case tests and fuzz target are authored and wired into the host workflow on the development branch. They have **not** been run yet. No claim of compilation, sanitizer cleanliness, or fuzz success is made until the user authorizes the final runner pass.

## Security boundary

Fuzzing and parser bounds do not make package installation safe by themselves. The archive layer remains inspection-only: it does not extract files, execute maintainer scripts, mutate the filesystem, or activate packages. Installation remains disabled pending device-backed durable state, safe staged extraction, atomic replacement, rollback restoration, and end-to-end integration.
