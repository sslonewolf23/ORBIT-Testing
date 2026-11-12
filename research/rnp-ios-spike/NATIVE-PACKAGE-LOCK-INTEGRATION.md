# Native package-manager lock coordination

## Purpose

ORBIT's private `.orbit-package-transaction.lock` only serializes ORBIT processes.
It does not coordinate with the target jailbreak's existing APT/dpkg clients.
Before ORBIT reads or mutates the live package database or package-owned files,
the privileged adapter must acquire the target's native package-manager locks
as well as ORBIT's own transaction lock, and retain them through recovery,
rollback/finalization, and durable journal cleanup.

## Lock primitive

The isolated `ORBITPackageNativeLock` helper uses POSIX `fcntl(F_SETLK)`
whole-file write locks. This is intentionally distinct from `flock()`: Linux
and Darwin expose different lock namespaces for flock and POSIX record locks.
A flock-only implementation would not coordinate with a package manager using
fcntl record locks.

The helper takes an already-open trusted parent directory descriptor and an
existing lock-file leaf name. It does not create or unlink native lock files.
It rejects symlinks, non-regular files, multiply-linked files, unexpected
owner, group/world-writable lock files, cross-volume entries, and name/inode
replacement during acquisition. Lock contention returns BUSY. It checks the
same inode again at release and reports CONFLICT if the pathname was replaced.

## Integration contract

The target-specific privileged adapter must provide:
- The exact lock-file locations for each supported jailbreak/bootstrap and
  package-manager version; do not guess paths or silently skip missing locks.
- The expected lock-file owner and trusted parent descriptors.
- The native package manager's documented acquisition order. Acquire every
  required native lock in that order, and release in reverse order.
- A single process-wide ORBIT coordinator lock held before native locks, to
  serialize ORBIT callers and avoid same-process POSIX-lock reentrancy.
- A policy for process lifecycle, cancellation, interruption, and recovery.
  A BUSY result must not be bypassed or converted into success.
- A compatibility test against the actual target APT/dpkg build proving that
  its process cannot obtain the same lock while ORBIT holds it, and vice versa.

Do not invent a universal list of APT locks. A common Debian-family setup has
frontend and dpkg database locks, but jailbreak layouts and implementations
vary. Discover and verify them from the selected bootstrap's own package
manager source/build and runtime configuration. In particular, never acquire
locks in an order that can deadlock with apt/dpkg.

## POSIX record-lock caveat

POSIX record locks are process-associated. Closing *any* descriptor for the
same lock inode in the same process can release the process's locks on that
inode. Do not open/close a second descriptor for a held native lock. The
ORBIT coordinator must serialize same-process operations and centralize all
opens/closes. Locks are advisory; privileged non-cooperating writers remain
outside this guarantee.

## Current status

The portable helper and host contention harness are research-only. They are
not wired into the app or privileged helper. No actual jailbreak/bootstrap
target has been selected and no real APT/dpkg interoperability test has been
performed. Therefore this work does not close the production filesystem
concurrency gate. Package installation remains disabled.
