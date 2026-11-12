# Native package-manager lock coordination

## Purpose

ORBIT's private `.orbit-package-transaction.lock` only serializes ORBIT processes.
It does not coordinate with the target jailbreak's existing APT/dpkg clients.
Before ORBIT reads or mutates the live package database or package-owned files,
the privileged adapter must acquire the target's native package-manager locks
as well as ORBIT's own transaction lock, and retain them through recovery,
rollback/finalization, and durable journal cleanup.

## Verified APT lock behavior and primitive

The Procursus build repository currently builds upstream APT 2.9.4 and sets
its state directory under `$(MEMO_PREFIX)/var/lib/apt`. The APT Debian-system
backend derives the dpkg administration directory from `Dir::State::status`;
with that Procursus layout the default administration directory is
`$(MEMO_PREFIX)/var/lib/dpkg`. Procursus also builds and packages dpkg. Its
APT build patches do not replace the upstream lock implementation.

The upstream APT implementation uses `open(..., O_RDWR | O_CREAT | O_NOFOLLOW,
0640)` and `fcntl(F_SETLK)` for a whole-file write lock. `debSystem::Lock`
acquires `lock-frontend` first, then `LockInner` acquires `lock`. The new
`ORBITPackageNativeLock` helper now matches the create/open flags, mode, and
fcntl locking primitive. It rejects symlinks, non-regular files, multiply-
linked files, unexpected owner, group/world-writable lock files or parent
directories, cross-volume entries, and name/inode replacement during
acquisition. Lock contention returns BUSY. It checks the same inode again at
release and reports CONFLICT if the pathname was replaced.

The `ORBITPackageBootstrapProfile` and `ORBITPackageBootstrapLockset` modules
model the shared relative `var/lib/dpkg` location under a caller-supplied
trusted bootstrap root, then acquire frontend followed by dpkg lock and
release in reverse order. Rootful Procursus uses a verified root descriptor;
rootless Procursus uses a descriptor for the resolved bootstrap root (the
well-known `/var/jb` link must be resolved and validated before this layer is
called). The Dopamine/ElleKit profile intentionally aliases the Procursus
rootless package-database layout: ElleKit is a tweak-injection platform, not a
separate package bootstrap or package-manager lock protocol.

The profile is only a default. Before use, the runtime adapter must inspect the
active APT configuration and confirm `Dir::State::status` resolves to this
profile's dpkg administration directory. If it is overridden, the profile
must fail closed rather than locking a guessed path. The lockset does not yet
acquire APT archive-cache or package-list locks; those are separate resource
locks and should only be added if ORBIT shares those mutable directories.

## Integration contract

The target-specific privileged adapter must provide:
- The exact trusted bootstrap root descriptor and expected lock-file owner.
- The active APT `Dir::State::status` value, validated against the selected profile.
- The native package manager's documented acquisition order. For the verified
  APT Debian-system backend, acquire `lock-frontend` then `lock`; release in
  reverse order. Do not silently skip missing directories or invalid lock files.
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

The helper, profile, lockset and host harness are research-only. They are not
wired into the app or privileged helper. The profile defaults are grounded in
the current Procursus build recipe and upstream APT lock behavior, but the
actual Procursus-built APT/dpkg binaries have not yet been exercised on-device.
No real APT/dpkg interoperability test has been performed on either a rootful
Procursus jailbreak or Dopamine's rootless Procursus bootstrap. Therefore this
work does not close the production filesystem concurrency gate. Package
installation remains disabled.
