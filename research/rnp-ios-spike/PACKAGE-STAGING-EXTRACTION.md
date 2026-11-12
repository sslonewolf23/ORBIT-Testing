# ORBIT private package staging

## Scope

This is a research-stage, descriptor-relative extractor for the validated `data.tar` payload. It writes only beneath a caller-supplied trusted directory descriptor. It does not install into the live filesystem, run package scripts, set ownership, create links, or activate packages.

## Archive-to-stage flow

Call `orbit_package_staging_begin` with an already-open trusted base directory and a new single-component staging name. Pass the staging callbacks to `orbit_package_archive_inspect_deb_with_data`:

- `orbit_package_staging_entry_callback` creates directories and exclusive regular-file placeholders from the validated data manifest.
- `orbit_package_staging_data_callback` writes each file's data chunks, checking the path, exact offset, expected byte count, and final-chunk marker.
- Call `orbit_package_staging_finish` only if the complete archive inspection returns `ORBIT_ARCHIVE_OK`.

All callback writes are provisional. If archive inspection or staging fails, discard the entire staging tree. The archive callback API intentionally does not promise that callbacks are delivered only after the complete archive has validated.

## Filesystem protections

- Uses `openat`, `mkdirat`, `fstatat`, `unlinkat`, and descriptor-relative traversal.
- Uses `O_NOFOLLOW` and `O_DIRECTORY` for directory traversal and file creation.
- Rejects unsafe archive paths, symlink parents, existing file destinations, non-regular file descriptors, and unexpected link counts.
- Creates a new private 0700 staging root; implicit directories are 0755.
- Preserves only validated ordinary permission bits (0777); setuid, setgid, and sticky bits are rejected by archive inspection.
- Writes files with exclusive creation, verifies exact payload offsets and lengths, and fsyncs completed files and relevant directories.
- Recursive discard uses no-follow metadata inspection and descriptor-relative unlink operations; partial cleanup can be retried.

## Deliberate limitations

This module is not a production iOS privileged installer. It has no live-root commit, atomic multi-file swap, filesystem snapshot, package database transaction, ownership database commit, rollback restoration, code-signing policy, or physical-device validation. It does not execute `preinst`, `postinst`, `prerm`, `postrm`, or other maintainer scripts. Packages that depend on those scripts will need an explicit, separately reviewed policy before they can be installed.

The caller must keep the base directory trusted and private while staging. The iOS adapter must additionally validate the actual jailbreak filesystem, privilege boundary, volume semantics, and durability behavior on supported devices.

Installation remains disabled.
