# ORBIT Public Tester Program

**Status: recruiting volunteer interest — no public installable ORBIT beta is being distributed by this repository yet.**

ORBIT is an independent iOS package manager project. We are building a community of device owners, jailbreak users, repository maintainers, package developers, and testers who can help validate compatibility and security before a public beta.

See [PUBLIC-RELEASE-STATUS.md](PUBLIC-RELEASE-STATUS.md) for the current release stage and the exact gates before an installable beta is announced.

## What testers can help with

Testing will open in stages. The available scope will be stated in each build announcement.

### Stage 1 — preview and non-destructive validation
- Review the interface and report usability/accessibility issues.
- Check app launch, navigation, diagnostics, and read-only screens.
- Review repository metadata display and report incorrect compatibility information.
- Submit device and environment details for the compatibility matrix.

### Stage 2 — controlled device validation
Only when a specific build and test plan are published:
- Validate supported device and jailbreak/bootstrap detection.
- Test authenticated repository refresh and signer warnings.
- Inspect package metadata and dependency plans.
- Exercise install/remove/rollback only when those operations are explicitly enabled in that build's release notes and the relevant safety gates have passed.

A preview build is not permission to experiment with privileged operations. Never attempt to bypass a disabled feature or safety gate.

## Current availability

There is **no public installable beta or package-installation build available from this repository at this time**. Do not download or install unofficial ORBIT binaries, profiles, debs, or links claiming to be official. Wait for a release announcement from the ORBIT project that links to a versioned build and its checksum.

The ORBIT-Testing repository contains engineering and CI validation materials; it is not itself an installer.

## Device information requested

When submitting a compatibility report, include only what is needed:
- Device model (for example, iPhone 15).
- Exact iOS/iPadOS version and build number, if available.
- Jailbreak name and version, if applicable.
- Bootstrap name/version, if applicable.
- Rootless or rootful environment, or "not sure".
- ORBIT build/version and test stage.
- What you expected, what happened, and reproducible steps.

**Never post your device UDID, serial number, IMEI, Apple ID, passwords, private keys, tokens, personal files, or unredacted logs containing personal information.** Redact identifying details before attaching logs or screenshots.

## Safety and risk notice

Participation is voluntary. Pre-release software can contain serious defects and may cause application crashes, data loss, package database corruption, loss of jailbreak functionality, boot loops, or require a device restore.

- Prefer a spare test device that contains no important personal data.
- Make and verify a recoverable backup before testing.
- Keep the device charged and understand how to restore it before participating.
- Do not test on a device you cannot afford to erase or restore.
- Do not add unknown repositories or install packages from untrusted sources.
- Do not run destructive tests unless the exact build's instructions explicitly request them.
- Stop immediately if the device becomes unstable or ORBIT reports recovery-required/safe mode.
- Do not treat "at your own risk" as a substitute for a test plan or verified recovery path.

ORBIT developers cannot guarantee that a pre-release build will preserve your device or data. No one is required to test any feature.

## Reporting problems

Use the **Device compatibility report** issue form for environment and test results, or **Bug report** for a reproducible defect. Include the build version and relevant logs after removing secrets and personal data.

For suspected security vulnerabilities, do not publish exploit details or sensitive proof-of-concept material in a public issue. Follow [SECURITY.md](SECURITY.md) and report privately.

Be respectful: reports are most useful when they are factual, reproducible, and include enough environment detail to investigate.

## Tester program principles

- No forced installation or destructive testing.
- No collection of UDIDs or personal account credentials.
- Clear build provenance, versioning, checksums, known issues, and supported environments for every test release.
- Clear distinction between preview-only capabilities and enabled package operations.
- Acknowledgement of reports and transparent status updates where practical.

Thank you for helping make ORBIT safer and more compatible.
