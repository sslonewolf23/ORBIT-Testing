# ORBIT

**A modern iOS package manager in development.**

ORBIT is an independent package manager project focused on a modern iOS experience, Debian/APT repository compatibility, and safer package-management workflows. The project is targeting iOS 18–27 and rootless/rootful jailbreak environments; compatibility across those combinations has not yet been established.

## Community

We're building a volunteer community of iOS users, jailbreak enthusiasts, developers, repository maintainers, and package creators. We want broad device and environment coverage—not just testing on one phone.

- **[Volunteer tester interest form](https://github.com/sslonewolf23/ORBIT-Testing/issues/new?template=volunteer-interest.yml)** — tell us you'd like to participate. This is an expression of interest, not beta access.
- **[Public tester program](TESTER-PROGRAM.md)** — testing stages, safety requirements, and what information to provide.
- **[Device compatibility report](https://github.com/sslonewolf23/ORBIT-Testing/issues/new?template=device-test-report.yml)** — for results from an explicitly announced official build.
- **[Bug report](https://github.com/sslonewolf23/ORBIT-Testing/issues/new?template=bug-report.yml)** — for reproducible defects in official builds.

Please do not post UDIDs, serial numbers, IMEIs, Apple IDs, credentials, private keys, tokens, or unredacted personal logs in public issues.

## Release status

<ins>There is currently no public installable ORBIT beta or package-installation build.</ins> The app and package engine are still in active development. Do not install unofficial binaries, profiles, debs, or links claiming to be ORBIT.

A future test release will be announced with its exact version, supported devices/environments, enabled feature scope, known issues, installation instructions, and checksums. Privileged package operations will remain disabled until their security and recovery gates have been implemented and validated.

## Engineering validation

This public repository contains isolated security-verification and compatibility-testing materials. It is not the ORBIT app source repository and is not an installer.

Current experimental work includes:
- Host-side RNP/OpenPGP verification and a bounded C-FFI adapter.
- Positive and negative signature fixtures.
- Fail-closed validation for invalid, untrusted, revoked, expired, malformed, oversized, and ambiguous inputs.

**Experimental — not production-ready.** The verifier bridge is not integrated into the ORBIT app and must not authorize package installation. No production verifier integration or public installable build is claimed here.

## Safety and security

Read [TESTER-PROGRAM.md](TESTER-PROGRAM.md) before volunteering. For security-sensitive reports, follow [SECURITY.md](SECURITY.md) and do not publish exploit details in public issues.

## Dependencies and licensing

The workflow pins upstream source revisions for reproducibility. RNP, Botan, vcpkg, and other dependencies retain their own upstream licenses. This repository's MIT license does not relicense those dependencies.
