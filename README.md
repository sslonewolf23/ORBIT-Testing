# ORBIT-Testing

ORBIT's isolated security verification and compatibility testing environment.

## Current focus

- Host-side RNP 0.18.1 clear-signed Debian `InRelease` verification.
- A bounded C-FFI adapter draft and standalone smoke harness.
- Disposable positive and negative signature fixtures.
- Fail-closed checks for invalid, untrusted, revoked, expired, malformed, oversized, and ambiguous inputs.

## Status

**Experimental — not production-ready.** The verifier and bridge are being transferred for isolated public CI validation. No successful public CI run is claimed yet. The bridge is not integrated into the ORBIT app and must not be used to authorize package installation.

## Community testing

Volunteer tester information, staged testing scope, device-reporting requirements, and safety guidance are documented in [TESTER-PROGRAM.md](TESTER-PROGRAM.md). Use the [Device compatibility report](.github/ISSUE_TEMPLATE/device-test-report.yml) or [Bug report](.github/ISSUE_TEMPLATE/bug-report.yml) issue form when reporting an official test build. There is currently no public installable ORBIT beta in this repository; do not install unofficial binaries or treat this engineering repository as an installer.

## Security boundary

See [SECURITY.md](SECURITY.md) for repository scope and reporting guidance. Never commit private keys, production credentials, tokens, or user data.

## Dependencies

The workflow pins upstream source revisions for reproducibility. RNP, Botan, vcpkg, and other dependencies retain their own upstream licenses; this repository's MIT license does not relicense those dependencies.
