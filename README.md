# ORBIT-Testing

ORBIT's isolated security verification and compatibility testing environment.

## Current focus

- Host-side RNP 0.18.1 clear-signed Debian `InRelease` verification.
- A bounded C-FFI adapter draft and standalone smoke harness.
- Disposable positive and negative signature fixtures.
- Fail-closed checks for invalid, untrusted, revoked, expired, malformed, oversized, and ambiguous inputs.

## Status

**Experimental — not production-ready.** The verifier and bridge are being transferred for isolated public CI validation. No successful public CI run is claimed yet. The bridge is not integrated into the ORBIT app and must not be used to authorize package installation.

## Security boundary

See [SECURITY.md](SECURITY.md) for repository scope and reporting guidance. Never commit private keys, production credentials, tokens, or user data.

## Dependencies

The workflow pins upstream source revisions for reproducibility. RNP, Botan, vcpkg, and other dependencies retain their own upstream licenses; this repository's MIT license does not relicense those dependencies.
