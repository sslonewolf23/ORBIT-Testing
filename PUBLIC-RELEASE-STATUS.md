# ORBIT Public Test Release Status

**Current stage: volunteer recruitment and non-destructive preview only. No installable beta is available.**

ORBIT is being built as a proprietary iOS package manager. The public tester repository is for volunteer coordination, compatibility feedback, and issue reporting; it is not an installer or a source-code release.

## What is available now

- Volunteer interest form.
- Device compatibility report form.
- Bug report form.
- Non-destructive review of preview UI and project information.
- Engineering progress updates and tester safety guidance.

## What is not available

- No public IPA, signed test build, package, profile, or installation link.
- No live repository refresh or public repository-key enrollment flow.
- No package install/remove/upgrade/downgrade testing.
- No validated public device/jailbreak compatibility matrix.

Do not install unofficial binaries or unsigned CI artifacts. Do not attempt to bypass disabled controls or perform privileged operations.

## What must happen before a controlled device beta

1. Finish and review the transaction/recovery and adversarial archive test matrix.
2. Validate RNP runtime behavior and environment/privilege detection on disposable physical devices.
3. Validate rootless and rootful filesystem boundaries on the exact supported combinations.
4. Keep maintainer scripts disabled until a safe execution boundary is reviewed.
5. Integrate the app's live repository/trust presentation without enabling unsafe operations.
6. Produce a signed, versioned device build with SHA-256 checksums and reproducible build provenance.
7. Publish supported environments, known issues, explicit test steps, privacy/redaction guidance, and a stop-testing/recovery procedure.
8. Obtain an explicit release review before sharing any installable artifact.

A passing Swift test suite, simulator build, host cryptographic fixture run, or Apple-target compile/link is useful engineering evidence, but none alone establishes physical jailbroken-device compatibility.

## Volunteer participation

Volunteers can still help by reviewing the preview, reporting accessibility/usability issues, and sharing non-sensitive device/environment compatibility information through the issue forms. Never submit UDID, serial number, IMEI, Apple ID, credentials, private keys, tokens, or unredacted personal logs.

See [TESTER-PROGRAM.md](TESTER-PROGRAM.md) for full safety and reporting instructions.
