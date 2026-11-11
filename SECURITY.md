# Security and testing boundaries

ORBIT-Testing is a public, isolated environment for reproducible host-side verification research.

## Scope

- This repository contains only the RNP host verifier, test harnesses, disposable fixture generation, and related design notes.
- CI-generated OpenPGP secret keys are disposable test material. They must never be reused or committed.
- The workflow uses pinned source revisions for RNP, its `libsexpp` submodule, and vcpkg.
- CI is granted read-only repository contents permission.

## Explicit non-goals

- No production ORBIT application code or proprietary interface code belongs here.
- No signing keys, production repository credentials, tokens, or user data belong here.
- Passing host tests does not authorize package installation or enable the production verifier.
- Host results do not establish iOS device compatibility, simulator compatibility, trust-store safety, or package integrity.

## Reporting

Report suspected vulnerabilities privately to the repository maintainer rather than publishing exploit details in an issue. Include the affected commit, reproduction steps, and impact where possible.
