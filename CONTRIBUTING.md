# Contributing

Read `README.md`, `SECURITY.md`, `docs/security/THREAT_MODEL.md` and the ADRs before changing authority-sensitive code.

Preserve:
- one canonical deterministic Rust authority kernel;
- fail-closed behavior;
- model/provider neutrality;
- bounded parsing;
- revocation, expiry and anti-rollback semantics;
- protocol interoperability without duplicating authority logic.

Do not add secrets, customer data, signing keys, protected Capsule content or enterprise control-plane code.
