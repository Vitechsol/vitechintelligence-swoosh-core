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

## Local setup

```bash
cargo test --locked --workspace --all-targets
cargo run --locked -p proof-pack --quiet
```

For protocol changes:

```bash
cd protocol
python -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m unittest discover -s tests -v
```

## Issues and pull requests

- Search existing issues before opening a duplicate.
- Use a minimal reproducible case for bugs.
- For authority-sensitive changes, explain the invariant being changed and include positive and adversarial tests.
- Issues labeled `good first issue` are intended for contributors who are new to the codebase.
- Security vulnerabilities belong in the process described by `SECURITY.md`, not public issue threads.

By participating, contributors agree to follow `CODE_OF_CONDUCT.md`.

## Proposal-first changes

Before coding a substantial change to authority semantics, protocol contracts, cryptographic/trust assumptions, or interoperability behavior, open a **Feature or architecture proposal** issue first.

Maintainers may require an Architecture Decision Record (ADR) before implementation. This keeps high-impact changes reviewable and prevents contributors from spending time on designs that conflict with Swoosh's security invariants or open/commercial boundary.

Small bug fixes, tests, documentation corrections, and clearly scoped maintenance work can proceed through the normal pull-request workflow.
