# ViTech Swoosh Core

**Private staging release: v0.1.0-preview**

Swoosh Core is the inspectable deterministic authority foundation for governed AI, agents, tools, software and machines.

> **Models may reason. Swoosh decides whether protected action is authorized.**

```text
authenticated human / trusted workload
        ↓
structured action intent
        ↓
canonical Swoosh verifier
        ↓
identity + tenant + role + policy + purpose
resource + destination + generation
policy version + trust epoch + expiry/revocation
        ↓
ALLOW / DENY
        ↓
brokered effect + evidence
```

Natural language, model output, classifiers and observability findings are signals, not capabilities.

## Layout

- `trust-kernel/` — canonical zero-I/O Rust authority engine
- `trust-sdk/` — thin host interface
- `trust-console/` — reference CLI
- `proof-pack/` — adversarial/reproducible validation
- `protocol/` — schemas, fixtures and optional Python codec
- `docs/` — threat model, key management and architecture decisions

## Licensing

- local enforcement/runtime: **MPL-2.0**
- protocol/contracts/schemas/fixtures/docs: **Apache-2.0**

This repo excludes the organization control plane, protected Intelligence Capsule methods, enterprise observability intelligence, production signer custody and customer/institutional data.

**Do not simply trust ViTech. Verify ViTech.**
