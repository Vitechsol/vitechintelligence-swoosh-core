# SWOOSH Reproducible Proof Pack

**Status:** BUILT — HARDENING REQUIRED

## Run

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p trust-kernel --no-default-features
cargo check -p trust-kernel --target wasm32-unknown-unknown --no-default-features
cargo test --workspace --all-targets
cargo run -p proof-pack --quiet
```

The final command prints one deterministic JSON report for four industrial drills. It does not access the network or production credentials.

## Drill contracts

### Revocation

A valid claim succeeds, then the same opaque claim ID is inserted into a higher-sequence status manifest. Evaluation must return `ClaimRevoked`.

### Offline

A valid signed claim and bounded TrustPack succeed using only supplied bytes. At the exact TrustPack `valid_until` boundary, evaluation must fail with `TrustPackExpired` before claim parsing.

### Recovery

The harness writes a valid local pack, evaluates it, purges the temporary state directory, verifies a clean pack against its pinned checkpoint, restores the state and evaluates the claim again.

### Key rotation

A higher-epoch, next-generation root deprecates the old claim key and adds a rotated key. The update must validate against the current pack signer. A pre-rotation old-key claim remains valid during the acceptance window, a rotated-key claim succeeds, and new issuance with the deprecated key fails.

## Adversarial/property suite

`proof-pack/tests/adversarial.rs` covers signature tampering, unknown issuer, expiry, stale claims, trust-domain mismatch, policy denial, Trust Epoch rollback, oversized claims and arbitrary byte-input parser properties.

## Interpretation

Passing this pack proves deterministic behavior for the implemented profile and fixtures. It does not replace external review, production key custody, live pilot drills, representative hardware testing, a secure clock strategy or measured performance evidence.
