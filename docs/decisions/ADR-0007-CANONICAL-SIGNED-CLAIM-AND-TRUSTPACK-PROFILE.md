# ADR-0007 — Canonical Signed Claim and TrustPack Profile

- **Status:** Accepted
- **Date:** 2026-08-30
- **Decision scope:** First implemented claim profile, canonical serialization, verifier key custody, TrustPack bootstrap/update, Rust SDK boundary
- **Depends on:** ADR-0001 through ADR-0006

## Context

SWOOSH requires one real claim profile and one deterministic implementation before additional external credential adapters are added. The repository already locks Rust as the canonical kernel, standard cryptography, explicit time injection, bounded offline state, signed authoritative publication and anti-rollback.

The implementation needs a compact internal profile that is deterministic under native and `no_std + alloc` builds, does not require JSON normalization inside the kernel and is straightforward to reproduce in the Proof Pack.

## Decision

SWOOSH supports exactly one claim profile in this phase: **SWOOSH Signed Claim Profile v1**.

The profile is a strongly typed, versioned organizational claim envelope. It uses Ed25519 signatures verified by `ed25519-dalek::VerifyingKey::verify_strict`. SWOOSH does not implement or claim a new signature algorithm.

The profile binds:

- opaque claim ID;
- trust domain;
- issuer and key ID;
- pseudonymous subject commitment;
- issue and expiry times;
- action, resource and capability;
- assurance level;
- evidence digest.

No raw identity record or evidence file is carried by the profile.

## Canonical bytes

Signature material uses a manually specified, domain-separated encoding:

- fixed domain separator;
- fixed field order;
- unsigned integers in big-endian form;
- UTF-8 identifiers with unsigned 32-bit length prefixes;
- fixed-size digests as raw bytes;
- enums as explicit one-byte discriminants;
- no maps, locale processing, floating point, native struct layout or host endianness.

Postcard is used only as the bounded wire envelope. Cryptographic signatures and fingerprints never depend on Postcard implementation details.

## Trust anchors and key custody

The verifier receives public keys only. A `TrustAnchorRoot` is isolated inside the signed TrustPack and binds each key to one trust domain, issuer, key ID, Ed25519 algorithm, purpose, validity window and lifecycle state.

Key purposes are non-interchangeable:

- `ClaimSigning`;
- `TrustPackSigning`.

Production private keys remain outside the kernel, SDK, browser, repository and Proof Pack runtime. The deterministic private keys in `proof-pack` are test vectors only and are not production credentials.

## TrustPack bootstrap and updates

A TrustPack is a signed, bounded checkpoint containing:

- trust domain and monotonic Trust Epoch;
- root generation and public trust anchors;
- embedded status/revocation manifest;
- deterministic default-deny policy;
- claim and offline freshness limits;
- validity boundaries.

Initial installation requires an out-of-band pinned SHA-256 checkpoint. A self-signature alone is not accepted as bootstrap authority.

Each revocation is stored as a canonical `rev1:` identifier: a domain-separated SHA-256 digest over the length-prefixed issuer ID and issuer-local claim ID. This prevents one issuer's claim-ID namespace from revoking another issuer's claim while avoiding raw identifiers in the status index. Accepted transitions are append-only for revocations; removing an existing revocation is rejected as rollback. Reinstatement requires a future explicitly governed profile and is not supported by v1.

Subsequent installation requires:

1. a valid current installed pack;
2. a valid candidate pack;
3. a strictly greater Trust Epoch;
4. no status, append-only revocation set or policy rollback;
5. the same root identity;
6. an unchanged root generation or exactly one generation of advancement;
7. a candidate signature authorized by the current root;
8. an exclusive host-side advisory lock spanning read, verification and atomic replacement.

This phase implements signed full checkpoints, not delta transport. Delta selection/distribution remains a later synchronization layer.

## Evaluation order

After bounded decoding and TrustPack validation, the claim pipeline fails closed in this order:

1. issuer/key authorization and strict signature verification;
2. embedded status/revocation lookup;
3. claim expiry;
4. issue-time and maximum-age freshness;
5. default-deny policy binding;
6. privacy-minimized receipt generation.

The host supplies Unix time. The kernel never reads a wall clock, filesystem, network, environment or random source.

## SDK and console

The Rust SDK exposes:

```rust
pub fn evaluate_claim(
    claim_bytes: &[u8],
    trust_pack: &[u8],
) -> Result<DecisionReceipt, SdkError>
```

The SDK obtains host time and forwards borrowed buffers into the kernel. It does not reproduce parsing, cryptography, revocation, freshness or policy logic.

The reference CLI consumes only the SDK for evaluation and pack management. It emits JSON and performs atomic local TrustPack replacement after SDK validation. Install and update acquire an operating-system advisory lock across the complete read → verify → replace sequence; a leftover lock file carries no ownership and cannot block recovery after a terminated process.

## Alternatives considered

### JWS/JWT as the first implemented adapter

Still a candidate external adapter under ADR-0001. It was not selected for this first kernel slice because the current requirement prioritizes deterministic compact typed buffers and `no_std + alloc` verification. Adding JWS later requires its own strict algorithm/profile and conformance corpus; it must normalize into the same canonical decision model.

### Self-signed TrustPack bootstrap without a pin

Rejected. It would prove integrity but not authority because an attacker could replace both the pack and embedded bootstrap key.

### SDK-side trust logic

Rejected. It would create a second implementation and cross-runtime semantic drift.

### Unlimited offline packs

Rejected. A disconnected verifier cannot know newer revocations. Expired packs fail closed.

## Security and privacy impact

Positive controls include strict algorithm selection, key-purpose isolation, bounded parsing, deterministic canonical bytes, fail-fast typed errors, trust-domain binding, revocation-before-expiry ordering, anti-rollback, pinned bootstrap and receipts without subject/evidence payloads.

Residual deployment risks remain: host clock integrity, private-key custody, compromised verifier hosts, availability denial, correct out-of-band checkpoint distribution and the absence of an external independent security review.

## Migration and rollback

The Rust workspace is additive and does not replace the current React demo path in this change. Rollback is removal of the additive workspace/CI job before a production consumer depends on the profile. Once production packs exist, format or semantic changes require a new version and migration tooling; v1 bytes must never be silently reinterpreted.

## Required evidence

- native Rust formatting, Clippy, check and test;
- `trust-kernel --no-default-features` check;
- `wasm32-unknown-unknown` no-std check;
- deterministic Proof Pack execution;
- revocation, offline, recovery and key-rotation drills;
- forged signature, wrong issuer, expiry, stale claim, cross-domain, policy-deny, rollback and malformed-input tests;
- dependency audit;
- external review before a high-impact production deployment.

## Implementation status

**BUILT — HARDENING REQUIRED.**

The code and reproducible local drills are implemented by the corresponding feature branch. This ADR does not claim that the TypeScript/Wasm SDK, production control plane, production KMS/HSM custody or a live industrial pilot is complete.
