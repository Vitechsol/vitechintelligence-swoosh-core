# ADR 0008: additive action v2 and pinned host context

Status: accepted product direction by repository owner, 2026-10-05; implementation subject to PR review.

## Decision

Keep one canonical zero-I/O Rust kernel. Add SignedActionV2 as an explicit envelope around an unmodified v1 organizational claim. The same authorized claim-signing key signs the extended binding. v1 claim bytes, canonical signing rules and receipts retain their existing meaning and golden vectors.

The new binding contains workflow, task, assignment generation, purpose, destination, exact effect digest, policy version and Trust Epoch. A trusted host supplies authenticated subject, expected action/resource and the exact binding. The kernel verifies the existing claim, the additional Ed25519 signature, host subject/scope equality and current policy/epoch equality. Unknown versions, tampering and stale assignments deny. Issuer signing stays outside the verifier.

Use InstalledTrustContext to bootstrap with an out-of-band checkpoint and accept only verified anti-rollback transitions. Requesters cannot replace its private pack bytes. An authenticated newer-epoch announcement makes old installed state unusable until synchronization. Hosts must persist the checkpoint/epoch floor across restarts; this in-memory library does not claim durable synchronization.

## Canonical bytes

The v2 signature covers, in order: `SWOOSH\0action-binding\0v2\0`, u16 version 2 in big-endian, the 32-byte canonical v1 signed-claim fingerprint, workflow/task/purpose/destination as UTF-8 bytes each with u32 big-endian byte length, u64 big-endian generation, 32-byte effect digest, u64 big-endian policy version, u64 big-endian Trust Epoch. No final terminator is appended. Postcard is a bounded transport envelope, not signing material. Maximum envelope size is 16,384 bytes; each binding string has 1–160 bytes and no control characters; numeric bindings are positive and the effect digest is nonzero.

The effect digest is supplied by a reviewed adapter profile. The synthetic integration uses UTF-8, key-sorted compact JSON for one local record. This is not a universal JSON signature standard. Consumers must agree on the adapter bytes before signing an action.

## Host and commercial boundary

Halibut's host broker must reauthorize before the protected commit and atomically couple task fencing, local effect and durable audit. Untrusted workers cannot own the host identity/session, trust files, broker database or privileged tools. A Python class boundary does not establish hostile-process isolation.

The owner approved public protocol, open local core and private organizational plane as product policy. Current visibility stays private during release selection. Selected protocol/contracts target Apache-2.0; selected local kernel/host target MPL-2.0; fleet and organization operations and protected Capsule methods remain private commercial assets. Basic authentication, revocation, rotation, safe execution and local audit/export stay in Community. MPL permits commercial operation at arbitrary device counts; organizational value, not a license device limit, creates the paid offering.

## Migration, tests and remaining gates

The new API and CLI command are additive; old consumers continue to use v1. Rollback before adoption removes the additive module. After an issuer adopts v2, profile and publication compatibility must be handled explicitly. Tests exercise wrong pins, known-newer epochs, scope/subject substitution, tampering, malformed/oversized bindings, policy changes, rollback and failed-install preservation. Existing v1 golden vectors must remain green.

Status: BUILT — HARDENING REQUIRED. Browser/Node Wasm wrapper, cross-runtime execution conformance, OS worker isolation, durable epoch-floor management, production signer custody, independent review and industrial pilot remain gates. A Wasm compilation check alone is not cross-runtime conformance.
