# SWOOSH Key Management Contract

**Status:** Deployment contract; production provider selection remains human-controlled.

## Key classes

| Key class | Purpose | Verifier contains private key? |
|---|---|---|
| Issuer claim-signing key | Signs Signed Claim Profile v1 | No |
| TrustPack signing key | Signs authoritative TrustPack checkpoints | No |
| Optional receipt/audit signer | Signs exported receipt batches outside the kernel | No |

The Rust kernel contains public verification keys only. Proof Pack signing keys are deterministic test vectors and must never be reused outside tests.

## Production custody requirements

- Generate private keys in an approved KMS, HSM, secure element or client-controlled signing service.
- Make keys non-exportable where the selected platform supports it.
- Bind every key to one trust domain, issuer, key ID and purpose.
- Separate claim signing from TrustPack signing.
- Require authenticated, audited release approval for TrustPack publication.
- Never place private keys in GitHub, environment examples, browser bundles, mobile application assets, logs or general AI-agent sandboxes.
- Back up/recover keys only through the approved custody system and dual-control procedure.
- Record owner, activation, deprecation, revocation and destruction evidence outside the claim data plane.

## Bootstrap

Initial TrustPack installation requires a 32-byte checkpoint delivered over an independent authenticated channel. Acceptable deployment examples include controlled device enrollment, signed configuration management or an operator-verified provisioning package.

The first pack and its expected checkpoint must not be learned exclusively from the same unauthenticated source.

## Rotation

1. Generate the new key under the same custody controls.
2. Publish a higher-epoch TrustPack whose root generation advances by exactly one.
3. Keep the old public key as `Deprecated` through an explicit acceptance window when continuity is required.
4. Set `deprecated_at`; claims issued by the old key after that timestamp are rejected.
5. Verify new-key claims and pre-rotation old-key claims through the key-rotation drill.
6. After the acceptance window, remove or revoke the old key in a later higher-epoch pack.
7. Retain audit metadata, not private material.

TrustPack-signing-key rotation may require a staged cross-signing transition so the current root authorizes the candidate. Emergency loss of all current pack-signing authority requires a controlled re-bootstrap and a newly distributed out-of-band checkpoint.

## Compromise

- Claim key compromise: revoke the key in the next higher-epoch TrustPack; determine whether revocation is retroactive; issue replacement claims as required.
- TrustPack key compromise: use an unaffected current pack-signing key to publish a higher-epoch root; otherwise invoke controlled re-bootstrap.
- Verifier compromise: revoke device/operator credentials in the surrounding application and reprovision a clean last-known-good checkpoint.
- Never lower Trust Epoch, status sequence, policy version or root generation during recovery.

## Cryptoperiods

The code enforces explicit `not_before` and `not_after` windows but does not invent universal durations. Cryptoperiods, offline windows and rotation frequency are deployment-risk decisions that require documented approval.
