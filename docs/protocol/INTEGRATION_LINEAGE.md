# Authorization lineage and integration targets

Status: design comparison, not a compatibility or standards-conformance claim. Reviewed 2026-10-09.

Capability security, deterministic reference monitors, explicit policy enforcement and fenced execution predate this project. Swoosh combines these ideas with signed offline trust state, revocation/freshness checks and exact action bindings. Novelty and market leadership require independent evidence; this preview makes neither claim.

| Reference | Relevant mechanism | Swoosh integration boundary | Preview status |
|---|---|---|---|
| [Biscuit](https://www.biscuitsec.org/docs/why-biscuit/) | Public-key authorization tokens with offline attenuation; revocation uses external state | A future adapter must preserve the token's narrowed rights and bind the final action to Swoosh's current signed state | No Biscuit parser or delegation chain |
| [Cedar](https://docs.cedarpolicy.com/auth/authorization.html) | Principal/action/resource/context policy evaluation, default deny and forbid precedence | A future signer may use policy evaluation to decide what can be signed; its result cannot override a Swoosh denial | No Cedar evaluator or translator |
| [SPIFFE/SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/) | Workload identities issued after node/workload attestation | A trusted identity adapter may derive the authenticated subject/role before the kernel evaluates an action | No SPIFFE identity resolver or attestation service |

These references are design inputs, not dependencies, endorsements or evidence of wire-format compatibility. The current native profiles remain ViTech's signed Claim/TrustPack formats and Action V2/V3. A role-bound Halibut integration uses V3. Portable JSON schemas validate shape; they do not grant authority.

Before advertising an adapter as supported, publish its authenticated identity mapping, signed-scope translation, failure semantics and positive/negative canonical vectors. Add property tests that delegation only narrows resources, actions, purpose, data-flow budget and lifetime once a delegation mechanism exists. Do not add a vacuous subset test to a kernel that does not issue delegated capabilities.

Identity/federation and fleet implementations may remain commercial while their security-relevant public contracts and conformance tests remain inspectable. No enterprise adapter may convert a canonical denial into permission.
