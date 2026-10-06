# Swoosh interoperability contracts v1

Status: preview, versioned and tested. A schema-valid document is untrusted input. It cannot authenticate an actor, grant a lease, prove an approval or authorize a tool.

The single JSON Schema source is [contracts.schema.json](../../swoosh_contracts/schemas/v1/contracts.schema.json). The thin Python codec performs bounded, strict format and binding checks. It contains no signature verification, RBAC engine or production trust-decision path.

| Contract | Meaning and authority |
| --- | --- |
| GovernedContext | References an authenticated host context. Identity, consent and safeguarding evidence must be independently verified before protected retrieval or inference. |
| ActionIntent | Observable proposal bound to task generation, action, resource, purpose, destination and exact effect digest. |
| CapabilityDescriptor | Metadata about an opaque host lease and separately verified native v2 envelope. Never a bearer token or permission by itself. |
| TaskExecution | Durable state, bounded attempts, dependencies, deadline and idempotency correlation. |
| ApprovalEvidence | Reference to independently verified approver evidence for the full action-envelope digest, with expiry. A Boolean or model statement is insufficient. |
| ResultEvidence | Separates produced, validated, committed and closed. Only a source-of-truth commit supplies a commit reference. |
| AuditEvent | Minimal fixed envelope with no arbitrary metadata, secrets, prompts or private reasoning. |
| CapsuleExecution | Owner, method version, input/output schemas, digest, provider and license evidence references. Protected method content remains external. |
| Packet | Correlates context, intent and capability metadata. Signature and current host-state checks remain mandatory. |

Every object rejects unknown fields and versions. UUIDs are lowercase standard UUIDs; commitments use `sha256:` plus 64 lowercase hex characters. UTC timestamps use RFC 3339 with `Z` and optional one-to-six fractional digits. JSON integers are capped at 2^53−1 for exact interoperable numbers. The native profile independently uses u64; larger values require an explicit future JSON profile.

Portable descriptors never carry process-local monotonic ticks. A receiving host must authenticate issuer and audience, verify the actual signed envelope against its installed state, enforce clock/freshness policy, and create a new local monotonic lease. Capability and approval periods are positive and at most 600 seconds. No portable remote capability-consumption implementation is claimed here.

## Canonical native action profile

The verifier remains in `vitechintelligence/swooshbyvitech`. ADR-0008 adds `swoosh.action.v2.native` over unchanged Signed Claim Profile v1 and TrustPack v1. Native v2 signing bytes are, in order:

1. Exact bytes `SWOOSH\0action-binding\0v2\0`, then unsigned u16 big-endian version 2.
2. Existing 32-byte signed v1 claim fingerprint.
3. UTF-8 workflow, task, purpose and destination, each preceded by a u32 big-endian byte length.
4. Generation as u64 big-endian, 32-byte effect digest, policy version and trust epoch as u64 big-endian.

Standard Ed25519 signs these bytes. Wire representation is Rust `SignedActionV2` serialized with the locked Postcard dependency, bounded to 16,384 bytes. This is a named application profile, not a W3C credential-suite claim. The inner claim binds domain, issuer, key, subject, action, resource, capability and expiry. The authenticated host supplies the expected subject and full binding. The verifier checks these against the signature and current pinned TrustPack. Worker JSON supplies neither identity nor installed state. Unknown profiles fail closed.

[The fixed signing vector](../../fixtures/native-v2/signing-vector.json) is independently assembled with explicit lengths and endian encoding in protocol tests. The canonical Rust test pins the same digest. Existing v1 receipt/checkpoint golden vectors remain unchanged. Native execution is tested; Wasm compilation alone is insufficient to claim a supported Wasm integration.


### Role-bound native action profile (v3)

`swoosh.action.v3.native` is an additive profile over the existing trust kernel. V2 remains supported for compatibility.

V3 cryptographically binds an authenticated **role** into the action envelope in addition to the existing workflow, task, generation, purpose, destination, effect digest, policy version and trust epoch.

The trusted host supplies:

- authenticated subject;
- authenticated role;
- expected action/resource;
- the exact role-bound action binding.

The verifier requires all of those values to match the signed envelope exactly. Worker/model text, prompt content, tool proposals and observability signals are never accepted as role or authority inputs.

This turns role identity into a hard authorization boundary rather than a soft prompt convention. A model cannot promote itself from `site-entry-worker` to `site-admin`, and a copied valid action cannot be replayed under a different role without failing signature/scope verification.

The profile deliberately binds only the **role identifier**, not proprietary role methodology or system-prompt text. Halibut may separately bind a versioned cognitive-profile digest while keeping protected Intelligence Capsule content outside the public protocol.

All fixtures are synthetic format material. Hashes and references do not prove real permissions, approvals, Capsule licenses or deployment identity.

## Run

```bash
python -m pip install .
python -m unittest discover -s tests -v
```

The async example adapts structured proposals to Halibut's real Rust-backed local broker. Install the Halibut host from its corresponding review branch, build `trust-console` and generate a synthetic fixture using Halibut's foundation guide. Then use fresh paths:

```bash
python examples/async_reference_monitor.py --trust-console /path/to/trust-console --fixture /path/to/synthetic-fixture --database /path/to/fresh-state.sqlite
```

No LLM, network service, commercial token or paid Capsule is required. The example supports a local SQLite record effect. Arbitrary tools, protected-context inference and irreversible remote effects remain unimplemented. It replaces the old independent Python policy/lease demonstration.
