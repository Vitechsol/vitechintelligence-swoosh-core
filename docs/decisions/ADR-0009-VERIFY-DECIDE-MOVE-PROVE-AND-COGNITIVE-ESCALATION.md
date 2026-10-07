# ADR-0009: Verify-Decide-Move-Prove and Cognitive Escalation Boundary

- Status: Accepted for public-preview architecture
- Date: 2026-10-07
- Scope: Swoosh Core authority semantics and Halibut integration boundary

## Context

Swoosh is the deterministic authority plane used by Halibut and other compatible hosts.

The broader Halibut runtime includes a supervisory AI, asynchronous worker execution, observability, Intelligence Capsules, and optional physical-system adapters. That broader environment creates an important architectural question:

**What happens when a worker or Halibut Intelligence asks for an action that is ambiguous, outside current authority, or safety-sensitive?**

The answer must preserve Swoosh's narrow trust boundary.

## Decision

Swoosh adopts the canonical doctrine:

> **VERIFY -> DECIDE -> MOVE -> PROVE**

Swoosh remains deterministic. It is not an AI planner, semantic supervisor, or source of human purpose.

A compatible host may use Halibut Intelligence or another cognitive system to interpret context, plan work, diagnose anomalies, or recommend a next action. That cognitive output is not authority.

Every protected effect must return through Swoosh before execution.

## VERIFY

VERIFY establishes whether the proposed action and its context are structurally and cryptographically acceptable for evaluation.

Inputs may include:

- authenticated subject;
- tenant/trust domain;
- role/delegation;
- task/workflow and generation;
- purpose;
- action/resource;
- destination;
- exact effect binding;
- signature;
- installed policy version;
- trust epoch;
- expiry;
- revocation state;
- capability/lease reference;
- bounded payload constraints.

External stream guards, DLP, RegEx, classifiers, semantic guardrails or anomaly detectors may provide signals.

Those signals can cause a request to be blocked or escalated.

They cannot grant permission.

## DECIDE

DECIDE is deterministic policy evaluation.

It must not be implemented as "ask an LLM whether this is allowed."

The canonical **authoritative outcome** is one of:

```text
ALLOW
DENY
```

A compatible host may separately attach non-authorizing routing statuses such as `REQUIRE_COGNITIVE_REVIEW`, `REQUIRE_HUMAN_AUTHORITY`, or `REQUIRE_PHYSICAL_SAFETY_APPROVAL`. Those statuses do not permit MOVE. The protected effect remains fail-closed until the required review or authority change occurs and Swoosh reevaluates the request to a final `ALLOW` or `DENY`.

The exact API representation of routing metadata may evolve, but it must never be interpreted as authorization.

### Deterministic authority

When Swoosh has sufficient verified state, it returns ALLOW or DENY according to installed authority.

### Cognitive review

When semantic interpretation or supervisory reasoning is needed, the host may ask Halibut Intelligence.

Examples:

- objective alignment;
- anomalous worker behavior;
- recovery planning;
- worker/Capsule selection;
- ambiguous operational context.

Halibut Intelligence returns a structured recommendation.

The recommendation must then return to the deterministic authority path.

> **Cognitive review can explain or refine an action proposal. It cannot convert missing authority into authority.**

### Missing authority

If the requested protected effect is outside the current authority envelope, the result is DENY.

A compatible Halibut host may raise an **Authority Request** to a human-controlled RBAC surface.

If a human grants or modifies authority, Swoosh reevaluates the action under the new verified state.

> **Beyond Swoosh's cognition -> cognitive escalation. Beyond Swoosh's authority -> DENY.**

## MOVE

MOVE is a brokered protected effect.

The worker or model must not gain direct privileged infrastructure access merely because it emitted a tool call.

Examples include:

- file effect;
- API request;
- database change;
- network egress;
- code/sandbox execution;
- connector invocation;
- device/robot command.

The broker must execute only the exact effect authorized by Swoosh, preserving effect binding and task-generation fencing.

## PROVE

PROVE records bounded evidence of the authority and effect lifecycle.

Evidence may include:

- decision receipt;
- denial receipt;
- capability/lease reference;
- task generation;
- policy/trust state;
- effect commitment;
- result/effect evidence;
- failure/reconciliation state.

For important or irreversible effects, an implementation should durably record the authorization/intention boundary before the side effect and append completion evidence afterward.

This is an implementation refinement of MOVE/PROVE, not a fifth public doctrine stage.

A local hash chain may make modification detectable relative to a trusted head. A writable local database is not inherently immutable and must not be described as such.

## Halibut Intelligence boundary

Halibut Intelligence is a supervisory cognitive plane in the Halibut architecture.

It may:

- plan;
- analyze;
- coordinate;
- delegate;
- diagnose;
- recommend;
- request missing authority.

It must not:

- mint Swoosh capabilities for itself;
- alter trusted RBAC state without authorized human/system action;
- convert DENY into ALLOW;
- bypass effect binding;
- bypass expiry/revocation;
- bypass physical safety controls.

The trust kernel must not depend on Halibut Intelligence being available.

## Human authority boundary

Human-controlled RBAC remains the normal source of authority changes.

A human may:

- grant;
- narrow;
- modify;
- expire;
- revoke

a scoped authority record.

Swoosh then verifies and enforces that state.

There is no generic "human override security" primitive. Human action changes the authority state; Swoosh still evaluates it.

## Physical-system boundary

Swoosh authorization is necessary but not sufficient for physical safety.

A Halibut physical execution profile may add:

- human-in-the-loop interruption;
- pre-action approval;
- mid-execution stop;
- emergency stop;
- deterministic fail-safe state;
- native machine safety controller/interlocks;
- ROS/ROS 2 or PLC/device adapters.

These controls live outside the Swoosh trust kernel but must not be bypassed by an Swoosh ALLOW.

A valid digital capability does not constitute a functional-safety approval.

## Asynchronous runtime consequence

Swoosh is compatible with always-on event-driven RTOS supervision.

Workers may stream observable events while the host independently performs:

- verification;
- authority decisions;
- cancellation/fencing;
- brokered execution;
- evidence recording.

A host may cancel or fence a worker generation after a denial or interrupt without waiting for the worker to complete free-form generation.

Swoosh does not claim deterministic LLM latency or hard-real-time machine timing.

## Security consequences

This decision preserves:

1. deterministic authority even when cognition is probabilistic;
2. model/provider neutrality;
3. default deny for missing authority;
4. human ownership of authority changes;
5. broker-only protected effects;
6. inspectable proof/evidence;
7. separation between AI supervision and machine safety.

## Compatibility

This ADR does not change the existing Action V2 or Action V3 wire/signing profiles.

It clarifies how compatible Halibut runtimes and future protocol revisions must interpret authority, cognitive escalation and protected execution.

Any future wire-level representation of cognitive review, Authority Requests, or physical-safety state must be additive, versioned and fail closed when unsupported.
