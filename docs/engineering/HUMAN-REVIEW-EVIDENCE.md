# Human review evidence and candidate disposition

## Completed review

The owner reports that human review is complete. The supplied six-page **ViTech Swoosh Core & Halibut Core Code and Design Review**, dated 9 October 2026, and **ViTech_SWOOSh_Halibut_Review_Manifest.txt** identify these reviewed snapshots:

| Repository | Reviewed commit |
| --- | --- |
| SWOOSH Core | `4ebbcf7dc8f947451a4bb557e01bf2096823e4b4` |
| Halibut Core | `24c42a82ea4d4b423c8f135b9f082ea93ce42a39` |

- [x] Supplied code/design review inspected; the owner's statement of completed human review is recorded.
- [x] Reviewed revisions and review limitations retained rather than marking the historical review missing.
- [x] Owner authorized the commercial-boundary documentation, further verification and publication in the work session.
- [ ] Independent authorized approval of the changed final candidate recorded through the repository's required review process.
- [ ] Package-specific rights/distribution decision recorded; a technical review is not counsel approval or contributor assent.

The supplied report does not identify a reviewer in its extracted text. It states that Rust compilation/CI was not verified during that review and excludes fuzzing, independent cryptographic review and hostile-worker testing. It expressly says it is not a security certification and does not replace release sign-off. Original review files are retained privately by the owner; no private review document or personal identity is republished here. The owner's current instruction is recorded as authorization, not attributed to an unnamed reviewer or represented as an approval of an unseen later commit.

## Findings and later candidate work

This is a disposition record, not a claim that every finding has been eliminated. SWOOSH PR #13 and Halibut PR #1 contain the later changes; their exact CI runs establish verification of those candidates. Human review of the historical snapshots and automated verification of later corrections remain distinct evidence.

| Finding | Candidate disposition / remaining limit |
| --- | --- |
| F1: unpinned public evaluation | SWOOSH SDK defaults to installed pinned context; raw compatibility requires explicit feature opt-in. Low-level kernel APIs still require a trusted host. See `trust-sdk/src/lib.rs` and its tests. |
| F2: checkpoint/epoch update invalidates old actions | Retained update/re-signing integration requirement; no seamless migration claim. |
| F3: role, subject and supervisor trust | Halibut foundation requires host-authenticated role, adds Linux peer credentials/registry and durable supervisor decision replay checks. Distinct worker identities, protected broker and external signing remain deployment requirements. |
| F4: regex bounds, leakage and evasion | Halibut foundation bounds accumulated stream/input and findings, redacts excerpts and fences interruption. Regex remains an advisory signal, not complete semantic or authorization enforcement. |
| F5: append-only revocation capacity | Retained capacity/rotation design limit; no production-scale rotation claim. |
| F6: clocks and blocking broker transaction | Retained clock and transaction-latency deployment limits; software tests do not establish worst-case timing. |
| F7: audit anchoring | Checkpoint/adversarial tests provide local evidence. Independent retention, signatures and external anchoring remain deployment work. |
| F8: normalization and digest profile | Retained cross-language/profile limitation; no RFC 8785 conformance claim. |
| F9: lease multiplicity / version downgrade | Retained integration constraints; deployments must enforce their intended lease policy and accepted action versions. |
| F10: Halibut main is a placeholder | Release foundation is in PR #1 until governed merge and exact-main CI are verified. Branch evidence does not change main. |

See [Release checklist](../../RELEASE_CHECKLIST.md), [release closeout](RELEASE-CLOSEOUT.md), [threat model](../security/THREAT_MODEL.md), and Halibut's `docs/FOUNDATION-2026-10-11.md`. This preview does not certify industrial safety, board isolation, production signing custody or independent cryptographic assurance.
