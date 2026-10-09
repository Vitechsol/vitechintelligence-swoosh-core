# Contribution-rights and CLA acceptance workflow

**Status: proposal — not activated until legal sign-off.**

1. Obtain owner/counsel approval of the exact legal entity, CLA version, copyright/patent wording, electronic signature mechanism and retention/privacy terms.
2. Activate a suitable consent mechanism (e.g., a reviewed CLA-signature service or signed document) that verifies the contributor, records the exact agreement version and supplies durable evidence to ViTech.
3. Require maintainer verification of signed status **before merging** any new external copyrightable contribution. A PR template checkbox is only a disclosure reminder, never a substitute for evidence.
4. For employee or corporate contributions, verify the signatory has authority for employer-owned IP. For existing third-party contributions, obtain a separate documented grant/assignment where needed; never assume this CLA is retroactive.
5. Store contributor name, acceptance timestamp, signed agreement/version hash and provenance in a restricted record outside the public repository. Limit access and define retention/deletion rules according to applicable law.
6. Prefer a required repository status check that fails closed for unsigned external PRs when the selected provider supports it. Set branch rules only after the service is configured and tested; maintainers must not infer enforcement from this document alone.
7. If a contributor does not wish to sign, discuss whether their work can be contributed under current licenses without future relicensing; **do not merge** it into a relicensable code path until rights are resolved.

## Licensing principles
- SWOOSH Trust Kernel, SDK, reference Console and Proof Pack are MPL-2.0 under REUSE.toml.
- Protocols, schemas, public interoperability material and documentation are Apache-2.0.
- Existing distributed versions remain available to lawful recipients under the terms they received.
- New, independently authored ViTech Enterprise modules can be proprietary; any distributed modifications to MPL-covered files remain subject to MPL obligations unless all copyright holders have granted sufficient relicensing rights.
- Trademark rights are separate from copyright licenses; see NOTICE.

## Pull-request review evidence
- CLA acceptance check: `NOT_CONFIGURED` / `VALIDATED` / `NOT_APPLICABLE` (maintainer's actual documented determination)
- Contributor type and rights/employee clearance: reviewed
- New dependencies and their licenses: reviewed
- No private keys, data, Enterprise code or protected Capsule content: checked
- Independent reviewer / merge approval: recorded

**Do not state that CLA protection is active or enforceable merely because this document exists.**
