# v0.1.0-preview release checklist

12 October 2026. The repository is already PUBLIC. This checklist distinguishes the published baseline from unmerged foundation work; it does not claim that an unfinished CLA or a green branch run closes publication gates.

## Established baseline

- [x] Canonical Rust kernel, SDK, reference CLI and Proof Pack extracted.
- [x] Public protocol/contracts, full MPL-2.0 / Apache-2.0 texts and per-path map included.
- [x] Public main confirmed at `4ebbcf7dc8f947451a4bb557e01bf2096823e4b4`.
- [x] Baseline post-merge CI successful: run 37819996090; source/dependency checks, license coverage, Rust/protocol SBOM generation and packaged native V3 tests recorded.
- [x] Existing main ruleset 24739014 active: required rust/protocol checks, signed commits, linear history, review/codeowner/last-push approval, resolved discussions, and deletion/force-push protection.
- [x] Repository visibility PUBLIC confirmed; historical private-staging wording is superseded.

## Foundation candidate evidence

- [x] PR #13 base candidate `72d68153a333d35ceff47779d37c8cbcef423c38` has successful Rust, protocol and RTOS-reference jobs in run 38146106994.
- [x] Halibut branch candidate `93e50ab5e621dea2efb9ebb8ea027df2cf679761` has recorded foundation/native CI 38146270502 / 38146270561 against that exact SWOOSH pin.
- [x] Current closeout patch tested locally: 20 contribution/publication tests, bounded C gate tests, actual pinned FreeRTOS POSIX broker/worker replay/halt/resume tests.
- [ ] New closeout head CI successful with all required jobs and mandatory steps executed.
- [ ] Fresh independent authorized human technical review of the final PR head; older or automated reviews do not substitute.
- [ ] Sufficient package rights and distribution/notices review recorded. Proposed CLA remains draft until its separate legal conditions are satisfied.
- [ ] Reviewed changes merged through existing branch controls.
- [ ] Successful post-merge CI on the exact resulting main SHA.
- [ ] Halibut repinned and native conformance rerun against that final SWOOSH SHA.
- [ ] Release artifacts and SBOMs retained durably with source/hash identities.

## Governance installation and publication

- [ ] Contributor-rights workflow installed on trusted main and rehearsed on real PRs. External work remains blocked while the CLA is draft; no signatures are invented.
- [ ] Add required rtos-reference and contributor-rights checks using the prepared SWOOSH_MAIN_RULESET.json without dropping existing protections. Install the contributor-rights requirement only after its trusted-base workflow exists and produces a head-bound status.
- [ ] Owner publication instruction linked to the final verified candidate; execution was authorized in the current work session.
- [ ] Run the reviewed main-only publication workflow after its authorized independent review and exact-main gates pass.
- [ ] Immutable v0.1.0-preview tag resolves to the approved commit.
- [ ] GitHub prerelease includes source, CI/review evidence, licenses and accurate developer-preview limits.

An existing-license preview does not establish future proprietary relicensing rights. See LEGAL-ACTIVATION-DECISIONS.md. Local/POSIX RTOS evidence is not board isolation, worst-case timing, physical interlocks, or functional-safety certification.

A passing branch check is not an installed repository rule or successful post-merge run. No unchecked item may be checked solely because its intended configuration is stored in this repository.
