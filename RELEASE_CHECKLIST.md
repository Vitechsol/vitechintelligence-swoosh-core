# v0.1.0-preview public open-core release checklist

13 October 2026. SWOOSH Core is already PUBLIC; this checklist distinguishes public source access from official versioned preview publication and excludes the proprietary RTOS implementation.

## Verified public baseline

- [x] GitHub repository is public; default branch is `main`.
- [x] Rust trust kernel, SDK, reference console and Proof Pack are on the public baseline `4ebbcf7dc8f947451a4bb557e01bf2096823e4b4`.
- [x] Public contracts/protocol, source provenance and MPL-2.0 / Apache-2.0 licence texts and per-path mapping are present.
- [x] Previous exact-main baseline CI `37819996090` passed rust/protocol, packaged native Action V3, license/provenance and SBOM checks.
- [x] Public `main` tree does not contain an `rtos/` directory or FreeRTOS/C broker implementation at the inspected baseline.
- [x] Earlier October 9 human code/design review covered the public baseline; its limitations remain and it is NOT an approval of later candidate changes.

## RTOS / proprietary boundary

- [ ] Retire unmerged public PR #13 without merging its `rtos/` implementation. Private working reference is preserved in the separate ViTech personal-account ViRTOS repository.
- [ ] Remove the publicly accessible RTOS engineering branch after an owner-approved exposure/rights assessment; closing PR/deleting a branch does not revoke any already-effective open-source grant or all copies/caches/PR refs.
- [ ] Confirm no other public release branches/tags/artifacts mirror RTOS source, including any future CI publication path.
- [ ] Keep future ViRTOS scheduling, RTOS adaptation and device execution engineering private, in separate modules with reviewed rights/terms. No retroactive exclusivity claim for already-distributed MPL-covered files.

## Official preview publication gates

- [ ] Review and merge only the RTOS-free public cleanup, with fresh exact-head CI and authorized human review.
- [ ] Confirm the final `main` tree has no RTOS implementation and contains consistent public licensing, attribution, notice and documentation.
- [ ] Run exact post-merge `main` CI, including protocol conformance, native V3 tests, security/audit checks, license/source provenance and SPDX SBOM generation.
- [ ] Archive evidence and artifacts with their source/digests before retention expiry.
- [ ] Verify effective installed repository rules and required status contexts, not merely checked-in rule templates.
- [ ] Complete contributor/package-rights decision; CLA PR #12 is still draft and does not confer future proprietary relicensing rights.
- [ ] Obtain independent human technical and release approval for the exact candidate and review actual limitations/claims.
- [ ] Resolve Halibut native conformance against the exact chosen SWOOSH public commit; no RTOS source is needed in public SWOOSH.
- [ ] Create immutable `v0.1.0-preview` tag and GitHub prerelease only after the gates above pass.

Publishing a link to the public source is not the same as publishing the official developer-preview tag. No banking-production, machine functional-safety, MPU isolation or RTOS WCET certification is claimed.
