# Contributor rights check and CLA activation

11 October 2026. The proposed CLA in PR #12 is **draft and not effective**. No signatures or legal approval are represented by this engineering update. Existing public MPL-2.0 and Apache-2.0 rights remain unchanged; SDK and reference execution code remain MPL-2.0.

The new `Contributor rights` workflow runs on the protected PR base, reads PR metadata through the GitHub API, and executes no PR code. It uses read-only contents/PR permissions plus narrowly scoped status-write permission. It posts `contributor-rights` against the immutable PR head SHA after checking that the head did not move; the base workflow's own check is not substituted for a head-bound result.

The trusted `.github/contributor-rights.json` currently permits maintainer-originated work subject to separate source provenance review. External authors are blocked while the CLA is draft. When an agreement is actually approved and activated, every external PR author/commit author must have a verified acceptance record for that exact agreement digest. Unknown authors, unmapped coauthors, bots, incomplete history and unverified/stale agreements fail closed. A bot has no automatic rights exemption. Registry records retain account and agreement/acceptance digests only; actual signature records remain private under a reviewed retention policy.

Eight decision tests cover maintainer origin, external authors, draft terms, bots, unknown/empty evidence, current signatures, changed terms and missing acceptance records. They test check behavior, not the validity of legal terms or signatures.

Activation steps remain:

1. Resolve the actual contracting/rightsholding entity and qualified legal review required by PR #12. The planned LLC is not assumed to exist.
2. Approve versioned individual/corporate terms and choose an acceptance provider; inventory historical contributors and rights.
3. Verify signatures/employer authority privately; add minimal verified digest records to the protected registry through review.
4. Merge the check onto protected `main` and require the `contributor-rights` status in repository rules. A branch-only workflow is not an installed required gate.
5. Rehearse unsigned, signed, amended, corporate, bot and unknown-coauthor PRs through the actual GitHub workflow.

Do not mark the CLA completed merely because unit tests or CI are green. Do not merge PR #12 against its recorded legal conditions without resolving those conditions. A future change of commercial packaging does not revoke existing open-source grants.
