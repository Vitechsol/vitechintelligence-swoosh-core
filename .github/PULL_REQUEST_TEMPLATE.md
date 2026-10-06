## Summary

Describe what changed and why.

## Related issue / proposal

Link the issue or proposal. Significant authority, protocol, trust, or interoperability changes should be discussed before implementation.

## Validation

- [ ] Tests added or updated where behavior changed.
- [ ] `cargo fmt --all --check` passes.
- [ ] `cargo clippy --locked --workspace --all-targets -- -D warnings` passes.
- [ ] `cargo test --locked --workspace --all-targets` passes.
- [ ] Proof Pack passes where relevant.
- [ ] Protocol conformance passes where relevant.
- [ ] License coverage/provenance remains complete.

## Authority invariants

- [ ] The change does not let model output, observability, or execution create authority.
- [ ] A canonical Swoosh `DENY` cannot be converted into `ALLOW` by another layer.
- [ ] Fail-closed, expiry, revocation, generation binding, destination/effect binding, and trust state remain explicit where applicable.

## Open-source boundary

- [ ] No secrets, customer data, production signing material, protected Intelligence Capsule methods/content, or private enterprise control-plane implementation are included.
- [ ] Documentation has been updated if public behavior or contracts changed.

## Contributor note

By submitting this pull request, you confirm that you have the right to contribute the submitted material under the repository's applicable licenses.
