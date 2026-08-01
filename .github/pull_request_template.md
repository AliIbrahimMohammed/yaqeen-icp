## Summary

<!-- What does this PR do, in one or two sentences? -->

## What was verified, and how

<!-- House rule: say exactly what you ran and how —
     real dfx/pocket-ic replica, in-process arkworks oracle,
     typecheck only. -->

- [ ] `cargo build --release` passes
- [ ] relevant `circuit/src/bin` regression tests pass (list them)
- [ ] Motoko typechecks with zero warnings (moc + real base/core)
- [ ] `verify_test` flow on a real replica (if change touches canister)
- [ ] no new vendored-file changes without justification

## Security impact

- [ ] No security-relevant change
- [ ] Cryptography / verifier behavior changed (explain equivalence or
      differential test used)
- [ ] Candid API or auth model changed

## Related issues

<!-- Fixes #... -->
