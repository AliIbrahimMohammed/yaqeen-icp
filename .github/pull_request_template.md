## Summary

What this change does, in one or two sentences.

## What's verified

Be explicit about what you actually ran — the repo's convention is to
distinguish "compiled/typechecked only" from "run on a live
`dfx`/`pocket-ic` replica." For security/crypto changes, say how you
verified it and include regression tool output where relevant.

- [ ] Typechecked/compiled with the `motoko` npm package (`moc`)
- [ ] `cargo build --release` (+ relevant `circuit/src/bin/*` runs if applicable)
- [ ] Ran on a live replica (dfx / pocket-ic)
- [ ] Upgrade round-trip exercised, if stable state changed

## Changes

- (list the concrete changes, with file paths)

## Interface / breaking changes

Note any change to the Candid interface (e.g. `requestChallenge` returning
a `Result`), so integrators aren't surprised.

## Residual risk / follow-ups

Anything that is intentionally out of scope, unverified, or needs a
follow-up `PATCH_NOTES-*.md` mention. If any change touches the *vendored*
Groth16 verifier (`motoko/src/groth16/vendor/`), flag it explicitly — fixes
must go upstream first.