# Fix: fast endomorphism-based subgroup check (P2 from the roadmap)

## What changed

`CurveJac.mo` (L2) and `CurveFlat.mo` (L3, the production arena-based path)
each gained new, **additive** functions — the existing `g1IsInSubgroup`/
`g2IsInSubgroup` (L2) and `g1InSubgroup`/`g2InSubgroup` (L3) are **untouched**:

- `g1IsInSubgroupFast` / `g1InSubgroupFast` — Bowe's endomorphism check:
  `[X²]P == −φ(P)`, `φ(X,Y,Z) = (β·X, Y, Z)`.
- `g2IsInSubgroupFast` / `g2InSubgroupFast` — Galbraith-Scott's ψ check:
  `ψ(P) == [−X]P`, `ψ(X,Y,Z) = (psi_x_coeff·conj(X), psi_y_coeff·conj(Y), conj(Z))`.
- `g1FastCheckAgrees` / `g2FastCheckAgrees` — differential self-check
  helpers comparing the fast and slow verdicts on the same point, written
  for exactly the real-replica run this needs before going further.

All Jacobian-point equality (across different Z) is done via
cross-multiplication, no inversion — `X1·Z2² == X2·Z1²  &&  Y1·Z2³ == Y2·Z1³`
— the same test `g1Add`/`g2Add` already use internally to detect "same point".

## Why this, and why not just replace the slow path

`Curve.mo`'s own header comment is explicit about this architecture:
> "So this module implements the subgroup check **literally**: `isInSubgroup(P)
> := [r]P == O`. Production code uses fast endomorphism-based checks (GLV /
> Bowe's trick)... **L2 may optimize it, and the L2-vs-L1 differential will
> catch it if it does.**"

That's exactly the path taken: implemented at L2 first (where the codebase's
own differential-testing architecture expects new subgroup-check logic to
land), then ported identically to L3/`CurveFlat.mo`. The existing slow
functions are left in place, and the new fast ones are exposed
*alongside* them rather than swapped in, specifically because:

1. This is security-critical code (a subgroup-check bug is the "classic
   catastrophic verifier omission" `Curve.mo` itself warns about — it can
   silently accept forged proofs while byte-matching every honest one).
2. It could not be executed here — no `dfx`/`pocket-ic`, and the
   JS-interpreted `moc` fallback is too slow for pairing-scale field
   arithmetic (documented elsewhere in this project).
3. Shipping a silent replacement for security-critical code that could only
   be typechecked, never run, would be reckless. Presenting it as ready to
   *validate* rather than ready to *trust* is the honest framing.

## What was actually verified, and how

1. **The math**, independently, via `circuit/src/bin/oracle_subgroup_jacobian.rs`
   (arkworks oracle): 32/32 G1 and 32/32 G2 test cases pass, including
   deliberate random-Z Jacobian rescalings to catch representation bugs —
   this ran for real, not just typechecked.
2. **Every numeric constant** (`BETA`, `PSI_X_COEFF`, `PSI_Y.c0`, `PSI_Y.c1`)
   copied into `CurveJac.mo`/`CurveFlat.mo` was diffed byte-for-byte against
   the oracle file's own constants — confirmed identical, not just
   eyeballed, given a single wrong digit here would be a silent security bug.
3. **Typechecks cleanly** — 0 errors in `CurveJac.mo`, 0 errors in
   `CurveFlat.mo`, and the full project (`main.mo` and every other entry
   point) still typechecks end to end with these additions, against the
   real `motoko-base`/`motoko-core` sources.

## What was NOT verified (the honest gap)

**Whether this Motoko implementation of the check itself is bug-free** —
that needs `g1FastCheckAgrees`/`g2FastCheckAgrees` actually *run*, on real
proof/vk points from `wire_export.json` and on deliberately invalid points
(wrong subgroup, wrong curve, small-order points), under `dfx`/`pocket-ic`.
The oracle validates the *formulas*; it can't validate that this specific
hand-written Motoko port of those formulas (arena offsets, scratch-region
reuse, limb-count of `X_ABS_LIMBS`) is itself correct. That gap is real and
is exactly why the fast path isn't wired into `verifyWithFlat` yet.

## Next step to actually land this

Run, under a real `dfx` session:
```motoko
// on the real vk/proof points from wire_export.json, and on deliberately
// invalid points constructed off-chain (wrong subgroup, wrong curve order)
assert CurveFlat.g1FastCheckAgrees(z, proofAOffset, tmpPt, s);
assert CurveFlat.g2FastCheckAgrees(z, proofBOffset, tmpPt, s);
```
Once that agrees across enough real and adversarial points, swap
`g1InSubgroup`/`g2InSubgroup` for the `*Fast` variants inside
`verifyWithFlat`, and re-measure the instruction count.
