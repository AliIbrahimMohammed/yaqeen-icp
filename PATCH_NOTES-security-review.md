# Security review disposition

How each finding from the security review was addressed. Review quotes are
abridged; see the review text for full context.

## "Before this touches anything real" findings

### 1. Admin principal is a hardcoded placeholder — **FIXED (two rounds)**

The review's quoted code (`let admin : Principal = Principal.fromText("aaaaa-aa")`)
was already superseded by the `bootstrapAdmin`/`setAdmin` bootstrap sentinel
(commit `952ef3f`, see `PATCH_NOTES-admin-bootstrap.md`). This round upgraded
that further to the review's preferred shape:

- **Multi-principal allow-list** (`var admins : [Principal]`), seeded exactly
  once by `bootstrapAdmin`, governed thereafter by `addAdmin`/`removeAdmin`
  (existing-admin-only), never removable to an empty list, and queryable via
  `listAdmins`.
- No constructor argument was used: the available `moc` doesn't parse
  constructor args on a plain `persistent actor`, so the one-time sentinel +
  governed path is the enforced runtime equivalent ("init then lock").
- Typechecked: 0 errors on `main.mo`, `verify_test/main.mo`,
  `Groth16MultiTest.mo` (node-motoko `moc` + real base/core sources).

Remaining (tracked): threshold/multi-sig admin scheme (P3).

### 2. Groth16 trusted setup is dev-only — **PARTIALLY ADDRESSED (code side)**

The underlying fact stands: single-party `setup.rs` output must never back
real value until a real multi-party ceremony (Phase-1 powers-of-tau +
Phase-2 contribution, independent participants, verifiably destroyed
randomness) or a transparent/universal setup scheme exists. That ceremony is
operational — it cannot be run from this repo or this sandbox.

Code-side hardening landed in `setup.rs`:
- **Fail-closed**: the binary now refuses to run unless the explicit
  `--allow-dev` flag is passed, so accidental/CI invocation of the
  dev-key path is impossible, and the toxic-waste warning is printed at
  every run.

## P1 — confirm what's only been typechecked, not executed — **BLOCKED (environment)**

Two validated-but-not-replica-tested patches still need one real
`dfx`/`pocket-ic` session:

1. Alpha/beta precompute in `Groth16Multi.mo` (3-pair vs 4-pair Miller
   loop) — math validated against arkworks, never run on a replica.
2. Jacobian fast subgroup check — the review cites
   `oracle_subgroup_jacobian.rs` (32/32 G1 + 32/32 G2 passing) and wiring
   it into `CurveFlat.mo`'s `g1InSubgroup`/`g2InSubgroup`.

**Status: not executable in this sandbox** — no `dfx`, no `pocket-ic`, no
Rust toolchain, no IC network path. Also, `oracle_subgroup_jacobian.rs`
does not exist in this repo (checked working tree, history, and the
`yaqeen-icp-patched*.zip` artifacts in Downloads — the zips are
byte-identical to the repo). If that oracle exists in a lost/other tree,
it needs to be brought in before the `CurveFlat.mo` wiring can be
validated here; implementing the endomorphism-based check from scratch
without any ability to compile Rust in this sandbox was judged
irresponsible. This is the single highest-leverage next action on a
machine with the toolchain.

## P2 — endomorphism fast subgroup check in `CurveFlat.mo` — **BLOCKED (same)**

The ~4× reduction on the three per-verify subgroup checks is real and
worth doing — but only after the P1 groundwork exists in-repo and is
validated. Same blocker as above. Re-measure instruction count on dfx
after it lands.

## P3 — general productization — **NOTED, OUT OF SCOPE HERE**

- BN254 migration: real re-port, sequence after P1/P2 are measured.
- Batch verification entry point: depends on volume numbers.
- Admin model: allow-list landed (see finding 1); threshold scheme next.
- Operational hygiene (monitoring, VK-rotation procedure, CI running
  `verify_test/main.mo` + `Groth16MultiTest.mo`): needs a real dfx
  environment; CI wiring is a one-line add once one exists.
