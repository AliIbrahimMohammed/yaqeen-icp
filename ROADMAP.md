# Yaqeen on ICP — Project Review & Roadmap

**Scope:** Motoko canister on the Internet Computer that verifies BLS12-381 Groth16
zk-SNARK proofs natively on-chain, for a privacy-preserving property-title registry
(ownership, no liens, valid license, Merkle-tree membership) with nullifier-based
replay protection.

**Purpose of this document:** capture where the project actually stands today,
what's confirmed vs. only typechecked/estimated, and a prioritized, sequenced plan
to get it to a genuinely production-ready state.

**Update:** P0.1, P2, and the admin-model half of P3 have since been implemented
(not just planned) — see the "Status" column below and each item's own
`PATCH_NOTES-*.md` for what was actually done and verified.

---

## 1. What this project is

| | |
|---|---|
| **Network** | Internet Computer (ICP) |
| **Runtime** | Single Motoko canister (`main.mo`), no bridge, no off-chain verifier trust |
| **Cryptography** | BLS12-381 Groth16 zk-SNARK, verified natively in Motoko |
| **Statement proven** | Ownership + no liens + valid license + Merkle-tree membership, without revealing underlying identity/property data |
| **Replay protection** | Nullifier tracking + single-use challenge/nonce scheme |

**Security mechanisms currently in place**
- **Challenge/nonce scheme** — `requestChallenge` issues a live `merkleRoot` /
  `purpose` / `nonce` / `timestamp`; `verify` checks the proof's public inputs
  against that *exact* challenge before the pairing check runs, then marks it
  consumed. Confirmed live on a real replica: correct replay rejection, and a
  failed verification attempt does not burn the challenge.
- **Nullifier tracking** to block proof replay across challenges.
- **Admin-gated writes** (`submitRecord`, `setVerifyingKey`) via `msg.caller != admin`.

---

## 2. Priority roadmap

### P0 — Fix before this touches anything real

These are trust-model-breaking issues, not polish. Nothing downstream matters if
either of these is still open.

**2.1 — Hardcoded admin principal — ✅ IMPLEMENTED**

`main.mo`, line 35:
```motoko
let admin : Principal = Principal.fromText("aaaaa-aa"); // TODO: set at init
```
`"aaaaa-aa"` is the IC management-canister's well-known principal — not a real
admin identity. The code flags this itself. Right now `submitRecord` and
`setVerifyingKey` are gated against a principal nobody actually controls as intended.

- **Action taken:** replaced with a one-time `bootstrapAdmin` sentinel, then
  further upgraded to a real multi-principal allow-list (`addAdmin`/`removeAdmin`,
  never removes the last admin) — see `PATCH_NOTES-admin-bootstrap.md` and
  `PATCH_NOTES-admin-allowlist.md`. Typechecked with 0 errors; not yet run on
  a real replica (see each patch note for the exact verification sequence to
  run under `dfx`).
- **Owner:** canister/backend engineer.
- **Blocking:** everything else. This should land before any other item on this
  list is considered "in progress."

**2.2 — Dev-only trusted setup — ⚠️ MECHANICS BUILT + TESTED; REAL CEREMONY STILL NOT RUN**

`circuit/src/bin/setup.rs` says so itself:
```
real_value_eligible: false — dev setup only, toxic waste not destroyed via ceremony
```
Whoever ran that binary holds the "toxic waste" and can forge arbitrary
valid-looking proofs for any statement. For a title registry this is
existential, not cosmetic.

- **Action taken:** a real `ceremony/` Rust crate (`ceremony_init` /
  `ceremony_contribute` / `ceremony_verify`) implementing the standard
  delta-only Groth16 Phase-2 MPC (same structure as Zcash Sapling /
  Filecoin / Semaphore), built on `ark-groth16`'s own real API. Independently
  re-verified in this pass, not just taken on faith: compiled clean, ran a
  full 3-round chain (init + two contributions) end to end, confirmed
  `ceremony_verify` accepts the honest chain and rejects a tampered one
  (real nonzero exit code), and confirmed the ceremony's *final* proving/
  verifying key actually produces a valid proof that `verify_smoke` accepts
  — and correctly rejects inconsistent/tampered inputs — via a fresh,
  independent `prove` + `verify_smoke` run against the ceremony-derived key.
  See `PATCH_NOTES-ceremony-and-provenance.md` and `CEREMONY_SPEC.md`.
- **What this does NOT close:** `alpha`/`beta`/`gamma` are still fixed once,
  at `ceremony_init`, by whoever runs it — this tool only rotates `delta`
  across participants (the real Phase-2-equivalent trust dependency).
  Closing that needs either reusing an existing audited Powers-of-Tau
  transcript, or a real Phase-1 ceremony with independent, non-colluding
  human participants — not something achievable by tooling alone, and not
  attempted here.
- **Owner:** cryptography lead + at least 2–3 independent external contributors
  for both the real delta-rotation rounds (using the now-tested `ceremony/`
  crate) and, separately, sourcing/combining a real Phase-1 transcript.
- **Blocking:** any real property data touching the system.

---

### P1 — Confirm what's only been typechecked, not executed

Two pieces of real cryptographic work are validated in isolation (arkworks
oracle + Motoko typecheck) but not yet run end-to-end on a real replica:

- **Alpha/beta precompute patch** to `Groth16Multi.mo` (3-pair vs. 4-pair
  Miller loop) — math validated against arkworks on the real fixture, 0
  typecheck errors, never run on `dfx`/`pocket-ic`.
- **Jacobian-reformulated fast subgroup check**
  (`oracle_subgroup_jacobian.rs` — 32/32 G1 and 32/32 G2 cases pass,
  including deliberate random-Z rescalings to catch representation bugs) —
  solid, validated groundwork, but not yet wired into `CurveFlat.mo`.
  `g1InSubgroup`/`g2InSubgroup` currently still do a full ~255-bit scalar
  multiplication by the group order (`R_LIMBS`) per point.

- **Action:** one real `dfx`/`pocket-ic` session against the actual
  `wire_export.json` fixture and the existing `verify_test/main.mo` harness —
  this closes out two substantial patches at once.
- **Owner:** whoever has `dfx` access (this could not be run in the sandbox
  that produced these patches — no network path to the IC there).
- **Sequencing:** after P0, before P2 lands in production (P2 depends on
  wiring the subgroup check that P1 only validates in isolation).

---

### P2 — The concrete next performance win — ✅ IMPLEMENTED (pending validation)

Worth doing next specifically *because* the groundwork above is now proven
correct, not just theorized.

- **Today:** 3 subgroup checks per verify (proof's A, B, C — the VK's own
  points are already validated once at setup), each a full ~255-bit scalar
  multiplication.
- **After:** each becomes a ~64-bit scalar multiplication (by `X_ABS`) plus
  one cheap endomorphism application (`beta * X` for G1; conjugate + twist
  coefficients for G2) and one Jacobian equality check — roughly a **4x**
  reduction on just these three checks, a real (previously uncounted) chunk
  of the ~20.9B-instruction total.
- Combined with the alpha/beta precompute, this attacks a *second* major
  cost center instead of re-optimizing the same one.

- **Action taken:** `g1IsInSubgroupFast`/`g2IsInSubgroupFast` (L2,
  `CurveJac.mo`) and `g1InSubgroupFast`/`g2InSubgroupFast` (L3,
  `CurveFlat.mo`) are implemented, additive (existing slow functions
  untouched), and typecheck cleanly. Math re-confirmed against the arkworks
  oracle; every numeric constant byte-diffed against the oracle source.
  **Not yet wired into `verifyWithFlat`** — that requires the differential
  self-check (`g1FastCheckAgrees`/`g2FastCheckAgrees`, included) to actually
  run under `dfx` first. See `PATCH_NOTES-fast-subgroup-check.md`.
- **Then:** repeat the instruction-count measurement on `dfx` to get one
  real, current total, reflecting both landed optimizations instead of
  estimates layered on estimates.
- **Owner:** Motoko/crypto engineer, ideally the same person who validated
  the oracle.
- **Sequencing:** after P1's `dfx` session confirms the alpha/beta patch is
  safe to build on top of, and after `*FastCheckAgrees` confirms the fast
  subgroup check on real and adversarial points.

---

### P3 — General productization

- **BN254 migration** — the biggest single remaining lever if per-verify
  cost is still the bottleneck after P1/P2 (roughly 2x from field-width
  alone). This is a genuine re-port, not a patch — sequence it *after* the
  cheaper wins land and get measured, not before.
- **Batch verification** entry point, if proof volume grows — settle N
  proofs' pairing checks in one shared final exponentiation.
- **Admin model** — ✅ IMPLEMENTED: moved past a single hardcoded principal
  (see P0.1) to a real multi-principal allow-list, set via `bootstrapAdmin`
  and changed only through governed `addAdmin`/`removeAdmin` calls (never
  removing the last admin), not a bare caller-equality check. See
  `PATCH_NOTES-admin-allowlist.md`. A full threshold-signature scheme is
  still a further step up if the operational risk profile calls for it.
- **Operational hygiene:**
  - Monitoring for challenge-expiry / replay-attempt rates.
  - A documented key-rotation procedure for `setVerifyingKey` — what happens
    to challenges issued under the old VK when it rotates?
  - CI that automatically runs `verify_test/main.mo` and the
    `Groth16MultiTest.mo` differential test once a real `dfx` environment is
    available for it, so future patches don't regress silently back to
    "typechecked but never executed."

---

## 3. Suggested sequencing at a glance

```
P0.1 admin principal  ─┐
                        ├─► P1 (dfx session: confirm alpha/beta + validate  ─► P2 (wire fast     ─► P3 (BN254 /
P0.2 trusted setup    ─┘     subgroup-check groundwork)                        subgroup check,        batch verify /
                                                                                re-measure)            ops hardening)
```

P0 items are independent of each other and can run in parallel. P1 is a
single gating event (the first real `dfx`/`pocket-ic` access). P2 depends on
P1's confirmation. P3 items are largely independent of each other and can be
picked up opportunistically once P0–P2 are settled.

---

## 4. Patch notes index

Every fix in this document has a corresponding `PATCH_NOTES-*.md` at the repo
root with exactly what changed, what was actually run/verified vs. only
typechecked, and what's still open:

- `PATCH_NOTES-alphabeta-precompute.md` — Groth16 verifier, 3-pair vs 4-pair
  Miller loop (P1/performance).
- `PATCH_NOTES-fast-subgroup-check.md` — endomorphism-based fast subgroup
  check, additive alongside the slow literal check (P2).
- `PATCH_NOTES-admin-bootstrap.md` / `PATCH_NOTES-admin-allowlist.md` —
  hardcoded admin principal → one-time bootstrap → multi-principal
  allow-list (P0.1/P3).
- `PATCH_NOTES-ceremony-and-provenance.md` — the delta-only Phase-2 ceremony
  toolkit (P0.2, mechanics only — see 2.2 above), plus the `base`/`core`
  package-provenance fix in `package_flags.sh` (new, folded in below).

**New in this pass — package provenance (folded into general productization):**
`package_flags.sh` previously pointed `moc` at whatever `base`/`core` a local
`dfx cache install` happened to have, with no check that it matched
`mops.toml`'s declared versions and no recorded hash — so two machines (or
one machine after a `dfx` upgrade) could silently typecheck/compile against
different library sources. Rewritten to pin both packages to specific
upstream git refs, fetch them via `codeload.github.com` (reachable; the real
`mops` registry at `icp-api.io` is not, from this sandbox), and check a
recorded content hash (`mops.lock.json`) on every run — refusing to proceed,
not just warning, on a mismatch. Independently re-verified in this pass: a
fresh run (empty cache) fetches and records a hash that matches the shipped
`mops.lock.json` exactly; a second run confirms the match; a deliberately
corrupted cache file causes a real `FATAL` failure with nonzero exit code,
not a silent continue. The full Motoko project was then re-typechecked
end-to-end using these exact freshly-fetched sources — 0 errors, confirming
the two halves of this project (crypto patches + provenance fix) actually
work together, not just sit side by side.

**Honest residual gap (stated in the script's own comments):** the pinned
git refs are a reasonable, standard inference from `mops.toml`'s declared
versions (the same inference `dfx cache install` itself relies on), not a
guarantee from the real `mops` registry, which this sandbox cannot reach.
Closing that last gap needs `mops install` run from a machine with mainnet
access, diffed against `mops.lock.json`.
