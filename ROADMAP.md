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

**2.2 — Dev-only trusted setup**

`circuit/src/bin/setup.rs` says so itself:
```
real_value_eligible: false — dev setup only, toxic waste not destroyed via ceremony
```
Whoever ran that binary holds the "toxic waste" and can forge arbitrary
valid-looking proofs for any statement. For a title registry this is
existential, not cosmetic.

- **Action:** run a real multi-party ceremony — Phase-1 powers-of-tau +
  Phase-2 circuit-specific contribution, several independent contributors,
  at least one verifiably destroying their randomness — or move to a
  universal/transparent setup scheme.
- **Owner:** cryptography lead + at least 2–3 independent external contributors.
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
