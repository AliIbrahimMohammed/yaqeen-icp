# Yaqeen on ICP

<p align="center">
  <img alt="Motoko" src="https://img.shields.io/badge/Motoko-0.13.5-3C3C3C">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-1.75-orange">
  <img alt="Internet Computer" src="https://img.shields.io/badge/Internet%20Computer-ICP-29AFF2">
  <img alt="Runs on ICP" src="https://img.shields.io/badge/Runs%20on-ICP%20mainnet-29AFF2">
  <img alt="dfx" src="https://img.shields.io/badge/dfx-0.32-00B0FF">
  <img alt="CI" src="https://github.com/AliIbrahimMohammed/yaqeen-icp/actions/workflows/ci.yml/badge.svg">
  <img alt="Groth16" src="https://img.shields.io/badge/Groth16-SNARK-6B8E23">
  <img alt="BLS12-381" src="https://img.shields.io/badge/BLS12--381-zk--Curve-448AFF">
  <img alt="Poseidon" src="https://img.shields.io/badge/Poseidon-Hash-7A85EE">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green">
</p>

**Zero-knowledge property-title verification on the Internet Computer.**

A Motoko canister that issues challenges and verifies **BLS12-381 Groth16
proofs natively on-chain** — no bridge, no off-chain verifier trust. The proof
asserts that the prover owns a verified title (no liens, valid license, valid
Merkle-tree membership) **without revealing the underlying property data or
the owner's secret**. The statement is a port of Yaqeen's title-verification
logic from Noir/Barretenberg/BN254 to the IC, following the architecture of
`Shielded-Ledger-Hivemind`.

---

## Table of contents

- [How it works](#how-it-works)
- [The proven statement](#the-proven-statement)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Security model](#security-model)
- [Verification status](#verification-status)
- [Performance](#performance)
- [Trusted setup (`ceremony/`)](#trusted-setup-ceremony)
- [Building and testing](#building-and-testing)
- [Deployment checklist](#deployment-checklist)
- [Roadmap](#roadmap)
- [Known limitations](#known-limitations)
- [License and attribution](#license-and-attribution)

---

## How it works

The system mirrors Yaqeen's original three-route flow — challenge, prove,
verify — into a single canister with stable state.

1. **`submitRecord`** (admin-only) — an author commits a property record. The
   record stores an `ownerCommitment = Poseidon(owner_secret, property_id)`
   computed **off-chain**: the canister never learns `owner_secret`. The
   record is hashed into a domain-separated leaf and inserted into a depth-25
   sparse Merkle tree.

2. **`requestChallenge`** — the canister issues a short-lived, single-use
   challenge that pins every security-relevant value **server-side**:
   `registryId`, `merkleRoot`, `purpose`, `requestNonce`, `currentTimestamp`,
   plus an expiry. Nothing is accepted from the caller.

3. **`verify`** — the client submits a Groth16 proof plus those public inputs.
   The canister, in order:
   1. checks the public inputs match the *exactly issued* challenge
      (**before any cryptographic work**),
   2. runs the pairing check natively,
   3. marks the challenge consumed and the nullifier spent.

   Replay is blocked twice: a challenge can only be used once, and a nullifier
   can only ever be spent once — enforced atomically inside sequential update
   calls (one canister = no Redis/Lua race to manage).

## The proven statement

The R1CS circuit (`circuit/src/lib.rs`) proves, over the BLS12-381 scalar
field and domain-separated Poseidon hashing:

- the prover knows an `owner_secret` whose owner-commitment sits inside a leaf
  at `merkle_root` (25-level Merkle path, with per-level left/right bits),
- `encumbrance_flag == 0` — no liens, disputes, or court holds,
- `license_status == 1` — license currently valid,
- `license_expiry > current_timestamp` — license not expired (64-bit
  range-checked comparison),
- `nullifier == Poseidon(owner_secret, property_id, purpose, request_nonce)` —
  replay scoped to the purpose and this one challenge.

Public inputs (6, in order): `[registry_id, merkle_root, purpose,
request_nonce, current_timestamp, nullifier]`.

Everyone's hashes are domain-tagged (`DOMAIN_LEAF=1`, `DOMAIN_OWNER_COMMITMENT=2`,
`DOMAIN_NULLIFIER=3`, `DOMAIN_NODE=4`) so a value produced for one role can
never be silently reinterpreted as another.

---

## Architecture

| Layer | Technology | Role |
|---|---|---|
| **Circuit** | Rust / `arkworks` (R1CS, Groth16, BLS12-381) | Defines the constraint system, generates setups/proofs, and provides differential oracles for the Motoko side. |
| **Poseidon** | Motoko module, matched byte-for-byte to arkworks | The exact sponge both circuit and canister use (owner commitments, leaves, internal nodes, nullifiers). |
| **Canister** | Motoko `persistent actor` (`main.mo`) | Registry records, Merkle tree + root, challenge store, nullifier set, admin allow-list, native Groth16 verification. |
| **Verifier** | Vendored BLS12-381 Groth16 verifier + thin adapter (`TitleGroth16.mo`) | Full field tower, Miller loop, final exponentiation, subgroup checks — sourced from `Shielded-Ledger-Hivemind` (MIT), integrated unmodified. |

Two optimizations have landed on top of the vendored verifier:

- **alpha/beta precompute** — `e(α,β)` is computed once at vk-preparation time
  instead of re-paired every proof (3-pair vs. 4-pair verifier), validated
  against arkworks (`oracle_alphabeta.rs`).
- **fast subgroup checks** (additive, not yet merged into the hot path) —
  endomorphism-based G1/G2 checks that replace ~255-bit scalar
  multiplications, differential-tested against arkworks; see
  `PATCH_NOTES-fast-subgroup-check.md`.

---

## Repository layout

```
circuit/                     # Rust / arkworks R1CS, setup/prove/verify bins, oracles
ceremony/                    # Rust — Phase-2 Groth16 MPC toolkit (init / contribute / verify)
motoko/src/main.mo           # the canister — records, challenges, nullifiers, admin
├── poseidon/Poseidon.mo     # Poseidon hash, matched to the circuit
├── groth16/TitleGroth16.mo  # thin wire adapter (no crypto of its own)
└── groth16/vendor/          # vendored BLS12-381 Groth16 verifier (MIT)
verify_test/main.mo          # differential / acceptance harness
perf-testing/                # instruction-count and DTS-round measurements
CEREMONY_SPEC.md, ROADMAP.md, PATCH_NOTES-*.md, SECURITY.md
```

---

## Security model

- **No secrets on-chain.** The canister holds commitments and proofs only; the
  owner's device keeps `owner_secret`. There is nothing sensitive for an
  attacker to steal from the ledger.
- **The canister is the verifier.** The Groth16 check runs natively — no
  bridge, no oracle, no off-chain trust root.
- **Server-pinned challenges.** Every security-relevant public input is issued
  by the canister; a capture cannot transplant a proof onto another property,
  tree, or nonce.
- **Replay protection.** Single-use challenges + once-only nullifiers,
  enforced atomically.
- **Admin allow-list.** `bootstrapAdmin` sets the initial admin once;
  `addAdmin`/`removeAdmin` are governed by existing admins, and the last admin
  can never be removed (the list can't empty itself into a bricked canister).
- **Key hygiene.** The verifying key is validated (canonical, on-curve,
  in-subgroup) at registration and cached in prepared form; per-proof cost
  excludes all key preparation.

The one place the security model leans on a human process is the **trusted
setup** — see [below](#trusted-setup-ceremony).

---

## Verification status

Everything below was confirmed by running code (real compilers, and a real
replica where noted) — not assumed.

| Component | Status | How verified |
|---|---|---|
| `circuit/` (arkworks R1CS) | **Compiles clean, crypto-verified** | `setup → prove → verify_smoke`: consistent witness `true`, tampered/forged `false`. |
| Poseidon (`Poseidon.mo`) | **Real constants, real construction, cross-language** | ARK/MDS exported from the circuit's own `poseidon_config()` and diffed value-for-value; Motoko `hash` output matches the Rust test vector exactly. |
| Vendored Groth16 verifier | **ACCEPT / REJECT on a real replica** | `GW.tryVerify` on the static fixture: `ACCEPT` valid, `REJECT` forged — on real `dfx`/`pocket-ic`. |
| Full end-to-end flow | **Live, real challenge** | `submitRecord → requestChallenge → prove_live → setVerifyingKey → verify`: real `#ok` + correct nullifier; replay rejected; tampered-nullifier rejected; cross-challenge proof rejected *before* crypto. |
| Upgrade round-trip | **Merkle structure survives** | Forced upgrade on real state; post-upgrade insert against the live first leaf reproduces the root **independently**. |
| Second-leaf proof | **Real Merkle path** | Genuine non-zero sibling + `is_right=true` step — after finding and fixing a real test-toolchain bug (off-by-one zero-hash chain). |

Everything checkable without a live replica was re-verified independently in a
second pass — exact constants re-derived and diffs against the Rust oracle,
predicted roots/nullifiers rebuilt from scratch matching for the stated numbers,
and the new `verify_prove2` regression test (rebuild + in-process verify, no
replica) passing `true`/`false` on valid/tampered.

The one thing that could not be re-run in the build sandbox is the live
replica measurement behind the ~20.9B-instruction figure — it needs real
`dfx` access and is reported as measured by the session that had it.

---

## Performance

Measured on a real replica via `Prim.performanceCounter(0)`:

- **One `verify` call ≈ 20.9 × 10⁹ Wasm instructions** (valid proof, full
  pairing + subgroup checks).

| Limit | 20.9B call |
|---|---|
| Update-instruction limit (40B) | **fits** (~2× headroom) — will not trap on mainnet |
| Execution-round limit (7B) | **spans ~3 DTS-rounds** → multi-second finality |
| Query-call limit (5B) | **not exposed** as a query — it must be a paid update call |

So the verifier works and is within hard limits, but it is expensive: budget
real cycles per call, expect multi-second latency, and consider batch
verification / a cheaper curve if volume grows. The landed alpha/beta
precompute and the pending fast-subgroup wire-in (P1→P2) target exactly this
hot spot.

---

## Trusted setup (`ceremony/`)

The dev key from `circuit/src/bin/setup.rs` is **single-party and not
value-eligible**. The repo ships a Phase-2 Groth16 MPC toolkit
(`ceremony_init` / `ceremony_contribute` / `ceremony_verify`) implementing the
standard delta-rotation protocol (same structure as Zcash Sapling / Filecoin /
Semaphore). It was independently re-verified end-to-end:

- a full 3-round chain (init + two participants) verified via real pairing
  checks;
- a byte-flip in a published round file is rejected (nonzero exit);
- the ceremony's *final* proving/verifying key actually produced a proof that
  `verify_smoke` accepts and that tampered input rejects;
- the batch, Fiat-Shamir-style verification keeps it fast despite large query
  vectors.

**Exactly what remains open** (and cannot be closed by tooling alone):

- `alpha`/`beta`/`gamma` are fixed once at `ceremony_init`; only `delta` is
  rotated across participants. Feasible Phase-1 (Powers-of-Tau) sources still
  need to be sourced/verified, or a fresh Phase-1 run with independent,
  non-colluding humans.
- The QAP-combination step and the crate's own cryptography have **not** been
  independently audited.

See `CEREMONY_SPEC.md` for the runbook and checklist.

---

## Building and testing

### Circuit (Rust)

```bash
cd circuit
cargo build --release
cargo run --release --bin setup           # dev-only key (never for production)
cargo run --release --bin prove
cargo run --release --bin verify_smoke
cargo run --release --bin verify_prove2   # second-leaf regression
cargo run --release --bin prove_live      # live end-to-end witness tool
```

### Canister (Motoko / dfx)

```sh
dfx start --background
dfx deploy
```

- The project uses `package_flags.sh` as `dfx`'s `packtool`. It pins
  `base`/`core` to specific upstream refs recorded in `mops.lock.json`,
  computes a content hash of every fetched file, and **fails loudly** on a
  mismatch (no silent divergence between machines).
- Re-typechecking the full Motoko project against these pinned sources
  reports **0 errors / 0 warnings**.

> Note for a real deployment: the mops registry is on ICP mainnet and
> unreachable from the build sandbox. Run `mops install` on a machine with
> mainnet access and diff the result against `mops.lock.json`.

### Continuous integration

`.github/workflows/ci.yml` re-runs the verification claims on every push/PR:

- **circuit** — `cargo build --release` + crate tests, then the full
  `setup → prove → verify_smoke → verify_prove2` pipeline (in a scratch
  dir, so committed fixtures are never overwritten) with hard assertions
  on the accept/reject outputs. The crates have no Rust unit tests —
  differential coverage lives in the oracle binaries
  (`oracle_alphabeta`/`oracle_subgroup_jacobian`/`oracle_pin_fixture`)
  and the `verify_test` fixture harness; the pipeline assertions are the
  real gate.
- **ceremony** — `cargo build --release` + crate tests.
- **motoko** — `dfx build` through `package_flags.sh`, whose pinned
  base/core content hashes must match `mops.lock.json` (the build fails
  loudly on drift), plus a working-tree-dirtiness guard.
- **replica-smoke** — deploys `title_registry` on a real local replica and
  runs the leaf-update regression: a resubmitted property must keep its
  leaf index (update in place) while the root changes, and unknown
  properties must return `null`.

---

## Deployment checklist

Before any real value touches this chain:

1. **Real multi-party trusted setup** — never deploy the `setup.rs` dev key;
   complete `CEREMONY_SPEC.md` steps using real, independent participants.
2. **Provision the admin** — call `bootstrapAdmin(principal)` in the same
   deploy session, before sharing the canister id.
3. **Confirm package sources** (`mops install` vs `mops.lock.json`).
4. **Budget the cost model** — preparation cycles and latency for ~21B
   `/verify` calls if volume is non-trivial.
5. **Re-run the dfx/pocket-ic suite** from a machine with `dfx` access, to
   corroborate the replica-level sessions that could not run in this sandbox.

---

## Roadmap

- **P0.1** Admin allow-list — implemented (`bootstrapAdmin` + allow-list,
  typechecked 0 errors; add/remove governed, last-admin protected).
- **P0.2** Trusted setup — mechanics built + independently re-tested
  (`ceremony/`); **real multi-party ceremony still not run** (needs humans).
- **P1** Validate alpha/beta precompute and fast subgroup check on a real
  replica (first real `dfx` access).
- **P2** Wire the fast subgroup check into the hot path; re-measure.
- **P3** BN254 migration, batch verify, ops hardening (monitoring, key
  rotation procedure, CI).

Full detail in `ROADMAP.md` and each `PATCH_NOTES-*.md`.

---

## Known limitations

- **Verification is expensive** (~21B instr, ~3 DTS rounds) — acceptable for
  low volume; budget cycles and latency accordingly if volume grows.
- **No real trusted-multi-party ceremony has run yet** — the highest-stakes
  open item.
- **Package provenance** is pinned to codeload GitHub refs (the best that's
  reachable from the build sandbox), not the mops registry itself.
- The vendored verifier is **unmodified** upstream code — any fix must go
  upstream, not be forked here.
- **No independent audit** of the circuit's R1CS/QAP construction or the
  vendored Groth16 verifier has been performed — differential testing
  catches implementation bugs, not protocol-level issues.
- **Throttling is a floor, not a complete DoS solution** — 2s/principal on
  `requestChallenge`/`verify` plus anonymous-caller rejection (see
  `PATCH_NOTES-leaf-update-and-hardening.md`) stops the cheap version of a
  cycles-drain attack; a real deployment should still budget cycles, alert
  on anomalous call volume, and consider a boundary-level rate limiter.

Previously-open items now fixed — see
`PATCH_NOTES-leaf-update-and-hardening.md` for detail:
- ~~Resubmitting a property appended a new leaf without invalidating the
  old one, so a stale record stayed permanently provable.~~ Fixed:
  `submitRecord` now updates a property's existing leaf in place.
- ~~No client-facing way to fetch a Merkle witness.~~ Fixed: `getRecord`
  and `getMerkleProof` query endpoints added.
- ~~`SECURITY.md` claimed per-principal throttling and anonymous-caller
  rejection that didn't exist in code.~~ Fixed: both are now implemented
  and match the doc.
- ~~`challenges` grew without bound.~~ Fixed: a `heartbeat` prunes expired
  entries.
- ~~No CI — verification claims were point-in-time, not continuously
  re-checked.~~ Fixed: `.github/workflows/ci.yml` re-runs the circuit
  pipeline, Motoko typecheck, and a replica leaf-update regression on
  every push/PR (see *Building and testing → Continuous integration*).

---

## License and attribution

- Project code: MIT — see `LICENSE`.
- Groth16 verifier under `motoko/src/groth16/vendor/`: vendored, **unmodified**
  from [Menese-Protocol/Shielded-Ledger-Hivemind] and MIT-attributed
  (`vendor/ATTRIBUTION.md`, original `LICENSE` preserved).
- Contributing: `CONTRIBUTING.md` · Security: `SECURITY.md` (report privately).

---

<p align="center"><em>Prove the title, keep it private.</em></p>