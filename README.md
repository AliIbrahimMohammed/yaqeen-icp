# 🛡️ Yaqeen on ICP

**Zero-knowledge property-title verification on the Internet Computer.**

[![Motoko](https://img.shields.io/badge/Motoko-ICP-orange)](#)
[![Rust](https://img.shields.io/badge/Rust-arkworks-blue)](#)
[![Groth16](https://img.shields.io/badge/Groth16-BLS12--381-purple)](#)
[![Poseidon](https://img.shields.io/badge/Poseidon-hash-red)](#)
[![DFX](https://img.shields.io/badge/dfx-0.32.0-green)](#)

Yaqeen's title-verification statement — **ownership, no liens, valid
license**, proven via Merkle-tree inclusion — is ported from
Noir/Barretenberg/BN254 onto the Internet Computer, following the
architecture of `Shielded-Ledger-Hivemind`: proofs are generated
**client-side** and verified **natively inside a Motoko canister** — no
bridge, no oracle, no off-chain trust assumption on the verifier.

![Yaqeen Project ZK Verification Overview](Yaqeen_Project_ZK_Verification_Overview.png)

## Table of contents

- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Status](#status)
- [Getting started](#getting-started)
- [Canister API](#canister-api)
- [Security model](#security-model)
- [Performance](#performance)
- [Roadmap](#roadmap)
- [Attribution](#attribution)

## How it works

```
┌──────────────┐   owner_secret (never leaves the client)
│    Client    │   ┌──────────────────────────────────────────────┐
│   (prover)   │   │ 1. submitRecord      → registry Merkle root   │
└──────┬───────┘   │ 2. requestChallenge  → { root, purpose,       │
       │  proof    │                        nonce, timestamp }     │
       ▼           │ 3. verify(proof)     → nullifier or error     │
┌──────────────┐   └───────────────────────────────┬──────────────┘
│  circuit/    │                                     ▲
│  (Rust R1CS) │   arkworks statement: Poseidon       │
│              │   commitment + Merkle inclusion      │
└──────┬───────┘   (depth 25) + encumbrance/license   │
       └──────────────────▶ proof bytes ──────────────┘
                            verified in-canister via
                            vendored Groth16 verifier
```

1. **Register** — a title record is committed via
   `Poseidon(domain_owner, owner_secret, property_id)`. The canister never
   sees `owner_secret`.
2. **Challenge** — the owner requests a challenge bound to the current
   registry Merkle root.
3. **Prove** — a client builds a Groth16 proof over private inputs and the
   challenge's public inputs.
4. **Verify** — the canister matches the public inputs to the issued
   challenge, checks the challenge is unconsumed, and runs a full
   BLS12-381 pairing verification in Motoko. Success returns a unique
   nullifier; replaying a proof fails with `"challenge already consumed"`.

## Repository layout

| Path | Contents |
|---|---|
| `circuit/` | Rust (arkworks) R1CS statement; setup/prove/verify tooling |
| `motoko/src/main.mo` | `title_registry` canister — registry, challenges, verification |
| `motoko/src/poseidon/` | Poseidon hash (real arkworks constants + duplex-sponge schedule) |
| `motoko/src/groth16/` | `TitleGroth16.mo` adapter + vendored BLS12-381 Groth16 verifier (`vendor/`) |
| `verify_test/` | Standalone canister for direct `Groth16Wire.tryVerify` tests |
| `perf-testing/` | Instruction-cost measurement artifacts (orig/patched wasm, WASI runner) |
| `node-tests/` | dfx-free test suite (node-motoko): typecheck, wasm compile, Poseidon vector, canister driver |
| `DEPLOYMENT.md` | Local + mainnet deployment runbook |
| `dfx.json` | Canister definitions (`title_registry`, `verify_test`) |

## Status

| Component | State | How it was verified |
|---|---|---|
| R1CS circuit (`circuit/`) | Compiles clean, cryptographically verified | `cargo build --release`; `setup` → `prove` → `verify_smoke` — valid witnesses verify `true`, tampered ones `false` |
| Poseidon (`Poseidon.mo`) | Real constants, real construction, cross-language verified | Exported from `poseidon_config()`, diffed field-for-field; byte-identical hash output vs the Rust side on real `moc` |
| Groth16 verifier (vendored) | ACCEPT/REJECT confirmed on a real replica | Deployed on `dfx 0.32.0` + `pocket-ic`; `ACCEPT` on valid proof, `REJECT:pairing-check` on forged inputs |
| End-to-end flow (`main.mo`) | Confirmed against a live, freshly-issued challenge | Full `submitRecord` → `requestChallenge` → `prove_live` → `verify` round-trip on a real replica |
| Upgrade round-trip | Confirmed, including Merkle-tree structure | Forced `--mode upgrade`; consumed-challenge state and the `nodes` HashMap (real tree, not just root) survived |
| Merkle inclusion (non-trivial path) | Confirmed — after finding and fixing a real tooling bug | Real sibling + `is_right = true` path verified on a real replica; permanent regression test in `verify_prove2` |

## Getting started

### Prerequisites

- [DFINITY SDK](https://internetcomputer.org/docs/building-apps/getting-started/install) (`dfx` ≥ 0.32.0)
- Rust toolchain (`cargo`)

### 1. Build the circuit tooling

```bash
cd circuit
cargo build --release
```

Key binaries: `setup` (dev keypair), `prove` (build proofs), `prove_live`
(witness against live canister state, root cross-checked before proving),
`verify_prove2` (in-process regression test), `verify_smoke`,
`wire_export`, `export_poseidon_params`, `oracle_alphabeta` (differential
test against arkworks).

### 2. Deploy the canister

```bash
dfx start --background
dfx deploy
```

### 3. Bootstrap the admin

`admin` starts unset. Call `bootstrapAdmin` immediately after deploy, in
the same deploy session:

```bash
dfx canister call title_registry bootstrapAdmin '(principal "<your-principal>")'
```

The sentinel locks permanently after the first success; rotation afterward
is via `addAdmin`/`removeAdmin`, callable only by current admins. See
`PATCH_NOTES-admin-bootstrap.md`.

### 4. Run the end-to-end flow

```bash
dfx canister call title_registry submitRecord '(1, <ownerCommitment>, 0, 1, <expiry>)'
dfx canister call title_registry requestChallenge '(1)'
cd circuit && cargo run --release --bin prove_live -- <challenge values>
dfx canister call title_registry verify '(record { challengeId = ...; proof = blob "..."; publicInputs = vec { ... } })'
```

See `circuit/src/bin/prove_live.rs` and `motoko/src/main.mo` for the exact
shapes. Full mainnet walkthrough (cycles, `--network ic`, per-canister
install, `ic0.app`): see [DEPLOYMENT.md](DEPLOYMENT.md).

### 5. Run the test suite without dfx

`node-tests/` typechecks every Motoko target, wasm-compiles the canister,
and runs a Poseidon differential vector plus a ~50-check functional driver
(admin bootstrap/rotation incl. the controller gate, record validation +
provenance, VK staging/activation, challenge cap, Merkle roots, `verify`
rejection ordering) inside node-motoko's interpreter — no dfx or cargo
needed:

```bash
bash node-tests/run-tests.sh
```

Run it twice per suite: once with the controller-gate oracle stubbed
**on** (full functional suite) and once **off** (proves a non-controller
caller cannot bootstrap the registry). Two deeper caveats, kept honest in
`PATCH_NOTES-security-round3.md`: real pairing paths and the canister-call
oracle can't execute inside the interpreter, so those are covered by the
driver's stub points and must be smoke-tested on a real `dfx` replica.

## Canister API

| Method | Access | Purpose |
|---|---|---|
| `bootstrapAdmin(principal)` | **canister controller**, once | Seed the admin allow-list (locks permanently) |
| `addAdmin(principal)` | any admin | Add a principal to the admin allow-list |
| `removeAdmin(principal)` | any admin | Revoke admin (never the last one) |
| `listAdmins()` | anyone (query) | Current admin allow-list |
| `submitRecord(...)` | admin | Insert a validated title record (provenance recorded); returns new Merkle root |
| `requestChallenge(purpose)` | anyone | Issue a challenge bound to the current root (capped at 500 pending) |
| `verify(...)` | anyone | Submit proof + public inputs; returns a nullifier or error |
| `setVerifyingKey(hex)` | admin | First VK activates; replacements are **staged** pending confirmation |
| `confirmVerifyingKey(hex)` | admin (≠ proposer) | Activate a staged VK replacement (threshold-2) |
| `cancelVerifyingKeyChange()` | admin | Discard a staged VK replacement |
| `getCurrentRoot()` | anyone (query) | Current registry Merkle root |
| `getRecord(propertyId)` | anyone (query) | Record lookup (incl. provenance) |
| `getChallenge(challengeId)` | anyone (query) | Challenge lookup |
| `getVkStatus()` | anyone (query) | Active/pending verifying-key state |
| `getAuditLog()` | anyone (query) | Capped (1000) admin/record audit trail |
| `getStats()` | anyone (query) | Records, challenges, spent nullifiers, root, next leaf |

## Security model

- **No verifier trust** — Groth16 verification runs entirely in-canister
  with a vendored, attribution-preserved BLS12-381 verifier; no bridge or
  off-chain component is involved.
- **Owner privacy** — `owner_secret` never leaves the client; the canister
  only ever sees its Poseidon commitment.
- **Challenge binding** — public inputs must match the issued challenge
  *before* any cryptographic verification runs; mismatches fail at the
  input-matching stage (registry → purpose → nonce ordering).
- **Replay protection** — each challenge is consumed exactly once; a failed
  verification does not burn the challenge.
- **Bootstrap integrity** — `bootstrapAdmin` is gated to the canister
  controllers (management-canister oracle, fails closed), closing the
  fresh-deploy takeover race; the sentinel locks permanently after the
  first success.
- **Admin model** — multi-principal allow-list, governed by existing
  admins; the last admin can never be removed. **Verifying-key
  replacements are threshold-2** (staged by one admin, confirmed by a
  different one), so a single compromised admin can't swap in a key they
  control. A full multi-sig *admin* scheme remains future work.
- **Record integrity** — every `submitRecord` is field-validated
  (canonical commitment, flag enums, future expiry, nonzero propertyId)
  and stamped with `submittedBy`/`submittedAt` for attribution.
- **Flood resistance** — pending challenges capped (500) with an
  opportunistic expired-challenge sweep, and the audited log is capped.

### Known caveats (honest)

- **No multi-party trusted-setup ceremony yet.** `setup.rs` is
  single-party, dev-only. A Powers-of-Tau-style ceremony run by
  independent participants is required before real value is involved.
- **Cost** — one verify call measures ~20.9B Wasm instructions: within the
  40B update-call limit, but spanning ~3 DTS rounds and ~10× the per-block
  target. Verification must run as a paid update call, never a query.
- **Package resolution** — `base`/`core` resolved via `dfx`'s bundled
  cache; a real deployment should `mops install` from a machine with
  mainnet access.

## Performance

Measured on a real replica with `Prim.performanceCounter(0)`:

| Metric | Value |
|---|---|
| Instructions per verify call | ~20.9B |
| Update-call limit | 40B — fits, ~2× headroom |
| Execution-round limit | 7B — ~3 DTS rounds (multi-second finality) |
| Query-call limit | 5B — verification can never be a query |
| Per-block target | ~2B — ~10× per call at volume |

If per-user verification volume will be non-trivial, budget cycles
accordingly or invest in verification batching / a cheaper proof system.

## Roadmap

1. **Multi-party trusted-setup ceremony** — non-negotiable before real value.
2. **Admin threshold scheme** — VK changes are already threshold-2; a multi-sig
   threshold model for admin *actions* (submit, add/remove admin) is next.
3. **`mops install` for real** — mops' own integrity/version guarantees.
4. **Cost/latency optimization** — batching or a cheaper curve/proof system.
5. **Mainnet deployment dry run** — cycles budgeting, subnet selection.

## Attribution

The BLS12-381 Groth16 verifier under `motoko/src/groth16/vendor/` is
vendored unmodified from
[Shielded-Ledger-Hivemind](https://github.com/Menese-Protocol/Shielded-Ledger-Hivemind)
(MIT, Copyright (c) 2026 Menese DeFi Team) — see
`motoko/src/groth16/vendor/ATTRIBUTION.md` and the preserved original
license (`LICENSE-menese-defi`). `TitleGroth16.mo` is a thin adapter on top
and does no cryptography itself.
