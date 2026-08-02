# Yaqeen on ICP

Zero-knowledge property-title verification on the Internet Computer.

Yaqeen's title-verification statement — ownership, no liens, valid license,
proven via Merkle-tree inclusion — is ported from Noir/Barretenberg/BN254
onto the Internet Computer. Proofs are generated **client-side** and verified
**natively inside a Motoko canister**: no bridge, no oracle, no off-chain
trust assumption on the verifier.

---

## Table of contents

- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Status](#status)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [1. Build the circuit tooling](#1-build-the-circuit-tooling)
  - [2. Deploy the canister](#2-deploy-the-canister)
  - [3. Bootstrap the admin](#3-bootstrap-the-admin)
  - [4. Run the end-to-end flow](#4-run-the-end-to-end-flow)
- [Canister API](#canister-api)
- [Security model](#security-model)
- [Performance](#performance)
- [Roadmap](#roadmap)
- [Attribution](#attribution)

## How it works

```
┌──────────────┐  owner_secret (never leaves the client)
│   Client     │  ┌─────────────────────────────────────────────┐
│  (prover)    │  │ 1. submitRecord     → registry Merkle root   │
└──────┬───────┘  │ 2. requestChallenge → { merkleRoot, nonce,   │
       │          │                        purpose, timestamp }  │
       │  proof   │ 3. verify(proof)     → nullifier or error    │
       ▼          └──────────────────────────────┬──────────────┘
┌──────────────┐                                   ▲
│ circuit/src  │  arkworks R1CS statement:         │
│    (Rust)    │  Poseidon(owner_secret, ...)       │
│              │  + Merkle inclusion at depth 25    │
│              │  + encumbrance/license checks      │
└──────────────┘                                   │
       └─────────────▶ proof bytes (JSON/blob) ─────┘
                       verified in-canister via
                       vendored BLS12-381 Groth16 verifier
```

1. A title record is registered; the owner commits to a private secret via
   `Poseidon(domain_owner, owner_secret, property_id)` — the canister never
   sees the secret.
2. The owner requests a challenge bound to the current registry Merkle root.
3. A client builds a Groth16 proof over the private inputs and the
   challenge's public inputs, then submits it to the canister.
4. The canister matches the public inputs to the issued challenge, checks
   the challenge is unconsumed, and runs a full BLS12-381 pairing
   verification in Motoko. Success returns a unique nullifier; replaying
   the proof fails with `"challenge already consumed"`.

## Repository layout

| Path | Contents |
|---|---|
| `circuit/` | Rust (arkworks) R1CS statement, setup/prove/verify tooling |
| `motoko/src/main.mo` | The `title_registry` canister (registry, challenges, verification) |
| `motoko/src/poseidon/` | Poseidon hash (real arkworks constants + duplex-sponge schedule) |
| `motoko/src/groth16/` | `TitleGroth16.mo` adapter + vendored BLS12-381 Groth16 verifier (`vendor/`) |
| `verify_test/` | Standalone canister for direct `Groth16Wire.tryVerify` tests |
| `perf-testing/` | Instruction-cost measurement artifacts (orig/patched wasm, WASI runner) |
| `dfx.json` | Canister definitions (`title_registry`, `verify_test`) |

## Status

| Component | State |
|---|---|
| R1CS circuit (`circuit/`) | Builds clean; setup → prove → verify smoke-tested with real cargo |
| Poseidon (`Poseidon.mo`) | Real constants and construction, cross-verified byte-identical against arkworks |
| Groth16 verifier (vendored) | ACCEPT/REJECT confirmed on a real `dfx`/`pocket-ic` replica |
| End-to-end flow (`main.mo`) | Confirmed against a live, freshly-issued challenge |
| Upgrade round-trip | `preupgrade`/`postupgrade` round-trip confirmed, including Merkle-tree state |
| Merkle inclusion (non-trivial path) | Real sibling + `is_right` path confirmed on a real replica |

## Getting started

### Prerequisites

- [DFINITY SDK](https://internetcomputer.org/docs/building-apps/getting-started/install) (`dfx` ≥ 0.32.0)
- Rust toolchain (`cargo`)
- `motoko-base` / `motoko-core` (resolved via `dfx cache install`; see
  `package_flags.sh`)

### 1. Build the circuit tooling

```bash
cd circuit
cargo build --release
```

Key binaries:

| Binary | Purpose |
|---|---|
| `setup` | Generate a dev-only proving/verifying key pair |
| `prove` | Build a proof from a witness |
| `prove_live` | Build a witness against live canister state (root cross-checked before proving) |
| `verify_prove2` | Self-contained in-process regression test of the second-leaf inclusion proof |
| `verify_smoke` | Smoke-test a keypair + proof |
| `wire_export` | Export wire-format fixtures for the Motoko verifier |
| `export_poseidon_params` | Export the real ARK/MDS constants used by `Poseidon.mo` |
| `oracle_alphabeta` | Differential-test the verifier against arkworks |

### 2. Deploy the canister

```bash
dfx start --background
dfx deploy
```

### 3. Bootstrap the admin

`admin` starts unset — call `bootstrapAdmin` immediately after deploy, in
the same deploy session, before the canister id is shared:

```bash
dfx canister call title_registry bootstrapAdmin '(principal "<your-principal>")'
```

After the first successful call the sentinel locks permanently; admin
rotation from then on is via `setAdmin`, callable only by the current
admin.

### 4. Run the end-to-end flow

```bash
dfx canister call title_registry submitRecord '(1, <ownerCommitment>, 0, 1, <expiry>)'
dfx canister call title_registry requestChallenge '(1)'
# build the witness against the returned challenge:
cd circuit && cargo run --release --bin prove_live -- <challenge values>
dfx canister call title_registry verify '(record { challengeId = ...; proof = blob "..." ; publicInputs = vec { ... } })'
```

See `circuit/src/bin/prove_live.rs` and `motoko/src/main.mo` for the exact
shapes.

## Canister API

| Method | Access | Purpose |
|---|---|---|
| `bootstrapAdmin(principal)` | anyone, once | One-time admin bootstrap (locks permanently) |
| `setAdmin(principal)` | current admin | Governed admin rotation |
| `submitRecord(...)` | admin | Insert a title record; returns new Merkle root |
| `requestChallenge(purpose)` | anyone | Issue a challenge bound to the current root |
| `verify(...)` | anyone | Submit proof + public inputs; returns a nullifier or error |

## Security model

- **No verifier trust**: the Groth16 verification runs entirely in-canister
  using a vendored, attribution-preserved BLS12-381 verifier
  (`motoko/src/groth16/vendor/`). No bridge or off-chain component is
  involved.
- **Owner privacy**: `owner_secret` never leaves the client; the canister
  only ever sees its Poseidon commitment.
- **Challenge binding**: public inputs must match the issued challenge
  (purpose, root, nonce, timestamp) **before** any cryptographic
  verification runs — mismatches fail at the input-matching stage.
- **Replay protection**: each challenge can be consumed exactly once;
  a failed verification does not burn the challenge.
- **Admin model**: one-time `bootstrapAdmin` sentinel, then governed
  `setAdmin` rotation (single-principal; see Roadmap).

### Known caveats (honest)

- **No multi-party trusted-setup ceremony yet.** `circuit/src/bin/setup.rs`
  is single-party, dev-only. A real Powers-of-Tau-style ceremony run by
  independent participants is required before real value is involved.
- **Cost**: one verify call measures ~20.9B Wasm instructions — within the
  40B update-call limit, but spanning ~3 DTS rounds and roughly 10× the
  per-block target. Verification must run as a paid update call, never a
  query.
- **Package resolution**: this repo resolves `base`/`core` via `dfx`'s
  bundled cache; a real deployment should install via `mops install` from
  a machine with mainnet access.

## Performance

Measured on a real replica with `Prim.performanceCounter(0)`:

| Metric | Value |
|---|---|
| Instructions per verify call | ~20.9B |
| Update-call limit | 40B (fits, ~2× headroom) |
| Execution-round limit | 7B → ~3 DTS rounds (~multi-second finality) |
| Query-call limit | 5B → verification can never be a query |
| Per-block target | ~2B → ~10× per call at volume |

If per-user verification volume will be non-trivial, budget cycles
accordingly or invest in verification batching / a cheaper proof system.

## Roadmap

1. **Multi-party trusted-setup ceremony** — non-negotiable before real value.
2. **Admin model hardening** — allow-list or threshold/governance scheme.
3. **`mops install` for real** — mops' own integrity/version guarantees.
4. **Cost/latency optimization** — batching or a cheaper curve/proof system.
5. **Mainnet deployment dry run** — cycles budgeting, subnet selection.

## Attribution

The BLS12-381 Groth16 verifier under `motoko/src/groth16/vendor/` is
vendored unmodified from
[Shielded-Ledger-Hivemind](https://github.com/Menese-Protocol/Shielded-Ledger-Hivemind)
(MIT, Copyright (c) 2026 Menese DeFi Team) — see
`motoko/src/groth16/vendor/ATTRIBUTION.md` and the preserved original
license (`LICENSE-menese-deFi`). `TitleGroth16.mo` is a thin adapter on top
and does no cryptography itself.
