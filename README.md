# Yaqeen on ICP

Zero-knowledge title verification on the Internet Computer — a Motoko canister that validates Groth16 proofs over BLS12-381 for property title statements (ownership, lien status, license validity) using a sparse Merkle tree registry.

## Overview

Yaqeen on ICP ports the Yaqeen title-verification protocol from Noir/Barretenberg/BN254 onto the Internet Computer. The architecture follows the `Shielded-Ledger-Hivemind` pattern: proofs are generated client-side and verified natively inside a Motoko canister — no bridge, no off-chain trust assumption on the verifier.

### Flow

```
Client (off-chain)                     Canister (on-chain)
       │                                       │
       │  owner_secret (never sent)            │
       │                                       │
       ├── submitRecord(ownerCommitment, …) ──►│  admin-gated, inserts leaf into Merkle tree
       │                                       │
       │◄── requestChallenge(purpose) ────────┤  returns merkleRoot, nonce, timestamp
       │                                       │
       │  prove(secret, challenge) locally     │
       │  using arkworks R1CS circuit          │
       │                                       │
       ├── verify(challengeId, proof, inputs)─►│  checks public inputs match challenge,
       │                                       │  verifies Groth16 proof, marks nullifier spent
       │◄── ok({ nullifier }) ─────────────────┤
```

## Repository Structure

```
├── circuit/                     # Rust crate — arkworks R1CS circuit + proving tooling
│   ├── src/lib.rs               # TitleVerificationCircuit (ConstraintSynthesizer)
│   ├── src/bin/
│   │   ├── setup.rs             # Single-party trusted setup (dev only)
│   │   ├── prove.rs             # Generate proof from JSON witness
│   │   ├── verify_smoke.rs      # Offline sanity check
│   │   ├── prove_live.rs        # Original live-proving tool
│   │   ├── prove_live2.rs       # Generalised: N-leaf, arbitrary indices, constraint oracle
│   │   ├── export_poseidon_params.rs
│   │   └── wire_export.rs
│   └── Cargo.toml
├── motoko/
│   └── src/
│       ├── main.mo              # Persistent actor: registry, challenges, verify
│       ├── poseidon/            # Poseidon hash (Motoko, cross-validated against Rust)
│       └── groth16/             # Groth16 verifier (vendored from Shielded-Ledger-Hivemind)
├── verify_test/                 # Motoko test canister
├── dfx.json                     # DFX project configuration
├── mops.toml                    # Mops package manager
└── package_flags.sh
```

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (1.75+)
- [DFX / icp-cli](https://internetcomputer.org/docs/current/developer-docs/setup/install)
- [Mops](https://mops.one/) (for Motoko dependencies)

### Build the Circuit

```bash
cd circuit
cargo build --release

# Generate proving & verifying keys (dev-only, single-party)
./target/release/setup

# Sanity check
./target/release/prove_live2 commitment 0
./target/release/prove_live2 tree-root 1
```

### Deploy the Canister

```bash
dfx start --background --pocketic
dfx deploy title_registry
```

Set the `admin` principal in `main.mo` to your DFX identity before deploying:

```motoko
let admin : Principal = Principal.fromText("<your-principal>");
```

### Run the Full Flow

```bash
# 1. Submit a record (admin only)
dfx canister call title_registry submitRecord '(2001, <owner_commitment>, 0, 1, 4000000000)'

# 2. Request a challenge
dfx canister call title_registry requestChallenge '(1)'

# 3. Generate proof (off-chain, using live challenge values)
cd circuit
./target/release/prove_live2 prove <leaf_index> <n_submitted> <merkle_root> <purpose> <request_nonce> <current_timestamp>

# 4. Register verifying key
dfx canister call title_registry setVerifyingKey '("<vk_hex>")'

# 5. Verify
dfx canister call title_registry verify '(<challenge_id>, blob "<proof_hex>", vec <public_inputs>)'
```

## Testing

### Constraint Satisfaction Oracle

`prove_live2 prove` includes an R1CS constraint oracle that predicts whether a witness will satisfy the circuit **before** running the Groth16 prover, using `ConstraintSystem::is_satisfied()`.

Pre-configured test identities (4 clean + 3 deliberately invalid):

| Index | Label | encumbranceFlag | licenseStatus | licenseExpiry | Expected |
|-------|-------|:-:|:-:|:-:|:-:|
| 0 | clean-0 | 0 | 1 | 4000000000 | ACCEPT |
| 1 | clean-1 | 0 | 1 | 4000000000 | ACCEPT |
| 2 | clean-2 | 0 | 1 | 4000000000 | ACCEPT |
| 3 | clean-3 | 0 | 1 | 4000000000 | ACCEPT |
| 4 | DIRTY-lien | **1** | 1 | 4000000000 | REJECT |
| 5 | DIRTY-invalid-license | 0 | **0** | 4000000000 | REJECT |
| 6 | DIRTY-expired-license | 0 | 1 | **1000000000** | REJECT |

```bash
# Verify the oracle predictions
./target/release/prove_live2 prove 0 7 <root> <purpose> <nonce> <timestamp>
# predictedSatisfied: true (clean)

./target/release/prove_live2 prove 4 7 <root> <purpose> <nonce> <timestamp>
# predictedSatisfied: false (dirty — lien present)
```

### Useful prove_live2 Commands

```bash
# Show a test identity's commitment and leaf hash
./target/release/prove_live2 commitment <index>

# Predict tree root after N sequential submissions
./target/release/prove_live2 tree-root <n_submitted>

# Generate a proof with constraint oracle
./target/release/prove_live2 prove <leaf_index> <n_submitted> <merkle_root> <purpose> <request_nonce> <current_timestamp>
```

## Circuit Statement

The `TitleVerificationCircuit` (R1CS over BLS12-381) proves that the prover knows an `owner_secret` such that:

1. **Merkle inclusion** — a leaf derived from `(registry_id, Poseidon(domain_owner, owner_secret, property_id), encumbrance_flag, license_status, license_expiry)` exists in the registry's sparse Merkle tree at the published `merkle_root`
2. **No encumbrances** — `encumbrance_flag == 0`
3. **Valid license** — `license_status == 1`
4. **Non-expired license** — `license_expiry > current_timestamp`
5. **Correct nullifier** — `nullifier == Poseidon(domain_nullifier, owner_secret, property_id, purpose, request_nonce)`

Domain separation tags (`DOMAIN_LEAF = 1`, `DOMAIN_OWNER_COMMITMENT = 2`, `DOMAIN_NULLIFIER = 3`, `DOMAIN_NODE = 4`) prevent cross-role hash collisions.

## Performance

Measured on a live canister with `Prim.performanceCounter(0)`:

| Metric | Value |
|---|---|
| Wasm instructions per verify | ~20.9 billion |
| ICP update call limit | 40 billion — fits with ~2x headroom |
| DTS rounds (per-execution-round limit 7B) | ~3 rounds |
| Query call limit (5B) | Cannot use free queries — must be update call |
| Network target per block | ~2B — verify is ~10x, significant cycle cost |

## Production Readiness

### Implemented and verified

- [x] Off-chain circuit proving (arkworks R1CS + Groth16)
- [x] On-chain Groth16 verification (motoko, BLS12-381)
- [x] Poseidon hash cross-validated between Rust and Motoko
- [x] Sparse Merkle tree with O(depth) incremental insert
- [x] Challenge-issuance with server-authoritative public inputs
- [x] Nullifier-based replay protection
- [x] Canister upgrade round-trip (preupgrade/postupgrade)
- [x] Authorization gating (admin principal check)
- [x] Multi-leaf Merkle inclusion with non-trivial paths

### Required before mainnet

- [ ] **Multi-party trusted-setup ceremony** — current `setup.rs` is single-party, dev-only. Security depends on multiple independent participants each destroying their share of toxic waste.
- [ ] **Real admin provisioning** — replace hardcoded principal with init-time argument or DAO-governed allow-list.
- [ ] **Mops dependency resolution** — run `mops install` from a machine with mainnet access for package integrity guarantees.
- [ ] **Cycles budgeting** — verify cost (~20.9B instructions) has significant resource implications at volume. Consider batching or cheaper curve/proof system for production scale.

## Attribution

The Motoko Groth16 verifier is vendored from [Shielded-Ledger-Hivemind](https://github.com/Menese-Protocol/Shielded-Ledger-Hivemind) (MIT license). See `motoko/src/groth16/vendor/ATTRIBUTION.md`.

## License

MIT
