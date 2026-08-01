# Contributing to Yaqeen on ICP

Thanks for your interest. This is a zero-knowledge title-verification project
(a Groth16 circuit + Poseidon hashing + Motoko canisters on the Internet
Computer). Cryptography projects deserve extra care, so please read all of
this before opening an issue or PR.

## Project map

| Path | What it is |
|---|---|
| `circuit/` | Rust/arkworks R1CS circuit and tooling (BLS12-381, Groth16, Poseidon) |
| `motoko/src/main.mo` | Production canister: record submission, challenge issuance, verification |
| `motoko/src/poseidon/` | Poseidon hash, cross-language-verified against the circuit |
| `motoko/src/groth16/` | `TitleGroth16.mo` adapter + `vendor/` (vendored verifier, MIT, see `vendor/ATTRIBUTION.md`) |
| `verify_test/` | Canister-level test harness |

## Environment notes (read before you build)

- `dfx.json` uses a `packtool` script (`package_flags.sh`) that resolves
  `base`/`core` from the local `dfx` cache instead of the mops registry
  (mainnet-only). On a machine with mainnet access, prefer a real
  `mops install` and `mops sources` for reproducible builds.
- The JS-interpreted `moc` (npm `motoko` package) is fast enough for
  typechecking and Poseidon tests, but **not** for full pairing
  verification — use `dfx`/`pocket-ic` for that.
- The `admin` principal in `main.mo` is a placeholder (`aaaaa-aa`). Never
  assume it is correct; never bake in your dev identity in a PR.

## Getting started

```sh
# Circuit (Rust, arkworks)
cd circuit && cargo build --release

# Canisters (requires dfx ~0.32.0)
dfx start --background
dfx deploy
```

Quick cryptographic regression tests (no replica needed):

```sh
cd circuit
cargo run --release --bin verify_smoke
cargo run --release --bin verify_prove2    # real non-trivial Merkle path
cargo run --release --bin oracle_alphabeta # pairing-form equivalence oracle
```

## Making changes

1. Fork the repo and create a branch from `main`.
2. Make your change with tests. For cryptography changes, a standalone
   oracle/differential test in `circuit/src/bin/` (like `oracle_alphabeta.rs`)
   is the house style: check your claim against arkworks directly, in-process,
   and keep it as a permanent regression test.
3. Typecheck Motoko: `moc --check` with the real `base`/`core` sources
   (see `package_flags.sh`). Zero warnings preferred.
4. Run the cargo tests above; if your change touches the canister, run the
   `verify_test` flow on a real `dfx`/`pocket-ic` replica if you can.
5. Open a PR against `main` with the PR template.

## Do / don't

- **Do** state exactly what you verified and how (real replica vs in-process
  oracle vs typecheck only) — the README's review sections set the bar.
- **Do** add regression tests for adversarial cases (tampered inputs, wrong
  VK, replayed challenges), not just the happy path.
- **Don't** modify anything under `motoko/src/groth16/vendor/` without strong
  justification — it is vendored unmodified from
  [Shielded-Ledger-Hivemind](https://github.com/Menese-Protocol/Shielded-Ledger-Hivemind)
  under MIT. Fix upstream first, or clearly mark the change.
- **Don't** commit keys or secrets. The trusted setup is dev-only by design;
  see `SECURITY.md`.
- **Don't** squash-merge PRs with large diffs into noisy single commits —
  keep the history reviewable, like the existing commits.

## Getting help

Open a discussion or issue with the `question` label, or a PR draft if you
have partial work and want feedback early. Be specific about what you tried
and what failed.
