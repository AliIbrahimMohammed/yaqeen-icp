# Contributing

Thanks for your interest in Yaqeen on ICP. This is a security-sensitive
project (zero-knowledge verification of title records on the Internet
Computer), so contributions are reviewed carefully and verification claims
are taken seriously.

## Getting started

- Read `README.md` — the status table explains what is actually verified
  versus what is still in flight.
- Read `ROADMAP.md` — the prioritized open items live here.
- Every landed change that touches security boundaries ships with a
  `PATCH_NOTES-*.md` doc (e.g. `PATCH_NOTES-security-hardening.md`) that
  explains the change, how it was verified, and any residual risk. Follow
  that pattern for anything security-related.

## Environment

The project has a mixed toolchain:

- **Rust / arkworks** (`circuit/`) — the R1CS statement, setup, prover,
  and verification tooling. Built with `cargo build --release`.
- **Motoko** (`motoko/`) — the canister. The compiler is the `motoko` npm
  package (`node-motoko`, a real WASM-compiled `moc`); dependencies resolve
  against `mo:base` / `mo:core` (see `mops.toml`).
- **`dfx` / `pocket-ic`** — needed for anything that exercises a live
  replica (install, updates, timers, upgrades). The sandboxed CI environment
  this project historically ran in has no working `wasmtime`/`dfx`; those
  checks are run by whoever has real access and documented honestly.

## Where the vendored code comes from

`motoko/src/groth16/vendor/` contains an **unmodified** copy of the
MIT-licensed BLS12-381 Groth16 verifier from
[Shielded-Ledger-Hivemind](https://github.com/Menese-Protocol/Shielded-Ledger-Hivemind).
Do **not** edit those files without explicit agreement — integration goes
through `TitleGroth16.mo`, which sits on top of the vendored verifier.
If you need to fix the verifier, send the fix upstream first.

## How to contribute

### Bug reports

Open an issue using the bug template. For anything crypto or
security-related, include the evidence: which check produced the failure,
the exact command / call shape, and (if you have it) instruction counts or
replica output. A failing reproduction is worth far more than a description.

### Code changes

1. Discuss first for anything non-trivial — open an issue or comment on an
   existing one before writing a large PR. Small, focused changes can go
   straight to a PR.
2. Follow the existing conventions in the file you touch (module doc
   comments, `Result.Result<_, Text>` error style, stable-state discipline
   in `main.mo`).
3. Verify what you claim, and say how:
   - Motoko changes must typecheck/compile with the real `moc` (
     `motoko` npm package) against `mo/` base/core.
   - Circuit changes must `cargo build --release` and ideally run the
     relevant `circuit/src/bin/*` regression tools.
   - Be explicit in the PR description about what you could and could not
     run (e.g. "compiled only; the live-replica checks still need a `dfx`
     session").
4. Never commit secrets, keys, or a hardcoded admin principal.
5. Prefer one logical change per PR.

### Review

- Security-critical changes (access control, crypto, state serialization)
  get an extra round of review.
- Respect the "residual risk" disclosures in `PATCH_NOTES-*.md` — the
  maintainers'd rather have an honest caveat than overclaim.

## License

By contributing, you agree your contributions are licensed under the same
[MIT License](LICENSE) that covers the repo (the vendored verifier keeps
its own separate MIT attribution, see
`motoko/src/groth16/vendor/ATTRIBUTION.md`).