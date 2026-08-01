# Patch: precompute the alpha/beta pairing (Groth16 verifier)

## What changed

`motoko/src/groth16/vendor/Groth16Multi.mo` — and only that file. No caller
(`Groth16Wire.mo`, `TitleGroth16.mo`, `main.mo`) needed to change, since all of
them treat `PreparedVk`/`FlatVk` as opaque types.

Before: every `verify` call interleaved **four** pairing pairs —
`(A,B)`, `(−vk_x,γ)`, `(−C,δ)`, `(−α,β)` — and checked the product equals 1.
The fourth pair is a constant: α and β never change once the verifying key is
fixed, yet the old code re-paired them on every single proof.

After: `prepareVk` computes `alphaBetaTarget = finalExp(e(α,β))` **once**, at
VK-registration time (already documented as outside the per-proof budget).
Every `verify` call now interleaves only the **three** pairs that actually
depend on the proof/public inputs, and compares their product against the
stored target instead of against 1:

```
e(A,B) · e(−vk_x,γ) · e(−C,δ)  ==  e(α,β)
```

This is not a novel trick — it's exactly what `ark_groth16`'s own
`prepare_verifying_key` / `verify_proof_with_prepared_inputs` already do
upstream (see `alpha_g1_beta_g2` in `ark_groth16::verifier`). The vendored
Motoko verifier had simply drifted from that pattern.

## What was verified, and how (being precise about the boundary)

1. **The algebraic restructuring is sound.** `circuit/src/bin/oracle_alphabeta.rs`
   generates a real BLS12-381 Groth16 keypair + proof via arkworks and checks
   that the old 4-pair-product==1 form and the new
   3-pair-vs-precomputed-target form agree, on:
   - a valid proof,
   - a tampered public input,
   - a tampered `proof.A`,
   - a tampered `proof.C`,
   - a proof checked against the wrong verifying key.

   All five cases agree between old/new forms and match arkworks' own
   `Groth16::verify_proof`. Run it yourself:
   ```
   cd circuit && cargo run --release --bin oracle_alphabeta
   ```
   This was actually run (not just written) during this session, on a real
   `cargo build --release` with rustc 1.75, and all assertions passed.

2. **The Motoko change typechecks cleanly.** Checked with the same
   JS-interpreted `moc` (npm `motoko` package) this project already uses when
   `dfx` isn't available, against the real `motoko-base`/`motoko-core`
   sources (not stubs). Checked `Groth16Multi.mo` itself and every caller
   (`Groth16Wire.mo`, `TitleGroth16.mo`, `main.mo`): **0 errors**. The single
   pre-existing warning (`M0155` in the untouched `Fp.mo`) is present
   identically before and after this patch — confirmed by typechecking the
   original tree the same way for comparison.

## What was **not** verified here, and why

- **The actual instruction-count reduction.** The README's ~20.9B figure came
  from `Prim.performanceCounter(0)` on a real `dfx`/`pocket-ic` replica; this
  sandbox has no network path to `dfx`/the IC, so that measurement could not
  be re-run, before or after this patch. Expect a real but partial reduction
  (one fewer pairing's line-evaluations/sparse-multiplications per call out
  of four; the shared squaring chain cost is unchanged), not a multi-x win —
  the big remaining lever for that is curve size (BN254 vs BLS12-381), not
  this change.
- **`GW.tryVerify` end-to-end on the real `wire_export.json` fixture** for
  the same reason — the JS interpreter is documented in this repo
  (`verify_test/main.mo`) as too slow to finish a full pairing (killed after
  17+ minutes on a prior attempt), so it cannot substitute for a real
  replica run here either.
- **The byte-diff differential test** (`Groth16MultiTest.mo`, referenced in
  this file's own doc comments) isn't present in this repo snapshot, so it
  couldn't be updated/re-run. If/when it exists, it needs to be re-pinned:
  the intermediate Miller-loop value is now a genuinely different (3-pair,
  not 4-pair) value than before, and the differential test's whole point is
  comparing that intermediate byte-for-byte against an arkworks oracle.

## Suggested next step

Before this replaces the current production path: run the project's real
`dfx`/`pocket-ic` differential test (or re-run `verify_test/main.mo`'s
`verifyRealWithInstructions`) against the same `wire_export.json` fixture,
both to confirm the new instruction count and to get a fresh byte-diff of the
3-pair intermediate against a regenerated arkworks oracle value.
