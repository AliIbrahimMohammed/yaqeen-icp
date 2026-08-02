# Performance-testing artifacts

- `orig.wasm` / `patched.wasm` — standalone WASI wasm builds of
  `groth16/Test.mo` (calls `GW.tryVerify` on the real `wire_export.json`
  fixture) compiled from the *unmodified* and *patched* trees respectively,
  via `node-motoko`'s `mo.wasm(path, 'wasi')`.
- `wasi_test_harness/Test.mo` — the tiny entry-point file that was compiled
  (drop it at `motoko/src/groth16/Test.mo` in either tree to reproduce).
- `wasi_runner/` — a `wasmtime` + fuel-metering Rust harness intended to run
  the two `.wasm` files and report consumed fuel as an instruction-count
  proxy. Builds cleanly on a current Rust toolchain; blocked in this sandbox
  because only rustc/cargo 1.75 is available (see PATCH_NOTES). Run with:
  `cargo run --release -- ../orig.wasm` and `... -- ../patched.wasm`.
- `run_wasi_node.js` — attempted to run the same two `.wasm` files via
  Node's built-in `node:wasi`, no extra toolchain required. Currently fails
  on both files with `invalid table elements limits flags`, a V8
  wasm-feature gap, not a difference between orig/patched (reproduces
  identically on both).
- `perf_estimate.py` — the analytical, source-grounded instruction estimate
  (see PATCH_NOTES's "Performance testing" section for the numbers and
  what they do/don't cover).
