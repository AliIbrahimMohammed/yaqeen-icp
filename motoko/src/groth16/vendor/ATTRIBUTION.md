# Vendored: BLS12-381 Groth16 verifier

The `.mo` files in this directory (`Curve.mo`, `CurveFlat.mo`, `CurveJac.mo`,
`Decode.mo`, `DecodeG2.mo`, `Fp.mo`, `FpFlat.mo`, `FpMont.mo`, `Fr.mo`,
`FrFlat.mo`, `Groth16Multi.mo`, `Groth16Wire.mo`, `PairingFinalExp.mo`,
`PairingFlat.mo`, `PairingMont.mo`, `PairingProjective.mo`, `Tower.mo`,
`TowerFlat.mo`, `TowerMont.mo`) are copied, unmodified, from:

  https://github.com/Menese-Protocol/Shielded-Ledger-Hivemind
  (`src/groth16/`, `main` branch, fetched 2026-07-29)

under the MIT license reproduced in `LICENSE-menese-defi` in this directory.
Copyright (c) 2026 Menese DeFi Team.

This is the "reuse" path described in the original (now-replaced) stub
`Groth16.mo`'s doc comment: a full BLS12-381 pairing implementation (field
tower, Miller loop, final exponentiation, subgroup checks) is a large,
easy-to-get-subtly-wrong undertaking, and this module's own doc comments
describe a real differential-testing discipline (byte-diffed against an
arkworks oracle across valid and adversarial proof classes) that a fresh
implementation in this session could not replicate or verify.

Wire format (`Groth16Wire.mo`) uses ZCash/arkworks-compatible compressed
point serialization — the same format `ark-serialize`'s
`CanonicalSerialize` produces on the Rust side, confirmed by direct source
inspection of `ark-serialize`'s derive behavior (see
`circuit/src/bin/wire_export.rs`'s doc comment) rather than assumed.

Nothing in this directory has been modified from the upstream source.
Integration (`../TitleGroth16.mo`) sits on top of it, unmodified files
below.
