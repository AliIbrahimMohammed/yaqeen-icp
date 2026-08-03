//! Parses the REAL `wire_export.json` fixture (not synthetic data) and pins the exact
//! expected Fp12 values for the NEW 3-pair verify path, in decimal-Nat form matching
//! Motoko's TowerMont.mo tower layout (c0.c0.c0 .. c1.c2.c1, normal — not Montgomery — form,
//! since the differential test converts Motoko's Mont-form output back via `FpM.montMul(x,1)`
//! before comparing). This is the "expected" side of the byte-diff differential test;
//! Groth16MultiTest.mo (added alongside this file) is the "actual" side.
//!
//! Run: cargo run --release --bin oracle_pin_fixture

use ark_bls12_381::{Bls12_381, Fq12, Fr};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use serde_json::Value;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Print all 12 base-field coefficients of an Fp12 element, in the exact nested order
/// TowerMont.mo's Fp12M/Fp6M/Fp2M records use: c0.c0.c0, c0.c0.c1, c0.c1.c0, c0.c1.c1,
/// c0.c2.c0, c0.c2.c1, c1.c0.c0, c1.c0.c1, c1.c1.c0, c1.c1.c1, c1.c2.c0, c1.c2.c1.
fn print_fp12_coeffs(label: &str, f: &Fq12) {
    // Fq12 = Fp6[c0,c1] over Fp6 = Fp2[c0,c1,c2] over Fp2 = Fp[c0,c1]
    let outer = [("c0", f.c0), ("c1", f.c1)];
    println!("  // {label}");
    for (oname, o) in outer {
        let mid = [("c0", o.c0), ("c1", o.c1), ("c2", o.c2)];
        for (mname, m) in mid {
            println!("  // {oname}.{mname}.c0 = {}", m.c0);
            println!("  // {oname}.{mname}.c1 = {}", m.c1);
        }
    }
}

fn main() {
    let raw = std::fs::read_to_string("wire_export.json").expect("run from circuit/ directory");
    let v: Value = serde_json::from_str(&raw).unwrap();
    let vk_hex = v["vkHex"].as_str().unwrap();
    let proof_hex = v["proofHex"].as_str().unwrap();
    let inputs_hex = v["inputsHex"].as_str().unwrap();
    let forged_hex = v["forgedInputsHex"].as_str().unwrap();

    let vk_bytes = hex_to_bytes(vk_hex);
    let proof_bytes = hex_to_bytes(proof_hex);
    let inputs_bytes = hex_to_bytes(inputs_hex);
    let forged_bytes = hex_to_bytes(forged_hex);

    let vk = VerifyingKey::<Bls12_381>::deserialize_compressed(&*vk_bytes).unwrap();
    let proof = Proof::<Bls12_381>::deserialize_compressed(&*proof_bytes).unwrap();
    let inputs = Vec::<Fr>::deserialize_compressed(&*inputs_bytes).unwrap();
    let forged = Vec::<Fr>::deserialize_compressed(&*forged_bytes).unwrap();

    let vkx = |ins: &[Fr]| -> <Bls12_381 as Pairing>::G1Affine {
        let mut acc = vk.gamma_abc_g1[0].into_group();
        for (i, x) in ins.iter().enumerate() {
            acc += vk.gamma_abc_g1[i + 1].into_group() * x;
        }
        acc.into_affine()
    };

    let raw_and_target = |ins: &[Fr]| -> (Fq12, Fq12) {
        let vx = vkx(ins);
        let neg_vx = (-vx.into_group()).into_affine();
        let neg_c = (-proof.c.into_group()).into_affine();
        let ml = Bls12_381::multi_miller_loop(
            [proof.a, neg_vx, neg_c],
            [proof.b, vk.gamma_g2, vk.delta_g2],
        );
        let out = Bls12_381::final_exponentiation(ml).unwrap().0;
        let target = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2).0;
        (out, target)
    };

    let (valid_out, target) = raw_and_target(&inputs);
    let (forged_out, _) = raw_and_target(&forged);

    println!("=== alphaBetaTarget = e(alpha,beta) [precomputed once at vk-prep time] ===");
    print_fp12_coeffs("alphaBetaTarget", &target);

    println!("\n=== VALID fixture: finalExp(3-pair Miller product) — must equal alphaBetaTarget ===");
    print_fp12_coeffs("valid_out", &valid_out);
    println!("  // valid_out == target: {}", valid_out == target);

    println!("\n=== FORGED fixture (tampered nullifier): finalExp(3-pair Miller product) — must NOT equal target ===");
    print_fp12_coeffs("forged_out", &forged_out);
    println!("  // forged_out == target: {}", forged_out == target);
}
