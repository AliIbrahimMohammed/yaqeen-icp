//! Standalone oracle: proves that restructuring the Groth16 pairing check from
//!   e(A,B) * e(-vkx,gamma) * e(-C,delta) * e(-alpha,beta) == 1        (OLD, 4 pairs)
//! to
//!   e(A,B) * e(-vkx,gamma) * e(-C,delta) == e(alpha,beta)             (NEW, 3 pairs)
//! gives an identical accept/reject verdict, using arkworks' own BLS12-381 pairing
//! as ground truth (no dependency on the Motoko side at all).
//!
//! This is the same restructuring arkworks itself already does in
//! `ark_groth16::verifier::prepare_verifying_key` / `verify_proof_with_prepared_inputs`
//! (alpha_g1_beta_g2 precomputed once, only 3 pairs in the per-proof Miller loop).

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::Field;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::UniformRand;

/// Toy circuit: prove knowledge of x such that x*x*x = y (public).
#[derive(Clone)]
struct CubeCircuit {
    x: Option<Fr>,
    y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for CubeCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
        let x = FpVar::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y = FpVar::new_input(cs.clone(), || {
            self.y.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let x2 = &x * &x;
        let x3 = &x2 * &x;
        x3.enforce_equal(&y)?;
        Ok(())
    }
}

/// Old-form check: multi-pairing product of FOUR pairs, compared to GT identity.
fn old_form_accept(
    a: <Bls12_381 as Pairing>::G1Affine,
    b: <Bls12_381 as Pairing>::G2Affine,
    c: <Bls12_381 as Pairing>::G1Affine,
    vkx: <Bls12_381 as Pairing>::G1Affine,
    alpha: <Bls12_381 as Pairing>::G1Affine,
    beta: <Bls12_381 as Pairing>::G2Affine,
    gamma: <Bls12_381 as Pairing>::G2Affine,
    delta: <Bls12_381 as Pairing>::G2Affine,
) -> bool {
    let neg_vkx = (-vkx.into_group()).into_affine();
    let neg_c = (-c.into_group()).into_affine();
    let neg_alpha = (-alpha.into_group()).into_affine();

    let ml = Bls12_381::multi_miller_loop(
        [a, neg_vkx, neg_c, neg_alpha],
        [b, gamma, delta, beta],
    );
    let out = Bls12_381::final_exponentiation(ml).unwrap();
    out.0 == <Bls12_381 as Pairing>::TargetField::ONE
}

/// New-form check: precompute target = e(alpha,beta) ONCE (vk-prep time), then a
/// per-proof multi-pairing of only THREE pairs compared against that stored target.
fn new_form_accept(
    a: <Bls12_381 as Pairing>::G1Affine,
    b: <Bls12_381 as Pairing>::G2Affine,
    c: <Bls12_381 as Pairing>::G1Affine,
    vkx: <Bls12_381 as Pairing>::G1Affine,
    precomputed_target: <Bls12_381 as Pairing>::TargetField,
    gamma: <Bls12_381 as Pairing>::G2Affine,
    delta: <Bls12_381 as Pairing>::G2Affine,
) -> bool {
    let neg_vkx = (-vkx.into_group()).into_affine();
    let neg_c = (-c.into_group()).into_affine();

    let ml = Bls12_381::multi_miller_loop([a, neg_vkx, neg_c], [b, gamma, delta]);
    let out = Bls12_381::final_exponentiation(ml).unwrap();
    out.0 == precomputed_target
}

fn main() {
    let mut rng = StdRng::seed_from_u64(42);

    // Real trusted setup + real proof for a real (tiny) circuit, all via arkworks itself.
    let circuit_for_setup = CubeCircuit { x: None, y: None };
    let pk = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
        circuit_for_setup,
        &mut rng,
    )
    .unwrap();
    let vk = &pk.vk;

    let x = Fr::from(7u64);
    let y = x * x * x; // 343
    let circuit = CubeCircuit {
        x: Some(x),
        y: Some(y),
    };
    let proof = Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, &pk, &mut rng)
        .unwrap();

    // vk_x = gamma_abc[0] + y * gamma_abc[1]  (single public input)
    let vkx = (vk.gamma_abc_g1[0].into_group() + vk.gamma_abc_g1[1].into_group() * y)
        .into_affine();

    // Precompute the alpha/beta target ONCE, exactly as arkworks' own
    // `prepare_verifying_key` does internally.
    let precomputed_target = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2).0;

    // Sanity: arkworks' own high-level verifier accepts this proof.
    let pvk = Groth16::<Bls12_381>::process_vk(vk).unwrap();
    let lib_accepts =
        Groth16::<Bls12_381>::verify_proof(&pvk, &proof, &[y]).unwrap();
    assert!(lib_accepts, "sanity: arkworks' own verifier should accept a valid proof");

    // --- Case 1: valid proof ---
    let old_valid = old_form_accept(proof.a, proof.b, proof.c, vkx, vk.alpha_g1, vk.beta_g2, vk.gamma_g2, vk.delta_g2);
    let new_valid = new_form_accept(proof.a, proof.b, proof.c, vkx, precomputed_target, vk.gamma_g2, vk.delta_g2);
    println!("valid proof:            old={old_valid}  new={new_valid}  lib={lib_accepts}");
    assert_eq!(old_valid, new_valid);
    assert!(old_valid);

    // --- Case 2: tampered public input (verifier recomputes vkx for wrong y) ---
    let wrong_y = y + Fr::from(1u64);
    let vkx_wrong = (vk.gamma_abc_g1[0].into_group() + vk.gamma_abc_g1[1].into_group() * wrong_y)
        .into_affine();
    let old_bad_input = old_form_accept(proof.a, proof.b, proof.c, vkx_wrong, vk.alpha_g1, vk.beta_g2, vk.gamma_g2, vk.delta_g2);
    let new_bad_input = new_form_accept(proof.a, proof.b, proof.c, vkx_wrong, precomputed_target, vk.gamma_g2, vk.delta_g2);
    let lib_bad_input = Groth16::<Bls12_381>::verify_proof(&pvk, &proof, &[wrong_y]).unwrap();
    println!("tampered public input:  old={old_bad_input}  new={new_bad_input}  lib={lib_bad_input}");
    assert_eq!(old_bad_input, new_bad_input);
    assert_eq!(old_bad_input, lib_bad_input);
    assert!(!old_bad_input);

    // --- Case 3: tampered proof.C (forged/corrupted proof element) ---
    let c_tampered = (proof.c.into_group() + <Bls12_381 as Pairing>::G1::generator()).into_affine();
    let old_bad_c = old_form_accept(proof.a, proof.b, c_tampered, vkx, vk.alpha_g1, vk.beta_g2, vk.gamma_g2, vk.delta_g2);
    let new_bad_c = new_form_accept(proof.a, proof.b, c_tampered, vkx, precomputed_target, vk.gamma_g2, vk.delta_g2);
    println!("tampered proof.C:       old={old_bad_c}  new={new_bad_c}");
    assert_eq!(old_bad_c, new_bad_c);
    assert!(!old_bad_c);

    // --- Case 4: tampered proof.A ---
    let a_tampered = (proof.a.into_group() + <Bls12_381 as Pairing>::G1::generator()).into_affine();
    let old_bad_a = old_form_accept(a_tampered, proof.b, proof.c, vkx, vk.alpha_g1, vk.beta_g2, vk.gamma_g2, vk.delta_g2);
    let new_bad_a = new_form_accept(a_tampered, proof.b, proof.c, vkx, precomputed_target, vk.gamma_g2, vk.delta_g2);
    println!("tampered proof.A:       old={old_bad_a}  new={new_bad_a}");
    assert_eq!(old_bad_a, new_bad_a);
    assert!(!old_bad_a);

    // --- Case 5: different (still-valid-looking) VK swapped in (forged VK class) ---
    let circuit_for_setup2 = CubeCircuit { x: None, y: None };
    let pk2 = Groth16::<Bls12_381>::generate_random_parameters_with_reduction(
        circuit_for_setup2,
        &mut rng,
    )
    .unwrap();
    let vk2 = &pk2.vk;
    let precomputed_target2 = Bls12_381::pairing(vk2.alpha_g1, vk2.beta_g2).0;
    let old_bad_vk = old_form_accept(proof.a, proof.b, proof.c, vkx, vk2.alpha_g1, vk2.beta_g2, vk2.gamma_g2, vk2.delta_g2);
    let new_bad_vk = new_form_accept(proof.a, proof.b, proof.c, vkx, precomputed_target2, vk2.gamma_g2, vk2.delta_g2);
    println!("wrong VK:               old={old_bad_vk}  new={new_bad_vk}");
    assert_eq!(old_bad_vk, new_bad_vk);
    assert!(!old_bad_vk);

    println!("\nALL CASES AGREE: old 4-pair-product==1 form and new 3-pair-vs-precomputed-target form are equivalent.");
}
