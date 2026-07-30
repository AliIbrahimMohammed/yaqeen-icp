//! Smoke test: proves the pipeline end-to-end rejects a self-inconsistent
//! witness (placeholder merkle_root=0 / nullifier=0 from prove.rs) instead
//! of silently accepting it. This is NOT a real proof-of-concept for valid
//! titles — it's a check that the R1CS constraints are actually wired to
//! the public inputs, i.e. that verify() isn't a no-op.

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use title_verification::TitleVerificationCircuit;

fn main() {
    let pk_bytes = std::fs::read("proving_key.bin").expect("run `setup` first");
    let pk = ark_groth16::ProvingKey::<Bls12_381>::deserialize_compressed(&*pk_bytes).unwrap();
    let vk_bytes = std::fs::read("verifying_key.bin").expect("run `setup` first");
    let vk = ark_groth16::VerifyingKey::<Bls12_381>::deserialize_compressed(&*vk_bytes).unwrap();
    let pvk = ark_groth16::prepare_verifying_key(&vk);

    // ---- Case A: the known-inconsistent placeholder witness from prove.rs ----
    let bad_circuit = TitleVerificationCircuit {
        registry_id: Some(Fr::from(1u64)),
        merkle_root: Some(Fr::from(0u64)),
        purpose: Some(Fr::from(1u64)),
        request_nonce: Some(Fr::from(42u64)),
        current_timestamp: Some(Fr::from(1_753_500_000u64)),
        nullifier: Some(Fr::from(0u64)),
        owner_secret: Some(Fr::from(999u64)),
        property_id: Some(Fr::from(1001u64)),
        encumbrance_flag: Some(Fr::from(0u64)),
        license_status: Some(Fr::from(1u64)),
        license_expiry: Some(Fr::from(2_000_000_000u64)),
        merkle_path: vec![Some(Fr::from(0u64)); title_verification::TREE_DEPTH],
        merkle_path_bits: vec![Some(false); title_verification::TREE_DEPTH],
    };
    let mut rng = ChaCha20Rng::from_entropy();
    let bad_proof = Groth16::<Bls12_381>::prove(&pk, bad_circuit, &mut rng).unwrap();
    let bad_public_inputs = vec![
        Fr::from(1u64), Fr::from(0u64), Fr::from(1u64), Fr::from(42u64),
        Fr::from(1_753_500_000u64), Fr::from(0u64),
    ];
    let bad_ok = Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &bad_public_inputs, &bad_proof).unwrap();
    println!("inconsistent witness verifies as: {} (expect false)", bad_ok);

    // ---- Case B: a genuinely self-consistent witness, built by hand ----
    // Single-leaf tree: property at index 0, all siblings are the empty-leaf
    // zero-hash chain, matching main.mo's `computeZeroHashes`.
    use title_verification::{poseidon_config, DOMAIN_LEAF, DOMAIN_NODE, DOMAIN_NULLIFIER, DOMAIN_OWNER_COMMITMENT, TREE_DEPTH};
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};

    let cfg = poseidon_config();
    let h = |domain: u64, inputs: &[Fr]| -> Fr {
        let mut sponge = PoseidonSponge::new(&cfg);
        sponge.absorb(&Fr::from(domain));
        for i in inputs { sponge.absorb(i); }
        sponge.squeeze_field_elements::<Fr>(1)[0]
    };

    let registry_id = Fr::from(1u64);
    let owner_secret = Fr::from(999u64);
    let property_id = Fr::from(1001u64);
    let encumbrance_flag = Fr::from(0u64);
    let license_status = Fr::from(1u64);
    let license_expiry = Fr::from(2_000_000_000u64);
    let current_timestamp = Fr::from(1_753_500_000u64);
    let purpose = Fr::from(1u64);
    let request_nonce = Fr::from(42u64);

    let owner_commitment = h(DOMAIN_OWNER_COMMITMENT, &[owner_secret, property_id]);
    let leaf = h(DOMAIN_LEAF, &[registry_id, owner_commitment, encumbrance_flag, license_status, license_expiry]);

    // empty-leaf zero hash chain for a single-leaf-populated tree at index 0
    let mut zero = Fr::from(0u64);
    let mut path = Vec::with_capacity(TREE_DEPTH);
    for _ in 0..TREE_DEPTH {
        path.push(zero);
        zero = h(DOMAIN_NODE, &[zero, zero]);
    }
    let mut root = leaf;
    for sib in &path {
        root = h(DOMAIN_NODE, &[root, *sib]); // index 0 is always "left"
    }

    let nullifier = h(DOMAIN_NULLIFIER, &[owner_secret, property_id, purpose, request_nonce]);

    let good_circuit = TitleVerificationCircuit {
        registry_id: Some(registry_id),
        merkle_root: Some(root),
        purpose: Some(purpose),
        request_nonce: Some(request_nonce),
        current_timestamp: Some(current_timestamp),
        nullifier: Some(nullifier),
        owner_secret: Some(owner_secret),
        property_id: Some(property_id),
        encumbrance_flag: Some(encumbrance_flag),
        license_status: Some(license_status),
        license_expiry: Some(license_expiry),
        merkle_path: path.iter().map(|x| Some(*x)).collect(),
        merkle_path_bits: vec![Some(false); TREE_DEPTH],
    };
    let good_proof = Groth16::<Bls12_381>::prove(&pk, good_circuit, &mut rng).unwrap();
    let good_public_inputs = vec![registry_id, root, purpose, request_nonce, current_timestamp, nullifier];
    let good_ok = Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &good_public_inputs, &good_proof).unwrap();
    println!("consistent witness verifies as: {} (expect true)", good_ok);

    // ---- Case C: tamper with a public input (wrong nullifier) ----
    let tampered_inputs = vec![registry_id, root, purpose, request_nonce, current_timestamp, Fr::from(123456789u64)];
    let tampered_ok = Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &tampered_inputs, &good_proof).unwrap();
    println!("tampered public input verifies as: {} (expect false)", tampered_ok);
}
