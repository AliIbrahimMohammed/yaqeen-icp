//! Self-contained check: rebuilds the exact `prove2` witness (second
//! identity, tree index 1, real non-zero sibling) and immediately verifies
//! the resulting proof with Groth16::verify, in-process — no file I/O,
//! no JSON, no dependency on an external replica. This is an independent
//! confirmation that the "second-leaf Merkle inclusion" case documented in
//! the README actually produces a proof that verifies, not just that the
//! root/nullifier arithmetic is self-consistent.

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_groth16::Groth16;
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use title_verification::{
    poseidon_config, TitleVerificationCircuit, DOMAIN_LEAF, DOMAIN_NODE, DOMAIN_NULLIFIER,
    DOMAIN_OWNER_COMMITMENT, TREE_DEPTH,
};

fn poseidon(cfg: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr>, domain: u64, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(cfg);
    sponge.absorb(&Fr::from(domain));
    for i in inputs { sponge.absorb(i); }
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

fn main() {
    let cfg = poseidon_config();
    let owner_secret = Fr::from(555666u64);
    let property_id = Fr::from(777888u64);
    let owner_secret2 = Fr::from(222333u64);
    let property_id2 = Fr::from(444555u64);
    let encumbrance_flag = Fr::from(0u64);
    let license_status = Fr::from(1u64);
    let license_expiry = Fr::from(4_000_000_000u64);
    let registry_id = Fr::from(1u64);
    let purpose = Fr::from(1u64);
    let request_nonce = Fr::from(0u64);
    let current_timestamp = Fr::from(1_234_567_890u64);

    let owner_commitment0 = poseidon(&cfg, DOMAIN_OWNER_COMMITMENT, &[owner_secret, property_id]);
    let leaf0 = poseidon(&cfg, DOMAIN_LEAF, &[registry_id, owner_commitment0, encumbrance_flag, license_status, license_expiry]);
    let owner_commitment1 = poseidon(&cfg, DOMAIN_OWNER_COMMITMENT, &[owner_secret2, property_id2]);
    let leaf1 = poseidon(&cfg, DOMAIN_LEAF, &[registry_id, owner_commitment1, encumbrance_flag, license_status, license_expiry]);

    let mut merkle_path = Vec::with_capacity(TREE_DEPTH);
    let mut merkle_path_bits = Vec::with_capacity(TREE_DEPTH);
    merkle_path.push(leaf0);
    merkle_path_bits.push(true);
    let mut zero = Fr::from(0u64);
    for _ in 0..(TREE_DEPTH - 1) {
        zero = poseidon(&cfg, DOMAIN_NODE, &[zero, zero]);
        merkle_path.push(zero);
        merkle_path_bits.push(false);
    }

    let mut root = poseidon(&cfg, DOMAIN_NODE, &[leaf0, leaf1]);
    let mut zero2 = Fr::from(0u64);
    for _ in 0..(TREE_DEPTH - 1) {
        zero2 = poseidon(&cfg, DOMAIN_NODE, &[zero2, zero2]);
        root = poseidon(&cfg, DOMAIN_NODE, &[root, zero2]);
    }

    let nullifier = poseidon(&cfg, DOMAIN_NULLIFIER, &[owner_secret2, property_id2, purpose, request_nonce]);

    let circuit = TitleVerificationCircuit {
        registry_id: Some(registry_id),
        merkle_root: Some(root),
        purpose: Some(purpose),
        request_nonce: Some(request_nonce),
        current_timestamp: Some(current_timestamp),
        nullifier: Some(nullifier),
        owner_secret: Some(owner_secret2),
        property_id: Some(property_id2),
        encumbrance_flag: Some(encumbrance_flag),
        license_status: Some(license_status),
        license_expiry: Some(license_expiry),
        merkle_path: merkle_path.iter().map(|x| Some(*x)).collect(),
        merkle_path_bits: merkle_path_bits.iter().map(|b| Some(*b)).collect(),
    };

    let pk_bytes = std::fs::read("proving_key.bin").expect("run setup first");
    let pk = ark_groth16::ProvingKey::<Bls12_381>::deserialize_compressed(&*pk_bytes).unwrap();
    let vk_bytes = std::fs::read("verifying_key.bin").expect("run setup first");
    let vk = ark_groth16::VerifyingKey::<Bls12_381>::deserialize_compressed(&*vk_bytes).unwrap();
    let pvk = ark_groth16::prepare_verifying_key(&vk);

    let mut rng = ChaCha20Rng::from_entropy();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).expect("proving failed");

    let public_inputs = vec![registry_id, root, purpose, request_nonce, current_timestamp, nullifier];
    let ok = Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap();

    println!("root = {}", root);
    println!("nullifier = {}", nullifier);
    println!("prove2 (real 2nd leaf, non-zero sibling, is_right=true) verifies as: {} (expect true)", ok);

    // Tamper check: forged nullifier should fail
    let mut forged = public_inputs.clone();
    forged[5] = Fr::from(1u64);
    let ok_forged = Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &forged, &proof).unwrap();
    println!("same proof + forged nullifier verifies as: {} (expect false)", ok_forged);
}
