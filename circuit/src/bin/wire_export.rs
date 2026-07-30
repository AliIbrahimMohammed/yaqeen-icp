//! Exports vk/proof/public-inputs in the exact wire format the vendored
//! Motoko Groth16 verifier (`Groth16Wire.mo`, from Shielded-Ledger-Hivemind)
//! expects, for a genuinely self-consistent witness (same construction as
//! `verify_smoke.rs`). This is the cross-language test fixture: proof/vk
//! generated here should verify ACCEPT in the real Motoko verifier.
//!
//! Confirmed by direct source inspection (see project notes) that:
//!   - ark_groth16::Proof<Bls12_381>::serialize_compressed derives field
//!     order (a, b, c) -> exactly A:G1(48) || B:G2(96) || C:G1(48) = 192B
//!   - ark_groth16::VerifyingKey::serialize_compressed derives field order
//!     (alpha, beta, gamma, delta, gamma_abc: Vec<G1>) with Vec serialized
//!     as u64-LE length + elements -> exactly the vk wire format
//!   - Fp::serialize_compressed writes MODULUS_BIT_SIZE-based little-endian
//!     bytes (32 for BLS12-381 Fr) -> exactly the LE canonical Fr format
//! So the SAME bytes our `setup`/`prove` binaries already produce are
//! directly usable here, unmodified.

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use title_verification::{
    poseidon_config, TitleVerificationCircuit, DOMAIN_LEAF, DOMAIN_NODE, DOMAIN_NULLIFIER,
    DOMAIN_OWNER_COMMITMENT, TREE_DEPTH,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn poseidon(cfg: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr>, domain: u64, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(cfg);
    sponge.absorb(&Fr::from(domain));
    for i in inputs {
        sponge.absorb(i);
    }
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

fn main() {
    let pk_bytes = std::fs::read("proving_key.bin").expect("run `setup` first");
    let pk = ark_groth16::ProvingKey::<Bls12_381>::deserialize_compressed(&*pk_bytes).unwrap();
    let vk_bytes = std::fs::read("verifying_key.bin").expect("run `setup` first");
    // sanity round-trip check (not required for export, just confirms our own file is valid)
    let _vk = ark_groth16::VerifyingKey::<Bls12_381>::deserialize_compressed(&*vk_bytes).unwrap();

    let cfg = poseidon_config();

    let registry_id = Fr::from(1u64);
    let owner_secret = Fr::from(999u64);
    let property_id = Fr::from(1001u64);
    let encumbrance_flag = Fr::from(0u64);
    let license_status = Fr::from(1u64);
    let license_expiry = Fr::from(2_000_000_000u64);
    let current_timestamp = Fr::from(1_753_500_000u64);
    let purpose = Fr::from(1u64);
    let request_nonce = Fr::from(42u64);

    let owner_commitment = poseidon(&cfg, DOMAIN_OWNER_COMMITMENT, &[owner_secret, property_id]);
    let leaf = poseidon(&cfg, DOMAIN_LEAF, &[registry_id, owner_commitment, encumbrance_flag, license_status, license_expiry]);

    let mut zero = Fr::from(0u64);
    let mut merkle_path = Vec::with_capacity(TREE_DEPTH);
    for _ in 0..TREE_DEPTH {
        merkle_path.push(zero);
        zero = poseidon(&cfg, DOMAIN_NODE, &[zero, zero]);
    }
    let mut root = leaf;
    for sib in &merkle_path {
        root = poseidon(&cfg, DOMAIN_NODE, &[root, *sib]); // index 0 always "left"
    }
    let nullifier = poseidon(&cfg, DOMAIN_NULLIFIER, &[owner_secret, property_id, purpose, request_nonce]);

    let circuit = TitleVerificationCircuit {
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
        merkle_path: merkle_path.iter().map(|x| Some(*x)).collect(),
        merkle_path_bits: vec![Some(false); TREE_DEPTH],
    };

    let mut rng = ChaCha20Rng::from_entropy();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).expect("proving failed");
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();

    let public_inputs: Vec<Fr> = vec![registry_id, root, purpose, request_nonce, current_timestamp, nullifier];
    let mut inputs_bytes = Vec::new();
    public_inputs.serialize_compressed(&mut inputs_bytes).unwrap(); // Vec<Fr> -> u64 LE len + 32B LE each

    // A forged variant: tamper with the nullifier public input only (proof stays the same).
    let mut forged_inputs = public_inputs.clone();
    forged_inputs[5] = Fr::from(123456789u64);
    let mut forged_inputs_bytes = Vec::new();
    forged_inputs.serialize_compressed(&mut forged_inputs_bytes).unwrap();

    let out = serde_like_json(&hex(&vk_bytes), &hex(&proof_bytes), &hex(&inputs_bytes), &hex(&forged_inputs_bytes));
    std::fs::write("wire_export.json", &out).unwrap();
    println!("{}", out);
}

fn serde_like_json(vk_hex: &str, proof_hex: &str, inputs_hex: &str, forged_inputs_hex: &str) -> String {
    format!(
        "{{\n  \"vkHex\": \"{}\",\n  \"proofHex\": \"{}\",\n  \"inputsHex\": \"{}\",\n  \"forgedInputsHex\": \"{}\"\n}}\n",
        vk_hex, proof_hex, inputs_hex, forged_inputs_hex
    )
}
