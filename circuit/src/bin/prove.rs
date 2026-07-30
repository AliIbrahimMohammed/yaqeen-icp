//! Generates a Groth16 proof for a genuinely self-consistent example witness
//! (a single-leaf registry tree, verified in `verify_smoke.rs` to actually
//! pass Groth16::verify), and dumps proof + public inputs as JSON (hex).
//!
//! Replace the marked section with real registry lookups (real Merkle path
//! for the property's actual leaf index, real challenge-issued public
//! inputs) before using this for anything beyond wiring/format testing.

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
    let cfg = poseidon_config();

    // ==== REPLACE THIS BLOCK with real registry data ====
    let registry_id = Fr::from(1u64);
    let owner_secret = Fr::from(999u64); // stays client-side in the real flow
    let property_id = Fr::from(1001u64);
    let encumbrance_flag = Fr::from(0u64);
    let license_status = Fr::from(1u64);
    let license_expiry = Fr::from(2_000_000_000u64);
    let current_timestamp = Fr::from(1_753_500_000u64); // must equal the issued challenge's
    let purpose = Fr::from(1u64); // must equal the issued challenge's
    let request_nonce = Fr::from(42u64); // must equal the issued challenge's
    // real merkle_path must come from the canister's actual tree for this
    // leaf's index; this example assumes leaf index 0 in an otherwise-empty
    // tree, giving the empty-leaf zero-hash chain as siblings.
    let mut zero = Fr::from(0u64);
    let mut merkle_path = Vec::with_capacity(TREE_DEPTH);
    for _ in 0..TREE_DEPTH {
        merkle_path.push(zero);
        zero = poseidon(&cfg, DOMAIN_NODE, &[zero, zero]);
    }
    let merkle_path_bits = vec![false; TREE_DEPTH];
    // ==== END REPLACE ====

    let owner_commitment = poseidon(&cfg, DOMAIN_OWNER_COMMITMENT, &[owner_secret, property_id]);
    let leaf = poseidon(
        &cfg,
        DOMAIN_LEAF,
        &[registry_id, owner_commitment, encumbrance_flag, license_status, license_expiry],
    );
    let mut root = leaf;
    for (sib, is_right) in merkle_path.iter().zip(merkle_path_bits.iter()) {
        root = if *is_right {
            poseidon(&cfg, DOMAIN_NODE, &[*sib, root])
        } else {
            poseidon(&cfg, DOMAIN_NODE, &[root, *sib])
        };
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
        merkle_path_bits: merkle_path_bits.iter().map(|b| Some(*b)).collect(),
    };

    let mut rng = ChaCha20Rng::from_entropy();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).expect("proving failed");

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();

    println!(
        "{{\"proofHex\": \"{}\", \"publicInputs\": [\"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\"]}}",
        hex(&proof_bytes), registry_id, root, purpose, request_nonce, current_timestamp, nullifier
    );
}
