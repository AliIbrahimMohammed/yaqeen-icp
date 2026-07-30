//! Exports the circuit's exact Poseidon parameters (ARK, MDS) as JSON, plus
//! a native (non-R1CS) test vector computed with the real arkworks duplex
//! sponge, so the Motoko implementation can be generated from real numbers
//! and cross-checked byte-for-byte instead of hand-typed.
//!
//! Native PoseidonSponge (this file) and PoseidonSpongeVar (the in-circuit
//! gadget used by `poseidon_hash` in lib.rs) are arkworks' two
//! implementations of the *same* duplex-sponge algorithm — one over plain
//! field elements, one over R1CS variables. They are required to agree by
//! construction (that's the whole point of the constraint system), so a
//! native test vector here is a faithful stand-in for "what the circuit's
//! in-circuit hash computes."

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::PoseidonSponge, CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ff::PrimeField;
use title_verification::{poseidon_config, DOMAIN_OWNER_COMMITMENT};

fn fr_to_dec(f: &Fr) -> String {
    f.into_bigint().to_string()
}

fn main() {
    let config = poseidon_config();

    // ---- 1. dump ARK / MDS as flat, row-major decimal-string arrays ----
    let ark_flat: Vec<String> = config
        .ark
        .iter()
        .flat_map(|row| row.iter().map(fr_to_dec))
        .collect();
    let mds_flat: Vec<String> = config
        .mds
        .iter()
        .flat_map(|row| row.iter().map(fr_to_dec))
        .collect();

    // ---- 2. native test vector: same call shape as circuit's owner_commitment ----
    // poseidon_hash(cs, &config, &[domain_owner, owner_secret, property_id])
    // In-circuit this is sponge.absorb(&[domain_owner, owner_secret, property_id]); squeeze(1).
    // Native equivalent:
    let owner_secret = Fr::from(12345u64);
    let property_id = Fr::from(67890u64);
    let domain_owner = Fr::from(DOMAIN_OWNER_COMMITMENT);

    let mut sponge = PoseidonSponge::<Fr>::new(&config);
    sponge.absorb(&vec![domain_owner, owner_secret, property_id]);
    let out: Vec<Fr> = sponge.squeeze_native_field_elements(1);

    let json = format!(
        r#"{{
  "field": "BLS12-381 Fr",
  "modulus": "52435875175126190479447740508185965837690552500527637822603658699938581184513",
  "full_rounds": {},
  "partial_rounds": {},
  "alpha": {},
  "rate": {},
  "capacity": {},
  "T": {},
  "ark_flat_row_major": [{}],
  "mds_flat_row_major": [{}],
  "test_vector": {{
    "note": "domain tag is absorbed as inputs[0], NOT placed directly in the capacity slot. capacity starts at 0.",
    "domain_tag": "{}",
    "inputs": ["{}", "{}"],
    "expected_hash": "{}"
  }}
}}
"#,
        config.full_rounds,
        config.partial_rounds,
        config.alpha,
        config.rate,
        config.capacity,
        config.rate + config.capacity,
        ark_flat
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", "),
        mds_flat
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", "),
        fr_to_dec(&domain_owner),
        fr_to_dec(&owner_secret),
        fr_to_dec(&property_id),
        fr_to_dec(&out[0]),
    );

    std::fs::write("poseidon_params.json", &json).unwrap();
    eprintln!(
        "WROTE poseidon_params.json: {} ARK values, {} MDS values, 1 test vector",
        ark_flat.len(),
        mds_flat.len()
    );
    eprintln!("expected_hash = {}", fr_to_dec(&out[0]));
}
