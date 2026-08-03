//! Extracts the `VerifyingKey` half of a `ProvingKey` (e.g. a ceremony's final
//! `round_N.pk.bin`) into standalone `verifying_key.bin` bytes — the format
//! `verify_smoke`/`wire_export` already expect, and what the ledger canister's
//! `setVerifyingKey` ultimately needs. Bridges `ceremony_verify`'s output to the
//! rest of this crate's existing tooling.
//!
//! Usage: `extract_vk` (reads `proving_key.bin`, writes `verifying_key.bin`,
//! both in the current directory — same convention as `prove`/`verify_smoke`).
use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

fn main() {
    let pk_bytes = std::fs::read("proving_key.bin").unwrap();
    let pk = ark_groth16::ProvingKey::<Bls12_381>::deserialize_compressed(&*pk_bytes).unwrap();
    let mut out = Vec::new();
    pk.vk.serialize_compressed(&mut out).unwrap();
    std::fs::write("verifying_key.bin", out).unwrap();
    println!("wrote verifying_key.bin");
}
