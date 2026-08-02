//! DEV-ONLY setup. This runs a single-party Groth16 setup, exactly the
//! "single-party OS-CSPRNG setup" the reference ICP repo labels
//! `real_value_eligible: false`. Do not point a production verifying key at
//! output from this binary. A real deployment needs the multi-party ceremony
//! (see project README).

use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use title_verification::TitleVerificationCircuit;

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();
    let circuit = TitleVerificationCircuit::empty();

    let (pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng).expect("setup failed");

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).unwrap();
    std::fs::write("proving_key.bin", &pk_bytes).unwrap();

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();
    std::fs::write("verifying_key.bin", &vk_bytes).unwrap();

    eprintln!(
        "WROTE proving_key.bin ({} bytes) and verifying_key.bin ({} bytes)",
        pk_bytes.len(),
        vk_bytes.len()
    );
    eprintln!("real_value_eligible: false — dev setup only, toxic waste not destroyed via ceremony");
}
