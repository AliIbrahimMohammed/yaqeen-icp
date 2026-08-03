//! ceremony_init — produces "round 0" of the delta-only Phase-2 ceremony.
//!
//! What this DOES do, provably: it sets delta = 1 exactly (not a random
//! value that then gets "reset" — it is never anything but 1 in this
//! process), so delta_g1 == G1::generator() and delta_g2 == G2::generator()
//! byte-for-byte. `ceremony_verify` checks this directly. That means round 0
//! contains provably zero secret material in delta — the entire security of
//! the final delta comes from whichever later `ceremony_contribute` rounds
//! run, and correctness only needs ONE of those to be honest.
//!
//! What this does NOT do: `alpha`, `beta`, `gamma` (the Phase-1-equivalent
//! parameters) are still generated once, here, by whoever runs this binary.
//! That is real toxic waste this tool does not rotate. Two honest ways to
//! handle that, in order of preference:
//!
//!   1. (Best) Don't use this binary's alpha/beta/gamma at all. Take an
//!      existing, already-completed, publicly-audited Powers-of-Tau
//!      transcript for BLS12-381 (e.g. the "Perpetual Powers of Tau"
//!      project, or Zcash Sapling's/Filecoin's own original ceremony
//!      transcripts) and combine it with this circuit's QAP the standard
//!      way. That combination step is a big enough piece of work (matching
//!      arkworks' R1CS-to-QAP reduction against externally-sourced tau
//!      powers) that it deserves its own dedicated effort — flagging it
//!      here rather than faking it.
//!   2. (Minimum viable, what this binary does) Gather independent entropy
//!      contributions from MULTIPLE people (not just the operator running
//!      this binary) via `--entropy-file`, one per contributor, each
//!      containing something only that person could know/generate (dice
//!      rolls, a hardware RNG dump, a signed message, etc.), plus a public
//!      randomness beacon value (e.g. https://drand.love) via
//!      `--beacon-value`. All of these are hashed together with fresh OS
//!      randomness to derive the seed for alpha/beta/gamma. This raises
//!      the bar from "one operator's RNG" to "every listed contributor AND
//!      the operator would all have to be dishonest/colluding," but it is
//!      still fundamentally a single generation event, not an MPC with
//!      independent rounds and pairing-based verifiability the way delta's
//!      rotation (via ceremony_contribute) is. Say so plainly in whatever
//!      you publish alongside round 0.
//!
//! Usage:
//!   ceremony_init --out-dir ./ceremony_out \
//!       --entropy-file alice_dice_rolls.txt \
//!       --entropy-file bob_hw_rng_dump.bin \
//!       --beacon-value <drand round signature hex>

use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::Group;
use ark_groth16::Groth16;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use ceremony::*;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use title_verification::TitleVerificationCircuit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut out_dir = PathBuf::from("./ceremony_out");
    let mut entropy_files: Vec<String> = vec![];
    let mut beacon_values: Vec<String> = vec![];

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out-dir" => {
                out_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--entropy-file" => {
                entropy_files.push(args[i + 1].clone());
                i += 2;
            }
            "--beacon-value" => {
                beacon_values.push(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(1);
            }
        }
    }

    if entropy_files.is_empty() && beacon_values.is_empty() {
        eprintln!(
            "WARNING: no --entropy-file or --beacon-value supplied. alpha/beta/gamma will be \
             derived from this machine's OS RNG alone, which means THIS OPERATOR is a full \
             single point of trust for those parameters (delta rotation via ceremony_contribute \
             does not cover them). Re-run with at least one --entropy-file from someone else, or \
             a --beacon-value from a public randomness beacon, unless this is just a local test."
        );
    }

    std::fs::create_dir_all(&out_dir).expect("create out-dir");

    // ---- derive alpha/beta/gamma seed from every supplied source ----
    let mut hasher = Sha256::new();
    hasher.update(b"ceremony_init/v1/title_verification/BLS12-381");
    for f in &entropy_files {
        let bytes = std::fs::read(f).unwrap_or_else(|e| panic!("reading {f}: {e}"));
        hasher.update(format!("entropy_file:{f}:").as_bytes());
        hasher.update(&bytes);
    }
    for b in &beacon_values {
        hasher.update(b"beacon_value:");
        hasher.update(b.as_bytes());
    }
    // Fresh OS randomness is always mixed in too, so even a from-scratch
    // solo run (no entropy files) isn't deterministic/replayable.
    let mut os_random = [0u8; 32];
    getrandom(&mut os_random);
    hasher.update(b"os_random:");
    hasher.update(os_random);
    let seed: [u8; 32] = hasher.finalize().into();

    let mut rng = ChaCha20Rng::from_seed(seed);

    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let gamma = Fr::rand(&mut rng);
    // The whole point: delta is NOT randomized here. It is fixed to the
    // multiplicative identity, so delta_g1 / delta_g2 below are exactly
    // the standard generators — no secret to leak, nothing to destroy.
    let delta = Fr::from(1u64);

    let g1_generator = G1Projective::generator();
    let g2_generator = G2Projective::generator();

    let circuit = TitleVerificationCircuit::empty();

    let pk = Groth16::<Bls12_381>::generate_parameters_with_qap(
        circuit,
        alpha,
        beta,
        gamma,
        delta,
        g1_generator,
        g2_generator,
        &mut rng,
    )
    .expect("parameter generation failed");

    // Sanity-check our own claim before publishing anything.
    assert_eq!(
        pk.delta_g1,
        ark_bls12_381::G1Affine::from(g1_generator),
        "internal error: delta_g1 is not the generator even though delta=1"
    );
    assert_eq!(
        pk.vk.delta_g2,
        ark_bls12_381::G2Affine::from(g2_generator),
        "internal error: delta_g2 is not the generator even though delta=1"
    );

    let pk_path = out_dir.join("round_0.pk.bin");
    let bytes = save_pk(&pk_path, &pk);
    let params_sha256 = sha256_hex(&bytes);

    let record = RoundRecord {
        round: 0,
        participant: "ceremony_init (bootstrap, delta fixed to 1)".to_string(),
        timestamp_unix: now_unix(),
        contribution_g1: g1_hex(&pk.delta_g1),
        contribution_g2: g2_hex(&pk.vk.delta_g2),
        new_delta_g1: g1_hex(&pk.delta_g1),
        new_delta_g2: g2_hex(&pk.vk.delta_g2),
        params_sha256: params_sha256.clone(),
        prev_entry_hash: String::new(),
        entry_hash: String::new(), // filled below
        attestation: format!(
            "delta fixed to 1 (provable, see ceremony_verify). alpha/beta/gamma seeded from {} \
             entropy file(s) and {} beacon value(s) plus OS randomness. Full trust in \
             alpha/beta/gamma rests on whoever supplied those inputs unless/until this is \
             replaced by a real externally-sourced Phase-1 transcript (see module docs).",
            entropy_files.len(),
            beacon_values.len()
        ),
    };
    let mut record = record;
    record.entry_hash = record_hash(&record);

    let transcript = Transcript {
        circuit: "title_verification".to_string(),
        curve: "BLS12-381".to_string(),
        rounds: vec![record],
    };
    let transcript_path = out_dir.join("transcript.json");
    save_transcript(&transcript_path, &transcript);

    println!("wrote {}", pk_path.display());
    println!("wrote {}", transcript_path.display());
    println!("params_sha256 = {params_sha256}");
    println!(
        "Publish both files publicly before the first real ceremony_contribute round runs."
    );
}

/// Minimal OS randomness without pulling in the `getrandom` crate as a
/// separate dependency: ark_std::rand's OsRng-backed thread_rng is already
/// available transitively via ark-std/rand, so use that directly.
fn getrandom(buf: &mut [u8]) {
    use ark_std::rand::RngCore;
    ark_std::rand::rngs::OsRng.fill_bytes(buf);
}
