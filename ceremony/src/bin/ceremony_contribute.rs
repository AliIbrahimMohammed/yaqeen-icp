//! ceremony_contribute — one participant's round of the delta-only Groth16
//! Phase-2 ceremony.
//!
//! Run this ONCE per participant, sequentially — round N+1 must be built on
//! top of round N's published output, never in parallel with it. Each run:
//!   1. re-verifies the entire chain published so far (refuses to build on
//!      a broken one — see ceremony_verify for what "broken" means),
//!   2. mixes OS randomness with whatever `--entropy` string you pass in
//!      (put something unpredictable here: dice rolls, a hardware RNG
//!      dump's hash, whatever — this is your actual contribution to
//!      security, so don't skip it) and the previous round's entry hash,
//!   3. samples this round's secret delta_i from that seed,
//!   4. transforms delta_g1/delta_g2/l_query/h_query by delta_i, publishes
//!      the (delta_i*G1, delta_i*G2) pair so anyone can verify the
//!      transformation was applied honestly without ever learning delta_i,
//!   5. best-effort zeroizes delta_i before exiting.
//!
//! YOU MUST personally delete/never persist the `--entropy` value you used
//! and any intermediate value, on this machine, after this program exits.
//! Rebooting into a fresh VM/live-USB per contributor, the way real
//! ceremonies do it, is stronger than trusting any program's zeroize call —
//! `zeroize` only overwrites what Rust knows about; it can't reach values a
//! swap file, a core dump, or a debugger already captured.
//!
//! Usage:
//!   ceremony_contribute --dir ./ceremony_out --participant "Alice" \
//!       --entropy "<dice rolls / hw rng hash / whatever>" \
//!       --attestation "generated on an offline machine, entropy destroyed after this run"

use ark_bls12_381::Fr;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use ceremony::*;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use zeroize::Zeroize;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut dir = PathBuf::from("./ceremony_out");
    let mut participant = String::new();
    let mut entropy = String::new();
    let mut attestation = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => {
                dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--participant" => {
                participant = args[i + 1].clone();
                i += 2;
            }
            "--entropy" => {
                entropy = args[i + 1].clone();
                i += 2;
            }
            "--attestation" => {
                attestation = args[i + 1].clone();
                i += 2;
            }
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(1);
            }
        }
    }

    if participant.is_empty() {
        eprintln!("--participant is required (use your real name or a stable public handle)");
        std::process::exit(1);
    }
    if entropy.len() < 16 {
        eprintln!(
            "--entropy is required and should be substantial (>=16 chars of real randomness, \
             not a placeholder) — this is refused rather than silently accepted because it's \
             the one input this tool can't generate for you."
        );
        std::process::exit(1);
    }

    let transcript_path = dir.join("transcript.json");
    let transcript = load_transcript(&transcript_path);
    if transcript.rounds.is_empty() {
        eprintln!("no transcript found at {} — run ceremony_init first", transcript_path.display());
        std::process::exit(1);
    }

    // Refuse to build on a chain we haven't just re-verified ourselves.
    if let Err(e) = ceremony::verify_chain(&dir, &transcript) {
        eprintln!("REFUSING to contribute: existing ceremony chain does not verify: {e}");
        std::process::exit(1);
    }

    let prev_round_num = transcript.rounds.last().unwrap().round;
    let prev_entry = transcript.rounds.last().unwrap();
    let prev_pk_path = dir.join(format!("round_{prev_round_num}.pk.bin"));
    let prev_pk = load_pk(&prev_pk_path);

    // ---- derive this round's delta_i ----
    let mut hasher = Sha256::new();
    hasher.update(b"ceremony_contribute/v1/");
    hasher.update(prev_entry.entry_hash.as_bytes());
    hasher.update(b"/participant:");
    hasher.update(participant.as_bytes());
    hasher.update(b"/entropy:");
    hasher.update(entropy.as_bytes());
    let mut os_random = [0u8; 32];
    {
        use ark_std::rand::RngCore;
        ark_std::rand::rngs::OsRng.fill_bytes(&mut os_random);
    }
    hasher.update(b"/os_random:");
    hasher.update(os_random);
    let mut seed: [u8; 32] = hasher.finalize().into();

    let mut rng = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    entropy.zeroize();

    let mut delta_i = Fr::rand(&mut rng);

    let delta_i_g1 = {
        use ark_ec::{CurveGroup, Group};
        (ark_bls12_381::G1Projective::generator() * delta_i).into_affine()
    };
    let delta_i_g2 = {
        use ark_ec::{CurveGroup, Group};
        (ark_bls12_381::G2Projective::generator() * delta_i).into_affine()
    };

    let new_pk = apply_delta_contribution(&prev_pk, delta_i);
    delta_i.zeroize();

    let new_round_num = prev_round_num + 1;
    let new_pk_path = dir.join(format!("round_{new_round_num}.pk.bin"));
    let bytes = save_pk(&new_pk_path, &new_pk);
    let params_sha256 = sha256_hex(&bytes);

    let mut record = RoundRecord {
        round: new_round_num,
        participant: participant.clone(),
        timestamp_unix: now_unix(),
        contribution_g1: g1_hex(&delta_i_g1),
        contribution_g2: g2_hex(&delta_i_g2),
        new_delta_g1: g1_hex(&new_pk.delta_g1),
        new_delta_g2: g2_hex(&new_pk.vk.delta_g2),
        params_sha256: params_sha256.clone(),
        prev_entry_hash: prev_entry.entry_hash.clone(),
        entry_hash: String::new(),
        attestation: if attestation.is_empty() {
            "(no attestation text supplied)".to_string()
        } else {
            attestation
        },
    };
    record.entry_hash = record_hash(&record);

    let mut transcript = transcript;
    transcript.rounds.push(record);
    save_transcript(&transcript_path, &transcript);

    println!("wrote {}", new_pk_path.display());
    println!("round {new_round_num} params_sha256 = {params_sha256}");
    println!(
        "Publish round_{new_round_num}.pk.bin and the updated transcript.json publicly BEFORE \
         the next participant runs ceremony_contribute — and before you shut down this machine, \
         confirm delta_i is not sitting in shell history, a log file, or a core dump."
    );
}

