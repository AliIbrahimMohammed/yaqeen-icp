//! ceremony_verify — standalone auditor. Anyone who downloads `transcript.json`
//! and every `round_N.pk.bin` can run this with no other trust assumptions
//! and no access to any participant's secret: it re-derives every check
//! `ceremony_contribute` and `ceremony_init` claim to satisfy, from the
//! published bytes alone.
//!
//! What "verified" means here, precisely:
//!   - round 0 has delta fixed to the plain generator in both groups
//!     (no hidden secret at genesis)
//!   - every later round's delta_g1/delta_g2 are the previous round's,
//!     raised to one consistent (but never revealed) scalar per round
//!   - that same per-round scalar was applied to invert l_query/h_query
//!   - alpha/beta/gamma/A-query/B-query never changed after round 0
//!   - the hash chain across transcript.json entries is unbroken and
//!     each entry's params_sha256 matches the actual bytes on disk
//!
//! What this can NEVER tell you, no matter how many rounds pass: whether
//! alpha/beta/gamma (fixed once, at round 0) were honestly generated. This
//! tool only ever reports on `delta`. See ceremony_init.rs's module docs.
//!
//! Usage: ceremony_verify --dir ./ceremony_out

use ark_serialize::CanonicalSerialize;
use ceremony::*;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut dir = PathBuf::from("./ceremony_out");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => {
                dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(1);
            }
        }
    }

    let transcript_path = dir.join("transcript.json");
    if !transcript_path.exists() {
        eprintln!("no transcript.json found at {}", transcript_path.display());
        std::process::exit(1);
    }
    let transcript = load_transcript(&transcript_path);

    match verify_chain(&dir, &transcript) {
        Ok(()) => {
            let last = transcript.rounds.last().unwrap();
            println!("OK — chain verifies end to end.");
            println!("  rounds:              {}", transcript.rounds.len());
            println!("  final round:         {}", last.round);
            println!("  final params_sha256: {}", last.params_sha256);
            println!("  final delta_g1:      {}", last.new_delta_g1);
            println!("  final delta_g2:      {}", last.new_delta_g2);

            // Print vk fingerprint too, since that's what a client actually
            // pins/checks against on-chain, and it should be stable-looking
            // (only delta_g2 inside it changes across rounds — everything
            // else in vk is fixed from round 0).
            let final_pk_path = dir.join(format!("round_{}.pk.bin", last.round));
            let pk = load_pk(&final_pk_path);
            let mut vk_bytes = Vec::new();
            pk.vk.serialize_compressed(&mut vk_bytes).unwrap();
            println!("  final vk sha256:     {}", sha256_hex(&vk_bytes));
            println!();
            println!(
                "Reminder: this confirms delta was rotated correctly across all {} round(s). \
                 It does NOT and cannot confirm alpha/beta/gamma (fixed at round 0) were honestly \
                 generated — see round 0's attestation text and ceremony_init.rs's docs for what \
                 that step still relies on.",
                transcript.rounds.len() - 1
            );
        }
        Err(e) => {
            eprintln!("FAILED — chain does not verify: {e}");
            std::process::exit(1);
        }
    }
}
