//! Shared plumbing for the Phase-2 (delta-only) Groth16 MPC ceremony tools.
//!
//! IMPORTANT — READ THIS BEFORE TRUSTING ANY OUTPUT OF THIS CRATE:
//!
//! This crate implements exactly one piece of a real trusted setup: the
//! sequential, pairing-verifiable rotation of the Groth16 `delta` parameter
//! (and the `l_query`/`h_query` vectors that depend on it) across many
//! independent participants, in the same style used by the Zcash Sapling /
//! Filecoin / Semaphore "Phase 2" ceremonies. It does NOT implement:
//!
//!   - A Phase 1 "Powers of Tau" ceremony for `alpha`/`beta`/`gamma`/`tau`.
//!     Those are still fixed once, by whoever runs `ceremony_init`, and are
//!     the actual "toxic waste" that this crate's delta-rotation does not
//!     touch. See CEREMONY_SPEC.md for why this is the standard split (Phase
//!     1 is circuit-independent and meant to be *reused* from an existing
//!     public/audited ceremony, not redone per-project) and for how to wire
//!     a real Phase 1 output in instead of `ceremony_init`'s single-party
//!     alpha/beta/gamma if you don't already have one to reuse.
//!   - Any network transport, coordination server, or identity/attestation
//!     verification. Publishing each round's output (e.g. to GitHub, IPFS)
//!     and checking who ran it is left to the people running the ceremony.
//!   - Independent cryptographic audit. The pairing checks below are
//!     standard and I've derived/verified them by hand, but this code has
//!     not been reviewed by anyone else. Before pointing a production
//!     verifying key at this, get it looked at by someone with Groth16 MPC
//!     experience, or use an audited tool (`phase2-bn254`, `snarkjs zkey
//!     contribute`) for the delta-rotation step instead of this crate.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// One round of the delta-only ceremony, as published for public
/// verification. `params_file` is a sibling file (`round_<n>.pk.bin`)
/// holding the full canonically-serialized `ProvingKey<Bls12_381>` for
/// that round; this record is the tamper-evident metadata pointing at it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RoundRecord {
    pub round: u64,
    pub participant: String,
    /// Unix seconds, wall-clock, as reported by the contributing machine.
    /// Not a security property — just an audit convenience.
    pub timestamp_unix: u64,
    /// hex-encoded compressed points: this round's contribution keypair
    /// (delta_i * G1, delta_i * G2), published so anyone can check they
    /// encode the same scalar (see `check_contribution_well_formed`)
    /// without ever learning delta_i itself.
    pub contribution_g1: String,
    pub contribution_g2: String,
    /// hex-encoded compressed points: the new delta_g1 / delta_g2 this
    /// round produces (i.e. old * delta_i).
    pub new_delta_g1: String,
    pub new_delta_g2: String,
    /// sha256, hex, of the exact bytes in `round_<n>.pk.bin`.
    pub params_sha256: String,
    /// sha256, hex, of the *previous* record's canonical JSON (with that
    /// record's own `entry_hash` field blanked before hashing — see
    /// `record_hash`). Empty string for round 0.
    pub prev_entry_hash: String,
    /// sha256, hex, of this record's own canonical JSON (with this field
    /// itself blanked before hashing). Fixed-points the whole record,
    /// including `prev_entry_hash`, into a hash chain.
    pub entry_hash: String,
    /// Free-text attestation from the participant, e.g. what entropy
    /// sources they mixed in and a statement that they destroyed their
    /// share of delta_i afterward. Not cryptographically checked — it's
    /// a human-readable record for later dispute resolution, same as
    /// every real MPC ceremony publishes.
    pub attestation: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Transcript {
    pub circuit: String,
    pub curve: String,
    pub rounds: Vec<RoundRecord>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Hash of a RoundRecord for chaining purposes: canonical JSON of the
/// record with `entry_hash` set to "" first, so the hash doesn't depend
/// on itself.
pub fn record_hash(rec: &RoundRecord) -> String {
    let mut r = rec.clone();
    r.entry_hash = String::new();
    let json = serde_json::to_string(&r).expect("RoundRecord always serializes");
    sha256_hex(json.as_bytes())
}

pub fn load_transcript(path: &Path) -> Transcript {
    if !path.exists() {
        return Transcript {
            circuit: "title_verification".to_string(),
            curve: "BLS12-381".to_string(),
            rounds: vec![],
        };
    }
    let data = fs::read_to_string(path).expect("read transcript.json");
    serde_json::from_str(&data).expect("parse transcript.json")
}

pub fn save_transcript(path: &Path, t: &Transcript) {
    let json = serde_json::to_string_pretty(t).expect("serialize transcript");
    fs::write(path, json).expect("write transcript.json");
}

pub fn load_pk(path: &Path) -> ProvingKey<Bls12_381> {
    let bytes = fs::read(path).expect("read proving key file");
    ProvingKey::<Bls12_381>::deserialize_compressed(&bytes[..])
        .expect("deserialize ProvingKey (corrupt file or wrong format?)")
}

pub fn save_pk(path: &Path, pk: &ProvingKey<Bls12_381>) -> Vec<u8> {
    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)
        .expect("serialize ProvingKey");
    fs::write(path, &bytes).expect("write proving key file");
    bytes
}

pub fn g1_hex(p: &G1Affine) -> String {
    let mut b = Vec::new();
    p.serialize_compressed(&mut b).unwrap();
    hex::encode(b)
}
pub fn g2_hex(p: &G2Affine) -> String {
    let mut b = Vec::new();
    p.serialize_compressed(&mut b).unwrap();
    hex::encode(b)
}
pub fn g1_from_hex(s: &str) -> G1Affine {
    let b = hex::decode(s).expect("bad hex");
    G1Affine::deserialize_compressed(&b[..]).expect("bad G1 point")
}
pub fn g2_from_hex(s: &str) -> G2Affine {
    let b = hex::decode(s).expect("bad hex");
    G2Affine::deserialize_compressed(&b[..]).expect("bad G2 point")
}

/// Checks that `g1_pub` and `g2_pub` encode the same unknown scalar delta_i,
/// i.e. that the participant didn't publish an unrelated (g1, g2) pair.
///   e(delta_i * G1, G2) == e(G1, delta_i * G2)
pub fn check_contribution_well_formed(g1_pub: &G1Affine, g2_pub: &G2Affine) -> bool {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    Bls12_381::pairing(*g1_pub, g2) == Bls12_381::pairing(g1, *g2_pub)
}

/// Checks that `new_delta_g1`/`new_delta_g2` are `old_delta_g1`/`old_delta_g2`
/// each multiplied by the same delta_i that `contribution_g1`/`contribution_g2`
/// commit to — without ever learning delta_i.
///   e(new_delta_g1, G2)      == e(old_delta_g1, contribution_g2)
///   e(contribution_g1, old_delta_g2) == e(G1, new_delta_g2)
pub fn check_delta_ratio(
    old_delta_g1: &G1Affine,
    old_delta_g2: &G2Affine,
    new_delta_g1: &G1Affine,
    new_delta_g2: &G2Affine,
    contribution_g1: &G1Affine,
    contribution_g2: &G2Affine,
) -> bool {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let check_a = Bls12_381::pairing(*new_delta_g1, g2) == Bls12_381::pairing(*old_delta_g1, *contribution_g2);
    let check_b = Bls12_381::pairing(*contribution_g1, *old_delta_g2) == Bls12_381::pairing(g1, *new_delta_g2);
    check_a && check_b
}

/// The core "did this L/H query vector rotate correctly under the new
/// delta, with nothing else changed" invariant. The *numerator* each query
/// entry encodes (beta*a_i + alpha*b_i + c_i, or the H-query's t(x)*x^i
/// term) never changes across the whole ceremony — only which delta it's
/// divided by does. That numerator is invariant, so this pairing is
/// invariant too, across every round, for every entry j:
///   e(l_query_this_round[j], delta_g2_this_round)
///     == e(l_query_prev_round[j], delta_g2_prev_round)
/// (same formula for h_query).
///
/// Checking this one pairing per entry is correct but does NOT scale: this
/// circuit's query vectors run into the tens of thousands of entries, and
/// at ~1ms/pairing that's tens of seconds PER round PER vector, compounding
/// as the ceremony grows (verify re-checks every round from genesis each
/// time). Real implementations (snarkjs, phase2-bn254) instead take a
/// random linear combination of all entries and do 2 pairings total,
/// relying on Schwartz-Zippel: if the invariant fails for even one entry,
/// it fails for the random combination too except with probability
/// ~1/|Fr|, which is cryptographically negligible. The challenge `r` is
/// derived by hashing every point involved (Fiat-Shamir) rather than drawn
/// interactively, so any third party re-running this later gets the exact
/// same challenge and the exact same answer — it's not "trust my random
/// number," it's a deterministic function of public data.
pub fn check_query_vector_invariant(
    old_query: &[G1Affine],
    old_delta_g2: &G2Affine,
    new_query: &[G1Affine],
    new_delta_g2: &G2Affine,
) -> bool {
    use ark_ff::One;
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;

    if old_query.len() != new_query.len() {
        return false;
    }
    if old_query.is_empty() {
        return true;
    }

    // Fiat-Shamir challenge: hash every point in both vectors plus both
    // delta_g2 values, so the challenge can't be predicted before the
    // contribution that produced new_query/new_delta_g2 was published,
    // and can be independently recomputed by anyone auditing later.
    let mut hasher = Sha256::new();
    for p in old_query {
        let mut b = Vec::new();
        p.serialize_compressed(&mut b).unwrap();
        hasher.update(&b);
    }
    for p in new_query {
        let mut b = Vec::new();
        p.serialize_compressed(&mut b).unwrap();
        hasher.update(&b);
    }
    {
        let mut b = Vec::new();
        old_delta_g2.serialize_compressed(&mut b).unwrap();
        hasher.update(&b);
        let mut b2 = Vec::new();
        new_delta_g2.serialize_compressed(&mut b2).unwrap();
        hasher.update(&b2);
    }
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let r = Fr::rand(&mut rng);

    // acc_old = sum_j r^j * old_query[j], acc_new = sum_j r^j * new_query[j]
    let mut acc_old = old_query[0].into_group();
    let mut acc_new = new_query[0].into_group();
    let mut coef = Fr::one();
    for (o, n) in old_query.iter().zip(new_query.iter()).skip(1) {
        coef *= r;
        acc_old += o.into_group() * coef;
        acc_new += n.into_group() * coef;
    }

    Bls12_381::pairing(acc_new.into_affine(), *new_delta_g2)
        == Bls12_381::pairing(acc_old.into_affine(), *old_delta_g2)
}

/// Applies one contribution scalar `delta_i` to a proving key, producing
/// the next round's key. Pure group-element arithmetic; does not touch
/// alpha_g1 / beta_g1 / beta_g2 / gamma_g2 / gamma_abc_g1 / a_query /
/// b_g1_query / b_g2_query, which stay fixed for the whole ceremony.
pub fn apply_delta_contribution(
    prev: &ProvingKey<Bls12_381>,
    delta_i: Fr,
) -> ProvingKey<Bls12_381> {
    use ark_ff::Field;
    let delta_i_inv = delta_i.inverse().expect("delta_i is sampled nonzero");

    let new_delta_g1 = (prev.delta_g1.into_group() * delta_i).into_affine();
    let new_delta_g2 = (prev.vk.delta_g2.into_group() * delta_i).into_affine();

    let new_l_query: Vec<G1Affine> = prev
        .l_query
        .iter()
        .map(|p| (p.into_group() * delta_i_inv).into_affine())
        .collect();
    let new_h_query: Vec<G1Affine> = prev
        .h_query
        .iter()
        .map(|p| (p.into_group() * delta_i_inv).into_affine())
        .collect();

    let mut vk = prev.vk.clone();
    vk.delta_g2 = new_delta_g2;

    ProvingKey {
        vk,
        beta_g1: prev.beta_g1,
        delta_g1: new_delta_g1,
        a_query: prev.a_query.clone(),
        b_g1_query: prev.b_g1_query.clone(),
        b_g2_query: prev.b_g2_query.clone(),
        h_query: new_h_query,
        l_query: new_l_query,
    }
}

/// Full re-verification of every round published so far under `dir`,
/// against `transcript`. Returns Err with a human-readable reason on the
/// first problem found. Used both by `ceremony_contribute` (refuses to
/// build on a broken chain) and `ceremony_verify` (the standalone auditor).
pub fn verify_chain(dir: &Path, transcript: &Transcript) -> Result<(), String> {
    if transcript.rounds.is_empty() {
        return Err("transcript has no rounds".to_string());
    }
    if transcript.rounds[0].round != 0 {
        return Err("first round must be numbered 0".to_string());
    }

    let mut prev_hash = String::new();
    let mut prev_pk: Option<ProvingKey<Bls12_381>> = None;

    for (idx, rec) in transcript.rounds.iter().enumerate() {
        if rec.round != idx as u64 {
            return Err(format!(
                "round numbers must be sequential from 0; found round={} at position {}",
                rec.round, idx
            ));
        }
        if rec.prev_entry_hash != prev_hash {
            return Err(format!(
                "round {}: prev_entry_hash does not match previous round's actual hash (chain broken or reordered)",
                rec.round
            ));
        }
        let recomputed = record_hash(rec);
        if recomputed != rec.entry_hash {
            return Err(format!(
                "round {}: entry_hash does not match recomputed hash — record was tampered with after being written",
                rec.round
            ));
        }

        let pk_path = dir.join(format!("round_{}.pk.bin", rec.round));
        if !pk_path.exists() {
            return Err(format!("round {}: missing params file {}", rec.round, pk_path.display()));
        }
        let bytes = fs::read(&pk_path).map_err(|e| format!("round {}: {}", rec.round, e))?;
        let actual_sha = sha256_hex(&bytes);
        if actual_sha != rec.params_sha256 {
            return Err(format!(
                "round {}: params file on disk does not match the hash recorded in transcript.json (file was swapped/modified after publication)",
                rec.round
            ));
        }
        let pk = ProvingKey::<Bls12_381>::deserialize_compressed(&bytes[..])
            .map_err(|e| format!("round {}: corrupt ProvingKey: {}", rec.round, e))?;

        if rec.round == 0 {
            let g1 = G1Affine::generator();
            let g2 = G2Affine::generator();
            if pk.delta_g1 != g1 || pk.vk.delta_g2 != g2 {
                return Err(
                    "round 0: delta_g1/delta_g2 are not the plain generators — round 0 must have delta fixed to 1 with nothing hidden (did this come from ceremony_init?)"
                        .to_string(),
                );
            }
        } else {
            let prev = prev_pk.as_ref().unwrap();
            if !fixed_fields_match(prev, &pk) {
                return Err(format!(
                    "round {}: alpha/beta/gamma/A-query/B-query changed — only delta/L/H may change after round 0",
                    rec.round
                ));
            }
            let contribution_g1 = g1_from_hex(&rec.contribution_g1);
            let contribution_g2 = g2_from_hex(&rec.contribution_g2);
            if !check_contribution_well_formed(&contribution_g1, &contribution_g2) {
                return Err(format!(
                    "round {}: published contribution (g1,g2) pair does not encode the same scalar in both groups",
                    rec.round
                ));
            }
            if !check_delta_ratio(
                &prev.delta_g1,
                &prev.vk.delta_g2,
                &pk.delta_g1,
                &pk.vk.delta_g2,
                &contribution_g1,
                &contribution_g2,
            ) {
                return Err(format!(
                    "round {}: new delta_g1/delta_g2 are not old delta_g1/delta_g2 raised to the published contribution scalar",
                    rec.round
                ));
            }
            if !check_query_vector_invariant(&prev.l_query, &prev.vk.delta_g2, &pk.l_query, &pk.vk.delta_g2) {
                return Err(format!("round {}: l_query did not rotate consistently with delta", rec.round));
            }
            if !check_query_vector_invariant(&prev.h_query, &prev.vk.delta_g2, &pk.h_query, &pk.vk.delta_g2) {
                return Err(format!("round {}: h_query did not rotate consistently with delta", rec.round));
            }
        }

        prev_hash = rec.entry_hash.clone();
        prev_pk = Some(pk);
    }

    Ok(())
}

pub fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Fields other than alpha/beta/gamma/tau that must stay byte-identical
/// across every round of a delta-only ceremony. Used by ceremony_verify to
/// catch a round that changed something it shouldn't have.
pub fn fixed_fields_match(a: &ProvingKey<Bls12_381>, b: &ProvingKey<Bls12_381>) -> bool {
    a.vk.alpha_g1 == b.vk.alpha_g1
        && a.vk.gamma_g2 == b.vk.gamma_g2
        && a.vk.gamma_abc_g1 == b.vk.gamma_abc_g1
        && a.beta_g1 == b.beta_g1
        && a.vk.beta_g2 == b.vk.beta_g2
        && a.a_query == b.a_query
        && a.b_g1_query == b.b_g1_query
        && a.b_g2_query == b.b_g2_query
}
