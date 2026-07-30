//! Generates a proof against LIVE values read from an actual running
//! `title_registry` canister, instead of `wire_export.rs`'s static,
//! self-contained demo fixture. This is the "wire the off-chain proving flow
//! to the canister's real challenge issuance" step the README's next-steps
//! list called out as still open.
//!
//! Two subcommands (plus prove2, added to close the leaf-index-1 gap):
//!
//!   prove_live commitment
//!     Prints `owner_commitment` (decimal Nat) for a fixed, hardcoded
//!     (owner_secret, property_id) pair. Feed this into `submitRecord` as
//!     the ownerCommitment argument — the canister never learns
//!     owner_secret itself, exactly like Yaqeen's original backend.
//!
//!   prove_live prove <merkle_root> <purpose> <request_nonce> <current_timestamp>
//!     Builds the full witness for a leaf inserted at index 0 of an
//!     otherwise-empty tree (i.e. the first record submitted), using the
//!     SAME (owner_secret, property_id, encumbrance_flag, license_status,
//!     license_expiry) as `commitment` used, plus the merkle_root/purpose/
//!     request_nonce/current_timestamp that a real `requestChallenge` call
//!     actually returned. Independently recomputes the expected root from
//!     the zero-hash chain (same construction as `main.mo`'s
//!     `computeZeroHashes`/`insertLeaf`) and asserts it matches the
//!     merkle_root argument BEFORE proving, so a mismatch fails loudly
//!     instead of silently producing an unprovable circuit.
//!
//!   prove_live prove2 <merkle_root> <purpose> <request_nonce> <current_timestamp>
//!     Same idea as `prove`, but for the SECOND identity's leaf at tree
//!     index 1 — i.e. a real, non-zero sibling (leaf0) at level 0, not an
//!     all-zero path. Requires exactly two records to have been submitted
//!     (identity 1 at index 0, identity 2 at index 1).
//!
//!     Prints JSON: vkHex, proofHex (raw compressed bytes, hex), the six
//!     decimal public inputs in circuit order, and the nullifier — ready to
//!     hand to `main.mo`'s real `verify(challengeId, proofBytes: Blob,
//!     publicInputs: [Nat])`, which (per `TitleGroth16.mo`) takes public
//!     inputs as plain decimal Nats, NOT the hex-encoded wire format
//!     `Groth16Wire`'s `tryVerify` uses.

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ff::PrimeField;
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

fn dec(f: &Fr) -> String {
    f.into_bigint().to_string()
}

// Fr implements From<u64> but not From<&str>; decimal strings (arbitrary
// size, e.g. a 77-digit BLS12-381 Fr value) are folded digit-by-digit
// in-field instead of pulling in num-bigint as an extra dependency.
fn fr_from_dec_str(s: &str) -> Fr {
    let mut acc = Fr::from(0u64);
    let ten = Fr::from(10u64);
    for c in s.trim().chars() {
        let d = c.to_digit(10).expect("non-digit in decimal Fr string") as u64;
        acc = acc * ten + Fr::from(d);
    }
    acc
}

fn poseidon(cfg: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr>, domain: u64, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(cfg);
    sponge.absorb(&Fr::from(domain));
    for i in inputs {
        sponge.absorb(i);
    }
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

// Fixed test identities: known privately by the "owner" (us, for this
// test), never sent to the canister. Chosen arbitrarily; only their
// consistency across `commitment` and `prove` calls matters. A second
// identity is used for the upgrade-round-trip test, so the second record
// is a genuinely distinct leaf inserted at tree index 1.
fn owner_secret() -> Fr { Fr::from(555666u64) }
fn property_id() -> Fr { Fr::from(777888u64) }
fn owner_secret2() -> Fr { Fr::from(222333u64) }
fn property_id2() -> Fr { Fr::from(444555u64) }
fn encumbrance_flag() -> Fr { Fr::from(0u64) }
fn license_status() -> Fr { Fr::from(1u64) }
fn license_expiry() -> Fr { Fr::from(4_000_000_000u64) } // must exceed current_timestamp
fn registry_id() -> Fr { Fr::from(1u64) } // matches main.mo's hardcoded `registryId : Nat = 1`

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cfg = poseidon_config();

    match args.get(1).map(|s| s.as_str()) {
        Some("commitment") => {
            let owner_commitment = poseidon(&cfg, DOMAIN_OWNER_COMMITMENT, &[owner_secret(), property_id()]);
            let leaf = poseidon(
                &cfg,
                DOMAIN_LEAF,
                &[registry_id(), owner_commitment, encumbrance_flag(), license_status(), license_expiry()],
            );
            println!("{{");
            println!("  \"ownerCommitment\": \"{}\",", dec(&owner_commitment));
            println!("  \"encumbranceFlag\": \"{}\",", dec(&encumbrance_flag()));
            println!("  \"licenseStatus\": \"{}\",", dec(&license_status()));
            println!("  \"licenseExpiry\": \"{}\",", dec(&license_expiry()));
            println!("  \"expectedLeaf\": \"{}\"", dec(&leaf));
            println!("}}");
        }
        Some("prove") => {
            let merkle_root_arg = args.get(2).expect("usage: prove_live prove <merkle_root> <purpose> <request_nonce> <current_timestamp>");
            let purpose_arg = args.get(3).expect("missing purpose");
            let request_nonce_arg = args.get(4).expect("missing request_nonce");
            let current_timestamp_arg = args.get(5).expect("missing current_timestamp");

            let merkle_root_live = fr_from_dec_str(merkle_root_arg);
            let purpose = fr_from_dec_str(purpose_arg);
            let request_nonce = fr_from_dec_str(request_nonce_arg);
            let current_timestamp = fr_from_dec_str(current_timestamp_arg);

            let owner_commitment = poseidon(&cfg, DOMAIN_OWNER_COMMITMENT, &[owner_secret(), property_id()]);
            let leaf = poseidon(
                &cfg,
                DOMAIN_LEAF,
                &[registry_id(), owner_commitment, encumbrance_flag(), license_status(), license_expiry()],
            );

            // Independently recompute the zero-hash chain and the resulting
            // root for a leaf inserted at index 0 of an otherwise-empty
            // tree — same construction as main.mo's computeZeroHashes +
            // insertLeaf. This is a cross-check, not a substitute for the
            // canister's own value: we PROVE against merkle_root_live (what
            // the canister actually reports), but if our independent
            // computation disagrees, that's a real bug worth failing loudly
            // on rather than silently proving something unverifiable.
            let mut zero = Fr::from(0u64);
            let mut merkle_path = Vec::with_capacity(TREE_DEPTH);
            for _ in 0..TREE_DEPTH {
                merkle_path.push(zero);
                zero = poseidon(&cfg, DOMAIN_NODE, &[zero, zero]);
            }
            let mut computed_root = leaf;
            for sib in &merkle_path {
                computed_root = poseidon(&cfg, DOMAIN_NODE, &[computed_root, *sib]); // index 0 always "left"
            }

            if computed_root != merkle_root_live {
                eprintln!("MISMATCH: independently computed root does not match the live canister's merkle_root.");
                eprintln!("  computed_root = {}", dec(&computed_root));
                eprintln!("  merkle_root (live, from canister) = {}", dec(&merkle_root_live));
                eprintln!("This likely means this wasn't the first record inserted (index != 0), or the");
                eprintln!("owner_secret/property_id/license fields don't match what was actually submitted.");
                std::process::exit(1);
            }
            eprintln!("Root cross-check OK: independently computed root matches the live canister's merkle_root.");

            let nullifier = poseidon(&cfg, DOMAIN_NULLIFIER, &[owner_secret(), property_id(), purpose, request_nonce]);

            let circuit = TitleVerificationCircuit {
                registry_id: Some(registry_id()),
                merkle_root: Some(merkle_root_live),
                purpose: Some(purpose),
                request_nonce: Some(request_nonce),
                current_timestamp: Some(current_timestamp),
                nullifier: Some(nullifier),
                owner_secret: Some(owner_secret()),
                property_id: Some(property_id()),
                encumbrance_flag: Some(encumbrance_flag()),
                license_status: Some(license_status()),
                license_expiry: Some(license_expiry()),
                merkle_path: merkle_path.iter().map(|x| Some(*x)).collect(),
                merkle_path_bits: vec![Some(false); TREE_DEPTH],
            };

            let pk_bytes = std::fs::read("proving_key.bin").expect("run `setup` first");
            let pk = ark_groth16::ProvingKey::<Bls12_381>::deserialize_compressed(&*pk_bytes).unwrap();
            let vk_bytes = std::fs::read("verifying_key.bin").expect("run `setup` first");

            let mut rng = ChaCha20Rng::from_entropy();
            let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).expect("proving failed");
            let mut proof_bytes = Vec::new();
            proof.serialize_compressed(&mut proof_bytes).unwrap();

            let public_inputs = vec![registry_id(), merkle_root_live, purpose, request_nonce, current_timestamp, nullifier];

            let out = format!(
                "{{\n  \"vkHex\": \"{}\",\n  \"proofHex\": \"{}\",\n  \"publicInputsDecimal\": [{}],\n  \"nullifierDecimal\": \"{}\"\n}}\n",
                hex(&vk_bytes),
                hex(&proof_bytes),
                public_inputs.iter().map(|f| format!("\"{}\"", dec(f))).collect::<Vec<_>>().join(", "),
                dec(&nullifier),
            );
            std::fs::write("prove_live_output.json", &out).unwrap();
            println!("{}", out);
        }
        Some("commitment2") => {
            let owner_commitment = poseidon(&cfg, DOMAIN_OWNER_COMMITMENT, &[owner_secret2(), property_id2()]);
            let leaf = poseidon(
                &cfg,
                DOMAIN_LEAF,
                &[registry_id(), owner_commitment, encumbrance_flag(), license_status(), license_expiry()],
            );
            println!("{{");
            println!("  \"ownerCommitment\": \"{}\",", dec(&owner_commitment));
            println!("  \"expectedLeaf\": \"{}\"", dec(&leaf));
            println!("}}");
        }
        Some("predict-root-after-second-insert") => {
            let leaf0_arg = args.get(2).expect("usage: prove_live predict-root-after-second-insert <leaf0> <leaf1>");
            let leaf1_arg = args.get(3).expect("missing leaf1");
            let leaf0 = fr_from_dec_str(leaf0_arg);
            let leaf1 = fr_from_dec_str(leaf1_arg);
            let mut cur = poseidon(&cfg, DOMAIN_NODE, &[leaf0, leaf1]);
            let mut zero = Fr::from(0u64);
            for _ in 0..(TREE_DEPTH - 1) {
                zero = poseidon(&cfg, DOMAIN_NODE, &[zero, zero]);
                cur = poseidon(&cfg, DOMAIN_NODE, &[cur, zero]);
            }
            println!("{{\n  \"predictedRootAfterSecondInsert\": \"{}\"\n}}", dec(&cur));
        }
        Some("nullifier2") => {
            let purpose_arg = args.get(2).expect("usage: prove_live nullifier2 <purpose> <request_nonce>");
            let nonce_arg = args.get(3).expect("missing request_nonce");
            let purpose = fr_from_dec_str(purpose_arg);
            let request_nonce = fr_from_dec_str(nonce_arg);
            let nullifier = poseidon(&cfg, DOMAIN_NULLIFIER, &[owner_secret2(), property_id2(), purpose, request_nonce]);
            println!("{{\n  \"nullifierDecimal\": \"{}\"\n}}", dec(&nullifier));
        }
        Some("prove2") => {
            // Proves inclusion of the SECOND identity's record, which sits
            // at tree index 1 — i.e. its Merkle path has a real, non-zero
            // sibling at level 0 (leaf0), not an all-zero path like index
            // 0's. This is the gap flagged at the end of the last session:
            // `prove` only ever handled the index-0 case.
            let merkle_root_arg = args.get(2).expect("usage: prove_live prove2 <merkle_root> <purpose> <request_nonce> <current_timestamp>");
            let purpose_arg = args.get(3).expect("missing purpose");
            let request_nonce_arg = args.get(4).expect("missing request_nonce");
            let current_timestamp_arg = args.get(5).expect("missing current_timestamp");

            let merkle_root_live = fr_from_dec_str(merkle_root_arg);
            let purpose = fr_from_dec_str(purpose_arg);
            let request_nonce = fr_from_dec_str(request_nonce_arg);
            let current_timestamp = fr_from_dec_str(current_timestamp_arg);

            // leaf0 (first identity, tree index 0) — needed as the real
            // sibling for leaf1's inclusion proof at level 0.
            let owner_commitment0 = poseidon(&cfg, DOMAIN_OWNER_COMMITMENT, &[owner_secret(), property_id()]);
            let leaf0 = poseidon(
                &cfg,
                DOMAIN_LEAF,
                &[registry_id(), owner_commitment0, encumbrance_flag(), license_status(), license_expiry()],
            );

            // leaf1 (second identity, tree index 1) — the leaf we're
            // actually proving inclusion of here.
            let owner_commitment1 = poseidon(&cfg, DOMAIN_OWNER_COMMITMENT, &[owner_secret2(), property_id2()]);
            let leaf1 = poseidon(
                &cfg,
                DOMAIN_LEAF,
                &[registry_id(), owner_commitment1, encumbrance_flag(), license_status(), license_expiry()],
            );

            // Merkle path for index 1: level 0's sibling is the REAL leaf0
            // value (not a zero-hash), and this leaf is the RIGHT child
            // (is_right = true) at level 0. Every level after that, index
            // becomes 0 and stays 0 (1 >> 1 == 0), so from level 1 onward
            // it's the same zero-hash-chain / "always left" pattern as the
            // index-0 case.
            let mut merkle_path = Vec::with_capacity(TREE_DEPTH);
            let mut merkle_path_bits = Vec::with_capacity(TREE_DEPTH);
            merkle_path.push(leaf0);
            merkle_path_bits.push(true);
            let mut zero = Fr::from(0u64);
            for _ in 0..(TREE_DEPTH - 1) {
                // Advance to the NEXT zero-hash level BEFORE pushing: level 1's
                // sibling is zeroHashes[1] = poseidon(node, [0,0]), not the raw
                // 0 that seeds the chain (that's zeroHashes[0], only correct
                // as a level-0 sibling, which this leaf doesn't need since its
                // level-0 sibling is the real leaf0 above). Getting this
                // order backwards was a real bug caught by this exact
                // end-to-end test: the root cross-check below still passed
                // (it independently used the correct post-update chain), but
                // the circuit's witness — built from this array — would have
                // silently used the wrong sibling for every level past 0,
                // producing a proof that fails verification (E_PAIRING_FAIL)
                // even though the public root matched.
                zero = poseidon(&cfg, DOMAIN_NODE, &[zero, zero]);
                merkle_path.push(zero);
                merkle_path_bits.push(false);
            }

            // Independent root cross-check, same discipline as `prove`:
            // fail loudly before proving if this doesn't match what the
            // canister actually reports.
            let mut computed_root = poseidon(&cfg, DOMAIN_NODE, &[leaf0, leaf1]); // level 0: (left=leaf0, right=leaf1)
            let mut zero2 = Fr::from(0u64);
            for _ in 0..(TREE_DEPTH - 1) {
                zero2 = poseidon(&cfg, DOMAIN_NODE, &[zero2, zero2]);
                computed_root = poseidon(&cfg, DOMAIN_NODE, &[computed_root, zero2]);
            }
            if computed_root != merkle_root_live {
                eprintln!("MISMATCH: independently computed root (leaf0+leaf1) does not match the live canister's merkle_root.");
                eprintln!("  computed_root = {}", dec(&computed_root));
                eprintln!("  merkle_root (live, from canister) = {}", dec(&merkle_root_live));
                eprintln!("This likely means the tree doesn't have exactly these two leaves at indices 0 and 1.");
                std::process::exit(1);
            }
            eprintln!("Root cross-check OK (two-leaf tree): independently computed root matches the live canister's merkle_root.");

            let nullifier = poseidon(&cfg, DOMAIN_NULLIFIER, &[owner_secret2(), property_id2(), purpose, request_nonce]);

            let circuit = TitleVerificationCircuit {
                registry_id: Some(registry_id()),
                merkle_root: Some(merkle_root_live),
                purpose: Some(purpose),
                request_nonce: Some(request_nonce),
                current_timestamp: Some(current_timestamp),
                nullifier: Some(nullifier),
                owner_secret: Some(owner_secret2()),
                property_id: Some(property_id2()),
                encumbrance_flag: Some(encumbrance_flag()),
                license_status: Some(license_status()),
                license_expiry: Some(license_expiry()),
                merkle_path: merkle_path.iter().map(|x| Some(*x)).collect(),
                merkle_path_bits: merkle_path_bits.iter().map(|b| Some(*b)).collect(),
            };

            let pk_bytes = std::fs::read("proving_key.bin").expect("run `setup` first");
            let pk = ark_groth16::ProvingKey::<Bls12_381>::deserialize_compressed(&*pk_bytes).unwrap();
            let vk_bytes = std::fs::read("verifying_key.bin").expect("run `setup` first");

            let mut rng = ChaCha20Rng::from_entropy();
            let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).expect("proving failed");
            let mut proof_bytes = Vec::new();
            proof.serialize_compressed(&mut proof_bytes).unwrap();

            let public_inputs = vec![registry_id(), merkle_root_live, purpose, request_nonce, current_timestamp, nullifier];

            let out = format!(
                "{{\n  \"vkHex\": \"{}\",\n  \"proofHex\": \"{}\",\n  \"publicInputsDecimal\": [{}],\n  \"nullifierDecimal\": \"{}\"\n}}\n",
                hex(&vk_bytes),
                hex(&proof_bytes),
                public_inputs.iter().map(|f| format!("\"{}\"", dec(f))).collect::<Vec<_>>().join(", "),
                dec(&nullifier),
            );
            std::fs::write("prove_live2_output.json", &out).unwrap();
            println!("{}", out);
        }
        _ => {
            eprintln!("usage:");
            eprintln!("  prove_live commitment");
            eprintln!("  prove_live commitment2");
            eprintln!("  prove_live prove <merkle_root> <purpose> <request_nonce> <current_timestamp>");
            eprintln!("  prove_live prove2 <merkle_root> <purpose> <request_nonce> <current_timestamp>");
            eprintln!("  prove_live predict-root-after-second-insert <leaf0> <leaf1>");
            eprintln!("  prove_live nullifier2 <purpose> <request_nonce>");
            std::process::exit(2);
        }
    }
}
