//! General-purpose successor to `prove_live.rs`: instead of only handling
//! leaf index 0 or a hardcoded second identity at index 1, this tool
//! maintains a local Merkle-tree simulation that exactly mirrors
//! `main.mo`'s `insertLeaf`/`nodeAt`/`computeZeroHashes`, for an arbitrary
//! number of sequentially-submitted records — so it can build a correct
//! witness (real path, real left/right bits) for ANY leaf index, not just
//! the two hand-derived cases the previous tool covered.
//!
//! It also adds a ground-truth oracle: before spending the time to run the
//! real Groth16 prover, it checks whether the witness satisfies the R1CS
//! constraint system directly (`ConstraintSystem::is_satisfied()`). This
//! gives an independent prediction of ACCEPT/REJECT that the real on-chain
//! verification can be checked against — turning "the pairing check failed"
//! from a mystery into an expected, cross-checked outcome, especially for
//! the deliberately-dirty test identities below (liened, invalid license,
//! expired license), which exist specifically to confirm the circuit's
//! core security properties reject bad witnesses, not just malformed ones.
//!
//! Subcommands:
//!   prove_live2 commitment <identity_index>
//!     Prints ownerCommitment/leaf for the given identity (see IDENTITIES
//!     below). Feed ownerCommitment into submitRecord, in identity-index
//!     order, to build up the on-chain tree this tool's local simulation
//!     tracks.
//!
//!   prove_live2 tree-root <n_submitted>
//!     Predicts the tree root after identities 0..n_submitted-1 have been
//!     submitted in order, purely from local simulation — no reliance on
//!     canister state. Useful to cross-check against a live submitRecord
//!     result before proving anything.
//!
//!   prove_live2 prove <leaf_index> <n_submitted> <merkle_root> <purpose> <request_nonce> <current_timestamp>
//!     Builds the real witness for identities[leaf_index], assuming
//!     identities 0..n_submitted-1 were submitted in order (leaf_index must
//!     be < n_submitted). Cross-checks the local tree-root prediction
//!     against merkle_root (the live value from requestChallenge) before
//!     doing anything else. Runs the constraint-satisfaction oracle, then
//!     always still generates a real proof regardless of the oracle's
//!     verdict (so the real verifier's answer can be compared against it).
//!     Prints JSON including `predictedSatisfied`.

use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
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

fn registry_id() -> Fr { Fr::from(1u64) } // matches main.mo's hardcoded `registryId : Nat = 1`

#[derive(Clone, Copy)]
struct Identity {
    label: &'static str,
    secret: u64,
    property: u64,
    encumbrance_flag: u64,
    license_status: u64,
    license_expiry: u64,
}

// Fixed catalog, known privately (never sent to the canister as anything
// but their derived ownerCommitment). Indices 0-1 match the previous
// tool's hardcoded identities exactly, so re-running the original
// two-leaf test sequence reproduces byte-identical roots/commitments.
// Indices 2-3 extend the tree further (genuinely different, deeper
// Merkle-path shapes). Indices 4-6 are deliberately DIRTY — a real lien,
// an invalid license status, and an expired license — included to test
// that the circuit actually refuses to produce a satisfying witness for
// exactly the cases the statement claims to reject.
const IDENTITIES: &[Identity] = &[
    Identity { label: "clean-0", secret: 555666, property: 777888, encumbrance_flag: 0, license_status: 1, license_expiry: 4_000_000_000 },
    Identity { label: "clean-1", secret: 222333, property: 444555, encumbrance_flag: 0, license_status: 1, license_expiry: 4_000_000_000 },
    Identity { label: "clean-2", secret: 111222, property: 333444, encumbrance_flag: 0, license_status: 1, license_expiry: 4_000_000_000 },
    Identity { label: "clean-3", secret: 999888, property: 777666, encumbrance_flag: 0, license_status: 1, license_expiry: 4_000_000_000 },
    Identity { label: "DIRTY-lien", secret: 444777, property: 888222, encumbrance_flag: 1, license_status: 1, license_expiry: 4_000_000_000 },
    Identity { label: "DIRTY-invalid-license", secret: 333999, property: 666111, encumbrance_flag: 0, license_status: 0, license_expiry: 4_000_000_000 },
    Identity { label: "DIRTY-expired-license", secret: 888555, property: 222999, encumbrance_flag: 0, license_status: 1, license_expiry: 1_000_000_000 },
];

fn identity(i: usize) -> Identity {
    *IDENTITIES.get(i).unwrap_or_else(|| panic!("no identity at index {i}; catalog has {} entries", IDENTITIES.len()))
}

fn leaf_of(cfg: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr>, id: Identity) -> Fr {
    let owner_commitment = poseidon(cfg, DOMAIN_OWNER_COMMITMENT, &[Fr::from(id.secret), Fr::from(id.property)]);
    poseidon(
        cfg,
        DOMAIN_LEAF,
        &[
            registry_id(),
            owner_commitment,
            Fr::from(id.encumbrance_flag),
            Fr::from(id.license_status),
            Fr::from(id.license_expiry),
        ],
    )
}

/// Local simulation of main.mo's sparse-Merkle-tree state, exact mirror of
/// `nodeAt`/`insertLeaf`/`computeZeroHashes`. `nodes[(level, index)]` mimics
/// the `nodes` HashMap; missing entries fall back to `zero_hashes[level]`,
/// exactly like `nodeAt`'s `case null zeroHashes[level]`.
struct TreeSim {
    zero_hashes: Vec<Fr>, // zero_hashes[level], level 0..=TREE_DEPTH
    nodes: std::collections::HashMap<(usize, u128), Fr>,
    current_root: Fr,
}

impl TreeSim {
    fn new(cfg: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr>) -> Self {
        let mut zero_hashes = vec![Fr::from(0u64)];
        for _ in 0..TREE_DEPTH {
            let prev = *zero_hashes.last().unwrap();
            zero_hashes.push(poseidon(cfg, DOMAIN_NODE, &[prev, prev]));
        }
        let current_root = zero_hashes[TREE_DEPTH];
        Self { zero_hashes, nodes: std::collections::HashMap::new(), current_root }
    }

    fn node_at(&self, level: usize, index: u128) -> Fr {
        *self.nodes.get(&(level, index)).unwrap_or(&self.zero_hashes[level])
    }

    /// Exact port of main.mo's insertLeaf. Also records, for the given
    /// `index`, the sibling/bit sequence used along the way, so callers
    /// proving inclusion of that same leaf later can reuse it directly
    /// instead of re-deriving it from the tree structure a second time.
    fn insert_leaf(&mut self, cfg: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr>, index: u128, leaf: Fr) {
        self.nodes.insert((0, index), leaf);
        let mut idx = index;
        let mut level = 0usize;
        let mut cur = leaf;
        while level < TREE_DEPTH {
            let pair_base = (idx / 2) * 2;
            let sibling_index = if idx == pair_base { pair_base + 1 } else { pair_base };
            let sibling = self.node_at(level, sibling_index);
            let (l, r) = if idx % 2 == 0 { (cur, sibling) } else { (sibling, cur) };
            cur = poseidon(cfg, DOMAIN_NODE, &[l, r]);
            idx /= 2;
            level += 1;
            self.nodes.insert((level, idx), cur);
        }
        self.current_root = cur;
    }

    /// Merkle path (siblings) and left/right bits for `index`, read back
    /// from the tree structure AFTER all relevant leaves have been
    /// inserted — i.e. this reconstructs what a prover would fetch from
    /// the canister's own tree, not just what insert_leaf saw at the time
    /// that particular leaf went in (which matters once later insertions
    /// change what index's siblings resolve to).
    fn path_for(&self, index: u128) -> (Vec<Fr>, Vec<bool>) {
        let mut path = Vec::with_capacity(TREE_DEPTH);
        let mut bits = Vec::with_capacity(TREE_DEPTH);
        let mut idx = index;
        for level in 0..TREE_DEPTH {
            let pair_base = (idx / 2) * 2;
            let sibling_index = if idx == pair_base { pair_base + 1 } else { pair_base };
            path.push(self.node_at(level, sibling_index));
            bits.push(idx % 2 == 1); // is_right
            idx /= 2;
        }
        (path, bits)
    }
}

fn build_tree(cfg: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr>, n_submitted: usize) -> TreeSim {
    let mut tree = TreeSim::new(cfg);
    for i in 0..n_submitted {
        let leaf = leaf_of(cfg, identity(i));
        tree.insert_leaf(cfg, i as u128, leaf);
    }
    tree
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cfg = poseidon_config();

    match args.get(1).map(|s| s.as_str()) {
        Some("commitment") => {
            let idx: usize = args.get(2).expect("usage: prove_live2 commitment <identity_index>").parse().expect("identity_index must be a number");
            let id = identity(idx);
            let owner_commitment = poseidon(&cfg, DOMAIN_OWNER_COMMITMENT, &[Fr::from(id.secret), Fr::from(id.property)]);
            let leaf = leaf_of(&cfg, id);
            println!("{{");
            println!("  \"label\": \"{}\",", id.label);
            println!("  \"ownerCommitment\": \"{}\",", dec(&owner_commitment));
            println!("  \"encumbranceFlag\": \"{}\",", id.encumbrance_flag);
            println!("  \"licenseStatus\": \"{}\",", id.license_status);
            println!("  \"licenseExpiry\": \"{}\",", id.license_expiry);
            println!("  \"expectedLeaf\": \"{}\"", dec(&leaf));
            println!("}}");
        }
        Some("tree-root") => {
            let n: usize = args.get(2).expect("usage: prove_live2 tree-root <n_submitted>").parse().expect("n_submitted must be a number");
            let tree = build_tree(&cfg, n);
            println!("{{\n  \"predictedRoot\": \"{}\"\n}}", dec(&tree.current_root));
        }
        Some("prove") => {
            let leaf_index: usize = args.get(2).expect("usage: prove_live2 prove <leaf_index> <n_submitted> <merkle_root> <purpose> <request_nonce> <current_timestamp>").parse().expect("leaf_index must be a number");
            let n_submitted: usize = args.get(3).expect("missing n_submitted").parse().expect("n_submitted must be a number");
            let merkle_root_arg = args.get(4).expect("missing merkle_root");
            let purpose_arg = args.get(5).expect("missing purpose");
            let request_nonce_arg = args.get(6).expect("missing request_nonce");
            let current_timestamp_arg = args.get(7).expect("missing current_timestamp");

            assert!(leaf_index < n_submitted, "leaf_index must be < n_submitted");

            let merkle_root_live = fr_from_dec_str(merkle_root_arg);
            let purpose = fr_from_dec_str(purpose_arg);
            let request_nonce = fr_from_dec_str(request_nonce_arg);
            let current_timestamp = fr_from_dec_str(current_timestamp_arg);

            let id = identity(leaf_index);
            let tree = build_tree(&cfg, n_submitted);
            let (merkle_path, merkle_path_bits) = tree.path_for(leaf_index as u128);

            if tree.current_root != merkle_root_live {
                eprintln!("MISMATCH: locally-simulated root does not match the live canister's merkle_root.");
                eprintln!("  simulated_root = {}", dec(&tree.current_root));
                eprintln!("  merkle_root (live, from canister) = {}", dec(&merkle_root_live));
                eprintln!("This likely means n_submitted doesn't match how many records were actually");
                eprintln!("submitted on-chain, or they weren't submitted in identity-index order.");
                std::process::exit(1);
            }
            eprintln!("Root cross-check OK ({} leaves): locally-simulated root matches the live canister's merkle_root.", n_submitted);

            let nullifier = poseidon(&cfg, DOMAIN_NULLIFIER, &[Fr::from(id.secret), Fr::from(id.property), purpose, request_nonce]);

            let circuit = TitleVerificationCircuit {
                registry_id: Some(registry_id()),
                merkle_root: Some(merkle_root_live),
                purpose: Some(purpose),
                request_nonce: Some(request_nonce),
                current_timestamp: Some(current_timestamp),
                nullifier: Some(nullifier),
                owner_secret: Some(Fr::from(id.secret)),
                property_id: Some(Fr::from(id.property)),
                encumbrance_flag: Some(Fr::from(id.encumbrance_flag)),
                license_status: Some(Fr::from(id.license_status)),
                license_expiry: Some(Fr::from(id.license_expiry)),
                merkle_path: merkle_path.iter().map(|x| Some(*x)).collect(),
                merkle_path_bits: merkle_path_bits.iter().map(|b| Some(*b)).collect(),
            };

            // Ground-truth oracle: does this witness actually satisfy the
            // R1CS constraints? Run BEFORE proving, on a fresh constraint
            // system, independent of the Groth16 proving/verifying keys.
            let cs = ConstraintSystem::<Fr>::new_ref();
            circuit.clone().generate_constraints(cs.clone()).expect("constraint synthesis itself failed (not a satisfaction issue)");
            let predicted_satisfied = cs.is_satisfied().expect("is_satisfied() check itself failed");

            let pk_bytes = std::fs::read("proving_key.bin").expect("run `setup` first");
            let pk = ark_groth16::ProvingKey::<Bls12_381>::deserialize_compressed(&*pk_bytes).unwrap();
            let vk_bytes = std::fs::read("verifying_key.bin").expect("run `setup` first");

            let mut rng = ChaCha20Rng::from_entropy();
            let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).expect("proving failed");
            let mut proof_bytes = Vec::new();
            proof.serialize_compressed(&mut proof_bytes).unwrap();

            let public_inputs = vec![registry_id(), merkle_root_live, purpose, request_nonce, current_timestamp, nullifier];

            let out = format!(
                "{{\n  \"identityLabel\": \"{}\",\n  \"predictedSatisfied\": {},\n  \"vkHex\": \"{}\",\n  \"proofHex\": \"{}\",\n  \"publicInputsDecimal\": [{}],\n  \"nullifierDecimal\": \"{}\"\n}}\n",
                id.label,
                predicted_satisfied,
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
            eprintln!("  prove_live2 commitment <identity_index>");
            eprintln!("  prove_live2 tree-root <n_submitted>");
            eprintln!("  prove_live2 prove <leaf_index> <n_submitted> <merkle_root> <purpose> <request_nonce> <current_timestamp>");
            std::process::exit(2);
        }
    }
}
