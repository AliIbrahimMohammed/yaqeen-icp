//! title_verification: the ZK statement Yaqeen originally expressed in Noir,
//! re-expressed as an arkworks R1CS circuit for Groth16 over BLS12-381.
//!
//! Statement (unchanged from the Noir version):
//!   - the prover knows `owner_secret` such that a leaf built from
//!     (registry_id, owner_commitment, encumbrance_flag, license_status,
//!     license_expiry) sits in the registry's sparse Merkle tree at `merkle_root`
//!   - encumbrance_flag == 0            (no liens / disputes / court holds)
//!   - license_status == 1              (license currently valid)
//!   - license_expiry > current_timestamp
//!   - nullifier is correctly derived from (owner_secret, property_id, purpose,
//!     request_nonce) so the same title can't be replayed against the same
//!     challenge, while still being provable again under a fresh nonce.
//!
//! Domain separation constants mirror Yaqeen's hardening history: every
//! Poseidon call is tagged so a value computed for one role (leaf, owner
//! commitment, nullifier, tree node) can never be silently reinterpreted as
//! another.

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::FieldVar,
    ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

pub const TREE_DEPTH: usize = 25;

// Domain tags — arbitrary distinct field elements, one per hash role.
// (In production these should be fixed once and never reused; see
// docs/DOMAIN-TAGS.md for the registry.)
pub const DOMAIN_LEAF: u64 = 1;
pub const DOMAIN_OWNER_COMMITMENT: u64 = 2;
pub const DOMAIN_NULLIFIER: u64 = 3;
pub const DOMAIN_NODE: u64 = 4;

/// Poseidon config shared by circuit and the Motoko-side hasher. Both sides
/// must use byte-identical round constants / MDS matrix — see
/// `scripts/export_poseidon_params.rs`, which dumps this config as a JSON
/// fixture the Motoko implementation is generated from and tested against.
pub fn poseidon_config() -> PoseidonConfig<Fr> {
    // NOTE: placeholder parameter generation for scaffolding purposes only.
    // Production must use parameters generated (and reviewed) via the
    // standard Poseidon parameter script for BLS12-381's scalar field,
    // exactly as Yaqeen's `hasher/` package pinned specific constants for
    // its Noir/BN254 setup. Do not deploy with ad hoc constants.
    let full_rounds: usize = 8;
    let partial_rounds: usize = 57;
    let rate: usize = 2; // state width T = rate + capacity = 3
    let capacity: usize = 1;
    let alpha: u64 = 5;
    let (ark, mds) = ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds::<Fr>(
        255,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );
    PoseidonConfig {
        full_rounds,
        partial_rounds,
        alpha,
        ark,
        mds,
        rate,
        capacity,
    }
}

#[derive(Clone)]
pub struct TitleVerificationCircuit {
    // ---- public inputs (must match the challenge the backend/canister issued) ----
    pub registry_id: Option<Fr>,
    pub merkle_root: Option<Fr>,
    pub purpose: Option<Fr>,
    pub request_nonce: Option<Fr>,
    pub current_timestamp: Option<Fr>,
    pub nullifier: Option<Fr>,

    // ---- private witness ----
    pub owner_secret: Option<Fr>,
    pub property_id: Option<Fr>,
    pub encumbrance_flag: Option<Fr>, // must be 0
    pub license_status: Option<Fr>,   // must be 1
    pub license_expiry: Option<Fr>,   // must be > current_timestamp
    pub merkle_path: Vec<Option<Fr>>, // TREE_DEPTH sibling hashes
    pub merkle_path_bits: Vec<Option<bool>>, // TREE_DEPTH left/right bits
}

impl TitleVerificationCircuit {
    pub fn empty() -> Self {
        Self {
            registry_id: None,
            merkle_root: None,
            purpose: None,
            request_nonce: None,
            current_timestamp: None,
            nullifier: None,
            owner_secret: None,
            property_id: None,
            encumbrance_flag: None,
            license_status: None,
            license_expiry: None,
            merkle_path: vec![None; TREE_DEPTH],
            merkle_path_bits: vec![None; TREE_DEPTH],
        }
    }
}

fn poseidon_hash(
    cs: ConstraintSystemRef<Fr>,
    config: &PoseidonConfig<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, config);
    sponge.absorb(&inputs)?;
    let out = sponge.squeeze_field_elements(1)?;
    Ok(out[0].clone())
}

impl ConstraintSynthesizer<Fr> for TitleVerificationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let config = poseidon_config();

        // ---- allocate public inputs ----
        let registry_id = FpVar::new_input(cs.clone(), || {
            self.registry_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let merkle_root = FpVar::new_input(cs.clone(), || {
            self.merkle_root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let purpose = FpVar::new_input(cs.clone(), || {
            self.purpose.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let request_nonce = FpVar::new_input(cs.clone(), || {
            self.request_nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let current_timestamp = FpVar::new_input(cs.clone(), || {
            self.current_timestamp
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier_public = FpVar::new_input(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ---- allocate private witness ----
        let owner_secret = FpVar::new_witness(cs.clone(), || {
            self.owner_secret.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let property_id = FpVar::new_witness(cs.clone(), || {
            self.property_id.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let encumbrance_flag = FpVar::new_witness(cs.clone(), || {
            self.encumbrance_flag
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let license_status = FpVar::new_witness(cs.clone(), || {
            self.license_status
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let license_expiry = FpVar::new_witness(cs.clone(), || {
            self.license_expiry
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let domain_leaf = FpVar::constant(Fr::from(DOMAIN_LEAF));
        let domain_owner = FpVar::constant(Fr::from(DOMAIN_OWNER_COMMITMENT));
        let domain_nullifier = FpVar::constant(Fr::from(DOMAIN_NULLIFIER));
        let domain_node = FpVar::constant(Fr::from(DOMAIN_NODE));
        let zero = FpVar::constant(Fr::from(0u64));
        let one = FpVar::constant(Fr::from(1u64));

        // ---- 1. no liens / disputes / court holds ----
        encumbrance_flag.enforce_equal(&zero)?;

        // ---- 2. license currently valid ----
        license_status.enforce_equal(&one)?;

        // ---- 3. license not expired ----
        // Range-checked comparison (closes the Field->u64 truncation class of
        // bug the Noir hardening pass fixed). Both values are constrained to
        // fit in 64 bits before comparing, then compared as field elements.
        let expiry_bits = license_expiry.to_bits_le()?;
        let ts_bits = current_timestamp.to_bits_le()?;
        enforce_fits_in_bits(&expiry_bits, 64)?;
        enforce_fits_in_bits(&ts_bits, 64)?;
        enforce_greater_than(&license_expiry, &current_timestamp, 64)?;

        // ---- 4. owner commitment, domain-separated ----
        let owner_commitment = poseidon_hash(
            cs.clone(),
            &config,
            &[domain_owner, owner_secret.clone(), property_id.clone()],
        )?;

        // ---- 5. leaf, domain- and registry-bound ----
        let leaf = poseidon_hash(
            cs.clone(),
            &config,
            &[
                domain_leaf,
                registry_id.clone(),
                owner_commitment,
                encumbrance_flag,
                license_status,
                license_expiry,
            ],
        )?;

        // ---- 6. Merkle inclusion, leaf -> merkle_root ----
        let mut current = leaf;
        for i in 0..TREE_DEPTH {
            let sibling = FpVar::new_witness(cs.clone(), || {
                self.merkle_path[i].ok_or(SynthesisError::AssignmentMissing)
            })?;
            let is_right = Boolean::new_witness(cs.clone(), || {
                self.merkle_path_bits[i].ok_or(SynthesisError::AssignmentMissing)
            })?;
            // left/right order depends on the bit; select without branching
            // so both witnesses cost the same regardless of the real path.
            let left = is_right.select(&sibling, &current)?;
            let right = is_right.select(&current, &sibling)?;
            current = poseidon_hash(cs.clone(), &config, &[domain_node.clone(), left, right])?;
        }
        current.enforce_equal(&merkle_root)?;

        // ---- 7. nullifier, purpose- and nonce-scoped ----
        let nullifier = poseidon_hash(
            cs.clone(),
            &config,
            &[
                domain_nullifier,
                owner_secret,
                property_id,
                purpose,
                request_nonce,
            ],
        )?;
        nullifier.enforce_equal(&nullifier_public)?;

        Ok(())
    }
}

fn enforce_fits_in_bits(bits: &[Boolean<Fr>], n: usize) -> Result<(), SynthesisError> {
    for b in &bits[n..] {
        b.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(())
}

/// Enforces `a > b` for values already range-checked to `n` bits, via the
/// standard trick: `a - b - 1` must not underflow, i.e. `(a - b - 1)` fits in
/// `n` bits when added to `2^n`.
fn enforce_greater_than(
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    n: usize,
) -> Result<(), SynthesisError> {
    let two_n = FpVar::constant(Fr::from(1u128 << n));
    let diff = &two_n + a - b - FpVar::constant(Fr::from(1u64));
    let diff_bits = diff.to_bits_le()?;
    // diff must fit in n+1 bits and its top bit (the 2^n term) must be 1,
    // i.e. no borrow occurred, i.e. a - b - 1 >= 0, i.e. a > b.
    diff_bits[n].enforce_equal(&Boolean::TRUE)?;
    enforce_fits_in_bits(&diff_bits, n + 1)?;
    Ok(())
}
