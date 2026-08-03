//! Verifies the INVERSION-FREE Jacobian reformulation of the fast subgroup checks that
//! will actually be implemented in CurveFlat.mo (which works in Jacobian coordinates
//! throughout and must avoid extra inversions). This goes further than
//! oracle_subgroup.rs (which used affine conversions for clarity): here every check is
//! done directly on Jacobian (X,Y,Z) triples, including on points deliberately
//! re-scaled to a RANDOM nonzero Z, to confirm the reformulated formulas are truly
//! representation-invariant (a bug here would silently accept/reject the wrong points).
//!
//! G1: endomorphism_jac(X,Y,Z) = (BETA*X, Y, Z)   [scaling only X is valid because
//!     BETA*(X/Z^2) = (BETA*X)/Z^2 - same Z, so it stays a valid rep of (BETA*x,y)]
//! G2: psi_jac(X,Y,Z) = (psi_x_coeff_asFp2 * conj(X), psi_y_coeff * conj(Y), conj(Z))
//!     [conj is a field automorphism: conj(X/Z^2) = conj(X)/conj(Z)^2, so conjugating all
//!     three coordinates together is representation-consistent]
//! Point equality on two Jacobian points with DIFFERENT Z is done via cross-multiplication
//! (the same U1==U2 && S1==S2 test point addition already uses to detect "same point"):
//!     X1*Z2^2 == X2*Z1^2  &&  Y1*Z2^3 == Y2*Z1^3

use ark_bls12_381::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{Field, UniformRand};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::Zero;
use std::str::FromStr;

const X_ABS: u64 = 0xd201000000010000;

fn beta() -> Fq {
    Fq::from_str(
        "793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350",
    )
    .unwrap()
}
fn psi_x_coeff() -> Fq {
    Fq::from_str(
        "4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437",
    )
    .unwrap()
}
fn psi_y_coeff() -> Fq2 {
    let c0 = Fq::from_str(
        "2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530",
    )
    .unwrap();
    let c1 = Fq::from_str(
        "1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257",
    )
    .unwrap();
    Fq2::new(c0, c1)
}

// ---- G1 Jacobian-triple helpers (raw, not using Projective's own +/dbl, so this is an
// independent check of the RAW coordinate formulas, not just re-testing arkworks' own code) ----
type G1Jac = (Fq, Fq, Fq); // (X, Y, Z)

fn g1_to_jac(p: G1Projective) -> G1Jac {
    (p.x, p.y, p.z)
}
fn g1_rescale(j: G1Jac, lambda: Fq) -> G1Jac {
    // (X,Y,Z) -> (X*lambda^2, Y*lambda^3, Z*lambda) — same affine point, different Z.
    let l2 = lambda * lambda;
    let l3 = l2 * lambda;
    (j.0 * l2, j.1 * l3, j.2 * lambda)
}
fn g1_endo_jac(j: G1Jac) -> G1Jac {
    (beta() * j.0, j.1, j.2)
}
fn g1_eq_jac(a: G1Jac, b: G1Jac) -> bool {
    let (x1, y1, z1) = a;
    let (x2, y2, z2) = b;
    if z1.is_zero() {
        return z2.is_zero();
    }
    if z2.is_zero() {
        return false;
    }
    let z1z1 = z1 * z1;
    let z2z2 = z2 * z2;
    let u1 = x1 * z2z2;
    let u2 = x2 * z1z1;
    if u1 != u2 {
        return false;
    }
    let s1 = y1 * z2 * z2z2;
    let s2 = y2 * z1 * z1z1;
    s1 == s2
}
fn g1_mul_jac(j: G1Jac, e: u64) -> G1Jac {
    // plain double-and-add on affine-derived projective, using arkworks' own group ops for
    // the SCALAR MULT part (that part isn't what we're checking — it's the endomorphism /
    // equality formulas that are new) — reconstruct a Projective from the raw triple first.
    let p = G1Projective::new_unchecked(j.0, j.1, j.2);
    let r = p * Fr::from(e);
    g1_to_jac(r)
}

fn g1_fast_check_jacobian(j: G1Jac) -> bool {
    if j.2.is_zero() {
        return true;
    }
    let x_p = g1_mul_jac(j, X_ABS);
    if g1_eq_jac(x_p, j) {
        return false;
    }
    let mut x2_p = g1_mul_jac(x_p, X_ABS);
    x2_p.1 = -x2_p.1; // negate Y => -[X^2]P
    let endo_p = g1_endo_jac(j);
    g1_eq_jac(x2_p, endo_p)
}

// ---- G2 Jacobian-triple helpers ----
type G2Jac = (Fq2, Fq2, Fq2);

fn g2_to_jac(p: G2Projective) -> G2Jac {
    (p.x, p.y, p.z)
}
fn g2_rescale(j: G2Jac, lambda: Fq2) -> G2Jac {
    let l2 = lambda * lambda;
    let l3 = l2 * lambda;
    (j.0 * l2, j.1 * l3, j.2 * lambda)
}
fn conj(f: Fq2) -> Fq2 {
    Fq2::new(f.c0, -f.c1)
}
fn psi_jac(j: G2Jac) -> G2Jac {
    let cx = Fq2::new(Fq::from(0u64), psi_x_coeff()); // pure-imaginary constant
    (cx * conj(j.0), psi_y_coeff() * conj(j.1), conj(j.2))
}
fn g2_eq_jac(a: G2Jac, b: G2Jac) -> bool {
    let (x1, y1, z1) = a;
    let (x2, y2, z2) = b;
    if z1.is_zero() {
        return z2.is_zero();
    }
    if z2.is_zero() {
        return false;
    }
    let z1z1 = z1 * z1;
    let z2z2 = z2 * z2;
    let u1 = x1 * z2z2;
    let u2 = x2 * z1z1;
    if u1 != u2 {
        return false;
    }
    let s1 = y1 * z2 * z2z2;
    let s2 = y2 * z1 * z1z1;
    s1 == s2
}
fn g2_mul_jac(j: G2Jac, e: u64) -> G2Jac {
    let p = G2Projective::new_unchecked(j.0, j.1, j.2);
    let r = p * Fr::from(e);
    g2_to_jac(r)
}
fn g2_fast_check_jacobian(j: G2Jac) -> bool {
    if j.2.is_zero() {
        return true;
    }
    let mut x_p = g2_mul_jac(j, X_ABS);
    x_p.1 = -x_p.1; // X_IS_NEGATIVE => negate
    let psi_p = psi_jac(j);
    g2_eq_jac(x_p, psi_p)
}

fn sample_on_curve_g1(rng: &mut StdRng) -> G1Affine {
    loop {
        let x = Fq::rand(rng);
        let greatest: bool = bool::rand(rng);
        if let Some(p) = G1Affine::get_point_from_x_unchecked(x, greatest) {
            return p;
        }
    }
}
fn sample_on_curve_g2(rng: &mut StdRng) -> G2Affine {
    loop {
        let x = Fq2::rand(rng);
        let greatest: bool = bool::rand(rng);
        if let Some(p) = G2Affine::get_point_from_x_unchecked(x, greatest) {
            return p;
        }
    }
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE_1234);
    let mut all_pass = true;
    let mut n = 0;

    println!("=== G1 Jacobian-consistent fast check (with random Z rescalings) ===");
    let mut cases: Vec<(G1Affine, bool)> = vec![(G1Affine::zero(), true), (G1Affine::generator(), true)];
    for _ in 0..15 {
        let r = Fr::rand(&mut rng);
        cases.push(((G1Projective::generator() * r).into_affine(), true));
    }
    for _ in 0..15 {
        cases.push((sample_on_curve_g1(&mut rng), false /* placeholder, recomputed below */));
    }
    for (p, _) in cases {
        let real = <ark_bls12_381::g1::Config as SWCurveConfig>::is_in_correct_subgroup_assuming_on_curve(&p);
        // test at the natural Z=1 representation
        let base_jac = g1_to_jac(Projective::from(p));
        let r1 = g1_fast_check_jacobian(base_jac);
        // test again after rescaling to a random nonzero Z (representation-invariance check)
        let lambda = loop {
            let l = Fq::rand(&mut rng);
            if !l.is_zero() {
                break l;
            }
        };
        let rescaled = if p.is_zero() { base_jac } else { g1_rescale(base_jac, lambda) };
        let r2 = g1_fast_check_jacobian(rescaled);
        n += 1;
        if real != r1 || real != r2 {
            all_pass = false;
            println!("MISMATCH at case {n}: arkworks={real} jac(Z=1)={r1} jac(rescaled)={r2}");
        }
    }
    println!("{n} G1 cases checked, all_pass={all_pass}");

    println!("=== G2 Jacobian-consistent fast check (with random Z rescalings) ===");
    let mut n2 = 0;
    let mut all_pass2 = true;
    let mut cases2: Vec<G2Affine> = vec![G2Affine::zero(), G2Affine::generator()];
    for _ in 0..15 {
        let r = Fr::rand(&mut rng);
        cases2.push((G2Projective::generator() * r).into_affine());
    }
    for _ in 0..15 {
        cases2.push(sample_on_curve_g2(&mut rng));
    }
    for p in cases2 {
        let real = <ark_bls12_381::g2::Config as SWCurveConfig>::is_in_correct_subgroup_assuming_on_curve(&p);
        let base_jac = g2_to_jac(Projective::from(p));
        let r1 = g2_fast_check_jacobian(base_jac);
        let lambda = loop {
            let l = Fq2::rand(&mut rng);
            if !l.is_zero() {
                break l;
            }
        };
        let rescaled = if p.is_zero() { base_jac } else { g2_rescale(base_jac, lambda) };
        let r2 = g2_fast_check_jacobian(rescaled);
        n2 += 1;
        if real != r1 || real != r2 {
            all_pass2 = false;
            println!("MISMATCH at case {n2}: arkworks={real} jac(Z=1)={r1} jac(rescaled)={r2}");
        }
    }
    println!("{n2} G2 cases checked, all_pass={all_pass2}");

    println!(
        "\nOVERALL: {}",
        if all_pass && all_pass2 { "ALL AGREE (Jacobian formulation verified)" } else { "MISMATCH DETECTED" }
    );
    if !(all_pass && all_pass2) {
        std::process::exit(1);
    }
}
