/// **OPTIMIZED** — inversion-free Jacobian scalar multiplication for BLS12-381 G1/G2,
/// Montgomery-form coordinates.
///
/// Menese DeFi Team. Why this module exists: the affine L2 group ops (`CurveMont`) pay a Fermat
/// field inversion (~150M instructions) per add/double, so ONE 255-bit scalar multiplication costs
/// ~57B — the vk_x MSM and each literal `[r]P` subgroup check would individually exceed the 40B
/// per-message ceiling. Jacobian coordinates remove the per-step inversion entirely; the ONLY
/// inversion is the single final conversion back to affine (and the subgroup check needs none:
/// `[r]P == O` is exactly `Z == 0`).
///
/// Formulas are the standard a=0 Jacobian ones (EFD dbl-2009-l / add-2007-bl), the same ones
/// arkworks' short-Weierstrass projective backend reduces to for these curves.
///
/// Correctness boundary: this module is DIFFED against the literal L1 `Curve` (`g1Mul/g2Mul`,
/// `g1Validate/g2Validate`) in `CurveJacTest.mo` — generator multiples, the real Groth16 proof
/// points, the pinned wrong-subgroup adversarial points (MUST reject), edge scalars 0/1/2/r−1/r/r+1,
/// and a live formula mutant that must turn the differential RED. L1 stays the untouched anchor.

import FpM "FpMont";
import TM "TowerMont";
import C "Curve";

module {
  // =============================================================================================
  // G1 over FpMont, Jacobian (X : Y : Z), Z == 0 encodes infinity.
  // =============================================================================================
  public type G1J = { x : Nat; y : Nat; z : Nat };

  public func g1Inf() : G1J { { x = FpM.toMont(1); y = FpM.toMont(1); z = 0 } };
  public func g1IsInf(p : G1J) : Bool { p.z == 0 };

  public func g1FromAffine(p : C.G1) : G1J {
    switch (p) {
      case (#inf) { g1Inf() };
      case (#pt(q)) { { x = FpM.toMont(q.x); y = FpM.toMont(q.y); z = FpM.toMont(1) } };
    };
  };

  /// One inversion, at the very end of a whole scalar-mul/MSM — not per step.
  public func g1ToAffine(p : G1J) : C.G1 {
    if (p.z == 0) { return #inf };
    let zN = FpM.montMul(p.z, 1);
    let zInvM = FpM.toMont(FpM.inv(zN));
    let zInv2 = FpM.montMul(zInvM, zInvM);
    let zInv3 = FpM.montMul(zInv2, zInvM);
    #pt({ x = FpM.montMul(FpM.montMul(p.x, zInv2), 1); y = FpM.montMul(FpM.montMul(p.y, zInv3), 1) });
  };

  /// EFD dbl-2009-l (a = 0).
  public func g1Dbl(p : G1J) : G1J {
    if (p.z == 0) { return p };
    if (p.y == 0) { return g1Inf() };
    let a = FpM.montMul(p.x, p.x);
    let b = FpM.montMul(p.y, p.y);
    let c = FpM.montMul(b, b);
    let xb = FpM.add(p.x, b);
    let d0 = FpM.sub(FpM.sub(FpM.montMul(xb, xb), a), c);
    let d = FpM.add(d0, d0);
    let e = FpM.add(FpM.add(a, a), a);
    let f = FpM.montMul(e, e);
    let x3 = FpM.sub(f, FpM.add(d, d));
    let c8 = FpM.add(FpM.add(FpM.add(c, c), FpM.add(c, c)), FpM.add(FpM.add(c, c), FpM.add(c, c)));
    let y3 = FpM.sub(FpM.montMul(e, FpM.sub(d, x3)), c8);
    let yz = FpM.montMul(p.y, p.z);
    { x = x3; y = y3; z = FpM.add(yz, yz) };
  };

  /// EFD add-2007-bl, with the doubling/infinity degeneracies handled explicitly.
  public func g1Add(p : G1J, q : G1J) : G1J {
    if (p.z == 0) { return q };
    if (q.z == 0) { return p };
    let z1z1 = FpM.montMul(p.z, p.z);
    let z2z2 = FpM.montMul(q.z, q.z);
    let u1 = FpM.montMul(p.x, z2z2);
    let u2 = FpM.montMul(q.x, z1z1);
    let s1 = FpM.montMul(FpM.montMul(p.y, q.z), z2z2);
    let s2 = FpM.montMul(FpM.montMul(q.y, p.z), z1z1);
    if (u1 == u2) {
      if (s1 == s2) { return g1Dbl(p) };
      return g1Inf();
    };
    let h = FpM.sub(u2, u1);
    let h2 = FpM.add(h, h);
    let i = FpM.montMul(h2, h2);
    let j = FpM.montMul(h, i);
    let r0 = FpM.sub(s2, s1);
    let r = FpM.add(r0, r0);
    let v = FpM.montMul(u1, i);
    let x3 = FpM.sub(FpM.sub(FpM.montMul(r, r), j), FpM.add(v, v));
    let s1j = FpM.montMul(s1, j);
    let y3 = FpM.sub(FpM.montMul(r, FpM.sub(v, x3)), FpM.add(s1j, s1j));
    let zs = FpM.add(p.z, q.z);
    let z3 = FpM.montMul(FpM.sub(FpM.sub(FpM.montMul(zs, zs), z1z1), z2z2), h);
    { x = x3; y = y3; z = z3 };
  };

  /// Double-and-add, structurally identical to L1 `Curve.g1Mul`.
  public func g1Mul(p : G1J, k : Nat) : G1J {
    var result = g1Inf();
    var base = p;
    var e = k;
    while (e > 0) {
      if (e % 2 == 1) { result := g1Add(result, base) };
      base := g1Dbl(base);
      e := e / 2;
    };
    result;
  };

  /// `[r]P == O` — the same literal definition as L1, inversion-free.
  public func g1IsInSubgroup(p : C.G1) : Bool {
    g1IsInf(g1Mul(g1FromAffine(p), C.R));
  };

  /// Same codes, same order as L1 `Curve.g1Validate`; canonical/on-curve reuse L1 directly,
  /// only the subgroup scalar-mul is replaced by the Jacobian one.
  public func g1Validate(p : C.G1) : { #ok; #err : Text } {
    if (not C.g1IsCanonical(p)) { return #err("E_NONCANONICAL") };
    if (not C.g1IsOnCurve(p)) { return #err("E_NOT_ON_CURVE") };
    if (not g1IsInSubgroup(p)) { return #err("E_NOT_IN_SUBGROUP") };
    #ok;
  };

  // =============================================================================================
  // G2 over TowerMont Fp2, Jacobian (X : Y : Z), Z == 0 encodes infinity.
  // =============================================================================================
  public type G2J = { x : TM.Fp2M; y : TM.Fp2M; z : TM.Fp2M };

  func fp2IsZero(a : TM.Fp2M) : Bool { a.c0 == 0 and a.c1 == 0 };
  let fp2Zero : TM.Fp2M = { c0 = 0; c1 = 0 };

  public func g2Inf() : G2J { { x = TM.fp2OneM(); y = TM.fp2OneM(); z = fp2Zero } };
  public func g2IsInf(p : G2J) : Bool { fp2IsZero(p.z) };

  public func g2FromAffine(p : C.G2) : G2J {
    switch (p) {
      case (#inf) { g2Inf() };
      case (#pt(q)) { { x = TM.toM2(q.x); y = TM.toM2(q.y); z = TM.fp2OneM() } };
    };
  };

  public func g2ToAffine(p : G2J) : C.G2 {
    if (fp2IsZero(p.z)) { return #inf };
    let zInv = TM.fp2Inv(p.z);
    let zInv2 = TM.fp2SqrFast(zInv);
    let zInv3 = TM.fp2Mul(zInv2, zInv);
    #pt({ x = TM.fromM2(TM.fp2Mul(p.x, zInv2)); y = TM.fromM2(TM.fp2Mul(p.y, zInv3)) });
  };

  public func g2Dbl(p : G2J) : G2J {
    if (fp2IsZero(p.z)) { return p };
    if (fp2IsZero(p.y)) { return g2Inf() };
    let a = TM.fp2SqrFast(p.x);
    let b = TM.fp2SqrFast(p.y);
    let c = TM.fp2SqrFast(b);
    let xb = TM.fp2Add(p.x, b);
    let d0 = TM.fp2Sub(TM.fp2Sub(TM.fp2SqrFast(xb), a), c);
    let d = TM.fp2Add(d0, d0);
    let e = TM.fp2Add(TM.fp2Add(a, a), a);
    let f = TM.fp2SqrFast(e);
    let x3 = TM.fp2Sub(f, TM.fp2Add(d, d));
    let c2 = TM.fp2Add(c, c);
    let c4 = TM.fp2Add(c2, c2);
    let c8 = TM.fp2Add(c4, c4);
    let y3 = TM.fp2Sub(TM.fp2Mul(e, TM.fp2Sub(d, x3)), c8);
    let yz = TM.fp2Mul(p.y, p.z);
    { x = x3; y = y3; z = TM.fp2Add(yz, yz) };
  };

  public func g2Add(p : G2J, q : G2J) : G2J {
    if (fp2IsZero(p.z)) { return q };
    if (fp2IsZero(q.z)) { return p };
    let z1z1 = TM.fp2SqrFast(p.z);
    let z2z2 = TM.fp2SqrFast(q.z);
    let u1 = TM.fp2Mul(p.x, z2z2);
    let u2 = TM.fp2Mul(q.x, z1z1);
    let s1 = TM.fp2Mul(TM.fp2Mul(p.y, q.z), z2z2);
    let s2 = TM.fp2Mul(TM.fp2Mul(q.y, p.z), z1z1);
    if (u1 == u2) {
      if (s1 == s2) { return g2Dbl(p) };
      return g2Inf();
    };
    let h = TM.fp2Sub(u2, u1);
    let h2 = TM.fp2Add(h, h);
    let i = TM.fp2SqrFast(h2);
    let j = TM.fp2Mul(h, i);
    let r0 = TM.fp2Sub(s2, s1);
    let r = TM.fp2Add(r0, r0);
    let v = TM.fp2Mul(u1, i);
    let x3 = TM.fp2Sub(TM.fp2Sub(TM.fp2SqrFast(r), j), TM.fp2Add(v, v));
    let s1j = TM.fp2Mul(s1, j);
    let y3 = TM.fp2Sub(TM.fp2Mul(r, TM.fp2Sub(v, x3)), TM.fp2Add(s1j, s1j));
    let zs = TM.fp2Add(p.z, q.z);
    let z3 = TM.fp2Mul(TM.fp2Sub(TM.fp2Sub(TM.fp2SqrFast(zs), z1z1), z2z2), h);
    { x = x3; y = y3; z = z3 };
  };

  public func g2Mul(p : G2J, k : Nat) : G2J {
    var result = g2Inf();
    var base = p;
    var e = k;
    while (e > 0) {
      if (e % 2 == 1) { result := g2Add(result, base) };
      base := g2Dbl(base);
      e := e / 2;
    };
    result;
  };

  public func g2IsInSubgroup(p : C.G2) : Bool {
    g2IsInf(g2Mul(g2FromAffine(p), C.R));
  };

  public func g2Validate(p : C.G2) : { #ok; #err : Text } {
    if (not C.g2IsCanonical(p)) { return #err("E_NONCANONICAL") };
    if (not C.g2IsOnCurve(p)) { return #err("E_NOT_ON_CURVE") };
    if (not g2IsInSubgroup(p)) { return #err("E_NOT_IN_SUBGROUP") };
    #ok;
  };

  // =============================================================================================
  // FAST endomorphism-based subgroup check (Bowe's trick for G1, Galbraith-Scott ψ for G2).
  // NEW, additive — g1IsInSubgroup/g2IsInSubgroup above are UNTOUCHED and remain the literal
  // [r]P == O definition. This is exactly the module's own stated architecture: "L2 may optimize
  // it, and the L2-vs-L1 differential will catch it if it does."
  //
  // Validated against arkworks via `circuit/src/bin/oracle_subgroup_jacobian.rs`: 32/32 G1 and
  // 32/32 G2 cases agree with `is_in_correct_subgroup_assuming_on_curve`, including deliberate
  // random-Z Jacobian rescalings (representation-invariance check). NOT YET cross-validated
  // against `g1IsInSubgroup`/`g2IsInSubgroup` on THIS Motoko implementation via a real
  // differential run — that needs `dfx` (see `g1FastCheckAgrees`/`g2FastCheckAgrees` below,
  // written for exactly that purpose). Exposed as separate `*Fast` functions, not a replacement
  // for the slow ones, until that run happens and confirms agreement on real data.
  //
  // G1: endomorphism φ(X,Y,Z) = (β·X, Y, Z) — same Z, since β·(X/Z²) = (β·X)/Z² is still a valid
  //     representation of the point (β·x, y). Check (Bowe): [X²]P == −φ(P), X the BLS parameter.
  // G2: ψ(X,Y,Z) = (psi_x_coeff · conj(X), psi_y_coeff · conj(Y), conj(Z)) — conj is a field
  //     automorphism, so conjugating all three coordinates together is representation-consistent.
  //     Check (Galbraith-Scott): ψ(P) == [−X]P (X_IS_NEGATIVE, so computed as −[X_ABS]P).
  // Point equality across different Z uses the same cross-multiplication test point-addition
  // already relies on to detect "same point": X1·Z2² == X2·Z1²  &&  Y1·Z2³ == Y2·Z1³.

  let X_ABS : Nat = 0xd201000000010000;

  func BETA() : Nat { FpM.toMont(793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350) };
  func PSI_X_COEFF() : Nat { FpM.toMont(4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437) };
  func PSI_Y() : TM.Fp2M {
    {
      c0 = FpM.toMont(2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530);
      c1 = FpM.toMont(1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257);
    };
  };

  func fp2EqLocal(a : TM.Fp2M, b : TM.Fp2M) : Bool { a.c0 == b.c0 and a.c1 == b.c1 };
  func fp2Conj(a : TM.Fp2M) : TM.Fp2M { { c0 = a.c0; c1 = FpM.sub(0, a.c1) } };
  func fp2Neg(a : TM.Fp2M) : TM.Fp2M { { c0 = FpM.sub(0, a.c0); c1 = FpM.sub(0, a.c1) } };

  func g1EqJac(a : G1J, b : G1J) : Bool {
    if (a.z == 0) { return b.z == 0 };
    if (b.z == 0) { return false };
    let z1z1 = FpM.montMul(a.z, a.z);
    let z2z2 = FpM.montMul(b.z, b.z);
    let u1 = FpM.montMul(a.x, z2z2);
    let u2 = FpM.montMul(b.x, z1z1);
    if (u1 != u2) { return false };
    let s1 = FpM.montMul(FpM.montMul(a.y, b.z), z2z2);
    let s2 = FpM.montMul(FpM.montMul(b.y, a.z), z1z1);
    s1 == s2;
  };

  func g1EndoJac(p : G1J) : G1J { { x = FpM.montMul(BETA(), p.x); y = p.y; z = p.z } };

  /// `p` is assumed already canonical/on-curve (call `C.g1IsCanonical`/`g1IsOnCurve` first, same
  /// as `g1Validate` does for the slow check) — this function only replaces the subgroup test.
  public func g1IsInSubgroupFast(p : C.G1) : Bool {
    let j = g1FromAffine(p);
    if (g1IsInf(j)) { return true };
    let xP = g1Mul(j, X_ABS);
    if (g1EqJac(xP, j)) { return false };
    let x2P0 = g1Mul(xP, X_ABS);
    let x2P = { x = x2P0.x; y = FpM.sub(0, x2P0.y); z = x2P0.z }; // negate Y => -[X²]P
    let endoP = g1EndoJac(j);
    g1EqJac(x2P, endoP);
  };

  func g2EqJac(a : G2J, b : G2J) : Bool {
    if (fp2IsZero(a.z)) { return fp2IsZero(b.z) };
    if (fp2IsZero(b.z)) { return false };
    let z1z1 = TM.fp2Mul(a.z, a.z);
    let z2z2 = TM.fp2Mul(b.z, b.z);
    let u1 = TM.fp2Mul(a.x, z2z2);
    let u2 = TM.fp2Mul(b.x, z1z1);
    if (not fp2EqLocal(u1, u2)) { return false };
    let s1 = TM.fp2Mul(TM.fp2Mul(a.y, b.z), z2z2);
    let s2 = TM.fp2Mul(TM.fp2Mul(b.y, a.z), z1z1);
    fp2EqLocal(s1, s2);
  };

  func g2Psi(p : G2J) : G2J {
    let cx : TM.Fp2M = { c0 = 0; c1 = PSI_X_COEFF() };
    {
      x = TM.fp2Mul(cx, fp2Conj(p.x));
      y = TM.fp2Mul(PSI_Y(), fp2Conj(p.y));
      z = fp2Conj(p.z);
    };
  };

  /// `p` is assumed already canonical/on-curve, same convention as `g1IsInSubgroupFast`.
  public func g2IsInSubgroupFast(p : C.G2) : Bool {
    let j = g2FromAffine(p);
    if (g2IsInf(j)) { return true };
    let xP0 = g2Mul(j, X_ABS);
    let xP = { x = xP0.x; y = fp2Neg(xP0.y); z = xP0.z }; // X_IS_NEGATIVE => negate
    let psiP = g2Psi(j);
    g2EqJac(xP, psiP);
  };

  /// Differential self-check: fast vs. slow verdict on the same point. Intended to be run over
  /// real proof/vk points (and deliberately invalid ones — wrong-subgroup, wrong-curve-order
  /// points) under `dfx`/`pocket-ic` before `*Fast` ever replaces `g1IsInSubgroup` in production.
  public func g1FastCheckAgrees(p : C.G1) : Bool {
    g1IsInSubgroupFast(p) == g1IsInSubgroup(p);
  };
  public func g2FastCheckAgrees(p : C.G2) : Bool {
    g2IsInSubgroupFast(p) == g2IsInSubgroup(p);
  };

  // =============================================================================================
  // The Groth16 public-input MSM: vk_x = gammaAbc[0] + Σ inputᵢ·gammaAbc[i+1], one final inversion.
  // =============================================================================================
  public func vkX(gammaAbc : [C.G1], inputs : [Nat]) : C.G1 {
    var acc = g1FromAffine(gammaAbc[0]);
    var i = 0;
    while (i < inputs.size()) {
      acc := g1Add(acc, g1Mul(g1FromAffine(gammaAbc[i + 1]), inputs[i] % C.R));
      i += 1;
    };
    g1ToAffine(acc);
  };
}
