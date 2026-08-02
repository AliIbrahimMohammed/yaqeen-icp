# Derived directly from source (not guessed): Fp-Montgomery-multiplication counts
# for each tower operation, read out of TowerMont.mo / PairingProjective.mo.

fp2Mul_mm      = 4    # FpM.montMul calls in TowerMont.fp2Mul
fp2SqrFast_mm  = 2    # TowerMont.fp2SqrFast
fp6Mul_fp2muls = 9    # TowerMont.fp6Mul, counted fp2Mul() call sites
fp6Mul_mm      = fp6Mul_fp2muls * fp2Mul_mm          # = 36
fp12SqrFast_fp6muls = 2                               # TowerMont.fp12SqrFast
fp12SqrFast_mm = fp12SqrFast_fp6muls * fp6Mul_mm      # = 72

fp6MulBy01_fp2muls = 5   # TowerMont.fp6MulBy01
fp6MulBy1_fp2muls  = 3   # TowerMont.fp6MulBy1
fp12MulBy014_fp2muls = fp6MulBy01_fp2muls*2 + fp6MulBy1_fp2muls   # 2x MulBy01 + 1x MulBy1 = 13
fp12MulBy014_mm = fp12MulBy014_fp2muls * fp2Mul_mm     # = 52
ell_extra_mm = 2 * 2   # two fp2MulByFp calls (c1, c4), 2 montMuls each = 4
ell_mm = fp12MulBy014_mm + ell_extra_mm                # = 56

X_ABS = 0xd201000000010000
bitlen = X_ABS.bit_length()
popcount = bin(X_ABS).count('1')
squarings = bitlen - 1                       # 63
ells_per_pair = (bitlen - 1) + (popcount - 1) # 68  (PairingProjective.mo's own formula)

squaring_cost = squarings * fp12SqrFast_mm     # shared across all pairs, unchanged by this patch
old_line_cost = 4 * ells_per_pair * ell_mm      # 4 pairs
new_line_cost = 3 * ells_per_pair * ell_mm      # 3 pairs

old_miller = squaring_cost + old_line_cost
new_miller = squaring_cost + new_line_cost

print(f"squarings={squarings}  ells_per_pair={ells_per_pair}")
print(f"fp12SqrFast = {fp12SqrFast_mm} base-field mults;  ell() = {ell_mm} base-field mults")
print(f"shared squaring-chain cost: {squaring_cost} base-field mults (unchanged)")
print(f"OLD (4 pairs) line-eval cost: {old_line_cost}   -> Miller loop total: {old_miller}")
print(f"NEW (3 pairs) line-eval cost: {new_line_cost}   -> Miller loop total: {new_miller}")
print(f"Miller-loop-only reduction: {(old_miller-new_miller)/old_miller*100:.1f}%")
print(f"(exactly 1/4 of the *line-eval* work drops out: {(old_line_cost-new_line_cost)/old_line_cost*100:.0f}%,")
print(f" but the squaring chain — the other big chunk of Miller-loop cost — is untouched)")
