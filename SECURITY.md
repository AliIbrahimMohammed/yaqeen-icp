# Security Policy

## Reporting a vulnerability

This project deals with zero-knowledge proofs, pairing-based cryptography, and
title-verification state on the Internet Computer. Do **not** open a public
issue for suspected vulnerabilities. Report privately:

- Email: `wekaali4335@gmail.com`
- Subject prefix: `[yaqeen-icp security]`

You can also open a GitHub issue with the `security` label if you prefer
tracked private issues (make it private where possible).

Please include, if you have it:

- a description of the bug and its security impact (verifier accepts a forged
  proof, replay of a consumed challenge, Merkle tree inconsistency, admin
  bypass, etc.),
- the affected files/lines and the conditions required to exploit it,
- a minimal reproduction (witness values, proof bytes, call sequence).

## What we take seriously

- Anything that could let an attacker verify a proof that should fail
  (forgery, malleability, subgroup attacks).
- Anything that could let an attacker burn, replay, or forge a challenge or
  record submission.
- Admin/auth bypasses and access-control issues in the canister.
- Memory/liveness traps in the Motoko verifier (the pairing code runs in
  update calls with tight instruction budgets).

## Scope and known limitations

These are known and documented in the README — do not report them as bugs:

- `setup.rs` is a **dev-only, single-party** trusted setup
  (`real_value_eligible: false`). The security property of a real deployment
  requires a real multi-party ceremony, which is a deployment concern.
- The `admin` principal is a placeholder (`aaaaa-aa`) to be set at
  deployment/init.
- The vendored verifier's differential test (`Groth16MultiTest.mo`) currently
  pins the pre-alpha/beta-precompute Miller-loop intermediate and must be
  re-pinned before the new 3-pair path ships to production (see
  `PATCH_NOTES-alphabeta-precompute.md`).

## Disclosure

We will acknowledge within 7 days, and we will disclose the fix (and credit
the reporter) after it is deployed or when the reporter agrees. Please hold
off on public disclosure until then.
