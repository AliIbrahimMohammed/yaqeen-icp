# CEREMONY_SPEC.md — Multi-party trusted setup for the Groth16 circuit

## Why this document exists

`ROADMAP.md`'s P0.2 item says the trusted setup is "single-party, dev-only."
That's accurate and it can't be fixed by writing more code alone — the
security property (nobody knows the full toxic waste) requires multiple
real, independent participants. This document is the concrete, actionable
spec for running that ceremony for real, plus the tooling in `ceremony/`
that's ready for those participants to use.

## What "the toxic waste" actually is, precisely

A Groth16 setup for this circuit has five secret scalars: `tau`, `alpha`,
`beta`, `gamma`, `delta`. Anyone who learns all of them (or a sufficient
algebraic combination — in practice, knowing `tau`/`alpha`/`beta` together
is already enough) can forge a proof for a false statement that verifies
successfully against the resulting verifying key. The only way to make
that impossible is to ensure no single party ever holds the full set —
each contributing participant multiplies in fresh randomness and destroys
their share, so a false proof requires *every* participant to have
colluded or been compromised.

## The two-phase split (why `ceremony/` only rotates `delta`)

This is the standard structure used by Zcash Sapling, Filecoin, and most
Groth16 deployments since:

- **Phase 1 — "Powers of Tau."** Universal, circuit-independent. Multi-party
  contributions to `tau`, `alpha`, `beta` (as powers/monomials, not yet
  combined with any specific circuit's constraints). Because it's
  circuit-independent, **the standard practice is to reuse an existing,
  already-completed, publicly-audited Phase 1 ceremony** rather than
  running a new one. Two well-known options for BLS12-381 (this circuit's
  curve):
  - The original Zcash Sapling MPC transcript.
  - Filecoin's "Powers of Tau" ceremony (also BLS12-381, larger
    participant count, more recent, transcript and verification tooling
    both public).
  Re-deriving your own alpha/beta/tau from scratch only makes sense if
  none of these fit (wrong curve, wrong circuit size, or a policy reason
  to want a fresh ceremony) — and if so, that's its own multi-week
  participant-recruitment effort, not a code task.

- **Phase 2 — circuit-specific.** Takes the circuit's R1CS/QAP and the
  Phase 1 output, combines them into an initial proving key with `delta`
  fixed to a known, secret-free value (this repo's `ceremony_init`
  produces exactly that: `delta = 1`, verifiable by anyone by checking
  `delta_g1 == G1::generator()`). Then N independent participants each
  contribute a fresh `delta_i`, verifiable via the pairing-ratio checks in
  `ceremony/src/lib.rs`. **Only one of the N delta-contributors needs to
  be honest and to actually destroy their randomness** for the final
  `delta` to be secure.

`ceremony_init`/`ceremony_contribute`/`ceremony_verify` in this repo
implement Phase 2 only. Phase 1 (or reusing an existing one) is a
separate, human/process problem, described below.

## Checklist: closing P0.2 for real

1. **Choose the Phase 1 source.**
   - [ ] Decide: reuse an existing public Powers-of-Tau transcript, or run
     a new one.
   - [ ] If reusing: download the chosen transcript and its independent
     verification tool; run that verification yourself, don't trust a
     download.
   - [ ] If running new: recruit ≥3 independent, non-colluding
     participants (different organizations ideally); this is 1-2 weeks of
     coordination minimum, not a coding task.

2. **Combine Phase 1 output with this circuit's QAP.** This is the one
   piece of engineering work still open even after Phase 1 is sourced:
   writing the combination step that takes the chosen Phase 1's `tau`
   powers (in G1/G2, up to the circuit's constraint count) plus `alpha`,
   `beta`, and produces this circuit's `alpha_g1`, `beta_g1`, `beta_g2`,
   `a_query`, `b_g1_query`, `b_g2_query`, and initial (`delta=1`)
   `l_query`/`h_query`. This has to match arkworks' R1CS-to-QAP reduction
   bit-for-bit or later verification (comparing against a from-scratch
   `generate_parameters_with_qap` run) will fail. Budget this as its own
   focused task with real `dfx`/full toolchain access, verified the same
   way this pass verified everything else: real compile, real test
   vectors, not "should work."

3. **Recruit Phase 2 (delta) participants.** Independent of #1/#2's
   participant set is fine — more independence is strictly better.
   - [ ] ≥3 participants, ideally on air-gapped or single-purpose machines
     (a fresh live-USB boot per contributor is the gold standard;
     `ceremony_contribute.rs`'s doc comment says this explicitly).
   - [ ] Each runs `ceremony_contribute` once, publishes
     `round_N.pk.bin` + updated `transcript.json` (e.g. to GitHub, IPFS, or
     both) **before** the next participant starts.
   - [ ] Mix in real entropy per the `--entropy` flag — dice rolls, a
     hardware RNG dump's hash, whatever; don't pass a placeholder string.
   - [ ] Optionally include a public randomness beacon value (e.g.
     https://drand.love) as an additional, publicly-checkable entropy
     source alongside each participant's own contribution.

4. **Independent verification.** Anyone — not just participants — runs
   `ceremony_verify --dir <published transcript dir>` against the fully
   published transcript + all `round_N.pk.bin` files. This is designed to
   need zero trust: it re-derives every pairing check from public bytes.
   - [ ] At least 2-3 people *outside* the participant list should run
     this independently and publish that they did, with the resulting
     `final vk sha256` fingerprint, so it's cross-checkable against what
     the canister/client actually deploys.

5. **Publish the final artifacts + attestations.** The final round's
   `round_N.pk.bin` becomes the real proving key; `round_N`'s embedded
   `vk` (same as any round's `vk`, since only `vk.delta_g2` changes)
   becomes the real verifying key baked into `Groth16Wire.mo` /
   `setVerifyingKey`. Publish:
   - [ ] The full transcript + all round files.
   - [ ] Each participant's attestation text (already captured in
     `transcript.json`, but worth also publishing prose write-ups if
     participants are willing).
   - [ ] The independent-verifier fingerprints from step 4.

6. **Only after all of the above:** flip `real_value_eligible` in
   `circuit/src/bin/setup.rs`'s conceptual successor (the ceremony
   output) to true, and point the canister's `setVerifyingKey` at the
   ceremony's final `vk`, not the dev `setup.rs` output.

## What's explicitly NOT solved by any of this

- **Phase 1 participant honesty** is still a real-world trust question the
  code can't answer — this doc can tell you how to check the *math*, not
  vet the *people*. Choosing well-known, reputable Phase 1 transcripts
  with public participant lists is the best available mitigation.
- **The QAP-combination step (#2)** is unimplemented in this repo. It's
  real, bounded, verifiable engineering work — but it's substantial enough
  (matching a compiler-internal reduction) that it deserves dedicated
  effort with full `dfx`/toolchain access, not a rushed pass.
- **This crate (`ceremony/`) has not been independently audited.** The
  pairing checks are standard and I've derived/tested them (see
  `ceremony/` — real compile, real end-to-end run with two simulated
  participants, real tamper-detection test, all confirmed working in this
  sandbox), but "I tested it" is not the same bar as "a second
  cryptographer reviewed it." For anything real-value-eligible, get
  independent review, or use the delta-rotation step of an established,
  audited tool (`phase2-bn254`, `snarkjs zkey contribute`) instead of this
  crate's `ceremony_contribute`.
