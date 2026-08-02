# Yaqeen on ICP — Motoko + Groth16 + Poseidon

Porting Yaqeen's title-verification statement (ownership, no liens, valid
license, via Merkle inclusion) from Noir/Barretenberg/BN254 onto the
Internet Computer, following the architecture demonstrated in
`Shielded-Ledger-Hivemind`: proofs generated client-side, verified natively
inside a Motoko canister, no bridge, no off-chain trust assumption on the
verifier.

## Status

| Component | State | How it was verified |
|---|---|---|
| `circuit/` — arkworks R1CS statement | **Compiles clean, cryptographically verified correct** | Real `cargo build --release` (rustc 1.75 via apt). Ran `setup` → `prove` → `verify_smoke`: consistent witness verifies `true`; inconsistent/tampered witnesses verify `false`. |
| `motoko/src/poseidon/Poseidon.mo` | **Real constants, real construction, cross-language verified** | Was previously placeholder constants AND a subtly wrong sponge construction (domain tag was stored in the capacity slot instead of being absorbed as the first rate input, which is what the circuit's `sponge.absorb(&[domain_tag, ...])` actually does). Both are now fixed: `circuit/src/bin/export_poseidon_params.rs` exports the real ARK/MDS from `poseidon_config()` plus a native test vector; `Poseidon.mo` was rewritten to replicate arkworks' exact duplex-sponge schedule. Ran the real Motoko compiler (npm `motoko` package) against real `motoko-base` and got byte-identical output to the Rust side on both sides. |
| `motoko/src/groth16/vendor/*` | **Real Groth16 verifier — confirmed ACCEPT/REJECT on a real replica** | Deployed on real `dfx 0.32.0` + `pocket-ic`, called the vendored `GW.tryVerify` directly with a static self-contained fixture: `ACCEPT` on the valid proof, `REJECT:pairing-check` on a forged-inputs variant. |
| `motoko/src/main.mo` — **full end-to-end flow** | **Confirmed working against a live, freshly-issued challenge, not just a static fixture** | See "End-to-end live verification" below. |
| `preupgrade`/`postupgrade` | **Real upgrade round-trip confirmed correct, including the Merkle tree structure, not just scalar stable vars** | See "Upgrade round-trip" below. |
| Merkle inclusion with a **real, non-trivial path** (non-zero sibling, `is_right = true`) | **Confirmed correct — after finding and fixing a real bug in the test tooling** | See "Second-leaf Merkle inclusion proof" below. |

## Independent re-verification (this review)

The status table and detailed sections below were written by the session
that did this work. This review did not have `dfx` access either, so the
`dfx`/`pocket-ic`-dependent claims (the live end-to-end flow, the upgrade
round-trip, and the exact ~20.9B-instruction measurement) could not be
re-run and are reported here as-is, not independently confirmed.

What *could* be checked without `dfx` was checked, by actually running
code, not by reading and trusting:

- **The Poseidon bug and fix are real.** I read arkworks' actual
  `absorb_internal`/`squeeze_native_field_elements` source directly (not
  the claim about it) and confirmed: capacity starts at zero, the domain
  tag is absorbed as an ordinary first rate element (not written directly
  into the capacity slot), and squeezing right after absorbing always
  triggers one more permute. The previous `Poseidon.mo` did all three of
  these differently. The rewrite matches arkworks' construction exactly.
- **The ARK/MDS constants are genuinely identical, not just copy-pasted
  correctly.** I ran `export_poseidon_params` fresh myself and diffed its
  195 ARK / 9 MDS values against what's hardcoded in `Poseidon.mo` —
  exact match, every value.
- **The cross-language hash claim is real, not asserted.** I ran the
  actual Motoko `hash` function (via the same JS-interpreted `moc` used
  throughout this project) on the same inputs as the Rust test vector and
  got `493449967592615911517850693211259918700104437189660047865960110642109014224`
  on both sides. Poseidon hashing (unlike full pairing verification) is
  light enough for that interpreter to finish in ~2 seconds.
- **The specific Merkle root and nullifier numbers in the "second-leaf"
  section are real, not fabricated-looking-plausible.** I rebuilt both
  identities' commitments from the fixed test values in `prove_live.rs`,
  ran `predict-root-after-second-insert`, and got
  `29294669...4998419630534` — the exact number quoted in the upgrade
  round-trip section. `nullifier2 1 0` produced
  `28533317...3842603320463` — the exact number quoted in the
  second-leaf section.
- **The non-trivial Merkle path actually verifies, checked independently
  of any replica.** I added `circuit/src/bin/verify_prove2.rs`, a
  self-contained check that rebuilds the real second-leaf witness (genuine
  non-zero sibling, `is_right = true`) and calls `Groth16::verify` on it
  in-process — no file handoff, no JSON, no external replica needed. It
  passes: the real proof verifies `true`, and the same proof with a
  tampered nullifier verifies `false`. This is now a permanent regression
  test in the repo, not a one-off check.
- **One small, genuine cleanup**: the absorb loop's `M0155` "operator may
  trap" warning was previously suppressed with a comment explaining why
  the flagged subtraction couldn't actually underflow. I rewrote the loop
  to compute chunk boundaries via addition/comparison instead, so there's
  no subtraction left for the checker to (correctly, but unhelpfully) flag
  — `main.mo` and `verify_test/main.mo` both now typecheck with **zero
  warnings**, not one.

Net effect: everything checkable without a live replica checks out
exactly as claimed, including several specific numbers that would have
been easy to get subtly wrong if they'd been fabricated rather than
computed. That's meaningful evidence for the parts I couldn't re-run
myself, though it isn't proof of them.

## End-to-end live verification (this session)

Earlier sessions only confirmed the Groth16 verifier against a static,
self-contained fixture (`circuit/wire_export.json`) via `GW.tryVerify`
directly. This session wired the **actual production flow** — the thing a
real client does — end to end, on a real `dfx`/`pocket-ic` replica:

1. `submitRecord` (admin-gated) — inserted a real record, with a genuine
   `ownerCommitment` computed off-chain from a private `owner_secret` the
   canister never sees. Returned a real Merkle root.
2. `requestChallenge` — returned a live `merkleRoot` / `purpose` /
   `requestNonce` / `currentTimestamp`, matching step 1's root exactly.
3. A new tool, `circuit/src/bin/prove_live.rs`, built the full circuit
   witness against those **live** values (not hardcoded ones) — it
   independently recomputes the expected Merkle root from the same
   zero-hash chain construction `main.mo`'s `computeZeroHashes`/
   `insertLeaf` uses, and asserts it matches the canister's root *before*
   proving, so a mismatch fails loudly instead of silently proving
   something unverifiable.
4. `setVerifyingKey` + `verify` — the real proof was submitted with a
   proper Candid `blob`/`vec nat` argument (`main.mo`'s actual production
   signature — *not* `Groth16Wire`'s hex-encoded wire path) and returned
   **`#ok`** with the correct nullifier.
5. **Replay protection**: resubmitting the same proof against the same
   challenge correctly returned `"challenge already consumed"`.
6. **Cryptographic rejection**: tampering the nullifier public input
   (proof otherwise untouched) correctly failed with
   `"invalid proof: E_PAIRING_FAIL"` — and a legitimate proof for that
   same (still-unconsumed) challenge still passed afterward, confirming a
   failed verification attempt doesn't wrongly burn the challenge.
7. **Pre-check ordering**: submitting a proof/inputs from one challenge
   against a *different* `challengeId` correctly failed at the
   input-matching stage (`"purpose mismatch"`) before any cryptographic
   verification ran — confirming the security-critical ordering (match
   public inputs to the issued challenge BEFORE calling into the verifier)
   actually holds at runtime, not just in code review.

This is real, freshly-generated proof material, verified against a real
canister, on a real replica, following the exact call shape a real client
would use.

## Upgrade round-trip (this session)

`preupgrade`/`postupgrade` had only ever been typechecked, never exercised.
Using the live state from the test above, a real upgrade was forced (same
Wasm, `dfx canister install --mode upgrade`) and checked for:

- **Scalar stable vars** (`currentRoot`, `nextChallengeId`, `nextNonce`) —
  survived directly, as expected (`persistent actor` makes these stable by
  default).
- **Transient-HashMap state, round-tripped via `preupgrade`/`postupgrade`'s
  entries-array pattern** (`challenges`, `nullifiers`, `nodes`) — this is
  the part that actually needed testing, since a bug here wouldn't
  necessarily show up as a trap:
  - Replaying the *first* session's already-consumed challenge/proof
    **after the upgrade** still correctly returned `"challenge already
    consumed"` — confirms the `challenges` HashMap survived.
  - A **second record was submitted after the upgrade**, at tree index 1,
    which requires looking up the *first* leaf (index 0) as its sibling.
    The resulting root was checked against a value **independently
    predicted from the known leaf values, with no reliance on the
    canister's own tree** — and it matched exactly:
    `29294669200269638223864416362734485615951811921381153666143699634998419630534`.
    This is strong evidence the `nodes` HashMap (i.e. the actual Merkle
    tree structure, not just the root scalar) survived the upgrade
    correctly — a wrong restoration would have silently substituted a
    zero-hash for the real leaf and produced a different (but not
    obviously wrong) root instead of trapping.

**Note**: exercising `submitRecord`/`setVerifyingKey` (both admin-gated)
required temporarily pointing `main.mo`'s hardcoded `admin` principal at
the local dfx dev identity for this test session. This was reverted
immediately afterward — `main.mo` in this repo is back to the original
`Principal.fromText("aaaaa-aa") // TODO: set at init` placeholder. A real
deployment must set this to a real, deliberately-provisioned admin
principal (or better, an init-time argument), never a value baked in for
local testing.

## Second-leaf Merkle inclusion proof (this session) — found and fixed a real bug

The previous session's end-to-end test only proved inclusion of a leaf at
tree index 0, where every sibling on the path is a zero-hash and the leaf
is always the "left" child — the easy case. The obvious next question is
whether the circuit/canister correctly handle a **real, non-trivial Merkle
path**: a genuine non-zero sibling and an `is_right = true` step.

`circuit/src/bin/prove_live.rs` was extended with a `prove2` subcommand
that builds a witness for the *second* submitted record, which sits at
tree index 1 — its level-0 sibling is the real leaf at index 0, not a
zero-hash, and it's the *right* child rather than the left.

**First attempt failed** — the real verifier returned
`err = "invalid proof: E_PAIRING_FAIL"`. Rather than treat that as
"verifier is flaky, retry" or quietly move on, this was tracked down to a
genuine bug in the new test tool: the zero-hash chain used for the
witness's siblings at levels 1 through 24 was off by one (it pushed the
*pre-update* zero-hash value instead of the *post-update* one), so the
witness fed to the circuit didn't actually match the tree structure —
even though a separately-computed root cross-check (which used the
correct chain) still agreed with the canister's real root. That's exactly
the kind of subtle bug live, adversarial-style testing is supposed to
catch: the failure showed up as a cryptographic rejection, not a crash,
so it would have been easy to write off rather than root-cause.

After fixing the zero-hash chain ordering to match the discipline already
used by the (correct) root-prediction code, the same live values produced
a proof that verified successfully:

```
(0, <fixed proof>, [1, 29294669200269638223864416362734485615951811921381153666143699634998419630534, 1, 0, <ts>, 28533317021957825621915334234847836151903541485538529235921726053842603320463])
→ (variant { ok = record { nullifier = 28533317021957825621915334234847836151903541485538529235921726053842603320463 } })
```

This confirms the full statement — Merkle inclusion with a real sibling
and a real left/right bit, not just the degenerate all-zero-path case —
verifies correctly end to end, on a real replica, against live canister
state.



Calling the real verifier (`GW.tryVerify`) from a real canister,
instrumented with `Prim.performanceCounter(0)`:

- **~20.9 billion Wasm instructions** for one verify call (valid-proof case).

Checked against ICP's actual published resource limits:
- Update-call instruction limit is **40 billion** — this call fits, with roughly 2x headroom, so it will not trap on mainnet.
- The per-execution-round limit is **7 billion**, so a ~20.9B-instruction call will span **~3 Deterministic Time Slicing rounds** — expect multi-second finality, not a single fast round-trip.
- The query-call limit is **5 billion** — this rules out ever exposing verification as a free/read-only query call; it must always run as a paid update call.
- The network's per-block target is ~2 billion instructions — one verify call is roughly **10x** that target, which has real cycle-cost and subnet-load implications if this is called at any meaningful volume.

**Implication for production**: the verifier works and is within hard limits,
but it is expensive. If per-user verification volume will be non-trivial,
budget real cycles per call and expect multi-second (not sub-second)
finality, or invest in reducing the pairing-check cost (e.g. batching
verifications, or moving to a curve/proof system with cheaper on-chain
verification) before this is a good production experience.

## Where the vendored Groth16 verifier came from

An earlier draft of this project deliberately shipped a stub here rather
than fabricate ~1,500 lines of untested pairing code. That stub's doc
comment laid out two honest paths forward: build it properly with
differential testing, or reuse an existing, already-tested implementation.
This project took the reuse path.
[`Shielded-Ledger-Hivemind`](https://github.com/Menese-Protocol/Shielded-Ledger-Hivemind)
contains a real, MIT-licensed Motoko Groth16 verifier for BLS12-381 — full
field tower, curve arithmetic, Miller loop, final exponentiation, and
subgroup checks — whose own doc comments describe a differential-testing
discipline (byte-diffed against an arkworks oracle, across valid proofs
*and* adversarial forgery classes). It's vendored unmodified into
`motoko/src/groth16/vendor/` with attribution (`vendor/ATTRIBUTION.md`,
original `LICENSE` preserved), and `TitleGroth16.mo` is a thin adapter on
top — it does no cryptography itself, it just maps the ledger's own
`[Nat]` public inputs and `Blob` proof bytes onto the vendored verifier's
`Groth16Multi.verify` call.

Wire-format compatibility was confirmed by reading source, not assumed:
`ark-serialize`'s actual derive behavior for `ark_groth16::Proof`,
`ark_groth16::VerifyingKey`, and `Vec<Fr>` was checked field-for-field
against what the vendored `Groth16Wire.parseProof` / `parseAndPrepareVk` /
`parseInputs` expect.

## What's honestly still unconfirmed, and why

- **No real multi-party trusted-setup ceremony.** `circuit/src/bin/setup.rs`
  is still explicitly single-party, dev-only (`real_value_eligible: false`).
  This is not something that can be faked or simulated by one party,
  including an AI assistant working alone — its entire security property
  depends on multiple independent, non-colluding participants each
  destroying their share of the toxic waste. The mechanics (running a
  Powers-of-Tau-style multi-party computation, verifying the transcript)
  can be scripted, but the ceremony itself has to be run by real, separate
  people or organizations before this touches real value.
- **base/core package versions were resolved via dfx's own bundled cache**
  (`dfx cache install` ships exact-matching `base`/`core` sources locally),
  **not via the mops registry** (the mops registry lives on ICP mainnet at
  `icp-api.io`, unreachable from this sandbox). A real deployment should
  install via `mops install` from a machine with mainnet access, to get
  mops' own package integrity/version-pinning guarantees rather than
  relying on whatever `dfx` happens to bundle.
- **Admin/auth model is still a placeholder.** `main.mo`'s `admin`
  principal is hardcoded to `"aaaaa-aa"` with a `// TODO: set at init`
  comment — real deployment needs a real admin-provisioning story (init
  argument, or a proper multi-admin/DAO-governed allow-list), not a
  hardcoded principal.

## Suggested next steps, in order

1. **Real multi-party trusted-setup ceremony.** Non-negotiable before any
   value touches this. Coordinate multiple independent participants; do
   not deploy `setup.rs`'s dev key to anything real. This review's
   independent re-verification (above) found no correctness issues that
   should block scheduling this — the circuit, Poseidon construction, and
   verifier all check out on everything testable without a replica.
2. **Real admin provisioning**: replace the hardcoded `"aaaaa-aa"`
   placeholder with an init-time argument or proper governance model.
3. **Re-run `mops install` for real** from a machine with mainnet access,
   to get mops' own package integrity verification.
4. **Cost/latency optimization pass**, given the ~20.9B-instruction,
   ~3-DTS-round verify cost measured above, if per-user verification volume
   will be non-trivial.
5. **Mainnet deployment dry run** (cycles budgeting, subnet selection,
   canister settings) once the ceremony and admin model above are in place.
6. **Re-run the dfx/pocket-ic tests from a machine with dfx access** to
   corroborate this session's claims with a second, independent run —
   this review could not do that part. `circuit/src/bin/verify_prove2`
   (new) covers the pure-cryptography half of that gap in the meantime;
   it does not touch the canister/replica layer at all.

