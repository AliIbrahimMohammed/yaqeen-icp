# Fix: leaf update/revocation, Merkle-proof endpoint, throttling, challenge cleanup

Four independent fixes to `motoko/src/main.mo`, found by an external code
review that read the source directly rather than relying on the README's
self-assessment. Three of these were real gaps the docs didn't mention at
all; the fourth was a documentation/code mismatch (a claimed protection
that didn't exist in the code).

## 1. Stale leaves stayed permanently provable (highest severity)

**Before:** `submitRecord` always inserted at `nextLeafIndex` — a fresh
position — and never touched a property's previous leaf. Resubmitting a
property (e.g. to add a lien, or mark a license expired) appended a new
leaf but left the old, now-inaccurate leaf sitting in the tree as a
structurally valid member forever. Since a proof only needs to show
membership at the *current* root, an owner could keep generating valid
"no liens, valid license" proofs from their original leaf indefinitely,
regardless of what was submitted later. This directly undermined the
system's core guarantee.

**After:** a `propertyId -> leafIndex` map (`leafIndexByProperty`) is
populated on first submission. Every later `submitRecord` call for the
same `propertyId` reuses that index, so `insertLeaf` recomputes the
existing leaf and its full root-ward path in place instead of appending a
second one. `insertLeaf` itself needed no change — it already worked
correctly for both insert and update given an index; the bug was entirely
in `submitRecord` always choosing a fresh one.

## 2. No way for a client to build a Merkle witness

**Before:** no query existed for a property's leaf index or sibling path.
Without this, a prover cannot construct a proof against `currentRoot` at
all — the described "prove" flow wasn't actually usable end-to-end from
this repo alone.

**After:** two new query functions:
- `getRecord(propertyId) : async ?Record`
- `getMerkleProof(propertyId) : async ?{ leafIndex; siblings; pathBits; root }`

`pathBits[level] == true` means the tracked node is the right child at
that level (mirrors the left/right convention already used inside
`insertLeaf`). Callers should re-fetch immediately before proving, not
cache — siblings can shift as unrelated leaves are inserted elsewhere in
the tree.

## 3. `SECURITY.md` claimed a DoS mitigation that didn't exist

`SECURITY.md` stated `verify` is "DoS-mitigated by per-principal throttles
and anonymous-caller rejection." A full grep of the Motoko tree for
`throttle`/`rate`/`anonymous` turned up nothing — `requestChallenge` and
`verify` were plain `public shared func`, callable by anyone including the
anonymous principal, with no rate limit. Since a caller can legitimately
obtain a valid challenge and then submit garbage proof bytes, this was a
real cycles-drain vector: force repeated ~21B-instruction rejections.

**After:** `checkAndUpdateThrottle` rejects `Principal.isAnonymous(caller)`
and enforces a 2-second minimum interval between calls from the same
principal, applied to both `requestChallenge` and `verify` (now
`shared (msg)` instead of unauthenticated `shared`). This is a floor, not
a complete solution — pair with canister-level cycle budgets/alerts, and a
boundary-level rate limiter if abuse persists at scale — but it closes the
cheap, obvious version of the attack. `requestChallenge`'s return type
changed from a bare record to `Result.Result<{...}, Text>` to carry
throttle/anonymity failures; this is a breaking API change for any
existing client.

## 4. Unbounded growth of the challenge store

**Before:** every `requestChallenge` call added an entry to `challenges`
that was never removed, consumed or not, expired or not — unbounded
stable-memory and cycle-cost growth with no cleanup path.

**After:** a `heartbeat` sweeps expired, unconsumed challenges. Challenge
IDs are issued in strictly increasing order with a fixed TTL, so
`expiresAt` is non-decreasing in ID order — walking forward from
`oldestUnprunedChallengeId` and stopping at the first not-yet-expired
entry is a correct, O(1)-amortized sweep, no full-map scan required.
Bounded to 50 deletions per heartbeat so a large backlog can't itself
become an expensive call.

## Verified

Hand-reviewed against the existing file's conventions and cross-checked
for type consistency (`HashMap<Principal, Int>` throttle stores,
`Result`-wrapped return types, stable-entries/transient-HashMap pairing
matching every other piece of state in this file, `preupgrade`/
`postupgrade` extended for the three new HashMaps).

**Update:** a real Motoko typecheck has now been run (`node-motoko`, the
same WASM build of `moc` published to npm, with `base` pinned to
`moc-0.13.5` via a `codeload.github.com` tarball — `api.github.com`'s
tree-listing endpoint used by `node-motoko`'s own package fetcher is
rate-limited per-IP and was exhausted mid-session, so the base sources
were pulled directly instead — and `core` pinned to `v2.5.0`, matching
`mops.lock.json` exactly for both). Result: **0 errors** across
`main.mo` and every file it imports (`groth16/`, `poseidon/`). One
pre-existing warning (`M0155`, possible trap on `Nat` subtraction) in
untouched vendored code (`groth16/vendor/Fp.mo:87`) — unrelated to this
patch, not introduced by it. `mo.candid('main.mo')` was also generated
successfully and confirms the actor's public interface matches this
document exactly, including `requestChallenge`'s `Result`-wrapped return
type (`Result_3` in the generated Candid) and the two new query methods.

This covers the typecheck half of the recommended verification sequence.

**Update 2:** the replica half has now also been run for real — `dfx
0.32.0` (installed directly via `codeload.github.com`/GitHub release
assets, bypassing the deprecation-notice installer) with its bundled
`moc 1.4.1` and `pocket-ic`. `dfx build` compiles clean (same single
pre-existing `Fp.mo` warning as the standalone typecheck, nothing new).
`dfx deploy` to a live local replica, then, against the running
canister:

- `bootstrapAdmin`, then `submitRecord(1, ...)` — `getMerkleProof(1)`
  returns `leafIndex = 0`. Resubmitted the same `propertyId` with
  `encumbranceFlag = 1` — `getMerkleProof(1)` now returns **the same**
  `leafIndex = 0` with a **different** `root` (confirmed root changed
  between calls). `getMerkleProof(999)` on an unrequested property
  returns `null`. A second `submitRecord` for a different `propertyId`
  got `leafIndex = 1`, confirming indices are assigned per-property, not
  reused across properties.
- `requestChallenge` from the anonymous identity: rejected
  (`"anonymous callers are not permitted"`). Two authenticated calls
  back-to-back: first succeeds, second rejected
  (`"rate limit: try again shortly"`); after a 3s wait, succeeds again.
  Same pattern independently confirmed on `verify` (anonymous rejected,
  rapid repeat throttled) — `verify`'s throttle check fires before the
  challenge lookup, so a throttled call never reaches challenge/crypto
  work, matching the "cheap rejects happen cheaply" design.
- `setVerifyingKey` with the real VK from `circuit/wire_export.json`,
  then `verify` with a syntactically-valid challenge and public inputs
  but 192 all-zero proof bytes: rejected with
  `"invalid proof: E_PROOF_DESERIALIZE"` — the cheap checks all passed
  (proving the reviewer's DoS scenario is real: a caller with a
  legitimate challenge reaches the crypto path with garbage bytes) and
  only the deserialize step caught it, which is exactly the case the
  per-principal throttle exists to slow down.
- Triggered a real canister upgrade (`dfx deploy --upgrade-unchanged`)
  mid-session: `getMerkleProof(1)` returned the identical `leafIndex`
  and `root` afterward (confirms `leafIndexByProperty` and the Merkle
  tree state round-tripped through `preupgrade`/`postupgrade`), and a
  post-upgrade `requestChallenge` continued the pre-upgrade
  `challengeId`/`requestNonce` sequence rather than resetting —
  confirming all upgrade-hook-covered state, including the new
  throttle maps, survives an upgrade correctly.

Not exercised: a full accept-path proof (the fixture's `proofHex` was
generated against a different, fixed set of public inputs than what a
live challenge issues, so reproducing an ACCEPT here would need
`prove_live`-style off-chain proving against the exact live challenge —
out of scope for this pass) and the `heartbeat` cleanup sweep specifically
(5-minute TTL; canister stayed healthy with no trap in its logs for the
duration of this session, but a full TTL-expiry-to-deletion cycle wasn't
timed out).

## What this does not fix

Real multi-party trusted setup and independent audit of the circuit and
vendored verifier are still open — see `README.md`'s Deployment checklist
and `SECURITY.md`. This patch addresses the functional-correctness and
DoS-surface gaps found in this review; it does not touch cryptographic
trust assumptions.

**Update 3 (supplementary, third machine):** the Rust side has now also
been built and exercised for real — `rustc/cargo 1.75.0` (matching the
README's Rust badge) — with the ceremony tooling and the circuit pipeline
run end-to-end from source:

- `ceremony/` builds clean. A full simulated Phase-2 ceremony was run
  through the actual tooling: `ceremony_init` (round 0, `delta=1` by
  construction, seeded from simulated multi-party entropy files plus a
  beacon value) then three `ceremony_contribute` rounds (Alice/Bob/Carol,
  each labeled SIMULATION ONLY — one sandbox, not independent parties).
  `ceremony_verify` reports `OK — chain verifies end to end` across all 4
  rounds and prints the final `delta_g1`/`delta_g2` and vk fingerprint.
  This is a mechanism demo, not a real ceremony — the single party running
  it holds the full toxic waste. The real ceremony still requires
  independent participants per `CEREMONY_SPEC.md`.
- The verifier actually verifies, confirmed three ways: (1) a flipped
  byte in `round_2.pk.bin` is caught by the params hash check; (2) a lie
  in `transcript.json` (claimed delta values swapped between rounds) is
  caught by the `entry_hash` chain; (3) the definitive test — a forged
  round where the delta/contribution points were replaced with other
  rounds' real, valid points and the hash chain recomputed to be
  internally self-consistent, so bookkeeping alone could not catch it —
  rejected by the **pairing-ratio check itself**
  (`"new delta_g1/delta_g2 are not old delta_g1/delta_g2 raised to the
  published contribution scalar"`), confirming the verification is
  cryptographic, not hash bookkeeping.
- `circuit/` builds clean (`setup`, `prove`, `verify_smoke`,
  `verify_prove2`, oracles). The full pipeline was run in a scratch dir:
  `setup` writes the keypair, `prove` emits a JSON proof, `verify_smoke`
  reports `false / true / false` for the inconsistent/consistent/tampered
  cases exactly as documented, and `verify_prove2` (second leaf,
  non-zero sibling, `is_right=true`) reports `true` with the forged
  nullifier rejected `false`. Every accept/reject claim in the README's
  circuit status row is now reproduced by actually running the compiled
  binaries.
- Note on test counts: `cargo test` reports 0 tests in both crates —
  the differential coverage this repo claims lives in the oracle
  binaries (`oracle_alphabeta`, `oracle_subgroup_jacobian`,
  `oracle_pin_fixture`) and the Motoko-side fixture harness
  (`verify_test`/`wire_export.json`), not in Rust unit tests, and the CI
  workflow exercises the pipeline bins with hard output assertions.

## Follow-up: CI

`.github/workflows/ci.yml` re-runs the verification claims on every
push/PR — the circuit verification pipeline (`setup → prove →
verify_smoke → verify_prove2`, with hard accept/reject assertions),
`cargo build`/tests for the `ceremony` crate, `dfx build` for the Motoko
side through `package_flags.sh` (which fails loudly if the pinned
base/core hashes drift from `mops.lock.json`), and a `replica-smoke` job
that deploys `title_registry` on a local replica and runs the leaf-update
regression (resubmit must keep the same `leafIndex` while `root` changes;
unknown property must return `null`). The first CI run doubles as the
ongoing re-check of the typecheck and replica results documented in the
Verified section above.
