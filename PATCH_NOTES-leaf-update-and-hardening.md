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
vendored verifier are still open in the sense that matters — see below for
exactly what was and wasn't done about each, and about CI.

### CI — actually added, not simulated

`.github/workflows/ci.yml` now exists and runs on every push/PR: builds
and tests both Rust crates, runs the full `setup → prove → verify_smoke →
verify_prove2` pipeline with hard accept/reject assertions, `dfx build`s
the Motoko side, and deploys to a real local replica to re-run the
leaf-update, throttle/anonymous, and upgrade-safety regressions from this
document. Every step was hand-validated against a real `dfx 0.32.0` +
bundled `moc 1.4.1`/`pocket-ic` in this session before being written into
the workflow — not written speculatively. (Getting `dfx` at all required
pulling its release tarball directly from
`github.com/dfinity/sdk/releases`, since the installer script's usual
host wasn't reachable from this sandbox; the workflow does the same.)

Also confirmed while doing this: `package_flags.sh`'s recorded provenance
hashes for `base`/`core` in `mops.lock.json` are independently
reproducible — pulled both packages fresh via `codeload.github.com` and
the bundled `node-motoko` core package, hashed them with the exact
algorithm `tree_hash()` in `package_flags.sh` uses, and both matched
byte-for-byte.

### Multi-party trusted setup — simulated end-to-end, not performed

`ceremony_init` → `ceremony_contribute` (×3, simulated participants) →
`ceremony_verify` were run for real in this session and the chain
verifies. Two tamper tests were run against the *real* verifier: (1)
flipping a byte in an intermediate round's proving-key file — caught
immediately via the file-hash check; (2) a harder test — forging round
2's public `delta_g1`/`delta_g2`/contribution values to a different
round's (valid-looking, well-formed) values, then *correctly
recomputing* the transcript's hash-chain fields so the bookkeeping layer
alone couldn't catch it — and `ceremony_verify` still rejected it, with
`"new delta_g1/delta_g2 are not old delta_g1/delta_g2 raised to the
published contribution scalar"`. That confirms the verifier is checking
the actual pairing relation between rounds, not just file/hash
bookkeeping.

**What this does and does not establish:** it proves the ceremony
tooling is mechanically correct and that forgery is actually detected —
genuinely useful, since untested crypto tooling is a real risk on its
own. It does **not** constitute a trusted setup, and it would be actively
misleading to represent it as progress toward one: every round in this
simulation was run by the same party (this session), which means a
single party holds the full transcript of "toxic waste" that the whole
point of a multi-party ceremony is to make no single party hold. Per
`CEREMONY_SPEC.md`, the security property here is structural — it comes
from real, independent, non-colluding participants each contributing
genuine private randomness and provably destroying it — and no amount of
running the same binaries in one sandbox can produce that property. This
item stays open until real participants run it.

### Independent audit — a supplementary adversarial pass was done, not an audit

A deeper review of the crypto-sensitive code was done as a genuine,
adversarial second look — but it does not satisfy this checklist item,
for two structural reasons: this reviewer already worked on this
codebase (not independent), and lacks the specialized cryptographic
audit tooling/process a real audit firm would bring (no substitute for
one). Flagging findings honestly rather than either skipping the check
or overstating what it is:

- `circuit/src/lib.rs`'s constraint logic was read end-to-end.
  `enforce_greater_than`'s range-check-based comparison gadget (used for
  `license_expiry > current_timestamp`) was hand-verified algebraically
  and checks out for the 64-bit range it's used at. Public-input
  allocation order in the circuit
  (`registry_id, merkle_root, purpose, request_nonce, current_timestamp,
  nullifier`) matches `main.mo`'s `verify()` order exactly — a mismatch
  here would be a silent, severe bug, and there isn't one. Domain
  separation tags are small distinct constants absorbed as the first
  Poseidon input in every hash role, consistent with the stated design.
- `Groth16Multi.mo`'s `verify`/`verifyWithFlat` validates proof points
  A, B, C (canonical encoding, on-curve, correct subgroup) before any
  pairing work, and reduces public inputs mod the scalar field order
  before the `vk_x` MSM (`inputs[i] % C.R`) — both are exactly the
  checks whose absence is a classic Groth16-verifier soundness bug
  class, and both are present. `TitleGroth16.mo` was confirmed to be a
  genuinely thin adapter with no cryptography of its own, as its own
  doc comment claims.
- Not reviewed in this pass: the ~4,000 remaining lines of vendored
  field/curve/pairing arithmetic (`Fp*.mo`, `Tower*.mo`, `Curve*.mo`,
  `Pairing*.mo`) — the differential tests already in the repo
  (`Groth16MultiTest.mo`, `verify_smoke`, `verify_prove2`) are the real
  coverage there, and this pass didn't re-derive or re-check that math
  independently.
- Already self-flagged by this codebase, and not re-litigated here:
  `poseidon_config()` in `circuit/src/lib.rs` generates Poseidon round
  constants at runtime rather than using fixed, published, reviewed
  parameters — the code's own comment says not to deploy with these as
  they are, and that's still accurate.

No vulnerabilities were found in the code actually reviewed. That is
meaningfully different from "this code has been audited" — treat it as
one more (careful) set of eyes, not as clearing this checklist item.

### One more gap closed along the way: `Groth16MultiTest.mo` actually run

That file's own header said it was "written and pinned against a real,
independently-computed oracle value, but NOT executed... that is the one
remaining honest gap in this patch's verification story" — its `run()`
was too expensive even for the JS-interpreted `moc` fallback used when
`dfx` isn't available. With real `dfx`/`pocket-ic` access in this
session, this got closed for real: `run()` itself turned out to exceed
even a real update call's instruction budget (~5x a single `verify()`'s
pairing work in one message), so it was split into six separate
messages — `groth16_test/main.mo`, deployed live — each costing about
what one real `TitleRegistry.verify()` call costs. All six passed on a
live replica:

```
prepareVk                              -> true
alphaBetaTargetMatchesOracle           -> true
validRawIntermediateMatchesOracle      -> true
forgedRawIntermediateMatchesOracle     -> true
acceptsValidProof                      -> true
rejectsForgedProof                     -> true
```

That's the alpha/beta precompute, both raw 3-pair Miller intermediates
(valid and forged), and the fully-assembled verifier's ACCEPT/REJECT
verdict, all independently byte-diffed against arkworks — for real, on a
real replica, not asserted. `.github/workflows/ci.yml`'s
`groth16-differential` job now re-runs this same six-call sequence on
every push/PR.

