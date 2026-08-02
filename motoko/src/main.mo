import HashMap "mo:base/HashMap";
import Nat "mo:base/Nat";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Int "mo:base/Int";
import Time "mo:base/Time";
import Timer "mo:base/Timer";
import Iter "mo:base/Iter";
import Array "mo:base/Array";
import Text "mo:base/Text";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Poseidon "./poseidon/Poseidon";
import Groth16 "./groth16/TitleGroth16";

/// Yaqeen's registry/challenge/nullifier logic, ported from the Node/Redis
/// backend onto canister stable state. Same three-step flow
/// (challenge -> prove -> verify), same server-authoritative public inputs,
/// same domain-separated hashing discipline — different substrate.
///
/// Proving happens off-canister (client-side, matching the reference ICP
/// project's model — the owner's device holds `owner_secret`, never the
/// canister). This canister issues challenges, verifies proofs, and tracks
/// nullifiers, mirroring `/challenge`, `/verify`, and the nullifier half of
/// Yaqeen's original three routes. `/prove` and `/admin/records` remain
/// off-canister concerns: `/prove`'s server-side custody model doesn't
/// belong in a canister meant to *not* hold owner secrets, and
/// `/admin/records`-equivalent writes happen via `submitRecord` below,
/// gated the same way.
///
/// SECURITY REVIEW ROUND 2 — fixes landed this pass (see
/// PATCH_NOTES-security-hardening.md for the full writeup):
///   1. `bootstrapAdmin` front-running/race — closed by additionally
///      requiring the caller be an actual canister controller, not just
///      "first caller wins."
///   2. Unbounded `challenges` growth — closed by a recurring timer that
///      prunes expired entries.
///   3. Unauthenticated cycles-drain via `verify`/`requestChallenge` (an
///      attacker can self-issue a challenge, then submit a garbage proof
///      to force a full ~21B-instruction pairing check, repeatedly, for
///      free) — mitigated by rejecting the anonymous principal and a
///      per-principal minimum-interval throttle on both entry points.
///      NOTE ON RESIDUAL RISK: this raises the cost of the attack (an
///      attacker needs many distinct, non-anonymous principals to
///      parallelize it) but does not eliminate it — Sybil identities are
///      still cheap to generate. It is not a substitute for the P3
///      "operational hygiene" monitoring the roadmap already calls for
///      (alerting on abnormal verify-failure/challenge-issuance rates).
///      A cycles-payment gate was considered and rejected: ingress calls
///      from a plain user agent (dfx/ic-agent) cannot attach cycles to a
///      call at all — only canister-to-canister calls can — so a cycles
///      gate here would lock out every direct end-user call.
///   4. VK-rotation gap ("what happens to challenges issued under the old
///      key when it rotates") — closed by stamping each challenge with the
///      verifying-key version live at issuance time and rejecting `verify`
///      if the key has since rotated, forcing a fresh challenge under the
///      new key instead of silently using whichever key happens to be
///      cached when `verify` runs.

persistent actor TitleRegistry {

  // Simple, collision-safe-enough Nat -> Nat32 hash for HashMap keys, via
  // the text representation (avoids relying on `**` overflow semantics).
  func natHash(n : Nat) : Nat32 { Text.hash(Nat.toText(n)) };

  // ---- admin allow-list ----
  //
  // FIXED (round 2): `bootstrapAdmin` used to be racy — "first caller
  // wins" is not a real access-control gate once the canister id is
  // public, which happens the moment the canister is created (often
  // before code is even installed, depending on tooling). It is now
  // additionally gated on `Principal.isController`, which is a property
  // nobody but the canister's actual controllers (set at `dfx canister
  // create` time, off-chain, before this code ever runs) can satisfy —
  // so racing to call it first no longer helps an attacker who isn't
  // already a controller. This closes the window completely without
  // needing an actor-class constructor argument (which would additionally
  // require every `dfx canister install --mode upgrade` to keep passing a
  // matching `--argument`, a footgun of its own).
  var adminsEntries : [(Principal, ())] = [];
  transient let admins = HashMap.fromIter<Principal, ()>(adminsEntries.vals(), 10, Principal.equal, Principal.hash);

  func isAdmin(p : Principal) : Bool { admins.get(p) != null };

  /// One-time bootstrap: succeeds only while there are no admins yet, AND
  /// only for an actual controller of this canister.
  public shared (msg) func bootstrapAdmin(realAdmin : Principal) : async Result.Result<(), Text> {
    if (admins.size() > 0) { return #err("admins already bootstrapped — use addAdmin instead") };
    if (not Principal.isController(msg.caller)) {
      return #err("unauthorized — only a canister controller may bootstrap the admin set");
    };
    admins.put(realAdmin, ());
    #ok(());
  };

  /// Governed: any current admin can add another principal to the allow-list.
  public shared (msg) func addAdmin(newAdmin : Principal) : async Result.Result<(), Text> {
    if (not isAdmin(msg.caller)) { return #err("unauthorized") };
    admins.put(newAdmin, ());
    #ok(());
  };

  /// Governed: any current admin can remove another — but never the last one.
  public shared (msg) func removeAdmin(oldAdmin : Principal) : async Result.Result<(), Text> {
    if (not isAdmin(msg.caller)) { return #err("unauthorized") };
    if (admins.size() <= 1) { return #err("cannot remove the last remaining admin") };
    admins.delete(oldAdmin);
    #ok(());
  };

  let treeDepth : Nat = 25;

  // ---- registry state ----

  type Record = {
    propertyId : Nat;
    ownerCommitment : Nat; // Poseidon(domain_owner, owner_secret, property_id) — backend never learns owner_secret
    encumbranceFlag : Nat;
    licenseStatus : Nat;
    licenseExpiry : Nat;
  };

  let registryId : Nat = 1;
  var recordsEntries : [(Nat, Record)] = [];
  transient let records = HashMap.fromIter<Nat, Record>(recordsEntries.vals(), 100, Nat.equal, natHash);

  func computeZeroHashes(depth : Nat) : [Nat] {
    let buf = Array.init<Nat>(depth + 1, 0);
    buf[0] := 0; // empty leaf
    var i = 1;
    while (i <= depth) {
      buf[i] := Poseidon.hash(Poseidon.fromNat(4 /* DOMAIN_NODE */), [buf[i - 1], buf[i - 1]]);
      i += 1;
    };
    Array.freeze(buf);
  };

  func nodeKey(level : Nat, index : Nat) : Text {
    Nat.toText(level) # ":" # Nat.toText(index)
  };

  // Precomputed "zero hash" per level of an empty sparse Merkle tree, plus
  // filled nodes keyed by (level, index) — same O(depth)-per-write discipline
  // as Yaqeen's `merkleTree.ts`, just backed by canister stable memory
  // instead of an in-process JS object.
  let zeroHashes : [Nat] = computeZeroHashes(treeDepth);
  var nodesEntries : [(Text, Nat)] = [];
  transient let nodes = HashMap.fromIter<Text, Nat>(nodesEntries.vals(), 1000, Text.equal, Text.hash);
  var currentRoot : Nat = zeroHashes[treeDepth];
  var nextLeafIndex : Nat = 0;

  func nodeAt(level : Nat, index : Nat) : Nat {
    switch (nodes.get(nodeKey(level, index))) {
      case (?v) v;
      case null zeroHashes[level];
    };
  };

  func leafHash(r : Record) : Nat {
    Poseidon.hash(
      Poseidon.fromNat(1 /* DOMAIN_LEAF */),
      [registryId, r.ownerCommitment, r.encumbranceFlag, r.licenseStatus, r.licenseExpiry],
    );
  };

  /// O(depth) incremental insert — matches Yaqeen's `merkleTree.ts` contract:
  /// this is the only place `currentRoot` changes.
  func insertLeaf(index : Nat, leaf : Nat) {
    nodes.put(nodeKey(0, index), leaf);
    var idx = index;
    var level = 0;
    var cur = leaf;
    while (level < treeDepth) {
      let pairBase = (idx / 2) * 2; // even index of this pair, no subtraction needed
      let siblingIndex = if (idx == pairBase) pairBase + 1 else pairBase;
      let sibling = nodeAt(level, siblingIndex);
      let (l, r) = if (idx % 2 == 0) (cur, sibling) else (sibling, cur);
      cur := Poseidon.hash(Poseidon.fromNat(4 /* DOMAIN_NODE */), [l, r]);
      idx := idx / 2;
      level += 1;
      nodes.put(nodeKey(level, idx), cur);
    };
    currentRoot := cur;
  };

  /// Internal back-office write — the `submitRecord`/`/admin/records`
  /// equivalent. In production this must sit behind real caller
  /// authentication (an admin principal allow-list is the floor; an
  /// authenticated registry-department identity is the real target),
  /// exactly as Yaqeen's README calls out for its own `/admin/records`.
  public shared (msg) func submitRecord(
    propertyId : Nat,
    ownerCommitment : Nat,
    encumbranceFlag : Nat,
    licenseStatus : Nat,
    licenseExpiry : Nat,
  ) : async Result.Result<Nat, Text> {
    if (not isAdmin(msg.caller)) {
      return #err("unauthorized — see production checklist: gate this behind real admin auth");
    };
    let record : Record = {
      propertyId; ownerCommitment; encumbranceFlag; licenseStatus; licenseExpiry;
    };
    records.put(propertyId, record);
    let leaf = leafHash(record);
    insertLeaf(nextLeafIndex, leaf);
    nextLeafIndex += 1;
    #ok(currentRoot);
  };

  // ---- anti-spam: reject anonymous callers + per-principal throttle ----
  //
  // FIXED (round 2): `requestChallenge` and `verify` used to be reachable
  // by anyone, including the anonymous principal shared by every
  // unauthenticated agent. `verify` in particular can be forced through
  // its full ~21B-instruction pairing check for free: an attacker can
  // self-issue a matching challenge via `requestChallenge`, then submit a
  // garbage 192-byte proof against it — the cheap checks (challenge
  // lookup, public-input match, nullifier lookup) all pass, so the
  // canister pays the full verification cost before rejecting it. Under
  // ICP's reverse-gas model that cost is the canister's own cycles, not
  // the caller's, and it's repeatable at will. Rejecting anonymous callers
  // plus a minimum interval between calls per principal doesn't make this
  // free for an attacker with many identities, but it means every attempt
  // now costs the attacker a distinct, addressable principal instead of
  // being literally free and untraceable — a real increase in attack cost,
  // not a complete fix. Pair this with off-canister monitoring (roadmap
  // P3) for anything that looks like a real attack in progress.

  transient let MIN_CHALLENGE_INTERVAL_NS : Int = 2_000_000_000; // 2s
  transient let MIN_VERIFY_INTERVAL_NS : Int = 5_000_000_000; // 5s
  transient let RATE_LIMIT_ENTRY_TTL_NS : Int = 3_600_000_000_000; // 1h — stale entries are pruned, see below

  var lastChallengeCallEntries : [(Principal, Int)] = [];
  transient let lastChallengeCall = HashMap.fromIter<Principal, Int>(lastChallengeCallEntries.vals(), 100, Principal.equal, Principal.hash);
  var lastVerifyCallEntries : [(Principal, Int)] = [];
  transient let lastVerifyCall = HashMap.fromIter<Principal, Int>(lastVerifyCallEntries.vals(), 100, Principal.equal, Principal.hash);

  /// Returns an error message if the caller should be throttled, else
  /// records this call's timestamp and allows it through.
  func checkAndRecordRateLimit(store : HashMap.HashMap<Principal, Int>, caller : Principal, minIntervalNs : Int) : ?Text {
    if (Principal.isAnonymous(caller)) {
      return ?"anonymous callers are not permitted for this operation";
    };
    let now = Time.now();
    switch (store.get(caller)) {
      case (?last) {
        if (now - last < minIntervalNs) {
          return ?"rate limit: please wait before retrying";
        };
      };
      case null {};
    };
    store.put(caller, now);
    null;
  };

  // ---- challenge store ----
  // Server-issued, short-lived, single-use — every security-relevant public
  // input pinned here, never accepted from the caller on the way in. Same
  // rule Yaqeen's README calls "the single most exploitable mistake an
  // integration like this can make" if skipped.

  type Challenge = {
    registryId : Nat;
    merkleRoot : Nat;
    purpose : Nat;
    requestNonce : Nat;
    currentTimestamp : Nat;
    expiresAt : Int;
    consumed : Bool;
    vkVersion : Nat;
  };

  var challengeEntries : [(Nat, Challenge)] = [];
  transient let challenges = HashMap.fromIter<Nat, Challenge>(challengeEntries.vals(), 100, Nat.equal, natHash);
  var nextChallengeId : Nat = 0;
  var nextNonce : Nat = 0;

  transient let CHALLENGE_TTL_NS : Int = 5 * 60 * 1_000_000_000; // 5 minutes

  public shared (msg) func requestChallenge(purpose : Nat) : async Result.Result<{ challengeId : Nat; registryId : Nat; merkleRoot : Nat; purpose : Nat; requestNonce : Nat; currentTimestamp : Nat; expiresAt : Int }, Text> {
    switch (checkAndRecordRateLimit(lastChallengeCall, msg.caller, MIN_CHALLENGE_INTERVAL_NS)) {
      case (?err) return #err(err);
      case null {};
    };
    let id = nextChallengeId;
    nextChallengeId += 1;
    let nonce = nextNonce;
    nextNonce += 1;
    let now = Time.now();
    let ts = Nat64.toNat(Nat64.fromIntWrap(now / 1_000_000_000));
    let challenge : Challenge = {
      registryId;
      merkleRoot = currentRoot;
      purpose;
      requestNonce = nonce;
      currentTimestamp = ts;
      expiresAt = now + CHALLENGE_TTL_NS;
      consumed = false;
      vkVersion = currentVkVersion;
    };
    challenges.put(id, challenge);
    #ok({
      challengeId = id;
      registryId = challenge.registryId;
      merkleRoot = challenge.merkleRoot;
      purpose = challenge.purpose;
      requestNonce = challenge.requestNonce;
      currentTimestamp = challenge.currentTimestamp;
      expiresAt = challenge.expiresAt;
    });
  };

  // ---- nullifier store ----
  // Canister stable state gives us for free what Yaqeen's backend needed
  // Redis + Lua scripts for: atomic, cross-replica-consistent claim, because
  // there is only one canister and update calls are sequential.

  var spentNullifiers : [(Nat, Bool)] = [];
  transient let nullifiers = HashMap.fromIter<Nat, Bool>(spentNullifiers.vals(), 100, Nat.equal, natHash);

  // ---- verifying key ----
  // Stored as its arkworks-compressed hex encoding (stable — plain Text
  // round-trips upgrades trivially); the expensive parsed+validated+
  // prepared form is cached in a transient var, matching the vendored
  // verifier's own "FlatVk ... transient cache, invalidated at every vk
  // write site" pattern (see vendor/Groth16Multi.mo's doc comments).
  //
  // FIXED (round 2): `currentVkVersion` increments on every
  // `setVerifyingKey` call and is stamped onto each `Challenge` at
  // issuance. `verify` now rejects a proof against a challenge whose
  // `vkVersion` no longer matches the live key instead of silently
  // verifying it against whatever key happens to be cached when `verify`
  // runs — closing the "what happens to challenges issued under the old
  // VK" gap the roadmap flagged under P3 operational hygiene.

  var vkHex : ?Text = null;
  transient var preparedVkCache : ?Groth16.PreparedVk = null;
  var currentVkVersion : Nat = 0;

  /// Admin-only: register (or replace) the verifying key. Run once per
  /// circuit version, never per proof. Rejects malformed/invalid keys
  /// (bad encoding, off-curve points, points outside the r-torsion
  /// subgroup) rather than caching something unusable.
  public shared (msg) func setVerifyingKey(hex : Text) : async Result.Result<(), Text> {
    if (not isAdmin(msg.caller)) return #err("unauthorized");
    switch (Groth16.parseAndPrepareVk(hex)) {
      case (null) { #err("invalid verifying key encoding or contents") };
      case (?prepared) {
        vkHex := ?hex;
        preparedVkCache := ?prepared;
        currentVkVersion += 1;
        #ok(());
      };
    };
  };

  func getPreparedVk() : ?Groth16.PreparedVk {
    switch (preparedVkCache) {
      case (?vk) { ?vk };
      case null {
        switch (vkHex) {
          case (null) { null };
          case (?hex) {
            let parsed = Groth16.parseAndPrepareVk(hex);
            preparedVkCache := parsed;
            parsed;
          };
        };
      };
    };
  };


  // ---- verify ----

  public shared (msg) func verify(
    challengeId : Nat,
    proofBytes : Blob, // 192 bytes: A:G1(48) ‖ B:G2(96) ‖ C:G1(48), arkworks-compressed
    publicInputs : [Nat], // [registry_id, merkle_root, purpose, request_nonce, current_timestamp, nullifier]
  ) : async Result.Result<{ nullifier : Nat }, Text> {
    switch (checkAndRecordRateLimit(lastVerifyCall, msg.caller, MIN_VERIFY_INTERVAL_NS)) {
      case (?err) return #err(err);
      case null {};
    };

    let challenge = switch (challenges.get(challengeId)) {
      case (?c) c;
      case null return #err("unknown or expired challenge");
    };
    if (challenge.consumed) return #err("challenge already consumed");
    if (Time.now() > challenge.expiresAt) return #err("challenge expired");
    if (challenge.vkVersion != currentVkVersion) {
      return #err("verifying key has rotated since this challenge was issued — request a new challenge");
    };

    // Public inputs must match the ORIGINAL issued challenge exactly, checked
    // BEFORE any cryptographic verification — same ordering Yaqeen's
    // `proofService.ts` calls load-bearing, for the same reason: skip this
    // and an attacker can build a fabricated one-leaf tree and pass off a
    // proof against it as real.
    if (publicInputs.size() != 6) return #err("wrong public input count");
    if (publicInputs[0] != challenge.registryId) return #err("registry_id mismatch");
    if (publicInputs[1] != challenge.merkleRoot) return #err("merkle_root mismatch");
    if (publicInputs[2] != challenge.purpose) return #err("purpose mismatch");
    if (publicInputs[3] != challenge.requestNonce) return #err("request_nonce mismatch");
    if (publicInputs[4] != challenge.currentTimestamp) return #err("current_timestamp mismatch");

    let nullifier = publicInputs[5];
    switch (nullifiers.get(nullifier)) {
      case (?true) return #err("nullifier already spent");
      case _ {};
    };

    let vk = switch (getPreparedVk()) {
      case (null) return #err("no verifying key configured");
      case (?vk) vk;
    };

    switch (Groth16.verifyWithReason(vk, proofBytes, publicInputs)) {
      case (#err(reason)) return #err("invalid proof: " # reason);
      case (#ok) {};
    };

    // mark consumed / spent only after a passing verification
    challenges.put(challengeId, { challenge with consumed = true });
    nullifiers.put(nullifier, true);

    #ok({ nullifier });
  };

  // ---- state hygiene: prune expired challenges & stale rate-limit entries ----
  //
  // FIXED (round 2): nothing used to remove consumed/expired entries from
  // `challenges`, so `requestChallenge` — fully public, no admin gate —
  // grew the map without bound. Beyond enabling the cycles-drain issue
  // above, unbounded growth also risks `preupgrade`/`postupgrade` (which
  // serialize the whole map to an array) eventually running into
  // per-message instruction limits on upgrade. A recurring timer sweeps
  // expired challenges and stale rate-limit bookkeeping every 5 minutes.
  // Timers are not persisted across upgrades (a Motoko/IC property, not a
  // bug here), so `postupgrade` re-arms it.

  transient let PRUNE_INTERVAL_SECONDS : Nat = 300; // 5 minutes
  transient let MAX_PRUNE_PER_TICK : Nat = 500; // bound the work done in one heartbeat-scale call

  func pruneExpiredChallenges() : async () {
    let now = Time.now();
    var removed = 0;
    label sweep for ((id, c) in challenges.entries()) {
      if (removed >= MAX_PRUNE_PER_TICK) break sweep;
      if (now > c.expiresAt) {
        challenges.delete(id);
        removed += 1;
      };
    };
    var rlRemoved = 0;
    label sweepRl1 for ((p, t) in lastChallengeCall.entries()) {
      if (rlRemoved >= MAX_PRUNE_PER_TICK) break sweepRl1;
      if (now - t > RATE_LIMIT_ENTRY_TTL_NS) {
        lastChallengeCall.delete(p);
        rlRemoved += 1;
      };
    };
    var rlRemoved2 = 0;
    label sweepRl2 for ((p, t) in lastVerifyCall.entries()) {
      if (rlRemoved2 >= MAX_PRUNE_PER_TICK) break sweepRl2;
      if (now - t > RATE_LIMIT_ENTRY_TTL_NS) {
        lastVerifyCall.delete(p);
        rlRemoved2 += 1;
      };
    };
  };

  transient var pruneTimerId : ?Timer.TimerId = null;

  func armPruneTimer<system>() {
    pruneTimerId := ?Timer.recurringTimer<system>(#seconds PRUNE_INTERVAL_SECONDS, pruneExpiredChallenges);
  };

  armPruneTimer<system>();

  // ---- upgrade hooks ----

  system func preupgrade() {
    adminsEntries := Iter.toArray(admins.entries());
    recordsEntries := Iter.toArray(records.entries());
    nodesEntries := Iter.toArray(nodes.entries());
    challengeEntries := Iter.toArray(challenges.entries());
    spentNullifiers := Iter.toArray(nullifiers.entries());
    lastChallengeCallEntries := Iter.toArray(lastChallengeCall.entries());
    lastVerifyCallEntries := Iter.toArray(lastVerifyCall.entries());
  };

  system func postupgrade() {
    adminsEntries := [];
    recordsEntries := [];
    nodesEntries := [];
    challengeEntries := [];
    spentNullifiers := [];
    lastChallengeCallEntries := [];
    lastVerifyCallEntries := [];
    armPruneTimer<system>();
  };

};
