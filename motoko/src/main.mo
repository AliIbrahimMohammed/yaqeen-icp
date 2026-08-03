import HashMap "mo:base/HashMap";
import Nat "mo:base/Nat";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Time "mo:base/Time";
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

persistent actor TitleRegistry {

  // Simple, collision-safe-enough Nat -> Nat32 hash for HashMap keys, via
  // the text representation (avoids relying on `**` overflow semantics).
  func natHash(n : Nat) : Nat32 { Text.hash(Nat.toText(n)) };

  // FIXED (was a hardcoded "aaaaa-aa" placeholder — the IC management
  // canister's well-known principal, not a real admin identity).
  //
  // This build of `moc` doesn't parse constructor arguments on a plain
  // `actor` (that needs `actor class ... = this { }`, a bigger structural
  // change not attempted here), so the real fix is a one-time bootstrap
  // sentinel instead: no admins exist until `bootstrapAdmin` is called once,
  // then admin status is a real multi-principal allow-list (not a single
  // hardcoded/rotatable-only identity) — any current admin can add or
  // remove another, but the last remaining admin can never be removed
  // (that would permanently brick every admin-gated function).
  //
  // OPERATIONAL REQUIREMENT: call `bootstrapAdmin` with the real admin
  // principal immediately after deploy, in the same deploy script/session,
  // BEFORE the canister id is shared or any other call is made — the same
  // "init then lock" discipline a constructor argument would have given
  // you for free, just enforced by a runtime check instead of the type
  // system. Until `bootstrapAdmin` is called, `submitRecord`/`setVerifyingKey`/
  // `addAdmin`/`removeAdmin` are unreachable by anyone (there are no admins
  // yet), so there is no window where an attacker can act AS admin — only a
  // window where the real admin hasn't claimed the role yet.
  var adminsEntries : [(Principal, ())] = [];
  transient let admins = HashMap.fromIter<Principal, ()>(adminsEntries.vals(), 10, Principal.equal, Principal.hash);

  func isAdmin(p : Principal) : Bool { admins.get(p) != null };

  /// One-time bootstrap: succeeds only while there are no admins yet.
  public shared func bootstrapAdmin(realAdmin : Principal) : async Result.Result<(), Text> {
    if (admins.size() > 0) { return #err("admins already bootstrapped — use addAdmin instead") };
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
  };

  var challengeEntries : [(Nat, Challenge)] = [];
  transient let challenges = HashMap.fromIter<Nat, Challenge>(challengeEntries.vals(), 100, Nat.equal, natHash);
  var nextChallengeId : Nat = 0;
  var nextNonce : Nat = 0;

  transient let CHALLENGE_TTL_NS : Int = 5 * 60 * 1_000_000_000; // 5 minutes

  public shared func requestChallenge(purpose : Nat) : async { challengeId : Nat; registryId : Nat; merkleRoot : Nat; purpose : Nat; requestNonce : Nat; currentTimestamp : Nat; expiresAt : Int } {
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
    };
    challenges.put(id, challenge);
    {
      challengeId = id;
      registryId = challenge.registryId;
      merkleRoot = challenge.merkleRoot;
      purpose = challenge.purpose;
      requestNonce = challenge.requestNonce;
      currentTimestamp = challenge.currentTimestamp;
      expiresAt = challenge.expiresAt;
    };
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

  var vkHex : ?Text = null;
  transient var preparedVkCache : ?Groth16.PreparedVk = null;

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

  public shared func verify(
    challengeId : Nat,
    proofBytes : Blob, // 192 bytes: A:G1(48) ‖ B:G2(96) ‖ C:G1(48), arkworks-compressed
    publicInputs : [Nat], // [registry_id, merkle_root, purpose, request_nonce, current_timestamp, nullifier]
  ) : async Result.Result<{ nullifier : Nat }, Text> {
    let challenge = switch (challenges.get(challengeId)) {
      case (?c) c;
      case null return #err("unknown or expired challenge");
    };
    if (challenge.consumed) return #err("challenge already consumed");
    if (Time.now() > challenge.expiresAt) return #err("challenge expired");

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

  // ---- upgrade hooks ----

  system func preupgrade() {
    adminsEntries := Iter.toArray(admins.entries());
    recordsEntries := Iter.toArray(records.entries());
    nodesEntries := Iter.toArray(nodes.entries());
    challengeEntries := Iter.toArray(challenges.entries());
    spentNullifiers := Iter.toArray(nullifiers.entries());
  };

  system func postupgrade() {
    adminsEntries := [];
    recordsEntries := [];
    nodesEntries := [];
    challengeEntries := [];
    spentNullifiers := [];
  };

};
