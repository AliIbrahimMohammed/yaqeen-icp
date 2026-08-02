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
///
/// SECURITY ROUND 3 (see PATCH_NOTES-security-round3.md):
///   - bootstrapAdmin is gated to the canister's CONTROLLER (management
///     canister), closing the first-come-first-served takeover race on
///     fresh deploys; fails closed if the management canister is
///     unreachable.
///   - submitRecord validates every field (canonical commitment, flags in
///     {0,1}, expiry in (now, 2^64), nonzero propertyId) and records
///     provenance (submittedBy, submittedAt) — no more silently-unprovable
///     or non-canonical records, and forged records are attributable.
///   - Verifying-key REPLACEMENTS require a second admin to confirm
///     (staged + confirmed by a different admin); the first VK on a fresh
///     deploy activates immediately (deploy-ceremony path).
///   - requestChallenge is capped (no unbounded state growth) and sweeps
///     expired challenges opportunistically (bounded cost per call).
///   - verify() records the caller; every privileged mutation and every
///     accepted verification lands in a capped, queryable audit log.
///   - Read-only transparency APIs: getCurrentRoot, getRecord,
///     getChallenge, getVkStatus, getAuditLog, getStats.

persistent actor TitleRegistry {

  // Simple, collision-safe-enough Nat -> Nat32 hash for HashMap keys, via
  // the text representation (avoids relying on `**` overflow semantics).
  func natHash(n : Nat) : Nat32 { Text.hash(Nat.toText(n)) };

  // ---- audit log ----
  // Capped append-only log of privileged actions and accepted
  // verifications. Purely informative state (never load-bearing for
  // security checks), so a full log can only over-report, never
  // under-enforce.

  type AuditEntry = {
    at : Int;
    caller : Principal;
    action : Text;
    detail : Text;
  };

  let MAX_AUDIT_ENTRIES : Nat = 1000;
  var auditEntries : [AuditEntry] = [];

  func logAudit(caller : Principal, action : Text, detail : Text) {
    let next = Array.append<AuditEntry>(auditEntries, [
      { at = Time.now(); caller; action; detail },
    ]);
    auditEntries := if (next.size() > MAX_AUDIT_ENTRIES) {
      Array.subArray<AuditEntry>(next, next.size() - MAX_AUDIT_ENTRIES, MAX_AUDIT_ENTRIES);
    } else { next };
  };

  // ---- admin allow-list ----
  // Multi-principal allow-list, seeded exactly once, governed thereafter by
  // existing admins, never removable to an empty list. History: hardcoded
  // "aaaaa-aa" placeholder -> one-time bootstrap sentinel -> allow-list
  // (round 2). Round 3 adds the controller gate on the bootstrap itself.

  var admins : [Principal] = [];

  func isAdmin(p : Principal) : Bool {
    for (a in admins.vals()) {
      if (a == p) return true;
    };
    false;
  };

  // Bootstrap authorization oracle. PRODUCTION behavior: the caller must be
  // one of the canister's controllers (the deploying identity) — an
  // attacker watching the network can no longer front-run bootstrapAdmin on
  // a fresh deploy, because they are not the controller. Fails closed if
  // the management canister is unreachable (only possible off the IC or in
  // a broken environment; the registry then simply stays un-bootstrapped).
  //
  // TEST-ONLY STUB: the node-motoko interpreter cannot make canister calls
  // (the await on "aaaaa-aa" hard-crashes the interpreter, uncatchable), so
  // node-tests/tests.js rewrites the body between the @stub markers to a
  // constant (`true` / `false`) to simulate a controller-authorized or
  // unauthorized environment. The pristine production source (typechecked
  // in stage 1) is never modified.
  let management : actor {
    get_canister_controllers : shared { canister_id : Principal } -> async { controllers : [Principal] };
  } = actor "aaaaa-aa";

  func bootstrapAuthorized(caller : Principal) : async Bool {
    // @stub-start
    try {
      let { controllers } = await management.get_canister_controllers({
        canister_id = Principal.fromActor(TitleRegistry);
      });
      var found = false;
      for (c in controllers.vals()) {
        if (c == caller) { found := true };
      };
      found;
    } catch (_) {
      // Fail closed: an unreachable management canister must never open
      // the bootstrap to arbitrary callers.
      false;
    };
    // @stub-end
  };

  /// One-time bootstrap: succeeds only while the allow-list is still empty,
  /// and only for a canister controller (see bootstrapAuthorized).
  public shared (msg) func bootstrapAdmin(realAdmin : Principal) : async Result.Result<(), Text> {
    if (admins.size() > 0) {
      return #err("admins already set — use addAdmin instead");
    };
    if (not (await bootstrapAuthorized(msg.caller))) {
      return #err("only a canister controller may bootstrap the registry");
    };
    admins := [realAdmin];
    logAudit(msg.caller, "bootstrap", Principal.toText(realAdmin));
    #ok(());
  };

  /// Governed path: any current admin can grant admin to a new principal.
  public shared (msg) func addAdmin(newAdmin : Principal) : async Result.Result<(), Text> {
    if (not isAdmin(msg.caller)) { return #err("unauthorized") };
    if (isAdmin(newAdmin)) { return #err("already an admin") };
    admins := Array.append<Principal>(admins, [newAdmin]);
    logAudit(msg.caller, "addAdmin", Principal.toText(newAdmin));
    #ok(());
  };

  /// Governed path: any current admin can revoke admin (but never the last
  /// one — the registry must always stay administered).
  public shared (msg) func removeAdmin(target : Principal) : async Result.Result<(), Text> {
    if (not isAdmin(msg.caller)) { return #err("unauthorized") };
    if (admins.size() <= 1) { return #err("cannot remove the last admin") };
    if (not isAdmin(target)) { return #err("not an admin") };
    admins := Array.filter<Principal>(admins, func (p : Principal) : Bool { p != target });
    logAudit(msg.caller, "removeAdmin", Principal.toText(target));
    #ok(());
  };

  /// Read-only: current allow-list (operational visibility).
  public shared query func listAdmins() : async [Principal] { admins };

  let treeDepth : Nat = 25;

  // ---- registry state ----

  type Record = {
    propertyId : Nat;
    ownerCommitment : Nat; // Poseidon(domain_owner, owner_secret, property_id) — backend never learns owner_secret
    encumbranceFlag : Nat; // 0 = unencumbered (only provable value in-circuit)
    licenseStatus : Nat; // 1 = active (only provable value in-circuit)
    licenseExpiry : Nat; // seconds, must be > current_timestamp and < 2^64
    // Provenance (round 3): who wrote this record and when — the
    // attribution a fraud investigation needs. NOT part of the Merkle
    // leaf (leafHash hashes only the five registry values above).
    submittedBy : Principal;
    submittedAt : Int;
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
  /// equivalent, admin-gated with per-record provenance and full field
  /// validation (round 3): nothing that the circuit can never prove (or
  /// that would silently wrap mod r) may enter the registry.
  public shared (msg) func submitRecord(
    propertyId : Nat,
    ownerCommitment : Nat,
    encumbranceFlag : Nat,
    licenseStatus : Nat,
    licenseExpiry : Nat,
  ) : async Result.Result<Nat, Text> {
    if (not isAdmin(msg.caller)) {
      return #err("unauthorized");
    };
    if (propertyId == 0) { return #err("propertyId must be nonzero") };
    if (ownerCommitment >= Poseidon.MODULUS) {
      return #err("ownerCommitment must be canonical (below the Fr modulus)");
    };
    if (encumbranceFlag != 0 and encumbranceFlag != 1) {
      return #err("encumbranceFlag must be 0 or 1 (0 is the only provable value)");
    };
    if (licenseStatus != 0 and licenseStatus != 1) {
      return #err("licenseStatus must be 0 or 1 (1 is the only provable value)");
    };
    let nowSec = Nat64.toNat(Nat64.fromIntWrap(Time.now() / 1_000_000_000));
    if (licenseExpiry <= nowSec) {
      return #err("licenseExpiry must be in the future");
    };
    if (licenseExpiry >= (2 ** 64)) {
      return #err("licenseExpiry must fit in 64 bits (the circuit's range check)");
    };
    let record : Record = {
      propertyId;
      ownerCommitment;
      encumbranceFlag;
      licenseStatus;
      licenseExpiry;
      submittedBy = msg.caller;
      submittedAt = Time.now();
    };
    records.put(propertyId, record);
    let leaf = leafHash(record);
    insertLeaf(nextLeafIndex, leaf);
    nextLeafIndex += 1;
    logAudit(msg.caller, "submitRecord", Nat.toText(propertyId) # " idx=" # Nat.toText(nextLeafIndex - 1));
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

  type ChallengeInfo = {
    challengeId : Nat;
    registryId : Nat;
    merkleRoot : Nat;
    purpose : Nat;
    requestNonce : Nat;
    currentTimestamp : Nat;
    expiresAt : Int;
  };

  var challengeEntries : [(Nat, Challenge)] = [];
  transient let challenges = HashMap.fromIter<Nat, Challenge>(challengeEntries.vals(), 100, Nat.equal, natHash);
  var nextChallengeId : Nat = 0;
  var nextNonce : Nat = 0;

  transient let CHALLENGE_TTL_NS : Int = 5 * 60 * 1_000_000_000; // 5 minutes

  // Round 3: bounded outstanding challenges + opportunistic expiry sweep.
  // Challenges are public and free to issue, so without a cap an attacker
  // could grow canister state (and storage costs) without bound.
  let MAX_PENDING_CHALLENGES : Nat = 500;
  let SWEEP_BUDGET : Nat = 256; // expired entries removed per call, max

  /// Issue a challenge bound to the current Merkle root. Returns an error
  /// when too many challenges are already outstanding (the caller should
  /// reuse an existing one or wait for expiry).
  public shared func requestChallenge(purpose : Nat) : async Result.Result<ChallengeInfo, Text> {
    // Bounded opportunistic sweep of expired challenges.
    var swept : Nat = 0;
    var expired : [Nat] = [];
    let now = Time.now();
    for ((id, c) in challenges.entries()) {
      if (swept >= SWEEP_BUDGET) { break };
      if (now > c.expiresAt) {
        expired := Array.append<Nat>(expired, [id]);
        swept += 1;
      };
    };
    for (id in expired.vals()) {
      challenges.delete(id);
    };

    // Cap on outstanding (unexpired, unconsumed) challenges.
    var pending : Nat = 0;
    let now2 = Time.now();
    for ((_, c) in challenges.entries()) {
      if (not c.consumed and now2 <= c.expiresAt) { pending += 1 };
    };
    if (pending >= MAX_PENDING_CHALLENGES) {
      return #err("too many pending challenges — reuse an existing one or wait for expiry");
    };

    let id = nextChallengeId;
    nextChallengeId += 1;
    let nonce = nextNonce;
    nextNonce += 1;
    let issuedAt = Time.now();
    let ts = Nat64.toNat(Nat64.fromIntWrap(issuedAt / 1_000_000_000));
    let challenge : Challenge = {
      registryId;
      merkleRoot = currentRoot;
      purpose;
      requestNonce = nonce;
      currentTimestamp = ts;
      expiresAt = issuedAt + CHALLENGE_TTL_NS;
      consumed = false;
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
  // Stored as its raw arkworks-compressed hex encoding (stable — plain Text
  // round-trips upgrades trivially); the expensive parsed+validated+
  // prepared form is cached in a transient var, matching the vendored
  // verifier's own "FlatVk ... transient cache, invalidated at every vk
  // write site" pattern (see vendor/Groth16Multi.mo's doc comments).
  //
  // Round 3: REPLACEMENTS are staged and must be confirmed by a DIFFERENT
  // admin (threshold-2), so a single compromised admin cannot silently swap
  // the verifying key for one they hold the proving key to. The first VK on
  // a fresh deploy activates immediately — the deploy-ceremony path.
  //
  // TEST-ONLY STUB: full VK validation costs a pairing (subgroup checks +
  // the alpha/beta target), which the node-motoko interpreter cannot run
  // (same step budget that makes real verify untestable there — a full
  // pairing run was killed after 17 minutes). tests.js rewrites the body of
  // parseVkForActivation between the @stub markers to return a fabricated
  // PreparedVk so the staging/activation LOGIC is exercised without the
  // pairing. Deployed (unstubbed) behavior is unchanged: every VK still
  // goes through Groth16.parseAndPrepareVk (full arkworks-equivalent
  // validation) before activation.

  var vkHex : ?Text = null;
  var pendingVk : ?{ hex : Text; proposedBy : Principal } = null;
  transient var preparedVkCache : ?Groth16.PreparedVk = null;

  func parseVkForActivation(hex : Text) : ?Groth16.PreparedVk {
    // @stub-start
    Groth16.parseAndPrepareVk(hex);
    // @stub-end
  };

  func isHexDigit(c : Char) : Bool {
    for (h in "0123456789abcdefABCDEF".chars()) {
      if (h == c) { return true };
    };
    false
  };

  // Cheap structural sanity before a hex string can stage/activate:
  // even-length hex, within the plausible arkworks compressed VK window
  // (length-field len in [1, 64] => compressed bytes in [344, 3416]).
  func structurallyValidVk(hex : Text) : Bool {
    let n = hex.size();
    if (n < 688 or n > 6832) { return false };
    for (c in hex.chars()) {
      if (not isHexDigit(c)) { return false };
    };
    true
  };

  /// Admin-only: register (or stage a replacement of) the verifying key.
  /// Run once per circuit version, never per proof. Rejects malformed/
  /// invalid keys (bad encoding, off-curve points, points outside the
  /// r-torsion subgroup) rather than caching something unusable.
  /// - First VK (fresh deploy): activates immediately.
  /// - Replacement: staged; `confirmVerifyingKey` by a different admin
  ///   activates it, `cancelVerifyingKeyChange` discards it.
  public shared (msg) func setVerifyingKey(hex : Text) : async Result.Result<(), Text> {
    if (not isAdmin(msg.caller)) return #err("unauthorized");
    if (not structurallyValidVk(hex)) return #err("invalid verifying key encoding or contents");
    switch (parseVkForActivation(hex)) {
      case (null) { #err("invalid verifying key encoding or contents") };
      case (?prepared) {
        switch (vkHex) {
          case (null) {
            vkHex := ?hex;
            preparedVkCache := ?prepared;
            logAudit(msg.caller, "setVerifyingKey", "initial activation");
            #ok(());
          };
          case (?_) {
            pendingVk := ?{ hex; proposedBy = msg.caller };
            logAudit(msg.caller, "setVerifyingKey", "staged replacement");
            #ok(());
          };
        };
      };
    };
  };

  /// Admin-only: activate a staged VK replacement. Must come from an admin
  /// other than the one who staged it (threshold-2 on VK changes).
  public shared (msg) func confirmVerifyingKey(hex : Text) : async Result.Result<(), Text> {
    if (not isAdmin(msg.caller)) return #err("unauthorized");
    switch (pendingVk) {
      case (null) { #err("no pending verifying key change") };
      case (?p) {
        if (p.proposedBy == msg.caller) {
          return #err("confirmation must come from a different admin");
        };
        if (p.hex != hex) { return #err("hex does not match the pending change") };
        switch (parseVkForActivation(hex)) {
          case (null) { #err("invalid verifying key encoding or contents") };
          case (?prepared) {
            vkHex := ?hex;
            preparedVkCache := ?prepared;
            pendingVk := null;
            logAudit(msg.caller, "confirmVerifyingKey", "activated replacement");
            #ok(());
          };
        };
      };
    };
  };

  /// Admin-only: discard a staged VK replacement.
  public shared (msg) func cancelVerifyingKeyChange() : async Result.Result<(), Text> {
    if (not isAdmin(msg.caller)) return #err("unauthorized");
    switch (pendingVk) {
      case (null) { #err("no pending verifying key change") };
      case (?_) {
        pendingVk := null;
        logAudit(msg.caller, "cancelVerifyingKeyChange", "");
        #ok(());
      };
    };
  };

  /// Read-only: active/pending VK state (operational visibility).
  public shared query func getVkStatus() : async {
    active : Bool;
    pending : Bool;
    pendingProposedBy : ?Principal;
  } {
    {
      active = vkHex != null;
      pending = pendingVk != null;
      pendingProposedBy = switch (pendingVk) {
        case (null) { null };
        case (?p) { ?p.proposedBy };
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
            let parsed = parseVkForActivation(hex);
            preparedVkCache := parsed;
            parsed;
          };
        };
      };
    };
  };

  // ---- transparency queries (round 3) ----
  // A registry should be transparent about everything except the owner's
  // secret. ownerCommitment is a commitment (owner identity stays hidden);
  // the remaining fields are public registry data. These queries are what a
  // centralized back-end, an auditor, or a reconciler integrates against.

  /// Read-only: current Merkle root (fingerprint of registry state).
  public shared query func getCurrentRoot() : async Nat { currentRoot };

  /// Read-only: the authoritative record for a property, with provenance.
  public shared query func getRecord(propertyId : Nat) : async ?Record {
    records.get(propertyId);
  };

  /// Read-only: a challenge's pinned values (no secrets — challenges are
  /// handed to the prover anyway).
  public shared query func getChallenge(challengeId : Nat) : async ?ChallengeInfo {
    switch (challenges.get(challengeId)) {
      case (null) { null };
      case (?c) {
        ?{
          challengeId;
          registryId = c.registryId;
          merkleRoot = c.merkleRoot;
          purpose = c.purpose;
          requestNonce = c.requestNonce;
          currentTimestamp = c.currentTimestamp;
          expiresAt = c.expiresAt;
        };
      };
    };
  };

  /// Read-only: the capped audit trail.
  public shared query func getAuditLog() : async [AuditEntry] { auditEntries };

  /// Read-only: size/counter snapshot for monitoring and capacity planning.
  public shared query func getStats() : async {
    admins : Nat;
    records : Nat;
    challenges : Nat;
    spentNullifiers : Nat;
    currentRoot : Nat;
    nextLeafIndex : Nat;
  } {
    {
      admins = admins.size();
      records = records.size();
      challenges = challenges.size();
      spentNullifiers = nullifiers.size();
      currentRoot;
      nextLeafIndex;
    };
  };

  // ---- verify ----

  public shared (msg) func verify(
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
    logAudit(msg.caller, "verify", Nat.toText(challengeId) # " nullifier=" # Nat.toText(nullifier));

    #ok({ nullifier });
  };

  // ---- upgrade hooks ----

  system func preupgrade() {
    recordsEntries := Iter.toArray(records.entries());
    nodesEntries := Iter.toArray(nodes.entries());
    challengeEntries := Iter.toArray(challenges.entries());
    spentNullifiers := Iter.toArray(nullifiers.entries());
  };

  system func postupgrade() {
    recordsEntries := [];
    nodesEntries := [];
    challengeEntries := [];
    spentNullifiers := [];
  };

};
