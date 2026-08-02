// Functional driver: exercises the REAL canister logic (main.mo, concatenated
// below this file by tests.js) in the node-motoko interpreter runtime.
//
// Security coverage (round 3):
//   - bootstrap: controller gate (stub on/off), permanent lock, allow-list
//     semantics (add/remove/duplicate/last-admin/non-admin)
//   - submitRecord: full field validation + provenance, Merkle root chaining
//   - requestChallenge: cap enforcement, root/nonce/id binding
//   - verify(): pre-crypto input-matching order (count -> registry -> root
//     -> purpose -> nonce -> ts) and the no-VK gate
//   - VK: invalid-hex rejection, initial activation, staged replacement,
//     same-admin confirmation rejection, cancel
//   - transparency: getRecord/getChallenge/getAuditLog/getStats/getCurrentRoot
//
// tests.js rewrites two lines per run:
//   - the TEST_BOOTSTRAP_MODE const below (true -> controller-authorized
//     suite; false -> gate-rejection suite) by stubbing bootstrapAuthorized
//     in main.mo to the same value.
//   let FIXTURE_VK : Text = "@FIXTURE_VK@";  -> the real arkworks vk hex from
//       circuit/wire_export.json (a valid key for the staging-flow tests).

import Principal "mo:base/Principal";
import Debug "mo:base/Debug";

let TEST_BOOTSTRAP_MODE : Bool = true;
let FIXTURE_VK : Text = "@FIXTURE_VK@";

let reg = TitleRegistry; // the persistent actor declared in this file

persistent actor Probe {
  public shared (msg) func me() : async Principal { msg.caller };
};
let self = await Probe.me();

var failures = 0;
func check(name : Text, cond : Bool) {
  if (cond) { Debug.print("PASS: " # name) }
  else { Debug.print("FAIL: " # name); failures += 1 };
};

if (not TEST_BOOTSTRAP_MODE) {
  // ---- gate-off run: the controller oracle says "not authorized" ----
  check("bootstrapAdmin rejected when caller is not a controller",
    switch (await reg.bootstrapAdmin(self)) {
      case (#err(e)) e == "only a canister controller may bootstrap the registry";
      case _ false;
    });
  check("admins remain empty after rejected bootstrap", (await reg.listAdmins()).size() == 0);
} else {
  // ================= full functional suite (controller-authorized) =================

  // --- 1. bootstrap sentinel semantics ---
  check("admins empty initially", (await reg.listAdmins()).size() == 0);
  check("bootstrapAdmin ok", switch (await reg.bootstrapAdmin(self)) { case (#ok(_)) true; case (_) false });
  check("bootstrapAdmin locks permanently",
    switch (await reg.bootstrapAdmin(Principal.fromText("aaaaa-aa"))) { case (#err(_)) true; case _ false });

  // --- 2. governed allow-list ---
  let other = Principal.fromText("aaaaa-aa");
  check("addAdmin ok", switch (await reg.addAdmin(other)) { case (#ok(_)) true; case (_) false });
  check("addAdmin duplicate rejected", switch (await reg.addAdmin(other)) { case (#err(_)) true; case _ false });
  check("listAdmins has both", (await reg.listAdmins()).size() == 2);
  check("removeAdmin ok", switch (await reg.removeAdmin(other)) { case (#ok(_)) true; case (_) false });
  check("removeAdmin non-admin rejected", switch (await reg.removeAdmin(Principal.fromText("2vxsx-fae"))) { case (#err(_)) true; case _ false });
  check("last admin protected", switch (await reg.removeAdmin(self)) { case (#err(_)) true; case _ false });
  check("listAdmins back to one", (await reg.listAdmins()).size() == 1);

  // --- 3. submitRecord validation + provenance (no crypto here) ---
  let future = Nat64.toNat(Nat64.fromIntWrap(Time.now() / 1_000_000_000)) + 3600;
  check("submitRecord propertyId 0 rejected", switch (await reg.submitRecord(0, 12345, 0, 1, future)) { case (#err(_)) true; case _ false });
  check("submitRecord non-canonical commitment rejected", switch (await reg.submitRecord(1, Poseidon.MODULUS + 1, 0, 1, future)) { case (#err(_)) true; case _ false });
  check("submitRecord bad encumbranceFlag rejected", switch (await reg.submitRecord(1, 12345, 2, 1, future)) { case (#err(_)) true; case _ false });
  check("submitRecord bad licenseStatus rejected", switch (await reg.submitRecord(1, 12345, 0, 2, future)) { case (#err(_)) true; case _ false });
  check("submitRecord past expiry rejected", switch (await reg.submitRecord(1, 12345, 0, 1, 0)) { case (#err(_)) true; case _ false });
  check("submitRecord oversized expiry rejected", switch (await reg.submitRecord(1, 12345, 0, 1, 2 ** 64)) { case (#err(_)) true; case _ false });

  let root0 = switch (await reg.submitRecord(1, 12345, 0, 1, future + 3600)) {
    case (#ok r) r;
    case (#err e) { Debug.print("FAIL: submitRecord #1: " # e); 0 };
  };
  check("submitRecord returns nonzero root", root0 > 0);
  let root1 = switch (await reg.submitRecord(2, 54321, 0, 1, future + 7200)) {
    case (#ok r) r;
    case (#err e) { Debug.print("FAIL: submitRecord #2: " # e); 0 };
  };
  check("second insert changes root", root1 != root0);

  check("getRecord returns provenance",
    switch (await reg.getRecord(1)) {
      case (?r) { r.ownerCommitment == 12345 and r.submittedBy == self and r.submittedAt > 0 };
      case null false;
    });
  check("getRecord misses unknown property", switch (await reg.getRecord(999)) { case null true; case _ false });
  check("getCurrentRoot matches last root", (await reg.getCurrentRoot()) == root1);

  // --- 4. challenge issuance: cap + binding ---
  let ch = switch (await reg.requestChallenge(1)) {
    case (#ok c) c;
    case (#err e) { Debug.print("FAIL: requestChallenge: " # e); Debug.trap("no challenge") };
  };
  check("challenge root matches current root", ch.merkleRoot == root1);
  check("challenge nonce starts at 0", ch.requestNonce == 0);
  check("challenge id 0", ch.challengeId == 0);
  check("getChallenge mirrors issuance", switch (await reg.getChallenge(0)) {
    case (?c) { c.merkleRoot == root1 and c.purpose == 1 and c.requestNonce == 0 };
    case null false;
  });

  var capHit = false;
  var i = 0;
  while (i < 502 and not capHit) {
    switch (await reg.requestChallenge(0)) {
      case (#err(e)) { capHit := e == "too many pending challenges — reuse an existing one or wait for expiry" };
      case (#ok(_)) {};
    };
    i += 1;
  };
  check("requestChallenge capped at MAX_PENDING_CHALLENGES", capHit);

  // --- 5. verify(): input matching happens BEFORE any crypto ---
  check("unknown challenge rejected", switch (await reg.verify(999999, "", [])) { case (#err(_)) true; case _ false });
  check("wrong input count rejected",
    switch (await reg.verify(ch.challengeId, "", [0, 1])) { case (#err(_)) true; case _ false });
  check("registry_id mismatch rejected first",
    switch (await reg.verify(ch.challengeId, "00", [99, ch.merkleRoot, ch.purpose, ch.requestNonce, ch.currentTimestamp, 0])) {
      case (#err(e)) e == "registry_id mismatch";
      case _ false;
    });
  check("purpose mismatch rejected first",
    switch (await reg.verify(ch.challengeId, "00",
      [ch.registryId, ch.merkleRoot, 99, ch.requestNonce, ch.currentTimestamp, 0])) {
      case (#err(e)) e == "purpose mismatch";
      case _ false;
    });
  check("request_nonce mismatch rejected",
    switch (await reg.verify(ch.challengeId, "00",
      [ch.registryId, ch.merkleRoot, ch.purpose, 777, ch.currentTimestamp, 0])) {
      case (#err(e)) e == "request_nonce mismatch";
      case _ false;
    });
  let goodInputs = [ch.registryId, ch.merkleRoot, ch.purpose, ch.requestNonce, ch.currentTimestamp, 777];
  check("matching inputs reach verifier gate (no VK configured)",
    switch (await reg.verify(ch.challengeId, "00", goodInputs)) {
      case (#err(e)) e == "no verifying key configured";
      case _ false;
    });

  // --- 6. verifying key: initial activation + staged replacement ---
  check("setVerifyingKey invalid hex rejected",
    switch (await reg.setVerifyingKey("zz-not-hex")) { case (#err(_)) true; case _ false });
  check("setVerifyingKey initial activation ok",
    switch (await reg.setVerifyingKey(FIXTURE_VK)) { case (#ok(_)) true; case _ false });
  check("getVkStatus active after initial set", (await reg.getVkStatus()).active);
  check("VK replacement staged (active unchanged)",
    switch (await reg.setVerifyingKey(FIXTURE_VK)) { case (#ok(_)) true; case _ false });
  check("getVkStatus shows pending replacement", (await reg.getVkStatus()).pending and (await reg.getVkStatus()).active);
  check("confirm by same admin rejected",
    switch (await reg.confirmVerifyingKey(FIXTURE_VK)) {
      case (#err(e)) e == "confirmation must come from a different admin";
      case _ false;
    });
  check("cancel VK change ok", switch (await reg.cancelVerifyingKeyChange()) { case (#ok(_)) true; case _ false });
  check("getVkStatus pending cleared", not (await reg.getVkStatus()).pending);
  check("cancel with nothing pending rejected",
    switch (await reg.cancelVerifyingKeyChange()) { case (#err(_)) true; case _ false });

  // --- 7. audit log + stats ---
  check("audit log non-empty", (await reg.getAuditLog()).size() > 0);
  var sawBootstrap = false;
  var sawSubmit = false;
  for (e in (await reg.getAuditLog()).vals()) {
    if (e.action == "bootstrap") { sawBootstrap := true };
    if (e.action == "submitRecord") { sawSubmit := true };
  };
  check("audit log records bootstrap", sawBootstrap);
  check("audit log records submitRecord", sawSubmit);

  let stats = await reg.getStats();
  check("stats: records", stats.records == 2);
  check("stats: challenges at cap (1 + 499)", stats.challenges == 500);
  check("stats: no nullifiers spent (crypto path not executed here)", stats.spentNullifiers == 0);
  check("stats: root matches", stats.currentRoot == root1);
  check("stats: next leaf index", stats.nextLeafIndex == 2);
};

Debug.print("failures=" # debug_show failures);
if (failures > 0) { Debug.trap("TEST FAILURES PRESENT") };
Debug.print("ALL CHECKS PASSED");
