// Functional driver: exercises the real canister logic (main.mo, transformed
// persistent actor -> actor class) in the node-motoko interpreter runtime:
// admin allow-list, gates, VK validation, Merkle inserts, challenge
// issuance, and verify()'s pre-crypto input matching (the security-critical
// ordering).

import Principal "mo:base/Principal";
import Debug "mo:base/Debug";

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

// --- 3. setVerifyingKey: admin gate + validation (no crypto here) ---
check("setVerifyingKey invalid hex rejected",
  switch (await reg.setVerifyingKey("zz-not-hex")) { case (#err(_)) true; case _ false });

// --- 4. submitRecord (admin): registry + Merkle ---
let root0 = switch (await reg.submitRecord(1, 12345, 0, 1, 0)) {
  case (#ok r) r;
  case (#err e) { Debug.print("FAIL: submitRecord #1: " # e); 0 };
};
check("submitRecord returns nonzero root", root0 > 0);
let root1 = switch (await reg.submitRecord(2, 54321, 1, 1, 1)) {
  case (#ok r) r;
  case (#err e) { Debug.print("FAIL: submitRecord #2: " # e); 0 };
};
check("second insert changes root", root1 != root0);

// --- 5. challenge issuance binds to current root ---
let ch = await reg.requestChallenge(1);
check("challenge root matches current root", ch.merkleRoot == root1);
check("challenge nonce starts at 0", ch.requestNonce == 0);
check("challenge id 0", ch.challengeId == 0);

// --- 6. verify(): input matching happens BEFORE any crypto ---
check("unknown challenge rejected", switch (await reg.verify(999, "", [])) { case (#err(_)) true; case _ false });
check("wrong input count rejected",
  switch (await reg.verify(ch.challengeId, "", [0, 1])) { case (#err(_)) true; case _ false });
check("purpose mismatch rejected first",
  switch (await reg.verify(ch.challengeId, "00",
    [ch.registryId, ch.merkleRoot, 99, ch.requestNonce, ch.currentTimestamp, 0])) {
    case (#err(e)) e == "purpose mismatch";
    case _ false;
  });
let goodInputs = [ch.registryId, ch.merkleRoot, ch.purpose, ch.requestNonce, ch.currentTimestamp, 777];
check("matching inputs reach verifier gate (no VK configured)",
  switch (await reg.verify(ch.challengeId, "00", goodInputs)) {
    case (#err(e)) e == "no verifying key configured";
    case _ false;
  });

Debug.print("failures=" # debug_show failures);
if (failures > 0) { Debug.trap("TEST FAILURES PRESENT") };
Debug.print("ALL CHECKS PASSED");
