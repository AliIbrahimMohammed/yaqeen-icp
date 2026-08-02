// Poseidon differential tests: Motoko hasher vs. arkworks-native values.
//
// Vector 1: hash(domain=2, [12345, 67890]) — the original cross-language
// vector from circuit/src/bin/export_poseidon_params.rs.
//
// Vector 2: nullifier hash(domain=3, [999, 1001, 1, 42]) — the 4-input
// absorption used for nullifiers, pinned against the arkworks value in
// circuit/wire_export.json (publicInputs[5], produced by circuit/src/bin/
// prove.rs with owner_secret=999, property_id=1001, purpose=1, nonce=42).
//
// Vector 3: the full 25-level Merkle-root chain for the same fixture leaf
// (owner_secret=999, property_id=1001, encumbrance=0, license=1,
// expiry=2_000_000_000) — leaf hash (5 inputs) folded up the zero-hash
// chain, pinned against wire_export.json's publicInputs[1] (the root that
// arkworks' prove.rs computed and the fixture's proof was made against).

import Poseidon "motoko/src/poseidon/Poseidon";
import Debug "mo:base/Debug";
import Nat "mo:base/Nat";
import Array "mo:base/Array";

var failures = 0;
func check(name : Text, cond : Bool) {
  if (cond) { Debug.print("PASS " # name) }
  else { Debug.print("FAIL " # name); failures += 1 };
};

// --- vector 1: original two-input vector ---
let expected1 : Nat = 493449967592615911517850693211259918700104437189660047865960110642109014224;
let got1 : Nat = Poseidon.hash(Poseidon.fromNat(2), [Poseidon.fromNat(12345), Poseidon.fromNat(67890)]);
check("poseidon vector v1 (2 inputs)", got1 == expected1);

// --- vector 2: nullifier (4 inputs) ---
let expected2 : Nat = 4906672577764984050910889352920011279769338728263885578893283853266286551693;
let got2 : Nat = Poseidon.hash(Poseidon.fromNat(3), [Poseidon.fromNat(999), Poseidon.fromNat(1001), Poseidon.fromNat(1), Poseidon.fromNat(42)]);
check("poseidon vector v2 (nullifier, 4 inputs)", got2 == expected2);

// --- vector 3: 25-level root chain (leaf = 5 inputs) ---
let commitment = Poseidon.hash(Poseidon.fromNat(2), [Poseidon.fromNat(999), Poseidon.fromNat(1001)]);
let leaf = Poseidon.hash(Poseidon.fromNat(1), [
  Poseidon.fromNat(1), // registryId
  commitment,
  Poseidon.fromNat(0), // encumbranceFlag
  Poseidon.fromNat(1), // licenseStatus
  Poseidon.fromNat(2000000000), // licenseExpiry
]);
let zh = Array.init<Nat>(25, 0); // zeroHashes[0] = 0, zeroHashes[i] = H(node, [prev, prev])
var lvl = 1;
while (lvl < 25) {
  zh[lvl] := Poseidon.hash(Poseidon.fromNat(4), [zh[lvl - 1], zh[lvl - 1]]);
  lvl += 1;
};
var cur = leaf;
var j = 0;
while (j < 25) {
  cur := Poseidon.hash(Poseidon.fromNat(4), [cur, zh[j]]);
  j += 1;
};
let expected3 : Nat = 48510825714604771897097607745450647431454473471606723851420871738545508225189;
check("poseidon vector v3 (leaf+25-level root, matches wire_export.json)", cur == expected3);

Debug.print("failures=" # debug_show failures);
if (failures > 0) { Debug.trap("POSEIDON TEST FAILURES PRESENT") };
Debug.print("PASS poseidon vector (cross-language, matches arkworks)");
