// Poseidon differential test: hash(domain=2, [12345, 67890]) must equal the
// arkworks-native test vector from circuit/src/bin/export_poseidon_params.rs
// (documented cross-language value, verified byte-identical in earlier sessions).
import Poseidon "motoko/src/poseidon/Poseidon";
import Debug "mo:base/Debug";
import Nat "mo:base/Nat";

let expected : Nat = 493449967592615911517850693211259918700104437189660047865960110642109014224;
let got : Nat = Poseidon.hash(Poseidon.fromNat(2), [Poseidon.fromNat(12345), Poseidon.fromNat(67890)]);

if (got != expected) {
  Debug.print("FAIL poseidon vector: got " # Nat.toText(got) # " expected " # Nat.toText(expected));
  Debug.trap("poseidon vector mismatch");
};
Debug.print("PASS poseidon vector (cross-language, matches arkworks)");
