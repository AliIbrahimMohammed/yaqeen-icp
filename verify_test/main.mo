// SCRATCH TEST CANISTER — not part of the production tree.
// Exercises GW.tryVerify directly against the real wire_export.json
// fixture, on a real dfx/pocket-ic replica, at real WASM speed. This is
// the test the project README flagged as "the single most valuable
// remaining test" and the one the sandboxed JS Motoko interpreter could
// not finish (killed after 17+ minutes still computing the pairing).

import GW "../motoko/src/groth16/vendor/Groth16Wire";
import Prim "mo:⛔";

persistent actor {
  public func verifyReal(vkHex : Text, proofHex : Text, inputsHex : Text) : async Text {
    GW.tryVerify(vkHex, proofHex, inputsHex);
  };

  public func verifyRealWithInstructions(vkHex : Text, proofHex : Text, inputsHex : Text) : async { result : Text; instructions : Nat64 } {
    let before = Prim.performanceCounter(0);
    let result = GW.tryVerify(vkHex, proofHex, inputsHex);
    let after = Prim.performanceCounter(0);
    { result; instructions = after - before };
  };

  public func verifyRealTimed(vkHex : Text, proofHex : Text, inputsHex : Text) : async { result : Text; instructions_note : Text } {
    let result = GW.tryVerify(vkHex, proofHex, inputsHex);
    { result; instructions_note = "see dfx canister call --query cycles / ic-repl for exact instruction counts" };
  };
};
