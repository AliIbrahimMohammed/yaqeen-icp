/// Integration layer between the ledger canister (`main.mo`) and the
/// vendored BLS12-381 Groth16 verifier (`vendor/`, from
/// Shielded-Ledger-Hivemind — see `vendor/ATTRIBUTION.md`).
///
/// This is the only file in this directory that isn't vendored verbatim.
/// It does no cryptography itself — it just adapts wire formats:
/// the ledger already carries public inputs as `[Nat]` (registry_id,
/// merkle_root, purpose, request_nonce, current_timestamp, nullifier), so
/// this calls `Groth16Multi.verify` directly with those, skipping
/// `Groth16Wire`'s hex-encoded-inputs path entirely (that path exists in
/// the vendored code for a Rust-boundary-compatible one-shot hex API,
/// which isn't what a canister with its own state needs).
///
/// Proof bytes are still expected in the same 192-byte
/// A:G1(48) ‖ B:G2(96) ‖ C:G1(48) compressed layout `Groth16Wire.parseProof`
/// defines — confirmed (by direct inspection of `ark-serialize`'s derive
/// behavior, not assumed) to be exactly what
/// `ark_groth16::Proof::serialize_compressed` produces, so the client's
/// proof bytes need no re-encoding on the way in.

import GM "./vendor/Groth16Multi";
import GW "./vendor/Groth16Wire";
import Blob "mo:core/Blob";

module {
  public type PreparedVk = GM.PreparedVk;

  /// Parse + fully validate + prepare a verifying key from its
  /// arkworks-compressed hex encoding (see `vendor/Groth16Wire.mo`'s module
  /// doc for the exact byte layout). Run this once, at vk configuration
  /// time — never per proof.
  public func parseAndPrepareVk(vkHex : Text) : ?PreparedVk {
    GW.parseAndPrepareVk(vkHex);
  };

  /// Per-proof verification. `proofBytes` is the 192-byte compressed
  /// A‖B‖C encoding; `publicInputs` are the ledger's own `[Nat]` public
  /// inputs, in the same order the circuit declares them. Returns `false`
  /// on ANY failure — malformed bytes, wrong point encoding, failed
  /// subgroup check, or a failed pairing check all collapse to `false`
  /// here; callers that need the failure reason should use
  /// `verifyWithReason` instead.
  public func verify(vk : PreparedVk, proofBytes : Blob, publicInputs : [Nat]) : Bool {
    switch (verifyWithReason(vk, proofBytes, publicInputs)) {
      case (#ok) { true };
      case (#err(_)) { false };
    };
  };

  public func verifyWithReason(vk : PreparedVk, proofBytes : Blob, publicInputs : [Nat]) : { #ok; #err : Text } {
    let bytes = Blob.toArray(proofBytes);
    switch (GW.parseProof(bytes)) {
      case (null) { #err("E_PROOF_DESERIALIZE") };
      case (?p) {
        switch (GM.verify(vk, p.a, p.b, p.c, publicInputs)) {
          case (#ok) { #ok };
          case (#err(e)) { #err(e) };
        };
      };
    };
  };
};
