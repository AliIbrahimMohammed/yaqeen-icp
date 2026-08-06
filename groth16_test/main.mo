import T "../motoko/src/groth16/Groth16MultiTest";

/// Thin actor wrapper so `Groth16MultiTest.run()` — written and pinned
/// against a real oracle, but self-documented as never having been
/// executed (no dfx/pocket-ic access in the sandbox that wrote it) — can
/// actually be called on a real replica.
///
/// `run()` itself does ~5x a single verify()'s pairing work in one message
/// (vk prep + 2 raw Miller computations + 2 full verifies) and exceeds the
/// per-message instruction budget even as an update call (confirmed
/// empirically). Parse+cache the vk once, then expose each check as its
/// own message — each costing roughly what one real `verify()` call
/// costs, which main.mo's own live testing already confirmed fits.
persistent actor {
  transient var cachedVk : ?T.TestVk = null;

  public func prepareVk() : async Bool {
    let vk = T.parseVkForTest();
    cachedVk := vk;
    switch (vk) { case (?_) true; case null false };
  };

  public func alphaBetaTargetMatchesOracle() : async Bool {
    switch (cachedVk) { case (?vk) T.checkAlphaBetaTarget(vk); case null false };
  };

  public func validRawIntermediateMatchesOracle() : async Bool {
    switch (cachedVk) { case (?vk) T.checkValidRaw(vk); case null false };
  };

  public func forgedRawIntermediateMatchesOracle() : async Bool {
    switch (cachedVk) { case (?vk) T.checkForgedRaw(vk); case null false };
  };

  public func acceptsValidProof() : async Bool {
    switch (cachedVk) { case (?vk) T.checkAcceptValid(vk); case null false };
  };

  public func rejectsForgedProof() : async Bool {
    switch (cachedVk) { case (?vk) T.checkRejectForged(vk); case null false };
  };
};
