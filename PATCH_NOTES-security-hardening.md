# PATCH_NOTES — Security hardening pass (round 2)

**Scope:** `motoko/src/main.mo` only. No changes to the vendored Groth16
verifier, the Poseidon hasher, or the circuit — this pass is about the
canister's own trust boundary (admin bootstrap, DoS surface, state growth,
VK rotation), the four issues raised in the prior review that weren't in
the original roadmap.

**Verification method used this pass:** the sandbox has no `dfx`/`pocket-ic`
and no working `wasmtime` (see "Toolchain notes" below for exactly why), but
it does have network access to npm and GitHub. The `motoko` npm package
(`node-motoko`, the same WASM-compiled `moc` that powers the Motoko
Playground) bundles a real Motoko compiler. Every change below was actually
**typechecked and then fully compiled to a canister WASM module** against
the real `mo:base` and `mo:core` dependency trees (pulled from
`caffeinelabs/motoko-base` and `dfinity/motoko-core` — `dfinity/motoko-base`
has moved/redirects there) — not just read over by eye. This is real
compiler feedback, not a claim of "should work."

This is still not a `dfx`/`pocket-ic` run — no canister was actually
installed, no update calls were actually made, no timer actually fired. It
closes the "did I even get the syntax and types right" gap, not the
"does it behave correctly on a live replica" gap. Someone with real `dfx`
access should still run through the checklist at the bottom before this
touches anything real.

---

## 1. `bootstrapAdmin` front-running / race — FIXED

**Before:** `bootstrapAdmin` succeeded for whoever called it first, gated
only on `admins.size() == 0`. The canister ID is public from the moment the
canister is created — often before code is even installed — so there was a
real window for an attacker to call `bootstrapAdmin(attacker_principal)`
before the legitimate deploy script did, and permanently own the admin set.
The prior patch notes treated this as solved by operational discipline
("call it in the same deploy session"); it wasn't structurally closed.

**After:**
```motoko
public shared (msg) func bootstrapAdmin(realAdmin : Principal) : async Result.Result<(), Text> {
  if (admins.size() > 0) { return #err("admins already bootstrapped — use addAdmin instead") };
  if (not Principal.isController(msg.caller)) {
    return #err("unauthorized — only a canister controller may bootstrap the admin set");
  };
  admins.put(realAdmin, ());
  #ok(());
};
```
`Principal.isController` checks the caller against the canister's actual
controller set — a property fixed at `dfx canister create` time, off-chain,
before this code ever runs. An attacker who isn't already a controller
cannot win this race no matter how fast they call it. This was chosen over
the alternative (an `actor class Main(admin : Principal) = this {}`
constructor argument, which I confirmed this compiler *does* support,
contrary to the old code comment) because a constructor argument would
require every future `dfx canister install --mode upgrade` to keep passing
a matching `--argument`, which is its own footgun (miss it once and the
upgrade either fails or silently reruns the seed logic). The controller
check needs nothing extra at upgrade time.

**Residual risk:** if the deployer's identity is later removed as a
controller (or the controller set is otherwise mismanaged), nobody can
re-bootstrap. This is the same tradeoff every controller-gated pattern on
ICP has; not new to this change.

## 2. Cycles-drain DoS via `verify`/`requestChallenge` — MITIGATED, not eliminated

**Before:** both entry points were fully unauthenticated. An attacker could
call `requestChallenge()` themselves (it returns every public input needed),
then submit a garbage 192-byte `proofBytes` blob with matching public
inputs. The cheap checks (challenge lookup, public-input match, nullifier
lookup) all pass, so the canister pays the full ~21B-instruction Groth16
pairing check before rejecting it — and under ICP's reverse-gas model, that
cost comes out of the *canister's* cycles balance, not the caller's, for
free and unlimited repetition.

**After:** both functions now reject the anonymous principal and enforce a
minimum interval per (non-anonymous) principal — 2s for `requestChallenge`,
5s for `verify` — via a `checkAndRecordRateLimit` helper backed by two
`HashMap<Principal, Int>`.

**I want to be direct about what this does and doesn't do:** it raises the
cost of the attack from "free and untraceable" to "needs one throwaway
principal per attempt at the rate limit's cadence." Generating a fresh
Ed25519 keypair is still computationally cheap, so a well-resourced
attacker with many identities isn't fully stopped by this alone — it is a
real increase in attack cost and in traceability (each attempt is now tied
to an addressable principal you can see in your own canister's call
pattern), not a complete fix. A cycles-payment gate was considered and
rejected: **plain ingress calls from a user agent (dfx, ic-agent, any
wallet) cannot attach cycles to a call at all** — only canister-to-canister
calls can — so a cycles gate on these functions would lock out every direct
end-user call, which doesn't fit this canister's "users call it directly"
model. The roadmap's existing P3 "operational hygiene" item (monitoring
challenge-issuance / verify-failure rates) is still the real backstop here
and hasn't gotten any less necessary.

## 3. Unbounded `challenges` growth — FIXED

**Before:** nothing ever removed a `challenges` entry, consumed or expired.
Combined with #2, this is a state-bloat vector, and since
`preupgrade`/`postupgrade` serialize the whole map to an array, unbounded
growth eventually risks an upgrade running out of per-message instructions.

**After:** a `Timer.recurringTimer` (`mo:base/Timer`) sweeps expired
challenges every 5 minutes, bounded to 500 deletions per tick so a single
prune pass can't itself become an expensive call; the same tick also prunes
rate-limit bookkeeping older than 1 hour. Timers don't persist across
upgrades on IC (a platform property, not a bug), so `postupgrade` re-arms
it. Confirmed via the compiler that `Timer.recurringTimer<system>` needs the
calling function itself to carry a `<system>` type parameter — I initially
missed this and the compiler caught it immediately (see "what the compiler
actually caught" below).

## 4. VK-rotation gap — FIXED

**Before:** the roadmap's own P3 list flagged this as open: "what happens to
challenges issued under the old VK when it rotates?" Answer, previously:
whatever key happened to be cached when `verify` ran — silently, with no
signal to the caller that anything had changed.

**After:** `currentVkVersion : Nat` increments on every `setVerifyingKey`
call; each `Challenge` is stamped with the version live at issuance;
`verify` now explicitly rejects (`"verifying key has rotated..."`) if the
version has since moved on, forcing the client to request a fresh challenge
under the new key instead of getting an ambiguous pass/fail against a key
they didn't know was stale.

---

## Interface change clients need to know about

`requestChallenge`'s return type changed from a bare record to
`Result<record, Text>`, because it can now fail (rate-limited or anonymous
caller). Generated Candid, confirmed by a real compile:

```candid
requestChallenge: (purpose: nat) -> (variant { err: text; ok: record {
  challengeId: nat; currentTimestamp: nat; expiresAt: int; merkleRoot: nat;
  purpose: nat; registryId: nat; requestNonce: nat } });
```

Any client code doing `const c = await actor.requestChallenge(purpose)` and
reading `c.challengeId` directly will break — it now needs to unwrap
`{ ok } / { err }` first. This is a real, intentional breaking change, not
an oversight; flagging it so it isn't a surprise at integration time.

## What the compiler actually caught (so this isn't just "trust me")

First compile attempt: `M0197 'system' capability required, but not
available` on the top-level `armPruneTimer()` call — I'd written
`Timer.recurringTimer<system>(...)` inside a plain helper function, but a
plain function doesn't carry the `system` capability into its body just
because it's *called* from a context that has one; the function itself
needs `<system>` in its own signature. Fixed by declaring
`func armPruneTimer<system>()`. Second pass: two `M0195` warnings for
calling `armPruneTimer()` without an explicit type instantiation at its two
call sites (top-level actor init, and `postupgrade`) — fixed by calling
`armPruneTimer<system>()` explicitly at both. Final compile: clean, only
the same six pre-existing vendor-code deprecation warnings the unmodified
project already had (`Fp.mo`, `CurveFlat.mo`, `PairingFlat.mo`,
`PairingProjective.mo`, `Groth16Wire.mo` — all in code this pass didn't
touch).

## Toolchain notes (why this still isn't a `dfx` run)

- `run_wasi_node.js` still fails identically on both `orig.wasm` and
  `patched.wasm` with `invalid table elements limits flags`. Decompiling
  with `wabt` shows the module declares `(table (;0;) i64 17 17 funcref)` —
  a **table64** module (part of the memory64 proposal). Checked
  `node --v8-options` on this Node build: there is no
  `--experimental-wasm-table64` or `--experimental-wasm-memory64` flag at
  all, meaning this Node/V8 build has no path to opt into it, not even
  behind an experimental flag. This needs either a newer Node/V8 or actual
  `wasmtime`/`dfx`, full stop.
- Building the `wasmtime`+fuel-metering harness from source still fails:
  installed `rustc`/`cargo` 1.75.0 (the only version `apt` offers here) and
  confirmed `wasmtime` 13.0.0 pulls in `psm`, which hard-requires
  `ar_archive_writer ^0.5.0`, which requires Cargo's `edition2024` —
  unsupported by 1.75. Tried pinning `ar_archive_writer` down with
  `cargo update --precise`; `psm`'s manifest rejects anything below 0.5.0,
  so there's no compatible combination on this toolchain. The `wasmtime`
  npm binding (a real native wasmtime under the hood) doesn't help either:
  its `Instance::new` binds zero imports and exposes no fuel-metering API,
  so it can't even satisfy the module's one `fd_write` WASI import.

## Checklist for whoever has real `dfx`/`pocket-ic` access

1. `dfx start --clean --background`
2. Deploy, then immediately call `bootstrapAdmin` with the real admin
   principal from a controller identity — confirm a non-controller
   identity gets `#err("unauthorized...")` even when `admins.size() == 0`.
3. Call `requestChallenge` twice in quick succession from the same
   identity — confirm the second is rate-limited; confirm the anonymous
   identity (`dfx canister call --identity anonymous ...` or an
   un-authenticated agent) is rejected outright.
4. Call `verify` with a stale/garbage proof against a self-issued
   challenge — confirm it still fails, and separately confirm the rate
   limit kicks in on repeat attempts.
5. Wait 5+ minutes (or adjust `PRUNE_INTERVAL_SECONDS` down for testing),
   confirm expired challenge entries actually disappear from state (e.g.
   via a debug query or by checking stable memory size).
6. Call `setVerifyingKey` again after issuing a challenge under the old
   key; confirm `verify` against the old challenge now returns the
   "verifying key has rotated" error instead of silently passing/failing
   against the new key.
7. Run `verify_test/main.mo` and `Groth16MultiTest.mo` for real — these
   remain the P1 item from the original roadmap, unchanged by this pass.
