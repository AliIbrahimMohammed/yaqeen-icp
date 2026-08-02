# Security round 3 — registry hardening

What landed this round, why, and how it was verified. Companion to
`PATCH_NOTES-security-review.md` (the review disposition) and
`PATCH_NOTES-admin-bootstrap.md` (round 1–2 bootstrap work). All of this
is cross-checkable against the original review findings.

## 1. `bootstrapAdmin` is gated to the canister's CONTROLLER

Closes the first-come-first-served takeover race on fresh deploys: before,
the first caller of `bootstrapAdmin` — whoever raced onto a brand-new
canister id — became sole admin.

Now `bootstrapAdmin` asks the management canister (`aaaaa-aa`) for the
canister's controllers (`get_canister_controllers`) and only seeds the
allow-list if the caller is among them. If the management canister is
unreachable the gate **fails closed** (a `try/catch` that resolves to
`false`) — an unreachable oracle can never open the registry to arbitrary
callers.

- Deploy session note: call `bootstrapAdmin` from the identity that
  deployed/controls the canister. `dfx canister status` shows the current
  controllers.
- Test strategy: the node-motoko interpreter cannot make canister calls
  (the `await` on the management actor hard-crashes it), so the oracle
  body between the `@stub-start`/`@stub-end` markers in `main.mo` is
  replaced by a constant in the driver runs. The suite runs **twice**:
  1. stub = `true`  → full functional suite (below)
  2. stub = `false` → proves the gate itself rejects a non-controller
     caller and leaves `admins` empty.

## 2. `submitRecord` validates every field and keeps provenance

No more silently-unprovable or non-canonical records:

| Check | Rationale |
|---|---|
| `propertyId != 0` | zero is not a title property |
| commitment canonical (`< Fp` modulus) | non-canonical commitments can never be proven against |
| `encumbranceFlag ∈ {0,1}`, `licenseStatus ∈ {0,1}` | flag fields are booleans |
| `expiry ∈ (now, 2^64)` | no expired records, no wrap-overflow snowflakes |
| `submittedBy` / `submittedAt` recorded | forged records are attributable |

## 3. Verifying-key REPLACEMENTS need a second admin

A single compromised admin could previously swap the verifying key for one
they hold the proving key to — silently killing the registry's
soundness. Now:

- **First VK on a fresh deploy**: activates immediately (deploy-ceremony
  path). Still fully validated (encoding, on-curve, in-subgroup,
  alpha/beta target pairing) before activation.
- **Replacement**: `setVerifyingKey` only *stages* `{ hex, proposedBy }`.
  `confirmVerifyingKey(hex)` activates it only when called by an admin
  *other than the proposer* (threshold-2). `cancelVerifyingKeyChange`
  discards a staged change.
- A cheap structural sanity check (hex-only, even-length, size within the
  arkworks compressed-VK window) runs before staging so garbage can't be
  parked; the expensive full validation runs at activation.

Test-notes: full VK validation costs a pairing the interpreter cannot run
(a real parse in this sandbox exceeds the step budget — same wall that
makes real verify untestable there). `parseVkForActivation` is the one
function whose body sits behind @stub markers in **tests.js**; production
(un-stubbed) code is unchanged and still runs the full
`Groth16.parseAndPrepareVk` validation. The driver covers initial
activation, staging, pending status, same-admin confirmation rejection,
and cancel — on the real arkworks fixture bytes.

## 4. Challenge flood protection

`requestChallenge` is capped at `MAX_PENDING_CHALLENGES = 500` pending
challenges, and each successful issuance opportunistically sweeps expired
challenges (`SWEEP_BUDGET = 256`) so the cap is not a permanent DoS state.
`requestChallenge`'s binding (root, nonce, id) is unchanged.

## 5. Audit log + transparency

Every admin action and record write is appended to a capped (1000) audit
log with `{caller, action, detail, at}`, and the registry exposes:
`getCurrentRoot`, `getRecord(propertyId)`, `getChallenge(id)`,
`getVkStatus`, `getAuditLog`, `getStats`. The owner's *secret* is never
stored — `ownerCommitment` is only ever a poseidon commitment.

## Test evidence

`node-tests/tests.js` (dfx-free, node-motoko interpreter):

```
=== 1. TYPECHECK ===            OK (main.mo, verify_test/main.mo, Groth16MultiTest.mo)
=== 2. WASM COMPILE ===         OK
=== 3. POSEIDON VECTOR ===      PASS (incl. 25-level root matching arc/wire_export.json)
=== 4. CANISTER DRIVER ===      OK — all PASS, both runs (gate-on full suite + gate-off)
```

The functional driver exercises both convenience (41+) checks including:
the 6 VK-stage/activate/confirm/cancel assertions, record provenance,
registry-mismatch-vs-purpose-vs-nonce ordering, and the "no verifying key
configured" gate. Known limit: real pairing paths (proof verification,
real VK validation) still require a `dfx`/`pocket-ic` run — the reviewer
identified this same environment limit before.