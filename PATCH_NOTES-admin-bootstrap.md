# Fix: hardcoded admin principal (P0.1 from the roadmap)

> **Update (security review round 2):** the single-principal
> `bootstrapAdmin`/`setAdmin` model below has been upgraded to a
> **multi-principal allow-list** — see the "Round 2: allow-list upgrade"
> section at the bottom. The historical record is kept for context.

## What changed (round 1)

`motoko/src/main.mo` — `admin` was:
```motoko
let admin : Principal = Principal.fromText("aaaaa-aa"); // TODO: set at init
```
`"aaaaa-aa"` is the IC management canister's well-known principal, not a real
admin — every admin-gated call (`submitRecord`, `setVerifyingKey`) was
effectively gated against a principal nobody actually controls as intended.

## Why not a constructor argument

The obvious fix — `persistent actor TitleRegistry(initialAdmin : Principal) { ... }`,
set via `dfx deploy --argument '(principal "...")'` — was tried first. The
`moc` build available for typechecking in this environment (the npm
`motoko` package) doesn't parse constructor arguments on a plain `actor`;
that requires restructuring to `actor class ... = this { }`, a bigger
structural change than this fix warranted. Went with the pattern below
instead, which needs no special syntax and typechecks cleanly against every
`moc` version.

## What it is instead: one-time bootstrap sentinel

```motoko
var admin : ?Principal = null;

public shared func bootstrapAdmin(realAdmin : Principal) : async Result.Result<(), Text> {
  switch (admin) {
    case (?_) { #err("admin already set — use setAdmin instead") };
    case null { admin := ?realAdmin; #ok(()) };
  };
};

public shared (msg) func setAdmin(newAdmin : Principal) : async Result.Result<(), Text> {
  if (?msg.caller != admin) { return #err("unauthorized") };
  admin := ?newAdmin;
  #ok(());
};
```

- `admin` starts unset (`null`). Every admin-gated call
  (`submitRecord`/`setVerifyingKey`/`setAdmin`) compares against `?msg.caller
  != admin`, which is `true` (i.e. rejects) for *everyone* while `admin` is
  `null` — there is no window where an attacker can act as admin, only a
  window where the real admin hasn't claimed the role yet.
- `bootstrapAdmin` is callable by anyone, but only succeeds once — the
  first successful call permanently sets `admin` and locks the sentinel
  path (`#err("admin already set...")` on every call after).
- `setAdmin` is the governed rotation path afterward: only the current
  admin can hand off to a new principal.

## Operational requirement (this replaces what a constructor arg would have
## given you automatically)

**Call `bootstrapAdmin(<real admin principal>)` immediately after deploy, in
the same deploy script/session, before the canister id is shared or any
other call is made.** This is the "init then lock" discipline a constructor
argument enforces via the type system; here it's enforced by a runtime
check instead, so it depends on this being done promptly. Example, right
after `dfx deploy`:
```
dfx canister call title_registry bootstrapAdmin '(principal "<your-principal>")'
```

## What this does and doesn't fix

- **Fixes:** the specific hardcoded-placeholder bug — `admin` is no longer
  a value nobody controls, and it's a one-time, race-safe bootstrap rather
  than a "first caller after deploy wins in a race" pattern.
- **Doesn't fix (tracked separately, P3 in the roadmap):** this is still a
  single-principal model. A real allow-list or threshold scheme for admin
  actions is the next step up if that's needed operationally.
- **Verification:** typechecked with 0 errors (same single pre-existing
  unrelated warning in `Fp.mo` as before this change) against the real
  `motoko-base`/`motoko-core` sources, using the same JS-interpreted `moc`
  this project already falls back to without `dfx`. Not run on a real
  replica in this sandbox — same `dfx`/`pocket-ic` network limitation as
  the earlier Groth16 patches; recommend exercising `bootstrapAdmin` →
  `setAdmin` → re-attempt with the old admin (should fail) as part of the
  same real `dfx` session recommended for the P1 items in the roadmap.

## Round 2: allow-list upgrade (security review)

A follow-up security review asked to move past a single rotated principal
toward a real multi-principal allow-list, "changeable only through a
governed path". Landed in `main.mo`:

```motoko
var admins : [Principal] = [];       // stable by default (persistent actor)

func isAdmin(p : Principal) : Bool { ... }   // linear scan, list is tiny

public shared func bootstrapAdmin(realAdmin : Principal) : async Result.Result<(), Text>
public shared (msg) func addAdmin(newAdmin : Principal) : async Result.Result<(), Text>
public shared (msg) func removeAdmin(target : Principal) : async Result.Result<(), Text>
public shared query func listAdmins() : async [Principal]
```

- `bootstrapAdmin` succeeds only while the list is empty (same one-time
  sentinel semantics as round 1).
- `addAdmin`/`removeAdmin` require an existing admin caller.
- `removeAdmin` refuses to remove the **last** admin — the registry can
  never be left unadministered by accident.
- The list is a plain `[Principal]` array: stable across upgrades with no
  `preupgrade`/`postupgrade` hooks.
- `setAdmin` (round 1) is **removed** — there are no other callers in the
  repo; deploy scripts should use `addAdmin`/`removeAdmin`.

Verification: typechecked with **0 errors** on `main.mo`,
`verify_test/main.mo`, and `Groth16MultiTest.mo` using node-motoko's
JS-interpreted `moc` against real `motoko-base` (moc-1.9.0) and
`motoko-core` (2.5.0) sources — same single pre-existing unrelated M0155
warning in vendored `Fp.mo` as before. Still not run on a real replica
here (no `dfx`/`pocket-ic` in this sandbox); exercise
`bootstrapAdmin` → `addAdmin` → `removeAdmin` (incl. last-admin refusal
and non-admin refusal) in the real `dfx` session.

Still open (P3): a threshold/multi-sig admin scheme, and the multi-party
trusted-setup ceremony (see `circuit/src/bin/setup.rs` — now fail-closed
without an explicit `--allow-dev` flag).
