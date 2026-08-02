# Fix: hardcoded admin principal (P0.1 from the roadmap)

## What changed

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
