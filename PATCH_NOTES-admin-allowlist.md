# Fix: multi-principal admin allow-list (P3 item from the roadmap)

## What changed

`main.mo`'s admin model went from a single hardcoded principal, to a
one-time-bootstrapped single principal (the previous fix in this series),
to a real multi-principal allow-list:

```motoko
var adminsEntries : [(Principal, ())] = [];
transient let admins = HashMap.fromIter<Principal, ()>(adminsEntries.vals(), 10, Principal.equal, Principal.hash);

func isAdmin(p : Principal) : Bool { admins.get(p) != null };

public shared func bootstrapAdmin(realAdmin : Principal) : async Result.Result<(), Text> { ... };
public shared (msg) func addAdmin(newAdmin : Principal) : async Result.Result<(), Text> { ... };
public shared (msg) func removeAdmin(oldAdmin : Principal) : async Result.Result<(), Text> { ... };
```

- `bootstrapAdmin` works once — succeeds only while the allow-list is empty.
- `addAdmin`/`removeAdmin` are governed: only a current admin can call them.
- `removeAdmin` refuses to remove the last remaining admin — the allow-list
  can never be emptied out from under itself, which would permanently brick
  every admin-gated function with no recovery path.
- The allow-list persists across upgrades using the same
  stable-array-as-transfer-buffer pattern already used for `records`/`nodes`/
  `challenges`/`nullifiers` elsewhere in this file: `preupgrade` copies the
  live `admins` HashMap into `adminsEntries`, `postupgrade` clears it back to
  `[]` once the `transient let admins = HashMap.fromIter(adminsEntries.vals(), ...)`
  initializer has already consumed it.

`submitRecord` and `setVerifyingKey`'s admin checks were updated from
`?msg.caller != admin` to `not isAdmin(msg.caller)`.

## Why this, beyond the earlier single-admin fix

The roadmap's P3 called this out specifically: "move past a single
hardcoded principal toward a real allow-list or threshold scheme." A single
admin principal is a single point of failure — losing that one key/identity
locks out all admin functionality permanently, with no recovery path. A
small allow-list (a few independent, trusted principals) means losing any
one identity doesn't lock out the registry, and it's a meaningfully smaller
change than a full threshold-signature scheme while covering the realistic
failure mode (one lost/compromised key) that matters most operationally.

## Verified

Typechecked with 0 errors against the real `motoko-base`/`motoko-core`
sources — confirmed for `main.mo` directly and for the full project
(including the alpha/beta Groth16 patch, the fast-subgroup-check additions,
and the differential test file) typechecking together with 0 errors. Not
run on a real replica here — same `dfx` limitation as every other patch in
this series. Recommended verification sequence under a real `dfx` session:
`bootstrapAdmin` → `addAdmin` a second principal → `removeAdmin` the first
→ confirm the second can still act as admin → attempt to remove the last
remaining admin and confirm it's refused.
