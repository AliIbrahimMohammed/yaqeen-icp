# Deployment — running Yaqeen on ICP

How to run the `title_registry` canister on a local replica and on the
Internet Computer mainnet. Sources: the Motoko Book (IC deployment), the
DFINITY SDK docs, and this project's own canister API.

## Prerequisites

- [DFINITY SDK](https://internetcomputer.org/docs/building-apps/getting-started/install) (`dfx` ≥ 0.32.0, ships `moc` and `candid`)
- Mainnet deployment additionally needs an **identity with cycles** (ICP converted to cycles)

## 1. Local replica (development)

```bash
dfx start --background          # boot a local replica
dfx deploy                      # compile + create + install title_registry & verify_test
dfx canister call title_registry bootstrapAdmin '(principal "<your-principal>")'
```

State persists across `dfx start`/`stop` (`.dfx/`), so the registry,
challenges, and nullifiers survive restarts.

## 2. Mainnet (production network)

### 2.1 Verify connectivity and identity

```bash
dfx ping ic                     # expect JSON with ic_api_version
dfx identity whoami             # active identity
dfx identity get-principal      # principal that pays the cycles
dfx wallet balance --network ic # cycles available
```

If your identity holds cycles directly (no legacy wallet), add
`--no-wallet` to the deploy/call commands below.

### 2.2 Deploy

One-step (create + build + install):

```bash
dfx deploy --network ic --no-wallet
```

Or step by step, per canister:

```bash
dfx canister create title_registry --network ic        # registers the canister id
dfx build title_registry --network ic                  # compiles Motoko -> wasm
dfx canister install title_registry --network ic       # installs the wasm
```

`dfx deploy title_registry --network ic` combines all three. On success
dfx prints the mainnet canister id (also in `canister_ids.json`).

### 2.3 Bootstrap the admin — controller-gated, immediately

`admin` starts **unset** on a fresh canister. `bootstrapAdmin` only
succeeds if the **caller is one of the canister's controllers**
(checked against the management canister; fails closed if it's
unreachable). Call it *from the deploying identity*, before the canister
id is shared with anyone:

```bash
dfx canister --network ic status title_registry    # confirms current controllers
dfx canister --network ic call title_registry bootstrapAdmin '(principal "<your-principal>")'
```

The controller gate closes the first-come-first-served takeover race on a
fresh canister id and locks permanently after the first success. Admin
management from then on (governed by existing admins):

```bash
dfx canister --network ic call title_registry addAdmin '(principal "<other-principal>")'
dfx canister --network ic call title_registry removeAdmin '(principal "<other-principal>")'
dfx canister --network ic call title_registry listAdmins '()'
```

(In the local-replica section above, replace the plain `bootstrapAdmin`
call with the same controller-gated form — the first `dfx` identity owns
the deployed canister and is its controller.)

### 2.4 Configure the verifying key (ceremony output required)

```bash
# first VK on a fresh deploy — activates immediately (deploy ceremony)
dfx canister --network ic call title_registry setVerifyingKey '("<vk-hex>")'
```

**Do not use output from `circuit/src/bin/setup.rs` for real value** — it is
dev-only and fail-closed (`--allow-dev` required) precisely because a
single-party setup holds the toxic waste. Only a verifying key produced by
a real multi-party ceremony (or a transparent-setup scheme) belongs on
mainnet. See `README.md` → Security model.

**Rotating the verifying key later is threshold-2**: one admin stages the
replacement, then a *different* admin confirms it (or cancels):

```bash
dfx canister --network ic call title_registry setVerifyingKey '("<new-vk-hex>")'        # stages
dfx canister --network ic call title_registry getVkStatus '()'                          # shows pending
dfx canister --network ic call title_registry confirmVerifyingKey '("<new-vk-hex>")'    # by a 2nd admin
# dfx canister --network ic call title_registry cancelVerifyingKeyChange '()'           # to abort instead
```

### 2.5 Use the canister

```bash
# register a title record (admin; expiry must be a future unix-seconds value)
dfx canister --network ic call title_registry submitRecord '(1, 12345, 0, 1, 4102444800)'
# issue a challenge (anyone)
dfx canister --network ic call title_registry requestChallenge '(1)'
# verify a proof (anyone; paid update call — ~20.9B instructions, multi-second)
dfx canister --network ic call title_registry verify '(record { challengeId = 0; proofBytes = blob "…"; publicInputs = vec { … } })'
# status / cycle balance of the live canister
dfx canister --network ic status title_registry
```

Any browser can reach a public canister at `https://<canister-id>.ic0.app`.

## 3. Inspecting what was deployed

| Check | Command |
|---|---|
| Network reachability | `dfx ping ic` |
| Canister id | `cat canister_ids.json` |
| Status/cycles | `dfx canister --network ic status <name>` |
| Candid interface | `dfx canister --network ic metadata <name> candid:service` |

## 4. Teardown (local or mainnet)

```bash
dfx canister stop <name> [--network ic]
dfx canister delete <name> [--network ic]   # returns remaining cycles to your wallet
```

## 5. Testing without dfx (this repo)

`node-tests/` runs typecheck + wasm-compile + the Poseidon vector + the
canister functional driver using node-motoko's JS interpreter — no dfx
needed:

```bash
bash node-tests/run-tests.sh
```

The one thing it cannot do is a real replica run (pairing-cost paths).
After any deployment, exercise `bootstrapAdmin` → `addAdmin` →
`removeAdmin` (incl. last-admin refusal) and a real verify against a
freshly-issued challenge on the replica itself.
