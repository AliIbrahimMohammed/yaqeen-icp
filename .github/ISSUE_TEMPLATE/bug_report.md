---
name: Bug report
about: Report a reproducible problem with the circuit, the canister, or the tooling
title: "[bug] "
labels: bug
assignees: ""
---

## Description

A clear, concise description of the bug.

## Component

- [ ] Canister (`motoko/src/main.mo`)
- [ ] Circuit / Rust tooling (`circuit/`)
- [ ] Vendored Groth16 verifier (`motoko/src/groth16/vendor/`)
- [ ] Tests / harness (Poseidon hashing, Merkle path, verify_test/)
- [ ] Docs / CI / tooling

## Reproduction

Steps to reproduce, with exact commands and inputs:

1. ...
2. ...

```bash
# if applicable, the exact command(s)
```

## Expected vs observed

- Expected:
- Observed:

## What verification did you actually run?

Be explicit the way the repo already does — distinguish "compiled/typechecked
only" from "run on a live `dfx`/`pocket-ic` replica." If crypto or
security-related, include instruction counts or replica output if you have it.

- [ ] Compiler/typecheck only
- [ ] Ran `circuit/src/bin/*` tooling
- [ ] Ran on a live replica (dfx / pocket-ic)

## Environment

- rustc / cargo version:
- `moc` / motoko npm package version:
- dfx version:
- mops.toml resolved packages:

Please use the issue prepended with `[security]` if you believe this is a
security concern, and consider `SECURITY.md` for private reporting instead.