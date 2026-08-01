---
name: Bug report
about: Report a bug — including a cryptographic or verifier bug
title: ""
labels: bug
assignees: ""
---

**Check first**: if this involves a possible security vulnerability
(accepting a forged proof, replay, admin bypass), do not file publicly — see
SECURITY.md.

## Description

<!-- What happened, what did you expect? -->

## Component

- [ ] circuit/ (Rust/arkworks)
- [ ] motoko/ canister (main.mo)
- [ ] motoko/src/groth16 (verifier / adapter)
- [ ] motoko/src/poseidon
- [ ] verify_test/ or tooling

## Reproduction

<!-- Exact commands or inputs. For crypto issues: witness values, proof bytes, challenge state. -->

## What was verified and how

<!-- Real dfx/pocket-ic replica? In-process oracle? Typecheck only? -->

## Environment

- dfx version: <!-- if used -->
- rustc version: <!-- if used -->
- moc / mops versions: <!-- if used -->
- OS:

## Screenshots / logs

<!-- Optional -->
