# PATCH_NOTES — Ceremony tooling, package provenance, admin status (round 3)

This pass addressed the three items flagged as open after the security
hardening pass: the trusted-setup ceremony (mechanics + spec), base/core
package provenance, and the claimed hardcoded admin principal.

## 1. Admin principal — was already fixed, previous claim was stale

I re-checked before doing anything: `diff` between the uploaded
`main.mo` and the previously-hardened `motoko/src/main.mo` shows they are
**byte-identical**. The controller-gated `bootstrapAdmin` / `admins`
allowlist from the earlier security-hardening pass is already in place;
there is no hardcoded `"aaaaa-aa"` principal in the file I was given. The
claim to that effect in the prior turn's summary was wrong — flagging that
explicitly rather than re-doing work that wasn't needed, or worse,
pretending to fix something that wasn't broken.

## 2. `package_flags.sh` — real provenance gap, fixed and tested

**Before:** pointed `moc` directly at whatever `base`/`core` a local `dfx
cache install` happened to have bundled, with no check that this matched
the versions `mops.toml` declares (base 0.13.5, core 2.5.0), and no
recorded hash — so two different machines (or the same machine after a
`dfx` upgrade) could silently compile against different library sources.

**After:** rewritten to pin `base`/`core` to specific upstream git refs
(`caffeinelabs/motoko-base@moc-0.13.5`, `dfinity/motoko-core@v2.5.0` —
confirmed to exist via `git ls-remote`, not guessed), fetch them fresh via
`codeload.github.com` (reachable from this sandbox; the mops registry
itself at `icp-api.io` is not), and check a recorded content hash
(`mops.lock.json`) on every run — refusing to proceed (not just warning)
if the hash has changed. If a local `dfx` cache is also present, it's
diffed against the pinned version and any mismatch is surfaced loudly.

**Actually run, not just written:** I deleted the local cache and ran it
from scratch (confirmed real fetch + hash recording), ran it again
unchanged (confirmed idempotent match), then corrupted a cached file and
ran it a third time (confirmed it fails loudly with the exact expected
`FATAL` message rather than silently continuing).

**Honest residual gap, stated in the script's own comments:**
`caffeinelabs/motoko-base`'s tags follow a `moc-X.Y.Z` scheme (tied to the
compiler release each `base` version shipped with), not a `base-X.Y.Z`
scheme — mapping "base 0.13.5" to "moc-0.13.5" is a reasonable, standard
inference (the same one `dfx cache install` itself relies on), but it is
still an inference, not a guarantee from the real mops registry, which
this sandbox cannot reach. Closing that last gap needs `mops install` run
from a machine with mainnet access, diffed against `mops.lock.json`.

## 3. Trusted-setup ceremony — mechanics scripted, spec written, NOT run for real

I want to be precise about what this is and isn't, because it's the
highest-stakes item in this pass.

**What I built (`ceremony/`, a new Rust crate):** a working
`ceremony_init` / `ceremony_contribute` / `ceremony_verify` toolkit
implementing the delta-only Groth16 Phase-2 MPC (the same structure used
by Zcash Sapling / Filecoin / Semaphore), built on `ark-groth16`'s own
real `generate_parameters_with_qap` API rather than reimplemented
low-level crypto. Compiled clean via a real `rustc`/`cargo` 1.75.0
toolchain against the actual `ark-bls12-381`/`ark-groth16` dependency
tree (same approach as the Motoko compile-verification in the prior
pass, applied here to Rust).

**Actually run, not just written:**
- `ceremony_init` → produces round 0 with `delta` fixed to exactly the
  curve generator (confirmed via an internal assertion plus
  `ceremony_verify`'s independent check).
- `ceremony_contribute` → ran for two simulated participants ("Alice",
  "Bob"), each correctly rotating delta and rescaling the L/H query
  vectors.
- `ceremony_verify` → confirmed the full 3-round chain (init + 2
  contributions) verifies end-to-end via real pairing checks, not just
  hash bookkeeping.
- **A real bug this caught:** the first version checked one pairing per
  L/H query entry — correct, but this circuit's query vectors run into
  the tens of thousands of entries, so verification took minutes and blew
  through a tool timeout on the first full end-to-end timed run. Fixed by
  switching to the standard randomized-linear-combination batch check
  (Fiat-Shamir-derived challenge, 2 pairings total instead of thousands),
  then re-ran the full ceremony end-to-end successfully.
- **A forgery test, not just a tamper test:** flipping a byte in a
  published round file is caught by the cheap hash check alone — that's
  necessary but not sufficient evidence the crypto works. I additionally
  wrote a throwaway harness that forges a round with a *self-consistent
  but dishonest* delta contribution (correct hashes, wrong pairing
  relationship) and confirmed `ceremony_verify` rejects it specifically
  via the pairing-ratio check, with the exact expected error message —
  then deleted that harness before packaging, since it's a test artifact,
  not a deliverable.

**What this does NOT do, and cannot be made to do by one party working
alone:** `alpha`, `beta`, `gamma` are still fixed once, by whoever runs
`ceremony_init`, from that single run's combined entropy sources. This
tool only rotates `delta` across many participants — by design, matching
how real two-phase Groth16 ceremonies split the problem (see
`CEREMONY_SPEC.md`). Closing the full gap needs either reusing an
existing audited Phase 1 (Powers of Tau) transcript, or running one from
scratch with real, independent, non-colluding participants — genuinely
not something achievable by an AI assistant working alone in a sandbox,
regardless of tooling.

**Also not done:** the QAP-combination step that would let a real Phase 1
transcript be wired into `ceremony_init` instead of its own single-shot
alpha/beta/gamma generation. Scoped out explicitly in `CEREMONY_SPEC.md`
item 2 as its own follow-up task, because matching arkworks' internal
R1CS-to-QAP reduction correctly is substantial, security-critical work
that deserves dedicated effort and independent review — not something to
rush inside this pass.

**Not independently audited.** The pairing math is standard and I've
derived, tested, and confirmed it works against real forgery attempts in
this sandbox — but that's not equivalent to review by someone with Groth16
MPC expertise. Said plainly in `ceremony/src/lib.rs`'s module docs and in
`CEREMONY_SPEC.md`.

## Files added/changed this pass

- `package_flags.sh` — rewritten (see #2).
- `mops.lock.json` — new, recorded content-hash lockfile.
- `ceremony/` — new crate: `Cargo.toml`, `src/lib.rs`,
  `src/bin/ceremony_init.rs`, `src/bin/ceremony_contribute.rs`,
  `src/bin/ceremony_verify.rs`.
- `CEREMONY_SPEC.md` — new, the concrete checklist described above.
- `motoko/src/main.mo` — unchanged (see #1).
