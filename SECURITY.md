# Security Policy

This repository holds a ZK-based registry on the Internet Computer. It
combines a Motoko canister, a Groth16 verifier, and a Poseidon-based
Merkle tree. Security is taken seriously; any flaw in access control,
the crypto layer, or the canister's trust boundary could compromise real
records.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Instead, report privately to the maintainers. If you don't have a
maintainer contact handy, please reach out via the repository owner's
e-mail address listed in the git history / GitHub profile, or open a
_private_ GitHub advisory if you are able to (Repository →
Security → Report a vulnerability).

Please include:

- The component affected (canister `motoko/src/main.mo`, the vendored
  verifier, the circuit, the Merkle/Touching construction).
- The attack scenario and its impact (e.g. cycles-drain, unauthorized
  admin, challenge forgery, upgrade memory exhaustion).
- A minimal reproduction: command-level call shape, input values, and
  expected vs. observed result.
- Whether it has been observed on a live replica or only in sandboxed/
  compiler-level testing — this project is explicit about what was and was
  not actually run.

## Known, documented risk areas

Review `README.md` and the `PATCH_NOTES-*.md` files for the maintainers'
own, honest statement of what is still unconfirmed:

- The **trusted-setup** is single-party dev-only (`circuit/src/bin/setup.rs`);
  a real multi-party ceremony is required before real value.
- The **admin provisioning** must never be a hardcoded principal in
  production; bootstrap is controller-gated, `addAdmin`/`removeAdmin` are
  allow-list governed, and the last admin cannot be removed.
- **`verify` is a ~21B-instruction update call**: it is DoS-mitigated by
  per-principal throttles and anonymous-caller rejection but not eliminated.
- The vendored Groth16 verifier is **unmodified** upstream code — do not
  patch it in this repo; fixes go upstream.

## Reporting expectations

We aim to acknowledge reports within 48 hours and to verify or triage the
situation on a reasonable time frame. After a public fix and release,
details may be disclosed at the maintainers' discretion.