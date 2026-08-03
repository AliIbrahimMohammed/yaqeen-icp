#!/bin/bash
# Stand-in for `mops sources`, hardened.
#
# WHAT CHANGED FROM THE PREVIOUS VERSION, AND WHY:
#
# The previous version pointed moc straight at whatever base/core happened
# to be sitting in `dfx cache install`'s local directory for this dfx
# version, with no check that those sources actually matched the versions
# mops.toml declares (base 0.13.5, core 2.5.0), and no recorded hash to
# detect drift later. That's a real provenance gap: two people running this
# script on two different dfx installs (or the same person after a `dfx
# upgrade`) could silently compile against two different base/core trees
# with no error, no warning, and no way to later prove what was actually
# used to produce a given canister WASM.
#
# The real fix is `mops install` from a machine that can reach the mops
# registry on ICP mainnet (icp-api.io) — this sandbox's network allowlist
# doesn't include that host, so this script still can't call the actual
# registry. What it CAN do, using hosts that ARE reachable
# (github.com/codeload.github.com), is:
#
#   1. Pin base/core to a specific upstream git ref per package, chosen to
#      match the versions mops.toml declares (see PINNED_REFS below).
#   2. Download each pinned ref fresh (or reuse a local cache keyed by that
#      exact ref) rather than trusting dfx's bundle.
#   3. Compute a deterministic content hash over every file in each
#      package and check it against mops.lock.json. First run on a given
#      machine records the hash (TOFU); every run after that either
#      matches or fails loudly — it does not silently continue on a
#      mismatch.
#   4. If a dfx cache IS present locally, additionally diff its base/core
#      against the pinned download and WARN (not silently prefer one over
#      the other) if they differ, so a real `dfx`-based build downstream
#      can't quietly diverge from what typechecked here.
#
# HONEST RESIDUAL GAP: `caffeinelabs/motoko-base`'s git tags follow the
# `moc-X.Y.Z` scheme (tied to the moc compiler release each version of
# base shipped with), not a `base-X.Y.Z` scheme — I'm inferring that
# `moc-0.13.5`'s bundled base is what mops calls "base 0.13.5" by
# convention, the same inference dfx's own cache bundling already relies
# on. That inference, and this whole pinned-to-GitHub approach, is still
# not the same guarantee as asking the actual mops registry "what bytes do
# you serve for base@0.13.5" — the registry could in principle point at an
# untagged commit or a tree that doesn't match any GitHub tag at all. This
# script narrows the provenance gap from "trust dfx's cache, unverified,
# unrecorded" to "trust these specific recorded commit hashes, checked on
# every run" — it does not close the gap entirely. That still needs someone
# with mainnet access to run `mops install` and diff the result against
# mops.lock.json below.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCKFILE="$REPO_ROOT/mops.lock.json"
CACHE_DIR="${MOPS_PINNED_CACHE:-$HOME/.cache/motoko-pinned}"

# Package name -> "github_owner/repo@git_ref"
declare -A PINNED_REFS=(
  [base]="caffeinelabs/motoko-base@moc-0.13.5"
  [core]="dfinity/motoko-core@v2.5.0"
)

log() { echo "[package_flags] $*" >&2; }

tree_hash() {
  # Deterministic hash over every file's path + content, independent of
  # mtimes/permissions/download order.
  local dir="$1"
  find "$dir" -type f -not -path '*/.git/*' -print0 \
    | sort -z \
    | while IFS= read -r -d '' f; do
        rel="${f#"$dir"/}"
        printf '%s\0' "$rel"
        sha256sum "$f" | cut -d' ' -f1
        printf '\0'
      done \
    | sha256sum | cut -d' ' -f1
}

fetch_pinned() {
  local pkg="$1"
  local spec="${PINNED_REFS[$pkg]}"
  local repo="${spec%@*}"
  local ref="${spec#*@}"
  local dest="$CACHE_DIR/$pkg-$ref"

  if [ ! -d "$dest" ]; then
    log "fetching $pkg from $repo@$ref (not cached yet at $dest)"
    mkdir -p "$dest"
    local tmp
    tmp="$(mktemp -d)"
    curl -sL "https://codeload.github.com/$repo/tar.gz/$ref" -o "$tmp/src.tar.gz"
    tar -xzf "$tmp/src.tar.gz" -C "$tmp"
    local extracted
    extracted="$(find "$tmp" -maxdepth 1 -mindepth 1 -type d | head -1)"
    # mops expects the package directory itself to contain src/, not a
    # wrapper folder — base/core repos keep the library under src/.
    cp -r "$extracted/src" "$dest/src" 2>/dev/null || cp -r "$extracted"/* "$dest/"
    rm -rf "$tmp"
  fi
  echo "$dest"
}

check_or_record_hash() {
  local pkg="$1" dir="$2"
  local actual
  actual="$(tree_hash "$dir")"

  local recorded=""
  if [ -f "$LOCKFILE" ]; then
    recorded="$(python3 -c "
import json,sys
try:
    d = json.load(open('$LOCKFILE'))
    print(d.get('$pkg', {}).get('tree_sha256', ''))
except Exception:
    print('')
")"
  fi

  if [ -z "$recorded" ]; then
    log "no recorded hash for '$pkg' yet in mops.lock.json — recording $actual (trust-on-first-use; review this commit before relying on it)"
    python3 - "$LOCKFILE" "$pkg" "$actual" "${PINNED_REFS[$pkg]}" <<'PYEOF'
import json, sys, os
lockfile, pkg, tree_sha256, spec = sys.argv[1:5]
d = {}
if os.path.exists(lockfile):
    d = json.load(open(lockfile))
d[pkg] = {"pinned_ref": spec, "tree_sha256": tree_sha256}
json.dump(d, open(lockfile, "w"), indent=2, sort_keys=True)
PYEOF
  elif [ "$recorded" != "$actual" ]; then
    log "FATAL: '$pkg' content hash changed since it was last recorded."
    log "  recorded: $recorded"
    log "  actual:   $actual"
    log "  This means either the pinned ref was force-moved upstream (rare, investigate!)"
    log "  or the local cache at $CACHE_DIR was tampered with/corrupted. Refusing to build."
    exit 1
  else
    log "'$pkg' content hash matches mops.lock.json ($actual)"
  fi
}

warn_if_dfx_cache_diverges() {
  local pkg="$1" pinned_dir="$2"
  local dfx_versions_dir="$HOME/.cache/dfinity/versions"
  [ -d "$dfx_versions_dir" ] || return 0
  local dfx_pkg_dir
  dfx_pkg_dir="$(find "$dfx_versions_dir" -maxdepth 2 -type d -name "$pkg" 2>/dev/null | head -1)"
  [ -n "$dfx_pkg_dir" ] || return 0

  local dfx_hash pinned_hash
  dfx_hash="$(tree_hash "$dfx_pkg_dir")"
  pinned_hash="$(tree_hash "$pinned_dir")"
  if [ "$dfx_hash" != "$pinned_hash" ]; then
    log "WARNING: local dfx cache's '$pkg' ($dfx_pkg_dir) does NOT match the pinned"
    log "  $pkg (${PINNED_REFS[$pkg]}) used for this typecheck/compile. A real \`dfx deploy\`"
    log "  on this machine using its own cache would build against DIFFERENT source than"
    log "  what was verified here. Investigate before deploying — do not ignore this."
  else
    log "local dfx cache's '$pkg' matches the pinned version — consistent."
  fi
}

BASE_DIR="$(fetch_pinned base)"
CORE_DIR="$(fetch_pinned core)"

check_or_record_hash base "$BASE_DIR"
check_or_record_hash core "$CORE_DIR"

warn_if_dfx_cache_diverges base "$BASE_DIR"
warn_if_dfx_cache_diverges core "$CORE_DIR"

echo "--package base $BASE_DIR/src --package core $CORE_DIR/src"
