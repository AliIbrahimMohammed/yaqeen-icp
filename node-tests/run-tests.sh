#!/usr/bin/env bash
# Run the node-motoko test suite (typecheck + wasm compile + Poseidon
# vector + canister functional driver) without dfx.
#
# Downloads node-motoko (npm) and real motoko-base/motoko-core sources
# (GitHub) on first run; caches them under node-tests/.packages.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d node_modules/motoko ]; then
  echo "== installing node-motoko (npm) =="
  npm install motoko --no-save >/dev/null
fi

PKG=".packages"
mkdir -p "$PKG"

if [ ! -d "$PKG/base" ]; then
  echo "== fetching motoko-base (moc-1.9.0) =="
  curl -sL -o "$PKG/base.zip" "https://codeload.github.com/caffeinelabs/motoko-base/zip/refs/tags/moc-1.9.0"
  unzip -q -o "$PKG/base.zip" -d "$PKG"
  mv "$PKG/motoko-base-moc-1.9.0" "$PKG/base-src"
  mkdir -p "$PKG/base" && cp -r "$PKG/base-src/src/." "$PKG/base/"
  rm -rf "$PKG/base-src" "$PKG/base.zip"
fi

if [ ! -d "$PKG/core" ]; then
  echo "== fetching motoko-core (v2.5.0) =="
  curl -sL -o "$PKG/core.zip" "https://codeload.github.com/dfinity/motoko-core/zip/refs/tags/v2.5.0"
  unzip -q -o "$PKG/core.zip" -d "$PKG"
  mv "$PKG/motoko-core-2.5.0" "$PKG/core-src"
  mkdir -p "$PKG/core" && cp -r "$PKG/core-src/src/." "$PKG/core/"
  rm -rf "$PKG/core-src" "$PKG/core.zip"
fi

export YAQEEN_TEST_BASE="$(pwd)/$PKG/base"
export YAQEEN_TEST_CORE="$(pwd)/$PKG/core"

echo "== running node-motoko test suite =="
node tests.js
