#!/bin/bash
# Stand-in for `mops sources`. The real mops CLI resolves packages via the
# mops registry, which lives on ICP mainnet (icp-api.io) — not reachable from
# this sandbox's network allowlist. Instead, point moc directly at the real
# base/core libraries `dfx cache install` already bundles for this exact dfx
# version (0.32.0) — these are the same real, unmodified library sources,
# just resolved locally instead of through the mops registry.
DFX_CACHE="$HOME/.cache/dfinity/versions/0.32.0"
echo "--package base $DFX_CACHE/base --package core $DFX_CACHE/core"
