#!/usr/bin/env bash
set -euo pipefail

# Spring HTTP conformance, with a pinned Rails reference oracle.
# Explicit profile arguments use the owner-aware runner (including cookie login CSRF).
if [[ ${1:-} == full ]]; then shift; fi
if (($#)); then
    exec contracts/conformance/run.sh "$@"
fi
cd contracts/conformance
uv sync --locked
uv run pytest
