#!/usr/bin/env bash
set -euo pipefail

# Owned by the parity builder. The uv suite lands in contracts/conformance.
# The existing standalone check.py is not the new cross-platform parity suite.
if [[ ! -f contracts/conformance/pyproject.toml ]]; then
    echo 'skipped: contracts/conformance/pyproject.toml not present (parity suite pending)'
    exit 0
fi
# Explicit profile arguments use the owner-aware runner (including cookie login CSRF).
if [[ ${1:-} == full ]]; then shift; fi
if (($#)); then
    exec contracts/conformance/run.sh "$@"
fi
cd contracts/conformance
uv sync --locked
uv run pytest
