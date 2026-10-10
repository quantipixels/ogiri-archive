#!/usr/bin/env bash
set -euo pipefail

# Owned by the FastAPI builder. Invoked from the repository root.
if [[ ! -d packages/python ]]; then
    echo 'skipped: packages/python not present'
    exit 0
fi
mode=${1:?task mode required}
shift
cd packages/python
case "$mode" in
check | full)
    uv run ruff check .
    uv run ruff format --check .
    uv run pytest
    ;;
staged)
    if (($#)); then
        uv run --no-sync ruff check "$@"
        uv run --no-sync ruff format --check "$@"
    fi
    ;;
fix)
    uv run ruff check --fix .
    uv run ruff format .
    ;;
*)
    echo "unknown Python task: $mode" >&2
    exit 2
    ;;
esac
