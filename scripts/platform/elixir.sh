#!/usr/bin/env bash
set -euo pipefail

# Owned by the Phoenix builder. Invoked from the repository root.
if [[ ! -d packages/elixir ]]; then
    echo 'skipped: packages/elixir not present'
    exit 0
fi
mode=${1:?task mode required}
shift
cd packages/elixir
export MIX_ENV=test
case "$mode" in
check | full)
    mix deps.get --check-locked
    mix compile --warnings-as-errors
    mix format --check-formatted
    mix credo --strict
    mix test
    ;;
staged)
    if (($#)); then mix format --check-formatted "$@"; fi
    ;;
fix) mix format ;;
*)
    echo "unknown Elixir task: $mode" >&2
    exit 2
    ;;
esac
