#!/usr/bin/env sh
set -eu
suite_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec uv run --project "$suite_dir" python "$suite_dir/runner.py" "$@"
