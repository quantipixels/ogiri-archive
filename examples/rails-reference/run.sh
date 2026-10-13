#!/usr/bin/env sh
set -eu
example_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec "$example_dir/../../contracts/conformance/run.sh" "$@"
