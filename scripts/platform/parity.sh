#!/usr/bin/env bash
set -euo pipefail

# Spring HTTP conformance, with a pinned Rails reference oracle.
# Explicit profile arguments use the owner-aware runner (including cookie login CSRF).
if [[ ${1:-} == full ]]; then shift; fi
if (($#)); then
    exec contracts/conformance/run.sh "$@"
fi
# Default: every profile against the packaged Spring sample (plain HTTP, so no Secure cookies).
bash scripts/platform/java.sh sample
OGIRI_COOKIE_SECURE=false exec contracts/conformance/run.sh --profile all \
    --sample-command 'python3 examples/spring-app/run.py'
