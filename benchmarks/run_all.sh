#!/usr/bin/env bash
# Runs every benchmark target and writes benchmarks/results/latest.md (WP-9.1).
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run python benchmarks/run_all.py "$@"
