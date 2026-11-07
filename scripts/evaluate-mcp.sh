#!/usr/bin/env bash
# Prepare synthetic catalog/result fixtures. This script never calls a model.
set -euo pipefail
cd "$(dirname "$0")/.."
evaluation_dir="${1:-${TMPDIR:-/tmp}/forti-mcp-evaluation}"
mkdir -p "$evaluation_dir"
evaluation_dir="$(cd "$evaluation_dir" && pwd)"
export FORTI_EVAL_DIR="$evaluation_dir"
{
  git rev-parse HEAD
  go version
  git status --short
  git diff --stat
} > "$evaluation_dir/manifest.txt"
go test -count=1 -v ./internal/mcpserver ./internal/service \
  -run '^Test(CatalogMeasurements|CompactInvestigationPreservesDiagnosticEvidence|ResultFixtureMeasurements)$' \
  | tee "$evaluation_dir/measurements.txt"
printf 'Synthetic evaluation artifacts: %s\n' "$evaluation_dir"
