#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  cat <<'EOF'
Usage: run_analysis_bundle.sh <bundle_root> <manifest> <run_name>

Required layout:
  <bundle_root>/cpg_generator_export
  <bundle_root>/VUL

Environment:
  CPG_NEO4J_URI
  CPG_NEO4J_USER
  CPG_NEO4J_PASSWORD
  SUPPLYCHAIN_DISABLE_NATIVE_SOURCE_SUPPLEMENT=1  Optional.
EOF
  exit 1
fi

BUNDLE_ROOT="$(cd "$1" && pwd)"
MANIFEST="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
RUN_NAME="$3"

export SUPPLYCHAIN_VUL_ROOT="${SUPPLYCHAIN_VUL_ROOT:-$BUNDLE_ROOT/VUL}"
export SUPPLYCHAIN_ARCHIVE_ROOT="${SUPPLYCHAIN_ARCHIVE_ROOT:-$BUNDLE_ROOT/VUL/cases/by-analysis-status}"

REPO_ROOT="$BUNDLE_ROOT/cpg_generator_export"

cd "$REPO_ROOT"

CMD=(
  python3 tools/supplychain/run_manifest_analysis.py
  --manifest "$MANIFEST"
  --run-name "$RUN_NAME"
  --archive
)

if [[ "${SUPPLYCHAIN_DISABLE_NATIVE_SOURCE_SUPPLEMENT:-0}" == "1" ]]; then
  CMD+=(--disable-native-source-supplement)
fi

"${CMD[@]}"

echo "Archived results under: $SUPPLYCHAIN_ARCHIVE_ROOT"
