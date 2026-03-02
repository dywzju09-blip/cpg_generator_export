#!/usr/bin/env zsh
set -e

ROOT_DIR="$(cd -- "${0:A:h}" && pwd)"

# Build real PoC and .so (libxml2 2.9.3)
zsh "$ROOT_DIR/vulnerabilities/Indirect_Libxml2/run_poc.sh"

OUTPUT_DIR="$ROOT_DIR/output/vulnerabilities/Indirect_Libxml2"
mkdir -p "$OUTPUT_DIR/cpg"

# Generate CPGs
"$ROOT_DIR/generate_cpgs.sh" --lang c --input "$ROOT_DIR/vulnerabilities/Indirect_Libxml2/c_src/component_a.c" --output "$OUTPUT_DIR/cpg/c_sc_xml_a"
"$ROOT_DIR/generate_cpgs.sh" --lang c --input "$ROOT_DIR/vulnerabilities/Indirect_Libxml2/c_src/component_b.c" --output "$OUTPUT_DIR/cpg/c_sc_xml_b"
"$ROOT_DIR/generate_cpgs.sh" \
  --lang rust \
  --input "$ROOT_DIR/vulnerabilities/Indirect_Libxml2/rust_app/app/src/main.rs" \
  --output "$OUTPUT_DIR/cpg/rust_sc_xml" \
  --cargo-dir "$ROOT_DIR/vulnerabilities/Indirect_Libxml2/rust_app" \
  --edition 2021

# Import into Neo4j
python3 "$ROOT_DIR/tools/neo4j/import_cpg.py" "$OUTPUT_DIR/cpg/c_sc_xml_a/cpg_final.json" --clear --offset 0 --label C
python3 "$ROOT_DIR/tools/neo4j/import_cpg.py" "$OUTPUT_DIR/cpg/c_sc_xml_b/cpg_final.json" --offset 500000 --label C
python3 "$ROOT_DIR/tools/neo4j/import_cpg.py" "$OUTPUT_DIR/cpg/rust_sc_xml/cpg_final.json" --offset 1000000 --label Rust

# Cross-language linking
python3 "$ROOT_DIR/tools/neo4j/link_cpgs.py" --log "$OUTPUT_DIR/linking_log.json"

# Auto-generate supply-chain extras (C/.so deps)
python3 "$ROOT_DIR/tools/supplychain/auto_extras.py" \
  --cargo-dir "$ROOT_DIR/vulnerabilities/Indirect_Libxml2/rust_app" \
  --so-dir "$OUTPUT_DIR/artifacts" \
  --so-dir "$ROOT_DIR/vendor/so/libxml2-2.9.3/install/lib" \
  --out "$OUTPUT_DIR/auto_extras_libxml2.json"

# Supply-chain analysis (deps from cargo metadata + extras)
python3 "$ROOT_DIR/tools/supplychain/supplychain_analyze.py" \
  --cargo-dir "$ROOT_DIR/vulnerabilities/Indirect_Libxml2/rust_app" \
  --extras "$OUTPUT_DIR/auto_extras_libxml2.json" \
  --vulns "$ROOT_DIR/tools/supplychain/supplychain_vulns_libxml2.json" \
  --report "$OUTPUT_DIR/analysis_report.json" \
  --clear-supplychain

echo "[+] Pipeline complete."
