#!/usr/bin/env zsh
set -e

ROOT_DIR="$(cd -- "${0:A:h}/../.." && pwd)"
SRC_DIR="$ROOT_DIR/vulnerabilities/Indirect_Libxml2/c_src"
CARGO_DIR="$ROOT_DIR/vulnerabilities/Indirect_Libxml2/rust_app"
OUT_DIR="$ROOT_DIR/output/vulnerabilities/Indirect_Libxml2/artifacts"

SO_DIR="$ROOT_DIR/vendor/so/libxml2-2.9.3"
INSTALL_DIR="$SO_DIR/install"
LIBXML2_LIB="$INSTALL_DIR/lib"
LIBXML2_INC="$INSTALL_DIR/include/libxml2"

mkdir -p "$OUT_DIR"

echo "[1] Fetching/building libxml2..."
python3 "$ROOT_DIR/tools/fetch/fetch_official_so.py" \
  --sources "$ROOT_DIR/tools/fetch/so_sources.json" \
  --index "$ROOT_DIR/output/vulnerabilities/so_index.json"

echo "[2] Building C components..."
cc -fPIC -shared \
  -I"$LIBXML2_INC" \
  -L"$LIBXML2_LIB" \
  -lxml2 \
  -o "$OUT_DIR/libcompb.so" \
  "$SRC_DIR/component_b.c"

cc -fPIC -shared \
  -L"$OUT_DIR" -lcompb \
  -o "$OUT_DIR/libcompa.so" \
  "$SRC_DIR/component_a.c"

echo "[3] Building Rust driver (Cargo)..."
COMP_A_LIB_DIR="$OUT_DIR" \
COMP_B_LIB_DIR="$OUT_DIR" \
LIBXML2_LIB_DIR="$LIBXML2_LIB" \
cargo build -p app --manifest-path "$CARGO_DIR/Cargo.toml"

RUST_BIN="$CARGO_DIR/target/debug/app"

echo "[+] Build complete."
echo "Run with:"
echo "  export LD_LIBRARY_PATH=\"$OUT_DIR:$LIBXML2_LIB:\$LD_LIBRARY_PATH\""
echo "  $RUST_BIN"
