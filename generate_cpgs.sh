#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"
RUST_GEN_DIR="$ROOT_DIR/rust_src"
C_TOOLS_DIR="$ROOT_DIR/c_tools"

# Default Input/Output
INPUT_FILE=""
OUTPUT_DIR="output"
LANG=""
CARGO_DIR=""
EDITION=""

print_usage() {
    echo "Usage: ./generate_cpgs.sh --lang <rust|c> --input <file> --output <dir> [--cargo-dir <dir>] [--edition <year>]"
    echo ""
    echo "Examples:"
    echo "  ./generate_cpgs.sh --lang rust --input examples/rust/simple.rs --output output/rust_run"
    echo "  ./generate_cpgs.sh --lang c --input examples/c/test.c --output output/c_run"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lang)
            LANG="$2"
            shift 2
            ;;
        --input)
            INPUT_FILE="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --cargo-dir)
            CARGO_DIR="$2"
            shift 2
            ;;
        --edition)
            EDITION="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            print_usage
            exit 1
            ;;
    esac
done

if [[ -z "$LANG" || -z "$INPUT_FILE" ]]; then
    echo "Error: --lang and --input are required."
    print_usage
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
ABS_INPUT="$(cd "$(dirname "$INPUT_FILE")"; pwd)/$(basename "$INPUT_FILE")"
ABS_OUTPUT="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR"; pwd)"

if [[ "$LANG" == "rust" ]]; then
    echo "[*] Generating Rust CPG..."

    # Default to nightly if not specified (required for rustc_private)
    if [[ -z "$RUSTUP_TOOLCHAIN" ]]; then
        export RUSTUP_TOOLCHAIN=nightly
    fi
    
    # Check if built
    NEED_BUILD=0
    if [[ ! -f "$RUST_GEN_DIR/target/release/rust-cpg-generator" ]]; then
        NEED_BUILD=1
    else
        if find "$RUST_GEN_DIR/src" -type f -newer "$RUST_GEN_DIR/target/release/rust-cpg-generator" | grep -q .; then
            NEED_BUILD=1
        fi
    fi

    if [[ "$NEED_BUILD" -eq 1 ]]; then
        echo "    Building Rust Generator..."
        cd "$RUST_GEN_DIR"
        cargo build --release --quiet
        cd "$ROOT_DIR"
    fi

    # Setup environment for rustc dynamic libs
    RUSTC_SYSROOT=$(rustc --print sysroot)
    HOST_TRIPLE=$(rustc -vV | grep host | cut -d: -f2 | tr -d ' ')
    RUSTC_LIB_PATH="$RUSTC_SYSROOT/lib/rustlib/$HOST_TRIPLE/lib"
    
    export DYLD_LIBRARY_PATH="$RUSTC_LIB_PATH:$DYLD_LIBRARY_PATH"
    export LD_LIBRARY_PATH="$RUSTC_LIB_PATH:$LD_LIBRARY_PATH"

    RUSTC_ARGS=()
    if [[ -n "$EDITION" ]]; then
        RUSTC_ARGS+=(--rustc-arg "--edition=$EDITION")
    fi

    if [[ -n "$CARGO_DIR" ]]; then
        CARGO_DIR_ABS="$(cd "$CARGO_DIR" && pwd)"
        CARGO_TARGET_DIR="$CARGO_DIR_ABS/target_cpg"
        DEPS_DIR="$CARGO_TARGET_DIR/debug/deps"
        if [[ ! -d "$DEPS_DIR" ]] || [[ -z "$(ls -1 "$DEPS_DIR"/lib*.rlib 2>/dev/null)" ]]; then
            echo "    Building Cargo workspace to produce rlibs..."
            RUSTUP_TOOLCHAIN="$RUSTUP_TOOLCHAIN" CARGO_TARGET_DIR="$CARGO_TARGET_DIR" cargo build --manifest-path "$CARGO_DIR_ABS/Cargo.toml"
        fi

        if [[ -d "$DEPS_DIR" ]]; then
            RUSTC_ARGS+=(--rustc-arg "-L" --rustc-arg "dependency=$DEPS_DIR")
            shopt -s nullglob
            SEEN_NAMES=()
            for rlib in "$DEPS_DIR"/lib*.rlib; do
                base="$(basename "$rlib")"
                name="${base#lib}"
                name="${name%%-*}"
                found=0
                for seen in "${SEEN_NAMES[@]}"; do
                    if [[ "$seen" == "$name" ]]; then
                        found=1
                        break
                    fi
                done
                if [[ "$found" -eq 1 ]]; then
                    continue
                fi
                SEEN_NAMES+=("$name")
                RUSTC_ARGS+=(--rustc-arg "--extern" --rustc-arg "$name=$rlib")
            done
            shopt -u nullglob
        fi
    fi

    "$RUST_GEN_DIR/target/release/rust-cpg-generator" \
        --input "$ABS_INPUT" \
        --output "$ABS_OUTPUT/cpg_final.json" \
        "${RUSTC_ARGS[@]}"
    
    echo "[+] Rust CPG saved to: $ABS_OUTPUT/cpg_final.json"

elif [[ "$LANG" == "c" ]]; then
    echo "[*] Generating C CPG..."
    
    # Check dependencies
    if ! command -v joern-parse &> /dev/null; then
        echo "Error: joern-parse not found. Please install Joern."
        exit 1
    fi

    BIN_OUTPUT="$ABS_OUTPUT/cpg.bin"
    EXPORT_DIR="$ABS_OUTPUT/cpg_export"
    JSON_OUTPUT="$ABS_OUTPUT/cpg_final.json"

    # Give Joern explicit heap settings instead of relying on JVM defaults.
    # These can still be overridden by the caller if needed.
    JOERN_PARSE_JAVA_TOOL_OPTIONS_DEFAULT="-Xms4g -Xmx32g -XX:+UseG1GC"
    JOERN_EXPORT_JAVA_TOOL_OPTIONS_DEFAULT="-Xms8g -Xmx96g -XX:+UseG1GC"
    JOERN_PARSE_JAVA_TOOL_OPTIONS="${JOERN_PARSE_JAVA_TOOL_OPTIONS:-$JOERN_PARSE_JAVA_TOOL_OPTIONS_DEFAULT}"
    JOERN_EXPORT_JAVA_TOOL_OPTIONS="${JOERN_EXPORT_JAVA_TOOL_OPTIONS:-$JOERN_EXPORT_JAVA_TOOL_OPTIONS_DEFAULT}"

    if [[ -n "${JAVA_TOOL_OPTIONS:-}" ]]; then
        JOERN_PARSE_JAVA_TOOL_OPTIONS="$JOERN_PARSE_JAVA_TOOL_OPTIONS $JAVA_TOOL_OPTIONS"
        JOERN_EXPORT_JAVA_TOOL_OPTIONS="$JOERN_EXPORT_JAVA_TOOL_OPTIONS $JAVA_TOOL_OPTIONS"
    fi

    # 1. Joern Parse
    JAVA_TOOL_OPTIONS="$JOERN_PARSE_JAVA_TOOL_OPTIONS" \
        joern-parse "$ABS_INPUT" --output "$BIN_OUTPUT"

    # 2. Joern Export
    rm -rf "$EXPORT_DIR"
    JAVA_TOOL_OPTIONS="$JOERN_EXPORT_JAVA_TOOL_OPTIONS" \
        joern-export "$BIN_OUTPUT" --repr all --format graphml --out "$EXPORT_DIR"

    # 3. Convert to JSON
    echo "    Converting GraphML to JSON..."
    python3 "$C_TOOLS_DIR/convert_graphml_to_json.py" \
        "$EXPORT_DIR" \
        "$JSON_OUTPUT" \
        --include-nodes "METHOD,CALL,BLOCK,CONTROL_STRUCTURE,LOCAL,RETURN,IDENTIFIER,LITERAL,METHOD_RETURN,METHOD_PARAMETER_IN" \
        --include-edges "AST,CALL,CFG,CFG_UNWIND,ARGUMENT,DDG,DOMINATE,POST_DOMINATE,REACHING_DEF,CONTAINS,BINDS,REF"

    echo "[+] C CPG saved to: $JSON_OUTPUT"

else
    echo "Error: Unsupported language '$LANG'. Use 'rust' or 'c'."
    exit 1
fi
