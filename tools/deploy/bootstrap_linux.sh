#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage: bootstrap_linux.sh [workspace]

Prepare a Linux host for the CPG + supply-chain analysis tool.
Defaults:
  workspace: /opt/cpg_bundle

Environment:
  JOERN_VERSION   Optional. If set, install Joern into $workspace/joern.
  RUST_TOOLCHAIN  Optional. Default nightly.
EOF
  exit 0
fi

WORKSPACE="${1:-/opt/cpg_bundle}"
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-nightly}"

sudo apt-get update
sudo apt-get install -y \
  build-essential \
  clang \
  cmake \
  curl \
  git \
  graphviz \
  jq \
  libclang-dev \
  libssl-dev \
  openjdk-17-jre-headless \
  pkg-config \
  python3 \
  python3-pip \
  python3-venv \
  unzip \
  zlib1g-dev

if ! command -v rustup >/dev/null 2>&1; then
  curl https://sh.rustup.rs -sSf | sh -s -- -y
fi

export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install "$RUST_TOOLCHAIN"
rustup default "$RUST_TOOLCHAIN"

python3 -m pip install --user --upgrade pip
python3 -m pip install --user neo4j

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed. Install docker if you want the bundled Neo4j workflow." >&2
fi

if [[ -n "${JOERN_VERSION:-}" ]]; then
  mkdir -p "$WORKSPACE"
  cd "$WORKSPACE"
  if [[ ! -d "$WORKSPACE/joern/joern-cli" ]]; then
    curl -L "https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/joern-install.sh" -o joern-install.sh
    bash joern-install.sh --version "$JOERN_VERSION" --install-dir "$WORKSPACE/joern"
    rm -f joern-install.sh
  fi
fi

echo "Linux bootstrap completed."
