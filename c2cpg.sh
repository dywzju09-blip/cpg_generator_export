#!/usr/bin/env bash
set -euo pipefail

export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"

CP="$(find /root/.m2/repository -name '*.jar' | paste -sd: -)"

JAVA_OPTS=()
ARGS=()

for arg in "$@"; do
  if [[ "$arg" == -J* ]]; then
    JAVA_OPTS+=("${arg:2}")
  else
    ARGS+=("$arg")
  fi
done

exec java "${JAVA_OPTS[@]}" -cp "$CP" io.joern.c2cpg.Main "${ARGS[@]}"
