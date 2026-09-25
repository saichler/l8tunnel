#!/usr/bin/env bash
set -e
MODE="${1:-local}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KUBECTL=(kubectl)
if [ "$MODE" = "kind" ]; then
  KUBECTL=(kubectl --context "kind-l8tunnel")
fi
"${KUBECTL[@]}" delete -f "${SCRIPT_DIR}/l8tunnel-${MODE}.yaml" --ignore-not-found
echo "l8tunnel removed (${MODE}). The Secrets stay; delete the namespace to remove them."
