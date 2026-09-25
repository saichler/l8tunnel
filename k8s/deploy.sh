#!/usr/bin/env bash
set -e

MODE="${1:-local}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FILE="${SCRIPT_DIR}/l8tunnel-${MODE}.yaml"

if [ ! -f "$FILE" ]; then
  echo "Usage: $0 [local|baremetal|gke|kind]"
  echo "  (no l8tunnel-${MODE}.yaml found in ${SCRIPT_DIR})"
  exit 1
fi

# Per-node workloads are DaemonSets in local/gke mode and StatefulSets in
# baremetal/kind mode (K8sRules).
WORKLOAD_KIND="daemonset"
if [ "$MODE" = "baremetal" ] || [ "$MODE" = "kind" ]; then
  WORKLOAD_KIND="statefulset"
fi

# Pin the KIND context instead of inheriting the ambient one (kind create
# cluster rewrites the current context). The other modes deploy to the
# caller's context on purpose.
KUBECTL=(kubectl)
if [ "$MODE" = "kind" ]; then
  KUBECTL=(kubectl --context "kind-l8tunnel")
fi

echo "Applying l8tunnel (${MODE})..."
"${KUBECTL[@]}" apply -f "$FILE"

# Dependency order: vnet -> backend -> web.
echo "Waiting for l8tunnel-vnet..."
"${KUBECTL[@]}" -n l8tunnel rollout status "${WORKLOAD_KIND}/l8tunnel-vnet" --timeout=180s
echo "Waiting for l8tunnel (backend)..."
"${KUBECTL[@]}" -n l8tunnel rollout status statefulset/l8tunnel --timeout=300s
echo "Waiting for l8tunnel-web..."
"${KUBECTL[@]}" -n l8tunnel rollout status "${WORKLOAD_KIND}/l8tunnel-web" --timeout=180s

echo "l8tunnel deployed (${MODE})."
