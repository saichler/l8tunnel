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

# Pin the KIND context instead of inheriting the ambient one (kind create
# cluster rewrites the current context). The other modes deploy to the
# caller's context on purpose.
KUBECTL=(kubectl)
if [ "$MODE" = "kind" ]; then
  KUBECTL=(kubectl --context "kind-l8tunnel")
fi

# The edge and the web UI run only on the node labeled
# l8tunnel.io/edge=true, except in single-node KIND.
if [ "$MODE" != "kind" ] && [ -z "$("${KUBECTL[@]}" get nodes -l l8tunnel.io/edge=true -o name)" ]; then
  echo "No node is labeled l8tunnel.io/edge=true; run k8s/label-edge.sh <node> first."
  exit 1
fi

echo "Applying l8tunnel (${MODE})..."
"${KUBECTL[@]}" apply -f "$FILE"

# wait_for waits for an app's workload, whatever its kind in this mode
# (DaemonSet, StatefulSet or Deployment).
wait_for() {
  local workload
  workload=$("${KUBECTL[@]}" -n l8tunnel get daemonset,statefulset,deployment -l "app=$1" -o name | head -1)
  echo "Waiting for $1 (${workload})..."
  "${KUBECTL[@]}" -n l8tunnel rollout status "$workload" --timeout="${2:-180s}"
}

# Dependency order: vnet -> logs -> backend -> web -> registry -> edge.
wait_for l8tunnel-vnet
wait_for l8tunnel-log-vnet
wait_for l8tunnel-log-agent
wait_for l8tunnel 300s
wait_for l8tunnel-web
wait_for l8tunnel-registry
wait_for l8tunnel-edge
# Relays become ready once a tunnel certificate exists (uploaded in the UI,
# or the first-start l8tunnel-tls Secret), so they aren't waited for here.

echo "l8tunnel deployed (${MODE})."
