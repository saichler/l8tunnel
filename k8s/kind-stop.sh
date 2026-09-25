#!/usr/bin/env bash
set -e
CLUSTER_NAME="l8tunnel"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if ! command -v kind &>/dev/null || ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "KIND cluster '${CLUSTER_NAME}' does not exist."
  exit 0
fi
kind delete cluster --name "${CLUSTER_NAME}"
rm -f "${SCRIPT_DIR}/kind-cluster.yaml"
echo "KIND cluster '${CLUSTER_NAME}' deleted."
