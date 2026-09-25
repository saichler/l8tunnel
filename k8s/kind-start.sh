#!/usr/bin/env bash
set -e

CLUSTER_NAME="l8tunnel"
KIND_CONFIG="kind-cluster.yaml"
KUBECTL=(kubectl --context "kind-${CLUSTER_NAME}")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v kind &>/dev/null; then
  echo "kind not found — installing..."
  curl -Lo ./kind https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64
  chmod +x ./kind
  sudo mv ./kind /usr/local/bin/kind
fi

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  echo "KIND cluster '${CLUSTER_NAME}' already exists. Run ./kind-stop.sh first to recreate it."
  exit 1
fi

# One node (control plane only; KIND makes it schedulable). The web UI's
# port is mapped to the host so tests reach it at https://localhost:5443.
cat > "${SCRIPT_DIR}/${KIND_CONFIG}" <<'KIND'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 5443
        hostPort: 5443
        protocol: TCP
      # The relays' NodePorts (tests reach each relay directly).
      - {containerPort: 30443, hostPort: 30443, protocol: TCP}
      - {containerPort: 30444, hostPort: 30444, protocol: TCP}
      - {containerPort: 30222, hostPort: 30222, protocol: TCP}
      - {containerPort: 31443, hostPort: 31443, protocol: TCP}
      - {containerPort: 31444, hostPort: 31444, protocol: TCP}
      - {containerPort: 31222, hostPort: 31222, protocol: TCP}
KIND

echo "Creating KIND cluster '${CLUSTER_NAME}'..."
kind create cluster --name "${CLUSTER_NAME}" --config "${SCRIPT_DIR}/${KIND_CONFIG}"
"${KUBECTL[@]}" wait --for=condition=Ready nodes --all --timeout=120s

echo "Loading images into KIND..."
IMAGES=(
  saichler/l8tunnel-vnet:latest
  saichler/l8tunnel:latest
  saichler/l8tunnel-web:latest
  saichler/l8tunnel-registry:latest
  saichler/l8tunnel-relay:latest
)
for img in "${IMAGES[@]}"; do
  if docker image inspect "$img" &>/dev/null; then
    echo "  Loading $img..."
    kind load docker-image "$img" --name "${CLUSTER_NAME}"
  else
    echo "  SKIP $img (not found locally; the cluster will pull it)"
  fi
done

"${SCRIPT_DIR}/secrets.sh" "kind-${CLUSTER_NAME}"
"${SCRIPT_DIR}/deploy.sh" kind

echo ""
echo "l8tunnel is up in KIND: https://localhost:5443 (admin/admin)."
echo "Run ./kind-stop.sh to tear it down."
