#!/usr/bin/env bash
# Creates the Secrets l8tunnel needs (they are never committed):
#   l8tunnel-agent-ca   the agent CA (ca.crt, ca.key) that signs agent certificates
#   l8tunnel-cluster    forward-key (signs PROXY headers between the edge and
#                       relays) and gateway-host-key (the SSH gateway's host
#                       key, the same on every relay)
# An existing Secret is never replaced (except the CA, when a directory is
# given): relays and agents depend on them staying the same.
#
# Usage: secrets.sh <kubectl context> [agent-ca-dir]
#   agent-ca-dir holds ca.crt and ca.key (for example the files
#   "l8tunnel-server export" wrote) and replaces the Secret. Without it a
#   new CA is generated, but only when there is no Secret yet.
set -e
CONTEXT="$1"
CA_DIR="$2"
if [ -z "$CONTEXT" ]; then
  echo "Usage: $0 <kubectl context> [agent-ca-dir]"
  exit 1
fi
KUBECTL=(kubectl --context "$CONTEXT")
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The same namespace (with its K8sRules label) the manifests declare.
cat <<NS | "${KUBECTL[@]}" apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: l8tunnel
  labels:
    name: l8tunnel
NS

if "${KUBECTL[@]}" -n l8tunnel get secret l8tunnel-cluster >/dev/null 2>&1; then
  echo "Secret l8tunnel-cluster already exists; keeping it."
else
  echo "Generating the cluster secret..."
  openssl rand -hex 32 > "$TMP/forward-key"
  ssh-keygen -q -t ed25519 -N "" -C "l8tunnel gateway" -f "$TMP/gateway-host-key"
  "${KUBECTL[@]}" -n l8tunnel create secret generic l8tunnel-cluster \
    --from-file=forward-key="$TMP/forward-key" --from-file=gateway-host-key="$TMP/gateway-host-key"
fi

if [ -z "$CA_DIR" ] && "${KUBECTL[@]}" -n l8tunnel get secret l8tunnel-agent-ca >/dev/null 2>&1; then
  # Never replace an existing CA by accident: every agent certificate it
  # signed would stop working. Pass a directory to replace it on purpose.
  echo "Secret l8tunnel-agent-ca already exists; keeping it."
  exit 0
fi
if [ -z "$CA_DIR" ]; then
  echo "Generating a new agent CA..."
  openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/ca.key"
  openssl req -x509 -new -key "$TMP/ca.key" -days 3650 -subj "/CN=l8tunnel agent CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign" \
    -out "$TMP/ca.crt" 2>/dev/null
  CA_DIR="$TMP"
fi
for f in ca.crt ca.key; do
  [ -f "$CA_DIR/$f" ] || { echo "missing $CA_DIR/$f"; exit 1; }
done

"${KUBECTL[@]}" -n l8tunnel create secret generic l8tunnel-agent-ca \
  --from-file=ca.crt="$CA_DIR/ca.crt" --from-file=ca.key="$CA_DIR/ca.key" \
  --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f -
echo "Secret l8tunnel-agent-ca is in place."
