#!/usr/bin/env bash
set -e
# Marks the node the router forwards the public ports to: the edge and the
# web UI run only there (nodeSelector l8tunnel.io/edge=true).
# Usage: k8s/label-edge.sh <node> [context]
NODE="$1"
if [ -z "$NODE" ]; then
  echo "Usage: $0 <node> [context]"
  kubectl ${2:+--context "$2"} get nodes -o wide
  exit 1
fi
kubectl ${2:+--context "$2"} label node "$NODE" l8tunnel.io/edge=true --overwrite
echo "Node ${NODE} runs the l8tunnel edge and web UI."
