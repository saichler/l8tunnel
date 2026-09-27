#!/usr/bin/env bash
set -e
# $1: amd64, arm64, or blank to build both.
cd "$(dirname "$0")"
case "$1" in
    amd64) PLATFORM=linux/amd64 ;;
    arm64) PLATFORM=linux/arm64 ;;
    "") PLATFORM=linux/amd64,linux/arm64 ;;
    *) echo "Usage: $0 [amd64|arm64]"; exit 1 ;;
esac

# The agent packages the dashboard offers for download: templates without a
# token or domain (the browser adds a new token and the cluster's domain to
# each download), served from web/downloads/ (not in git).
DL=web/downloads
rm -rf "$DL" && mkdir -p "$DL"
(cd ../../.. && TEMPLATE=1 ./packaging/build-agent.sh amd64 unset.invalid >/dev/null &&
  TEMPLATE=1 ./packaging/build-agent-macos.sh arm64 unset.invalid >/dev/null)
cp ../../../dist/l8tunnel-agent-download-"$(git describe --tags --always --dirty)"-linux-amd64.tar.gz "$DL/l8tunnel-agent-linux-amd64.tar.gz"
cp ../../../dist/l8tunnel-agent-download-"$(git describe --tags --always --dirty)"-darwin-arm64.tar.gz "$DL/l8tunnel-agent-darwin-arm64.tar.gz"

docker buildx build --no-cache --platform=$PLATFORM -t saichler/l8tunnel-web:latest --push .
