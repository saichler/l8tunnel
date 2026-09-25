#!/usr/bin/env bash
# Builds release binaries into dist/<os>-<arch>/.
#   ./build.sh            all platforms
#   ./build.sh linux/arm64 darwin/arm64
# The relay (l8tunnel-server) is built for Linux only; the agent and the
# l8tunnel client helper for every platform.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
PLATFORMS=("$@")
if [ ${#PLATFORMS[@]} -eq 0 ]; then
  PLATFORMS=(linux/amd64 linux/arm64 linux/arm/7 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64)
fi

for platform in "${PLATFORMS[@]}"; do
  IFS=/ read -r os arch arm <<<"$platform"
  out="dist/${os}-${arch}${arm:+v$arm}"
  mkdir -p "$out"
  cmds=(./cmd/l8tunnel-agent ./cmd/l8tunnel)
  [ "$os" = linux ] && cmds+=(./cmd/l8tunnel-server)
  echo "building $out (${VERSION})"
  (cd go && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOARM="$arm" \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "../$out/" "${cmds[@]}")
done
