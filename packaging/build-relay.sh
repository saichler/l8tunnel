#!/usr/bin/env bash
# Builds the relay install package: dist/l8tunnel-server-<version>-linux-<arch>.tar.gz
#   ./packaging/build-relay.sh [amd64|arm64|armv7]
set -euo pipefail
cd "$(dirname "$0")/.."
ARCH="${1:-amd64}"
case "$ARCH" in
  amd64|arm64) GOARCH="$ARCH" GOARM="" ;;
  armv7) GOARCH=arm GOARM=7 ;;
  *) echo "unknown arch $ARCH" >&2; exit 2 ;;
esac
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
NAME="l8tunnel-server-${VERSION}-linux-${ARCH}"
STAGE="dist/$NAME"
rm -rf "$STAGE" && mkdir -p "$STAGE/bin"
(cd go && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOARM="$GOARM" \
  go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "../$STAGE/bin/" ./cmd/l8tunnel-server)
cp packaging/relay/install.sh packaging/relay/install-cert.sh packaging/relay/uninstall.sh \
   packaging/relay/server.yaml packaging/relay/README.txt "$STAGE/"
cp deploy/systemd/l8tunnel-server.service "$STAGE/"
echo "$ARCH" > "$STAGE/ARCH"
chmod 0755 "$STAGE"/*.sh
tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
echo "dist/$NAME.tar.gz"
