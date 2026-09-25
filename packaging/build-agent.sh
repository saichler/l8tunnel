#!/usr/bin/env bash
# Builds the agent install package.
#   ./packaging/build-agent.sh [amd64|arm64|armv7] [DOMAIN]
# DOMAIN is the relay's base domain (agents connect to connect.DOMAIN:443);
# it defaults to the base_domain of packaging/relay/server.yaml.
set -euo pipefail
cd "$(dirname "$0")/.."
ARCH="${1:-amd64}"
DOMAIN="${2:-$(sed -n 's/^base_domain: *//p' packaging/relay/server.yaml | head -1)}"
case "$ARCH" in
  amd64|arm64) GOARCH="$ARCH" GOARM="" ;;
  armv7) GOARCH=arm GOARM=7 ;;
  *) echo "unknown arch $ARCH" >&2; exit 2 ;;
esac
echo "$DOMAIN" | grep -Eq '^[a-z0-9.-]+\.[a-z]+$' || { echo "invalid domain $DOMAIN" >&2; exit 2; }
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
NAME="l8tunnel-agent-${DOMAIN}-${VERSION}-linux-${ARCH}"
STAGE="dist/$NAME"
rm -rf "$STAGE" && mkdir -p "$STAGE/bin"
(cd go && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOARM="$GOARM" \
  go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "../$STAGE/bin/" ./cmd/l8tunnel-agent ./cmd/l8tunnel)
cp packaging/agent/install.sh packaging/agent/uninstall.sh packaging/agent/README.txt "$STAGE/"
cp deploy/systemd/l8tunnel-agent.service "$STAGE/"
echo "$ARCH" > "$STAGE/ARCH"
echo "$DOMAIN" > "$STAGE/DOMAIN"
chmod 0755 "$STAGE"/*.sh
tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
echo "dist/$NAME.tar.gz  (relay connect.$DOMAIN:443)"
