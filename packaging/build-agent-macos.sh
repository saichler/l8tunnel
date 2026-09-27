#!/usr/bin/env bash
# Builds the macOS agent package (launchd; SSH only).
#   ./packaging/build-agent-macos.sh [arm64|amd64] [DOMAIN]
# DOMAIN defaults to the base_domain of packaging/relay/server.yaml; the agent
# connects to connect.DOMAIN:443.
# ENROLL_TOKEN_FILE=<file> puts that token in the package, so install.sh asks
# nothing. Anyone holding such a package can register an agent: give it a
# token of its own and revoke that token to retire the package.
# TEMPLATE=1 builds it without a token, named l8tunnel-agent-download-...:
# the management UI adds a new token (and the domain) to each download.
set -euo pipefail
cd "$(dirname "$0")/.."
ARCH="${1:-arm64}"
DOMAIN="${2:-$(sed -n 's/^base_domain: *//p' packaging/relay/server.yaml | head -1)}"
case "$ARCH" in arm64|amd64) ;; *) echo "unknown arch $ARCH (arm64 or amd64)" >&2; exit 2 ;; esac
echo "$DOMAIN" | grep -Eq '^[a-z0-9.-]+\.[a-z]+$' || { echo "invalid domain $DOMAIN" >&2; exit 2; }
ENROLL_TOKEN_FILE="${ENROLL_TOKEN_FILE:-}"
LABEL="$DOMAIN"
if [ -n "$ENROLL_TOKEN_FILE" ]; then
  grep -Eq '^l8t_[0-9a-f]+_[A-Za-z0-9_-]+$' "$ENROLL_TOKEN_FILE" || { echo "$ENROLL_TOKEN_FILE doesn't hold an agent token" >&2; exit 2; }
  LABEL="$DOMAIN-enroll"
fi
TEMPLATE="${TEMPLATE:-}"
[ -n "$TEMPLATE" ] && [ -n "$ENROLL_TOKEN_FILE" ] && { echo "TEMPLATE and ENROLL_TOKEN_FILE exclude each other" >&2; exit 2; }
[ -n "$TEMPLATE" ] && LABEL="download"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
NAME="l8tunnel-agent-${LABEL}-${VERSION}-darwin-${ARCH}"
STAGE="dist/$NAME"
rm -rf "$STAGE" && mkdir -p "$STAGE/bin"
(cd go && CGO_ENABLED=0 GOOS=darwin GOARCH="$ARCH" \
  go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "../$STAGE/bin/" ./cmd/l8tunnel-agent ./cmd/l8tunnel)
cp packaging/agent-macos/install.sh packaging/agent-macos/uninstall.sh packaging/agent-macos/README.txt "$STAGE/"
echo "$ARCH" > "$STAGE/ARCH"
echo "$DOMAIN" > "$STAGE/DOMAIN"
[ -n "$ENROLL_TOKEN_FILE" ] && install -m 0600 "$ENROLL_TOKEN_FILE" "$STAGE/TOKEN"
chmod 0755 "$STAGE"/*.sh
tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
[ -n "$ENROLL_TOKEN_FILE" ] && echo "no-questions package: token built in, exposes ssh"
echo "dist/$NAME.tar.gz  (relay connect.$DOMAIN:443)"
