#!/usr/bin/env bash
# Builds the agent install package.
#   ./packaging/build-agent.sh [amd64|arm64|armv7] [DOMAIN] [RELAY_ADDR]
# DOMAIN is the relay's base domain; it defaults to the base_domain of
# packaging/relay/server.yaml. Agents connect to connect.DOMAIN:443, or to
# RELAY_ADDR (e.g. 192.168.1.120 for agents on the relay's own network,
# which avoids the router's loopback path); the relay's certificate is
# still verified as connect.DOMAIN.
#
# ENROLL_TOKEN_FILE=<file> builds a no-questions package: the token in that
# file goes into the package, and install.sh installs, names the machine
# after its host name and exposes ENROLL_EXPOSE (default ssh+https: SSH as
# <host>-ssh and https://<host>.DOMAIN passed through to the machine's own
# HTTPS server). Anyone holding such a package can register an agent, so
# give it a token of its own and revoke that token to retire the package.
set -euo pipefail
cd "$(dirname "$0")/.."
ARCH="${1:-amd64}"
DOMAIN="${2:-$(sed -n 's/^base_domain: *//p' packaging/relay/server.yaml | head -1)}"
RELAY_ADDR="${3:-}"
case "$ARCH" in
  amd64|arm64) GOARCH="$ARCH" GOARM="" ;;
  armv7) GOARCH=arm GOARM=7 ;;
  *) echo "unknown arch $ARCH" >&2; exit 2 ;;
esac
echo "$DOMAIN" | grep -Eq '^[a-z0-9.-]+\.[a-z]+$' || { echo "invalid domain $DOMAIN" >&2; exit 2; }
if [ -n "$RELAY_ADDR" ]; then
  case "$RELAY_ADDR" in *:*) ;; *) RELAY_ADDR="$RELAY_ADDR:443" ;; esac
  echo "$RELAY_ADDR" | grep -Eq '^[A-Za-z0-9.-]+:[0-9]+$' || { echo "invalid relay address $RELAY_ADDR" >&2; exit 2; }
fi
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
LABEL="$DOMAIN"; [ -n "$RELAY_ADDR" ] && LABEL="$DOMAIN-via-${RELAY_ADDR%:*}"
ENROLL_TOKEN_FILE="${ENROLL_TOKEN_FILE:-}"
ENROLL_EXPOSE="${ENROLL_EXPOSE:-ssh+https}"
if [ -n "$ENROLL_TOKEN_FILE" ]; then
  grep -Eq '^l8t_[0-9a-f]+_[A-Za-z0-9_-]+$' "$ENROLL_TOKEN_FILE" || { echo "$ENROLL_TOKEN_FILE doesn't hold an agent token" >&2; exit 2; }
  case "$ENROLL_EXPOSE" in ssh|ssh+https) ;; *) echo "ENROLL_EXPOSE must be ssh or ssh+https" >&2; exit 2 ;; esac
  LABEL="$LABEL-enroll"
fi
NAME="l8tunnel-agent-${LABEL}-${VERSION}-linux-${ARCH}"
STAGE="dist/$NAME"
rm -rf "$STAGE" && mkdir -p "$STAGE/bin"
(cd go && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOARM="$GOARM" \
  go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "../$STAGE/bin/" ./cmd/l8tunnel-agent ./cmd/l8tunnel)
cp packaging/agent/install.sh packaging/agent/uninstall.sh packaging/agent/README.txt "$STAGE/"
cp deploy/systemd/l8tunnel-agent.service "$STAGE/"
echo "$ARCH" > "$STAGE/ARCH"
echo "$DOMAIN" > "$STAGE/DOMAIN"
[ -n "$RELAY_ADDR" ] && echo "$RELAY_ADDR" > "$STAGE/RELAY"
if [ -n "$ENROLL_TOKEN_FILE" ]; then
  install -m 0600 "$ENROLL_TOKEN_FILE" "$STAGE/TOKEN"
  echo "$ENROLL_EXPOSE" > "$STAGE/EXPOSE"
fi
chmod 0755 "$STAGE"/*.sh
tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
[ -n "$ENROLL_TOKEN_FILE" ] && echo "no-questions package: token built in, exposes $ENROLL_EXPOSE"
echo "dist/$NAME.tar.gz  (relay ${RELAY_ADDR:-connect.$DOMAIN:443}${RELAY_ADDR:+, certificate checked as connect.$DOMAIN})"
