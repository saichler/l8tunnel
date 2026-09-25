#!/usr/bin/env bash
# Builds the relay install package.
#   ./packaging/build-relay.sh [amd64|arm64|armv7] [CERT_DIR]
# With CERT_DIR (holding domain.cert.pem and private.key.pem, e.g. a Porkbun
# SSL bundle) the certificate and key go into the package and the base
# domain is taken from the certificate's wildcard name, so install.sh needs
# no arguments. The package then contains a private key: keep it private.
set -euo pipefail
cd "$(dirname "$0")/.."
ARCH="${1:-amd64}"
CERT_DIR="${2:-}"
case "$ARCH" in
  amd64|arm64) GOARCH="$ARCH" GOARM="" ;;
  armv7) GOARCH=arm GOARM=7 ;;
  *) echo "unknown arch $ARCH" >&2; exit 2 ;;
esac
die() { echo "build-relay: $*" >&2; exit 1; }

DOMAIN=""
if [ -n "$CERT_DIR" ]; then
  CERT="$CERT_DIR/domain.cert.pem" KEY="$CERT_DIR/private.key.pem"
  [ -r "$CERT" ] && [ -r "$KEY" ] || die "$CERT_DIR must contain domain.cert.pem and private.key.pem"
  [ "$(openssl x509 -in "$CERT" -noout -pubkey)" = "$(openssl pkey -in "$KEY" -pubout 2>/dev/null)" ] ||
    die "the private key doesn't match the certificate"
  openssl x509 -in "$CERT" -noout -checkend 604800 >/dev/null || die "the certificate expires within a week"
  DOMAIN="$(openssl x509 -in "$CERT" -noout -ext subjectAltName | grep -o 'DNS:\*\.[^,]*' | head -1 | sed 's/^DNS:\*\.//')"
  [ -n "$DOMAIN" ] || die "the certificate has no wildcard name (*.example.com); the relay needs one"
fi

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
NAME="l8tunnel-relay${DOMAIN:+-$DOMAIN}-${VERSION}-linux-${ARCH}"
STAGE="dist/$NAME"
rm -rf "$STAGE" && mkdir -p "$STAGE/bin"
(cd go && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOARM="$GOARM" \
  go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "../$STAGE/bin/" ./cmd/l8tunnel-server)
cp packaging/relay/install.sh packaging/relay/install-cert.sh packaging/relay/uninstall.sh \
   packaging/relay/server.yaml packaging/relay/README.txt "$STAGE/"
cp deploy/systemd/l8tunnel-server.service "$STAGE/"
echo "$ARCH" > "$STAGE/ARCH"
if [ -n "$DOMAIN" ]; then
  sed -i "s/^base_domain: .*/base_domain: $DOMAIN/" "$STAGE/server.yaml"
  mkdir -p "$STAGE/certs"
  install -m 0644 "$CERT" "$STAGE/certs/fullchain.pem"
  install -m 0600 "$KEY" "$STAGE/certs/privkey.pem"
fi
chmod 0755 "$STAGE"/*.sh
tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
chmod 0600 "dist/$NAME.tar.gz"
echo "dist/$NAME.tar.gz${DOMAIN:+  (base domain $DOMAIN, includes the certificate and private key)}"
