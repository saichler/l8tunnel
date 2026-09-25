#!/usr/bin/env bash
# Installs (or renews) the relay's TLS certificate and restarts the relay.
#   sudo ./install-cert.sh [--no-restart] domain.cert.pem private.key.pem
# The certificate file should hold the full chain (Porkbun's domain.cert.pem does).
set -euo pipefail

RESTART=1
if [ "${1:-}" = "--no-restart" ]; then RESTART=0; shift; fi
[ $# -eq 2 ] || { sed -n '2,3p' "$0"; exit 2; }
CERT="$1" KEY="$2"
die() { echo "install-cert: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root"
[ -r "$CERT" ] || die "can't read $CERT"
[ -r "$KEY" ] || die "can't read $KEY"
getent group l8tunnel >/dev/null || die "run install.sh first (no l8tunnel group)"

if command -v openssl >/dev/null; then
  openssl x509 -in "$CERT" -noout 2>/dev/null || die "$CERT is not a PEM certificate"
  [ "$(openssl x509 -in "$CERT" -noout -pubkey)" = "$(openssl pkey -in "$KEY" -pubout 2>/dev/null)" ] ||
    die "the private key doesn't match the certificate"
  openssl x509 -in "$CERT" -noout -checkend 0 >/dev/null || die "the certificate has already expired"
  names="$(openssl x509 -in "$CERT" -noout -ext subjectAltName 2>/dev/null | grep -o 'DNS:[^,]*' | tr '\n' ' ')"
  expires="$(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2)"
fi

install -d -m 0750 -o root -g l8tunnel /etc/l8tunnel/tls
install -m 0644 -o root -g l8tunnel "$CERT" /etc/l8tunnel/tls/fullchain.pem
install -m 0640 -o root -g l8tunnel "$KEY" /etc/l8tunnel/tls/privkey.pem
echo "installed certificate for ${names:-?}(expires ${expires:-?})"

if [ "$RESTART" -eq 1 ] && systemctl is-enabled --quiet l8tunnel-server 2>/dev/null; then
  systemctl restart l8tunnel-server
  sleep 2
  systemctl is-active --quiet l8tunnel-server || { journalctl -u l8tunnel-server -n 20 --no-pager >&2; die "the relay didn't come back up"; }
  echo "restarted l8tunnel-server"
fi
