#!/usr/bin/env bash
# Installs (or upgrades) the l8tunnel relay as a systemd service.
#   sudo ./install.sh [--domain example.com] [--cert domain.cert.pem --key private.key.pem] [--no-start]
# --domain sets base_domain in a fresh /etc/l8tunnel/server.yaml (default: the packaged one).
set -euo pipefail
cd "$(dirname "$0")"

CERT="" KEY="" START=1 DOMAIN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --cert) CERT="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --no-start) START=0; shift ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    -h|--help) sed -n '2,4p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

die() { echo "install: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./install.sh)"
command -v systemctl >/dev/null || die "systemd is required"
[ -z "$CERT$KEY" ] || [ -n "$CERT" -a -n "$KEY" ] || die "--cert and --key go together"
if [ -n "$DOMAIN" ]; then
  echo "$DOMAIN" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' || die "--domain $DOMAIN is not a domain name"
fi
# The packaged config, with --domain applied.
PKGCONF="$(mktemp)"
trap 'rm -f "$PKGCONF"' EXIT
if [ -n "$DOMAIN" ]; then
  sed "s/^base_domain: .*/base_domain: $DOMAIN/" server.yaml > "$PKGCONF"
else
  cp server.yaml "$PKGCONF"
fi
want_arch="$(cat ARCH)"
case "$(uname -m)" in
  x86_64) have_arch=amd64 ;; aarch64) have_arch=arm64 ;; armv7l) have_arch=armv7 ;; *) have_arch="$(uname -m)" ;;
esac
[ "$have_arch" = "$want_arch" ] || die "this package is for linux/$want_arch, but this machine is $have_arch"

NOLOGIN="$(command -v nologin || echo /usr/bin/nologin)"
if ! getent passwd l8tunnel >/dev/null; then
  useradd --system --user-group --home-dir /var/lib/l8tunnel --no-create-home --shell "$NOLOGIN" l8tunnel
  echo "created system user l8tunnel"
fi

was_active=0
systemctl is-active --quiet l8tunnel-server 2>/dev/null && was_active=1

install -m 0755 bin/l8tunnel-server /usr/local/bin/l8tunnel-server
install -d -m 0755 /etc/l8tunnel
install -d -m 0750 -o root -g l8tunnel /etc/l8tunnel/tls
if [ -e /etc/l8tunnel/server.yaml ]; then
  if [ "$(sha256sum < "$PKGCONF")" != "$(sha256sum < /etc/l8tunnel/server.yaml)" ]; then
    install -m 0640 -o root -g l8tunnel "$PKGCONF" /etc/l8tunnel/server.yaml.new
    echo "kept your /etc/l8tunnel/server.yaml; the packaged version is /etc/l8tunnel/server.yaml.new"
  fi
else
  install -m 0640 -o root -g l8tunnel "$PKGCONF" /etc/l8tunnel/server.yaml
fi
BASE="$(sed -n 's/^base_domain: *//p' /etc/l8tunnel/server.yaml | head -1)"
echo "base domain: $BASE (tunnels at <name>.$BASE, agents connect to connect.$BASE)"
install -m 0644 l8tunnel-server.service /etc/systemd/system/l8tunnel-server.service
systemctl daemon-reload
systemctl enable --quiet l8tunnel-server
echo "installed $(/usr/local/bin/l8tunnel-server -version)"

if [ -n "$CERT" ]; then
  ./install-cert.sh --no-restart "$CERT" "$KEY"
fi

# Ports the relay needs, unless it is the one holding them.
for port in 443 80; do
  holder="$(ss -ltnpH "sport = :$port" 2>/dev/null | grep -o 'users:(("[^"]*"' | head -1 | cut -d'"' -f2 || true)"
  if [ -n "$holder" ] && [ "$holder" != "l8tunnel-server" ]; then
    echo "WARNING: port $port is already used by $holder; the relay can't start until it's free" >&2
  fi
done

started=0
if [ ! -s /etc/l8tunnel/tls/fullchain.pem ] || [ ! -s /etc/l8tunnel/tls/privkey.pem ]; then
  echo
  echo "No certificate installed yet, so the relay isn't started. Install one with:"
  echo "  sudo $(pwd)/install-cert.sh /path/to/domain.cert.pem /path/to/private.key.pem"
elif [ "$START" -eq 1 ]; then
  if [ "$was_active" -eq 1 ]; then systemctl restart l8tunnel-server; else systemctl start l8tunnel-server; fi
  sleep 2
  if systemctl is-active --quiet l8tunnel-server; then
    started=1
    echo "l8tunnel-server is running"
  else
    echo "l8tunnel-server failed to start:" >&2
    journalctl -u l8tunnel-server -n 20 --no-pager >&2 || true
    exit 1
  fi
fi

cat <<MSG

Next steps
  1. DNS: *.$BASE  A  <this machine's public IP>
     Any existing explicit records (e.g. $BASE, www) keep working; they take precedence.
  2. Firewall: allow inbound TCP 443, 80 and 22000-22999 (ssh/tcp tunnels).
MSG
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "     ufw is active:  sudo ufw allow 443/tcp; sudo ufw allow 80/tcp; sudo ufw allow 22000:22999/tcp"
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  echo "     firewalld is active:  sudo firewall-cmd --permanent --add-port={443,80}/tcp --add-port=22000-22999/tcp && sudo firewall-cmd --reload"
fi
cat <<MSG
  3. Create an agent token:  sudo l8tunnel-server token create --name <name>
  Logs: journalctl -u l8tunnel-server -f     Status: sudo l8tunnel-server status
MSG
