#!/usr/bin/env bash
# Removes the l8tunnel relay service and binary.
#   sudo ./uninstall.sh            keeps /etc/l8tunnel (config, certificate) and /var/lib/l8tunnel (tokens)
#   sudo ./uninstall.sh --purge    also deletes those and the l8tunnel user
set -euo pipefail
[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
PURGE=0; [ "${1:-}" = "--purge" ] && PURGE=1

systemctl disable --now l8tunnel-server 2>/dev/null || true
rm -f /etc/systemd/system/l8tunnel-server.service /usr/local/bin/l8tunnel-server
systemctl daemon-reload
echo "removed the l8tunnel-server service and binary"
if [ "$PURGE" -eq 1 ]; then
  rm -rf /etc/l8tunnel /var/lib/l8tunnel
  getent passwd l8tunnel >/dev/null && userdel l8tunnel
  echo "purged configuration, certificate, tokens and the l8tunnel user"
else
  echo "kept /etc/l8tunnel and /var/lib/l8tunnel (use --purge to delete them)"
fi
