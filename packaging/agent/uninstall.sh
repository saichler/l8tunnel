#!/usr/bin/env bash
# Removes the l8tunnel agent service and binaries.
#   ./uninstall.sh            keeps /etc/l8tunnel/agent.yaml and agent.env
#   ./uninstall.sh --purge    also deletes them (the token)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
systemctl disable --now l8tunnel-agent 2>/dev/null || true
rm -f /etc/systemd/system/l8tunnel-agent.service /usr/local/bin/l8tunnel-agent /usr/local/bin/l8tunnel
systemctl daemon-reload
echo "removed the l8tunnel-agent service and binaries"
if [ "${1:-}" = "--purge" ]; then
  rm -f /etc/l8tunnel/agent.yaml /etc/l8tunnel/agent.env
  rmdir /etc/l8tunnel 2>/dev/null || true
  echo "deleted the agent configuration and token"
else
  echo "kept /etc/l8tunnel/agent.yaml and agent.env (use --purge to delete them)"
fi
