#!/bin/bash
# Removes the l8tunnel agent daemon and binaries from macOS.
#   ./uninstall.sh            keeps /etc/l8tunnel/agent.yaml (it holds the token)
#   ./uninstall.sh --purge    also deletes it and the log
set -euo pipefail
[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
LABEL=io.l8tunnel.agent
launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist" /usr/local/bin/l8tunnel-agent /usr/local/bin/l8tunnel
echo "removed the l8tunnel agent daemon and binaries"
if [ "${1:-}" = "--purge" ]; then
  rm -f /etc/l8tunnel/agent.yaml /var/log/l8tunnel-agent.log
  rmdir /etc/l8tunnel 2>/dev/null || true
  echo "deleted the agent configuration (token) and log"
else
  echo "kept /etc/l8tunnel/agent.yaml (use --purge to delete it)"
fi
