#!/bin/bash
# Installs (or upgrades) the l8tunnel agent on macOS as a launchd daemon
# that starts at boot, and exposes this Mac's SSH (Remote Login) as
# <name>-ssh.<domain>.
#   ./install.sh      a package built with a token asks nothing; otherwise it
#                     asks for the token. NAME=x picks the name (default: this
#                     Mac's local host name).
# Unattended: L8TUNNEL_TOKEN=l8t_... [NAME=x] ./install.sh
# (bash 3.2, as macOS ships it.)
set -euo pipefail
cd "$(dirname "$0")"
die() { echo "install: $*" >&2; exit 1; }
if [ "$(id -u)" -ne 0 ]; then
  echo "The installer needs root; asking sudo..."
  exec sudo L8TUNNEL_TOKEN="${L8TUNNEL_TOKEN:-}" NAME="${NAME:-}" "$0" "$@"
fi
[ "$(uname -s)" = Darwin ] || die "this package is for macOS"
want_arch="$(cat ARCH)"
case "$(uname -m)" in arm64) have_arch=arm64 ;; x86_64) have_arch=amd64 ;; *) have_arch="$(uname -m)" ;; esac
[ "$have_arch" = "$want_arch" ] || die "this package is for macOS/$want_arch, but this Mac is $have_arch"

DOMAIN="$(cat DOMAIN)"
RELAY="connect.$DOMAIN:443"
LABEL=io.l8tunnel.agent
PLIST="/Library/LaunchDaemons/$LABEL.plist"
CONF=/etc/l8tunnel/agent.yaml
LOG=/var/log/l8tunnel-agent.log
SOCK=/var/run/l8tunnel-agent/status.sock

mkdir -p /usr/local/bin
install -m 0755 bin/l8tunnel-agent bin/l8tunnel /usr/local/bin/
# A downloaded package is quarantined; the daemon must be able to start.
xattr -d com.apple.quarantine /usr/local/bin/l8tunnel-agent /usr/local/bin/l8tunnel 2>/dev/null || true
echo "installed $(/usr/local/bin/l8tunnel-agent version) for relay $RELAY"

if [ -s "$CONF" ]; then
  echo "keeping the existing configuration ($CONF)"
else
  TOKEN="${L8TUNNEL_TOKEN:-}"
  [ -z "$TOKEN" ] && [ -s TOKEN ] && TOKEN="$(tr -d '[:space:]' < TOKEN)"
  while [ -z "$TOKEN" ]; do
    [ -t 0 ] || die "no token: run interactively, or set L8TUNNEL_TOKEN"
    read -r -s -p "agent token (l8t_...): " TOKEN || die "no token entered"
    echo
    case "$TOKEN" in l8t_*_*) ;; *) echo "that doesn't look like a token (l8t_...)"; TOKEN="" ;; esac
  done

  default_name="$(scutil --get LocalHostName 2>/dev/null || uname -n)"
  default_name="$(echo "$default_name" | cut -d. -f1 | tr 'A-Z_' 'a-z-' | tr -cd 'a-z0-9-' | sed 's/^-*//; s/-*$//')"
  NAME="${NAME:-${default_name:-mac}}"
  echo "$NAME" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,57}[a-z0-9])?$' || die "name $NAME must be lowercase letters, digits and dashes"

  mkdir -p /etc/l8tunnel
  umask 077
  {
    echo "# $CONF, written by install.sh (root only: it holds the token)"
    echo "relay: $RELAY"
    echo "token: $TOKEN"
    echo "status_socket: $SOCK"
    echo "tunnels:"
    echo "  - name: $NAME-ssh"
    echo "    type: ssh              # this Mac's Remote Login, 127.0.0.1:22"
  } > "$CONF"
  chown root:wheel "$CONF"
  chmod 0600 "$CONF"
  umask 022
  echo "wrote $CONF"
fi

if ! (exec 3<>/dev/tcp/127.0.0.1/22) 2>/dev/null; then
  echo "WARNING: nothing listens on port 22: turn on System Settings > General > Sharing > Remote Login, or SSH won't work" >&2
fi

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/l8tunnel-agent</string>
    <string>--config</string>
    <string>$CONF</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
PLIST
chown root:wheel "$PLIST"
chmod 0644 "$PLIST"

launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable "system/$LABEL"
echo "starting the agent..."
ready=0
for i in $(seq 1 15); do
  sleep 1
  # grep reads all its input: an early exit would fail the pipeline under pipefail.
  if /usr/local/bin/l8tunnel-agent status --json 2>/dev/null | grep '"connected": true' >/dev/null; then ready=1; break; fi
done

echo
echo "=================================================================="
if [ "$ready" -eq 1 ]; then
  echo " The l8tunnel agent is connected to $RELAY"
  echo "=================================================================="
  /usr/local/bin/l8tunnel-agent status | sed 's/^/ /'
  echo
  /usr/local/bin/l8tunnel-agent status --json | awk -F'"' -v d="$DOMAIN" '
    /"type"/ {type=$4} /"public_address"/ {addr=$4}
    /"hostname"/ {host=$4; if (type=="ssh") {
        split(addr, a, ":"); print " SSH here from anywhere:   ssh -p " a[2] " <user>@" d
        print "   or over port 443:       ssh -o ProxyCommand=\"l8tunnel connect %h\" <user>@" host } }'
else
  echo " The agent didn't connect. Recent log ($LOG):"
  echo "=================================================================="
  tail -n 15 "$LOG" 2>/dev/null | sed 's/^/ /'
  echo
  echo " Common causes: a wrong or revoked token, a tunnel name another machine"
  echo " holds (rerun with NAME=<other>), or TCP 443 to connect.$DOMAIN blocked."
  echo " To start over: sudo ./uninstall.sh --purge && ./install.sh"
  exit 1
fi
echo
echo " Logs: tail -f $LOG      Status: sudo l8tunnel-agent status"
