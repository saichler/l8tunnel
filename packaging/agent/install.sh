#!/usr/bin/env bash
# Installs (or upgrades) the l8tunnel agent as a systemd service.
#   ./install.sh      asks for the agent token and what to expose, then installs,
#                     starts the agent and shows how to reach this machine.
# Unattended: L8TUNNEL_TOKEN=l8t_... EXPOSE=ssh|web|both [WEB_PORT=3000] [NAME=x] ./install.sh
set -euo pipefail
cd "$(dirname "$0")"
die() { echo "install: $*" >&2; exit 1; }
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || die "run as root"
  echo "The installer needs root; asking sudo..."
  exec sudo --preserve-env=L8TUNNEL_TOKEN,EXPOSE,WEB_PORT,NAME "$0" "$@"
fi
command -v systemctl >/dev/null || die "systemd is required"
want_arch="$(cat ARCH)"
case "$(uname -m)" in
  x86_64) have_arch=amd64 ;; aarch64) have_arch=arm64 ;; armv7l) have_arch=armv7 ;; *) have_arch="$(uname -m)" ;;
esac
[ "$have_arch" = "$want_arch" ] || die "this package is for linux/$want_arch, but this machine is $have_arch"

DOMAIN="$(cat DOMAIN)"
RELAY="connect.$DOMAIN:443"
CONF=/etc/l8tunnel/agent.yaml ENVF=/etc/l8tunnel/agent.env
interactive=0; [ -t 0 ] && interactive=1

install -m 0755 bin/l8tunnel-agent bin/l8tunnel /usr/local/bin/
install -d -m 0755 /etc/l8tunnel
install -m 0644 l8tunnel-agent.service /etc/systemd/system/l8tunnel-agent.service
systemctl daemon-reload
echo "installed $(/usr/local/bin/l8tunnel-agent version) for relay $RELAY"

if [ -s "$CONF" ] && [ -s "$ENVF" ]; then
  echo "keeping the existing configuration ($CONF)"
else
  # --- the token ---
  TOKEN="${L8TUNNEL_TOKEN:-}"
  while [ -z "$TOKEN" ]; do
    [ "$interactive" -eq 1 ] || die "no token: run interactively, or set L8TUNNEL_TOKEN"
    echo
    echo "Paste the agent token. It was printed at the end of the relay's install.sh"
    echo "(on the relay: sudo cat /etc/l8tunnel/agent1.token, or: sudo l8tunnel-server token create --name <name>)"
    read -r -s -p "token: " TOKEN || die "no token entered"
    echo
    case "$TOKEN" in l8t_*_*) ;; *) echo "that doesn't look like a token (l8t_...)"; TOKEN="" ;; esac
  done

  # --- what to expose ---
  EXPOSE="${EXPOSE:-}"
  if [ -z "$EXPOSE" ] && [ "$interactive" -eq 1 ]; then
    echo
    echo "What should be reachable through the relay?"
    echo "  1) SSH to this machine (default)"
    echo "  2) A web app running on this machine"
    echo "  3) Both"
    read -r -p "choice [1]: " choice || choice=1
    case "${choice:-1}" in 1) EXPOSE=ssh ;; 2) EXPOSE=web ;; 3) EXPOSE=both ;; *) die "no such choice: $choice" ;; esac
  fi
  EXPOSE="${EXPOSE:-ssh}"
  WEB_PORT="${WEB_PORT:-}"
  if [ "$EXPOSE" != ssh ] && [ -z "$WEB_PORT" ]; then
    [ "$interactive" -eq 1 ] || die "EXPOSE=$EXPOSE needs WEB_PORT"
    read -r -p "the web app's port on this machine [3000]: " WEB_PORT || WEB_PORT=""
    WEB_PORT="${WEB_PORT:-3000}"
  fi
  case "$WEB_PORT" in ''|*[!0-9]*) [ "$EXPOSE" = ssh ] || die "invalid port $WEB_PORT" ;; esac

  # --- the tunnel name: a DNS label, defaulting to the host name ---
  default_name="$(uname -n | cut -d. -f1 | tr 'A-Z_' 'a-z-' | tr -cd 'a-z0-9-' | sed 's/^-*//; s/-*$//')"
  default_name="${default_name:-agent}"
  NAME="${NAME:-}"
  if [ -z "$NAME" ] && [ "$interactive" -eq 1 ]; then
    read -r -p "name for this machine (becomes <name>.$DOMAIN) [$default_name]: " NAME || NAME=""
  fi
  NAME="${NAME:-$default_name}"
  echo "$NAME" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' || die "name $NAME must be lowercase letters, digits and dashes"

  umask 077
  printf 'L8TUNNEL_TOKEN=%s\n' "$TOKEN" > "$ENVF"
  chmod 0600 "$ENVF"
  umask 022
  {
    echo "# /etc/l8tunnel/agent.yaml, written by install.sh"
    echo "relay: $RELAY"
    echo "# the token is in $ENVF (root only)"
    echo "token: \${L8TUNNEL_TOKEN}"
    echo "status_socket: /run/l8tunnel-agent/status.sock"
    echo "tunnels:"
    if [ "$EXPOSE" = ssh ] || [ "$EXPOSE" = both ]; then
      echo "  - name: $NAME"
      echo "    type: ssh              # this machine's sshd, 127.0.0.1:22"
    fi
    if [ "$EXPOSE" = web ] || [ "$EXPOSE" = both ]; then
      web_name="$NAME"; [ "$EXPOSE" = both ] && web_name="$NAME-web"
      echo "  - name: $web_name"
      echo "    type: http             # https://$web_name.$DOMAIN"
      echo "    target: $WEB_PORT"
    fi
  } > "$CONF"
  chmod 0644 "$CONF"
  echo "wrote $CONF"
fi

if grep -q 'type: ssh' "$CONF" && ! ss -ltnH 'sport = :22' 2>/dev/null | grep -q .; then
  echo "WARNING: nothing listens on port 22 here; start sshd (sudo systemctl enable --now sshd) or SSH won't work" >&2
fi

systemctl enable --quiet l8tunnel-agent
systemctl restart l8tunnel-agent
echo "starting the agent..."
ready=0
for i in $(seq 1 15); do
  sleep 1
  if l8tunnel-agent status --json 2>/dev/null | grep -q '"connected": true'; then ready=1; break; fi
  systemctl is-active --quiet l8tunnel-agent || break
done

echo
echo "=================================================================="
if [ "$ready" -eq 1 ]; then
  echo " The l8tunnel agent is connected to $RELAY"
  echo "=================================================================="
  l8tunnel-agent status | sed 's/^/ /'
  echo
  l8tunnel-agent status --json | awk -F'"' -v d="$DOMAIN" '
    /"type"/ {type=$4} /"public_address"/ {addr=$4}
    /"hostname"/ {host=$4; if (type=="ssh" || type=="tcp") {
        split(addr, a, ":"); print " SSH here from anywhere:   ssh -p " a[2] " <user>@" d
        print "   or over port 443:       ssh -o ProxyCommand=\"l8tunnel connect %h\" <user>@" host }
      else if (type=="http") print " Web app:                  " addr }'
else
  echo " The agent didn't connect. Recent log:"
  echo "=================================================================="
  journalctl -u l8tunnel-agent -n 15 --no-pager | sed 's/^/ /'
  echo
  echo " Common causes: a wrong or revoked token, DNS for connect.$DOMAIN not pointing"
  echo " at the relay yet, or TCP 443 not reachable on the relay."
  echo " Fix, then rerun ./install.sh; to change the answers: sudo rm $CONF $ENVF"
  exit 1
fi
echo
echo " Logs: journalctl -u l8tunnel-agent -f      Status: sudo l8tunnel-agent status"
