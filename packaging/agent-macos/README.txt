l8tunnel agent for macOS
========================

Install (on the Mac you want to reach)
  tar xzf l8tunnel-agent-*-darwin-*.tar.gz
  cd l8tunnel-agent-*-darwin-*/
  ./install.sh

It asks for your password (sudo), and for the agent token unless the
package has one built in. It installs the agent as a launchd daemon that
starts at boot, connects to the relay and registers this Mac as
<name>-ssh.<domain> (name: this Mac's local host name, or NAME=x ./install.sh).
It prints how to reach the Mac:
  ssh -p <port> <user>@<domain>
The management UI shows the same (Tunnels > Live > Connect).

SSH needs Remote Login on:  System Settings > General > Sharing > Remote Login

When the agent can't connect (a revoked token, a name another machine
holds, 443 blocked), the installer shows the log and stops; nothing is
retried or renamed.

What it installs
  /usr/local/bin/l8tunnel-agent                  the agent
  /usr/local/bin/l8tunnel                        client helper (ssh over port 443)
  /Library/LaunchDaemons/io.l8tunnel.agent.plist the launchd daemon
  /etc/l8tunnel/agent.yaml                       configuration and token (root only)
  /var/log/l8tunnel-agent.log                    log

Everyday commands
  sudo l8tunnel-agent status                     connection and tunnels
  tail -f /var/log/l8tunnel-agent.log            log
  sudo launchctl kickstart -k system/io.l8tunnel.agent   restart

Uninstall:  ./uninstall.sh   (--purge also deletes the configuration and token)
