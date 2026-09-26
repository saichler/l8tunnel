l8tunnel agent
==============

No-questions package (l8tunnel-agent-<domain>-enroll-...)
  tar xzf l8tunnel-agent-*-enroll-*.tar.gz
  cd l8tunnel-agent-*-enroll-*/
  ./install.sh
That's all: it installs the agent as a system service, connects to the relay
and registers this machine under its host name:
  ssh:    ssh -p <port> <user>@<domain>   (install.sh prints the port;
          the management UI shows it too: Tunnels > Live > Connect)
  https:  https://<host name>.<domain>     passed through untouched to this
          machine's own HTTPS server on port 443 (it serves the certificate;
          until something listens on 443, that address has nothing to show)
If another machine already uses this host name, the install fails and says
so: run it again with another name (NAME=x ./install.sh).
Set HTTPS_PORT=8443 before ./install.sh for an HTTPS server on another port.


There are two agent packages; use the one that matches where this machine is:
  l8tunnel-agent-<domain>-...             machines anywhere on the internet
  l8tunnel-agent-<domain>-via-<ip>-...    machines on the relay's own network
                                          (connects straight to the relay's LAN IP)

Install (on the machine you want to reach)
  tar xzf l8tunnel-agent-*.tar.gz
  cd l8tunnel-agent-*/
  ./install.sh

install.sh asks for:
  - the agent token: printed at the end of the relay's install.sh
    (on the relay: sudo cat /etc/l8tunnel/agent1.token, or create another one
    with: sudo l8tunnel-server token create --name <name>)
  - what to expose: SSH to this machine, a web app, or both
  - a name for this machine (default: its host name)
Then it installs and starts the agent and prints how to connect.

SSH to this machine needs sshd running here:  sudo systemctl enable --now sshd

What it installs
  /usr/local/bin/l8tunnel-agent              the agent
  /usr/local/bin/l8tunnel                    client helper (ssh over port 443)
  /etc/systemd/system/l8tunnel-agent.service systemd unit
  /etc/l8tunnel/agent.yaml                   what to expose (edit, then: sudo systemctl restart l8tunnel-agent)
  /etc/l8tunnel/agent.env                    the token (root only)

Everyday commands
  sudo l8tunnel-agent status                 connection and tunnels
  journalctl -u l8tunnel-agent -f            logs

Change the answers:  sudo rm /etc/l8tunnel/agent.yaml /etc/l8tunnel/agent.env && ./install.sh
Unattended install:  L8TUNNEL_TOKEN=l8t_... EXPOSE=both WEB_PORT=3000 ./install.sh
                     (EXPOSE: ssh, web, both, or ssh+https as in the no-questions package)
Uninstall:           ./uninstall.sh   (--purge also deletes the token)
