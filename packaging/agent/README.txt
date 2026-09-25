l8tunnel agent
==============

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
Uninstall:           ./uninstall.sh   (--purge also deletes the token)
