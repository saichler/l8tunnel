l8tunnel relay
==============

Install (on the relay machine)
  tar xzf l8tunnel-relay-*.tar.gz
  cd l8tunnel-relay-*/
  ./install.sh

That's it. install.sh asks for your sudo password, then installs the relay
as a systemd service, installs the certificate that comes with this package,
opens the firewall (ufw or firewalld, if active), starts the relay, creates a
first agent token and prints what to do next:

  1. One DNS record at your registrar:  *.<domain>  A  <public IP of this machine>
  2. If there's a router or cloud firewall in front: allow TCP 443, 80, 22000-22999.
  3. Run the agent on the machine you want to reach, with the printed token.

This package contains the certificate's PRIVATE KEY (certs/privkey.pem).
Keep the .tar.gz private and delete it from the relay after installing.

What it installs
  /usr/local/bin/l8tunnel-server              the relay
  /etc/systemd/system/l8tunnel-server.service systemd unit (runs as user l8tunnel)
  /etc/l8tunnel/server.yaml                   configuration
  /etc/l8tunnel/tls/                          certificate and key
  /etc/l8tunnel/agent1.token                  the first agent token (root only)
  /var/lib/l8tunnel/                          tokens and reservations

Everyday commands
  sudo l8tunnel-server status                 connected agents and tunnels
  sudo l8tunnel-server token create --name X  another agent token
  journalctl -u l8tunnel-server -f            logs

Renewing the certificate: build a new package with the new certificate and run
its ./install.sh (settings and tokens are kept), or on the relay:
  sudo ./install-cert.sh domain.cert.pem private.key.pem

Uninstall:  ./uninstall.sh   (add --purge to delete configuration and tokens)
