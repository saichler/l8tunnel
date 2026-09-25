l8tunnel relay (l8tunnel-server)
================================

Install
  tar xzf l8tunnel-server-*-linux-amd64.tar.gz
  cd l8tunnel-server-*-linux-amd64
  sudo ./install.sh --cert /path/to/domain.cert.pem --key /path/to/private.key.pem

  The packaged configuration uses the base domain layer8-tunnel.info; for
  another domain add --domain example.com (the certificate must cover
  *.example.com).

  The certificate and key are copied to /etc/l8tunnel/tls (readable only by
  root and the l8tunnel user); they are never part of this package.

What it installs
  /usr/local/bin/l8tunnel-server              the relay
  /etc/systemd/system/l8tunnel-server.service systemd unit (runs as user l8tunnel)
  /etc/l8tunnel/server.yaml                   configuration (base domain layer8-tunnel.info)
  /etc/l8tunnel/tls/                          certificate and key
  /var/lib/l8tunnel/                          tokens and reservations (created by systemd)

After installing
  1. DNS at Porkbun:  *.layer8-tunnel.info  A  <public IP of this machine>
  2. Open TCP 443, 80 and 22000-22999 in the firewall.
  3. sudo l8tunnel-server token create --name laptop    (copy the token; it's shown once)
  4. On the machine behind the firewall:
       L8TUNNEL_TOKEN=l8t_... l8tunnel-agent --relay connect.layer8-tunnel.info:443 ssh --name homebox
       L8TUNNEL_TOKEN=l8t_... l8tunnel-agent --relay connect.layer8-tunnel.info:443 http 3000 --name app

Renewing the certificate (it expires every 90 days)
  sudo ./install-cert.sh domain.cert.pem private.key.pem     (validates, installs, restarts)
  The relay logs a warning daily from 21 days before expiry: journalctl -u l8tunnel-server

Upgrade:    run the new package's install.sh (your server.yaml is kept)
Uninstall:  sudo ./uninstall.sh [--purge]
