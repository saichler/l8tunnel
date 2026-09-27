// The dashboard's "Connect a machine" card and the collapsible user guide,
// shared by both shells. Commands in the guide use this cluster's domain.
(function() {
    'use strict';

    const esc = Layer8DUtils.escapeHtml;
    const code = (s) => '<pre class="tun-guide-code">' + esc(s) + '</pre>';
    const topic = (title, body) => '<details class="tun-guide-topic"><summary>' + esc(title) + '</summary>' +
        '<div class="tun-guide-body">' + body + '</div></details>';

    function downloads() {
        const buttons = Object.keys(TunDownload.PACKAGES).map(key => {
            const p = TunDownload.PACKAGES[key];
            return '<button type="button" class="layer8d-btn layer8d-btn-primary tun-download-btn" data-tun-download="' + key + '">' +
                'Download for ' + esc(p.label) + '</button><span class="tun-muted">' + esc(p.exposes) + '</span>';
        }).join('');
        return '<div class="tun-downloads">' +
            '<h3 class="tun-guide-heading">Connect a machine</h3>' +
            '<p>Download the agent for the machine, copy it there, extract it and run <code>./install.sh</code>. ' +
            'It installs the agent as a system service and registers the machine; nothing to answer.</p>' +
            '<div class="tun-download-row">' + buttons + '</div>' +
            '<p class="tun-muted">Each download carries its own token (named <code>pkg-...</code>). ' +
            'Keep the file private: anyone who has it can register machines. To retire a copy, revoke its token in Access &gt; Tokens.</p>' +
            '</div>';
    }

    function guide(d) {
        return '<details class="tun-guide"><summary>How to use l8tunnel</summary><div class="tun-guide-topics">' +
            topic('What l8tunnel does',
                '<p>l8tunnel makes machines behind NAT or a firewall reachable from anywhere, without opening anything on their network. ' +
                'A small <b>agent</b> on each machine connects out to the <b>relays</b> of this cluster and keeps that connection open; ' +
                'traffic for the machine comes in through the <b>edge</b> on the public address of <code>' + esc(d) + '</code> and travels back over it.</p>' +
                '<ul><li><b>SSH</b> to a machine, on a port of its own or over port 443.</li>' +
                '<li><b>HTTPS</b> to a service on the machine, at <code>https://&lt;name&gt;.' + esc(d) + '</code>, encrypted end to end.</li>' +
                '<li><b>TCP</b> to any other service, on a port of its own.</li></ul>') +
            topic('Connect a machine',
                '<ol><li>Download the package for the machine above (Linux x86-64 or macOS on Apple silicon).</li>' +
                '<li>Copy it to the machine and run:' +
                code('tar xzf l8tunnel-agent-*.tar.gz\ncd l8tunnel-agent-download-*/\n./install.sh') + '</li>' +
                '<li>The installer asks for the machine\'s administrator password (sudo), installs the agent as a service that starts at boot, ' +
                'and prints how to reach the machine.</li></ol>' +
                '<p>The machine is registered under its host name:</p>' +
                '<ul><li><code>&lt;host&gt;-ssh</code>: SSH to the machine (Linux needs <code>sshd</code> running; on a Mac, turn on ' +
                'System Settings &gt; General &gt; Sharing &gt; Remote Login).</li>' +
                '<li><code>&lt;host&gt;</code> (Linux): <code>https://&lt;host&gt;.' + esc(d) + '</code>, passed through to the machine\'s ' +
                'own HTTPS server on port 443, which serves its own certificate for that name.</li></ul>' +
                '<p>If another machine already uses the host name, the installer stops and says so: run it again as ' +
                '<code>NAME=another-name ./install.sh</code>.</p>') +
            topic('Reach a machine',
                '<p>Open <b>Tunnels &gt; Live</b>, click the machine\'s SSH tunnel and press <b>Connect</b>: it shows the exact commands, ' +
                'with your user name filled in and a copy button each.</p>' +
                '<ul><li>By port, with any SSH client:' + code('ssh -p <port> <user>@' + d) + '</li>' +
                '<li>Over port 443 by name, for networks that only allow HTTPS (needs the <code>l8tunnel</code> client, installed with every agent):' +
                code('ssh -o ProxyCommand="l8tunnel connect %h" <user>@<host>-ssh.' + d) + '</li>' +
                '<li>HTTPS: <code>https://&lt;host&gt;.' + esc(d) + '</code>. The relay never decrypts it.</li>' +
                '<li>A TCP tunnel is reached at <code>' + esc(d) + ':&lt;port&gt;</code>, or with ' +
                '<code>l8tunnel connect &lt;name&gt;.' + esc(d) + '</code> over port 443.</li></ul>') +
            topic('Machine and tunnel states',
                '<ul><li><b>Online / Active</b>: the agent is connected and its tunnels carry traffic.</li>' +
                '<li><b>Grace</b>: the agent just disconnected (a reboot, a network switch). For 5 minutes all its names and ports stay held ' +
                'for it; when it reconnects in time, it gets them back unchanged.</li>' +
                '<li><b>Offline</b>: the grace period ended. The agent record shows why it disconnected.</li></ul>' +
                '<p><b>Ports never change.</b> The first time an SSH or TCP tunnel gets a port, the cluster reserves that name and port for the ' +
                'machine\'s token (<b>Access &gt; Reservations</b>, note <i>assigned automatically</i>). The machine gets the same port back ' +
                'whenever it returns: after a reboot, a long time offline or a restart of the whole cluster. Delete the reservation to free the port.</p>' +
                '<p>HTTPS tunnels have no port; their names are free for other machines once the grace period ends. Add a reservation ' +
                '(Access &gt; Reservations) to keep one for the token.</p>' +
                '<p>Agents reconnect on their own. A laptop that changes networks is back within seconds of the new network coming up.</p>') +
            topic('Add tunnels to a machine',
                '<p>A machine\'s tunnels are listed in <code>/etc/l8tunnel/agent.yaml</code> on the machine. To add one:</p>' +
                '<ol><li>In <b>Access &gt; Tokens</b>, edit the machine\'s token: add the new name to <b>Tunnel names</b> (or use a pattern such as ' +
                '<code>&lt;host&gt;-*</code>), make sure its type is allowed, and raise <b>Max tunnels</b> if needed.</li>' +
                '<li>On the machine, add the tunnel and restart the agent:' +
                code('  - name: <host>-db\n    type: tcp              # or ssh, tls (HTTPS passthrough), http\n    target: 127.0.0.1:5432') +
                code('sudo systemctl restart l8tunnel-agent                    # Linux\nsudo launchctl kickstart -k system/io.l8tunnel.agent    # macOS') + '</li></ol>' +
                '<p>If the token doesn\'t allow a name or type, the agent registers none of its tunnels and its log says which one was refused.</p>') +
            topic('Tokens and access',
                '<p>Every agent authenticates with a token. A token\'s <b>policy</b> limits what its agents may register: tunnel names (patterns), ' +
                'tunnel types, the number of tunnels, TCP ports and custom domains.</p>' +
                '<ul><li><b>Access &gt; Tokens &gt; Add Token</b> issues one; the token is shown once.</li>' +
                '<li>Deleting a token revokes it: its agents are disconnected at once and can\'t reconnect.</li>' +
                '<li><b>Reservations</b> keep a name (and a TCP port) for one token, even while its machine is offline. SSH and TCP tunnels get one ' +
                'automatically for the port they are assigned.</li>' +
                '<li><b>Gateway keys</b> let an SSH key reach named tunnels through the SSH gateway on port 2222.</li></ul>') +
            topic('Sites on the edge',
                '<p><b>Edge &gt; Domains</b> puts other sites behind the edge, besides the tunnels: a domain with its certificate and ' +
                '<b>port forwards</b> (protocol, in port, to port). Tick <b>Enabled</b> on a new domain to put it in service. ' +
                '<b>Edge &gt; Router ports</b> shows every port the edge listens on and whether it could bind it.</p>') +
            topic('Load balancing',
                '<p>The edge routes each connection to a domain\'s port forward (by name for HTTPS and HTTP, by port for TCP), then ' +
                'balances it over that forward\'s targets. In <b>Edge &gt; Domains</b>, open a domain\'s <b>Port forwarding</b> tab and ' +
                'add or edit a forward:</p><ul>' +
                '<li><b>Targets</b>: the backends, each a host, a port, a <b>weight</b> (its share of the traffic; 0 counts as 1) and ' +
                '<b>Disabled</b> to take it out without deleting it. With no targets, the forward goes to <b>To port</b> on the edge\'s own node.</li>' +
                '<li><b>Balancing</b>: round robin (weighted), least connections, source hash (a client keeps its backend) or random.</li>' +
                '<li><b>Health check</b>: TCP, HTTP or HTTPS (with a path); a target that fails 3 checks gets no traffic until it passes 2.</li>' +
                '<li><b>Mode</b>: <b>Passthrough</b> balances each connection and leaves TLS to the backends; <b>Terminate</b> decrypts with ' +
                'the domain\'s certificate and balances each HTTP request (set the backend scheme, and skip verification only for ' +
                'self-signed backends).</li></ul>') +
            topic('Alerts',
                '<p><b>Alerts &gt; Rules</b> notifies you (webhook, Slack, email, PagerDuty) when a relay is lost, no relay is ready, an edge ' +
                'backend is down, a certificate is about to expire, or a given token or agent goes offline. <b>Deliveries</b> lists what was sent.</p>') +
            topic('Using it from the home network',
                '<p>On the network the relay itself is on, <code>' + esc(d) + '</code> must resolve to the relay\'s LAN address: most routers don\'t ' +
                'loop traffic for their public address back in. Point the DNS of devices on that network at the resolver that answers the LAN ' +
                'address; away from home they use normal DNS. The agent looks the name up again on every reconnect, so machines that move ' +
                'between networks follow along.</p>') +
            topic('Troubleshooting',
                '<ul><li>On the machine:' + code('sudo l8tunnel-agent status') + 'shows whether the agent is connected and each tunnel\'s public address.</li>' +
                '<li>Agent log: <code>journalctl -u l8tunnel-agent -f</code> (Linux), <code>tail -f /var/log/l8tunnel-agent.log</code> (macOS).</li>' +
                '<li><i>token may not use the tunnel name</i> / <i>type</i>: allow it in the token\'s policy.</li>' +
                '<li><i>tunnel name ... is taken</i>: another machine holds the name; choose another one.</li>' +
                '<li><i>dial relay ... i/o timeout</i>: the relay isn\'t reachable from that network (from the home network, check the DNS above).</li>' +
                '<li>The cluster\'s own logs: <b>System &gt; Logs</b>.</li></ul>') +
            topic('Security',
                '<ul><li>Change the default administrator password (<b>System &gt; Security &gt; Users</b>).</li>' +
                '<li>Agent packages carry a token: share them only with people who may add machines, and revoke tokens you no longer use.</li>' +
                '<li>HTTPS tunnels are passed through untouched; each machine is responsible for its own certificate.</li></ul>') +
            '</div></details>';
    }

    window.TunGuide = {
        // render fills container with the download card and the guide, and
        // wires the downloads; notify(ok, message) reports the outcome.
        render: async function(container, prefix, notify) {
            if (!container) return;
            let domain = '';
            try {
                domain = await TunDownload.baseDomain();
            } catch (e) {
                domain = '';
            }
            container.innerHTML = downloads() + guide(domain || '<your domain>');
            container.querySelectorAll('[data-tun-download]').forEach(btn => btn.addEventListener('click', async () => {
                btn.disabled = true;
                try {
                    const name = await TunDownload.download(btn.dataset.tunDownload, prefix);
                    notify(true, 'Package downloaded with its own token, ' + name);
                } catch (e) {
                    notify(false, 'Download failed: ' + e.message);
                } finally {
                    btn.disabled = false;
                }
            }));
        }
    };
})();
