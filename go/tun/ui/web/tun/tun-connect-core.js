// How to reach an SSH or TCP tunnel, shared by both shells: the exact
// commands for that tunnel, with the user name filled in, each with a copy
// button. The shells show it from the tunnel's "Connect" action.
(function() {
    'use strict';

    const esc = Layer8DUtils.escapeHtml;
    const TYPE = { TCP: 1, SSH: 2 };
    const USER_KEY = 'tunConnectUser';

    // The last user name typed is remembered in this browser only.
    function savedUser() {
        try { return localStorage.getItem(USER_KEY) || ''; } catch (e) { return ''; }
    }
    function saveUser(user) {
        try { localStorage.setItem(USER_KEY, user); } catch (e) { /* storage blocked */ }
    }

    // baseDomain is the tunnel's hostname without its own name.
    function baseDomain(t) {
        const host = t.hostname || '';
        return host.startsWith(t.name + '.') ? host.slice(t.name.length + 1) : host;
    }

    // commands lists { label, cmd } for the tunnel: its public port when it
    // has one, and port 443 by name through the l8tunnel client.
    function commands(t, user) {
        const u = user || '<user>';
        const port = Number(t.publicPort) || 0;
        const token = t.accessToken ? ' --access-token <access token>' : '';
        const out = [];
        if (Number(t.type) === TYPE.SSH) {
            if (port) out.push({ label: 'SSH', cmd: 'ssh -p ' + port + ' ' + u + '@' + baseDomain(t) });
            out.push({ label: 'SSH over port 443 (needs the l8tunnel client)',
                cmd: 'ssh -o ProxyCommand="l8tunnel connect' + token + ' %h" ' + u + '@' + t.hostname });
        } else {
            if (port) out.push({ label: 'Address', cmd: baseDomain(t) + ':' + port });
            out.push({ label: 'Over port 443 (stdin/stdout, needs the l8tunnel client)',
                cmd: 'l8tunnel connect' + token + ' ' + t.hostname });
        }
        return out;
    }

    function block(c, i) {
        return '<div class="tun-secret">' +
            '<label>' + esc(c.label) + '</label>' +
            '<textarea class="tun-secret-value" readonly rows="2" data-connect="' + i + '">' + esc(c.cmd) + '</textarea>' +
            '<div class="tun-secret-actions">' +
            '<button type="button" class="layer8d-btn layer8d-btn-small layer8d-btn-secondary" data-copy>Copy</button>' +
            '</div></div>';
    }

    window.TunConnect = {
        // supports: the tunnels a Connect action is offered for.
        supports: (t) => !!t && (Number(t.type) === TYPE.SSH || Number(t.type) === TYPE.TCP) && !!t.hostname,

        title: (t) => 'Connect to ' + t.name,

        html: function(t) {
            const ssh = Number(t.type) === TYPE.SSH;
            const user = ssh ? savedUser() : '';
            return '<div class="tun-connect">' +
                (ssh ? '<div class="form-group"><label for="tun-connect-user">User on the machine</label>' +
                    '<input type="text" id="tun-connect-user" class="tun-connect-user" value="' + esc(user) +
                    '" placeholder="user" autocomplete="off"></div>' : '') +
                commands(t, user).map(block).join('') +
                (t.accessToken ? '<p class="tun-muted">This tunnel needs its access token (set by the agent\'s config).</p>' : '') +
                '</div>';
        },

        // wire refreshes the commands as the user name changes and connects
        // the copy buttons. The shells call it shortly after the popup
        // shows, so a name typed before that is applied at once.
        wire: function(body, t, onCopied) {
            const input = body.querySelector('.tun-connect-user');
            const areas = body.querySelectorAll('[data-connect]');
            const refresh = () => {
                const user = input.value.trim();
                saveUser(user);
                commands(t, user).forEach((c, i) => { if (areas[i]) areas[i].value = c.cmd; });
            };
            if (input) {
                input.addEventListener('input', refresh);
                refresh();
            }
            body.querySelectorAll('.tun-connect .tun-secret').forEach(b => {
                b.querySelector('[data-copy]').addEventListener('click', async () => {
                    await navigator.clipboard.writeText(b.querySelector('.tun-secret-value').value);
                    onCopied();
                });
            });
        },

        commands: commands
    };
})();
