// Agent package downloads, shared by both shells. The web server holds
// package templates without a token (safe to serve to anyone); a download
// issues a new token for that copy, writes it and this cluster's base domain
// into the package in the browser, and saves the file. Each downloaded copy
// can then be revoked on its own in Access > Tokens.
(function() {
    'use strict';

    const TYPE = { SSH: 2, TLS: 4 };
    const BLOCK = 512;

    const PACKAGES = {
        linux: {
            label: 'Linux (x86-64)', exposes: 'SSH and HTTPS',
            template: 'downloads/l8tunnel-agent-linux-amd64.tar.gz',
            saveAs: 'l8tunnel-agent-linux-amd64.tar.gz', types: [TYPE.SSH, TYPE.TLS]
        },
        mac: {
            label: 'macOS (Apple silicon)', exposes: 'SSH',
            template: 'downloads/l8tunnel-agent-darwin-arm64.tar.gz',
            saveAs: 'l8tunnel-agent-darwin-arm64.tar.gz', types: [TYPE.SSH]
        }
    };

    // --- gzip, through the browser's streams ---
    async function pipe(bytes, stream) {
        return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer());
    }

    // --- tar (the ustar/GNU headers tar -czf writes) ---
    const text = (h, off, len) => new TextDecoder().decode(h.subarray(off, off + len)).replace(/\0.*$/s, '');
    const padded = (n) => Math.ceil(n / BLOCK) * BLOCK;

    function readTar(bytes) {
        const entries = [];
        for (let off = 0; off + BLOCK <= bytes.length;) {
            const header = bytes.subarray(off, off + BLOCK);
            if (header.every(b => b === 0)) break;
            const size = parseInt(text(header, 124, 12).trim() || '0', 8);
            if (Number.isNaN(size)) throw new Error('the package template is not a tar archive');
            entries.push({ name: text(header, 0, 100), header: header, data: bytes.subarray(off + BLOCK, off + BLOCK + size) });
            off += BLOCK + padded(size);
        }
        if (entries.length === 0) throw new Error('the package template is empty');
        return entries;
    }

    function octal(h, off, len, value) {
        const s = value.toString(8).padStart(len - 1, '0');
        for (let i = 0; i < len - 1; i++) h[off + i] = s.charCodeAt(i);
        h[off + len - 1] = 0;
    }

    // fileHeader builds a regular file's header from another entry's
    // (owner, times and format stay the same).
    function fileHeader(template, name, size, mode) {
        const h = new Uint8Array(template);
        const n = new TextEncoder().encode(name);
        if (n.length > 99) throw new Error('path too long for the package: ' + name);
        h.fill(0, 0, 100);
        h.set(n, 0);
        octal(h, 100, 8, mode);
        octal(h, 124, 12, size);
        h[156] = '0'.charCodeAt(0);
        h.fill(0x20, 148, 156);
        const sum = h.reduce((a, b) => a + b, 0);
        octal(h, 148, 7, sum);
        h[155] = 0x20;
        return h;
    }

    // customize returns the package with DOMAIN replaced and TOKEN added.
    function customize(entries, domain, token) {
        const top = entries[0].name.split('/')[0];
        const domainEntry = entries.find(e => e.name === top + '/DOMAIN');
        if (!domainEntry) throw new Error('the package template has no DOMAIN file');
        const parts = [];
        const add = (header, data) => {
            parts.push(header, data);
            const pad = padded(data.length) - data.length;
            if (pad) parts.push(new Uint8Array(pad));
        };
        const enc = new TextEncoder();
        entries.forEach(e => {
            if (e.name === top + '/TOKEN') return;
            if (e === domainEntry) {
                const data = enc.encode(domain + '\n');
                add(fileHeader(e.header, e.name, data.length, 0o644), data);
                return;
            }
            add(e.header, e.data);
        });
        const tokenData = enc.encode(token + '\n');
        add(fileHeader(domainEntry.header, top + '/TOKEN', tokenData.length, 0o600), tokenData);
        parts.push(new Uint8Array(2 * BLOCK));
        return new Blob(parts);
    }

    function tokenName(key) {
        const t = new Date().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
        const rand = Math.floor(Math.random() * 0xffff).toString(16).padStart(4, '0');
        return 'pkg-' + key + '-' + t + '-' + rand;
    }

    window.TunDownload = {
        PACKAGES: PACKAGES,

        // baseDomain is the cluster's tunnel base domain (the TUNNEL_BASE
        // edge domain), or '' when it isn't set up yet.
        baseDomain: async function() {
            const rows = await TunData.list('/41/EdgeDomain', 'EdgeDomain');
            const base = rows.find(d => Number(d.kind) === 2);
            return base ? base.domain : '';
        },

        // download builds the package for key ('linux' or 'mac'), with a new
        // token, and saves it. prefix is the path from the shell to the web
        // root ('' on desktop, '../' on mobile). Returns the token's name.
        download: async function(key, prefix) {
            const pkg = PACKAGES[key];
            if (!pkg) throw new Error('no package ' + key);
            if (typeof DecompressionStream !== 'function' || typeof CompressionStream !== 'function') {
                throw new Error('this browser can\'t build packages (it has no gzip streams); use a current browser');
            }
            const domain = await TunDownload.baseDomain();
            if (!domain) throw new Error('the tunnel base domain isn\'t set up yet (Edge > Domains)');
            const resp = await fetch(prefix + pkg.template);
            if (!resp.ok) throw new Error('package template: HTTP ' + resp.status);
            const entries = readTar(await pipe(new Uint8Array(await resp.arrayBuffer()), new DecompressionStream('gzip')));
            // The token is issued only once the template is known to be good.
            const name = tokenName(key);
            const issued = await TunData.request('POST', TunData.ISSUE_ENDPOINT, {
                kind: 1, tokenName: name,
                tokenDescription: 'built into a ' + pkg.label + ' agent package downloaded by ' + (TunData.currentUser() || 'a user'),
                policy: { types: pkg.types }
            });
            if (!issued.token) throw new Error(issued.error || 'no token was issued');
            const tarBytes = new Uint8Array(await customize(entries, domain, issued.token).arrayBuffer());
            const gz = await pipe(tarBytes, new CompressionStream('gzip'));
            const a = document.createElement('a');
            a.href = URL.createObjectURL(new Blob([gz], { type: 'application/gzip' }));
            a.download = pkg.saveAs;
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(a.href), 60000);
            return name;
        }
    };
})();
