// Runs once before the suite:
//   1. builds the agent binary from this checkout, so the realtime specs
//      can connect a real agent;
//   2. installs a throwaway CA-signed certificate for the tunnel base
//      domain (as the Go KIND tests do) and waits until the relay serves it,
//      so that agent can verify the relay.
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as tls from 'tls';
import { Api } from './api';
import { AREA } from './api';
import { ENV } from './env';

const repoGo = path.resolve(__dirname, '../../go');

function openssl(dir: string, ...args: string[]): void {
    execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
}

/** A CA and a certificate for the tunnel base domain and its wildcard. */
function makeTunnelCert(dir: string): void {
    const base = ENV.tunnelBase;
    fs.writeFileSync(path.join(dir, 'leaf.ext'),
        `subjectAltName=DNS:${base},DNS:*.${base}\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n`);
    openssl(dir, 'ecparam', '-genkey', '-name', 'prime256v1', '-noout', '-out', 'ca.key');
    openssl(dir, 'req', '-x509', '-new', '-key', 'ca.key', '-subj', '/CN=l8tunnel e2e CA', '-days', '90', '-out', 'ca.pem');
    openssl(dir, 'ecparam', '-genkey', '-name', 'prime256v1', '-noout', '-out', 'tunnel.key');
    openssl(dir, 'req', '-new', '-key', 'tunnel.key', '-subj', `/CN=${base}`, '-out', 'tunnel.csr');
    openssl(dir, 'x509', '-req', '-in', 'tunnel.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
        '-days', '60', '-extfile', 'leaf.ext', '-out', 'tunnel.crt');
}

/** Whether the relay's control port presents a certificate from our CA. */
function relayTrusts(ca: Buffer): Promise<boolean> {
    const [host, port] = ENV.relayControl.split(':');
    return new Promise((resolve) => {
        const sock = tls.connect({ host, port: Number(port), servername: `connect.${ENV.tunnelBase}`, ca,
            ALPNProtocols: ['l8tunnel/1'] }, () => { sock.end(); resolve(true); });
        sock.on('error', () => resolve(false));
        sock.setTimeout(5000, () => { sock.destroy(); resolve(false); });
    });
}

export default async function globalSetup(): Promise<void> {
    fs.mkdirSync(ENV.stateDir, { recursive: true });
    execFileSync('go', ['build', '-o', path.join(ENV.stateDir, 'l8tunnel-agent'), './cmd/l8tunnel-agent'],
        { cwd: repoGo, stdio: 'inherit' });

    makeTunnelCert(ENV.stateDir);
    const api = await Api.login();
    try {
        const base = await api.domainNamed(ENV.tunnelBase);
        if (!base) throw new Error(`no ${ENV.tunnelBase} domain; is the KIND deployment up?`);
        // A new file name per run: the same name maps to the same storage
        // path, and an unchanged path doesn't make the relays reload.
        const stamp = Date.now().toString(36);
        base.certStoragePath = await api.upload(`e2e-tunnel-${stamp}.crt`, fs.readFileSync(path.join(ENV.stateDir, 'tunnel.crt')));
        base.keyStoragePath = await api.upload(`e2e-tunnel-${stamp}.key`, fs.readFileSync(path.join(ENV.stateDir, 'tunnel.key')));
        await api.put(AREA.edge, 'EdgeDomain', base);
    } finally {
        await api.dispose();
    }
    const ca = fs.readFileSync(path.join(ENV.stateDir, 'ca.pem'));
    const deadline = Date.now() + 90_000;
    while (!(await relayTrusts(ca))) {
        if (Date.now() > deadline) throw new Error(`relay ${ENV.relayControl} never served the e2e tunnel certificate`);
        await new Promise((r) => setTimeout(r, 1000));
    }
}
