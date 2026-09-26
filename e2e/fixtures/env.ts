// Where the suite points. The defaults are the KIND deployment's stable
// host ports (k8s/kind-start.sh), never a node IP.
function env(name: string, fallback: string): string {
    const v = process.env[name];
    return v === undefined || v === '' ? fallback : v;
}

export const ENV = {
    baseURL: env('L8TUNNEL_BASE_URL', 'https://localhost:5443'),
    /** login.json app.apiPrefix */
    apiPrefix: '/tun',
    user: env('L8TUNNEL_USER', 'admin'),
    pass: env('L8TUNNEL_PASS', 'admin'),
    desktopShell: '/app.html',
    mobileShell: '/m/app.html',
    loginShell: '/l8ui/login/',
    /** The KIND cluster's tunnel base domain and relay-0's control NodePort. */
    tunnelBase: 'tunnel.kind.test',
    relayControl: env('L8TUNNEL_RELAY', 'localhost:30443'),
    /** Where global setup leaves the agent binary and the tunnel CA. */
    stateDir: __dirname + '/../.state'
};

/** A name no other run or spec uses. */
export function uniqueName(prefix: string): string {
    return `${prefix}-${Date.now().toString(36)}${Math.floor(Math.random() * 1296).toString(36)}`;
}
