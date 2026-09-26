// A REST client for the management API, used to set up and clean up the
// data the specs drive through the UI. It talks to the same web server the
// browser does, as the same admin user.
import { APIRequestContext, request } from '@playwright/test';
import { ENV } from './env';

export const AREA = { access: 40, edge: 41, live: 42, alerts: 43, filestore: 0 } as const;

/** TunIssueKind (proto/tun.proto). */
export const ISSUE = { token: 1, revoke: 4 } as const;

export class Api {
    private constructor(private ctx: APIRequestContext, readonly token: string) {}

    static async login(): Promise<Api> {
        const ctx = await request.newContext({ baseURL: ENV.baseURL, ignoreHTTPSErrors: true });
        const resp = await ctx.post('/auth', { data: { user: ENV.user, pass: ENV.pass } });
        if (!resp.ok()) throw new Error(`login as ${ENV.user}: ${resp.status()} ${await resp.text()}`);
        const token = (await resp.json()).token;
        if (!token) throw new Error(`login as ${ENV.user}: no token`);
        return new Api(ctx, token);
    }

    async dispose(): Promise<void> {
        await this.ctx.dispose();
    }

    private url(area: number, service: string): string {
        return `${ENV.apiPrefix}/${area}/${service}`;
    }

    private async call(method: string, area: number, service: string, body?: unknown): Promise<any> {
        const headers = { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' };
        let url = this.url(area, service);
        const opts: any = { method, headers };
        if (body !== undefined) {
            if (method === 'GET') url += '?body=' + encodeURIComponent(JSON.stringify(body));
            else opts.data = body;
        }
        const resp = await this.ctx.fetch(url, opts);
        const text = await resp.text();
        if (!resp.ok()) throw new Error(`${method} ${service}: ${resp.status()} ${text}`);
        if (!text.trim()) return {};
        const json = JSON.parse(text);
        const err = json.error || json.Error || json.errorMessage;
        if (typeof err === 'string' && err) throw new Error(`${method} ${service}: ${err}`);
        return json;
    }

    post(area: number, service: string, body: unknown): Promise<any> {
        return this.call('POST', area, service, body);
    }

    put(area: number, service: string, body: unknown): Promise<any> {
        return this.call('PUT', area, service, body);
    }

    /** Rows an L8Query selects. */
    async query<T = any>(area: number, service: string, text: string): Promise<T[]> {
        const out = await this.call('GET', area, service, { text });
        return (out.list || []) as T[];
    }

    /** Deletes the rows a where-clause selects (REST deletes take a query). */
    async remove(area: number, service: string, typeName: string, where: string): Promise<void> {
        await this.call('DELETE', area, service, { text: `select * from ${typeName} where ${where}` });
    }

    /** Issues a token; returns its ID and the show-once token string. */
    async issueToken(name: string, policy: Record<string, unknown> = {}): Promise<{ tokenId: string; token: string }> {
        const out = await this.post(AREA.access, 'TunIssue', { kind: ISSUE.token, tokenName: name, policy });
        return { tokenId: out.tokenId, token: out.token };
    }

    async revokeToken(tokenId: string): Promise<void> {
        await this.post(AREA.access, 'TunIssue', { kind: ISSUE.revoke, tokenId });
    }

    async tokenNamed(name: string): Promise<any | undefined> {
        return (await this.query(AREA.access, 'TunToken', `select * from TunToken where name=${name}`)).find((t) => t.name === name);
    }

    async domainNamed(domain: string): Promise<any | undefined> {
        return (await this.query(AREA.edge, 'EdgeDomain', `select * from EdgeDomain where domain=${domain}`)).find((d) => d.domain === domain);
    }

    /** Stores a file in FileStore, as the UI's certificate upload does. */
    async upload(fileName: string, data: Buffer): Promise<string> {
        const out = await this.post(AREA.filestore, 'FileStore', {
            fileName, mimeType: 'application/x-pem-file', fileData: data.toString('base64'), documentId: 'edgecert', version: 1
        });
        return out.storagePath;
    }
}

/** Runs cleanup without letting its failure mask the test's own result. */
export async function quietly(what: string, fn: () => Promise<unknown>): Promise<void> {
    try {
        await fn();
    } catch (e) {
        console.warn(`cleanup (${what}) failed: ${(e as Error).message}`);
    }
}
