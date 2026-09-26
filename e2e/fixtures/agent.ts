// A real l8tunnel agent (the binary global setup builds), connected to
// relay-0 with one TCP tunnel to a local echo server. The realtime specs
// watch it appear and disappear in the UI.
import { ChildProcess, spawn } from 'child_process';
import * as net from 'net';
import * as path from 'path';
import { ENV } from './env';

export class RunningAgent {
    private output = '';

    private constructor(private proc: ChildProcess, private echo: net.Server, readonly tunnel: string) {
        proc.stdout?.on('data', (d) => (this.output += d));
        proc.stderr?.on('data', (d) => (this.output += d));
    }

    /** Starts an agent for token with a TCP tunnel named tunnel. */
    static async start(token: string, tunnel: string): Promise<RunningAgent> {
        const echo = net.createServer((c) => c.pipe(c));
        await new Promise<void>((r) => echo.listen(0, '127.0.0.1', () => r()));
        const port = (echo.address() as net.AddressInfo).port;
        const proc = spawn(path.join(ENV.stateDir, 'l8tunnel-agent'), [
            '--relay', ENV.relayControl, '--server-name', `connect.${ENV.tunnelBase}`,
            '--ca', path.join(ENV.stateDir, 'ca.pem'), '--token', token, '--proxy', 'none',
            'tcp', `127.0.0.1:${port}`, '--name', tunnel
        ], { stdio: ['ignore', 'pipe', 'pipe'] });
        return new RunningAgent(proc, echo, tunnel);
    }

    /** What the agent logged, for failure messages. */
    log(): string {
        return this.output;
    }

    /** A clean stop: the agent closes its session (AGENT_CLOSED). */
    async stop(): Promise<void> {
        if (this.proc.exitCode === null && this.proc.signalCode === null) {
            const exited = new Promise((r) => this.proc.once('exit', r));
            this.proc.kill('SIGTERM');
            await Promise.race([exited, new Promise((r) => setTimeout(r, 5000))]);
            if (this.proc.exitCode === null) this.proc.kill('SIGKILL');
        }
        await new Promise((r) => this.echo.close(() => r(null)));
    }
}
