# l8tunnel browser suite

Playwright specs that drive the real UI (desktop `app.html` and the mobile
bundle `m/app.html` on a Pixel 7 profile) against the KIND deployment.

## Running

```bash
k8s/kind-start.sh            # or an already running KIND deployment
cd e2e && npm install
npx playwright install chromium   # once per machine
npm test                     # both; or npm run test:desktop / test:mobile
npm run report               # the HTML report of the last run
```

Global setup builds the agent binary from this checkout (`go` must be on
the PATH) and installs a throwaway CA-signed certificate for the tunnel base
domain, so the realtime specs can connect a real agent to relay-0. The Go
KIND tests install their own certificate the same way.

| Variable | Default |
|---|---|
| `L8TUNNEL_BASE_URL` | `https://localhost:5443` |
| `L8TUNNEL_USER` / `L8TUNNEL_PASS` | `admin` / `admin` |
| `L8TUNNEL_RELAY` | `localhost:30443` (relay-0's control NodePort) |

## Layout

- `fixtures/`: the session fixture (bearer token seeded into
  sessionStorage, page error capture), the REST client used for setup and
  cleanup, the real agent, and global setup
- `pages/`: page objects for the desktop nav, tables, popups and reference
  picker, the mobile nav, and the login page
- `tests/desktop/`, `tests/mobile/`

## Hygiene

- Every spec cleans up what it creates, and a cleanup failure never hides
  the spec's own result.
- Specs assert on the rows they created (after filtering), never on counts.
- Scratch specs are named `zzz-*` and never committed (`npm run lint:scratch`).
- After a pod restart, rerun a failure once before calling it a bug.
