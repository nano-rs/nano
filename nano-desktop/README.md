# nano Desktop

Native macOS-first client for nano, built on Tauri 2. Connects to any nano
instance over HTTPS — the user supplies the server URL at first launch.

Built to the `nano Desktop` design handoff (see `design-ref/`), which is a
deliberately different design language from `nanosiem-web`: glass/vibrancy
surfaces, the macOS system font, roomier radii, and the hot-pink accent
(`#FF5CA8`).

## Running it

```sh
npm install
npm run tauri dev
```

Against a local stack, connect to `http://localhost:3000` and set the search
service to `http://localhost:3002` (see below).

## Architecture

**Every HTTP request originates in Rust, never in the webview.** This is load
bearing, not a preference:

- `nanosiem-api` only allows CORS origins it was explicitly configured with
  (`build_cors_layer` in `nanosiem-api/src/routes.rs`). A webview's origin is
  `tauri://localhost`, which no operator will have in their allowlist — so
  `fetch()` from the frontend would be blocked against every real instance.
  Requests issued from Rust are not subject to CORS at all.
- The access token never enters JavaScript's reach. The refresh token lives in
  the macOS Keychain; the access token lives in Rust memory only. The webview's
  CSP (`connect-src 'self' ipc:`) forbids it from making network requests.
- On-prem instances with an internal CA work because reqwest is built against
  native-tls (Security.framework), and a self-signed cert can be accepted
  explicitly by the user.

| File | Role |
| --- | --- |
| `src-tauri/src/siem.rs` | The client: connect, login, MFA, refresh, search stream |
| `src-tauri/src/store.rs` | Server config on disk, refresh token in the Keychain |
| `src-tauri/src/lib.rs` | Tauri commands exposed to the frontend |
| `src/screens/Auth.tsx` | Server URL → password → MFA challenge |
| `src/screens/Search.tsx` | nPL query bar, histogram, streaming results table |

The Tauri crate is its **own cargo workspace**, excluded from the root nanosiem
workspace, so the wry/webkit dependency tree stays out of the backend lockfile.

### Search is a separate service

`/api/search*` is served by `nanosiem-search`, not `nanosiem-api`. A deployed
instance fans those paths to it from the same origin, so one URL is normally
enough. Local dev splits them (API on `:3000`, search on `:3002`), so the
connect screen has an optional **search service** override — the same escape
hatch a split-ingress deployment would need.

Search uses `POST /api/search/stream` (SSE). Rust parses the frames and forwards
them to the frontend over a Tauri `Channel`, so rows paint as ClickHouse
produces them. The `X-Nano-Cache` response header is forwarded as a `cache_meta`
event so a cached result is labelled as cached, with a refresh that bypasses the
server-side cache.

## Scope

This build covers **auth** and **search**. The handoff's other surfaces — the
agent panel, MCP server, workspace tabs, quick search, tray, desktop widgets,
right-click IOC service — are not built yet. The sidebar shows their entries
inert rather than as buttons that do nothing.
