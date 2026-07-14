# nano Desktop — Handoff

Native macOS-first Tauri 2 client for nano, at `nano-desktop/` in the nanosiem
monorepo. This doc is the single source of truth for picking the work up in a
fresh session.

Built to the design handoff in `nano-desktop/design-ref/` (`README.md` +
`nano Desktop.dc.html` — open the `.dc.html` in a browser to see all 10 mocks
1a–6a). **Read `design-ref/README.md` for exact tokens/copy per screen** before
building a new surface.

---

## 0. State

Branch `feat/NAN-1813-nano-desktop`, worktree
`../nanosiem-worktrees/feat/NAN-1813-nano-desktop`. Everything is committed and
**rebased on `origin/main`**.

Commits (oldest→newest):
- `e3f52cb8` NAN-1813 — the app: connect/auth, search (nPL, histogram, tabs,
  results, event detail), embedded terminal (PTY), pivt agent panel over MCP.
- `d4a13085` NAN-1824 — menu-bar tray + native new-alert notifications.
- `a37ab722` NAN-1826 — Quick Search (⌥Space) spotlight.
- `b93a2488` NAN-1826 — search-based IOC peek, selection capture, Ask pivt; the
  production-build CodeMirror fix; the app icon.
- `abe57db7` **NAN-1830** — pivt panel polish: safe markdown, per-turn collapsible
  tool cards, no horizontal bleed.
- `f5791b35` **NAN-1831** — ⭐ pivt drives the product: its tool calls become real,
  grouped, preview-capped search tabs.
- `cb90a464` **NAN-1832** — bulk IOC lookup (⌘B): paste a report, see what's in
  your data.
- `240f6d8a` **NAN-1833** — AGENT rail: pivt Sessions + the real MCP tool inventory.
- `e14be37e` **NAN-1834** — macOS Service: right-click any IOC in any app.
- `7f2e8681` **NAN-1835** — SOC Overview dashboard + always-on-top desktop widgets.
- `7cc45f60` — six correctness bugs from an adversarial review.
- `b4b4e5e7` — five more from an independent second-pass (Codex) review.

**The whole roadmap in the previous handoff is done.** All six Linear issues
(NAN-1830…1835) are implemented, reviewed twice, and verified.

### Verified how far a machine can take it
- `cargo test` (35), `npx vitest run` (53), `npx tsc --noEmit`, `npx vite build`,
  and `npx tauri build --debug --bundles app` are all green.
- **pivt's tool stream** was captured from a REAL headless run against dan's local
  instance and the parser written against it (see §2).
- **The bulk-IOC and dashboard queries** were run against the live search service
  and the responses pinned as test fixtures.
- **The MCP handshake** was performed against the real server (69 tools).
- **The macOS Service** is registered in the live system services registry
  (`pbs -dump_pboard` shows "Search in nano").

### What still needs a HUMAN (the AM validation list)
Everything below needs a person at the keyboard, because it needs a Touch ID
unlock and a mouse:
1. **⌘I → ask pivt something that makes it search.** Confirm a `pivt` tab group
   appears with real, preview-capped search tabs in it, and that closing the group
   closes them together.
2. **⌘B → paste a defanged threat report.** Confirm the indicators are extracted
   and refanged, and that "N of M seen" is right.
3. **Rail → Sessions / MCP tools.** Sessions needs Enterprise notebooks; MCP tools
   spawns npx (first load is slow) and should list ~69 tools.
4. **Rail → Dashboards → 📌 Pin.** Confirm the widget floats above other apps,
   updates, and goes blank when you Lock.
5. **Select an IP in any app → right-click → Services → "Search in nano."**
   Bundle only. macOS caches the registry; `pbs -flush` if it doesn't appear.

---

## 1. How to build & run

`nano-desktop/` has its own frontend (`src/`, React+Vite+Tailwind v4) and its own
Rust cargo workspace (`src-tauri/`, excluded from the root workspace).

- **Dev (hot-reload):** `npm run tauri:dev`. USE THIS for iteration. **Caveats:**
  the ⌥Space selection capture needs Accessibility, which macOS will not grant a
  bare `tauri dev` binary; and the **macOS Service (NAN-1834) does not exist in dev
  at all** — the Services registry is keyed off the `.app`'s Info.plist.
- **Bundle (`.app`):** `npx tauri build --debug --bundles app` (~40s incremental)
  → `src-tauri/target/debug/bundle/macos/nano.app`. Launch with `open <path>`.
  Each rebuild changes the ad-hoc signature and **resets the Accessibility grant**.
- **⌥Space is a single system-wide shortcut** — only ONE nano instance can hold it.
  Stop the dev app before launching the bundle, or the second registration
  silently fails.
- **Verify before committing:** `(cd src-tauri && cargo test)`, `npm test`,
  `npx tsc --noEmit`, `npx vite build`. All must be green.

The app connects to a nano instance chosen on the connect screen. Dan's local
instance is `http://localhost:5173` (API + search on one origin). Split dev is
`:3000` / `:3002` with a search-URL override. Local API key for direct probing:
`X-API-Key: -PopdJxnG9EY1P71Vt6XTcpuWOSLg6IJ8BZTwLKzY7Y` (search only — it lacks
`alerts:view`, `notebooks:view` and `prevalence:view`, which is why some endpoints
must be probed through the app's user session instead).

### Test IOCs (verified live)
Real: domain `reddit.com` (1895 events / 1075 assets), IP `151.101.195.5`
(319/295), hash `b4b1ea144e9225e4740a0369553c7724eb5fee2859af9f9985ca82dc891829d7`
(120/1). Not seen: `c2-totally-fake-8823.net`, `203.0.113.77`,
`9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`.

---

## 2. Critical gotchas (do not re-break)

- **All HTTP originates in Rust, never the webview.** The API's CORS only allows
  configured origins; a webview's origin is `tauri://localhost`. New data access =
  a `#[tauri::command]` + a method on `Siem` + an `ipc.ts` wrapper.
- **Reused `nanosiem-web/src` modules** (via the `@` alias) resolve their deps
  against `nanosiem-web/node_modules` — a SECOND copy of shared packages. Traps,
  all silent in dev and breaking only in the bundle:
  - React → `dedupe: ['react','react-dom']`.
  - **CodeMirror/Lezer → the `forceSingletonCodemirror` resolveId plugin** in
    `vite.config.ts`. Two `@codemirror/state` copies blank the whole Search screen
    in the bundle. `dedupe`/aliases do NOT fix it. **Keep the plugin.**
  - Tailwind doesn't scan reused files → add `@source '../../nanosiem-web/…'` per
    reused file in `styles.css`.
  - This is also why the dashboard's charts are hand-drawn bars and not Recharts.
- **pivt's output is attacker-influenceable.** Its context is deliberately filled
  with log content, which the attacker being investigated wrote. Anything that
  renders it must be containment-first: `lib/markdown.tsx` emits React elements
  only, never raw HTML, and never an anchor (a link whose target the attacker chose
  is a phishing primitive). NEVER `--permission-mode bypassPermissions` in
  `agent.rs`; the read-only key and the tool deny-list are the boundary.
- **pivt cannot call `search_sql`.** The MCP server advertises it as its PRIMARY
  search tool, but the app's key deliberately lacks `search:sql`, so it returns
  Forbidden. The system prompt now steers pivt to the nPL `search` tool — verified
  to remove the wasted turn. Don't "fix" this by granting `search:sql`.
- **Search `limit` caps GROUPS, not events**, on an aggregate query. A hidden
  default silently truncates an answer — it once cut a 24h hourly timechart to 20
  of its 25 buckets and drew a healthy cluster flatlining. `peek_request` takes an
  explicit limit at every call site for this reason.
- **`min(timestamp)` over an empty match set returns the epoch, not null.** An
  indicator nobody has seen will claim "first seen 1 Jan 1970" unless suppressed.
- **A 200 is not a result set.** Anything that isn't `{results: [...]}` must be an
  error, never a zero — a false "not seen" is the worst bug this app can have.
- **Accent is pink `#FF5CA8` on purpose.** Don't "fix" it to the mock's mint.
- **Widget windows** need `"widget-*"` in `capabilities/default.json`, or every
  `invoke` from one is denied. The `Destroyed` handler is scoped to `main`, or
  unpinning a widget reaps the analyst's shell.

---

## 3. Key files

Frontend (`src/`): `App.tsx` (auth gate), `main.tsx` (routes by window label:
`quick` / `widget-*` / the app), `screens/Search.tsx` (the workspace: tabs, agent
mirroring, all the panes), `screens/QuickSearch.tsx`, `screens/Widget.tsx`,
`components/AgentPanel.tsx` (pivt), `components/{Search,Tool,Bulk,Sessions,
McpTools,Dashboard}Pane.tsx`, `components/TabStrip.tsx`, `state/tabs.ts` (tab
reducer + groups), `lib/agent-tools.ts` (MCP tool → product surface), `lib/
markdown.tsx` (containment-first renderer), `lib/indicator.ts` (classify + extract
+ refang), `lib/dashboard.ts`, `lib/ipc.ts` (the command surface).

Rust (`src-tauri/src/`): `lib.rs` (command registry, windows, tray), `siem.rs`
(HTTP, auth, SSE search, `ioc_peek`, `bulk_ioc_peek`, `dashboard`, notebooks),
`agent.rs` (pivt: mint key, write MCP configs, run `claude`, parse stream-json),
`mcp.rs` (stdio handshake → the real tool inventory), `services.rs` (macOS
Services provider), `quick.rs`, `tray.rs`, `pty.rs`, `store.rs`, `biometric.rs`.
`Info.plist` (NSServices — its NSMessage is pinned to the Rust selector by a test).

---

## 4. What's next

Nothing on the previous roadmap is outstanding. Candidates, roughly by value:

1. **Detections & Cases surfaces** (mocks 2a, 5a). The two remaining inert rail
   items. 2a's "agent verdict" column is the natural next step for pivt.
2. **Expanded search result** (mock 2b) — the raw/extracted split with pivot chips.
   The event detail today is simpler than the mock.
3. **The per-tool policy engine** (mock 4a). The MCP tools screen deliberately does
   NOT draw the auto-allow / ask / 2-person-confirm column, because that engine
   doesn't exist. Building it is what would let pivt hold a write-capable key.
4. **Light appearance** (mock 6a) — tokens are all `var(--color-*)`, so this is
   mostly a second token set plus `prefers-color-scheme`.
5. **Open follow-ups already filed:** NAN-1821 (pivt off-screen event, P2),
   NAN-1822 (cert pinning + agent-key revoke on sign-out, P2), NAN-1823 (P3
   robustness batch).

---

## 5. Reminders
- Every code task → a Linear issue (Nanos-sh) first, `In Progress`.
- Review before each commit. Both review passes on this branch paid for
  themselves — eleven real bugs, several of them the "confident zero" class this
  product cannot ship.
- The bundle path is the only way to validate Accessibility (⌥Space capture) and
  macOS Services; everything else iterates faster in `tauri:dev`.
