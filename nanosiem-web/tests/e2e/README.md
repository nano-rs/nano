<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# nano E2E: dead-route / 404 defense

The repo's first front-end tests (NAN-1934). They guard against the class of bug
that shipped NAN-1933 — an in-app/notification link whose target matches no route,
so it renders the 404 page. Two complementary tools:

| Tool | Needs a running stack? | Where it runs | Catches |
|------|------------------------|---------------|---------|
| `check-dead-links.mjs` | **No** | **CI gate** (`.github/workflows/frontend-dead-links.yml`) + local | literal internal links (FE + backend) that match no route |
| `crawl-404.mjs` | Yes | local / manual, optional nightly | reachable routes rendering 404 + runtime `/api` 4xx/5xx + client crashes |

## Why a static check is the CI gate (not the crawler)

The SPA serves **`200 index.html` for every path** — React Router decides 404
client-side, so HTTP status can't see a dead route. The crawler solves that by
running a real browser, but that needs a **booted stack + login** — too heavy and
flaky for a merge gate. The static checker needs **nothing running**: it reads the
route table out of `App.tsx` and greps the source for link targets, in ~1s. So the
enforceable "no new 404" gate is static; the crawler is the deeper local/runtime
pass.

## `check-dead-links.mjs` — the gate

```bash
npm run test:deadlinks            # exit 1 on any NEW dead link
node tests/e2e/check-dead-links.mjs --update-baseline   # accept current findings
```

- Extracts routes from `App.tsx` (drops the `*` / `/*` catch-alls — those *are*
  the 404).
- Scans `nanosiem-web/src` and `nanosiem-*/src` for `to=/href=/navigate()/href:`
  (TS/TSX) and `link: Some("…")` / `"url": "…"` (Rust).
- Flags any target that matches no route. **Ratchet:** anything in
  `dead-links-baseline.json` is grandfathered; only *new* dead links fail the
  gate. `dead-links-baseline.json` is the living fix-list — remove an entry when
  you fix its link.
- **Precision-first** (a noisy gate gets disabled). Known gaps, left to the
  crawler / review: fully-dynamic `to={item.href}`, Rust nav strings built
  outside `link:`/`"url":`, and leading-slash-less webhook deep-links.

## `crawl-404.mjs` — the runtime crawler

Needs a running stack + a Chrome/Chromium binary; `puppeteer-core` (no bundled
Chromium) is a devDependency.

```bash
NANO_E2E_USER=you@example.com NANO_E2E_PASS='…' npm run test:e2e:404
```

Logs in via the real `/login` prompt, BFS-crawls internal links, and flags routes
that render `NotFoundPage` (keyed off `data-testid="not-found-404"`), plus network
responses ≥ 400 and console/page errors. Writes `crawl-404-report.json`. Detection
is **DOM/marker-based** — `response.status()` is 200 even for a dead SPA route.

| env | default | notes |
|-----|---------|-------|
| `BASE_URL` | `http://localhost:5173` | target origin |
| `NANO_E2E_USER` / `NANO_E2E_PASS` | — | required; never commit creds; E2E user must have MFA disabled |
| `CHROME_PATH` | auto-detect | explicit Chrome executable |
| `MAX_PAGES` | `250` | crawl cap |
| `HEADLESS` | `1` | `0` to watch it |
| `STRICT` | `0` | `1` = also fail on runtime 4xx/5xx + console errors |

> Known tuning item: against `vite dev`, on-demand lazy-chunk compilation can make
> later navigations slow (20s timeouts). Prefer running it against `vite preview`
> (a production build) or bump `NAV_TIMEOUT_MS`.
