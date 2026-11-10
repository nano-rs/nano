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

## `ui/playbooks/security-update.mjs` — full UI walk across roles (NAN-5085)

A re-runnable playbook that checks the web UI still works as designed after a
batch of security fixes (built for a `security/<version>` integration
branch, usable for any branch). It brings up a **throwaway** e2e stack from a
checkout (`scripts/e2e.sh up`, compose project `nanoe2e-<id>`, its own free
127.0.0.1 ports, never the `nanoch-*` dev stack), publishes that checkout's
web build into the stack's nginx edge (the shipped `nginx.opensource.conf`),
seeds data, runs the playbook, writes the report and tears the stack down.

**One command** (from the repo root; `--checkout` is the tree under test, both
its backend and its web UI):

```bash
git worktree add --detach ../sec-ui origin/security/<version>
nanosiem-web/tests/e2e/ui/playbooks/run-security-update.sh --checkout ../sec-ui --compare <baseline-out>/report.json
# via npm (runs from nanosiem-web/, so give absolute paths):
npm --prefix nanosiem-web run e2e:security-update -- --checkout "$PWD/../sec-ui"
```

Run it once on the **baseline** and once on the branch. Pass the baseline's
`report.json` to `--compare`. `diff-reports.mjs` then lists:

- **regressions**: pass on the baseline, fail on the branch
- denied-source leaks that only the branch has
- new heuristic warnings, such as dead buttons
- pre-existing failures (fail on both) and fixes

Use the branch's fork point as the baseline (`git merge-base origin/main
<branch>`), not the moving `origin/main`. Commits that land on main after the
cut change behaviour on their own. For example, the v2 entitlements change on
main (#8862) locks cases, notebooks and AI on an unlicensed e2e stack. The fork
point compares like with like.

On a shared machine, wrap the runner in the codex Docker gate
(`CODEX/docker-slot.sh <lane> -- …`). It refuses to start with less than
100 GiB free and tears its stack down on exit unless you pass `--keep`.

**Licensing.** e2e stacks carry no licence. When `/api/capabilities` reports a
surface as unlicensed (cases, notebooks, shadow investigation, AI providers),
its flows are recorded as SKIP with the reason. Its routes are still walked:
they must render the "Licensed feature unavailable" gate, not crash.

| Option | Meaning |
|---|---|
| `--checkout DIR` | tree to test (default: this checkout) |
| `--edition enterprise\|open` | default: enterprise when `nanosiem-enterprise/` exists |
| `--stack-env FILE` | reuse a live `scripts/e2e.sh up` stack (no up/down) |
| `--keep` | leave the stack up afterwards |
| `--compare REPORT` | diff against an earlier report → `diff.md` |
| `--out DIR` | report dir (default `target/e2e/security-update/<label>-<edition>-<ts>`) |

Env knobs: `PLAYBOOK_ROLES=admin,analyst` (subset), `PLAYBOOK_ONLY=<regex on
check id>`, `PLAYBOOK_WALK=0` (flows only), `PLAYBOOK_BUTTONS=0` (no
dead-button probe) or `=all` (also as the analyst; default admin only), `E2E_UI_HEADED=1` (watch it), `CHROME_PATH`.

**Users** (created through the API by the bootstrap admin):

| role | permissions |
|---|---|
| `admin` | the bootstrap Admin |
| `analyst` | search, saved searches, dashboards, alerts, cases, notebooks, detections:view, hunts (incl. recon) — granted the restricted source |
| `helpdesk` | `users:view` + `users:edit` only |
| `scoped` | the analyst permissions, but NOT granted the restricted source |

Every user is also in the built-in Everyone group (ReadOnly role).

**What it checks**

- *Route walk*: every route in `App.tsx` (read at run time, so new routes are
  covered automatically) as every user. Each page must not render NotFound, go
  blank, bounce to `/login`, or log console/page errors. It must not get an
  unexpected 4xx/5xx. A route must not render for a user who lacks its `PermissionRoute`
  permission. Entitlement is judged on the route the browser lands on, so
  redirects count. Access Denied fails the check for the Admin. For other users
  it is a warning, because some pages gate tabs inside the page. As admin the playbook also clicks each
  non-destructive button in `main`. A click with no effect (no DOM change,
  request, dialog or navigation) is reported as a dead button.
- *Flows*:
  - search: nPL with eval/strftime, anomaly, prevalence, sequence, bin,
    fillnull and reserved-word aliases; Inspect SQL; saved searches
  - detections: UI create (real-time), UI edit, UI promote, real-time delete,
    and scheduled alerting rules whose alerts must fire
  - alerts
  - cases, case notebooks and shadow investigation (enterprise)
  - dashboards
  - reports: generate, run and download
  - log sources: sampling exclude condition, Test VRL, publish, deploy and
    parser repository import
  - ingest tokens
  - AI provider Test connection with a bad URL and a private URL
  - users, roles and groups: invite, edit, disable/enable, password reset,
    MFA reset
  - API keys: create, edit expiry, rotate
  - SIEM health, audit log export, licence, marketplace
- *Denied source*: the `scoped` user must never see the restricted source's
  events or `source_type` in search results, explain/SQL, alerts, cases,
  notebooks, report artifacts or recon. Every `/api` response body of that
  user's browser session is scanned.
- *`sec` checks*: hardening expectations from the 2026-11-08 security review,
  e.g. a `users:edit` holder cannot take over an Admin, or a password reset
  ends the user's sessions. They fail on a branch without the fix. The diff
  reports them as fixed, never as regressions.

**Known issues**: `ui/playbooks/known-issues.mjs` lists pre-existing defects the
playbook still sees on main. Each entry has a narrow pattern and a Linear ID.
A match downgrades the check to a warning and is reported once under "Known
pre-existing issues". Delete the entry when its issue is fixed.

**Output**: `report.json`, `report.md` (coverage routes × roles, failures with
url/problems/screenshot, warnings, leaks, observed 403/404 per role),
`screenshots/` on failure, and `diff.md` with `--compare`. Secrets (passwords,
tokens, API keys) are scrubbed from every artifact and masked before any
screenshot. Exit code 1 on any failure or leak.
