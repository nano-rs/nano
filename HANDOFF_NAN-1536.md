# NAN-1536 — Observability Console — Verification & Repair Handoff

Branch: `feat/NAN-1536-observability-console`
Worktree: `/Users/dan/Documents/git/nanosiem-worktrees/feat/NAN-1536-observability-console`
Status as of this pass: **COMPILES CLEAN, both Rust and web.** Not committed; no `cargo fmt` run.

---

## Compile state (authoritative, run this pass)

| Target | Command | Result |
|--------|---------|--------|
| Rust (4 crates) | `cargo check -p nanosiem-core -p nanosiem-search -p nanosiem-api -p nanosiem-enterprise` | **PASS** (exit 0) |
| Web | `npm run build` (`generate-udm-fields` + `tsc -b` + `vite build`) | **PASS** (exit 0) |

Remaining Rust output: one **pre-existing, unrelated** warning, not from this branch:
```
warning: associated constant `VALIDATE_SAFE_STRINGS_MAX_DEPTH` is never used
  --> nanosiem-core/src/source_configs/service.rs:518:11
```
Web build: no TS errors. All observability chunks emit
(`ObservabilityConsole`, `ServicesTab`, `TracesTab`, `MetricsTab`, `SlosTab`).
Vite emits the usual "chunks larger than 500 kB" advisory (`index`, vendor-recharts,
vendor-codemirror) — pre-existing, not introduced here.

No stubs were inserted. **`// TODO(NAN-1536)` count: 0.** Every slice landed real code.

---

## What shipped, per surface

### Backend — core (BE-CORE)
- `nanosiem-core/src/query/clickhouse_sql_gen/otel.rs` — RED SQL builders +
  `SliKind` enum (`Availability` | `Latency`), 6 new tests. Single time-bounded
  WHERE, no PREWHERE, `quantileTDigest`, bounded LIMITs, escaped params.
- `nanosiem-core/src/search/service/otel.rs` — `SearchService` glue:
  `observability_services_overview`, `observability_service_detail`,
  `observability_slo_compute` (returns `(current 0..1, total_spans)`).
- `nanosiem-core/src/observability/{mod.rs,slo_repository.rs}` — `SloRepository`
  (runtime sqlx, no offline cache), `SloDefinition`, `SloSliKind`.
- `nanosiem-core/src/typeid.rs` — `slo_` typeid prefix.
- 16 otel tests pass.

### Backend — search + api (BE-API)
- `nanosiem-search/src/handlers/otel.rs` + `mod.rs` + `lib.rs` + `openapi.rs` —
  `GET /api/search/services`, `GET /api/search/services/{service}` (routes
  registered at `nanosiem-search/src/lib.rs:572-574`).
- `nanosiem-api/src/handlers/observability_slos.rs` + `routes.rs` + `openapi.rs` —
  SLO CRUD (routes at `nanosiem-api/src/routes.rs:2394-2402`). On-read compute,
  no recompute job.
- OpenAPI path floors bumped (+4 both editions). open=384 (floor 375),
  enterprise=519 (floor 484). `verify_openapi` tests pass.
- No core `SearchRequest` field added → **no enterprise SearchRequest literal
  churn** needed.

### Frontend — foundation (FE-FOUNDATION)
- Single nav entry `Observability` → `/observability`
  (`AppLayout.tsx:229`); old NAN-1534 Traces/Metrics accordion removed.
- Routing (`App.tsx`): `/observability` + `/observability/:tab` →
  `ObservabilityConsole`. `/trace/:traceId` kept (log→trace pivot).
  Retired files **deleted**: `pages/TracesExplorerPage.tsx`,
  `pages/MetricsExplorerPage.tsx`, `components/search/MetricsChartView.tsx`.
- `pages/observability/ObservabilityConsole.tsx` — tab shell (URL `:tab`,
  drill-in via `?service=`), shared `DateTimeRangePicker`.
- `components/observability/charts.tsx` — `Sparkline`, `REDChart`,
  `LatencyScatter`, `BudgetBar`.
- `lib/api/observability.ts` (`api.observability`) — typed client to the pinned
  contracts; traces/metrics passthroughs delegate to `SearchApi`.

### Frontend — surfaces (5 agents)
- `ServicesTab.tsx` + `ServiceDetail.tsx` + `components/observability/format.ts`
  — RED overview (list/grid, health-sorted, sparklines) → service detail
  (RED panels, endpoints table, exemplar scatter, SLO strip when SLOs exist).
- `TracesTab.tsx` + `components/observability/TraceWaterfall.tsx` — filter →
  scatter → inline waterfall + span drawer (richer console waterfall; the
  shared `/trace/:id` page is left intact).
- `MetricsTab.tsx` — multi-panel ad-hoc metric explorer (catalog → per-panel
  query: metric / service filter / step). Group-by/agg dropped (the NAN-1534
  endpoint only buckets one metric by step).
- `AlertsTab.tsx` + `components/observability/AlertsMonitors.tsx` — consumes the
  **existing** `/api/alerts` subsystem (no new backend); adapts `Alert` → monitors.
- `SlosTab.tsx` + `components/observability/SloEditorDialog.tsx` — error-budget
  cards + create/edit dialog + canonical `ConfirmDialog` delete.

---

## Contract fixes made this pass

**1. Service-aware URL routing gap (the only real bug found).**
`nanosiem-web/src/lib/api/utils.ts` `getServiceUrl()` routes by an explicit
path allowlist. The new `/api/search/services` + `/api/search/services/{service}`
endpoints (and the NAN-1534 `/api/search/traces` + `/api/search/metrics*`
endpoints the console now depends on) were **not** in the allowlist, so in any
deployment where `VITE_SEARCH_URL` ≠ `VITE_API_URL` they would have hit the main
API (3000) and 404'd. Added them to the SEARCH_URL branch (handles both the
exact path and the `?query`/`/{id}` variants, since `getServiceUrl` receives the
full path-with-querystring). tsc + build re-verified green after the edit.

> Note: this also repairs a latent NAN-1534 routing gap (traces/metrics were
> never in the allowlist either). They happen to work in single-origin local dev
> where SEARCH_URL falls back to API_BASE_URL, which is why it went unnoticed.

No other contract drift found. The surface↔foundation↔backend contracts line up:
- `ServiceDetailResponse` is **top-level** (`service`/`red`/`endpoints`/`exemplars`,
  not wrapped) on both the API and the client — matches.
- SLO verbs/paths match: GET/POST `/api/observability/slos`,
  PUT/DELETE `/api/observability/slos/{id}`.
- `api.observability` getter, types, and all five tabs are imported and wired
  in the console; drill-ins resolve.

---

## Coherence confirmation

- Single `Observability` rail entry → `/observability`. ✔
- All 5 tabs imported + rendered in `ObservabilityConsole` (not stubs). ✔
- Service-detail drill-in: `openService` → `?service=` on services tab →
  `ServiceDetail` mounts inline with working `onBack`. ✔
- Trace drill-in: `onOpenTrace` → `/trace/:id` (shared page); TracesTab also has
  its own inline waterfall. ✔
- Old `TracesExplorerPage` / `MetricsExplorerPage` routes retired (files deleted,
  routes replaced). ✔
- SLO migration `209_observability_slos.sql` is numbered above the current
  highest (`208_ai_usage_events.sql`). ✔ Idempotent (`CREATE TABLE IF NOT
  EXISTS`), with SLI-kind + latency-threshold CHECK constraints and a
  `(service, created_at DESC)` index.

---

## Endpoint contracts (final)

**Search service (port 3002; auth: bearer JWT or X-API-Key):**
- `GET /api/search/services?start&end&window_hours`
  → `{ services: [{ service, request_count, rate_per_sec, error_rate(0..1),
    p50_ms, p95_ms, p99_ms, health:"good"|"warn"|"bad", sparkline:[{t,v}] }] }`
- `GET /api/search/services/{service}?start&end&window_hours&exemplar_limit`
  → `{ service, red:{rate:[{t,v}],errors:[{t,v}],latency:[{t,p50,p95,p99}]},
    endpoints:[{span_name,request_count,error_rate,p95_ms}],
    exemplars:[{trace_id,duration_ms,error,start_time,span_name}] }`
    (top-level, not wrapped)

**API service (port 3000; reads need `search:view`, mutations `settings:system`):**
- `GET /api/observability/slos` → `{ slos: [Slo] }`
- `POST /api/observability/slos` `{name,service,sli_kind,target(0..1],
  window_days(1..=90),latency_threshold_ms?}` → `201 Slo`
- `PUT /api/observability/slos/{id}` (typeid `slo_…` or bare UUID) → `200 Slo`
- `DELETE /api/observability/slos/{id}` → `204`
- `Slo` = SloDefinition + computed `current`, `budget_remaining_pct`,
  `burn_rate`, `status`("ok"|"at_risk"|"breaching").

**Alerts surface reuses existing** `GET /api/alerts` (+ `/counts`, `/velocity`).

**SLO migration: `migrations/postgres/209_observability_slos.sql`.**

---

## Smoke test (Step 4)

Both local services are up, but the running binaries are the **stale main-checkout
build**, not this branch — so SLO results below reflect the old binary, not the
branch code:

```
GET http://localhost:3000/health          → 200
GET http://localhost:3002/health          → 200
GET http://localhost:3002/api/search/services → 401  (route present, auth required)
GET http://localhost:3000/api/observability/slos → 404  (stale binary; route IS
                                                          registered in branch source)
```

The 404 is expected: the locally-running api process predates this branch. Both
new routes are registered in the branch (`routes.rs:2394-2402`,
`lib.rs:572-574`). I did **not** restart the local services (user owns
`start-microservices-dev.sh`). To smoke the real endpoints, rebuild + restart the
microservices from this worktree, then re-curl with `X-API-Key`.

---

## How to test (manual)

1. Build & run the branch microservices (api 3000, search 3002) + apply migration
   209 against the dev Postgres. Run `npm run dev` (or serve `dist/`).
2. Generate OTLP data: `log-blaster --otlp --otlp-direct` (writes spans/metrics
   into `otel_spans` / OTLP metrics so the RED + traces + metrics tabs have data).
3. Nav → **Observability** (single rail entry):
   - **Services** — RED overview; click a service → inline Service detail (RED
     panels, endpoints, exemplar scatter; SLO strip appears once an SLO exists
     for that service). Click an exemplar → `/trace/:id`.
   - **Traces** — filter (service / min-duration / errors-only) → scatter → click
     a point → inline waterfall + span drawer.
   - **Metrics** — pick a metric from the catalog, add panels, set step/service.
   - **Alerts** — monitors view over existing alerts (needs alerts present).
   - **SLOs** — New SLO dialog (availability or latency+threshold); cards show
     current / budget-left / burn-rate; edit + delete.

---

## Known gaps / deferred (be honest)

- **Routing fix is unverified at runtime.** `getServiceUrl` repair is correct by
  inspection and type-checks, but was not exercised against a two-origin
  deployment this pass (local dev is single-origin, so it can't surface the bug
  either way). Verify in a deploy where `VITE_SEARCH_URL` ≠ `VITE_API_URL`.
- **Deferred tabs not built:** Infra, RUM, Synthetics, Profiling (design had
  these; out of NAN-1536 scope — only Services/Traces/Metrics/Alerts/SLOs ship).
- **Deploy markers:** `REDChart` supports `markers` but no deploy-marker data
  source is wired — `ServiceDetail` passes empty markers. Not implemented.
- **On-call / owner / team / runbook / dependency-topology map:** present in the
  design mock, dropped by the Services surface agent (no wire backing). Not faked.
- **Metrics group-by/aggregation:** dropped — backend endpoint buckets a single
  metric by step only.
- **SLO attainment is on-read** (no background recompute job, by design) — every
  list/get recomputes `current`/`budget`/`burn` over `now - window_days .. now`.
  At high SLO counts × long windows this is N span-aggregation queries per list
  call; revisit if it gets slow.
- **Alerts surface** maps detection alerts → a "monitors" UI client-side; it is
  not a native monitor model.
- **SLO compute on no-data:** `total=0 → current=1.0` (treated as fully met).
  Confirm that's the desired semantics vs. surfacing "no data".

---

## Not done (per task constraints)

- No `git commit`. No `cargo fmt`. No local service restart.
- `SloRepository` uses runtime `sqlx::query`, so no `cargo sqlx prepare` needed.
