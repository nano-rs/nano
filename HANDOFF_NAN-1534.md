# NAN-1534 — Observability First-Class Surface — HANDOFF

Branch: `feat/NAN-1534-observability-surface`
Worktree: `/Users/dan/Documents/git/nanosiem-worktrees/feat/NAN-1534-observability-surface`
Stage: verification + contract reconciliation (post three build-agent landings). NOT committed.

## Compile state (brutally honest)

- **Rust: PASS.** `cargo check -p nanosiem-core -p nanosiem-search -p nanosiem-api` finished clean (exit 0, 31s). One pre-existing dead-code warning unrelated to this work (`VALIDATE_SAFE_STRINGS_MAX_DEPTH` in `source_configs/service.rs`). No errors, no stubs.
- **Frontend: PASS.** `npm run build` (codegen + `tsc -b` + `vite build`) finished clean (exit 0). `tsc -b` gates `vite build`, so TypeScript is strict-clean including the contract-type changes below. Only the usual >500kB chunk-size advisory (cosmetic).
- **TODO(NAN-1534) stubs: ZERO.** The two TODO comments the frontend agent left (in `search.ts` and `types.ts`, flagged "verify stage reconciles") are now resolved and removed — the contracts were confirmed against the real backend, not stubbed.

## What shipped

1. **Dataset-aware search.** `SearchRequest` gained `dataset: Option<String>` (`nanosiem-core/src/search/types.rs`). The single SQL-gen site in `core_search.rs::search()` builds `Dataset::from_selector(request.dataset)` and applies `.with_dataset(dataset)` only for non-logs datasets (Logs is deliberately NOT applied so the tenant-aware logs/ocsf_logs table from `with_table` is preserved; `with_dataset(Logs)` would clobber it to the literal `"logs"`). `spans` → `otel_spans` (time col `start_time`), `metrics` → `otel_metrics` (time col `timestamp`). Unknown values fall back to logs, never an error. Promoted span/metric columns resolve to direct columns (no `ext.*`).
2. **Nav pillar.** `AppLayout.tsx` — an expandable **Observability** accordion group after Alerts (mirrors Cases/Detection pattern: nav array, filtered nav, isActive, NavSection union, accordion state, auto-expand, desktop + collapsed-flyout + mobile). Items: Traces → `/observability/traces`, Metrics → `/observability/metrics`, both gated on `search:view`.
3. **Two explorers.**
   - `TracesExplorerPage.tsx` — dense recent-traces table (mono trace id / service, tabular-nums span+error counts, duration, UTC start), filters (service, errors-only, min-duration-ms), time picker, row click → `/trace/:id`.
   - `MetricsExplorerPage.tsx` — metric-name dropdown + service filter + step selector + time range, renders `MetricsChartView` from the bucketed timeseries.
4. **Search dataset toggle.** `Search.tsx` — dense Logs|Traces|Metrics segmented control above the search bar; `dataset` state threaded into the non-streaming `search()` and load-more request paths.

## New endpoint contracts (frontend ↔ backend, reconciled)

All four endpoints are auth-gated (bearer or `X-API-Key`).

### `GET /api/search/traces` — recent-traces list
Query params (all optional): `start`, `end` (RFC3339), `window_hours` (default 24, clamp 1–720), `service`, `errors_only` (bool), `min_duration_ns` (u64), `limit` (u32, clamp ≤1000, default 200).
Response: `{ traces: [...], count }`. Each trace object: `{ trace_id, root_service, root_name, span_count, error_count, duration_ns, start_time }`. Ordered most-recent-first.
Frontend: `api.listTraces()` (search.ts) sends `start/end/service/errors_only/min_duration_ns`; `RecentTrace` type uses **`root_service` / `root_name`** (matches the SQL `argMin(...) AS root_service` / `AS root_name`).

### `GET /api/search/metrics/names` — metric-names dropdown
Query param: `service` (optional). Response: `{ names: [{ metric_name }], count }`.
Frontend: `api.listMetricNames()`; `MetricNamesResponse.names` is **`MetricName[]` (objects), not `string[]`**. `MetricsExplorerPage` flattens via `.map(n => n.metric_name)`.

### `GET /api/search/trace/{trace_id}` — waterfall (NAN-1528, unchanged)
Path param `trace_id`. Response `{ trace_id, spans[], span_count }`. Frontend `api.getTrace()` (GET, no body — backend resolves the window internally).

### `POST /api/search/metrics/timeseries` — metric series (NAN-1528, reconciled)
Request: `{ metric_name, service_name?, time_range, step_secs? }` (default step 60s). Response: `{ metric_name, points: [{ bucket, value }], step_secs }` — `avg(value)` per `toStartOfInterval` bucket. `MetricsChartView` reads `p.bucket ?? p.timestamp` (timestamp kept as a legacy optional alias).

### Dataset-aware `POST /api/search`
`SearchRequest.dataset?: 'logs'|'spans'|'metrics'` ↔ backend `dataset: Option<String>`.

## Contract mismatches FIXED in this stage

The frontend agent coded `RecentTrace` / `MetricNamesResponse` defensively against the *spec*, and the real backend landed with different field names. Fixed:
1. `RecentTrace.service_name`/`root_span_name` → **`root_service`/`root_name`** (`types.ts` + `TracesExplorerPage.tsx` row render).
2. `MetricNamesResponse.names: string[]` → **`MetricName[]` objects** (backend emits `SELECT DISTINCT metric_name` rows, i.e. `{metric_name}`). Added the `MetricName` interface and flattened in `MetricsExplorerPage`.
3. Added optional `count` to `ListTracesResponse` / `MetricNamesResponse` to mirror the backend (non-breaking).
4. Removed the two now-stale `TODO(NAN-1534)` reconciliation comments.

(The HTTP verbs were already correct this time — `listTraces`/`listMetricNames` are GET, matching the backend. This is the class of bug — frontend POST vs backend GET — that bit NAN-1528; verified it does NOT recur here.)

## Smoke test (STEP 4) — could NOT validate the new code at runtime

- Search service IS up on `:3002` (`/health` → 200).
- `GET /api/search/traces` → 401 (auth required); `GET /api/search/metrics/names` → 404.
- **The running :3002 binary is the OLD build (predates this branch)** — the new routes aren't compiled into it, so the 404 is the stale binary, not a routing bug in the branch. The routes ARE registered in `nanosiem-search/src/lib.rs` and assert in the openapi path test (which passed in `cargo check`/tests per the build agents).
- I did NOT restart :3002 (per project rule: user owns local service restarts via `start-microservices-dev.sh`). **To smoke-test for real: rebuild + restart the search service, then `curl -H "X-API-Key: <key>" 'http://localhost:3002/api/search/traces?window_hours=24'` and `.../metrics/names`.** Needs OTLP data in `otel_spans`/`otel_metrics` to return non-empty.

## How to test (manual, once services are rebuilt)

1. Nav: left rail → **Observability** accordion → **Traces** and **Metrics**.
2. Traces explorer (`/observability/traces`): set a time range, filter by `service.name`, toggle errors-only, set min-duration-ms. Click a row → `/trace/:id` waterfall.
3. Metrics explorer (`/observability/metrics`): pick a metric from the dropdown, optional service filter, pick a step (15s–1h) → line chart.
4. Search dataset toggle (`/search`): switch Logs|Traces|Metrics segmented control above the search bar.
   - On the **Traces (spans)** dataset, run e.g.:
     `service_name=checkout status_code=ERROR | stats p95(duration_ns) by span_name`
   - On the **Metrics** dataset, the dataset hint points to the dedicated explorer for charting.

## Known gaps / deferred

- **Streaming search path is logs-only.** `POST /api/search/stream` (SSE) does NOT read `dataset` — the toggle is honored only on the non-streaming `POST /api/search` path. The frontend sends `dataset` on the streaming request too, but the backend ignores it there. If a user has streaming enabled and selects Traces/Metrics, the query runs against logs. Either wire `dataset` through `streaming.rs` or force the non-streaming path when `dataset != logs`.
- **Metric-as-dashboard-panel: not implemented.** Metrics are explorable but cannot be pinned as a dashboard panel. Deferred.
- **No runtime smoke test performed** (stale local binary; see above). Backend correctness is covered by the core query tests (245 + 10 otel, incl. byte-identical-logs assertion) and the openapi path tests, but the live HTTP round-trip for the two new GET endpoints has not been exercised on this branch's binary.
- **Metric timeseries aggregation is fixed to `avg`** (gauge-safe default). Counter/histogram semantics (`rate()` / `histogram_quantile()`) are only reachable via nPL on the metrics dataset, not the explorer chart.

## Files touched (verification stage only)

- `nanosiem-web/src/lib/api/types.ts` — `RecentTrace` (root_service/root_name), `MetricName` + `MetricNamesResponse.names: MetricName[]`, `count` optionals.
- `nanosiem-web/src/pages/TracesExplorerPage.tsx` — `t.root_service`.
- `nanosiem-web/src/pages/MetricsExplorerPage.tsx` — flatten `names` to `n.metric_name`.
- `nanosiem-web/src/lib/api/search.ts` — removed stale TODO, confirmed param names.

(Backend + the bulk of the frontend were landed by the three build agents; see their summaries.)
