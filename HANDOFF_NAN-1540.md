# NAN-1540 — Metrics v2 — Verification + Repair Handoff

Worktree: `/Users/dan/Documents/git/nanosiem-worktrees/feat/NAN-1540-metrics-v2`
Branch: `feat/NAN-1540-metrics-v2`
Date: 2026-06-24

## TL;DR — compile state (brutally honest)

| Slice | State |
|---|---|
| **Rust** (core / search / api / api-lib / enterprise) | **PASS** — `cargo check` clean, warnings only |
| **OpenAPI tests** (open + enterprise) | **PASS** — 3/3 each edition |
| **Core otel unit tests** | **PASS** — 22/22 |
| **Web** (`tsc -b && vite build`) | **PASS** — exit 0 |
| **Backend chain** (SQL builders → SearchService glue → repo → CRUD handlers → jobs evaluator → alert path) | **COMPLETE & coherent** |
| **Dashboard `obs_metric` widget** | **COMPLETE & coherent** — wired end-to-end into DashboardView + DashboardEditor |
| **Metrics-builder UI slice** (query builder w/ agg/group-by/filter + viz switcher + Add-to-dashboard + Create-monitor) | **DID NOT LAND** — see "Honest gap" below |

There were **no compile errors to repair** and **no stubs written**. TODO count: **0** (`todo!()`/`unimplemented!()`/`// TODO(NAN-1540)` — none present). The landed code from the three completed slices is real and compiles as-is. The only repair the task anticipated (series[] contract drift, OpenAPI floors, migration registering, jobs wiring) was already correct in the landed slices; I verified each rather than fixing.

> Note: the prompt listed a crate `nanosiem-jobs`. **No such crate exists** — `members` in `Cargo.toml` are core/enterprise/api/api-lib/search (+ tools). The "jobs" runner is the **`nanosiem-api` bin target `src/bin/jobs.rs`**, covered by `-p nanosiem-api`. The actual check run was:
> `cargo check -p nanosiem-core -p nanosiem-search -p nanosiem-api -p nanosiem-api-lib -p nanosiem-enterprise` → exit 0.

### Exact build results (verbatim)

Rust (`cargo check`, all crates incl. `--features enterprise`): clean except two cosmetic warnings:
- `nanosiem-api/src/state/schedulers.rs:452` — `variable does not need to be mutable` (`let mut interval`). Harmless; not fixed (no-commit task, and "don't reformat" rule).
- one `dead_code` warning in `nanosiem-core` (pre-existing pattern).

OpenAPI:
```
=== OPEN edition ===
test openapi::tests::verify_openapi_spec_generates ... ok
test openapi::tests::verify_openapi_path_count ... ok
test result: ok. 3 passed; 0 failed
=== ENTERPRISE edition ===
test result: ok. 3 passed; 0 failed
```

Core otel: `running 22 tests ... test result: ok. 22 passed; 0 failed`

Web: `✓ built in ~520ms`, exit 0 (only the pre-existing >500kB chunk-size advisory).

---

## What shipped (and is verified coherent)

### 1. Query layer — `nanosiem-core/src/query/clickhouse_sql_gen/otel.rs`
`MetricAgg {Avg,Sum,Min,Max,Count,Rate,P50,P95,P99}`, `valid_tag_key`, `MetricTagFilter`, `MetricQuery<'a>`, and SQL builders `metric_timeseries_v2_sql` / `metric_scalar_sql` / `metric_tag_keys_sql` / `metric_tag_values_sql`. v1 `metric_timeseries_sql` untouched (back-compat). All escape strings, single time-bound WHERE (no PREWHERE), bounded LIMITs. Re-exported via `query/mod.rs`.

### 2. SearchService glue — `nanosiem-core/src/search/service/otel.rs`
`query_otel_metric_timeseries_v2`, `list_otel_metric_tag_keys`, `list_otel_metric_tag_values`, `evaluate_metric_monitor`. v1 `query_otel_metric_timeseries` still present.

### 3. Monitor repo — `nanosiem-core/src/observability/metric_monitor_repository.rs`
`MonitorComparator`, `MonitorTagFilter`, `MetricMonitor` (id → typeid `mon_…`), `MetricMonitorRepository` (list/list_enabled/get/create/update/delete). `typeid_prefix!(metric_monitor,"mon")`.

### 4. Search service HTTP — `nanosiem-search/src/handlers/otel.rs` + `lib.rs`
- `POST /api/search/metrics/timeseries` — response shape **CHANGED to series[]** (see contract below).
- `GET /api/search/metrics/tags?metric_name=&key=&start=&end=&window_hours=` — new.

### 5. Monitor CRUD — `nanosiem-api/src/handlers/observability_metric_monitors.rs` + `routes.rs`
- `GET /api/observability/metric-monitors` (read = `search:view`)
- `POST /api/observability/metric-monitors` → 201 (mutations = `settings:system`)
- `PUT /api/observability/metric-monitors/{id}`
- `DELETE /api/observability/metric-monitors/{id}`
- Validation: agg allowlist (400 on unknown), group_by + filter keys `valid_tag_key`, threshold finite, `window_secs` 1..=86400, `eval_interval_secs` 30..=3600.

### 6. Jobs evaluator — `nanosiem-api/src/state/schedulers.rs` + `lifecycle.rs`
`start_metric_monitor_scheduler` registered **leader-only** at `lifecycle.rs:351`. Ticks every 30s, loads `list_enabled()`, applies an in-memory per-monitor `eval_interval_secs` due-gate, runs each monitor inside `AssertUnwindSafe(...).catch_unwind()` (panic-isolated per NAN-1102). On breach it raises via the **existing alert store** — a direct `INSERT INTO alerts (rule_id, severity, matched_events) VALUES (NULL, 'high', $1)`. **Verified against the schema** (`001_init_postgres.sql:348`): `rule_id` nullable, `severity='high'` satisfies the CHECK, `id`/`status`/`created_at` default — INSERT is valid at runtime.

### 7. Migration 211 — `migrations/postgres/211_observability_metric_monitors.sql`
Sits **above the highest existing** (was 209). Gaps at 204–207/210 are **pre-existing** (210 never existed; the task's "210 untouched" refers to a file that isn't there — nothing to disturb). 142/143 untouched (verified `git diff --name-only HEAD migrations/postgres/` is empty). Auto-registered: migrations load via `sqlx::migrate!("../migrations/postgres")` (directory-embedded — no manual list to edit). CHECK constraints mirror the API validation ranges. **No CH migration** — reuses `nanosiem.otel_metrics` (CH 144 was not needed).

### 8. Web client + dashboard widget (COMPLETE)
- `types.ts`: `MetricAgg`, `MetricFilter`, `MetricSeriesPoint`, `MetricSeries`, `MetricTimeseriesV2Request/Response`, `MetricTagsResponse`, `MetricMonitor`, `MetricMonitorRequest`, `MetricMonitorComparator`, `MetricMonitorListResponse`; `VisualizationType` gains `'obs_metric'`; `MetricWidgetConfig` + `MetricWidgetViz` + `PanelConfig.metricConfig?`. Legacy `MetricsQueryRequest/Response` kept intact.
- `search.ts`: `queryMetricsV2`, `listMetricTags`.
- `observability.ts`: facade delegates `queryMetricsV2`/`listMetricTags` to SearchApi (wired in `index.ts:162-163`), plus `listMetricMonitors`/`createMetricMonitor`/`updateMetricMonitor`/`deleteMetricMonitor`.
- `components/dashboard/ObsMetricWidget.tsx`: renders `timeseries` (REDChart) / `toplist` / `query_value`; exports `metricSeriesToRows` / `rowsToMetricSeries`.
- `components/dashboard/metric-widget.ts`: `addMetricToDashboard(args)` + `buildMetricPanelConfig`.
- `DashboardView.tsx` + `DashboardEditor.tsx`: `fetchPanelData` branches to `queryMetricsV2` for `obs_metric` panels, stashes `series[]` as rows; `renderPanel` branches to `ObsMetricWidget`. `Panel.tsx` icon case added.

---

## The pinned `series[]` timeseries contract (reconciled across all 4 layers)

**Request** `POST /api/search/metrics/timeseries`:
```jsonc
{ "metric_name": "...", "time_range": {"start","end"}, "service_name"?: "...",
  "step_secs"?: 60, "agg"?: "avg|sum|min|max|count|rate|p50|p95|p99",
  "group_by"?: "<tag key>", "filters"?: [{"key","value"}] }
```
**Response** (shape CHANGED — was `{metric_name, points, step_secs}`):
```jsonc
{ "metric_name": "...", "agg": "avg", "group_by"?: "...",
  "series": [ { "key": "<group value or \"\">", "points": [ {"t":"<rfc3339>","v":<f64>} ] } ],
  "step_secs": 60 }
```
Back-compat: omit `agg`/`group_by`/`filters` → one `avg` series with `key:""`.

Verified field-for-field: `nanosiem-search/.../otel.rs MetricTimeseriesRequest/Response` ↔ web `MetricTimeseriesV2Request/Response` (`types.ts`) ↔ `search.ts queryMetricsV2` (posts request verbatim) ↔ `DashboardView/Editor` (`metricSeriesToRows(resp.series)` → rows) ↔ `ObsMetricWidget` (`rowsToMetricSeries(data)`). **No drift.**

Tags: `GET /api/search/metrics/tags?metric_name=` → `{tag_keys:[…]}`; add `&key=` → `{tag_values:[…]}`.

Monitors CRUD payload (`MetricMonitorRequest`) and row (`MetricMonitor`, id as `mon_…`) match the Rust `MetricMonitorRepository`/handler. `addMetricToDashboard` signature matches the fe-dash-widget helper. **All verified.**

---

## HONEST GAP — the metrics-builder UI slice did not land

The metrics-builder subagent returned `[object Promise]` (a failed/aborted result). Consequences:

- **`MetricsTab.tsx` is unchanged from HEAD** — it is still the **v1 explorer** (NAN-1536): metric-name picker + service filter + step toggle, single `avg` series per panel via the **legacy** `api.observability.queryMetrics` (`MetricsQueryResponse`, the `points[]` shape). It does **not** expose agg, group-by, tag filters, a viz switcher, an Add-to-dashboard button, or a Create-monitor form.
- Therefore these landed-and-compiling helpers are currently **orphaned (zero UI callers):**
  - `api.observability.queryMetricsV2` (consumed ONLY by the dashboard widget, not the tab)
  - `api.observability.listMetricTags`
  - `api.observability.listMetricMonitors / createMetricMonitor / updateMetricMonitor / deleteMetricMonitor`
  - `addMetricToDashboard` / `buildMetricPanelConfig`
- TS does not error on unused exports, so **the build stays green** — but the user-facing "Metrics tab is a query builder + viz switcher + add-to-dashboard + create-monitor" half of NAN-1540 is **not delivered**.

I deliberately did **not** fabricate the query-builder UI: it is a large, design-sensitive feature (the metrics-builder slice's actual job), not a compile fix, and the no-commit/repair scope says stub only "if stuck." The codebase is coherent in that nothing is half-wired or broken; the missing piece is a whole front-end surface.

**To finish NAN-1540, the remaining work is exactly the metrics-builder slice:** rebuild `MetricsTab.tsx` (or add a new builder surface) to:
1. drive `api.observability.queryMetricsV2` (agg dropdown, group-by from `listMetricTags(metric)`, filter rows from `listMetricTags(metric, key)`),
2. render the `series[]` via a viz switcher (timeseries/toplist/query_value — reuse `ObsMetricWidget` or its chart pieces),
3. wire an "Add to dashboard" action to `addMetricToDashboard(...)` then navigate to `/dashboards/<id>`,
4. wire a "Create monitor" action to `api.observability.createMetricMonitor(MetricMonitorRequest)`,
5. (optional) a monitors list view backed by `listMetricMonitors` + update/delete.

---

## How to test end-to-end (after the builder UI exists)

Services are likely **stale binaries** — the user owns restarts (`./start-microservices-dev.sh`; never kill :3000/:3002 manually). New routes are confirmed present in source (`routes.rs`, `lib.rs`).

1. **Restart** api (:3000) + search (:3002) + jobs to pick up the new routes + migration 211 (PG migrate runs on api boot).
2. **Blast metrics** so `nanosiem.otel_metrics` has rows (OTLP export, or the existing metrics blaster).
3. **Grouped query** (curl, before UI lands):
   ```
   POST :3002/api/search/metrics/timeseries
   {"metric_name":"<m>","time_range":{"start":"<iso>","end":"<iso>"},
    "agg":"p95","group_by":"<tag>","step_secs":60}
   ```
   Expect `series:[{key,points:[{t,v}]}]` with one series per tag value.
4. **Tags:** `GET :3002/api/search/metrics/tags?metric_name=<m>` then `…&key=<tag>`.
5. **Switch viz** (UI): timeseries ↔ toplist ↔ query_value over the same `series[]`.
6. **Add to dashboard** (UI): creates an `obs_metric` panel; open the dashboard and confirm `ObsMetricWidget` fetches via `queryMetricsV2` and renders.
7. **Create a monitor with a low threshold and watch it fire:**
   ```
   POST :3000/api/observability/metric-monitors  (needs settings:system)
   {"name":"smoke","metric_name":"<m>","agg":"avg","filters":[],
    "comparator":"gt","threshold":0,"window_secs":300,"eval_interval_secs":30,"enabled":true}
   ```
   The leader jobs evaluator ticks ≤30s, evaluates, and on breach `INSERT`s a `severity='high'` row into `alerts` with the breach payload in `matched_events` (`rule_id=NULL`). Confirm via the alerts surface or `SELECT * FROM alerts WHERE rule_id IS NULL ORDER BY created_at DESC`.

---

## Coherence checklist (verified)

- [x] series[] response shape identical across server ↔ types.ts ↔ search.ts ↔ DashboardView/Editor ↔ ObsMetricWidget
- [x] obs_metric widget renders on a dashboard (fetch + render branches wired; build green)
- [x] monitor persists (repo + migration 211 + CRUD handlers + routes)
- [x] jobs evaluator registered (leader-only, panic-isolated) and raises via existing `alerts` INSERT (schema-verified)
- [x] migration 211 above highest; 142/143 untouched; auto-registered via sqlx dir-embed
- [x] OpenAPI floors bumped (487 ent / 378 open) and tests pass both editions
- [ ] **Metrics tab as a query builder + viz switcher + add-to-dashboard + create-monitor — NOT done (metrics-builder slice never landed)**
