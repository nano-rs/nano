# NAN-1539 — Scale-harden the observability console

Branch: `feat/NAN-1539-obs-scale-hardening`. **Not committed** (per instructions).

## TL;DR

- Service-RED aggregates (overview / sparkline / per-service RED timeseries) no
  longer GROUP BY raw `otel_spans` on every console load — they read a new
  per-service-per-minute rollup `nanosiem.otel_service_red_1m`
  (AggregatingMergeTree + MV, migration **143**).
- The recent-traces list gained a **`before` keyset pagination cursor**; the
  Traces tab now has **load-more** pagination (not virtualized — see below).
- Latency scatter is client-capped to a bounded sample (errored-first).
- Compile state: **Rust PASS** (`cargo check` for core/search/api clean,
  `cargo test` otel SQL gen 16/16, search `verify_openapi` 3/3). **Web PASS**
  (`tsc -b && vite build` clean).

## Compile / test results (verbatim)

```
cargo check -p nanosiem-core -p nanosiem-search -p nanosiem-api
  Finished `dev` profile ... (only a PRE-EXISTING dead_code warning in
  source_configs/service.rs — unrelated to this change)

cargo test -p nanosiem-core --lib query::clickhouse_sql_gen::otel
  test result: ok. 16 passed; 0 failed

cargo test -p nanosiem-search verify_openapi
  test result: ok. 3 passed; 0 failed

nanosiem-web: npm install && npm run build
  > tsc -b && vite build
  ✓ built in ~0.5s   (pre-existing >500kB chunk-size warning only)
```

## Files changed

### ClickHouse
- **`clickhouse/143_otel_service_red_rollup.sql`** (NEW) — the rollup.

### Rust — `nanosiem-core/src/query/clickhouse_sql_gen/otel.rs`
- `services_overview_sql`, `services_sparkline_sql`, `service_red_timeseries_sql`
  repointed from `nanosiem.otel_spans` → `nanosiem.otel_service_red_1m`.
- `TraceListFilters` gained `before: Option<DateTime<Utc>>`; `recent_traces_sql`
  emits `AND otel_spans.start_time < '<before>'` when set.
- Tests updated for the rollup column shape + a new cursor assertion.

### Rust — `nanosiem-search/src/handlers/otel.rs`
- `ListTracesParams` gained `before: Option<DateTime<Utc>>`, threaded into
  `TraceListFilters`. (New query param only — no new OpenAPI path.)

### Web
- `nanosiem-web/src/lib/api/types.ts` — `ListTracesRequest` gained `limit?` +
  `before?` (RFC3339 string).
- `nanosiem-web/src/lib/api/search.ts` — `listTraces` sends `limit` / `before`.
- `nanosiem-web/src/pages/observability/tabs/TracesTab.tsx` —
  `useQuery` → `useInfiniteQuery` keyset pagination + load-more button; scatter
  capped to `SCATTER_CAP = 1500`.

## Rollup schema + backfill note

`nanosiem.otel_service_red_1m` (AggregatingMergeTree):

| column          | type                                                      |
|-----------------|-----------------------------------------------------------|
| `service_name`  | `LowCardinality(String)`                                  |
| `minute`        | `DateTime('UTC')` (`toStartOfMinute(start_time)`)         |
| `request_count` | `SimpleAggregateFunction(sum, UInt64)`                    |
| `error_count`   | `SimpleAggregateFunction(sum, UInt64)`                    |
| `duration_state`| `AggregateFunction(quantilesTDigest(0.5,0.95,0.99), Float64)` over **ms** (`duration_ns/1e6`) |

`PARTITION BY toYYYYMMDD(minute)`, `ORDER BY (service_name, minute)`,
`TTL minute + toIntervalDay(30)`.

MV `otel_service_red_1m_mv TO otel_service_red_1m` folds new `otel_spans` inserts.

**Go-forward vs historical:** the MV only sees spans inserted AFTER it is
created, so the migration includes a **one-time backfill**
`INSERT INTO otel_service_red_1m SELECT … FROM otel_spans GROUP BY service,minute`
to populate existing spans. This is one-shot — the migration runner applies each
numbered file once. Do NOT manually re-execute the backfill against a populated
table; counts are additive (`sum`), so a re-run would double the backfilled
minutes. (Re-running the whole migration file would re-INSERT — only the
`CREATE`s are `IF NOT EXISTS` idempotent; the `INSERT` is not.)

### Read-path gotchas (encoded in the SQL + tests)
1. `request_count`/`error_count` are `SimpleAggregateFunction` → read with plain
   **`sum(col)`**, NOT `sumMerge` (that errors **Code 43** on a
   SimpleAggregateFunction).
2. Latency reads `quantilesTDigestMerge(0.5,0.95,0.99)(duration_state)[i]` —
   the digest stores **ms** already, so NO `/1e6` re-divide (preserves the
   `pXX_ms` contract).
3. `minute` is a second-precision **`DateTime`** (not `DateTime64`), so the three
   rollup SQL builders format the time bound **without** `%.6f` microseconds
   (`%Y-%m-%d %H:%M:%S`). A fractional literal fails to parse into `DateTime`
   (**Code 53**). `metric_timeseries_sql` (reads `otel_metrics`, whose
   `timestamp` IS `DateTime64`) deliberately KEEPS `%.6f`.

### Local-CH validation (`:8123`, nanosiem/nanosiem, ~700 live spans)
Applied the migration objects in the real `nanosiem` db, backfilled, ran the
EXACT repointed SQL, and compared to the raw-spans reference: counts and
p50/p95/p99 matched (small deltas only from a generator inserting concurrently —
e.g. raw p95 frontend `226.263` == rollup p95 `226.263`). The keyset cursor query
also ran clean against raw spans. **Test objects were dropped afterward** — the
local `nanosiem` db is back to its pre-test state so the real migration runner
applies 143 cleanly. The real `otel_spans` was never mutated.

## Pagination contract (FE / other branches MUST know)

`GET /api/search/traces` gained two query params:
- **`limit`** (u32, clamped `[1,1000]` by the SQL builder, default 200) — page size.
- **`before`** (RFC3339 datetime) — keyset cursor. Returns only traces whose
  `start_time` is **strictly before** this instant. The list is
  `ORDER BY start_time DESC`, so the next page is fetched by passing the
  **previous page's last row's `start_time`** as `before`.

Edge: traces sharing the exact boundary `start_time` (sub-second tie) are
dropped at the page boundary — acceptable for a recent-traces explorer; if exact
completeness is ever needed, switch to a composite `(start_time, trace_id)`
keyset. No response-shape change: `{ traces:[…], count }` is unchanged; the FE
derives the next cursor from the last row.

## Table: load-more, NOT virtualized (this pass)

The repo has `@tanstack/react-virtual` (used in `SearchResults.tsx`), but the
Traces table is a flat `grid` of `<button>` rows inside a bordered card, not a
single scroll container with a measured parent ref. Retrofitting the virtualizer
would mean restructuring that card into a fixed-height scroll region + absolute
positioned rows — larger than this pass warranted. **Load-more keyset pagination
was implemented instead** (`useInfiniteQuery` + a "Load more (N shown)" button;
"end of results" when a page returns < page size). This bounds the DOM growth
per interaction and is the higher-leverage scale fix (it bounds the *server*
scan via the cursor, not just the client render).

**TODO(NAN-1539):** if trace volumes make even paged DOM heavy, virtualize the
table body with `useVirtualizer` (mirror `SearchResults.tsx`): wrap rows in a
fixed-height scroll div, `estimateSize` ≈ 30px (row height), keep the
infinite-query pages as the data source.

## Latency scatter sampling (Task 3)

Done cheaply, client-side: `SCATTER_CAP = 1500` in `TracesTab.tsx`. When the
accumulated (paged) trace list exceeds the cap, the scatter plots errored traces
first (the whole point of the scatter is spotting outliers) then fills with the
most recent up to the cap. The table still shows every loaded row. No backend
`SAMPLE BY` was added — the scatter is bounded by the keyset page count anyway,
and a client cap was zero-risk vs. changing the spans read path.

## How to test

1. **Apply migration 143** (CH migration runner, or manually against a dev CH).
   Confirm `otel_service_red_1m` + `_mv` exist and the backfill populated rows:
   `SELECT count() FROM nanosiem.otel_service_red_1m`.
2. **Services tab** (`/observability` → Services): rows should match the prior
   behavior (request rate, error rate, p50/p95/p99, sparkline). Cross-check a
   service against the raw query
   `SELECT service_name, count(), quantileTDigest(0.95)(duration_ns)/1e6 FROM
   nanosiem.otel_spans WHERE start_time BETWEEN … GROUP BY service_name`.
3. **Traces tab**: scroll to the bottom of the table → "Load more (N shown)";
   each click appends the next page. Verify no duplicate trace_ids across pages
   and that it ends with "end of results".
4. **API**: `GET /api/search/traces?limit=50` then
   `GET /api/search/traces?limit=50&before=<last start_time>` returns the next
   page (strictly older traces).
5. `cargo test -p nanosiem-core --lib query::clickhouse_sql_gen::otel` and
   `npm run build` both green.
