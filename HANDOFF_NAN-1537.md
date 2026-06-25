# HANDOFF — NAN-1537 / NAN-1538 (Observability: Infrastructure + RUM + Synthetics)

Branch: `feat/NAN-1537-obs-infra-rum-synth`
Worktree: `/Users/dan/Documents/git/nanosiem-worktrees/feat/NAN-1537-obs-infra-rum-synth`
Verification date: 2026-06-24. No git commit, no cargo fmt, main checkout untouched.

---

## Compile state (brutally honest)

| Target | Result |
|---|---|
| `cargo check -p nanosiem-core -p nanosiem-search -p nanosiem-api -p nanosiem-enterprise` | **PASS** (one pre-existing, unrelated dead-code warning: `VALIDATE_SAFE_STRINGS_MAX_DEPTH` in `source_configs/service.rs`) |
| `cargo check -p nanosiem-api --bin nanosiem-jobs` | **PASS** |
| `cargo build -p log-blaster` | **PASS** |
| `cargo test -p nanosiem-api verify_openapi` (open edition) | **PASS** (3/3; path-count floor satisfied) |
| `cargo test -p nanosiem-api --features enterprise verify_openapi` | **PASS** (3/3) |
| `cargo test -p nanosiem-core otel` | **PASS** (23/23) |
| `cargo test -p event-core otlp` | **PASS** (6/6) |
| `npm run build` (`tsc -b && vite build`) in `nanosiem-web` | **PASS** (built clean, only the usual >500kB chunk advisory) |

`nanosiem-jobs` is a **bin inside the `nanosiem-api` crate** (`nanosiem-api/Cargo.toml` `[[bin]] name = "nanosiem-jobs"`), not a standalone package — check it with `--bin nanosiem-jobs`, not `-p nanosiem-jobs`.

TODO count: **0**. No `todo!`/`unimplemented!`/`TODO(NAN-1537)`/`TODO(NAN-1538)` stubs were needed — every slice landed working code; nothing was stubbed to make the branch compile.

---

## Contract fix applied during verification (the one real defect)

**Symptom:** the Synthetics PUT endpoint would 422 on the console's pause/resume toggle.

- FE `SyntheticsTab` fires `api.observability.updateSynthetic(c.id, { enabled })` — a body of only `{ "enabled": true }` (PATCH-style; FE `SyntheticCheckUpdate` is all-optional).
- The api `update_synthetic` handler was wired to `CheckRequest`, whose `name` / `target_url` / `interval_secs` are **non-`Option`**, and `validate()` rejects empty `name`. A partial toggle body would have been rejected by serde/validation at runtime (compile-clean, would have silently broken the toggle on first click).

**Fix** (`nanosiem-api/src/handlers/observability_synthetics.rs`):
- Added `UpdateCheckRequest` — all fields `Option`, mirrors the FE `SyntheticCheckUpdate` exactly (`name?`, `target_url?`, `interval_secs?`, `expected_status?`, `timeout_secs?`, `enabled?`).
- `update_synthetic` now `repo.get(id)`s the existing definition, `merge_onto`s the partial body (omitted fields fall back to persisted values), then runs the shared `CheckRequest::validate()`. A `{enabled:false}` body now pauses without blanking the other columns; the full editor body still works unchanged.
- Registered `UpdateCheckRequest` in the handler's `OpenApi` `components(schemas(...))` and switched the PUT `request_body`. openapi tests stay green in both editions (schema add, no new path).

No FE change was required — the frontend types/calls were already correct; the backend was the side rejecting the partial body.

---

## What shipped

### Infrastructure tab (NAN-1537)
- **Endpoint:** `GET /api/search/infra/hosts?start&end&window_hours` (search service, auth `bearer_auth`/`api_key`).
  Response: `{ "hosts": [ { host, group|null, cpu_pct|null, mem_pct|null, load|null, net_bytes_per_sec|null, status:"good|warn|bad" } ] }`.
  Reads `otel_metrics`; latest gauge per `(host, metric_name)` via `argMax`; `group` = `resource_attributes['host.group']` else `service_name`; cpu/mem ×100 (OTLP utilization is 0..1); a gauge a host never emitted is `null` (distinct from a real 0); `status` from CPU/mem thresholds (bad ≥90%, warn ≥75%).
- **FE:** `pages/observability/tabs/InfraTab.tsx` + `components/observability/infra-waffle.tsx` (host waffle grouped by `host.group`, metric selector cpu/mem/load/net, hottest-list rail, "Explore in search" pivot keyed `host.name="…"`). Latest-snapshot only — the wire contract carries no per-host time series.

### RUM tab (NAN-1537/1538)
- **Endpoint:** `GET /api/search/rum?start&end&window_hours` (search service).
  Response (flat, no wrapper key): `{ web_vitals:{lcp_ms|null,inp_ms|null,cls|null}, page_views:int, page_views_series:[{t,v}], js_errors:int, top_pages:[{page,views,lcp_ms|null}], recent_errors:[{message,page,ts}] }`.
  Web vitals are p75 (`quantileTDigestIf`) with `*_n` count companions → `null` when no data points (distinct from true 0); page-views/errors/top-pages/recent-errors read `otel_spans`.
- **FE:** `pages/observability/tabs/RumTab.tsx` + `components/observability/web-vital.tsx` (Core Web Vitals gauges, page-views REDChart series, top-pages table, recent-JS-errors strip). LCP converted ms→s for the gauge; sessions/Apdex/per-page-INP omitted (not in contract, not faked).

### Synthetics subsystem (NAN-1538)
- **Endpoints** (main api service, reads `search:view`, mutations `settings:system`):
  - `GET /api/observability/synthetics` → `{ "checks": [ Check ] }`
  - `POST /api/observability/synthetics` body `{name, target_url, interval_secs, expected_status?, timeout_secs?, enabled?}` → 201 `Check`
  - `PUT /api/observability/synthetics/{id}` (`synth_` typeid or bare UUID) body = **partial** `{name?, target_url?, interval_secs?, expected_status?, timeout_secs?, enabled?}` → 200 `Check`
  - `DELETE /api/observability/synthetics/{id}` → 204
  - `Check` = flattened `SyntheticCheck` (`id` serializes `synth_`, name, check_type, target_url, interval_secs, expected_status, timeout_secs, enabled, created_by, created_at, updated_at) **plus** merged-on-read `uptime_pct:f64`, `p50_latency_ms:f64|null`, `history:[{success,latency_ms,ts}]` (last 90, chronological). Defs in PG; summary/history computed from CH on read; a check with no runs → `0% / null / []`.
- **Validation:** http(s) URL, name 1..=200 chars, interval 30..=3600, expected_status 100..=599, timeout 1..=120; `check_type` pinned to `"http"` (not yet requestable).
- **Runner:** `nanosiem-core/src/observability/synthetic_runner.rs` (`SyntheticRunner`), registered via `AppState::start_synthetics_runner()` in `start_leader_schedulers` (`nanosiem-api/src/state/lifecycle.rs:337`), inside the **egress-gated, leader-only** block (called by `nanosiem-jobs`, `src/bin/jobs.rs:177/184`). 15s tick → `list_enabled()` from PG → per-check `due_for()` (CH max-timestamp vs interval) → `probe_and_record()` (reqwest GET, redirects disabled, per-check timeout cap 120s, `success = status_code == expected_status`; network/timeout failure records `status_code=0, success=0, error=<msg>`). **Failure isolation (NAN-1102):** per-check errors are `warn!`-logged-and-`continue`; a PG list failure skips the tick; the outer loop never `?`-propagates — one bad check can't abort the scheduler. Verified by reading the loop and the `otel`/runner tests.

### log-blaster generators (NAN-1537)
- New `--otlp-signals` value default: `traces,metrics,logs,infra,rum` (so `--otlp` lights up every new tab).
- `infra` (aliases `hosts`/`host`): a fixed 10-host fleet emitting `system.cpu.utilization`, `system.memory.utilization`, `system.cpu.load_average.1m`, `system.network.io` gauges (40 points/tick), resource attrs `host.name`/`host.group`/`service.name`. Rides the existing **metrics** lane → `otel_metrics_raw` (HTTP/Vector) or direct-CH.
- `rum`: 3 web-vital gauges/tick (`web.vitals.lcp/inp/cls`, resource `service.name=web-frontend`) on the metrics lane; plus 1–3 root CLIENT page-view spans/tick (`pageview <path>`, `attributes['page.url']`, ~12% `status.code=2` ERROR with `exception.*`) on the **traces** lane → `otel_spans_raw`.
- Infra/rum are *content kinds* riding the existing metrics/spans lanes/tables; the wire-level `OtlpSignal` enum (`http.rs`) was intentionally left untouched.

### Migrations (above the prior highest — 209 PG / 141 CH)
- `migrations/postgres/210_observability_synthetic_checks.sql` — `observability_synthetic_checks` (UUID pk, `check_type` CHECK in `('http')` default `'http'`, `interval_secs` CHECK 30..=3600, `expected_status` default 200, `timeout_secs` default 10, `enabled` default true, `created_by` → users(id); index on `enabled`).
- `clickhouse/142_synthetic_check_results.sql` — `nanosiem.synthetic_check_results` plain MergeTree (`check_id String`, `timestamp DateTime64(3,'UTC')`, `success UInt8`, `latency_ms Float64`, `status_code UInt16`, `error String`), PARTITION BY toYYYYMMDD, ORDER BY (check_id, timestamp), 30d TTL. Runner writes rows directly (no Null/MV staging).

### Console shell (FE-shell, NAN-1537)
- `pages/observability/ObservabilityConsole.tsx`: 8 tabs in order — Services, Traces, Metrics, **Infrastructure**, **RUM**, **Synthetics**, Alerts, SLOs — each lazy-loaded; the 3 new tabs render their surfaces (`tab === 'infrastructure'|'rum'|'synthetics'` blocks present).
- Client methods on `api.observability` (`lib/api/observability.ts`): `getInfraHosts`, `getRum`, `listSynthetics`, `createSynthetic`, `updateSynthetic`, `deleteSynthetic` — paths/verbs/field-names confirmed against the backend structs (see "Coherence" below).

---

## Coherence verification (the verb/path/field-name drift that bit every prior pass)

- Client paths/verbs ↔ routes: `/api/search/infra/hosts` GET, `/api/search/rum` GET (`nanosiem-search/src/lib.rs:578-579`); `/api/observability/synthetics` GET+POST, `/{id}` PUT+DELETE (`nanosiem-api/src/routes.rs:2407-2412`). **Match.**
- Infra response: backend `InfraHostsResponse { hosts: Vec<Value> }` ↔ FE `InfraHostsResponse { hosts: InfraHost[] }`. Field names (host/group/cpu_pct/mem_pct/load/net_bytes_per_sec/status) pinned by the core SQL builder JSON ↔ FE `InfraHost`. **Match.**
- RUM response: backend `RumSummaryResponse` is `#[serde(flatten)]` of the core RUM object (no wrapper) ↔ FE `RumResponse` flat (web_vitals/page_views/page_views_series/js_errors/top_pages/recent_errors). **Match.**
- Synthetics: backend `ListChecksResponse { checks: Vec<Check> }`, `Check` flattens `SyntheticCheck` + uptime_pct/p50_latency_ms/history ↔ FE `SyntheticChecksResponse { checks: SyntheticCheck[] }` with all fields flat. POST body `CheckRequest` ↔ FE `SyntheticCheckInput`. PUT body **now** `UpdateCheckRequest` (all-optional) ↔ FE `SyntheticCheckUpdate`. **Match (after the fix above).**

---

## How to test locally

Local services are likely **stale binaries** — the user owns restarts (`start-microservices-dev.sh`; never kill :3000/:3002 directly). All the routes above exist in source on this branch but won't be served until the binaries are rebuilt and restarted.

1. **Restart the stack** with the new binaries (user-owned): `start-microservices-dev.sh`. Run the migrations so PG 210 / CH 142 land.
2. **Populate signals:**
   ```
   log-blaster --otlp --otlp-direct --otlp-signals infra,rum --rate 120 --duration 5
   ```
   (or via Vector OTLP receiver: `--otlp --otlp-signals infra,rum --vector http://localhost:4318`). This fills the Infrastructure and RUM tabs (host fleet metrics + web-vitals + page-view/JS-error spans).
3. **Synthetics:** create a check pointing at a reachable URL —
   `POST /api/observability/synthetics` body `{"name":"google","target_url":"https://www.google.com","interval_secs":30,"expected_status":200}` — then watch results accrue in `nanosiem.synthetic_check_results` (runner is leader-only + egress-gated; ensure egress jobs enabled). The console's uptime bar / uptime_pct / p50 fill in as rows land. Toggle enabled off/on to confirm the partial-PUT fix.
4. **Nav:** Observability → Infrastructure / RUM / Synthetics — each new tab should render its surface.

---

## Known gaps

- **Profiling tab is still deferred** — not in this branch (only the 3 new tabs landed; console shows 8 total).
- **Synthetics = HTTP(S) checks only** — `check_type` is pinned to `"http"` server-side and not requestable; no TCP/ICMP/DNS/browser checks. The PG CHECK constraint only allows `'http'`.
- **Infra has no per-host time series** — the contract is latest-snapshot per host; `HostDetail` shows a snapshot + pivots to search rather than a sparkline. Mock's group selector (none/service/zone) collapsed to the single `host.group` grouping.
- **RUM omits** sessions / Apdex / per-page INP+error% / browser-on-error / dedicated error-rate series (not in the wire contract; deliberately not faked).
- **Runner is leader-only + egress-gated** — in a deployment with egress jobs disabled, no probes run and synthetic summaries stay at 0% / null / [].
- **Pre-existing dead-code warning** (`VALIDATE_SAFE_STRINGS_MAX_DEPTH`) is unrelated to this work and was present on main.
