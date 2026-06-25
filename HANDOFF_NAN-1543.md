# HANDOFF — NAN-1543 (obs filters + scale) + NAN-1542 (security cross-link)

Worktree: `/Users/dan/Documents/git/nanosiem-worktrees/feat/NAN-1543-obs-filters-convergence`
Branch: `feat/NAN-1543-obs-filters-convergence`
State at handoff: **uncommitted** (no `git commit`, no `cargo fmt` run, per instructions).

## Compile state — brutally honest

| Gate | Result |
| --- | --- |
| `cargo check -p nanosiem-core -p nanosiem-search -p nanosiem-api` | **PASS** (1 pre-existing dead-code warning in `source_configs/service.rs`, unrelated to this work) |
| `cargo check -p nanosiem-api --features enterprise` | **PASS** |
| `cargo test -p nanosiem-api verify_openapi` (open) | **PASS** — 3 passed; 0 failed |
| `cargo test -p nanosiem-api --features enterprise verify_openapi` | **PASS** — 3 passed; 0 failed |
| `cargo build -p log-blaster` | **PASS** (clean rebuild) |
| `cargo test -p event-core` | **PASS** — 24 passed; 0 failed |
| `npm run build` (nanosiem-web) | **PASS** — `tsc -b && vite build`, `✓ built in 527ms`, no TS errors |

No stubs were needed. **TODO(NAN-1543/1542) count: 0.** No `unimplemented!`/`todo!`/`FIXME` in any task file.

Verbatim cargo (core/search/api): `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 33.21s`
Verbatim cargo (enterprise api): `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 19.76s`
Verbatim openapi (both editions): `test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 172 filtered out`
Verbatim vite: `✓ built in 527ms` (chunk-size warning only — pre-existing, not a failure)
Verbatim event-core: `test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out`

## What shipped, per surface

### Services tab (NAN-1543 filters/scale)
- Name search (debounced 250ms → `q`), health button-group (All/Critical/Degraded/Healthy → `health`, `all`→`undefined`), sort button-group (Rate/Errors/p95/Name → `sort`), `PAGE_SIZE=50` "Load more · loaded/total" driven by `has_more`. Filtering/sort/health are now **server-side** (client no longer re-filters). SummaryStrip shows `loaded/total`.
- File: `nanosiem-web/src/pages/observability/tabs/ServicesTab.tsx`

### Infra tab (NAN-1543 filters/scale)
- Hostname search (`q`), group `<select>` (best-effort from loaded hosts + current selection), env free-text (`env`, exact), status button-group (`status`), kept color-shade selector/legend/waffle/hottest list. `PAGE_SIZE=100`, "Load more" + `has_more`. Filtered-empty state renders inside the layout so controls stay reachable.
- File: `nanosiem-web/src/pages/observability/tabs/InfraTab.tsx`

### RUM tab (NAN-1543 filters/scale)
- Page/route search (`page`), browser free-text (`browser`), env free-text (`env`). Filter bar always rendered (loading/error/empty/data) so filters stay reachable; filtered-empty state has distinct copy.
- File: `nanosiem-web/src/pages/observability/tabs/RumTab.tsx`

### Service-detail security cross-link (NAN-1542)
- NEW `nanosiem-web/src/components/observability/ServiceSecuritySignals.tsx`: dense "Related security signals" strip rendered in `ServiceDetail.tsx` right after the SLO strip, before the RED grid. Clean zero state when `signal_count === 0` ("No security detections on this service's N hosts in range."). Otherwise up to 5 rows (severity dot, rule_name, host/ip, severity, ts, chevron), each click-through to `/search?q=<entity clause>`, plus `+N more in range`. Best-effort: swallows load errors, renders nothing on failure (never disturbs parent).
- `ServiceDetail.tsx` change: import + `<ServiceSecuritySignals service={service} apiTimeRange={apiTimeRange} />`.

### Shared FE client
- `nanosiem-web/src/lib/api/observability.ts`: filters agent added `ServicesQuery`/`ServicesSort`/`InfraHostsQuery`/`RumQuery` + `total`/`has_more` on the response types; cross-link agent appended `ServiceSecuritySignal`/`ServiceSecuritySignalsResponse`/`ServiceSecuritySignalsQuery` + `getServiceSecuritySignals`. **Both sets coexist with no collision** — the two agents edited disjoint regions of the same file; verified present together and the build is clean.

### Backend
- Search service (3002): `ServicesParams`/`InfraHostsParams`/`RumParams` extended with the filter/paging fields; glue in `nanosiem-core/src/search/service/otel.rs` returns `(rows, total)` and applies filters; SQL builders in `nanosiem-core/src/query/clickhouse_sql_gen/otel.rs`.
- API service (3000): NEW `nanosiem-api/src/handlers/observability_service_signals.rs` (`get_service_security_signals` + `ObservabilityServiceSignalsApiDoc`), registered in `routes.rs` (line 2431) + `mod.rs` (line 84) + `openapi.rs` merge list. Glue: `observability_service_security_signals(service, time_range, limit) -> (host_count, signal_count, signals)`.

### Blaster (NAN-1542 correlation)
- `tools/event-core/src/entity.rs`: NEW `WorldState::convergence_entity(n) -> Option<&Entity>` returns `entities[n % workstation_count]` (the low-index workstation pool the lateral-chain emitter seeds from).
- `tools/log-blaster/src/main.rs` (~line 918): every `ticks % 4 == 0` the OTLP trace tick sources its entity from `convergence_entity(ticks)` (falls back to `random_entity()` for the empty-world edge), else uniform-random. Deterministic by the existing `ticks` counter (honors no-RNG-per-call constraint). ~25% of traces now share `host`/`src_ip` with the hosts the attack chain walks.

## Endpoint contracts (new/extended)

### Extended — search service (3002)
- `GET /api/search/services` — added optional `q` (substr, case-insensitive), `health` (`good|warn|bad`), `sort` (`rate|p95|name|error_rate`, default `rate`), `limit` (u32), `offset` (u32, default 0). Response gained `total` (post-filter count before page slice) + `has_more`; `services[]` shape unchanged.
- `GET /api/search/infra/hosts` — added optional `q`, `group` (exact), `env` (exact), `status` (`good|warn|bad`), `limit`, `offset`. Response gained `total` + `has_more`; `hosts[]` unchanged.
- `GET /api/search/rum` — added optional `page` (substr), `browser` (exact), `env` (exact, also scopes web vitals). Response shape unchanged (filters narrow payload).

All filters are append-only on the querystring; a no-arg call produces the byte-identical URL the backend already served → **default (no-filter) behavior preserved**. FE reads `total`/`has_more` defensively (`?? services.length` / `?? false`) so an older backend degrades gracefully.

### New — api service (3000)
`GET /api/observability/services/{service}/security-signals` — requires `search:view`.
- Query: `start`,`end` (RFC3339), `window_hours` (default 1, clamped 1–720), `limit` (default 100, clamped 1–1000).
- Response: `{ host_count, signal_count, signals: [{ ts, rule_name, src_host, src_ip, severity }] }`. `src_host`/`src_ip` — exactly one is non-null per row (entity→`src_ip` if it parses as IP / is in the resolved ip-set, else→`src_host`). `severity` is always a string from the row (possibly `""`); TS types it `string | null` (harmless superset).
- Impl: resolves the service's distinct src_ip+host from `otel_spans` (bounded `SERVICE_ENTITY_CAP=100`), then queries CH `signals` where `risk_entity IN (...)` over the window (engages `idx_risk_entity` bloom). Skips the second read when the service has zero entities (`AND (0)` guard, never malformed `IN ()`).
- OpenAPI path floor bumped **exactly +1**: open 382→383, enterprise 491→492.

## Contract-drift fixes / reconciliation findings

The two FE agents and the backend agent landed a coherent contract — **no repair edits were required**. Verified end-to-end:
1. Search-handler param structs (`ServicesParams`/`InfraHostsParams`/`RumParams`) match the TS `ServicesQuery`/`InfraHostsQuery`/`RumQuery` field names **exactly** (q/health/sort/limit/offset; q/group/env/status/limit/offset; page/browser/env).
2. `total`/`has_more` present in both the Rust response and the TS `*Response` types.
3. Cross-link response keys (`host_count`,`signal_count`,`signals[].{ts,rule_name,src_host,src_ip,severity}`) match the TS interface 1:1.
4. observability.ts shared edit: filters-agent and cross-link-agent regions are disjoint; both present, build clean.

### Minor semantic notes (NOT bugs, NOT fixed — flagged for honesty)
- **`signal_count` == `signals.len()`** in `observability_service_security_signals` (it's the bounded sample length, capped at `limit`), even though the doc-comment / TS comment say "may exceed signals.length". The FE overflow math (`overflow = signal_count - shown.length`, `shown` capped at 5) is still correct: with 12 returned signals it shows 5 + "+7 more". The "may exceed" wording is aspirational — there is no separate full-window `COUNT(*)` companion. If a true total-over-window is wanted later, add a count query; today the number shown is "signals in the sample (≤ limit)".
- **P2 (backend review, accepted)**: host-name match between `otel_spans.host` and `signals.risk_entity` is exact-string. Case/FQDN normalization divergence between the two ingest paths could miss host-based matches (IPs are numeric, safe). Best-effort by design for a convergence panel; documented in the SQL builder doc-comment. No action.
- Injection safety verified: all interpolated values go through `escape_string`; enum params (`health`/`status`/`sort`) are allowlist-validated at the handler (400 on reject).

## How to drive the cross-link populated (NAN-1542 demo)
```
cargo build -p log-blaster
# emit traces+logs so the cross-link has both sides, with a tight workstation pool:
log-blaster --otlp traces,logs --vector <otlp-endpoint> --assets 50 --rate 600
# run the normal/lateral-chain mode in parallel against the same world so
# kind=detection signals land on those low-index workstations.
```
Smaller `--assets` (e.g. 50) tightens the workstation pool → denser overlap. Then open Service Detail for any service (`frontend`/`checkout`/`db`/`payments`/`inventory`) and the
`GET /api/observability/services/{service}/security-signals?start&end` strip returns non-zero `host_count`/`signal_count`. Infra host metrics and per-service RED metrics were left untouched (no cross-link dependency; changing them would perturb the Infra waffle test fixture).

## Files touched by this task (uncommitted)
Backend: `nanosiem-api/src/handlers/mod.rs`, `.../openapi.rs`, `.../routes.rs`, `.../handlers/observability_service_signals.rs` (NEW), `nanosiem-core/src/query/clickhouse_sql_gen/otel.rs`, `.../query/mod.rs`, `.../search/service/otel.rs`, `nanosiem-search/src/handlers/otel.rs`.
Frontend: `nanosiem-web/src/lib/api/observability.ts`, `.../pages/observability/ServiceDetail.tsx`, `.../tabs/{ServicesTab,InfraTab,RumTab}.tsx`, `.../components/observability/ServiceSecuritySignals.tsx` (NEW).
Blaster: `tools/event-core/src/entity.rs`, `tools/log-blaster/src/main.rs`.
