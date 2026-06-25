# HANDOFF — NAN-1541: Unified Alert Spine

Verification + repair pass. **Both compile states PASS.** One pre-existing-style
warning in the new code was fixed; no stubs, no `todo!()`, no
`// TODO(NAN-1541)` markers left in code. One feature is intentionally deferred
(SLO burn raise — see below).

---

## Compile state (brutally honest)

| Target | Command | Result |
|---|---|---|
| Rust open edition | `cargo check -p nanosiem-core -p nanosiem-search -p nanosiem-api` | **PASS** — `Finished dev ... in 0.79s`. Only 1 pre-existing warning (`VALIDATE_SAFE_STRINGS_MAX_DEPTH` dead const in `source_configs/service.rs`, unrelated). |
| Rust enterprise | `cargo check -p nanosiem-core -p nanosiem-search -p nanosiem-api --features enterprise` | **PASS** — `Finished dev ... in 20.37s`. (`nanosiem-enterprise` has no own feature flag; it builds via `--features enterprise` on the three crates. Same pre-existing warning, nothing else.) |
| OpenAPI verify | `cargo test -p nanosiem-api --lib openapi` | **PASS** — 3/3 (`verify_openapi_has_security_schemes`, `verify_openapi_spec_generates`, `verify_openapi_path_count`). Path floor **unchanged** — no new route was added; `kinds` is a query param on existing routes. (Note: `cargo test -p nanosiem-api verify_openapi` matches 0 tests — the filter must be the module path `openapi`, the functions are `verify_openapi_*` under `openapi::tests`.) |
| Alert repo unit tests | `cargo test -p nanosiem-core --lib alerts` | **PASS** — 2/2 (`test_compute_event_hash_strips_nano_fields`, `test_compute_event_hash_differs_for_different_events`). |
| Frontend | `npm run build` (`generate-udm-fields` + `tsc -b` + `vite build`) | **PASS** — `✓ built in 541ms`, no TS errors. Only the standard "chunk > 500 kB" advisory. |

### Repair made this pass
- `nanosiem-api/src/state/schedulers.rs:467` — the new metric-monitor evaluator
  had `let mut interval = ...; tokio::pin!(interval);`. The `mut` is redundant
  because `pin!` rebinds, so it produced an `unused_mut` warning **introduced by
  this branch** (the rest of the file uses `let interval`). Changed to
  `let interval`. After the fix, `nanosiem-api` compiles with zero new warnings.

### Environment note
- The worktree had no `node_modules`; it is a **symlink** to the main checkout's
  (`/Users/dan/Documents/git/nanosiem/nanosiem-web/node_modules`). gitignored, no
  main-checkout write, no `npm install` run.
- No `git commit`, no `cargo fmt` (per house rule — repo isn't rustfmt-clean).

---

## What changed

### Schema — migration `212_alert_spine_kind.sql` (NEW)
Sits **above 211** (`211_observability_metric_monitors.sql` is the highest prior;
`ls migrations/postgres | sort | tail` confirms 208→209→210→211→**212**, no
collision). Enterprise dir (`postgres-enterprise/`, 9000xxx range) untouched.

```sql
ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'detection'
        CONSTRAINT alerts_kind_check
        CHECK (kind IN ('detection', 'metric_monitor', 'slo', 'synthetic'));
ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS source_id TEXT;            -- TEXT: holds rule UUID OR monitor typeid
UPDATE public.alerts SET source_id = rule_id::text
    WHERE source_id IS NULL AND rule_id IS NOT NULL;    -- backfill existing detection rows
CREATE INDEX IF NOT EXISTS idx_alerts_kind ON public.alerts (kind);
```
- `kind` defaults to `'detection'` → every existing row + every untouched
  detection insert keeps its historical meaning, **zero backfill of meaning**.
- `rule_id` was **already nullable** (FK `ON DELETE SET NULL`, NAN-1356) — no
  nullability change needed; observability rows leave `rule_id = NULL`.
- Idempotent (`IF NOT EXISTS` / named constraint) — safe to re-run.

### One spine entrypoint — `AlertRepository::create_alert`
`nanosiem-core/src/db/repository/alerts.rs` (exported via
`nanosiem-core/src/db/repository.rs`):
```rust
pub struct AlertInsert<'a> {
    pub kind: &'a str,                       // detection | metric_monitor | slo | synthetic
    pub rule_id: Option<Uuid>,               // Some for detection, None for monitors
    pub source_id: Option<String>,           // rule UUID text OR monitor/check typeid
    pub severity: &'a Severity,
    pub matched_events: &'a serde_json::Value,
    pub event_hash: Option<String>,          // Some => ON CONFLICT(rule_id,event_hash) dedup; None => plain insert
}
pub async fn create_alert(&self, insert: AlertInsert<'_>) -> Result<Alert, AlertRepositoryError>
```
- `create` / `create_without_dedup` are now **thin wrappers** → call
  `create_alert` with `kind="detection"`, `rule_id=Some(id)`,
  `source_id=Some(id.to_string())`. **Detection path is byte-identical**: same
  `compute_event_hash`, same `ON CONFLICT (rule_id, event_hash) WHERE event_hash
  IS NOT NULL DO NOTHING` SQL, same `DuplicateAlert` error. The INSERT just gains
  two columns (`kind`, `source_id`).

### Alert model — `nanosiem-core/src/models/alert.rs`
Added `pub kind: String` (`#[serde(default = default_alert_kind)]` → `"detection"`,
mirrors the migration default) and `pub source_id: Option<String>`.

### Detection call sites — UNCHANGED behavior
`nanosiem-core/src/detection/service/alerts.rs` still calls
`self.alert_repo.create(&new_alert)` (lines ~256, ~447). No signature change at
the call site — the wrapper absorbs `kind`. Enterprise + the null-rule-id
integration test (`nanosiem-core/tests/alerts_null_rule_id_integration.rs`) were
adjusted only where they construct the insert directly.

### Monitor raises (the new producers)
- **metric_monitor** — `nanosiem-api/src/state/schedulers.rs`
  `evaluate_one_metric_monitor`. Replaced the old raw
  `INSERT INTO alerts (rule_id, severity, matched_events) VALUES (NULL,'high',$1)`
  with `create_alert(AlertInsert{ kind:"metric_monitor", rule_id:None,
  source_id:Some(monitor.id), severity:&Severity::High, matched_events:&payload,
  event_hash:None })`. `AlertRepository` built once per monitor (outside the
  per-series loop). No dedup — window cadence is the boundary (matches prior
  behavior). Raise `Err` is logged, never aborts the tick.
- **synthetic** — `nanosiem-core/src/observability/synthetic_runner.rs`.
  `SyntheticRunner` now holds an `AlertRepository` (built from the `pool` it
  already takes). On failure (`success == 0` = observed status ≠ expected, or
  request error / status 0) → `raise_failure_alert` → `create_alert(kind="synthetic",
  rule_id=None, source_id=Some(check.id), severity= High if status==0 else Medium,
  event_hash:None)`. Raise `Err` is logged and **never propagated** (NAN-1102
  blast-radius safety) — can't abort the result-row write or the tick.
- **slo** — **RESERVED ONLY** (see deferred).

### API — `kinds` filter (no new route)
`nanosiem-api/src/handlers/alerts.rs`:
- `parse_kinds(&Option<String>) -> Option<Vec<String>>` — splits the
  comma-separated param; absent OR empty → `None` (= all kinds).
- Added `kinds: Option<String>` to `ListAlertsQuery`, new `AlertCountsQuery`,
  and `VelocityQuery`. Threaded into `DetectionService::list_alerts(.., kinds:
  Option<&[String]>, ..)`, `get_alert_counts(kinds)`, and the velocity SQL.
- Repo binds `($N::text[] IS NULL OR kind = ANY($N))`. Permission unchanged
  (`alerts:view`).

---

## Kinds-filter contract (frontend ↔ backend)

- **Param name:** `kinds` — comma-separated string, e.g. `?kinds=detection` or
  `?kinds=metric_monitor,slo,synthetic`.
- **Omitted / empty = ALL kinds** (default-compatible). Before NAN-1541 every
  alert was a detection, so `kinds=detection` returns exactly the pre-change set.
- **Frontend chain** (all load-bearing):
  - `lib/api/detections.ts` — `listAlerts({kinds?})`, `getAlertCounts(kinds?)`,
    `getAlertVelocity(hours?, kinds?)` set the param (`kinds.join(',')`).
  - `lib/api/index.ts` — the `ApiClient` aggregator wrappers **forward** kinds
    (the hooks call the aggregator, not the sub-client; without this forward the
    param is silently dropped).
  - `hooks/use-api.ts` — `useAlerts`/`useAlertCounts`/`useAlertVelocity` accept
    `kinds` and key the query cache by `kinds?.join(',')` so caches split by kind.
- **Surface scoping:**
  - **Obs Alerts tab** (`pages/observability/tabs/AlertsTab.tsx` → renders
    `components/observability/AlertsMonitors.tsx`): `MONITOR_KINDS =
    ['metric_monitor','slo','synthetic']` passed to **all four** reads
    (`useAlertCounts`, `useAlertVelocity(24,…)`, the filterable `useAlerts`, the
    active-incidents `useAlerts({status:'new',…})`). Detection alerts cannot
    appear here. (AlertsTab itself does no unscoped reads — pure delegation.)
  - **SIEM Alerts page** (`pages/Alerts.tsx`): `listAlerts({kinds:['detection']})`
    + `getAlertCounts(['detection'])`. Only detections.
  - **Other detection/case surfaces scoped to `['detection']`** so nothing leaks
    now the table is shared: `pages/Rules.tsx` (firing counts/velocity),
    `components/dashboard/AlertSummary.tsx`, `components/dashboard/UnassignedAlerts.tsx`,
    `enterprise/.../notebook/NotebookSidebar.tsx`,
    `enterprise/.../playbooks/new/DryResolvePanel.tsx`.
  - **Left intentionally unchanged** (already detection-safe — filter by
    `rule_id`, and monitor alerts have `rule_id = NULL` so they can't match):
    `pages/Matches.tsx`, `enterprise/.../detection/AiTuningPanel.tsx`. Same logic
    protects the API `list_alerts` `rule_id` branch
    (`alerts.rs:214` — when `rule_id` is set, it bypasses the kinds filter but a
    monitor can never match a non-null rule_id).

---

## Safety check (STEP 3) — all PASS

1. **Detection alerts flow exactly as before** — `create`/`create_without_dedup`
   are byte-identical wrappers (`kind="detection"` default, same dedup SQL, same
   hash). Detection call sites unchanged.
2. **SIEM Alerts page shows ONLY detections** — both reads pass `['detection']`.
   No monitor leakage.
3. **Obs Alerts tab shows ONLY monitors** — all four reads pass `MONITOR_KINDS`.
   No detection leakage.
4. **metric_monitor + synthetic set their kind** — verified at the raise sites
   (`kind:"metric_monitor"` / `kind:"synthetic"`, `rule_id:None`, `source_id`
   set, `event_hash:None`).
5. **Migration 212 sits above 211** — confirmed by `sort | tail`.

> Dedup note: monitor rows have `rule_id = NULL`. Postgres treats NULLs as
> distinct in the `(rule_id, event_hash)` unique index, so event-hash dedup does
> not apply to monitor alerts even if a hash were supplied — hence all monitor
> raises use `event_hash: None`.

---

## TODOs / deferred (count: 1 deferred feature; 0 code stubs)

- **SLO burn-rate raise — DEFERRED.** `slo` is in the migration CHECK + the
  `kind` space, but there is **no scheduled SLO burn-rate evaluator** that raises
  an alert. SLO is compute-on-read today (`nanosiem-core/src/observability/
  slo_repository.rs`, `nanosiem-api/src/handlers/observability_slos.rs`). When a
  burn-rate evaluator is added, it should raise via
  `create_alert(AlertInsert{ kind:"slo", rule_id:None, source_id:Some(slo.id),
  … })` — the spine + the `MONITOR_KINDS` frontend scoping already include `slo`,
  so SLO alerts will surface in the Obs Alerts tab with zero further wiring.
- **Optional service-detail cross-link** — skipped per task scope (non-trivial).
- No `todo!()`, `unimplemented!()`, or `// TODO(NAN-1541)` markers exist in the
  changed Rust or TS files.

---

## How to test (manual)

Restart the stack (`start-microservices-dev.sh`; do not hand-kill :3000/:3002),
run migration 212, then:

1. **Metric monitor** — create a metric monitor with a deliberately low threshold
   so it breaches on the next 30s evaluator tick.
   - **Expect:** an alert appears in the **Obs Alerts tab** (kind
     `metric_monitor`, `rule_id` NULL, `source_id` = monitor id) and **NOT** on
     the SIEM Alerts page.
2. **Synthetic check** — create a synthetic check pointing at a URL that returns
   the wrong status (or is unreachable → status 0). Wait one interval (≥30s).
   - **Expect:** an alert in the **Obs Alerts tab** (kind `synthetic`, severity
     High if hard-down / Medium if wrong-status), **NOT** on the SIEM Alerts page.
3. **Real detection** — let a Live/Alerting rule fire (or fire one).
   - **Expect:** the alert lands **only on the SIEM Alerts page** (kind
     `detection`), **not** in the Obs Alerts tab. Counts/velocity on Rules +
     dashboard widgets show the same numbers as before (they're now scoped to
     `['detection']`, which == the historical all-detections set).
4. **Quick DB check:** `SELECT kind, count(*) FROM alerts GROUP BY kind;` — should
   show `detection` for pre-existing + new detections, `metric_monitor` /
   `synthetic` for the monitor raises.
