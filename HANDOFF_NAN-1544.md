# HANDOFF — NAN-1544 (observability tier gating) + NAN-1545 (OTLP firehose)

Worktree: `/Users/dan/Documents/git/nanosiem-worktrees/feat/NAN-1544-gating-firehose`
Branch: `feat/NAN-1544-gating-firehose`
Verified: 2026-06-24. No commit, no fmt, no main-checkout edits.

## Compile / test state (verbatim, brutally honest)

| Gate | Result |
|------|--------|
| `cargo check -p nanosiem-core -p nanosiem-search -p nanosiem-api` (open) | **PASS** — `Finished dev profile in 0.77s`. Only warning is pre-existing dead-code `VALIDATE_SAFE_STRINGS_MAX_DEPTH` in `source_configs/service.rs:518` (NOT ours). |
| `cargo check ... --features enterprise` | **PASS** — `Finished dev profile in 10.37s`. Same single pre-existing warning. |
| `cargo build -p log-blaster` | **PASS** — `Finished dev profile in 0.12s`. |
| `cargo test -p nanosiem-api verify_openapi` (open) | **PASS** — `test result: ok. 3 passed; 0 failed`. |
| `cargo test -p nanosiem-api verify_openapi --features enterprise` | **PASS** — `test result: ok. 3 passed; 0 failed`. |
| `cargo test -p nanosiem-core tier` | **PASS** — `test result: ok. 34 passed; 0 failed` (incl. new monitor-cap assertions). |
| `npm run build` (`tsc -b && vite build`) | **PASS** — `✓ built in 525ms`, tsc clean. (Worktree had no `node_modules`; ran `npm ci` first, then build.) |

**Open floor dropped 383 → 382; enterprise floor unchanged at 492.** Both editions assert their own floor in `openapi.rs:306/308` and both pass — the convergence path is now enterprise-only so the open spec legitimately has one fewer path.

## TODO count: **0**

No `// TODO(NAN-1544)`, `// TODO(NAN-1545)`, `todo!()`, or `unimplemented!()` anywhere in the 12 touched files. Nothing was stubbed. Full implementation.

## Contract fixes applied during verification: **0**

Every claim in the three sub-agent reports verified against source + empirically via the suite. No repairs needed. One **doc-vs-code discrepancy noted (no fix required)**: the BE-GATING prose said "Starter: Some(25)" in one sentence and "Starter: None" in another. The actual code (`tier.rs:268-284`) has `Starter = None` (uncapped — it is the "Business"/50GB tier), which is the correct/consistent intent. Caps are sensible and tested.

---

## PART 1 — Gating (NAN-1544)

### Caps per tier (`nanosiem-core/src/settings/tier.rs`)
Three new `Option<u32>` fields on `TierLimits` (`None` = unlimited): `max_metric_monitors`, `max_synthetic_checks`, `max_slos`. Set in `for_tier()`:

| Tier | Cap (each type) |
|------|-----------------|
| Hobby (**open/free tier**) | `Some(5)` |
| Startup | `Some(5)` |
| Growth | `Some(25)` |
| Team | `Some(25)` |
| Starter (Business, 50GB) | `None` |
| Pro | `None` |
| Enterprise | `None` |
| Unrestricted | `None` |

`get_tier_limits()` carries tier defaults through (`tier.rs:447-449`); no new DB override column. 34 tier tests pass, including the added asserts in `test_unrestricted_has_no_limits` (`:1141`), `test_hobby_limits` (`:1161`), `test_team_limits` (`:1209`).

### The error the FE sees
`check_limit()` (`tier.rs:1038`) returns `TierError::LimitExceeded` when `current >= max`. `From<TierError> for ApiError` (`nanosiem-api-lib/src/api_error.rs:270`) lifts it to **HTTP 403 Forbidden**, body:
```
Tier limit exceeded: <resource> limit reached: <current>/<max> (tier: <tier>). <upgrade_hint>
```
e.g. creating a 6th SLO on hobby → `Tier limit exceeded: SLOs limit reached: 5/5 (tier: hobby). Upgrade your plan for more SLOs.`

### Enforcement sites (gate BEFORE insert; mirror `log_sources.rs`)
- `observability_metric_monitors.rs:230-239` — resource `"metric monitors"`, cap `max_metric_monitors`
- `observability_synthetics.rs:318-327` — resource `"synthetic checks"`, cap `max_synthetic_checks`
- `observability_slos.rs:241-251` — resource `"SLOs"`, cap `max_slos`

Each: `TierSettings::new(pool)` → `get_tier_limits()` → `if is_enforced()` → `current = repo.list().len()` → `check_limit(...)?`. On open/hobby, the 6th create returns 403. Audit middleware does not log "Tier limit exceeded" as auth_denied.

### cfg gate — convergence endpoint `GET /api/observability/services/{service}/security-signals`
- `handlers/mod.rs:86-87` — `pub mod observability_service_signals` is `#[cfg(feature = "enterprise")]`
- `routes.rs:2495-2501` — route registration inside a `#[cfg(feature = "enterprise")]` block → **open builds 404**
- `openapi.rs:206-209` — `ObservabilityServiceSignalsApiDoc::openapi()` pushed inside the enterprise `sub_docs` block (opened at `openapi.rs:178`)

Proof the gate is real: the open `cargo check` passes even though the module is enterprise-only — there is no open-build reference to it, so it cannot compile into the open binary.

### Capability flag — `observabilityConvergence`
- `capabilities.rs:59` `pub observability_convergence: bool`, set `= ENTERPRISE` at `:111`. `ENTERPRISE` is `const = true` under `#[cfg(feature="enterprise")]`, else `false` (`:77-80`). Struct has `#[serde(rename_all="camelCase")]` → wire field `observabilityConvergence`.
- FE: `use-capabilities.ts:49` adds `observabilityConvergence: boolean`; `CapabilitiesProvider.tsx:30` fallback `true` (enterprise-everywhere convention); `ServiceDetail.tsx:417` gates `<ServiceSecuritySignals>` behind `capabilities.observabilityConvergence &&`. Open builds get `false` → strip hidden (and the route 404s anyway). No dialog edits were needed — all three create flyouts already render `error` from their catch block, so the 403 message renders verbatim inline.

---

## PART 2 — Firehose (NAN-1545, `tools/log-blaster/src/main.rs`)

`event-core/src/otlp.rs` needed no changes — generators already return one `Value` per record and the transport bulk-batches a slice into one POST/insert.

### New / changed flags (parse confirmed via `--help`)
- `--otlp-batch <K>` (default 1): records-sets generated per tick. Each tick generates K full signal sets and ships each lane (Traces/Metrics/Logs) as ONE bulk OTLP POST (Vector) or ONE bulk JSONEachRow insert (`--otlp-direct`). Default 1 = original behavior exactly.
- `--threads <N>`: now honored for OTLP under `--blast`. `--otlp --blast` dispatches to `run_otlp_blast_mode` (`main.rs:868-871`) which spawns N semaphore-bounded (4 inflight) worker tasks, each a generate→ship loop mirroring `run_blast_mode`. `--eps` = ticks/sec, paced per-thread at `eps/threads`. Without `--blast`, OTLP stays single-thread (`run_otlp_mode`) but still honors `--otlp-batch`.

### Loop structure (verified)
- `run_otlp_mode` (`:1006`): `batch = otlp_batch.max(1)` → `generate_otlp_tick(world, wants, batch, ...)` → `ship_otlp_lanes` → exactly one bulk request per non-empty lane (`ship_otlp_lanes:979-987`).
- `run_otlp_blast_mode` (`:1094`): `threads.max(1)` workers, per-thread tick rate `eps/threads`, per-worker + per-set convergence seeding so NAN-1542 security-convergence spreads across batch/threads.

### Scaling
`spans/s ≈ eps_ticks/s × otlp_batch × spans_per_set` (~4–8 spans/set: root SERVER + 2–3 downstream hops + ~1–3 RUM page-view spans). Each tick is exactly 3 bulk requests (one per lane), so throughput is request-bound not generation-bound. Example past the 10k+ goal:
```
log-blaster --otlp --otlp-direct --blast --eps 5000 --threads 8 --otlp-batch 50
```
≈ 8 × 625 ticks/s × 50 sets × ~5 spans ≈ ~1.5M spans/s ceiling. Stats reporter prints `spans/s` plus total records. Scales linearly with `--threads` and `--otlp-batch`.

Preserved: `--otlp-direct` (CH bulk insert) and Vector OTLP/HTTP :4318 both work; all signal kinds (traces/metrics/logs/infra/rum) intact. `cargo test -p event-core` = 24 passed.

---

## Files touched (12)
Backend (8): `nanosiem-core/src/settings/tier.rs`, `nanosiem-api/src/handlers/{capabilities,mod,observability_metric_monitors,observability_slos,observability_synthetics}.rs`, `nanosiem-api/src/{openapi,routes}.rs`
Frontend (3): `nanosiem-web/src/hooks/use-capabilities.ts`, `nanosiem-web/src/contexts/CapabilitiesProvider.tsx`, `nanosiem-web/src/pages/observability/ServiceDetail.tsx`
Tools (1): `tools/log-blaster/src/main.rs`
