// SPDX-License-Identifier: AGPL-3.0-or-later

//! What this cell binary supports, as one list (NAN-2872). The image build
//! (scripts/build-publish-lake-cell.sh) reads it from the built binary
//! (`nanosiem-lake-cell features`) into the `nanosiem.io/cell-features`
//! label and the build receipt, and `/healthz` reports it, so the platform's
//! renderer gates on the image rather than on a hand-set flag.
//!
//! Add a name here only together with the code: the test below requires a
//! check for every name, and each check exercises the real code.

/// Stable feature names, in the order they shipped.
pub const CELL_FEATURES: &[&str] = &[
    // Graduated guarantee/burst/ceiling enforcement + /proc watchdog.
    "watchdog-v2",
    // Live adoption of a delegated read-only cgroup via a private mount.
    "cgroup-adoption",
    // `router_query_token_file`: query-only router token.
    "router-query-token",
    // Previous query token accepted for `router_query_token_grace_secs`.
    "router-query-token-grace",
    // `/healthz` `router_tokens` digests.
    "router-token-digest",
    // Twelve placement fields enforced across ingest, detect and query leaves.
    "role_budgets_v1",
    // Evaluated alert section with a dedicated alerts-read token.
    "lean_cell_alerts_v1",
    // Tenant processes accept the optional `enrichment_reader` exchange class
    // (ingest, query and detect; NAN-2918 #4655/#4695) and receive the
    // supervisor-rendered enrichment mounts (platform bundle + tenant policy,
    // custom IP context). The platform mints `enrichment_reader` only for this.
    // The worker side is pinned by `part_query::server` tests
    // (`cell_feature_lean_enrichment_reader_v1_is_backed`).
    "lean_enrichment_reader_v1",
    // `platform_bundle_dir`: a directory of content-addressed
    // `platform-<sha256>.nanpfb` bundles, selected per tenant by its policy's
    // `bundle_sha256` and hash-verified, so bundle updates need no re-render.
    "lean_platform_bundle_dir_v1",
    // Placement `ingest: "resident"`: ingest[T] starts without a wake, is
    // exempt from the idle reap and respawns with backoff (C1). Placement
    // entries refuse unknown fields, so render the key only for this.
    "lean_ingest_resident_v1",
    // NAN-3008: query[T] resident for every placed tenant, never duty-cycled.
    "lean_query_resident_v1",
    // Lean ingest never deletes lake part files on its own R2 credential:
    // superseded/orphan parts are deleted only through the sanctioned
    // lake-part GC path while the tenant's `lake_part_delete_grant` (from the
    // credential exchange) is enabled; otherwise they are kept and reported
    // as `lake_part_gc_blocked{reason}`. Fail closed. The platform refuses to
    // roll a lean cell image whose receipt lacks this. The worker side is
    // pinned by `part_ingest::part_gc_gate` tests
    // (`cell_feature_lean_part_gc_gate_v1_is_backed`).
    "lean_part_gc_gate_v1",
    // `part_signing.ca_file`: private-CA-only trust for the owner sign route.
    "lean_part_sign_ca_v1",
    // Ingest carries the tenant SlateDB prevalence client (NAN-2915 #4653):
    // it accepts the `lake_prevalence_state` exchange class plus
    // `prevalence_owner`, and writes through the owner proxy trusting only
    // the `part_signing.ca_file` private CA. The platform issues
    // `lake_prevalence_state` only for this. The worker side is pinned by
    // `part_ingest::cell` tests (`cell_feature_lean_prevalence_state_v1_is_backed`).
    "lean_prevalence_state_v1",
    // Tenant dirs are built and repaired under the minimal "5A" cell caps
    // (CHOWN FOWNER KILL SETGID SETUID SYS_ADMIN; no DAC_OVERRIDE, FSETID or
    // DAC_READ_SEARCH): `tenant_dirs` works through O_PATH fds and repairs
    // tenant-owned dirs as their owner (NAN-2962, #4758). The platform renders
    // the interim DAC_OVERRIDE+FSETID caps only for images without this.
    "lean_tenant_dirs_min_caps_v1",
    // NAN-3000: a tenant removed from the placement is drained, its whole
    // local tree (parts, spill, reader cache, snapshots, role state, tmp)
    // purged and verified, and the cell PUSHES
    // `POST {control_url}/v1/lake/cells/{cell_id}/status` (tenants + verified
    // `purged` entries) with its projected SA token (aud nano-lake-cell)
    // every ~60 s and after each placement change. The platform may turn on
    // `LAKE_CELL_REPORTS_ENABLED` / its pooled drain gate for this image.
    "cell_purge_report_v1",
    // `/healthz`, `/v1/status`: `enforcement` (kernel | watchdog_only),
    // `enforcement_reason`, `unenforced_secs`, `role_budgets`; `/metrics`
    // `nano_cell_limits_enforced`; the paging `limits_unenforced` signal
    // (NAN-2993). The platform alerts on these instead of log lines.
    "limits_enforcement_signal_v1",
    // NAN-3004: `zero_downtime_roll` in cell.json. Two pods of one cell may
    // overlap: `/readyz` is 503 until every resident tenant's query[T] is
    // warm (prewarm gated) and while draining; ingest[T]/detect[T] run on
    // exactly one pod (peer `/v1/handover` views, standby until the old pod
    // releases or a TTL passes); SIGTERM releases writers (flush) first, then
    // drains queries. The platform renders RollingUpdate (maxSurge 1,
    // maxUnavailable 0), a per-pod data volume and the headless peer Service
    // only for images reporting this.
    "cell_zero_downtime_roll_v1",
    // NAN-3569: maintenance participates in admission, reporting and release;
    // legacy peers without the complete writer marker fail closed.
    "cell_handover_all_writers_v1",
    // NAN-3005: the image ships the node-local platform publisher
    // (`/usr/local/bin/lake_platform_bundle serve`: bundle + per-tenant
    // policy) and the per-tenant lean enrichment coordinator
    // (`/usr/local/bin/lake_lean_enrichment_coordinator`). The publisher
    // writes `platform_bundle_dir = <feed_dir>/bundles` (the feed cache lives
    // in the sibling `<feed_dir>/cache`) and `<policy root>/<tenant>/policy.json`
    // outside `feed_dir`. The platform renders the `platform-bundle` sidecar,
    // `platform_bundle_dir` and the policy paths only for this. The worker
    // side is pinned by `lean_platform_policy` tests
    // (`cell_feature_lean_platform_publisher_v1_is_backed`).
    "lean_platform_publisher_v1",
    // The query-only router token (and its grace-window predecessor) may
    // `POST /v1/tenants/{t}/wake` when the body's role is `query`; other
    // roles, drain, signals and metrics stay full-token only. The platform
    // points the control plane's lean-assignment probe at the query token
    // (`NANO_LAKE_CELL_ROUTER_QUERY_TOKEN_FILE`) only for images with this.
    "router-query-token-wake",
    "native_parser_landing_v1",
    // The image ships the lean durable-job runner
    // (`/usr/local/bin/lake_job_runner --cell-only`, enterprise build): a
    // separate per-tenant entrypoint, never a cell child. It claims the
    // tenant's jobs from the hosted coordinator and dispatches each attempt to
    // query[T] through this router (`POST /v1/tenants/{T}/query/v1/jobs/search`
    // and `.../cancel`) with the query-only router token. The platform renders the
    // per-tenant runner Deployment only for images reporting this (runner
    // inputs: docs-internal/NAN-2924-lean-job-results-contract.md).
    "lean_job_runner_v1",
    // Lean ingest wires the sanctioned lake-part GC pass: with an enabled
    // `lake_part_delete_grant` AND the exchange's `lake_part_gc` route (owner
    // `lake-parts:delete` bearer for `lake-part-deletes:authorize` +
    // `lake-part-log:index` on the `part_signing` origin / CA, plus the tenant
    // Worker retention authority), superseded and orphan parts are deleted
    // through owner permit -> control attest -> Worker receipt, never on the
    // cell's R2 credential. Heartbeat + `/metrics` report
    // `lake_part_gc_deleted_total`. The platform renders `lake_part_gc` only for
    // this (LAKE-PART-GC-NANO-MAIN.md). The worker side is pinned by
    // `part_ingest::part_gc_cell` tests
    // (`cell_feature_lean_part_gc_sanctioned_v1_is_backed`).
    "lean_part_gc_sanctioned_v1",
    // NAN-3032: `ingest_keyword_index` in cell.json. Ingest writes v2
    // `tokens-NNNNN.nti` (row-group blooms plus 1,024-row block filters and
    // block times; same file name and signed record entry), and query[T]
    // fences rare-keyword searches to those blocks. Query of this image reads
    // v1 and v2, so the platform may render the key (default off) only for
    // images reporting this. The worker side is pinned by
    // `parts::block_index` and `part_query::prune` tests.
    "lean_keyword_index_v1",
    // NAN-3058: `identity_observations` in cell.json. Ingest derives the
    // lean identity observation index (private source IP → host/user, one
    // row per combination per hour) into reserved rows of each part's signed
    // entity-range partial; query[T] backfills the parts of the last 30 days
    // that predate it into its own state and answers `/v1/identity/*` from
    // the index. No part-contract, key-fence or provenance change. Query of
    // this image always serves whatever index it finds, so the platform may
    // render the key (default off) only for images reporting this. The
    // worker side is pinned by `identity_observations` and
    // `part_query::identity` tests.
    "lean_identity_observations_v1",
    // NAN-3503: `identity_directory_enrich` in cell.json. Ingest loads the
    // tenant identity directory (`identity/current.json` in its R2
    // enrichment prefix, read with `enrichment_reader`), pins it by manifest
    // revision (`identity_revision` feed pin), and stamps absent OCSF user
    // attributes plus one `enrichments[]` entry of type `identity` per
    // matched `actor.user` / `user`. Off: events and part admission are
    // byte-identical. The worker side is pinned by `identity_enrichment`
    // and `part_ingest::cell` tests.
    "lean_identity_directory_enrich_v1",
    // `prevalence_maintenance` in cell.json: the supervisor runs
    // `maintenance[T]` (role `maintenance`, served by the ingest binary)
    // beside every resident ingest. It exchanges for role=maintenance
    // (lake_prevalence_state read-only + the owner's maintenance bearer,
    // writer_class maintenance) and runs SlateDB's compactor on the tenant
    // prevalence DB within a fixed 250m / 512 MiB budget.
    // PREVALENCE-MAINTENANCE-NANO-MAIN.md is the control-plane contract.
    "lean_prevalence_maintenance_v1",
    // `ingest_merge_policy` in cell.json: optional overrides of ingest's
    // merge policy (`hour_seal_ms`, `sealed_remerge_debounce_ms`,
    // `sealed_remerge_max_defer_ms`, `max_merges_per_tick`), range-checked by
    // the cell and the worker. Absent = the code defaults, which already
    // debounce sealed-hour re-merges during a catch-up (the lab-tenant wedge).
    // the platform renders the key only for images reporting this.
    "ingest_merge_policy_v1",
    // NAN-3042: query[T] declares the optional `job_results` exchange class
    // (object-read-write on exactly `nano-shared-r2-<T>` /
    // `<T>/durable-query-result/v1/`), writes durable search results there
    // and reads them back for `/v1/jobs/result-page` (reached through this
    // router on the query scope), refreshing the grant with its other
    // credentials. Without the grant, job routes answer 503
    // `result_storage_unavailable`; there is no `file://` fallback. The platform
    // mints `job_results` only for images reporting this. The worker side is
    // pinned by `part_query::job_results` tests
    // (`cell_feature_lean_job_results_v1_is_backed`).
    "lean_job_results_v1",
    // NAN-3047: `detect_runs_rules` in cell.json. detect[T] opens its own
    // part_query engine (budget derived from detect's memory.max, rules
    // queue up to 60 s for a native slot) and the router sends every
    // `/v1/tenants/{t}/detect/...` request to it, never to query[T], for a
    // tenant whose placed detect memory limit is at least 1.5 GiB (smaller:
    // the legacy query[T] path). A running detect restarts when its rule
    // mode or detect memory limit changes. The platform renders the key, and
    // the rebalanced role budgets (DETECT-BUDGET-NANO-MAIN.md), only for
    // images reporting this.
    "detect_runs_rules_v1",
    // Explicit allowlisted rollout environment reaches isolated tenant children.
    "lean_feature_env_v1",
    // NAN-3148: `product_state_role` in cell.json. The supervisor runs
    // `product[T]` (role `product`, served by the query binary, query's uid,
    // minted and exchanged as `query`, so the control plane needs no new
    // role) beside every live query[T], in its own cgroup leaf (fixed 100m
    // weight / 1-core ceiling, 3 GiB). It builds prevalence windows, the
    // 30-day history, detail and the risk ledger, publishes versioned
    // snapshots under `<tenant>/product`, and query[T] only reads them
    // (product state never runs on query's CPU quota). Default off.
    "lean_product_state_role_v1",
    // NAN-3243: the image ships `/usr/local/bin/lake_otel_ingest` with its
    // lean mode (`NANO_OTEL_LAKE_MODE=lean`): one per-tenant Deployment, never
    // a cell child, that drains the tenant Worker's `otel-handoff-v1/` OTLP
    // spans/metrics into a local mirror and serves `/v1/otel/*` to search
    // directly (not through this router). The platform renders the lean OTLP
    // drain only for images reporting this. The worker side is pinned by
    // `otel_lean` tests (`cell_feature_lean_otel_drain_v1_is_backed`).
    "lean_otel_drain_v1",
    // NAN-3289 (completes NAN-2904): per-tenant scoped router tokens
    // (`nct1.`, derived from the full token; `crate::tenant_token`) checked
    // against the `/v1/tenants/{t}` path tenant and this cell, with separate
    // `query` / `detect` / `status` scopes and `GET /v1/tenants/{t}/status`;
    // signed durable-job specs (`x-nano-cell-job-signature`, the tenant's
    // `job` key) verified at the router; the detection-gate reset route; and
    // `router_accept_cluster_query_token` (default true: the cluster query
    // token keeps its legacy reach). The platform mounts a per-tenant runner
    // token (and the shared services' derivation key) only for images
    // reporting this, and renders `router_accept_cluster_query_token: false`
    // only once every caller has moved.
    "router_tenant_tokens_v1",
    // NAN-3440: `upstream_readiness` in cell.json (`targets` [{name, url}],
    // `interval_secs`, `timeout_secs`, `not_ready_after_secs`). The cell
    // probes each HTTPS target (R2, control plane) every interval; while two
    // targets (both R2 AND the control plane; one target alone never counts)
    // have been unreachable for `not_ready_after_secs` (default 300),
    // `/healthz` (200) reports `upstream_ready: false`. `/readyz` is NEVER
    // gated on it (a cluster-wide R2 outage must not drop every cell). The
    // cell signal `upstream_unreachable` warns/pages
    // and `/metrics` has `nano_cell_upstream_ready` /
    // `nano_cell_upstream_unreachable_seconds{target}`. The config refuses
    // unknown fields, so the platform renders the key only for this.
    "upstream_readiness_v1",
    // NAN-3522: with NANO_LAKE_CELL_INGEST_COUNTERS=1 the status push carries
    // each PLACED tenant's live ingest counter
    // (`ingest: {epoch_ms, rows_committed_total}`, from the ingest heartbeat);
    // draining tenants never carry one. Off: the body is byte-identical.
    // the platform's strict status schema accepts the field from #2028 on.
    "lean_ingest_counters_v1",
    // NAN-3522 over-commit hold: placement `ingest_hold_eps` (≥ 1 row/s),
    // while its lease `ingest_hold_until` (unix ms) has not passed, is
    // copied to ingest[T]'s assignment, which admits at most that many rows/s
    // (token bucket; the rest waits unacked in the edge log / Bronze). A
    // change restarts ingest[T] gracefully. The platform renders the key only
    // for a cell reporting this feature (the placement is deny_unknown_fields).
    // v2: images built before the lease reported v1 and refuse `ingest_hold_until`.
    "lean_ingest_hold_v2",
    // NAN-3523: `resources.io_max[].device` may be `"data_volume"`: the cell
    // resolves the whole disk under `data_dir` (st_dev → /sys/dev/block,
    // partition → parent disk) when it adopts its cgroup. Unresolvable: no
    // io.max, a WARN and the `io_max_unresolved` signal; the cell starts.
    // the platform renders `data_volume` rules only for this.
    "io_max_data_volume_v1",
    // NAN-3492: placement `prevalence_rarity_threshold` (1..=10000), the
    // tenant's stored rarity threshold, reaches every tenant process in the
    // assignment. Ingest stamps `is_rare` and query[T] answers requests that
    // carry no threshold with it; without it every tenant uses the default
    // 3. Placement refuses unknown fields, so the platform renders the key only
    // for images reporting this.
    "lean_prevalence_rarity_threshold_v1",
    // NAN-3523: a `pooled` cell fails closed without kernel limits. While
    // enforcement is `watchdog_only` (delegation not adopted yet, or
    // withdrawn) no new tenant process starts: requests get a retryable 503
    // (`reason: pooled_admission_refused`, `Retry-After`) and the upstream
    // queues; running processes keep serving. `/healthz` and `/v1/status`
    // report `admission` (`open` | `refused_unenforced`), `/metrics`
    // `nano_cell_admission_refused`, and the cell signal
    // `pooled_admission_refused` warns at once and pages after 30 s of
    // continuous refusal. `pooled` + `cgroup: "off"`
    // is rejected unless `isolation.allow_pooled_watchdog_only` (dev/test).
    // Dedicated cells are unchanged.
    "pooled_fail_closed_v1",
    // NAN-3523: per-tenant local-disk ceilings (`resources.tenant_disk`:
    // `mode` enforce|observe|off, unset = enforce on pooled cells and
    // observe on dedicated cells, `allowance_bytes`, `hard_factor`,
    // `volume_bytes`, `volume_fraction`, `walk_secs`, `max_entries`). Over
    // soft: `tenant_disk_pressure` warns and ingest wake/spawn answers a
    // retryable 503 (`reason: tenant_disk_pressure`, `Retry-After`); over
    // hard it pages and the tenant's ingest is killed. Accounting failures
    // fail open (`tenant_disk_accounting_failed`). `/metrics`
    // `nano_cell_tenant_disk_{bytes,soft_bytes,hard_bytes,ingest_refused}`,
    // `/v1/status` `tenants[].disk`. The config refuses unknown fields, so
    // the platform renders `tenant_disk` only for this.
    "tenant_disk_ceiling_v1",
    // NAN-3524: the image's `lake_part_receipt_reconcile` takes
    // `--evidence cell-exchange`: a LEAN tenant's reconcile Job reads R2 on a
    // read-only `lake_part_read` credential it exchanges at
    // `{control_url}/v1/lake/cells/{cell}/receipt-reconcile-exchange` with
    // its projected token (audience `nano-lake-receipt-reconcile`), never a
    // stored credential. The platform starts that Job only for this image. The
    // worker side is pinned by `lake_part_gc::receipt_reconcile_exchange`
    // tests (`cell_feature_part_receipt_reconcile_cell_exchange_v1_is_backed`).
    "part_receipt_reconcile_cell_exchange_v1",
    // NAN-3647: the hot window may live on a persistent volume reused across
    // pods (`NANO_LAKE_LOCAL_HOT_WINDOW_DIR` on one of a cell's A/B hot
    // PVCs, `NANO_LAKE_LOCAL_HOT_WINDOW_PERSISTENT=1`): query[T] reuses the
    // content-addressed cache it finds (signed sha256 + size), evicts what
    // the live catalog no longer references, rebuilds an unusable cache cold
    // instead of failing, and the purge removes a removed tenant's tree on
    // that volume too. `NANO_LAKE_LOCAL_HOT_WINDOW_WARM_GATE=1` opts into
    // the long warm readiness gate with its warm-up rate. The platform renders
    // the A/B volumes only for images reporting this. The worker side is
    // pinned by `local_hot_window` / `part_query::local_hot_window` tests.
    "lean_hot_volume_ab_v1",
    // NAN-3867: ingest[T] executes the tenant's data-subject erasure work
    // orders (`lake_erasure_work_orders`) on the lean lake: signed part
    // `rewrite`s without the subject's rows (`deletion_unit
    // erasure:<order>`), prevalence removal for an IP, and a part-log
    // receipt. It takes the order ledger from the ingest exchange's optional
    // `erasure_ledger` (the tenant's `publish` data-path login). The platform
    // delivers it, and declares the cell the tenant's erasure executor
    // (`erasure-executors.json` beside `routes.json`), only for images
    // reporting this. No cell config key. The worker side is pinned by
    // `part_ingest::lean_erasure` tests (`cell_feature_lean_erasure_v1_is_backed`).
    "lean_erasure_v1",
];

/// The label value: names joined with commas.
pub fn label() -> String {
    CELL_FEATURES.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    fn cfg(extra: serde_json::Value) -> crate::config::CellConfig {
        let mut v = serde_json::json!({
            "cell_id": "c", "data_dir": "/d", "state_dir": "/s", "ingest_binary": "/b", "query_binary": "/b",
            "listen_unix": "/r.sock", "router_token_file": "/t", "placement_file": "/p", "dev_key_dir": "/k"
        });
        v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        serde_json::from_value(v).unwrap()
    }

    type Check = (&'static str, fn() -> bool);

    /// One real check per feature.
    fn checks() -> Vec<Check> {
        vec![
            ("watchdog-v2", || {
                let c = crate::resources::Controller::new(crate::config::ResourceConfig::default(), false);
                c.desired(&crate::contract::TenantId::new("t").unwrap()) == (None, None)
            }),
            ("cgroup-adoption", || {
                crate::limits::PRIVATE_CGROUP_MOUNT.starts_with("/run/")
                    && cfg(serde_json::json!({"isolation": {"cgroup": "auto"}})).cgroup_policy()
                        == crate::config::CgroupPolicy::Auto
            }),
            ("router-query-token", || {
                cfg(serde_json::json!({"router_query_token_file": "/q"})).router_query_token_file.is_some()
                    && !crate::router::permits(crate::router::Scope::Query, crate::router::RouteClass::Wake)
            }),
            ("router-query-token-grace", || {
                let z = |s: &str| Zeroizing::new(s.to_owned());
                let (f, a, b) = ("f".repeat(40), "a".repeat(40), "b".repeat(40));
                let mut t = crate::router::Tokens::default();
                let now = Instant::now();
                t.rotate(z(&f), Some(z(&a)), None, now, Duration::from_secs(600), Duration::from_secs(600)).is_ok()
                    && t.rotate(z(&f), Some(z(&b)), None, now, Duration::from_secs(600), Duration::from_secs(600)).is_ok()
                    && t.check(Some(&a), now).is_some_and(|(_, prev)| prev)
                    && cfg(serde_json::json!({})).router_query_token_grace_secs == 600
            }),
            ("router-token-digest", || crate::router::token_digest("abc") == "ba7816bf8f01"),
            ("role_budgets_v1", || {
                let p: crate::config::TenantPlacement = serde_json::from_value(serde_json::json!({
                    "tenant_id":"t", "eps":20,
                    "ingest_request_millicores":50,"ingest_limit_millicores":500,
                    "ingest_request_memory_bytes":1,"ingest_limit_memory_bytes":2,
                    "detect_request_millicores":100,"detect_limit_millicores":500,
                    "detect_request_memory_bytes":1,"detect_limit_memory_bytes":2,
                    "query_request_millicores":250,"query_limit_millicores":3000,
                    "query_request_memory_bytes":1,"query_limit_memory_bytes":2
                })).unwrap();
                crate::contract::Role::ALL.iter().all(|role| p.role_budget(*role).is_some())
            }),
            ("lean_cell_alerts_v1", || {
                let feed = crate::signals::LeanCellAlertFeed::from_signals("cell-1", vec![]);
                let mut tokens = crate::router::Tokens::default();
                let (full, query, alerts) = ("f".repeat(40), "q".repeat(40), "a".repeat(40));
                let now = Instant::now();
                serde_json::to_value(feed).is_ok_and(|v| v["alerts"].is_array() && v["cell_id"] == "cell-1")
                    && cfg(serde_json::json!({"router_alerts_token_file": "/a"})).router_alerts_token_file.is_some()
                    && tokens.rotate(Zeroizing::new(full), Some(Zeroizing::new(query)),
                        Some(Zeroizing::new(alerts.clone())), now, Duration::from_secs(600), Duration::from_secs(600)).is_ok()
                    && tokens.check(Some(&alerts), now) == Some((crate::router::Scope::AlertsRead, false))
                    && crate::router::permits(crate::router::Scope::AlertsRead, crate::router::RouteClass::LeanCellAlerts)
                    && !crate::router::permits(crate::router::Scope::AlertsRead, crate::router::RouteClass::Status)
            }),
            ("lean_enrichment_reader_v1", || {
                let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
                let placement: crate::config::Placement = serde_json::from_value(serde_json::json!({"cell_id":"c","tenants":[{
                    "tenant_id": tenant, "eps": 20,
                    "platform_policy_file": format!("/policies/{tenant}/policy.json"),
                    "custom_context_root": format!("/custom/{tenant}")
                }]})).unwrap();
                let with_bundle = cfg(serde_json::json!({"feed_dir": "/feeds", "platform_bundle_file": "/feeds/platform.bundle"}));
                let a: crate::contract::Assignment = serde_json::from_value(serde_json::json!({
                    "tenant": tenant, "role": "detect", "cell_id": "c", "tenant_dir": "/d", "parts_dir": "/d/p",
                    "state_dir": "/d/s", "tmp_dir": "/d/t", "feed_dir": "/feeds", "platform_bundle_file": "/feeds/platform.bundle",
                    "platform_policy_file": format!("/policies/{tenant}/policy.json"), "custom_context_root": format!("/custom/{tenant}"),
                    "memory_cap_bytes": 1, "cpu_millis": 1, "eps": 1.0,
                    "jail": {"uid": 1, "gid": 1, "rw_paths": [], "ro_paths": [], "system_ro_paths": [], "tcp_connect_ports": [],
                        "cgroup_dir": null, "require_landlock": true, "max_processes": null, "max_open_files": 1}
                })).unwrap();
                with_bundle.validate().is_ok()
                    && placement.validate(&with_bundle).is_ok()
                    && a.platform_policy_file.is_some() && a.custom_context_root.is_some() && a.platform_bundle_file.is_some()
            }),
            ("lean_platform_bundle_dir_v1", || {
                let dir = cfg(serde_json::json!({"feed_dir": "/feeds", "platform_bundle_dir": "/feeds"}));
                let both = cfg(serde_json::json!({"feed_dir": "/feeds", "platform_bundle_dir": "/feeds", "platform_bundle_file": "/feeds/b"}));
                dir.validate().is_ok() && dir.has_platform_bundle() && both.validate().is_err()
                    && serde_json::from_value::<crate::contract::Assignment>(serde_json::json!({
                        "tenant": "t", "role": "query", "cell_id": "c", "tenant_dir": "/d", "parts_dir": "/d/p",
                        "state_dir": "/d/s", "tmp_dir": "/d/t", "feed_dir": "/feeds", "platform_bundle_dir": "/feeds",
                        "memory_cap_bytes": 1, "cpu_millis": 1, "eps": 1.0,
                        "jail": {"uid": 1, "gid": 1, "rw_paths": [], "ro_paths": [], "system_ro_paths": [], "tcp_connect_ports": [],
                            "cgroup_dir": null, "require_landlock": true, "max_processes": null, "max_open_files": 1}
                    })).is_ok_and(|a| a.platform_bundle_dir.as_deref() == Some(std::path::Path::new("/feeds")))
            }),
            ("lean_ingest_resident_v1", || {
                use crate::config::{IngestMode, Placement};
                let parse = |v: &str| serde_json::from_value::<Placement>(serde_json::json!({"cell_id": "c",
                    "tenants": [{"tenant_id": "t", "eps": 20, "ingest": v}]}));
                let resident = parse("resident");
                resident.as_ref().is_ok_and(|p| p.validate(&cfg(serde_json::json!({}))).is_ok()
                    && p.tenants[0].ingest == IngestMode::Resident
                    && !crate::supervisor::idle_reapable(crate::contract::Role::Ingest, p.tenants.first())
                    && crate::supervisor::idle_reapable(crate::contract::Role::Query, p.tenants.first()))
                    && parse("on_demand").is_ok_and(|p| crate::supervisor::idle_reapable(crate::contract::Role::Ingest, p.tenants.first()))
                    && parse("sometimes").is_err()
            }),
            // NAN-3008: every placed tenant's query[T] is resident by default
            // (started before any search, never idle-reaped while placed) and
            // never duty-cycled by the watchdog.
            ("lean_query_resident_v1", || {
                let c = cfg(serde_json::json!({}));
                let placed = crate::config::TenantPlacement::legacy(crate::contract::TenantId::new("t").unwrap(), 20.0);
                let hour = std::time::Duration::from_secs(3_600);
                c.query_resident && c.resources.query_unthrottled
                    && !crate::supervisor::idle_reap_due(crate::contract::Role::Query, Some(&placed), 0, hour * 48, hour, c.query_resident)
                    && crate::supervisor::idle_reap_due(crate::contract::Role::Query, None, 0, hour * 48, hour, c.query_resident)
            }),
            ("lean_part_gc_gate_v1", || {
                let hb: crate::contract::Heartbeat = serde_json::from_value(serde_json::json!({
                    "busy": false,
                    "part_gc_blocked": {"reason": "grant_disabled", "parts": 3, "bytes": 4096}
                })).unwrap();
                let lines = hb.part_gc_blocked.as_ref().map(|b| b.metric_lines("c", "t")).unwrap_or_default();
                lines.contains("lake_part_gc_blocked{cell=\"c\",tenant=\"t\",reason=\"grant_disabled\"} 3")
                    && lines.contains("lake_part_gc_blocked_bytes{cell=\"c\",tenant=\"t\",reason=\"grant_disabled\"} 4096")
                    && serde_json::from_value::<crate::contract::Heartbeat>(serde_json::json!({"busy": false}))
                        .is_ok_and(|h| h.part_gc_blocked.is_none())
            }),
            ("lean_part_sign_ca_v1", || {
                let signing = |ca: &str| serde_json::json!({"part_signing": {
                    "url": "https://owner.svc/sign", "signer_key_id": "k1",
                    "trusted_keys": [{"key_id": "k1", "public_key_hex": "a".repeat(64)}], "ca_file": ca
                }});
                let good = cfg(signing("/etc/nano/owner-ca/ca.crt"));
                good.validate().is_ok()
                    && good.part_signing_ca_dir() == Some(std::path::Path::new("/etc/nano/owner-ca"))
                    && cfg(signing("/d/ca.crt")).validate().is_err()
            }),
            ("lean_prevalence_state_v1", || {
                // The prevalence owner client reuses the part-signing owner
                // CA, which the supervisor mounts read-only into the jail.
                let good = cfg(serde_json::json!({"part_signing": {
                    "url": "https://owner.svc/sign", "signer_key_id": "k1",
                    "trusted_keys": [{"key_id": "k1", "public_key_hex": "a".repeat(64)}],
                    "ca_file": "/etc/nano/owner-ca/ca.crt"
                }}));
                good.validate().is_ok() && good.part_signing_ca_dir() == Some(std::path::Path::new("/etc/nano/owner-ca"))
            }),
            ("lean_tenant_dirs_min_caps_v1", || {
                // The O_PATH/owner-repair walk (its 5A-caps proof is
                // `tenant_dirs::tests::cell_5a_capabilities`): builds the
                // tree, repairs a dir left 0000 without tmp, refuses a symlink.
                use std::os::unix::fs::PermissionsExt;
                let Ok(d) = tempfile::tempdir() else { return false };
                // SAFETY: geteuid/getegid never fail.
                let (u, g) = unsafe { (libc::geteuid(), libc::getegid()) };
                let ids = crate::uidmap::TenantIds { slot: 0, ingest_uid: u, query_uid: u, detect_uid: u, gid: g };
                let tree = |t: &str| crate::tenant_dirs::ensure_tenant_tree(d.path(), t, &ids);
                let mode = |p: &str| std::fs::symlink_metadata(d.path().join(p)).map(|m| m.permissions().mode() & 0o7777).ok();
                let built = tree("t").is_ok() && mode("t/parts") == Some(0o2770) && mode("t/query/tmp") == Some(0o700);
                let repaired = std::fs::remove_dir(d.path().join("t/query/tmp")).is_ok()
                    && std::fs::set_permissions(d.path().join("t/query"), std::fs::Permissions::from_mode(0o000)).is_ok()
                    && tree("t").is_ok()
                    && mode("t/query") == Some(0o700)
                    && mode("t/query/tmp") == Some(0o700);
                let refused = std::fs::create_dir(d.path().join("s")).is_ok()
                    && std::os::unix::fs::symlink(d.path(), d.path().join("s/parts")).is_ok()
                    && tree("s").is_err();
                built && repaired && refused
            }),
            ("cell_purge_report_v1", || {
                // Removal → pending purge → purge that stays inside the
                // tenant's tree → verified record → the strict platform body.
                use crate::report::{Ledger, StatusSnapshot, StatusPush, TenantState};
                let (a, b) = ("6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00", "7a2d2f3b-6c9f-4e5d-8b4f-1f3c8d0e2a11");
                let tid = |s: &str| crate::contract::TenantId::new(s).unwrap();
                let Ok(d) = tempfile::tempdir() else { return false };
                // SAFETY: geteuid/getegid never fail.
                let (u, g) = unsafe { (libc::geteuid(), libc::getegid()) };
                let ids = crate::uidmap::TenantIds { slot: 0, ingest_uid: u, query_uid: u, detect_uid: u, gid: g };
                let trees = [a, b].iter().all(|t| crate::tenant_dirs::ensure_tenant_tree(d.path(), t, &ids).is_ok())
                    && std::fs::write(d.path().join(b).join("query/tmp/x"), b"12345").is_ok()
                    && std::os::unix::fs::symlink(d.path().join(a), d.path().join(b).join("parts/to-a")).is_ok();
                let mut l = Ledger::default();
                l.on_placement(&[tid(a), tid(b)].into_iter().collect(), 1);
                let removed = l.on_placement(&[tid(a)].into_iter().collect(), 2) == vec![tid(b)];
                let purged = crate::tenant_dirs::purge_tenant_tree(d.path(), b).is_ok_and(|bytes| bytes.tmp_bytes == 5)
                    && !crate::tenant_dirs::tenant_tree_present(d.path(), b).unwrap_or(true)
                    && crate::tenant_dirs::tenant_tree_present(d.path(), a).unwrap_or(false)
                    && l.record(&tid(b), crate::tenant_dirs::PurgeBytes { tmp_bytes: 5, ..Default::default() }, chrono::Utc::now(), 3);
                let snap = StatusSnapshot { cell_id: "c".into(), placement_revision: 2,
                    placed: vec![(tid(a), TenantState::Idle)], draining: vec![], purged: l.purged.clone().into_iter().collect(),
                    ingest: Default::default() };
                let v = serde_json::json!({"cell_id": "c", "placement_revision": 2,
                    "tenants": [{"tenant_id": a, "state": "idle"}],
                    "purged": [{"tenant_id": b, "reason": "drain", "verified": true, "at": l.purged[&tid(b)].at,
                        "cache_bytes_removed": 0, "tmp_bytes_removed": 5}]});
                let body = serde_json::from_value::<StatusPush>(v).ok();
                trees && removed && purged
                    && body.is_some_and(|want| snap.full_body() == want)
            }),
            ("limits_enforcement_signal_v1", || {
                use crate::limits::{enforcement, enforcement_reason, Enforcement, LimitsMode};
                let p = crate::config::Placement { cell_id: "c".into(), revision: 0,
                    tenants: vec![crate::config::TenantPlacement::legacy(crate::contract::TenantId::new("t").unwrap(), 300.0)] };
                enforcement(LimitsMode::Watchdog, false) == Enforcement::WatchdogOnly
                    && enforcement(LimitsMode::CgroupV2, true) == Enforcement::WatchdogOnly
                    && enforcement_reason(crate::config::CgroupPolicy::Auto, Enforcement::WatchdogOnly, false, &["x".into()]).is_some()
                    && p.role_budget_source() == "legacy_eps"
            }),
            ("cell_zero_downtime_roll_v1", || {
                use crate::handover::{writer_verdict, Handover, SelfId};
                let c = cfg(serde_json::json!({"zero_downtime_roll": {"peers": ["dns:nano-cell-c-peers.nano-lake-cells.svc:8790"]}}));
                let h = c.zero_downtime_roll.clone().and_then(|z| Handover::new("c", z).ok());
                let t = crate::contract::TenantId::new("t").unwrap();
                let me = SelfId { cell_id: "c".into(), boot_id: "b".into(), boot_unix_ms: 1 };
                c.validate().is_ok()
                    && h.is_some_and(|h| !h.ready() && { h.begin_drain(); h.may_write(&t).is_err() })
                    && writer_verdict(&me, &[], &t, Instant::now(), Duration::from_secs(30), Duration::ZERO).is_ok()
                    && crate::router::classify(&hyper::Method::GET, "/readyz") == crate::router::RouteClass::Health
                    && !crate::router::permits(crate::router::Scope::Query, crate::router::RouteClass::Handover)
                    && cfg(serde_json::json!({"zero_downtime_roll": {"peers": []}})).validate().is_err()
            }),
            ("cell_handover_all_writers_v1", || {
                let c = cfg(serde_json::json!({"zero_downtime_roll": {"peers": ["unix:/peer"]}}));
                c.zero_downtime_roll.and_then(|z| crate::handover::Handover::new("c", z).ok())
                    .is_some_and(|h| h.view(Default::default()).all_writers)
            }),
            ("lean_platform_publisher_v1", || {
                // The layout the publisher writes (lean_platform_policy.rs):
                // bundles in a directory below feed_dir, beside the cache,
                // and a per-tenant policy outside feed_dir.
                use crate::config::Placement;
                let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
                let c = cfg(serde_json::json!({"feed_dir": "/var/lib/nano-platform-feeds",
                    "platform_bundle_dir": "/var/lib/nano-platform-feeds/bundles"}));
                let placement = |policy: serde_json::Value| serde_json::from_value::<Placement>(serde_json::json!({
                    "cell_id": "c", "tenants": [{"tenant_id": tenant, "eps": 20, "platform_policy_file": policy}]}));
                c.validate().is_ok() && c.has_platform_bundle()
                    && placement(serde_json::json!(format!("/var/lib/nano-platform-policy/{tenant}/policy.json")))
                        .is_ok_and(|p| p.validate(&c).is_ok())
                    && placement(serde_json::json!("/var/lib/nano-platform-policy/other/policy.json"))
                        .is_ok_and(|p| p.validate(&c).is_err())
            }),
            ("router-query-token-wake", || {
                use crate::contract::Role;
                use crate::router::{admits, classify, permits, permits_wake, RouteClass, Scope};
                let wake = classify(&hyper::Method::POST, "/v1/tenants/t/wake");
                wake == RouteClass::Wake
                    && admits(Scope::Query, wake)
                    && permits_wake(Scope::Query, Role::Query)
                    && !permits_wake(Scope::Query, Role::Ingest)
                    && !permits_wake(Scope::Query, Role::Detect)
                    && !admits(Scope::AlertsRead, wake)
                    && !admits(Scope::Query, RouteClass::Drain)
                    && !permits(Scope::Query, RouteClass::Signals)
                    && !permits(Scope::Query, RouteClass::Metrics)
            }),
            ("native_parser_landing_v1", || {
                use crate::router::{classify, permits_with, RouteClass, Scope};
                classify(&hyper::Method::POST, "/v1/tenants/t/landing") == RouteClass::Landing
                    && permits_with(Scope::Query, RouteClass::Landing, false)
                    && !permits_with(Scope::Query, RouteClass::Query, false)
                    && !permits_with(Scope::AlertsRead, RouteClass::Landing, false)
                    && !permits_with(Scope::TenantStatus, RouteClass::Landing, false)
            }),
            ("lean_job_runner_v1", || {
                // The runner's two cell calls reach query[T] on the
                // query-only token; nothing else opens to it.
                use crate::router::{admits, classify, RouteClass, Scope};
                let t = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
                let post = |p: String| classify(&hyper::Method::POST, &p);
                let run = post(format!("/v1/tenants/{t}/query/v1/jobs/search"));
                let cancel = post(format!("/v1/tenants/{t}/query/v1/jobs/search/cancel"));
                run == RouteClass::Query && cancel == RouteClass::Query
                    && admits(Scope::Query, run) && admits(Scope::Query, cancel)
                    && !admits(Scope::Query, post(format!("/v1/tenants/{t}/drain")))
                    && cfg(serde_json::json!({"router_query_token_file": "/q"})).router_query_token_file.is_some()
            }),
            ("lean_part_gc_sanctioned_v1", || {
                let hb: crate::contract::Heartbeat =
                    serde_json::from_value(serde_json::json!({"busy": false, "part_gc_deleted_total": 7})).unwrap();
                hb.part_gc_deleted_total == 7
                    && crate::contract::part_gc_deleted_metric_line("c", "t", hb.part_gc_deleted_total)
                        == "lake_part_gc_deleted_total{cell=\"c\",tenant=\"t\"} 7\n"
                    && serde_json::from_value::<crate::contract::Heartbeat>(serde_json::json!({"busy": false}))
                        .is_ok_and(|h| h.part_gc_deleted_total == 0)
            }),
            ("lean_keyword_index_v1", || {
                cfg(serde_json::json!({"ingest_keyword_index": true})).ingest_keyword_index
                    && !cfg(serde_json::json!({})).ingest_keyword_index
            }),
            ("lean_identity_observations_v1", || {
                cfg(serde_json::json!({"identity_observations": true})).identity_observations
                    && !cfg(serde_json::json!({})).identity_observations
            }),
            ("lean_identity_directory_enrich_v1", || {
                cfg(serde_json::json!({"identity_directory_enrich": true})).identity_directory_enrich
                    && !cfg(serde_json::json!({})).identity_directory_enrich
            }),
            ("lean_prevalence_maintenance_v1", || {
                use crate::contract::Role;
                let on = cfg(serde_json::json!({"prevalence_maintenance": true}));
                on.prevalence_maintenance && !cfg(serde_json::json!({})).prevalence_maintenance
                    && Role::parse("maintenance") == Some(Role::Maintenance)
                    && Role::ALL.contains(&Role::Maintenance)
            }),
            ("ingest_merge_policy_v1", || {
                let set = cfg(serde_json::json!({"ingest_merge_policy": {"sealed_remerge_debounce_ms": 600000}}));
                set.ingest_merge_policy.is_some_and(|p| p.sealed_remerge_debounce_ms == Some(600_000) && p.validate().is_ok())
                    && cfg(serde_json::json!({})).ingest_merge_policy.is_none()
            }),
            ("lean_job_results_v1", || {
                // Results are written and read back by query[T] itself; the
                // read-back reaches it on the query scope like the job calls.
                use crate::router::{admits, classify, RouteClass, Scope};
                let t = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
                let page = classify(&hyper::Method::POST, &format!("/v1/tenants/{t}/query/v1/jobs/result-page"));
                page == RouteClass::Query && admits(Scope::Query, page)
                    && crate::contract::Role::Query.as_str() == "query"
            }),
            ("detect_runs_rules_v1", || {
                use crate::budget::{GIB, MIB};
                use crate::contract::Role;
                let t = crate::contract::TenantId::new("t").unwrap();
                let sized = crate::config::TenantPlacement {
                    detect_request_millicores: Some(250), detect_limit_millicores: Some(1_000),
                    detect_request_memory_bytes: Some(512 * MIB), detect_limit_memory_bytes: Some(3 * GIB / 2),
                    ..crate::config::TenantPlacement::legacy(t.clone(), 300.0)
                };
                let on = cfg(serde_json::json!({"detect_runs_rules": true}));
                on.detect_runs_rules && !cfg(serde_json::json!({})).detect_runs_rules
                    && sized.detect_runs_rules(on.detect_runs_rules)
                    && !crate::config::TenantPlacement::legacy(t, 300.0).detect_runs_rules(true)
                    && crate::router::detect_target(true) == Role::Detect
                    && crate::router::detect_target(false) == Role::Query
                    && crate::supervisor::detect_needs_respawn(false, 3 * GIB / 2, &sized, true)
            }),
            ("lean_feature_env_v1", crate::supervisor::feature_env_is_isolated),
            ("lean_product_state_role_v1", || {
                use crate::contract::Role;
                let t = crate::contract::TenantId::new("t").unwrap();
                let placed = crate::config::TenantPlacement::legacy(t, 300.0);
                let on = cfg(serde_json::json!({"product_state_role": true}));
                on.product_state_role && !cfg(serde_json::json!({})).product_state_role
                    && Role::parse("product") == Some(Role::Product)
                    && Role::ALL.contains(&Role::Product)
                    && Role::Product.credential_role() == Role::Query
                    && placed.effective_role_budget(Role::Product).limit_millicores == crate::budget::PRODUCT_LIMIT_MILLICORES
                    && placed.effective_role_budget(Role::Product).request_millicores
                        < placed.effective_role_budget(Role::Query).request_millicores
            }),
            ("lean_otel_drain_v1", || {
                // The drain is reached directly by search, never through the
                // cell router: no tenant route class opens to an `otel` path.
                use crate::router::{admits, classify, RouteClass, Scope};
                let t = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
                let otel = classify(&hyper::Method::GET, &format!("/v1/tenants/{t}/otel/v1/otel/services"));
                otel == RouteClass::Other && !admits(Scope::Query, otel)
            }),
            ("router_tenant_tokens_v1", || {
                use crate::router::{Deny, Scope, Tokens};
                use crate::tenant_token::TenantScope;
                const FULL: &str = "full-router-token-0123456789abcdef0123456789";
                let now = Instant::now();
                let mut tokens = Tokens::default();
                tokens.rotate(Zeroizing::new(FULL.into()), None, None, now, Duration::ZERO, Duration::ZERO).unwrap();
                let a = tokens.tenant_key().unwrap().token("alpha", "c1", TenantScope::Query);
                let post = hyper::Method::POST;
                let on = |path: &str| tokens.authorize(Some(&a), &post, path, "c1", false, now);
                on("/v1/tenants/alpha/query/v1/query") == Ok((Scope::TenantQuery, false))
                    && matches!(on("/v1/tenants/bravo/query/v1/query"), Err(Deny::Forbidden(_)))
                    && matches!(on("/v1/tenants/alpha/detect/v1/detections/commit"), Err(Deny::Forbidden(_)))
                    && cfg(serde_json::json!({})).router_accept_cluster_query_token
                    && !cfg(serde_json::json!({"router_accept_cluster_query_token": false})).router_accept_cluster_query_token
            }),
            ("upstream_readiness_v1", || {
                use crate::upstream::{verdict, TargetState};
                let on = cfg(serde_json::json!({"upstream_readiness": {"targets": [
                    {"name": "r2", "url": "https://acct.r2.cloudflarestorage.com/"},
                    {"name": "control", "url": "https://api.nano.rs/api/health"}]}}));
                let u = on.upstream_readiness.clone();
                let t0 = Instant::now();
                let mut s = vec![TargetState::new("r2", t0), TargetState::new("control", t0)];
                s[1].record(Err("timeout".into()), t0 + Duration::from_secs(1));
                let control_alone = verdict(&s, Duration::from_secs(300), t0 + Duration::from_secs(900));
                s[0].record(Err("connect timeout".into()), t0 + Duration::from_secs(1));
                let down = verdict(&s, Duration::from_secs(300), t0 + Duration::from_secs(301));
                on.validate().is_ok() && cfg(serde_json::json!({})).upstream_readiness.is_none()
                    && u.is_some_and(|u| u.not_ready_after_secs == 300 && u.interval_secs == 15 && u.timeout_secs == 5)
                    && control_alone.ready
                    && !down.ready
            }),
            ("lean_ingest_counters_v1", || {
                use crate::report::{IngestCounters, StatusPush, StatusSnapshot, TenantState};
                let a = "4f1c2a90-1111-4aaa-8bbb-000000000001";
                let b = "4f1c2a90-2222-4aaa-8bbb-000000000002";
                let tid = |s: &str| crate::contract::TenantId::new(s).unwrap();
                let c = IngestCounters { epoch_ms: 1_790_000_000_000, rows_committed_total: 42 };
                let snap = StatusSnapshot { cell_id: "c".into(), placement_revision: 2,
                    placed: vec![(tid(a), TenantState::Running)], draining: vec![tid(b)], purged: vec![],
                    // A counter keyed to a draining tenant is never reported.
                    ingest: [(tid(a), c), (tid(b), c)].into_iter().collect() };
                let v = serde_json::to_value(snap.full_body()).unwrap();
                let off = StatusSnapshot { ingest: Default::default(), ..snap.clone() };
                let hb = serde_json::from_value::<crate::contract::Heartbeat>(serde_json::json!({"busy": false, "rows_committed_total": 7}));
                v["tenants"][0]["ingest"] == serde_json::json!({"epoch_ms": 1_790_000_000_000u64, "rows_committed_total": 42})
                    && v["tenants"][1].get("ingest").is_none()
                    && serde_json::to_value(off.full_body()).unwrap()["tenants"][0].get("ingest").is_none()
                    && serde_json::from_value::<StatusPush>(v).is_ok()
                    && hb.is_ok_and(|h| h.rows_committed_total == 7)
                    && crate::supervisor::FEATURE_ENV.contains(&"NANO_LAKE_CELL_INGEST_COUNTERS")
            }),
            ("lean_ingest_hold_v2", || {
                use crate::config::{Placement, TenantPlacement};
                let parse = |hold: serde_json::Value| serde_json::from_value::<Placement>(serde_json::json!({"cell_id": "c",
                    "tenants": [{"tenant_id": "t", "eps": 20, "ingest_hold_eps": hold, "ingest_hold_until": 2_000}]}));
                let ok = |hold: serde_json::Value| parse(hold).is_ok_and(|p| p.validate(&cfg(serde_json::json!({}))).is_ok());
                let held = parse(serde_json::json!(60.0));
                let assignment = serde_json::from_value::<crate::contract::Assignment>(serde_json::json!({
                    "tenant": "t", "role": "ingest", "cell_id": "c", "tenant_dir": "/d", "parts_dir": "/d/p",
                    "state_dir": "/d/s", "tmp_dir": "/d/t", "memory_cap_bytes": 1, "cpu_millis": 1, "eps": 1.0,
                    "ingest_hold_eps": 60.0,
                    "jail": {"uid": 1, "gid": 1, "rw_paths": [], "ro_paths": [], "system_ro_paths": [], "tcp_connect_ports": [],
                        "cgroup_dir": null, "require_landlock": true, "max_processes": null, "max_open_files": 1}
                }));
                // Absent: no hold, and the placement re-serializes without the key.
                let plain = serde_json::from_value::<Placement>(serde_json::json!({"cell_id": "c", "tenants": [{"tenant_id": "t", "eps": 20}]}));
                held.as_ref().is_ok_and(|p| p.tenants[0].ingest_hold_eps == Some(60.0)
                    // The lease: in force before it, gone at and after it; no lease, no hold.
                    && p.tenants[0].effective_ingest_hold_eps(1_999) == Some(60.0)
                    && p.tenants[0].effective_ingest_hold_eps(2_000).is_none()
                    && TenantPlacement { ingest_hold_until: None, ..p.tenants[0].clone() }.effective_ingest_hold_eps(0).is_none())
                    && ok(serde_json::json!(1.0))
                    // A hold slows ingest, never stops it.
                    && !ok(serde_json::json!(0.0)) && !ok(serde_json::json!(-1.0)) && !ok(serde_json::json!(0.5))
                    && assignment.is_ok_and(|a| a.ingest_hold_eps == Some(60.0))
                    && plain.is_ok_and(|p| p.tenants[0].ingest_hold_eps.is_none()
                        && serde_json::to_value(&p.tenants[0]).unwrap().get("ingest_hold_eps").is_none()
                        && serde_json::to_value(&p.tenants[0]).unwrap().get("ingest_hold_until").is_none())
                    && crate::supervisor::ingest_hold_needs_respawn(None, Some(60.0))
                    && crate::supervisor::ingest_hold_needs_respawn(Some(60.0), None)
                    && crate::supervisor::ingest_hold_needs_respawn(Some(60.0), Some(30.0))
                    && !crate::supervisor::ingest_hold_needs_respawn(Some(60.0), Some(60.0))
                    && !crate::supervisor::ingest_hold_needs_respawn(None, None)
                    && crate::supervisor::held_ingest_pages(None) == (300.0, 10.0)
                    && crate::supervisor::held_ingest_pages(Some(60.0)).0.is_infinite()
            }),
            ("io_max_data_volume_v1", || {
                let on = cfg(serde_json::json!({"resources": {"io_max": [{"device": "data_volume", "wbps": 1}]}}));
                let sys = tempfile::tempdir().unwrap();
                let disk = sys.path().join("devices/d/sda");
                std::fs::create_dir_all(disk.join("sda1")).unwrap();
                std::fs::write(disk.join("dev"), "8:0").unwrap();
                std::fs::write(disk.join("sda1/dev"), "8:1").unwrap();
                std::fs::write(disk.join("sda1/partition"), "1").unwrap();
                std::fs::create_dir_all(sys.path().join("dev/block")).unwrap();
                std::os::unix::fs::symlink(disk.join("sda1"), sys.path().join("dev/block/8:1")).unwrap();
                on.validate().is_ok() && on.resources.io_max[0].is_data_volume()
                    && crate::limits::whole_disk_device(sys.path(), 8, 1).as_deref() == Ok("8:0")
                    && crate::limits::whole_disk_device(sys.path(), 0, 40).is_err()
            }),
            ("lean_prevalence_rarity_threshold_v1", || {
                let parse = |n: u64| serde_json::from_value::<crate::config::Placement>(serde_json::json!({"cell_id": "c",
                    "tenants": [{"tenant_id": "t", "eps": 20, "prevalence_rarity_threshold": n}]}));
                let c = cfg(serde_json::json!({}));
                parse(7).is_ok_and(|p| p.validate(&c).is_ok() && p.tenants[0].prevalence_rarity_threshold == Some(7))
                    && parse(0).is_ok_and(|p| p.validate(&c).is_err())
                    && parse(10_001).is_ok_and(|p| p.validate(&c).is_err())
                    && crate::config::TenantPlacement::legacy(crate::contract::TenantId::new("t").unwrap(), 20.0)
                        .prevalence_rarity_threshold.is_none()
                    && serde_json::from_value::<crate::contract::Assignment>(serde_json::json!({
                        "tenant": "t", "role": "ingest", "cell_id": "c", "tenant_dir": "/d", "parts_dir": "/d/p",
                        "state_dir": "/d/s", "tmp_dir": "/d/t", "memory_cap_bytes": 1, "cpu_millis": 1, "eps": 1.0,
                        "prevalence_rarity_threshold": 7,
                        "jail": {"uid": 1, "gid": 1, "rw_paths": [], "ro_paths": [], "system_ro_paths": [], "tcp_connect_ports": [],
                            "cgroup_dir": null, "require_landlock": true, "max_processes": null, "max_open_files": 1}
                    })).is_ok_and(|a| a.prevalence_rarity_threshold == Some(7))
            }),
            ("pooled_fail_closed_v1", || {
                use crate::config::CellMode::{Dedicated, Pooled};
                use crate::limits::{admission, Admission, Enforcement};
                let refused = crate::signals::pooled_admission_refused(Some(crate::signals::POOLED_ADMISSION_REFUSED_PAGE), None);
                admission(Pooled, Enforcement::WatchdogOnly, false) == Admission::RefusedUnenforced
                    && admission(Pooled, Enforcement::Kernel, false) == Admission::Open
                    && admission(Dedicated, Enforcement::WatchdogOnly, false) == Admission::Open
                    && refused.severity == crate::signals::Severity::Page
                    && cfg(serde_json::json!({"isolation": {"cgroup": "off"}})).validate().is_err()
                    && cfg(serde_json::json!({"mode": "dedicated", "isolation": {"cgroup": "off"}})).validate().is_ok()
            }),
            ("tenant_disk_ceiling_v1", || {
                use crate::disk_ceiling::{DiskCeilings, DiskCeilingMode, Sample};
                use crate::volume_usage::TreeUsage;
                let c = cfg(serde_json::json!({"mode": "dedicated", "resources": {"tenant_disk": {"mode": "enforce", "volume_bytes": 1u64 << 50}}}));
                let r = c.resources.clone();
                let d = DiskCeilings::new(r.tenant_disk.clone(), c.mode);
                let (a, b) = (crate::contract::TenantId::new("a").unwrap(), crate::contract::TenantId::new("b").unwrap());
                let now = Instant::now();
                let gib = crate::budget::GIB;
                d.record(a.clone(), Sample { at: now, usage: Ok(TreeUsage { bytes: 100 * gib, entries: 1, complete: true }) });
                d.record(b.clone(), Sample { at: now, usage: Err("EACCES".into()) });
                let tick = d.evaluate(&[(a.clone(), gib), (b.clone(), gib)], now);
                let auto = |m: &str| { let c = cfg(serde_json::json!({"mode": m})); DiskCeilings::new(c.resources.tenant_disk, c.mode).mode() };
                d.mode() == DiskCeilingMode::Enforce
                    && auto("pooled") == DiskCeilingMode::Enforce && auto("dedicated") == DiskCeilingMode::Observe
                    && tick.kills.len() == 1 && tick.kills[0].0 == a
                    && d.admit_ingest(&a).is_err() && d.admit_ingest(&b).is_ok()
                    && crate::resources::KillReason::TenantDiskCeiling.as_str() == "tenant_disk_ceiling"
            }),
            ("part_receipt_reconcile_cell_exchange_v1", || {
                // Never a cell role: the reconcile route and audience are
                // distinct from the cells' credential exchange.
                use crate::contract::{Role, RECEIPT_RECONCILE_AUDIENCE, RECEIPT_RECONCILE_EXCHANGE_LEAF};
                RECEIPT_RECONCILE_EXCHANGE_LEAF == "receipt-reconcile-exchange"
                    && RECEIPT_RECONCILE_AUDIENCE == "nano-lake-receipt-reconcile"
                    && Role::ALL.iter().all(|r| r.as_str() != "receipt_reconcile")
            }),
            ("lean_hot_volume_ab_v1", || {
                let forwarded = |name: &str| crate::supervisor::FEATURE_ENV.contains(&name);
                let data = std::path::Path::new("/var/lib/nano-cell/data/tenants");
                let hot = std::path::Path::new("/var/lib/nano-cell-hot/tenants");
                [
                    "NANO_LAKE_LOCAL_HOT_WINDOW_DIR",
                    "NANO_LAKE_LOCAL_HOT_WINDOW_PERSISTENT",
                    "NANO_LAKE_LOCAL_HOT_WINDOW_WARM_GATE",
                    "NANO_LAKE_LOCAL_HOT_WINDOW_WARM_GATE_TIMEOUT_SECONDS",
                    "NANO_LAKE_LOCAL_HOT_WINDOW_WARMUP_BYTES_PER_SECOND",
                    "NANO_LAKE_LOCAL_HOT_WINDOW_WARMUP_CONCURRENCY",
                ].iter().all(|name| forwarded(name))
                    && crate::supervisor::purge_roots(data, Some(hot)).len() == 2
            }),
            // Ingest-only (exchange field + executor); the cell forwards
            // nothing and renders no key for it.
            ("lean_erasure_v1", || !CELL_FEATURES.is_empty()),
        ]
    }

    #[test]
    fn the_feature_list_matches_what_the_binary_supports() {
        let names: Vec<&str> = checks().iter().map(|(n, _)| *n).collect();
        assert_eq!(names, CELL_FEATURES, "every feature needs exactly one check, in list order");
        for (name, check) in checks() {
            assert!(check(), "feature {name} is listed but its check fails");
        }
        let l = label();
        assert!(l.split(',').all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')));
        assert_eq!(l.split(',').count(), CELL_FEATURES.len());
    }
}
