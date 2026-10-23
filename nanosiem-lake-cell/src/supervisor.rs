// SPDX-License-Identifier: AGPL-3.0-or-later

//! The cell supervisor (NAN-2871): spawns per-tenant `ingest[T]` and
//! `query[T]` processes on demand, keeps a warm pool, reaps idle processes,
//! enforces per-tenant limits, and exposes per-tenant health, metrics and
//! stall/lag signals.
//!
//! It holds **no tenant keys**. Per assignment it mints a tenant/role-scoped
//! bootstrap token through the [`KeySource`], writes it into a sealed memfd
//! and passes the fd to the process only after verifying (from
//! `/proc/<pid>/status`) that the process already runs as the tenant uid.

/// Explicit rollout knobs only. Never inherit arbitrary NANO_LAKE_* or credentials.
/// Reader locations below are relative to nanosiem-lake-worker/src.
pub(crate) const FEATURE_ENV: &[&str] = &[
    // planner.rs (opt-in until live aggregate latency is verified)
    "NANO_LAKE_NARROW_AGGREGATE_SCHEMA",
    // planner.rs (NAN-3386 flat entity filter leaves for chDB PREWHERE;
    // literal "1" enables, default off, live A/B only)
    "NANO_LAKE_FLAT_FILTER_LEAVES",
    "NANO_LAKE_PART_RESULT_CACHE",
    // part_query/host_hint.rs (NAN-3154 dotless hostname hint, default off)
    "NANO_LAKE_DOTLESS_HOST_HINT",
    // part_query/range_fetch.rs (NAN-3133 signed column-range cold fetch)
    "NANO_LAKE_SEARCH_RANGE_FETCH",
    // part_query/two_pass.rs (NAN-3155 two-pass row fetch; query role;
    // "0" is the kill switch, default on)
    "NANO_LAKE_TWO_PASS",
    // part_query/lanes.rs (NAN-3393 lane routing v2: wide-text bounded
    // reader, lane memo, 4-thread cap, 2 x 768 MiB large lane; query role;
    // "0" is the kill switch, default on)
    "NANO_LAKE_LANE_ROUTING_V2",
    // planner.rs (NAN-3411 full-event payload reader threads / block rows;
    // query role; unset keeps NAN-3077's 1 thread / 128 rows; clamped to
    // 1..=4 threads and 128..=8192 rows; live A/B only)
    "NANO_LAKE_PAYLOAD_MAX_THREADS",
    "NANO_LAKE_PAYLOAD_BLOCK_ROWS",
    // part_query/prewarm_pacing.rs (NAN-3403 arrival prewarm: one pass per
    // interval over files no earlier pass finished; query role; "0" is the
    // kill switch, default on; interval default 60 s)
    "NANO_LAKE_PREWARM_THROTTLE",
    "NANO_LAKE_PREWARM_MIN_INTERVAL_SECONDS",
    // reader_object_cache.rs (NAN-3403 bit-rot sample at most once per
    // object per interval, default 3600 s, "0" per-hit as before; O_DIRECT
    // verification reads, "0" restores buffered reads)
    "NANO_LAKE_READER_SCRUB_MIN_INTERVAL_SECONDS",
    "NANO_LAKE_READER_VERIFY_DIRECT_IO",
    // reader_object_cache.rs (NAN-3644 heavy cold reads queue per reader
    // instead of being refused; slots run at once, 1..=16, default 1)
    "NANO_LAKE_READER_COLD_HEAVY_CONCURRENCY",
    // part_query/product_publish.rs: product-state cycle gap (NAN-3148),
    // for product[T] and query[T]'s in-process publisher alike.
    "NANO_LAKE_PRODUCT_STATE_CYCLE_SECS",
    // Query-only local residency policy.
    "NANO_LAKE_LOCAL_HOT_WINDOW",
    "NANO_LAKE_LOCAL_HOT_WINDOW_HOURS",
    "NANO_LAKE_LOCAL_HOT_WINDOW_DIR",
    "NANO_LAKE_LOCAL_HOT_WINDOW_BYTES_PER_SECOND",
    "NANO_LAKE_LOCAL_HOT_WINDOW_RESERVE_BYTES",
    "NANO_LAKE_LOCAL_HOT_WINDOW_MAX_BYTES",
    // NAN-3164 hydration scheduling and the bounded startup warm gate.
    "NANO_LAKE_LOCAL_HOT_WINDOW_CONCURRENCY",
    "NANO_LAKE_LOCAL_HOT_WINDOW_QUERY_BACKOFF",
    "NANO_LAKE_LOCAL_HOT_WINDOW_WARM_HOURS",
    "NANO_LAKE_LOCAL_HOT_WINDOW_WARM_TIMEOUT_SECONDS",
    "NANO_LAKE_LOCAL_HOT_WINDOW_START_DELAY_SECONDS",
    // NAN-3647: the opt-in warm readiness gate and its warm-up pace, and the
    // persistent (A/B) hot-window volume mode.
    "NANO_LAKE_LOCAL_HOT_WINDOW_WARM_GATE",
    "NANO_LAKE_LOCAL_HOT_WINDOW_WARM_GATE_TIMEOUT_SECONDS",
    "NANO_LAKE_LOCAL_HOT_WINDOW_WARMUP_BYTES_PER_SECOND",
    "NANO_LAKE_LOCAL_HOT_WINDOW_WARMUP_CONCURRENCY",
    "NANO_LAKE_LOCAL_HOT_WINDOW_PERSISTENT",
    // part_ingest/writer.rs
    "NANO_LAKE_UID_SIDECAR_WRITE",
    "NANO_LAKE_PARQUET_RANGE_WRITE",
    "NANO_LAKE_ENTITY_SIDECAR_FIELDS",
    "NANO_LAKE_MERGE_MINUTE_CONCURRENCY",
    "NANO_LAKE_MERGE_HISTORY_CONCURRENCY",
    "NANO_LAKE_COMPACTION_LAYOUT",
    "NANO_LAKE_COMPACTION_PACING",
    "NANO_LAKE_ENTITY_LOCATOR_WRITE",
    "NANO_LAKE_ENTITY_COUNT_WRITE",
    // part_ingest/host_sort.rs (NAN-3412 host-sorted endpoint hour files;
    // ingest role; default off)
    "NANO_LAKE_ENDPOINT_HOST_SORT",
    // part_ingest/merge.rs (NAN-3437 (source, class) hour family files in
    // the default layout, one merge pass; ingest role; default off)
    "NANO_LAKE_CLASS_FAMILIES",
    // cloud_facet_summaries.rs (signed writer and exact summary reader)
    "NANO_LAKE_CLOUD_FACET_SUMMARIES",
    "NANO_LAKE_CLOUD_FACET_READS",
    "NANO_LAKE_ASSET_FACET_SUMMARIES",
    "NANO_LAKE_ASSET_FACET_READS",
    // part_query/identity_spill.rs (local historical observation cache)
    "NANO_LAKE_IDENTITY_SPILL_BACKFILL",
    // part_query/identity_merged.rs (NAN-3399 merged identity index;
    // query role; "0" is the kill switch, default on)
    "NANO_LAKE_IDENTITY_MERGED_INDEX",
    // NAN-4190: window entity index (build + lookups) and its fields.
    "NANO_LAKE_ENTITY_INDEX",
    "NANO_LAKE_ENTITY_INDEX_FIELDS",
    "NANO_LAKE_DURABLE_LATERAL",
    // part_ingest/reindex.rs
    "NANO_LAKE_REINDEX_OLD_HOURS",
    "NANO_LAKE_SIDECAR_BACKFILL",
    // parts/sidecar.rs
    "NANO_LAKE_TRIGRAM_INDEX",
    "NANO_LAKE_PAIR_INDEX",
    "NANO_LAKE_IP_TOKEN_INDEX",
    // part_ingest/merge_quota.rs (local and remote compaction budgets)
    "NANO_LAKE_COMPACTION_ROWS_PER_SECOND",
    "NANO_LAKE_COMPACTION_BYTES_PER_SECOND",
    "NANO_LAKE_COMPACTION_CPU_PERCENT",
    "NANO_LAKE_COMPACTION_REMOTE_BYTES_PER_SECOND",
    "NANO_LAKE_COMPACTION_REMOTE_REQUESTS_PER_SECOND",
    // part_ingest/ingest.rs (NAN-3619): pipelined flush depth ("2" adds a
    // second flight; unset/"1" keeps the serial contract) and commit a
    // finished flush as soon as it is ready ("1"/"true"/"on"); ingest role,
    // default off.
    "NANO_LAKE_INGEST_FLUSH_DEPTH",
    "NANO_LAKE_INGEST_COMMIT_WHEN_READY",
    // parts/refusal_tally.rs (NAN-3662): each part-log `reject` detail
    // starts with the refused rows per source lane, read by query[T]'s
    // `/v1/ingest/refusals`; ingest role; "1"/"true"/"on", default off. The
    // tag lives in the existing bounded detail, so every part-log reader
    // accepts it; until it is on, lean refusals count on the default source.
    "NANO_LAKE_REFUSAL_SOURCE_COUNTS",
    // producer_cache.rs (NAN-3610 indexed producer tier; ingest writer and
    // query fetch; "1"/"true"/"on" enables, default off)
    "NANO_LAKE_PRODUCER_CACHE_INDEX",
    // Query-path kill switches, all default on; "0" disables:
    // executor.rs (NAN-3168 bounded chDB parsing pool),
    "NANO_LAKE_BOUND_PARSING_THREADS",
    // part_query/engine.rs (fine run cost, payload at instants, resident
    // in-file blooms, density over selective),
    "NANO_LAKE_FINE_RUN_COST",
    "NANO_LAKE_PAYLOAD_AT_INSTANTS",
    "NANO_LAKE_RESIDENT_INFILE_BLOOMS",
    "NANO_LAKE_DENSITY_OVER_SELECTIVE",
    // part_query/density.rs (density seed; "0"/"false"),
    "NANO_LAKE_DENSITY_SEED",
    // planner.rs (fence set, full-event locator).
    "NANO_LAKE_FENCE_SET",
    "NANO_LAKE_FULL_EVENT_LOCATOR",
    // part_query/product_state.rs and product_publish.rs (NAN-3168 product
    // state build threads / step bytes / leaf hours and per-window rebuild
    // intervals; product[T] and query[T]; unset keeps the defaults)
    "NANO_LAKE_PRODUCT_STATE_THREADS",
    "NANO_LAKE_PRODUCT_STATE_STEP_BYTES",
    "NANO_LAKE_PRODUCT_STATE_LEAF_HOURS",
    "NANO_LAKE_PRODUCT_STATE_REBUILD_1H_SECS",
    "NANO_LAKE_PRODUCT_STATE_REBUILD_24H_SECS",
    "NANO_LAKE_PRODUCT_STATE_REBUILD_7D_SECS",
    "NANO_LAKE_PRODUCT_STATE_REBUILD_30D_SECS",
    // process_limits.rs boot budget for every lake binary: descriptor soft
    // limit (default 65536, capped by the hard limit) and the vendored
    // iceberg-storage-opendal manifest fetch concurrency (default 64).
    "NANO_LAKE_NOFILE_SOFT",
    "NANO_LAKE_MANIFEST_FETCH_CONCURRENCY",
    // report.rs (NAN-3522): the status push carries each placed tenant's
    // ingest committed-row counter (`ingest`). Read by the supervisor; "1"
    // enables, default off: the platform's strict status schema must accept the
    // field first (the platform).
    "NANO_LAKE_CELL_INGEST_COUNTERS",
];

/// NAN-3522: whether status pushes carry the per-tenant ingest counters.
pub(crate) fn ingest_counters_enabled() -> bool {
    std::env::var("NANO_LAKE_CELL_INGEST_COUNTERS").is_ok_and(|v| matches!(v.as_str(), "1" | "true"))
}

/// NAN-3164: `Some(reason)` while a query process that is otherwise ready
/// still hydrates its warm hours and the gate applies. An older query image
/// (no `hot_window_warm` field) is warm as before.
fn hot_window_pending(status: &serde_json::Value, gate_applies: bool) -> Option<String> {
    if !gate_applies || status["hot_window_warm"] != false {
        return None;
    }
    let c = &status["local_hot_window"];
    Some(format!(
        "local hot window hydrating: {}h of {}h warm hours, {}/{} parts, rate {:.1} MB/s",
        c["effective_hours"].as_f64().map_or("?".into(), |h| format!("{h:.1}")),
        c["warm_hours"].as_u64().map_or("?".into(), |h| h.to_string()),
        c["local_parts"].as_u64().unwrap_or(0),
        c["selected_parts"].as_u64().unwrap_or(0),
        c["rate_bytes_per_second"].as_f64().unwrap_or(0.0) / 1e6,
    ))
}

fn feature_allowed_for_role(name: &str, role: Role) -> bool {
    role == Role::Query || !name.starts_with("NANO_LAKE_LOCAL_HOT_WINDOW")
}

fn local_hot_window_enabled() -> bool {
    std::env::var("NANO_LAKE_LOCAL_HOT_WINDOW").is_ok_and(|v| matches!(v.as_str(), "1" | "true"))
}

/// NAN-3647: `<NANO_LAKE_LOCAL_HOT_WINDOW_DIR>/tenants` when the hot window
/// lives outside the data volume (the A/B hot volumes). Tenant trees there
/// outlive the pod, so the purge must cover them like the data dir's.
fn external_hot_tenants_dir() -> Option<PathBuf> {
    local_hot_window_enabled()
        .then(|| std::env::var_os("NANO_LAKE_LOCAL_HOT_WINDOW_DIR"))
        .flatten()
        .map(|base| PathBuf::from(base).join("tenants"))
        .filter(|dir| dir.is_absolute())
}

/// NAN-3799: where product[T] publishes for `tenant`. On the persistent
/// A/B hot volume (NAN-3647) the published windows outlive the pod, so a
/// rolled cell serves them at once instead of answering
/// `product_state_warming` until every window is rebuilt (tenant-a 7d: 1,245 s).
/// Each pod mounts its own PVC of the pair, so one product[T] writes a
/// volume; every file is content-addressed and the manifest is renamed
/// into place. Otherwise: the data volume's `<T>/product` (unchanged).
pub(crate) fn product_dir_for(data_tenant_root: &Path, tenant: &str, persistent_hot_tenants: Option<&Path>) -> PathBuf {
    match persistent_hot_tenants {
        Some(hot) => hot.join(tenant).join(Role::Product.as_str()),
        None => data_tenant_root.join(Role::Product.as_str()),
    }
}

/// NAN-4183: where ingest[T]'s lake-part GC keeps its folded part-log view:
/// ingest[T]'s own directory of its tree on the persistent A/B hot volume
/// (created by the hot tree with the ingest uid, 0700), so a rolled pod
/// resumes the view instead of refolding the log from seq 0. None without a
/// persistent hot volume: the GC keeps it in the (per-pod) state dir.
pub(crate) fn part_gc_state_dir_for(tenant: &str, persistent_hot_tenants: Option<&Path>) -> Option<PathBuf> {
    persistent_hot_tenants.map(|hot| hot.join(tenant).join(Role::Ingest.as_str()))
}

/// NAN-3799: [`external_hot_tenants_dir`] when that volume is persistent.
fn persistent_hot_tenants_dir() -> Option<PathBuf> {
    external_hot_tenants_dir().filter(|_| {
        std::env::var("NANO_LAKE_LOCAL_HOT_WINDOW_PERSISTENT").is_ok_and(|v| matches!(v.as_str(), "1" | "true"))
    })
}

/// NAN-3875: where the tenant uid map lives. Tenant-owned files must never
/// outlive the map that says whose they are: with a persistent A/B hot
/// volume (the state dir is per-pod ephemeral under a zero-downtime roll)
/// the map lives ON that volume, in a supervisor-private 0700 directory
/// beside `tenants/` (no tenant role is granted any path there). Otherwise
/// the state dir, which then shares the data volume's lifetime.
pub(crate) fn uid_map_path(state_dir: &Path, persistent_hot_base: Option<&Path>) -> PathBuf {
    match persistent_hot_base {
        Some(base) => base.join(UID_MAP_HOT_DIR).join("uids.json"),
        None => state_dir.join("uids.json"),
    }
}

/// NAN-3875: the supervisor-private directory on the hot volume (0700,
/// supervisor-owned; no tenant role is granted any path in it).
pub(crate) const UID_MAP_HOT_DIR: &str = "cell-supervisor";

/// NAN-3875: where conflicting rebuildable hot trees are moved before their
/// purge: `<hot base>/cell-supervisor/quarantine` (same filesystem as
/// `<hot base>/tenants`, so the move is a rename).
fn hot_quarantine_dir() -> Option<PathBuf> {
    external_hot_tenants_dir().and_then(|t| t.parent().map(|b| b.join(UID_MAP_HOT_DIR).join("quarantine")))
}

/// Load the uid map from [`uid_map_path`] (a corrupt one is moved aside, not
/// fatal) and record every tenant tree's on-disk ownership as a claim, so
/// allocation follows the disk, never first-touch order (NAN-3875, r56).
/// Also prepares (and sweeps) the hot-volume quarantine.
fn load_uid_map(cfg: &CellConfig, euid: u32, egid: u32) -> anyhow::Result<UidMap> {
    let hot_base = persistent_hot_tenants_dir().and_then(|t| t.parent().map(Path::to_path_buf));
    let path = uid_map_path(&cfg.state_dir, hot_base.as_deref());
    if let Some(dir) = path.parent().filter(|_| hot_base.is_some()) {
        ensure_dir(dir, euid, egid, 0o700)?;
    }
    if let Some(q) = hot_quarantine_dir() {
        if let Some(parent) = q.parent() {
            std::fs::create_dir_all(parent.parent().unwrap_or(parent))?;
            ensure_dir(parent, euid, egid, 0o700)?;
        }
        ensure_dir(&q, euid, egid, 0o700)?;
        match crate::tenant_dirs::sweep_quarantine(&q) {
            Ok(0) => {}
            Ok(n) => tracing::info!(swept = n, "purged quarantined hot trees left by an earlier boot"),
            Err(error) => tracing::warn!(%error, "hot quarantine sweep failed; leftovers stay unreachable"),
        }
    }
    let (mut map, aside) = UidMap::load_or_recover(&path, cfg.uid_base, cfg.uid_slots)?;
    let roots = purge_roots(&cfg.data_dir.join("tenants"), external_hot_tenants_dir().as_deref());
    let observed = UidMap::observe_trees(&roots)?;
    let unclaimed = map.set_disk_claims(&observed);
    for t in &unclaimed {
        tracing::warn!(tenant = %t, "tenant tree ownership names no single uid slot (half-walked, or volumes disagree); its tenant gets a slot no tree claims");
    }
    tracing::info!(path = %path.display(), tenants = map.all().len(), trees = observed.len(), unclaimed = unclaimed.len(),
        recovered_from = ?aside, "tenant uid map loaded");
    Ok(map)
}

/// NAN-3875: ensure a REBUILDABLE tenant tree (the hot-window volume). If
/// part of it is owned by another placed tenant, move it out of reach,
/// purge it, and recreate it fresh: there is nothing in it that cannot be
/// re-fetched or rebuilt (NAN-3647 reader cache, NAN-3799 product windows),
/// so no operator step and no refusal. Without a quarantine dir: refuse.
pub(crate) fn ensure_rebuildable_tree(tenants: &Path, tenant: &str, ids: &TenantIds,
    foreign: &std::collections::BTreeSet<u32>, quarantine: Option<&Path>) -> std::io::Result<()> {
    match crate::tenant_dirs::ensure_tenant_tree_guarded(tenants, tenant, ids, foreign) {
        Err(e) if crate::tenant_dirs::is_foreign_owner(&e) => {
            let Some(q) = quarantine else { return Err(e) };
            tracing::warn!(tenant, error = %e, "hot tree owned by another placed tenant; rebuilding it");
            match crate::tenant_dirs::quarantine_tenant_tree(tenants, tenant, q) {
                Ok(_) => {}
                // Moved but not (fully) purged: unreachable, swept next boot.
                Err(pe) if !crate::tenant_dirs::tenant_tree_present(tenants, tenant).unwrap_or(true) =>
                    tracing::warn!(tenant, error = %pe, "quarantined hot tree not fully purged; left for the next sweep"),
                Err(pe) => return Err(pe),
            }
            crate::tenant_dirs::ensure_tenant_tree_guarded(tenants, tenant, ids, foreign)
        }
        other => other,
    }
}

/// NAN-3647: every directory holding tenant trees: the data dir's, then the
/// external hot window's (if any).
pub(crate) fn purge_roots(data_tenants: &Path, hot_tenants: Option<&Path>) -> Vec<PathBuf> {
    std::iter::once(data_tenants.to_path_buf())
        .chain(hot_tenants.filter(|hot| *hot != data_tenants).map(Path::to_path_buf))
        .collect()
}

fn forward_feature_env(
    cmd: &mut tokio::process::Command,
    lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
) {
    for name in FEATURE_ENV {
        if let Some(value) = lookup(name) {
            cmd.env(name, value);
        }
    }
}

/// Exercise the same forwarding path without mutating the test process environment.
#[cfg(test)]
pub(crate) fn feature_env_is_isolated() -> bool {
    let mut cmd = tokio::process::Command::new("/usr/bin/env");
    cmd.env_clear();
    forward_feature_env(&mut cmd, |name| Some(format!("test-{name}").into()));
    let Ok(output) = cmd.as_std_mut().output() else { return false; };
    let Ok(output) = String::from_utf8(output.stdout) else { return false; };
    let mut actual = output.lines().collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = FEATURE_ENV.iter().map(|name| format!("{name}=test-{name}")).collect::<Vec<_>>();
    expected.sort_unstable();
    !output.is_empty() && actual == expected && cmd.as_std().get_envs().count() == FEATURE_ENV.len()
}

#[cfg(test)]
mod feature_env_tests {
    #[test]
    fn hot_window_is_forwarded_only_to_query_role() {
        for name in super::FEATURE_ENV.iter().filter(|name| name.starts_with("NANO_LAKE_LOCAL_HOT_WINDOW")) {
            assert!(super::feature_allowed_for_role(name, super::Role::Query));
            for role in [super::Role::Ingest, super::Role::Detect, super::Role::Maintenance] {
                assert!(!super::feature_allowed_for_role(name, role));
            }
        }
        assert!(super::feature_allowed_for_role("NANO_LAKE_PARQUET_RANGE_WRITE", super::Role::Ingest));
        assert!(super::FEATURE_ENV.contains(&"NANO_LAKE_ENTITY_COUNT_WRITE"));
        assert!(super::feature_allowed_for_role("NANO_LAKE_ENTITY_COUNT_WRITE", super::Role::Ingest));
    }

    /// NAN-3808: open core runs the entity count and locator writers by
    /// default, like hosted cells. The compose lake-cell service defaults both
    /// to "1" and still lets `.env` override them. The supervisor must
    /// forward both to ingest[T].
    #[test]
    fn open_core_compose_turns_entity_writers_on() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docker-compose.opensource.yml");
        let compose = std::fs::read_to_string(&path).unwrap();
        let start = compose.find("\n  lake-cell:\n").expect("lake-cell service");
        // The service block runs until the next two-space-indented key.
        let body = &compose[start + 1..];
        let end = body.match_indices('\n').map(|(i, _)| i + 1)
            .find(|&i| body[i..].starts_with("  ") && !body[i..].starts_with("   "))
            .unwrap_or(body.len());
        let service = &body[..end];
        for name in ["NANO_LAKE_ENTITY_COUNT_WRITE", "NANO_LAKE_ENTITY_LOCATOR_WRITE"] {
            assert!(service.contains(&format!("      {name}: ${{{name}:-1}}\n")), "{name} default in lake-cell:\n{service}");
            assert!(super::FEATURE_ENV.contains(&name));
            assert!(super::feature_allowed_for_role(name, super::Role::Ingest));
        }
    }

    /// NAN-3647: the purge covers the external (persistent) hot-window tree
    /// too, and never lists one directory twice.
    #[test]
    fn purge_roots_include_the_external_hot_volume() {
        use std::path::{Path, PathBuf};
        let data = Path::new("/var/lib/nano-cell/data/tenants");
        assert_eq!(super::purge_roots(data, None), vec![data.to_path_buf()]);
        assert_eq!(super::purge_roots(data, Some(data)), vec![data.to_path_buf()]);
        let hot = Path::new("/var/lib/nano-cell-hot/tenants");
        assert_eq!(super::purge_roots(data, Some(hot)), vec![data.to_path_buf(), PathBuf::from(hot)]);
    }

    #[test]
    fn hot_window_pending_gates_only_when_applicable() {
        use serde_json::json;
        let hydrating = json!({"ready": true, "hot_window_warm": false,
            "local_hot_window": {"effective_hours": 3.5, "warm_hours": 24, "local_parts": 7, "selected_parts": 85,
                "rate_bytes_per_second": 33.0e6}});
        let reason = super::hot_window_pending(&hydrating, true).unwrap();
        assert!(reason.contains("3.5h of 24h") && reason.contains("7/85") && reason.contains("33.0 MB/s"), "{reason}");
        assert_eq!(super::hot_window_pending(&hydrating, false), None, "lone pod never waits");
        assert_eq!(super::hot_window_pending(&json!({"ready": true, "hot_window_warm": true}), true), None);
        // Older query image, or hot window off: unchanged behavior.
        assert_eq!(super::hot_window_pending(&json!({"ready": true}), true), None);
    }

    /// Why a NANO_LAKE_* name the child crates mention is NOT forwarded.
    const CREDENTIAL: &str = "credential or key material: a child gets tenant-scoped keys only through the sealed bootstrap memfd";
    const IDENTITY: &str = "tenant identity comes from the assignment; inheriting it from the cell env would cross tenants";
    const PATH: &str = "host path: a child's files come from its assignment and jail, never from the cell env";
    const OTHER_BINARY: &str = "read only by other lake-worker binaries (gen1 worker, job runner, generation/bronze/bootstrap tools), never by lake_part_ingest or lake_part_query";
    const CORE_SERVICE: &str = "nanosiem-core API/search/worker-release side (a client of the cell), not on a cell child's path";
    const NO_RUNTIME_READER: &str = "no production reader: ReaderObjectCacheSettings::from_env has no caller";
    const TEST_ONLY: &str = "test, lab or bench harness only";
    const SUPERVISOR_ONLY: &str = "read by the supervisor itself, not by a child";

    /// NAN-3683: every NANO_LAKE_* name the child crates mention that is not
    /// in FEATURE_ENV, with the reason. Adding a child env read means adding
    /// it to FEATURE_ENV (a rollout knob) or here (with why it must not be).
    const NOT_FORWARDED: &[(&str, &str)] = &[
        ("NANO_LAKE_ACCESS_KEY", CREDENTIAL),
        ("NANO_LAKE_ACCESS_KEY_ID", CREDENTIAL),
        ("NANO_LAKE_SECRET_ACCESS_KEY", CREDENTIAL),
        ("NANO_LAKE_CELL_JOB_SPEC_KEY_FILE", CREDENTIAL),
        ("NANO_LAKE_CELL_ROUTER_TENANT_KEY_FILE", CREDENTIAL),
        ("NANO_LAKE_CELL_ROUTER_TOKEN_FILE", CREDENTIAL),
        // The control plane's lean-assignment probe token (nanosiem-core
        // parser rollout observation, enterprise shared_assignment_generation).
        ("NANO_LAKE_CELL_ROUTER_QUERY_TOKEN_FILE", CREDENTIAL),
        ("NANO_LAKE_ENRICHMENT_COORDINATOR_TOKEN_FILE", CREDENTIAL),
        ("NANO_LAKE_HOT_TAIL_DISK_CACHE_KEY_FILE", CREDENTIAL),
        ("NANO_LAKE_JOB_SIGNING_KEY_FILE", CREDENTIAL),
        ("NANO_LAKE_QUERY_TOKEN_FILE", CREDENTIAL),
        ("NANO_LAKE_SCHEMA_TOKEN_FILE", CREDENTIAL),
        ("NANO_LAKE_RESULT_S3_ACCESS_KEY_ID", CREDENTIAL),
        ("NANO_LAKE_RESULT_S3_SECRET_ACCESS_KEY", CREDENTIAL),
        ("NANO_LAKE_RESULT_S3_SESSION_TOKEN", CREDENTIAL),
        ("NANO_LAKE_RESULT_S3_DEFAULT_CREDENTIALS", CREDENTIAL),
        ("NANO_LAKE_SHARED_R2_READ_ACCESS_KEY_ID", CREDENTIAL),
        ("NANO_LAKE_SHARED_R2_READ_SECRET_ACCESS_KEY", CREDENTIAL),
        ("NANO_LAKE_SHARED_R2_READ_SESSION_TOKEN", CREDENTIAL),
        ("NANO_LAKE_SHARED_CACHE_ENCRYPTION_KEY_ID", CREDENTIAL),
        ("NANO_LAKE_SHARED_CACHE_ENCRYPTION_KEY_REVISION", CREDENTIAL),
        ("NANO_LAKE_SHARED_CACHE_ENCRYPTION_PROVIDER", CREDENTIAL),
        ("NANO_LAKE_TENANT_ID", IDENTITY),
        ("NANO_LAKE_PLATFORM_POLICY_FILE", PATH),
        ("NANO_LAKE_AUTHORITATIVE_STATE_STORE", OTHER_BINARY),
        ("NANO_LAKE_BRONZE_BUCKET", OTHER_BINARY), // lake_landing_ingest (NAN-3807), its own compose service
        ("NANO_LAKE_BRONZE_FULL_RECONCILIATION_SECONDS", OTHER_BINARY),
        ("NANO_LAKE_BRONZE_RECLAIM_REPORT_ONLY", OTHER_BINARY),
        ("NANO_LAKE_BRONZE_RETENTION_HOURS", OTHER_BINARY),
        ("NANO_LAKE_BUILD_MEMORY_BYTES", OTHER_BINARY),
        ("NANO_LAKE_BUNDLE_PUBLISH_CONCURRENCY", OTHER_BINARY),
        ("NANO_LAKE_DERIVATIVE_CACHE_BYTES", OTHER_BINARY),
        ("NANO_LAKE_DERIVATIVE_CACHE_DIR", OTHER_BINARY),
        ("NANO_LAKE_DERIVATIVE_TIER_STORE", OTHER_BINARY),
        ("NANO_LAKE_DERIVATIVE_TIER_URL", OTHER_BINARY),
        ("NANO_LAKE_FRESHNESS_NOTICE_MIN_LAG_MS", OTHER_BINARY),
        ("NANO_LAKE_HANDOVER_LISTEN", OTHER_BINARY),
        ("NANO_LAKE_HANDOVER_PEERS", OTHER_BINARY),
        ("NANO_LAKE_HANDOVER_STREAMS", OTHER_BINARY),
        ("NANO_LAKE_HANDOVER_TABLE_UUID", OTHER_BINARY),
        ("NANO_LAKE_HOSTED_COORDINATOR_CONFIG", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_CACHE_BYTES", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_CACHE_DIR", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_CACHE_SCHEMA_V4", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_DISK_CACHE_BYTES", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_DISK_CACHE_DIR", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_DISK_CACHE_ENCRYPTION", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_PUBLICATION_HEALTH", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_QUERY_SLOW_PATH_BYTES", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_SLOW_PATH_CONCURRENCY", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_SLOW_PATH_TIMEOUT_SECONDS", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_STAGING_BYTES", OTHER_BINARY),
        ("NANO_LAKE_HOT_TAIL_STAGING_DIR", OTHER_BINARY),
        ("NANO_LAKE_JOB_RESULT_ROOT", OTHER_BINARY),
        ("NANO_LAKE_OBJECT_ENDPOINT", OTHER_BINARY), // lake_landing_ingest (NAN-3807), its own compose service
        ("NANO_LAKE_QUERY_COMPILER_PATH", OTHER_BINARY),
        ("NANO_LAKE_READER_PEERS", OTHER_BINARY),
        ("NANO_LAKE_RESULT_S3_ENDPOINT", OTHER_BINARY),
        ("NANO_LAKE_RESULT_S3_REGION", OTHER_BINARY),
        ("NANO_LAKE_RESULT_S3_VIRTUAL_HOST_STYLE", OTHER_BINARY),
        ("NANO_LAKE_RUNNER_DRAIN_SECONDS", OTHER_BINARY),
        ("NANO_LAKE_RUNNER_PIN_BOUNCE_SECONDS", OTHER_BINARY),
        ("NANO_LAKE_SERVING_CANARY", OTHER_BINARY),
        ("NANO_LAKE_SHARED_CACHE_CELL_BYTES", OTHER_BINARY),
        ("NANO_LAKE_SHARED_R2_CACHE_PURGE_EPOCH", OTHER_BINARY),
        ("NANO_LAKE_SHARED_R2_READ_BUCKET", OTHER_BINARY),
        ("NANO_LAKE_SHARED_R2_READ_CREDENTIAL_BUCKET", OTHER_BINARY),
        ("NANO_LAKE_SHARED_R2_READ_CREDENTIAL_MODE", OTHER_BINARY),
        ("NANO_LAKE_SHARED_R2_READ_ENDPOINT", OTHER_BINARY),
        ("NANO_LAKE_SHARED_R2_READ_REGION", OTHER_BINARY),
        ("NANO_LAKE_SHARED_R2_READ_VIRTUAL_HOST_STYLE", OTHER_BINARY),
        ("NANO_LAKE_SHUTDOWN_DRAIN_SECONDS", OTHER_BINARY),
        ("NANO_LAKE_SHUTDOWN_INFLIGHT_SECONDS", OTHER_BINARY),
        ("NANO_LAKE_TAIL_STALENESS_BUDGET_MS", OTHER_BINARY),
        ("NANO_LAKE_VERIFY_WORKERS", OTHER_BINARY),
        ("NANO_LAKE_WORKER_ASSIGNMENT_ID", OTHER_BINARY),
        ("NANO_LAKE_WORKER_ASSIGNMENT_REVISION", OTHER_BINARY),
        ("NANO_LAKE_ASSET_IN_PREDICATE", CORE_SERVICE),
        ("NANO_LAKE_BATCH_MAX_BYTES", CORE_SERVICE),
        ("NANO_LAKE_BATCH_MAX_EVENTS", CORE_SERVICE),
        ("NANO_LAKE_BATCH_TIMEOUT_SECS", CORE_SERVICE),
        ("NANO_LAKE_BRONZE_SHARDS", CORE_SERVICE),
        ("NANO_LAKE_CELL_ROUTES_FILE", CORE_SERVICE),
        ("NANO_LAKE_ENRICHMENT_COORDINATOR_URL", CORE_SERVICE),
        ("NANO_LAKE_EVENT_TABLE_LOCATION_PREFIX", CORE_SERVICE),
        ("NANO_LAKE_IDENTITY_SNAPSHOT", CORE_SERVICE),
        ("NANO_LAKE_IDENTITY_TIMEOUT_SECS", CORE_SERVICE),
        ("NANO_LAKE_IOC_SNAPSHOT_ID", CORE_SERVICE),
        ("NANO_LAKE_IOC_TIMEOUT_SECS", CORE_SERVICE),
        ("NANO_LAKE_LEAN_ENRICHMENT_ASSIGNMENTS_FILE", CORE_SERVICE),
        ("NANO_LAKE_PART_DELETE_ENABLED", CORE_SERVICE),
        ("NANO_LAKE_PREVALENCE_RARITY_THRESHOLD", CORE_SERVICE),
        ("NANO_LAKE_PREVALENCE_SNAPSHOT_1H", CORE_SERVICE),
        ("NANO_LAKE_PREVALENCE_SNAPSHOT_24H", CORE_SERVICE),
        ("NANO_LAKE_PREVALENCE_SNAPSHOT_7D", CORE_SERVICE),
        ("NANO_LAKE_PREVALENCE_SNAPSHOT_30D", CORE_SERVICE),
        ("NANO_LAKE_PREVALENCE_TIMEOUT_SECS", CORE_SERVICE),
        ("NANO_LAKE_QUERY_TIMEOUT_SECS", CORE_SERVICE),
        ("NANO_LAKE_QUERY_URL", CORE_SERVICE),
        ("NANO_LAKE_SCHEMA_MANIFEST", CORE_SERVICE),
        ("NANO_LAKE_SHARED_WORKER_REGISTRY_FILE", CORE_SERVICE),
        ("NANO_LAKE_SINK_STATIC_AUTH", CORE_SERVICE),
        ("NANO_LAKE_WORKER_CONFIG", CORE_SERVICE),
        ("NANO_LAKE_READER_CACHE_BYTES", NO_RUNTIME_READER),
        ("NANO_LAKE_READER_CACHE_DIR", NO_RUNTIME_READER),
        ("NANO_LAKE_READER_CACHE_FETCH_CONCURRENCY", NO_RUNTIME_READER),
        ("NANO_LAKE_READER_CACHE_FETCH_TIMEOUT_SECONDS", NO_RUNTIME_READER),
        ("NANO_LAKE_READER_CACHE_MODE", NO_RUNTIME_READER),
        ("NANO_LAKE_READER_CACHE_QUERY_BYTES", NO_RUNTIME_READER),
        ("NANO_LAKE_COMPILER", TEST_ONLY),
        ("NANO_LAKE_MANIFEST_COST_FIXTURE", TEST_ONLY),
        ("NANO_LAKE_VOLUME_USAGE_REWALK_SECONDS", SUPERVISOR_ONLY),
    ];

    /// Source trees linked into lake_part_ingest / lake_part_query (the
    /// child binaries), relative to this crate.
    const CHILD_SOURCE_ROOTS: &[&str] = &[
        "src",
        "../nanosiem-lake-worker/src",
        "../nanosiem-core/src",
        "../vendor/iceberg/src",
        "../vendor/iceberg-storage-opendal/src",
        "../vendor/slatedb/src",
    ];

    /// Every complete `"NANO_LAKE_*"` string literal under `CHILD_SOURCE_ROOTS`.
    fn child_env_names() -> std::collections::BTreeSet<String> {
        fn walk(dir: &std::path::Path, out: &mut std::collections::BTreeSet<String>) {
            let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let source = std::fs::read_to_string(&path).unwrap();
                    for (start, _) in source.match_indices("\"NANO_LAKE_") {
                        let rest = &source[start + 1..];
                        let Some(end) = rest.find('"') else { continue };
                        let name = &rest[..end];
                        if !name.ends_with('_') && name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
                            out.insert(name.to_string());
                        }
                    }
                }
            }
        }
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut names = std::collections::BTreeSet::new();
        for root in CHILD_SOURCE_ROOTS {
            walk(&crate_dir.join(root), &mut names);
        }
        names
    }

    /// NAN-3683 drift guard: a knob a child reads but the supervisor drops
    /// is silently a no-op on every cell (NAN-3619/NAN-3610 flags were).
    #[test]
    fn every_child_env_name_is_forwarded_or_excluded_with_a_reason() {
        let names = child_env_names();
        assert!(names.contains("NANO_LAKE_INGEST_FLUSH_DEPTH"), "the scan must see the child crates");
        let excluded: std::collections::BTreeMap<_, _> = NOT_FORWARDED.iter().copied().collect();
        assert_eq!(excluded.len(), NOT_FORWARDED.len(), "NOT_FORWARDED has duplicates");
        let unaccounted: Vec<_> = names.iter()
            .filter(|name| !super::FEATURE_ENV.contains(&name.as_str()) && !excluded.contains_key(name.as_str()))
            .collect();
        assert!(unaccounted.is_empty(),
            "child crates read NANO_LAKE_* names the supervisor neither forwards nor excludes: {unaccounted:?}; \
             add each to FEATURE_ENV (rollout knob) or NOT_FORWARDED (with the reason)");
        for (name, reason) in NOT_FORWARDED {
            assert!(!super::FEATURE_ENV.contains(name), "{name} is both forwarded and excluded");
            assert!(names.contains(*name), "{name} is excluded but no child crate mentions it any more; drop it");
            assert!(!reason.is_empty());
        }
        let mut forwarded = super::FEATURE_ENV.to_vec();
        forwarded.sort_unstable();
        forwarded.dedup();
        assert_eq!(forwarded.len(), super::FEATURE_ENV.len(), "FEATURE_ENV has duplicates");
    }

    /// NAN-3619 / NAN-3610: the ingest pipelining and producer cache index
    /// flags reach the child (they were dropped before).
    #[test]
    fn ingest_pipelining_and_producer_cache_flags_are_forwarded() {
        for name in ["NANO_LAKE_INGEST_FLUSH_DEPTH", "NANO_LAKE_INGEST_COMMIT_WHEN_READY", "NANO_LAKE_PRODUCER_CACHE_INDEX"] {
            assert!(super::FEATURE_ENV.contains(&name), "{name}");
            for role in [super::Role::Ingest, super::Role::Query] {
                assert!(super::feature_allowed_for_role(name, role), "{name} {role:?}");
            }
        }
    }

    /// NAN-3662: the lean per-source refusal tag reaches ingest[T].
    #[test]
    fn refusal_source_counts_flag_is_forwarded_to_ingest() {
        assert!(super::FEATURE_ENV.contains(&"NANO_LAKE_REFUSAL_SOURCE_COUNTS"));
        assert!(super::feature_allowed_for_role("NANO_LAKE_REFUSAL_SOURCE_COUNTS", super::Role::Ingest));
    }

    #[test]
    fn allowlisted_feature_env_reaches_child_only() {
        assert!(super::feature_env_is_isolated());
        let mut cmd = tokio::process::Command::new("/usr/bin/env");
        cmd.env_clear();
        super::forward_feature_env(&mut cmd, |_| None);
        assert!(cmd.as_std_mut().output().unwrap().stdout.is_empty());
    }
}

use crate::budget::TenantBudget;
use crate::config::{CellConfig, CgroupPolicy, IngestMode, Placement, TenantPlacement};
use crate::contract::{ROLES, 
    Assignment, Heartbeat, JailSpec, Role, TenantId, ToChild, ToSupervisor, WakeReason, CONTROL_FD,
    CONTROL_FD_FLAG, HEARTBEAT_INTERVAL_MAX, PROTOCOL_VERSION,
};
use crate::fdpass::{self, AsyncSeqpacket};
use crate::identity::IdentityReport;
use crate::limits::{self, CgroupTree, DelegationCheck, LimitsMode, TenantUsage};
use crate::pidfd::PidFd;
use crate::resources::{
    CellCapacity, CellResourceView, EventKind, KillReason, LimitEvent, TenantLimits, TenantResourceView,
};
use crate::procfs::{self, ProcKey};
use crate::spawn_flight::{FlightError, Progress, RoleLock, SpawnFlight, LOCK_WAIT_LOG_EVERY};
use crate::watchdog::{kill_all, Monitor, TenantSpec};
use crate::secrets::KeySource;
use crate::signals::Signal;
use crate::uidmap::{TenantIds, UidMap};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, thiserror::Error)]
pub enum CellError {
    #[error("tenant {0} is not placed on this cell")]
    NotPlaced(TenantId),
    #[error("spawn failed: {0}")]
    Spawn(String),
    #[error("tenant process unavailable: {0}")]
    Unavailable(String),
    /// Zero-downtime roll (NAN-3004): the tenant's writer runs on another
    /// pod of this cell, or this pod is draining. Retryable.
    #[error("writer standby: {0}")]
    Standby(String),
    /// The control plane refused this role's bootstrap token; the role is in
    /// spawn backoff until `retry_after_secs` (see `role_spawn_blocked`).
    #[error("{} spawn blocked: control plane refused its bootstrap token ({status} {code}); retry in {retry_after_secs}s", role.as_str())]
    SpawnBlocked { role: Role, status: u16, code: String, retry_after_secs: u64 },
    /// NAN-3523: a pooled cell without kernel limits starts no tenant
    /// process. Retryable (the upstream queues); clears once delegation is
    /// adopted.
    #[error("pooled cell admission refused: tenant limits are not kernel-enforced ({reason}); retry in {retry_after_secs}s")]
    AdmissionRefused { reason: String, retry_after_secs: u64 },
    /// NAN-3523: the tenant's local tree is over its soft disk ceiling; no
    /// new ingest work until it is back under. Retryable: the raw-handoff
    /// DO keeps the backlog.
    #[error("tenant disk pressure: {bytes} bytes over the {soft_bytes}-byte soft ceiling; ingest not admitted")]
    DiskPressure { bytes: u64, soft_bytes: u64, retry_after_secs: u64 },
    /// NAN-4128: the role's spawn did not finish in time. `still_running`:
    /// this caller stopped waiting but the attempt continues (a retry joins
    /// it); otherwise the attempt hit its deadline at `step` and was torn
    /// down. Retryable.
    #[error("{} spawn {} at step {step} after {secs}s", role.as_str(), if *still_running { "still in progress" } else { "timed out" })]
    SpawnTimedOut { role: Role, step: &'static str, secs: u64, still_running: bool },
}

/// Backoff for a role whose bootstrap-token mint the control plane refused.
/// A 4xx is policy (a fact or grant must change): it backs off to
/// [`SPAWN_BLOCKED_POLICY_MAX`]; a 5xx is transient and caps lower. A
/// `Retry-After` is honoured up to [`SPAWN_BLOCKED_RETRY_AFTER_MAX`].
const SPAWN_BLOCKED_BASE: Duration = Duration::from_secs(2);
const SPAWN_BLOCKED_POLICY_MAX: Duration = Duration::from_secs(120);
const SPAWN_BLOCKED_TRANSIENT_MAX: Duration = Duration::from_secs(60);
const SPAWN_BLOCKED_RETRY_AFTER_MAX: Duration = Duration::from_secs(600);
/// A role blocked this long pages (`role_spawn_blocked` signal).
const SPAWN_BLOCKED_PAGE: Duration = Duration::from_secs(900);

/// Why a role of a tenant cannot start: the control plane's refusal of its
/// bootstrap token, kept until a spawn of that role succeeds.
#[derive(Debug, Clone)]
struct SpawnBlock {
    status: u16,
    code: String,
    missing: Option<String>,
    since: Instant,
    since_unix_ms: u64,
    attempts: u32,
    not_before: Instant,
}

impl SpawnBlock {
    /// Fold one more refusal in; returns whether the code changed (log it).
    fn refused(prev: Option<&SpawnBlock>, r: &crate::secrets::MintRefused, now: Instant) -> (SpawnBlock, bool) {
        let attempts = prev.map_or(1, |p| p.attempts.saturating_add(1));
        let max = if r.is_policy() { SPAWN_BLOCKED_POLICY_MAX } else { SPAWN_BLOCKED_TRANSIENT_MAX };
        let exp = attempts.saturating_sub(1).min(16);
        let mut wait = SPAWN_BLOCKED_BASE.saturating_mul(1u32 << exp).min(max);
        if let Some(ra) = r.retry_after {
            wait = wait.max(ra.min(SPAWN_BLOCKED_RETRY_AFTER_MAX));
        }
        let changed = prev.is_none_or(|p| p.code != r.code || p.status != r.status);
        let (since, since_unix_ms) = match prev {
            Some(p) if !changed => (p.since, p.since_unix_ms),
            _ => (now, now_ms()),
        };
        (SpawnBlock { status: r.status, code: r.code.clone(), missing: r.missing.clone(), since, since_unix_ms, attempts,
            not_before: now + wait }, changed)
    }

    fn view(&self, role: Role, now: Instant) -> RoleSpawnBlocked {
        RoleSpawnBlocked {
            role,
            reason: self.code.clone(),
            http_status: self.status,
            missing: self.missing.clone(),
            since_unix_ms: self.since_unix_ms,
            blocked_secs: now.saturating_duration_since(self.since).as_secs(),
            attempts: self.attempts,
            retry_in_secs: self.not_before.saturating_duration_since(now).as_secs(),
        }
    }
}

/// `role_spawn_blocked{role,reason}` in the tenant status: a role the
/// control plane will not start, and its refusal code.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RoleSpawnBlocked {
    pub role: Role,
    /// The control plane's refusal code, e.g. `detect_drain_disabled`.
    pub reason: String,
    pub http_status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing: Option<String>,
    pub since_unix_ms: u64,
    pub blocked_secs: u64,
    pub attempts: u32,
    pub retry_in_secs: u64,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Restart backoff of a crashing maintenance[T].
pub const MAINTENANCE_BACKOFF_BASE: Duration = Duration::from_secs(10);
pub const MAINTENANCE_BACKOFF_MAX: Duration = Duration::from_secs(600);

/// Live processes of `slot`'s other roles that run under `role`'s uid.
fn shared_uid_siblings(slot: &TenantSlot, role: Role) -> Vec<ProcKey> {
    let uid = slot.ids.uid(role);
    let procs = slot.procs.lock().unwrap();
    Role::ALL.iter()
        .filter(|other| **other != role && slot.ids.uid(**other) == uid)
        .filter_map(|other| procs[role_idx(*other)].as_ref())
        .filter(|p| !p.exited.load(Ordering::SeqCst))
        .map(|p| (p.pid, p.starttime))
        .collect()
}

/// How often a running search is relayed to the tenant's ingest (NAN-3795).
pub const SEARCH_RELAY_EVERY: Duration = Duration::from_secs(2);

/// The running ingest to tell about this tenant's search, when one is due.
/// Only routed search RPCs ([`is_search_rpc`]) count: status polls and
/// schema reads arrive every few seconds from nanosiem-api / -search on an
/// idle tenant, and counting them kept a backfill yielding forever (CT 106).
fn search_relay_target(slot: &TenantSlot, now: Instant) -> Option<Arc<Proc>> {
    let ingest = slot.procs.lock().unwrap()[role_idx(Role::Ingest)].clone();
    let ingest = ingest.filter(|p| !p.exited.load(Ordering::SeqCst) && !p.stopping.load(Ordering::SeqCst))?;
    let mut st = slot.stats.lock().unwrap();
    let in_flight = st.searches_in_flight > 0;
    let searched = st.relayable_search_at.is_some_and(|at| now.saturating_duration_since(at) <= SEARCH_RELAY_EVERY);
    if !search_relay_due(in_flight, searched, st.search_relayed_at, now) {
        return None;
    }
    st.search_relayed_at = Some(now);
    Some(ingest)
}

/// Whether a query[T] sub-path is a search the backfill should yield to
/// (NAN-3795): queries, aggregates, search jobs and result pages, entity
/// and prevalence reads, identity resolution. Not status/progress polls,
/// schema manifests, refusal reads, operator probes or job status/cancel.
pub fn is_search_rpc(sub: &str) -> bool {
    let path = sub.split('?').next().unwrap_or(sub).trim_end_matches('/');
    match path {
        "/v1/query/progress" | "/v1/jobs/search/status" | "/v1/jobs/search/cancel" => false,
        "/v1/query" | "/v1/jobs/search" | "/v1/jobs/result-page" => true,
        _ => ["/v1/query/", "/v1/aggregate/", "/v1/entity/", "/v1/prevalence/", "/v1/identity/resolve"]
            .iter().any(|prefix| path.starts_with(prefix)),
    }
}

/// Holds one routed search as in flight for the relay until dropped.
pub struct SearchGuard(Arc<TenantSlot>);

impl Drop for SearchGuard {
    fn drop(&mut self) {
        let mut st = self.0.stats.lock().unwrap();
        st.searches_in_flight = st.searches_in_flight.saturating_sub(1);
        st.relayable_search_at = Some(Instant::now());
    }
}

/// A relay is due while a search runs or was just routed, once per period.
fn search_relay_due(in_flight: bool, searched_recently: bool, relayed_at: Option<Instant>, now: Instant) -> bool {
    (in_flight || searched_recently)
        && relayed_at.is_none_or(|at| now.saturating_duration_since(at) >= SEARCH_RELAY_EVERY)
}

fn role_idx(r: Role) -> usize {
    match r {
        Role::Ingest => 0,
        Role::Detect => 2,
        Role::Query => 1,
        Role::Maintenance => 3,
        Role::Product => 4,
        Role::Landing => 5,
    }
}

/// `Some(SpawnBlocked)` while `role`'s refusal backoff is pending.
fn spawn_blocked_error(st: &TenantStats, role: Role, now: Instant) -> Option<CellError> {
    let b = st.spawn_blocked[role_idx(role)].as_ref()?;
    (b.not_before > now).then(|| CellError::SpawnBlocked {
        role,
        status: b.status,
        code: b.code.clone(),
        retry_after_secs: b.not_before.saturating_duration_since(now).as_secs().max(1),
    })
}

/// NAN-4052: why this pod is standby for the tenant's writers after its
/// ingest found the cell writer lease held elsewhere, while that lasts.
fn writer_standby(st: &TenantStats, now: Instant) -> Option<String> {
    let until = st.writer_standby_until.filter(|until| *until > now)?;
    Some(format!(
        "{}; retry in {} s",
        st.writer_standby_reason.as_deref().unwrap_or("cell writer lease held by another pod generation"),
        until.saturating_duration_since(now).as_secs().max(1)
    ))
}

/// A warm, unassigned process.
struct WarmProc {
    pid: u32,
    child: tokio::process::Child,
    control: Arc<AsyncSeqpacket>,
    pidfd: PidFd,
    /// With the pid, the process identity.
    starttime: u64,
    label: Arc<OnceLock<String>>,
}

/// A running, assigned tenant process.
pub struct Proc {
    pub pid: u32,
    pub role: Role,
    pub tenant: TenantId,
    pub uid: u32,
    pub landlock: String,
    /// detect: assigned `detect_runs_rules` (the router sends `/detect/...`
    /// here only then), and the memory cap its engine budget was sized from.
    pub runs_rules: bool,
    pub memory_cap_bytes: u64,
    /// The role CPU limit it was assigned; query sizes its chDB threads from
    /// it once, at spawn (NAN-3177).
    pub cpu_millis: u32,
    control: Arc<AsyncSeqpacket>,
    pidfd: PidFd,
    /// With the pid, the process identity (watchdog roots are keyed by it).
    pub starttime: u64,
    started: Instant,
    /// Unix ms at spawn: the process-life identity (`epoch_ms`) of the
    /// counters it reports (NAN-3522 ingest counters).
    pub spawned_unix_ms: u64,
    /// ingest: the over-commit hold it was assigned (NAN-3522); a placement
    /// that changes it restarts the process gracefully.
    pub ingest_hold_eps: Option<f64>,
    last_activity: Mutex<Instant>,
    heartbeat: Mutex<(Instant, Heartbeat)>,
    last_busy: Mutex<Instant>,
    /// Last heartbeat that reported work (`busy`); unlike `last_busy` not
    /// seeded at spawn, so a freshly started idle ingest is not "active".
    busy_seen: Mutex<Option<Instant>>,
    stopping: AtomicBool,
    killed: Mutex<Option<&'static str>>,
    exited: AtomicBool,
    next_request: AtomicU64,
    /// Routed requests not yet fully answered (the idle reaper skips a
    /// process with any in flight).
    inflight: AtomicU64,
    /// Supervisor-generated append IDs awaiting ingest completion.
    pending_finding: Mutex<std::collections::HashSet<u64>>,
}

/// Held while a routed request is in flight; see [`Proc::begin_request`].
pub struct InflightGuard(Arc<Proc>);

impl InflightGuard {
    /// The held process runs rule searches itself (detect[T], NAN-3047).
    pub fn runs_rules(&self) -> bool {
        self.0.runs_rules
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::SeqCst);
        self.0.touch();
    }
}

impl Proc {
    /// Mark activity (defers the idle reap).
    pub fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    fn kill(&self, why: &'static str) {
        if !self.exited.load(Ordering::SeqCst) {
            self.killed.lock().unwrap().get_or_insert(why);
            self.pidfd.kill();
        }
    }

    /// Count a routed request as in flight until the guard drops.
    pub fn begin_request(self: &Arc<Self>) -> InflightGuard {
        self.inflight.fetch_add(1, Ordering::SeqCst);
        self.touch();
        InflightGuard(self.clone())
    }

    /// Last moment this process did or was asked to do work.
    fn active_at(&self) -> Instant {
        let a = *self.last_activity.lock().unwrap();
        let b = *self.last_busy.lock().unwrap();
        a.max(b)
    }
}

#[derive(Default)]
struct TenantStats {
    query_duration_buckets: [u64; 8],
    query_duration_count: u64,
    query_duration_sum: f64,
    spawns: [u64; ROLES],
    reaps: [u64; ROLES],
    crashes: [u64; ROLES],
    stall_kills: [u64; ROLES],
    watchdog_kills: u64,
    oom_kills: u64,
    /// oom_kill counter last read from the live cgroup (reset with it).
    oom_seen_in_cgroup: u64,
    recent_crashes: VecDeque<Instant>,
    recent_ooms: VecDeque<Instant>,
    recent_stalls: VecDeque<Instant>,
    last_spawn_ms: [u64; ROLES],
    last_exit: Option<String>,
    /// Last ingest work seen for this tenant, across ingest restarts
    /// (NAN-2989 query residency).
    ingest_busy_at: Option<Instant>,
    /// Last routed search (query RPC) for this tenant (NAN-3008).
    last_search_at: Option<Instant>,
    /// Last search-activity relay to this tenant's ingest (NAN-3795).
    search_relayed_at: Option<Instant>,
    /// Routed search RPCs ([`is_search_rpc`]) still in flight (NAN-3795).
    searches_in_flight: usize,
    /// Last routed search RPC start or end (NAN-3795).
    relayable_search_at: Option<Instant>,
    /// CPU consumed by tenant cgroups that have since been removed.
    cpu_usec_retired: u64,
    /// CPU measured by the watchdog (all modes), cumulative.
    cpu_usec_watchdog: f64,
    /// Recent limit events (throttles, kills, pressure), newest last.
    events: VecDeque<LimitEvent>,
    event_counts: HashMap<&'static str, u64>,
    /// Restart backoff per role after limit kills / crashes.
    kill_streak: [u32; ROLES],
    last_kill: [Option<Instant>; ROLES],
    restart_not_before: [Option<Instant>; ROLES],
    /// Control-plane refusal of a role's bootstrap token, until it spawns.
    spawn_blocked: [Option<SpawnBlock>; ROLES],
    /// NAN-4052: ingest[T] found the cell writer lease held by another pod
    /// generation (or lost it): no writer of this tenant starts here until
    /// then, and it is not "down".
    writer_standby_until: Option<Instant>,
    writer_standby_reason: Option<String>,
}

/// Recent limit events kept per tenant.
const EVENTS_KEPT: usize = 32;

impl TenantStats {
    fn record(&mut self, e: LimitEvent) {
        *self.event_counts.entry(e.kind.as_str()).or_default() += 1;
        if self.events.len() >= EVENTS_KEPT {
            self.events.pop_front();
        }
        self.events.push_back(e);
    }

    /// A limit kill or a crash: back off before the next respawn of `role`.
    fn backoff(&mut self, i: usize, now: Instant, base: Duration, max: Duration) {
        let recent = self.last_kill[i].is_some_and(|t| now.duration_since(t) < Duration::from_secs(600));
        self.kill_streak[i] = if recent { self.kill_streak[i].saturating_add(1) } else { 1 };
        self.last_kill[i] = Some(now);
        let exp = self.kill_streak[i].saturating_sub(1).min(16);
        let wait = base.saturating_mul(1u32 << exp).min(max);
        self.restart_not_before[i] = Some(now + wait);
    }
}

const QUERY_DURATION_BUCKETS: [f64; 8] = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 120.0];

struct TenantSlot {
    id: TenantId,
    ids: TenantIds,
    /// Per tenant AND role (NAN-4128: a wedged spawn of one tenant never
    /// holds up another tenant's wake). Records its holder and step, and a
    /// waiter logs every [`LOCK_WAIT_LOG_EVERY`].
    spawn_lock: [RoleLock; ROLES],
    /// NAN-4128: the one detached spawn attempt per role. Wakes join it with
    /// a bounded wait, and a caller that leaves never cancels it.
    flights: [SpawnFlight<Arc<Proc>, CellError>; ROLES],
    /// NAN-3875: ONE per tenant (spawn locks are per role). Held across the
    /// tenant-tree ensure, so two roles spawning at once never interleave
    /// the hot-tree ownership check and its quarantine/rebuild (the second
    /// would otherwise quarantine the tree the first just rebuilt).
    /// NAN-4128: owned (`Arc`), so a timed-out ensure keeps it until its
    /// blocking walk really ends.
    dirs_lock: Arc<tokio::sync::Mutex<()>>,
    procs: Mutex<[Option<Arc<Proc>>; ROLES]>,
    stats: Mutex<TenantStats>,
}

impl TenantSlot {
    fn new(id: TenantId, ids: TenantIds) -> Self {
        Self {
            id,
            ids,
            spawn_lock: std::array::from_fn(|_| RoleLock::default()),
            flights: std::array::from_fn(|_| SpawnFlight::default()),
            dirs_lock: Arc::new(tokio::sync::Mutex::new(())),
            procs: Mutex::new(std::array::from_fn(|_| None)),
            stats: Mutex::new(TenantStats::default()),
        }
    }

    /// Run `f` (the tenant-tree ensure) under the per-tenant dirs lock.
    #[cfg(test)]
    async fn with_dirs_lock<T>(&self, f: impl std::future::Future<Output = T>) -> T {
        let _dirs = self.dirs_lock.lock().await;
        f.await
    }

    /// Did this tenant's ingest report work within `window` of `now`?
    /// Remembered across ingest restarts (NAN-2989).
    fn ingest_active_within(&self, now: Instant, window: Duration) -> bool {
        let seen = self.procs.lock().unwrap()[role_idx(Role::Ingest)].as_ref().and_then(|p| *p.busy_seen.lock().unwrap());
        let mut st = self.stats.lock().unwrap();
        if let Some(at) = seen {
            st.ingest_busy_at = Some(st.ingest_busy_at.map_or(at, |b| b.max(at)));
        }
        st.ingest_busy_at.is_some_and(|at| now.saturating_duration_since(at) <= window)
    }

    /// Was this tenant searched within `window` of `now`? (NAN-3008)
    fn searched_within(&self, now: Instant, window: Duration) -> bool {
        self.stats.lock().unwrap().last_search_at.is_some_and(|at| now.saturating_duration_since(at) <= window)
    }

    fn record_search(&self, now: Instant) {
        self.stats.lock().unwrap().last_search_at = Some(now);
    }
}

#[derive(Default)]
struct AlertWindows {
    cell_cpu: VecDeque<(Instant, f64)>,
    query_cpu: HashMap<TenantId, VecDeque<(Instant, u64, u64)>>,
}

impl AlertWindows {
    fn observe(&mut self, now: Instant, cell_ratio: f64, query: impl IntoIterator<Item = (TenantId, u64, u64)>) {
        self.cell_cpu.push_back((now, cell_ratio));
        while self.cell_cpu.front().is_some_and(|(at, _)| now.duration_since(*at) > Duration::from_secs(600)) {
            self.cell_cpu.pop_front();
        }
        for (tenant, usage, throttled) in query {
            let samples = self.query_cpu.entry(tenant).or_default();
            samples.push_back((now, usage, throttled));
            while samples.front().is_some_and(|(at, _, _)| now.duration_since(*at) > Duration::from_secs(300)) {
                samples.pop_front();
            }
        }
    }

    fn cell_cpu_10m(&self) -> f64 {
        if self.cell_cpu.front().zip(self.cell_cpu.back()).is_none_or(|(first, last)| last.0.duration_since(first.0) < Duration::from_secs(590)) {
            return 0.0;
        }
        self.cell_cpu.iter().map(|(_, ratio)| ratio).sum::<f64>() / self.cell_cpu.len() as f64
    }

    fn query_throttled_5m(&self, tenant: &TenantId) -> f64 {
        let Some(samples) = self.query_cpu.get(tenant) else { return 0.0 };
        let Some((first, last)) = samples.front().zip(samples.back()) else { return 0.0 };
        if last.0.duration_since(first.0) < Duration::from_secs(290) { return 0.0; }
        let usage = last.1.saturating_sub(first.1);
        let throttled = last.2.saturating_sub(first.2);
        if usage + throttled == 0 { 0.0 } else { throttled as f64 / (usage + throttled) as f64 }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcStatus {
    pub role: Role,
    pub pid: u32,
    pub uid: u32,
    pub uptime_secs: f64,
    pub idle_secs: f64,
    pub heartbeat_age_secs: f64,
    pub heartbeat: Heartbeat,
    pub landlock: String,
    pub stopping: bool,
    /// detect: this process runs the tenant's rule searches itself.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub runs_rules: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantStatus {
    pub tenant_id: TenantId,
    pub eps: f64,
    /// `on_demand` or `resident` (placement `ingest`).
    pub ingest: IngestMode,
    pub budget: TenantBudget,
    pub processes: Vec<ProcStatus>,
    pub usage: TenantUsage,
    pub spawns: HashMap<&'static str, u64>,
    pub reaps: HashMap<&'static str, u64>,
    pub crashes: HashMap<&'static str, u64>,
    pub stall_kills: HashMap<&'static str, u64>,
    pub oom_kills: u64,
    pub watchdog_kills: u64,
    pub last_spawn_ms: HashMap<&'static str, u64>,
    pub last_exit: Option<String>,
    /// Roles the control plane refuses to start, with its refusal code.
    pub role_spawn_blocked: Vec<RoleSpawnBlocked>,
    /// `/detect/...` requests go to detect[T] (cell `detect_runs_rules` and a
    /// detect budget that holds the engine); false: served by query[T].
    pub detect_runs_rules: bool,
    /// Guarantee / ceilings and what the watchdog measures now (observed
    /// vs guarantee, throttle state, sustained pressure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<TenantResourceView>,
    /// Recent limit events (tenant, reason, observed, limit), newest last.
    pub limit_events: Vec<LimitEvent>,
    pub limit_event_counts: HashMap<&'static str, u64>,
    /// NAN-3523: local-disk use against the tenant's soft/hard ceilings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<crate::disk_ceiling::TenantDiskView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CellStatus {
    pub cell_id: String,
    pub mode: crate::config::CellMode,
    pub limits_mode: LimitsMode,
    /// `kernel` or `watchdog_only` (NAN-2993): what really enforces limits.
    pub enforcement: limits::Enforcement,
    /// Why not `kernel` (null when it is).
    pub enforcement_reason: Option<String>,
    /// How long limits asked for (`auto`/`require`) have not been
    /// kernel-enforced (0 when they are, or with `cgroup: off`).
    pub unenforced_secs: u64,
    /// `placement` | `legacy_eps` | `none`: where role budgets come from.
    pub role_budgets: &'static str,
    pub landlock_abi: i32,
    pub placement_revision: u64,
    pub warm: HashMap<&'static str, usize>,
    pub spawn_failures: u64,
    pub resources: CellResourceView,
    pub delegation: DelegationCheck,
    /// How the delegated cgroup was made writable (null = not adopted).
    pub cgroup_mount: Option<limits::MountMethod>,
    /// The delegator took the adopted scope back (re-checked every tick).
    pub delegation_withdrawn: bool,
    /// `open` | `refused_unenforced` (NAN-3523): a pooled cell without
    /// kernel limits starts no new tenant process.
    pub admission: limits::Admission,
    pub identity: IdentityReport,
    /// Cell-level limit events (e.g. memory critical with no victim).
    pub limit_events: Vec<LimitEvent>,
    pub tenants: Vec<TenantStatus>,
    /// Zero-downtime roll state (NAN-3004); absent for a single-pod cell.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handover: Option<crate::handover::HandoverStatus>,
    /// NAN-3523: OOM ordering and the `init/` cgroup reserve.
    pub supervisor_reserve: crate::oom::SupervisorReserve,
}

pub struct Supervisor {
    cfg: CellConfig,
    keys: Arc<dyn KeySource>,
    /// Set at boot, or later by the live adoption loop (auto).
    cgroups: OnceLock<CgroupTree>,
    mount_method: Mutex<Option<limits::MountMethod>>,
    /// Supervisor children seen in init/ last pass (moved if still there).
    init_pending: Mutex<std::collections::HashSet<u32>>,
    /// The delegator took the scope back (re-checked every tick).
    delegation_withdrawn: AtomicBool,
    /// Latest reasons the scope is not delegated (boot check, then every
    /// adoption poll / failed adoption); what `enforcement_reason` shows.
    delegation_reasons: Mutex<Vec<String>>,
    /// Since when limits are not kernel-enforced, and the last periodic
    /// WARN about it (NAN-2993).
    unenforced: Mutex<UnenforcedClock>,
    /// Since when admission is refused (NAN-3523): delays the page only.
    admission_refused: Mutex<limits::RefusalClock>,
    /// Background loops stop (after `shutdown_all`, e.g. in tests running
    /// several cells in one process).
    halted: AtomicBool,
    delegation: DelegationCheck,
    identity: IdentityReport,
    monitor: Arc<Mutex<Monitor>>,
    cell_events: Mutex<VecDeque<LimitEvent>>,
    landlock_abi: i32,
    uidmap: Mutex<UidMap>,
    placement: RwLock<Placement>,
    tenants: Mutex<HashMap<TenantId, Arc<TenantSlot>>>,
    warm: Mutex<HashMap<Role, VecDeque<WarmProc>>>,
    warm_notify: tokio::sync::Notify,
    /// Wakes the resident-ingest keeper (placement change, ingest exit).
    keeper_notify: tokio::sync::Notify,
    /// Resident tenants whose ingest is not running, since when (keeper).
    resident_down_since: Mutex<HashMap<TenantId, Instant>>,
    /// `drain_all` / `shutdown_all` began: the keeper starts nothing more.
    stopping_all: AtomicBool,
    spawn_failures: AtomicU64,
    recent_spawn_failures: Mutex<VecDeque<Instant>>,
    alert_windows: Mutex<AlertWindows>,
    /// NAN-3773: fire/resolve hysteresis for the alert feed and `/metrics`.
    signal_debounce: Mutex<crate::signals::SignalDebouncer>,
    started_at: Instant,
    restarted: bool,
    /// NAN-3000: removals still to purge and verified purges still to report
    /// (persisted in `state_dir`).
    ledger: Arc<crate::report::LedgerStore>,
    /// Tenants whose tree is being purged: no slot (so no spawn) until done.
    purging: Mutex<std::collections::HashSet<TenantId>>,
    /// A placement was applied this boot. Nothing is purged before: an
    /// unreadable placement file must never look like "no tenants".
    placement_loaded: AtomicBool,
    /// Wakes the purge loop (placement change, a drained tenant forgotten).
    purge_notify: tokio::sync::Notify,
    /// Wakes the status reporter (placement change, a new verified purge).
    report_notify: Arc<tokio::sync::Notify>,
    /// Failed purge attempts: (consecutive failures, next attempt not before).
    purge_retry: Mutex<HashMap<TenantId, (u32, Instant)>>,
    /// Purges refused by design, by tenant (reason).
    purge_blocked: Mutex<HashMap<TenantId, &'static str>>,
    purge_failures: AtomicU64,
    status_pushes: Mutex<HashMap<&'static str, u64>>,
    /// Zero-downtime roll state (NAN-3004); `None` = single-pod cell.
    handover: Option<Arc<crate::handover::Handover>>,
    /// Egress watchdog (NAN-3440); `None` = `upstream_readiness` unset.
    upstream: Option<Arc<crate::upstream::UpstreamMonitor>>,
    /// Hot-window volume accountant; query processes get a preconnected
    /// connection to it with their assignment (NAN-3139).
    volume_accountant: OnceLock<crate::volume_usage::Accountant>,
    /// NAN-3523: per-tenant local-disk ceilings.
    disk: Arc<crate::disk_ceiling::DiskCeilings>,
}

/// Purge loop tick (it is also woken on placement changes).
const PURGE_TICK: Duration = Duration::from_secs(10);
/// Longest wait between retries of a failing purge.
const PURGE_RETRY_MAX: Duration = Duration::from_secs(300);

/// Landlock ABI of the running kernel (0 = unavailable).
pub fn landlock_abi() -> i32 {
    // SAFETY: LANDLOCK_CREATE_RULESET_VERSION query; no pointers used.
    let v = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, 1u32) };
    if v < 0 {
        0
    } else {
        v as i32
    }
}

/// Raise RLIMIT_NOFILE's soft limit to the hard limit: the supervisor holds
/// sockets and pidfds per tenant process.
fn raise_nofile() {
    // SAFETY: getrlimit/setrlimit on a stack struct.
    unsafe {
        let mut r: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) == 0 && r.rlim_cur < r.rlim_max {
            r.rlim_cur = r.rlim_max;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &r) != 0 {
                tracing::warn!("could not raise RLIMIT_NOFILE to {}", r.rlim_max);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StrayScope {
    Limbo,
    Init,
    Warm,
}

/// How often `auto` checks whether the delegator has handed the scope over.
const ADOPTION_POLL: Duration = Duration::from_secs(5);

/// How often a cell without kernel limits repeats its WARN (NAN-2993): one
/// line at boot was all it said before, and nobody saw it.
const UNENFORCED_WARN_EVERY: Duration = Duration::from_secs(300);
/// `limits_unenforced` pages after this long (warns from the first second).
const LIMITS_UNENFORCED_PAGE: Duration = Duration::from_secs(900);
/// `Retry-After` on a refused admission (NAN-3523): the adoption poll, so a
/// late delegation is picked up by the next retry.
const ADMISSION_RETRY_AFTER: Duration = ADOPTION_POLL;

/// Since when limits are not kernel-enforced, and when we last said so.
#[derive(Debug, Default)]
struct UnenforcedClock {
    since: Option<Instant>,
    last_warn: Option<Instant>,
}

impl UnenforcedClock {
    /// Record the state at `now`. True when a WARN is due (first sight,
    /// then every [`UNENFORCED_WARN_EVERY`]).
    fn observe(&mut self, now: Instant, unenforced: bool) -> bool {
        if !unenforced {
            *self = Self::default();
            return false;
        }
        self.since.get_or_insert(now);
        let due = self.last_warn.is_none_or(|w| now.duration_since(w) >= UNENFORCED_WARN_EVERY);
        if due {
            self.last_warn = Some(now);
        }
        due
    }

    fn secs(&self, now: Instant) -> u64 {
        self.since.map_or(0, |s| now.duration_since(s).as_secs())
    }
}

/// How often the keeper re-checks resident ingest processes (it is also
/// woken on every placement change and every ingest exit).
const KEEPER_TICK: Duration = Duration::from_secs(5);

/// A resident tenant's ingest not running for this long warns / pages.
const RESIDENT_DOWN_WARN: Duration = Duration::from_secs(60);
const RESIDENT_DOWN_PAGE: Duration = Duration::from_secs(300);
/// detect: age of the oldest unpublished finding-outbox row (`finding_outbox_age`).
const FINDING_OUTBOX_AGE_WARN_S: f64 = 300.0;
const FINDING_OUTBOX_AGE_PAGE_S: f64 = 600.0;

/// Whether the idle reaper may stop `role` of a tenant placed as `placed`.
/// A resident ingest never idles out; everything else does (C1).
/// A running detect[T] no longer matches its placement: assigned for the
/// other rule mode, or its engine sized for another detect memory limit
/// (the budget is derived once, at engine open, from `memory.max`).
pub fn detect_needs_respawn(runs_rules: bool, memory_cap_bytes: u64, placement: &TenantPlacement, cell_enabled: bool) -> bool {
    let want = placement.detect_runs_rules(cell_enabled);
    runs_rules != want || (want && memory_cap_bytes != placement.effective_role_budget(Role::Detect).limit_memory_bytes)
}

/// NAN-3522: the `ingest_lag` page threshold (seconds) and the
/// `ingest_progress_stalled` page threshold (minutes) for an ingest[T] with
/// this hold. Held: the lag never pages (it is the queued backlog), and a
/// paused admission may go up to an hour between commits at a low hold rate
/// (one object of debt), so the stall pages at 60 min instead of 10.
pub fn held_ingest_pages(hold_eps: Option<f64>) -> (f64, f64) {
    if hold_eps.is_some() { (f64::INFINITY, 60.0) } else { (300.0, 10.0) }
}

/// NAN-3522: a running ingest[T] applies the hold it was assigned at spawn.
pub fn ingest_hold_needs_respawn(assigned: Option<f64>, placed: Option<f64>) -> bool {
    assigned != placed
}

/// NAN-3177: a running query[T] sized its chDB threads from the CPU limit it
/// was spawned with; it restarts only when the new limit gives another count.
pub fn query_needs_respawn(spawned_cpu_millis: u32, cpu_millis: u32) -> bool {
    crate::budget::query_threads(spawned_cpu_millis) != crate::budget::query_threads(cpu_millis)
}

/// NAN-3148: product[T]'s ceilings sit ON TOP of the tenant's (never carved
/// out of query's): its CPU and memory limits are added to the tenant
/// ceiling and soft/hard memory, not to the guarantee or the cpu.weight, so
/// a product build can neither starve query[T] nor push the tenant into its
/// own memory ceiling.
pub fn with_product_role(mut limits: TenantLimits, placement: &TenantPlacement) -> TenantLimits {
    let product = placement.effective_role_budget(Role::Product);
    limits.cpu_ceiling_millicores = limits.cpu_ceiling_millicores.saturating_add(product.limit_millicores);
    limits.memory_soft_bytes = limits.memory_soft_bytes.saturating_add(product.limit_memory_bytes);
    limits.memory_hard_bytes = limits.memory_hard_bytes.saturating_add(product.limit_memory_bytes);
    limits
}

/// The tenant paths a `role` process may write and read (its Landlock
/// rules, before feed/system/enrichment paths). `product_state_role`
/// (NAN-3148): query[T] reads product[T]'s published dir and may write only
/// the demand inbox beneath it. `product` is product[T]'s published dir
/// (NAN-3799: `<root>/product`, or its tree on the persistent hot volume).
pub fn role_mounts(root: &Path, role: Role, product_state_role: bool, product: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let own = root.join(role.as_str());
    let parts = root.join("parts");
    let (mut rw, mut ro) = match role {
        Role::Ingest => (vec![own, parts], vec![]),
        Role::Detect => (vec![own, parts], vec![]),
        Role::Query => (vec![own], vec![parts]),
        // SlateDB compaction reads R2 and writes through the owner; its
        // only local state is the owner request journal.
        Role::Maintenance => (vec![own], vec![]),
        // NAN-3148: query's read access to parts, its own state only.
        Role::Product => (vec![own], vec![parts]),
        // NAN-4137: its own state only. It never reads parts (landed files
        // come from R2 through its landing_reader credential).
        Role::Landing => (vec![own], vec![]),
    };
    if role == Role::Product && rw[0] != product {
        rw.push(product.to_path_buf());
    }
    if role == Role::Query && product_state_role {
        rw.push(product.join(crate::tenant_dirs::PRODUCT_DEMAND_DIR));
        ro.push(product.to_path_buf());
    }
    (rw, ro)
}

/// NAN-4137: landing[T]'s ceilings sit on top of the tenant's, like
/// product[T]'s: a large landed file never squeezes ingest or query.
pub fn with_landing_role(mut limits: TenantLimits, placement: &TenantPlacement) -> TenantLimits {
    let landing = placement.effective_role_budget(Role::Landing);
    limits.cpu_ceiling_millicores = limits.cpu_ceiling_millicores.saturating_add(landing.limit_millicores);
    limits.memory_soft_bytes = limits.memory_soft_bytes.saturating_add(landing.limit_memory_bytes);
    limits.memory_hard_bytes = limits.memory_hard_bytes.saturating_add(landing.limit_memory_bytes);
    limits
}

/// NAN-4137: does this cell run landing[T] for the tenant? Only on a
/// `tenzir_landing` cell, for a tenant placed with `landing`.
pub fn landing_wanted(cell_enabled: bool, placed: Option<&TenantPlacement>) -> bool {
    cell_enabled && placed.is_some_and(|p| p.landing)
}

pub fn idle_reapable(role: Role, placed: Option<&TenantPlacement>) -> bool {
    // product[T] (NAN-3148) is never idle-reaped on its own: it has no
    // routed requests, and the keeper ties it to a live query[T].
    // landing[T] (NAN-4137) likewise: the keeper owns its life.
    if matches!(role, Role::Product | Role::Landing) {
        return false;
    }
    // maintenance[T] lives beside a resident ingest (the keeper stops
    // starting it when the tenant is no longer resident).
    !(matches!(role, Role::Ingest | Role::Maintenance) && placed.is_some_and(|p| p.ingest == IngestMode::Resident))
}

/// Whether the idle reaper stops a process now. `query_kept_resident`: a
/// placed tenant's query process is resident (NAN-3008: always, by
/// default; NAN-2989: while ingest or search is recent) and is never
/// reaped. Search on a live tenant must not pay a cold start.
pub fn idle_reap_due(role: Role, placed: Option<&TenantPlacement>, inflight: u64, idle_for: Duration, idle_timeout: Duration, query_kept_resident: bool) -> bool {
    inflight == 0 && idle_for > idle_timeout && idle_reapable(role, placed)
        && !(role == Role::Query && placed.is_some() && query_kept_resident)
}

/// NAN-3008: is a placed tenant's query process kept resident? Always when
/// `query_resident` (the default); otherwise while its ingest worked or it
/// was searched within the configured windows.
fn query_kept_resident(cfg: &CellConfig, slot: &TenantSlot, now: Instant) -> bool {
    cfg.query_resident
        || cfg.query_resident_ingest_window().is_some_and(|window| slot.ingest_active_within(now, window))
        || cfg.query_resident_search_window().is_some_and(|window| slot.searched_within(now, window))
}

/// A writable view of the delegated scope (the private cgroup2 mount when
/// the pod's /sys/fs/cgroup is read-only) and the adopted tree on it.
fn adopt_delegated(cfg: &CellConfig, check: &DelegationCheck) -> Result<(CgroupTree, limits::MountMethod), String> {
    let mut attempts = limits::MountAttempts::default();
    let wm = limits::make_writable(
        check,
        &cfg.cgroup_mount,
        Path::new(limits::PRIVATE_CGROUP_MOUNT),
        &limits::SysMounter,
        &mut attempts,
    )?;
    let mut tree = CgroupTree::adopt(
        &wm.mount,
        cfg.resources.io_max.clone(),
        cfg.resources.cpu_max_burst,
        cfg.cgroup_policy() == CgroupPolicy::Require,
    )
    .map_err(|e| format!("adopt at {}: {e}", wm.mount.display()))?;
    tree.resolve_io_max_data_volume(&cfg.data_dir, Path::new("/sys"));
    let warm_n = (cfg.warm_query + cfg.warm_ingest).max(1) as u64;
    tree.set_warm_limit(cfg.warm_memory_bytes_each * warm_n).map_err(|e| e.to_string())?;
    // NAN-3523: the supervisor's memory reserve. Not fatal: an unprotected
    // supervisor is reported in `supervisor_reserve`, never a boot failure.
    let cell_memory = crate::resources::detect_capacity(&cfg.resources, Some(&wm.mount)).memory_bytes;
    match tree.reserve_init(cfg.resources.supervisor_memory_min_bytes, cell_memory) {
        Ok(bytes) => tracing::info!(memory_min = bytes, cpu_weight = limits::INIT_CPU_WEIGHT, "supervisor cgroup reserve set"),
        Err(e) => tracing::warn!(error = %e, "supervisor memory.min not set"),
    }
    Ok((tree, wm.method))
}

fn read_status_ids(pid: u32) -> Option<(Vec<u32>, Vec<u32>)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let parse = |key: &str| -> Option<Vec<u32>> {
        s.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.split_whitespace().filter_map(|x| x.parse().ok()).collect())
    };
    Some((parse("Uid:")?, parse("Gid:")?))
}

use crate::tenant_dirs::ensure_dir;

impl Supervisor {
    pub fn new(cfg: CellConfig, keys: Arc<dyn KeySource>) -> anyhow::Result<Arc<Self>> {
        cfg.validate()?;
        raise_nofile();
        // SAFETY: geteuid never fails.
        let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
        ensure_dir(&cfg.state_dir, euid, egid, 0o700)?;
        // tenants/ is traversable but not listable: a tenant can reach its
        // own dir by name, never enumerate the others.
        std::fs::create_dir_all(&cfg.data_dir)?;
        std::fs::set_permissions(&cfg.data_dir, std::fs::Permissions::from_mode(0o711))?;
        ensure_dir(&cfg.data_dir.join("tenants"), euid, egid, 0o711)?;

        // Identity: caps, the tenant id range in our userns, landlock (fatal
        // in hosted user namespaces; trusted-local dedicated cells opt out).
        let identity = crate::identity::check_with_policy(cfg.uid_base, cfg.uid_slots, cfg.require_landlock, cfg.trusted_local);
        if !identity.fatal.is_empty() {
            anyhow::bail!("cell supervisor preflight failed: {}", identity.fatal.join("; "));
        }
        if cfg.trusted_local && identity.landlock_abi <= 0 {
            tracing::warn!("Landlock unavailable: trusted-local single-tenant cell continues with uid separation, seccomp and namespaces; enable Landlock in the host kernel LSM list for filesystem confinement");
        }
        let delegation = limits::check_delegation(&cfg.cgroup_mount);
        let mode = limits::select_mode(cfg.cgroup_policy(), &delegation).map_err(|e| anyhow::anyhow!(e))?;
        let mut mount_method = None;
        let mut boot_reasons = delegation.reasons.clone();
        let cgroups = match mode {
            LimitsMode::Watchdog => {
                if cfg.cgroup_policy() != CgroupPolicy::Off {
                    tracing::warn!(reasons = ?delegation.reasons,
                        "no cgroup delegation yet; watchdog-only limits (polling for the delegator every 5 s)");
                }
                None
            }
            LimitsMode::CgroupV2 => match adopt_delegated(&cfg, &delegation) {
                Ok((t, method)) => {
                    tracing::info!(controllers = ?t.controllers(), ?method, "cgroup v2 delegation adopted; watchdog is the second layer");
                    mount_method = Some(method);
                    Some(t)
                }
                Err(e) if cfg.cgroup_policy() == CgroupPolicy::Require => anyhow::bail!("cgroup delegation required: {e}"),
                Err(e) => {
                    tracing::warn!(error = %e, "cgroup delegation looked available but adoption failed; watchdog-only limits");
                    boot_reasons = vec![format!("adoption failed: {e}")];
                    None
                }
            },
        };
        let abi = landlock_abi();
        let cg_root = cgroups.as_ref().map(|c| c.root().to_path_buf()).or_else(|| delegation.root.clone());
        let capacity = crate::resources::detect_capacity(&cfg.resources, cg_root.as_deref());
        tracing::info!(cpu_millicores = capacity.cpu_millicores, memory_bytes = capacity.memory_bytes,
            cpu_source = capacity.cpu_source, memory_source = capacity.memory_source, "cell capacity");
        let monitor = Monitor::new(cfg.resources.clone(), capacity, cgroups.is_some()).with_cell_cgroup(cg_root.clone());
        let uidmap = load_uid_map(&cfg, euid, egid)?;
        let startup_marker = cfg.state_dir.join("supervisor-started");
        let restarted = startup_marker.exists();
        std::fs::write(&startup_marker, now_ms().to_string())?;
        // Leftovers from a previous supervisor in this pid namespace (e.g.
        // stopped by its throttle, or orphans): nothing may run as a tenant
        // uid before we start it.
        let (lo, hi) = uidmap.tenant_uid_range();
        let stale: Vec<u32> = procfs::scan().iter().map(|p| p.status.uid).filter(|u| (lo..hi).contains(u)).collect();
        if !stale.is_empty() {
            let n = Self::kill_uids(&stale);
            tracing::warn!(killed = n, "killed processes left under tenant uids by a previous supervisor");
        }
        let placement = Placement { cell_id: cfg.cell_id.clone(), revision: 0, tenants: vec![] };
        let ledger = Arc::new(crate::report::LedgerStore::open(&cfg.state_dir.join("purge-ledger.json"))?);
        // Boot already WARNed above (unless `off`); the clock repeats it.
        let boot = Instant::now();
        let unenforced = cgroups.is_none() && cfg.cgroup_policy() != CgroupPolicy::Off;
        let unenforced_at_boot = UnenforcedClock { since: unenforced.then_some(boot), last_warn: unenforced.then_some(boot) };
        let handover = match &cfg.zero_downtime_roll {
            Some(h) => {
                let h = crate::handover::Handover::new(&cfg.cell_id, h.clone())?;
                tracing::info!(boot_id = %h.me.boot_id, peers = ?h.cfg.peers, "zero-downtime roll: writer handover on");
                Some(Arc::new(h))
            }
            None => None,
        };
        let upstream = cfg.upstream_readiness.clone().map(|u| {
            tracing::info!(targets = ?u.targets.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
                not_ready_after_secs = u.not_ready_after_secs, "upstream readiness watchdog on");
            Arc::new(crate::upstream::UpstreamMonitor::new(u, Instant::now()))
        });
        let disk = Arc::new(crate::disk_ceiling::DiskCeilings::new(cfg.resources.tenant_disk.clone(), cfg.mode));
        let sup = Arc::new(Self {
            cfg,
            keys,
            cgroups: {
                let l = OnceLock::new();
                if let Some(t) = cgroups {
                    let _ = l.set(t);
                }
                l
            },
            mount_method: Mutex::new(mount_method),
            init_pending: Mutex::new(Default::default()),
            delegation_withdrawn: AtomicBool::new(false),
            delegation_reasons: Mutex::new(boot_reasons),
            unenforced: Mutex::new(unenforced_at_boot),
            admission_refused: Mutex::new(Default::default()),
            halted: AtomicBool::new(false),
            volume_accountant: OnceLock::new(),
            disk,
            delegation,
            identity,
            monitor: Arc::new(Mutex::new(monitor)),
            cell_events: Mutex::new(VecDeque::new()),
            landlock_abi: abi,
            uidmap: Mutex::new(uidmap),
            placement: RwLock::new(placement),
            tenants: Mutex::new(HashMap::new()),
            warm: Mutex::new(HashMap::new()),
            warm_notify: tokio::sync::Notify::new(),
            keeper_notify: tokio::sync::Notify::new(),
            resident_down_since: Mutex::new(HashMap::new()),
            stopping_all: AtomicBool::new(false),
            spawn_failures: AtomicU64::new(0),
            recent_spawn_failures: Mutex::new(VecDeque::new()),
            alert_windows: Mutex::new(AlertWindows::default()),
            signal_debounce: Mutex::new(crate::signals::SignalDebouncer::default()),
            started_at: Instant::now(),
            restarted,
            ledger,
            purging: Mutex::new(Default::default()),
            placement_loaded: AtomicBool::new(false),
            purge_notify: tokio::sync::Notify::new(),
            report_notify: Arc::new(tokio::sync::Notify::new()),
            purge_retry: Mutex::new(HashMap::new()),
            purge_failures: AtomicU64::new(0),
            purge_blocked: Mutex::new(HashMap::new()),
            status_pushes: Mutex::new(HashMap::new()),
            handover,
            upstream,
        });
        // Adopted at boot: limbo/ holds whatever else was in the scope.
        if sup.cgroups.get().is_some() {
            sup.finish_adoption();
        }
        Ok(sup)
    }

    pub fn config(&self) -> &CellConfig {
        &self.cfg
    }

    pub fn limits_mode(&self) -> LimitsMode {
        if self.cgroups.get().is_some() {
            LimitsMode::CgroupV2
        } else {
            LimitsMode::Watchdog
        }
    }

    /// What enforces tenant limits right now (NAN-2993).
    pub fn enforcement(&self) -> limits::Enforcement {
        limits::enforcement(self.limits_mode(), self.delegation_withdrawn.load(Ordering::SeqCst))
    }

    /// Why limits are not kernel-enforced (`None` when they are).
    pub fn enforcement_reason(&self) -> Option<String> {
        limits::enforcement_reason(
            self.cfg.cgroup_policy(),
            self.enforcement(),
            self.delegation_withdrawn.load(Ordering::SeqCst),
            &self.delegation_reasons.lock().unwrap(),
        )
    }

    /// Whether new tenant processes may start (NAN-3523): a pooled cell
    /// fails closed while limits are watchdog-only (before adoption, or
    /// after the delegator withdrew the scope).
    pub fn admission(&self) -> limits::Admission {
        limits::admission(self.cfg.mode, self.enforcement(), self.cfg.isolation.allow_pooled_watchdog_only)
    }

    /// Advance the refusal clock; how long admission has been refused
    /// continuously (`None` while open). Ticked by the watchdog and on every
    /// signal evaluation.
    fn admission_refused_for(&self) -> Option<Duration> {
        self.admission_refused.lock().unwrap().observe(Instant::now(), self.admission())
    }

    fn admission_error(&self) -> Option<CellError> {
        (self.admission() == limits::Admission::RefusedUnenforced).then(|| CellError::AdmissionRefused {
            reason: self.enforcement_reason().unwrap_or_default(),
            retry_after_secs: ADMISSION_RETRY_AFTER.as_secs(),
        })
    }

    /// Limits the configuration asked for (`auto`/`require`) but the kernel
    /// is not enforcing. `off` is a deliberate choice, not a gap.
    fn limits_unenforced(&self) -> bool {
        self.cfg.cgroup_policy() != CgroupPolicy::Off && self.enforcement() != limits::Enforcement::Kernel
    }

    /// Every watchdog tick: keep the unenforced clock, and repeat the WARN
    /// every [`UNENFORCED_WARN_EVERY`] while limits are not kernel-enforced
    /// (with the role-budget source for context). Never silent (NAN-2993).
    fn note_enforcement(&self) {
        self.admission_refused_for();
        let unenforced = self.limits_unenforced();
        let (due, secs) = {
            let mut clock = self.unenforced.lock().unwrap();
            let now = Instant::now();
            (clock.observe(now, unenforced), clock.secs(now))
        };
        if due {
            let role_budgets = self.placement.read().unwrap().role_budget_source();
            tracing::warn!(
                enforcement = self.enforcement().as_str(),
                admission = self.admission().as_str(),
                reason = self.enforcement_reason().unwrap_or_default(),
                unenforced_secs = secs,
                role_budgets,
                "tenant limits are NOT kernel-enforced: watchdog-only (per-tenant throttle/kill; no per-role cpu/memory limits)"
            );
        }
    }

    /// Start the background loops (reaper/watchdog, warm pool, placement).
    pub fn start_background(self: &Arc<Self>) {
        if local_hot_window_enabled() {
            let root = std::env::var_os("NANO_LAKE_LOCAL_HOT_WINDOW_DIR")
                .map(PathBuf::from).unwrap_or_else(|| self.cfg.data_dir.clone());
            match crate::volume_usage::start(root.clone(), vec![self.cfg.data_dir.clone(), root]) {
                Ok(accountant) => { let _ = self.volume_accountant.set(accountant); }
                Err(error) => tracing::error!(%error,
                    "hot-window volume accountant unavailable; query caches fall back to statvfs headroom"),
            }
        }
        // NAN-3523: the per-tenant disk walk runs on its own thread (it
        // switches fsuid per directory); the watchdog tick applies it.
        let weak = Arc::downgrade(self);
        if let Err(error) = self.disk.spawn_walker(self.cfg.data_dir.join("tenants"), move || {
            weak.upgrade().filter(|s| !s.is_halted())
                .map(|s| s.placement.read().unwrap().tenants.iter().map(|t| t.tenant_id.clone()).collect())
        }) {
            tracing::error!(%error, "tenant disk walker unavailable; disk ceilings fail open");
        }
        let me = self.clone();
        tokio::spawn(async move { me.reaper_loop().await });
        let me = self.clone();
        tokio::spawn(async move { me.warm_loop().await });
        let me = self.clone();
        tokio::spawn(async move { me.placement_loop().await });
        let me = self.clone();
        tokio::spawn(async move { me.resource_loop().await });
        let me = self.clone();
        tokio::spawn(async move { me.keeper_loop().await });
        let me = self.clone();
        tokio::spawn(async move { me.purge_loop().await });
        if self.handover.is_some() {
            let me = self.clone();
            tokio::spawn(async move { me.peer_loop().await });
            let me = self.clone();
            tokio::spawn(async move { me.startup_warm_loop().await });
        }
        if self.cgroups.get().is_none() && self.cfg.cgroup_policy() == CgroupPolicy::Auto {
            let me = self.clone();
            tokio::spawn(async move { me.adoption_loop().await });
        }
        if let Some(u) = &self.upstream {
            let me = self.clone();
            tokio::spawn(u.clone().run(move || me.is_halted()));
        }
    }

    /// `auto` without delegation at boot: poll every 5 s for the node-side
    /// delegator to hand the scope over, then adopt it live: private
    /// cgroup2 mount, supervisor into `init/`, controllers on, and every
    /// existing tenant (and warm) process moved into its cgroup. The watchdog
    /// keeps running throughout.
    async fn adoption_loop(self: Arc<Self>) {
        let mut last_reason = String::new();
        let mut last_check: Vec<String> = vec![];
        loop {
            if self.halted.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(ADOPTION_POLL).await;
            let reasons = limits::check_delegation(&self.cfg.cgroup_mount).reasons;
            if reasons != last_check {
                tracing::info!(?reasons, "cgroup delegation check");
                *self.delegation_reasons.lock().unwrap() = reasons.clone();
                last_check = reasons;
            }
            let me = self.clone();
            let r = tokio::task::spawn_blocking(move || me.try_adopt_live()).await;
            match r {
                // Later strays (mid-spawn, re-parented) are reconciled every
                // watchdog tick from now on.
                Ok(Ok(true)) => return,
                Ok(Ok(false)) => {}
                Ok(Err(e)) if e != last_reason => {
                    *self.delegation_reasons.lock().unwrap() = vec![format!("live adoption failed: {e}")];
                    tracing::warn!(error = %e, "cgroup delegation present but live adoption failed; retrying");
                    last_reason = e;
                }
                Ok(Err(_)) => {}
                Err(e) => tracing::error!(error = %e, "adoption pass panicked"),
            }
        }
    }

    /// One adoption attempt. `Ok(false)`: not delegated yet.
    fn try_adopt_live(&self) -> Result<bool, String> {
        let check = limits::check_delegation(&self.cfg.cgroup_mount);
        if !check.delegated() {
            return Ok(false);
        }
        let (tree, method) = adopt_delegated(&self.cfg, &check)?;
        if self.cgroups.set(tree).is_err() {
            return Ok(true);
        }
        *self.mount_method.lock().unwrap() = Some(method);
        self.delegation_reasons.lock().unwrap().clear();
        self.monitor.lock().unwrap().set_delegated(true);
        let (moved, killed) = self.finish_adoption();
        tracing::info!(?method, moved, killed, "cgroup delegation adopted live; tenant processes moved into their cgroups");
        Ok(true)
    }

    /// After adopting: sort every process frozen in `limbo/` into its
    /// cgroup (tenant uid → its role leaf, supervisor child → `warm/`,
    /// anything else killed), then remove `limbo/`. Returns (moved, killed).
    fn finish_adoption(&self) -> (usize, usize) {
        let Some(cg) = self.cgroups.get() else { return (0, 0) };
        let (mut moved, mut killed) = (0, 0);
        for _ in 0..5 {
            let pids = cg.limbo_pids();
            if pids.is_empty() {
                break;
            }
            let (m, k) = self.sort_strays(cg, &pids, StrayScope::Limbo);
            moved += m;
            killed += k;
        }
        match cg.remove_limbo() {
            Ok(0) => {}
            Ok(n) => {
                tracing::error!(left = n, "processes left in limbo after sorting were killed");
                killed += n;
            }
            Err(e) => tracing::error!(error = %e, "could not remove limbo/"),
        }
        (moved, killed)
    }

    /// Sort stray `pids` into their cgroups. Returns (moved, killed).
    fn sort_strays(&self, cg: &CgroupTree, pids: &[u32], scope: StrayScope) -> (usize, usize) {
        let mut owners = HashMap::new();
        let mut slots = HashMap::new();
        for (t, ids) in self.uidmap.lock().unwrap().all() {
            owners.insert(ids.ingest_uid, (t.clone(), Role::Ingest));
            owners.insert(ids.query_uid, (t.clone(), Role::Query));
            owners.insert(ids.detect_uid, (t.clone(), Role::Detect));
            if let Some(uid) = ids.landing_uid {
                owners.insert(uid, (t.clone(), Role::Landing));
            }
            slots.insert(t, ids.slot);
        }
        let warm: Vec<u32> = self.warm.lock().unwrap().values().flatten().map(|w| w.pid).collect();
        let info: HashMap<u32, procfs::ProcInfo> =
            procfs::scan().into_iter().filter(|p| pids.contains(&p.pid)).map(|p| (p.pid, p)).collect();
        let strays: Vec<limits::Stray> =
            info.values().map(|p| (p.pid, p.status.uid, p.stat.ppid)).collect();
        let me = std::process::id();
        let mut plan = limits::plan_sweep(&strays, me, &owners, &warm);
        // A uid can serve two roles (maintenance runs as ingest's, product
        // as query's): a process we assigned goes to its own role's leaf.
        let assigned: HashMap<u32, Role> = self.tenants.lock().unwrap().values()
            .flat_map(|slot| slot.procs.lock().unwrap().iter().flatten().map(|p| (p.pid, p.role)).collect::<Vec<_>>())
            .collect();
        for (pid, target) in plan.iter_mut() {
            if let (limits::SweepTarget::Tenant(_, role), Some(own)) = (target, assigned.get(pid)) {
                *role = *own;
            }
        }
        match scope {
            StrayScope::Limbo => {}
            // Only tenant processes are moved out of warm/.
            StrayScope::Warm => plan.retain(|(_, t)| matches!(t, limits::SweepTarget::Tenant(..))),
            // A supervisor child in init/ may be mid-spawn (it is placed in
            // warm/ right after): move it only if it was already there last
            // pass.
            StrayScope::Init => {
                let mut pending = self.init_pending.lock().unwrap();
                let seen = std::mem::take(&mut *pending);
                plan.retain(|(pid, t)| {
                    if *t == limits::SweepTarget::Warm && !seen.contains(pid) {
                        pending.insert(*pid);
                        false
                    } else {
                        true
                    }
                });
            }
        }
        for (_, t) in &plan {
            if let limits::SweepTarget::Tenant(t, _) = t {
                if !cg.tenant_dir(t).exists() {
                    let placement = self.placed(t).unwrap_or_else(|| TenantPlacement::legacy(t.clone(), 0.0));
                    if let Some(slot) = slots.get(t) {
                        if let Err(e) = self.ensure_tenant_cgroup(cg, t, *slot, &placement) {
                            tracing::warn!(tenant = %t, error = %e, "tenant cgroup for a stray");
                        }
                    }
                }
            }
        }
        let (moved, kill) = cg.apply_sweep(&plan);
        let keys: Vec<ProcKey> = kill.iter().filter_map(|pid| info.get(pid).map(|p| p.key())).collect();
        let killed = kill_all(&keys);
        if moved + killed > 0 && scope != StrayScope::Limbo {
            tracing::warn!(?scope, moved, killed, "reconciled stray processes into their cgroups");
        }
        (moved, killed)
    }

    /// Delegated mode, every tick: nothing but the supervisor stays in
    /// `init/`, no tenant process stays in `warm/`, and the delegation is
    /// still ours (the delegator may withdraw it).
    fn reconcile_cgroups(&self) {
        let Some(cg) = self.cgroups.get() else { return };
        let ours = cg.still_delegated();
        let was = self.delegation_withdrawn.swap(!ours, Ordering::SeqCst);
        if !ours && !was {
            tracing::error!(root = %cg.root().display(),
                "cgroup delegation withdrawn: the scope is no longer ours; kernel limits may be stale, the watchdog keeps enforcing");
        } else if ours && was {
            tracing::info!("cgroup delegation back");
        }
        if !ours {
            return;
        }
        let init: Vec<u32> = cg.init_pids().into_iter().filter(|p| *p != std::process::id()).collect();
        if !init.is_empty() {
            self.sort_strays(cg, &init, StrayScope::Init);
        } else {
            self.init_pending.lock().unwrap().clear();
        }
        let warm = cg.warm_pids();
        if !warm.is_empty() {
            self.sort_strays(cg, &warm, StrayScope::Warm);
        }
        self.rehome_assigned(cg);
    }

    /// NAN-3720: every assigned process sits in its own role's leaf. A uid
    /// shared by two roles (product runs as query's uid, maintenance as
    /// ingest's) lets the uid sweep put a process that was mid-assignment
    /// into the other role's leaf; observed on the load-test tenant: product[T] in
    /// `query/`, so 30 d prevalence rebuilds ran on interactive search's
    /// CPU quota and 4 GiB memory ceiling (page cache refaults for queries).
    fn rehome_assigned(&self, cg: &CgroupTree) {
        let slots: Vec<Arc<TenantSlot>> = self.tenants.lock().unwrap().values().cloned().collect();
        for slot in slots {
            let live: Vec<(u32, Role, u64)> = slot.procs.lock().unwrap().iter().flatten()
                .filter(|p| !p.exited.load(Ordering::SeqCst))
                .map(|p| (p.pid, p.role, p.starttime))
                .collect();
            if live.is_empty() || !cg.tenant_dir(&slot.id).exists() {
                continue;
            }
            let assigned: Vec<(u32, Role)> = live.iter().map(|(pid, role, _)| (*pid, *role)).collect();
            for (pid, role) in limits::plan_rehome(&assigned, |role| cg.role_pids(&slot.id, role)) {
                // Same process identity as assigned (never a reused pid).
                let starttime = live.iter().find(|(p, _, _)| *p == pid).map(|(_, _, t)| *t);
                let current = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()
                    .and_then(|s| procfs::parse_stat(&s)).map(|stat| stat.starttime);
                if current.is_none() || current != starttime {
                    continue;
                }
                match cg.place(pid, &slot.id, role) {
                    Ok(()) => tracing::warn!(tenant = %slot.id, pid, role = role.as_str(),
                        "assigned process was outside its role cgroup; moved into it"),
                    Err(e) => tracing::warn!(tenant = %slot.id, pid, role = role.as_str(), error = %e,
                        "assigned process is outside its role cgroup and could not be moved"),
                }
            }
        }
    }

    fn monitor_handle(&self) -> Arc<Mutex<Monitor>> {
        self.monitor.clone()
    }

    /// The cell's capacity (what guarantees and ceilings are sized against).
    pub fn capacity(&self) -> CellCapacity {
        self.monitor.lock().unwrap().capacity().clone()
    }

    /// A tenant's guarantee, soft limit and ceilings at `eps`.
    pub fn tenant_limits(&self, eps: f64) -> TenantLimits {
        TenantLimits::derive(&TenantBudget::from_eps(eps), &self.capacity(), &self.cfg.resources)
    }

    fn placement_limits(&self, p: &TenantPlacement) -> TenantLimits {
        let limits = TenantLimits::from_placement(p, &self.capacity(), &self.cfg.resources);
        let limits = if self.cfg.product_state_role { with_product_role(limits, p) } else { limits };
        if landing_wanted(self.cfg.tenzir_landing, Some(p)) { with_landing_role(limits, p) } else { limits }
    }

    fn ensure_tenant_cgroup(&self, cg: &CgroupTree, tenant: &TenantId, slot: u32, placement: &TenantPlacement) -> std::io::Result<()> {
        let limits = self.placement_limits(placement);
        cg.ensure_tenant(tenant, slot, &limits)?;
        for role in Role::ALL {
            let budget = placement.effective_role_budget(role);
            cg.set_role_cpu_max(tenant, role, budget.limit_millicores)?;
            cg.set_role_cpu_weight(tenant, role, budget.request_millicores)?;
            cg.set_role_memory(tenant, role, budget.request_memory_bytes, budget.limit_memory_bytes)?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- placement

    pub fn set_placement(self: &Arc<Self>, p: Placement) -> anyhow::Result<()> {
        p.validate(&self.cfg)?;
        let placed: std::collections::HashSet<TenantId> = p.tenants.iter().map(|t| t.tenant_id.clone()).collect();
        *self.placement.write().unwrap() = p;
        // NAN-3000: removed tenants become pending purges (after the drain).
        let placed_set: std::collections::BTreeSet<TenantId> = placed.iter().cloned().collect();
        let removed = self.ledger.update(|l| {
            let before = l.clone();
            let removed = l.on_placement(&placed_set, now_ms());
            let changed = *l != before;
            (removed, changed)
        });
        for t in &removed {
            tracing::info!(tenant = %t, "tenant removed from this cell's placement; purge pending after the drain");
        }
        self.placement_loaded.store(true, Ordering::SeqCst);
        self.purge_notify.notify_one();
        self.report_notify.notify_one();
        // Tenants moved off this cell: drain them.
        let gone: Vec<Arc<TenantSlot>> =
            self.tenants.lock().unwrap().values().filter(|s| !placed.contains(&s.id)).cloned().collect();
        for slot in gone {
            tracing::info!(tenant = %slot.id, "tenant no longer placed on this cell; draining");
            self.drain_slot(&slot);
        }
        // An eps change resizes a live tenant's cgroup right away.
        if let Some(cg) = self.cgroups.get() {
            let placement = self.placement.read().unwrap().clone();
            for tp in &placement.tenants {
                let slot = self.uidmap.lock().unwrap().get(&tp.tenant_id).map(|i| i.slot);
                if let (true, Some(slot)) = (cg.tenant_dir(&tp.tenant_id).exists(), slot) {
                    let resize = self.ensure_tenant_cgroup(cg, &tp.tenant_id, slot, tp)
                        .and_then(|_| cg.set_cpu_max(&tp.tenant_id, self.placement_limits(tp).cpu_ceiling_millicores));
                    if let Err(e) = resize {
                        tracing::warn!(tenant = %tp.tenant_id, error = %e, "cgroup resize failed");
                    }
                }
            }
        }
        // A detect[T] assigned for another rule mode, or whose engine was
        // sized for another memory limit, restarts gracefully; the next
        // wake assigns it from this placement. Likewise a query[T] whose
        // chDB threads were sized for another CPU limit (NAN-3177): it
        // drains its in-flight requests, and the next one (or the keeper,
        // when resident) starts a replacement at the new size.
        let placement = self.placement.read().unwrap().clone();
        for tp in &placement.tenants {
            let slot = self.tenants.lock().unwrap().get(&tp.tenant_id).cloned();
            let (detect, query, ingest) = slot.map(|s| {
                let procs = s.procs.lock().unwrap();
                (procs[role_idx(Role::Detect)].clone(), procs[role_idx(Role::Query)].clone(), procs[role_idx(Role::Ingest)].clone())
            }).unwrap_or_default();
            // NAN-3522: a hold set, changed or lifted takes effect at once: the
            // running ingest[T] stops gracefully (flushes, acks what it
            // committed) and the next wake/keeper assigns it the new rate.
            if let Some(p) = ingest.filter(|p| !p.exited.load(Ordering::SeqCst)) {
                if ingest_hold_needs_respawn(p.ingest_hold_eps, tp.effective_ingest_hold_eps(now_ms())) {
                    self.stop(p, "ingest_hold_changed");
                }
            }
            if let Some(p) = detect.filter(|p| !p.exited.load(Ordering::SeqCst)) {
                if detect_needs_respawn(p.runs_rules, p.memory_cap_bytes, tp, self.cfg.detect_runs_rules) {
                    self.stop(p, "detect_rule_budget_changed");
                }
            }
            if let Some(p) = query.filter(|p| !p.exited.load(Ordering::SeqCst)) {
                if query_needs_respawn(p.cpu_millis, tp.effective_role_budget(Role::Query).limit_millicores) {
                    self.stop(p, "query_cpu_budget_changed");
                }
            }
        }
        // Resident ingest starts (or stops being kept) right away.
        self.keeper_notify.notify_one();
        Ok(())
    }

    pub fn reload_placement(self: &Arc<Self>) -> anyhow::Result<()> {
        let bytes = std::fs::read(&self.cfg.placement_file)?;
        let p: Placement = serde_json::from_slice(&bytes)?;
        // The first load always applies, even when it equals the empty boot
        // placement: it is what arms the purge (an empty placement removes
        // every tenant the previous one had).
        if *self.placement.read().unwrap() != p || !self.placement_loaded.load(Ordering::SeqCst) {
            tracing::info!(revision = p.revision, tenants = p.tenants.len(), "placement updated");
            self.set_placement(p)?;
        }
        Ok(())
    }

    async fn placement_loop(self: Arc<Self>) {
        let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
        loop {
            if self.halted.load(Ordering::SeqCst) {
                return;
            }
            if let Err(e) = self.reload_placement() {
                if self.cfg.placement_file.exists() {
                    tracing::error!(error = %e, "placement reload failed; keeping the previous placement");
                }
            }
            let sleep = tokio::time::sleep(Duration::from_secs(self.cfg.placement_reload_secs.max(1)));
            match hup.as_mut() {
                Some(h) => {
                    tokio::select! { _ = sleep => {}, _ = h.recv() => {} }
                }
                None => sleep.await,
            }
        }
    }

    fn placed(&self, t: &TenantId) -> Option<TenantPlacement> {
        self.placement.read().unwrap().tenants.iter().find(|p| &p.tenant_id == t).cloned()
    }

    fn slot(&self, t: &TenantId) -> Result<(Arc<TenantSlot>, TenantPlacement), CellError> {
        let placement = self.placed(t).ok_or_else(|| CellError::NotPlaced(t.clone()))?;
        let mut tenants = self.tenants.lock().unwrap();
        if let Some(s) = tenants.get(t) {
            return Ok((s.clone(), placement));
        }
        // Checked under the tenants lock, which `purge_tenant` also holds
        // while it fences: a tenant placed back mid-purge waits it out.
        if self.purging.lock().unwrap().contains(t) {
            return Err(CellError::Unavailable(format!("tenant {t} is being purged from this cell; retry shortly")));
        }
        let ids = self.uidmap.lock().unwrap().get_or_allocate(t).map_err(|e| CellError::Spawn(e.to_string()))?;
        let slot = Arc::new(TenantSlot::new(t.clone(), ids));
        if let Some(cg) = self.cgroups.get() {
            cg.register(t, ids.slot);
        }
        tenants.insert(t.clone(), slot.clone());
        Ok((slot, placement))
    }

    // ---------------------------------------------------------------- directories

    fn tenant_root(&self, t: &TenantId) -> PathBuf {
        self.cfg.data_dir.join("tenants").join(t.as_str())
    }

    /// NAN-3799: see [`product_dir_for`].
    fn product_dir(&self, t: &TenantId) -> PathBuf {
        product_dir_for(&self.tenant_root(t), t.as_str(), persistent_hot_tenants_dir().as_deref())
    }

    /// Create/repair the tenant tree under the cell's exact capability set
    /// (see [`crate::tenant_dirs`]). Blocking filesystem work off the
    /// runtime; the fsuid/fsgid-switched walk itself runs on its own
    /// dedicated thread inside `ensure_tenant_tree`.
    ///
    /// NAN-4128: takes the tenant's dirs guard and moves it into the blocking
    /// task, so a caller that times out never lets a second walk start
    /// while this one still runs.
    async fn ensure_tenant_dirs(&self, t: &TenantId, ids: &TenantIds, dirs_guard: tokio::sync::OwnedMutexGuard<()>) -> std::io::Result<()> {
        let tenants = self.cfg.data_dir.join("tenants");
        let tenant = t.as_str().to_owned();
        let ids = *ids;
        // NAN-3875: every other PLACED tenant's ids. A directory of this
        // tree owned by one of them belongs to another live tenant: never
        // reclaimed. Durable data (the data volume) is refused, fail closed;
        // the rebuildable hot tree is quarantined, purged and recreated.
        let placed: std::collections::BTreeSet<TenantId> =
            self.placement.read().unwrap().tenants.iter().map(|p| p.tenant_id.clone()).collect();
        let foreign = self.uidmap.lock().unwrap().foreign_ids(t, &placed);
        let external = local_hot_window_enabled().then(|| std::env::var_os("NANO_LAKE_LOCAL_HOT_WINDOW_DIR")).flatten();
        let quarantine = hot_quarantine_dir();
        tokio::task::spawn_blocking(move || {
            let _dirs_guard = dirs_guard;
            crate::tenant_dirs::ensure_tenant_tree_guarded(&tenants, &tenant, &ids, &foreign)?;
            if let Some(base) = external {
                let base = PathBuf::from(base);
                if !base.is_absolute() { return Err(std::io::Error::other("hot-window directory must be absolute")); }
                let tenants = base.join("tenants");
                std::fs::create_dir_all(&tenants)?;
                ensure_rebuildable_tree(&tenants, &tenant, &ids, &foreign, quarantine.as_deref())?;
            }
            Ok(())
        })
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(format!("tenant dirs task: {e}"))))
    }

    // ---------------------------------------------------------------- spawning

    fn binary(&self, role: Role) -> &Path {
        match role {
            Role::Ingest => &self.cfg.ingest_binary,
            Role::Detect => &self.cfg.query_binary,
            Role::Query => &self.cfg.query_binary,
            // The ingest binary serves the maintenance role (its exchange,
            // owner client and SlateDB build), dispatched on the assignment.
            Role::Maintenance => &self.cfg.ingest_binary,
            // The query binary builds product state (NAN-3148).
            Role::Product => &self.cfg.query_binary,
            // The ingest binary serves landing[T] (NAN-4137): the shared
            // landing conversion, dispatched on the assignment's role.
            Role::Landing => &self.cfg.ingest_binary,
        }
    }

    /// Start an unassigned process and wait for its `Hello`.
    async fn spawn_warm(&self, role: Role) -> Result<WarmProc, CellError> {
        let err = |e: std::io::Error| CellError::Spawn(e.to_string());
        let (ours, theirs) = fdpass::seqpacket_pair().map_err(err)?;
        let theirs_raw = theirs.as_raw_fd();
        let mut cmd = tokio::process::Command::new(self.binary(role));
        cmd.arg(CONTROL_FD_FLAG)
            .arg(CONTROL_FD.to_string())
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        if let Ok(v) = std::env::var("RUST_LOG") {
            cmd.env("RUST_LOG", v);
        }
        // No endpoint or credential enters a tenant jail: static operation spans
        // use the existing stdout pipe and the region shipper owns export.
        if std::env::var("NANO_OTLP_TRACE_STDOUT").as_deref() == Ok("1") {
            cmd.env("NANO_OTLP_TRACE_STDOUT", "1")
                .env("NANO_OTLP_TRACE_SERVICE", format!("nano-lake-{}", role.as_str()));
        }
        forward_feature_env(&mut cmd, |name| {
            if !feature_allowed_for_role(name, role) { None }
            else { std::env::var_os(name) }
        });
        // NAN-3523: warm and tenant processes rank above the supervisor for
        // the OOM killer (raising needs no capability).
        let oom_adj = crate::oom::report(self.cfg.resources.tenant_oom_score_adj).tenant_adj;
        let pre_exec_adj = crate::oom::PreExecAdj::new(oom_adj);
        // SAFETY: only async-signal-safe calls (dup2, fcntl, prctl, and
        // open/write/close for oom_score_adj).
        unsafe {
            cmd.pre_exec(move || {
                // Best effort; checked after spawn.
                let _ = pre_exec_adj.apply();
                if theirs_raw == CONTROL_FD {
                    let f = libc::fcntl(CONTROL_FD, libc::F_GETFD);
                    if f < 0 || libc::fcntl(CONTROL_FD, libc::F_SETFD, f & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(theirs_raw, CONTROL_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // Own session (and process group): no controlling terminal,
                // no signals from the supervisor's group.
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let started = Instant::now();
        let mut child = cmd.spawn().map_err(err)?;
        drop(theirs);
        let pid = child.id().ok_or_else(|| CellError::Spawn("child exited immediately".into()))?;
        let pidfd = PidFd::open(pid).map_err(err)?;
        match crate::oom::read_adj(Some(pid)) {
            Ok(adj) if adj >= oom_adj => {}
            seen => tracing::warn!(role = role.as_str(), pid, want = oom_adj, ?seen, "child oom_score_adj not raised"),
        }
        // Our unreaped child: its pid cannot be recycled, so this read is its identity.
        let starttime = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| procfs::parse_stat(&s))
            .map(|s| s.starttime)
            .ok_or_else(|| CellError::Spawn(format!("no /proc/{pid}/stat")))?;
        if let Some(cg) = self.cgroups.get() {
            if let Err(e) = cg.place_warm(pid) {
                pidfd.kill();
                return Err(CellError::Spawn(format!("cgroup warm placement: {e}")));
            }
        }
        let label: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
        forward_output(child.stdout.take(), pid, role, label.clone());
        forward_output(child.stderr.take(), pid, role, label.clone());
        let control = Arc::new(AsyncSeqpacket::new(ours).map_err(err)?);
        let hello = tokio::time::timeout(self.cfg.spawn_timeout(), control.recv_json::<ToSupervisor>()).await;
        match hello {
            Ok(Ok(Some((ToSupervisor::Hello { pid: p, protocol_version }, _))))
                if p == pid && protocol_version == PROTOCOL_VERSION => {}
            other => {
                pidfd.kill();
                return Err(CellError::Spawn(format!("bad hello from {pid}: {other:?}")));
            }
        }
        tracing::debug!(role = role.as_str(), pid, ms = started.elapsed().as_millis() as u64, "process hello");
        Ok(WarmProc { pid, child, control, pidfd, starttime, label })
    }

    fn jail_spec(
        &self,
        t: &TenantId,
        role: Role,
        ids: &TenantIds,
        budget: &TenantBudget,
        cgroups: Option<&CgroupTree>,
        placement: &TenantPlacement,
    ) -> JailSpec {
        let root = self.tenant_root(t);
        let product = self.product_dir(t);
        let (mut rw, mut ro) = role_mounts(&root, role, self.cfg.product_state_role, &product);
        if role == Role::Query && local_hot_window_enabled() {
            if let Some(base) = std::env::var_os("NANO_LAKE_LOCAL_HOT_WINDOW_DIR") {
                rw.push(PathBuf::from(base).join("tenants").join(t.as_str()).join("query"));
            }
        }
        // NAN-4183: ingest[T] keeps its GC view on the persistent hot volume.
        if role == Role::Ingest {
            rw.extend(part_gc_state_dir_for(t.as_str(), persistent_hot_tenants_dir().as_deref()));
        }
        // NAN-4137: landing[T] converts untrusted sender files; it gets no
        // shared or tenant input path at all (feed, policy, custom context).
        let tenant_inputs = role != Role::Landing;
        if let Some(f) = self.cfg.feed_dir.as_ref().filter(|_| tenant_inputs) {
            ro.push(f.clone());
        }
        // The owner-sign CA bundle: its directory, not the file, because a
        // Kubernetes Secret/ConfigMap file is a symlink into `..data/`.
        // Detect signs finding parts with the same owner (NAN-2916).
        if matches!(role, Role::Ingest | Role::Detect | Role::Maintenance) {
            if let Some(dir) = self.cfg.part_signing_ca_dir() {
                ro.push(dir.to_path_buf());
            }
        }
        if let Some(policy) = placement.platform_policy_file.as_ref().filter(|_| tenant_inputs) {
            if let Some(parent) = policy.parent() { ro.push(parent.to_path_buf()); }
        }
        if let Some(custom) = placement.custom_context_root.as_ref().filter(|_| tenant_inputs) { ro.push(custom.clone()); }
        if role == Role::Query && local_hot_window_enabled() {
            let base = std::env::var_os("NANO_LAKE_LOCAL_HOT_WINDOW_DIR")
                .map(PathBuf::from).unwrap_or_else(|| self.cfg.data_dir.clone());
            ro.push(base.join(crate::volume_usage::SOCKET));
        }
        let mut system = self.cfg.system_ro_paths.clone();
        system.extend(self.cfg.extra_ro_paths.iter().cloned());
        if let Some(dir) = self.binary(role).parent() {
            system.push(dir.to_path_buf());
        }
        JailSpec {
            uid: ids.uid(role),
            gid: ids.gid,
            rw_paths: rw,
            ro_paths: ro,
            system_ro_paths: system,
            tcp_connect_ports: self.cfg.tcp_connect_ports.clone(),
            cgroup_dir: cgroups.map(|c| c.role_rel(t, role)),
            // Query shares the tenant gid with detect, which has group-write
            // access to parts. Without Landlock, query would inherit that
            // local write permission through DAC even with read-only R2 keys.
            require_landlock: self.cfg.require_landlock || (!self.cfg.trusted_local && matches!(role, Role::Query | Role::Detect | Role::Product | Role::Landing)),
            // RLIMIT_NPROC is per uid. Split the tenant cap across roles.
            max_processes: Some((budget.max_pids / 3).max(64)),
            max_open_files: 65_536,
        }
    }

    /// Turn a warm process into `role` for tenant `slot`.
    async fn assign(
        self: &Arc<Self>,
        warm: WarmProc,
        slot: &Arc<TenantSlot>,
        placement: &TenantPlacement,
        role: Role,
        progress: &Progress,
    ) -> Result<Arc<Proc>, CellError> {
        let WarmProc { pid, child, control, pidfd, starttime, label } = warm;
        let fail = |pidfd: &PidFd, msg: String| {
            pidfd.kill();
            CellError::Spawn(msg)
        };
        let t = &slot.id;
        let budget = TenantBudget::from_eps(placement.eps);
        if let Err(e) = validate_enrichment_mounts(&self.cfg, placement) {
            return Err(fail(&pidfd, format!("enrichment mounts: {e}")));
        }
        let to = self.cfg.spawn_timeout();
        // A hot-tree quarantine/rebuild (NAN-3875) can legitimately outlast
        // one step timeout, so the tree ensure is bounded by the attempt's
        // overall deadline only. Its guard travels into the blocking walk:
        // a torn-down attempt never lets a second walk start beside it.
        progress.set("tenant_dirs_lock");
        let dirs_guard = slot.dirs_lock.clone().lock_owned().await;
        progress.set("tenant_dirs");
        if let Err(e) = self.ensure_tenant_dirs(t, &slot.ids, dirs_guard).await {
            return Err(fail(&pidfd, format!("tenant dirs: {e}")));
        }
        progress.set("cgroup");
        // One snapshot for the whole assignment: a live adoption in the
        // middle must not leave the process placed but jailed without its
        // cgroup (or the reverse). A process assigned just before adoption
        // is picked up by the per-tick reconcile.
        let cgroups = self.cgroups.get();
        if let Some(cg) = cgroups {
            let fresh = !cg.tenant_dir(t).exists();
            if let Err(e) =
                self.ensure_tenant_cgroup(cg, t, slot.ids.slot, placement).and_then(|_| cg.place(pid, t, role))
            {
                return Err(fail(&pidfd, format!("cgroup: {e}")));
            }
            if fresh {
                slot.stats.lock().unwrap().oom_seen_in_cgroup = 0;
            }
        }
        let _ = label.set(format!("{}/{}", t, role.as_str()));
        let root = self.tenant_root(t);
        let jail = self.jail_spec(t, role, &slot.ids, &budget, cgroups, placement);
        let assignment = Assignment {
            outbound_proxy: assignment_proxy(&self.cfg, t).await?,
            tenant: t.clone(),
            role,
            cell_id: self.cfg.cell_id.clone(),
            tenant_dir: root.clone(),
            parts_dir: root.join("parts"),
            state_dir: root.join(role.as_str()),
            tmp_dir: root.join(role.as_str()).join("tmp"),
            feed_dir: self.cfg.feed_dir.clone(),
            platform_bundle_file: self.cfg.platform_bundle_file.clone(),
            platform_bundle_dir: self.cfg.platform_bundle_dir.clone(),
            platform_policy_file: placement.platform_policy_file.clone(),
            custom_context_root: placement.custom_context_root.clone(),
            memory_cap_bytes: match role {
                Role::Ingest => placement.effective_role_budget(Role::Ingest).limit_memory_bytes.min(budget.ingest_memory_cap_bytes),
                Role::Detect => placement.effective_role_budget(Role::Detect).limit_memory_bytes,
                Role::Query => placement.effective_role_budget(Role::Query).limit_memory_bytes,
                Role::Maintenance => placement.effective_role_budget(Role::Maintenance).limit_memory_bytes,
                Role::Product => placement.effective_role_budget(Role::Product).limit_memory_bytes,
                Role::Landing => placement.effective_role_budget(Role::Landing).limit_memory_bytes,
            },
            cpu_millis: placement.effective_role_budget(role).limit_millicores,
            eps: placement.eps,
            jail: jail.clone(),
            control_url: self.cfg.control_url.clone(),
            prevalence_rarity_threshold: placement.prevalence_rarity_threshold,
            // Maintenance uses only its CA (the owner endpoint's trust).
            part_signing: match role {
                Role::Ingest | Role::Detect | Role::Maintenance => self.cfg.part_signing.clone(),
                Role::Query | Role::Product | Role::Landing => None,
            },
            owner_requires_checksum: self.cfg.owner_requires_checksum,
            // A resident ingest must not exit on its own when idle: the
            // keeper would only count it as a crash and respawn it.
            ingest_idle_exit: match placement.ingest {
                IngestMode::Resident if role == Role::Ingest => Some(false),
                _ => self.cfg.ingest_idle_exit,
            },
            ingest_day_merges: self.cfg.ingest_day_merges,
            ingest_keyword_index: self.cfg.ingest_keyword_index,
            identity_observations: match role {
                Role::Ingest | Role::Query => self.cfg.identity_observations,
                Role::Detect | Role::Maintenance | Role::Product | Role::Landing => false,
            },
            identity_directory_enrich: matches!(role, Role::Ingest) && self.cfg.identity_directory_enrich,
            ingest_flush: match role {
                Role::Ingest => self.cfg.ingest_flush,
                Role::Detect | Role::Query | Role::Maintenance | Role::Product | Role::Landing => None,
            },
            ingest_merge_policy: match role {
                Role::Ingest => self.cfg.ingest_merge_policy,
                Role::Detect | Role::Query | Role::Maintenance | Role::Product | Role::Landing => None,
            },
            ingest_hold_eps: match role {
                Role::Ingest => placement.effective_ingest_hold_eps(now_ms()),
                Role::Detect | Role::Query | Role::Maintenance | Role::Product | Role::Landing => None,
            },
            // NAN-3004: the startup warm of a zero-downtime pod gates its
            // first readiness on the prewarm; later respawns stay lazy.
            query_prewarm_before_ready: role == Role::Query && self.handover.as_ref().is_some_and(|h| !h.warm()),
            detect_runs_rules: role == Role::Detect && placement.detect_runs_rules(self.cfg.detect_runs_rules),
            product_state_role: role == Role::Query && self.cfg.product_state_role,
            product_dir: matches!(role, Role::Query | Role::Product).then(|| self.product_dir(t)),
            trusted_local: self.cfg.trusted_local,
            // NAN-4052: the Postgres writer lease, wherever pods hand over.
            writer_lease: match role {
                Role::Ingest => self.handover.as_ref().map(|h| h.writer_lease_assignment()),
                Role::Detect | Role::Query | Role::Maintenance | Role::Product | Role::Landing => None,
            },
            // NAN-4183: the GC view on the persistent hot volume (mounted rw above).
            part_gc_state_dir: match role {
                Role::Ingest => part_gc_state_dir_for(t.as_str(), persistent_hot_tenants_dir().as_deref()),
                Role::Detect | Role::Query | Role::Maintenance | Role::Product | Role::Landing => None,
            },
        };
        if let Err(e) = check_assignment_signing(&self.cfg, &assignment) {
            return Err(fail(&pidfd, format!("assignment: {e}")));
        }
        let (runs_rules, memory_cap_bytes, cpu_millis, ingest_hold_eps) =
            (assignment.detect_runs_rules, assignment.memory_cap_bytes, assignment.cpu_millis, assignment.ingest_hold_eps);
        let msg = ToChild::Assign { protocol_version: PROTOCOL_VERSION, assignment: Box::new(assignment) };
        // NAN-3139: the jail denies socket(AF_UNIX) and pathname-unix
        // connects, so a query process reaches the volume accountant only
        // through a connection we create for it and pass with the assignment.
        let accountant_fd = match (role, self.volume_accountant.get()) {
            (Role::Query, Some(accountant)) => match accountant.pair() {
                Ok(fd) => Some(fd),
                Err(error) => {
                    tracing::warn!(tenant = %t, %error, "volume accountant connection unavailable for query process");
                    None
                }
            },
            _ => None,
        };
        let fds: Vec<_> = accountant_fd.iter().map(|fd| fd.as_fd()).collect();
        progress.set("send_assign");
        match tokio::time::timeout(to, control.send_json(&msg, &fds)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(fail(&pidfd, format!("send assign: {e}"))),
            Err(_) => return Err(fail(&pidfd, format!("send assign: not accepted after {}s", to.as_secs()))),
        }
        progress.set("jailed");
        match tokio::time::timeout(to, control.recv_json::<ToSupervisor>()).await {
            Ok(Ok(Some((ToSupervisor::Jailed { uid, gid, landlock, seccomp }, _))))
                if uid == jail.uid && gid == jail.gid && seccomp =>
            {
                // Trust, then verify: the kernel's view of the credentials.
                match read_status_ids(pid) {
                    Some((u, g)) if u.iter().all(|x| *x == jail.uid) && g.iter().all(|x| *x == jail.gid) => {}
                    other => return Err(fail(&pidfd, format!("credential check failed: {other:?}"))),
                }
                if jail.require_landlock && landlock == "none" {
                    return Err(fail(&pidfd, "landlock not enforced".into()));
                }
                // Each role's token is bound to that role; detect exchanges as detect.
                progress.set("mint_bootstrap_token");
                let minted = mint_awaiting_assignment(
                    self.keys.as_ref(), t, role, to, self.precondition_wait(), &self.stopping_all,
                ).await;
                let secret = match minted {
                    Ok(s) => s,
                    Err(e) => {
                        if let Some(r) = e.downcast_ref::<crate::secrets::MintRefused>() {
                            self.note_spawn_refused(slot, role, r);
                        }
                        return Err(fail(&pidfd, format!("mint bootstrap token: {e}")));
                    }
                };
                // NAN-3569: a slow mint may finish after SIGTERM. The child
                // has no credentials yet, so kill it before it can become a writer.
                if matches!(role, Role::Ingest | Role::Detect | Role::Maintenance)
                    && self.handover.as_ref().is_some_and(|h| h.draining())
                {
                    return Err(fail(&pidfd, "cell began draining during writer bootstrap".into()));
                }
                let memfd = match fdpass::secret_memfd(&secret) {
                    Ok(f) => f,
                    Err(e) => return Err(fail(&pidfd, format!("memfd: {e}"))),
                };
                drop(secret);
                progress.set("send_secrets");
                match tokio::time::timeout(to, control.send_json(&ToChild::Secrets, &[memfd.as_fd()])).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(fail(&pidfd, format!("send secrets: {e}"))),
                    Err(_) => return Err(fail(&pidfd, format!("send secrets: not accepted after {}s", to.as_secs()))),
                }
                drop(memfd);
                progress.set("ready");
                match tokio::time::timeout(to, control.recv_json::<ToSupervisor>()).await {
                    Ok(Ok(Some((ToSupervisor::Ready, _)))) => {}
                    other => return Err(fail(&pidfd, format!("expected ready: {other:?}"))),
                }
                if self.cgroups.get().is_none() {
                    // SAFETY: setpriority on a live child pid we own.
                    unsafe { libc::setpriority(libc::PRIO_PROCESS, pid, 10) };
                }
                let now = Instant::now();
                let proc = Arc::new(Proc {
                    pid,
                    role,
                    tenant: t.clone(),
                    uid,
                    landlock,
                    runs_rules,
                    memory_cap_bytes,
                    cpu_millis,
                    control: control.clone(),
                    pidfd,
                    starttime,
                    started: now,
                    spawned_unix_ms: now_ms(),
                    ingest_hold_eps,
                    last_activity: Mutex::new(now),
                    heartbeat: Mutex::new((now, Heartbeat::default())),
                    last_busy: Mutex::new(now),
                    busy_seen: Mutex::new(None),
                    stopping: AtomicBool::new(false),
                    killed: Mutex::new(None),
                    exited: AtomicBool::new(false),
                    next_request: AtomicU64::new(1),
                    inflight: AtomicU64::new(0),
                    pending_finding: Mutex::new(std::collections::HashSet::new()),
                });
                slot.stats.lock().unwrap().spawns[role_idx(role)] += 1;
                tracing::info!(tenant = %t, role = role.as_str(), pid, uid, landlock = %proc.landlock,
                    "tenant process ready");
                self.spawn_control_reader(proc.clone());
                self.spawn_waiter(proc.clone(), slot.clone(), child);
                Ok(proc)
            }
            Ok(Ok(Some((ToSupervisor::Fatal { error }, _)))) => Err(fail(&pidfd, format!("child: {error}"))),
            other => Err(fail(&pidfd, format!("expected jailed: {other:?}"))),
        }
    }

    fn spawn_control_reader(self: &Arc<Self>, proc: Arc<Proc>) {
        let keys = self.keys.clone();
        let supervisor = self.clone();
        tokio::spawn(async move {
            let pacer = Arc::new(Mutex::new(RefreshPacer::new(REFRESH_MIN_INTERVAL)));
            loop {
                match proc.control.recv_json::<ToSupervisor>().await {
                    Ok(Some((ToSupervisor::RefreshSecrets, _))) => {
                        // At most one fresh bootstrap per REFRESH_MIN_INTERVAL;
                        // an early request is answered at the interval's end,
                        // never dropped (NAN-4326).
                        let pace = pacer.lock().unwrap().request(Instant::now());
                        match pace {
                            RefreshPace::MintNow => send_fresh_secret(&keys, &proc).await,
                            RefreshPace::DeferUntil(at) => {
                                tracing::info!(tenant = %proc.tenant, role = proc.role.as_str(), pid = proc.pid,
                                    defer_ms = at.saturating_duration_since(Instant::now()).as_millis() as u64,
                                    "refresh request inside the mint interval; answering at its end");
                                let (keys, proc, pacer) = (keys.clone(), proc.clone(), pacer.clone());
                                tokio::spawn(async move {
                                    tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
                                    pacer.lock().unwrap().deferred_due(Instant::now());
                                    if !proc.exited.load(Ordering::SeqCst) {
                                        send_fresh_secret(&keys, &proc).await;
                                    }
                                });
                            }
                            RefreshPace::AlreadyDeferred => {
                                tracing::debug!(tenant = %proc.tenant, pid = proc.pid, "refresh request coalesced into the deferred one");
                            }
                        }
                    }
                    Ok(Some((ToSupervisor::Heartbeat(mut hb), _))) => {
                        // Tenant-controlled text flows into alerts: bound it.
                        if let Some(d) = hb.detail.as_mut() {
                            *d = d.chars().filter(|c| !c.is_control()).take(200).collect();
                        }
                        let now = Instant::now();
                        if hb.busy {
                            *proc.last_busy.lock().unwrap() = now;
                            *proc.busy_seen.lock().unwrap() = Some(now);
                        }
                        let mut previous = proc.heartbeat.lock().unwrap();
                        let observed = heartbeat_progress_at(&previous, &hb, now);
                        *previous = (observed, hb);
                    }
                    Ok(Some((ToSupervisor::ConnectIngest { request_id }, _))) => {
                        if proc.role != Role::Detect {
                            tracing::warn!(tenant = %proc.tenant, role = proc.role.as_str(), "non-Detect peer request refused");
                            continue;
                        }
                        let result = async {
                            let ingest = supervisor.ensure_running(&proc.tenant, Role::Ingest).await?;
                            let (detect_end, ingest_end) = fdpass::stream_pair()
                                .map_err(|e| CellError::Unavailable(e.to_string()))?;
                            let append_id = ingest.next_request.fetch_add(1, Ordering::Relaxed);
                            ingest.pending_finding.lock().unwrap().insert(append_id);
                            ingest.inflight.fetch_add(1, Ordering::SeqCst);
                            ingest.touch();
                            if let Err(error) = ingest.control.send_json(&ToChild::FindingAppend { request_id: append_id }, &[ingest_end.as_fd()]).await {
                                if ingest.pending_finding.lock().unwrap().remove(&append_id) {
                                    ingest.inflight.fetch_sub(1, Ordering::SeqCst);
                                    ingest.touch();
                                }
                                return Err(CellError::Unavailable(error.to_string()));
                            }
                            // Once ingest has its endpoint, only its completion
                            // releases in-flight protection, even if Detect
                            // disconnects before receiving the peer endpoint.
                            proc.control.send_json(&ToChild::PeerRpc { request_id }, &[detect_end.as_fd()]).await
                                .map_err(|e| CellError::Unavailable(e.to_string()))?;
                            Ok::<(), CellError>(())
                        }.await;
                        if let Err(error) = result {
                            tracing::warn!(tenant = %proc.tenant, request_id, %error, "tenant ingest peer connection refused");
                        }
                    }
                    Ok(Some((ToSupervisor::FindingAppendComplete { request_id }, _))) => {
                        if proc.role == Role::Ingest && proc.pending_finding.lock().unwrap().remove(&request_id) {
                            proc.inflight.fetch_sub(1, Ordering::SeqCst);
                            proc.touch();
                        } else {
                            tracing::warn!(tenant = %proc.tenant, request_id, "unexpected finding append completion");
                        }
                    }
                    Ok(Some((ToSupervisor::Fatal { error }, _))) => {
                        tracing::error!(tenant = %proc.tenant, role = proc.role.as_str(), pid = proc.pid, %error,
                            "tenant process reported a fatal error");
                    }
                    Ok(Some((other, _))) => {
                        tracing::warn!(tenant = %proc.tenant, pid = proc.pid, ?other, "unexpected control message");
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        });
    }

    fn spawn_waiter(self: &Arc<Self>, proc: Arc<Proc>, slot: Arc<TenantSlot>, mut child: tokio::process::Child) {
        let me = self.clone();
        tokio::spawn(async move {
            let status = child.wait().await;
            proc.exited.store(true, Ordering::SeqCst);
            // Nothing of this role may outlive it (double-forked orphans
            // included): kill everything left under its uid. Under the
            // role's spawn lock, so a replacement cannot be mid-assignment;
            // one that already took over (and its children) is spared.
            {
                let i = role_idx(proc.role);
                let cleanup = Progress::new("exit_cleanup");
                let _g = slot.spawn_lock[i].lock_logged(&cleanup, slot.id.as_str(), proc.role.as_str(), LOCK_WAIT_LOG_EVERY).await;
                cleanup.set("kill_role_leftovers");
                let replacement = slot.procs.lock().unwrap()[i]
                    .as_ref()
                    .filter(|p| !Arc::ptr_eq(p, &proc) && !p.exited.load(Ordering::SeqCst))
                    .map(|p| (p.pid, p.starttime));
                // Roles sharing this uid (maintenance runs as ingest's) are
                // never leftovers of this one: cell26, 2026-09-30, every
                // maintenance crash killed the tenant's ingest.
                let siblings = shared_uid_siblings(&slot, proc.role);
                let (me2, slot2, role) = (me.clone(), slot.clone(), proc.role);
                let _ = tokio::task::spawn_blocking(move || me2.kill_role_leftovers(&slot2, role, replacement, &siblings)).await;
            }
            me.on_exit(&slot, &proc, status);
        });
    }

    /// SIGKILL every process running as `role`'s uid of `slot` except
    /// `replacement` (this role's successor), live `siblings` (other roles
    /// sharing the uid) and their descendants; with delegation and no
    /// replacement, the role's own `cgroup.kill` too (role-scoped).
    fn kill_role_leftovers(&self, slot: &TenantSlot, role: Role, replacement: Option<ProcKey>, siblings: &[ProcKey]) -> usize {
        if replacement.is_none() {
            if let Some(cg) = self.cgroups.get() {
                let _ = cg.kill_role(&slot.id, role);
            }
        }
        let keep = replacement.into_iter().chain(siblings.iter().copied()).collect::<Vec<_>>();
        let left = procfs::processes_of_keeping(&procfs::scan(), &[slot.ids.uid(role)], &keep);
        let n = kill_all(&left);
        if n > 0 {
            tracing::warn!(tenant = %slot.id, role = role.as_str(), killed = n, "killed leftover tenant processes (orphans)");
        }
        n
    }

    /// SIGKILL every process under any of `uids` (a tenant moved off the
    /// cell, or leftovers from a previous supervisor).
    fn kill_uids(uids: &[u32]) -> usize {
        kill_all(&procfs::processes_of(&procfs::scan(), uids, None))
    }

    fn on_exit(&self, slot: &Arc<TenantSlot>, proc: &Arc<Proc>, status: std::io::Result<std::process::ExitStatus>) {
        use std::os::unix::process::ExitStatusExt;
        let i = role_idx(proc.role);
        {
            let mut procs = slot.procs.lock().unwrap();
            if procs[i].as_ref().is_some_and(|p| Arc::ptr_eq(p, proc)) {
                procs[i] = None;
            }
        }
        let desc = match &status {
            Ok(s) => match (s.code(), s.signal()) {
                (Some(c), _) => format!("exit {c}"),
                (_, Some(sig)) => format!("signal {sig}"),
                _ => "unknown".into(),
            },
            Err(e) => format!("wait error: {e}"),
        };
        let stopping = proc.stopping.load(Ordering::SeqCst);
        let killed = *proc.killed.lock().unwrap();
        let clean = matches!(&status, Ok(s) if s.success());
        // NAN-4052: ingest found the cell writer lease held elsewhere (or
        // lost it). Standby, not a crash: no crash count, no backoff growth;
        // this pod's other writers of the tenant stop, and it retries later.
        let standby = proc.role == Role::Ingest
            && killed.is_none()
            && matches!(&status, Ok(s) if s.code() == Some(crate::contract::WRITER_STANDBY_EXIT_CODE));
        if standby {
            let retry = self.handover.as_ref().map_or(Duration::from_secs(20), |h| h.standby_retry());
            {
                let mut st = slot.stats.lock().unwrap();
                st.writer_standby_until = Some(Instant::now() + retry);
                st.writer_standby_reason = Some(format!("cell writer lease held by another pod generation (ingest pid {} exited standby)", proc.pid));
            }
            tracing::warn!(tenant = %slot.id, pid = proc.pid, retry_secs = retry.as_secs(),
                "ingest is standby: the cell writer lease is held by another pod generation; stopping this pod's writers for the tenant");
            let others: Vec<Arc<Proc>> = [Role::Detect, Role::Maintenance]
                .iter()
                .filter_map(|r| slot.procs.lock().unwrap()[role_idx(*r)].clone())
                .filter(|p| !p.exited.load(Ordering::SeqCst))
                .collect();
            for p in others {
                self.stop(p, "writer_lease_standby");
            }
        }
        let now = Instant::now();
        // OOM accounting from the tenant cgroup (kernel truth).
        let cgroup_oom = self.note_cgroup_ooms(slot);
        let mut st = slot.stats.lock().unwrap();
        // The watchdog pass may have folded this OOM in a moment earlier.
        let sigkill = matches!(&status, Ok(s) if s.signal() == Some(libc::SIGKILL));
        let cgroup_oom = cgroup_oom
            || (sigkill && self.cgroups.get().is_some() && st.recent_ooms.back().is_some_and(|t| now.duration_since(*t) < Duration::from_secs(5)));
        if (stopping && (clean || killed == Some("shutdown_grace"))) || standby {
            st.reaps[i] += 1;
        } else if killed.is_none() {
            if !cgroup_oom {
                st.crashes[i] += 1;
                st.recent_crashes.push_back(now);
            }
            self.backoff(&mut st, i, now);
        } else if killed.is_some_and(|k| k.starts_with("watchdog_")) {
            self.backoff(&mut st, i, now);
        }
        st.last_exit = Some(format!("{} pid {}: {desc}{}", proc.role.as_str(), proc.pid,
            killed.map(|k| format!(" (killed: {k})")).unwrap_or_default()));
        tracing::info!(tenant = %slot.id, role = proc.role.as_str(), pid = proc.pid, status = %desc,
            stopping, killed = ?killed, "tenant process exited");
        drop(st);
        self.maybe_remove_tenant_cgroup(slot);
        if proc.role == Role::Ingest {
            self.keeper_notify.notify_one();
        }
    }

    fn backoff(&self, st: &mut TenantStats, i: usize, now: Instant) {
        let r = &self.cfg.resources;
        let (mut base, mut max) = (Duration::from_millis(r.restart_backoff_base_ms), Duration::from_millis(r.restart_backoff_max_ms));
        if i == role_idx(Role::Maintenance) || i == role_idx(Role::Product) {
            // A failing compactor (or product builder) is never urgent:
            // 10 s doubling to 10 min.
            base = base.max(MAINTENANCE_BACKOFF_BASE);
            max = max.max(MAINTENANCE_BACKOFF_MAX);
        }
        st.backoff(i, now, base, max);
    }

    /// Fold new `oom_kill`s from the tenant's `memory.events` into its stats
    /// (one `cgroup_oom_kill` event each). Returns whether there were any.
    fn note_cgroup_ooms(&self, slot: &Arc<TenantSlot>) -> bool {
        let Some(cg) = self.cgroups.get() else { return false };
        let Some(u) = cg.usage(&slot.id) else { return false };
        let mut st = slot.stats.lock().unwrap();
        if u.oom_kills <= st.oom_seen_in_cgroup {
            return false;
        }
        let n = u.oom_kills - st.oom_seen_in_cgroup;
        st.oom_seen_in_cgroup = u.oom_kills;
        st.oom_kills += n;
        let now = Instant::now();
        let limit = self.placed(&slot.id).map(|p| self.placement_limits(&p).memory_hard_bytes).unwrap_or(0);
        for _ in 0..n {
            st.recent_ooms.push_back(now);
        }
        let observed = u.memory_peak_bytes.max(u.memory_bytes) as f64;
        let e = LimitEvent::new(Some(&slot.id), EventKind::CgroupOomKill, "memory_max", observed, limit as f64, "bytes");
        e.log();
        st.record(e);
        true
    }

    /// Remove the tenant's cgroup once nothing of it runs. Returns false,
    /// touching nothing, while a spawn for any of its roles is in flight.
    ///
    /// NAN-2971: a spawn publishes its process in `procs` only after
    /// `assign` has created the tenant cgroup and placed the pid in it. A
    /// reaper tick in between saw "no procs, empty leaves", removed the
    /// cgroup, and the placement failed with ENOENT ("spawn failed: cgroup:
    /// No such file or directory"). Holding every role's spawn lock (without
    /// waiting) for the check-and-remove keeps a spawn out of that window. A
    /// failed spawn still holds its own lock here, so its cleanup is left to
    /// the next reaper tick.
    fn maybe_remove_tenant_cgroup(&self, slot: &Arc<TenantSlot>) -> bool {
        let Ok(_no_spawn) = slot.spawn_lock.iter().map(|l| l.try_lock()).collect::<Result<Vec<_>, _>>() else {
            return false;
        };
        let Some(cg) = self.cgroups.get() else { return true };
        if slot.procs.lock().unwrap().iter().any(|p| p.is_some()) {
            return true;
        }
        let usage = cg.usage(&slot.id);
        match cg.remove_tenant_if_empty(&slot.id) {
            Ok(true) => {
                if let Some(u) = usage {
                    slot.stats.lock().unwrap().cpu_usec_retired += u.cpu_usage_usec;
                }
            }
            Ok(false) => {}
            Err(e) => tracing::debug!(tenant = %slot.id, error = %e, "tenant cgroup not removed yet"),
        }
        true
    }

    /// Return the tenant's running `role` process, spawning it if needed.
    pub async fn ensure_running(self: &Arc<Self>, t: &TenantId, role: Role) -> Result<Arc<Proc>, CellError> {
        if role == Role::Maintenance && !self.cfg.prevalence_maintenance {
            return Err(CellError::Unavailable("prevalence maintenance is not enabled on this cell".into()));
        }
        if role == Role::Product && !self.cfg.product_state_role {
            return Err(CellError::Unavailable("the product state role is not enabled on this cell".into()));
        }
        let (slot, placement) = self.slot(t)?;
        // NAN-4137: landing[T] only for a tenant placed with `landing` on a
        // `tenzir_landing` cell, and only under its own uid.
        if role == Role::Landing {
            if !landing_wanted(self.cfg.tenzir_landing, Some(&placement)) {
                return Err(CellError::Unavailable("landing is not placed for this tenant on this cell".into()));
            }
            if slot.ids.landing_uid.is_none() {
                return Err(CellError::Unavailable("no landing uid is available for this tenant on this cell".into()));
            }
        }
        // NAN-3523: over its soft disk ceiling a tenant gets no new ingest
        // work (wake or spawn): a retryable 503, the backlog stays upstream.
        if role == Role::Ingest {
            if let Err(r) = self.disk.admit_ingest(t) {
                return Err(CellError::DiskPressure { bytes: r.bytes, soft_bytes: r.soft_bytes, retry_after_secs: r.retry_after_secs });
            }
        }
        let i = role_idx(role);
        if let Some(p) = slot.procs.lock().unwrap()[i].clone() {
            if !p.stopping.load(Ordering::SeqCst) && !p.exited.load(Ordering::SeqCst) {
                return Ok(p);
            }
        }
        // NAN-4128: the spawn runs detached under an overall deadline; this
        // caller joins it and waits a bounded time. A caller that gives up
        // (client timeout, dropped request) no longer kills the half-started
        // process with no log, so the next wake finds it running.
        let deadline = self.spawn_deadline();
        let me = self.clone();
        let flight_slot = slot.clone();
        let res = slot.flights[i]
            .run(deadline, deadline + Duration::from_secs(1), move |progress| async move {
                me.spawn_role(flight_slot, placement, role, progress).await
            })
            .await;
        match res {
            Ok(p) => Ok(p),
            Err(FlightError::Failed(e)) => Err(e),
            Err(FlightError::TimedOut { step, secs }) => {
                self.spawn_failures.fetch_add(1, Ordering::Relaxed);
                self.recent_spawn_failures.lock().unwrap().push_back(Instant::now());
                tracing::error!(tenant = %t, role = role.as_str(), step, deadline_secs = secs,
                    "spawn timed out; attempt torn down and role lock released");
                Err(CellError::SpawnTimedOut { role, step, secs, still_running: false })
            }
            Err(FlightError::StillRunning { step, secs }) => {
                tracing::warn!(tenant = %t, role = role.as_str(), step, running_secs = secs,
                    "wake stopped waiting; spawn continues in the background");
                Err(CellError::SpawnTimedOut { role, step, secs, still_running: true })
            }
        }
    }

    /// NAN-4128: the overall bound of one spawn attempt: its restart
    /// backoff, the warm hello, the assignment and jail, the token mint and
    /// readiness are each bounded by `spawn_timeout`, plus a lock wait.
    fn spawn_deadline(&self) -> Duration {
        self.cfg.spawn_timeout().saturating_mul(6).max(Duration::from_secs(5))
    }

    /// NAN-4314: how long one spawn attempt waits for a birth precondition
    /// (its enrichment inputs; the first lean assignment behind its token):
    /// a third of the attempt's deadline each, so both waits plus the
    /// process start still fit inside it.
    fn precondition_wait(&self) -> Duration {
        self.spawn_deadline() / 3
    }

    /// Wait (bounded) until every enrichment input the placement names
    /// exists. Logs once when it has to wait and once when the inputs land;
    /// past the bound the spawn fails with the missing path.
    async fn await_enrichment_inputs(
        &self,
        t: &TenantId,
        role: Role,
        placement: &TenantPlacement,
        progress: &Progress,
    ) -> Result<(), CellError> {
        let Some(first) = missing_enrichment_input(&self.cfg, placement) else { return Ok(()) };
        let bound = self.precondition_wait();
        progress.set("enrichment_inputs");
        tracing::info!(tenant = %t, role = role.as_str(), missing = %first.display(), wait_secs = bound.as_secs(),
            "waiting for enrichment inputs before spawning");
        match wait_for_enrichment_inputs(&self.cfg, placement, bound, ENRICHMENT_INPUTS_POLL, &self.stopping_all).await {
            InputsWait::Ready(waited) => {
                tracing::info!(tenant = %t, role = role.as_str(), waited_ms = waited.as_millis() as u64,
                    "enrichment inputs present; spawning");
                Ok(())
            }
            InputsWait::Stopping => Err(CellError::Unavailable("cell is shutting down; not starting tenant processes".into())),
            InputsWait::Missing(path) => Err(CellError::Spawn(format!(
                "enrichment mounts: {} still missing after {}s", path.display(), bound.as_secs()
            ))),
        }
    }

    /// One spawn attempt of `role` for `slot`, under its role lock. Run only
    /// through `slot.flights` (detached, deadline-bounded).
    async fn spawn_role(
        self: Arc<Self>,
        slot: Arc<TenantSlot>,
        placement: TenantPlacement,
        role: Role,
        progress: Arc<Progress>,
    ) -> Result<Arc<Proc>, CellError> {
        let t = &slot.id;
        let i = role_idx(role);
        progress.set("role_lock");
        let _guard = slot.spawn_lock[i].lock_logged(&progress, t.as_str(), role.as_str(), LOCK_WAIT_LOG_EVERY).await;
        progress.set("admission");
        if let Some(p) = slot.procs.lock().unwrap()[i].clone() {
            if !p.stopping.load(Ordering::SeqCst) && !p.exited.load(Ordering::SeqCst) {
                return Ok(p);
            }
        }
        // Shutting down: never start a process the final kill would take
        // down mid-request (that surfaced as a 502 "tenant rpc: connection
        // closed" after a long cold start on the dying pod).
        if self.stopping_all.load(Ordering::SeqCst) {
            return Err(CellError::Unavailable("cell is shutting down; not starting tenant processes".into()));
        }
        // NAN-3523: a pooled cell without kernel limits admits no new tenant
        // process (running ones keep serving). Checked under the spawn lock,
        // before any warm process is assigned or token minted.
        if let Some(e) = self.admission_error() {
            return Err(e);
        }
        // NAN-3004: one writer per tenant across the pods of this cell.
        // Checked under the spawn lock, which `/v1/handover` reports as
        // `writing`, so a peer never sees this spawn as unowned.
        if matches!(role, Role::Ingest | Role::Detect | Role::Maintenance) {
            if let Some(h) = &self.handover {
                if let Err(why) = h.may_write(t) {
                    return Err(CellError::Standby(why.to_string()));
                }
                if let Some(why) = writer_standby(&slot.stats.lock().unwrap(), Instant::now()) {
                    return Err(CellError::Standby(why));
                }
                // A predecessor of this role may still be flushing here.
                if let Some(p) = slot.procs.lock().unwrap()[i].as_ref().filter(|p| !p.exited.load(Ordering::SeqCst)) {
                    return Err(CellError::Standby(format!("previous {} pid {} is still stopping", role.as_str(), p.pid)));
                }
            }
        }
        // Over the cell-wide task ceiling (watchdog mode): no new processes
        // until the watchdog has brought it back down.
        if self.monitor.lock().unwrap().pids_saturated() {
            return Err(CellError::Unavailable("cell task ceiling reached; refusing new tenant processes".into()));
        }
        // The control plane refused this role's token: no mint (and no warm
        // process burnt) until its backoff has passed.
        if let Some(e) = spawn_blocked_error(&slot.stats.lock().unwrap(), role, Instant::now()) {
            return Err(e);
        }
        // Restart backoff after a limit kill or crash: wait it out if it is
        // short, else refuse (the caller retries; 503).
        let not_before = slot.stats.lock().unwrap().restart_not_before[i];
        if let Some(at) = not_before {
            let now = Instant::now();
            if at > now {
                let wait = at - now;
                if wait > self.cfg.spawn_timeout() {
                    return Err(CellError::Unavailable(format!(
                        "{} restart backoff: {} ms left", role.as_str(), wait.as_millis()
                    )));
                }
                tracing::info!(tenant = %t, role = role.as_str(), wait_ms = wait.as_millis() as u64, "restart backoff");
                progress.set("restart_backoff");
                tokio::time::sleep(wait).await;
            }
        }
        let t0 = Instant::now();
        let result = async {
            // NAN-4314: the placement can land before the enrichment inputs
            // it names (the bundle sidecar writes a new tenant's policy on
            // its next cycle). Wait for them here, before a warm process or
            // a cgroup is used, instead of failing every second until then.
            self.await_enrichment_inputs(t, role, &placement, &progress).await?;
            let warm = self.take_warm(role);
            let warm = match warm {
                Some(w) => w,
                None => {
                    progress.set("spawn_process");
                    self.spawn_warm(role).await?
                }
            };
            self.warm_notify.notify_one();
            self.assign(warm, &slot, &placement, role, &progress).await
        }
        .await;
        match result {
            Ok(p) => {
                let ms = t0.elapsed().as_millis() as u64;
                let unblocked = {
                    let mut st = slot.stats.lock().unwrap();
                    st.last_spawn_ms[i] = ms;
                    st.spawn_blocked[i].take()
                };
                if let Some(b) = unblocked {
                    tracing::info!(tenant = %t, role = role.as_str(), reason = %b.code, attempts = b.attempts,
                        blocked_secs = b.since.elapsed().as_secs(), "role spawn unblocked");
                }
                tracing::info!(tenant = %t, role = role.as_str(), pid = p.pid, spawn_ms = ms, "tenant process started");
                slot.procs.lock().unwrap()[i] = Some(p.clone());
                // A spawn admitted before begin_drain may publish after the
                // drain's first snapshot. Keep it visible to peers until exit
                // and release it immediately instead of serving a writer wake.
                if matches!(role, Role::Ingest | Role::Detect | Role::Maintenance)
                    && self.handover.as_ref().is_some_and(|h| h.draining())
                {
                    self.stop(p, "handover_release");
                    return Err(CellError::Standby("cell began draining during writer spawn".into()));
                }
                Ok(p)
            }
            Err(e) => {
                self.spawn_failures.fetch_add(1, Ordering::Relaxed);
                self.recent_spawn_failures.lock().unwrap().push_back(Instant::now());
                tracing::error!(tenant = %t, role = role.as_str(), error = %e, "spawn failed");
                // An emptied tenant cgroup is removed by the next reaper
                // tick: this spawn still holds its lock (NAN-2971).
                // A refused mint answers with the refusal, not a bare spawn error.
                Err(spawn_blocked_error(&slot.stats.lock().unwrap(), role, Instant::now()).unwrap_or(e))
            }
        }
    }

    /// Record the control plane's refusal of `role`'s token and back off.
    fn note_spawn_refused(&self, slot: &Arc<TenantSlot>, role: Role, r: &crate::secrets::MintRefused) {
        let i = role_idx(role);
        let now = Instant::now();
        let mut st = slot.stats.lock().unwrap();
        let (block, changed) = SpawnBlock::refused(st.spawn_blocked[i].as_ref(), r, now);
        if changed {
            tracing::warn!(tenant = %slot.id, role = role.as_str(), status = r.status, reason = %r.code,
                missing = r.missing.as_deref().unwrap_or(""), "role spawn blocked by the control plane; backing off");
        }
        st.restart_not_before[i] = Some(st.restart_not_before[i].map_or(block.not_before, |at| at.max(block.not_before)));
        st.spawn_blocked[i] = Some(block);
    }

    fn take_warm(&self, role: Role) -> Option<WarmProc> {
        let mut warm = self.warm.lock().unwrap();
        let q = warm.entry(role).or_default();
        while let Some(mut w) = q.pop_front() {
            // Skip warm processes that died while waiting.
            if matches!(w.child.try_wait(), Ok(None)) {
                return Some(w);
            }
        }
        None
    }

    fn warm_target(&self, role: Role) -> usize {
        match role {
            Role::Ingest => self.cfg.warm_ingest,
            Role::Detect | Role::Maintenance | Role::Product | Role::Landing => 0,
            Role::Query => self.cfg.warm_query,
        }
    }

    async fn warm_loop(self: Arc<Self>) {
        loop {
            if self.halted.load(Ordering::SeqCst) {
                return;
            }
            for role in Role::ALL {
                loop {
                    let have = {
                        let mut warm = self.warm.lock().unwrap();
                        let q = warm.entry(role).or_default();
                        q.retain_mut(|w| matches!(w.child.try_wait(), Ok(None)));
                        q.len()
                    };
                    if have >= self.warm_target(role) {
                        break;
                    }
                    match self.spawn_warm(role).await {
                        Ok(w) => {
                            tracing::debug!(role = role.as_str(), pid = w.pid, "warm process ready");
                            self.warm.lock().unwrap().entry(role).or_default().push_back(w);
                        }
                        Err(e) => {
                            tracing::error!(role = role.as_str(), error = %e, "warm spawn failed");
                            self.spawn_failures.fetch_add(1, Ordering::Relaxed);
                            self.recent_spawn_failures.lock().unwrap().push_back(Instant::now());
                            break;
                        }
                    }
                }
            }
            tokio::select! {
                _ = self.warm_notify.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(5)) => {},
            }
        }
    }

    // ---------------------------------------------------------------- resident ingest

    /// Keep every `ingest: resident` tenant's ingest running (C1): start it
    /// on placement (boot and reload) without a wake, and respawn it after
    /// any exit once its restart backoff has passed.
    async fn keeper_loop(self: Arc<Self>) {
        loop {
            if self.halted.load(Ordering::SeqCst) {
                return;
            }
            let next = self.keep_resident();
            let wait = next.map_or(KEEPER_TICK, |at| at.saturating_duration_since(Instant::now()).min(KEEPER_TICK));
            tokio::select! {
                _ = self.keeper_notify.notified() => {},
                _ = tokio::time::sleep(wait.max(Duration::from_millis(50))) => {},
            }
        }
    }

    /// One keeper pass. Starts a spawn task per resident tenant whose
    /// ingest is down and not in backoff; returns the earliest backoff
    /// deadline still pending so the loop wakes for it.
    pub fn keep_resident(self: &Arc<Self>) -> Option<Instant> {
        let placement = self.placement.read().unwrap().clone();
        let now = Instant::now();
        let resident: Vec<TenantId> = placement.tenants.iter()
            .filter(|t| t.ingest == IngestMode::Resident).map(|t| t.tenant_id.clone()).collect();
        self.resident_down_since.lock().unwrap().retain(|t, _| resident.contains(t));
        if self.stopping_all.load(Ordering::SeqCst) || self.halted.load(Ordering::SeqCst) {
            return None;
        }
        let i = role_idx(Role::Ingest);
        let mut next: Option<Instant> = None;
        // NAN-3523: refused admission still counts a resident ingest as down
        // (`ingest_not_running`), but no keeper spawns anything (nor logs per
        // tenant every tick: `pooled_admission_refused` signals for the cell).
        let refused = self.admission() == limits::Admission::RefusedUnenforced;
        for t in resident {
            let slot = self.tenants.lock().unwrap().get(&t).cloned();
            let running = slot.as_ref().is_some_and(|s| s.procs.lock().unwrap()[i].as_ref()
                .is_some_and(|p| !p.stopping.load(Ordering::SeqCst) && !p.exited.load(Ordering::SeqCst)));
            if running {
                self.resident_down_since.lock().unwrap().remove(&t);
                continue;
            }
            // NAN-3004: standby for a tenant whose writer runs on a peer (or
            // while draining / discovering). Not "down": the peer writes.
            if let Some(h) = &self.handover {
                let standby = slot.as_ref().and_then(|s| writer_standby(&s.stats.lock().unwrap(), now));
                if h.may_write(&t).is_err() || standby.is_some() {
                    self.resident_down_since.lock().unwrap().remove(&t);
                    if let Some(until) = slot.as_ref().and_then(|s| s.stats.lock().unwrap().writer_standby_until).filter(|_| standby.is_some()) {
                        next = Some(next.map_or(until, |n| n.min(until)));
                    }
                    continue;
                }
            }
            self.resident_down_since.lock().unwrap().entry(t.clone()).or_insert(now);
            if refused {
                continue;
            }
            if let Some(slot) = &slot {
                // A spawn (or a stopping predecessor's cleanup) holds the lock.
                if slot.spawn_lock[i].try_lock().is_err() {
                    continue;
                }
                let not_before = slot.stats.lock().unwrap().restart_not_before[i];
                if let Some(at) = not_before.filter(|at| *at > now) {
                    next = Some(next.map_or(at, |n| n.min(at)));
                    continue;
                }
            }
            let me = self.clone();
            tokio::spawn(async move {
                match me.ensure_running(&t, Role::Ingest).await {
                    Ok(p) => tracing::info!(tenant = %t, pid = p.pid, "resident ingest running"),
                    Err(e) => tracing::warn!(tenant = %t, error = %e, "resident ingest not started; retrying"),
                }
            });
        }
        if refused {
            return next;
        }
        if let Some(at) = self.keep_query_warm(&placement, now) {
            next = Some(next.map_or(at, |n| n.min(at)));
        }
        if let Some(at) = self.keep_maintenance(&placement, now) {
            next = Some(next.map_or(at, |n| n.min(at)));
        }
        if let Some(at) = self.keep_product(&placement, now) {
            next = Some(next.map_or(at, |n| n.min(at)));
        }
        if let Some(at) = self.keep_landing(&placement, now) {
            next = Some(next.map_or(at, |n| n.min(at)));
        }
        next
    }

    /// `tenzir_landing` (NAN-4137, `lean_tenzir_landing_v1`): keep
    /// `landing[T]` running for every tenant placed with `landing` that this
    /// cell writes for (a standby pod never converts: its edge-log appends
    /// and ledger commits would race the writer's). The ledger lease fences
    /// any overlap during a hand-over. Returns the earliest restart-backoff
    /// deadline still pending.
    fn keep_landing(self: &Arc<Self>, placement: &Placement, now: Instant) -> Option<Instant> {
        if !self.cfg.tenzir_landing {
            return None;
        }
        let l = role_idx(Role::Landing);
        let mut next: Option<Instant> = None;
        for t in placement.tenants.iter().filter(|t| t.landing).map(|t| t.tenant_id.clone()) {
            if let Some(h) = &self.handover {
                if h.may_write(&t).is_err() {
                    continue;
                }
            }
            if let Some(slot) = self.tenants.lock().unwrap().get(&t).cloned() {
                let running = slot.procs.lock().unwrap()[l].as_ref()
                    .is_some_and(|p| !p.stopping.load(Ordering::SeqCst) && !p.exited.load(Ordering::SeqCst));
                if running || slot.spawn_lock[l].try_lock().is_err() {
                    continue;
                }
                let not_before = slot.stats.lock().unwrap().restart_not_before[l];
                if let Some(at) = not_before.filter(|at| *at > now) {
                    next = Some(next.map_or(at, |n| n.min(at)));
                    continue;
                }
            }
            let me = self.clone();
            tokio::spawn(async move {
                match me.ensure_running(&t, Role::Landing).await {
                    Ok(p) => tracing::info!(tenant = %t, pid = p.pid, "landing converter running"),
                    Err(e) => tracing::warn!(tenant = %t, error = %e, "landing converter not started; retrying"),
                }
            });
        }
        next
    }

    /// `product_state_role` (NAN-3148, `lean_product_state_role_v1`): keep
    /// `product[T]`, the product-state builder, running beside every live
    /// query[T]. Its work only serves query[T]'s reads, so it starts once
    /// query runs and is reaped with it. Returns the earliest restart-backoff
    /// deadline still pending.
    fn keep_product(self: &Arc<Self>, placement: &Placement, now: Instant) -> Option<Instant> {
        if !self.cfg.product_state_role {
            return None;
        }
        let (q, p) = (role_idx(Role::Query), role_idx(Role::Product));
        let mut next: Option<Instant> = None;
        for t in placement.tenants.iter().map(|t| t.tenant_id.clone()) {
            let Some(slot) = self.tenants.lock().unwrap().get(&t).cloned() else { continue };
            let live = |i: usize| slot.procs.lock().unwrap()[i].as_ref()
                .is_some_and(|p| !p.stopping.load(Ordering::SeqCst) && !p.exited.load(Ordering::SeqCst));
            if !live(q) || live(p) || slot.spawn_lock[p].try_lock().is_err() {
                continue;
            }
            let not_before = slot.stats.lock().unwrap().restart_not_before[p];
            if let Some(at) = not_before.filter(|at| *at > now) {
                next = Some(next.map_or(at, |n| n.min(at)));
                continue;
            }
            let me = self.clone();
            tokio::spawn(async move {
                match me.ensure_running(&t, Role::Product).await {
                    Ok(p) => tracing::info!(tenant = %t, pid = p.pid, "product state builder running"),
                    Err(e) => tracing::warn!(tenant = %t, error = %e, "product state builder not started; retrying"),
                }
            });
        }
        next
    }

    /// `prevalence_maintenance` (cell feature `lean_prevalence_maintenance_v1`):
    /// keep `maintenance[T]`, the tenant prevalence SlateDB compactor,
    /// running beside every resident ingest this cell may write for. Without
    /// it ingest's L0 reaches SlateDB's cap and prevalence stalls. Returns
    /// the earliest restart-backoff deadline still pending.
    fn keep_maintenance(self: &Arc<Self>, placement: &Placement, now: Instant) -> Option<Instant> {
        if !self.cfg.prevalence_maintenance {
            return None;
        }
        let m = role_idx(Role::Maintenance);
        let mut next: Option<Instant> = None;
        for t in placement.tenants.iter().filter(|t| t.ingest == IngestMode::Resident).map(|t| t.tenant_id.clone()) {
            // Only the writer cell compacts (NAN-3004 standby cells do not).
            let slot = self.tenants.lock().unwrap().get(&t).cloned();
            if let Some(h) = &self.handover {
                if h.may_write(&t).is_err() {
                    continue;
                }
                // NAN-4052: and only beside an ingest that finished start-up
                // here, i.e. holds the cell writer lease (or runs without
                // one). A pod cut off from its peer must not open the
                // compactor (fencing the writer pod's) before ingest learned
                // the lease is held elsewhere.
                // One lock at a time (stats, then the process table).
                let ingest_writes = slot.as_ref().is_some_and(|s| {
                    let standby = writer_standby(&s.stats.lock().unwrap(), now).is_some();
                    let ingest = s.procs.lock().unwrap()[role_idx(Role::Ingest)].clone();
                    !standby && ingest.is_some_and(|p| {
                        !p.stopping.load(Ordering::SeqCst) && !p.exited.load(Ordering::SeqCst) && p.heartbeat.lock().unwrap().1.writer_ready
                    })
                });
                if !ingest_writes {
                    continue;
                }
            }
            if let Some(slot) = &slot {
                let running = slot.procs.lock().unwrap()[m].as_ref()
                    .is_some_and(|p| !p.stopping.load(Ordering::SeqCst) && !p.exited.load(Ordering::SeqCst));
                if running || slot.spawn_lock[m].try_lock().is_err() {
                    continue;
                }
                let not_before = slot.stats.lock().unwrap().restart_not_before[m];
                if let Some(at) = not_before.filter(|at| *at > now) {
                    next = Some(next.map_or(at, |n| n.min(at)));
                    continue;
                }
            }
            let me = self.clone();
            tokio::spawn(async move {
                match me.ensure_running(&t, Role::Maintenance).await {
                    Ok(p) => tracing::info!(tenant = %t, pid = p.pid, "prevalence maintenance running"),
                    Err(e) => tracing::warn!(tenant = %t, error = %e, "prevalence maintenance not started; retrying"),
                }
            });
        }
        next
    }

    /// Start `query[T]` ahead of the first search (after a cell start, a
    /// crash or a roll) for every placed tenant it is resident for: all of
    /// them by default (NAN-3008 `query_resident`), else those whose ingest
    /// worked or which were searched recently (NAN-2989). Returns the
    /// earliest restart-backoff deadline still pending.
    fn keep_query_warm(self: &Arc<Self>, placement: &Placement, now: Instant) -> Option<Instant> {
        let q = role_idx(Role::Query);
        let mut next: Option<Instant> = None;
        for t in placement.tenants.iter().map(|t| t.tenant_id.clone()) {
            let slot = self.tenants.lock().unwrap().get(&t).cloned();
            if !self.cfg.query_resident {
                // The activity rules need history, which only a slot has.
                let Some(slot) = &slot else { continue };
                if !query_kept_resident(&self.cfg, slot, now) {
                    continue;
                }
            }
            if let Some(slot) = &slot {
                let running = slot.procs.lock().unwrap()[q].as_ref()
                    .is_some_and(|p| !p.stopping.load(Ordering::SeqCst) && !p.exited.load(Ordering::SeqCst));
                if running || slot.spawn_lock[q].try_lock().is_err() {
                    continue;
                }
                let not_before = slot.stats.lock().unwrap().restart_not_before[q];
                if let Some(at) = not_before.filter(|at| *at > now) {
                    next = Some(next.map_or(at, |n| n.min(at)));
                    continue;
                }
            }
            let me = self.clone();
            tokio::spawn(async move {
                match me.ensure_running(&t, Role::Query).await {
                    Ok(p) => tracing::info!(tenant = %t, pid = p.pid, "resident query running"),
                    Err(e) => tracing::warn!(tenant = %t, error = %e, "resident query not started; retrying"),
                }
            });
        }
        next
    }

    // ---------------------------------------------------------------- requests

    /// Wake (spawning if needed) the tenant's `role` process.
    pub async fn wake(self: &Arc<Self>, t: &TenantId, role: Role, reason: WakeReason) -> Result<u32, CellError> {
        let p = self.ensure_running(t, role).await?;
        p.touch();
        // NAN-4128: a child that stopped reading its control socket must not
        // hang the wake.
        match tokio::time::timeout(self.cfg.spawn_timeout(), p.control.send_json(&ToChild::Wake { reason }, &[])).await {
            Ok(r) => r.map_err(|e| CellError::Unavailable(e.to_string()))?,
            Err(_) => return Err(CellError::Unavailable(format!("{} pid {} did not accept the wake", role.as_str(), p.pid))),
        }
        Ok(p.pid)
    }

    /// NAN-3795: count a routed search RPC for the backfill relay until the
    /// guard drops. `None` when the tenant has no slot (nothing to relay to).
    pub fn begin_search(&self, t: &TenantId) -> Option<SearchGuard> {
        let slot = self.tenants.lock().unwrap().get(t).cloned()?;
        {
            let mut st = slot.stats.lock().unwrap();
            st.searches_in_flight += 1;
            st.relayable_search_at = Some(Instant::now());
        }
        Some(SearchGuard(slot))
    }

    /// Open one RPC stream to the tenant's read-only role process.
    pub async fn open_rpc(self: &Arc<Self>, t: &TenantId, role: Role) -> Result<(InflightGuard, u64, tokio::net::UnixStream), CellError> {
        if role == Role::Detect {
            self.wake(t, role, WakeReason::Detection).await?;
        }
        if role == Role::Query {
            // NAN-3008: recent search keeps query resident (with
            // `query_resident = false`); recorded before a possible spawn.
            if let Ok((slot, _)) = self.slot(t) {
                slot.record_search(Instant::now());
            }
        }
        let p = self.ensure_running(t, role).await?;
        let guard = p.begin_request();
        let (ours, theirs) = fdpass::stream_pair().map_err(|e| CellError::Unavailable(e.to_string()))?;
        let id = p.next_request.fetch_add(1, Ordering::Relaxed);
        match tokio::time::timeout(self.cfg.spawn_timeout(), p.control.send_json(&ToChild::Rpc { request_id: id }, &[theirs.as_fd()])).await {
            Ok(r) => r.map_err(|e| CellError::Unavailable(e.to_string()))?,
            Err(_) => return Err(CellError::Unavailable(format!("{} pid {} did not accept the rpc", role.as_str(), p.pid))),
        }
        drop(theirs);
        let std = std::os::unix::net::UnixStream::from(ours);
        std.set_nonblocking(true).map_err(|e| CellError::Unavailable(e.to_string()))?;
        let stream = tokio::net::UnixStream::from_std(std).map_err(|e| CellError::Unavailable(e.to_string()))?;
        Ok((guard, id, stream))
    }

    /// Keep a role alive while work routed through another role still depends
    /// on it. The guard uses the same in-flight counter as an ordinary RPC.
    pub async fn hold_inflight(self: &Arc<Self>, t: &TenantId, role: Role) -> Result<InflightGuard, CellError> {
        let p = self.ensure_running(t, role).await?;
        Ok(p.begin_request())
    }

    pub fn observe_query_duration(&self, tenant: &TenantId, seconds: f64) {
        if let Some(slot) = self.tenants.lock().unwrap().get(tenant) {
            let mut stats = slot.stats.lock().unwrap();
            stats.query_duration_count += 1;
            stats.query_duration_sum += seconds;
            for (count, bound) in stats.query_duration_buckets.iter_mut().zip(QUERY_DURATION_BUCKETS) {
                if seconds <= bound { *count += 1; }
            }
        }
    }

    /// Gracefully stop both of a tenant's processes.
    pub fn drain(self: &Arc<Self>, t: &TenantId) -> bool {
        let slot = self.tenants.lock().unwrap().get(t).cloned();
        match slot {
            Some(s) => {
                self.drain_slot(&s);
                true
            }
            None => false,
        }
    }

    fn drain_slot(&self, slot: &Arc<TenantSlot>) {
        let procs: Vec<Arc<Proc>> = slot.procs.lock().unwrap().iter().flatten().cloned().collect();
        for p in procs {
            self.stop(p, "drain");
        }
    }

    fn stop(&self, p: Arc<Proc>, why: &'static str) {
        if p.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        let grace = self.cfg.shutdown_grace_ms;
        tracing::info!(tenant = %p.tenant, role = p.role.as_str(), pid = p.pid, why, "stopping tenant process");
        // A SIGSTOPped process cannot answer `Shutdown`: continue it first.
        // (The watchdog exempts stopping processes from then on.)
        // Off the async runtime: the monitor lock may be held by a tick.
        let me = self.monitor_handle();
        let t = p.tenant.clone();
        tokio::task::spawn_blocking(move || me.lock().unwrap().release(&t));
        tokio::spawn(async move {
            let _ = p.control.send_json(&ToChild::Shutdown { grace_ms: grace }, &[]).await;
            tokio::time::sleep(Duration::from_millis(grace + 500)).await;
            if !p.exited.load(Ordering::SeqCst) {
                p.kill("shutdown_grace");
            }
        });
    }

    // ---------------------------------------------------------------- resource watchdog

    /// NAN-3522: an ingest[T] whose hold lease ran out stops gracefully; the
    /// next wake/keeper starts it at full speed. Runs every resource tick, so
    /// the lease holds even when no placement change ever arrives.
    fn expire_ingest_holds(&self) {
        let placement = self.placement.read().unwrap().clone();
        let now = now_ms();
        for tp in placement.tenants.iter().filter(|tp| tp.ingest_hold_eps.is_some()) {
            let Some(slot) = self.tenants.lock().unwrap().get(&tp.tenant_id).cloned() else { continue };
            let ingest = slot.procs.lock().unwrap()[role_idx(Role::Ingest)].clone();
            if let Some(p) = ingest.filter(|p| !p.exited.load(Ordering::SeqCst) && !p.stopping.load(Ordering::SeqCst)) {
                if ingest_hold_needs_respawn(p.ingest_hold_eps, tp.effective_ingest_hold_eps(now)) {
                    tracing::warn!(tenant = %tp.tenant_id, until = ?tp.ingest_hold_until, "ingest hold lease expired; ingest returns to full speed");
                    self.stop(p, "ingest_hold_expired");
                }
            }
        }
    }

    async fn resource_loop(self: Arc<Self>) {
        let mut last_cpu_log = Instant::now();
        let every = self.monitor.lock().unwrap().interval();
        let mut interval = tokio::time::interval(every);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if self.halted.load(Ordering::SeqCst) {
                return;
            }
            interval.tick().await;
            self.expire_ingest_holds();
            let log_cpu = last_cpu_log.elapsed() >= Duration::from_secs(60);
            if log_cpu { last_cpu_log = Instant::now(); }
            let me = self.clone();
            // cgroup and /proc reads and signals are blocking: off the reactor.
            if let Err(e) = tokio::task::spawn_blocking(move || {
                if log_cpu { me.log_role_cpu(); }
                me.resources_once();
            }).await {
                tracing::error!(error = %e, "resource watchdog pass panicked");
            }
        }
    }

    fn log_role_cpu(&self) {
        let Some(cg) = self.cgroups.get() else { return };
        let placement = self.placement.read().unwrap().clone();
        for tenant in &placement.tenants {
            for role in Role::ALL {
                if let Some(u) = cg.role_usage(&tenant.tenant_id, role) {
                    tracing::info!(tenant = %tenant.tenant_id, role = role.as_str(),
                        usage_usec = u.cpu_usage_usec, throttled_usec = u.cpu_throttled_usec,
                        nr_throttled = u.nr_throttled, "role CPU counters");
                }
            }
        }
    }

    /// One watchdog pass: measure every tenant, throttle/kill per the
    /// graduated policy (`resources.rs`), record events.
    pub fn resources_once(&self) {
        self.note_enforcement();
        let placement = self.placement.read().unwrap().clone();
        let slots: Vec<Arc<TenantSlot>> = self.tenants.lock().unwrap().values().cloned().collect();
        // Every tenant this cell ever gave uids to, not only those with a
        // supervisor-started process: an orphan under a tenant uid is still
        // that tenant's, measured and throttled with it.
        let all_ids = self.uidmap.lock().unwrap().all();
        let mut specs = Vec::new();
        for (tenant, ids) in all_ids {
            let slot = slots.iter().find(|s| s.id == tenant);
            let procs: Vec<Arc<Proc>> =
                slot.map(|s| s.procs.lock().unwrap().iter().flatten().cloned().collect()).unwrap_or_default();
            let placed = placement.tenants.iter().find(|x| x.tenant_id == tenant).cloned().unwrap_or_else(|| TenantPlacement::legacy(tenant.clone(), 0.0));
            specs.push(TenantSpec {
                limits: self.placement_limits(&placed),
                roots: procs.iter().map(|p| (p.pid, p.starttime)).collect(),
                uids: ids.uids(),
                exempt: procs.iter().filter(|p| p.stopping.load(Ordering::SeqCst)).map(|p| (p.pid, p.starttime)).collect(),
                unthrottled_uids: if self.cfg.resources.query_unthrottled { vec![ids.query_uid] } else { vec![] },
                tenant,
            });
        }
        let dt = self.monitor.lock().unwrap().interval();
        // No pids cap on the pod in watchdog mode (podPidsLimit=-1): enforce
        // a cell-wide task ceiling across all tenant uids ourselves.
        let pids_ceiling = self.cgroups.get().is_none().then(|| placement.tenants.len() as u64 * 1024 + 1024);
        let out = {
            let mut m = self.monitor.lock().unwrap();
            m.set_pids_ceiling(pids_ceiling);
            m.tick(&specs, self.cgroups.get())
        };
        let by_id: HashMap<&TenantId, &Arc<TenantSlot>> = slots.iter().map(|s| (&s.id, s)).collect();
        let now = Instant::now();
        let cap = self.capacity().cpu_millicores.max(1) as f64;
        let query = placement.tenants.iter().filter_map(|p| {
            self.cgroups.get().and_then(|cg| cg.role_usage(&p.tenant_id, Role::Query))
                .map(|u| (p.tenant_id.clone(), u.cpu_usage_usec, u.cpu_throttled_usec))
        }).collect::<Vec<_>>();
        self.alert_windows.lock().unwrap().observe(now, out.cell.cpu_millicores / cap, query);
        for s in &out.samples {
            if let Some(slot) = by_id.get(&s.tenant) {
                slot.stats.lock().unwrap().cpu_usec_watchdog += s.cpu_millicores * dt.as_micros() as f64 / 1000.0;
            }
        }
        for k in out.kills {
            let why = match k.reason {
                KillReason::MemoryHardCeiling => "watchdog_memory_hard_ceiling",
                KillReason::CellMemoryCritical => "watchdog_cell_memory_critical",
                KillReason::CellPidsCeiling => "watchdog_cell_pids_ceiling",
                KillReason::TenantDiskCeiling => "watchdog_tenant_disk_ceiling",
            };
            let Some(slot) = by_id.get(&k.tenant) else {
                k.kill();
                continue;
            };
            let root = slot.procs.lock().unwrap().iter().flatten().find(|p| (p.pid, p.starttime) == (k.pid, k.starttime)).cloned();
            {
                let mut st = slot.stats.lock().unwrap();
                st.watchdog_kills += 1;
                st.oom_kills += 1;
                st.recent_ooms.push_back(now);
            }
            match root {
                // Mark first so the exit is accounted as this kill, not a crash.
                Some(p) => p.kill(why),
                None => k.kill(),
            }
        }
        for (tenant, reason) in out.kill_tenants {
            let ids = self.uidmap.lock().unwrap().get(&tenant);
            if let Some(slot) = by_id.get(&tenant) {
                let mut st = slot.stats.lock().unwrap();
                st.watchdog_kills += 1;
                drop(st);
                for p in slot.procs.lock().unwrap().iter().flatten() {
                    p.kill(if reason == KillReason::CellPidsCeiling { "watchdog_cell_pids_ceiling" } else { "watchdog_kill" });
                }
            }
            if let Some(ids) = ids {
                Self::kill_uids(&ids.uids());
            }
        }
        for e in out.events {
            e.log();
            match e.tenant.as_ref().and_then(|t| by_id.get(t)) {
                Some(slot) => slot.stats.lock().unwrap().record(e),
                None => {
                    let mut q = self.cell_events.lock().unwrap();
                    if q.len() >= EVENTS_KEPT {
                        q.pop_front();
                    }
                    q.push_back(e);
                }
            }
        }
        self.enforce_disk_ceilings(&placement, &by_id, now);
        // Delegated: nothing stays unlimited in init/ or warm/, and the
        // delegation is re-checked.
        self.reconcile_cgroups();
        // Kernel OOM kills in delegated mode surface as events right away.
        for slot in &slots {
            self.note_cgroup_ooms(slot);
        }
    }

    /// NAN-3523: apply the last disk walk. Over soft: ingest admission is
    /// refused ([`Self::ensure_running`]). Over hard: SIGKILL this tenant's
    /// ingest only (never another tenant, never another role). Nothing
    /// acknowledged is lost: ingest acks DO notices and finding appends
    /// only after the part-log commit, so uncommitted work is redelivered.
    fn enforce_disk_ceilings(&self, placement: &Placement, by_id: &HashMap<&TenantId, &Arc<TenantSlot>>, now: Instant) {
        let placed: Vec<(TenantId, u64)> = placement.tenants.iter()
            .map(|t| (t.tenant_id.clone(), TenantBudget::from_eps(t.eps).cache_disk_bytes)).collect();
        let tick = self.disk.evaluate(&placed, now);
        for e in tick.events {
            e.log();
            if let Some(slot) = e.tenant.as_ref().and_then(|t| by_id.get(t)) {
                slot.stats.lock().unwrap().record(e);
            }
        }
        for (tenant, bytes, ceiling) in tick.kills {
            let Some(slot) = by_id.get(&tenant) else { continue };
            let ingest = slot.procs.lock().unwrap()[role_idx(Role::Ingest)].clone()
                .filter(|p| !p.exited.load(Ordering::SeqCst) && p.killed.lock().unwrap().is_none());
            let Some(p) = ingest else { continue };
            let e = LimitEvent::new(Some(&tenant), EventKind::Killed, KillReason::TenantDiskCeiling.as_str(),
                bytes as f64, ceiling.hard_bytes as f64, "bytes");
            e.log();
            {
                let mut st = slot.stats.lock().unwrap();
                st.watchdog_kills += 1;
                st.record(e);
            }
            p.kill("watchdog_tenant_disk_ceiling");
        }
    }

    // ---------------------------------------------------------------- reaper

    async fn reaper_loop(self: Arc<Self>) {
        // Idle reap and stall kill; resource limits run in `resource_loop`.
        let tick = (self.cfg.idle_timeout() / 20).clamp(Duration::from_millis(200), Duration::from_millis(500));
        let mut interval = tokio::time::interval(tick);
        loop {
            if self.halted.load(Ordering::SeqCst) {
                return;
            }
            interval.tick().await;
            self.reap_once();
            self.relay_search_activity(Instant::now());
        }
    }

    /// NAN-3795: while a tenant's searches are in flight (or one was routed
    /// within [`SEARCH_RELAY_EVERY`]), tell its running ingest[T] with a
    /// `Wake { Query }`, at most once per [`SEARCH_RELAY_EVERY`]. Ingest
    /// pauses background count backfill rewrites while the relay is recent,
    /// so k6-level search never competes with them. Never spawns ingest; an
    /// older ingest treats the wake as an ordinary tick wake.
    fn relay_search_activity(&self, now: Instant) {
        let slots: Vec<Arc<TenantSlot>> = self.tenants.lock().unwrap().values().cloned().collect();
        for slot in slots {
            let Some(ingest) = search_relay_target(&slot, now) else { continue };
            tokio::spawn(async move {
                let _ = ingest.control.send_json(&ToChild::Wake { reason: WakeReason::Query }, &[]).await;
            });
        }
    }

    /// One reaper pass: idle reap, stall kill, watchdog, cgroup cleanup.
    pub fn reap_once(&self) {
        let now = Instant::now();
        let stall = Duration::from_secs(self.cfg.stall_kill_secs);
        let placement = self.placement.read().unwrap().clone();
        let slots: Vec<Arc<TenantSlot>> = self.tenants.lock().unwrap().values().cloned().collect();
        for slot in slots {
            let procs: Vec<Arc<Proc>> = slot.procs.lock().unwrap().iter().flatten().cloned().collect();
            let placed_entry = placement.tenants.iter().find(|x| x.tenant_id == slot.id);
            let placed = placed_entry.is_some();
            if !placed && !procs.is_empty() {
                // Spawned while its placement was being removed.
                self.drain_slot(&slot);
            }
            for p in &procs {
                if p.stopping.load(Ordering::SeqCst) {
                    continue;
                }
                let (hb_at, hb) = p.heartbeat.lock().unwrap().clone();
                let budget = heartbeat_stall_budget(&hb, stall);
                if now.duration_since(hb_at) > budget {
                    tracing::error!(tenant = %p.tenant, role = p.role.as_str(), pid = p.pid,
                        startup_progress = ?hb.startup_progress, detail = ?hb.detail,
                        "no heartbeat/progress for {}s; killing stalled tenant process", budget.as_secs());
                    let mut st = slot.stats.lock().unwrap();
                    st.stall_kills[role_idx(p.role)] += 1;
                    st.recent_stalls.push_back(now);
                    drop(st);
                    p.kill("stall");
                    continue;
                }
                let idle = self.cfg.idle_timeout_for(p.role);
                // NAN-2989: a live tenant's query stays resident so search
                // never pays a cold start.
                let query_kept = p.role == Role::Query && query_kept_resident(&self.cfg, &slot, now);
                // A busy Detect drain stays up (NAN-2916); placement decides
                // whether a role may be idle-reaped at all (resident ingest).
                let role_busy = p.heartbeat.lock().unwrap().1.busy;
                if !role_busy
                    && idle_reap_due(p.role, placed_entry, p.inflight.load(Ordering::SeqCst), now.duration_since(p.active_at()), idle, query_kept)
                {
                    self.stop(p.clone(), "idle");
                    continue;
                }
                // NAN-3148: product[T] only serves query[T]; it stops with it.
                if p.role == Role::Product && !procs.iter().any(|q| q.role == Role::Query
                    && !q.stopping.load(Ordering::SeqCst) && !q.exited.load(Ordering::SeqCst)) {
                    self.stop(p.clone(), "query_stopped");
                }
                // NAN-4137: landing[T] runs only while its tenant is placed
                // with `landing` on a cell that runs the role.
                if p.role == Role::Landing && !landing_wanted(self.cfg.tenzir_landing, placed_entry) {
                    self.stop(p.clone(), "landing_not_placed");
                }
            }
            if procs.is_empty() {
                // False while a spawn is in flight: neither remove its
                // cgroup nor forget the tenant under it (NAN-2971).
                let settled = self.maybe_remove_tenant_cgroup(&slot);
                // Forget tenants moved off this cell once they are drained,
                // after making sure nothing runs under their uids.
                if !placed && settled {
                    Self::kill_uids(&slot.ids.uids());
                    self.tenants.lock().unwrap().remove(&slot.id);
                    // Drained: its purge can run now.
                    self.purge_notify.notify_one();
                }
            }
            let horizon = now.checked_sub(Duration::from_secs(3600)).unwrap_or(now);
            let mut guard = slot.stats.lock().unwrap();
            let st = &mut *guard;
            for q in [&mut st.recent_crashes, &mut st.recent_ooms, &mut st.recent_stalls] {
                while q.front().is_some_and(|t| *t < horizon) {
                    q.pop_front();
                }
            }
        }
        let horizon = now.checked_sub(Duration::from_secs(3600)).unwrap_or(now);
        let mut f = self.recent_spawn_failures.lock().unwrap();
        while f.front().is_some_and(|t| *t < horizon) {
            f.pop_front();
        }
    }

    // ---------------------------------------------------------------- purge (NAN-3000)

    /// Wakes the status reporter (see [`crate::report::Reporter::run`]).
    pub fn report_notify(&self) -> Arc<tokio::sync::Notify> {
        self.report_notify.clone()
    }

    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    /// The purge ledger (tests, status).
    pub fn purge_ledger(&self) -> crate::report::Ledger {
        self.ledger.snapshot()
    }

    async fn purge_loop(self: Arc<Self>) {
        loop {
            if self.halted.load(Ordering::SeqCst) {
                return;
            }
            self.purge_pass().await;
            tokio::select! {
                _ = tokio::time::sleep(PURGE_TICK) => {}
                _ = self.purge_notify.notified() => {}
            }
        }
    }

    /// One pass: every removed tenant that is fully drained is purged,
    /// verified and recorded for the status push. Returns the tenants
    /// purged in this pass.
    ///
    /// Candidates are the ledger's pending removals plus any tenant tree on
    /// disk for a tenant not placed here (a removal while the supervisor was
    /// down, or a crash mid-purge). Nothing runs before a placement has been
    /// applied this boot.
    pub async fn purge_pass(self: &Arc<Self>) -> Vec<TenantId> {
        if !self.placement_loaded.load(Ordering::SeqCst) {
            return vec![];
        }
        let placed: std::collections::HashSet<TenantId> =
            self.placement.read().unwrap().tenants.iter().map(|t| t.tenant_id.clone()).collect();
        let tenants_dir = self.cfg.data_dir.join("tenants");
        // NAN-3647: a persistent hot volume can carry the tree of a tenant
        // removed while it sat idle (the roll before last): purge it too.
        let roots = purge_roots(&tenants_dir, external_hot_tenants_dir().as_deref());
        match tokio::task::spawn_blocking(move || -> std::io::Result<Vec<TenantId>> {
            let mut names = Vec::new();
            for (i, dir) in roots.iter().enumerate() {
                match crate::tenant_dirs::tenant_tree_names(dir) {
                    Ok(found) => names.extend(found),
                    Err(e) if i > 0 && e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            names.sort();
            names.dedup();
            Ok(names)
        }).await {
            Ok(Ok(names)) => {
                let orphans: Vec<TenantId> = names.into_iter().filter(|t| !placed.contains(t)).collect();
                self.ledger.update(|l| {
                    let mut adopted = false;
                    for t in &orphans {
                        if l.adopt_orphan(t, now_ms()) {
                            tracing::info!(tenant = %t, "tenant tree on disk for a tenant not placed here; purge pending");
                            adopted = true;
                        }
                    }
                    ((), adopted)
                });
            }
            Ok(Err(e)) => tracing::warn!(error = %e, "could not list tenant trees for the purge"),
            Err(e) => tracing::warn!(error = %e, "tenant tree listing task failed"),
        }
        let pending: Vec<TenantId> =
            self.ledger.snapshot().pending.into_keys().filter(|t| !placed.contains(t)).collect();
        self.purge_blocked.lock().unwrap().retain(|t, _| pending.contains(t));
        let mut done = Vec::new();
        for t in pending {
            if self.tenants.lock().unwrap().contains_key(&t) {
                continue; // still draining; the reaper forgets it once drained
            }
            if self.purge_retry.lock().unwrap().get(&t).is_some_and(|(_, next)| Instant::now() < *next) {
                continue;
            }
            match self.purge_tenant(&t).await {
                Ok(bytes) => {
                    self.purge_retry.lock().unwrap().remove(&t);
                    self.purge_blocked.lock().unwrap().remove(&t);
                    let at = chrono::Utc::now();
                    let recorded = self.ledger.update(|l| {
                        let r = l.record(&t, bytes, at, now_ms());
                        (r, r)
                    });
                    if recorded {
                        tracing::info!(tenant = %t, cache_bytes = bytes.cache_bytes, tmp_bytes = bytes.tmp_bytes,
                            entries = bytes.entries, "tenant purged from this cell and verified");
                        done.push(t);
                    }
                }
                Err(PurgeSkip::NotYet(why)) => tracing::debug!(tenant = %t, why, "purge deferred"),
                Err(PurgeSkip::Blocked(reason)) => {
                    if self.purge_blocked.lock().unwrap().insert(t.clone(), reason).is_none() {
                        tracing::error!(tenant = %t, reason,
                            "tenant purge refused: its local parts dir is the part store of record (no part_signing); the tenant stays draining");
                    }
                }
                Err(PurgeSkip::Failed(e)) => {
                    self.purge_failures.fetch_add(1, Ordering::Relaxed);
                    let mut retry = self.purge_retry.lock().unwrap();
                    let n = retry.get(&t).map_or(0, |(n, _)| *n) + 1;
                    let wait = (PURGE_TICK * 2u32.saturating_pow(n.min(8))).min(PURGE_RETRY_MAX);
                    retry.insert(t.clone(), (n, Instant::now() + wait));
                    tracing::error!(tenant = %t, error = %e, failures = n, retry_in_secs = wait.as_secs(),
                        "tenant purge failed; not reported, will retry");
                }
            }
        }
        let expired = self.ledger.update(|l| {
            let old = l.expire(now_ms(), crate::report::PURGED_TTL);
            let changed = !old.is_empty();
            (old, changed)
        });
        for t in expired {
            tracing::warn!(tenant = %t, "verified purge never acknowledged by the platform; aged out");
        }
        if !done.is_empty() {
            self.report_notify.notify_one();
        }
        done
    }

    /// Drain check → purge → verify for one unplaced tenant.
    async fn purge_tenant(self: &Arc<Self>, t: &TenantId) -> Result<crate::tenant_dirs::PurgeBytes, PurgeSkip> {
        // Fence under the tenants lock (see `slot`): no slot now, none until
        // the fence drops.
        {
            let tenants = self.tenants.lock().unwrap();
            if tenants.contains_key(t) {
                return Err(PurgeSkip::NotYet("still draining"));
            }
            if self.placed(t).is_some() {
                return Err(PurgeSkip::NotYet("placed again"));
            }
            self.purging.lock().unwrap().insert(t.clone());
        }
        struct Unfence<'a>(&'a Supervisor, &'a TenantId);
        impl Drop for Unfence<'_> {
            fn drop(&mut self) {
                self.0.purging.lock().unwrap().remove(self.1);
            }
        }
        let _unfence = Unfence(self, t);
        let fail = |e: String| PurgeSkip::Failed(e);

        // 1. Nothing of it runs (its uids are never reused by another tenant).
        let ids = self.uidmap.lock().unwrap().get(t);
        let uids: Vec<u32> = ids.map(|i| i.uids()).unwrap_or_default();
        let running = |uids: &[u32]| if uids.is_empty() { vec![] } else { procfs::processes_of(&procfs::scan(), uids, None) };
        let left = running(&uids);
        if !left.is_empty() {
            let n = kill_all(&left);
            tracing::warn!(tenant = %t, killed = n, "processes still ran under a removed tenant's uids; killed before purge");
            return Err(PurgeSkip::NotYet("processes were still running"));
        }
        // 2. Its cgroup is gone (delegated mode).
        if let (Some(cg), Some(ids)) = (self.cgroups.get(), ids) {
            cg.register(t, ids.slot);
            match cg.remove_tenant_if_empty(t) {
                Ok(true) => {}
                Ok(false) => return Err(PurgeSkip::NotYet("tenant cgroup still has processes")),
                Err(e) => return Err(fail(format!("remove tenant cgroup: {e}"))),
            }
        }
        let tenants_dir = self.cfg.data_dir.join("tenants");
        // 3. Never purge data of record. Without `part_signing`, ingest's part
        //    store IS `<T>/parts` (LocalObjectStore, lab cells) and it acks the
        //    edge log / notices upstream after committing there: deleting it
        //    would lose committed data. With R2 parts, everything local is
        //    re-derivable (spill = transient PUT temp files; part drafts are
        //    uploaded before the part-log Add, which precedes the upstream
        //    commit, so the next consumer re-pulls anything not committed).
        if self.cfg.part_signing.is_none() {
            let (dir, name) = (tenants_dir.clone(), t.as_str().to_owned());
            let nonempty = tokio::task::spawn_blocking(move || crate::tenant_dirs::tenant_subdir_nonempty(&dir, &name, "parts"))
                .await
                .map_err(|e| fail(format!("parts check task: {e}")))?
                .map_err(|e| fail(format!("parts check: {e}")))?;
            if nonempty {
                return Err(PurgeSkip::Blocked(BLOCKED_LOCAL_PARTS));
            }
        }
        // 4. Purge its tree (never outside it, never following a link), and
        //    (NAN-3647) its hot-window tree on an external hot volume.
        let roots = purge_roots(&tenants_dir, external_hot_tenants_dir().as_deref());
        let (dirs, name) = (roots.clone(), t.as_str().to_owned());
        let bytes = tokio::task::spawn_blocking(move || -> std::io::Result<crate::tenant_dirs::PurgeBytes> {
            let mut total = crate::tenant_dirs::PurgeBytes::default();
            for (i, dir) in dirs.iter().enumerate() {
                if i > 0 {
                    match crate::tenant_dirs::tenant_tree_present(dir, &name) {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(e),
                    }
                }
                let b = crate::tenant_dirs::purge_tenant_tree(dir, &name)?;
                total.cache_bytes += b.cache_bytes;
                total.tmp_bytes += b.tmp_bytes;
                total.entries += b.entries;
            }
            Ok(total)
        })
            .await
            .map_err(|e| fail(format!("purge task: {e}")))?
            .map_err(|e| fail(e.to_string()))?;
        // 5. Verify: nothing left on disk, nothing running, no cgroup, no
        //    descriptor of ours into it (tenant processes are all gone, so
        //    no other process can hold one).
        for (i, dir) in roots.iter().enumerate() {
            match crate::tenant_dirs::tenant_tree_present(dir, t.as_str()) {
                Ok(false) => {}
                Ok(true) => return Err(fail("tenant tree still present after purge".into())),
                Err(e) if i > 0 && e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(fail(format!("verify tenant tree: {e}"))),
            }
        }
        if !running(&uids).is_empty() {
            return Err(fail("a process started under the tenant's uids during the purge".into()));
        }
        if let Some(cg) = self.cgroups.get() {
            if ids.is_some() && cg.tenant_dir(t).exists() {
                return Err(fail("tenant cgroup reappeared during the purge".into()));
            }
        }
        let open = own_fds_under(&tenants_dir.join(t.as_str()));
        if open > 0 {
            return Err(fail(format!("the supervisor still holds {open} descriptors into the purged tree")));
        }
        // 6. NAN-3875: trees, processes and cgroup verified gone, and still
        //    fenced (`slot` refuses it while purging): its uid slot may now
        //    be reused. A failure only keeps the slot reserved.
        if let Err(error) = self.uidmap.lock().unwrap().release(t) {
            tracing::warn!(tenant = %t, %error, "could not release the purged tenant's uid slot; it stays reserved");
        }
        Ok(bytes)
    }

    // ---------------------------------------------------------------- status

    pub fn status(&self) -> CellStatus {
        let placement = self.placement.read().unwrap().clone();
        let slots: HashMap<TenantId, Arc<TenantSlot>> = self.tenants.lock().unwrap().clone();
        let now = Instant::now();
        let names = |a: [u64; ROLES]| -> HashMap<&'static str, u64> {
            Role::ALL.iter().map(|r| (r.as_str(), a[role_idx(*r)])).collect()
        };
        let mut tenants = Vec::new();
        let monitor = self.monitor.lock().unwrap();
        for tp in &placement.tenants {
            let budget = TenantBudget::from_eps(tp.eps);
            let Some(slot) = slots.get(&tp.tenant_id) else {
                tenants.push(TenantStatus {
                    tenant_id: tp.tenant_id.clone(),
                    eps: tp.eps,
                    ingest: tp.ingest,
                    budget,
                    processes: vec![],
                    usage: TenantUsage::default(),
                    spawns: names([0; ROLES]),
                    reaps: names([0; ROLES]),
                    crashes: names([0; ROLES]),
                    stall_kills: names([0; ROLES]),
                    oom_kills: 0,
                    watchdog_kills: 0,
                    last_spawn_ms: names([0; ROLES]),
                    last_exit: None,
                    role_spawn_blocked: vec![],
                    detect_runs_rules: tp.detect_runs_rules(self.cfg.detect_runs_rules),
                    resources: None,
                    limit_events: vec![],
                    limit_event_counts: HashMap::new(),
                    disk: self.disk.view(&tp.tenant_id),
                });
                continue;
            };
            let procs: Vec<Arc<Proc>> = slot.procs.lock().unwrap().iter().flatten().cloned().collect();
            let processes = procs
                .iter()
                .map(|p| {
                    let (hb_at, hb) = p.heartbeat.lock().unwrap().clone();
                    ProcStatus {
                        role: p.role,
                        pid: p.pid,
                        uid: p.uid,
                        uptime_secs: now.duration_since(p.started).as_secs_f64(),
                        idle_secs: now.duration_since(p.active_at()).as_secs_f64(),
                        heartbeat_age_secs: now.duration_since(hb_at).as_secs_f64(),
                        heartbeat: hb,
                        landlock: p.landlock.clone(),
                        stopping: p.stopping.load(Ordering::SeqCst),
                        runs_rules: p.runs_rules,
                    }
                })
                .collect();
            let st = slot.stats.lock().unwrap();
            let view = if procs.is_empty() { None } else { monitor.tenant_view(&slot.id) };
            let mut usage = match self.cgroups.get() {
                Some(cg) => {
                    let mut u = cg.usage(&slot.id).unwrap_or_default();
                    u.cpu_usage_usec += st.cpu_usec_retired;
                    u
                }
                None => TenantUsage {
                    memory_bytes: view.as_ref().map(|v| v.memory_bytes).unwrap_or(0),
                    cpu_usage_usec: st.cpu_usec_watchdog as u64,
                    pids: procs.len() as u64,
                    ..Default::default()
                },
            };
            usage.oom_kills = st.oom_kills.max(usage.oom_kills);
            tenants.push(TenantStatus {
                tenant_id: tp.tenant_id.clone(),
                eps: tp.eps,
                ingest: tp.ingest,
                budget,
                processes,
                usage,
                spawns: names(st.spawns),
                reaps: names(st.reaps),
                crashes: names(st.crashes),
                stall_kills: names(st.stall_kills),
                oom_kills: st.oom_kills,
                watchdog_kills: st.watchdog_kills,
                last_spawn_ms: names(st.last_spawn_ms),
                last_exit: st.last_exit.clone(),
                role_spawn_blocked: Role::ALL.iter()
                    .filter_map(|r| st.spawn_blocked[role_idx(*r)].as_ref().map(|b| b.view(*r, now)))
                    .collect(),
                detect_runs_rules: tp.detect_runs_rules(self.cfg.detect_runs_rules),
                resources: view,
                limit_events: st.events.iter().cloned().collect(),
                limit_event_counts: st.event_counts.clone(),
                disk: self.disk.view(&tp.tenant_id),
            });
        }
        let resources = monitor.cell_view();
        drop(monitor);
        let warm = self.warm.lock().unwrap();
        CellStatus {
            cell_id: self.cfg.cell_id.clone(),
            mode: self.cfg.mode,
            limits_mode: self.limits_mode(),
            enforcement: self.enforcement(),
            enforcement_reason: self.enforcement_reason(),
            unenforced_secs: self.unenforced.lock().unwrap().secs(Instant::now()),
            role_budgets: placement.role_budget_source(),
            landlock_abi: self.landlock_abi,
            placement_revision: placement.revision,
            warm: Role::ALL.iter().map(|r| (r.as_str(), warm.get(r).map_or(0, |q| q.len()))).collect(),
            spawn_failures: self.spawn_failures.load(Ordering::Relaxed),
            resources,
            delegation: self.delegation.clone(),
            cgroup_mount: *self.mount_method.lock().unwrap(),
            delegation_withdrawn: self.delegation_withdrawn.load(Ordering::SeqCst),
            admission: self.admission(),
            identity: self.identity.clone(),
            limit_events: self.cell_events.lock().unwrap().iter().cloned().collect(),
            tenants,
            handover: self.handover_status(&placement),
            supervisor_reserve: self.supervisor_reserve(),
        }
    }

    /// NAN-3523: how the supervisor is protected (OOM ordering, and the
    /// kernel's `init/` reserve when delegated).
    pub fn supervisor_reserve(&self) -> crate::oom::SupervisorReserve {
        crate::oom::SupervisorReserve::read(self.cfg.resources.tenant_oom_score_adj, self.cgroups.get().map(|cg| cg.root()))
    }

    /// Stall/lag signals in the lake pipeline alert shape (NAN-2780).
    pub fn signals(&self) -> Vec<Signal> {
        let now = Instant::now();
        let mut out = Vec::new();
        let cell = |signal: &'static str, unit: &'static str, value: f64, warn: f64, page: f64, detail: Option<String>| {
            Signal::evaluate(None, "cell", "supervisor", signal, unit, value, warn, page, detail)
        };
        out.push(cell("cell_restart", "count", (self.restarted && self.started_at.elapsed() < Duration::from_secs(3600)) as u8 as f64,
            1.0, f64::INFINITY, None));
        out.push(cell(
            "limits_degraded",
            "flag",
            if self.cgroups.get().is_none() { 1.0 } else { 0.0 },
            1.0,
            f64::INFINITY,
            self.cgroups.get().is_none().then(|| format!("no cgroup delegation: watchdog only ({})",
                self.delegation_reasons.lock().unwrap().join("; "))),
        ));
        // NAN-2993: limits the config asked for but the kernel is not
        // enforcing. Warns at once, pages after 15 min: a cell must never
        // run without per-role limits unnoticed.
        let unenforced_secs = self.unenforced.lock().unwrap().secs(now);
        out.push(cell("limits_unenforced", "seconds", if self.limits_unenforced() { unenforced_secs.max(1) as f64 } else { 0.0 },
            1.0, LIMITS_UNENFORCED_PAGE.as_secs_f64(), self.limits_unenforced().then(|| self.enforcement_reason().unwrap_or_default())));
        // NAN-3523: a pooled cell refusing tenant processes warns at once and
        // pages after 30 s of continuous refusal: its tenants' data queues upstream.
        out.push(crate::signals::pooled_admission_refused(self.admission_refused_for(), self.enforcement_reason()));
        let role_budgets = self.placement.read().unwrap().role_budget_source();
        out.push(cell("placement_role_budgets_missing", "flag", (role_budgets == "legacy_eps") as u8 as f64, 1.0, f64::INFINITY,
            (role_budgets == "legacy_eps").then(|| "placement lacks role budgets (role_budgets_v1); legacy eps-derived limits".to_owned())));
        // NAN-3523: `data_volume` io.max asked for but not applied.
        let io_unresolved = self.cgroups.get().and_then(|t| t.io_max_unresolved().map(str::to_owned));
        out.push(cell("io_max_unresolved", "flag", io_unresolved.is_some() as u8 as f64, 1.0, f64::INFINITY, io_unresolved));
        let withdrawn = self.delegation_withdrawn.load(Ordering::SeqCst);
        out.push(cell("cgroup_delegation_withdrawn", "flag", withdrawn as u8 as f64, 1.0, 1.0,
            withdrawn.then(|| "the delegator took the cell's cgroup scope back; watchdog-only enforcement".to_owned())));
        let cell_view = self.monitor.lock().unwrap().cell_view();
        out.push(cell("cpu_utilization_10m", "ratio", self.alert_windows.lock().unwrap().cell_cpu_10m(), 0.8, f64::INFINITY, None));
        out.push(cell("cpu_contended", "flag", cell_view.cpu_contended as u8 as f64, 1.0, f64::INFINITY,
            cell_view.cpu_contended.then(|| format!("demand {:.0} of {} millicores", cell_view.cpu_demand_millicores,
                cell_view.capacity.cpu_millicores))));
        out.push(cell("memory_contended", "flag", cell_view.memory_contended as u8 as f64, 1.0, f64::INFINITY,
            cell_view.memory_contended.then(|| format!("{} of {} bytes", cell_view.memory_bytes, cell_view.capacity.memory_bytes))));
        out.push(cell(
            "spawn_failures",
            "count_1h",
            self.recent_spawn_failures.lock().unwrap().len() as f64,
            1.0,
            3.0,
            None,
        ));
        // NAN-3440: an upstream (R2 / control plane) unreachable from this
        // pod. Warns at half the threshold, pages at it (when `/healthz`
        // reports `upstream_ready: false`; `/readyz` never gates on it).
        if let Some(u) = &self.upstream {
            let v = u.verdict(now);
            let after = u.config().not_ready_after_secs as f64;
            out.push(cell("upstream_unreachable", "seconds", v.stalled_secs, after / 2.0, after, v.detail()));
        }
        // A resident ingest that stays down (crash loop, long backoff, spawn
        // failures) pages: nothing else would restart the tenant's data flow.
        let placement = self.placement.read().unwrap().clone();
        let down = self.resident_down_since.lock().unwrap().clone();
        for tp in placement.tenants.iter().filter(|t| t.ingest == IngestMode::Resident) {
            let secs = down.get(&tp.tenant_id).map_or(0.0, |at| now.duration_since(*at).as_secs_f64());
            out.push(Signal::evaluate(Some(tp.tenant_id.clone()), "cell", "ingest", "ingest_not_running", "seconds", secs,
                RESIDENT_DOWN_WARN.as_secs_f64(), RESIDENT_DOWN_PAGE.as_secs_f64(), None));
        }
        for tp in &placement.tenants {
            out.extend(self.disk.signals(&tp.tenant_id));
        }
        let slots: Vec<Arc<TenantSlot>> = self.tenants.lock().unwrap().values().cloned().collect();
        let stall_page = self.cfg.stall_kill_secs as f64;
        let pressure_min = self.cfg.resources.sustained_pressure_secs as f64 / 60.0;
        for slot in slots {
            let t = Some(slot.id.clone());
            out.push(Signal::evaluate(t.clone(), "cell", "query", "query_throttled_5m", "ratio",
                self.alert_windows.lock().unwrap().query_throttled_5m(&slot.id), 0.25, f64::INFINITY, None));
            let has_procs = slot.procs.lock().unwrap().iter().any(|p| p.is_some());
            if let Some(v) = has_procs.then(|| self.monitor.lock().unwrap().tenant_view(&slot.id)).flatten() {
                let l = &v.limits;
                // Stress signal for placement/autoscaling: observed vs guarantee.
                out.push(Signal::evaluate(t.clone(), "cell", "tenant", "tenant_sustained_pressure", "minutes",
                    v.over_guarantee_secs as f64 / 60.0, pressure_min, f64::INFINITY,
                    Some(format!("cpu {:.0}/{} mc, memory {}/{} bytes (observed/guarantee)", v.cpu_demand_millicores,
                        l.cpu_guarantee_millicores, v.memory_bytes, l.memory_guarantee_bytes))));
                out.push(Signal::evaluate(t.clone(), "cell", "tenant", "cpu_throttled", "flag",
                    v.throttle.is_some() as u8 as f64, 1.0, f64::INFINITY,
                    v.throttle.map(|th| format!("{} to {} mc (duty {:.2})", th.reason.as_str(), th.target_millicores, th.duty))));
            }
            for p in slot.procs.lock().unwrap().iter().flatten() {
                let (hb_at, hb) = p.heartbeat.lock().unwrap().clone();
                let age = now.duration_since(hb_at).as_secs_f64();
                let hb_warn = HEARTBEAT_INTERVAL_MAX.as_secs_f64() * 2.0;
                out.push(Signal::evaluate(t.clone(), "cell", p.role.as_str(), "heartbeat_age", "seconds", age,
                    hb_warn, (stall_page / 2.0).max(hb_warn * 2.0), None));
                if p.role == Role::Ingest {
                    // ≤ 2 min arrival → searchable is the acceptance; 5 is not.
                    // NAN-3522: a tenant under the over-commit hold lags on purpose (its
                    // backlog drains at the hold rate): warn, never page, on the lag; a
                    // held ingest that stops committing still pages (progress_stalled).
                    let (lag_page, stall_page_min) = held_ingest_pages(p.ingest_hold_eps);
                    out.push(Signal::evaluate(t.clone(), "ingest", "ingest", "ingest_lag", "seconds",
                        hb.lag_seconds, 120.0, lag_page, hb.detail.clone()));
                    out.push(crate::signals::unmerged_l0_age(t.clone(), hb.oldest_unmerged_l0_age_seconds));
                    out.push(crate::signals::l0_merge_overdue(t.clone(), hb.l0_merge_overdue_seconds));
                    out.push(crate::signals::prevalence_behind(t.clone(), hb.prevalence_behind_seconds,
                        hb.prevalence_behind_entries));
                    out.push(crate::signals::prevalence_degraded(t.clone(), hb.prevalence_degraded_seconds));
                    // NAN-3773: pending input that does not commit, not "busy
                    // and the last commit is old" (a quiet tenant's next batch).
                    let stalled = crate::signals::ingest_stalled_minutes(now_ms(), hb.busy, hb.retrying,
                        hb.last_progress_unix_ms, hb.lag_seconds);
                    out.push(Signal::evaluate(t.clone(), "ingest", "ingest", "ingest_progress_stalled", "minutes",
                        stalled, 5.0, stall_page_min, None));
                    // Refused data is never silent: any refused object warns,
                    // and a refusal burst pages (thresholds per process life).
                    out.push(Signal::evaluate(t.clone(), "ingest", "ingest", "objects_rejected", "count",
                        hb.objects_rejected as f64, 1.0, 10.0, None));
                    out.push(Signal::evaluate(t.clone(), "ingest", "ingest", "rows_rejected", "count",
                        hb.rows_rejected as f64, 1.0, 1_000.0, None));
                    out.push(Signal::evaluate(t.clone(), "ingest", "ingest", "commit_retrying", "flag",
                        if hb.retrying { 1.0 } else { 0.0 }, 1.0, f64::INFINITY, hb.detail.clone()));
                }
                if p.role == Role::Detect {
                    // Findings not yet in the lake: risk and `source_type=findings`
                    // are blind to them. Warn at 5 min, page at 10.
                    out.push(Signal::evaluate(t.clone(), "detect", "detect", "finding_outbox_age", "seconds",
                        hb.lag_seconds, FINDING_OUTBOX_AGE_WARN_S, FINDING_OUTBOX_AGE_PAGE_S, hb.detail.clone()));
                }
            }
            let st = slot.stats.lock().unwrap();
            let window = now.checked_sub(Duration::from_secs(900)).unwrap_or(now);
            let crashes_15m = st.recent_crashes.iter().filter(|t| **t >= window).count() as f64;
            out.push(Signal::evaluate(t.clone(), "cell", "tenant", "crash_loop", "count_15m", crashes_15m, 3.0, 5.0,
                st.last_exit.clone()));
            out.push(Signal::evaluate(t.clone(), "cell", "tenant", "oom_kills", "count_1h",
                st.recent_ooms.len() as f64, 1.0, 1.0, None));
            for role in Role::ALL {
                let i = role_idx(role);
                let recent_restart = st.spawns[i] > 1 && now_ms().saturating_sub(st.last_spawn_ms[i]) < 3_600_000;
                out.push(Signal::evaluate(t.clone(), "cell", role.as_str(), "process_restart", "count",
                    recent_restart as u8 as f64, 1.0, f64::INFINITY, None));
            }
            out.push(Signal::evaluate(t.clone(), "cell", "tenant", "stall_kills", "count_1h",
                st.recent_stalls.len() as f64, 1.0, 1.0, None));
            // A role the control plane will not start: warns at once, pages
            // after 15 min, and names the refusal code.
            for role in Role::ALL {
                let blocked = st.spawn_blocked[role_idx(role)].as_ref();
                out.push(Signal::evaluate(t.clone(), "cell", role.as_str(), "role_spawn_blocked", "seconds",
                    blocked.map_or(0.0, |b| now.saturating_duration_since(b.since).as_secs().max(1) as f64),
                    1.0, SPAWN_BLOCKED_PAGE.as_secs_f64(),
                    blocked.map(|b| format!("control plane refused the {} bootstrap token: {} {}{}", role.as_str(), b.status, b.code,
                        b.missing.as_deref().map(|m| format!(" (missing {m})")).unwrap_or_default()))));
            }
        }
        out
    }

    /// NAN-3773: [`Self::signals`] through the fire/resolve hysteresis
    /// (`signals::Hysteresis`). What the lean-cell alert feed and `/metrics`
    /// report; `/v1/signals` stays the raw instantaneous view.
    pub fn alert_signals(&self) -> Vec<Signal> {
        let raw = self.signals();
        self.signal_debounce.lock().unwrap().apply_all(Instant::now(), raw)
    }

    /// Prometheus text exposition. `include_tenants` = false (the
    /// unauthenticated `metrics_public` endpoint) leaves out every
    /// per-tenant series and signal: tenant ids and their load are not for
    /// anyone who can reach the port.
    pub fn metrics(&self, include_tenants: bool) -> String {
        use std::fmt::Write;
        let s = self.status();
        let mut m = String::new();
        let _ = writeln!(m, "# TYPE nano_cell_info gauge");
        let _ = writeln!(m, "nano_cell_info{{cell_id=\"{}\",limits_mode=\"{:?}\",landlock_abi=\"{}\"}} 1",
            s.cell_id, s.limits_mode, s.landlock_abi);
        let _ = writeln!(m, "nano_cell_placement_revision {}", s.placement_revision);
        // NAN-2993: 1 only when the kernel enforces per-tenant/per-role limits.
        let _ = writeln!(m, "# TYPE nano_cell_limits_enforced gauge");
        let _ = writeln!(m, "nano_cell_limits_enforced{{cell=\"{}\",enforcement=\"{}\"}} {}", s.cell_id, s.enforcement.as_str(),
            (s.enforcement == limits::Enforcement::Kernel) as u8);
        let _ = writeln!(m, "nano_cell_limits_unenforced_seconds{{cell=\"{}\"}} {}", s.cell_id, s.unenforced_secs);
        // NAN-3523: 1 while a pooled cell refuses new tenant processes.
        let _ = writeln!(m, "# TYPE nano_cell_admission_refused gauge");
        let _ = writeln!(m, "nano_cell_admission_refused{{cell=\"{}\",admission=\"{}\"}} {}", s.cell_id, s.admission.as_str(),
            (s.admission != limits::Admission::Open) as u8);
        // NAN-3004: readiness and writer handover.
        if let Some(h) = &s.handover {
            let _ = writeln!(m, "# TYPE nano_cell_ready gauge");
            let _ = writeln!(m, "nano_cell_ready{{cell=\"{}\"}} {}", s.cell_id, h.ready as u8);
            let _ = writeln!(m, "nano_cell_handover_draining{{cell=\"{}\"}} {}", s.cell_id,
                (h.phase == crate::handover::Phase::Draining) as u8);
            let _ = writeln!(m, "nano_cell_warm_pending_tenants{{cell=\"{}\"}} {}", s.cell_id, h.warm_pending);
            let _ = writeln!(m, "nano_cell_standby_tenants{{cell=\"{}\"}} {}", s.cell_id, h.standby.len());
            let _ = writeln!(m, "nano_cell_peers_alive{{cell=\"{}\"}} {}", s.cell_id, h.peers.iter().filter(|p| p.alive).count());
        }
        // NAN-3440: egress watchdog (target names are config-validated
        // `[a-z0-9_]`, never URLs).
        if let Some(v) = self.upstream_verdict() {
            let _ = writeln!(m, "# TYPE nano_cell_upstream_ready gauge");
            let _ = writeln!(m, "nano_cell_upstream_ready{{cell=\"{}\"}} {}", s.cell_id, v.ready as u8);
            let _ = writeln!(m, "# TYPE nano_cell_upstream_unreachable_seconds gauge");
            for t in &v.targets {
                let _ = writeln!(m, "nano_cell_upstream_unreachable_seconds{{cell=\"{}\",target=\"{}\"}} {}", s.cell_id, t.name, t.unreachable_s);
            }
        }
        let _ = writeln!(m, "nano_cell_placement_role_budgets{{cell=\"{}\",source=\"{}\"}} {}", s.cell_id, s.role_budgets,
            (s.role_budgets == "placement") as u8);
        let _ = writeln!(m, "nano_cell_capacity_cpu_millicores {}", s.resources.capacity.cpu_millicores);
        let _ = writeln!(m, "nano_cell_capacity_memory_bytes {}", s.resources.capacity.memory_bytes);
        let _ = writeln!(m, "nano_cell_cpu_utilization_ratio{{cell=\"{}\"}} {:.6}", s.cell_id,
            s.resources.cpu_demand_millicores / s.resources.capacity.cpu_millicores.max(1) as f64);
        let _ = writeln!(m, "nano_cell_active_processes{{cell=\"{}\"}} {}", s.cell_id,
            s.tenants.iter().map(|t| t.processes.len()).sum::<usize>());
        let _ = writeln!(m, "nano_cell_cpu_demand_millicores {:.1}", s.resources.cpu_demand_millicores);
        let _ = writeln!(m, "nano_cell_memory_bytes {}", s.resources.memory_bytes);
        let _ = writeln!(m, "nano_cell_cpu_contended {}", s.resources.cpu_contended as u8);
        let _ = writeln!(m, "nano_cell_memory_contended {}", s.resources.memory_contended as u8);
        let _ = writeln!(m, "nano_cell_spawn_failures_total {}", s.spawn_failures);
        for (role, n) in &s.warm {
            let _ = writeln!(m, "nano_cell_warm_processes{{role=\"{role}\"}} {n}");
        }
        let _ = writeln!(m, "nano_cell_tenants_placed {}", s.tenants.len());
        let ledger = self.ledger.snapshot();
        let _ = writeln!(m, "nano_cell_purges_pending {}", ledger.pending.len());
        let _ = writeln!(m, "nano_cell_purges_unacknowledged {}", ledger.purged.len());
        let _ = writeln!(m, "nano_cell_purge_failures_total {}", self.purge_failures.load(Ordering::Relaxed));
        for (t, reason) in self.purge_blocked.lock().unwrap().iter() {
            let _ = writeln!(m, "nano_cell_purge_blocked{{tenant=\"{t}\",reason=\"{reason}\"}} 1");
        }
        for (outcome, n) in self.status_pushes.lock().unwrap().iter() {
            let _ = writeln!(m, "nano_cell_status_pushes_total{{outcome=\"{outcome}\"}} {n}");
        }
        let tenants: &[TenantStatus] = if include_tenants { &s.tenants } else { &[] };
        for t in tenants {
            let id = t.tenant_id.as_str();
            let _ = writeln!(m, "nano_cell_tenant_eps{{tenant=\"{id}\"}} {}", t.eps);
            let _ = writeln!(m, "nano_cell_tenant_memory_bytes{{tenant=\"{id}\"}} {}", t.usage.memory_bytes);
            let _ = writeln!(m, "nano_cell_tenant_memory_limit_bytes{{tenant=\"{id}\"}} {}", t.budget.limit_memory_bytes);
            let _ = writeln!(m, "nano_cell_tenant_cpu_seconds_total{{tenant=\"{id}\"}} {}",
                t.usage.cpu_usage_usec as f64 / 1e6);
            let _ = writeln!(m, "nano_cell_tenant_cpu_limit_millicores{{tenant=\"{id}\"}} {}", t.budget.limit_millicores);
            let _ = writeln!(m, "nano_cell_tenant_oom_kills_total{{tenant=\"{id}\"}} {}", t.oom_kills);
            let _ = writeln!(m, "nano_cell_tenant_watchdog_kills_total{{tenant=\"{id}\"}} {}", t.watchdog_kills);
            for (kind, n) in &t.limit_event_counts {
                let _ = writeln!(m, "nano_cell_tenant_limit_events_total{{tenant=\"{id}\",kind=\"{kind}\"}} {n}");
            }
            if let Some(d) = &t.disk {
                // NAN-3523: local tree (without query/cache) vs its ceilings.
                if let Some(b) = d.bytes {
                    let _ = writeln!(m, "nano_cell_tenant_disk_bytes{{cell=\"{}\",tenant=\"{id}\"}} {b}", s.cell_id);
                }
                let _ = writeln!(m, "nano_cell_tenant_disk_soft_bytes{{cell=\"{}\",tenant=\"{id}\"}} {}", s.cell_id, d.soft_bytes);
                let _ = writeln!(m, "nano_cell_tenant_disk_hard_bytes{{cell=\"{}\",tenant=\"{id}\"}} {}", s.cell_id, d.hard_bytes);
                let _ = writeln!(m, "nano_cell_tenant_disk_ingest_refused{{cell=\"{}\",tenant=\"{id}\"}} {}", s.cell_id, d.ingest_refused as u8);
            }
            for b in &t.role_spawn_blocked {
                let _ = writeln!(m, "nano_cell_role_spawn_blocked{{cell=\"{}\",tenant=\"{id}\",role=\"{}\",reason=\"{}\"}} 1",
                    s.cell_id, b.role.as_str(), b.reason);
                let _ = writeln!(m, "nano_cell_role_spawn_blocked_seconds{{cell=\"{}\",tenant=\"{id}\",role=\"{}\"}} {}",
                    s.cell_id, b.role.as_str(), b.blocked_secs);
            }
            if let Some(v) = &t.resources {
                let l = &v.limits;
                let _ = writeln!(m, "nano_cell_tenant_cpu_millicores{{tenant=\"{id}\"}} {:.1}", v.cpu_millicores);
                let _ = writeln!(m, "nano_cell_tenant_cpu_demand_millicores{{tenant=\"{id}\"}} {:.1}", v.cpu_demand_millicores);
                let _ = writeln!(m, "nano_cell_tenant_cpu_guarantee_millicores{{tenant=\"{id}\"}} {}", l.cpu_guarantee_millicores);
                let _ = writeln!(m, "nano_cell_tenant_cpu_ceiling_millicores{{tenant=\"{id}\"}} {}", l.cpu_ceiling_millicores);
                let _ = writeln!(m, "nano_cell_tenant_memory_guarantee_bytes{{tenant=\"{id}\"}} {}", l.memory_guarantee_bytes);
                let _ = writeln!(m, "nano_cell_tenant_memory_hard_bytes{{tenant=\"{id}\"}} {}", l.memory_hard_bytes);
                let _ = writeln!(m, "nano_cell_tenant_cpu_throttled{{tenant=\"{id}\"}} {}", v.throttle.is_some() as u8);
                let _ = writeln!(m, "nano_cell_tenant_over_guarantee_seconds{{tenant=\"{id}\"}} {}", v.over_guarantee_secs);
            }
            for role in Role::ALL {
                let r = role.as_str();
                let budget = self.placed(&t.tenant_id).map(|p| p.effective_role_budget(role));
                if let Some(b) = budget {
                    let _ = writeln!(m, "nano_cell_role_cpu_request_millicores{{cell=\"{}\",tenant=\"{id}\",role=\"{r}\"}} {}", s.cell_id, b.request_millicores);
                    let _ = writeln!(m, "nano_cell_role_cpu_limit_millicores{{cell=\"{}\",tenant=\"{id}\",role=\"{r}\"}} {}", s.cell_id, b.limit_millicores);
                    let _ = writeln!(m, "nano_cell_role_memory_limit_bytes{{cell=\"{}\",tenant=\"{id}\",role=\"{r}\"}} {}", s.cell_id, b.limit_memory_bytes);
                }
                if let Some(u) = self.cgroups.get().and_then(|cg| cg.role_usage(&t.tenant_id, role)) {
                    let labels = format!("cell=\"{}\",tenant=\"{id}\",role=\"{r}\"", s.cell_id);
                    let _ = writeln!(m, "nano_cell_role_cpu_usage_seconds_total{{{labels}}} {:.6}", u.cpu_usage_usec as f64 / 1e6);
                    let _ = writeln!(m, "nano_cell_role_cpu_throttled_usec_total{{{labels}}} {}", u.cpu_throttled_usec);
                    let _ = writeln!(m, "nano_cell_role_cpu_nr_throttled_total{{{labels}}} {}", u.nr_throttled);
                    let _ = writeln!(m, "nano_cell_role_memory_current_bytes{{{labels}}} {}", u.memory_bytes);
                    let _ = writeln!(m, "nano_cell_role_oom_kills_total{{{labels}}} {}", u.oom_kills);
                }
                if role == Role::Query {
                    if let Some(slot) = self.tenants.lock().unwrap().get(&t.tenant_id) {
                        let st = slot.stats.lock().unwrap();
                        for (bound, count) in QUERY_DURATION_BUCKETS.into_iter().zip(st.query_duration_buckets) {
                            let _ = writeln!(m, "nano_cell_query_request_duration_seconds_bucket{{cell=\"{}\",tenant=\"{id}\",le=\"{bound}\"}} {count}", s.cell_id);
                        }
                        let _ = writeln!(m, "nano_cell_query_request_duration_seconds_bucket{{cell=\"{}\",tenant=\"{id}\",le=\"+Inf\"}} {}", s.cell_id, st.query_duration_count);
                        let _ = writeln!(m, "nano_cell_query_request_duration_seconds_count{{cell=\"{}\",tenant=\"{id}\"}} {}", s.cell_id, st.query_duration_count);
                        let _ = writeln!(m, "nano_cell_query_request_duration_seconds_sum{{cell=\"{}\",tenant=\"{id}\"}} {}", s.cell_id, st.query_duration_sum);
                    }
                }
                let up = t.processes.iter().find(|p| p.role == role);
                let _ = writeln!(m, "nano_cell_tenant_process_up{{tenant=\"{id}\",role=\"{r}\"}} {}", up.is_some() as u8);
                let _ = writeln!(m, "nano_cell_tenant_spawns_total{{tenant=\"{id}\",role=\"{r}\"}} {}", t.spawns[r]);
                let _ = writeln!(m, "nano_cell_role_process_restarts_total{{cell=\"{}\",tenant=\"{id}\",role=\"{r}\"}} {}",
                    s.cell_id, t.spawns[r].saturating_sub(1));
                let _ = writeln!(m, "nano_cell_tenant_reaps_total{{tenant=\"{id}\",role=\"{r}\"}} {}", t.reaps[r]);
                let _ = writeln!(m, "nano_cell_tenant_crashes_total{{tenant=\"{id}\",role=\"{r}\"}} {}", t.crashes[r]);
                let _ = writeln!(m, "nano_cell_tenant_stall_kills_total{{tenant=\"{id}\",role=\"{r}\"}} {}",
                    t.stall_kills[r]);
                let _ = writeln!(m, "nano_cell_tenant_last_spawn_ms{{tenant=\"{id}\",role=\"{r}\"}} {}",
                    t.last_spawn_ms[r]);
                if let Some(p) = up {
                    let _ = writeln!(m, "nano_cell_credential_refresh_at_risk{{cell=\"{}\",tenant=\"{id}\",role=\"{r}\"}} {}",
                        s.cell_id, u8::from(p.heartbeat.credential_refresh_at_risk));
                    let _ = writeln!(m, "nano_cell_tenant_heartbeat_age_seconds{{tenant=\"{id}\",role=\"{r}\"}} {:.3}",
                        p.heartbeat_age_secs);
                    let _ = writeln!(m, "nano_cell_tenant_queue_depth{{tenant=\"{id}\",role=\"{r}\"}} {}",
                        p.heartbeat.queue_depth);
                    if role == Role::Query {
                        if let Some(cache) = &p.heartbeat.selection_evidence_cache {
                            for field in ["entries", "bytes", "max_bytes", "metadata_entries", "metadata_bytes", "mask_entries", "mask_bytes"] {
                                if let Some(value) = cache[field].as_u64() {
                                    let _ = writeln!(m, "nano_cell_selection_evidence_cache_{field}{{cell=\"{}\",tenant=\"{id}\"}} {value}", s.cell_id);
                                }
                            }
                            for field in ["total_files", "completed_files", "skipped_files"] {
                                if let Some(value) = cache["prewarm"][field].as_u64() {
                                    let _ = writeln!(m, "nano_cell_evidence_prewarm_{field}{{cell=\"{}\",tenant=\"{id}\"}} {value}", s.cell_id);
                                }
                            }
                            for state in ["running", "yielded", "complete"] {
                                let active = u8::from(cache["prewarm"]["state"] == state);
                                let _ = writeln!(m, "nano_cell_evidence_prewarm_state{{cell=\"{}\",tenant=\"{id}\",state=\"{state}\"}} {active}", s.cell_id);
                            }
                        }
                    }
                    if role == Role::Detect {
                        let _ = writeln!(m, "nano_cell_finding_outbox_backlog{{cell=\"{}\",tenant=\"{id}\"}} {}",
                            s.cell_id, p.heartbeat.queue_depth);
                        let _ = writeln!(m, "nano_cell_finding_outbox_oldest_age_seconds{{cell=\"{}\",tenant=\"{id}\"}} {:.3}",
                            s.cell_id, p.heartbeat.lag_seconds);
                    }
                    if role == Role::Ingest {
                        let _ = writeln!(m, "nano_cell_oldest_unmerged_l0_age_seconds{{cell=\"{}\",tenant=\"{id}\"}} {:.3}",
                            s.cell_id, p.heartbeat.oldest_unmerged_l0_age_seconds);
                        let _ = writeln!(m, "nano_cell_tenant_ingest_lag_seconds{{tenant=\"{id}\"}} {:.3}",
                            p.heartbeat.lag_seconds);
                        let _ = writeln!(m, "nano_cell_prevalence_behind_seconds{{cell=\"{}\",tenant=\"{id}\"}} {:.3}",
                            s.cell_id, p.heartbeat.prevalence_behind_seconds);
                        let _ = writeln!(m, "nano_cell_prevalence_behind_entries{{cell=\"{}\",tenant=\"{id}\"}} {}",
                            s.cell_id, p.heartbeat.prevalence_behind_entries);
                        // NAN-3781: per process life (resets on respawn).
                        let _ = writeln!(m, "nano_cell_prevalence_degraded_seconds{{cell=\"{}\",tenant=\"{id}\"}} {:.3}",
                            s.cell_id, p.heartbeat.prevalence_degraded_seconds);
                        let _ = writeln!(m, "nano_cell_prevalence_degraded_seconds_total{{cell=\"{}\",tenant=\"{id}\"}} {:.3}",
                            s.cell_id, p.heartbeat.prevalence_degraded_seconds_total);
                        // NAN-3522: per process life (resets on respawn); the status push carries it with its epoch.
                        // Only with NANO_LAKE_CELL_INGEST_COUNTERS: off, the metrics body is unchanged too.
                        if ingest_counters_enabled() {
                            let _ = writeln!(m, "nano_cell_tenant_rows_committed_total{{tenant=\"{id}\"}} {}",
                                p.heartbeat.rows_committed_total);
                        }
                        let _ = writeln!(m, "nano_cell_ingest_arrival_searchable_lag_seconds{{cell=\"{}\",tenant=\"{id}\"}} {:.3}",
                            s.cell_id, p.heartbeat.lag_seconds);
                        if p.heartbeat.last_progress_unix_ms > 0 {
                            let age = now_ms().saturating_sub(p.heartbeat.last_progress_unix_ms) as f64 / 1000.0;
                            let _ = writeln!(m, "nano_cell_part_log_advance_age_seconds{{cell=\"{}\",tenant=\"{id}\"}} {:.3}", s.cell_id, age);
                        }
                        if let Some(blocked) = &p.heartbeat.part_gc_blocked {
                            m.push_str(&blocked.metric_lines(&s.cell_id, id));
                        }
                        m.push_str(&crate::contract::part_gc_deleted_metric_line(
                            &s.cell_id, id, p.heartbeat.part_gc_deleted_total));
                        if let Some(identity) = &p.heartbeat.identity_directory {
                            m.push_str(&identity.metric_lines(&s.cell_id, id));
                        }
                    }
                }
            }
        }
        for sig in self.alert_signals().into_iter().filter(|g| include_tenants || g.tenant_id.is_none()) {
            let _ = writeln!(m, "nano_cell_signal{{tenant=\"{}\",stage=\"{}\",component=\"{}\",signal=\"{}\",severity=\"{}\"}} {}",
                sig.tenant_id.as_ref().map(|t| t.as_str()).unwrap_or(""), sig.stage, sig.component, sig.signal,
                sig.severity.as_str(), if sig.value.is_finite() { sig.value } else { 0.0 });
        }
        m
    }

    /// Is `uid` one of this cell's tenant uids (for SO_PEERCRED checks)?
    pub fn is_tenant_uid(&self, uid: u32) -> bool {
        self.uidmap.lock().unwrap().is_tenant_uid(uid)
    }

    /// Graceful stop of every tenant process (SIGTERM path): `Shutdown`,
    /// wait the grace, then kill whatever is left.
    pub async fn drain_all(&self) {
        self.stopping_all.store(true, Ordering::SeqCst);
        let slots: Vec<Arc<TenantSlot>> = self.tenants.lock().unwrap().values().cloned().collect();
        for s in &slots {
            self.drain_slot(s);
        }
        let deadline = Instant::now() + Duration::from_millis(self.cfg.shutdown_grace_ms);
        while Instant::now() < deadline
            && slots.iter().any(|s| s.procs.lock().unwrap().iter().any(|p| p.is_some()))
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.shutdown_all();
    }

    /// Stop the background loops (placement, warm pool, reaper, watchdog,
    /// adoption). Call after [`Supervisor::shutdown_all`].
    pub fn halt(&self) {
        self.halted.store(true, Ordering::SeqCst);
    }

    // ---------------------------------------------------------------- zero-downtime roll (NAN-3004)

    /// The writer handover state, when `zero_downtime_roll` is configured.
    pub fn handover(&self) -> Option<&Arc<crate::handover::Handover>> {
        self.handover.as_ref()
    }

    /// Readiness for Service traffic (`/readyz`): warm and not draining.
    /// Always true for a single-pod cell (no `zero_downtime_roll`). Never
    /// gated on [`Self::upstream_verdict`] (NAN-3440: a signal, not readiness).
    pub fn ready(&self) -> bool {
        self.handover.as_ref().is_none_or(|h| h.ready())
    }

    /// The egress watchdog's verdict now (NAN-3440); `None` when
    /// `upstream_readiness` is not configured.
    pub fn upstream_verdict(&self) -> Option<crate::upstream::Verdict> {
        self.upstream.as_ref().map(|u| u.verdict(Instant::now()))
    }

    /// Tenants with a writer (ingest, detect or maintenance) alive here,
    /// stopping but not yet exited (flushing), or being spawned right now.
    pub fn writer_tenants(&self) -> std::collections::BTreeSet<TenantId> {
        let slots: Vec<Arc<TenantSlot>> = self.tenants.lock().unwrap().values().cloned().collect();
        let mut out = std::collections::BTreeSet::new();
        for s in slots {
            for role in [Role::Ingest, Role::Detect, Role::Maintenance] {
                let i = role_idx(role);
                let alive = s.procs.lock().unwrap()[i].as_ref().is_some_and(|p| !p.exited.load(Ordering::SeqCst));
                if alive || s.spawn_lock[i].try_lock().is_err() {
                    out.insert(s.id.clone());
                }
            }
        }
        out
    }

    /// `GET /v1/handover`.
    pub fn handover_view(&self) -> Option<crate::handover::HandoverView> {
        self.handover.as_ref().map(|h| h.view(self.writer_tenants()))
    }

    fn handover_status(&self, placement: &Placement) -> Option<crate::handover::HandoverStatus> {
        let h = self.handover.as_ref()?;
        let writing = self.writer_tenants();
        let standby = placement
            .tenants
            .iter()
            .filter(|t| t.ingest == IngestMode::Resident && !writing.contains(&t.tenant_id))
            .filter_map(|t| {
                let lease = || {
                    let slot = self.tenants.lock().unwrap().get(&t.tenant_id).cloned()?;
                    let st = slot.stats.lock().unwrap();
                    writer_standby(&st, Instant::now())
                };
                match h.may_write(&t.tenant_id) {
                    Err(why) => Some((t.tenant_id.clone(), why.to_string())),
                    Ok(()) => lease().map(|why| (t.tenant_id.clone(), why)),
                }
            })
            .collect();
        Some(crate::handover::HandoverStatus {
            boot_id: h.me.boot_id.clone(),
            boot_unix_ms: h.me.boot_unix_ms,
            phase: h.phase(),
            ready: h.ready(),
            warm: h.warm(),
            warm_pending: h.warm_pending().len(),
            standby,
            released: h.released(),
            peers: h.peer_status(),
        })
    }

    /// Read the peers' views every `peer_poll_ms` and poke the keeper, so a
    /// released writer is claimed within one poll.
    async fn peer_loop(self: Arc<Self>) {
        let Some(h) = self.handover.clone() else { return };
        loop {
            if self.halted.load(Ordering::SeqCst) {
                return;
            }
            let token = match crate::router::read_full_token(&self.cfg.router_token_file) {
                Ok(t) => Some(Arc::new(t)),
                Err(e) => {
                    tracing::warn!(error = %e, "router token unreadable; asking peers without it");
                    None
                }
            };
            h.poll_once(token).await;
            self.keeper_notify.notify_one();
            tokio::time::sleep(h.cfg.poll()).await;
        }
    }

    /// Startup warm (NAN-3004): start `query[T]` for every resident tenant
    /// (its prewarm gates its readiness) and latch the pod ready once each
    /// one answers `/v1/status` ready. Until then `/readyz` is 503 and the
    /// Service keeps sending searches to the old pod. No timeout: a tenant
    /// that cannot warm on this image holds the roll (the Deployment's
    /// progress deadline reports it), the old pod keeps serving. With a
    /// local hot window (NAN-3164) "warm" also means the newest
    /// `NANO_LAKE_LOCAL_HOT_WINDOW_WARM_HOURS` are resident while a Ready
    /// peer serves; the query process bounds that part with its own timeout.
    async fn startup_warm_loop(self: Arc<Self>) {
        let Some(h) = self.handover.clone() else { return };
        let t0 = Instant::now();
        let mut last_log = Instant::now();
        loop {
            if self.halted.load(Ordering::SeqCst) || h.warm() || h.draining() {
                return;
            }
            // No placement read yet: an empty warm set would latch the pod
            // ready with nothing warm (and the Service would route every
            // search to a pod that cold-starts query[T]).
            if !self.placement_loaded.load(Ordering::SeqCst) {
                if last_log.elapsed() >= Duration::from_secs(30) {
                    last_log = Instant::now();
                    tracing::info!(waited_secs = t0.elapsed().as_secs(), "startup warm: no placement loaded yet; not ready");
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            let resident = self.startup_warm_set();
            let checks: Vec<_> = resident
                .iter()
                .cloned()
                .map(|t| {
                    let me = self.clone();
                    (t.clone(), tokio::spawn(async move { me.query_warm(&t).await }))
                })
                .collect();
            let mut pending = std::collections::BTreeSet::new();
            let mut why = Vec::new();
            for (t, c) in checks {
                match c.await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        why.push(format!("{t}: {e}"));
                        pending.insert(t);
                    }
                    Err(e) => {
                        why.push(format!("{t}: {e}"));
                        pending.insert(t);
                    }
                }
            }
            if h.set_warm_pending(pending) {
                tracing::info!(tenants = resident.len(), warm_secs = t0.elapsed().as_secs_f64(), "startup warm complete");
                return;
            }
            if last_log.elapsed() >= Duration::from_secs(30) {
                last_log = Instant::now();
                tracing::info!(pending = why.len(), waited_secs = t0.elapsed().as_secs(), detail = ?why.iter().take(5).collect::<Vec<_>>(),
                    "startup warm: query processes still cold; not ready");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// What the startup warm must see serving before the pod is Ready:
    /// every tenant whose query[T] this pod starts before a search arrives —
    /// all placed tenants with `query_resident` (NAN-3008, the production
    /// default: the keeper starts them all), else the ingest-resident ones —
    /// plus every tenant that already has a query process here (spawned
    /// before the latch, so its prewarm gates its readiness). The warm used
    /// to wait on ingest-resident tenants only, so with `query_resident` an
    /// on-demand-ingest tenant's query[T] was still in its gated prewarm when
    /// the pod turned Ready and answered 503 "query prewarm is incomplete".
    pub fn startup_warm_set(&self) -> Vec<TenantId> {
        let placement = self.placement.read().unwrap().clone();
        let mut set: std::collections::BTreeSet<TenantId> = placement.tenants.iter()
            .filter(|t| self.cfg.query_resident || t.ingest == IngestMode::Resident)
            .map(|t| t.tenant_id.clone()).collect();
        let placed: std::collections::BTreeSet<&TenantId> = placement.tenants.iter().map(|t| &t.tenant_id).collect();
        let slots: Vec<Arc<TenantSlot>> = self.tenants.lock().unwrap().values().cloned().collect();
        for s in slots {
            let live = s.procs.lock().unwrap()[role_idx(Role::Query)].as_ref()
                .is_some_and(|p| !p.exited.load(Ordering::SeqCst) && !p.stopping.load(Ordering::SeqCst));
            if live && placed.contains(&s.id) {
                set.insert(s.id.clone());
            }
        }
        set.into_iter().collect()
    }

    /// One routed `GET /v1/status` to `query[T]`: warm when it answers 200
    /// with `"ready": true` (engine open, log verified, prewarm done).
    async fn query_warm(self: &Arc<Self>, t: &TenantId) -> Result<(), String> {
        use http_body_util::BodyExt;
        let gate_applies = self.handover.as_ref().is_some_and(|h| h.hot_window_gate_applies());
        let (_guard, request_id, stream) = self.open_rpc(t, Role::Query).await.map_err(|e| e.to_string())?;
        let check = async move {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .map_err(|e| e.to_string())?;
            tokio::spawn(conn);
            let req = hyper::Request::builder()
                .method("GET")
                .uri("/v1/status")
                .header("host", "cell")
                .header("x-nano-cell-tenant", t.as_str())
                .header("x-nano-cell-request-id", request_id)
                .body(http_body_util::Full::new(bytes::Bytes::new()))
                .map_err(|e| e.to_string())?;
            let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
            let status = resp.status();
            let body = http_body_util::Limited::new(resp.into_body(), 1 << 20)
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            if status.is_success() && v["ready"] == true {
                // NAN-3164: also wait for the newest hours of the local hot
                // window while another pod can carry search. The query
                // process reports warm on its own timeout, so this is bounded.
                if let Some(reason) = hot_window_pending(&v, gate_applies) {
                    return Err(reason);
                }
                Ok(())
            } else {
                Err(format!("status {} {}", status.as_u16(), v["reason"].as_str().or(v["error"].as_str()).unwrap_or("not ready")))
            }
        };
        tokio::time::timeout(Duration::from_secs(30), check).await.map_err(|_| "status timed out".to_string())?
    }

    /// SIGTERM with `zero_downtime_roll` (NAN-3004): withdraw readiness,
    /// release every writer at once (ingest flushes and commits; the new pod
    /// claims each tenant as soon as its writer has exited here), keep
    /// serving queries through `drain_secs` of endpoint propagation, wait
    /// for in-flight queries up to `inflight_secs`, then stop everything.
    /// Without the feature: [`Supervisor::drain_all`].
    pub async fn handover_drain(self: &Arc<Self>) {
        self.handover_quiesce().await;
        self.drain_all().await;
    }

    /// Whether this pod is going away: SIGTERM withdrew readiness (a
    /// zero-downtime drain) or every tenant process is being stopped. The
    /// router answers `Connection: close` from here on, so a caller's pooled
    /// keep-alive connection (pinned to this pod by the Service at connect
    /// time) is closed cleanly after each response and its next request
    /// reconnects through the Service to a pod that stays.
    pub fn draining(&self) -> bool {
        self.stopping_all.load(Ordering::SeqCst) || self.handover.as_ref().is_some_and(|h| h.draining())
    }

    /// The part of [`Supervisor::handover_drain`] that keeps serving:
    /// withdraw readiness, release the writers, serve queries through
    /// `drain_secs` of endpoint propagation and wait for in-flight queries.
    /// Tenant processes are still running when it returns, so the caller
    /// can close the router's connections gracefully before
    /// [`Supervisor::drain_all`] stops them (a request that reaches the pod
    /// after that would be answered 503). Without `zero_downtime_roll`:
    /// returns at once.
    pub async fn handover_quiesce(self: &Arc<Self>) {
        let Some(h) = self.handover.clone() else {
            return;
        };
        let t0 = Instant::now();
        h.begin_drain();
        let slots: Vec<Arc<TenantSlot>> = self.tenants.lock().unwrap().values().cloned().collect();
        let held = self.writer_tenants();
        tracing::info!(writers = held.len(), "SIGTERM: readiness withdrawn; releasing writers to the next pod");
        for s in &slots {
            for role in [Role::Ingest, Role::Detect, Role::Maintenance] {
                if let Some(p) = s.procs.lock().unwrap()[role_idx(role)].clone() {
                    self.stop(p, "handover_release");
                }
            }
        }
        let deadline = Instant::now() + Duration::from_millis(self.cfg.shutdown_grace_ms + 1000);
        loop {
            let still = self.writer_tenants();
            for t in held.difference(&still) {
                h.note_released(t);
            }
            if still.is_empty() || Instant::now() >= deadline {
                if !still.is_empty() {
                    tracing::warn!(tenants = still.len(), "writers still exiting at the release deadline");
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tracing::info!(released = h.released().len(), release_ms = t0.elapsed().as_millis() as u64,
            "writers released; serving queries through the drain window");
        tokio::time::sleep(Duration::from_secs(h.cfg.drain_secs)).await;
        let inflight_deadline = Instant::now() + Duration::from_secs(h.cfg.inflight_secs);
        loop {
            let inflight: u64 = slots.iter()
                .flat_map(|s| s.procs.lock().unwrap().iter().flatten().map(|p| p.inflight.load(Ordering::SeqCst)).collect::<Vec<_>>())
                .sum();
            if inflight == 0 || Instant::now() >= inflight_deadline {
                if inflight > 0 {
                    tracing::warn!(inflight, "in-flight requests at the drain deadline");
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tracing::info!(drain_ms = t0.elapsed().as_millis() as u64, "drain complete; closing connections, then stopping tenant processes");
    }

    /// Stop everything now (SIGKILL).
    pub fn shutdown_all(&self) {
        self.stopping_all.store(true, Ordering::SeqCst);
        let slots: Vec<Arc<TenantSlot>> = self.tenants.lock().unwrap().values().cloned().collect();
        for s in slots {
            for p in s.procs.lock().unwrap().iter().flatten() {
                p.kill("supervisor_shutdown");
            }
        }
        let mut warm = self.warm.lock().unwrap();
        for q in warm.values_mut() {
            for w in q.drain(..) {
                w.pidfd.kill();
            }
        }
    }
}

/// Why a purge did not complete this pass.
enum PurgeSkip {
    /// Expected to clear by itself (draining, re-placed): no failure.
    NotYet(&'static str),
    /// A real failure: counted, logged, retried with backoff, not reported.
    Failed(String),
    /// Refused by design (the local tree holds data of record): the tenant
    /// stays draining, `nano_cell_purge_blocked{reason}` is set, re-checked
    /// every pass.
    Blocked(&'static str),
}

/// `<T>/parts` is the ingest part store itself (no `part_signing`).
const BLOCKED_LOCAL_PARTS: &str = "local_part_store_of_record";

/// Descriptors of this process that resolve under `root` (by path; the
/// purge removes `root`, so a live one would show as `… (deleted)` too).
fn own_fds_under(root: &Path) -> usize {
    let root = root.to_string_lossy().into_owned();
    std::fs::read_dir("/proc/self/fd")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| std::fs::read_link(e.path()).ok())
                .filter(|p| {
                    let p = p.to_string_lossy();
                    p == root.as_str() || p.starts_with(&format!("{root}/")) || p.starts_with(&format!("{root} (deleted)"))
                })
                .count()
        })
        .unwrap_or(0)
}

impl crate::report::StatusSource for Supervisor {
    fn snapshot(&self) -> crate::report::StatusSnapshot {
        use crate::report::TenantState;
        let placement = self.placement.read().unwrap().clone();
        let slots: HashMap<TenantId, Arc<TenantSlot>> = self.tenants.lock().unwrap().clone();
        let live = |s: &Arc<TenantSlot>| s.procs.lock().unwrap().iter().flatten().any(|p| !p.exited.load(Ordering::SeqCst));
        let placed: Vec<(TenantId, TenantState)> = placement
            .tenants
            .iter()
            .map(|tp| {
                let running = slots.get(&tp.tenant_id).is_some_and(live);
                (tp.tenant_id.clone(), if running { TenantState::Running } else { TenantState::Idle })
            })
            .collect();
        let is_placed = |t: &TenantId| placement.tenants.iter().any(|tp| &tp.tenant_id == t);
        // NAN-3522: each placed tenant's live ingest process counter, keyed by its spawn time.
        let ingest = if ingest_counters_enabled() {
            placement.tenants.iter().filter_map(|tp| {
                let slot = slots.get(&tp.tenant_id)?;
                let procs = slot.procs.lock().unwrap();
                let p = procs.iter().flatten().find(|p| p.role == crate::contract::Role::Ingest && !p.exited.load(Ordering::SeqCst))?;
                let rows = p.heartbeat.lock().unwrap().1.rows_committed_total;
                Some((tp.tenant_id.clone(), crate::report::IngestCounters { epoch_ms: p.spawned_unix_ms, rows_committed_total: rows }))
            }).collect()
        } else {
            std::collections::BTreeMap::new()
        };
        // NAN-4137: each placed tenant's live landing[T] counters, keyed by its spawn time.
        let landing = if self.cfg.tenzir_landing {
            placement.tenants.iter().filter(|tp| tp.landing).filter_map(|tp| {
                let slot = slots.get(&tp.tenant_id)?;
                let procs = slot.procs.lock().unwrap();
                let p = procs.iter().flatten().find(|p| p.role == crate::contract::Role::Landing && !p.exited.load(Ordering::SeqCst))?;
                let status = p.heartbeat.lock().unwrap().1.landing.clone()?;
                Some((tp.tenant_id.clone(), crate::report::LandingCounters { epoch_ms: p.spawned_unix_ms, status }))
            }).collect()
        } else {
            std::collections::BTreeMap::new()
        };
        let ledger = self.ledger.snapshot();
        let mut draining: std::collections::BTreeSet<TenantId> = slots.keys().filter(|t| !is_placed(t)).cloned().collect();
        draining.extend(ledger.pending.keys().filter(|t| !is_placed(t)).cloned());
        crate::report::StatusSnapshot {
            cell_id: self.cfg.cell_id.clone(),
            placement_revision: placement.revision,
            placed,
            draining: draining.into_iter().collect(),
            purged: ledger.purged.into_iter().collect(),
            ingest,
            landing,
        }
    }

    fn purges_settled(&self, tenants: &[TenantId]) {
        self.ledger.update(|l| {
            let n = l.forget_purged(tenants);
            (n, n > 0)
        });
    }

    fn push_outcome(&self, outcome: crate::report::PushOutcome) {
        *self.status_pushes.lock().unwrap().entry(outcome.as_str()).or_default() += 1;
    }
}

fn forward_output<R>(r: Option<R>, pid: u32, role: Role, label: Arc<OnceLock<String>>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let Some(r) = r else { return };
    tokio::spawn(async move {
        forward_bounded_lines(r, |line| {
            let who = label.get().map(|s| s.as_str()).unwrap_or("warm");
            tracing::info!(target: "nano_cell::tenant", pid, role = role.as_str(), tenant = who, "{line}");
        })
        .await;
    });
}

/// Bytes of one child output line kept for the log; the rest of the line is
/// read and discarded (NAN-3289 P2-3).
pub const MAX_FORWARDED_LINE_BYTES: usize = 4096;

/// Forward a tenant process's output line by line with BOUNDED memory
/// (NAN-3289 P2-3): `lines()` buffered a whole line before truncating it, so
/// one child writing gigabytes without a newline grew the supervisor until
/// it was OOM-killed, taking every tenant's processes with it (PDEATHSIG).
/// Here at most [`MAX_FORWARDED_LINE_BYTES`] of a line plus the reader's own
/// 8 KiB buffer are ever held; an over-long line is emitted truncated with a
/// `[truncated N bytes]` marker. Control characters are escaped so a tenant
/// cannot forge log lines.
pub async fn forward_bounded_lines<R>(r: R, mut emit: impl FnMut(&str))
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    let mut reader = tokio::io::BufReader::with_capacity(8192, r);
    let mut line: Vec<u8> = Vec::with_capacity(MAX_FORWARDED_LINE_BYTES);
    let mut dropped: u64 = 0;
    let mut flush = |line: &mut Vec<u8>, dropped: &mut u64| {
        let text = String::from_utf8_lossy(line);
        let mut out: String = text.chars().flat_map(|c| if c.is_control() && c != '\t' { c.escape_default().collect::<Vec<_>>() } else { vec![c] }).collect();
        if *dropped > 0 {
            out.push_str(&format!(" …[truncated {dropped} bytes]"));
        }
        emit(&out);
        line.clear();
        *dropped = 0;
    };
    loop {
        let buf = match reader.fill_buf().await {
            Ok(buf) => buf,
            Err(_) => break,
        };
        if buf.is_empty() {
            if !line.is_empty() || dropped > 0 {
                flush(&mut line, &mut dropped);
            }
            break;
        }
        let newline = buf.iter().position(|b| *b == b'\n');
        let chunk = &buf[..newline.unwrap_or(buf.len())];
        let room = MAX_FORWARDED_LINE_BYTES - line.len();
        let keep = chunk.len().min(room);
        line.extend_from_slice(&chunk[..keep]);
        dropped = dropped.saturating_add((chunk.len() - keep) as u64);
        let consumed = newline.map_or(buf.len(), |i| i + 1);
        reader.consume(consumed);
        if newline.is_some() {
            flush(&mut line, &mut dropped);
        }
    }
}

/// Minimum spacing between two `RefreshSecrets` mints for one process.
pub const REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// What to do with one `RefreshSecrets` request ([`RefreshPacer::request`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshPace {
    /// Mint and answer now.
    MintNow,
    /// Inside the mint interval: answer at this instant (the interval's end).
    DeferUntil(Instant),
    /// A deferred answer is already scheduled; this request rides on it.
    AlreadyDeferred,
}

/// Paces one process's `RefreshSecrets` mints: at most one per `interval`.
/// A request inside the interval is deferred to its end and coalesced with
/// any other early request; it is never dropped. A dropped request left
/// maintenance[T] waiting for a bootstrap that never came until its
/// credential lapsed and it exited (UK cell-uk-1, 2026-10-21, NAN-4326).
#[derive(Debug)]
pub struct RefreshPacer {
    interval: Duration,
    last_mint: Option<Instant>,
    deferred: bool,
}

impl RefreshPacer {
    pub fn new(interval: Duration) -> Self {
        Self { interval, last_mint: None, deferred: false }
    }

    /// A `RefreshSecrets` arrived at `now`.
    pub fn request(&mut self, now: Instant) -> RefreshPace {
        if self.deferred {
            return RefreshPace::AlreadyDeferred;
        }
        match self.last_mint {
            Some(at) if now < at + self.interval => {
                self.deferred = true;
                RefreshPace::DeferUntil(at + self.interval)
            }
            _ => {
                self.last_mint = Some(now);
                RefreshPace::MintNow
            }
        }
    }

    /// The deferred answer is being minted at `now`.
    pub fn deferred_due(&mut self, now: Instant) {
        self.deferred = false;
        self.last_mint = Some(now);
    }
}

/// Mint a fresh bootstrap for `proc` and send it as `Secrets` + memfd. A
/// failure is logged; the child's own retry schedule asks again.
async fn send_fresh_secret(keys: &Arc<dyn KeySource>, proc: &Proc) {
    let secret = match keys.mint(&proc.tenant, proc.role.credential_role()).await {
        Ok(secret) => secret,
        Err(error) => {
            tracing::warn!(tenant = %proc.tenant, role = proc.role.as_str(), pid = proc.pid, %error, "refresh: mint bootstrap token failed; child will retry");
            return;
        }
    };
    let sent = match fdpass::secret_memfd(&secret) {
        Ok(memfd) => proc.control.send_json(&ToChild::Secrets, &[memfd.as_fd()]).await,
        Err(error) => Err(error),
    };
    if let Err(error) = sent {
        tracing::error!(tenant = %proc.tenant, pid = proc.pid, %error, "refresh: send secrets failed");
    }
}

/// An assignment's owner-signing config must be exactly the release-pinned
/// cell config for `ingest`/`detect`, and absent for `query`: nothing a tenant process
/// or tenant data can influence may change which keys it trusts.
pub fn check_assignment_signing(cfg: &CellConfig, assignment: &Assignment) -> anyhow::Result<()> {
    let expected = match assignment.role {
        Role::Ingest | Role::Detect | Role::Maintenance => cfg.part_signing.as_ref(),
        Role::Query | Role::Product | Role::Landing => None,
    };
    anyhow::ensure!(
        assignment.part_signing.as_ref() == expected,
        "assignment part_signing differs from the cell config"
    );
    Ok(())
}

fn validate_enrichment_mounts(cfg: &CellConfig, placement: &TenantPlacement) -> anyhow::Result<()> {
    use std::path::Component;
    let clean = |path: &Path| path.is_absolute() && path.components().all(|part| matches!(part, Component::RootDir | Component::Normal(_)));
    let regular = |path: &Path| -> anyhow::Result<()> {
        anyhow::ensure!(clean(path), "enrichment mount path must be absolute and normalized");
        anyhow::ensure!(std::fs::symlink_metadata(path)?.file_type().is_file(), "enrichment artifact must be a regular file");
        Ok(())
    };
    let data_root = std::fs::canonicalize(&cfg.data_dir)?;
    let state_root = std::fs::canonicalize(&cfg.state_dir)?;
    let isolated = |path: &Path| -> anyhow::Result<()> {
        anyhow::ensure!(!path.starts_with(&data_root) && !data_root.starts_with(path)
            && !path.starts_with(&state_root) && !state_root.starts_with(path),
            "enrichment authority overlaps child-writable state");
        Ok(())
    };
    if let Some(bundle) = &cfg.platform_bundle_file {
        regular(bundle)?;
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(std::fs::metadata(bundle)?.permissions().mode() & 0o222 == 0,
            "platform bundle inode must be read-only");
        let feed = cfg.feed_dir.as_ref().ok_or_else(|| anyhow::anyhow!("missing feed directory"))?;
        isolated(feed)?;
        anyhow::ensure!(bundle.parent() == Some(feed.as_path()), "bundle outside feed directory");
        anyhow::ensure!(std::fs::canonicalize(feed)? == *feed, "feed directory must not be a symlink");
    }
    if let Some(dir) = &cfg.platform_bundle_dir {
        // Only the directory is checked here; each tenant process opens the
        // bundle its policy names and verifies it (name = content hash,
        // regular read-only inode) through `PlatformBundleSource`.
        anyhow::ensure!(cfg.platform_bundle_file.is_none(), "platform bundle file and dir are mutually exclusive");
        anyhow::ensure!(clean(dir), "enrichment mount path must be absolute and normalized");
        let feed = cfg.feed_dir.as_ref().ok_or_else(|| anyhow::anyhow!("missing feed directory"))?;
        isolated(feed)?;
        anyhow::ensure!(dir.starts_with(feed), "bundle dir outside feed directory");
        anyhow::ensure!(std::fs::symlink_metadata(dir)?.file_type().is_dir(), "platform bundle dir must be a directory");
        anyhow::ensure!(std::fs::canonicalize(dir)? == *dir, "platform bundle dir must not be a symlink");
        anyhow::ensure!(std::fs::canonicalize(feed)? == *feed, "feed directory must not be a symlink");
    }
    if let Some(policy) = &placement.platform_policy_file {
        regular(policy)?;
        let parent = policy.parent().ok_or_else(|| anyhow::anyhow!("policy has no parent"))?;
        isolated(parent)?;
        if let Some(feed) = &cfg.feed_dir {
            anyhow::ensure!(!parent.starts_with(feed) && !feed.starts_with(parent), "tenant policy overlaps shared feed directory");
        }
        anyhow::ensure!(policy.file_name().is_some_and(|name| name == "policy.json")
            && parent.file_name().is_some_and(|name| name == placement.tenant_id.as_str()), "policy tenant path differs");
        anyhow::ensure!(std::fs::canonicalize(parent)? == parent, "policy directory must not be a symlink");
    }
    if let Some(root) = &placement.custom_context_root {
        isolated(root)?;
        if let Some(feed) = &cfg.feed_dir {
            anyhow::ensure!(!root.starts_with(feed) && !feed.starts_with(root), "tenant custom context overlaps shared feed directory");
        }
        anyhow::ensure!(clean(root) && root.file_name().is_some_and(|name| name == placement.tenant_id.as_str()), "custom context tenant path differs");
        anyhow::ensure!(std::fs::canonicalize(root)? == *root, "custom context directory must not be a symlink");
    }
    Ok(())
}

/// How often a spawn re-checks its enrichment inputs while it waits.
const ENRICHMENT_INPUTS_POLL: Duration = Duration::from_millis(250);

/// NAN-4314: the first enrichment input `validate_enrichment_mounts` opens
/// that does not exist yet. A missing input is a precondition still
/// landing (the bundle sidecar writes a new tenant's `policy.json` on its
/// next cycle after the grants Secret syncs); anything else about an input
/// that exists is left to the validation, which fails at once.
fn missing_enrichment_input(cfg: &CellConfig, placement: &TenantPlacement) -> Option<PathBuf> {
    let feed = cfg.feed_dir.as_ref().filter(|_| cfg.platform_bundle_file.is_some() || cfg.platform_bundle_dir.is_some());
    feed.into_iter()
        .chain(cfg.platform_bundle_file.iter())
        .chain(cfg.platform_bundle_dir.iter())
        .chain(placement.platform_policy_file.iter())
        .chain(placement.custom_context_root.iter())
        .find(|path| matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound))
        .cloned()
}

#[derive(Debug, PartialEq, Eq)]
enum InputsWait {
    /// Every input exists; waited this long.
    Ready(Duration),
    /// Still missing at the bound: this path.
    Missing(PathBuf),
    /// The cell began shutting down.
    Stopping,
}

/// Poll until every enrichment input of `placement` exists, at most `bound`.
async fn wait_for_enrichment_inputs(
    cfg: &CellConfig,
    placement: &TenantPlacement,
    bound: Duration,
    poll: Duration,
    stopping: &AtomicBool,
) -> InputsWait {
    let t0 = Instant::now();
    loop {
        let Some(missing) = missing_enrichment_input(cfg, placement) else { return InputsWait::Ready(t0.elapsed()) };
        if stopping.load(Ordering::SeqCst) {
            return InputsWait::Stopping;
        }
        let left = bound.saturating_sub(t0.elapsed());
        if left.is_zero() {
            return InputsWait::Missing(missing);
        }
        tokio::time::sleep(poll.min(left)).await;
    }
}

/// NAN-4314: mint `role`'s bootstrap token. Each request is bounded by
/// `step`. While the control plane answers that the tenant's first lean
/// assignment is still being committed (`503 lean_assignment_pending`),
/// wait its `Retry-After` (1–5 s) and ask again, for at most `pending_bound`
/// in all; past that (or on any other refusal) the refusal is returned for
/// the caller's backoff, as before.
async fn mint_awaiting_assignment(
    keys: &dyn KeySource,
    t: &TenantId,
    role: Role,
    step: Duration,
    pending_bound: Duration,
    stopping: &AtomicBool,
) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    let t0 = Instant::now();
    let mut waiting = false;
    loop {
        let minted = match tokio::time::timeout(step, keys.mint(t, role.credential_role())).await {
            Ok(r) => r,
            Err(_) => anyhow::bail!("no answer after {}s", step.as_secs()),
        };
        let pending = match &minted {
            Err(e) => e.downcast_ref::<crate::secrets::MintRefused>().filter(|r| r.is_assignment_pending()),
            Ok(_) => None,
        };
        let Some(r) = pending else {
            if waiting && minted.is_ok() {
                tracing::info!(tenant = %t, role = role.as_str(), waited_ms = t0.elapsed().as_millis() as u64,
                    "first lean assignment committed; bootstrap token minted");
            }
            return minted;
        };
        let pause = r.retry_after.unwrap_or(Duration::from_secs(2)).clamp(Duration::from_secs(1), Duration::from_secs(5));
        if stopping.load(Ordering::SeqCst) || t0.elapsed() + pause > pending_bound {
            return minted;
        }
        if !waiting {
            waiting = true;
            tracing::info!(tenant = %t, role = role.as_str(), reason = %r.code, wait_secs = pending_bound.as_secs(),
                "waiting for the control plane's first lean assignment before starting the role");
        }
        tokio::time::sleep(pause).await;
    }
}

#[cfg(test)]
mod unenforced_clock_tests {
    use super::*;

    #[test]
    fn warns_at_once_then_every_five_minutes_and_resets_when_enforced() {
        let t0 = Instant::now();
        let mut c = UnenforcedClock::default();
        assert!(c.observe(t0, true), "first sight warns");
        assert!(!c.observe(t0 + Duration::from_secs(1), true));
        assert!(!c.observe(t0 + Duration::from_secs(299), true));
        assert!(c.observe(t0 + Duration::from_secs(300), true), "repeats, never once-only");
        assert_eq!(c.secs(t0 + Duration::from_secs(400)), 400);
        assert!(!c.observe(t0 + Duration::from_secs(401), false));
        assert_eq!(c.secs(t0 + Duration::from_secs(500)), 0, "kernel-enforced resets the clock");
        assert!(c.observe(t0 + Duration::from_secs(502), true), "a new gap (withdrawn) warns again at once");
    }
}

#[cfg(test)]
mod alert_window_tests {
    use super::*;

    #[test]
    fn requires_full_window_and_uses_counter_deltas() {
        let tenant = TenantId::new("t1").unwrap();
        let now = Instant::now();
        let mut windows = AlertWindows::default();
        windows.observe(now - Duration::from_secs(600), 0.9, [(tenant.clone(), 0, 0)]);
        assert_eq!(windows.cell_cpu_10m(), 0.0);
        assert_eq!(windows.query_throttled_5m(&tenant), 0.0);
        windows.observe(now - Duration::from_secs(300), 0.9, [(tenant.clone(), 100, 100)]);
        windows.observe(now, 0.9, [(tenant.clone(), 850, 350)]);
        assert!((windows.cell_cpu_10m() - 0.9).abs() < 0.001);
        assert!((windows.query_throttled_5m(&tenant) - 0.25).abs() < 0.001);
    }

    /// The `query_throttled_5m` signal through the window and the hysteresis,
    /// read every 15 s: (raw breaching reads, fires, resolves).
    fn replay_query_throttle(samples: &[(u64, u64, u64)], end_s: u64) -> (usize, usize, usize) {
        let tenant = TenantId::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap();
        let t0 = Instant::now();
        let mut windows = AlertWindows::default();
        let mut debounce = crate::signals::SignalDebouncer::default();
        let (mut raw_breaches, mut fires, mut resolves, mut firing) = (0, 0, 0, false);
        // The supervisor observes cpu.stat every monitor tick (seconds); the
        // fixture is the once-a-minute log line, interpolated per 15 s read.
        let counters = |at: u64| -> (u64, u64) {
            let i = samples.partition_point(|s| s.0 <= at);
            if i == 0 { return (samples[0].1, samples[0].2); }
            if i == samples.len() { let l = samples[i - 1]; return (l.1, l.2); }
            let (a, b) = (samples[i - 1], samples[i]);
            let f = (at - a.0) as f64 / (b.0 - a.0) as f64;
            let lerp = |x: u64, y: u64| x + ((y - x) as f64 * f) as u64;
            (lerp(a.1, b.1), lerp(a.2, b.2))
        };
        for at in (0..=end_s).step_by(15) {
            let (usage, throttled) = counters(at);
            windows.observe(t0 + Duration::from_secs(at), 0.5, [(tenant.clone(), usage, throttled)]);
            let now = t0 + Duration::from_secs(at);
            let raw = Signal::evaluate(Some(tenant.clone()), "cell", "query", "query_throttled_5m", "ratio",
                windows.query_throttled_5m(&tenant), 0.25, f64::INFINITY, None);
            raw_breaches += (raw.severity != crate::signals::Severity::Ok) as usize;
            let alert = debounce.apply(now, raw);
            assert_ne!(alert.severity, crate::signals::Severity::Page, "a capacity signal never pages");
            let now_firing = alert.severity != crate::signals::Severity::Ok;
            fires += (!firing && now_firing) as usize;
            resolves += (firing && !now_firing) as usize;
            firing = now_firing;
        }
        (raw_breaches, fires, resolves)
    }

    /// NAN-3773 replay: tenant-a's query[T] cpu.stat on 2026-10-13. Two single
    /// minutes of throttling (15:24Z, 151 s; 15:40Z, 94 s: operator 7d
    /// searches fanned out to ~30 segment queries) each held the 5-minute
    /// ratio at 0.29-0.31 for 5 minutes, which posted WARN, then RESOLVED.
    /// Through the hysteresis nothing fires.
    #[test]
    fn b12_query_throttle_replay_2026_10_13_does_not_flap() {
        let samples: Vec<(u64, u64, u64)> = include_str!("../tests/fixtures/nan3773-query-cpu-2026-10-13.txt")
            .lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let v: Vec<u64> = l.split_whitespace().map(|x| x.parse().unwrap()).collect();
                (v[0], v[1], v[2])
            }).collect();
        let end = samples.last().unwrap().0;
        let (raw_breaches, fires, resolves) = replay_query_throttle(&samples, end);
        assert!(raw_breaches >= 30, "the fixture reproduces the raw breaches ({raw_breaches} reads)");
        assert_eq!((fires, resolves), (0, 0), "no WARN/RESOLVE ping-pong");
    }

    /// Throttling that persists past the window still alerts: 30% of every
    /// minute for 20 min fires once (after 10 min held) and resolves once,
    /// 10 min after it stops.
    #[test]
    fn sustained_query_throttle_fires_once_and_resolves_once() {
        let (mut usage, mut throttled) = (0u64, 0u64);
        let samples: Vec<(u64, u64, u64)> = (0..=60).map(|m| {
            if (1..=20).contains(&m) {
                usage += 42_000_000;
                throttled += 18_000_000;
            } else {
                usage += 10_000_000;
            }
            (m * 60, usage, throttled)
        }).collect();
        let (raw_breaches, fires, resolves) = replay_query_throttle(&samples, 60 * 60);
        assert!(raw_breaches >= 15 * 4, "{raw_breaches}");
        assert_eq!((fires, resolves), (1, 1));
    }
}

#[cfg(test)]
mod signing_tests {
    use super::*;
    use crate::contract::{JailSpec, PartSigning, TrustedSignerKey};

    fn cfg(signing: Option<PartSigning>) -> CellConfig {
        let mut cfg: CellConfig = serde_json::from_value(serde_json::json!({
            "cell_id": "cell-a", "data_dir": "/d", "state_dir": "/s", "ingest_binary": "/b", "query_binary": "/b",
            "listen_unix": "/r.sock", "router_token_file": "/t", "placement_file": "/p", "dev_key_dir": "/k"
        }))
        .unwrap();
        cfg.part_signing = signing;
        cfg
    }

    fn signing(key: &str) -> PartSigning {
        PartSigning {
            url: "https://owner.example/internal/v1/enterprise-shared/lake-parts:sign".into(),
            signer_key_id: "release-key-0001".into(),
            trusted_keys: vec![TrustedSignerKey { key_id: "release-key-0001".into(), public_key_hex: key.repeat(64) }],
            ca_file: None,
        }
    }

    fn assignment(role: Role, part_signing: Option<PartSigning>) -> Assignment {
        let p = PathBuf::from("/x");
        Assignment {
            outbound_proxy: None,
            tenant: TenantId::new("t1").unwrap(),
            role,
            cell_id: "cell-a".into(),
            tenant_dir: p.clone(),
            parts_dir: p.clone(),
            state_dir: p.clone(),
            tmp_dir: p.clone(),
            feed_dir: None,
            platform_bundle_file: None,
            platform_bundle_dir: None,
            platform_policy_file: None,
            custom_context_root: None,
            memory_cap_bytes: 0,
            cpu_millis: 0,
            eps: 0.0,
            jail: JailSpec {
                uid: 1, gid: 1, rw_paths: vec![], ro_paths: vec![], system_ro_paths: vec![], tcp_connect_ports: vec![],
                cgroup_dir: None, require_landlock: false, max_processes: None, max_open_files: 64,
            },
            control_url: None,
            prevalence_rarity_threshold: None,
            part_signing,
            owner_requires_checksum: false,
            ingest_idle_exit: None,
            ingest_day_merges: false,
            ingest_keyword_index: false,
            identity_observations: false,
            identity_directory_enrich: false,
            ingest_flush: None,
            ingest_merge_policy: None,
            ingest_hold_eps: None,
            query_prewarm_before_ready: false,
            detect_runs_rules: false,
            product_state_role: false,
            product_dir: None,
            trusted_local: false,
            writer_lease: None,
            part_gc_state_dir: None,
        }
    }

    #[test]
    fn assignment_trusted_keys_must_equal_the_cell_config() {
        let cfg = cfg(Some(signing("a")));
        cfg.validate().unwrap();
        check_assignment_signing(&cfg, &assignment(Role::Ingest, Some(signing("a")))).unwrap();
        // Different trusted keys (e.g. influenced by anything but the pinned config): refused.
        assert!(check_assignment_signing(&cfg, &assignment(Role::Ingest, Some(signing("b")))).is_err());
        assert!(check_assignment_signing(&cfg, &assignment(Role::Ingest, None)).is_err());
        check_assignment_signing(&cfg, &assignment(Role::Detect, Some(signing("a")))).unwrap();
        assert!(check_assignment_signing(&cfg, &assignment(Role::Detect, None)).is_err());
        assert!(check_assignment_signing(&cfg, &assignment(Role::Detect, Some(signing("b")))).is_err());
        // Query never receives signing config.
        check_assignment_signing(&cfg, &assignment(Role::Query, None)).unwrap();
        assert!(check_assignment_signing(&cfg, &assignment(Role::Query, Some(signing("a")))).is_err());
        // The config itself must name its signer among its trusted keys, over https.
        let mut bad = signing("a");
        bad.signer_key_id = "other-key-0002".into();
        assert!(self::cfg(Some(bad)).validate().is_err());
        let mut plain = signing("a");
        plain.url = "http://owner".into();
        assert!(self::cfg(Some(plain)).validate().is_err());
    }

    #[test]
    fn part_signing_ca_file_must_be_a_dedicated_read_only_directory() {
        let with_ca = |path: &str| {
            let mut s = signing("a");
            s.ca_file = Some(PathBuf::from(path));
            cfg(Some(s))
        };
        let ok = with_ca("/etc/nano/owner-ca/ca.crt");
        ok.validate().unwrap();
        assert_eq!(ok.part_signing_ca_dir(), Some(Path::new("/etc/nano/owner-ca")));
        // An ingest assignment carries it verbatim; a different CA is refused.
        check_assignment_signing(&ok, &assignment(Role::Ingest, ok.part_signing.clone())).unwrap();
        assert!(check_assignment_signing(&ok, &assignment(Role::Ingest, Some(signing("a")))).is_err());
        for bad in ["relative/ca.crt", "/etc/../ca.crt", "/ca.crt", "/d/tenants/ca.crt", "/s/ca.crt"] {
            assert!(with_ca(bad).validate().is_err(), "{bad} must be refused");
        }
        // The keyless shape still parses (older the platform renders).
        let parsed: PartSigning = serde_json::from_value(serde_json::json!({
            "url": "https://o", "signer_key_id": "k", "trusted_keys": []
        })).unwrap();
        assert_eq!(parsed.ca_file, None);
        assert!(!serde_json::to_string(&parsed).unwrap().contains("ca_file"));
    }
}

#[cfg(test)]
mod enrichment_mount_tests {
    use super::*;
    #[test]
    fn exact_tenant_mounts_refuse_missing_sibling_and_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let sibling = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f01";
        let feed = tmp.path().join("feeds");
        std::fs::create_dir(&feed).unwrap();
        let data = tmp.path().join("cell-data");
        let state = tmp.path().join("cell-state");
        std::fs::create_dir(&data).unwrap();
        std::fs::create_dir(&state).unwrap();
        let bundle = feed.join("platform.bundle");
        std::fs::write(&bundle, b"artifact").unwrap();
        let mut permissions = std::fs::metadata(&bundle).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o444);
        std::fs::set_permissions(&bundle, permissions).unwrap();
        let parent = tmp.path().join(tenant);
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("policy.json"), b"{}").unwrap();
        let cfg: CellConfig = serde_json::from_value(serde_json::json!({
            "cell_id":"cell-a", "data_dir":data, "state_dir":state, "ingest_binary":"/b", "query_binary":"/b",
            "listen_unix":"/r.sock", "router_token_file":"/t", "placement_file":"/p", "dev_key_dir":"/k",
            "feed_dir":feed, "platform_bundle_file":bundle
        })).unwrap();
        let mut p = TenantPlacement::legacy(TenantId::new(tenant).unwrap(), 20.0);
        p.platform_policy_file = Some(parent.join("policy.json"));
        assert!(validate_enrichment_mounts(&cfg, &p).is_ok());
        let mut writable = std::fs::metadata(&bundle).unwrap().permissions();
        writable.set_mode(0o644);
        std::fs::set_permissions(&bundle, writable).unwrap();
        assert!(validate_enrichment_mounts(&cfg, &p).is_err());
        let mut readonly = std::fs::metadata(&bundle).unwrap().permissions();
        readonly.set_mode(0o444);
        std::fs::set_permissions(&bundle, readonly).unwrap();
        let mut overlapping = cfg.clone();
        overlapping.data_dir = tmp.path().to_path_buf();
        let writable_parent = tmp.path().join("tenants").join(tenant).join("ingest").join(tenant);
        std::fs::create_dir_all(&writable_parent).unwrap();
        std::fs::write(writable_parent.join("policy.json"), b"{}").unwrap();
        p.platform_policy_file = Some(writable_parent.join("policy.json"));
        assert!(validate_enrichment_mounts(&overlapping, &p).is_err());
        p.platform_policy_file = Some(parent.join("policy.json"));
        let alias = tmp.path().join("alias-data");
        std::os::unix::fs::symlink(tmp.path(), &alias).unwrap();
        overlapping.data_dir = alias;
        assert!(validate_enrichment_mounts(&overlapping, &p).is_err());
        std::fs::remove_file(parent.join("policy.json")).unwrap();
        assert!(validate_enrichment_mounts(&cfg, &p).is_err());
        std::fs::write(parent.join("policy.json"), b"{}").unwrap();
        p.platform_policy_file = Some(tmp.path().join(sibling).join("policy.json"));
        assert!(validate_enrichment_mounts(&cfg, &p).is_err());
        p.platform_policy_file = Some(parent.join("policy.json"));
        std::fs::remove_file(&bundle).unwrap();
        std::os::unix::fs::symlink(parent.join("policy.json"), &bundle).unwrap();
        assert!(validate_enrichment_mounts(&cfg, &p).is_err());
    }

    #[test]
    fn bundle_dir_mount_must_be_a_real_directory_inside_feed_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let feed = tmp.path().join("feeds");
        let bundles = feed.join("platform");
        std::fs::create_dir_all(&bundles).unwrap();
        for d in ["cell-data", "cell-state"] { std::fs::create_dir(tmp.path().join(d)).unwrap(); }
        let parent = tmp.path().join(tenant);
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("policy.json"), b"{}").unwrap();
        let cfg = |dir: &Path| -> CellConfig { serde_json::from_value(serde_json::json!({
            "cell_id":"cell-a", "data_dir":tmp.path().join("cell-data"), "state_dir":tmp.path().join("cell-state"),
            "ingest_binary":"/b", "query_binary":"/b",
            "listen_unix":"/r.sock", "router_token_file":"/t", "placement_file":"/p", "dev_key_dir":"/k",
            "feed_dir":feed, "platform_bundle_dir":dir
        })).unwrap() };
        let mut p = TenantPlacement::legacy(TenantId::new(tenant).unwrap(), 20.0);
        p.platform_policy_file = Some(parent.join("policy.json"));
        // The feed dir itself and a real subdirectory are accepted.
        assert!(validate_enrichment_mounts(&cfg(&feed), &p).is_ok());
        assert!(validate_enrichment_mounts(&cfg(&bundles), &p).is_ok());
        // Outside feed_dir, missing, or a symlinked directory: refused.
        assert!(validate_enrichment_mounts(&cfg(&parent), &p).is_err());
        assert!(validate_enrichment_mounts(&cfg(&feed.join("missing")), &p).is_err());
        let alias = feed.join("alias");
        std::os::unix::fs::symlink(&parent, &alias).unwrap();
        assert!(validate_enrichment_mounts(&cfg(&alias), &p).is_err());
        // File and dir together: refused.
        let mut both = cfg(&feed);
        both.platform_bundle_file = Some(feed.join("platform.bundle"));
        assert!(validate_enrichment_mounts(&both, &p).is_err());
        assert!(both.validate().is_err());
    }
}

#[cfg(test)]
mod birth_precondition_tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";

    /// A cell config with a bundle dir, and a placement whose policy file
    /// the bundle sidecar has not written yet (the birth state, NAN-4314).
    fn birth(tmp: &Path) -> (CellConfig, TenantPlacement, PathBuf) {
        let feed = tmp.join("feeds");
        std::fs::create_dir_all(feed.join("bundles")).unwrap();
        for d in ["cell-data", "cell-state", "policy"] { std::fs::create_dir(tmp.join(d)).unwrap(); }
        let cfg: CellConfig = serde_json::from_value(serde_json::json!({
            "cell_id":"cell-a", "data_dir":tmp.join("cell-data"), "state_dir":tmp.join("cell-state"),
            "ingest_binary":"/b", "query_binary":"/b",
            "listen_unix":"/r.sock", "router_token_file":"/t", "placement_file":"/p", "dev_key_dir":"/k",
            "feed_dir":feed, "platform_bundle_dir":feed.join("bundles")
        })).unwrap();
        let policy = tmp.join("policy").join(TENANT).join("policy.json");
        let mut p = TenantPlacement::legacy(TenantId::new(TENANT).unwrap(), 20.0);
        p.platform_policy_file = Some(policy.clone());
        (cfg, p, policy)
    }

    fn land(policy: &Path) {
        std::fs::create_dir_all(policy.parent().unwrap()).unwrap();
        std::fs::write(policy, b"{}").unwrap();
    }

    /// The AU/UK/EAST birth: the placement names a policy that lands a few
    /// cycles later. The spawn waits for it and then validates cleanly,
    /// instead of failing "enrichment mounts: ENOENT" every second.
    #[tokio::test]
    async fn a_spawn_waits_for_a_policy_that_lands_after_the_placement() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, p, policy) = birth(tmp.path());
        assert_eq!(missing_enrichment_input(&cfg, &p), Some(policy.clone()));
        assert!(validate_enrichment_mounts(&cfg, &p).is_err(), "the old spawn failed here");
        let lander = {
            let policy = policy.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                land(&policy);
            })
        };
        let stop = AtomicBool::new(false);
        let r = wait_for_enrichment_inputs(&cfg, &p, Duration::from_secs(10), Duration::from_millis(20), &stop).await;
        lander.await.unwrap();
        assert!(matches!(r, InputsWait::Ready(w) if w >= Duration::from_millis(250) && w < Duration::from_secs(5)), "{r:?}");
        validate_enrichment_mounts(&cfg, &p).expect("the landed inputs validate");
        // Present from the start: no wait at all.
        let r = wait_for_enrichment_inputs(&cfg, &p, Duration::from_secs(10), Duration::from_millis(20), &stop).await;
        assert!(matches!(r, InputsWait::Ready(w) if w < Duration::from_millis(20)), "{r:?}");
    }

    /// A policy that never lands is a real failure: the wait ends at its
    /// bound and names the missing path. Shutdown ends it at once.
    #[tokio::test]
    async fn a_policy_that_never_lands_fails_at_the_bound_and_shutdown_ends_the_wait() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, p, policy) = birth(tmp.path());
        let stop = AtomicBool::new(false);
        let t0 = Instant::now();
        let r = wait_for_enrichment_inputs(&cfg, &p, Duration::from_millis(200), Duration::from_millis(20), &stop).await;
        assert_eq!(r, InputsWait::Missing(policy));
        assert!(t0.elapsed() >= Duration::from_millis(200) && t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
        stop.store(true, Ordering::SeqCst);
        let t0 = Instant::now();
        let r = wait_for_enrichment_inputs(&cfg, &p, Duration::from_secs(30), Duration::from_millis(20), &stop).await;
        assert_eq!(r, InputsWait::Stopping);
        assert!(t0.elapsed() < Duration::from_secs(1));
    }

    /// Only absence is waited for: an input that exists but is wrong (a
    /// symlinked policy directory) is not "missing", so the validation
    /// refuses it at once, as before.
    #[test]
    fn an_existing_but_invalid_input_is_not_waited_for() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, p, policy) = birth(tmp.path());
        let real = tmp.path().join("elsewhere");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("policy.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(&real, policy.parent().unwrap()).unwrap();
        assert_eq!(missing_enrichment_input(&cfg, &p), None);
        assert!(validate_enrichment_mounts(&cfg, &p).is_err());
        // The bundle dir is an input too.
        let mut no_bundles = cfg.clone();
        no_bundles.platform_bundle_dir = Some(cfg.feed_dir.clone().unwrap().join("missing"));
        assert_eq!(missing_enrichment_input(&no_bundles, &p), no_bundles.platform_bundle_dir);
    }

    /// The control plane's key source as the cell sees it at a birth:
    /// `pending` mints answer `503 lean_assignment_pending` (Retry-After 1),
    /// then it mints.
    struct FirstAssignment { pending: u32, calls: AtomicU32, code: &'static str }

    #[async_trait::async_trait]
    impl KeySource for FirstAssignment {
        async fn mint(&self, tenant: &TenantId, role: Role) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n < self.pending {
                let body = format!(r#"{{"error":"{}"}}"#, self.code);
                return Err(crate::secrets::MintRefused::from_response(tenant, role, 503, body.as_bytes(), Some(Duration::from_secs(1))).into());
            }
            Ok(zeroize::Zeroizing::new(b"bootstrap".to_vec()))
        }
    }

    #[tokio::test]
    async fn the_mint_waits_for_the_first_lean_assignment_instead_of_failing() {
        let t = TenantId::new(TENANT).unwrap();
        let stop = AtomicBool::new(false);
        let keys = FirstAssignment { pending: 1, calls: 0.into(), code: "lean_assignment_pending" };
        let t0 = Instant::now();
        let secret = mint_awaiting_assignment(&keys, &t, Role::Ingest, Duration::from_secs(5), Duration::from_secs(30), &stop)
            .await
            .expect("minted once the assignment committed");
        assert_eq!(secret.as_slice(), b"bootstrap");
        assert_eq!(keys.calls.load(Ordering::SeqCst), 2);
        assert!(t0.elapsed() >= Duration::from_secs(1), "honours Retry-After");
    }

    /// Past the bound the pending refusal is returned (the spawn backs off
    /// and reports it); any other refusal is never waited on.
    #[tokio::test]
    async fn the_mint_wait_is_bounded_and_other_refusals_return_at_once() {
        let t = TenantId::new(TENANT).unwrap();
        let stop = AtomicBool::new(false);
        let keys = FirstAssignment { pending: u32::MAX, calls: 0.into(), code: "lean_assignment_pending" };
        let t0 = Instant::now();
        let e = mint_awaiting_assignment(&keys, &t, Role::Ingest, Duration::from_secs(5), Duration::from_millis(1500), &stop)
            .await
            .unwrap_err();
        let r = e.downcast_ref::<crate::secrets::MintRefused>().expect("the refusal itself");
        assert!(r.is_assignment_pending());
        assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
        assert_eq!(keys.calls.load(Ordering::SeqCst), 2, "1 s Retry-After inside a 1.5 s bound: one retry");

        let keys = FirstAssignment { pending: u32::MAX, calls: 0.into(), code: "credential_mint_unavailable" };
        let e = mint_awaiting_assignment(&keys, &t, Role::Ingest, Duration::from_secs(5), Duration::from_secs(30), &stop)
            .await
            .unwrap_err();
        assert!(e.downcast_ref::<crate::secrets::MintRefused>().is_some_and(|r| r.code == "credential_mint_unavailable"));
        assert_eq!(keys.calls.load(Ordering::SeqCst), 1);

        // Shutting down: no more waiting.
        stop.store(true, Ordering::SeqCst);
        let keys = FirstAssignment { pending: u32::MAX, calls: 0.into(), code: "lean_assignment_pending" };
        assert!(mint_awaiting_assignment(&keys, &t, Role::Ingest, Duration::from_secs(5), Duration::from_secs(30), &stop).await.is_err());
        assert_eq!(keys.calls.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod crash_backoff_tests {
    use super::*;

    /// NAN-2989/NAN-3008: a placed tenant's query kept resident is never
    /// idle-reaped; an unplaced tenant's always is; the usual rules (in
    /// flight, idle window) hold otherwise.
    #[test]
    fn query_residency_follows_tenant_ingest_activity() {
        let hour = Duration::from_secs(3_600);
        let idle_for = Duration::from_secs(7_200);
        let placed = TenantPlacement::legacy(TenantId::new("t").unwrap(), 20.0);
        let placed = Some(&placed);
        // Idle past the window, kept resident: kept.
        assert!(!idle_reap_due(Role::Query, placed, 0, idle_for, hour, true));
        // Not placed: reaped even when "kept".
        assert!(idle_reap_due(Role::Query, None, 0, idle_for, hour, true));
        // Not kept: reaped after the query window.
        assert!(idle_reap_due(Role::Query, placed, 0, idle_for, hour, false));
        assert!(!idle_reap_due(Role::Query, placed, 0, Duration::from_secs(1_800), hour, false));
        // In flight: never.
        assert!(!idle_reap_due(Role::Query, placed, 1, idle_for, hour, false));
        // The residency rule is query-only (detect still idles out).
        assert!(idle_reap_due(Role::Detect, placed, 0, idle_for, hour, true));
    }

    #[test]
    fn detect_respawns_when_its_rule_mode_or_engine_budget_changes() {
        use crate::budget::{GIB, MIB};
        let t = TenantId::new("t").unwrap();
        let with = |bytes: u64| TenantPlacement {
            detect_request_millicores: Some(250), detect_limit_millicores: Some(1_000),
            detect_request_memory_bytes: Some(512 * MIB), detect_limit_memory_bytes: Some(bytes),
            ..TenantPlacement::legacy(t.clone(), 300.0)
        };
        let big = with(3 * GIB / 2);
        // Running as assigned: no restart.
        assert!(!detect_needs_respawn(true, 3 * GIB / 2, &big, true));
        assert!(!detect_needs_respawn(false, 256 * MIB, &TenantPlacement::legacy(t.clone(), 300.0), true));
        // Flag turned on / off under a running detect: restart into the new mode.
        assert!(detect_needs_respawn(false, 3 * GIB / 2, &big, true));
        assert!(detect_needs_respawn(true, 3 * GIB / 2, &big, false));
        // Budget resized: the engine was sized from the old memory.max.
        assert!(detect_needs_respawn(true, 3 * GIB / 2, &with(2 * GIB), true));
        // Shrunk below the engine floor: back to the drain-only process.
        assert!(detect_needs_respawn(true, 3 * GIB / 2, &with(256 * MIB), true));
        // A drain-only detect ignores memory changes.
        assert!(!detect_needs_respawn(false, 256 * MIB, &with(512 * MIB), true));
    }

    #[test]
    fn query_respawns_only_when_its_thread_count_changes() {
        // 3 -> 8 threads: restart at the new size.
        assert!(query_needs_respawn(3_000, 8_000));
        assert!(query_needs_respawn(8_000, 3_000));
        // Both clamp to 8 threads: keep running.
        assert!(!query_needs_respawn(8_000, 9_000));
        // Unchanged, or a change within the same whole core.
        assert!(!query_needs_respawn(3_000, 3_000));
        assert!(!query_needs_respawn(3_000, 3_500));
        // Below one core both clamp to 1.
        assert!(!query_needs_respawn(250, 900));
    }

    fn refusal(status: u16, code: &str, retry_after: Option<u64>) -> crate::secrets::MintRefused {
        crate::secrets::MintRefused::from_response(&TenantId::new("t").unwrap(), Role::Detect, status,
            format!(r#"{{"error":"{code}"}}"#).as_bytes(), retry_after.map(Duration::from_secs))
    }

    /// A refused detect mint (the lean `detect_drain_disabled` 403) backs
    /// off exponentially to a cap instead of re-minting every request, and
    /// reports the refusal code until a spawn succeeds.
    #[test]
    fn refused_mint_blocks_the_role_with_backoff_and_its_code() {
        let start = Instant::now();
        let mut st = TenantStats::default();
        let d = role_idx(Role::Detect);
        assert!(spawn_blocked_error(&st, Role::Detect, start).is_none());
        let r = refusal(403, "detect_drain_disabled", None);
        let mut waits = vec![];
        let mut at = start;
        for _ in 0..9 {
            let (b, _) = SpawnBlock::refused(st.spawn_blocked[d].as_ref(), &r, at);
            waits.push(b.not_before.duration_since(at).as_secs());
            at = b.not_before;
            st.spawn_blocked[d] = Some(b);
        }
        assert_eq!(waits, [2, 4, 8, 16, 32, 64, 120, 120, 120]);
        let b = st.spawn_blocked[d].as_ref().unwrap();
        assert_eq!((b.attempts, b.since), (9, start), "the block keeps its start while the code is unchanged");

        // While the backoff is pending: an immediate, typed refusal.
        let before = b.not_before - Duration::from_secs(5);
        match spawn_blocked_error(&st, Role::Detect, before) {
            Some(CellError::SpawnBlocked { role, status, code, retry_after_secs }) => {
                assert_eq!((role, status, code.as_str(), retry_after_secs), (Role::Detect, 403, "detect_drain_disabled", 5));
            }
            other => panic!("{other:?}"),
        }
        // Other roles are not affected; after the backoff one retry is let through.
        assert!(spawn_blocked_error(&st, Role::Query, before).is_none());
        assert!(spawn_blocked_error(&st, Role::Detect, b.not_before).is_none());

        let view = b.view(Role::Detect, before);
        assert_eq!((view.reason.as_str(), view.http_status, view.retry_in_secs), ("detect_drain_disabled", 403, 5));
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["role"], "detect");
        assert_eq!(json["reason"], "detect_drain_disabled");
    }

    #[test]
    fn a_new_refusal_code_restarts_the_block_and_retry_after_is_honoured() {
        let now = Instant::now();
        let (first, changed) = SpawnBlock::refused(None, &refusal(403, "detect_drain_disabled", None), now);
        assert!(changed);
        let later = now + Duration::from_secs(30);
        // The fact flipped; now the assignment is missing (transient 503, Retry-After 45 s).
        let (next, changed) = SpawnBlock::refused(Some(&first), &refusal(503, "detect_assignment_unavailable", Some(45)), later);
        assert!(changed);
        assert_eq!(next.since, later);
        assert_eq!(next.code, "detect_assignment_unavailable");
        assert_eq!(next.not_before.duration_since(later), Duration::from_secs(45));
        // A transient refusal caps lower than a policy one.
        let mut b = next;
        for _ in 0..10 {
            b = SpawnBlock::refused(Some(&b), &refusal(503, "detect_assignment_unavailable", None), later).0;
        }
        assert_eq!(b.not_before.duration_since(later), SPAWN_BLOCKED_TRANSIENT_MAX);
        // An absurd Retry-After is bounded.
        let (b, _) = SpawnBlock::refused(None, &refusal(503, "tenant_fenced", Some(86_400)), now);
        assert_eq!(b.not_before.duration_since(now), SPAWN_BLOCKED_RETRY_AFTER_MAX);
    }

    #[test]
    fn backoff_grows_and_caps() {
        let mut stats = TenantStats::default();
        let base = Duration::from_secs(5);
        let max = Duration::from_secs(300);
        let start = Instant::now();
        for (n, expected) in [(1, 5), (2, 10), (3, 20), (8, 300), (100, 300)] {
            for step in stats.kill_streak[0]..n {
                stats.backoff(0, start + Duration::from_secs(step as u64), base, max);
            }
            assert_eq!(stats.restart_not_before[0].unwrap().duration_since(stats.last_kill[0].unwrap()), Duration::from_secs(expected));
        }
    }
}

// Startup has a longer no-progress budget, but timer heartbeats alone
// cannot extend it. Existing running-service heartbeats retain their policy.
fn startup_heartbeat(hb: &Heartbeat) -> bool {
    hb.startup_progress.is_some()
}

fn heartbeat_stall_budget(hb: &Heartbeat, stall: Duration) -> Duration {
    if startup_heartbeat(hb) { stall.saturating_mul(2) } else { stall }
}

fn heartbeat_progress_at(previous: &(Instant, Heartbeat), next: &Heartbeat, now: Instant) -> Instant {
    if startup_heartbeat(next) && next.startup_progress <= previous.1.startup_progress {
        previous.0
    } else {
        now
    }
}

#[cfg(test)]
mod startup_heartbeat_tests {
    use super::*;

    #[test]
    fn progressing_backlog_outlives_startup_budget() {
        let start = Instant::now();
        let mut previous = (start, Heartbeat::default());
        for revision in 1..=1000 {
            let now = start + Duration::from_secs(revision * 10);
            let hb = Heartbeat { detail: Some("starting: part-log catch-up".into()),
                startup_progress: Some(revision), ..Heartbeat::default() };
            let at = heartbeat_progress_at(&previous, &hb, now);
            assert!(now.duration_since(at) < heartbeat_stall_budget(&hb, Duration::from_secs(300)));
            previous = (at, hb);
        }
    }

    #[test]
    fn serving_uses_normal_heartbeat_budget() {
        let start = Instant::now();
        let old = Heartbeat { startup_progress: Some(10), ..Heartbeat::default() };
        let running = Heartbeat::default();
        let now = start + Duration::from_secs(700);
        assert_eq!(heartbeat_progress_at(&(start, old), &running, now), now);
        assert_eq!(heartbeat_stall_budget(&running, Duration::from_secs(300)), Duration::from_secs(300));
    }

    #[test]
    fn timer_cannot_keep_stuck_startup_alive() {
        let start = Instant::now();
        let hb = Heartbeat { detail: Some("starting: dedup hydration".into()),
            startup_progress: Some(1), ..Heartbeat::default() };
        let mut previous = (start, hb.clone());
        for seconds in 1..=601 {
            let now = start + Duration::from_secs(seconds);
            previous = (heartbeat_progress_at(&previous, &hb, now), hb.clone());
        }
        assert!(startup_heartbeat(&previous.1));
        assert!((start + Duration::from_secs(601)).duration_since(previous.0)
            > heartbeat_stall_budget(&previous.1, Duration::from_secs(300)));
    }
}

#[cfg(test)]
mod product_role_tests {
    use super::*;

    /// NAN-4183: on a persistent hot volume ingest[T]'s GC view lives in
    /// ingest[T]'s own hot-tree directory (a roll resumes it); without one it
    /// stays in the state dir. No other role's data mounts reach it.
    #[test]
    fn part_gc_state_dir_is_ingest_own_hot_tree_dir_only_when_persistent() {
        let hot = Path::new("/hot/tenants");
        assert_eq!(part_gc_state_dir_for("t1", Some(hot)), Some(hot.join("t1").join("ingest")));
        assert_eq!(part_gc_state_dir_for("t1", None), None);
        let root = Path::new("/data/tenants/t1");
        let published = product_dir_for(root, "t1", Some(hot));
        for role in Role::ALL {
            let (rw, ro) = role_mounts(root, role, true, &published);
            assert!(!rw.iter().chain(&ro).any(|path| path.starts_with(hot.join("t1/ingest"))),
                "{role:?}'s data mounts never include ingest[T]'s hot dir (jail_spec adds it for ingest only)");
        }
    }

    #[test]
    fn product_runs_in_its_own_leaf_with_query_authority_and_never_shares_query_quota() {
        let root = Path::new("/data/tenants/t1");
        // product[T]: its own state rw, parts ro: exactly query's data reach.
        let published = root.join("product");
        let (rw, ro) = role_mounts(root, Role::Product, true, &published);
        assert_eq!(rw, vec![root.join("product")]);
        assert_eq!(ro, vec![root.join("parts")]);
        // query[T] beside it: reads the published dir, writes only the inbox.
        let (rw, ro) = role_mounts(root, Role::Query, true, &published);
        assert_eq!(rw, vec![root.join("query"), root.join("product/demand")]);
        assert_eq!(ro, vec![root.join("parts"), root.join("product")]);
        // Flag off: query's mounts are unchanged.
        assert_eq!(role_mounts(root, Role::Query, false, &published), (vec![root.join("query")], vec![root.join("parts")]));
        // NAN-3799: published on the persistent hot volume. product[T]
        // keeps its data-volume state/tmp and writes the hot tree; query[T]
        // reads it and writes only its inbox there.
        let hot = Path::new("/hot/tenants");
        let published = product_dir_for(root, "t1", Some(hot));
        assert_eq!(published, hot.join("t1/product"));
        assert_eq!(product_dir_for(root, "t1", None), root.join("product"));
        let (rw, ro) = role_mounts(root, Role::Product, true, &published);
        assert_eq!(rw, vec![root.join("product"), hot.join("t1/product")]);
        assert_eq!(ro, vec![root.join("parts")]);
        let (rw, ro) = role_mounts(root, Role::Query, true, &published);
        assert_eq!(rw, vec![root.join("query"), hot.join("t1/product/demand")]);
        assert_eq!(ro, vec![root.join("parts"), hot.join("t1/product")]);
        for role in [Role::Ingest, Role::Detect, Role::Maintenance] {
            let (rw, ro) = role_mounts(root, role, true, &published);
            assert!(!rw.iter().chain(&ro).any(|path| path.starts_with(hot)), "{role:?} never reaches the hot product tree");
        }
        // A distinct per-role index (its own cgroup leaf and stats slot).
        let indices: std::collections::BTreeSet<usize> = Role::ALL.iter().map(|r| role_idx(*r)).collect();
        assert_eq!(indices.len(), crate::contract::ROLES);
        assert!(Role::ALL.iter().all(|r| role_idx(*r) < crate::contract::ROLES));
        // Its own budget, never placed and below query's weight.
        let placed = TenantPlacement::legacy(TenantId::new("t1").unwrap(), 300.0);
        let product = placed.effective_role_budget(Role::Product);
        let query = placed.effective_role_budget(Role::Query);
        assert_eq!(product.limit_millicores, crate::budget::PRODUCT_LIMIT_MILLICORES);
        assert!(product.request_millicores < query.request_millicores, "query wins contention by cpu.weight");
        assert!(product.limit_millicores < query.limit_millicores);
        // Minted and exchanged as query: no new control-plane role.
        assert_eq!(Role::Product.credential_role(), Role::Query);
        assert_eq!(Role::Query.credential_role(), Role::Query);
        // Its ceilings are added on top of the tenant's, never its guarantee.
        let base = TenantLimits::from_placement(&placed, &crate::resources::CellCapacity { cpu_millicores: 8_000, memory_bytes: 32 << 30, cpu_source: "config", memory_source: "config" },
            &crate::config::ResourceConfig::default());
        let with = with_product_role(base, &placed);
        assert_eq!(with.cpu_ceiling_millicores, base.cpu_ceiling_millicores + product.limit_millicores);
        assert_eq!(with.memory_hard_bytes, base.memory_hard_bytes + product.limit_memory_bytes);
        assert_eq!((with.cpu_guarantee_millicores, with.cpu_weight), (base.cpu_guarantee_millicores, base.cpu_weight));
        // The keeper ties it to query[T], not the idle reaper.
        assert!(!idle_reapable(Role::Product, Some(&placed)));
        assert!(!idle_reap_due(Role::Product, Some(&placed), 0, Duration::from_secs(7_200), Duration::from_secs(60), false));
    }
}

#[cfg(test)]
mod forward_output_tests {
    use super::*;

    /// A reader that yields `n` bytes of `fill` with no newline, then `tail`,
    /// counting the largest single read so the test sees what was buffered.
    struct Flood {
        left: u64,
        tail: std::io::Cursor<Vec<u8>>,
    }

    impl tokio::io::AsyncRead for Flood {
        fn poll_read(mut self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>)
            -> std::task::Poll<std::io::Result<()>> {
            if self.left > 0 {
                let n = (buf.remaining() as u64).min(self.left) as usize;
                buf.put_slice(&vec![b'A'; n]);
                self.left -= n as u64;
            } else {
                let pos = self.tail.position() as usize;
                let rest = &self.tail.get_ref()[pos..];
                let n = rest.len().min(buf.remaining());
                buf.put_slice(&rest[..n]);
                self.tail.set_position((pos + n) as u64);
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// NAN-3289 P2-3: 256 MiB without a newline is forwarded as one
    /// truncated line, the next line still arrives, and nothing close to the
    /// flood size is ever held (each emitted line is at most the cap plus
    /// the marker).
    #[tokio::test]
    async fn a_line_without_newline_is_truncated_not_buffered() {
        let flood = Flood { left: 256 << 20, tail: std::io::Cursor::new(b"\nok\n\x1b[31mforged\npartial".to_vec()) };
        let mut lines = Vec::new();
        forward_bounded_lines(flood, |l| lines.push(l.to_string())).await;
        assert_eq!(lines.len(), 4, "{:?}", lines.iter().map(|l| l.len()).collect::<Vec<_>>());
        assert!(lines[0].starts_with(&"A".repeat(MAX_FORWARDED_LINE_BYTES)));
        assert!(lines[0].ends_with(&format!("[truncated {} bytes]", (256u64 << 20) - MAX_FORWARDED_LINE_BYTES as u64)));
        assert!(lines[0].len() < MAX_FORWARDED_LINE_BYTES + 64);
        assert_eq!(lines[1], "ok");
        assert!(!lines[2].contains('\x1b'), "control characters are escaped: {}", lines[2]);
        assert_eq!(lines[3], "partial", "a final line without newline is still forwarded");
    }
}

#[cfg(test)]
mod search_relay_tests {
    use super::*;

    /// NAN-3795: ingest hears about searches while they run (or were just
    /// routed), at most once per relay period, and never when idle.
    #[test]
    fn search_activity_is_relayed_to_ingest_while_searches_run() {
        let now = Instant::now();
        assert!(!search_relay_due(false, false, None, now), "idle tenant: no relay");
        assert!(search_relay_due(true, false, None, now), "a running search is relayed");
        assert!(search_relay_due(false, true, None, now), "a just-routed short search is relayed");
        assert!(!search_relay_due(true, false, Some(now), now + Duration::from_millis(500)), "rate-limited");
        assert!(search_relay_due(true, false, Some(now), now + SEARCH_RELAY_EVERY), "repeated while it runs");
        assert!(!search_relay_due(false, false, Some(now), now + SEARCH_RELAY_EVERY), "stops once searches end");
    }

    /// NAN-3795 (CT 106 lab): nanosiem-search / -api poll `/v1/status` and
    /// `/v1/schema/manifest` every few seconds on an idle tenant; counting
    /// them as searches kept a count backfill yielding with no rewrite.
    #[test]
    fn only_search_rpcs_hold_the_backfill_back() {
        for sub in ["/v1/query", "/v1/query?x=1", "/v1/query/pages", "/v1/aggregate/count", "/v1/jobs/search",
            "/v1/jobs/result-page", "/v1/entity/ranges", "/v1/prevalence/explorer", "/v1/prevalence/detail",
            "/v1/identity/resolve-batch"] {
            assert!(is_search_rpc(sub), "{sub} is a search");
        }
        for sub in ["/v1/status", "/v1/status?x=1", "/v1/schema/manifest", "/v1/query/progress", "/v1/jobs/search/status",
            "/v1/jobs/search/cancel", "/v1/ingest/refusals", "/v1/debug/sql-probe", "/v1/identity/directory/stats", "/", "/v1/queryx"] {
            assert!(!is_search_rpc(sub), "{sub} is not a search");
        }
    }
}

#[cfg(test)]
mod nan3875_dirs_lock_tests {
    use super::*;

    /// NAN-3875: every role of one tenant serializes on ONE dirs lock, so
    /// concurrent spawns never interleave the hot-tree check and rebuild;
    /// another tenant is not held up by it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tenant_dirs_ensure_is_serialized_per_tenant_not_per_role() {
        let ids = TenantIds { slot: 0, ingest_uid: 1, query_uid: 1, detect_uid: 1, landing_uid: Some(1), gid: 1 };
        let a = Arc::new(TenantSlot::new(TenantId::new("aaaa").unwrap(), ids));
        let b = Arc::new(TenantSlot::new(TenantId::new("bbbb").unwrap(), ids));
        let inside = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _role in Role::ALL {
            let (a, inside, max) = (a.clone(), inside.clone(), max.clone());
            tasks.push(tokio::spawn(async move {
                a.with_dirs_lock(async {
                    let n = inside.fetch_add(1, Ordering::SeqCst) + 1;
                    max.fetch_max(n, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    inside.fetch_sub(1, Ordering::SeqCst);
                }).await
            }));
        }
        // While a's roles queue on a's lock, b's ensure proceeds at once.
        let held = a.dirs_lock.lock().await;
        let other = tokio::time::timeout(Duration::from_secs(1), b.with_dirs_lock(async {})).await;
        assert!(other.is_ok(), "another tenant is never blocked by this tenant's lock");
        drop(held);
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(max.load(Ordering::SeqCst), 1, "two roles of one tenant were inside the tree ensure at once");
    }

    /// NAN-4128: a hung detect spawn of tenant A (holding A's detect lock
    /// with no end) never holds up tenant B's detect wake, and A's own wake
    /// answers with a bounded error instead of hanging.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_hung_detect_spawn_wedges_neither_its_wake_nor_another_tenant() {
        let ids = TenantIds { slot: 0, ingest_uid: 1, query_uid: 1, detect_uid: 1, landing_uid: Some(1), gid: 1 };
        let a = Arc::new(TenantSlot::new(TenantId::new("aaaa").unwrap(), ids));
        let b = Arc::new(TenantSlot::new(TenantId::new("bbbb").unwrap(), ids));
        let d = role_idx(Role::Detect);
        let ms = Duration::from_millis;
        let hung = |slot: Arc<TenantSlot>| move |p: Arc<Progress>| async move {
            let _g = slot.spawn_lock[d].lock_logged(&p, slot.id.as_str(), "detect", ms(1000)).await;
            p.set("mint_bootstrap_token");
            std::future::pending::<Result<Arc<Proc>, CellError>>().await
        };
        let t0 = Instant::now();
        let r = a.flights[d].run(ms(200), ms(5000), hung(a.clone())).await;
        assert!(matches!(r, Err(FlightError::TimedOut { step: "mint_bootstrap_token", .. })), "{:?}", r.as_ref().err());
        assert!(t0.elapsed() < ms(2000));
        tokio::time::sleep(ms(20)).await;
        assert!(a.spawn_lock[d].try_lock().is_ok(), "the timed-out attempt released A's detect lock");

        // A hangs again; B's detect proceeds at once on its own lock.
        let r = a.flights[d].run(ms(5000), ms(50), hung(a.clone())).await;
        assert!(matches!(r, Err(FlightError::StillRunning { .. })), "{:?}", r.as_ref().err());
        let b2 = b.clone();
        let t0 = Instant::now();
        let r = b.flights[d]
            .run(ms(1000), ms(1000), move |p| async move {
                let _g = b2.spawn_lock[d].lock_logged(&p, b2.id.as_str(), "detect", ms(1000)).await;
                Err::<Arc<Proc>, _>(CellError::Spawn("b ran".into()))
            })
            .await;
        assert!(matches!(r, Err(FlightError::Failed(CellError::Spawn(ref m))) if m == "b ran"), "{:?}", r.as_ref().err());
        assert!(t0.elapsed() < ms(500), "B waited on A: {:?}", t0.elapsed());
        // A's other roles are not held by its detect lock either.
        assert!(a.spawn_lock[role_idx(Role::Query)].try_lock().is_ok());
    }
}

#[cfg(test)]
mod refresh_pacer_tests {
    use super::*;

    /// NAN-4326: a request inside the mint interval is answered at the
    /// interval's end (not dropped); further early requests coalesce into
    /// that one answer; the interval still bounds the mint rate.
    #[test]
    fn an_early_refresh_is_deferred_to_the_interval_end_not_dropped() {
        let t0 = Instant::now();
        let mut pacer = RefreshPacer::new(REFRESH_MIN_INTERVAL);
        assert_eq!(pacer.request(t0), RefreshPace::MintNow, "the first request mints at once");
        let early = t0 + Duration::from_secs(15);
        assert_eq!(pacer.request(early), RefreshPace::DeferUntil(t0 + REFRESH_MIN_INTERVAL));
        assert_eq!(pacer.request(early + Duration::from_secs(5)), RefreshPace::AlreadyDeferred, "coalesced");
        let fired = t0 + REFRESH_MIN_INTERVAL;
        pacer.deferred_due(fired);
        assert_eq!(pacer.request(fired + Duration::from_secs(1)), RefreshPace::DeferUntil(fired + REFRESH_MIN_INTERVAL),
            "the deferred mint starts a new interval");
        pacer.deferred_due(fired + REFRESH_MIN_INTERVAL);
        assert_eq!(pacer.request(fired + REFRESH_MIN_INTERVAL * 2), RefreshPace::MintNow, "after the interval: at once");
    }
}

// Deployment mode is the explicit cell trust boundary. The accepted storage
// stage adds proxy port 3128 to the existing jail contract. No root key is read.
async fn assignment_proxy(cfg: &crate::config::CellConfig, tenant: &TenantId) -> Result<Option<crate::contract::OutboundProxy>, CellError> {
    if cfg.trusted_local || !cfg.tcp_connect_ports.contains(&3128) { return Ok(None); }
    let refuse = || CellError::Spawn("storage proxy delegation unavailable".into());
    let control = cfg.control_url.as_deref().ok_or_else(refuse)?;
    let identity = cfg.cell_identity_file.as_ref().ok_or_else(refuse)?;
    let proxy = std::env::var("HTTPS_PROXY").map_err(|_| refuse())?;
    let client = supervisor_proxy_client(&proxy)?;
    let token = zeroize::Zeroizing::new(tokio::fs::read_to_string(identity).await.map_err(|_| refuse())?);
    let endpoint = format!("{}/v1/lake/cells/{}/egress-proxy", control.trim_end_matches('/'), cfg.cell_id);
    let mut response = client.post(endpoint).bearer_auth(token.trim()).json(&serde_json::json!({"tenant_id":tenant.as_str()}))
        .send().await.map_err(|_| refuse())?;
    if !response.status().is_success() { return Err(refuse()); }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| refuse())? {
        if bytes.len() + chunk.len() > 1024 { return Err(refuse()); }
        bytes.extend_from_slice(&chunk);
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Delegation { proxy_url: String }
    let response: Delegation = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    validate_cell_proxy(&response.proxy_url, "storage", Some(tenant.as_str()))?;
    Ok(Some(crate::contract::OutboundProxy(response.proxy_url)))
}

fn validate_cell_proxy(raw: &str, purpose: &str, tenant: Option<&str>) -> Result<(), CellError> {
    let refuse = || CellError::Spawn("storage proxy delegation refused".into());
    let url = reqwest::Url::parse(raw).map_err(|_| refuse())?;
    let (id, scope) = url.username().split_once("%2F").ok_or_else(refuse)?;
    if url.scheme() != "http" || url.host_str() != Some("search-storage-proxy.nano-egress-proxy.svc.cluster.local")
        || url.port() != Some(3128) || url.path() != "/" || url.query().is_some() || url.fragment().is_some()
        || scope != purpose || uuid::Uuid::parse_str(id).map_or(true,|id|id.is_nil())
        || tenant.is_some_and(|expected| expected != id)
        || !url.password().is_some_and(|p| p.len()==64 && p.bytes().all(|b|b.is_ascii_hexdigit())) { return Err(refuse()); }
    Ok(())
}
fn supervisor_proxy_client(proxy: &str) -> Result<reqwest::Client, CellError> {
    validate_cell_proxy(proxy,"supervisor",None)?;
    reqwest::Client::builder().no_proxy().proxy(reqwest::Proxy::all(proxy).map_err(|_|CellError::Spawn("cell proxy refused".into()))?)
        .redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build()
        .map_err(|_|CellError::Spawn("cell proxy unavailable".into()))
}

#[cfg(test)]
mod assignment_egress_tests {
    use super::*;
    #[test]
    fn supervisor_cannot_mint_or_move_storage_credentials() {
        let a="11111111-2222-4333-8444-555555555555";
        let b="22222222-2222-4333-8444-555555555555";
        let url=format!("http://{a}%2Fsupervisor:{}@search-storage-proxy.nano-egress-proxy.svc.cluster.local:3128","a".repeat(64));
        assert!(supervisor_proxy_client(&url).is_ok());
        assert!(supervisor_proxy_client(&url.replace("supervisor","storage")).is_err());
        let storage=url.replace("supervisor","storage");
        assert!(validate_cell_proxy(&storage,"storage",Some(a)).is_ok());
        assert!(validate_cell_proxy(&storage,"storage",Some(b)).is_err());
        for bad in [storage.replace(":3128",":80"),storage.replace("search-storage-proxy.nano-egress-proxy.svc.cluster.local","evil.example"),format!("{storage}?secret=value")] {
            assert!(validate_cell_proxy(&bad,"storage",Some(a)).is_err());
        }
        assert_eq!(format!("{:?}",crate::contract::OutboundProxy(storage)),"OutboundProxy([redacted])");
    }
}
