// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2361 wave 8: a hosted-shared tenant with an EMPTY lake must still
//! search. This walks the lifecycle at every in-process seam the product
//! owns, in order:
//!
//! 1. empty table (no Iceberg snapshot) -> the zero-snapshot **bootstrap
//!    generation** renders from the `bootstrap-pending` seed, in the exact
//!    signed format the worker admits;
//! 2. the first audit-shaped event (provisioning: `http_request` with a null
//!    user agent) is admitted by the additive-schema path AND accepted by the
//!    staged encoder against the resulting schema -- the pair that deadlocked
//!    `lake_event_publish` on tenant1;
//! 3. the staged tail signs against base 0 (so the tail manager, the worker,
//!    and the heartbeat all agree on the bootstrap identity);
//! 4. the query planner serves that tail with an EMPTY typed base -- never
//!    the Iceberg table function -- and answers with zero rows when no tail
//!    exists;
//! 5. the compactor treats the first pack on a snapshot-less table as ready,
//!    and once snapshot 1 exists the generation manager selects it as a
//!    first promotion with NO active predecessor.
//!
//! What this cannot prove without a catalog, an object store, PostgreSQL and
//! a chDB runtime: the REST commit of snapshot 1 itself and the engine
//! executing the emitted SQL. Those seams are covered by the live validation
//! runbook (`docs-internal/working-notes/SHARED-SOURCE-MODE-OPERATIONS.md`).

use nanosiem_lake_worker::bootstrap_generation::{
    bootstrap_generation_root, is_bootstrap_generation_id, is_bootstrap_stamps,
    render_bootstrap_generation, BootstrapGenerationInput, BOOTSTRAP_SNAPSHOT_ID,
};
use nanosiem_lake_worker::config::{event_config_sha256, event_generation_id, WorkerConfigFile};
use nanosiem_lake_worker::generation::{
    bind_hot_tail_read_contract, build_staged_hot_tail_manifest, hot_tail_is_bootstrap,
    sign_hot_tail_manifest, verify_hot_tail_manifest, HotTailObject, ObjectStampManifest,
};
use nanosiem_lake_worker::planner::{
    plan_broad_log_query_with_candidates_and_tail, plan_count_aggregate_query, read_manifest,
    snapshot_field_types,
    tenant_is_bootstrap, CompiledQuery, CountAggregatePlanRequest, CountAggregateSource,
    ObjectStoreCredentials, RequiredColumn, SnapshotCache, SourceManifest, TenantQueryConfig,
};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const TENANT: &str = "b464ceb9-0000-4000-8000-000000000001";
const TABLE: &str = "tenant1.events";
const PREFIX: &str = "s3://lake-bucket/tenants/tenant1/events";
const METADATA: &str = "s3://lake-bucket/tenants/tenant1/events/metadata/00000-4c1c.metadata.json";
const READ_SCHEMA: &str = "time Nullable(DateTime64(6, 'UTC')), metadata Tuple(uid Nullable(String), log_source Nullable(String)), http_request Tuple(user_agent Nullable(String))";
const HMAC_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

fn sha(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// The seed `lake_worker_config_bootstrap` writes: non-runnable placeholders
/// for every derivative, real digests for the runtime and the HMAC key.
fn write_seed(root: &Path) -> PathBuf {
    let file = |name: &str, content: &[u8]| {
        let path = root.join(name);
        std::fs::write(&path, content).unwrap();
        json!({ "path": path, "sha256": sha(content) })
    };
    let placeholder = root.join(".first-generation-pending");
    let placeholder_artifact = |name: &str| {
        json!({ "path": placeholder.join(name), "sha256": "0".repeat(64) })
    };
    let config = root.join("worker.json");
    std::fs::write(
        &config,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "generation_id": "bootstrap-pending",
            "assigned_tenant_id": TENANT,
            "compiler": file("nano-lake-compiler", b"compiler-bytes"),
            "native_library": file("libchdb.so", b"not-a-real-native-library"),
            "tenant": {
                "tenant_id": TENANT,
                "source": PREFIX,
                "iceberg_metadata_file_path": "metadata/bootstrap-pending.metadata.json",
                "source_manifest": placeholder_artifact("source-manifest.json"),
                "max_query_bytes": 1_073_741_824_u64,
                "max_memory_bytes": 4_294_967_296_u64,
                "max_execution_seconds": 120,
                "threads": 4,
                "event_contract": "ocsf-1.9",
                "allow_broad_npl": true,
                "iceberg_default_credentials": true
            },
            "entity_sidecar": {
                "manifest": placeholder_artifact("entity-manifest.json"),
                "hmac_key": file("entity-hmac.key", HMAC_KEY),
                "index_files": []
            },
            "keyword_sidecar": {
                "manifest": placeholder_artifact("keyword-manifest.json"),
                "index_directory": placeholder.join("keyword-index"),
                "index_tree_sha256": "0".repeat(64),
                "fragment_manifest": placeholder_artifact("fragment-manifest.json"),
                "fragment_index_directory": placeholder.join("fragment-index"),
                "fragment_index_tree_sha256": "0".repeat(64)
            }
        }))
        .unwrap(),
    )
    .unwrap();
    config
}

/// NAN-3366: the catalog field types of the same empty table (READ_SCHEMA's
/// leaves), as `iceberg::table_field_types` derives them.
fn field_types() -> &'static BTreeMap<String, String> {
    static TYPES: std::sync::OnceLock<BTreeMap<String, String>> = std::sync::OnceLock::new();
    TYPES.get_or_init(|| {
        BTreeMap::from([
            ("http_request.user_agent".to_string(), "string".to_string()),
            ("metadata.log_source".to_string(), "string".to_string()),
            ("metadata.uid".to_string(), "string".to_string()),
            ("time".to_string(), "timestamp".to_string()),
        ])
    })
}

fn bootstrap_input<'a>(
    worker_config: &'a Path,
    generations_root: &'a Path,
    table_uuid: uuid::Uuid,
) -> BootstrapGenerationInput<'a> {
    BootstrapGenerationInput {
        worker_config,
        generations_root,
        tenant_id: TENANT,
        table: TABLE,
        table_location_prefix: PREFIX,
        metadata_location: METADATA,
        table_uuid,
        read_schema: READ_SCHEMA,
        field_types: field_types(),
        worker_source: PREFIX,
        max_memory_bytes: 4_294_967_296,
    }
}

fn bootstrap_tenant() -> TenantQueryConfig {
    TenantQueryConfig {
        tenant_id: TENANT.to_string(),
        source: PREFIX.to_string(),
        iceberg_metadata_file_path: "metadata/00000-4c1c.metadata.json".to_string(),
        max_query_bytes: 1_073_741_824,
        max_memory_bytes: 4_294_967_296,
        max_execution_seconds: 120,
        threads: 4,
        credentials: ObjectStoreCredentials::DefaultChain,
        snapshot_cache: Some(SnapshotCache {
            source_spec: String::new(),
            objects: BTreeMap::new(),
            bytes: 0,
            read_schema: Some(READ_SCHEMA.to_string()),
            bootstrap: true,
        }),
    }
}

fn empty_manifest() -> SourceManifest {
    serde_json::from_value(json!({ "tenant_id": TENANT, "objects": [] })).unwrap()
}

fn compiled(sql: &str) -> CompiledQuery {
    CompiledQuery {
        stats_page: false,
        schema_version: 1,
        profile: "ocsf".to_string(),
        dataset: "logs".to_string(),
        source_placeholder: "__nano_lake_source__".to_string(),
        query_sha256: "a".repeat(64),
        start: "2026-09-17T00:00:00Z".to_string(),
        end: "2026-09-18T00:00:00Z".to_string(),
        limit: 100,
        table_view: true,
        newest_first_event_rows: true,
        candidate_hints: Vec::new(),
        required_columns: vec![
            RequiredColumn {
                name: "time".to_string(),
                field_type: "timestamp".to_string(),
            },
            RequiredColumn {
                name: "metadata.uid".to_string(),
                field_type: "string".to_string(),
            },
            RequiredColumn {
                name: "http_request.user_agent".to_string(),
                field_type: "string".to_string(),
            },
        ],
        projected_scan_columns: Vec::new(),
        sql: sql.to_string(),
    }
}

/// One staged audit object published into the tenant's tail prefix.
fn staged_object() -> HotTailObject {
    let tenant_hash = sha(TENANT.as_bytes());
    HotTailObject {
        source_uri: format!(
            "{PREFIX}/data/tail/tenant_sha256={tenant_hash}/event_hour=497124/audit-0001.parquet"
        ),
        version_id: "v-audit-0001".to_string(),
        etag: None,
        size_bytes: 2_048,
        rows: 1,
        sha256: None,
        min_time_ms: Some(1_789_646_400_000),
        max_time_ms: Some(1_789_646_400_000),
        committed: false,
    }
}

#[test]
fn empty_table_bootstraps_serves_the_tail_and_promotes_the_first_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let worker_config = write_seed(root.path());
    let generations = root.path().join("generations");
    std::fs::create_dir_all(&generations).unwrap();
    let table_uuid = uuid::Uuid::new_v4();

    // ---- 1. empty table -> bootstrap generation, exact format -------------
    let rendered =
        render_bootstrap_generation(&bootstrap_input(&worker_config, &generations, table_uuid))
            .unwrap();
    assert_eq!(rendered.current_generation_id, "bootstrap-pending");
    assert!(
        is_bootstrap_generation_id(&rendered.generation_id),
        "{}",
        rendered.generation_id
    );
    assert_eq!(
        rendered.snapshot_root,
        bootstrap_generation_root(&generations, table_uuid, METADATA).join("snapshot")
    );
    let value = &rendered.value;
    assert_eq!(value["generation_id"], rendered.generation_id);
    assert_eq!(value["assigned_tenant_id"], TENANT);
    assert_eq!(
        value["tenant"]["iceberg_metadata_file_path"],
        "metadata/00000-4c1c.metadata.json"
    );
    assert_eq!(value["snapshot_cache"]["max_bytes"], 0);
    assert_eq!(value["snapshot_cache"]["ancestor_snapshot_ids"], json!([]));
    assert_eq!(
        value["snapshot_cache"]["data_directory"],
        json!(rendered.snapshot_root.join("data"))
    );
    assert_eq!(value["entity_sidecar"]["index_files"], json!([]));
    assert_eq!(value["keyword_sidecar"]["index_tree_sha256"], "0".repeat(64));
    assert!(value.get("count_rollup").is_none());
    assert!(value.get("identity_snapshot").is_none());
    assert!(value.get("prevalence_snapshots").is_none());
    let stamp_path = PathBuf::from(
        value["snapshot_cache"]["object_stamp_manifest"]["path"]
            .as_str()
            .unwrap(),
    );
    let stamps: ObjectStampManifest =
        serde_json::from_slice(&std::fs::read(&stamp_path).unwrap()).unwrap();
    assert!(is_bootstrap_stamps(&stamps));
    assert_eq!(stamps.snapshot_id, BOOTSTRAP_SNAPSHOT_ID);
    assert_eq!(stamps.table, TABLE);
    assert_eq!(stamps.metadata_location, METADATA);
    assert_eq!(
        stamps.table_uuid.as_deref(),
        Some(table_uuid.hyphenated().to_string().as_str())
    );
    // The stamp artifact digest in the config is the file's real digest, so
    // the identity is bound to (table uuid, metadata location, snapshot 0).
    assert_eq!(
        value["snapshot_cache"]["object_stamp_manifest"]["sha256"],
        sha(&std::fs::read(&stamp_path).unwrap())
    );
    let read_schema_path = PathBuf::from(
        value["snapshot_cache"]["read_schema"]["path"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(std::fs::read_to_string(read_schema_path).unwrap(), READ_SCHEMA);
    // The source manifest the worker reads is empty and points at the stamps.
    let source_manifest: Value = serde_json::from_slice(
        &std::fs::read(value["tenant"]["source_manifest"]["path"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(source_manifest["objects"], json!([]));
    assert_eq!(source_manifest["object_stamp_manifest"], json!(stamp_path));
    // NAN-3366: the empty table's catalog field types travel with it, so the
    // worker serves them as its inventory instead of an empty one.
    let rendered_manifest_path =
        PathBuf::from(value["tenant"]["source_manifest"]["path"].as_str().unwrap());
    assert_eq!(source_manifest["bootstrap_field_types"], json!(field_types()));
    let rendered_manifest = read_manifest(&rendered_manifest_path).unwrap();
    assert_eq!(&snapshot_field_types(&rendered_manifest).unwrap(), field_types());
    assert_eq!(value["entity_sidecar"]["manifest"], value["tenant"]["source_manifest"]);

    // Identity is content-derived: re-rendering is byte-stable, a different
    // metadata location (schema evolution before the first snapshot) rolls it.
    let again =
        render_bootstrap_generation(&bootstrap_input(&worker_config, &generations, table_uuid))
            .unwrap();
    assert_eq!(again.generation_id, rendered.generation_id);
    let mut moved = bootstrap_input(&worker_config, &generations, table_uuid);
    moved.metadata_location = "s3://lake-bucket/tenants/tenant1/events/metadata/00001-9e2a.metadata.json";
    let rolled = render_bootstrap_generation(&moved).unwrap();
    assert_ne!(rolled.generation_id, rendered.generation_id);
    assert!(is_bootstrap_generation_id(&rolled.generation_id));
    // ...into its own immutable tree: the first render's artifacts still
    // match the digests its config carries.
    assert_ne!(rolled.snapshot_root, rendered.snapshot_root);
    assert_eq!(
        value["snapshot_cache"]["object_stamp_manifest"]["sha256"],
        sha(&std::fs::read(&stamp_path).unwrap())
    );

    // The rendered config is the worker's wire shape: it parses, identifies
    // as bootstrap, and the FULL load walks every bootstrap fence and fails
    // only at the native-library fence this fixture cannot satisfy.
    let candidate = root.path().join("worker.bootstrap.json");
    std::fs::write(&candidate, serde_json::to_vec_pretty(&rendered.value).unwrap()).unwrap();
    let parsed = WorkerConfigFile::read(&candidate).unwrap();
    assert!(parsed.is_bootstrap_generation());
    let error = WorkerConfigFile::load(&candidate)
        .err()
        .expect("fixture cannot pass the native-library fence");
    let message = error.to_string();
    assert!(
        message.contains("native chDB artifact"),
        "bootstrap load must reach the runtime fence, not a bootstrap fence: {message}"
    );

    // A risk/IOC state publication rotates the identity to `lakecfg-…`
    // without touching the event side; the worker must still recognize the
    // bootstrap by SHAPE and load it (again up to the runtime fence).
    let mut rotated_value = rendered.value.clone();
    rotated_value["generation_id"] = json!(format!("lakecfg-{}", "e".repeat(24)));
    let rotated = root.path().join("worker.rotated.json");
    std::fs::write(&rotated, serde_json::to_vec_pretty(&rotated_value).unwrap()).unwrap();
    assert!(WorkerConfigFile::read(&rotated).unwrap().is_bootstrap_generation());
    let rotated_error = WorkerConfigFile::load(&rotated).err().unwrap().to_string();
    assert!(rotated_error.contains("native chDB artifact"), "{rotated_error}");
    // A REAL generation identity over the empty shape is refused outright:
    // the empty cache is admitted only under a bootstrap identity.
    let mut forged_value = rendered.value.clone();
    forged_value["generation_id"] = json!(format!("lake-7-{}", "e".repeat(24)));
    let forged_path = root.path().join("worker.forged.json");
    std::fs::write(&forged_path, serde_json::to_vec_pretty(&forged_value).unwrap()).unwrap();
    let forged_error = WorkerConfigFile::load(&forged_path).err().unwrap().to_string();
    assert!(
        forged_error.contains("bootstrap generation must be exactly the empty zero-snapshot form"),
        "{forged_error}"
    );

    // The bootstrap is a real event generation with snapshot 0 under the same
    // digest contract, and its event config digest is stable.
    let bytes = std::fs::read(&candidate).unwrap();
    let event_sha = event_config_sha256(&bytes).unwrap();
    let event_generation = event_generation_id(BOOTSTRAP_SNAPSHOT_ID, &event_sha).unwrap();
    assert!(event_generation.starts_with("event-0-"));
    assert!(event_generation_id(-1, &event_sha).is_err());

    // A real generation is never mistaken for bootstrap, and a zero snapshot
    // without the table UUID is never admitted as one.
    let mut real = stamps.clone();
    real.snapshot_id = 1;
    assert!(!is_bootstrap_stamps(&real));
    let mut forged = stamps.clone();
    forged.table_uuid = None;
    assert!(!is_bootstrap_stamps(&forged));

    // ---- 2. first audit-shaped event: schema path and encoder agree --------
    // Covered end-to-end in `iceberg::tests::all_null_struct_does_not_require_a_physical_column`
    // (the exact `"http_request": {"user_agent": null}` provisioning row).
    // Here: the planner's read of the same row shape through the tail.

    // ---- 3. the staged tail signs against base 0 --------------------------
    let tail_id = sha(b"nano:staged-hot-tail:v1\0audit-0001");
    let mut tail = build_staged_hot_tail_manifest(
        PREFIX,
        TENANT,
        &stamps,
        &tail_id,
        vec![staged_object()],
        128,
        64 * 1_024 * 1_024,
        0,
    )
    .unwrap();
    assert!(hot_tail_is_bootstrap(&tail));
    assert_eq!(tail.base_snapshot_id, 0);
    assert_eq!(tail.head_snapshot_id, 0);
    assert_eq!(tail.iceberg_metadata_file_path, "metadata/00000-4c1c.metadata.json");
    bind_hot_tail_read_contract(
        &mut tail,
        READ_SCHEMA.to_string(),
        vec![
            "time".to_string(),
            "metadata.uid".to_string(),
            "metadata.log_source".to_string(),
            "http_request.user_agent".to_string(),
        ],
    )
    .unwrap();
    let signed = sign_hot_tail_manifest(tail.clone(), HMAC_KEY).unwrap();
    let verified = verify_hot_tail_manifest(&signed, HMAC_KEY).unwrap();
    assert_eq!(verified.base_snapshot_id, 0);
    assert_eq!(verified.objects.len(), 1);
    // A negative or mixed zero identity is still refused.
    let mut mixed = tail.clone();
    mixed.head_snapshot_id = 1;
    assert!(sign_hot_tail_manifest(mixed, HMAC_KEY).is_err());
    let mut negative = tail.clone();
    negative.base_snapshot_id = -1;
    negative.head_snapshot_id = -1;
    assert!(sign_hot_tail_manifest(negative, HMAC_KEY).is_err());

    // ---- 4. the planner serves tail-only over a typed empty base ----------
    let tenant = bootstrap_tenant();
    assert!(tenant_is_bootstrap(&tenant));
    let query = compiled(
        "SELECT \"time\", \"metadata.uid\", \"http_request.user_agent\" FROM __nano_lake_source__ ORDER BY \"time\" DESC LIMIT 100",
    );
    let with_tail = plan_broad_log_query_with_candidates_and_tail(
        &tenant,
        &empty_manifest(),
        &query,
        None,
        Some(&tail),
    )
    .unwrap();
    assert!(
        with_tail.sql.contains("null({snapshot_cache_read_schema:String})"),
        "{}",
        with_tail.sql
    );
    assert!(with_tail.sql.contains("WHERE 1 = 0"), "{}", with_tail.sql);
    assert!(with_tail.sql.contains("UNION ALL"), "{}", with_tail.sql);
    assert!(!with_tail.sql.contains("icebergS3("), "{}", with_tail.sql);
    assert!(!with_tail.sql.contains("_path"), "{}", with_tail.sql);
    assert!(with_tail
        .params
        .iter()
        .any(|(name, value)| name == "snapshot_cache_read_schema" && value == READ_SCHEMA));
    assert_eq!(with_tail.budget.candidate_objects, 1);
    assert_eq!(with_tail.budget.estimated_scan_bytes, 2_048);
    // The audit row's `http_request.user_agent` resolves through the tail's
    // read contract, not a schema default.
    assert!(!with_tail
        .schema_defaults
        .iter()
        .any(|column| column == "http_request.user_agent"));

    // Sidecar hints on a bootstrap generation fence the base to nothing and
    // still union the tail; a candidate naming any object is a lie.
    let fenced = plan_broad_log_query_with_candidates_and_tail(
        &tenant,
        &empty_manifest(),
        &query,
        Some(&[]),
        Some(&tail),
    )
    .unwrap();
    assert!(fenced.sql.contains("null({snapshot_cache_read_schema:String})"));
    assert!(fenced.sql.contains("UNION ALL"));
    assert!(!fenced.sql.contains("icebergS3("));

    // NAN-3366 / NAN-3081: with no tail, the typed empty base's own columns
    // are real. A manifest that does not carry the bootstrap field types
    // counts every required column as missing and re-materializes it as a
    // typed NULL beside the relation's column of the same name, which chDB
    // rejects (`Block structure mismatch ... time DateTime64 vs
    // Nullable(DateTime64) Const`, the reader's startup canary on a fresh
    // install). The rendered manifest does not.
    let without_paths =
        plan_broad_log_query_with_candidates_and_tail(&tenant, &empty_manifest(), &query, None, None)
            .unwrap();
    assert!(without_paths.schema_defaults.iter().any(|column| column == "time"));
    let rendered_plan =
        plan_broad_log_query_with_candidates_and_tail(&tenant, &rendered_manifest, &query, None, None)
            .unwrap();
    assert!(
        !rendered_plan.schema_defaults.iter().any(|column| column == "time"),
        "{:?}",
        rendered_plan.schema_defaults
    );
    assert!(!rendered_plan.sql.contains("Nullable(DateTime64"), "{}", rendered_plan.sql);

    // No tail at all: zero rows, still never the Iceberg table function.
    let no_tail =
        plan_broad_log_query_with_candidates_and_tail(&tenant, &empty_manifest(), &query, None, None)
            .unwrap();
    assert!(no_tail.sql.contains("null({snapshot_cache_read_schema:String})"));
    assert!(no_tail.sql.contains("WHERE 1 = 0"));
    assert!(!no_tail.sql.contains("UNION ALL"));
    assert!(!no_tail.sql.contains("icebergS3("));
    assert_eq!(no_tail.budget.candidate_objects, 0);
    assert_eq!(no_tail.budget.estimated_scan_bytes, 0);

    // Count companions: the base fragment is provably empty (no engine
    // round-trip), the tail fragment runs.
    let deny_source_types = std::collections::BTreeSet::new();
    let count = |source| {
        plan_count_aggregate_query(
            &tenant,
            &empty_manifest(),
            &CountAggregatePlanRequest {
                group_field: "metadata.log_source",
                group_results: true,
                multi_value: false,
                predicate: None,
                bucket_span_us: None,
                start_us: 1_789_603_200_000_000,
                end_exclusive_us: 1_789_689_600_000_000,
                source_filter: None,
                deny_source_types: &deny_source_types,
                source,
                group_by_source: false,
            },
        )
        .unwrap()
    };
    assert!(count(CountAggregateSource::Base).is_none());
    let tail_count = count(CountAggregateSource::HotTail(&tail)).expect("tail fragment");
    assert!(!tail_count.sql.contains("icebergS3("));

    // A real generation (non-bootstrap cache) never gets the empty base.
    let mut real_tenant = bootstrap_tenant();
    real_tenant.snapshot_cache = None;
    assert!(!tenant_is_bootstrap(&real_tenant));
    assert!(plan_broad_log_query_with_candidates_and_tail(
        &real_tenant,
        &empty_manifest(),
        &query,
        None,
        None
    )
    .is_err());

    // ---- 5. first snapshot: promoted as a first install ------------------
    // The compactor registers the first pack immediately on a snapshot-less
    // table (`bootstrap_pack_is_ready`, unit-tested in lake_tail_compact), and
    // the manager's `active_snapshot` reports NO active generation for a
    // bootstrap config, so `select_promotable_snapshot(head, None)` picks the
    // first generation-ready snapshot -- both covered by the binaries' own
    // unit tests (`lake_generation_manage::tests::bootstrap_*`). Once
    // snapshot 1 is served, the same tail re-signs against base 1 and the
    // bootstrap tail is no longer valid for it.
    let mut promoted = stamps.clone();
    promoted.snapshot_id = 1;
    promoted.table_uuid = None;
    promoted.metadata_location =
        "s3://lake-bucket/tenants/tenant1/events/metadata/00002-77aa.metadata.json".to_string();
    let after = build_staged_hot_tail_manifest(
        PREFIX,
        TENANT,
        &promoted,
        &tail_id,
        vec![staged_object()],
        128,
        64 * 1_024 * 1_024,
        0,
    )
    .unwrap();
    assert!(!hot_tail_is_bootstrap(&after));
    assert_eq!(after.base_snapshot_id, 1);
    assert_eq!(after.head_snapshot_id, 1);
}
