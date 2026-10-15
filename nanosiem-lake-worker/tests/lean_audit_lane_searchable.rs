// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2999 acceptance: an audited action on lean tenant A becomes searchable
//! as `metadata.log_source = audit` on A, and never on tenant B.
//!
//! Every hop after the control plane's delivery is the production code:
//! the delivered line (`AuditEvent::to_ocsf_event_for_lake`, the exact
//! `audit-events:delivery` body line) → the base's `audit` plumbing lane and
//! the base's own lake-sink prepare VRL (`platform_audit_lane::lake_row`, the
//! row a cell's Vector writes to bronze) → the real `lake_part_ingest` binary
//! (admission, owner-signed L0 parts) → `PartQueryEngine` over the signed
//! part log with native chDB. Tenant B is a separate part log: A's rows are
//! refused by B's lane (another tenant's line) and by B's admission (another
//! tenant's row), and B's search never returns them.
//! The control half (a delivery holds only A's rows) is pinned by
//! `nanosiem-core/tests/shared_lean_audit_delivery_integration.rs`.

use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use nanosiem_core::audit::{AuditEvent, AuditSource};
use nanosiem_core::parsers::tenant_bundle::{archive, platform_audit_lane};
use nanosiem_lake_worker::part_ingest::{SourceNotice, SpoolQueue};
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::{LocalPartSigner, TenantKeySet};
use parquet::arrow::ArrowWriter;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

const TENANT_A: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f10";
const TENANT_B: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f11";
const SIGNER_KEY_ID: &str = "lab-signer-test-2999";
/// The v1 source-bound base: its lake sink writes the metadata shape the live
/// lean tenants carry today (no NAN-2596/2645 `metadata.nano_*` stamps).
const BASE: &[u8] = include_bytes!("../../nanosiem-core/src/parsers/tenant_bundle/testdata/platform-base.tar.gz");

fn key() -> SigningKey {
    SigningKey::from_bytes(&[29; 32])
}

fn trusted() -> TenantKeySet {
    LocalPartSigner::new(SIGNER_KEY_ID, key()).unwrap().trusted()
}

/// One audited action of `tenant`, as the delivery body line.
fn delivered_line(tenant: &str, action: &str, at: chrono::DateTime<Utc>) -> (Uuid, String) {
    let event = AuditEvent::builder(AuditSource::Detection, action)
        .actor(Some(Uuid::new_v4()), Some("dan@nano.rs".to_string()))
        .resource("detection_rule", Some(Uuid::new_v4()), Some(format!("{action} target")))
        .client(Some("10.1.2.3".to_string()), Some("Mozilla/5.0".to_string()))
        .success(true)
        .build();
    let id = event.event_id();
    (id, serde_json::to_string(&event.to_ocsf_event_for_lake(at, id, tenant)).unwrap())
}

/// Bronze as the cell's sink writes it: the row minus `except_fields`.
fn write_bronze(path: &Path, rows: &[Value]) {
    let mut json = Vec::new();
    for row in rows {
        let mut row = row.clone();
        row.as_object_mut().unwrap().remove("_nano_bronze_partition");
        serde_json::to_writer(&mut json, &row).unwrap();
        json.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).build(Cursor::new(json)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap());
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

/// A tenant's ingest over one bronze object through the real binary.
fn ingest(root: &Path, tenant: &str, rows: &[Value], at_s: i64) -> std::process::Output {
    let sources = root.join("sources");
    std::fs::create_dir_all(sources.join("bronze")).unwrap();
    // The stores exist before the binary opens them (as in production).
    LocalObjectStore::new(root.join("parts")).unwrap();
    let object = format!("bronze/{at_s}-audit.parquet");
    write_bronze(&sources.join(&object), rows);
    let spool = SpoolQueue::new(root.join("spool"), tenant).unwrap();
    spool.deliver(&SourceNotice {
        tenant_id: tenant.into(), key: object, version: "1".into(), bytes: 0, sha256: None, edge_sha256: None,
        notified_at_ms: at_s * 1_000,
    }).unwrap();
    let key_file = root.join("signing-key.hex");
    std::fs::write(&key_file, hex::encode(key().to_bytes())).unwrap();
    std::process::Command::new(env!("CARGO_BIN_EXE_lake_part_ingest"))
        .env("RUST_LOG", "info")
        .args(["run", "--tenant-id", tenant, "--signer-key-id", SIGNER_KEY_ID,
            "--signing-key-file", key_file.to_str().unwrap(),
            "--parts-dir", root.join("parts").to_str().unwrap(),
            "--sources-dir", sources.to_str().unwrap(),
            "--spool-dir", root.join("spool").to_str().unwrap(),
            "--work-dir", root.join("work").to_str().unwrap(),
            "--tick-ms", "100", "--flush-ms", "1000", "--exit-when-idle"])
        .output().unwrap()
}

#[test]
fn the_lane_refuses_another_tenants_line_and_binds_the_row_to_the_cell_tenant() {
    let base = platform_audit_lane::add_platform_audit_lane(&archive::unpack(BASE).unwrap()).unwrap();
    let (id, line) = delivered_line(TENANT_A, "rule_created", Utc::now());
    let row = platform_audit_lane::lake_row(&base, &line, TENANT_A).unwrap();
    assert_eq!(row["metadata"]["log_source"], "audit");
    assert_eq!(row["metadata"]["tenant_uid"], TENANT_A);
    assert_eq!(row["metadata"]["uid"], id.to_string());
    // A's line delivered into B's cell never becomes a row there.
    assert!(platform_audit_lane::lake_row(&base, &line, TENANT_B).is_err());
}

async fn count(
    engine: &nanosiem_lake_worker::part_query::engine::PartQueryEngine,
    request: nanosiem_lake_worker::part_query::engine::BroadNplRequest,
) -> u64 {
    let query = request.query.clone();
    let result = engine.broad_npl(&request).await
        .unwrap_or_else(|error| panic!("{query:?}: {} {error}", error.status()));
    result["result"]["result_rows"].as_u64().unwrap_or_else(|| panic!("{query:?}: {result}"))
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn an_audited_action_on_a_is_searchable_as_audit_on_a_and_never_on_b() {
    use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
    use nanosiem_lake_worker::native::NativeChdb;
    use nanosiem_lake_worker::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
    use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
    use nanosiem_lake_worker::part_query::log_view::PartLogView;
    use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
    use std::time::Duration;

    let base = platform_audit_lane::add_platform_audit_lane(&archive::unpack(BASE).unwrap()).unwrap();
    let now = Utc::now();
    let now_s = now.timestamp();
    let a_actions = ["rule_created", "credential_issued", "apikey_authenticated"];
    let a_lines: Vec<(Uuid, String)> = a_actions.iter().enumerate()
        .map(|(i, action)| delivered_line(TENANT_A, action, now - chrono::Duration::seconds(120 - i as i64)))
        .collect();
    let (b_id, b_line) = delivered_line(TENANT_B, "case_opened", now - chrono::Duration::seconds(90));
    let a_rows: Vec<Value> = a_lines.iter().map(|(_, l)| platform_audit_lane::lake_row(&base, l, TENANT_A).unwrap()).collect();
    let b_row = platform_audit_lane::lake_row(&base, &b_line, TENANT_B).unwrap();

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let out_a = ingest(dir_a.path(), TENANT_A, &a_rows, now_s);
    assert!(out_a.status.success(), "A ingest: {}", String::from_utf8_lossy(&out_a.stderr));
    // B's own audit row, plus (in a second object) A's rows misdelivered to
    // B's cell: B's admission refuses another tenant's rows.
    let out_b = ingest(dir_b.path(), TENANT_B, &[b_row], now_s);
    assert!(out_b.status.success(), "B ingest: {}", String::from_utf8_lossy(&out_b.stderr));
    let out_b2 = ingest(dir_b.path(), TENANT_B, &a_rows, now_s + 1);
    assert!(out_b2.status.success(), "B ingest of A's rows: {}", String::from_utf8_lossy(&out_b2.stderr));

    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_named_with_mode(runtime, 1, "nan2999-native", ExecutorMode::ReadOnly).unwrap();
    let engine = |root: &Path, tenant: &str, executor: NativeExecutor| {
        let root = root.to_path_buf();
        let tenant = tenant.to_string();
        async move {
            let parts = root.join("parts");
            assert!(load_log(&LocalObjectStore::new(&parts).unwrap(), &tenant).await.unwrap().parts().next().is_some(), "{tenant}: no signed part");
            let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(&parts).unwrap());
            let view = PartLogView::open(store.as_ref(), &tenant, trusted()).await.unwrap();
            let bucket = "nan2999-local-proof";
            let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
                root: root.join("query-cache"), max_bytes: 128 << 20, query_max_bytes: 128 << 20,
                fetch_concurrency: 2, fetch_deadline: Duration::from_secs(30),
            }, &tenant, bucket, &parts_key_prefix(&tenant).unwrap(),
            Arc::new(StoreObjectSource::local(bucket, store.clone(), parts.clone()))).unwrap();
            let fetcher = PartFetcher::new(&tenant, bucket, store.clone(), trusted(), cache).unwrap();
            PartQueryEngine::new(EngineSettings {
                tenant_id: tenant.clone(), bucket: bucket.into(),
                compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
                max_query_bytes: 128 << 20, max_memory_bytes: 1 << 30, max_execution_seconds: 30, threads: 1,
            }, store, view, fetcher, executor).unwrap()
        }
    };
    let request = |tenant: &str, query: &str| BroadNplRequest {
        request_id: Uuid::new_v4().to_string(), tenant_id: tenant.into(), dataset: "logs".into(), query: query.into(),
        start: (now - chrono::Duration::hours(2)).to_rfc3339(), end: (now + chrono::Duration::minutes(1)).to_rfc3339(),
        limit: 50, offset: 0, table_view: false, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
    };
    // --- Tenant A: its three audit events, as audit, with the gen1 shape.
    let a = engine(dir_a.path(), TENANT_A, executor.clone()).await;
    assert_eq!(count(&a, request(TENANT_A, &String::from("metadata.log_source=audit"))).await, 3);
    assert_eq!(count(&a, request(TENANT_A, &String::from("metadata.log_source=audit class_uid=6003 actor.user.name=\"dan@nano.rs\""))).await, 3);
    for ((id, _), action) in a_lines.iter().zip(a_actions) {
        assert_eq!(count(&a, request(TENANT_A, &format!("metadata.log_source=audit metadata.uid=\"{id}\" api.operation={action}"))).await, 1,
            "{action}: the audit id stays the event uid");
    }
    assert_eq!(count(&a, request(TENANT_A, &String::from("metadata.log_source=audit | stats count by api.operation"))).await, 3);
    assert_eq!(count(&a, request(TENANT_A, &format!("metadata.uid=\"{b_id}\""))).await, 0, "B's audit event is never on A");

    // --- Tenant B: only its own event; none of A's, even misdelivered.
    let b = engine(dir_b.path(), TENANT_B, executor.clone()).await;
    assert_eq!(count(&b, request(TENANT_B, &String::from("metadata.log_source=audit"))).await, 1);
    assert_eq!(count(&b, request(TENANT_B, &format!("metadata.log_source=audit metadata.uid=\"{b_id}\""))).await, 1);
    for (id, _) in &a_lines {
        assert_eq!(count(&b, request(TENANT_B, &format!("metadata.uid=\"{id}\""))).await, 0, "A's event {id} is never on B");
    }
}

/// The lane's bronze row passes the production bronze admission for its own
/// tenant (as an audit row keyed by its audit id) and is refused for another.
#[test]
fn the_lane_row_passes_bronze_admission_for_its_tenant_only() {
    use nanosiem_lake_worker::bronze::admit_bronze_files;
    let base = platform_audit_lane::add_platform_audit_lane(&archive::unpack(BASE).unwrap()).unwrap();
    let (id, line) = delivered_line(TENANT_A, "rule_created", Utc::now());
    let row = platform_audit_lane::lake_row(&base, &line, TENANT_A).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.parquet");
    write_bronze(&path, &[row]);
    let admission = admit_bronze_files(&[path.clone()], TENANT_A).unwrap_or_else(|e| panic!("{e:#}"));
    let rows = admission.batch.into_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_uid, id.to_string());
    assert_eq!(rows[0].ocsf_event["metadata"]["log_source"], "audit");
    assert!(admit_bronze_files(&[path], TENANT_B).is_err(), "another tenant's row is never admitted");
}
