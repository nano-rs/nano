// SPDX-License-Identifier: AGPL-3.0-or-later

//! Run against a disposable PostgreSQL database with NANO_RISK_TEST_PG set
//! to its administrator URL. The database is intentionally rebuilt here.
//! With NANO_CHDB_LIBRARY_PATH set, also provide the current build's
//! NANO_RISK_TEST_COMPILER to execute `dataset=risk` through the lean route.

use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::part_ingest::finding_append::{FindingAppendRequest, FindingAppendResponse, FindingAppendTransport};
use nanosiem_lake_worker::part_ingest::finding_outbox::{committed_receipts, drain_once, FindingReceipt};
use nanosiem_lake_worker::part_ingest::ingest::{seed_schema, IngestConfig, Ingestor};
use nanosiem_lake_worker::part_ingest::SpoolQueue;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use nanosiem_lake_worker::part_query::log_view::PartLogView;
use nanosiem_lake_worker::part_query::risk::{broad_npl as read_risk_npl, risk as read_risk};
use nanosiem_lake_worker::parts::part_log::{LocalObjectStore, LogEntry, LogOp, ObjectStore};
use nanosiem_lake_worker::parts::format::PartKeys;
use nanosiem_lake_worker::parts::provenance::{LocalPartSigner, PartialKind, SignedProvenance};
use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use nanosiem_lake_worker::risk::{RiskDecay, RiskRequest};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const A: &str = "00000000-0000-4000-8000-000000000001";
const B: &str = "00000000-0000-4000-8000-000000000002";

struct FixtureAppend<'a> {
    ingest: tokio::sync::Mutex<Ingestor<'a>>,
    now_ms: i64,
}

#[async_trait::async_trait]
impl FindingAppendTransport for FixtureAppend<'_> {
    async fn submit(&self, request: &FindingAppendRequest) -> anyhow::Result<FindingAppendResponse> {
        self.ingest.lock().await.append_finding(FindingAppendRequest {
            tenant_id: request.tenant_id.clone(), writer_epoch: request.writer_epoch,
            schema: request.schema.clone(), parts: request.parts.clone(), receipts: request.receipts.clone(), deadline_unix_ms: request.deadline_unix_ms,
        }, self.now_ms).await
    }
}

async fn fixture_append<'a>(tenant: &str, dir: &std::path::Path, store: &'a LocalObjectStore,
    queue: &'a SpoolQueue, signer: &'a LocalPartSigner, now_ms: i64) -> FixtureAppend<'a> {
    let ingest = Ingestor::open(IngestConfig::new(tenant, dir.join(format!("ingest-{tenant}"))),
        store, store, queue, signer, signer.trusted(), BronzeIngestEnricher::disabled(),
        &seed_schema(), now_ms).await.unwrap();
    FixtureAppend { ingest: tokio::sync::Mutex::new(ingest), now_ms }
}

async fn setup(admin: &sqlx::PgPool) {
    for sql in [
        "CREATE SCHEMA nano_shared",
        "DROP ROLE IF EXISTS risk_drain_a",
        "DROP ROLE IF EXISTS risk_drain_b",
        "CREATE ROLE risk_drain_a LOGIN",
        "CREATE ROLE risk_drain_b LOGIN",
        "CREATE TABLE detection_finding_lake_outbox (security_tenant_id uuid NOT NULL, tenant_id text NOT NULL, finding_id text NOT NULL, compact_finding jsonb NOT NULL, ocsf_event jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), risk_published_at timestamptz, risk_snapshot_id text, event_published_at timestamptz, event_snapshot_id text, publish_attempts int NOT NULL DEFAULT 0, last_error text, PRIMARY KEY (tenant_id, finding_id))",
        "CREATE FUNCTION nano_shared.lake_data_path_tenant_id() RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT CASE session_user WHEN 'risk_drain_a' THEN '00000000-0000-4000-8000-000000000001'::uuid WHEN 'risk_drain_b' THEN '00000000-0000-4000-8000-000000000002'::uuid END $$",
        "CREATE FUNCTION nano_shared.lake_data_path_capability() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT CASE WHEN session_user IN ('risk_drain_a','risk_drain_b') THEN 'finding_drain' END $$",
        "GRANT USAGE ON SCHEMA nano_shared TO risk_drain_a, risk_drain_b",
        "GRANT EXECUTE ON FUNCTION nano_shared.lake_data_path_tenant_id() TO risk_drain_a, risk_drain_b",
        "GRANT EXECUTE ON FUNCTION nano_shared.lake_data_path_capability() TO risk_drain_a, risk_drain_b",
        "GRANT SELECT, UPDATE ON detection_finding_lake_outbox TO risk_drain_a, risk_drain_b",
        "ALTER TABLE detection_finding_lake_outbox ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE detection_finding_lake_outbox FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_select ON detection_finding_lake_outbox FOR SELECT USING (security_tenant_id = nano_shared.lake_data_path_tenant_id())",
        "CREATE POLICY tenant_update ON detection_finding_lake_outbox FOR UPDATE USING (security_tenant_id = nano_shared.lake_data_path_tenant_id()) WITH CHECK (security_tenant_id = nano_shared.lake_data_path_tenant_id())",
    ] {
        sqlx::query(sql).execute(admin).await.unwrap();
    }
    for tenant in [A, B] {
        let time_us = 1_790_444_800_000_000_i64;
        let compact = serde_json::json!({
            "id":"finding-1", "timestamp_us":time_us, "entity":"alice@example.com",
            "stamped_entity_type":"email", "risk_score":75, "rule_id":"rule-1",
            "rule_name":"fixture", "severity":"high", "origin_source_types":["auth"], "mitre_tactics":[]
        });
        let event = serde_json::json!({
            "class_uid":2004, "time":time_us / 1000,
            "metadata":{"uid":"finding-1","tenant_uid":tenant,"log_source":"detections","log_name":"findings"},
            // NAN-3224 shape: the alert link is `finding_info.uid_alt`.
            "is_alert":true, "risk_score":75,
            "finding_info":{"uid":"finding-1","types":["alert"],"uid_alt":format!("alert-{tenant}")}
        });
        sqlx::query("INSERT INTO detection_finding_lake_outbox (security_tenant_id, tenant_id, finding_id, compact_finding, ocsf_event) VALUES ($1,$2,$3,$4,$5)")
            .bind(uuid::Uuid::parse_str(tenant).unwrap()).bind(tenant).bind("finding-1")
            .bind(compact).bind(event).execute(admin).await.unwrap();
    }
}

fn tenant_pool(admin_url: &str, user: &str) -> sqlx::postgres::PgConnectOptions {
    let options = sqlx::postgres::PgConnectOptions::from_str(admin_url).unwrap();
    options.username(user)
}

async fn verify_native_risk_read(dir: &std::path::Path, signer_a: &LocalPartSigner, signer_b: &LocalPartSigner, now_ms: i64) {
    let library = std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap();
    let digest = std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap();
    let runtime = NativeChdb::load_verified(library, &digest).unwrap();
    std::mem::forget(runtime.clone());
    for (tenant, signer) in [(A, signer_a), (B, signer_b)] {
        let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(dir.join("store")).unwrap());
        let trusted = signer.trusted();
        let view = PartLogView::open(store.as_ref(), tenant, trusted.clone()).await.unwrap();
        let bucket = "risk-fixture";
        let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
            root: dir.join(format!("cache-{tenant}")), max_bytes: 64 * 1024 * 1024,
            query_max_bytes: 64 * 1024 * 1024, fetch_concurrency: 2,
            fetch_deadline: Duration::from_secs(30),
        }, tenant, bucket, &parts_key_prefix(tenant).unwrap(),
        Arc::new(StoreObjectSource::local(bucket, store.clone(), dir.join("store")))).unwrap();
        let fetcher = PartFetcher::new(tenant, bucket, store.clone(), trusted, cache).unwrap()
            .with_local_root(Some(dir.join("store")));
        let executor = NativeExecutor::start_named_with_mode(runtime.clone(), 1, "risk-read", ExecutorMode::ReadOnly).unwrap();
        let writer = NativeExecutor::start_named_with_mode(runtime.clone(), 1, "risk-write", ExecutorMode::ReadWrite).unwrap();
        let compiler = std::env::var("NANO_RISK_TEST_COMPILER")
            .expect("connected native risk proof requires NANO_RISK_TEST_COMPILER");
        let engine = PartQueryEngine::new(EngineSettings {
            tenant_id: tenant.into(), bucket: bucket.into(), compiler: compiler.into(),
            max_query_bytes: 64 * 1024 * 1024, max_memory_bytes: 512 * 1024 * 1024,
            max_execution_seconds: 30, threads: 1,
        }, store, view, fetcher, executor).unwrap().with_writer(writer);
        let request = RiskRequest {
            request_id: "drain-to-risk".into(), tenant_id: tenant.into(), risk_operation: "leaderboard".into(),
            anchor_us: now_ms * 1_000 + 1_000_000,
            decay: RiskDecay { decay_0_24h: 1.0, decay_1_3d: 0.7, decay_3_5d: 0.4, decay_5_7d: 0.2 },
            clear_boundaries: Default::default(), watch_weights: Default::default(), minimum_clear_revision: None,
            deny_source_types: vec![], window: Some("24h".into()), entity_type_filter: None,
            min_score: None, max_score: None, min_score_24h: None, min_score_7d: None,
            limit: None, offset: None, entities: vec![], lookback_days: None, suggest_patterns: Vec::new(),
        };
        let state = dir.join(format!("risk-state-{tenant}"));
        std::fs::create_dir_all(&state).unwrap();
        let response = read_risk(&engine, &state, &request).await.unwrap();
        assert_eq!(response["result"]["rows"][0]["entity"], "alice@example.com");
        assert_eq!(response["result"]["rows"][0]["decayed_score_24h"], 75);
        let anchor_us = request.anchor_us;
        let start = chrono::DateTime::from_timestamp_micros(anchor_us - 7 * 86_400_000_000)
            .unwrap().to_rfc3339();
        let end = chrono::DateTime::from_timestamp_micros(anchor_us).unwrap().to_rfc3339();
        let mut npl = BroadNplRequest {
            request_id: "drain-to-risk-npl".into(), tenant_id: tenant.into(),
            dataset: "risk".into(),
            query: "* | where score_24h > 70 | table entity, entity_type, score_24h, findings_24h".into(),
            start, end, limit: 10, offset: 0, table_view: false, use_cache: false,
            cursor_time: None, cursor_event_uid: None,
            anchor_us: Some(anchor_us), decay: Some(request.decay.clone()),
            clear_boundaries: Default::default(), watch_weights: Default::default(), minimum_clear_revision: None,
            deny_source_types: Default::default(),
        };
        let result = read_risk_npl(&engine, &state, &npl).await.unwrap();
        assert_eq!(result["result"]["result_rows"], 1);
        assert_eq!(result["result"]["rows"][0]["entity"], "alice@example.com");
        assert_eq!(result["result"]["rows"][0]["score_24h"], 75);
        assert_eq!(result["result"]["rows"][0]["findings_24h"], 1);
        npl.query = "* | where score_24h > 500 | table entity, score_24h".into();
        assert_eq!(read_risk_npl(&engine, &state, &npl).await.unwrap()["result"]["result_rows"], 0);
        verify_findings_search(&engine, tenant, &npl).await;
        npl.tenant_id = if tenant == A { B } else { A }.into();
        assert!(read_risk_npl(&engine, &state, &npl).await.is_err());
        let mut foreign = request;
        foreign.tenant_id = if tenant == A { B } else { A }.into();
        assert!(read_risk(&engine, &state, &foreign).await.is_err());
    }
}

/// NAN-2959: the drained finding is searchable in the tenant's own `logs`
/// dataset with the ClickHouse product's syntax (`source_type=findings`, the
/// `signal_type` filter and the alert pivot), and only there: the other
/// tenant's finding never appears, and a request naming the other tenant is
/// refused by this tenant's query process.
async fn verify_findings_search(engine: &PartQueryEngine, tenant: &str, risk_npl: &BroadNplRequest) {
    let foreign = if tenant == A { B } else { A };
    let mut request = risk_npl.clone();
    request.request_id = "findings-search".into();
    request.dataset = "logs".into();
    request.anchor_us = None;
    request.decay = None;
    let run = |query: String| {
        let mut request = request.clone();
        request.query = query;
        async move { engine.broad_npl(&request).await.unwrap() }
    };
    let rows = run("source_type=findings | table metadata.tenant_uid, metadata.uid, metadata.log_source".into()).await;
    assert_eq!(rows["result"]["result_rows"], 1, "{tenant}: {rows}");
    assert_eq!(rows["result"]["rows"][0]["metadata.tenant_uid"], tenant);
    assert_eq!(rows["result"]["rows"][0]["metadata.uid"], "finding-1");
    assert_eq!(rows["result"]["rows"][0]["metadata.log_source"], "findings");
    let alerts = run("source_type=findings finding_info.types=alert | table finding_info.uid_alt".into()).await;
    assert_eq!(alerts["result"]["result_rows"], 1, "{tenant}: {alerts}");
    assert_eq!(alerts["result"]["rows"][0]["finding_info.uid_alt"], format!("alert-{tenant}"));
    // NAN-3224: the `risk` alias selects the tenant's scored findings.
    let risk = run("metadata.log_source=risk | stats count() as n".into()).await;
    assert_eq!(risk["result"]["rows"][0]["n"], 1, "{tenant}: {risk}");
    let counted = run("source_type=findings | stats count() as n by metadata.tenant_uid".into()).await;
    assert_eq!(counted["result"]["result_rows"], 1, "{tenant}: {counted}");
    assert_eq!(counted["result"]["rows"][0]["metadata.tenant_uid"], tenant);
    let crossed = run(format!("source_type=findings metadata.tenant_uid=\"{foreign}\" | stats count() as n")).await;
    assert_eq!(crossed["result"]["rows"][0]["n"], 0, "{tenant} saw {foreign}'s finding: {crossed}");
    let crossed_alert = run(format!("finding_info.uid_alt=\"alert-{foreign}\" | stats count() as n")).await;
    assert_eq!(crossed_alert["result"]["rows"][0]["n"], 0, "{tenant} saw {foreign}'s alert: {crossed_alert}");
    let mut spoofed = request.clone();
    spoofed.tenant_id = foreign.into();
    spoofed.query = "source_type=findings".into();
    assert!(engine.broad_npl(&spoofed).await.is_err(), "{tenant}'s query process served {foreign}");
}

#[tokio::test]
async fn two_tenants_commit_before_ack_and_replay() {
    let Ok(admin_url) = std::env::var("NANO_RISK_TEST_PG") else { return };
    assert!(admin_url.starts_with("postgres://postgres@127.0.0.1:") && admin_url.ends_with("/risktest"),
        "finding drain test requires a loopback disposable risktest database");
    let admin = PgPoolOptions::new().max_connections(2).connect(&admin_url).await.unwrap();
    setup(&admin).await;
    let a = PgPoolOptions::new().max_connections(1).connect_with(tenant_pool(&admin_url, "risk_drain_a")).await.unwrap();
    let b = PgPoolOptions::new().max_connections(1).connect_with(tenant_pool(&admin_url, "risk_drain_b")).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
    let signer_a = LocalPartSigner::new("lab-risk-a", SigningKey::from_bytes(&[3; 32])).unwrap();
    let signer_b = LocalPartSigner::new("lab-risk-b", SigningKey::from_bytes(&[4; 32])).unwrap();
    // Real time: attempt markers are listed from the receipts' Last-Modified
    // (NAN-4181), so a fixed past clock hid the crash marker and the restart
    // re-sent a committed finding (the writer refused the double consume).
    let now_ms = chrono::Utc::now().timestamp_millis();
    let queue_a = SpoolQueue::new(dir.path().join("spool-a"), A).unwrap();
    let queue_b = SpoolQueue::new(dir.path().join("spool-b"), B).unwrap();
    let mut append_a = fixture_append(A, dir.path(), &store, &queue_a, &signer_a, now_ms).await;
    let append_b = fixture_append(B, dir.path(), &store, &queue_b, &signer_b, now_ms).await;

    assert!(drain_once(&a, &store, &signer_a, &signer_a.trusted(), B, 1, &append_a, &dir.path().join("b-wrong"), now_ms).await.is_err());
    let pending_b: i64 = sqlx::query_scalar("SELECT count(*) FROM detection_finding_lake_outbox WHERE tenant_id = $1 AND event_published_at IS NULL")
        .bind(B).fetch_one(&admin).await.unwrap();
    assert_eq!(pending_b, 1);

    sqlx::query("CREATE FUNCTION fail_risk_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected ack failure'; END $$")
        .execute(&admin).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_risk_ack BEFORE UPDATE ON detection_finding_lake_outbox FOR EACH ROW WHEN (NEW.tenant_id = '00000000-0000-4000-8000-000000000001') EXECUTE FUNCTION fail_risk_ack()")
        .execute(&admin).await.unwrap();
    assert!(drain_once(&a, &store, &signer_a, &signer_a.trusted(), A, 1, &append_a, &dir.path().join("a"), now_ms).await.is_err());
    let (compact, event): (serde_json::Value, serde_json::Value) = sqlx::query_as(
        "SELECT compact_finding, ocsf_event FROM detection_finding_lake_outbox WHERE tenant_id = $1 AND finding_id = 'finding-1' AND event_published_at IS NULL AND event_snapshot_id IS NULL")
        .bind(A).fetch_one(&admin).await.unwrap();
    assert_eq!(compact["id"], "finding-1", "tenant A must remain unacknowledged after failed ACK");
    let source = FindingReceipt::new(A, "finding-1", &compact, &event).unwrap().source().unwrap();
    let committed = committed_receipts(&store, A, &[source], &signer_a.trusted()).await.unwrap();
    assert_eq!(committed.len(), 1, "tenant A's signed Add must precede failed ACK");
    sqlx::query("DROP TRIGGER fail_risk_ack ON detection_finding_lake_outbox").execute(&admin).await.unwrap();
    drop(append_a);
    append_a = fixture_append(A, dir.path(), &store, &queue_a, &signer_a, now_ms + 1).await;
    assert_eq!(drain_once(&a, &store, &signer_a, &signer_a.trusted(), A, 1, &append_a, &dir.path().join("a-restart"), now_ms + 1).await.unwrap(), 1);
    assert_eq!(drain_once(&b, &store, &signer_b, &signer_b.trusted(), B, 1, &append_b, &dir.path().join("b"), now_ms + 2).await.unwrap(), 1);
    assert_eq!(drain_once(&a, &store, &signer_a, &signer_a.trusted(), A, 1, &append_a, &dir.path().join("a-again"), now_ms + 3).await.unwrap(), 0);

    for tenant in [A, B] {
        let mut adds = 0;
        for seq in 0..5 {
            let key = format!("lake/parts/v1/tenant={tenant}/log/entries/{seq:020}.json");
            let Some(bytes) = store.get(&key).await.unwrap() else { break };
            let entry = LogEntry::parse_bytes(&bytes, tenant).unwrap();
            if let LogOp::Add { parts, consumed, .. } = entry.op {
                adds += 1;
                assert_eq!(consumed.len(), 1, "one tenant receipt per finding add");
                assert!(consumed[0].key.starts_with(&format!("lake/parts/v1/tenant={tenant}/finding-outbox/receipts/")));
                assert_eq!(parts.len(), 1);
                let part = &parts[0];
                let keys = PartKeys::new(tenant, part.level, part.event_hour, &part.part_id).unwrap();
                let signed_bytes = store.get(&keys.provenance()).await.unwrap().unwrap();
                let trusted = if tenant == A { signer_a.trusted() } else { signer_b.trusted() };
                let signed = SignedProvenance::verify_bytes(&signed_bytes, tenant, &trusted).unwrap();
                assert_eq!(signed.record.tenant_id, tenant);
                assert_eq!(part.rows, 1);
                let risk = signed.record.files.partials.iter().find(|file| file.kind == PartialKind::Risk)
                    .expect("finding part must contain a signed risk partial");
                assert_eq!(risk.rows, 1);
                let risk_bytes = store.get(&keys.file(&risk.name)).await.unwrap().expect("signed risk partial must exist");
                assert_eq!(risk_bytes.len() as u64, risk.bytes);
                assert_eq!(hex::encode(Sha256::digest(&risk_bytes)), risk.sha256);
                let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(risk_bytes))
                    .unwrap().build().unwrap();
                let batch = reader.next().unwrap().unwrap();
                assert_eq!(batch.num_rows(), 1);
                let entity = batch.column_by_name("entity").unwrap()
                    .as_any().downcast_ref::<arrow_array::StringArray>().unwrap();
                let score = batch.column_by_name("risk_score_sum").unwrap()
                    .as_any().downcast_ref::<arrow_array::Int64Array>().unwrap();
                assert_eq!(entity.value(0), "alice@example.com");
                assert_eq!(score.value(0), 75);
            }
        }
        assert_eq!(adds, 1, "one signed finding add per tenant after replay");
    }
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT tenant_id, event_snapshot_id FROM detection_finding_lake_outbox ORDER BY tenant_id")
        .fetch_all(&admin).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|(_, head)| head.starts_with("parts:")));
    assert_ne!(rows[0].1, rows[1].1);
    if std::env::var_os("NANO_CHDB_LIBRARY_PATH").is_some() {
        verify_native_risk_read(dir.path(), &signer_a, &signer_b, now_ms).await;
    }
}
