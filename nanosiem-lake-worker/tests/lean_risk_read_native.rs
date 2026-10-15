// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real chDB parity over two isolated finding ledgers. The local Parquet input
//! has the exact schema materialized from signed finding parts by query[T].

use nanosiem_lake_worker::config::LoadedRiskSnapshotConfig;
use nanosiem_lake_worker::executor::NativeExecutor;
use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::part_query::risk::FINDING_STRUCTURE;
use nanosiem_lake_worker::planner::{ObjectStoreCredentials, TenantQueryConfig};
use nanosiem_lake_worker::risk::{RiskDecay, RiskRequest, RiskService};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

const A: &str = "00000000-0000-4000-8000-000000000001";
const B: &str = "00000000-0000-4000-8000-000000000002";

fn tenant(id: &str) -> TenantQueryConfig {
    TenantQueryConfig {
        tenant_id: id.into(),
        source: String::new(),
        iceberg_metadata_file_path: String::new(),
        max_query_bytes: 10_000_000,
        max_memory_bytes: 512_000_000,
        max_execution_seconds: 30,
        threads: 1,
        credentials: ObjectStoreCredentials::DefaultChain,
        snapshot_cache: None,
    }
}

fn request(id: &str, anchor_us: i64, operation: &str) -> RiskRequest {
    RiskRequest {
        request_id: "lab-risk".into(),
        tenant_id: id.into(),
        risk_operation: operation.into(),
        anchor_us,
        decay: RiskDecay {
            decay_0_24h: 1.0,
            decay_1_3d: 0.7,
            decay_3_5d: 0.4,
            decay_5_7d: 0.2,
        },
        clear_boundaries: BTreeMap::new(),
        watch_weights: Default::default(),
        minimum_clear_revision: None,
        deny_source_types: vec![],
        window: Some("24h".into()),
        entity_type_filter: None,
        min_score: None,
        max_score: None,
        min_score_24h: None,
        min_score_7d: None,
        limit: None,
        offset: None,
        entities: vec![],
        lookback_days: None,
        suggest_patterns: Vec::new(),
    }
}

fn service(path: &Path, id: &str) -> RiskService {
    let metadata = std::fs::metadata(path).unwrap();
    RiskService::new(LoadedRiskSnapshotConfig {
        snapshot_id: format!("lab-{id}"),
        snapshot_version: "v1".into(),
        source: path.into(),
        bytes: metadata.len(),
        modified: metadata.modified().unwrap(),
        clear_snapshot_version: None,
        clear_source: None,
        clear_bytes: 0,
        clear_modified: None,
        clear_published_revision: 0,
        global_clear_us: 0,
    })
}

#[tokio::test]
#[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
async fn ui_and_dataset_risk_share_tenant_scoped_finding_history() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let dir = tempfile::tempdir().unwrap();
    let connection = runtime.connect(&[]).unwrap();
    let anchor_us = 1_790_444_800_000_000_i64;
    let mut ledgers = Vec::new();
    for (id, scores) in [(A, vec![400, 200, 0]), (B, vec![20])] {
        let input = dir.path().join(format!("{id}.jsonl"));
        let output = dir.path().join(format!("{id}.parquet"));
        let rows = scores
            .into_iter()
            .enumerate()
            .map(|(index, score)| {
                json!({
            "id": format!("finding-{index}"), "timestamp_us": anchor_us - 1_000_000 - index as i64,
            "entity": "alice@example.com", "stamped_entity_type": "email",
            "risk_score": score, "rule_id": if score == 0 { "notable" } else { "detection" },
            "rule_name": "lab", "severity": "high", "origin_source_types": ["auth"],
            "mitre_tactics": ["credential_access"]
        }).to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&input, format!("{rows}\n")).unwrap();
        connection
            .query_with_params(
                "INSERT INTO FUNCTION file({output:String}, Parquet, {schema:String}) \
             SELECT * FROM file({input:String}, JSONEachRow, {schema:String})",
                "JSONEachRow",
                &[
                    ("output", output.to_str().unwrap()),
                    ("input", input.to_str().unwrap()),
                    ("schema", FINDING_STRUCTURE),
                ],
            )
            .unwrap();
        ledgers.push((id, output));
    }
    drop(connection);
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    for (id, path) in ledgers {
        let risk = service(&path, id);
        let foreign = if id == A { B } else { A };
        assert!(risk
            .execute(&executor, &tenant(id), &request(foreign, anchor_us, "leaderboard"))
            .await
            .is_err(), "a foreign request cannot read this tenant's ledger");
        let ui = risk
            .execute(
                &executor,
                &tenant(id),
                &request(id, anchor_us, "leaderboard"),
            )
            .await
            .unwrap();
        let rows = ui["result"]["rows"].as_array().unwrap();
        assert_eq!(
            rows.len(),
            1,
            "same entity is isolated by the assigned ledger"
        );
        let expected = if id == A { 600 } else { 20 };
        assert_eq!(rows[0]["entity"], "alice@example.com");
        assert_eq!(rows[0]["decayed_score_24h"], expected);
        assert_eq!(rows[0]["signal_count_24h"], if id == A { 3 } else { 1 });
        let (source, params, _) = risk
            .npl_source(&request(id, anchor_us, "leaderboard"))
            .unwrap();
        let output = executor.execute_sql(format!(
            "SELECT entity, entity_type, score_24h, raw_score_24h, findings_24h FROM {source} \
             SETTINGS max_threads=1, input_format_parquet_filter_push_down=0, optimize_move_to_prewhere=0"
        ), params).await.unwrap();
        let npl: Value = serde_json::from_slice(
            output
                .data
                .split(|byte| *byte == b'\n')
                .find(|line| !line.is_empty())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(npl["entity"], rows[0]["entity"]);
        assert_eq!(npl["entity_type"], rows[0]["entity_type"]);
        assert_eq!(npl["score_24h"], rows[0]["decayed_score_24h"]);
        assert_eq!(npl["raw_score_24h"], rows[0]["risk_score_24h"]);
        assert_eq!(npl["findings_24h"], rows[0]["signal_count_24h"]);
        assert_eq!(npl["score_24h"].as_i64().unwrap() > 500, id == A);

        let overview = risk
            .execute(&executor, &tenant(id), &request(id, anchor_us, "overview"))
            .await
            .unwrap();
        assert_eq!(overview["result"]["rows"][0]["total_entities"], 1);
        assert_eq!(
            overview["result"]["rows"][0]["total_signals"],
            if id == A { 3 } else { 1 }
        );

        let mut detail = request(id, anchor_us, "contributions");
        detail.entities = vec!["alice@example.com".into()];
        let contributions = risk.execute(&executor, &tenant(id), &detail).await.unwrap();
        let contributions = contributions["result"]["rows"].as_array().unwrap();
        assert_eq!(contributions.len(), if id == A { 2 } else { 1 });
        if id == A {
            assert_eq!(
                contributions
                    .iter()
                    .find(|row| row["rule_id"] == "notable")
                    .unwrap()["decayed_contribution_24h"],
                0
            );
        }

        let mut denied = request(id, anchor_us, "leaderboard");
        denied.deny_source_types = vec!["AUTH".into()];
        let scoped = risk.execute(&executor, &tenant(id), &denied).await.unwrap();
        assert_eq!(
            scoped["result"]["result_rows"], 0,
            "source scope must hide every auth finding"
        );
    }
}

/// Golden values come from the ClickHouse risk SQL contract: cutoffs are
/// inclusive, per-finding decay precedes rounding, and a clear excludes rows
/// at or before its timestamp. The two tenants deliberately share an entity.
#[tokio::test]
#[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
async fn fixed_time_decay_and_clears_are_tenant_local() {
    const DAY_US: i64 = 86_400_000_000;
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let dir = tempfile::tempdir().unwrap();
    let connection = runtime.connect(&[]).unwrap();
    let anchor_us = 1_790_444_800_000_000_i64;
    let fixtures = [
        (A, vec![(1, 100, "one"), (3, 50, "three"), (5, 25, "five"), (7, 10, "seven")]),
        (B, vec![(1, 90, "other")]),
    ];
    let mut ledgers = Vec::new();
    for (id, findings) in fixtures {
        let input = dir.path().join(format!("boundary-{id}.jsonl"));
        let output = dir.path().join(format!("boundary-{id}.parquet"));
        let rows = findings
            .into_iter()
            .map(|(age_days, score, name)| {
                json!({
                    "id": format!("{id}-{name}"),
                    "timestamp_us": anchor_us - age_days * DAY_US,
                    "entity": "shared@example.com", "stamped_entity_type": "email",
                    "risk_score": score, "rule_id": name, "rule_name": name,
                    "severity": "high", "origin_source_types": ["auth"],
                    "mitre_tactics": ["credential_access"]
                })
                .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&input, format!("{rows}\n")).unwrap();
        connection
            .query_with_params(
                "INSERT INTO FUNCTION file({output:String}, Parquet, {schema:String}) \
                 SELECT * FROM file({input:String}, JSONEachRow, {schema:String})",
                "JSONEachRow",
                &[
                    ("output", output.to_str().unwrap()),
                    ("input", input.to_str().unwrap()),
                    ("schema", FINDING_STRUCTURE),
                ],
            )
            .unwrap();
        ledgers.push((id, output));
    }
    drop(connection);
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    for (id, path) in ledgers {
        let risk = service(&path, id);
        let mut seven = request(id, anchor_us, "leaderboard");
        seven.window = Some("7d".into());
        let response = risk.execute(&executor, &tenant(id), &seven).await.unwrap();
        let row = &response["result"]["rows"][0];
        assert_eq!(row["entity"], "shared@example.com");
        assert_eq!(row["entity_type"], "email");
        if id == A {
            assert_eq!(row["risk_score_7d"], 185);
            assert_eq!(row["decayed_score_7d"], 147);
            assert_eq!(row["risk_score_24h"], 100);
            assert_eq!(row["signal_count_7d"], 4);
            assert_eq!(row["signal_count_24h"], 1);
            assert_eq!(row["distinct_rules_7d"], 4);
        } else {
            assert_eq!(row["risk_score_7d"], 90);
            assert_eq!(row["decayed_score_7d"], 90);
            assert_eq!(row["signal_count_7d"], 1);
        }

        seven.clear_boundaries.insert("shared@example.com".into(), anchor_us - 4 * DAY_US);
        let cleared = risk.execute(&executor, &tenant(id), &seven).await.unwrap();
        let row = &cleared["result"]["rows"][0];
        if id == A {
            assert_eq!(row["risk_score_7d"], 150);
            assert_eq!(row["decayed_score_7d"], 135);
            assert_eq!(row["signal_count_7d"], 2);
        } else {
            assert_eq!(row["risk_score_7d"], 90);
            assert_eq!(row["signal_count_7d"], 1);
        }
        let foreign = if id == A { B } else { A };
        assert!(risk.execute(&executor, &tenant(id), &request(foreign, anchor_us, "leaderboard")).await.is_err());
    }
}

// ---------------------------------------------------------------------------
// `| risk` over signed lean parts: source events go through the production
// part writer (PartWriter -> owner-signed publish_parts -> PartLogWriter Add)
// and are read back by query[T]'s PartQueryEngine with the pinned compiler.
// ---------------------------------------------------------------------------

mod lean_pipe_risk {
    use super::{A, B};
    use ed25519_dalek::SigningKey;
    use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
    use nanosiem_lake_worker::native::NativeChdb;
    use nanosiem_lake_worker::part_ingest::schema::{decode, infer_schema};
    use nanosiem_lake_worker::part_ingest::writer::{publish_parts, PartDraft, PartWriter, PartialSource};
    use nanosiem_lake_worker::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
    use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
    use nanosiem_lake_worker::part_query::log_view::PartLogView;
    use nanosiem_lake_worker::parts::format::schema_fingerprint;
    use nanosiem_lake_worker::parts::levels::Level;
    use nanosiem_lake_worker::parts::part_log::{LocalObjectStore, LogOp, ObjectStore, PartLogWriter, SourceRef};
    use nanosiem_lake_worker::parts::provenance::{Admission, LocalPartSigner, PartInputs, SourceObject};
    use nanosiem_lake_worker::parts::{event_hour_of, DedupWindow};
    use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    const BUCKET: &str = "pipe-risk-fixture";

    /// Tenant A: alice fails three times (severity 7), bob once (severity 30,
    /// scaled past the 100 clamp). Tenant B holds the same user names with
    /// distinct UIDs so any cross-tenant read changes every count.
    fn events(tenant: &str, time_us: i64) -> Vec<Value> {
        let rows: &[(&str, i64)] = if tenant == A {
            &[("alice", 7), ("alice", 7), ("alice", 7), ("bob", 30)]
        } else {
            &[("alice", 1)]
        };
        rows.iter().enumerate().map(|(index, (user, severity))| {
            let time = chrono::DateTime::from_timestamp_micros(time_us + index as i64).unwrap().to_rfc3339();
            json!({
                "time": time, "class_uid": 3002, "severity_id": severity,
                "message": format!("failed login {index}"),
                "metadata": {"uid": format!("{tenant}-login-{index}"), "tenant_uid": tenant, "log_source": "auth"},
                "actor": {"user": {"name": user}},
                "src_endpoint": {"ip": "10.9.8.7"}
            })
        }).collect()
    }

    async fn write_signed_source(tenant: &str, store_dir: &Path, work: &Path, signer: &LocalPartSigner, time_us: i64) {
        let events = events(tenant, time_us);
        let refs: Vec<&Value> = events.iter().collect();
        let schema = Arc::new(infer_schema(&refs).unwrap());
        let batch = decode(schema.clone(), &refs).unwrap();
        let source_key = format!("fixture/{tenant}/source.parquet");
        let draft = PartDraft {
            tenant_id: tenant.into(),
            signer_key_id: if tenant == A { "pipe-risk-a".into() } else { "pipe-risk-b".into() },
            level: Level::L0,
            event_hour: event_hour_of(time_us),
            schema_fingerprint: schema_fingerprint(&schema).unwrap(),
            schema,
            inputs: PartInputs::Sources {
                sources: vec![SourceObject {
                    key: source_key.clone(), version: "1".into(), bytes: 1,
                    sha256: "a".repeat(64), rows: events.len() as u64, edge_sha256: None,
                }],
                edge_log: None,
            },
            admission: Some(Admission {
                ocsf_version: "1.9.0".into(),
                admission_contract: "fixture-v1".into(),
                feed_pins: Default::default(),
            }),
            rows_in: events.len() as u64,
            duplicates_dropped: 0,
            window: DedupWindow::Exact,
            build: "pipe-risk-fixture".into(),
        };
        let mut writer = PartWriter::create(work, draft, PartialSource::FromRows, time_us / 1000, 1).unwrap();
        writer.write(&batch).unwrap();
        let finished = writer.finish().unwrap();
        let store = LocalObjectStore::new(store_dir).unwrap();
        let refs = publish_parts(&store, signer, &signer.trusted(), &[finished]).await.unwrap();
        assert_eq!(refs.len(), 1);
        let mut log = PartLogWriter::open(&store, tenant, 1, &batch.schema(), time_us / 1000).await.unwrap();
        log.append(LogOp::Add {
            parts: refs,
            consumed: vec![SourceRef { key: source_key, version: "1".into(), sha256: "a".repeat(64) }],
            edge_log: None,
        }, time_us / 1000 + 1).await.unwrap();
    }

    async fn engine(tenant: &str, dir: &Path, signer: &LocalPartSigner, runtime: &NativeChdb) -> PartQueryEngine {
        let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(dir.join("store")).unwrap());
        let trusted = signer.trusted();
        let view = PartLogView::open(store.as_ref(), tenant, trusted.clone()).await.unwrap();
        let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
            root: dir.join(format!("cache-{tenant}")), max_bytes: 64 * 1024 * 1024,
            query_max_bytes: 64 * 1024 * 1024, fetch_concurrency: 2,
            fetch_deadline: Duration::from_secs(30),
        }, tenant, BUCKET, &parts_key_prefix(tenant).unwrap(),
        Arc::new(StoreObjectSource::local(BUCKET, store.clone(), dir.join("store")))).unwrap();
        let fetcher = PartFetcher::new(tenant, BUCKET, store.clone(), trusted, cache).unwrap()
            .with_local_root(Some(dir.join("store")));
        let executor = NativeExecutor::start_named_with_mode(runtime.clone(), 1, "pipe-risk-read", ExecutorMode::ReadOnly).unwrap();
        let compiler = std::env::var("NANO_RISK_TEST_COMPILER")
            .expect("lean | risk proof requires the current build's NANO_RISK_TEST_COMPILER");
        PartQueryEngine::new(EngineSettings {
            tenant_id: tenant.into(), bucket: BUCKET.into(), compiler: compiler.into(),
            max_query_bytes: 64 * 1024 * 1024, max_memory_bytes: 512 * 1024 * 1024,
            max_execution_seconds: 30, threads: 1,
        }, store, view, fetcher, executor).unwrap()
    }

    fn npl(tenant: &str, query: &str, time_us: i64) -> BroadNplRequest {
        let at = |us: i64| chrono::DateTime::from_timestamp_micros(us).unwrap().to_rfc3339();
        BroadNplRequest {
            request_id: "lean-pipe-risk".into(), tenant_id: tenant.into(), dataset: "logs".into(),
            query: query.into(), start: at(time_us - 3_600_000_000), end: at(time_us + 3_600_000_000),
            limit: 100, offset: 0, table_view: false, use_cache: false,
            cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
            clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None,
            deny_source_types: Default::default(),
        }
    }

    fn rows(result: &Value) -> Vec<Value> {
        assert_eq!(result["source_mode"], "parts", "{result}");
        result["result"]["rows"].as_array().unwrap().clone()
    }

    fn by(rows: &[Value], key: &str, value: &str) -> Vec<Value> {
        rows.iter().filter(|row| row[key] == value).cloned().collect()
    }

    #[tokio::test]
    #[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256 and NANO_RISK_TEST_COMPILER"]
    async fn pipe_risk_literal_and_dynamic_over_signed_writer_parts() {
        let runtime = NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        std::mem::forget(runtime.clone());
        let dir = tempfile::tempdir().unwrap();
        let time_us = chrono::Utc::now().timestamp_micros() - 60_000_000;
        let signer_a = LocalPartSigner::new("pipe-risk-a", SigningKey::from_bytes(&[11; 32])).unwrap();
        let signer_b = LocalPartSigner::new("pipe-risk-b", SigningKey::from_bytes(&[12; 32])).unwrap();
        for (tenant, signer) in [(A, &signer_a), (B, &signer_b)] {
            let work = dir.path().join(format!("work-{tenant}"));
            std::fs::create_dir_all(&work).unwrap();
            write_signed_source(tenant, &dir.path().join("store"), &work, signer, time_us).await;
        }
        let a = engine(A, dir.path(), &signer_a, &runtime).await;
        let b = engine(B, dir.path(), &signer_b, &runtime).await;

        // Literal: every matching event carries the fixed score and the
        // event's own entity; the factor is the quoted literal.
        let literal = "class_uid=3002 | risk score=60 entity=actor.user.name factor=\"failed_login\"";
        let result = a.broad_npl(&npl(A, literal, time_us)).await.unwrap();
        let events = rows(&result);
        assert_eq!(events.len(), 4, "{result}");
        for row in &events {
            assert_eq!(row["risk_score"], 60, "{row}");
            assert_eq!(row["raw_risk_score"], 60, "{row}");
            assert_eq!(row["risk_factors"], json!(["failed_login"]), "{row}");
        }
        assert_eq!(by(&events, "risk_entity", "alice").len(), 3);
        assert_eq!(by(&events, "risk_entity", "bob").len(), 1);

        // Dynamic: the score is evaluated per result row (here after an
        // aggregation) and clamped to 0..=100.
        let dynamic = "class_uid=3002 | stats count() as hits, max(severity_id) as sev by actor.user.name \
                       | risk score=hits*sev entity=actor.user.name";
        let result = a.broad_npl(&npl(A, dynamic, time_us)).await.unwrap();
        let entities = rows(&result);
        assert_eq!(entities.len(), 2, "{result}");
        let alice = &by(&entities, "risk_entity", "alice")[0];
        assert_eq!((alice["hits"].as_i64(), alice["risk_score"].as_i64()), (Some(3), Some(21)), "{alice}");
        let bob = &by(&entities, "risk_entity", "bob")[0];
        assert_eq!((bob["hits"].as_i64(), bob["risk_score"].as_i64()), (Some(1), Some(30)), "{bob}");
        let clamped = "class_uid=3002 actor.user.name=\"bob\" | risk score=severity_id*10 entity=actor.user.name";
        let result = a.broad_npl(&npl(A, clamped, time_us)).await.unwrap();
        let bob = rows(&result);
        assert_eq!(bob.len(), 1, "{result}");
        assert_eq!(bob[0]["risk_score"], 100, "{}", bob[0]);

        // Tenant B's writer parts are its own: same query, same user name,
        // one event and B's severity only.
        let result = b.broad_npl(&npl(B, dynamic, time_us)).await.unwrap();
        let entities = rows(&result);
        assert_eq!(entities.len(), 1, "{result}");
        assert_eq!((entities[0]["risk_entity"].as_str(), entities[0]["risk_score"].as_i64()), (Some("alice"), Some(1)));
        assert!(a.broad_npl(&npl(B, literal, time_us)).await.is_err(), "foreign tenant request must be refused");
    }
}

/// Lean-shaped 7d history: 67,563 findings / 4,623 entities, with the measured
/// 43,730 findings / 4,618 entities in 24h. This measures the maintained local
/// ledger reads separately from HTTP/PG and cold signed-part materialization.
#[tokio::test]
#[ignore = "requires digest-verified chDB"]
async fn lean_shaped_risk_ledger_has_subsecond_warm_reads() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lean.parquet");
    let anchor_us = 1_790_444_800_000_000_i64;
    let connection = runtime.connect(&[]).unwrap();
    connection.query_with_params(
        "INSERT INTO FUNCTION file({output:String}, Parquet, {schema:String}) \
         SELECT concat('finding-', toString(number)) AS id, \
             {anchor:Int64} - if(number < 43730, 1000000, 172800000000) AS timestamp_us, \
             concat('host-', toString(number % if(number < 43730, 4618, 4623)), '.example.test') AS entity, \
             'hostname' AS stamped_entity_type, toInt64(number % 30 + 1) AS risk_score, \
             'rule-1' AS rule_id, 'fixture' AS rule_name, 'high' AS severity, \
             ['auth'] AS origin_source_types, ['execution'] AS mitre_tactics FROM numbers(67563)",
        "JSONEachRow", &[("output", path.to_str().unwrap()), ("schema", FINDING_STRUCTURE), ("anchor", &anchor_us.to_string())],
    ).unwrap();
    drop(connection);
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    let risk = service(&path, A);
    for (operation, window) in [("leaderboard", "24h"), ("scores", "24h"), ("overview", "24h"), ("overview", "7d"), ("entity_types", "7d")] {
        let mut request = request(A, anchor_us, operation);
        request.window = Some(window.into());
        request.limit = Some(50);
        let mut elapsed = Vec::new();
        for _ in 0..7 {
            let start = std::time::Instant::now();
            let result = risk.execute(&executor, &tenant(A), &request).await.unwrap();
            elapsed.push(start.elapsed());
            if operation == "overview" {
                assert_eq!(result["result"]["rows"][0]["total_entities"], if window == "24h" {4618} else {4623});
                assert_eq!(result["result"]["rows"][0]["total_signals"], if window == "24h" {43730} else {67563});
            }
        }
        elapsed.sort();
        println!("lean-shaped risk {operation}/{window} p50={:.3}s", elapsed[3].as_secs_f64());
        assert!(elapsed[3] < std::time::Duration::from_secs(1), "{operation}/{window}: {:?}", elapsed[3]);
    }
}

/// A sizeable maintained ledger must return actual overview and leaderboard
/// rows under a small scan budget, with exact 24h/7d parity. This exercises
/// the reader used by the fallback, without a production store or credentials.
#[tokio::test]
#[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
async fn large_maintained_ledger_returns_overview_and_entities_within_budget() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("large-risk.parquet");
    let anchor_us = 1_790_444_800_000_000_i64;
    let connection = runtime.connect(&[]).unwrap();
    connection.query_with_params(
        "INSERT INTO FUNCTION file({output:String}, Parquet, {schema:String}) \
         SELECT toString(number) AS id, {anchor:Int64} - if(number % 2 = 0, 1000000, 172800000000) AS timestamp_us, \
                concat('user-', toString(number % 1000)) AS entity, 'user' AS stamped_entity_type, \
                toInt64(10) AS risk_score, 'rule' AS rule_id, 'fixture' AS rule_name, 'low' AS severity, \
                ['auth'] AS origin_source_types, ['credential_access'] AS mitre_tactics FROM numbers(100000)",
        "JSONEachRow",
        &[("output", ledger.to_str().unwrap()), ("schema", FINDING_STRUCTURE), ("anchor", &anchor_us.to_string())],
    ).unwrap();
    drop(connection);
    let risk = service(&ledger, A);
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    let budget = tenant(A);
    assert!(std::fs::metadata(&ledger).unwrap().len() < budget.max_query_bytes);
    for (window, entities, signals) in [("24h", 500, 50_000), ("7d", 1000, 100_000)] {
        let mut query = request(A, anchor_us, "overview");
        query.window = Some(window.into());
        let overview = risk.execute(&executor, &budget, &query).await.unwrap();
        let row = &overview["result"]["rows"][0];
        assert_eq!(row["total_entities"], entities);
        assert_eq!(row["total_signals"], signals);
        query.risk_operation = "leaderboard".into();
        query.limit = Some(1000);
        let page = risk.execute(&executor, &budget, &query).await.unwrap();
        let rows = page["result"]["rows"].as_array().unwrap();
        assert_eq!(rows.len(), entities as usize);
        let count_field = if window == "24h" { "signal_count_24h" } else { "signal_count_7d" };
        assert_eq!(rows.iter().map(|row| row[count_field].as_i64().unwrap()).sum::<i64>(), signals);
    }
}

/// NAN-3225: the timeline buckets fold (core `build_timeline`) to exactly the
/// `contributions` answer at the anchor, and a restricted caller's buckets
/// carry no finding from a denied source — no bucket, marker or score leaks.
#[tokio::test]
#[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
async fn timeline_buckets_fold_to_contributions_and_hide_denied_sources() {
    use nanosiem_core::risk::timeline::{build_timeline, RiskTimelineBucket};
    use nanosiem_core::risk::RiskDecayConfig;
    const HOUR_US: i64 = 3_600_000_000;
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let dir = tempfile::tempdir().unwrap();
    let connection = runtime.connect(&[]).unwrap();
    let anchor_us = 1_790_444_800_000_000_i64;
    // (age, score, rule, origin): band edges, two rules, two origins, one
    // finding past the 7d window but inside the 14d lookback.
    let findings = [
        (1, 40, "brute", "auth"),
        (24 * HOUR_US, 30, "brute", "auth"),
        (24 * HOUR_US + 1, 30, "brute", "auth"),
        (80 * HOUR_US, 70, "web", "apache_access"),
        (167 * HOUR_US + 5, 20, "brute", "auth"),
        (200 * HOUR_US, 90, "web", "apache_access"),
    ];
    let input = dir.path().join("timeline.jsonl");
    let output = dir.path().join("timeline.parquet");
    let rows = findings
        .iter()
        .enumerate()
        .map(|(index, (age, score, rule, origin))| {
            json!({
                "id": format!("f-{index}"), "timestamp_us": anchor_us - age,
                "entity": "alice@example.com", "stamped_entity_type": "email",
                "risk_score": score, "rule_id": rule, "rule_name": rule, "severity": "high",
                "origin_source_types": [origin],
                "mitre_tactics": [if *rule == "web" { "initial_access" } else { "credential_access" }]
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&input, format!("{rows}\n")).unwrap();
    connection
        .query_with_params(
            "INSERT INTO FUNCTION file({output:String}, Parquet, {schema:String}) \
             SELECT * FROM file({input:String}, JSONEachRow, {schema:String})",
            "JSONEachRow",
            &[
                ("output", output.to_str().unwrap()),
                ("input", input.to_str().unwrap()),
                ("schema", FINDING_STRUCTURE),
            ],
        )
        .unwrap();
    drop(connection);
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    let risk = service(&output, A);
    let decay = RiskDecayConfig {
        decay_0_24h: 1.0,
        decay_1_3d: 0.7,
        decay_3_5d: 0.4,
        decay_5_7d: 0.2,
    };

    let read = |deny: Vec<String>, operation: &str| {
        let mut request = request(A, anchor_us, operation);
        request.entities = vec!["alice@example.com".into()];
        request.deny_source_types = deny;
        if operation == "timeline" {
            request.lookback_days = Some(14);
            request.limit = Some(10_000);
        }
        let risk = &risk;
        let executor = &executor;
        async move {
            let value = risk.execute(executor, &tenant(A), &request).await.unwrap();
            value["result"]["rows"].as_array().cloned().unwrap_or_default()
        }
    };
    let fold = |rows: &[Value]| {
        let buckets: Vec<RiskTimelineBucket> = rows
            .iter()
            .map(|row| serde_json::from_value(row.clone()).unwrap())
            .collect();
        let anchor = chrono::DateTime::from_timestamp_micros(anchor_us).unwrap();
        build_timeline(anchor, &decay, &buckets, false)
    };

    // Unrestricted: the anchor point and per-rule contributions equal the
    // `contributions` reader byte-for-byte.
    let buckets = read(vec![], "timeline").await;
    assert!(buckets.iter().any(|row| row["rule_id"] == "web"));
    let timeline = fold(&buckets);
    let contributions = read(vec![], "contributions").await;
    for row in &contributions {
        let folded = timeline
            .contributions
            .iter()
            .find(|c| c.rule_id == row["rule_id"].as_str().unwrap())
            .unwrap();
        assert_eq!(folded.decayed_contribution_7d, row["decayed_contribution_7d"].as_i64().unwrap());
        assert_eq!(folded.decayed_contribution_24h, row["decayed_contribution_24h"].as_i64().unwrap());
        assert_eq!(folded.fires_7d, row["fires_7d"].as_i64().unwrap());
    }
    let total: i64 = contributions.iter().map(|row| row["decayed_contribution_7d"].as_i64().unwrap()).sum();
    assert_eq!(timeline.points.last().unwrap().score, total);
    let web = buckets.iter().find(|row| row["rule_id"] == "web").unwrap();
    assert_eq!(web["mitre_tactics"], json!(["initial_access"]));

    // Restricted to everything but apache_access: no web bucket, marker,
    // contribution or score survives anywhere in the series.
    let scoped = read(vec!["apache_access".into()], "timeline").await;
    assert!(!scoped.is_empty());
    assert!(scoped.iter().all(|row| row["rule_id"] == "brute"), "{scoped:?}");
    let scoped_timeline = fold(&scoped);
    assert!(scoped_timeline.markers.iter().all(|m| m.rule_id == "brute"));
    assert!(scoped_timeline.contributions.iter().all(|c| c.rule_id == "brute"));
    let brute_only = read(vec!["apache_access".into()], "contributions").await;
    assert_eq!(
        scoped_timeline.points.last().unwrap().score,
        brute_only.iter().map(|row| row["decayed_contribution_7d"].as_i64().unwrap()).sum::<i64>()
    );
    // Denying every origin leaves nothing to fold.
    assert!(read(vec!["auth".into(), "apache_access".into()], "timeline").await.is_empty());
}

/// NAN-3228: watchlist weights amplify at read time in the entity grain, so
/// the leaderboard floor/order, the badge, the overview bands and the
/// `dataset=risk` nPL source (the notable rule's input) all see the
/// effective score while the base score stays alongside it.
#[tokio::test]
#[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
async fn watchlist_weights_amplify_every_score_read() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let dir = tempfile::tempdir().unwrap();
    let connection = runtime.connect(&[]).unwrap();
    let anchor_us = 1_790_444_800_000_000_i64;
    let input = dir.path().join("watch.jsonl");
    let output = dir.path().join("watch.parquet");
    let rows = [("Watched.User", 60), ("plain.user", 80)]
        .into_iter()
        .enumerate()
        .map(|(index, (entity, score))| {
            json!({
                "id": format!("w-{index}"), "timestamp_us": anchor_us - 1_000_000,
                "entity": entity, "stamped_entity_type": "user",
                "risk_score": score, "rule_id": "r", "rule_name": "r", "severity": "high",
                "origin_source_types": ["auth"], "mitre_tactics": []
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&input, format!("{rows}\n")).unwrap();
    connection
        .query_with_params(
            "INSERT INTO FUNCTION file({output:String}, Parquet, {schema:String}) \
             SELECT * FROM file({input:String}, JSONEachRow, {schema:String})",
            "JSONEachRow",
            &[
                ("output", output.to_str().unwrap()),
                ("input", input.to_str().unwrap()),
                ("schema", FINDING_STRUCTURE),
            ],
        )
        .unwrap();
    drop(connection);
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    let risk = service(&output, A);
    let weighted = |operation: &str| {
        let mut request = request(A, anchor_us, operation);
        // Lowercased key matches the mixed-case ledger entity.
        request.watch_weights = BTreeMap::from([("watched.user".to_string(), 0.6)]);
        request
    };

    // Unweighted: plain.user (80) outranks watched (60).
    let base = risk.execute(&executor, &tenant(A), &request(A, anchor_us, "leaderboard")).await.unwrap();
    assert_eq!(base["result"]["rows"][0]["entity"], "plain.user");
    assert_eq!(base["result"]["rows"][0]["watch_weight"], 0.0);

    // Weighted: 60 x 1.6 = 96 now leads; base stays visible.
    let ranked = risk.execute(&executor, &tenant(A), &weighted("leaderboard")).await.unwrap();
    let rows = ranked["result"]["rows"].as_array().unwrap();
    assert_eq!(rows[0]["entity"], "Watched.User");
    assert_eq!(rows[0]["decayed_score_24h"], 96);
    assert_eq!(rows[0]["base_decayed_score_24h"], 60);
    assert_eq!(rows[0]["watch_weight"], 0.6);
    assert_eq!(rows[1]["decayed_score_24h"], 80, "unwatched entities are unchanged");

    // The floor applies to the effective score.
    let mut floor = weighted("leaderboard");
    floor.min_score = Some(90);
    let floored = risk.execute(&executor, &tenant(A), &floor).await.unwrap();
    assert_eq!(floored["result"]["result_rows"], 1);
    assert_eq!(floored["result"]["rows"][0]["entity"], "Watched.User");

    // Member-score selection: lowercased entity set.
    let mut members = weighted("leaderboard");
    members.window = Some("7d".into());
    members.entities = vec!["watched.user".into()];
    let selected = risk.execute(&executor, &tenant(A), &members).await.unwrap();
    assert_eq!(selected["result"]["result_rows"], 1);

    // Overview bands count the effective score (96 is critical).
    let overview = risk.execute(&executor, &tenant(A), &weighted("overview")).await.unwrap();
    assert_eq!(overview["result"]["rows"][0]["critical_entities"], 2);

    // dataset=risk sees the effective score: a 90 notable threshold fires for
    // the watched entity only.
    let (source, params, _) = risk.npl_source(&weighted("leaderboard")).unwrap();
    let output = executor
        .execute_sql(
            format!(
                "SELECT entity, score_24h FROM {source} WHERE score_24h > 90 \
                 SETTINGS max_threads=1, input_format_parquet_filter_push_down=0, optimize_move_to_prewhere=0"
            ),
            params,
        )
        .await
        .unwrap();
    let hits: Vec<Value> = output
        .data
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["entity"], "Watched.User");
    assert_eq!(hits[0]["score_24h"], 96);

    // Out-of-range weights are refused.
    let mut bad = weighted("leaderboard");
    bad.watch_weights.insert("x".into(), 1.5);
    assert!(risk.execute(&executor, &tenant(A), &bad).await.is_err());
}

/// NAN-3249: real chDB over a finding ledger — the suggest operation returns
/// the observed variants of each typed value (domain user, UPN, FQDN, short
/// name), the exact sighting that sets `seen`, treats `%` / `_` literally,
/// caps rows per value, ignores findings outside the 28d window, is
/// tenant-pinned, and hides denied-source findings.
#[tokio::test]
#[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
async fn suggest_finds_observed_variants_under_source_scope() {
    use nanosiem_core::risk::watchlist_suggest::{
        assemble, plan, RiskSuggestRow, SuggestInput, SuggestMatchKind, SUGGEST_ROWS_PER_VALUE,
    };
    const DAY_US: i64 = 86_400_000_000;
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let dir = tempfile::tempdir().unwrap();
    let connection = runtime.connect(&[]).unwrap();
    let anchor_us = 1_790_444_800_000_000_i64;
    let mut findings: Vec<(&str, i64, &str)> = vec![
        ("CORP\\JSmith", 2, "auth"),
        ("jsmith@corp.com", 1, "auth"),
        ("JSmith", 3, "apache_access"),
        ("web01", 4, "auth"),
        ("db02.corp.local", 5, "auth"),
        ("axb", 1, "auth"),
        ("corp\\a_b", 1, "auth"),
        // Outside the 28-day window: never suggested.
        ("old\\jsmith", 40, "auth"),
    ];
    let many: Vec<String> = (0..30).map(|i| format!("svc@d{i}.io")).collect();
    for entity in &many {
        findings.push((entity.as_str(), 1, "auth"));
    }
    let input = dir.path().join("suggest.jsonl");
    let output = dir.path().join("suggest.parquet");
    let rows = findings
        .iter()
        .enumerate()
        .map(|(index, (entity, age_days, origin))| {
            json!({
                "id": format!("finding-{index}"), "timestamp_us": anchor_us - age_days * DAY_US,
                "entity": entity, "stamped_entity_type": "",
                "risk_score": 10, "rule_id": "r", "rule_name": "r", "severity": "high",
                "origin_source_types": [origin], "mitre_tactics": []
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&input, format!("{rows}\n")).unwrap();
    connection
        .query_with_params(
            "INSERT INTO FUNCTION file({output:String}, Parquet, {schema:String}) \
             SELECT * FROM file({input:String}, JSONEachRow, {schema:String})",
            "JSONEachRow",
            &[
                ("output", output.to_str().unwrap()),
                ("input", input.to_str().unwrap()),
                ("schema", FINDING_STRUCTURE),
            ],
        )
        .unwrap();
    drop(connection);
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    let risk = service(&output, A);
    let plan = plan(&[
        SuggestInput { value: "jsmith".into(), entity_type: None },
        SuggestInput { value: "web01.corp.local".into(), entity_type: None },
        SuggestInput { value: "db02".into(), entity_type: None },
        SuggestInput { value: "a_b".into(), entity_type: None },
        SuggestInput { value: "ghost".into(), entity_type: None },
        SuggestInput { value: "svc".into(), entity_type: None },
        SuggestInput { value: "svc1".into(), entity_type: None },
    ])
    .unwrap();
    let read = |deny: Vec<String>, tenant_id: &'static str| {
        let mut request = request(tenant_id, anchor_us, "suggest");
        request.window = None;
        request.lookback_days = Some(28);
        request.deny_source_types = deny;
        request.suggest_patterns = plan.patterns.clone();
        let risk = &risk;
        let executor = &executor;
        async move { risk.execute(executor, &tenant(A), &request).await }
    };
    assert!(read(vec![], B).await.is_err(), "a foreign request cannot read this tenant's ledger");
    let rows_of = |value: Value| -> Vec<RiskSuggestRow> {
        serde_json::from_value(value["result"]["rows"].clone()).unwrap()
    };
    let rows = rows_of(read(vec![], A).await.unwrap());
    for index in 0..plan.values.len() {
        let count = rows.iter().filter(|row| row.value_index as usize == index).count();
        assert!(count as u64 <= SUGGEST_ROWS_PER_VALUE, "value {index} returned {count} rows");
    }
    let results = assemble(&plan, &rows);
    let jsmith = &results[0];
    assert!(jsmith.seen, "{jsmith:?}");
    let variants: Vec<(&str, SuggestMatchKind)> =
        jsmith.suggestions.iter().map(|s| (s.value.as_str(), s.match_kind)).collect();
    assert_eq!(
        variants,
        vec![("jsmith@corp.com", SuggestMatchKind::UserPrincipal), ("corp\\jsmith", SuggestMatchKind::DomainUser)]
    );
    assert_eq!(jsmith.suggestions[0].entity_type, "email");
    let web = &results[1];
    assert!(!web.seen);
    assert_eq!(web.suggestions[0].value, "web01");
    assert_eq!(web.suggestions[0].match_kind, SuggestMatchKind::ShortName);
    let db = &results[2];
    assert!(!db.seen);
    assert_eq!(db.suggestions[0].value, "db02.corp.local");
    assert_eq!(db.suggestions[0].match_kind, SuggestMatchKind::Fqdn);
    assert_eq!(db.suggestions[0].entity_type, "hostname");
    let a_b = &results[3];
    assert!(!a_b.seen, "`_` is literal: axb is not a_b");
    assert_eq!(a_b.suggestions.iter().map(|s| s.value.as_str()).collect::<Vec<_>>(), vec!["corp\\a_b"]);
    assert!(!results[4].seen && results[4].suggestions.is_empty());
    assert!(!results[5].seen);
    assert_eq!(results[5].suggestions.len(), 10, "variants per value are capped");
    assert!(results[5].suggestions.iter().all(|s| s.match_kind == SuggestMatchKind::UserPrincipal));
    assert!(results[6].suggestions.is_empty(), "svc1 is not a prefix of svc@…");

    // Source scope: hiding apache_access hides the only exact jsmith finding.
    let scoped = assemble(&plan, &rows_of(read(vec!["APACHE_ACCESS".into()], A).await.unwrap()));
    assert!(!scoped[0].seen, "denied-source findings never set seen");
    assert_eq!(scoped[0].suggestions.len(), 2);
    let hidden = assemble(&plan, &rows_of(read(vec!["auth".into()], A).await.unwrap()));
    assert!(hidden[0].seen);
    assert!(hidden.iter().all(|r| r.suggestions.is_empty()), "auth-only variants hidden: {hidden:?}");
}
