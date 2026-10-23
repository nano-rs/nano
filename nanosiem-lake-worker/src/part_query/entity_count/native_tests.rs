// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local signed-part fixtures; no network or live tenant access.
use crate::enrichment::BronzeIngestEnricher;
use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
use crate::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use crate::part_query::log_view::PartLogView;
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::LocalPartSigner;
use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

const TENANT: &str = "5b1d2c3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e";
const FILES: usize = 6;
const ROWS_PER_FILE: usize = 150;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new(
        "lab-signer-nan3644",
        ed25519_dalek::SigningKey::from_bytes(&[44; 32]),
    )
    .unwrap()
}

fn source(i: usize) -> &'static str {
    [
        "aws_cloudtrail",
        "windows_sysmon",
        "conduit_proxy",
        "aws_cloudtrail",
        "audit",
        "conduit_proxy",
    ][i / ROWS_PER_FILE]
}

fn event(i: usize, time: &str) -> Value {
    json!({"class_uid":3002,"category_uid":3,"activity_id":1,"type_uid":300201,"severity_id":1,
        "time":time,"message":"entity count fixture","raw_data":"fixture", "raw_data_size":7,
        "metadata":{"profiles":["host"],"uid":format!("uid-{i}"),"version":"1.9.0","log_source":if i % 11 == 0 { "audit" } else { source(i) },"tenant_uid":TENANT,
            "product":{"name":source(i),"vendor_name":"fixture"}},
        "user":{"name":if i%3==0 {"ALIce"}else{"bob"}, "uid":"Alice", "email_addr":"ALIce@example.com"},
        "actor":{"user":{"name":if i%2==0 {"Alice"}else{"carol"},"uid":"alice", "email_addr":"alice@example.com"}},
        "src_endpoint":{"ip":if i%5==0 {"10.0.0.1"}else{"10.0.0.2"},"hostname":"HOST.example"},
        "dst_endpoint":{"ip":if i%7==0 {"10.0.0.1"}else{"10.0.0.3"},"hostname":"host.example"},
        "device":{"type_id":0,"hostname":"Host.example"}})
}

fn write_bronze(path: &std::path::Path, events: &[Value]) {
    use arrow_json::reader::infer_json_schema_from_seekable;
    let mut lines = Vec::new();
    for event in events {
        serde_json::to_writer(&mut lines, event).unwrap();
        lines.push(b'\n');
    }
    let (schema, _) =
        infer_json_schema_from_seekable(&mut std::io::Cursor::new(lines.clone()), None).unwrap();
    let reader = arrow_json::ReaderBuilder::new(Arc::new(schema))
        .build(std::io::Cursor::new(lines))
        .unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        writer
            .get_or_insert_with(|| {
                parquet::arrow::ArrowWriter::try_new(
                    std::fs::File::create(path).unwrap(),
                    batch.schema(),
                    None,
                )
                .unwrap()
            })
            .write(&batch)
            .unwrap();
    }
    writer.unwrap().close().unwrap();
}

/// `FILES` bronze files (a part per file and event hour), newest first, rows 10 s apart.
async fn ingest(root: &std::path::Path, now: DateTime<Utc>) {
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    let now_ms = now.timestamp_millis();
    let mut ingestor = Ingestor::open(
        config,
        &parts,
        &sources,
        &spool as &dyn NoticeQueue,
        &signer,
        signer.trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        now_ms,
    )
    .await
    .expect("ingest opens");
    for n in 0..FILES {
        std::env::set_var(
            "NANO_LAKE_ENTITY_COUNT_WRITE",
            if n % 2 == 0 { "1" } else { "0" },
        );
        let range = n * ROWS_PER_FILE..(n + 1) * ROWS_PER_FILE;
        let batch = range
            .map(|i| event(i, &(now - Duration::seconds(i as i64 * 31)).to_rfc3339()))
            .collect::<Vec<_>>();
        let key = format!("bronze/{n:04}.parquet");
        write_bronze(&sources_dir.join(&key), &batch);
        crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT)
            .expect("bronze admitted");
        let at = now_ms + n as i64 * 10_000;
        spool
            .deliver(&SourceNotice {
                tenant_id: TENANT.into(),
                key,
                version: "1".into(),
                bytes: 0,
                sha256: None,
                edge_sha256: None,
                notified_at_ms: at,
            })
            .unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor
            .flush_now(at + 5_000)
            .await
            .expect("ingest flushes");
    }
    std::env::remove_var("NANO_LAKE_ENTITY_COUNT_WRITE");
}

// Compact each L0 independently, retaining mixed coverage while producing
// real signed source-family inventories. Never invent an inventory in a test.
async fn compact(root: &std::path::Path) {
    use crate::part_ingest::merge::{merge_parts, MergeInput};
    use crate::part_ingest::writer::publish_compacted_parts;
    use crate::parts::format::PartKeys;
    use crate::parts::levels::Level;
    use crate::parts::part_log::{LogOp, PartLogWriter};
    let store = LocalObjectStore::new(root.join("parts")).unwrap();
    let owner = signer();
    let mut view = PartLogView::open(&store, TENANT, owner.trusted())
        .await
        .unwrap();
    let schema = view.read_schema().unwrap();
    let parts = view.live().parts().cloned().collect::<Vec<_>>();
    let mut log = PartLogWriter::open(&store, TENANT, 10_000, &schema, 1)
        .await
        .unwrap();
    for (i, part) in parts.into_iter().enumerate() {
        let dir = root.join("parts").join(
            PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id)
                .unwrap()
                .dir,
        );
        let rows = std::fs::read(dir.join(crate::parts::format::PROVENANCE_FILE)).unwrap();
        let record: crate::parts::provenance::SignedProvenance =
            serde_json::from_slice(&rows).unwrap();
        let indexed =
            std::fs::read(dir.join(crate::parts::format::PARTIAL_ENTITY_RANGES_FILE)).unwrap();
        // Check original coverage rather than relying on part ordering.
        let has_counts = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
            bytes::Bytes::from(indexed),
        )
        .unwrap()
        .build()
        .unwrap()
        .flat_map(|b| {
            use crate::part_ingest::partials::PartialRow;
            crate::part_ingest::partials::EntityRangeRow::from_batch(&b.unwrap()).unwrap()
        })
        .any(|r| matches!(r.key.0.as_str(), crate::parts::entity_counts::COVERAGE_PATH | crate::parts::entity_counts::V2_COVERAGE_PATH));
        std::env::set_var(
            "NANO_LAKE_ENTITY_COUNT_WRITE",
            if has_counts { "1" } else { "0" },
        );
        let merged = merge_parts(
            &root.join("merges"),
            TENANT,
            Level::Hour,
            part.event_hour,
            &[MergeInput {
                part: part.clone(),
                dir,
            }],
            schema.clone(),
            &part.schema_fingerprint,
            &record.record.signer_key_id,
            "entity-count-test",
            if has_counts { 1_791_849_600_000 + i as i64 } else { 2 + i as i64 },
        )
        .unwrap();
        assert!(merged
            .finished
            .record
            .files
            .data
            .iter()
            .all(|f| f.log_sources.is_some()));
        let output = publish_compacted_parts(&store, &owner, &owner.trusted(), &[merged.finished])
            .await
            .unwrap()
            .remove(0);
        log.append(
            LogOp::Merge {
                output,
                supersedes: vec![part.part_id],
            },
            if has_counts { 1_791_849_600_000 + i as i64 } else { 2 + i as i64 },
        )
        .await
        .unwrap();
    }
    std::env::remove_var("NANO_LAKE_ENTITY_COUNT_WRITE");
}

fn runtime() -> NativeChdb {
    static RUNTIME: std::sync::OnceLock<NativeChdb> = std::sync::OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            NativeChdb::load_verified(
                std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
                &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
            )
            .unwrap()
        })
        .clone()
}

/// One set of chDB lanes for every fixture engine of this process.
///
/// Engines of earlier tests leave lane threads (and so chDB connections)
/// alive after their test returns; a later engine opening fresh connections
/// beside them failed to connect (`Startup(ConnectionFailed)`) once the
/// suite ran in one process, while each test passed alone. Shared lanes are
/// opened once. Every fixture engine used identical lane settings, and each
/// engine keeps its own caches, memos and state directory.
fn executors() -> (NativeExecutor, NativeExecutor, NativeExecutor) {
    static EXECUTORS: std::sync::OnceLock<(NativeExecutor, NativeExecutor, NativeExecutor)> = std::sync::OnceLock::new();
    EXECUTORS
        .get_or_init(|| {
            let runtime = runtime();
            let small = NativeExecutor::start_with_server_memory_limit(
                runtime.clone(),
                1,
                "parts",
                ExecutorMode::ReadOnly,
                Some(256 << 20),
            )
            .unwrap()
            .with_result_limit(64 << 20);
            let large = NativeExecutor::start_with_server_memory_limit(
                runtime.clone(),
                1,
                "parts-large",
                ExecutorMode::ReadOnly,
                Some(3 << 29),
            )
            .unwrap();
            let writer = NativeExecutor::start_with_server_memory_limit(
                runtime,
                1,
                "parts-rw",
                ExecutorMode::ReadWrite,
                Some(3 << 29),
            )
            .unwrap();
            (small, large, writer)
        })
        .clone()
}

/// An engine over the fixture whose reader cache holds `cache_bytes`, with
/// `query_bytes` as its heavy threshold (one heavy slot).
async fn fixture_engine(
    root: &std::path::Path,
    name: &str,
    cache_bytes: u64,
    query_bytes: u64,
) -> PartQueryEngine {
    let signer = signer();
    let state = root.join(name);
    std::fs::create_dir_all(&state).unwrap();
    let trusted = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone())
        .await
        .unwrap();
    let bucket = "nan3644-local";
    let cache = ReaderObjectCache::open(
        ReaderObjectCacheSettings {
            root: state.join("cache"),
            max_bytes: cache_bytes,
            query_max_bytes: query_bytes,
            fetch_concurrency: 4,
            fetch_deadline: std::time::Duration::from_secs(60),
        },
        TENANT,
        bucket,
        &parts_key_prefix(TENANT).unwrap(),
        Arc::new(StoreObjectSource::local(
            bucket,
            store.clone(),
            root.join("parts"),
        )),
    )
    .unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let (small, large, writer) = executors();
    PartQueryEngine::new(
        EngineSettings {
            tenant_id: TENANT.into(),
            bucket: bucket.into(),
            compiler: std::env::var("NANO_LAKE_COMPILER")
                .expect("NANO_LAKE_COMPILER")
                .into(),
            max_query_bytes: 64 << 30,
            max_memory_bytes: 256 << 20,
            max_execution_seconds: 120,
            threads: 2,
        },
        store,
        view,
        fetcher,
        small,
    )
    .unwrap()
    .with_writer(writer)
    .with_large(large, 3 << 29)
    .with_state_dir(&state)
}

fn request(query: &str, from: DateTime<Utc>, to: DateTime<Utc>) -> BroadNplRequest {
    serde_json::from_value(json!({"request_id":"entity-count-parity","tenant_id":TENANT,"dataset":"logs",
        "query":query,"start":from.to_rfc3339(),"end":to.to_rfc3339(),"limit":100,"table_view":false})).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local digest-verified chDB and lake compiler"]
async fn entity_count_native_parity_mixed_parts_windows_and_debug() {
    use super::{count, shape};
    let connection = runtime().connect(&[]).unwrap();
    let nulls = connection.query_with_params(
        "SELECT count() AS count FROM values('source Nullable(String)', (NULL), ('audit'), ('AUDIT'), ('unknown'), (''), ('sysmon')) WHERE lower(source) != 'audit'",
        "JSONEachRow", &[]).unwrap();
    assert_eq!(count(&crate::part_query::engine::decode_rows(&nulls.data).unwrap(), "count"), Some(3));
    let root = tempfile::tempdir().unwrap();
    let now: DateTime<Utc> = "2026-10-12T12:00:00Z".parse().unwrap();
    ingest(root.path(), now).await;
    compact(root.path()).await;
    let engine = fixture_engine(root.path(), "reader", 1 << 30, 1 << 29).await;
    let pivots = [
        "src_endpoint.ip=\"10.0.0.1\" OR dst_endpoint.ip=\"10.0.0.1\" OR device.ip=\"10.0.0.1\" | stats count",
        "user.name=\"ALICE\" OR actor.user.name=\"Alice\" | stats count",
        "user.name=\"ALICE\" OR user.uid=\"alice\" OR actor.user.uid=\"alice\" | stats count",
        "user.email_addr=\"ALICE@example.com\" OR actor.user.email_addr=\"Alice@example.com\" | stats count",
        "device.hostname=\"HOST.example\" OR src_endpoint.hostname=\"Host.example\" | stats count",
        "user.name=\"absent\" | stats count as event_count",
    ];
    let mut seed = 3737_u64;
    async {
        for pivot in pivots {
            for iteration in 0..8 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let width = 3 + (seed % 5) as i64;
                let ragged = if iteration % 2 == 0 {
                    0
                } else {
                    (seed % 3000) as i64
                };
                let from = now - Duration::hours(width) + Duration::seconds(ragged);
                let to = now - Duration::seconds(ragged / 2);
                let mut request = request(pivot, from, to);
                if iteration % 3 != 0 { request.deny_source_types.insert("AuDiT".into()); }
                if iteration % 3 == 2 { request.deny_source_types.insert("windows_sysmon".into()); }
                engine
                    .pinned(async {
                        let compiled = engine
                            .compile(&request, engine.field_types().await.unwrap())
                            .await
                            .unwrap();
                        let alias = shape(&compiled).expect("supported compiler shape").alias;
                        let fast = super::run(&engine, &request, &compiled)
                            .await
                            .unwrap()
                            .expect("fixture has coverage");
                        let selection = engine
                            .select(
                                from.timestamp_micros(),
                                to.timestamp_micros() - 1,
                                &compiled.candidate_hints,
                            )
                            .await
                            .unwrap();
                        let plan = crate::part_query::engine::plan_logs(&selection, &compiled, None).unwrap();
                        let native = engine.execute(plan).await.unwrap();
                        let rows = crate::part_query::engine::decode_rows(&native.data).unwrap();
                        assert_eq!(
                            count(&fast.rows, &alias),
                            count(&rows, &alias),
                            "{pivot} {iteration}"
                        );
                        assert!(fast.planner["entity_count_index_parts"].as_u64().unwrap() > 0);
                    })
                    .await
                    .unwrap();
            }
        }
        // Latest complete hour contains indexed parts only. No data row
        // groups are needed. NAN-4280: the window is half-open, so the
        // complete hour is `[hour, next hour)` -- the end IS the hour mark.
        let complete = request(
            pivots[0],
            now - Duration::hours(1),
            now,
        );
        let answer = engine.broad_npl(&complete).await.unwrap();
        assert!(
            answer["planner"]["entity_count_index_parts"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(answer["result"]["storage_rows"], 0);
        assert_eq!(answer["planner"]["entity_count_native_parts"], 0);
        let probe = request(
            pivots[0],
            now - Duration::hours(8),
            now,
        );
        let answer = crate::part_query::debug::collect(engine.broad_npl(&probe))
            .await
            .unwrap();
        assert_eq!(
            answer["planner"]["entity_count_duplicate_part_hours"],
            0
        );
        let mut denied = probe.clone();
        denied.deny_source_types.insert("audit".into());
        let answer = crate::part_query::debug::collect(crate::query_timing::measure(
            "deny-count",
            engine.broad_npl(&denied),
        ))
        .await
        .unwrap();
        assert!(
            answer["planner"]["entity_count_index_parts"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(
            answer["planner"]["entity_count_native_parts"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(
            answer["planner"]["entity_count_duplicate_part_hours"],
            0
        );
        assert!(answer["planner"]["entity_count_fallback_reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("uncovered")));
        let mut web = complete.clone();
        web.table_view = true;
        let answer = engine.broad_npl(&web).await.unwrap();
        assert!(
            answer["planner"]["entity_count_index_parts"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(answer["result"]["storage_rows"], 0);

        // Older hour contains only unindexed parts: probe footer coverage metadata,
        // without leasing/decompressing any EntityRanges row group.
        let uncovered = request(
            pivots[0],
            now - Duration::hours(8),
            now - Duration::hours(7),
        );
        let unindexed = fixture_engine(root.path(), "uncovered-reader", 1 << 30, 1 << 29).await;
        unindexed
            .pinned(async {
                let compiled = unindexed
                    .compile(&uncovered, unindexed.field_types().await.unwrap())
                    .await
                    .unwrap();
                assert!(super::run(&unindexed, &uncovered, &compiled)
                    .await
                    .unwrap()
                    .is_none());
            })
            .await
            .unwrap();
        assert_eq!(
            unindexed
                .entity_count_memo
                .decodes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        let cache = unindexed.fetcher().cache().stats();
        assert_eq!(
            cache.hits + cache.misses,
            0,
            "uncovered parts never lease EntityRanges"
        );
        assert_eq!(cache.fetched_bytes, 0);

        // A cold reader whose decoder is occupied must use native counts
        // after the shared budget, then accelerate on the next attempt.
        let cold = fixture_engine(root.path(), "budget-reader", 1 << 30, 1 << 29).await;
        let permit = cold
            .entity_count_memo
            .point_gate
            .clone()
            .acquire_many_owned(8)
            .await
            .unwrap();
        let answer = crate::part_query::debug::collect(crate::query_timing::measure(
            "budget-count",
            cold.broad_npl(&complete),
        ))
        .await
        .unwrap();
        assert_eq!(
            answer["result"]["rows"],
            engine.broad_npl(&complete).await.unwrap()["result"]["rows"]
        );
        assert!(answer["planner"]["entity_count_fallback_reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("budget")));
        drop(permit);
        assert!(
            cold.broad_npl(&complete).await.unwrap()["planner"]["entity_count_index_parts"]
                .as_u64()
                .unwrap()
                > 0
        );
        // Use a fresh memo: the preceding query now retains hour vectors
        // across windows, and would otherwise prime extra parts for this test.
        let cold = fixture_engine(root.path(), "partial-budget-reader", 1 << 30, 1 << 29).await;
        // Keep one completed indexed digest when other decoders exhaust the
        // budget. The remaining native legs must neither omit nor recount it.
        let primed_parts = cold.pinned(async {
            let compiled = cold
                .compile(&probe, cold.field_types().await.unwrap())
                .await
                .unwrap();
            let shape = shape(&compiled).unwrap();
            let interior = super::split(
                (now - Duration::hours(8)).timestamp_micros(),
                now.timestamp_micros() - 1,
            )
            .unwrap()
            .0;
            let parts = cold
                .snapshot(
                    (now - Duration::hours(8)).timestamp_micros(),
                    now.timestamp_micros() - 1,
                )
                .await
                .unwrap()
                .0;
            let mut primed = None;
            for part in &parts {
                if super::lookup(
                    &cold,
                    part,
                    &shape,
                    interior,
                    std::time::Instant::now() + std::time::Duration::from_secs(2),
                )
                .await
                .1
                .is_some()
                {
                    let record = cold.fetcher().record(part).await.unwrap();
                    primed = Some(record.files.partials.iter().find(|p| p.kind == crate::parts::provenance::PartialKind::EntityRanges).unwrap().sha256.clone());
                    break;
                }
            }
            let digest = primed.expect("one covered part");
            // Identical partials share the value/hour memo even when their
            // part IDs differ; all matching covered parts can finish.
            let mut matching = 0;
            for part in &parts {
                let record = cold.fetcher().record(part).await.unwrap();
                if record.files.partials.iter().any(|p| p.kind == crate::parts::provenance::PartialKind::EntityRanges && p.sha256 == digest) {
                    matching += 1;
                }
            }
            matching
        })
        .await
        .unwrap();
        let expected = engine
            .pinned(async {
                let compiled = engine
                    .compile(&probe, engine.field_types().await.unwrap())
                    .await
                    .unwrap();
                let selection = engine
                    .select(
                        (now - Duration::hours(8)).timestamp_micros(),
                        now.timestamp_micros() - 1,
                        &compiled.candidate_hints,
                    )
                    .await
                    .unwrap();
                let plan = crate::part_query::engine::plan_logs(&selection, &compiled, None).unwrap();
                let output = engine.execute(plan).await.unwrap();
                crate::part_query::engine::decode_rows(&output.data).unwrap()
            })
            .await
            .unwrap();
        let permit = cold
            .entity_count_memo
            .point_gate
            .clone()
            .acquire_many_owned(8)
            .await
            .unwrap();
        // NAN-3759: an admin request has no source deny set. With whole-hour
        // bounds, the completed index split needs exactly one selection for
        // uncovered parts, even when diagnostics and budget fallback coexist.
        assert!(probe.deny_source_types.is_empty());
        let answer = crate::part_query::debug::collect(crate::query_timing::measure(
            "partial-budget-count",
            async {
                let answer = cold.broad_npl(&probe).await?;
                let phases = crate::query_timing::current().unwrap();
                let phases = phases.lock().unwrap();
                assert_eq!(phases.funnel.selections, 1);
                assert!(phases.funnel.counting);
                Ok::<_, crate::part_query::engine::PartQueryError>(answer)
            },
        ))
        .await
        .unwrap();
        assert_eq!(answer["planner"]["entity_count_index_parts"], primed_parts);
        assert_eq!(answer["result"]["rows"], json!(expected));
        // Debug collection must execute only the remainder, with no hidden
        // whole-window verification statement after the split native legs.
        let statements = answer["planner"]["native_debug"]["statements"]
            .as_array()
            .unwrap();
        assert!(!statements.is_empty());
        assert!(statements.iter().all(|statement| statement["sql"]
            .as_str()
            .unwrap()
            .contains("time >= fromUnixTimestamp64Micro")));
        assert!(answer["planner"].get("entity_count_self_check").is_none());
        assert!(
            answer["planner"]["entity_count_native_parts"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(
            answer["planner"]["entity_count_duplicate_part_hours"],
            0
        );
        assert!(answer["planner"]["entity_count_fallback_reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("budget")));
        drop(permit);
        let mut foreign = probe;
        foreign.tenant_id = "00000000-0000-0000-0000-000000000002".into();
        assert!(engine.broad_npl(&foreign).await.is_err());
    }
    .await;
}

/// NAN-3801: counts-only backfill of the uncovered parts makes every part
/// count-covered through its signed count record, and the indexed answer
/// equals the native scan exactly on every pivot, window and deny set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local digest-verified chDB and lake compiler"]
async fn entity_count_from_signed_count_records_matches_native() {
    use super::{count, shape};
    use crate::parts::format::PartKeys;
    let root = tempfile::tempdir().unwrap();
    let now: DateTime<Utc> = "2026-10-12T12:00:00Z".parse().unwrap();
    ingest(root.path(), now).await;
    compact(root.path()).await;
    // Before: some parts are uncovered (native legs).
    let before = fixture_engine(root.path(), "before", 1 << 30, 1 << 29).await;
    let window = request(
        "src_endpoint.ip=\"10.0.0.1\" OR dst_endpoint.ip=\"10.0.0.1\" OR device.ip=\"10.0.0.1\" | stats count",
        now - Duration::hours(8),
        now,
    );
    let answer = crate::part_query::debug::collect(before.broad_npl(&window)).await.unwrap();
    assert!(answer["planner"]["entity_count_native_parts"].as_u64().unwrap() > 0, "fixture: uncovered parts");
    // Counts-only backfill of every live part (covered parts get a record too).
    let store = LocalObjectStore::new(root.path().join("parts")).unwrap();
    let owner = signer();
    let view = PartLogView::open(&store, TENANT, owner.trusted()).await.unwrap();
    for part in view.live().parts().cloned().collect::<Vec<_>>() {
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        let bytes = store.get(&keys.provenance()).await.unwrap().unwrap();
        let signed = crate::parts::provenance::SignedProvenance::verify_bytes(&bytes, TENANT, &owner.trusted()).unwrap();
        crate::part_ingest::count_record::backfill_counts(&store, &owner, &owner.trusted(), TENANT,
            &root.path().join("backfill"), &part, &signed.record, now.timestamp_millis()).await.unwrap();
    }
    let engine = fixture_engine(root.path(), "after", 1 << 30, 1 << 29).await;
    let answer = crate::part_query::debug::collect(engine.broad_npl(&window)).await.unwrap();
    assert_eq!(answer["planner"]["entity_count_native_parts"], 0, "{answer}");
    let pivots = [
        "src_endpoint.ip=\"10.0.0.1\" OR dst_endpoint.ip=\"10.0.0.1\" OR device.ip=\"10.0.0.1\" | stats count",
        "user.name=\"ALICE\" OR actor.user.name=\"Alice\" | stats count",
        "user.email_addr=\"ALICE@example.com\" OR actor.user.email_addr=\"Alice@example.com\" | stats count",
        "device.hostname=\"HOST.example\" OR src_endpoint.hostname=\"Host.example\" | stats count",
        "user.name=\"absent\" | stats count as event_count",
    ];
    async {
        for pivot in pivots {
            for (hours, deny) in [(8, None), (3, Some("AuDiT")), (8, Some("windows_sysmon"))] {
                let (from, to) = (now - Duration::hours(hours), now);
                let mut request = request(pivot, from, to);
                if let Some(deny) = deny { request.deny_source_types.insert(deny.into()); }
                engine.pinned(async {
                    let compiled = engine.compile(&request, engine.field_types().await.unwrap()).await.unwrap();
                    let alias = shape(&compiled).expect("supported compiler shape").alias;
                    let fast = super::run(&engine, &request, &compiled).await.unwrap().expect("records cover the window");
                    let selection = engine.select(from.timestamp_micros(), to.timestamp_micros() - 1,
                        &compiled.candidate_hints).await.unwrap();
                    let plan = crate::part_query::engine::plan_logs(&selection, &compiled, None).unwrap();
                    let rows = crate::part_query::engine::decode_rows(&engine.execute(plan).await.unwrap().data).unwrap();
                    assert_eq!(count(&fast.rows, &alias), count(&rows, &alias), "{pivot} {hours}h deny={deny:?}");
                    assert_eq!(fast.planner["entity_count_native_parts"], 0, "{pivot} {hours}h deny={deny:?}");
                }).await.unwrap();
            }
        }
    }.await;
}

/// NAN-4298: the typed `count_aggregate` route (what search sends for
/// `F=v | stats count`) answers entity-field equality counts from the entity
/// counts, equal to the compiled native scan of the same nPL, over ragged
/// windows and deny sets; a window of only uncovered parts, and every other
/// shape, stays on the rollups with the same answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local digest-verified chDB and lake compiler"]
async fn typed_count_aggregate_uses_entity_counts_and_matches_the_scan() {
    let root = tempfile::tempdir().unwrap();
    let now: DateTime<Utc> = "2026-10-12T12:00:00Z".parse().unwrap();
    ingest(root.path(), now).await;
    compact(root.path()).await;
    let engine = fixture_engine(root.path(), "typed-reader", 1 << 30, 1 << 29).await;
    let typed = |field: &str, value: &str, from: DateTime<Utc>, to: DateTime<Utc>, deny: &[&str]| -> crate::count_aggregate::CountAggregateRequest {
        serde_json::from_value(json!({"request_id":"nan4298","tenant_id":TENANT,"group_field":field,"group_results":false,
            "predicate":{"kind":"eq","values":[value]},"count_alias":"count","start":from.to_rfc3339(),"end":to.to_rfc3339(),
            "max_groups":10,"deny_source_types":deny})).unwrap()
    };
    let scan = |field: &str, value: &str, from: DateTime<Utc>, to: DateTime<Utc>, deny: &[&str]| {
        // The typed route's `end` is inclusive; nPL windows are half-open.
        let mut request = request(&format!("{field}=\"{value}\" | stats count() as n"), from, to + Duration::microseconds(1));
        request.deny_source_types = deny.iter().map(|s| s.to_string()).collect();
        request
    };
    let cases = [
        ("src_endpoint.ip", "10.0.0.1"),
        ("dst_endpoint.ip", "10.0.0.1"),
        ("user.name", "alice"),
        ("actor.user.name", "Alice"),
        ("device.hostname", "host.example"),
        ("src_endpoint.hostname", "HOST.example"),
        ("user.name", "absent"),
    ];
    let mut seed = 4298_u64;
    let mut routed = 0;
    for (field, value) in cases {
        for iteration in 0..6 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let ragged = if iteration % 2 == 0 { 0 } else { (seed % 3000) as i64 };
            let from = now - Duration::hours(3 + (seed % 3) as i64) + Duration::seconds(ragged);
            let to = now - Duration::seconds(ragged / 2);
            let deny: &[&str] = match iteration % 3 { 0 => &[], 1 => &["audit"], _ => &["audit", "windows_sysmon"] };
            let (answer, phases) = crate::query_timing::measure("nan4298", async {
                let answer = super::super::partials::count_aggregate(&engine, &typed(field, value, from, to, deny)).await.unwrap();
                let phases = crate::query_timing::current().unwrap().lock().unwrap().entity_count_aggregate_routes;
                Ok::<_, ()>((answer, phases))
            }).await.unwrap();
            routed += phases;
            let native = engine.pinned(async {
                let request = scan(field, value, from, to, deny);
                let compiled = engine.compile(&request, engine.field_types().await.unwrap()).await.unwrap();
                let selection = engine.select(from.timestamp_micros(), to.timestamp_micros(), &compiled.candidate_hints).await.unwrap();
                let plan = crate::part_query::engine::plan_logs(&selection, &compiled, None).unwrap();
                let rows = crate::part_query::engine::decode_rows(&engine.execute(plan).await.unwrap().data).unwrap();
                super::count(&rows, "n")
            }).await.unwrap();
            let typed_count = answer["result"]["rows"][0]["count"].as_u64()
                .or_else(|| answer["result"]["rows"][0]["count"].as_str().and_then(|n| n.parse().ok()));
            assert_eq!(typed_count, native, "{field}={value} #{iteration} {answer}");
        }
    }
    assert!(routed > 0, "no typed count used the entity counts");

    // Only unindexed parts in the window: the rollups answer, identically.
    let (from, to) = (now - Duration::hours(8), now - Duration::hours(7) - Duration::microseconds(1));
    let (answer, phases) = crate::query_timing::measure("nan4298-uncovered", async {
        let answer = super::super::partials::count_aggregate(&engine, &typed("src_endpoint.ip", "10.0.0.1", from, to, &[])).await.unwrap();
        let phases = crate::query_timing::current().unwrap().lock().unwrap().entity_count_aggregate_routes;
        Ok::<_, ()>((answer, phases))
    }).await.unwrap();
    assert_eq!(phases, 0, "an uncovered window stays on the rollups");
    let native = engine.pinned(async {
        let request = scan("src_endpoint.ip", "10.0.0.1", from, to, &[]);
        let compiled = engine.compile(&request, engine.field_types().await.unwrap()).await.unwrap();
        let selection = engine.select(from.timestamp_micros(), to.timestamp_micros(), &compiled.candidate_hints).await.unwrap();
        let plan = crate::part_query::engine::plan_logs(&selection, &compiled, None).unwrap();
        super::count(&crate::part_query::engine::decode_rows(&engine.execute(plan).await.unwrap().data).unwrap(), "n")
    }).await.unwrap();
    assert_eq!(answer["result"]["rows"][0]["count"].as_u64().or_else(|| answer["result"]["rows"][0]["count"].as_str().and_then(|n| n.parse().ok())), native);
}
