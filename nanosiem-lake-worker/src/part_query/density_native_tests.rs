// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3158, native: density-seeded progressive pivots end-to-end (real
//! compiler, planner, parts with entity-ranges partials, chDB). A dense and
//! a sparse pivot in the Q6 timeline shapes (`<entity> | head N`,
//! `<entity> | sort -time | head N`) run with the density seed off and on:
//! rows are identical (and equal the `* | where` form and fixture truth),
//! cursor pages continue exactly, and the seeded walk runs at most two
//! native statements per step.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::density::native -- --ignored --nocapture --test-threads=1
//! ```

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
use sha2::Digest;
use std::sync::Arc;

pub(super) const TENANT: &str = "3b8d2f61-5c7e-4a9b-8d1f-2e4c6a8b0d13";
/// Three bronze files, three parts, one event every 2 s (~1.7 h).
pub(super) const ROWS: usize = 3_000;
const PARTS: usize = 3;
/// In a third of the rows: far denser than 1/32.
pub(super) const DENSE_IP: &str = "10.9.9.9";
/// In three rows spread over the parts: sparse.
pub(super) const SPARSE_IP: &str = "10.7.7.7";
const SPARSE_ROWS: [usize; 3] = [5, 1_700, 2_900];
pub(super) const DENSE_HOST: &str = "web1.corp.local";

fn signer() -> LocalPartSigner {
    LocalPartSigner::new(
        "lab-signer-nan3158",
        ed25519_dalek::SigningKey::from_bytes(&[58; 32]),
    )
    .unwrap()
}

pub(super) fn src_ip(i: usize) -> String {
    if SPARSE_ROWS.contains(&i) {
        SPARSE_IP.to_string()
    } else if i % 3 == 0 {
        DENSE_IP.to_string()
    } else {
        format!("10.1.{}.{}", i / 250, i % 250)
    }
}

pub(super) fn host(i: usize) -> String {
    // Mixed case at the source: admission lowercases the hostname.
    if i % 2 == 1 {
        "WEB1.Corp.Local".to_string()
    } else {
        format!("web0-{}.corp.local", i % 5)
    }
}

fn event(i: usize, time: &str) -> Value {
    let source = ["aws_cloudtrail", "windows_sysmon", "conduit_proxy"][i % 3];
    let text = format!("event {source} seq {i}");
    json!({
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "severity_id": 1,
        "time": time, "message": text, "raw_data": format!("raw {text}"), "raw_data_size": text.len() + 4, "status": "Success",
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": source, "tenant_uid": TENANT,
                     "product": {"name": source, "vendor_name": "fixture"}},
        "src_endpoint": {"ip": src_ip(i), "hostname": host(i)},
        "dst_endpoint": {"ip": "203.0.113.9", "port": 443},
    })
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

/// A smaller index is a newer event.
fn event_time(now: DateTime<Utc>, i: usize) -> DateTime<Utc> {
    now - Duration::seconds(i as i64 * 2 + 30)
}

pub(super) async fn ingest(root: &std::path::Path, now: DateTime<Utc>) {
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
    let per = ROWS / PARTS;
    // Oldest first, so each part is a disjoint, older-to-newer time slice.
    for n in 0..PARTS {
        let range = (PARTS - 1 - n) * per..(PARTS - n) * per;
        let batch = range
            .map(|i| event(i, &event_time(now, i).to_rfc3339()))
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
}

pub(super) async fn engine(root: &std::path::Path) -> PartQueryEngine {
    let signer = signer();
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let trusted = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone())
        .await
        .unwrap();
    let bucket = "nan3158-local";
    let cache = ReaderObjectCache::open(
        ReaderObjectCacheSettings {
            root: state.join("cache"),
            max_bytes: 1 << 30,
            query_max_bytes: 1 << 29,
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
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
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

pub(super) fn request(query: &str, now: DateTime<Utc>, limit: usize) -> BroadNplRequest {
    BroadNplRequest {
        request_id: "nan3158".into(),
        tenant_id: TENANT.into(),
        dataset: "logs".into(),
        query: query.into(),
        // 23 h; NAN-3162's sibling test also pages windows over 24 h.
        start: (now - Duration::hours(23)).to_rfc3339(),
        end: (now + Duration::minutes(1)).to_rfc3339(),
        limit,
        offset: 0,
        table_view: true,
        use_cache: false,
        cursor_time: None,
        cursor_event_uid: None,
        anchor_us: None,
        decay: None,
        clear_boundaries: Default::default(),
        watch_weights: Default::default(),
        minimum_clear_revision: None,
        deny_source_types: Default::default(),
    }
}

pub(super) fn granted() -> nanosiem_core::platform_enrichment::read::ReadAuthorization {
    use nanosiem_core::platform_enrichment::{AuthorizedRevision, FeedClass, RevisionReference};
    let tenant: uuid::Uuid = TENANT.parse().unwrap();
    let now = Utc::now();
    nanosiem_core::platform_enrichment::read::ReadAuthorization::from_resolved(
        tenant,
        now,
        &[AuthorizedRevision {
            tenant_id: tenant,
            reference: RevisionReference {
                feed_id: "ipinfo_lite".into(),
                feed_revision: 2,
                tier: "included".into(),
                grant_revision: 1,
                entitlement_revision: 1,
            },
            class: FeedClass::Baseline,
            digest: "0".repeat(64),
            mapping_revision: 1,
            deny_epoch: 0,
            valid_until: now + Duration::days(30),
            evaluated_at: now,
        }],
    )
}

pub(super) async fn envelope(engine: &PartQueryEngine, request: &BroadNplRequest) -> Value {
    // Statement counts are per cold step: no locator reuse across runs.
    engine.clear_locator_cache();
    crate::query_timing::measure(
        "nan3158",
        Box::pin(crate::enrichment_read::scope(
            granted(),
            engine.broad_npl(request),
        )),
    )
    .await
    .unwrap_or_else(|error| panic!("{}: {error}", request.query))
}

/// NAN-3172: [`envelope`] plus the request's logged selection funnel.
pub(super) async fn funneled(engine: &PartQueryEngine, request: &BroadNplRequest) -> (Value, crate::query_timing::Funnel) {
    crate::query_timing::measure("nan3172", async {
        let answer = envelope(engine, request).await;
        let funnel = crate::query_timing::current().expect("request scope").lock().unwrap().funnel.clone();
        Ok::<_, ()>((answer, funnel))
    })
    .await
    .unwrap()
}

async fn with_seed(engine: &PartQueryEngine, request: &BroadNplRequest, on: bool) -> Value {
    if on {
        std::env::remove_var(super::FLAG);
    } else {
        std::env::set_var(super::FLAG, "0");
    }
    let answer = envelope(engine, request).await;
    std::env::remove_var(super::FLAG);
    answer
}

pub(super) fn rows_of(answer: &Value) -> Vec<Value> {
    answer["result"]["rows"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("no rows in {answer}"))
}

pub(super) fn ordered_uids(rows: &[Value]) -> Vec<String> {
    rows.iter()
        .map(|row| {
            row["metadata.uid"]
                .as_str()
                .unwrap_or_else(|| panic!("{row}"))
                .to_string()
        })
        .collect()
}

pub(super) fn digest(rows: &[Value]) -> String {
    hex::encode(sha2::Sha256::digest(serde_json::to_vec(rows).unwrap()))
}

pub(super) fn statements(answer: &Value) -> u64 {
    answer["planner"]["successful_native_statements"]
        .as_u64()
        .unwrap_or_else(|| panic!("no statement count: {}", answer["planner"]))
}

/// NAN-3158: dense pivots skip the whole-window preselect and fill their
/// page in one density-sized chunk; sparse pivots keep the preselect. Rows
/// are hash-identical with the seed off, equal the `* | where` form and
/// truth, cursor pages continue exactly, and every seeded step runs at most
/// two native statements.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn density_seeded_pivots_match_where_and_run_two_statements() {
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    let uid = |i: &usize| format!("uid-{i:08}");
    let truth = |keep: &dyn Fn(usize) -> bool, n: usize| {
        (0..ROWS)
            .filter(|i| keep(*i))
            .take(n)
            .map(|i| uid(&i))
            .collect::<Vec<_>>()
    };
    let dense_ip = |i: usize| src_ip(i) == DENSE_IP;
    let sparse_ip = |i: usize| src_ip(i) == SPARSE_IP;
    let dense_host = |i: usize| i % 2 == 1;
    let cases: Vec<(String, String, &dyn Fn(usize) -> bool, bool)> = vec![
        (
            format!("src_endpoint.ip={DENSE_IP}"),
            format!("src_endpoint.ip=\"{DENSE_IP}\""),
            &dense_ip,
            true,
        ),
        (
            format!("src_endpoint.hostname=\"{DENSE_HOST}\""),
            format!("src_endpoint.hostname=\"{DENSE_HOST}\""),
            &dense_host,
            true,
        ),
        (
            format!("src_endpoint.ip={SPARSE_IP}"),
            format!("src_endpoint.ip=\"{SPARSE_IP}\""),
            &sparse_ip,
            false,
        ),
    ];
    for (pivot, where_form, keep, dense) in &cases {
        for (shape, head) in [("| head 20", 20_usize), ("| sort -time | head 50", 50)] {
            let query = format!("{pivot} {shape}");
            let step = request(&query, now, 200);
            let off = with_seed(&engine, &step, false).await;
            let on = with_seed(&engine, &step, true).await;
            let (rows_off, rows_on) = (rows_of(&off), rows_of(&on));
            let expected = truth(*keep, head);
            assert_eq!(ordered_uids(&rows_on), expected, "{query}: truth");
            assert_eq!(
                digest(&rows_on),
                digest(&rows_off),
                "{query}: rows hash-identical with the seed off"
            );
            assert_eq!(
                on["result"]["page_has_more"], off["result"]["page_has_more"],
                "{query}"
            );
            let reference = rows_of(
                &envelope(
                    &engine,
                    &request(
                        &format!("* | where {where_form} | sort -time | head {head}"),
                        now,
                        200,
                    ),
                )
                .await,
            );
            assert_eq!(
                ordered_uids(&rows_on),
                ordered_uids(&reference),
                "{query} vs | where"
            );
            let planner = &on["planner"];
            let density = &planner["density"];
            println!(
                "NAN3158 {query:?}: statements off={} on={} | chunks off={} on={} | preselect off={} on={} | density={density}",
                statements(&off), statements(&on), off["planner"]["chunks_executed"], planner["chunks_executed"],
                !off["planner"]["preselect"].is_null(), !planner["preselect"].is_null(),
            );
            assert!(statements(&on) <= 2, "{query}: {planner}");
            assert!(
                statements(&on) <= statements(&off),
                "{query}: the seed never adds statements"
            );
            assert_eq!(
                density["dense"].as_bool(),
                Some(*dense),
                "{query}: {density}"
            );
            assert_eq!(
                planner["preselect"].is_null(),
                *dense,
                "{query}: a dense pivot skips the whole-window preselect"
            );
        }
    }
    // Cursor paging (infinite scroll) over both seeded shapes: identical
    // pages with the seed on and off, continuing the result exactly.
    for query in [
        format!("src_endpoint.ip={DENSE_IP} | sort -time | head 50"),
        format!("src_endpoint.ip={DENSE_IP}"),
    ] {
        let mut pages = [Vec::new(), Vec::new()];
        for (slot, on) in [(0, false), (1, true)] {
            let mut step = request(&query, now, 10);
            for _ in 0..3 {
                let page = with_seed(&engine, &step, on).await;
                let rows = rows_of(&page);
                assert_eq!(rows.len(), 10, "{query}: {page}");
                let last = rows.last().unwrap();
                let time = last["time"].as_str().unwrap().replace(' ', "T");
                step.cursor_time = Some(if time.ends_with('Z') {
                    time
                } else {
                    format!("{time}Z")
                });
                step.cursor_event_uid = Some(last["metadata.uid"].as_str().unwrap().to_string());
                pages[slot].extend(rows);
            }
        }
        assert_eq!(
            digest(&pages[1]),
            digest(&pages[0]),
            "{query}: cursor pages identical with the seed off"
        );
        assert_eq!(
            ordered_uids(&pages[1]),
            truth(&dense_ip, 30),
            "{query}: cursor pages continue the result exactly"
        );
    }
}
