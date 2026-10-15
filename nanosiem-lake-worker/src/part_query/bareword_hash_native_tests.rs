// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3170, native: a field-less (bareword) search for a rare 64-hex hash
//! over many hot files (real compiler, planner, parts with token sidecars,
//! chDB). The three live shapes -- `<hash> | head 100`,
//! `metadata.log_source=windows_sysmon <hash> | head 100` and
//! `<hash> | stats count by metadata.log_source` -- must prune to the few
//! files that hold the token, return exactly the fixture truth (equal to the
//! unhinted `* | where like(...)` form), and a common word must not get
//! slower.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::density::bareword_hash_native -- --ignored --nocapture --test-threads=1
//! ```

use super::native::{digest, engine, envelope, funneled, ordered_uids, request, rows_of, statements, TENANT};
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

/// 48 parts (one data file each) of 2,000 events, one every 0.8 s (~21 h).
const PARTS: usize = 48;
const PER_PART: usize = 2_000;
const ROWS: usize = PARTS * PER_PART;
const HASH: &str = "0faafb1b35275f3912da163319c87e224985b26b36e662f813897f22445e187e";
/// The hash's events: three bursts of 50 sysmon rows (`i % 3 == 1`), about
/// 30 min, 9 h and 18 h old, in three of the 48 files. A `head 100` page
/// needs the two newest bursts; the field form reads them in one chunk.
const BURSTS: [usize; 3] = [2_000, 40_000, 80_000];
const BURST_SPAN: usize = 150;

fn has_hash(i: usize) -> bool {
    i % 3 == 1
        && BURSTS
            .iter()
            .any(|start| (*start..start + BURST_SPAN).contains(&i))
}

fn hash_of(i: usize) -> String {
    if has_hash(i) {
        HASH.to_string()
    } else {
        // A distinct 64-hex value per row, so every row group's token
        // filter is as full of hashes as a real sysmon file's.
        format!(
            "{:064x}",
            (i as u128 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835)
        )
    }
}

fn source(i: usize) -> &'static str {
    ["aws_cloudtrail", "windows_sysmon", "conduit_proxy"][i % 3]
}

fn event(i: usize, time: &str) -> Value {
    let source = source(i);
    let hash = hash_of(i);
    // `beacon7`: a sparse token in every file (two rows each), too spread
    // for the whole-window preselect.
    let beacon = if i % 1_000 == 7 { " beacon7" } else { "" };
    let text = format!("Process Create: Image=C:\\Windows\\proc{} Hashes=SHA256={hash} seq {i} source {source}{beacon}", i % 97);
    let raw = format!("raw seq {i}");
    json!({
        "class_uid": 1007, "category_uid": 1, "activity_id": 1, "type_uid": 100701, "severity_id": 1,
        "time": time, "message": text, "raw_data": raw, "raw_data_size": raw.len(), "status": "Success",
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": source, "tenant_uid": TENANT,
                     "product": {"name": source, "vendor_name": "fixture"}},
        "process": {"pid": 4000 + i % 97, "name": format!("proc{}", i % 97), "file": {"name": format!("proc{}.exe", i % 97), "type_id": 1,
                    "hashes": [{"algorithm_id": 3, "value": hash}]}},
        "actor": {"process": {"pid": 600, "name": "services.exe"}},
        "device": {"hostname": format!("ws{}.corp.local", i % 40), "type_id": 2},
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
    now - Duration::milliseconds(i as i64 * 800 + 30_000)
}

async fn ingest(root: &std::path::Path, now: DateTime<Utc>) {
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    // The density fixture's signer: `engine` trusts exactly this key.
    let signer = LocalPartSigner::new(
        "lab-signer-nan3158",
        ed25519_dalek::SigningKey::from_bytes(&[58; 32]),
    )
    .unwrap();
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
    for n in 0..PARTS {
        let range = (PARTS - 1 - n) * PER_PART..(PARTS - n) * PER_PART;
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

fn uid(i: usize) -> String {
    format!("uid-{i:08}")
}

fn bytes_read(answer: &Value) -> u64 {
    answer["result"]["storage_bytes"].as_u64().unwrap_or(0)
}

fn report(label: &str, answer: &Value) {
    let planner = &answer["planner"];
    if std::env::var_os("NAN3170_PLANNER").is_some() {
        println!("NAN3170-PLANNER {label}: {planner}");
    }
    println!(
        "NAN3170 {label}: wall_s={:.3} statements={} storage_rows={} storage_bytes={} kind={} chunks={} fetched_files={} \
         token_pruned_files={} time_files={} kept_row_groups={} preselect={} density={}",
        answer["result"]["wall_seconds"].as_f64().unwrap_or(0.0),
        planner["successful_native_statements"], answer["result"]["storage_rows"], bytes_read(answer),
        planner["kind"], planner["chunks_executed"], planner["fetched_files"],
        planner["token_pruned_files"], planner["time_files"], planner["kept_row_groups"],
        !planner["preselect"].is_null(), planner["density"],
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn rare_hash_bareword_prunes_to_its_files_in_every_shape() {
    // The live cell's writer flags: v4 keyword index (blocks, counts,
    // trigrams) and the part result cache.
    crate::parts::block_index::set_enabled(true);
    crate::parts::token_counts::set_enabled(true);
    std::env::set_var(crate::parts::sidecar::TRIGRAM_ENABLE_ENV, "1");
    std::env::set_var("NANO_LAKE_UID_SIDECAR_WRITE", "1");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    std::env::set_var("NANO_LAKE_PART_RESULT_CACHE", "1");
    let engine = engine(root.path()).await;
    // Warm: every data file local (the resident hot window).
    let _ = envelope(&engine, &request("* | stats count", now, 10)).await;

    let hash_rows = |keep: &dyn Fn(usize) -> bool| {
        (0..ROWS)
            .filter(|i| has_hash(*i) && keep(*i))
            .take(100)
            .map(uid)
            .collect::<Vec<_>>()
    };
    let all = |_: usize| true;
    let sysmon = |i: usize| source(i) == "windows_sysmon";
    let row_cases: [(String, String, &dyn Fn(usize) -> bool); 2] = [
        (format!("{HASH} | head 100"), format!("* | where like(message, \"%{HASH}%\") | sort -time | head 100"), &all),
        (
            format!("metadata.log_source=windows_sysmon {HASH} | head 100"),
            format!("* | where metadata.log_source=\"windows_sysmon\" AND like(message, \"%{HASH}%\") | sort -time | head 100"),
            &sysmon,
        ),
    ];
    for (query, reference, keep) in &row_cases {
        let step = request(query, now, 200);
        let _ = envelope(&engine, &step).await;
        let (answer, funnel) = funneled(&engine, &step).await;
        report(query, &answer);
        println!("NAN3172 funnel {query}: {funnel:?}");
        // NAN-3172: the per-request log record carries the funnel.
        assert!(funnel.progressive && !funnel.counting, "{query}: {funnel:?}");
        assert!(funnel.selections >= 1 && funnel.token_seed && funnel.seed_complete.is_some(), "{query}: {funnel:?}");
        assert_eq!(funnel.chunks_executed, 1, "{query}: {funnel:?}");
        assert!(funnel.keyword_hints >= 1, "{query}: {funnel:?}");
        assert!(funnel.time_files >= funnel.fetched_files && funnel.fetched_files >= 3, "{query}: {funnel:?}");
        assert!(funnel.token_pruned_files > 0 && funnel.kept_row_groups >= 3, "{query}: {funnel:?}");
        assert!(funnel.payload_source_files >= 1, "{query}: {funnel:?}");
        // The token indexes prove the whole window keeps three row groups:
        // one selection and one fenced read of the three files (the field
        // form's cost), not a walk of widening chunks.
        assert_eq!(statements(&answer), 2, "{query}: {}", answer["planner"]);
        assert_eq!(answer["planner"]["chunks_executed"], json!(1), "{query}");
        assert!(
            !answer["planner"]["preselect"].is_null(),
            "{query}: whole-window preselect"
        );
        assert_eq!(
            answer["planner"]["fetched_files"],
            json!(3),
            "{query}: only the token's files"
        );
        let rows = rows_of(&answer);
        assert_eq!(ordered_uids(&rows), hash_rows(*keep), "{query}: truth");
        let reference_answer = envelope(&engine, &request(reference, now, 200)).await;
        report(reference, &reference_answer);
        let reference_rows = rows_of(&reference_answer);
        assert_eq!(
            ordered_uids(&rows),
            ordered_uids(&reference_rows),
            "{query} vs | where"
        );
        assert_eq!(
            digest(&rows),
            digest(&reference_rows),
            "{query}: rows hash-identical to | where"
        );
        assert_eq!(
            answer["result"]["page_has_more"], reference_answer["result"]["page_has_more"],
            "{query}"
        );
    }

    // Paging: the second page of the hash equals the reference's.
    let mut page = request(&format!("{HASH} | head 100"), now, 40);
    page.offset = 40;
    let mut reference_page = request(
        &format!("* | where like(message, \"%{HASH}%\") | sort -time | head 100"),
        now,
        40,
    );
    reference_page.offset = 40;
    let (page, reference_page) = (
        envelope(&engine, &page).await,
        envelope(&engine, &reference_page).await,
    );
    assert_eq!(
        ordered_uids(&rows_of(&page)),
        hash_rows(&all)[40..80].to_vec(),
        "page 2: truth"
    );
    assert_eq!(
        digest(&rows_of(&page)),
        digest(&rows_of(&reference_page)),
        "page 2 vs | where"
    );
    assert_eq!(
        page["result"]["page_has_more"], reference_page["result"]["page_has_more"],
        "page 2"
    );

    // A sparse token in every file: seeded from its blocks to one chunk.
    let sparse = "beacon7 | head 100";
    let _ = envelope(&engine, &request(sparse, now, 200)).await;
    let answer = envelope(&engine, &request(sparse, now, 200)).await;
    report(sparse, &answer);
    let truth = (0..ROWS)
        .filter(|i| i % 1_000 == 7)
        .take(100)
        .map(uid)
        .collect::<Vec<_>>();
    assert_eq!(ordered_uids(&rows_of(&answer)), truth, "{sparse}: truth");
    let reference = envelope(
        &engine,
        &request(
            "* | where like(message, \"%beacon7%\") | sort -time | head 100",
            now,
            200,
        ),
    )
    .await;
    assert_eq!(
        digest(&rows_of(&answer)),
        digest(&rows_of(&reference)),
        "{sparse} vs | where"
    );
    assert!(statements(&answer) <= 2, "{sparse}: {}", answer["planner"]);

    // The aggregate: exact counts by source.
    let query = format!("{HASH} | stats count by metadata.log_source");
    let step = request(&query, now, 200);
    let _ = envelope(&engine, &step).await;
    let (answer, funnel) = funneled(&engine, &step).await;
    report(&query, &answer);
    println!("NAN3172 funnel {query}: {funnel:?}");
    // NAN-3172: the stats (counting-eligible) path records its selection too.
    assert!(!funnel.progressive, "{query}: {funnel:?}");
    assert!(funnel.selections >= 1 && funnel.keyword_hints >= 1, "{query}: {funnel:?}");
    assert!(funnel.time_files >= funnel.fetched_files && funnel.fetched_files >= 3, "{query}: {funnel:?}");
    assert!(funnel.token_pruned_files > 0 && funnel.kept_row_groups >= 3, "{query}: {funnel:?}");
    assert_eq!(
        answer["planner"]["fetched_files"],
        json!(3),
        "{query}: only the token's files"
    );
    assert_eq!(answer["planner"]["kept_row_groups"], json!(3), "{query}");
    let rows = rows_of(&answer);
    assert_eq!(rows.len(), 1, "{query}: {rows:?}");
    assert_eq!(
        rows[0]["metadata.log_source"],
        json!("windows_sysmon"),
        "{query}"
    );
    assert_eq!(
        rows[0]["count"]
            .as_u64()
            .or_else(|| rows[0]["count"].as_str().and_then(|s| s.parse().ok())),
        Some(150),
        "{query}"
    );
    let reference =
        format!("* | where like(message, \"%{HASH}%\") | stats count by metadata.log_source");
    let reference_answer = envelope(&engine, &request(&reference, now, 200)).await;
    report(&reference, &reference_answer);
    assert_eq!(
        digest(&rows),
        digest(&rows_of(&reference_answer)),
        "{query} vs | where"
    );

    // The field form, for the cost target.
    let field = format!("process.file.hashes.value=\"{HASH}\" | head 100");
    let _ = envelope(&engine, &request(&field, now, 200)).await;
    let field_answer = envelope(&engine, &request(&field, now, 200)).await;
    report(&field, &field_answer);
    assert_eq!(
        ordered_uids(&rows_of(&field_answer)),
        hash_rows(&all),
        "{field}: truth"
    );

    // A common word (in every row): the page fills from the newest chunk.
    for query in [
        "create | head 100",
        "create | stats count by metadata.log_source",
    ] {
        let step = request(query, now, 200);
        let _ = envelope(&engine, &step).await;
        let answer = envelope(&engine, &step).await;
        report(query, &answer);
        assert!(!rows_of(&answer).is_empty(), "{query}");
    }
    let common = envelope(&engine, &request("create | head 100", now, 200)).await;
    assert_eq!(
        ordered_uids(&rows_of(&common)),
        (0..100).map(uid).collect::<Vec<_>>(),
        "create | head 100: truth"
    );
    // Estimated from the newest file's index alone: the page fits in the
    // newest minutes, so the default seeds and no whole-window preselect.
    assert!(
        statements(&common) <= 4,
        "create | head 100: {}",
        common["planner"]
    );
    assert_eq!(
        common["planner"]["density"]["token"]["consulted_files"],
        json!(1),
        "{}",
        common["planner"]
    );
    assert!(
        common["planner"]["preselect"].is_null(),
        "create | head 100: no whole-window preselect"
    );
}

/// Lab measurement on the realistic 24 h / 300 eps local dataset
/// (`lake_part_query_lab generate-local`, 26 M rows, v4 token indexes).
/// `NAN3170_DATASET=<work dir>`; prints statements, bytes and wall per shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "lab: NAN3170_DATASET, NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn realistic_day_bareword_shapes() {
    use crate::executor::{ExecutorMode, NativeExecutor};
    use crate::native::NativeChdb;
    use crate::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
    use crate::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
    use crate::part_query::log_view::PartLogView;
    use crate::parts::part_log::ObjectStore;
    use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
    const LAB_TENANT: &str = "b464ceb9-28a6-4249-8e29-3489627ac5f6";
    const LAB_BUCKET: &str = "nan2869-fixture";
    let Some(work) = std::env::var_os("NAN3170_DATASET").map(std::path::PathBuf::from) else {
        return;
    };
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    let key = ed25519_dalek::SigningKey::from_bytes(
        &sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(
            b"nan2869-lab-owner-key",
        ))
        .into(),
    );
    let signer = LocalPartSigner::new("nan2869-lab-owner-signer", key).unwrap();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(work.join("store")).unwrap());
    let view = PartLogView::open(store.as_ref(), LAB_TENANT, signer.trusted())
        .await
        .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = ReaderObjectCache::open(
        ReaderObjectCacheSettings {
            root: cache_dir.path().to_path_buf(),
            max_bytes: 40 << 30,
            query_max_bytes: 40 << 30,
            fetch_concurrency: 8,
            fetch_deadline: std::time::Duration::from_secs(600),
        },
        LAB_TENANT,
        LAB_BUCKET,
        &parts_key_prefix(LAB_TENANT).unwrap(),
        Arc::new(StoreObjectSource::local(
            LAB_BUCKET,
            store.clone(),
            work.join("store"),
        )),
    )
    .unwrap();
    let fetcher = PartFetcher::new(
        LAB_TENANT,
        LAB_BUCKET,
        store.clone(),
        signer.trusted(),
        cache,
    )
    .unwrap()
    .with_local_root(Some(work.join("store")));
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_with_server_memory_limit(
        runtime.clone(),
        2,
        "parts",
        ExecutorMode::ReadOnly,
        Some(6 << 30),
    )
    .unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(
        runtime,
        1,
        "parts-rw",
        ExecutorMode::ReadWrite,
        Some(6 << 30),
    )
    .unwrap();
    let engine = PartQueryEngine::new(
        EngineSettings {
            tenant_id: LAB_TENANT.into(),
            bucket: LAB_BUCKET.into(),
            compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
            max_query_bytes: 200 << 30,
            max_memory_bytes: 3 << 30,
            max_execution_seconds: 300,
            threads: 2,
        },
        store,
        view,
        fetcher,
        executor,
    )
    .unwrap()
    .with_writer(writer);
    let request = |query: &str| BroadNplRequest {
        request_id: "nan3170-lab".into(),
        tenant_id: LAB_TENANT.into(),
        dataset: "logs".into(),
        query: query.into(),
        start: "2026-09-24T00:00:00Z".into(),
        end: "2026-09-25T00:00:00Z".into(),
        limit: 200,
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
    };
    let authority = || {
        let tenant: uuid::Uuid = LAB_TENANT.parse().unwrap();
        nanosiem_core::platform_enrichment::read::ReadAuthorization::unknown(tenant, Utc::now())
    };
    let queries = std::env::var("NAN3170_QUERIES").unwrap_or_else(|_| {
        [
            "1000003 | head 100",
            "metadata.log_source=windows_sysmon 1000003 | head 100",
            "1000003 | stats count by metadata.log_source",
            "powershell | head 100",
            "metadata.log_source=windows_sysmon powershell | head 100",
        ]
        .join(";")
    });
    for query in queries.split(';').map(str::trim).filter(|q| !q.is_empty()) {
        for run in ["first", "warm"] {
            engine.clear_locator_cache();
            let started = std::time::Instant::now();
            let cpu = crate::query_timing::process_cpu_ms().unwrap_or(0.0);
            let answer = crate::query_timing::measure(
                "nan3170-lab",
                Box::pin(crate::enrichment_read::scope(
                    authority(),
                    engine.broad_npl(&request(query)),
                )),
            )
            .await
            .unwrap_or_else(|error| panic!("{query}: {error}"));
            let cpu = crate::query_timing::process_cpu_ms().unwrap_or(0.0) - cpu;
            let rows = rows_of(&answer);
            println!(
                "NAN3170-LAB {run} {query:?}: wall_ms={:.0} cpu_ms={cpu:.0} rows={} digest={}",
                started.elapsed().as_secs_f64() * 1000.0,
                rows.len(),
                &digest(&rows)[..12]
            );
            report(&format!("lab {run} {query}"), &answer);
        }
    }
}
