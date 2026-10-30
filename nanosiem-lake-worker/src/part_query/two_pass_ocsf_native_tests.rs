// SPDX-License-Identifier: AGPL-3.0-or-later
//! External H1–H10 through the real compiler, signed parts and broad_npl.
use super::super::r2_wire_native_fixture::{MetadataStore, WireStore};
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "farm: real compiler/chDB and signed OCSF fixture; serial only"]
async fn mythos_ocsf_production_hunts() {
    run_hunts(1_000, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "farm: 1.12M OCSF rows, 28 files, 1000 hosts; serial only"]
async fn mythos_ocsf_scaled_hunts() {
    run_hunts(40_000, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "farm: same-host release comparison of the H1/H2 regression"]
async fn mythos_ocsf_regression_pair() {
    run_hunts(1_000, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "farm: 40k-row groups in the two point-hit files, 106k rows total"]
async fn mythos_ocsf_40k_point_groups_hunts() {
    run_hunts_with_layout(1_000, 40_000, false).await;
}

async fn run_hunts(rows_per_file: usize, regression_pair: bool) {
    run_hunts_with_layout(rows_per_file, rows_per_file, regression_pair).await;
}

// L0 admission can split an input batch. Seal each point input's
// pieces through the real signed writer/log merge contract so its 40k rows
// are one physical group, rather than assuming an input batch is one part.
async fn seal_point_inputs(root: &std::path::Path, now: DateTime<Utc>, rows: usize) {
    use crate::part_ingest::writer::{
        publish_parts, uid_strings, PartDraft, PartWriter, PartialSource,
    };
    use crate::parts::format::{schema_fingerprint, PartKeys};
    use crate::parts::part_log::{LogOp, PartLogWriter};
    use crate::parts::provenance::{row_digests_for_merge, InputPart, MerkleBuilder, PartInputs};
    let store = LocalObjectStore::new(root.join("parts")).unwrap();
    let signer = signer();
    let view = PartLogView::open(&store, TENANT, signer.trusted())
        .await
        .unwrap();
    let schema = Arc::new(view.live().schema().unwrap().to_arrow().unwrap());
    let live = view.live().parts().cloned().collect::<Vec<_>>();
    println!(
        "NAN4829B_INGEST_LAYOUT {}",
        json!({"rows": live.iter().map(|p| p.rows).sum::<u64>(), "part_rows": live.iter().map(|p| p.rows).collect::<Vec<_>>()})
    );
    let mut log = PartLogWriter::open(&store, TENANT, 1, &schema, now.timestamp_millis())
        .await
        .unwrap();
    for (n, class) in [1007, 4001].into_iter().enumerate() {
        let upper = now.timestamp_micros() - 60_000_000 - n as i64 * rows as i64 * 1_000;
        let lower = upper - (rows as i64 - 1) * 1_000;
        let mut inputs = live
            .iter()
            .filter(|p| p.min_time_us >= lower && p.max_time_us <= upper)
            .collect::<Vec<_>>();
        inputs.sort_by_key(|p| p.min_time_us);
        assert_eq!(
            inputs.iter().map(|p| p.rows).sum::<u64>(),
            rows as u64,
            "point input {n} must be covered by complete signed parts: {inputs:?}"
        );
        let mut batches = Vec::new();
        for input in &inputs {
            let keys =
                PartKeys::new(TENANT, input.level, input.event_hour, &input.part_id).unwrap();
            for file in 0..input.data_files as usize {
                let reader =
                    parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
                        std::fs::File::open(root.join("parts").join(keys.data(file))).unwrap(),
                    )
                    .unwrap()
                    .build()
                    .unwrap();
                for batch in reader {
                    batches.push(crate::parts::indicators::strip(batch.unwrap()).unwrap());
                }
            }
        }
        let schema = batches[0].schema();
        assert!(batches
            .iter()
            .all(|b| b.schema().fields() == schema.fields()));
        let draft = PartDraft {
            tenant_id: TENANT.into(),
            signer_key_id: "lab-signer-nan3150".into(),
            level: crate::parts::levels::Level::Hour,
            event_hour: inputs[0].event_hour,
            schema: schema.clone(),
            schema_fingerprint: schema_fingerprint(&schema).unwrap(),
            inputs: PartInputs::Parts {
                parts: inputs
                    .iter()
                    .map(|p| InputPart {
                        part_id: p.part_id.clone(),
                        level: p.level,
                        provenance_sha256: p.provenance_sha256.clone(),
                        rows: p.rows,
                        merkle_root: p.merkle_root.clone(),
                    })
                    .collect(),
            },
            admission: None,
            rows_in: rows as u64,
            duplicates_dropped: 0,
            window: crate::parts::DedupWindow::Exact,
            build: "nan4829-point-fixture".into(),
        };
        let at = now.timestamp_millis() + 1_000_000 + n as i64;
        let mut writer = PartWriter::create(
            &root.join("point-seal"),
            draft,
            PartialSource::FromRows,
            at,
            rows as u64,
        )
        .unwrap();
        writer
            .start_source_class(Some("windows_sysmon"), Some(class))
            .unwrap();
        let mut merkle = MerkleBuilder::new();
        for batch in batches {
            let uids = uid_strings(&batch).unwrap();
            for (row, digest) in row_digests_for_merge(&batch).unwrap().iter().enumerate() {
                merkle.push_row(uids.value(row), digest);
            }
            writer.write(&batch).unwrap();
        }
        writer
            .set_logical_merkle_root(merkle.root_hex().unwrap())
            .unwrap();
        let finished = writer.finish().unwrap();
        assert_eq!(finished.record.files.data.len(), 1);
        assert_eq!(finished.record.files.data[0].row_groups, 1);
        let output = publish_parts(&store, &signer, &signer.trusted(), &[finished])
            .await
            .unwrap()
            .remove(0);
        log.append(
            LogOp::Merge {
                output,
                supersedes: inputs.iter().map(|p| p.part_id.clone()).collect(),
            },
            at,
        )
        .await
        .unwrap();
    }
}

async fn run_hunts_with_layout(
    rows_per_file: usize,
    point_file_rows: usize,
    regression_pair: bool,
) {
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let root = tempfile::tempdir().unwrap();
    let now = DateTime::parse_from_rfc3339("2026-09-25T07:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let batches = (0..28).map(|file| (0..if file < 2 { point_file_rows } else { rows_per_file }).map(|row| {
        let i = if file < 2 { file * point_file_rows + row } else { 2 * point_file_rows + (file - 2) * rows_per_file + row };
        let class = [1007,4001,4003,3002,1001,4002][file % 6];
        let hit = row == 7;
        // Two hash hits in two class-family files model the lab's sparse
        // needle/raw-fetch case; IP/domain and rare-process hits still span
        // their respective class families.
        let hash_hit = hit && file < 2;
        let text = format!("event {i} {}", if hash_hit { HASH } else { "background" });
        let raw = format!("{text} {}", crate::parts::sha256_hex(text.as_bytes()).repeat(8));
        let opaque = (0..8).map(|n| crate::parts::sha256_hex(format!("opaque-{i}-{n}").as_bytes())).collect::<String>();
        let mut event = json!({
            "time": (now - if rows_per_file == 1_000 && point_file_rows == 1_000 { Duration::seconds(60 + i as i64 / 10) }
                else { Duration::microseconds(60_000_000 + i as i64 * 1_000) }).to_rfc3339(),
            "class_uid": class, "category_uid": class / 1000, "activity_id": 1,
            "type_uid": class * 100 + 1, "severity_id": 1, "status_id": 2,
            "status": "Failure", "message": text, "raw_data": raw, "raw_data_size": raw.len(),
            "device": {"hostname": format!("host-{:04}.corp.example", row % 1000), "type_id": 2},
            "process": {"name": if hit { "rare.exe" } else { "svchost.exe" },
                "cmd_line": "powershell -ExecutionPolicy Bypass", "pid": i+1,
                "file": {"name": "svchost.exe", "type_id": 1}},
            "actor": {"user": {"name": format!("user-{}", row%23)}},
            "dst_endpoint": {"ip": if hit { "198.51.100.7" } else { "192.0.2.1" },
                "domain": if hit { "bad.example" } else { "good.example" }},
            "query": {"hostname": if hit { "bad.example" } else { "good.example" }},
            "http_request": {"url": {"hostname": if hit { "bad.example" } else { "good.example" }}},
            "unmapped": {"opaque": opaque},
            "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "profiles": ["host"], "log_source": "windows_sysmon",
                "tenant_uid": TENANT, "product": {"name": "fixture", "vendor_name": "fixture"}}
        });
        let object = event.as_object_mut().unwrap();
        if !matches!(class, 1007) { object.remove("process"); }
        if !matches!(class, 1007 | 1001) { object.remove("actor"); }
        if !matches!(class, 4001 | 4002 | 4003 | 3002) { object.remove("dst_endpoint"); }
        if class != 4003 { object.remove("query"); }
        if class != 4002 { object.remove("http_request"); }
        if matches!(class, 4001 | 4002 | 4003 | 3002) {
            event["src_endpoint"] = json!({"ip": "10.0.0.7"});
        }
        if class == 3002 { event["user"] = json!({"name": format!("user-{}", row % 23)}); }
        if class == 1001 { event["file"] = json!({"name": "fixture.log", "path": "/tmp/fixture.log", "type_id": 1}); }
        if class == 4002 {
            event["http_request"]["http_method"] = json!("GET");
            event["http_request"]["url"]["url_string"] = json!(if hit { "https://bad.example/" } else { "https://good.example/" });
        }
        event
    }).collect()).collect();
    ingest_batches_with_merges(root.path(), now, batches, false).await;
    if point_file_rows != rows_per_file {
        seal_point_inputs(root.path(), now, point_file_rows).await;
    }
    let fixture_store = LocalObjectStore::new(root.path().join("parts")).unwrap();
    let layout = crate::parts::part_log::load_log(&fixture_store, TENANT)
        .await
        .unwrap();
    if point_file_rows != rows_per_file {
        let point_parts = layout
            .parts()
            .filter(|part| part.rows == point_file_rows as u64)
            .collect::<Vec<_>>();
        assert_eq!(
            point_parts.len(),
            2,
            "two point-hit parts must retain their target row count"
        );
        assert!(
            point_parts
                .iter()
                .all(|part| part.data_files == 1 && part.row_groups == 1),
            "each point-hit file must be one 40k-row group"
        );
    }
    println!(
        "NAN4829B_LAYOUT {}",
        json!({
            "rows": layout.parts().map(|p| p.rows).sum::<u64>(),
            "files": layout.parts().map(|p| p.data_files as u64).sum::<u64>(),
            "row_groups": layout.parts().map(|p| p.row_groups as u64).sum::<u64>(),
            "rows_per_file_input": rows_per_file,
            "point_file_rows": point_file_rows,
        })
    );
    let wire = WireStore::open(root.path().join("parts")).await;
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_with_server_memory_limit(
        runtime,
        1,
        "parts",
        ExecutorMode::ReadOnly,
        Some(2 << 30),
    )
    .unwrap();
    let thread_budget = crate::thread_budget::ThreadBudget::new(2);
    let executor = executor.with_thread_budget(thread_budget);
    let mut hunts: Vec<Value> = serde_json::from_str(include_str!(
        "../../../benchmarks/agent-query/hunts.fixture.json"
    ))
    .unwrap();
    hunts.sort_by_key(|hunt| if hunt["id"] == "H10" { 0 } else { 1 });
    for hunt in hunts {
        let id = hunt["id"].as_str().unwrap();
        if regression_pair && !matches!(id, "H1" | "H2") {
            continue;
        }
        let query = hunt["query"].as_str().unwrap();
        let mut truth = None;
        let mut timings = [Vec::new(), Vec::new()];
        let mut baseline_statements = [0_u64; 21];
        // Separate caches: the baseline must not warm the optimized reader.
        for (mode_index, mode) in ["single", "two"].into_iter().enumerate() {
            let metadata = Arc::new(MetadataStore::new(root.path().join("parts")));
            let store: Arc<dyn ObjectStore> = metadata.clone();
            let signer = signer();
            let cache = ReaderObjectCache::open(
                ReaderObjectCacheSettings {
                    root: root.path().join(format!("cache-{id}-{mode}")),
                    max_bytes: 2 << 30,
                    query_max_bytes: 2 << 30,
                    fetch_concurrency: 4,
                    fetch_deadline: std::time::Duration::from_secs(60),
                },
                TENANT,
                "bucket",
                &parts_key_prefix(TENANT).unwrap(),
                wire.source.clone(),
            )
            .unwrap();
            let fetcher =
                PartFetcher::new(TENANT, "bucket", store.clone(), signer.trusted(), cache).unwrap();
            let view = PartLogView::open(store.as_ref(), TENANT, signer.trusted())
                .await
                .unwrap();
            let engine = PartQueryEngine::new(
                EngineSettings {
                    tenant_id: TENANT.into(),
                    bucket: "bucket".into(),
                    compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
                    max_query_bytes: 64 << 30,
                    max_memory_bytes: 1 << 30,
                    max_execution_seconds: 120,
                    threads: 2,
                },
                store,
                view,
                fetcher,
                executor.clone(),
            )
            .unwrap();
            let mut req = request(query, now, false);
            req.limit = 500;
            req.use_cache = false;
            if mode == "single" {
                std::env::set_var("NANO_LAKE_TWO_PASS", "0");
            } else {
                std::env::remove_var("NANO_LAKE_TWO_PASS");
            }
            for pass in 0..21 {
                if pass == 1 {
                    // Populate the ordinary locator/full-file path and let
                    // the cache's two-second mtime collision fence settle.
                    // Keep promotion traffic visible outside steady p95.
                    let wire_before = wire.snapshot();
                    let meta_before = metadata.snapshot();
                    let warmup = engine.broad_npl(&req).await.unwrap();
                    assert_eq!(warmup["result"]["rows"].as_array().unwrap(), truth.as_ref().unwrap(),
                        "{id} {mode}: warm transition must preserve rows");
                    let wire_after = wire.snapshot();
                    let meta_after = metadata.snapshot();
                    println!("NAN4829B_WARMUP {}", json!({"hunt":id,"mode":mode,
                        "GETs":wire_after.0-wire_before.0,"bytes":wire_after.3-wire_before.3,
                        "metadata_GET_equivalents":meta_after.0-meta_before.0,
                        "metadata_HEAD_equivalents":meta_after.2-meta_before.2,
                        "metadata_LIST_equivalents":meta_after.3-meta_before.3,
                        "planner":warmup["planner"]}));
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
                let before = wire.snapshot();
                let metadata_before = metadata.snapshot();
                let started = std::time::Instant::now();
                let (answer, phases) = crate::query_timing::measure("nan4829b", async {
                    let answer = engine.broad_npl(&req).await?;
                    let phases = super::super::super::sql_probe::phases_json();
                    Ok::<_, crate::part_query::engine::PartQueryError>((answer, phases))
                })
                .await
                .unwrap_or_else(|e| panic!("{id} {mode}: {e}"));
                let wall_ms = started.elapsed().as_secs_f64() * 1000.;
                let native_statements = phases["native_statements"].as_u64().unwrap_or(0);
                if mode == "single" {
                    baseline_statements[pass] = native_statements;
                } else if id == "H10" && pass >= 2 {
                    assert!(native_statements <= baseline_statements[pass],
                        "warm H10 must restore the baseline locator topology: baseline={} enabled={native_statements}", baseline_statements[pass]);
                }
                if phases["native_statements"].as_u64().unwrap_or(0) > 0 {
                    assert_eq!(
                        phases["threads_granted"], 2,
                        "{id} must use the production thread budget"
                    );
                }
                let after = wire.snapshot();
                let metadata_after = metadata.snapshot();
                if mode == "two" {
                    let reason = answer["planner"]["two_pass_reason"].as_str().unwrap();
                    if matches!(id, "H1" | "H10") {
                        if point_file_rows < 40_000 || pass > 0 {
                            let expected = if point_file_rows < 40_000 { "small_or_unmeasured_row_groups" } else { "warm_row_page" };
                            assert_eq!(reason, expected, "{id}: {answer}");
                            assert_eq!(answer["planner"]["two_pass_chunks"].as_u64().unwrap_or(0), 0);
                            assert_eq!(answer["planner"]["two_pass"]["statements"].as_u64().unwrap_or(0), 0);
                            assert!(answer["planner"].get("range_fetch_rerun").is_none(), "decline before fetching: {answer}");
                        } else {
                            assert_eq!(reason, "eligible", "{id}: {answer}");
                            assert!(
                                answer["planner"].get("range_fetch_rerun").is_none(),
                                "{id}: eligible fixture must not hide a sparse-read failure: {answer}"
                            );
                            assert!(
                                answer["planner"]["two_pass_chunks"].as_u64().unwrap_or(0) > 0
                                    || answer["planner"]["two_pass"]["statements"]
                                        .as_u64()
                                        .unwrap_or(0)
                                        > 0,
                                "{id}: eligible plan must execute two passes: {answer}"
                            );
                        }
                    } else if id == "H9" {
                        assert_eq!(reason, "projection_has_no_wide_text");
                    } else {
                        assert!(
                            matches!(
                                reason,
                                "aggregate_stats_page" | "aggregate_requires_all_input_rows"
                            ),
                            "{id}: {reason}"
                        );
                    }
                }
                let rows = answer["result"]["rows"].as_array().unwrap();
                assert!(!rows.is_empty(), "{id}: nonempty reference result required");
                match id {
                    "H1" => assert_eq!(rows.len(), 2, "two planted hash hits"),
                    "H9" => assert_eq!(
                        rows.len(),
                        (2 * ((point_file_rows + 992) / 1000)
                            + 26 * ((rows_per_file + 992) / 1000))
                            .min(500)
                    ),
                    "H10" => {
                        assert_eq!(rows.len(), 2);
                        assert_eq!(
                            rows[0]["unmapped"]["opaque"].as_str().unwrap().len(),
                            512,
                            "full-event output must preserve producer payload"
                        );
                    }
                    "H2" => {
                        let number = |v: &Value| {
                            v.as_u64()
                                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                                .unwrap()
                        };
                        assert_eq!(number(&rows[0]["c"]), 19);
                        assert_eq!(number(&rows[0]["hosts"]), 1);
                    }
                    "H8" => assert_eq!(rows.len(), 1, "only rare.exe has fewer than 50 hosts"),
                    _ => {}
                }
                if let Some(truth) = &truth {
                    assert_eq!(rows, truth, "{id} {mode}: exact single-pass parity");
                } else {
                    truth = Some(rows.clone());
                }
                if pass > 0 {
                    timings[mode_index].push(wall_ms);
                }
                println!(
                    "NAN4829B {}",
                    json!({"hunt": id,"mode":mode,"pass":pass,"wall_ms":wall_ms,
                    "GETs":after.0-before.0,"bytes":after.3-before.3,
                    "metadata_GET_equivalents": metadata_after.0-metadata_before.0,
                    "metadata_bytes": metadata_after.1-metadata_before.1,
                    "metadata_HEAD_equivalents": metadata_after.2-metadata_before.2,
                    "metadata_LIST_equivalents": metadata_after.3-metadata_before.3,"rows":rows.len(),"planner":answer["planner"],"phases":phases})
                );
            }
            if mode == "two" && id == "H10" {
                let mut page_request = request(query, now, false);
                page_request.limit = 1;
                page_request.use_cache = false;
                let mut pages = Vec::new();
                for page_index in 0..2 {
                    let page = engine.broad_npl(&page_request).await.unwrap();
                    let rows = page["result"]["rows"].as_array().unwrap();
                    assert_eq!(rows.len(), 1);
                    assert_eq!(page["result"]["page_has_more"], page_index == 0);
                    let row = &rows[0];
                    let time = row["time"].as_str().unwrap().replace(' ', "T");
                    page_request.cursor_time = Some(if time.ends_with('Z') {
                        time
                    } else {
                        format!("{time}Z")
                    });
                    page_request.cursor_event_uid = Some(
                        row.pointer("/metadata/uid")
                            .unwrap()
                            .as_str()
                            .unwrap()
                            .to_string(),
                    );
                    pages.push(row.clone());
                }
                assert_eq!(
                    pages,
                    *truth.as_ref().unwrap(),
                    "full-event cursor pages must continue exactly"
                );
            }
            if mode == "two" {
                let compiled = engine
                    .compile_with_stats_page(&req, engine.field_types().await.unwrap(), true)
                    .await
                    .unwrap();
                println!(
                    "NAN4829B_COMPILED {} {}",
                    id,
                    serde_json::to_string(&compiled).unwrap()
                );
            }
        }
        for samples in &mut timings {
            samples.sort_by(f64::total_cmp);
        }
        // Nearest-rank p95 over 20 warm executions. Other hunts and the
        // small-group fallback must preserve the existing latency envelope.
        if !matches!(id, "H1" | "H10") || point_file_rows < 40_000 {
            assert!(timings[1][18] <= timings[0][18] * 1.05,
                "{id}: warm p95 regression single={:?} two={:?}", timings[0], timings[1]);
        }
        assert!(
            timings[1][10] <= timings[0][10] * 2.0 + 10.0,
            "{id}: warm p50 regression single={:?} two={:?}",
            timings[0],
            timings[1]
        );
    }
    std::env::remove_var("NANO_LAKE_TWO_PASS");
}
