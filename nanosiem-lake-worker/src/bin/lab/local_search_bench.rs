// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local-only synthetic workload and strict parity gate, sharing the lab's
//! production writer, signed log, compiler, planner and execution helpers.
use super::*;
use anyhow::ensure;
use std::sync::atomic::Ordering;

const VERSION: &str = "nano-local-search-v4";

pub(super) fn generate(work: &Path, hours: usize, eps: usize) -> Result<()> {
    ensure!([1, 24].contains(&hours), "hours must be 1 or 24");
    ensure!(
        (1..=300).contains(&eps),
        "eps must be 1..300 (300 for acceptance)"
    );
    std::fs::create_dir_all(work)?;
    let manifest = json!({"version": VERSION, "hours": hours, "eps": eps,
        "rows": hours * 3600 * eps, "end": CORPUS_END,
        "source_mix": {"windows_sysmon": 60, "windows_security": 15,
            "linux_auth": 10, "firewall": 10, "proxy": 5},
        "hosts": 400, "users": 600, "ips": 2048, "processes": 206, "common_process_period": 19,
        "rare_process": "SpeechModelDownload.exe", "rare_process_period": 20011,
        "flush_policy": "production default: 10s L0, 60s minute merges, sealed hours",
        "file_split_bytes": nanosiem_lake_worker::parts::format::DATA_FILE_SPLIT_BYTES});
    let marker = work.join("dataset.json");
    if marker.is_file() {
        ensure!(
            serde_json::from_slice::<Value>(&std::fs::read(&marker)?)? == manifest,
            "cached dataset configuration differs; choose a new directory"
        );
        return Ok(());
    }
    ensure!(
        !work.join("store").exists() && !work.join("packs").exists(),
        "incomplete dataset; choose a fresh directory or remove this disposable dataset explicitly"
    );
    nanosiem_lake_worker::parts::block_index::set_enabled(true);
    nanosiem_lake_worker::parts::token_counts::set_enabled(true);
    let packs = work.join("packs");
    std::fs::create_dir_all(&packs)?;
    let native = runtime()?;
    let connection = native.connect(&[
        "--memory_worker_use_cgroup=0",
        "--memory_worker_dynamic_hard_limit=0",
    ])?;
    let end = chrono::DateTime::parse_from_rfc3339(CORPUS_END)?.timestamp();
    for h in 0..hours {
        let hour = end / 3600 - hours as i64 + h as i64;
        let dir = packs.join(format!("event_hour={hour}"));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("events.parquet");
        let begin = Instant::now();
        // Independent modular periods avoid accidentally making every host's
        // events the same source or process. Stable unique times break top-K ties.
        let sql = format!(
            r#"
            INSERT INTO FUNCTION file({{out:String}}, Parquet)
            SELECT fromUnixTimestamp64Micro({} + intDiv(number * 1000000, {})) AS time,
              toInt64(1007) AS class_uid, 'Network Activity' AS category_name, toInt64(1 + number % 5) AS activity_id,
              toInt64(1 + number % 4) AS severity_id,
              CAST(tuple(concat('bench-', toString({hour}), '-', leftPad(toString(number), 8, '0')),
                multiIf(number % 100 < 60, 'windows_sysmon', number % 100 < 75, 'windows_security',
                  number % 100 < 85, 'linux_auth', number % 100 < 95, 'firewall', 'proxy'),
                '1.9.0', tuple('local-bench', 'synthetic')),
                'Tuple(uid String, log_source String, version String, product Tuple(name String, vendor_name String))') AS metadata,
              CAST(tuple(if(number % 101 < 3, 'busy.corp.local', concat('ws-support-', leftPad(toString(intDiv(number, 101) % 400), 3, '0'), '.corp.local'))),
                'Tuple(hostname String)') AS device,
              CAST(tuple(concat('ws-mkt-', leftPad(toString(intDiv(number, 103) % 400), 3, '0'), '.corp.local'),
                concat('10.20.', toString(intDiv(number, 107) % 8), '.', toString(intDiv(number, 109) % 256)), toInt64(49152 + number % 16000)),
                'Tuple(hostname String, ip String, port Int64)') AS src_endpoint,
              CAST(tuple(concat('172.16.1.', toString(number % 250)), toInt64(443)), 'Tuple(ip String, port Int64)') AS dst_endpoint,
              CAST(tuple(multiIf(number % 20011 = 0, 'SpeechModelDownload.exe', number % 19 = 0, 'powershell.exe', intDiv(number, 113) % 205 < 5, arrayElement(['powershell.exe','cmd.exe','svchost.exe','chrome.exe','sshd'], 1 + intDiv(number, 113) % 5), concat('worker-', toString(intDiv(number, 113) % 205), '.exe')),
                toInt64(number % 30000), concat('process --user ', toString(number % 600), ' --event ', toString(number)),
                tuple('explorer.exe', toInt64(4412))),
                'Tuple(name String, pid Int64, cmd_line String, parent_process Tuple(name String, pid Int64))') AS process,
              CAST(tuple(tuple(multiIf(number % 20011 = 0, 'SpeechModelDownload.exe', number % 19 = 0, 'powershell.exe', intDiv(number, 113) % 205 < 5, arrayElement(['powershell.exe','cmd.exe','svchost.exe','chrome.exe','sshd'], 1 + intDiv(number, 113) % 5), concat('worker-', toString(intDiv(number, 113) % 205), '.exe')), toInt64(number % 30000), 'actor command'), tuple(concat('user', toString(intDiv(number, 127) % 600)), 'CORP')),
                'Tuple(process Tuple(name String, pid Int64, cmd_line String), user Tuple(name String, domain String))') AS actor,
              concat('Process event ', toString(number), ' ', if(number % 97 = 0, 'powershell error', 'normal'), ' host activity') AS message,
              concat('<Event><Computer>', toString(number % 400), '</Computer><Data>', repeat(concat('value-', toString(number), ' '), 24), '</Data></Event>') AS raw_data
            FROM numbers({})
            SETTINGS max_threads=2, max_memory_usage=3000000000,
              output_format_parquet_row_group_size=65536, output_format_parquet_compression_method='zstd'
        "#,
            hour * 3600 * 1_000_000,
            eps,
            eps * 3600
        );
        connection.query_with_params(
            &sql,
            "JSONEachRow",
            &[("out", path.to_str().context("UTF-8 dataset path")?)],
        )?;
        eprintln!(
            "generated hour {h}: {} rows in {:.1}s",
            eps * 3600,
            begin.elapsed().as_secs_f64()
        );
    }
    let first = std::fs::read_dir(&packs)?
        .next()
        .context("no generated hour")??
        .path()
        .join("events.parquet");
    let schema = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(first)?)?
        .schema()
        .clone();
    std::fs::write(
        work.join("read_schema.txt"),
        nanosiem_lake_worker::iceberg::clickhouse_read_schema(&schema)?,
    )?;
    drop(connection);
    std::mem::forget(native);
    publish_generated(work, &packs, hours, eps)?;
    std::fs::write(marker, serde_json::to_vec_pretty(&manifest)?)?;
    std::fs::remove_dir_all(&packs)?;
    Ok(())
}

/// Replay production flush cadence and merges; references remain independent.
fn publish_generated(work: &Path, packs: &Path, hours: usize, eps: usize) -> Result<()> {
    use nanosiem_lake_worker::part_ingest::writer::sort_by_time_uid;
    let reference = work.join("reference");
    std::fs::create_dir_all(&reference)?;
    for entry in std::fs::read_dir(packs)? {
        let entry = entry?;
        let dest = reference.join(entry.file_name());
        std::fs::create_dir_all(&dest)?;
        std::fs::rename(
            entry.path().join("events.parquet"),
            dest.join("object.parquet"),
        )?;
    }
    let objects = reference_objects(work)?;
    let schema = objects_schema(&objects)?;
    let fingerprint = schema_fingerprint(&schema)?;
    let store = LocalObjectStore::new(work.join("store"))?;
    let scratch = work.join("parts-work");
    std::fs::create_dir_all(&scratch)?;
    let signer = signer();
    let trusted = signer.trusted();
    let flush = nanosiem_lake_worker::parts::levels::FlushPolicy::default();
    let interval_seconds = flush.interval_ms(eps as f64) as usize / 1000;
    let l0_rows = eps * interval_seconds;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let block_size = objects.len().div_ceil(4);
    let operations: Vec<Result<Vec<LogOp>>> = std::thread::scope(|scope| {
        let handles = objects
            .chunks(block_size)
            .enumerate()
            .map(|(block, objects)| {
                let (store, scratch, schema, fingerprint, signer, trusted) =
                    (&store, &scratch, &schema, &fingerprint, &signer, &trusted);
                scope.spawn(move || {
                    objects
                        .iter()
                        .enumerate()
                        .map(|(local, (hour, path))| {
                            let h = block * block_size + local;
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()?;
                            rt.block_on(async {
                                let mut operations = Vec::new();
                                let started = Instant::now();
                                let sha = nanosiem_lake_worker::native::file_sha256(path)?;
                                let bytes = std::fs::metadata(path)?.len();
                                let reader = ParquetRecordBatchReaderBuilder::try_new(
                                    std::fs::File::open(path)?,
                                )?
                                .with_batch_size(l0_rows)
                                .build()?;
                                let mut minute = Vec::<MergeInput>::new();
                                let mut hour_inputs = Vec::<MergeInput>::new();
                                for (chunk, batch) in reader.enumerate() {
                                    let batch = sort_by_time_uid(&batch?)?;
                                    let source_key = format!(
                                        "reference/event_hour={hour}/object.parquet#{chunk}"
                                    );
                                    let rows = batch.num_rows() as u64;
                                    let mut writer = PartWriter::create(
                                        &scratch,
                                        PartDraft {
                                            tenant_id: TENANT.into(),
                                            signer_key_id: SIGNER_KEY_ID.into(),
                                            level: Level::L0,
                                            event_hour: *hour,
                                            schema: schema.clone(),
                                            schema_fingerprint: fingerprint.clone(),
                                            inputs: PartInputs::Sources {
                                                edge_log: None,
                                                sources: vec![SourceObject {
                                                    key: source_key.clone(),
                                                    version: sha.clone(),
                                                    sha256: sha.clone(),
                                                    bytes,
                                                    rows,
                                                    edge_sha256: None,
                                                }],
                                            },
                                            admission: Some(Admission {
                                                ocsf_version: "1.9.0".into(),
                                                admission_contract: ADMISSION_CONTRACT.into(),
                                                feed_pins: BTreeMap::new(),
                                            }),
                                            rows_in: rows,
                                            duplicates_dropped: 0,
                                            window: DedupWindow::Exact,
                                            build: VERSION.into(),
                                        },
                                        PartialSource::FromRows,
                                        now_ms(),
                                        rows,
                                    )?;
                                    writer.write(&batch)?;
                                    let finished = writer.finish()?;
                                    let part = publish_parts(
                                        store,
                                        signer,
                                        &trusted,
                                        std::slice::from_ref(&finished),
                                    )
                                    .await?
                                    .remove(0);
                                    operations.push(LogOp::Add {
                                        edge_log: None,
                                        parts: vec![part.clone()],
                                        consumed: vec![SourceRef {
                                            key: source_key,
                                            version: sha.clone(),
                                            sha256: sha.clone(),
                                        }],
                                    });
                                    minute.push(MergeInput {
                                        part,
                                        dir: finished.dir,
                                    });
                                    let elapsed_seconds = (chunk + 1) * interval_seconds;
                                    if elapsed_seconds % 60 == 0 {
                                        // Keep the final minute of the open hour in L0. Earlier
                                        // minutes merge on the production 60s age cap.
                                        if h + 1 == hours && elapsed_seconds == 3600 {
                                            break;
                                        }
                                        let merged = merge_parts(
                                            &scratch,
                                            TENANT,
                                            Level::Minute,
                                            *hour,
                                            &minute,
                                            schema.clone(),
                                            &fingerprint,
                                            SIGNER_KEY_ID,
                                            VERSION,
                                            now_ms(),
                                        )?;
                                        let part = publish_parts(
                                            store,
                                            signer,
                                            &trusted,
                                            std::slice::from_ref(&merged.finished),
                                        )
                                        .await?
                                        .remove(0);
                                        operations.push(LogOp::Merge {
                                            output: part.clone(),
                                            supersedes: minute
                                                .iter()
                                                .map(|i| i.part.part_id.clone())
                                                .collect(),
                                        });
                                        for input in minute.drain(..) {
                                            std::fs::remove_dir_all(input.dir)?;
                                        }
                                        hour_inputs.push(MergeInput {
                                            part,
                                            dir: merged.finished.dir,
                                        });
                                    }
                                }
                                if h + 1 < hours {
                                    let merged = merge_parts(
                                        &scratch,
                                        TENANT,
                                        Level::Hour,
                                        *hour,
                                        &hour_inputs,
                                        schema.clone(),
                                        &fingerprint,
                                        SIGNER_KEY_ID,
                                        VERSION,
                                        now_ms(),
                                    )?;
                                    let output = publish_parts(
                                        store,
                                        signer,
                                        &trusted,
                                        std::slice::from_ref(&merged.finished),
                                    )
                                    .await?
                                    .remove(0);
                                    operations.push(LogOp::Merge {
                                        output,
                                        supersedes: hour_inputs
                                            .iter()
                                            .map(|i| i.part.part_id.clone())
                                            .collect(),
                                    });
                                    std::fs::remove_dir_all(merged.finished.dir)?;
                                }
                                for input in hour_inputs {
                                    std::fs::remove_dir_all(input.dir)?;
                                }
                                for input in minute {
                                    std::fs::remove_dir_all(input.dir)?;
                                }
                                eprintln!(
                                    "published production-cadence hour {h}: {:.1}s",
                                    started.elapsed().as_secs_f64()
                                );
                                Ok::<_, anyhow::Error>(operations)
                            })
                        })
                        .collect::<Vec<Result<Vec<LogOp>>>>()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .flat_map(|handle| match handle.join() {
                Ok(operations) => operations,
                Err(_) => vec![Err(anyhow::anyhow!("hour generation thread panicked"))],
            })
            .collect()
    });
    rt.block_on(async {
        let mut log = PartLogWriter::open(&store, TENANT, 1, &schema, now_ms()).await?;
        // Joining consecutive hour blocks retains event-hour order; each worker
        // retains Add/merge order. Only this thread appends to the signed log.
        for operations in operations {
            for operation in operations? {
                log.append(operation, now_ms()).await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    })?;
    std::fs::remove_dir_all(scratch)?;
    Ok(())
}

fn queries() -> Vec<(&'static str, String, Option<usize>)> {
    let source = "metadata.log_source=\"windows_sysmon\"";
    let host = format!("{source} device.hostname=\"ws-support-115.corp.local\"");
    vec![
        ("all", "*".into(), None),
        ("sysmon", source.into(), Some(0)),
        ("device", host.clone(), Some(1)),
        (
            "src_host",
            format!("{source} src_endpoint.hostname=\"ws-mkt-068.corp.local\""),
            Some(1),
        ),
        (
            "process",
            format!("{host} process.name=\"powershell.exe\""),
            Some(2),
        ),
        ("keyword", "powershell".into(), Some(0)),
        ("parent_page", format!("{source} category_name=\"Network Activity\""), Some(1)),
        ("busy_host", format!("{source} category_name=\"Network Activity\" device.hostname=\"busy.corp.local\""), Some(6)),
        ("rare_child", format!("{source} category_name=\"Network Activity\" actor.process.name=\"SpeechModelDownload.exe\""), Some(6)),
    ]
}

fn store_counters(lab: &Lab) -> (u64, u64) {
    let store = lab.measured_store.as_ref().expect("measured lab");
    (
        store.gets.load(Ordering::Relaxed),
        store.bytes.load(Ordering::Relaxed),
    )
}

fn count(rows: &[Value]) -> Result<u64> {
    rows.iter().try_fold(0_u64, |sum, row| {
        let n = row["count"]
            .as_u64()
            .or_else(|| row["count"].as_str().and_then(|s| s.parse().ok()))
            .context("missing numeric count")?;
        sum.checked_add(n).context("count overflow")
    })
}

/// Exact rollup shapes selected by core search for the fixed corpus. The
/// three-predicate and keyword cases use compiled nPL, as the API does.
fn companion_route(
    name: &str,
    kind: &str,
    req: &BroadNplRequest,
) -> Result<Option<CountAggregateRequest>> {
    let (field, value, source) = match name {
        "all" => ("metadata.log_source", None, None),
        "sysmon" => ("metadata.log_source", Some("windows_sysmon"), None),
        "device" => (
            "device.hostname",
            Some("ws-support-115.corp.local"),
            Some("windows_sysmon"),
        ),
        "src_host" => (
            "src_endpoint.hostname",
            Some("ws-mkt-068.corp.local"),
            Some("windows_sysmon"),
        ),
        _ => return Ok(None),
    };
    if kind == "rows" {
        return Ok(None);
    }
    Ok(Some(serde_json::from_value(json!({
        "request_id": req.request_id, "tenant_id": TENANT, "group_field": field,
        "group_results": false,
        "predicate": value.map(|value| json!({"kind": "eq", "values": [value]})),
        "bucket_span_us": if kind == "histogram" { Some(300_000_000_i64) } else { None },
        "count_alias": "count", "start": req.start, "end": req.end,
        "source_filter": source, "max_groups": 100_000,
    }))?))
}

async fn companion_rows(
    lab: &Lab,
    name: &str,
    kind: &str,
    req: &BroadNplRequest,
) -> Result<(Vec<Value>, bool, f64, Value)> {
    let Some(count) = companion_route(name, kind, req)? else {
        return parts_rows(lab, req).await;
    };
    let started = Instant::now();
    let result = nanosiem_lake_worker::query_timing::measure(
        &req.request_id,
        nanosiem_lake_worker::enrichment_read::scope(
            lab_authority(),
            partials::count_aggregate(&lab.engine, &count),
        ),
    )
    .await;
    let envelope = match result {
        Ok(envelope) => envelope,
        Err(error) => {
            // Core search falls back when a partial cannot serve the shape.
            let (rows, more, _, mut evidence) = parts_rows(lab, req).await?;
            evidence["count_route_fallback"] = json!(error.to_string());
            return Ok((rows, more, started.elapsed().as_secs_f64(), evidence));
        }
    };
    let rows = envelope["result"]["rows"]
        .as_array()
        .context("count route rows")?
        .clone();
    let mut evidence = envelope["planner"].clone();
    evidence["route"] = json!("count_aggregate");
    evidence["native_storage_rows"] = envelope["result"]["storage_rows"].clone();
    evidence["native_storage_bytes"] = envelope["result"]["storage_bytes"].clone();
    evidence["native_execute_s"] = envelope["result"]["engine_seconds"].clone();
    Ok((rows, false, started.elapsed().as_secs_f64(), evidence))
}

fn work_exceeds(child: &Value, parent: &Value) -> Vec<String> {
    [
        "get_calls",
        "get_bytes",
        "data_parts_fetched",
        "data_row_groups_fetched",
        "fetched_files",
        "kept_row_groups",
        "native_storage_rows",
        "native_storage_bytes",
    ]
    .iter()
    .filter_map(|key| {
        let (a, b) = (child[*key].as_u64()?, parent[*key].as_u64()?);
        (a > b).then(|| format!("{key}: {a} > {b}"))
    })
    .collect()
}

/// Optional specialty corpus: same local store/production signer/compiler,
/// independently unpruned reference, fresh copying cache for each path.
async fn asset_facets(work: &Path, manifest: Value) -> Result<Value> {
    let hours = manifest["hours"].as_u64().context("dataset hours")?;
    let end = chrono::DateTime::parse_from_rfc3339(CORPUS_END)?;
    let predicate = "(device.hostname IN (\"ws-support-008.corp.local\") OR src_endpoint.hostname IN (\"ws-mkt-008.corp.local\"))";
    let normalize = |row: &Value| {
        let mut row = row.clone();
        for field in ["event_count", "class_uid", "asset_auth_failure"] {
            if let Some(number) = row[field]
                .as_str()
                .and_then(|text| text.parse::<u64>().ok())
            {
                row[field] = json!(number);
            }
        }
        row
    };
    let mut results = Vec::new();
    let mut failures = Vec::new();
    for window in [1, 24].into_iter().filter(|window| *window <= hours) {
        let start = (end - chrono::Duration::hours(window as i64)).to_rfc3339();
        for (name, base) in [
            ("asset_raw", format!("{predicate} AND class_uid>=0")),
            ("asset_facets", predicate.into()),
        ] {
            let cache = tempfile::Builder::new()
                .prefix("asset-cache-")
                .tempdir_in(work)?;
            let lab = open_lab_inner(work, cache.path(), true, true).await?;
            let req = request(
                "local-asset",
                &format!(
                    "{base}{}",
                    nanosiem_lake_worker::asset_facet_summaries::SUFFIX
                ),
                &start,
                CORPUS_END,
                10_000,
                false,
            );
            let mut runs = Vec::new();
            let mut parity = true;
            for temperature in ["cold", "warm"] {
                let before = store_counters(&lab);
                let (rows, more, seconds, evidence) = parts_rows(&lab, &req).await?;
                let after = store_counters(&lab);
                // The reference bypasses part selection and every signed summary.
                let (reference, reference_more, _) = reference_rows(&lab, &req).await?;
                let matches = !more
                    && !reference_more
                    && !rows.is_empty()
                    && canonical_with(&rows, &normalize) == canonical_with(&reference, &normalize);
                parity &= matches;
                runs.push(json!({"temperature":temperature, "wall_ms":seconds*1000.0,
                    "get_calls":after.0-before.0, "get_bytes":after.1-before.1,
                    "planner":evidence, "parity":matches, "groups":rows.len()}));
            }
            if !parity {
                failures.push(format!("{window}h {name}: groups/count parity failed"));
            }
            eprintln!(
                "{window}h {name}: cold={}ms warm={}ms parity={parity}",
                runs[0]["wall_ms"], runs[1]["wall_ms"]
            );
            results.push(json!({"window_hours":window,"name":name,"parity":parity,"runs":runs}));
        }
    }
    Ok(
        json!({"dataset":manifest,"corpus":"asset_facets","passed":failures.is_empty(),"failures":failures,"queries":results}),
    )
}

pub(super) async fn run(work: &Path) -> Result<Value> {
    let manifest: Value = serde_json::from_slice(&std::fs::read(work.join("dataset.json"))?)?;
    ensure!(manifest["version"] == VERSION, "unknown dataset version");
    if std::env::var("BENCH_SPECIALTY_ASSET").as_deref() == Ok("1") {
        return asset_facets(work, manifest).await;
    }
    ensure!(std::env::var("BENCH_CASE").map_or(true, |case| case == "parent_page"),
        "BENCH_CASE, when set, must be parent_page");
    let hours = manifest["hours"].as_u64().context("dataset hours")?;
    let end = chrono::DateTime::parse_from_rfc3339(CORPUS_END)?;
    let mut results = Vec::new();
    let mut failures = Vec::new();
    eprintln!("window query         cold ms   warm ms   rows      total parity/work");
    for window in [1, 24].into_iter().filter(|h| *h <= hours) {
        let start = (end - chrono::Duration::hours(window as i64)).to_rfc3339();
        let mut work_by_query = Vec::<Vec<Vec<Value>>>::new();
        let mut cases = queries();
        let latest_hour = end.timestamp() / 3600 - 1;
        cases.push((
            "detail_uid",
            format!("metadata.uid=\"bench-{latest_hour}-00000100\""),
            None,
        ));
        if std::env::var("BENCH_CASE").as_deref() == Ok("parent_page") {
            cases.retain(|case| case.0 == "parent_page");
            cases[0].2 = None;
        }
        for (name, query, parent) in &cases {
            // A fresh object cache and engine for EACH case; warm repeats exactly
            // the same requests. Neither parent nor reference primes the child.
            let cache = tempfile::Builder::new()
                .prefix("query-cache-")
                .tempdir_in(work)?;
            eprintln!("{window}h {name}: opening engine");
            let opened = Instant::now();
            let lab = open_lab_inner(work, cache.path(), true, true).await?;
            eprintln!("{window}h {name}: engine ready");
            let open_ms = opened.elapsed().as_secs_f64() * 1000.0;
            let page = request(
                "local-page",
                query,
                &start,
                CORPUS_END,
                if *name == "detail_uid" { 1 } else { 100 },
                *name != "detail_uid",
            );
            let hist = request(
                "local-hist",
                &format!("{query} | timechart span=5m count() as count"),
                &start,
                CORPUS_END,
                100_000,
                false,
            );
            let total = request(
                "local-count",
                &format!("{query} | stats count() as count"),
                &start,
                CORPUS_END,
                100,
                false,
            );
            let mut runs = Vec::new();
            let mut case_work = Vec::new();
            for temperature in ["cold", "warm", "warm"] {
                if temperature == "warm" {
                    // Newly copied files are deliberately rehashed while their
                    // mtime can collide with the clock. Let that integrity
                    // guard mature to model older immutable live cache files.
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                lab.engine.clear_locator_cache();
                let mut outputs = Vec::new();
                let mut request_work = Vec::new();
                for (kind, req) in [("rows", &page), ("histogram", &hist), ("count", &total)] {
                    eprintln!("{window}h {name} {temperature} {kind}: starting");
                    let before = store_counters(&lab);
                    let measured = lab.measured_store.as_ref().expect("measured lab");
                    measured
                        .fetched_parts
                        .lock()
                        .map_err(|_| anyhow::anyhow!("GET measurement lock poisoned"))?
                        .clear();
                    let groups_before = measured.fetched_row_groups.load(Ordering::Relaxed);
                    let cache_before = lab.engine.fetcher().cache().stats();
                    let (rows, more, seconds, evidence) = if *name == "detail_uid" && kind == "rows"
                    {
                        let started = Instant::now();
                        let detail = nanosiem_lake_worker::part_query::engine::FetchLogRequest {
                            request_id: "local-detail".into(),
                            tenant_id: TENANT.into(),
                            id: format!("bench-{latest_hour}-00000100"),
                            start: Some(start.clone()),
                            end: Some(CORPUS_END.into()),
                            log_source: None,
                            deny_source_types: BTreeSet::new(),
                        };
                        let envelope = nanosiem_lake_worker::enrichment_read::scope(
                            lab_authority(),
                            lab.engine.fetch_log(&detail),
                        )
                        .await
                        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                        let rows = envelope["result"]["rows"]
                            .as_array()
                            .context("detail rows")?
                            .clone();
                        let mut evidence = envelope["planner"].clone();
                        evidence["route"] = json!("fetch_log");
                        evidence["native_storage_rows"] =
                            envelope["result"]["storage_rows"].clone();
                        evidence["native_storage_bytes"] =
                            envelope["result"]["storage_bytes"].clone();
                        (rows, false, started.elapsed().as_secs_f64(), evidence)
                    } else {
                        companion_rows(&lab, name, kind, req).await?
                    };
                    if *name == "parent_page" && kind == "rows" {
                        let max_ms = if temperature == "cold" { 400.0 } else { 150.0 };
                        if seconds * 1000.0 > max_ms {
                            failures.push(format!("{window}h parent_page {temperature}: {:.1} ms exceeds {max_ms} ms", seconds * 1000.0));
                        }
                    }
                    eprintln!("{window}h {name} {temperature} {kind}: {:.1}ms", seconds * 1000.0);
                    let after = store_counters(&lab);
                    let mut counters = evidence.clone();
                    counters["get_calls"] = json!(after.0 - before.0);
                    counters["get_bytes"] = json!(after.1 - before.1);
                    counters["data_parts_fetched"] = json!(measured
                        .fetched_parts
                        .lock()
                        .map_err(|_| anyhow::anyhow!("GET measurement lock poisoned"))?
                        .len());
                    counters["data_row_groups_fetched"] =
                        json!(measured.fetched_row_groups.load(Ordering::Relaxed) - groups_before);
                    let cache_after = lab.engine.fetcher().cache().stats();
                    counters["verified_cache_hits"] = json!(cache_after.hits - cache_before.hits);
                    counters["verified_cache_misses"] =
                        json!(cache_after.misses - cache_before.misses);
                    counters["verified_cache_fetched_bytes"] =
                        json!(cache_after.fetched_bytes - cache_before.fetched_bytes);
                    if temperature == "warm" && cache_after.misses != cache_before.misses {
                        failures.push(format!(
                            "{window}h {name} {kind}: warm verified cache had misses"
                        ));
                    }
                    request_work.push(counters.clone());
                    outputs.push(json!({"kind": kind, "wall_ms": seconds * 1000.0,
                        "rows": rows, "has_more": more, "evidence": counters}));
                }
                case_work.push(request_work);
                runs.push(json!({"temperature": temperature, "requests": outputs}));
            }
            let mut parity = true;
            for (n, req) in [&page, &hist, &total].into_iter().enumerate() {
                // Independent reference path has no token/entity/part pruning.
                let (reference, more, _) = reference_rows(&lab, req).await?;
                for run in &runs {
                    let actual = run["requests"][n]["rows"].as_array().context("rows")?;
                    if canonical(actual) != canonical(&reference)
                        || run["requests"][n]["has_more"] != more
                    {
                        parity = false;
                        failures.push(format!(
                            "{window}h {name} {} {} parity mismatch",
                            run["temperature"], run["requests"][n]["kind"]
                        ));
                    }
                }
            }
            if *name == "rare_child" {
                for run in &runs {
                    let cap = if run["temperature"] == "cold" { 2000.0 } else { 1000.0 };
                    let ms = run["requests"][0]["wall_ms"].as_f64().context("rows wall time")?;
                    if ms > cap { failures.push(format!("{window}h rare_child {} rows latency {ms:.1}ms > {cap}ms", run["temperature"])); }
                }
            }
            let total_count = count(
                runs[0]["requests"][2]["rows"]
                    .as_array()
                    .context("count rows")?,
            )?;
            let histogram_count = count(
                runs[0]["requests"][1]["rows"]
                    .as_array()
                    .context("hist rows")?,
            )?;
            if total_count != histogram_count || total_count == 0 {
                parity = false;
                failures.push(format!("{window}h {name}: empty fixture match or histogram/count mismatch ({histogram_count}/{total_count})"));
            }
            let mut monotonic = Vec::new();
            if let Some(parent) = parent {
                for (temperature, (child_requests, parent_requests)) in ["cold", "warm", "warm"]
                    .into_iter()
                    .zip(case_work.iter().zip(&work_by_query[*parent]))
                {
                    for (n, (child, parent)) in
                        child_requests.iter().zip(parent_requests).enumerate()
                    {
                        // Page queries stop once full. A rare child must scan
                        // more predicate rows than its dense parent; monotonic
                        // work only applies to exhaustive companions.
                        if n == 0 { continue; }
                        for failure in work_exceeds(child, parent) {
                            monotonic.push(format!("{temperature} request {n}: {failure}"));
                        }
                    }
                }
            }
            // Work is diagnostic, not parity or latency: rollup/memo routes,
            // added predicate leaves and per-request cache priming make raw
            // bytes/GET monotonicity ill-posed even for companions. Preserve
            // every observation; compare identical shapes off/on for regression.
            let wall = |run: &Value| {
                run["requests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| r["wall_ms"].as_f64().unwrap())
                    .sum::<f64>()
            };
            eprintln!(
                "{window:>4}h {name:<12} {:>9.1} {:>9.1} {:>6} {total_count:>10} {}/{}",
                wall(&runs[0]),
                wall(&runs[1]),
                runs[0]["requests"][0]["rows"].as_array().unwrap().len(),
                if parity { "PASS" } else { "FAIL" },
                if monotonic.is_empty() { "PASS" } else { "NOTE" }
            );
            results.push(json!({"window_hours": window, "name": name, "query": query,
                "parent": parent.map(|p| cases[p].0), "engine_open_ms": open_ms,
                "total_count": total_count, "parity": parity, "work_observations": monotonic, "runs": runs}));
            work_by_query.push(case_work);
            drop(lab);
            drop(cache);
        }
    }
    Ok(
        json!({"dataset": manifest, "get_latency_ms": get_latency().as_millis(),
        "native_execution": "streaming statements on persistent per-lane connections; native_init_ms excludes connection startup",
        "cache": "fresh verified copying cache per case; warm waits 2s for mtime guards then repeats rows/histogram/count with locator cache cleared",
        "passed": failures.is_empty(), "failures": failures, "queries": results}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_parent_work_regression_and_missing_counters() {
        assert_eq!(
            work_exceeds(&json!({"get_calls": 3}), &json!({"get_calls": 2})),
            vec!["get_calls: 3 > 2"]
        );
        assert!(work_exceeds(&json!({"get_calls": 1}), &json!({"get_calls": 2})).is_empty());
        assert!(work_exceeds(&json!({}), &json!({})).is_empty());
    }
    #[test]
    fn companion_routing_keeps_only_exact_supported_shapes() {
        let req = request("test", "*", "2026-09-24T00:00:00Z", CORPUS_END, 100, false);
        let host = companion_route("device", "histogram", &req)
            .unwrap()
            .unwrap();
        assert_eq!(host.group_field, "device.hostname");
        assert_eq!(host.source_filter.as_deref(), Some("windows_sysmon"));
        assert_eq!(host.bucket_span_us, Some(300_000_000));
        assert!(host.validate_shape().is_ok());
        assert!(companion_route("device", "rows", &req).unwrap().is_none());
        assert!(companion_route("process", "count", &req).unwrap().is_none());
        assert!(companion_route("keyword", "histogram", &req)
            .unwrap()
            .is_none());
    }
    #[test]
    fn rejects_missing_counts_and_overflow() {
        assert!(count(&[json!({})]).is_err());
        assert!(count(&[json!({"count": u64::MAX}), json!({"count": 1})]).is_err());
        assert_eq!(
            count(&[json!({"count": "5"}), json!({"count": 2})]).unwrap(),
            7
        );
    }
}
