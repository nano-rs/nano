// SPDX-License-Identifier: AGPL-3.0-or-later
//! Repeatable NAN-4830 fixture on the production ingestor and query engine.
use super::*;

async fn seal_families(root: &std::path::Path, now: DateTime<Utc>) {
    use crate::part_ingest::writer::{publish_parts, PartDraft, PartWriter, PartialSource};
    use crate::parts::format::{schema_fingerprint, PartKeys};
    use crate::parts::part_log::{LogOp, PartLogWriter};
    use crate::parts::provenance::{InputPart, PartInputs};
    use crate::parts::DedupWindow;
    let store = LocalObjectStore::new(root.join("parts")).unwrap();
    let signer = signer();
    let view = PartLogView::open(&store, TENANT, signer.trusted())
        .await
        .unwrap();
    let schema = Arc::new(view.live().schema().unwrap().to_arrow().unwrap());
    let inputs = view.live().parts().cloned().collect::<Vec<_>>();
    let mut log = PartLogWriter::open(&store, TENANT, 1, &schema, now.timestamp_millis())
        .await
        .unwrap();
    for (n, input) in inputs.iter().enumerate() {
        let keys = PartKeys::new(TENANT, input.level, input.event_hour, &input.part_id).unwrap();
        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
            std::fs::File::open(root.join("parts").join(keys.data(0))).unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
        let batches = reader
            .map(|batch| crate::parts::indicators::strip(batch.unwrap()).unwrap())
            .collect::<Vec<_>>();
        let schema = batches[0].schema();
        let draft = PartDraft {
            tenant_id: TENANT.into(),
            signer_key_id: "lab-signer-nan3150".into(),
            level: crate::parts::levels::Level::Hour,
            event_hour: input.event_hour,
            schema: schema.clone(),
            schema_fingerprint: schema_fingerprint(&schema).unwrap(),
            inputs: PartInputs::Parts {
                parts: vec![InputPart {
                    part_id: input.part_id.clone(),
                    level: input.level,
                    provenance_sha256: input.provenance_sha256.clone(),
                    rows: input.rows,
                    merkle_root: input.merkle_root.clone(),
                }],
            },
            admission: None,
            rows_in: input.rows,
            duplicates_dropped: 0,
            window: DedupWindow::Exact,
            build: "nan4830-fixture".into(),
        };
        let at = now.timestamp_millis() + 1_000_000 + n as i64;
        let mut writer = PartWriter::create(
            &root.join("family-work"),
            draft,
            PartialSource::FromRows,
            at,
            input.rows,
        )
        .unwrap();
        writer
            .start_source_class(Some("windows_sysmon"), Some(1007))
            .unwrap();
        for batch in batches {
            writer.write(&batch).unwrap();
        }
        writer
            .set_logical_merkle_root(input.merkle_root.clone())
            .unwrap();
        let finished = writer.finish().unwrap();
        assert_eq!(finished.record.files.data.len(), 1);
        assert_eq!(finished.record.files.data[0].class_id, Some(1007));
        let output = publish_parts(&store, &signer, &signer.trusted(), &[finished])
            .await
            .unwrap()
            .remove(0);
        log.append(
            LogOp::Merge {
                output,
                supersedes: vec![input.part_id.clone()],
            },
            at,
        )
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn mythos_multi_file_scan_hunts() {
    let root = tempfile::tempdir().unwrap();
    // All rows belong to the same sealed event hour, independent of when
    // the benchmark starts (and therefore always produce 28 files).
    let now = chrono::DateTime::from_timestamp(Utc::now().timestamp() / 3_600 * 3_600, 0).unwrap();
    // 28 class-family files, 1,000 hosts in every file. Unique UIDs, hash
    // hits and process hits prevent count/empty-result shortcuts.
    let batches = (0..28).map(|file| (0..1_000).map(|host| {
        let i = file * 1_000 + host;
        let process = if host == 483 { "rundll32.exe" } else { "svchost.exe" };
        let text = format!("Process Create {process} seq {i} {}", if host == 483 { HASH } else { "" });
        let raw = format!("raw {text}");
        json!({
            "class_uid": 1007, "category_uid": 1, "activity_id": 1, "type_uid": 100701, "severity_id": 1,
            "time": (now - Duration::seconds(60 + i as i64 / 10)).to_rfc3339(),
            "process": {"name": process, "pid": i + 1, "file": {"name": process, "type_id": 1}},
            "actor": {"process": {"pid": 600, "name": "services.exe"}},
            "device": {"hostname": format!("ws-{host:04}.corp.local"), "type_id": 2},
            "status": "Success", "message": text, "raw_data": raw, "raw_data_size": raw.len(),
            "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": "windows_sysmon", "tenant_uid": TENANT,
                "product": {"name": "windows_sysmon", "vendor_name": "fixture"}},
        })
    }).collect()).collect();
    ingest_batches_with_merges(root.path(), now, batches, false).await;
    seal_families(root.path(), now).await;
    let engine = engine(root.path()).await;
    // Install the production process-wide thread budget, shared by all
    // query lanes. Clones share the executor's OnceLock with its worker.
    let threads = crate::thread_budget::ThreadBudget::new(engine.settings().threads);
    let _ = engine
        .executor()
        .clone()
        .with_thread_budget(threads.clone());
    if let Some(large) = &engine.large {
        let _ = large.executor().clone().with_thread_budget(threads.clone());
    }

    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let probe = runtime.connect(&[]).unwrap();
    let events = || -> std::collections::BTreeMap<String, u64> {
        let out = probe.query_with_params("SELECT event, value FROM system.events WHERE event IN ('ParquetMetadataCacheHits', 'ParquetMetadataCacheMisses', 'ReadBufferFromFileDescriptorReadBytes', 'OSReadBytes')", "JSONEachRow", &[]).unwrap();
        out.data
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                let row: Value = serde_json::from_slice(line).unwrap();
                (
                    row["event"].as_str().unwrap().to_string(),
                    row["value"]
                        .as_u64()
                        .or_else(|| row["value"].as_str().and_then(|s| s.parse().ok()))
                        .unwrap(),
                )
            })
            .collect()
    };
    let files = engine.hot_live_parts().await;
    assert_eq!(files.len(), 28, "fixture must fan out over 28 parts");
    let hunts = [
        // Verbatim shapes from benchmarks/agent-query/hunts.py.
        ("H1", format!("{HASH} | table time, device.hostname, class_uid | head 100")),
        ("H8", "class_uid=1007 | stats dc(device.hostname) as h by process.name | where h < 50 | sort h | head 20".to_string()),
        ("H10", format!("{HASH} | head 10")),
        ("host-point", "device.hostname=ws-0483.corp.local | table metadata.uid, device.hostname".to_string()),
        ("wide-28", "class_uid=1007 | where severity_id=1 | stats count by device.hostname".to_string()),
    ];
    let mut truth = std::collections::BTreeMap::new();
    for pass in 0..6 {
        for (name, query) in &hunts {
            let mut request = request(query, now, false);
            request.use_cache = false;
            if *name == "host-point" {
                request.start = (now - Duration::seconds(160)).to_rfc3339();
            }
            let before = engine.fetcher().cache().stats();
            let native_before = events();
            let started = std::time::Instant::now();
            let (answer, phases) = crate::query_timing::measure("nan4830", async {
                let answer = engine.broad_npl(&request).await?;
                let phases =
                    serde_json::to_value(&*crate::query_timing::current().unwrap().lock().unwrap())
                        .unwrap();
                Ok::<_, crate::part_query::engine::PartQueryError>((answer, phases))
            })
            .await
            .unwrap();
            let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(
                phases["threads_granted"], 2,
                "fixture must use the production thread budget"
            );
            let after = engine.fetcher().cache().stats();
            let rows = answer["result"]["rows"].as_array().expect("rows");
            assert!(!rows.is_empty(), "{name}: {answer}");
            if *name == "host-point" {
                assert_eq!(rows.len(), 1);
            }
            if *name == "H1" {
                assert_eq!(rows.len(), 28);
            }
            if *name == "H8" {
                assert_eq!(rows.len(), 1);
            }
            if *name == "H10" {
                assert_eq!(rows.len(), 10);
            }
            let mut canonical = rows
                .iter()
                .map(|row| serde_json::to_string(row).unwrap())
                .collect::<Vec<_>>();
            canonical.sort();
            if pass == 0 {
                truth.insert(*name, canonical);
            } else {
                assert_eq!(canonical, truth[name], "{name}: repeat result changed");
            }
            let native = events()
                .into_iter()
                .map(|(key, value)| {
                    let delta = value - native_before.get(&key).copied().unwrap_or(0);
                    (key, delta)
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            println!(
                "NAN4830 {}",
                json!({"hunt": name, "pass": pass,
                "wall_ms": wall_ms,
                "gets": after.misses - before.misses, "fetched_bytes": after.fetched_bytes - before.fetched_bytes,
                "storage_bytes": answer["result"]["storage_bytes"], "rows": rows.len(), "phases": phases,
                "native": native, "planner": answer["planner"], "evidence": engine.selection_evidence_status()})
            );
        }
    }
    engine_phase_variants(now, &engine, &probe).await;
    phase_matrix(root.path(), now, &engine, &probe).await;
}

fn phase_events(
    connection: &crate::native::NativeConnection,
) -> std::collections::BTreeMap<String, u64> {
    let out = connection.query_with_params(
        "SELECT event, value FROM system.events WHERE event LIKE '%Parquet%' OR event IN ('FileOpen', 'ReadBufferFromFileDescriptorRead', 'ReadBufferFromFileDescriptorReadBytes', 'OSReadBytes', 'UserTimeMicroseconds', 'SystemTimeMicroseconds', 'OSCPUWaitMicroseconds', 'OSIOWaitMicroseconds', 'OSCPUVirtualTimeMicroseconds')",
        "JSONEachRow", &[],
    ).unwrap();
    out.data
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let row: Value = serde_json::from_slice(line).unwrap();
            let value = row["value"]
                .as_u64()
                .or_else(|| row["value"].as_str().and_then(|s| s.parse().ok()))
                .unwrap();
            (row["event"].as_str().unwrap().to_string(), value)
        })
        .collect()
}

fn native_phase(
    connection: &crate::native::NativeConnection,
    sql: &str,
    params: &[(&str, &str)],
) -> anyhow::Result<Value> {
    let before = phase_events(connection);
    let started = std::time::Instant::now();
    // chDB rejects EXPLAIN on its streaming ABI. Keep this plan-only
    // materialized control separate from the streamed execution timings.
    if sql.starts_with("EXPLAIN ") {
        let output = connection.query_with_params(sql, "JSONEachRow", params)?;
        let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
        let native = phase_events(connection)
            .into_iter()
            .map(|(key, value)| {
                let delta = value.saturating_sub(before.get(&key).copied().unwrap_or(0));
                (key, delta)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        return Ok(
            json!({"abi": "materialized-plan-only", "wall_ms": wall_ms, "native": native,
            "storage_rows": output.storage_rows_read, "storage_bytes": output.storage_bytes_read,
            "result": String::from_utf8_lossy(&output.data)}),
        );
    }
    let mut init = crate::native::NativeInitTimings::default();
    let mut stream =
        connection.stream_query_with_params_timed(sql, "JSONEachRow", params, &mut init)?;
    let init_ms = started.elapsed().as_secs_f64() * 1000.0;
    let mut first_ms = None;
    let mut fetch_ms = 0.0;
    let eof_ms;
    let mut calls = 0;
    let mut data = Vec::new();
    let mut rows = 0;
    let mut bytes = 0;
    loop {
        let tick = std::time::Instant::now();
        let chunk = stream.fetch()?;
        let elapsed = tick.elapsed().as_secs_f64() * 1000.0;
        first_ms.get_or_insert(elapsed);
        fetch_ms += elapsed;
        calls += 1;
        let Some(chunk) = chunk else {
            eof_ms = elapsed;
            break;
        };
        rows = rows.max(chunk.storage_rows_read);
        bytes = bytes.max(chunk.storage_bytes_read);
        data.extend(chunk.data);
    }
    let tick = std::time::Instant::now();
    drop(stream);
    let drop_ms = tick.elapsed().as_secs_f64() * 1000.0;
    let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
    let native = phase_events(connection)
        .into_iter()
        .map(|(key, value)| {
            let delta = value.saturating_sub(before.get(&key).copied().unwrap_or(0));
            (key, delta)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let result = data
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(
        json!({"wall_ms": wall_ms, "init_ms": init_ms, "bind_ms": init.bind_ms, "init_abi_ms": init.abi_ms,
        "first_fetch_ms": first_ms, "fetch_ms": fetch_ms, "fetch_calls": calls, "eof_ms": eof_ms,
        "drop_ms": drop_ms, "storage_rows": rows, "storage_bytes": bytes, "native": native, "result": result}),
    )
}

async fn phase_matrix(
    root: &std::path::Path,
    now: DateTime<Utc>,
    engine: &PartQueryEngine,
    connection: &crate::native::NativeConnection,
) {
    use crate::part_ingest::merge::{merge_parts, MergeInput};
    use crate::part_query::fetch::PartFile;
    use crate::parts::format::{schema_fingerprint, PartKeys};
    let parts = engine.hot_live_parts().await;
    let wanted = parts
        .iter()
        .map(|part| (part.clone(), PartFile::Data(0)))
        .collect::<Vec<_>>();
    let local = engine.fetcher().ensure_files(&wanted).await.unwrap();
    let mut paths = local
        .files
        .iter()
        .map(|file| file.path.to_str().unwrap().to_string())
        .collect::<Vec<_>>();
    paths.sort();
    let store = LocalObjectStore::new(root.join("parts")).unwrap();
    let view = PartLogView::open(&store, TENANT, signer().trusted())
        .await
        .unwrap();
    let schema = Arc::new(view.live().schema().unwrap().to_arrow().unwrap());
    let structure = crate::iceberg::clickhouse_read_schema(&schema).unwrap();
    let inputs = parts
        .iter()
        .map(|part| MergeInput {
            dir: root.join("parts").join(
                PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id)
                    .unwrap()
                    .dir,
            ),
            part: part.clone(),
        })
        .collect::<Vec<_>>();
    let merged = merge_parts(
        &root.join("coalesced"),
        TENANT,
        crate::parts::levels::Level::Hour,
        parts[0].event_hour,
        &inputs,
        schema.clone(),
        &schema_fingerprint(&schema).unwrap(),
        "lab-signer-nan3150",
        "nan4830-phase-control",
        now.timestamp_millis() + 2_000_000,
    )
    .unwrap()
    .finished;
    assert_eq!(merged.record.files.data.len(), 1);
    assert_eq!(merged.record.rows, 28_000);
    let merged_path = merged.dir.join("data-00000.parquet");
    // Use the signed production compiler SQL; only substitute its verified source.
    let request = request("class_uid=1007 | stats dc(device.hostname) as h by process.name | where h < 50 | sort h | head 20", now, false);
    let compiled = engine
        .compile(&request, std::collections::BTreeMap::new())
        .await
        .unwrap();
    let source = "file({paths:String}, Parquet, {structure:String})";
    let h8 = compiled.sql.replace(&compiled.source_placeholder, source);
    println!(
        "NAN4830_SQL {}",
        json!({"h8": h8, "schema_bytes": structure.len(), "coalesced_files": merged.record.files.data})
    );
    let settings = connection.query_with_params("SELECT name, value FROM system.settings WHERE name LIKE '%parquet%' OR name IN ('max_threads', 'max_parsing_threads', 'max_io_threads', 'storage_file_read_method')", "JSONEachRow", &[]).unwrap();
    println!(
        "NAN4830_SETTINGS {}",
        String::from_utf8_lossy(&settings.data).replace('\n', " ")
    );
    let controls = [
        ("constant", "SELECT 1 AS n".to_string()),
        ("footer-count", format!("SELECT count() AS n FROM {source} SETTINGS use_cache_for_count_from_files=0")),
        ("scalar-scan", format!("SELECT sum(severity_id) AS n FROM {source}")),
        ("pruned-scan", format!("SELECT sum(length(tupleElement(device, 'hostname'))) AS n FROM {source} WHERE time >= toDateTime64('{}', 6, 'UTC') SETTINGS use_query_condition_cache=0, input_format_parquet_filter_push_down=1", (now + Duration::hours(24)).format("%Y-%m-%d %H:%M:%S"))),
        ("decode", format!("SELECT sum(length(tupleElement(device, 'hostname'))) AS n, sum(length(tupleElement(process, 'name'))) AS p FROM {source}")),
        ("H8", h8.clone()),
        ("plan-H8", format!("EXPLAIN PIPELINE {h8}")),
    ];
    let mut full_truth = std::collections::BTreeMap::new();
    for layout in ["fanout", "coalesced"] {
        for count in [1, 2, 8, 16, 28] {
            if layout == "coalesced" && count != 28 {
                continue;
            }
            let mut selected = if layout == "coalesced" {
                vec![merged_path.to_str().unwrap().to_string()]
            } else {
                paths[..count].to_vec()
            };
            let path_spec = crate::planner::local_path_spec(&mut selected).unwrap();
            let params = [
                ("paths", path_spec.as_str()),
                ("structure", structure.as_str()),
            ];
            for (shape, base) in &controls {
                let variants = if *shape == "H8" || *shape == "decode" {
                    vec![("default", ""), ("no-bloom", "input_format_parquet_bloom_filter_push_down=0"), ("no-pushdown", "input_format_parquet_filter_push_down=0"), ("no-prefetch", "input_format_parquet_enable_row_group_prefetch=0"), ("manual-decode", "max_parsing_threads=1"), ("manual-no-prefetch", "max_parsing_threads=1, input_format_parquet_enable_row_group_prefetch=0")]
                } else {
                    vec![("default", "")]
                };
                let mut reference = None;
                for (variant, setting) in variants {
                    let mut sql = crate::executor::with_setting(base, "readonly=2, max_threads=2, max_memory_usage=268435456, max_execution_time=120, max_parsing_threads=2, use_query_cache=0, use_parquet_metadata_cache=1, storage_file_read_method='pread'");
                    if !setting.is_empty() {
                        sql = crate::executor::with_setting(&sql, setting);
                    }
                    for pass in 0..6 {
                        match native_phase(connection, &sql, &params) {
                            Ok(result) => {
                                if count == 28 && *shape != "plan-H8" {
                                    if layout == "fanout" && variant == "default" && pass == 0 {
                                        full_truth.insert(*shape, result["result"].clone());
                                    } else if layout == "coalesced" {
                                        assert_eq!(
                                            &result["result"], &full_truth[shape],
                                            "coalesced result changed: {shape}"
                                        );
                                    }
                                }
                                if *shape == "pruned-scan" {
                                    assert_eq!(
                                        result["native"]["ParquetDecodingTasks"]
                                            .as_u64()
                                            .unwrap_or(0),
                                        0
                                    );
                                    assert_eq!(
                                        result["native"]["ParquetReadRowGroups"]
                                            .as_u64()
                                            .unwrap_or(0),
                                        0
                                    );
                                    assert_eq!(
                                        result["native"]["ParquetMetadataCacheHits"]
                                            .as_u64()
                                            .unwrap_or(0)
                                            + result["native"]["ParquetMetadataCacheMisses"]
                                                .as_u64()
                                                .unwrap_or(0),
                                        if layout == "coalesced" {
                                            1
                                        } else {
                                            count as u64
                                        }
                                    );
                                }
                                if let Some(expected) = &reference {
                                    assert_eq!(
                                        &result["result"], expected,
                                        "{shape}/{layout}/{count}/{variant}"
                                    );
                                } else {
                                    reference = Some(result["result"].clone());
                                }
                                if *shape == "footer-count" {
                                    assert_eq!(
                                        result["result"][0]["n"]
                                            .as_u64()
                                            .or_else(|| result["result"][0]["n"]
                                                .as_str()
                                                .and_then(|s| s.parse().ok())),
                                        Some(if layout == "coalesced" {
                                            28_000
                                        } else {
                                            count as u64 * 1_000
                                        })
                                    );
                                }
                                println!(
                                    "NAN4830_PHASE {}",
                                    json!({"layout": layout, "files": if layout=="coalesced" {1} else {count}, "rows": if layout=="coalesced" {28_000} else {count*1_000}, "shape": shape, "variant": variant, "pass": pass, "measurement": result})
                                );
                            }
                            Err(error) => panic!("{shape}/{layout}/{count}/{variant}: {error}"),
                        }
                    }
                }
            }
        }
    }
}

// Interleaved before/after over the production planner and budgeted lanes.
async fn engine_phase_variants(
    now: DateTime<Utc>,
    engine: &PartQueryEngine,
    connection: &crate::native::NativeConnection,
) {
    let mut truth = None;
    for count in [1, 8, 28] {
        let mut request = request("class_uid=1007 | stats dc(device.hostname) as h by process.name | where h < 50 | sort h | head 20", now, false);
        request.start = (now - Duration::seconds(59 + count as i64 * 100)).to_rfc3339();
        request.use_cache = false;
        let compiled = engine
            .compile(&request, std::collections::BTreeMap::new())
            .await
            .unwrap();
        let (from, to) = crate::part_query::engine::compiled_window_us(&compiled).unwrap();
        let selection = engine
            .select(from, to, &compiled.candidate_hints)
            .await
            .unwrap();
        let plan = crate::part_query::engine::plan_logs(&selection, &compiled, None).unwrap();
        assert_eq!(plan.budget.candidate_objects, count);
        // All files share one scan and statement setup, rather than N queries
        // or N independent file() sources. The path glob batches the file set.
        assert_eq!(plan.sql.matches("file(").count(), 1, "{}", plan.sql);
        if count > 1 {
            assert!(plan
                .params
                .iter()
                .any(|(_, value)| value.starts_with('/') && value.contains('{')));
        }
        let parsing = crate::part_query::lanes::setting(&plan.sql, "max_parsing_threads");
        assert_eq!(
            parsing,
            if count as u64 >= engine.settings().threads {
                Some(1)
            } else {
                None
            }
        );
        drop(selection);
        for pass in 0..8 {
            let variants = if pass % 2 == 0 {
                ["pooled", "policy"]
            } else {
                ["policy", "pooled"]
            };
            for variant in variants {
                let mut scope = crate::perf_overrides::Parsed::default();
                scope.probe = Some(crate::perf_overrides::Probe {
                    knobs: Default::default(),
                    // Reproduce the old production grant's parser pool for the
                    // same role. The policy variant uses unmodified planned SQL.
                    settings: if variant == "pooled" {
                        vec![("max_parsing_threads", engine.settings().threads.to_string())]
                    } else {
                        vec![]
                    },
                });
                let before = phase_events(connection);
                let cache_before = engine.fetcher().cache().stats();
                let started = std::time::Instant::now();
                let (answer, phases) = crate::query_timing::measure(
                    "nan4830-variant",
                    crate::perf_overrides::scoped(Some(Arc::new(scope)), async {
                        let answer = engine.broad_npl(&request).await?;
                        let phases = serde_json::to_value(
                            &*crate::query_timing::current().unwrap().lock().unwrap(),
                        )
                        .unwrap();
                        Ok::<_, crate::part_query::engine::PartQueryError>((answer, phases))
                    }),
                )
                .await
                .unwrap();
                let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
                let cache_after = engine.fetcher().cache().stats();
                let rows = answer["result"]["rows"].clone();
                assert_eq!(rows.as_array().unwrap().len(), 1);
                if let Some(truth) = &truth {
                    assert_eq!(truth, &rows);
                } else {
                    truth = Some(rows);
                }
                assert_eq!(phases["threads_granted"], engine.settings().threads);
                assert_eq!(phases["native_statements"], 1);
                assert_eq!(phases["native_session_reused"], 1);
                assert_eq!(phases["funnel"]["fetched_files"], count);
                let native = phase_events(connection)
                    .into_iter()
                    .map(|(key, value)| {
                        let delta = value.saturating_sub(before.get(&key).copied().unwrap_or(0));
                        (key, delta)
                    })
                    .collect::<std::collections::BTreeMap<_, _>>();
                assert_eq!(
                    native.get("ParquetMetadataCacheHits").copied().unwrap_or(0),
                    count as u64
                );
                assert_eq!(
                    native
                        .get("ParquetMetadataCacheMisses")
                        .copied()
                        .unwrap_or(0),
                    0
                );
                println!(
                    "NAN4830_ENGINE_VARIANT {}",
                    json!({"files": count, "variant": variant, "pass":pass, "wall_ms":wall_ms,
                    "gets": cache_after.misses-cache_before.misses, "fetched_bytes":cache_after.fetched_bytes-cache_before.fetched_bytes,
                    "phases":phases, "native":native, "planner":answer["planner"], "result": answer["result"]})
                );
            }
        }
    }
}
