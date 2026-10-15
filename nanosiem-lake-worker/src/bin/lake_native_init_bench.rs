// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local-only native init probe: persistent connection, wide Parquet, file fanout.
use anyhow::{ensure, Context, Result};
use nanosiem_lake_worker::native::{NativeChdb, NativeInitTimings};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

fn data_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            data_files(&path, files)?;
        } else if path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("data-") && s.ends_with(".parquet"))
        {
            files.push(path);
        }
    }
    Ok(())
}

fn path_spec(files: &[PathBuf]) -> Result<String> {
    let mut paths = files
        .iter()
        .map(|p| p.to_str().context("UTF-8 path").map(str::to_string))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        paths
            .iter()
            .all(|p| !p.contains(['{', '}', ',', '*', '?', '[', ']'])),
        "unsupported glob path"
    );
    Ok(nanosiem_lake_worker::planner::local_path_spec(&mut paths)?)
}

/// Build disposable large-part fanout using the same wide rows. Distinct
/// reflink paths exercise native file setup without duplicating physical data.
fn prepare_large(input: &Path, output: &Path) -> Result<()> {
    ensure!(
        !output.exists(),
        "choose a fresh disposable output directory"
    );
    let mut files = Vec::new();
    data_files(&input.join("store"), &mut files)?;
    files.sort();
    ensure!(files.len() >= 30, "need 30 source files");
    let glob = path_spec(&files[..30])?;
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH")?,
        &std::env::var("NANO_CHDB_LIBRARY_SHA256")?,
    )?;
    std::mem::forget(runtime.clone());
    let connection = runtime.connect(&[
        "--memory_worker_use_cgroup=0",
        "--memory_worker_dynamic_hard_limit=0",
    ])?;
    std::fs::create_dir_all(output.join("store"))?;
    let seed = output.join("store/data-00000.parquet");
    connection.query_with_params(
        "INSERT INTO FUNCTION file({out:String}, Parquet) SELECT * FROM file({source:String}, Parquet) SETTINGS max_threads=1, max_block_size=8192, max_memory_usage=8000000000, output_format_parquet_row_group_size=8192, output_format_parquet_compression_method='zstd'",
        "Null", &[("out", seed.to_str().context("UTF-8 output")?), ("source", &glob)],
    )?;
    let bytes = std::fs::metadata(&seed)?.len();
    ensure!(
        (64 * 1024 * 1024..=1024 * 1024 * 1024).contains(&bytes),
        "merged fixture is outside 64 MiB–1 GiB: {bytes} bytes"
    );
    for index in 1..120 {
        let target = output.join(format!("store/data-{index:05}.parquet"));
        ensure!(
            std::process::Command::new("cp")
                .arg("--reflink=always")
                .arg("--")
                .arg(&seed)
                .arg(&target)
                .status()?
                .success(),
            "fixture requires filesystem reflink support"
        );
    }
    std::fs::write(
        output.join("dataset.json"),
        serde_json::to_vec_pretty(
            &json!({"kind": "large-wide-native-init", "source_files": 30, "files": 120, "bytes_per_file": bytes,
        "limitation": "distinct paths with repeated merged rows; isolates file fanout and schema width, not planner pruning or unique event identity"}),
        )?,
    )?;
    eprintln!(
        "prepared 120 reflink files of {:.1} MiB",
        bytes as f64 / 1048576.0
    );
    Ok(())
}

/// Compare fresh connections with one resident connection on existing local parts.
/// This bypasses the signed planner and measures native execution only.
fn real_parts(root: &Path) -> Result<()> {
    let mut files = Vec::new();
    data_files(root, &mut files)?;
    files.sort();
    ensure!(files.len() >= 73, "need 73 existing real parts");
    let schema = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&files[0])?)?
        .schema()
        .clone();
    let structure = nanosiem_lake_worker::iceberg::clickhouse_read_schema(&schema)?;
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH")?,
        &std::env::var("NANO_CHDB_LIBRARY_SHA256")?,
    )?;
    std::mem::forget(runtime.clone());
    let args = [
        "--memory_worker_use_cgroup=0",
        "--memory_worker_dynamic_hard_limit=0",
    ];
    let resident = runtime.connect(&args)?;
    resident.query_with_params("SELECT 1", "JSONEachRow", &[])?;
    let mut results = Vec::new();
    for (shape, count, projection) in [
        ("parent", 5, "time, metadata.log_source AS source"),
        ("child", 30, "time, metadata.log_source AS source"),
        (
            "stats",
            73,
            "metadata.log_source AS source, count() AS count",
        ),
    ] {
        let paths = path_spec(&files[..count])?;
        let suffix = if shape == "stats" {
            "GROUP BY source ORDER BY source"
        } else {
            "ORDER BY time, source LIMIT 100"
        };
        let sql = format!(
            "SELECT {projection} FROM file({{paths:String}}, Parquet, {{structure:String}}) WHERE time >= toDateTime64('2026-10-01 00:00:00', 6, 'UTC') AND time < toDateTime64('2026-10-02 00:00:00', 6, 'UTC') {suffix} SETTINGS readonly=2, max_threads=2, max_memory_usage=3000000000, max_execution_time=55, input_format_parquet_filter_push_down=1"
        );
        let params = [("paths", paths.as_str()), ("structure", structure.as_str())];
        let mut reference = None;
        for round in 0..3 {
            for cold in [true, false] {
                let fresh;
                let start = Instant::now();
                let connection = if cold {
                    fresh = runtime.connect(&args)?;
                    &fresh
                } else {
                    &resident
                };
                let connect_ms = start.elapsed().as_secs_f64() * 1000.0;
                let mut timing = NativeInitTimings::default();
                let mut stream = connection.stream_query_with_params_timed(
                    &sql,
                    "JSONEachRow",
                    &params,
                    &mut timing,
                )?;
                let mut data = Vec::new();
                while let Some(chunk) = stream.fetch()? {
                    data.extend(chunk.data);
                }
                let wall_ms = start.elapsed().as_secs_f64() * 1000.0;
                if let Some(expected) = &reference {
                    ensure!(
                        expected == &data,
                        "cold/resident byte parity failed: {shape}"
                    );
                } else {
                    reference = Some(data.clone());
                }
                eprintln!(
                    "{shape} round={round} fresh={cold} connect={connect_ms:.3} init={:.3} wall={wall_ms:.3}",
                    timing.abi_ms
                );
                results.push(json!({"shape":shape,"files":count,"round":round,"session":if cold {"fresh"} else {"resident"},"connect_ms":connect_ms,"native_init_abi_ms":timing.abi_ms,"wall_ms":wall_ms,"result_bytes":data.len()}));
            }
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"passed":true,"byte_parity_checks":15,"limitation":"native-only shapes; sorted local parts, no planner or production CPU quota; fresh session does not evict process-global or OS caches","results":results})
        )?
    );
    Ok(())
}

fn process_cpu_ms() -> Result<f64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes to a valid initialized timespec.
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time) } == 0,
        "process CPU clock unavailable"
    );
    Ok(time.tv_sec as f64 * 1000.0 + time.tv_nsec as f64 / 1_000_000.0)
}

/// Reproduce predicate work on local files without claiming active membership.
fn live_parts(root: &Path) -> Result<()> {
    let mut files = Vec::new();
    data_files(root, &mut files)?;
    files.sort();
    ensure!(!files.is_empty(), "need existing real parts");
    let old_prefix_bytes = [5, 30, 73]
        .into_iter()
        .map(|count| {
            let bytes = files.iter().take(count).try_fold(0_u64, |total, path| {
                Ok::<_, anyhow::Error>(
                    total
                        .checked_add(std::fs::metadata(path)?.len())
                        .context("prefix byte overflow")?,
                )
            })?;
            Ok::<_, anyhow::Error>((count.to_string(), bytes))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
    let mut canonical = std::collections::BTreeSet::new();
    let before_dedup = files.len();
    let mut unique_files = Vec::new();
    for file in files {
        if canonical.insert(std::fs::canonicalize(&file)?) {
            unique_files.push(file);
        }
    }
    let canonical_aliases_removed = before_dedup - unique_files.len();
    let files = unique_files;
    // Optional byte target retains whole files, rather than multiplying rows.
    let target = std::env::var("BENCH_FILE_BYTES")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?;
    ensure!(
        target.is_none_or(|target| target > 0),
        "byte target must be positive"
    );
    let mut bytes = 0_u64;
    let mut selected = Vec::new();
    for file in files {
        if target.is_some_and(|target| bytes >= target) {
            break;
        }
        bytes = bytes
            .checked_add(std::fs::metadata(&file)?.len())
            .context("file bytes overflow")?;
        selected.push(file);
    }
    ensure!(
        target.is_none_or(|target| bytes >= target),
        "not enough local bytes for target"
    );
    let mut physical = std::collections::BTreeMap::<String, i64>::new();
    let mut rows = 0_i64;
    let mut groups = 0_usize;
    let mut schemas = std::collections::BTreeMap::new();
    let mut tiers = std::collections::BTreeMap::<String, usize>::new();
    let mut typical_hour = None;
    let mut typical_hour_score = -1;
    for file in &selected {
        let builder = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(file)?)?;
        let structure = nanosiem_lake_worker::iceberg::clickhouse_read_schema(builder.schema())?;
        schemas
            .entry(structure)
            .or_insert_with(Vec::new)
            .push(file.clone());
        let tier = ["h", "m", "l0"]
            .into_iter()
            .find(|tier| file.components().any(|part| part.as_os_str() == *tier))
            .unwrap_or("other");
        *tiers.entry(tier.to_string()).or_default() += 1;
        let metadata = builder.metadata();
        rows += metadata.file_metadata().num_rows();
        groups += metadata.num_row_groups();
        let mut columns = std::collections::BTreeMap::<String, i64>::new();
        for group in metadata.row_groups() {
            for column in group.columns() {
                *columns.entry(column.column_path().string()).or_default() +=
                    column.compressed_size();
            }
        }
        for (path, size) in &columns {
            *physical.entry(path.clone()).or_default() += size;
        }
        let actor_name_bytes = columns.get("actor.process.name").copied().unwrap_or(0);
        if tier == "h" && actor_name_bytes > typical_hour_score {
            typical_hour_score = actor_name_bytes;
            typical_hour = Some(
                json!({"file_bytes":std::fs::metadata(file)?.len(), "rows":metadata.file_metadata().num_rows(), "row_groups":metadata.num_row_groups(), "physical_compressed_bytes":columns}),
            );
        }
    }
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH")?,
        &std::env::var("NANO_CHDB_LIBRARY_SHA256")?,
    )?;
    std::mem::forget(runtime.clone());
    let connection = runtime.connect(&[
        "--memory_worker_use_cgroup=0",
        "--memory_worker_dynamic_hard_limit=0",
    ])?;
    let settings_output = connection.query_with_params(
        "SELECT name, value FROM system.settings WHERE name IN ('max_threads', 'max_memory_usage', 'max_execution_time', 'input_format_parquet_filter_push_down', 'input_format_parquet_use_native_reader', 'input_format_parquet_use_offset_index', 'use_query_cache', 'use_uncompressed_cache', 'use_page_cache_for_disks_without_file_cache', 'input_format_parquet_use_metadata_cache', 'schema_inference_use_cache_for_file') UNION ALL SELECT concat('server.', name) AS name, value FROM system.server_settings WHERE name IN ('max_server_memory_usage', 'memory_worker_use_cgroup', 'memory_worker_dynamic_hard_limit', 'page_cache_max_size', 'mark_cache_size', 'uncompressed_cache_size', 'parquet_metadata_cache_size') SETTINGS readonly=2, max_threads=2, max_memory_usage=3000000000, max_execution_time=55, input_format_parquet_filter_push_down=1",
        "JSONEachRow", &[],
    )?;
    let native_settings = std::str::from_utf8(&settings_output.data)?
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let cpu_model = std::fs::read_to_string("/proc/cpuinfo")?
        .lines()
        .find_map(|line| {
            line.strip_prefix("model name")
                .and_then(|line| line.split_once(':'))
                .map(|(_, value)| value.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());
    let mut sources = Vec::new();
    let mut owned_params = Vec::new();
    for (index, (structure, paths)) in schemas.iter().enumerate() {
        let paths_key = format!("paths{index}");
        let schema_key = format!("schema{index}");
        sources.push(format!("SELECT time, metadata.log_source AS source, category_name AS category, actor.process.name AS process, dst_endpoint.ip AS ip FROM file({{{paths_key}:String}}, Parquet, {{{schema_key}:String}})"));
        owned_params.push((paths_key, path_spec(paths)?));
        owned_params.push((schema_key, structure.clone()));
    }
    let params = owned_params
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let source = sources.join(" UNION ALL ");
    let mut results = Vec::new();
    for (shape, child, projection, suffix) in [
        (
            "parent",
            false,
            "time, source, category",
            "ORDER BY time, source, category LIMIT 100",
        ),
        (
            "child",
            true,
            "time, source, category, process",
            "ORDER BY time, source, category, process LIMIT 100",
        ),
        (
            "stats",
            true,
            "ip, process, count() AS count",
            "GROUP BY ip, process ORDER BY ip, process",
        ),
    ] {
        let predicate = if child {
            " AND lower(process) = 'speechmodeldownload.exe'"
        } else {
            ""
        };
        let sql = format!(
            "SELECT {projection} FROM ({source}) WHERE time >= toDateTime64('2026-10-01 00:00:00', 6, 'UTC') AND time < toDateTime64('2026-10-02 00:00:00', 6, 'UTC') AND lower(source) = 'windows_sysmon' AND lower(category) = 'network activity'{predicate} {suffix} SETTINGS readonly=2, max_threads=2, max_memory_usage=3000000000, max_execution_time=55, input_format_parquet_filter_push_down=1"
        );
        let mut reference = None;
        for round in 0..3 {
            for pushdown in [true, false] {
                let query = if pushdown {
                    sql.clone()
                } else {
                    sql.replace(
                        "input_format_parquet_filter_push_down=1",
                        "input_format_parquet_filter_push_down=0",
                    )
                };
                let cpu_start = process_cpu_ms()?;
                let start = Instant::now();
                let mut timing = NativeInitTimings::default();
                let mut stream = connection.stream_query_with_params_timed(
                    &query,
                    "JSONEachRow",
                    &params,
                    &mut timing,
                )?;
                let mut data = Vec::new();
                let mut storage_rows = 0_u64;
                let mut storage_bytes = 0_u64;
                while let Some(chunk) = stream.fetch()? {
                    storage_rows = storage_rows.saturating_add(chunk.storage_rows_read);
                    storage_bytes = storage_bytes.saturating_add(chunk.storage_bytes_read);
                    data.extend(chunk.data);
                }
                if let Some(expected) = &reference {
                    ensure!(expected == &data, "pushdown/repeat parity failed: {shape}");
                } else {
                    reference = Some(data.clone());
                }
                let wall_ms = start.elapsed().as_secs_f64() * 1000.0;
                let cpu_ms = process_cpu_ms()? - cpu_start;
                let result_rows = data
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                    .count();
                eprintln!("{shape} round={round} pushdown={pushdown} wall={wall_ms:.3}");
                results.push(json!({"shape":shape,"round":round,"pushdown":pushdown,"native_init_abi_ms":timing.abi_ms,"wall_ms":wall_ms,"cpu_ms":cpu_ms,"cpu_scope":"process","reported_storage_rows":storage_rows,"reported_storage_bytes":storage_bytes,"result_rows":result_rows,"result_bytes":data.len()}));
            }
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"cpu_model":cpu_model,"native_settings":native_settings,"passed":true,"byte_parity_checks":15,"trusted_live_reproduction":false,"active_membership_verified":false,"canonical_aliases_removed":canonical_aliases_removed,"old_prefix_file_bytes":old_prefix_bytes,"files":selected.len(),"file_bytes":bytes,"rows":rows,"row_groups":groups,"tiers":tiers,"schema_variants":schemas.len(),"physical_compressed_bytes":physical,"typical_hour":typical_hour,"results":results,"limitation":"local immutable-file scan, sorted whole-file byte prefix; no signed membership, live window, full-row payload, planner pruning, ingest contention or OS cache eviction"})
        )?
    );
    Ok(())
}

/// Metadata-only fanout, independent of native payload reads. The uncached
/// control retains the existing footer cache but re-reads sidecars.
fn rust_metadata_reads(root: &Path, shape: &str, enabled: bool) -> Result<()> {
    use nanosiem_lake_worker::part_query::{
        metadata_cache::MetadataBytesCache, prune::FileMetadataCache,
    };
    let mut files = Vec::new();
    data_files(root, &mut files)?;
    files.sort();
    let count = match shape {
        "parent" => 5,
        "child" => 30,
        "stats" => 73,
        _ => anyhow::bail!("unknown shape"),
    };
    ensure!(files.len() >= count, "not enough real parts");
    let footers = FileMetadataCache::default();
    let sidecars = MetadataBytesCache::default();
    let mut reference = None;
    let mut elapsed = Vec::new();
    let mut sidecar_files = 0;
    for statement in 0..12 {
        let start = Instant::now();
        let mut result = Vec::new();
        let mut total = 0;
        for path in &files[..count] {
            // This metadata-only harness has no authority: stable fixture keys
            // model signed digests without re-hashing gigabytes of payload.
            let summary = footers
                .summary(path, &path.display().to_string())
                .context("footer unreadable")?;
            let mut lengths = Vec::new();
            for suffix in ["uids", "entities", "ranges"] {
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .context("data filename")?
                    .strip_prefix("data-")
                    .context("data prefix")?;
                let sidecar = path.with_file_name(format!("{suffix}-{name}.json"));
                if sidecar.is_file() {
                    let bytes = if enabled {
                        sidecars
                            .get(&sidecar, &sidecar.display().to_string())
                            .context("sidecar unreadable")?
                    } else {
                        std::sync::Arc::new(std::fs::read(&sidecar)?)
                    };
                    use sha2::{Digest, Sha256};
                    lengths.push((bytes.len(), hex::encode(Sha256::digest(&*bytes))));
                    total += 1;
                }
            }
            result.push((summary.ranges.clone(), summary.group_times.clone(), lengths));
        }
        elapsed.push(start.elapsed().as_secs_f64() * 1000.0);
        if statement == 0 {
            reference = Some(result);
            sidecar_files = total;
        } else {
            ensure!(reference.as_ref() == Some(&result), "metadata parity");
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"shape":shape,"files":count,"sidecar_files":sidecar_files,"statements":12,"cache":enabled,"wall_ms":elapsed,"parity_checks":11,"limitation":"metadata-only model, control retains existing footer summaries and re-reads sidecars; fixture identity is not a signed lease"})
        )?
    );
    Ok(())
}

/// Repeated real-file statements with only native metadata caching changed.
/// Results are checked in memory; reports contain counts/timing, never rows.
fn metadata_reads(root: &Path, shape: &str, enabled: bool) -> Result<()> {
    let mut files = Vec::new();
    data_files(root, &mut files)?;
    files.sort();
    let count = match shape {
        "parent" => 5,
        "child" => 30,
        "stats" => 73,
        _ => anyhow::bail!("unknown shape"),
    };
    ensure!(files.len() >= count, "not enough real parts");
    let schema = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&files[0])?)?
        .schema()
        .clone();
    let structure = nanosiem_lake_worker::iceberg::clickhouse_read_schema(&schema)?;
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH")?,
        &std::env::var("NANO_CHDB_LIBRARY_SHA256")?,
    )?;
    std::mem::forget(runtime.clone());
    let connection = runtime.connect(&[
        "--memory_worker_use_cgroup=0",
        "--memory_worker_dynamic_hard_limit=0",
    ])?;
    let effective = connection.query_with_params("SELECT name, value FROM system.settings WHERE name IN ('use_parquet_metadata_cache', 'schema_inference_use_cache_for_file', 'use_cache_for_count_from_files') ORDER BY name", "JSONEachRow", &[])?;
    let server = connection.query_with_params("SELECT name, value FROM system.server_settings WHERE name LIKE 'parquet_metadata_cache%' ORDER BY name", "JSONEachRow", &[])?;
    let paths = path_spec(&files[..count])?;
    let projection = if shape == "stats" {
        "metadata.log_source AS source, count() AS count"
    } else {
        "time, metadata.log_source AS source"
    };
    let suffix = if shape == "stats" {
        "GROUP BY source ORDER BY source"
    } else {
        "ORDER BY time, source LIMIT 100"
    };
    let sql = format!("SELECT {projection} FROM file({{paths:String}}, Parquet, {{structure:String}}) WHERE time >= toDateTime64('2026-10-01 00:00:00', 6, 'UTC') AND time < toDateTime64('2026-10-02 00:00:00', 6, 'UTC') {suffix} SETTINGS readonly=2, max_threads=2, max_memory_usage=3000000000, max_execution_time=55, input_format_parquet_filter_push_down=1, use_parquet_metadata_cache={}, schema_inference_use_cache_for_file=1", u8::from(enabled));
    let params = [("paths", paths.as_str()), ("structure", structure.as_str())];
    let mut reference = None;
    let mut elapsed = Vec::new();
    for _ in 0..12 {
        let start = Instant::now();
        let mut stream = connection.stream_query_with_params(&sql, "JSONEachRow", &params)?;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.fetch()? {
            bytes.extend(chunk.data);
        }
        elapsed.push(start.elapsed().as_secs_f64() * 1000.0);
        if let Some(expected) = &reference {
            ensure!(expected == &bytes, "statement byte parity");
        } else {
            reference = Some(bytes);
        }
    }
    use sha2::{Digest, Sha256};
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"shape":shape, "files":count, "statements":12, "metadata_cache":enabled, "effective_defaults":String::from_utf8(effective.data)?, "server_cache_limits":String::from_utf8(server.data)?, "wall_ms":elapsed, "result_sha256":hex::encode(Sha256::digest(reference.unwrap())), "parity_checks":11, "limitation":"native-only sorted-file shapes, not full signed planner; trace payload and footer reads separately"})
        )?
    );
    Ok(())
}

fn run() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    if std::env::args().nth(1).as_deref() == Some("rust-metadata-reads") {
        return rust_metadata_reads(
            Path::new(&std::env::args().nth(2).context("parts root")?),
            &std::env::args().nth(3).context("shape")?,
            std::env::args().nth(4).as_deref() == Some("on"),
        );
    }
    if std::env::args().nth(1).as_deref() == Some("metadata-reads") {
        return metadata_reads(
            Path::new(&std::env::args().nth(2).context("parts root")?),
            &std::env::args().nth(3).context("shape")?,
            std::env::args().nth(4).as_deref() == Some("on"),
        );
    }

    if std::env::args().nth(1).as_deref() == Some("live-parts") {
        return live_parts(Path::new(
            &std::env::args()
                .nth(2)
                .context("existing local parts root")?,
        ));
    }
    if std::env::args().nth(1).as_deref() == Some("real-parts") {
        return real_parts(Path::new(
            &std::env::args()
                .nth(2)
                .context("existing local parts root")?,
        ));
    }
    if std::env::args().nth(1).as_deref() == Some("prepare-large") {
        return prepare_large(
            Path::new(&std::env::args().nth(2).context("source dataset")?),
            Path::new(&std::env::args().nth(3).context("fresh output dataset")?),
        );
    }
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("usage: lake_native_init_bench LOCAL_DATASET")?,
    );
    let mut files = Vec::new();
    data_files(&root.join("store"), &mut files)?;
    files.sort();
    ensure!(
        files.len() >= 120,
        "probe requires at least 120 local data files"
    );
    let schema = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&files[0])?)?
        .schema()
        .clone();
    let full = nanosiem_lake_worker::iceberg::clickhouse_read_schema(&schema)?;
    let narrow = arrow_schema::Schema::new(
        schema
            .fields()
            .iter()
            .filter(|f| ["time", "metadata", "category_name", "actor"].contains(&f.name().as_str()))
            .cloned()
            .collect::<Vec<_>>(),
    );
    ensure!(
        narrow.fields().len() == 4,
        "fixture lacks required predicate fields"
    );
    let narrow = nanosiem_lake_worker::iceberg::clickhouse_read_schema(&narrow)?;
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH")?,
        &std::env::var("NANO_CHDB_LIBRARY_SHA256")?,
    )?;
    // chDB process-global hooks outlive the last connection.
    std::mem::forget(runtime.clone());
    let connection = runtime.connect(&[
        "--memory_worker_use_cgroup=0",
        "--memory_worker_dynamic_hard_limit=0",
    ])?;
    // Cache maintenance has its own local connection; readonly query settings
    // must not affect subsequent SYSTEM commands on the query connection.
    let maintenance = runtime.connect(&[
        "--memory_worker_use_cgroup=0",
        "--memory_worker_dynamic_hard_limit=0",
    ])?;
    let mut results = Vec::new();
    let mut parity_checks = 0;
    for count in [1, 30, 120] {
        let selected = &files[..count];
        let glob = path_spec(selected)?;
        let bytes: u64 = selected
            .iter()
            .map(|p| std::fs::metadata(p).map(|m| m.len()))
            .collect::<std::io::Result<Vec<_>>>()?
            .iter()
            .sum();
        let mut reference = None;
        for round in 0..7 {
            for (mode, structure) in [
                ("infer", None),
                ("full", Some(full.as_str())),
                ("narrow", Some(narrow.as_str())),
            ] {
                for cold in [true, false] {
                    // Advisory eviction of these disposable fixture files only, never global drop_caches.
                    if cold {
                        // These commands affect only this disposable embedded engine.
                        maintenance.query_with_params(
                            "SYSTEM DROP PARQUET METADATA CACHE",
                            "JSONEachRow",
                            &[],
                        )?;
                        maintenance.query_with_params(
                            "SYSTEM DROP SCHEMA CACHE FOR File",
                            "JSONEachRow",
                            &[],
                        )?;
                        #[cfg(target_os = "linux")]
                        {
                            use std::os::fd::AsRawFd;
                            for path in selected {
                                let file = std::fs::File::open(path)?;
                                let code = unsafe {
                                    libc::posix_fadvise(
                                        file.as_raw_fd(),
                                        0,
                                        0,
                                        libc::POSIX_FADV_DONTNEED,
                                    )
                                };
                                ensure!(code == 0, "file cache eviction failed: {code}");
                            }
                        }
                    }
                    let source = if structure.is_some() {
                        "file({paths:String}, Parquet, {structure:String})"
                    } else {
                        "file({paths:String}, Parquet)"
                    };
                    let sql = format!(
                        "SELECT count() AS count FROM {source} WHERE time >= toDateTime64('2026-09-24 00:00:00', 6, 'UTC') AND time < toDateTime64('2026-09-24 00:01:00', 6, 'UTC') AND metadata.log_source = 'windows_sysmon' AND category_name = 'Network Activity' AND actor.process.name = 'SpeechModelDownload.exe' SETTINGS readonly=2, input_format_parquet_filter_push_down=1, max_threads=2, max_memory_usage=3000000000"
                    );
                    let mut params = vec![("paths", glob.as_str())];
                    if let Some(structure) = structure {
                        params.push(("structure", structure));
                    }
                    let mut timing = NativeInitTimings::default();
                    let start = Instant::now();
                    let mut stream = connection.stream_query_with_params_timed(
                        &sql,
                        "JSONEachRow",
                        &params,
                        &mut timing,
                    )?;
                    let init_ms = start.elapsed().as_secs_f64() * 1000.0;
                    let fetch_start = Instant::now();
                    let mut data = Vec::new();
                    let mut first_fetch_ms = None;
                    let mut fetch_calls = 0;
                    loop {
                        let start = Instant::now();
                        let fetched = stream.fetch()?;
                        first_fetch_ms.get_or_insert(start.elapsed().as_secs_f64() * 1000.0);
                        fetch_calls += 1;
                        match fetched {
                            Some(chunk) => data.extend(chunk.data),
                            None => break,
                        }
                    }
                    let fetch_ms = fetch_start.elapsed().as_secs_f64() * 1000.0;
                    let value: serde_json::Value = serde_json::from_slice(&data)?;
                    ensure!(
                        value["count"].as_u64().is_some_and(|n| n > 0),
                        "empty fixture match"
                    );
                    if let Some(expected) = &reference {
                        ensure!(expected == &value, "count parity failed");
                    } else {
                        reference = Some(value.clone());
                    }
                    parity_checks += 1;
                    eprintln!(
                        "files={count} schema={mode} round={round} cold={cold}: init={init_ms:.3}ms fetch={fetch_ms:.3}ms"
                    );
                    results.push(json!({"files": count, "file_bytes": bytes, "round": round, "schema": mode,
                        "cache": if cold { "advisory-evicted" } else { "warm" }, "native_init_ms": init_ms,
                        "native_bind_ms": timing.bind_ms, "native_init_abi_ms": timing.abi_ms,
                        "native_fetch_ms": fetch_ms, "native_first_fetch_ms": first_fetch_ms,
                        "native_fetch_calls": fetch_calls, "result": value}));
                }
            }
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"passed": true, "parity_checks": parity_checks,
        "window": "2026-09-24T00:00:00Z to 00:01:00Z; bounded repeated-row scan, production parquet pushdown",
        "lifecycle": "one persistent connection; statement-scoped settings; streaming ABI", "cache_limit": "cold clears native parquet metadata and file schema caches; OS file eviction is advisory", "results": results}))?
    );
    Ok(())
}

fn main() {
    use std::io::Write;
    let code = match run() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("native init probe failed: {error:#}");
            1
        }
    };
    let _ = std::io::stdout().flush();
    // chDB static destructors are not exit-safe.
    unsafe { libc::_exit(code) }
}
