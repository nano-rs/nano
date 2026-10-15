// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2869 parity harness and budget lab for `query[T]` (lab only; reads
//! local fixture files, writes under the given work dir, touches nothing live).
//!
//! ```text
//! lake_part_query_lab prepare <packs_root> <work> [hours]
//!     reference: dedup + sort each hour of tail packs into one generation-
//!                style object (reference/event_hour=H/object.parquet);
//!     parts:     the same rows through the phase 2 writer as L0 parts
//!                (131,072 rows each), a signed part log, and phase 2 merges
//!                of every hour but the last two into H parts.
//! lake_part_query_lab parity <work> <corpus.json> <rules.json>... > report.json
//!     every k6 corpus query and every logs detection rule through the
//!     current reader's planner over the reference objects AND through the
//!     part engine; counts, prevalence and entity ranges against raw scans.
//! lake_part_query_lab bench <work> <corpus.json> [concurrency]
//!     the part engine alone (this process = query[T]): latency and RSS.
//! lake_part_query_lab coldstart <work>
//!     NAN-2989: serial vs windowed part-log open, engine open, cold then
//!     warm simple searches, idle-resident RSS (NAN2989_GET_LATENCY_MS adds
//!     an R2-like delay per GET).
//! lake_part_query_lab import-real <data_files_dir> <work> [hours]
//!     real tenant data files (`<YYYYMMDDHH>-data-N.parquet`) as L0 parts
//!     merged into H parts per hour, v3 token indexes (NAN2869_NO_COUNTS=1: v2).
//! lake_part_query_lab rollup-routing <work> <steps.json>
//!     NAN-3153: each step's lean-cell rollup route (count_aggregate, plus
//!     the narrowed overlap scan of a two-field union) against the compiled
//!     scan of the same nPL: per-step latency (first, then memo-warm) and
//!     group-for-group parity.
//! lake_part_query_lab ui <work> <steps.json>
//!     the UI's default search per step: rows page + histogram, concurrently.
//! lake_part_query_lab sql <query>
//!     ad-hoc chDB SQL over local files (JSONEachRow to stdout).
//! lake_part_query_lab corr-parity <work> <cases.json>
//!     strict sequence/correlation/retro parity over signed tenant parts and
//!     the reference ClickHouse-style generation objects. Fails on empty or
//!     unequal results, so it can serve as an end-to-end acceptance test.
//! ```
//!
//! Env: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER.

use anyhow::{bail, Context, Result};
use arrow_schema::SchemaRef;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::count_aggregate::{merge_outputs, CountAggregateRequest};
use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::part_ingest::merge::{merge_parts, MergeInput};
use nanosiem_lake_worker::part_ingest::writer::{publish_parts, PartDraft, PartWriter, PartialSource};
use nanosiem_lake_worker::part_query::engine::{page_rows, BroadNplRequest, EngineSettings, PartQueryEngine};
use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use nanosiem_lake_worker::part_query::log_view::PartLogView;
use nanosiem_lake_worker::part_query::partials::{self, EntityRangesRequest};
use nanosiem_lake_worker::parts::format::{schema_fingerprint, ParquetSettings};
use nanosiem_lake_worker::parts::levels::Level;
use nanosiem_lake_worker::parts::part_log::{LocalObjectStore, LogEntry, LogOp, ObjectStore, PartLogWriter, PartRef, SourceRef};
use nanosiem_lake_worker::parts::provenance::{Admission, LocalPartSigner, PartInputs, SourceObject, TenantKeySet, ADMISSION_CONTRACT};
use nanosiem_lake_worker::parts::DedupWindow;
use nanosiem_lake_worker::planner::{
    self, CountAggregatePlanRequest, CountAggregateSource, ManifestObject, ObjectStoreCredentials, SnapshotCache,
    SnapshotCacheObject, SourceManifest, TenantQueryConfig,
};
use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "lab/local_search_bench.rs"]
mod local_search_bench;

const TENANT: &str = "b464ceb9-28a6-4249-8e29-3489627ac5f6";
const BUCKET: &str = "nan2869-fixture";
const L0_ROWS: usize = 131_072;
const CORPUS_END: &str = "2026-09-25T00:00:00Z";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn runtime() -> Result<NativeChdb> {
    Ok(NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").context("NANO_CHDB_LIBRARY_PATH")?,
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").context("NANO_CHDB_LIBRARY_SHA256")?,
    )?)
}

const SIGNER_KEY_ID: &str = "nan2869-lab-owner-signer";
/// L0 data files roll at this size so the fixture exercises multi-file
/// parts (production: 1 GiB).
const LAB_FILE_SPLIT_BYTES: u64 = 16 * 1024 * 1024;

fn signer() -> LocalPartSigner {
    let key = SigningKey::from_bytes(&sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(b"nan2869-lab-owner-key")).into());
    LocalPartSigner::new(SIGNER_KEY_ID, key).expect("lab signer")
}

fn trusted() -> TenantKeySet {
    signer().trusted()
}

fn cpu_seconds() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let fields = stat.rsplit_once(')')?.1.split_whitespace().map(str::to_string).collect::<Vec<_>>();
    let ticks = fields.get(11)?.parse::<f64>().ok()? + fields.get(12)?.parse::<f64>().ok()?;
    Some(ticks / 100.0)
}

/// The platform-enrichment read authority the lab queries under.
/// `NAN2869_AUTHORITY=grant`: the tenant holds the ipinfo_lite baseline right
/// (the stamps that own the geo/ASN leaves), as a normal tenant does.
/// Otherwise: no rights, so every owned leaf is masked (worst case).
fn lab_authority() -> nanosiem_core::platform_enrichment::read::ReadAuthorization {
    use nanosiem_core::platform_enrichment::{AuthorizedRevision, FeedClass, RevisionReference};
    let tenant: uuid::Uuid = TENANT.parse().expect("tenant uuid");
    let now = chrono::Utc::now();
    if std::env::var("NAN2869_AUTHORITY").as_deref() != Ok("grant") {
        return nanosiem_core::platform_enrichment::read::ReadAuthorization::unknown(tenant, now);
    }
    // Both ipinfo_lite revisions present in the fixture (1 and 2).
    let revisions = [1_i64, 2]
        .into_iter()
        .map(|feed_revision| AuthorizedRevision {
            tenant_id: tenant,
            reference: RevisionReference {
                feed_id: "ipinfo_lite".to_string(),
                feed_revision,
                tier: "included".to_string(),
                grant_revision: 1,
                entitlement_revision: 1,
            },
            class: FeedClass::Baseline,
            digest: "0".repeat(64),
            mapping_revision: 1,
            deny_epoch: 0,
            // Fixed, so the authority identity is stable across queries (as
            // a resolved production authority is).
            valid_until: chrono::DateTime::parse_from_rfc3339("2026-12-01T00:00:00Z").expect("fixed").with_timezone(&chrono::Utc),
            evaluated_at: now,
        })
        .collect::<Vec<_>>();
    nanosiem_core::platform_enrichment::read::ReadAuthorization::from_resolved(tenant, now, &revisions)
}

fn rss() -> Value {
    nanosiem_lake_worker::part_query::server::process_memory()
}

fn profile_events(connection: &nanosiem_lake_worker::native::NativeConnection) -> Result<BTreeMap<String, u64>> {
    let output = connection.query_with_params("SELECT event, value FROM system.events", "JSONEachRow", &[])?;
    let mut events = BTreeMap::new();
    for line in output.data.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
        let row: Value = serde_json::from_slice(line)?;
        if let (Some(event), Some(value)) = (row["event"].as_str(), row["value"].as_u64()) {
            events.insert(event.to_string(), value);
        }
    }
    Ok(events)
}

// ---------------------------------------------------------------------------
// prepare
// ---------------------------------------------------------------------------

fn prepare(packs_root: &Path, work: &Path, hours: usize) -> Result<()> {
    let reference_dir = work.join("reference");
    std::fs::create_dir_all(&reference_dir)?;
    let runtime = runtime()?;
    let connection = runtime.connect(&["--memory_worker_use_cgroup=0", "--memory_worker_dynamic_hard_limit=0"])?;
    let read_schema = std::fs::read_to_string(work.join("read_schema.txt")).context("work/read_schema.txt (the live read schema)")?;
    let mut hour_dirs = std::fs::read_dir(packs_root)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("event_hour="))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    hour_dirs.sort();
    hour_dirs.truncate(hours);
    for dir in &hour_dirs {
        let hour = dir.file_name().unwrap().to_string_lossy().to_string();
        let out_dir = reference_dir.join(&hour);
        let out = out_dir.join("object.parquet");
        if out.is_file() {
            continue;
        }
        std::fs::create_dir_all(&out_dir)?;
        let temporary = out_dir.join(".object.parquet.tmp");
        let _ = std::fs::remove_file(&temporary);
        let started = Instant::now();
        connection.query_with_params(
            "INSERT INTO FUNCTION file({out:String}, Parquet) \
             SELECT * FROM file({input:String}, Parquet, {schema:String}) \
             ORDER BY time, metadata.uid LIMIT 1 BY metadata.uid \
             SETTINGS max_threads=2, max_memory_usage=5000000000, max_bytes_before_external_sort=400000000, \
                      max_bytes_ratio_before_external_sort=0, max_bytes_before_external_group_by=400000000, \
                      max_bytes_ratio_before_external_group_by=0, max_block_size=8192, \
                      output_format_parquet_row_group_size=65536, output_format_parquet_compression_method='zstd', \
                      output_format_compression_level=3, use_query_cache=0",
            "JSONEachRow",
            &[
                ("out", temporary.to_str().unwrap()),
                ("input", &format!("{}/*.parquet", dir.display())),
                ("schema", &read_schema),
            ],
        )?;
        std::fs::rename(&temporary, &out)?;
        eprintln!("reference {hour}: {:.1}s", started.elapsed().as_secs_f64());
    }
    drop(connection);
    std::mem::forget(runtime);

    // Parts through the phase 2 writer, a signed log, and phase 2 merges.
    let store_dir = work.join("store");
    if store_dir.join(format!("lake/parts/v1/tenant={TENANT}/log")).is_dir() {
        eprintln!("parts already written");
        return Ok(());
    }
    let store = LocalObjectStore::new(&store_dir)?;
    let signer = signer();
    let trusted = signer.trusted();
    let objects = reference_objects(work)?;
    let schema = objects_schema(&objects)?;
    let fingerprint = schema_fingerprint(&schema)?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        let mut log = PartLogWriter::open(&store, TENANT, 1, &schema, now_ms()).await?;
        let scratch = work.join("parts-work");
        std::fs::create_dir_all(&scratch)?;
        let mut per_hour: BTreeMap<i32, Vec<(PartRef, PathBuf)>> = BTreeMap::new();
        for (hour, path) in &objects {
            let started = Instant::now();
            let bytes = std::fs::metadata(path)?.len();
            let object_sha = nanosiem_lake_worker::native::file_sha256(path)?;
            let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?.with_batch_size(65_536).build()?;
            let mut writer: Option<PartWriter> = None;
            let mut chunk = 0_usize;
            let flush = |writer: PartWriter, chunk: usize| -> Result<(nanosiem_lake_worker::part_ingest::writer::FinishedPart, usize)> {
                Ok((writer.finish()?, chunk))
            };
            let mut finished = Vec::new();
            for batch in reader {
                let batch = batch?;
                if writer.is_none() {
                    let mut settings = ParquetSettings::for_level(Level::L0);
                    settings.max_file_bytes = LAB_FILE_SPLIT_BYTES;
                    writer = Some(PartWriter::create_with(
                        &scratch,
                        PartDraft {
                            tenant_id: TENANT.to_string(),
                            signer_key_id: SIGNER_KEY_ID.to_string(),
                            level: Level::L0,
                            event_hour: *hour,
                            schema: schema.clone(),
                            schema_fingerprint: fingerprint.clone(),
                            inputs: PartInputs::Sources {
                                edge_log: None,
                                sources: vec![SourceObject {
                                    key: format!("reference/event_hour={hour}/object.parquet#{chunk}"),
                                    version: object_sha.clone(),
                                    bytes,
                                    sha256: object_sha.clone(),
                                    rows: 0,
                                    edge_sha256: None,
                                }],
                            },
                            admission: Some(Admission {
                                ocsf_version: "1.9.0".to_string(),
                                admission_contract: ADMISSION_CONTRACT.to_string(),
                                feed_pins: BTreeMap::new(),
                            }),
                            rows_in: 0,
                            duplicates_dropped: 0,
                            window: DedupWindow::Exact,
                            build: "nan2869-lab".to_string(),
                        },
                        PartialSource::FromRows,
                        now_ms(),
                        L0_ROWS as u64,
                        settings,
                    )?);
                }
                let current = writer.as_mut().unwrap();
                current.write(&batch)?;
                if current.rows() as usize >= L0_ROWS {
                    finished.push(flush(writer.take().unwrap(), chunk)?);
                    chunk += 1;
                }
            }
            if let Some(writer) = writer.take() {
                finished.push(flush(writer, chunk)?);
            }
            for (mut part, chunk) in finished {
                // The draft could not know its row count up front.
                if let PartInputs::Sources { sources, .. } = &mut part.record.inputs {
                    sources[0].rows = part.record.rows;
                }
                part.record.dedup.rows_in = part.record.rows;
                let reference = publish_parts(&store, &signer, &trusted, std::slice::from_ref(&part)).await?.remove(0);
                log.append(
                    LogOp::Add {
                        edge_log: None,
                        parts: vec![reference.clone()],
                        consumed: vec![SourceRef {
                            key: format!("reference/event_hour={hour}/object.parquet#{chunk}"),
                            version: object_sha.clone(),
                            sha256: object_sha.clone(),
                        }],
                    },
                    now_ms(),
                )
                .await?;
                per_hour.entry(*hour).or_default().push((reference, part.dir.clone()));
            }
            eprintln!("parts hour {hour}: {} L0 in {:.1}s", per_hour[hour].len(), started.elapsed().as_secs_f64());
        }
        // Sealed hours become H parts; the newest two hours stay L0.
        let merge_hours = per_hour.keys().copied().collect::<Vec<_>>();
        let keep_l0 = merge_hours.len().saturating_sub(2);
        for hour in merge_hours.into_iter().take(keep_l0) {
            let inputs = per_hour[&hour]
                .iter()
                .map(|(part, dir)| MergeInput { part: part.clone(), dir: dir.clone() })
                .collect::<Vec<_>>();
            if inputs.len() < 2 {
                continue;
            }
            let started = Instant::now();
            let merged = merge_parts(&scratch, TENANT, Level::Hour, hour, &inputs, schema.clone(), &fingerprint, SIGNER_KEY_ID, "nan2869-lab", now_ms())?;
            let output = publish_parts(&store, &signer, &trusted, std::slice::from_ref(&merged.finished)).await?.remove(0);
            log.append(
                LogOp::Merge { output, supersedes: inputs.iter().map(|input| input.part.part_id.clone()).collect() },
                now_ms(),
            )
            .await?;
            eprintln!("merged hour {hour}: {} L0 -> H in {:.1}s", inputs.len(), started.elapsed().as_secs_f64());
        }
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
}

/// Rebuild a week from its immutable signed L0 inputs. The destination store
/// is seeded with reflinks of the old objects; only its log is replaced. A
/// completed H merge is committed one hour at a time, so a stopped run can
/// resume without redoing hours already in the new log.
fn recluster_week(old_work: &Path, work: &Path) -> Result<()> {
    anyhow::ensure!(std::fs::canonicalize(old_work)? != std::fs::canonicalize(work)?,
        "recluster destination must differ from the old fixture");
    let old_store = old_work.join("store");
    let store_dir = work.join("store");
    let log_rel = format!("lake/parts/v1/tenant={TENANT}/log");
    let mut names = std::fs::read_dir(old_store.join(&log_rel).join("entries"))?
        .filter_map(|entry| entry.ok()).map(|entry| entry.path()).collect::<Vec<_>>();
    names.sort();
    let mut adds = Vec::new();
    let mut schema = None;
    let mut l0_by_hour: BTreeMap<i32, Vec<PartRef>> = BTreeMap::new();
    for path in names {
        let entry = LogEntry::parse_bytes(&std::fs::read(path)?, TENANT)?;
        match entry.op {
            LogOp::Genesis { schema: s } => schema = Some(s),
            op @ LogOp::Add { .. } => {
                if let LogOp::Add { parts, .. } = &op {
                    for part in parts {
                        l0_by_hour.entry(part.event_hour).or_default().push(part.clone());
                    }
                }
                adds.push(op);
            }
            _ => {}
        }
    }
    let schema = schema.context("old part log has no genesis schema")?;
    let existing_log = store_dir.join(&log_rel).join("entries");
    let mut existing_adds = Vec::new();
    let mut has_merges = false;
    if existing_log.is_dir() {
        let mut entries = std::fs::read_dir(&existing_log)?
            .filter_map(|entry| entry.ok()).map(|entry| entry.path()).collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            match LogEntry::parse_bytes(&std::fs::read(path)?, TENANT)?.op {
                op @ LogOp::Add { .. } => existing_adds.push(op),
                LogOp::Merge { .. } => has_merges = true,
                _ => {}
            }
        }
    }
    anyhow::ensure!(existing_adds.len() <= adds.len() && existing_adds == adds[..existing_adds.len()],
        "destination Add log differs from old fixture");
    anyhow::ensure!(!has_merges || existing_adds.len() == adds.len(),
        "destination has merges before all source Adds");
    let arrow_schema = Arc::new(schema.to_arrow()?);
    let store = LocalObjectStore::new(&store_dir)?;
    let signer = signer();
    let trusted = signer.trusted();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        let mut log = PartLogWriter::open(&store, TENANT, 1, &arrow_schema, now_ms()).await?;
        // An interrupted replay resumes at the next Add; existing entries
        // were checked against the original immutable sequence above.
        for op in adds.into_iter().skip(existing_adds.len()) {
            log.append(op, now_ms()).await?;
        }
        let view = PartLogView::open(&store, TENANT, trusted.clone()).await?;
        let completed = view.live().parts()
            .filter(|part| part.level == Level::Hour)
            .map(|part| part.event_hour).collect::<BTreeSet<_>>();
        let scratch = work.join("parts-work-recluster");
        std::fs::create_dir_all(&scratch)?;
        let pending = l0_by_hour.into_iter().filter(|(hour, _)| !completed.contains(hour)).collect::<Vec<_>>();
        let workers = std::env::var("NAN2869_MERGE_WORKERS").ok()
            .and_then(|value| value.parse::<usize>().ok()).unwrap_or(4).clamp(1, 6);
        let queue = Arc::new(std::sync::Mutex::new(pending));
        let (sender, receiver) = std::sync::mpsc::sync_channel(workers);
        let mut handles = Vec::new();
        for _ in 0..workers {
            let (queue, sender, store_dir, scratch, arrow_schema, fingerprint) =
                (queue.clone(), sender.clone(), store_dir.clone(), scratch.clone(), arrow_schema.clone(), schema.fingerprint.clone());
            handles.push(std::thread::spawn(move || loop {
                let Some((hour, refs)) = queue.lock().unwrap().pop() else { break };
                let started = Instant::now();
                let result = (|| -> Result<_> {
                    let inputs = refs.iter().map(|part| {
                        let keys = nanosiem_lake_worker::parts::format::PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id)?;
                        Ok(MergeInput { part: part.clone(), dir: store_dir.join(&keys.dir) })
                    }).collect::<Result<Vec<_>>>()?;
                    let merged = merge_parts(&scratch, TENANT, Level::Hour, hour, &inputs,
                        arrow_schema.clone(), &fingerprint, SIGNER_KEY_ID, "nan2869-r3.5-recluster", now_ms())?;
                    Ok((hour, refs, merged.finished, started.elapsed()))
                })();
                if sender.send(result).is_err() { break; }
            }));
        }
        drop(sender);
        let mut first_error = None;
        for result in receiver {
            match result {
                Ok((hour, refs, finished, elapsed)) => {
                    let output = publish_parts(&store, &signer, &trusted, std::slice::from_ref(&finished)).await?.remove(0);
                    log.append(LogOp::Merge { output: output.clone(),
                        supersedes: refs.iter().map(|part| part.part_id.clone()).collect() }, now_ms()).await?;
                    anyhow::ensure!(finished.dir.starts_with(&scratch), "merge output escaped the fixture scratch directory");
                    std::fs::remove_dir_all(&finished.dir)?;
                    eprintln!("reclustered hour {hour}: {} rows, {} files, {} groups in {:.1}s",
                        output.rows, output.data_files, output.row_groups, elapsed.as_secs_f64());
                }
                Err(error) => {
                    eprintln!("recluster worker failed: {error:#}");
                    if first_error.is_none() { first_error = Some(error); }
                }
            }
        }
        for handle in handles { handle.join().expect("recluster worker panicked"); }
        if let Some(error) = first_error { return Err(error); }
        Ok::<_, anyhow::Error>(())
    })
}

/// Append sorted hour files (`src/event_hour=H.parquet`, sorted by
/// `(time, metadata.uid)`, one hour each) to an existing fixture log as one
/// L0 part per hour. Parts are written on `threads` threads; publish and log
/// appends stay sequential (one appender).
fn append_hours(src: &Path, work: &Path, threads: usize) -> Result<()> {
    let mut files = std::fs::read_dir(src)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            let hour = name.strip_prefix("event_hour=")?.strip_suffix(".parquet")?.parse::<i32>().ok()?;
            Some((hour, entry.path()))
        })
        .collect::<Vec<_>>();
    files.sort();
    let store = LocalObjectStore::new(work.join("store"))?;
    let signer = signer();
    let trusted = signer.trusted();
    let schema = objects_schema(&reference_objects(work)?)?;
    let fingerprint = schema_fingerprint(&schema)?;
    let scratch = work.join("parts-work-append");
    std::fs::create_dir_all(&scratch)?;
    let queue = Arc::new(std::sync::Mutex::new(files.clone()));
    let (sender, receiver) = std::sync::mpsc::channel::<Result<(i32, nanosiem_lake_worker::part_ingest::writer::FinishedPart)>>();
    let mut handles = Vec::new();
    for _ in 0..threads.max(1) {
        let (queue, sender, schema, fingerprint, scratch) = (queue.clone(), sender.clone(), schema.clone(), fingerprint.clone(), scratch.clone());
        handles.push(std::thread::spawn(move || loop {
            let Some((hour, path)) = queue.lock().unwrap().pop() else { break };
            let result = (|| -> Result<nanosiem_lake_worker::part_ingest::writer::FinishedPart> {
                let sha = nanosiem_lake_worker::native::file_sha256(&path)?;
                let bytes = std::fs::metadata(&path)?.len();
                let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&path)?)?.with_batch_size(65_536).build()?;
                let mut writer = PartWriter::create(
                    &scratch,
                    PartDraft {
                        tenant_id: TENANT.to_string(),
                        signer_key_id: SIGNER_KEY_ID.to_string(),
                        level: Level::L0,
                        event_hour: hour,
                        schema: schema.clone(),
                        schema_fingerprint: fingerprint.clone(),
                        inputs: PartInputs::Sources {
                            edge_log: None,
                            sources: vec![SourceObject {
                                key: format!("p0-week/event_hour={hour}.parquet"),
                                version: sha.clone(),
                                bytes,
                                sha256: sha.clone(),
                                rows: 0,
                                edge_sha256: None,
                            }],
                        },
                        admission: Some(Admission {
                            ocsf_version: "1.9.0".to_string(),
                            admission_contract: ADMISSION_CONTRACT.to_string(),
                            feed_pins: BTreeMap::new(),
                        }),
                        rows_in: 0,
                        duplicates_dropped: 0,
                        window: DedupWindow::Exact,
                        build: "nan2869-lab".to_string(),
                    },
                    PartialSource::FromRows,
                    now_ms(),
                    1_100_000,
                )?;
                for batch in reader {
                    let batch = nanosiem_lake_worker::part_ingest::schema::align(batch?, &schema)?;
                    writer.write(&batch)?;
                }
                let mut part = writer.finish()?;
                if let PartInputs::Sources { sources, .. } = &mut part.record.inputs {
                    sources[0].rows = part.record.rows;
                }
                part.record.dedup.rows_in = part.record.rows;
                Ok(part)
            })();
            let _ = sender.send(result.map(|part| (hour, part)));
        }));
    }
    drop(sender);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        let mut log = PartLogWriter::open(&store, TENANT, 1, &schema, now_ms()).await?;
        let mut done = 0;
        for result in receiver {
            let (hour, part) = result?;
            let reference = publish_parts(&store, &signer, &trusted, std::slice::from_ref(&part)).await?.remove(0);
            let sha = part.record.inputs.clone();
            let PartInputs::Sources { sources, .. } = sha else { bail!("source inputs") };
            log.append(
                LogOp::Add {
                    edge_log: None,
                    parts: vec![reference],
                    consumed: vec![SourceRef { key: sources[0].key.clone(), version: sources[0].version.clone(), sha256: sources[0].sha256.clone() }],
                },
                now_ms(),
            )
            .await?;
            let _ = std::fs::remove_dir_all(&part.dir);
            // Disk is tight on the lab box: the source hour is in the store now.
            let _ = std::fs::remove_file(src.join(format!("event_hour={hour}.parquet")));
            done += 1;
            eprintln!("appended hour {hour} ({done}/{})", files.len());
        }
        Ok::<_, anyhow::Error>(())
    })?;
    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

fn reference_objects(work: &Path) -> Result<Vec<(i32, PathBuf)>> {
    let mut objects = Vec::new();
    for entry in std::fs::read_dir(work.join("reference"))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(hour) = name.strip_prefix("event_hour=") else { continue };
        let path = entry.path().join("object.parquet");
        if path.is_file() {
            objects.push((hour.parse::<i32>()?, path));
        }
    }
    objects.sort();
    if objects.is_empty() {
        bail!("no reference objects under {}", work.display());
    }
    Ok(objects)
}

fn objects_schema(objects: &[(i32, PathBuf)]) -> Result<SchemaRef> {
    let mut schema: Option<SchemaRef> = None;
    for (_, path) in objects {
        let next = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?.schema().clone();
        if let Some(prior) = &schema {
            if prior.fields() != next.fields() {
                bail!("reference objects differ in schema; the lab expects one read schema");
            }
        }
        schema = Some(next);
    }
    schema.context("no schema")
}

// ---------------------------------------------------------------------------
// shared: engine and reference reader
// ---------------------------------------------------------------------------

struct Lab {
    engine: PartQueryEngine,
    reference_tenant: TenantQueryConfig,
    reference_manifest: SourceManifest,
    reference_paths: Vec<PathBuf>,
    field_types: BTreeMap<String, String>,
    measured_store: Option<Arc<DelayedStore>>,
}

fn tenant_config(snapshot_cache: Option<SnapshotCache>) -> TenantQueryConfig {
    TenantQueryConfig {
        tenant_id: TENANT.to_string(),
        source: format!("s3://{BUCKET}/reference"),
        iceberg_metadata_file_path: "lab/metadata.json".to_string(),
        max_query_bytes: 200 * 1024 * 1024 * 1024,
        max_memory_bytes: 3 * 1024 * 1024 * 1024,
        max_execution_seconds: 300,
        threads: 2,
        credentials: ObjectStoreCredentials::DefaultChain,
        snapshot_cache,
    }
}

/// The fixture store, optionally with a per-GET delay that stands in for an
/// R2 round trip (`NAN2989_GET_LATENCY_MS`, cold-start measurements).
struct DelayedStore {
    inner: LocalObjectStore,
    delay: Duration,
    gets: std::sync::atomic::AtomicU64,
    bytes: std::sync::atomic::AtomicU64,
    fetched_row_groups: std::sync::atomic::AtomicU64,
    fetched_parts: std::sync::Mutex<BTreeSet<String>>,
    measure_data: bool,
}

impl DelayedStore {
    fn new(inner: LocalObjectStore, delay: Duration, measure_data: bool) -> Self {
        Self { inner, delay, gets: Default::default(), bytes: Default::default(),
            fetched_row_groups: Default::default(), fetched_parts: Default::default(), measure_data }
    }
}

#[async_trait::async_trait]
impl ObjectStore for DelayedStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tokio::time::sleep(self.delay).await;
        let bytes = self.inner.get(key).await?;
        self.bytes.fetch_add(bytes.as_ref().map_or(0, |b| b.len() as u64), std::sync::atomic::Ordering::Relaxed);
        if self.measure_data && bytes.is_some() && key.rsplit('/').next().is_some_and(|name| name.starts_with("data-") && name.ends_with(".parquet")) {
            // Every cache miss transfers the complete data object. Count its
            // groups independently of the planner's surviving-group evidence.
            let file = std::fs::File::open(self.inner.path(key)?)?;
            let groups = ParquetRecordBatchReaderBuilder::try_new(file)?.metadata().num_row_groups();
            self.fetched_row_groups.fetch_add(groups as u64, std::sync::atomic::Ordering::Relaxed);
            if let Some((part, _)) = key.rsplit_once('/') {
                self.fetched_parts.lock().map_err(|_| anyhow::anyhow!("GET measurement lock poisoned"))?.insert(part.to_string());
            }
        }
        Ok(bytes)
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        self.inner.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix).await
    }
}

fn get_latency() -> Duration {
    Duration::from_millis(std::env::var("NAN2989_GET_LATENCY_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
}

fn lab_store(work: &Path) -> Result<Arc<dyn ObjectStore>> {
    let inner = LocalObjectStore::new(work.join("store"))?;
    let delay = get_latency();
    Ok(if delay.is_zero() { Arc::new(inner) } else { Arc::new(DelayedStore::new(inner, delay, false)) })
}

async fn open_lab(work: &Path, cache_dir: &Path, with_reference: bool) -> Result<Lab> {
    open_lab_inner(work, cache_dir, with_reference, false).await
}

async fn open_lab_inner(work: &Path, cache_dir: &Path, with_reference: bool, measured: bool) -> Result<Lab> {
    let measured_store = if measured {
        Some(Arc::new(DelayedStore::new(LocalObjectStore::new(work.join("store"))?, get_latency(), true)))
    } else { None };
    let store: Arc<dyn ObjectStore> = match &measured_store {
        Some(store) => store.clone(), None => lab_store(work)?,
    };
    let trusted = trusted();
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await?;
    let cache = ReaderObjectCache::open(
        ReaderObjectCacheSettings {
            root: cache_dir.to_path_buf(),
            max_bytes: 40 * 1024 * 1024 * 1024,
            query_max_bytes: 40 * 1024 * 1024 * 1024,
            fetch_concurrency: 8,
            fetch_deadline: Duration::from_secs(600),
        },
        TENANT,
        BUCKET,
        &parts_key_prefix(TENANT)?,
        if measured { Arc::new(StoreObjectSource::new(BUCKET, store.clone())) }
        else { Arc::new(StoreObjectSource::local(BUCKET, store.clone(), work.join("store"))) },
    )?;
    // Zero-copy mode as in a cell (the store is the cell-local parts dir);
    // NAN2869_COPY=1 forces the copying cache path for comparison.
    let local_root = (!measured && std::env::var("NAN2869_COPY").is_err()).then(|| work.join("store"));
    let fetcher = PartFetcher::new(TENANT, BUCKET, store.clone(), trusted, cache)?.with_local_root(local_root);
    // NAN2869_STATE_DIR: persist proofs across lab processes, as a cell's
    // query[T] state dir does across idle exits (unset: first-ever cold).
    let state_dir = if measured { None } else { std::env::var_os("NAN2869_STATE_DIR").map(PathBuf::from) };
    if let Some(dir) = &state_dir {
        std::fs::create_dir_all(dir)?;
    }
    let fetcher = match &state_dir {
        Some(dir) => fetcher.with_state_dir(dir),
        None => fetcher,
    };
    let runtime = runtime()?;
    if measured {
        anyhow::ensure!(runtime.supports_streaming(),
            "live-like search benchmark requires the streaming chDB ABI; materialized fallback cannot measure native_init_ms");
        // Native background threads can outlive the last executor connection.
        // Keep libchdb mapped while fresh engines are opened between cases.
        std::mem::forget(runtime.clone());
    }
    let server_cap = std::env::var("NAN2869_SERVER_MEMORY_BYTES").ok().and_then(|value| value.parse().ok()).unwrap_or(6_u64 << 30);
    let threads = std::env::var("NAN2869_THREADS").ok().and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=8).contains(value)).unwrap_or(2);
    let executor = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 2, "parts", ExecutorMode::ReadOnly, Some(server_cap))?;
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(server_cap))?;
    let engine = PartQueryEngine::new(
        EngineSettings {
            tenant_id: TENANT.to_string(),
            bucket: BUCKET.to_string(),
            compiler: PathBuf::from(std::env::var("NANO_LAKE_COMPILER").context("NANO_LAKE_COMPILER")?),
            max_query_bytes: 200 * 1024 * 1024 * 1024,
            max_memory_bytes: 3 * 1024 * 1024 * 1024,
            max_execution_seconds: 300,
            threads,
        },
        store,
        view,
        fetcher,
        executor,
    )?
    .with_writer(writer);
    let engine = match &state_dir {
        Some(dir) => engine.with_state_dir(dir),
        None => engine,
    };
    let field_types = engine.field_types().await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let (reference_tenant, reference_manifest, reference_paths) = if with_reference {
        let objects = reference_objects(work)?;
        let schema = objects_schema(&objects)?;
        let read_schema = nanosiem_lake_worker::iceberg::clickhouse_read_schema(&schema)?;
        let leaves = nanosiem_lake_worker::generation::schema_leaf_types(&schema);
        let available: Arc<[String]> = leaves.keys().cloned().collect::<Vec<_>>().into();
        let mut manifest_objects = Vec::new();
        let mut cache_objects = BTreeMap::new();
        let mut paths = Vec::new();
        let mut total = 0;
        for (hour, path) in &objects {
            let bytes = std::fs::metadata(path)?.len();
            let rows = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?.metadata().file_metadata().num_rows() as u64;
            let key = format!("s3://{BUCKET}/reference/data/event_hour={hour}/object.parquet");
            manifest_objects.push(ManifestObject {
                event_object_key: key.clone(),
                event_object_version: "v1".to_string(),
                event_object_bytes: bytes,
                rows,
                available_paths: available.clone(),
                field_types: leaves.clone(),
                column_compressed_bytes: BTreeMap::new(),
            });
            cache_objects.insert(key, SnapshotCacheObject { version_id: "v1".to_string(), bytes, path: path.canonicalize()? });
            paths.push(path.canonicalize()?.to_str().unwrap().to_string());
            total += bytes;
        }
        let reference_paths = paths.iter().map(PathBuf::from).collect();
        let source_spec = planner::local_path_spec(&mut paths)?;
        let tenant = tenant_config(Some(SnapshotCache {
            source_spec,
            objects: cache_objects,
            bytes: total,
            read_schema: Some(read_schema),
            bootstrap: false,
        }));
        if leaves != field_types {
            bail!("reference and part-log field types differ");
        }
        (tenant, SourceManifest::from_objects(TENANT, manifest_objects), reference_paths)
    } else {
        (tenant_config(None), SourceManifest::from_objects(TENANT, Vec::new()), Vec::new())
    };
    Ok(Lab { engine, reference_tenant, reference_manifest, reference_paths, field_types, measured_store })
}

fn corpus(path: &Path) -> Result<Vec<Value>> {
    let corpus: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let end = chrono::DateTime::parse_from_rfc3339(CORPUS_END)?;
    let mut out = Vec::new();
    for domain in corpus["domains"].as_array().context("corpus domains")? {
        for query in domain["queries"].as_array().context("corpus queries")? {
            let window = query["window"].as_str().unwrap_or("1h");
            let duration = match window {
                "15m" => chrono::Duration::minutes(15),
                "1h" => chrono::Duration::hours(1),
                "6h" => chrono::Duration::hours(6),
                "24h" => chrono::Duration::hours(24),
                "7d" => chrono::Duration::days(7),
                other => bail!("window {other}"),
            };
            let start = (end - duration).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            out.push(json!({
                "n": out.len() + 1,
                "tier": query["tier"], "window": window, "query": query["query"],
                "lake_supported": query.get("lake_supported").and_then(Value::as_bool).unwrap_or(true),
                "start": start, "end": CORPUS_END,
            }));
        }
    }
    Ok(out)
}

fn request(id: &str, query: &str, start: &str, end: &str, limit: usize, table_view: bool) -> BroadNplRequest {
    BroadNplRequest {
        request_id: id.to_string(),
        tenant_id: TENANT.to_string(),
        dataset: "logs".to_string(),
        query: query.to_string(),
        start: start.to_string(),
        end: end.to_string(),
        limit,
        offset: 0,
        table_view,
        use_cache: false,
        cursor_time: None,
        cursor_event_uid: None,
        anchor_us: None,
        decay: None,
        clear_boundaries: BTreeMap::new(),
        watch_weights: Default::default(),
        minimum_clear_revision: None,
        deny_source_types: BTreeSet::new(),
    }
}

/// The current reader's planner over the reference generation objects.
async fn reference_rows(lab: &Lab, request: &BroadNplRequest) -> Result<(Vec<Value>, bool, f64)> {
    let compiled = lab.engine.compile(request, lab.field_types.clone()).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let mut plan = planner::plan_broad_log_query_with_candidates_and_tail(&lab.reference_tenant, &lab.reference_manifest, &compiled, None, None)?;
    if lab.measured_store.is_some() {
        // Independent full scan: no native Parquet predicate pushdown either.
        plan.sql = plan.sql.replace("input_format_parquet_filter_push_down=1", "input_format_parquet_filter_push_down=0");
    }
    let started = Instant::now();
    let output = lab.engine.execute(plan.clone()).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let (rows, more) = page_rows(&output.data, &plan, request.offset, request.limit).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok((rows, more, started.elapsed().as_secs_f64()))
}

async fn parts_rows(lab: &Lab, request: &BroadNplRequest) -> Result<(Vec<Value>, bool, f64, Value)> {
    let started = Instant::now();
    // The debug build's broad-query future is large. Keep it out of the
    // task-local timing wrapper's inline state (and the caller's stack).
    let envelope = nanosiem_lake_worker::query_timing::measure(
        &request.request_id,
        Box::pin(nanosiem_lake_worker::enrichment_read::scope(
            lab_authority(),
            lab.engine.broad_npl(request),
        )),
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let rows = envelope["result"]["rows"].as_array().cloned().unwrap_or_default();
    let mut evidence = envelope["planner"].clone();
    evidence["native_storage_rows"] = envelope["result"]["storage_rows"].clone();
    evidence["native_storage_bytes"] = envelope["result"]["storage_bytes"].clone();
    evidence["native_execute_s"] = envelope["result"]["engine_seconds"].clone();
    Ok((rows, envelope["result"]["page_has_more"].as_bool().unwrap_or(false), started.elapsed().as_secs_f64(), evidence))
}

fn canonical(rows: &[Value]) -> Vec<String> {
    let mut out = rows.iter().map(|row| row.to_string()).collect::<Vec<_>>();
    out.sort();
    out
}

/// Sort every array inside a value (aggregate arrays such as `values()` /
/// `groupUniqArray` have no defined element order).
fn sort_arrays(value: &Value) -> Value {
    match value {
        Value::Array(items) => {
            let mut items = items.iter().map(sort_arrays).collect::<Vec<_>>();
            items.sort_by_key(|item| item.to_string());
            Value::Array(items)
        }
        Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), sort_arrays(v))).collect()),
        other => other.clone(),
    }
}

/// `values(x)` renders a ", "-joined list with no defined element order;
/// compare such strings as sets.
fn sort_lists(value: &Value) -> Value {
    match value {
        Value::String(text) if text.contains(", ") => {
            let mut items = text.split(", ").collect::<Vec<_>>();
            items.sort_unstable();
            Value::String(items.join(", "))
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_lists).collect()),
        Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), sort_lists(v))).collect()),
        other => other.clone(),
    }
}

fn canonical_with(rows: &[Value], normalize: impl Fn(&Value) -> Value) -> Vec<String> {
    canonical(&rows.iter().map(normalize).collect::<Vec<_>>())
}

/// Both sides equal once the rows tied with the last row on a shared numeric
/// field (the ORDER BY key a `sort … | head N` cut through) are set aside:
/// the query's result is not uniquely defined at that boundary.
fn equal_up_to_limit_ties(reference: &[Value], parts: &[Value]) -> bool {
    if reference.len() != parts.len() || reference.is_empty() {
        return false;
    }
    let (Some(Value::Object(last_ref)), Some(Value::Object(last_parts))) = (reference.last(), parts.last()) else { return false };
    let keys = last_ref
        .iter()
        .filter(|(key, value)| value.is_number() && last_parts.get(*key) == Some(*value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    keys.iter().any(|(key, tie)| {
        let keep = |rows: &[Value]| rows.iter().filter(|row| row.get(key) != Some(tie)).cloned().collect::<Vec<_>>();
        let (left, right) = (keep(reference), keep(parts));
        left.len() == right.len() && canonical_with(&left, sort_arrays) == canonical_with(&right, sort_arrays)
    })
}

fn compare(reference: &[Value], parts: &[Value]) -> &'static str {
    if reference == parts {
        "identical"
    } else if canonical(reference) == canonical(parts) {
        "identical_rows_order_differs"
    } else if canonical_with(reference, sort_arrays) == canonical_with(parts, sort_arrays) {
        "identical_up_to_array_order"
    } else if canonical_with(reference, |row| sort_lists(&sort_arrays(row))) == canonical_with(parts, |row| sort_lists(&sort_arrays(row))) {
        "identical_up_to_values_list_order"
    } else if equal_up_to_limit_ties(reference, parts) {
        "identical_up_to_limit_ties"
    } else {
        "MISMATCH"
    }
}

/// First differing canonical rows of each side (bounded), for the report.
fn diff_sample(reference: &[Value], parts: &[Value]) -> Value {
    let left = canonical(&reference.iter().map(sort_arrays).collect::<Vec<_>>());
    let right = canonical(&parts.iter().map(sort_arrays).collect::<Vec<_>>());
    let only_left = left.iter().filter(|row| !right.contains(row)).take(2).map(|row| row.chars().take(400).collect::<String>()).collect::<Vec<_>>();
    let only_right = right.iter().filter(|row| !left.contains(row)).take(2).map(|row| row.chars().take(400).collect::<String>()).collect::<Vec<_>>();
    json!({"reference_only": only_left, "parts_only": only_right, "reference_rows": reference.len(), "parts_rows": parts.len()})
}

// ---------------------------------------------------------------------------
// parity
// ---------------------------------------------------------------------------

async fn parity(work: &Path, corpus_path: &Path, rules: &[PathBuf]) -> Result<Value> {
    let cache_dir = work.join(format!("cache-parity-{}", std::process::id()));
    let lab = open_lab(work, &cache_dir, true).await?;
    let mut report = serde_json::Map::new();
    report.insert("log_head".into(), json!(lab.engine.head().await.map(|(seq, _)| seq)));
    report.insert("reference_objects".into(), json!(lab.reference_paths.len()));

    // 1. k6 hunt corpus.
    let mut k6 = Vec::new();
    for query in corpus(corpus_path)? {
        let id = format!("k6-{}", query["n"]);
        let request = request(&id, query["query"].as_str().unwrap(), query["start"].as_str().unwrap(), query["end"].as_str().unwrap(), 200, true);
        let reference = reference_rows(&lab, &request).await;
        let parts = parts_rows(&lab, &request).await;
        let entry = match (reference, parts) {
            (Ok((reference, reference_more, reference_s)), Ok((parts, parts_more, parts_s, planner))) => {
                let verdict = if reference_more != parts_more { "MISMATCH_HAS_MORE" } else { compare(&reference, &parts) };
                let mut entry = json!({
                    "n": query["n"], "tier": query["tier"], "window": query["window"], "query": query["query"],
                    "verdict": verdict, "rows": reference.len(), "reference_s": reference_s, "parts_s": parts_s, "planner": planner,
                });
                if verdict != "identical" {
                    // Is the reader itself deterministic for this query?
                    let again = reference_rows(&lab, &request).await?.0;
                    entry["reference_self_verdict"] = json!(compare(&reference, &again));
                    entry["diff"] = diff_sample(&reference, &parts);
                }
                entry
            }
            (Err(reference), Err(parts)) => json!({
                "n": query["n"], "verdict": if reference.to_string() == parts.to_string() { "both_refused_identically" } else { "both_refused" },
                "reference_error": reference.to_string(), "parts_error": parts.to_string(),
            }),
            (reference, parts) => json!({
                "n": query["n"], "verdict": "MISMATCH_ERROR",
                "reference_error": reference.err().map(|e| e.to_string()), "parts_error": parts.err().map(|e| e.to_string()),
            }),
        };
        eprintln!("k6 {} {} {}", query["n"], entry["verdict"], entry["parts_s"]);
        k6.push(entry);
    }
    report.insert("k6".into(), Value::Array(k6));

    // 2. Detections: every logs rule over 24 one-hour windows and the day.
    let mut detections = Vec::new();
    let windows = (0..24)
        .map(|hour| (format!("2026-09-24T{hour:02}:00:00Z"), format!("2026-09-24T{hour:02}:59:59Z")))
        .chain(std::iter::once(("2026-09-24T00:00:00Z".to_string(), "2026-09-25T00:00:00Z".to_string())))
        .collect::<Vec<_>>();
    for rules_path in rules {
        let rules: Value = serde_json::from_slice(&std::fs::read(rules_path)?)?;
        for rule in rules.as_array().context("rules array")? {
            if rule["dataset"].as_str() != Some("logs") {
                continue;
            }
            let name = rule["name"].as_str().unwrap_or("rule");
            let mut verdicts = BTreeMap::<String, usize>::new();
            let mut matches = 0_usize;
            let mut first_error = None;
            let mut details = Vec::new();
            for (start, end) in &windows {
                let request = request(&format!("det-{name}"), rule["query"].as_str().unwrap(), start, end, 1_000_000, false);
                let verdict = match (reference_rows(&lab, &request).await, parts_rows(&lab, &request).await) {
                    (Ok((reference, _, _)), Ok((parts, _, _, _))) => {
                        matches += reference.len();
                        let verdict = compare(&reference, &parts);
                        if verdict != "identical" && verdict != "identical_rows_order_differs" {
                            let again = reference_rows(&lab, &request).await?.0;
                            let self_verdict = compare(&reference, &again);
                            details.push(json!({"window": [start, end], "reference_self_verdict": self_verdict, "diff": diff_sample(&reference, &parts)}));
                            if self_verdict != "identical" && self_verdict != "identical_rows_order_differs" {
                                // The reader itself returns different rows run to run.
                                format!("{verdict} | reader_self={self_verdict}")
                            } else {
                                verdict.to_string()
                            }
                        } else {
                            verdict.to_string()
                        }
                    }
                    (Err(reference), Err(parts)) => {
                        first_error.get_or_insert_with(|| reference.to_string());
                        if reference.to_string() == parts.to_string() { "both_refused_identically".into() } else { "both_refused".into() }
                    }
                    (reference, parts) => {
                        first_error.get_or_insert_with(|| format!("{:?} / {:?}", reference.err(), parts.err()));
                        "MISMATCH_ERROR".into()
                    }
                };
                *verdicts.entry(verdict).or_default() += 1;
            }
            eprintln!("detection {name} {verdicts:?}");
            detections.push(json!({"rule": name, "source": rules_path.file_name().map(|n| n.to_string_lossy().to_string()),
                                   "windows": windows.len(), "matched_rows": matches, "verdicts": verdicts, "error": first_error,
                                   "mismatch_details": details.into_iter().take(3).collect::<Vec<_>>()}));
        }
    }
    report.insert("detections".into(), Value::Array(detections));

    // 3. Counts from rollup partials vs a full native scan of the reference.
    let mut counts = Vec::new();
    for (field, span, start, end) in [
        ("metadata.log_source", None, "2026-09-24T00:00:00Z", "2026-09-25T00:00:00Z"),
        ("class_uid", Some(3_600_000_000_i64), "2026-09-24T00:00:00Z", "2026-09-25T00:00:00Z"),
        ("device.hostname", None, "2026-09-24T03:17:41Z", "2026-09-24T21:02:09Z"),
        ("metadata.log_source", Some(300_000_000), "2026-09-24T22:03:10Z", "2026-09-24T23:59:59Z"),
    ] {
        let request: CountAggregateRequest = serde_json::from_value(json!({
            "request_id": "count", "tenant_id": TENANT, "group_field": field, "bucket_span_us": span,
            "count_alias": "count", "start": start, "end": end, "max_groups": 1_000_000,
        }))?;
        let parts = nanosiem_lake_worker::enrichment_read::scope(
            lab_authority(),
            partials::count_aggregate(&lab.engine, &request),
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let window = request.window().map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let plan = planner::plan_count_aggregate_query(
            &lab.reference_tenant,
            &lab.reference_manifest,
            &CountAggregatePlanRequest {
                group_field: field,
                group_results: true,
                multi_value: false,
                predicate: None,
                bucket_span_us: span,
                start_us: window.start_us,
                end_exclusive_us: window.end_exclusive_us,
                source_filter: None,
                deny_source_types: &BTreeSet::new(),
                source: CountAggregateSource::Base,
                group_by_source: false,
            },
        )?
        .context("reference count plan")?;
        let output = lab.engine.execute(plan).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let reference = merge_outputs(&request, vec![output]).map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let parts_rows = parts["result"]["rows"].as_array().cloned().unwrap_or_default();
        let verdict = compare(&reference.rows, &parts_rows);
        eprintln!("count {field} {span:?} {verdict}");
        counts.push(json!({"field": field, "bucket_span_us": span, "start": start, "end": end, "groups": reference.rows.len(),
                           "verdict": verdict, "parts_s": parts["wall_seconds"]}));
    }
    report.insert("counts".into(), Value::Array(counts));

    // 4. Prevalence (partials + exact edges) vs the builder's observation SQL
    //    over the reference rows, and 5. entity ranges vs raw scans.
    report.insert("prevalence".into(), prevalence_parity(&lab).await.unwrap_or_else(|error| json!({"error": error.to_string()})));
    report.insert("entity_ranges".into(), entity_parity(&lab).await.unwrap_or_else(|error| json!({"error": error.to_string()})));
    report.insert("memory".into(), rss());
    let _ = std::fs::remove_dir_all(&cache_dir);
    Ok(Value::Object(report))
}

/// Run the detection query shapes through both real storage routes. A zero-row
/// answer cannot establish that a sequence/correlation/retro rule worked, and
/// a refusal from both engines is not parity, so both are hard failures here.
async fn corr_parity(work: &Path, cases_path: &Path) -> Result<Value> {
    let cache_dir = work.join(format!("cache-corr-{}", std::process::id()));
    let lab = open_lab(work, &cache_dir, true).await?;
    let cases: Value = serde_json::from_slice(&std::fs::read(cases_path)?)?;
    let cases = cases.as_array().context("correlation cases must be an array")?;
    anyhow::ensure!(!cases.is_empty(), "correlation cases must not be empty");
    let mut results = Vec::new();
    for case in cases {
        let name = case["name"].as_str().context("case name")?;
        let query = case["query"].as_str().context("case query")?;
        let start = case["start"].as_str().context("case start")?;
        let end = case["end"].as_str().context("case end")?;
        let limit = usize::try_from(case["limit"].as_u64().context("case limit")?)?;
        anyhow::ensure!((1..=10_000).contains(&limit), "{name}: limit must be 1..=10000");
        let request = request(name, query, start, end, limit, false);
        let (reference, reference_more, reference_s) = reference_rows(&lab, &request).await
            .with_context(|| format!("{name}: reference query failed"))?;
        let (parts, parts_more, parts_s, planner) = parts_rows(&lab, &request).await
            .with_context(|| format!("{name}: signed-part query failed"))?;
        let verdict = compare(&reference, &parts);
        anyhow::ensure!(!reference.is_empty(), "{name}: reference matched no rows");
        anyhow::ensure!(!reference_more && !parts_more, "{name}: result reached its page limit");
        anyhow::ensure!(verdict == "identical" || verdict == "identical_rows_order_differs",
            "{name}: result differs ({verdict}): {}", diff_sample(&reference, &parts));
        if case["replay"].as_bool().unwrap_or(false) {
            let (replayed, replay_more, _, _) = parts_rows(&lab, &request).await
                .with_context(|| format!("{name}: signed-part replay failed"))?;
            anyhow::ensure!(!replay_more && canonical(&replayed) == canonical(&parts),
                "{name}: same signed snapshot changed on replay");
        }
        results.push(json!({"name": name, "verdict": verdict, "rows": reference.len(),
            "reference_s": reference_s, "parts_s": parts_s, "planner": planner}));
    }
    let _ = std::fs::remove_dir_all(&cache_dir);
    Ok(json!({"tenant_id": TENANT, "log_head": lab.engine.head().await.map(|(seq, _)| seq),
        "cases": results}))
}

async fn prevalence_parity(lab: &Lab) -> Result<Value> {
    // Reference: one exact aggregate over every reference row in the window.
    // NAN-3161: lookups answer whole (event-hour) parts, so the exact raw
    // reference uses hour-aligned bounds, where the two are identical.
    let (from, to) = ("2026-09-24T01:00:00Z", "2026-09-24T23:59:59.999999Z");
    let from_us = chrono::DateTime::parse_from_rfc3339(from)?.timestamp_micros();
    let to_us = chrono::DateTime::parse_from_rfc3339(to)?.timestamp_micros();
    let mut arms = Vec::new();
    let mut params = vec![("from_us".to_string(), from_us.to_string()), ("to_us".to_string(), to_us.to_string())];
    for (index, path) in lab.reference_paths.iter().enumerate() {
        let name = format!("ref_{index}");
        arms.push(format!("SELECT kind, scope, entity, host, is_private, time FROM ({})", nanosiem_lake_worker::prevalence_build::observation_select_sql(path, &name)?));
        params.push((name, path.to_str().unwrap().to_string()));
    }
    let sql = format!(
        "SELECT kind, entity, uniqExact(host) AS hosts, count() AS total, toUnixTimestamp64Micro(min(time)) AS first_us, \
                toUnixTimestamp64Micro(max(time)) AS last_us \
         FROM ({}) WHERE toUnixTimestamp64Micro(time) >= {{from_us:Int64}} AND toUnixTimestamp64Micro(time) <= {{to_us:Int64}} \
         GROUP BY kind, entity ORDER BY total DESC, kind, entity LIMIT 400 SETTINGS max_threads=4, max_memory_usage=6000000000",
        arms.join(" UNION ALL ")
    );
    let reference = lab.engine.execute_sql(sql, params).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let artifacts = reference.iter().map(|row| row["entity"].as_str().unwrap_or_default().to_string()).collect::<Vec<_>>();
    let span_hours = (to_us - from_us) as f64 / 3.6e9;
    let started = Instant::now();
    let result = partials::prevalence_lookup_bounds(&lab.engine, &artifacts, from_us, to_us, &[], partials::DEFAULT_RARITY_THRESHOLD)
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let seconds = started.elapsed().as_secs_f64();
    let mut mismatches = Vec::new();
    for row in &reference {
        let entity = row["entity"].as_str().unwrap_or_default();
        let found = result.iter().find(|candidate| candidate.artifact == entity);
        let hosts = row["hosts"].as_u64().unwrap_or(0).min(65);
        let ok = found.is_some_and(|found| {
            found.host_count == hosts
                && found.total_occurrences == row["total"].as_u64().unwrap_or(0)
                && found.first_seen == nanosiem_lake_worker::prevalence::format_micros(row["first_us"].as_i64().unwrap_or(0))
                && found.last_seen == nanosiem_lake_worker::prevalence::format_micros(row["last_us"].as_i64().unwrap_or(0))
        });
        if !ok {
            mismatches.push(json!({"reference": row, "parts": found.map(|found| serde_json::to_value(found).unwrap_or_default())}));
        }
    }
    eprintln!("prevalence: {} artifacts, {} mismatches, {:.2}s", reference.len(), mismatches.len(), seconds);
    Ok(json!({"window_hours": span_hours, "artifacts": reference.len(), "mismatches": mismatches.len(),
              "examples": mismatches.into_iter().take(5).collect::<Vec<_>>(), "parts_s": seconds}))
}

async fn entity_parity(lab: &Lab) -> Result<Value> {
    let (from, to) = ("2026-09-24T02:10:00Z", "2026-09-24T23:50:00Z");
    let from_us = chrono::DateTime::parse_from_rfc3339(from)?.timestamp_micros();
    let to_us = chrono::DateTime::parse_from_rfc3339(to)?.timestamp_micros();
    let mut out = Vec::new();
    for path in ["device.hostname", "src_endpoint.ip", "actor.user.name"] {
        let column = path.split('.').map(|segment| format!("`{segment}`")).collect::<Vec<_>>().join(".");
        let mut paths = lab.reference_paths.iter().map(|p| p.to_str().unwrap().to_string()).collect::<Vec<_>>();
        let spec = planner::local_path_spec(&mut paths)?;
        let read_schema = lab.reference_tenant.snapshot_cache.as_ref().and_then(|cache| cache.read_schema.clone()).unwrap();
        let reference = lab
            .engine
            .execute_sql(
                format!(
                    "SELECT lower(toString({column})) AS entity, toUnixTimestamp64Micro(min(time)) AS first_us, \
                            toUnixTimestamp64Micro(max(time)) AS last_us, count() AS events \
                     FROM file({{src:String}}, Parquet, {{schema:String}}) \
                     WHERE isNotNull({column}) AND toUnixTimestamp64Micro(time) >= {{from_us:Int64}} AND toUnixTimestamp64Micro(time) <= {{to_us:Int64}} \
                     GROUP BY entity ORDER BY events DESC, entity LIMIT 50 SETTINGS max_threads=4"
                ),
                vec![
                    ("src".into(), spec),
                    ("schema".into(), read_schema),
                    ("from_us".into(), from_us.to_string()),
                    ("to_us".into(), to_us.to_string()),
                ],
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let reference = reference.into_iter().filter(|row| !row["entity"].as_str().unwrap_or_default().is_empty()).collect::<Vec<_>>();
        let values = reference.iter().map(|row| row["entity"].as_str().unwrap_or_default().to_string()).collect::<Vec<_>>();
        if values.is_empty() {
            out.push(json!({"path": path, "values": 0}));
            continue;
        }
        let started = Instant::now();
        let parts = partials::entity_ranges(
            &lab.engine,
            &EntityRangesRequest {
                request_id: "ent".into(),
                tenant_id: TENANT.into(),
                path: path.into(),
                values,
                start: from.into(),
                end: to.into(),
                case_insensitive: true,
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let normalize = |rows: &[Value]| {
            let mut rows = rows
                .iter()
                .map(|row| {
                    let n = |value: &Value| value.as_i64().or_else(|| value.as_str().and_then(|s| s.parse().ok())).unwrap_or_default();
                    (row["entity"].as_str().unwrap_or_default().to_string(), n(&row["first_us"]), n(&row["last_us"]), n(&row["events"]))
                })
                .collect::<Vec<_>>();
            rows.sort();
            rows
        };
        let parts_rows = parts["result"]["rows"].as_array().cloned().unwrap_or_default();
        let verdict = if normalize(&reference) == normalize(&parts_rows) { "identical" } else { "MISMATCH" };
        eprintln!("entity {path} {verdict}");
        out.push(json!({"path": path, "values": reference.len(), "verdict": verdict, "parts_s": started.elapsed().as_secs_f64()}));
    }
    Ok(Value::Array(out))
}

// ---------------------------------------------------------------------------
// bench
// ---------------------------------------------------------------------------

/// Compare two signed part fixtures directly. The bench digest intentionally
/// hides row contents, so this diagnoses changes at a sorted/limited boundary.
async fn fixture_ab(old: &Path, new: &Path, corpus_path: &Path) -> Result<Value> {
    let old_cache = old.join(format!("cache-ab-{}", std::process::id()));
    let new_cache = new.join(format!("cache-ab-{}", std::process::id()));
    let old_lab = open_lab(old, &old_cache, false).await?;
    let new_lab = open_lab(new, &new_cache, false).await?;
    let filter = std::env::var("NAN2869_AB_FILTER").ok().map(|value| {
        value.split(',').filter_map(|number| number.trim().parse::<usize>().ok()).collect::<BTreeSet<_>>()
    });
    let mut results = Vec::new();
    for query in corpus(corpus_path)? {
        if filter.as_ref().is_some_and(|filter| !filter.contains(&(query["n"].as_u64().unwrap_or_default() as usize))) {
            continue;
        }
        let request = request(
            "fixture-ab",
            query["query"].as_str().unwrap(),
            query["start"].as_str().unwrap(),
            query["end"].as_str().unwrap(),
            200,
            true,
        );
        let (old_rows, old_more, old_s, _) = parts_rows(&old_lab, &request).await?;
        let (new_rows, new_more, new_s, planner) = parts_rows(&new_lab, &request).await?;
        let verdict = if old_more != new_more { "MISMATCH_HAS_MORE" } else { compare(&old_rows, &new_rows) };
        let result = json!({
            "n": query["n"], "verdict": verdict, "old_rows": old_rows.len(), "new_rows": new_rows.len(),
            "old_more": old_more, "new_more": new_more, "old_s": old_s, "new_s": new_s,
            "source_family_pruned_files": planner["source_family_pruned_files"],
        });
        results.push(result);
    }
    let _ = std::fs::remove_dir_all(&old_cache);
    let _ = std::fs::remove_dir_all(&new_cache);
    Ok(json!({"results": results}))
}

async fn bench(work: &Path, corpus_path: &Path, concurrency: usize, rules: &[PathBuf]) -> Result<Value> {
    let started = Instant::now();
    let cache_dir = work.join(format!("cache-bench-{}", std::process::id()));
    let lab = Arc::new(open_lab(work, &cache_dir, false).await?);
    let open_s = started.elapsed().as_secs_f64();
    let open_memory = rss();
    let queries = corpus(corpus_path)?;
    let mut rounds = Vec::new();
    for round in ["cold", "warm"] {
        let queue = Arc::new(std::sync::Mutex::new(queries.clone()));
        let results = Arc::new(std::sync::Mutex::new(Vec::new()));
        let round_started = Instant::now();
        let cpu_before = cpu_seconds();
        let fetched_before = lab.engine.fetcher().cache().stats().fetched_bytes;
        let workers = (0..concurrency.max(1))
            .map(|_| {
                let (lab, queue, results) = (lab.clone(), queue.clone(), results.clone());
                tokio::spawn(async move {
                    loop {
                        let Some(query) = queue.lock().unwrap().pop() else { break };
                        let request = request("bench", query["query"].as_str().unwrap(), query["start"].as_str().unwrap(), query["end"].as_str().unwrap(), 200, true);
                        let outcome = parts_rows(&lab, &request).await;
                        results.lock().unwrap().push(match outcome {
                            Ok((rows, _, seconds, planner)) => {
                                let canonical_rows = canonical_with(&rows, sort_arrays).join("\n");
                                let rows_sha256 = format!("{:x}", sha2::Sha256::digest(canonical_rows.as_bytes()));
                                json!({"n": query["n"], "tier": query["tier"], "window": query["window"], "s": seconds,
                                    "rows": rows.len(), "rows_sha256": rows_sha256, "planner": planner})
                            },
                            Err(error) => json!({"n": query["n"], "tier": query["tier"], "error": error.to_string()}),
                        });
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.await?;
        }
        let results = results.lock().unwrap().clone();
        let mut seconds = results.iter().filter_map(|result| result["s"].as_f64()).collect::<Vec<_>>();
        seconds.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pct = |p: f64| seconds.get(((seconds.len() as f64 - 1.0) * p).round() as usize).copied().unwrap_or(0.0);
        let by_tier = ["triage", "hunt", "ir"]
            .iter()
            .map(|tier| {
                let mut tier_seconds = results.iter().filter(|r| r["tier"] == *tier).filter_map(|r| r["s"].as_f64()).collect::<Vec<_>>();
                tier_seconds.sort_by(|a, b| a.partial_cmp(b).unwrap());
                let p95 = tier_seconds.get(((tier_seconds.len() as f64 - 1.0) * 0.95).round() as usize).copied().unwrap_or(0.0);
                (tier.to_string(), json!({"n": tier_seconds.len(), "p95_s": p95}))
            })
            .collect::<serde_json::Map<_, _>>();
        let slowest = {
            let mut sorted = results.clone();
            sorted.sort_by(|a, b| b["s"].as_f64().partial_cmp(&a["s"].as_f64()).unwrap_or(std::cmp::Ordering::Equal));
            sorted.into_iter().take(5).collect::<Vec<_>>()
        };
        let cache_stats = lab.engine.fetcher().cache().stats();
        rounds.push(json!({
            "round": round, "wall_s": round_started.elapsed().as_secs_f64(), "queries": results.len(),
            "cpu_s": cpu_seconds().zip(cpu_before).map(|(after, before)| after - before),
            "fetched_bytes": cache_stats.fetched_bytes - fetched_before,
            "verified_in_place_bytes": lab.engine.fetcher().verified_in_place_bytes(),
            "cache_stored_bytes": cache_stats.stored_bytes,
            "errors": results.iter().filter(|r| r.get("error").is_some()).count(),
            "p50_s": pct(0.5), "p95_s": pct(0.95), "max_s": pct(1.0), "by_tier": by_tier,
            "memory_after": rss(), "cache": lab.engine.fetcher().cache().stats(),
            "slowest": slowest,
            "results": results,
        }));
        eprintln!("bench {round}: {}", rounds.last().unwrap());
    }
    let cpu_after_hunts = cpu_seconds();
    // Detection cycles: every logs rule over twelve consecutive 5-minute
    // windows (one simulated hour of the scheduler at 1 cycle / 5 min per
    // rule), all warm. CPU per cycle / 300 s = steady detection cores.
    let mut rule_queries = Vec::new();
    for path in rules {
        let rules: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        for rule in rules.as_array().context("rules array")? {
            if rule["dataset"].as_str() == Some("logs") {
                rule_queries.push(rule["query"].as_str().unwrap_or_default().to_string());
            }
        }
    }
    let cycles_started = Instant::now();
    let cpu_before_cycles = cpu_seconds();
    let mut cycle_errors = 0;
    let mut cycle_seconds = Vec::new();
    for window in 0..12_i64 {
        let start = chrono::DateTime::parse_from_rfc3339("2026-09-24T20:00:00Z")? + chrono::Duration::minutes(5 * window);
        let end = start + chrono::Duration::minutes(5) - chrono::Duration::microseconds(1);
        let cycle_started = Instant::now();
        for query in &rule_queries {
            let request = request(
                "cycle",
                query,
                &start.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                &end.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                1_000_000,
                false,
            );
            if parts_rows(&lab, &request).await.is_err() {
                cycle_errors += 1;
            }
        }
        cycle_seconds.push(cycle_started.elapsed().as_secs_f64());
    }
    let cycle_cpu = cpu_seconds().zip(cpu_before_cycles).map(|(after, before)| (after - before) / 12.0);
    let _ = std::fs::remove_dir_all(&cache_dir);
    Ok(json!({
        "concurrency": concurrency, "open_s": open_s, "open_memory": open_memory, "rounds": rounds,
        "cpu_seconds_hunts": cpu_after_hunts,
        "detection_cycles": {
            "rules": rule_queries.len(), "cycles": 12, "errors": cycle_errors,
            "wall_s_per_cycle": cycle_seconds, "total_wall_s": cycles_started.elapsed().as_secs_f64(),
            "cpu_s_per_cycle": cycle_cpu,
            "cores_at_one_cycle_per_5min": cycle_cpu.map(|cpu| cpu / 300.0),
            "cores_at_one_cycle_per_minute": cycle_cpu.map(|cpu| cpu / 60.0),
        },
        "memory_final": rss(),
    }))
}

/// The Q6 hunt session: its steps in order, one analyst, cold process.
/// NAN-2989 cold vs warm start of query[T] over the fixture:
/// - the part-log open the old serial catch-up paid (one GET per entry, plus
///   the merge provenance, in series) vs the windowed `PartLogView::open`;
/// - the full engine open (chDB, view, schema) and RSS after it;
/// - two simple searches run cold (first after open, no prewarm) then warm;
/// - RSS idle-resident after them.
/// `NAN2989_GET_LATENCY_MS` adds an R2-like delay to every store GET.
async fn coldstart(work: &Path) -> Result<Value> {
    use nanosiem_lake_worker::parts::format::{LogKeys, PartKeys};
    // NAN-3008: artifact digests a query[T] start pays: libchdb and the
    // compiler, hashed in full (first start) vs served from the memo.
    let digests = {
        use nanosiem_lake_worker::native::artifact_sha256_memoized;
        let memo = tempfile::tempdir()?;
        let mut out = serde_json::Map::new();
        for (name, var, retain) in [("libchdb", "NANO_CHDB_LIBRARY_PATH", false), ("compiler", "NANO_LAKE_COMPILER", true)] {
            let path = PathBuf::from(std::env::var(var).with_context(|| var.to_string())?);
            let t = Instant::now();
            let full = artifact_sha256_memoized(&path, Some(memo.path()), retain)?;
            let full_s = t.elapsed().as_secs_f64();
            let t = Instant::now();
            let memo_hit = artifact_sha256_memoized(&path, Some(memo.path()), retain)?;
            anyhow::ensure!(full == memo_hit, "memoized digest differs");
            out.insert(name.into(), json!({"bytes": std::fs::metadata(&path)?.len(), "full_s": full_s, "memo_s": t.elapsed().as_secs_f64()}));
        }
        Value::Object(out)
    };
    let store = lab_store(work)?;
    let keys = LogKeys::new(TENANT)?;
    let started = Instant::now();
    let (mut entries, mut serial_gets) = (0_u64, 0_u64);
    while let Some(bytes) = store.get(&keys.entry(entries)).await? {
        serial_gets += 1;
        if let LogOp::Merge { output, .. } = LogEntry::parse_bytes(&bytes, TENANT)?.op {
            store.get(&PartKeys::new(TENANT, output.level, output.event_hour, &output.part_id)?.provenance()).await?;
            serial_gets += 1;
        }
        entries += 1;
    }
    let serial_open_s = started.elapsed().as_secs_f64();
    let started = Instant::now();
    let view = PartLogView::open(store.as_ref(), TENANT, trusted()).await?;
    let windowed_open_s = started.elapsed().as_secs_f64();
    anyhow::ensure!(view.head().map(|(seq, _)| seq + 1) == Some(entries), "windowed open disagrees with the serial walk");
    drop(view);
    let rss_before_open = rss();
    let cache_dir = work.join(format!("cache-coldstart-{}", std::process::id()));
    let started = Instant::now();
    let lab = open_lab(work, &cache_dir, false).await?;
    let engine_open_s = started.elapsed().as_secs_f64();
    let rss_after_open = rss();
    let end = chrono::DateTime::parse_from_rfc3339(CORPUS_END)?.with_timezone(&chrono::Utc);
    let window = |minutes: i64| ((end - chrono::Duration::minutes(minutes)).to_rfc3339(), end.to_rfc3339());
    let mut searches = Vec::new();
    for (name, query, minutes) in [("head1_15m", "* | head 1", 15), ("count_by_source_1h", "* | stats count by metadata.log_source", 60)] {
        let (start, stop) = window(minutes);
        let mut runs = Vec::new();
        for attempt in ["cold", "warm", "warm"] {
            let request = request(&format!("coldstart-{name}-{attempt}"), query, &start, &stop, 100, true);
            let (rows, _, seconds, _) = parts_rows(&lab, &request).await?;
            runs.push(json!({"attempt": attempt, "seconds": seconds, "rows": rows.len()}));
        }
        searches.push(json!({"name": name, "query": query, "minutes": minutes, "runs": runs}));
    }
    let rss_idle_resident = rss();
    let _ = std::fs::remove_dir_all(&cache_dir);
    Ok(json!({
        "get_latency_ms": get_latency().as_millis() as u64,
        "log_entries": entries,
        "serial_open": {"gets": serial_gets, "seconds": serial_open_s},
        "windowed_open_seconds": windowed_open_s,
        "engine_open_seconds": engine_open_s,
        "searches": searches,
        "rss_before_open": rss_before_open,
        "rss_after_open": rss_after_open,
        "rss_idle_resident": rss_idle_resident,
        "artifact_digests": digests,
    }))
}

/// `POSIX_FADV_DONTNEED` every file under `root` (lab cold-cache runs).
fn evict_page_cache(root: &Path) {
    use std::os::fd::AsRawFd;
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => evict_page_cache(&path),
            Ok(kind) if kind.is_file() => {
                if let Ok(file) = std::fs::File::open(&path) {
                    // SAFETY: a valid open descriptor; advice only.
                    unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
                }
            }
            _ => {}
        }
    }
}

/// NAN-3153: one count_aggregate call as the search service sends it.
async fn lab_count(lab: &Lab, spec: &Value, field: &str, predicate: &Value, group_by_source: bool, start: &Value, end: &Value) -> Result<Vec<Value>> {
    let count: CountAggregateRequest = serde_json::from_value(json!({
        "request_id": "nan3153-count", "tenant_id": TENANT, "group_field": field,
        "group_results": spec["group_results"].as_bool().unwrap_or(false),
        "group_by_source": group_by_source,
        "predicate": predicate, "bucket_span_us": spec["span_us"], "source_filter": spec["source_filter"],
        "count_alias": "count", "start": start, "end": end, "max_groups": 10_000,
    }))?;
    let envelope = nanosiem_lake_worker::query_timing::measure(
        "nan3153-count",
        Box::pin(nanosiem_lake_worker::enrichment_read::scope(lab_authority(), partials::count_aggregate(&lab.engine, &count))),
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if std::env::var_os("NAN3153_PLANNER").is_some() {
        eprintln!("  count {field}: planner {} storage_bytes {}", envelope["planner"], envelope["result"]["storage_bytes"]);
    }
    Ok(envelope["result"]["rows"].as_array().cloned().unwrap_or_default())
}

/// The rollup route of one step: rows plus how many raw overlap scans ran.
async fn lab_rollup_route(lab: &Lab, step: &Value) -> Result<(Vec<Value>, usize)> {
    let spec = &step["rollup"];
    let (start, end) = (&step["start"], &step["end"]);
    if spec["shape"] == "union" {
        let sides = spec["sides"].as_array().context("union sides")?;
        let mut per_side = Vec::new();
        for side in sides {
            let rows = lab_count(lab, spec, side["field"].as_str().unwrap_or_default(), &side["predicate"], true, start, end).await?;
            per_side.push(rows.iter().map(|row| (row["metadata.log_source"].as_str().map(str::to_string), row["count"].as_u64().unwrap_or(0))).collect::<BTreeMap<_, _>>());
        }
        let mut union = BTreeMap::new();
        let mut overlap = Vec::new();
        for source in per_side[0].keys().chain(per_side[1].keys()).collect::<BTreeSet<_>>() {
            let (l, r) = (per_side[0].get(source).copied().unwrap_or(0), per_side[1].get(source).copied().unwrap_or(0));
            if l > 0 && r > 0 {
                overlap.push(source.clone().context("NULL source on both sides: search falls back")?);
            } else if l + r > 0 {
                union.insert(source.clone(), l + r);
            }
        }
        if !overlap.is_empty() {
            let base = step["query"].as_str().unwrap_or_default().split(" | ").next().unwrap_or_default();
            let narrowed = format!("({base}) metadata.log_source IN ({}) | stats count by metadata.log_source",
                overlap.iter().map(|source| format!("\"{source}\"")).collect::<Vec<_>>().join(", "));
            let (rows, _, _, _) = parts_rows(lab, &request("nan3153-overlap", &narrowed, start.as_str().unwrap_or_default(), end.as_str().unwrap_or_default(), 100_000, false)).await?;
            for row in rows {
                let source = row["metadata.log_source"].as_str().map(str::to_string);
                if source.as_ref().is_some_and(|source| overlap.contains(source)) {
                    union.insert(source, row["count"].as_u64().unwrap_or(0));
                }
            }
        }
        let rows = union.into_iter().map(|(source, count)| json!({"metadata.log_source": source, "count": count})).collect();
        return Ok((rows, usize::from(!overlap.is_empty())));
    }
    let rows = lab_count(lab, spec, spec["field"].as_str().unwrap_or_default(), &spec["predicate"],
        spec["group_by_source"].as_bool().unwrap_or(false), start, end).await?;
    Ok((rows, 0))
}

/// `group columns → count` (non-zero), with time keys normalized.
fn lab_groups(rows: &[Value]) -> BTreeMap<String, u64> {
    rows.iter().filter_map(|row| {
        let object = row.as_object()?;
        let count = object.get("count").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|v| v.parse().ok())))?;
        let key = object.iter().filter(|(name, _)| name.as_str() != "count").map(|(name, value)| {
            let name = if matches!(name.as_str(), "_time" | "time" | "time_bucket" | "timestamp") { "time" } else { name.as_str() };
            let value = value.as_str().map(|v| v.replace('T', " ").trim_end_matches('Z').split('.').next().unwrap_or_default().to_string())
                .unwrap_or_else(|| value.to_string());
            format!("{name}={value}")
        }).collect::<Vec<_>>().join(",");
        (count > 0).then_some((key, count))
    }).collect()
}

async fn rollup_routing(work: &Path, steps_path: &Path) -> Result<Value> {
    let cache_dir = work.join(format!("cache-rollup-routing-{}", std::process::id()));
    let lab = open_lab(work, &cache_dir, false).await?;
    let steps: Value = serde_json::from_slice(&std::fs::read(steps_path)?)?;
    let repeats = std::env::var("NAN3153_REPEATS").ok().and_then(|v| v.parse().ok()).unwrap_or(3_usize);
    let mut out = Vec::new();
    for step in steps.as_array().context("steps")? {
        let (start, end) = (step["start"].as_str().unwrap_or_default(), step["end"].as_str().unwrap_or_default());
        let mut rollup_s = Vec::new();
        let mut routed = (Vec::new(), 0);
        for _ in 0..repeats {
            let started = Instant::now();
            routed = lab_rollup_route(&lab, step).await?;
            rollup_s.push(started.elapsed().as_secs_f64());
        }
        // The compiled scan of the full group set (parity) and of the Q6
        // query itself (the latency the lean cell paid before NAN-3153).
        let parity_query = step["parity_query"].as_str().unwrap_or_else(|| step["query"].as_str().unwrap_or_default());
        let mut compiled_s = Vec::new();
        let mut compiled = Vec::new();
        for _ in 0..repeats.min(2) {
            let (rows, _, seconds, _) = parts_rows(&lab, &request("nan3153-compiled", step["query"].as_str().unwrap_or_default(), start, end, 100_000, false)).await?;
            compiled_s.push(seconds);
            compiled = rows;
        }
        if parity_query != step["query"].as_str().unwrap_or_default() {
            compiled = parts_rows(&lab, &request("nan3153-parity", parity_query, start, end, 1_000_000, false)).await?.0;
        }
        let (routed_groups, compiled_groups) = (lab_groups(&routed.0), lab_groups(&compiled));
        let entry = json!({
            "n": step["n"], "query": step["query"], "rollup_s": rollup_s, "compiled_s": compiled_s,
            "groups": routed_groups.len(), "overlap_scans": routed.1,
            "events": routed_groups.values().sum::<u64>(),
            "identical": routed_groups == compiled_groups,
        });
        eprintln!("{entry}");
        if routed_groups != compiled_groups {
            eprintln!("  routed   {routed_groups:?}\n  compiled {compiled_groups:?}");
        }
        out.push(entry);
    }
    let _ = std::fs::remove_dir_all(&cache_dir);
    Ok(json!({"steps": out}))
}

async fn session(work: &Path, steps_path: &Path) -> Result<Value> {
    let cache_dir = work.join(format!("cache-session-{}", std::process::id()));
    let lab = open_lab(work, &cache_dir, false).await?;
    let profile_runtime = std::env::var_os("NAN2869_PROFILE").map(|_| runtime()).transpose()?;
    let profile_connection = profile_runtime.as_ref()
        .map(|runtime| runtime.connect(&["--memory_worker_use_cgroup=0", "--memory_worker_dynamic_hard_limit=0"]))
        .transpose()?;
    let steps: Value = serde_json::from_slice(&std::fs::read(steps_path)?)?;
    let cpu_start = cpu_seconds();
    let started = Instant::now();
    let mut out = Vec::new();
    for step in steps.as_array().context("session steps")? {
        // NAN-3152: NAN3152_EVICT=1 drops the work dir's pages before every
        // step (a hot window larger than the page cache the cell can keep).
        if std::env::var_os("NAN3152_EVICT").is_some() {
            evict_page_cache(work);
        }
        let before_events = profile_connection.as_ref().map(profile_events).transpose()?;
        let request = request(
            &format!("q6-{}", step["n"]),
            step["query"].as_str().unwrap_or_default(),
            step["start"].as_str().unwrap_or_default(),
            step["end"].as_str().unwrap_or_default(),
            step["limit"].as_u64().map_or(100, |limit| limit as usize),
            true,
        );
        let cpu_before = cpu_seconds();
        // Dashboard aggregations take the count route in production
        // (core search's lake_count_stats_plan → /v1/aggregate/count).
        let count_route = match step["name"].as_str().unwrap_or_default() {
            "structured:dashboard_breakdown" => Some(("__nano.dashboard_breakdown", None)),
            // The search service sends this high-cardinality top-N shape
            // through compiled nPL: a full count-cube merge exceeds its
            // group bound before it can apply `head 10`.
            "structured:dashboard_top_talkers" => None,
            "structured:dashboard_source_trend" => Some(("metadata.log_source", Some(3_600_000_000_i64))),
            // Any step may name its count route (core search's
            // lake_count_stats_plan shape): {"count_route": {"field": …, "span_us": …}}.
            _ => step["count_route"]["field"].as_str().map(|field| (field, step["count_route"]["span_us"].as_i64())),
        };
        let outcome = match count_route {
            Some((field, span)) => {
                let started = Instant::now();
                let count: CountAggregateRequest = serde_json::from_value(json!({
                    "request_id": "q6-count", "tenant_id": TENANT, "group_field": field, "bucket_span_us": span,
                    "count_alias": "count", "start": step["start"], "end": step["end"], "max_groups": 1_000_000,
                    "group_results": step["count_route"]["group_results"].as_bool().unwrap_or(true),
                }))?;
                let routed = nanosiem_lake_worker::enrichment_read::scope(
                    lab_authority(),
                    partials::count_aggregate(&lab.engine, &count),
                )
                .await
                .map(|envelope| {
                    let rows = envelope["result"]["rows"].as_array().cloned().unwrap_or_default();
                    (rows, false, started.elapsed().as_secs_f64(), json!({"route": "count_aggregate"}))
                })
                .map_err(|error| anyhow::anyhow!(error.to_string()));
                // Over the group bound the count route refuses and search
                // falls back to the scan path.
                match routed {
                    Ok(done) => Ok(done),
                    Err(error) => {
                        eprintln!("count route fallback for {}: {error}", step["name"]);
                        parts_rows(&lab, &request).await
                    },
                }
            }
            None => parts_rows(&lab, &request).await,
        };
        let cpu = cpu_seconds().zip(cpu_before).map(|(after, before)| after - before);
        let after_events = profile_connection.as_ref().map(profile_events).transpose()?;
        let events = before_events.zip(after_events).map(|(before, after)| {
            after.into_iter().filter_map(|(name, value)| {
                let delta = value.saturating_sub(before.get(&name).copied().unwrap_or(0));
                (delta > 0).then_some((name, delta))
            }).collect::<BTreeMap<_, _>>()
        });
        let entry = match outcome {
            Ok((rows, _, seconds, planner)) => {
                let canonical_rows = canonical_with(&rows, sort_arrays).join("\n");
                if let Some(dir) = std::env::var_os("NAN3152_ROWS_DIR") { let _ = std::fs::write(Path::new(&dir).join(format!("{}.jsonl", step["n"])), &canonical_rows); }
                let rows_sha256 = format!("{:x}", sha2::Sha256::digest(canonical_rows.as_bytes()));
                // NAN-3155: order matters for pages (cursor, infinite scroll).
                let ordered = rows.iter().map(|row| sort_arrays(row).to_string()).collect::<Vec<_>>().join("\n");
                let rows_ordered_sha256 = format!("{:x}", sha2::Sha256::digest(ordered.as_bytes()));
                json!({"n": step["n"], "name": step["name"], "s": seconds, "cpu_s": cpu,
                    "rows": rows.len(), "rows_sha256": rows_sha256, "rows_ordered_sha256": rows_ordered_sha256,
                    "planner": planner, "profile_events": events})
            },
            Err(error) => json!({"n": step["n"], "name": step["name"], "cpu_s": cpu, "error": error.to_string(), "profile_events": events}),
        };
        eprintln!("q6 {} {} {:?}", step["n"], step["name"], entry.get("s"));
        out.push(entry);
    }
    let total = started.elapsed().as_secs_f64();
    if std::env::var_os("NAN3152_KEEP_CACHE").is_none() { let _ = std::fs::remove_dir_all(&cache_dir); }
    Ok(json!({"total_s": total, "cpu_s": cpu_seconds().zip(cpu_start).map(|(a, b)| a - b), "steps": out, "memory": rss(),
              "cache_fetched_bytes": lab.engine.fetcher().cache().stats().fetched_bytes,
              "verified_in_place_bytes": lab.engine.fetcher().verified_in_place_bytes()}))
}

/// The run-10 k6 shape: `vus` analysts loop over the corpus for `seconds`
/// with 0.2 s think time, from a cold process.
async fn k6(work: &Path, corpus_path: &Path, vus: usize, seconds: u64) -> Result<Value> {
    let cache_dir = work.join(format!("cache-k6-{}", std::process::id()));
    let lab = Arc::new(open_lab(work, &cache_dir, false).await?);
    let queries = Arc::new(corpus(corpus_path)?);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));
    let peak = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let cpu_start = cpu_seconds();
    let sampler = {
        let peak = peak.clone();
        tokio::spawn(async move {
            loop {
                if let Some(rss) = rss()["RssAnon"].as_u64() {
                    peak.fetch_max(rss, std::sync::atomic::Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
    };
    let workers = (0..vus.max(1))
        .map(|vu| {
            let (lab, queries, results) = (lab.clone(), queries.clone(), results.clone());
            tokio::spawn(async move {
                let mut index = vu * 37;
                while Instant::now() < deadline {
                    let query = &queries[index % queries.len()];
                    index += 1;
                    let request = request("k6", query["query"].as_str().unwrap(), query["start"].as_str().unwrap(), query["end"].as_str().unwrap(), 200, true);
                    let started = Instant::now();
                    let outcome = parts_rows(&lab, &request).await;
                    results.lock().unwrap().push(json!({"n": query["n"], "tier": query["tier"], "window": query["window"],
                        "s": started.elapsed().as_secs_f64(), "error": outcome.err().map(|e| e.to_string())}));
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.await?;
    }
    sampler.abort();
    let results = results.lock().unwrap().clone();
    let pct = |filter: &dyn Fn(&Value) -> bool, p: f64| {
        let mut values = results.iter().filter(|r| filter(r)).filter_map(|r| r["s"].as_f64()).collect::<Vec<_>>();
        values.sort_by(|a, b| a.partial_cmp(b).unwrap());
        (values.len(), values.get(((values.len() as f64 - 1.0).max(0.0) * p).round() as usize).copied().unwrap_or(0.0))
    };
    let mut groups = serde_json::Map::new();
    for window in ["15m", "1h", "6h", "24h", "7d"] {
        let (n, p50) = pct(&|r: &Value| r["window"] == window, 0.5);
        let (_, p95) = pct(&|r: &Value| r["window"] == window, 0.95);
        groups.insert(window.to_string(), json!({"n": n, "p50_s": p50, "p95_s": p95}));
    }
    let mut by_query = serde_json::Map::new();
    for query in queries.iter() {
        let number = &query["n"];
        let (samples, median) = pct(&|r: &Value| r["n"] == *number, 0.5);
        let (_, tail) = pct(&|r: &Value| r["n"] == *number, 0.95);
        by_query.insert(number.as_i64().map_or_else(|| number.to_string(), |n| n.to_string()), json!({"n": samples, "p50_s": median, "p95_s": tail,
            "window": query["window"], "tier": query["tier"]}));
    }
    let (n, p50) = pct(&|_| true, 0.5);
    let (_, p95) = pct(&|_| true, 0.95);
    let (_, max) = pct(&|_| true, 1.0);
    let wall = seconds as f64;
    let cpu = cpu_seconds().zip(cpu_start).map(|(a, b)| a - b);
    let _ = std::fs::remove_dir_all(&cache_dir);
    let errors = results.iter().filter(|r| !r["error"].is_null()).count();
    let peak_anon = peak.load(std::sync::atomic::Ordering::Relaxed);
    let slowest = {
        let mut sorted = results.clone();
        sorted.sort_by(|a, b| b["s"].as_f64().partial_cmp(&a["s"].as_f64()).unwrap_or(std::cmp::Ordering::Equal));
        sorted.into_iter().take(10).collect::<Vec<_>>()
    };
    let cores = cpu.map(|c| c / wall);
    Ok(json!({"vus": vus, "seconds": seconds, "n": n, "errors": errors,
              "p50_s": p50, "p95_s": p95, "max_s": max, "by_window": groups, "by_query": by_query, "cpu_s": cpu, "cores": cores,
              "peak_anon_bytes": peak_anon, "memory_final": rss(), "slowest": slowest}))
}

/// The UI's default search: the newest rows page and the histogram companion
/// (`<base> | timechart span=… count() as count`, whose sum is the total), sent
/// concurrently as core search does. Steps: `[{"query","start","end"}]`.
async fn ui(work: &Path, steps_path: &Path) -> Result<Value> {
    let cache_dir = work.join(format!("cache-ui-{}", std::process::id()));
    let lab = Arc::new(open_lab(work, &cache_dir, false).await?);
    let steps: Value = serde_json::from_slice(&std::fs::read(steps_path)?)?;
    let mut out = Vec::new();
    let started = Instant::now();
    for (n, step) in steps.as_array().context("ui steps")?.iter().enumerate() {
        let (query, start, end) = (step["query"].as_str().unwrap_or_default(), step["start"].as_str().unwrap_or_default(), step["end"].as_str().unwrap_or_default());
        let seconds = (chrono::DateTime::parse_from_rfc3339(end)? - chrono::DateTime::parse_from_rfc3339(start)?).num_seconds();
        let span = match seconds {
            d if d <= 300 => "5s",
            d if d <= 900 => "10s",
            d if d <= 1_800 => "30s",
            d if d <= 7_200 => "1m",
            d if d <= 86_400 => "5m",
            d if d <= 172_800 => "10m",
            d if d <= 604_800 => "30m",
            _ => "1h",
        };
        let base = query.split('|').next().unwrap_or_default().trim().to_string();
        let rows_request = request(&format!("ui-{n}"), query, start, end, 100, true);
        let mut histogram_request = request(&format!("ui-{n}-hist"), &format!("{base} | timechart span={span} count() as count"), start, end, 100_000, false);
        histogram_request.limit = 100_000;
        let cpu_before = cpu_seconds();
        let step_started = Instant::now();
        let rows_lab = lab.clone();
        let rows_task = tokio::spawn(async move {
            let started = Instant::now();
            let result = parts_rows(&rows_lab, &rows_request).await;
            (result, started.elapsed().as_secs_f64())
        });
        let hist_lab = lab.clone();
        let hist_task = tokio::spawn(async move {
            let started = Instant::now();
            let result = parts_rows(&hist_lab, &histogram_request).await;
            (result, started.elapsed().as_secs_f64())
        });
        let (rows, rows_s) = rows_task.await?;
        let (hist, hist_s) = hist_task.await?;
        let wall = step_started.elapsed().as_secs_f64();
        let cpu = cpu_seconds().zip(cpu_before).map(|(after, before)| after - before);
        let (rows_n, rows_planner, rows_error) = match rows {
            Ok((rows, _, _, planner)) => (rows.len(), planner, Value::Null),
            Err(error) => (0, Value::Null, json!(error.to_string())),
        };
        let (total, buckets, hist_planner, hist_error) = match hist {
            Ok((rows, _, _, planner)) => (
                rows.iter().map(|row| row["count"].as_u64().or_else(|| row["count"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0)).sum::<u64>(),
                rows.len(),
                planner,
                Value::Null,
            ),
            Err(error) => (0, 0, Value::Null, json!(error.to_string())),
        };
        eprintln!("ui {n} {query}: rows {rows_n} in {rows_s:.3}s, histogram total {total} in {hist_s:.3}s, wall {wall:.3}s");
        out.push(json!({"n": n, "query": query, "start": start, "end": end, "rows": rows_n, "rows_s": rows_s,
            "total": total, "buckets": buckets, "histogram_s": hist_s, "wall_s": wall, "cpu_s": cpu,
            "rows_planner": rows_planner, "histogram_planner": hist_planner, "rows_error": rows_error, "histogram_error": hist_error}));
    }
    let _ = std::fs::remove_dir_all(&cache_dir);
    Ok(json!({"total_s": started.elapsed().as_secs_f64(), "steps": out, "memory": rss()}))
}

/// Real tenant data files (`<YYYYMMDDHH>-data-NNNNN.parquet`, each one
/// source family of a live H part, sorted by `(time, uid)`) become one L0 part
/// per file and one H merge per hour, with the v3 keyword index
/// (`NAN2869_NO_COUNTS=1`: v2, `NAN2869_V1_INDEX=1`: v1). The newest file's schema is the part
/// schema. The work dir can then run `session` / `ui` like a fixture.
fn import_real(src: &Path, work: &Path, hours: usize) -> Result<()> {
    nanosiem_lake_worker::parts::block_index::set_enabled(std::env::var_os("NAN2869_V1_INDEX").is_none());
    // v3 token counts unless NAN2869_NO_COUNTS=1 (then v2).
    nanosiem_lake_worker::parts::token_counts::set_enabled(std::env::var_os("NAN2869_NO_COUNTS").is_none());
    let mut files = std::fs::read_dir(src)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            let (stamp, rest) = name.split_once('-')?;
            rest.starts_with("data-").then_some(())?;
            let time = chrono::NaiveDateTime::parse_from_str(&format!("{stamp}0000"), "%Y%m%d%H%M%S").ok()?;
            Some(((time.and_utc().timestamp() / 3600) as i32, entry.path()))
        })
        .collect::<Vec<_>>();
    files.sort();
    let mut by_hour: BTreeMap<i32, Vec<PathBuf>> = BTreeMap::new();
    for (hour, path) in files {
        by_hour.entry(hour).or_default().push(path);
    }
    let keep = by_hour.keys().rev().take(hours).copied().collect::<BTreeSet<_>>();
    by_hour.retain(|hour, _| keep.contains(hour));
    let newest = by_hour.values().last().and_then(|paths| paths.first()).context("no data files")?;
    let schema = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(newest)?)?.schema().clone();
    let fingerprint = schema_fingerprint(&schema)?;
    let store = LocalObjectStore::new(work.join("store"))?;
    let signer = signer();
    let trusted = signer.trusted();
    let scratch = work.join("parts-work");
    std::fs::create_dir_all(&scratch)?;
    let odd_layout = std::env::var("NAN3156_ODD_HOUR_LAYOUT").ok();
    let even_layout = std::env::var("NANO_LAKE_COMPACTION_LAYOUT").ok();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        let mut log = PartLogWriter::open(&store, TENANT, 1, &schema, now_ms()).await?;
        for (hour, paths) in &by_hour {
            let started = Instant::now();
            let mut inputs = Vec::new();
            for path in paths {
                let sha = nanosiem_lake_worker::native::file_sha256(path)?;
                let bytes = std::fs::metadata(path)?.len();
                let key = format!("real/{}", path.file_name().unwrap().to_string_lossy());
                let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?.with_batch_size(65_536).build()?;
                let mut writer = PartWriter::create(
                    &scratch,
                    PartDraft {
                        tenant_id: TENANT.to_string(),
                        signer_key_id: SIGNER_KEY_ID.to_string(),
                        level: Level::L0,
                        event_hour: *hour,
                        schema: schema.clone(),
                        schema_fingerprint: fingerprint.clone(),
                        inputs: PartInputs::Sources {
                            edge_log: None,
                            sources: vec![SourceObject { key: key.clone(), version: sha.clone(), bytes, sha256: sha.clone(), rows: 0, edge_sha256: None }],
                        },
                        admission: Some(Admission { ocsf_version: "1.9.0".to_string(), admission_contract: ADMISSION_CONTRACT.to_string(), feed_pins: BTreeMap::new() }),
                        rows_in: 0,
                        duplicates_dropped: 0,
                        window: DedupWindow::Exact,
                        build: "nan2869-lab".to_string(),
                    },
                    PartialSource::FromRows,
                    now_ms(),
                    1_100_000,
                )?;
                for batch in reader {
                    writer.write(&nanosiem_lake_worker::part_ingest::schema::align(batch?, &schema)?)?;
                }
                let mut part = writer.finish()?;
                if let PartInputs::Sources { sources, .. } = &mut part.record.inputs {
                    sources[0].rows = part.record.rows;
                }
                part.record.dedup.rows_in = part.record.rows;
                let reference = publish_parts(&store, &signer, &trusted, std::slice::from_ref(&part)).await?.remove(0);
                log.append(
                    LogOp::Add { edge_log: None, parts: vec![reference.clone()], consumed: vec![SourceRef { key, version: sha.clone(), sha256: sha }] },
                    now_ms(),
                )
                .await?;
                inputs.push(MergeInput { part: reference, dir: part.dir.clone() });
            }
            // NAN-3156: NAN3156_ODD_HOUR_LAYOUT=rows:bytes merges odd hours with
            // that compaction layout (`none` = the default layout) and even
            // hours with the process's own, for a mixed-layout window.
            if let Some(odd) = &odd_layout {
                // Lab only: this import runs on a current-thread runtime and
                // nothing reads the environment concurrently.
                match if hour.rem_euclid(2) == 1 { Some(odd.as_str()) } else { even_layout.as_deref() } {
                    Some("none") | None => std::env::remove_var("NANO_LAKE_COMPACTION_LAYOUT"),
                    Some(layout) => std::env::set_var("NANO_LAKE_COMPACTION_LAYOUT", layout),
                }
            }
            let merged = merge_parts(&scratch, TENANT, Level::Hour, *hour, &inputs, schema.clone(), &fingerprint, SIGNER_KEY_ID, "nan2869-lab", now_ms())?;
            let output = publish_parts(&store, &signer, &trusted, std::slice::from_ref(&merged.finished)).await?.remove(0);
            log.append(LogOp::Merge { output, supersedes: inputs.iter().map(|input| input.part.part_id.clone()).collect() }, now_ms()).await?;
            for input in &inputs {
                let _ = std::fs::remove_dir_all(&input.dir);
            }
            let _ = std::fs::remove_dir_all(&merged.finished.dir);
            eprintln!("imported hour {hour}: {} files -> H in {:.1}s", paths.len(), started.elapsed().as_secs_f64());
        }
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
}

/// Repeated part-cache searches and advancing detection windows. Reports no events.
async fn fragment_bench(work: &Path, steps_path: &Path) -> Result<Value> {
    let lab = open_lab(work, &work.join("fragment-bench-cache"), false).await?;
    let steps: Value = serde_json::from_slice(&std::fs::read(steps_path)?)?;
    let mut results = Vec::new();
    for step in steps.as_array().context("steps array")? {
        let mut request = request("fragment-bench", step["query"].as_str().context("query")?,
            step["start"].as_str().context("start")?, step["end"].as_str().context("end")?, 100, true);
        request.use_cache = true;
        let mut previous = None;
        for temperature in ["cold", "warm"] {
            let answer = lab.engine.broad_npl(&request).await.map_err(|e| anyhow::anyhow!(e))?;
            let rows = answer["result"]["rows"].clone();
            if let Some(previous) = previous { anyhow::ensure!(previous == rows, "warm rows differ"); }
            previous = Some(rows);
            let rows_sha256 = format!("{:x}", sha2::Sha256::digest(canonical(answer["result"]["rows"].as_array().map_or(&[][..], Vec::as_slice)).join("\n").as_bytes()));
            results.push(json!({"name":step["name"],"temperature":temperature,"ms":answer["wall_seconds"].as_f64().unwrap_or(0.0)*1000.0,
                "rows":answer["result"]["result_rows"],"rows_sha256":rows_sha256,"storage_rows":answer["result"]["storage_rows"],"planner":answer["planner"]}));
        }
        request.use_cache = false;
        let reference = lab.engine.broad_npl(&request).await.map_err(|e| anyhow::anyhow!(e))?;
        anyhow::ensure!(previous == Some(reference["result"]["rows"].clone()), "cache-disabled rows differ");
        if step["cadence"].as_bool() == Some(true) {
            request.use_cache = true;
            for tick in 1..=5 {
                request.end = (chrono::DateTime::parse_from_rfc3339(step["end"].as_str().unwrap())? + chrono::Duration::seconds(tick * 5)).to_rfc3339();
                let answer = lab.engine.broad_npl(&request).await.map_err(|e| anyhow::anyhow!(e))?;
                request.use_cache = false;
                let reference = lab.engine.broad_npl(&request).await.map_err(|e| anyhow::anyhow!(e))?;
                anyhow::ensure!(answer["result"]["rows"] == reference["result"]["rows"], "cadence rows differ");
                request.use_cache = true;
                results.push(json!({"name":step["name"],"temperature":"cadence","tick":tick,
                    "ms":answer["wall_seconds"].as_f64().unwrap_or(0.0)*1000.0,"planner":answer["planner"]}));
            }
        }
    }
    Ok(json!({"passed":true,"runs":results,"note":"local immutable signed replay; first-observed cold; OS cache retained; no production p95 claim"}))
}

pub(crate) fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let args = std::env::args().collect::<Vec<_>>();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build()?;
    match args.get(1).map(String::as_str) {
        Some("generate-local") => {
            let result = local_search_bench::generate(Path::new(args.get(2).context("dataset directory")?), args.get(3).map_or(Ok(24), |v| v.parse())?, args.get(4).map_or(Ok(300), |v| v.parse())?);
            let code = match result { Ok(()) => 0, Err(error) => { eprintln!("dataset generation failed: {error:#}"); 1 } };
            // chDB static destructors are not exit-safe.
            unsafe { libc::_exit(code) }
        }
        Some("search-local") => {
            let result = rt.block_on(local_search_bench::run(Path::new(args.get(2).context("dataset directory")?)));
            use std::io::Write;
            let code = match result {
                Ok(report) => {
                    let ok = report["passed"].as_bool() == Some(true);
                    println!("{}", serde_json::to_string_pretty(&report)?);
                    std::io::stdout().flush()?;
                    if ok { 0 } else { 1 }
                }
                Err(error) => {
                    eprintln!("local bench failed: {error:#}");
                    println!("{}", json!({"passed": false, "failures": [format!("{error:#}")], "queries": []}));
                    std::io::stdout().flush()?;
                    1
                }
            };
            // chDB static destructors are not exit-safe.
            unsafe { libc::_exit(code) }
        }
        Some("prepare") => prepare(Path::new(&args[2]), Path::new(&args[3]), args.get(4).map_or(Ok(24), |h| h.parse())?),
        Some("recluster-week") => recluster_week(Path::new(&args[2]), Path::new(&args[3])),
        Some("sql") => {
            // Ad-hoc chDB SQL (lab analysis): `sql <query>`; output JSONEachRow.
            let runtime = runtime()?;
            let connection = runtime.connect(&["--memory_worker_use_cgroup=0", "--memory_worker_dynamic_hard_limit=0"])?;
            let started = Instant::now();
            let output = connection.query_with_params(&args[2], "JSONEachRow", &[])?;
            use std::io::Write;
            std::io::stdout().write_all(&output.data)?;
            std::io::stdout().flush()?;
            eprintln!("sql: {:.3}s", started.elapsed().as_secs_f64());
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("replay") => {
            // NAN-3152: re-run one dumped statement (NAN3152_SQL_DUMP_DIR
            // format: SQL, then `-- name = value` parameter lines) and report
            // CPU, wall and chDB read counters.
            let text = std::fs::read_to_string(&args[2])?;
            let (sql, rest) = text.split_once("\n-- params\n").context("dump format")?;
            let sql = std::env::var("NAN3152_REPLACE").ok().and_then(|pair| {
                let (from, to) = pair.split_once("=>")?;
                Some(sql.replace(from, to))
            }).unwrap_or_else(|| sql.to_string());
            let params = rest.lines().filter_map(|line| line.strip_prefix("-- ")?.split_once(" = "))
                .map(|(name, value)| (name.to_string(), value.to_string())).collect::<Vec<_>>();
            let borrowed = params.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect::<Vec<_>>();
            let runtime = runtime()?;
            let connection = runtime.connect(&["--memory_worker_use_cgroup=0", "--memory_worker_dynamic_hard_limit=0"])?;
            let before = profile_events(&connection)?;
            let (cpu, started) = (cpu_seconds(), Instant::now());
            let output = connection.query_with_params(&sql, "JSONEachRow", &borrowed)?;
            let wall = started.elapsed().as_secs_f64();
            let cpu = cpu_seconds().zip(cpu).map(|(a, b)| a - b);
            let after = profile_events(&connection)?;
            let events = after.into_iter().filter_map(|(name, value)| {
                let delta = value.saturating_sub(before.get(&name).copied().unwrap_or(0));
                (delta > 0 && ["Read", "Parquet", "Selected", "Rows", "Bytes", "Decompress", "UserTime", "SystemTime", "OSCPU", "RealTime", "FileOpen"]
                    .iter().any(|key| name.contains(key))).then_some((name, delta))
            }).collect::<BTreeMap<_, _>>();
            let rows = output.data.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count();
            let sha = format!("{:x}", sha2::Sha256::digest(&output.data));
            println!("{}", json!({"wall_s": wall, "cpu_s": cpu, "rows": rows, "sha256": sha,
                "storage_rows": output.storage_rows_read, "storage_bytes": output.storage_bytes_read, "events": events}));
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("ui") => {
            let report = rt.block_on(ui(Path::new(&args[2]), Path::new(&args[3])))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("import-real") => {
            import_real(Path::new(&args[2]), Path::new(&args[3]), args.get(4).map_or(Ok(24), |h| h.parse())?)?;
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("fragment-bench") => {
            let report = rt.block_on(fragment_bench(Path::new(&args[2]), Path::new(&args[3])))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            unsafe { libc::_exit(0) }
        }
        Some("rollup-routing") => {
            let report = rt.block_on(rollup_routing(Path::new(&args[2]), Path::new(&args[3])))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("session") => {
            let report = rt.block_on(session(Path::new(&args[2]), Path::new(&args[3])))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("k6") => {
            let vus = args.get(4).map_or(Ok(2), |v| v.parse())?;
            let seconds = args.get(5).map_or(Ok(600), |v| v.parse())?;
            let report = rt.block_on(k6(Path::new(&args[2]), Path::new(&args[3]), vus, seconds))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("append-hours") => {
            append_hours(Path::new(&args[2]), Path::new(&args[3]), args.get(4).map_or(Ok(4), |t| t.parse())?)?;
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("parity") => {
            let rules = args[4..].iter().map(PathBuf::from).collect::<Vec<_>>();
            let report = rt.block_on(parity(Path::new(&args[2]), Path::new(&args[3]), &rules))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // chDB's static destructors are not exit-safe; the reader and
            // tests never unload it either.
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("corr-parity") => {
            match rt.block_on(corr_parity(Path::new(&args[2]), Path::new(&args[3]))) {
                Ok(report) => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                    use std::io::Write;
                    std::io::stdout().flush()?;
                }
                Err(error) => {
                    eprintln!("correlation parity failed: {error:#}");
                    // SAFETY: chDB's static destructors are not exit-safe.
                    unsafe { libc::_exit(1) }
                }
            }
            // SAFETY: chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("coldstart") => {
            let report = rt.block_on(coldstart(Path::new(&args[2])))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("prewarm") => {
            // The background owner-proof/SHA prewarm a cell's query[T] runs on
            // part arrival (NAN2869_STATE_DIR persists what it proves).
            let hours = std::env::var("NAN2869_PREWARM_HOURS").ok()
                .and_then(|value| value.parse::<u64>().ok()).unwrap_or(24).clamp(1, 336);
            let report = rt.block_on(async {
                let cache_dir = Path::new(&args[2]).join(format!("cache-prewarm-{}", std::process::id()));
                let lab = open_lab(Path::new(&args[2]), &cache_dir, false).await?;
                let (cpu, started) = (cpu_seconds(), Instant::now());
                nanosiem_lake_worker::enrichment_read::scope(lab_authority(), lab.engine.prewarm_owner_proofs(hours)).await?;
                let _ = std::fs::remove_dir_all(&cache_dir);
                Ok::<_, anyhow::Error>(json!({"hours": hours, "wall_s": started.elapsed().as_secs_f64(), "cpu_s": cpu_seconds().zip(cpu).map(|(a, b)| a - b),
                    "verified_in_place_bytes": lab.engine.fetcher().verified_in_place_bytes(), "memory": rss()}))
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("bench") => {
            let concurrency = args.get(4).map_or(Ok(1), |c| c.parse())?;
            let rules = args.iter().skip(5).map(PathBuf::from).collect::<Vec<_>>();
            let report = rt.block_on(bench(Path::new(&args[2]), Path::new(&args[3]), concurrency, &rules))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // SAFETY: skip atexit handlers; chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        Some("fixture-ab") => {
            let report = rt.block_on(fixture_ab(Path::new(&args[2]), Path::new(&args[3]), Path::new(&args[4])))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // SAFETY: chDB's static destructors are not exit-safe.
            unsafe { libc::_exit(0) }
        }
        _ => bail!("usage: lake_part_query_lab prepare|parity|bench …"),
    }
}
