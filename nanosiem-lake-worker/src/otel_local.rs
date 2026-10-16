// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable, single-tenant OTLP storage for open-core lean. The existing
//! telemetry query planners read these native Parquet files. This directory
//! is a persistent volume, not the hosted drain's disposable mirror cache.

use crate::otel_handoff::{
    drain_batch_sha256, encode_staged_otel_objects, mirror_objects, OtelHandoffDrain,
};
use crate::otel_iceberg::{dedupe_otel_batch, OtelDataset, OtelLakeRow, OtelPublishResult};
use anyhow::{ensure, Context, Result};
use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub struct LocalOtelStore {
    tenant: Uuid,
    root: PathBuf,
    max_bytes: u64,
    serial: std::sync::Mutex<WriterState>,
    /// Released with an explicit LOCK_UN on drop (NAN-3866): a close-only
    /// release leaves the flock alive in any child another thread forked
    /// while the store was open, until that child's exec, so an immediate
    /// reopen saw a phantom "another local OTLP publisher".
    _writer_lock: nanosiem_core::flock_guard::FlockGuard,
}

/// Everything the single writer owns, behind one mutex.
struct WriterState {
    /// Running `durable_bytes(root)` total. Seeded by one walk at open and
    /// adjusted by every write/delete under the tree. `None` after a failed
    /// mutation (a partial write or stray temp file): the next holder re-walks
    /// once instead of trusting a drifted sum.
    used: Option<u64>,
    /// In-window batch receipts per dataset: digest -> commit day.
    receipts: [HashMap<[u8; 32], i64>; 2],
}

/// Receipts deduplicate Vector HTTP-sink retries of a whole batch: a retry
/// re-sends the identical NDJSON body, so it has the same batch digest. The
/// sink (`config/vector/04-otlp-lake-sink.toml`) retries without an attempt
/// limit, at most `retry_max_duration_secs` (300 s) apart with a 120 s request
/// timeout, so a retry of a batch whose acknowledgement was lost arrives within
/// ~7 minutes of this endpoint being reachable again. Dedupe only has to
/// outlast that; seven days also covers a week-long endpoint outage after such
/// a commit. Receipts live in whole commit days, so one survives 7-8 days.
const RECEIPT_RETRY_WINDOW_SECS: i64 = 7 * 86_400;
/// One receipt record: the hex batch digest and a newline.
const RECEIPT_LINE_BYTES: u64 = 65;

fn dataset_slot(dataset: OtelDataset) -> usize {
    match dataset {
        OtelDataset::Spans => 0,
        OtelDataset::Metrics => 1,
    }
}

fn receipt_key(digest: &str) -> Option<[u8; 32]> {
    let mut key = [0_u8; 32];
    (digest.len() == 64 && hex::decode_to_slice(digest, &mut key).is_ok()).then_some(key)
}

/// The `durable_bytes` charge of one path: length plus the per-file estimate.
fn file_cost(path: &Path) -> Result<u64> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.len().saturating_add(4096)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn adjust(used: &mut u64, before: u64, after: u64) {
    *used = used.saturating_sub(before).saturating_add(after);
}

fn durable_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("local OTLP file has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    let mut file = std::fs::File::create_new(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Append records and fsync them (and a new file's directory entries) before
/// returning, so an acknowledged batch's receipt is always durable.
fn append_lines(path: &Path, lines: &str) -> Result<()> {
    let parent = path.parent().context("local OTLP file has no parent")?;
    std::fs::create_dir_all(parent)?;
    let created = !path.try_exists()?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let start = file.metadata()?.len();
    if let Err(error) = file
        .write_all(lines.as_bytes())
        .and_then(|()| file.sync_data())
    {
        // Never leave a torn record for the next append to extend.
        let _ = file.set_len(start);
        return Err(error.into());
    }
    if created {
        std::fs::File::open(parent)?.sync_all()?;
        std::fs::File::open(parent.parent().context("index has no root")?)?.sync_all()?;
    }
    Ok(())
}

// Include receipts/journals and a conservative per-file allocation estimate.
// Never evict acknowledged records to make space for metadata.
fn durable_bytes(root: &Path) -> Result<u64> {
    let mut used = 0_u64;
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        ensure!(
            !entry.file_type()?.is_symlink(),
            "local OTLP volume refuses symlinks"
        );
        used = used.saturating_add(if metadata.is_dir() {
            durable_bytes(&entry.path())?
        } else {
            metadata.len().saturating_add(4096)
        });
    }
    Ok(used)
}

fn receipt_dir(root: &Path, dataset: OtelDataset) -> PathBuf {
    root.join(".received-index").join(dataset.as_str())
}

fn receipt_day_file(root: &Path, dataset: OtelDataset, day: i64) -> PathBuf {
    receipt_dir(root, dataset).join(format!("{day}.log"))
}

/// Commit days that have a receipt file, in order.
fn receipt_days(root: &Path, dataset: OtelDataset) -> Result<Vec<i64>> {
    let mut days = Vec::new();
    let Ok(entries) = std::fs::read_dir(receipt_dir(root, dataset)) else {
        return Ok(days);
    };
    for entry in entries {
        if let Some(day) = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.strip_suffix(".log"))
            .and_then(|day| day.parse::<i64>().ok())
        {
            days.push(day);
        }
    }
    days.sort_unstable();
    Ok(days)
}

/// Fold the previous one-file-per-receipt layout (`.received/<dataset>/
/// <digest>.json`) into day files keyed by each receipt's mtime, then remove
/// it. Idempotent: a crash before the removal only re-appends duplicates.
fn migrate_file_receipts(root: &Path) -> Result<()> {
    let legacy = root.join(".received");
    if !legacy.try_exists()? {
        return Ok(());
    }
    for dataset in [OtelDataset::Spans, OtelDataset::Metrics] {
        let Ok(entries) = std::fs::read_dir(legacy.join(dataset.as_str())) else {
            continue;
        };
        let mut by_day = std::collections::BTreeMap::<i64, String>::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(digest) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
                .filter(|digest| receipt_key(digest).is_some())
            else {
                continue;
            };
            let modified = entry
                .metadata()?
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |age| age.as_secs());
            let day = i64::try_from(modified)?.div_euclid(86_400);
            by_day
                .entry(day)
                .or_default()
                .push_str(&format!("{digest}\n"));
        }
        for (day, lines) in by_day {
            append_lines(&receipt_day_file(root, dataset, day), &lines)?;
        }
    }
    std::fs::remove_dir_all(&legacy)?;
    std::fs::File::open(root)?.sync_all()?;
    Ok(())
}

/// Load every receipt day file. A torn trailing record (a crash mid-append,
/// never acknowledged) is truncated away so the next append starts clean.
fn load_receipts(root: &Path) -> Result<[HashMap<[u8; 32], i64>; 2]> {
    let mut receipts = [HashMap::new(), HashMap::new()];
    for dataset in [OtelDataset::Spans, OtelDataset::Metrics] {
        for day in receipt_days(root, dataset)? {
            let path = receipt_day_file(root, dataset, day);
            let bytes = std::fs::read(&path)?;
            let complete = bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |end| end + 1);
            if complete < bytes.len() {
                let file = std::fs::OpenOptions::new().write(true).open(&path)?;
                file.set_len(complete as u64)?;
                file.sync_all()?;
            }
            for line in String::from_utf8_lossy(&bytes[..complete]).lines() {
                if let Some(key) = receipt_key(line) {
                    receipts[dataset_slot(dataset)].insert(key, day);
                }
            }
        }
    }
    Ok(receipts)
}

impl LocalOtelStore {
    pub fn open(tenant: Uuid, root: PathBuf, max_bytes: u64) -> Result<Self> {
        use std::os::fd::AsRawFd;
        ensure!(
            !tenant.is_nil() && root.is_absolute() && max_bytes > 0,
            "invalid local OTLP store"
        );
        std::fs::create_dir_all(&root)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(root.join(".writer.lock"))?;
        // SAFETY: advisory lock on this process's owned descriptor.
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another local OTLP publisher owns this volume"
        );
        // From here every exit, including a failed open, unlocks explicitly.
        let lock = nanosiem_core::flock_guard::FlockGuard::adopt(lock);
        let identity = root.join(".tenant");
        if identity.try_exists()? {
            ensure!(
                std::fs::read_to_string(&identity)? == tenant.to_string(),
                "local OTLP volume belongs to another tenant"
            );
        } else {
            durable_write(&identity, tenant.to_string().as_bytes())?;
        }
        for dataset in [OtelDataset::Spans, OtelDataset::Metrics] {
            crate::otel_lean::recover_compaction_durable(&root, dataset)?;
            std::fs::create_dir_all(root.join(dataset.as_str()))?;
        }
        migrate_file_receipts(&root)?;
        let receipts = load_receipts(&root)?;
        // The only full-tree walk: later publishes use the running counter.
        let used = durable_bytes(&root)?;
        let store = Self {
            tenant,
            root,
            max_bytes,
            serial: std::sync::Mutex::new(WriterState {
                used: Some(used),
                receipts,
            }),
            _writer_lock: lock,
        };
        store.recover_pending()?;
        Ok(store)
    }

    fn recover_pending(&self) -> Result<()> {
        let directory = self.root.join(".pending");
        if !directory.try_exists()? {
            return Ok(());
        }
        for entry in std::fs::read_dir(&directory)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            ensure!(
                std::fs::metadata(&path)?.len() <= 128 * 1024 * 1024,
                "local OTLP recovery journal exceeds cap"
            );
            let rows: Vec<OtelLakeRow> = serde_json::from_slice(&std::fs::read(&path)?)?;
            let dataset = rows.first().context("empty OTLP recovery journal")?.dataset;
            ensure!(
                path.file_name().and_then(|name| name.to_str())
                    == Some(
                        format!("{}-{}.json", dataset.as_str(), drain_batch_sha256(&rows)).as_str()
                    ),
                "OTLP recovery identity differs"
            );
            self.publish(dataset, &rows)?;
        }
        Ok(())
    }

    /// Run `mutate` under the writer lock with the running byte total and the
    /// receipt set. The total is committed back only on success; on error it
    /// is dropped and the next holder re-seeds it with one tree walk.
    fn with_used<T>(
        &self,
        mutate: impl FnOnce(&mut u64, &mut [HashMap<[u8; 32], i64>; 2]) -> Result<T>,
    ) -> Result<T> {
        let mut state = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("local OTLP writer lock poisoned"))?;
        let mut used = match state.used.take() {
            Some(used) => used,
            None => durable_bytes(&self.root)?,
        };
        let result = mutate(&mut used, &mut state.receipts)?;
        state.used = Some(used);
        Ok(result)
    }

    #[cfg(test)]
    fn tracked_bytes(&self) -> u64 {
        self.serial.lock().unwrap().used.expect("counter seeded")
    }

    #[cfg(test)]
    fn receipt_count(&self) -> usize {
        self.serial
            .lock()
            .unwrap()
            .receipts
            .iter()
            .map(HashMap::len)
            .sum()
    }

    pub fn publish(&self, dataset: OtelDataset, rows: &[OtelLakeRow]) -> Result<OtelPublishResult> {
        self.with_used(|used, receipts| {
            self.publish_locked(used, &mut receipts[dataset_slot(dataset)], dataset, rows)
        })
    }

    fn publish_locked(
        &self,
        used: &mut u64,
        receipts: &mut HashMap<[u8; 32], i64>,
        dataset: OtelDataset,
        rows: &[OtelLakeRow],
    ) -> Result<OtelPublishResult> {
        ensure!(
            rows.iter().all(|row| row.dataset == dataset
                && row
                    .row
                    .get("tenant_uid")
                    .and_then(serde_json::Value::as_str)
                    == Some(self.tenant.to_string().as_str())),
            "local OTLP batch names another tenant or dataset"
        );
        let (rows, _) = dedupe_otel_batch(rows);
        let digest = drain_batch_sha256(&rows);
        if rows.is_empty() {
            return Ok(OtelPublishResult {
                status: "committed",
                dataset,
                batch_sha256: digest,
                snapshot_id: 0,
                rows: 0,
                metadata_location: self.root.display().to_string(),
            });
        }
        let key = receipt_key(&digest).context("OTLP batch digest is not SHA-256 hex")?;
        let files = encode_staged_otel_objects(dataset, self.tenant, &rows, &digest)?;
        let journal = self
            .root
            .join(".pending")
            .join(format!("{}-{digest}.json", dataset.as_str()));
        if !receipts.contains_key(&key) {
            let incoming = files
                .iter()
                .filter(|file| {
                    !OtelHandoffDrain::mirror_path(
                        &self.root,
                        dataset,
                        file.event_hour,
                        &file.sha256,
                    )
                    .exists()
                })
                .map(|file| (file.bytes.len() as u64).saturating_add(4096))
                .sum::<u64>();
            let journal_bytes = serde_json::to_vec(&rows)?;
            ensure!(
                journal_bytes.len() <= 128 * 1024 * 1024,
                "local OTLP recovery journal exceeds cap"
            );
            let recovery_bytes = if journal.try_exists()? {
                0
            } else {
                journal_bytes.len() as u64 + 4096
            };
            let day = chrono::Utc::now().timestamp().div_euclid(86_400);
            let day_file = receipt_day_file(&self.root, dataset, day);
            let receipt_bytes = RECEIPT_LINE_BYTES + if day_file.try_exists()? { 0 } else { 4096 };
            // A full volume applies backpressure to Vector's durable buffer;
            // acknowledged telemetry is never evicted to satisfy the cap.
            ensure!(
                used.saturating_add(incoming)
                    .saturating_add(recovery_bytes)
                    .saturating_add(receipt_bytes)
                    <= self.max_bytes,
                "local OTLP durable volume is full"
            );
            // A durable redo journal completes a partially published batch
            // before compaction or retention can change its content identities.
            let before = file_cost(&journal)?;
            durable_write(&journal, &journal_bytes)?;
            adjust(used, before, file_cost(&journal)?);
            std::fs::File::open(&self.root)?.sync_all()?;
            for file in files {
                let path = OtelHandoffDrain::mirror_path(
                    &self.root,
                    dataset,
                    file.event_hour,
                    &file.sha256,
                );
                let before = file_cost(&path)?;
                durable_write(&path, &file.bytes)?;
                adjust(used, before, file_cost(&path)?);
                // Persist directory creation as well as the file rename.
                std::fs::File::open(self.root.join(dataset.as_str()))?.sync_all()?;
            }
            // The receipt is fsynced before this batch is acknowledged; a crash
            // before that replays the journal, which writes it then.
            let before = file_cost(&day_file)?;
            append_lines(&day_file, &format!("{digest}\n"))?;
            adjust(used, before, file_cost(&day_file)?);
            receipts.insert(key, day);
        }
        if journal.try_exists()? {
            let before = file_cost(&journal)?;
            std::fs::remove_file(&journal)?;
            adjust(used, before, 0);
            std::fs::File::open(journal.parent().unwrap())?.sync_all()?;
        }
        Ok(OtelPublishResult {
            status: "committed",
            dataset,
            batch_sha256: digest,
            snapshot_id: 0,
            rows: rows.len(),
            metadata_location: self.root.display().to_string(),
        })
    }

    /// Run with the same settings as log retention, floored at
    /// [`crate::otel_lean::OTEL_MIN_RETENTION_DAYS`] (NAN-3894: the longest
    /// SLO window stays inside retention). A disabled policy never expires
    /// telemetry. Bad/unreadable settings fail before deletion.
    pub fn maintain(
        &self,
        retention_days: Option<u32>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        self.recover_pending()?;
        ensure!(
            retention_days.is_none_or(|days| (1..=3650).contains(&days)),
            "invalid local OTLP retention"
        );
        let current_hour = i32::try_from(now.timestamp().div_euclid(3600))?;
        self.with_used(|used, receipts| {
            for dataset in [OtelDataset::Spans, OtelDataset::Metrics] {
                // Compaction rewrites a bounded set of hour directories; charge
                // the dataset's part tree before/after.
                let parts = self.root.join(dataset.as_str());
                let before = durable_bytes(&parts)?;
                crate::otel_lean::compact_mirror_durable(&self.root, dataset, current_hour)?;
                if let Some(days) = retention_days.map(crate::otel_lean::otel_retention_days) {
                    let cutoff = now
                        .timestamp()
                        .saturating_sub(i64::from(days) * 86_400)
                        .div_euclid(3600);
                    for (hour, path, _) in mirror_objects(&self.root, dataset)? {
                        // Expire only complete event hours, never a boundary hour.
                        if i64::from(hour) + 1 <= cutoff {
                            std::fs::remove_file(path)?;
                        }
                    }
                }
                std::fs::File::open(&parts)?.sync_all()?;
                adjust(used, before, durable_bytes(&parts)?);
                // Receipts expire by whole commit day once the day ends more
                // than the retry window ago. Drop the set entries first: a
                // crash after that only leaves a file the next pass deletes.
                let cutoff = now.timestamp().saturating_sub(RECEIPT_RETRY_WINDOW_SECS);
                let expired: Vec<i64> = receipt_days(&self.root, dataset)?
                    .into_iter()
                    .filter(|day| (day + 1) * 86_400 <= cutoff)
                    .collect();
                if let Some(newest) = expired.last() {
                    receipts[dataset_slot(dataset)].retain(|_, day| *day > *newest);
                    for day in &expired {
                        let path = receipt_day_file(&self.root, dataset, *day);
                        let before = file_cost(&path)?;
                        std::fs::remove_file(&path)?;
                        adjust(used, before, 0);
                    }
                    std::fs::File::open(receipt_dir(&self.root, dataset))?.sync_all()?;
                }
            }
            std::fs::File::open(&self.root)?.sync_all()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otel_iceberg::normalize_otel_row;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    fn row(tenant: Uuid, span: &str) -> OtelLakeRow {
        normalize_otel_row(
            OtelDataset::Spans,
            &tenant.to_string(),
            &serde_json::json!({
                "traceId":"0123456789abcdef0123456789abcdef", "spanId":span,
                "name":"local-test", "startTimeUnixNano":"1788220800000000000", "endTimeUnixNano":"1788220800000000010",
                "resource":{"attributes":[{"key":"service.name","value":{"stringValue":"local-test"}}]}
            }),
        )
        .unwrap()
    }

    fn count(root: &Path) -> usize {
        mirror_objects(root, OtelDataset::Spans)
            .unwrap()
            .iter()
            .map(|(_, path, _)| {
                ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path).unwrap())
                    .unwrap()
                    .build()
                    .unwrap()
                    .map(|batch| batch.unwrap().num_rows())
                    .sum::<usize>()
            })
            .sum()
    }

    #[tokio::test]
    #[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
    async fn native_trusted_local_volume_serves_trace_service_and_metric_ui_plans_after_restart() {
        use crate::otel_iceberg::{
            plan_metric_names, plan_recent_traces, plan_services_overview, OtelQuerySource,
            OtelServicesSort,
        };
        use crate::planner::{ObjectStoreCredentials, TenantQueryConfig};
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let metric = normalize_otel_row(OtelDataset::Metrics, &tenant.to_string(), &serde_json::json!({
            "name":"system.cpu.utilization", "type":"gauge", "timeUnixNano":"1788220800000000000", "value":0.25,
            "resource":{"attributes":[{"key":"service.name","value":{"stringValue":"local-test"}}]}
        })).unwrap();
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        store
            .publish(OtelDataset::Spans, &[row(tenant, "0123456789abcdef")])
            .unwrap();
        store.publish(OtelDataset::Metrics, &[metric]).unwrap();
        drop(store);
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        store.maintain(None, chrono::Utc::now()).unwrap();
        let runtime = crate::native::NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        )
        .unwrap();
        std::mem::forget(runtime.clone());
        let executor = crate::executor::NativeExecutor::start(runtime, 1).unwrap();
        let source = |dataset| {
            OtelQuerySource::from(TenantQueryConfig {
                tenant_id: tenant.to_string(),
                source: crate::otel_lean::lean_dataset_location(tenant, dataset),
                iceberg_metadata_file_path: "hosted-staged-hot-tail".into(),
                max_query_bytes: 1 << 30,
                max_memory_bytes: 1 << 30,
                max_execution_seconds: 60,
                threads: 1,
                credentials: ObjectStoreCredentials::DefaultChain,
                snapshot_cache: crate::otel_handoff::mirror_snapshot_cache(dir.path(), dataset)
                    .unwrap(),
            })
        };
        let start = chrono::DateTime::parse_from_rfc3339("2026-08-31T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let end = chrono::DateTime::parse_from_rfc3339("2026-09-02T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let spans = source(OtelDataset::Spans);
        let plans = [
            plan_recent_traces(
                &spans,
                &tenant.to_string(),
                start,
                end,
                None,
                false,
                None,
                None,
                50,
            )
            .unwrap(),
            plan_services_overview(
                &spans,
                &tenant.to_string(),
                start,
                end,
                None,
                OtelServicesSort::Name,
            )
            .unwrap(),
            plan_metric_names(&source(OtelDataset::Metrics), &tenant.to_string(), None).unwrap(),
        ];
        for plan in plans {
            let result = executor.execute_sql(plan.sql, plan.params).await.unwrap();
            let rows: Vec<_> = result
                .data
                .split(|byte| *byte == b'\n')
                .filter(|row| !row.is_empty())
                .collect();
            assert_eq!(rows.len(), 1, "{}", String::from_utf8_lossy(&result.data));
        }
    }

    #[test]
    fn native_metric_histograms_are_persisted_and_retained_with_spans() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let metric = normalize_otel_row(OtelDataset::Metrics, &tenant.to_string(), &serde_json::json!({
            "name":"http.server.duration", "type":"histogram", "unit":"ms", "timeUnixNano":"1788220800000000000",
            "count":3, "sum":42.0, "bucketCounts":[1,1,1], "explicitBounds":[10.0,50.0], "aggregationTemporality":2,
            "attributes":[], "resource":{"attributes":[{"key":"service.name","value":{"stringValue":"local-test"}}]}
        })).unwrap();
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        store
            .publish(OtelDataset::Metrics, std::slice::from_ref(&metric))
            .unwrap();
        let files = mirror_objects(dir.path(), OtelDataset::Metrics).unwrap();
        assert_eq!(files.len(), 1);
        let batch =
            ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&files[0].1).unwrap())
                .unwrap()
                .build()
                .unwrap()
                .next()
                .unwrap()
                .unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert!(batch.schema().index_of("bucket_counts").is_ok());
        store.maintain(Some(1), chrono::Utc::now()).unwrap();
        assert!(mirror_objects(dir.path(), OtelDataset::Metrics)
            .unwrap()
            .is_empty());
        store.publish(OtelDataset::Metrics, &[metric]).unwrap();
        assert!(mirror_objects(dir.path(), OtelDataset::Metrics)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn pending_batch_is_recovered_before_compaction_and_query() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let rows = vec![row(tenant, "0123456789abcdef")];
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        let digest = drain_batch_sha256(&rows);
        durable_write(
            &dir.path()
                .join(".pending")
                .join(format!("spans-{digest}.json")),
            &serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
        drop(store);
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        store.maintain(None, chrono::Utc::now()).unwrap();
        store.publish(OtelDataset::Spans, &rows).unwrap();
        assert_eq!(count(dir.path()), 1);
        drop(store);
        assert!(LocalOtelStore::open(Uuid::new_v4(), dir.path().into(), 1024 * 1024).is_err());
    }

    #[test]
    fn retries_after_compaction_and_restart_do_not_duplicate_telemetry() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let rows = vec![row(tenant, "0123456789abcdef")];
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        store.publish(OtelDataset::Spans, &rows).unwrap();
        store
            .publish(OtelDataset::Spans, &[row(tenant, "fedcba9876543210")])
            .unwrap();
        store.maintain(None, chrono::Utc::now()).unwrap();
        assert_eq!(count(dir.path()), 2);
        store.publish(OtelDataset::Spans, &rows).unwrap();
        assert_eq!(count(dir.path()), 2);
        drop(store);
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        store.publish(OtelDataset::Spans, &rows).unwrap();
        assert_eq!(count(dir.path()), 2);
        store.maintain(Some(1), chrono::Utc::now()).unwrap();
        assert_eq!(count(dir.path()), 0);
        store.publish(OtelDataset::Spans, &rows).unwrap();
        assert_eq!(count(dir.path()), 0);
    }

    /// NAN-3894: open core keeps OTLP for at least
    /// `OTEL_MIN_RETENTION_DAYS` even when log retention is shorter, so the
    /// longest SLO window stays inside retention.
    #[test]
    fn a_short_log_retention_keeps_otel_for_the_slo_floor() {
        use crate::otel_lean::{OTEL_MIN_RETENTION_DAYS, SLO_WINDOW_DAYS_MAX};
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        store.publish(OtelDataset::Spans, &[row(tenant, "0123456789abcdef")]).unwrap();
        // The row's event time (see `row`).
        let event = chrono::DateTime::from_timestamp(1_788_220_800, 0).unwrap();
        let at_slo_edge = event + chrono::Duration::days(i64::from(SLO_WINDOW_DAYS_MAX)) + chrono::Duration::hours(1);
        store.maintain(Some(1), at_slo_edge).unwrap();
        assert_eq!(count(dir.path()), 1, "a 1-day log retention must not expire SLO-window telemetry");
        store
            .maintain(Some(1), event + chrono::Duration::days(i64::from(OTEL_MIN_RETENTION_DAYS) + 2))
            .unwrap();
        assert_eq!(count(dir.path()), 0);
    }

    fn receipt_files(root: &Path) -> usize {
        std::fs::read_dir(receipt_dir(root, OtelDataset::Spans))
            .map(|entries| entries.count())
            .unwrap_or(0)
    }

    #[test]
    fn receipts_expire_after_retry_window_and_dedupe_holds_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let rows = vec![row(tenant, "0123456789abcdef")];
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        store.publish(OtelDataset::Spans, &rows).unwrap();
        store
            .publish(OtelDataset::Spans, &[row(tenant, "fedcba9876543210")])
            .unwrap();
        // Two receipts share one day file: tens of bytes each, not 4 KiB.
        assert_eq!(receipt_files(dir.path()), 1);
        let day = chrono::Utc::now().timestamp().div_euclid(86_400);
        assert_eq!(
            std::fs::metadata(receipt_day_file(dir.path(), OtelDataset::Spans, day))
                .unwrap()
                .len(),
            2 * RECEIPT_LINE_BYTES
        );
        store.maintain(None, chrono::Utc::now()).unwrap();
        assert_eq!(count(dir.path()), 2);
        // Inside the window: receipts survive and a retry after compaction is
        // still deduplicated.
        let now = chrono::Utc::now();
        store
            .maintain(None, now + chrono::Duration::days(6))
            .unwrap();
        assert_eq!(store.receipt_count(), 2);
        store.publish(OtelDataset::Spans, &rows).unwrap();
        assert_eq!(count(dir.path()), 2);
        // Retention does not extend the window.
        store
            .maintain(Some(3650), now + chrono::Duration::days(9))
            .unwrap();
        assert_eq!(store.receipt_count(), 0);
        assert_eq!(receipt_files(dir.path()), 0);
        assert_eq!(store.tracked_bytes(), durable_bytes(dir.path()).unwrap());
    }

    #[test]
    fn retry_after_restart_is_deduplicated_from_the_loaded_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let rows = vec![row(tenant, "0123456789abcdef")];
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        store.publish(OtelDataset::Spans, &rows).unwrap();
        store
            .publish(OtelDataset::Spans, &[row(tenant, "fedcba9876543210")])
            .unwrap();
        // Compaction changes the part identities, so only the receipt dedupes.
        store.maintain(None, chrono::Utc::now()).unwrap();
        drop(store);
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        assert_eq!(store.receipt_count(), 2);
        let bytes = durable_bytes(dir.path()).unwrap();
        store.publish(OtelDataset::Spans, &rows).unwrap();
        assert_eq!(count(dir.path()), 2);
        assert_eq!(durable_bytes(dir.path()).unwrap(), bytes);
    }

    #[test]
    fn interrupted_sweep_and_torn_tail_are_settled_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let rows = vec![row(tenant, "0123456789abcdef")];
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        store.publish(OtelDataset::Spans, &rows).unwrap();
        drop(store);
        // A sweep that crashed before deleting an expired day file, and a
        // crash mid-append that tore today's last record.
        let stale = receipt_day_file(dir.path(), OtelDataset::Spans, 1);
        append_lines(&stale, &format!("{}\n", "ab".repeat(32))).unwrap();
        let day = chrono::Utc::now().timestamp().div_euclid(86_400);
        let today = receipt_day_file(dir.path(), OtelDataset::Spans, day);
        append_lines(&today, "cdcdcd").unwrap();
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        assert_eq!(store.receipt_count(), 2);
        assert_eq!(std::fs::metadata(&today).unwrap().len(), RECEIPT_LINE_BYTES);
        store
            .publish(OtelDataset::Spans, &[row(tenant, "fedcba9876543210")])
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&today).unwrap().lines().count(),
            2,
            "the next append starts on a clean record boundary"
        );
        store.maintain(None, chrono::Utc::now()).unwrap();
        assert!(!stale.exists());
        assert_eq!(store.receipt_count(), 2);
        store.publish(OtelDataset::Spans, &rows).unwrap();
        assert_eq!(count(dir.path()), 2);
        assert_eq!(store.tracked_bytes(), durable_bytes(dir.path()).unwrap());
    }

    #[test]
    fn per_file_receipts_from_the_previous_layout_are_folded_in() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let rows = vec![row(tenant, "0123456789abcdef")];
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        store.publish(OtelDataset::Spans, &rows).unwrap();
        store.maintain(None, chrono::Utc::now()).unwrap();
        drop(store);
        std::fs::remove_dir_all(dir.path().join(".received-index")).unwrap();
        let digest = drain_batch_sha256(&rows);
        durable_write(
            &dir.path()
                .join(".received")
                .join("spans")
                .join(format!("{digest}.json")),
            b"\"2026-10-10T00:00:00Z\"",
        )
        .unwrap();
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        assert!(!dir.path().join(".received").exists());
        assert_eq!(store.receipt_count(), 1);
        assert_eq!(store.tracked_bytes(), durable_bytes(dir.path()).unwrap());
    }

    #[test]
    fn byte_counter_tracks_the_tree_across_publish_compaction_expiry_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        assert_eq!(store.tracked_bytes(), durable_bytes(dir.path()).unwrap());
        for span in ["0123456789abcdef", "1123456789abcdef", "2123456789abcdef"] {
            store
                .publish(OtelDataset::Spans, &[row(tenant, span)])
                .unwrap();
            assert_eq!(store.tracked_bytes(), durable_bytes(dir.path()).unwrap());
        }
        // A whole-batch retry changes nothing.
        store
            .publish(OtelDataset::Spans, &[row(tenant, "0123456789abcdef")])
            .unwrap();
        assert_eq!(store.tracked_bytes(), durable_bytes(dir.path()).unwrap());
        // Compaction rewrites the hour.
        store.maintain(None, chrono::Utc::now()).unwrap();
        assert_eq!(store.tracked_bytes(), durable_bytes(dir.path()).unwrap());
        // Boot seeding equals the walk, and a pending journal replayed at open
        // is charged and then released.
        drop(store);
        let rows = vec![row(tenant, "3123456789abcdef")];
        durable_write(
            &dir.path()
                .join(".pending")
                .join(format!("spans-{}.json", drain_batch_sha256(&rows))),
            &serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024).unwrap();
        assert_eq!(store.tracked_bytes(), durable_bytes(dir.path()).unwrap());
        // Retention deletes parts; receipt expiry deletes day files.
        store.maintain(Some(1), chrono::Utc::now()).unwrap();
        assert_eq!(count(dir.path()), 0);
        assert_eq!(store.tracked_bytes(), durable_bytes(dir.path()).unwrap());
        store
            .maintain(Some(1), chrono::Utc::now() + chrono::Duration::days(10))
            .unwrap();
        assert_eq!(receipt_files(dir.path()), 0);
        assert_eq!(store.tracked_bytes(), durable_bytes(dir.path()).unwrap());
        // A failed mutation drops the counter; the next holder re-seeds it.
        store.serial.lock().unwrap().used = None;
        std::fs::write(dir.path().join("stray"), b"partial").unwrap();
        store
            .publish(OtelDataset::Spans, &[row(tenant, "4123456789abcdef")])
            .unwrap();
        assert_eq!(store.tracked_bytes(), durable_bytes(dir.path()).unwrap());
    }

    /// NAN-3866: a dropped store must not leave its writer lock alive in a
    /// child another thread forked meanwhile; the reopen tests flaked with
    /// "another local OTLP publisher owns this volume" under parallel tests.
    #[test]
    fn reopen_is_not_refused_by_a_concurrently_forked_child() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        nanosiem_core::flock_guard::with_concurrent_spawns(std::time::Duration::from_secs(1), |i| {
            let store = LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024)
                .unwrap_or_else(|error| panic!("iteration {i}: {error}"));
            drop(store);
        });
        // A failed open (foreign tenant) also releases the lock it took.
        nanosiem_core::flock_guard::with_concurrent_spawns(std::time::Duration::from_millis(500), |i| {
            assert!(LocalOtelStore::open(Uuid::new_v4(), dir.path().into(), 1024 * 1024).is_err());
            drop(
                LocalOtelStore::open(tenant, dir.path().into(), 1024 * 1024)
                    .unwrap_or_else(|error| panic!("iteration {i}: {error}")),
            );
        });
    }

    #[test]
    fn full_volume_and_foreign_tenants_are_refused_without_acknowledging() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let store = LocalOtelStore::open(tenant, dir.path().into(), 1).unwrap();
        assert!(store
            .publish(OtelDataset::Spans, &[row(tenant, "0123456789abcdef")])
            .is_err());
        assert_eq!(count(dir.path()), 0);
        assert!(store
            .publish(
                OtelDataset::Spans,
                &[row(Uuid::new_v4(), "0123456789abcdef")]
            )
            .is_err());
        assert!(LocalOtelStore::open(tenant, dir.path().into(), 1024).is_err());
    }
}
