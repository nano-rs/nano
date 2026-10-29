// SPDX-License-Identifier: AGPL-3.0-or-later

//! Verified part fetch (contract section 4.4, NAN-2853 verified cache).
//!
//! For each part a query needs:
//! 1. `provenance.json` is fetched once (bounded, 4 MiB), its SHA-256 must
//!    equal the log entry's `provenance_sha256`, its signature must verify
//!    against the tenant key set, and its record must agree with the
//!    `PartRef` the log carried. Verified records are memoized by part id.
//! 2. The files the query reads (`data.parquet`, `tokens.nti`, partials) are
//!    leased through [`ReaderObjectCache::ensure_local`], keyed by the
//!    record's SHA-256 and byte count. chDB only ever sees local, verified,
//!    content-addressed bytes (`objects/{sha256}.bin`).

use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::parts::format::{PartId, PartKeys};
use crate::parts::part_log::{LocalObjectStore, ObjectStore, PartRef};
use crate::parts::provenance::{PartialKind, ProvenanceRecord, SignedProvenance, TenantKeySet};
use crate::parts::sha256_hex;
use crate::reader_object_cache::{ReaderCacheLease, ReaderObjectCache, ReaderObjectRef, ReaderObjectSource};

#[path = "late_materialization.rs"]
pub(crate) mod late_materialization;

/// Verified records kept in memory. A record is ~2 KB, so this bounds the
/// memo at a few MB while covering a day of L0 parts plus merged levels.
const RECORD_MEMO_ENTRIES: usize = 4_096;

tokio::task_local! {
    /// NAN-3161: set while a prevalence window, product window or lookup is
    /// being served. Those paths read only the parts' prevalence partials; a
    /// data-file lease inside one is a raw rescan and is counted as evidence.
    static PREVALENCE_PATH: ();
}

/// NAN-3161: run `work` as a prevalence path (see [`PartFetcher::prevalence_raw_scans`]).
pub(crate) async fn prevalence_path<F: std::future::Future>(work: F) -> F::Output {
    // NAN-3141: hold the work once, on the heap.
    let work = Box::pin(work);
    if in_prevalence_path() {
        return work.await;
    }
    PREVALENCE_PATH.scope((), work).await
}

fn in_prevalence_path() -> bool {
    PREVALENCE_PATH.try_with(|_| ()).is_ok()
}

/// One file of a part (contract r2: parts are multi-file; data file `i` has
/// its own token index `i`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PartFile {
    Data(usize),
    Ranges(usize),
    Tokens(usize),
    Uids(usize),
    Entities(usize),
    EntityLocators(usize),
    Partial(PartialKind),
}

/// Which files of every selected part a request wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSet {
    AllData,
    AllTokens,
    Partial(PartialKind),
}

impl FileSet {
    fn contains(self, file: PartFile) -> bool {
        match (self, file) {
            (Self::AllData, PartFile::Data(_)) | (Self::AllTokens, PartFile::Tokens(_)) => true,
            (Self::Partial(want), PartFile::Partial(kind)) => want == kind,
            _ => false,
        }
    }
}

/// One file of one part, verified and leased on local disk.
#[derive(Debug, Clone)]
pub struct LocalFile {
    pub part_id: PartId,
    pub file: PartFile,
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    /// NAN-3133: `path` is a per-query sparse copy holding only the signed
    /// chunks of the request's column scope (`sha256`/`bytes` still name the
    /// whole signed object, whose rows it serves).
    pub sparse: bool,
}

/// The leased local files of a query; dropping it releases the lease.
#[derive(Debug)]
pub struct LocalParts {
    pub files: Vec<LocalFile>,
    pub records: BTreeMap<PartId, Arc<ProvenanceRecord>>,
    pub lease: Option<ReaderCacheLease>,
    /// NAN-3133: the range chunks and sparse files of a ranged fetch.
    pub ranged: Option<RangedHold>,
}

/// What a ranged data fetch holds for the query: its sparse files (copies
/// of verified chunks, shared with the reuse memo) and their evidence.
#[derive(Debug)]
pub struct RangedHold {
    pub evidence: super::range_fetch::FetchEvidence,
    _sparse: Vec<Arc<super::range_fetch::SparseFile>>,
    // The query's capacity reservations for its sparse files.
    _reservations: Vec<crate::reader_object_cache::ScratchReservation>,
}

impl LocalParts {
    pub fn of(&self, set: FileSet) -> impl Iterator<Item = &LocalFile> {
        self.files.iter().filter(move |local| set.contains(local.file))
    }

    pub fn path(&self, part: &PartId, file: PartFile) -> Option<&LocalFile> {
        self.files.iter().find(|local| &local.part_id == part && local.file == file)
    }
}

/// The digest of `file` in a verified record, if the part has it.
pub fn file_digest(record: &ProvenanceRecord, file: PartFile) -> Option<(&str, &str, u64)> {
    match file {
        PartFile::Ranges(index) => record.files.data.get(index)?.parquet_ranges.as_ref()
            .map(|ranges| (ranges.name.as_str(), ranges.sha256.as_str(), ranges.bytes)),
        PartFile::Data(index) => record.files.data.get(index).map(|data| (data.name.as_str(), data.sha256.as_str(), data.bytes)),
        PartFile::Tokens(index) => record
            .files
            .data
            .get(index)
            .map(|data| (data.tokens.name.as_str(), data.tokens.sha256.as_str(), data.tokens.bytes)),
        PartFile::EntityLocators(index) => record.files.data.get(index)?.entity_locators.as_ref()
            .map(|locator| (locator.name.as_str(), locator.sha256.as_str(), locator.bytes)),
        PartFile::Entities(index) => record.files.data.get(index)?.entity_blooms.as_ref()
            .map(|entity| (entity.name.as_str(), entity.sha256.as_str(), entity.bytes)),
        PartFile::Uids(index) => record.files.data.get(index)?.uid_blooms.as_ref()
            .map(|uid| (uid.name.as_str(), uid.sha256.as_str(), uid.bytes)),
        PartFile::Partial(kind) => record
            .files
            .partials
            .iter()
            .find(|partial| partial.kind == kind)
            .map(|partial| (partial.name.as_str(), partial.sha256.as_str(), partial.bytes)),
    }
}

/// The tenant's verified part reader.
pub struct PartFetcher {
    tenant_id: String,
    bucket: String,
    store: Arc<dyn ObjectStore>,
    keys: TenantKeySet,
    cache: ReaderObjectCache,
    retired: tokio::sync::Mutex<Vec<String>>,
    range_objects: Mutex<BTreeMap<PartId, std::collections::BTreeSet<String>>>,
    pub hot_settings: Option<crate::local_hot_window::Settings>,
    pub hot_coverage: Mutex<crate::local_hot_window::Coverage>,
    /// NAN-3164: process start, for the bounded startup warm gate.
    hot_started: std::time::Instant,
    /// NAN-3647: the gated warm timeout was reported (once per process).
    hot_gate_timeout_logged: std::sync::atomic::AtomicBool,
    /// NAN-3647: the persistent volume's inherited objects were reconciled.
    pub(crate) hot_reconciled: std::sync::atomic::AtomicBool,
    /// NAN-3690: the one pre-latch rediscovery pass already ran.
    pub(crate) hot_caught_up: std::sync::atomic::AtomicBool,
    /// NAN-3690: the last pass asked for an immediate next pass.
    hot_rerun: std::sync::atomic::AtomicBool,
    memo: Mutex<RecordMemo>,
    edge_logs: Option<EdgeLogMap>,
    local_root: Option<PathBuf>,
    metadata_bytes: super::metadata_cache::MetadataBytesCache,
    count_footers: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    /// NAN-3801: verified signed count records by part (`None`: absent,
    /// re-checked after [`COUNT_RECORD_NEGATIVE_TTL`]).
    count_records: Mutex<BTreeMap<PartId, (Option<Arc<crate::parts::count_record::CountRecord>>, std::time::Instant)>>,
    /// NAN-3133: this process's sparse-file directory and memos (lazy).
    sparse: tokio::sync::Mutex<Option<Arc<super::range_fetch::SparseStore>>>,
    /// NAN-3161: data-file leases taken inside a prevalence path. Zero by
    /// construction; anything else is a raw rescan regression.
    prevalence_raw_scans: std::sync::atomic::AtomicU64,
}

/// Bound metadata probes separately from digest verification.
const LOCAL_PATH_CONCURRENCY: usize = 8;

/// part id → the `edge_log` of the `add` entry that added it (live L0 parts
/// added after the view's starting point).
pub type EdgeLogMap = Arc<Mutex<BTreeMap<PartId, Option<crate::parts::provenance::EdgeLogRange>>>>;

#[derive(Default)]
struct RecordMemo {
    records: BTreeMap<PartId, Arc<ProvenanceRecord>>,
    order: VecDeque<PartId>,
}

impl PartFetcher {
    pub fn new(
        tenant_id: &str,
        bucket: &str,
        store: Arc<dyn ObjectStore>,
        keys: TenantKeySet,
        cache: ReaderObjectCache,
    ) -> Result<Self> {
        crate::parts::format::validate_tenant_uuid(tenant_id)?;
        Ok(Self {
            tenant_id: tenant_id.to_string(),
            bucket: bucket.to_string(),
            store,
            keys,
            cache,
            retired: Default::default(),
            range_objects: Mutex::default(),
            hot_settings: None,
            hot_coverage: Mutex::default(),
            hot_started: std::time::Instant::now(),
            hot_gate_timeout_logged: Default::default(),
            hot_reconciled: Default::default(),
            hot_caught_up: Default::default(),
            hot_rerun: Default::default(),
            memo: Mutex::default(),
            edge_logs: None,
            local_root: None,
            metadata_bytes: Default::default(),
            count_footers: Default::default(),
            count_records: Default::default(),
            sparse: Default::default(),
            prevalence_raw_scans: Default::default(),
        })
    }

    /// NAN-3161 evidence: how many data-file leases (raw scans) this tenant's
    /// prevalence windows, product windows and lookups have taken.
    pub fn prevalence_raw_scans(&self) -> u64 {
        self.prevalence_raw_scans.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn note_raw_scan(&self, wanted: &[(PartRef, PartFile)]) {
        if in_prevalence_path() && wanted.iter().any(|(_, file)| matches!(file, PartFile::Data(_))) {
            self.prevalence_raw_scans.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(tenant_id = %self.tenant_id, parts = wanted.len(), "prevalence path leased raw data files");
        }
    }

    pub fn local_range_membership(&self) -> crate::local_hot_window::Membership {
        self.range_objects.lock().expect("range object ledger").iter()
            .map(|(id, digests)| (id.to_string(), digests.iter().cloned().collect())).collect()
    }

    pub fn with_hot_window(mut self, settings: Option<crate::local_hot_window::Settings>) -> Self {
        self.hot_settings = settings;
        self
    }

    /// NAN-3164: startup warm gate; `None` without a local hot window.
    pub fn hot_window_gate(&self) -> Option<crate::local_hot_window::WarmGate> {
        let settings = self.hot_settings.as_ref()?;
        let coverage = self.hot_coverage.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let gate = crate::local_hot_window::warm_gate(&settings.schedule, coverage.warm_resident, self.hot_started.elapsed());
        // NAN-3647: the opt-in gate never holds a roll forever, but going
        // Ready cold is an incident worth a page-level line, once.
        if gate == crate::local_hot_window::WarmGate::TimedOut && settings.schedule.warm_gate
            && !self.hot_gate_timeout_logged.swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::error!(
                tenant_id = %self.tenant_id,
                timeout_secs = settings.schedule.warm_timeout.as_secs(),
                warm_hours = settings.schedule.warm_hours,
                covered_hours = coverage.effective_hours,
                bytes_resident = coverage.local_bytes,
                bytes_target = coverage.selected_bytes,
                rate = coverage.rate_bytes_per_second,
                "hot-window warm gate timed out: going Ready COLD; recent searches read object storage until hydration catches up"
            );
        }
        Some(gate)
    }

    /// NAN-3690: ask the hydration loop to start the next pass now.
    pub(crate) fn request_hot_rerun(&self) {
        self.hot_rerun.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// NAN-3690: whether the last pass asked for an immediate next pass
    /// (cleared on read).
    pub fn take_hot_rerun(&self) -> bool {
        self.hot_rerun.swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn cache(&self) -> &ReaderObjectCache {
        &self.cache
    }

    pub fn store(&self) -> &Arc<dyn ObjectStore> {
        &self.store
    }

    pub fn keys_for(&self, part: &PartRef) -> Result<PartKeys> {
        PartKeys::new(&self.tenant_id, part.level, part.event_hour, &part.part_id)
    }

    /// The object URI of a part file (the cache's source identity). Data
    /// files use `ProvenanceRecord::data_key` (an adopted part's data file
    /// is its original object, contract r3); every other file lives in the
    /// part directory.
    pub fn file_uri(&self, part: &PartRef, record: &ProvenanceRecord, file: PartFile) -> Result<String> {
        let keys = self.keys_for(part)?;
        let key = match file {
            PartFile::Data(index) => record.data_key(&keys, index).context("data file index is out of range")?,
            other => keys.file(file_digest(record, other).context("part has no such file")?.0),
        };
        Ok(format!("s3://{}/{}", self.bucket, key))
    }

    /// Attach the log view's `add`-entry edge-log map (contract r3 4.1.1):
    /// each L0 record's `inputs.edge_log` must equal its entry's.
    pub fn with_edge_logs(mut self, edge_logs: EdgeLogMap) -> Self {
        self.edge_logs = Some(edge_logs);
        self
    }

    /// The verified provenance record of a live part (contract 4.5 steps
    /// 2–4: provenance SHA-256, owner signature, `PartRef` equality).
    pub async fn record(&self, part: &PartRef) -> Result<Arc<ProvenanceRecord>> {
        if let Some(record) = self.memo.lock().expect("record memo").records.get(&part.part_id) {
            return Ok(record.clone());
        }
        let key = self.keys_for(part)?.provenance();
        let bytes = self
            .store
            .get(&key)
            .await?
            .with_context(|| format!("provenance of live part {} is missing", part.part_id))?;
        let sha = sha256_hex(&bytes);
        if sha != part.provenance_sha256 {
            bail!("provenance of part {} does not match its log entry", part.part_id);
        }
        let signed = SignedProvenance::verify_bytes(&bytes, &self.tenant_id, &self.keys)?;
        part.check_record(&signed.record, &sha)?;
        if let Some(edge_logs) = &self.edge_logs {
            let expected = edge_logs.lock().expect("edge log map").get(&part.part_id).cloned();
            if let Some(expected) = expected {
                crate::parts::part_log::check_add_edge_log(expected.as_ref(), &signed.record)?;
            }
        }
        let record = Arc::new(signed.record);
        let mut memo = self.memo.lock().expect("record memo");
        if memo.records.insert(part.part_id.clone(), record.clone()).is_none() {
            memo.order.push_back(part.part_id.clone());
        }
        while memo.order.len() > RECORD_MEMO_ENTRIES {
            if let Some(evicted) = memo.order.pop_front() {
                memo.records.remove(&evicted);
            }
        }
        Ok(record)
    }

    /// Forget superseded cached inputs on verified discovery updates. Active
    /// cross-process leases defer canonical deletion until a later refresh.
    pub async fn retire_removed(&self, live: Option<&std::collections::BTreeSet<PartId>>) -> Result<()> {
        let digests = if let Some(live) = live {
            let mut memo = self.memo.lock().expect("record memo");
            let removed = memo.records.keys().filter(|id| !live.contains(*id)).cloned().collect::<Vec<_>>();
            let mut digests = Vec::new();
            for id in removed {
                if let Some(record) = memo.records.remove(&id) {
                    digests.extend(record.files.all().into_iter().map(|(_, sha, _)| sha.to_string()));
                }
            }
            memo.order.retain(|id| live.contains(id));
            digests
        } else { Vec::new() };
        let mut digests = digests;
        if let Some(live) = live {
            self.range_objects.lock().expect("range object ledger").retain(|id, ranges| {
                if live.contains(id) { true } else { digests.extend(ranges.iter().cloned()); false }
            });
        }
        let mut pending = self.retired.lock().await;
        pending.extend(digests);
        pending.sort();
        pending.dedup();
        if pending.is_empty() { return Ok(()) }
        let deferred = self.cache.evict_unleased(pending.clone()).await?;
        *pending = deferred;
        Ok(())
    }

    /// Verified records of `parts`, in order.
    pub async fn records(&self, parts: &[PartRef]) -> Result<Vec<Arc<ProvenanceRecord>>> {
        futures::future::try_join_all(parts.iter().map(|part| self.record(part))).await
    }

    pub(super) fn count_footer_cached(&self, digest: &str) -> bool {
        self.count_footers.lock().is_ok_and(|memo| memo.contains_key(digest))
    }

    /// Local verified evidence only. Called on the idle, low-priority evidence
    /// thread; eviction races simply leave the next query to fetch the footer.
    pub(super) fn count_footer_warmer(&self, digest: String) -> impl FnOnce() -> Option<u8> + Send + 'static {
        let cache = self.cache.clone();
        let memo = self.count_footers.clone();
        move || {
            let path = cache.verified_background_path(&digest)?;
            let footer = count_footer(&path).ok()?;
            let hint = count_coverage(&footer).ok()?;
            remember_count_footer(&memo, digest, footer);
            Some(hint)
        }
    }

    /// A bounded footer-only coverage probe. Bit 7 identifies the v2 layout;
    /// the lower bits are covered kinds. This is negative planning
    /// evidence, never count authority: a positive still leases/verifies the
    /// entire signed partial and validates its coverage against signed bounds.
    /// Pre-hint sidecars stay native; old readers ignore the added footer key.
    pub(super) async fn entity_count_coverage_hint(
        &self, part: &PartRef, record: &ProvenanceRecord,
    ) -> Result<u8> {
        let Some(partial) = record.files.partials.iter().find(|p| p.kind == PartialKind::EntityRanges) else {
            return Ok(0);
        };
        let cached = self.count_footers.lock().ok().and_then(|memo| memo.get(&partial.sha256).cloned());
        if let Some(footer) = cached {
            return tokio::task::spawn_blocking(move || count_coverage(&footer)).await?;
        }
        // Metadata outside this cap isn't worth attempting interactively.
        const MAX_FOOTER_BYTES: u64 = crate::part_ingest::reindex::COUNT_HINT_FOOTER_MAX_BYTES;
        if partial.bytes < 8 { return Ok(0); }
        let key = self.keys_for(part)?.file(&partial.name);
        let Some(tail) = self.store.get_range(&key, partial.bytes - 8..partial.bytes).await? else {
            return Ok(0);
        };
        if tail.len() != 8 || &tail[4..] != b"PAR1" { return Ok(0); }
        let length = u64::from(u32::from_le_bytes(tail[..4].try_into()?));
        if length > MAX_FOOTER_BYTES || length > partial.bytes - 8 { return Ok(0); }
        let Some(footer) = self.store.get_range(&key, partial.bytes - 8 - length..partial.bytes - 8).await? else {
            return Ok(0);
        };
        if footer.len() as u64 != length { return Ok(0); }
        // Remote hints are unauthenticated pruning hints only. Never put
        // them in the footer memo used to select authoritative count groups.
        tokio::task::spawn_blocking(move || count_coverage(&footer)).await?
    }

    /// Lease every file of `sets` for each part. A part without a requested
    /// partial (risk partials exist only on finding parts) is skipped for it.
    pub async fn ensure(&self, parts: &[PartRef], sets: &[FileSet]) -> Result<LocalParts> {
        let records = self.records(parts).await?;
        let mut wanted = Vec::new();
        for (part, record) in parts.iter().zip(&records) {
            for set in sets {
                match set {
                    FileSet::AllData => wanted.extend((0..record.files.data.len()).map(|i| (part.clone(), PartFile::Data(i)))),
                    FileSet::AllTokens => wanted.extend((0..record.files.data.len()).map(|i| (part.clone(), PartFile::Tokens(i)))),
                    FileSet::Partial(kind) => wanted.push((part.clone(), PartFile::Partial(*kind))),
                }
            }
        }
        self.ensure_files(&wanted).await
    }

    /// The cell-local path of `file`, when ingest wrote it to the local
    /// parts dir (an admission source only). `None`: remote only.
    pub fn local_file_path(&self, part: &PartRef, record: &ProvenanceRecord, file: PartFile) -> Option<PathBuf> {
        let root = self.local_root.as_ref()?;
        let source_uri = self.file_uri(part, record, file).ok()?;
        let key = crate::hot_tail_cache::parse_s3_uri(&source_uri).ok()?.1.to_string();
        let path = LocalObjectStore::new(root).ok()?.path(&key).ok()?;
        if path.is_file() { return Some(path) }
        if self.hot_settings.is_some() {
            let (_, digest, _) = file_digest(record, file)?;
            let producer = crate::producer_cache::object(root, digest).ok()?;
            if producer.is_file() { return Some(producer) }
        }
        None
    }

    /// NAN-4164: whether `file` is already on this cell (written by its
    /// ingest, or a verified reader-cache object), so leasing it reads no R2.
    pub async fn file_is_local(&self, part: &PartRef, record: &ProvenanceRecord, file: PartFile) -> Result<bool> {
        if self.local_file_path(part, record, file).is_some() {
            return Ok(true);
        }
        let Some((_, digest, size)) = file_digest(record, file) else { return Ok(false) };
        let object = ReaderObjectRef { range: None, source_uri: self.file_uri(part, record, file)?, sha256: digest.to_string(), size_bytes: size };
        Ok(self.cache.is_local(&object).await?)
    }

    /// Lease exactly these files.
    pub async fn ensure_files(&self, wanted: &[(PartRef, PartFile)]) -> Result<LocalParts> {
        self.ensure_files_within(wanted, None).await
    }

    /// [`Self::ensure_files`] drawing its cold bytes from `budget`.
    pub async fn ensure_files_within(
        &self, wanted: &[(PartRef, PartFile)], budget: Option<&crate::reader_object_cache::ColdBudget>,
    ) -> Result<LocalParts> {
        self.note_raw_scan(wanted);
        let _timer = crate::query_timing::timer(crate::query_timing::Phase::FilePrepare);
        let mut refs = Vec::new();
        let mut locals = Vec::new();
        let mut by_part = BTreeMap::new();
        let mut local_sources = Vec::new();
        use futures::{StreamExt, TryStreamExt};
        // Filesystem metadata may live on a network-backed parts mount. Do
        // not perform one blocking stat per file on the async query thread.
        // `buffered` retains requested order while bounding outstanding work.
        let probes = wanted.iter().cloned().map(|(part, file)| async move {
            let record = self.record(&part).await?;
            let Some((_, sha256, bytes)) = file_digest(&record, file) else { return Ok(None) };
            let sha256 = sha256.to_string();
            let source_uri = self.file_uri(&part, &record, file)?;
            let local = if let Some(root) = self.local_root.clone() {
                let uri = source_uri.clone();
                tokio::task::spawn_blocking(move || {
                    let key = crate::hot_tail_cache::parse_s3_uri(&uri).ok()?.1.to_string();
                    let path = LocalObjectStore::new(&root).ok()?.path(&key).ok()?;
                    path.is_file().then_some(path)
                }).await?
            } else {
                None
            };
            Ok::<_, anyhow::Error>(Some((part, file, record, sha256, bytes, source_uri, local)))
        }).collect::<Vec<_>>();
        let resolved = futures::stream::iter(probes).buffered(LOCAL_PATH_CONCURRENCY).try_collect::<Vec<_>>().await?;
        for (part, file, record, sha256, bytes, source_uri, local) in resolved.into_iter().flatten() {
            let object = ReaderObjectRef { range: None, source_uri, sha256: sha256.clone(), size_bytes: bytes };
            if let Some(path) = local {
                local_sources.push((object.clone(), path));
            }
            if let Some(settings) = &self.hot_settings {
                let cutoff = chrono::Utc::now().timestamp_micros().saturating_sub(
                    i64::try_from(settings.hours).unwrap_or(i64::MAX).saturating_mul(3_600_000_000));
                if part.max_time_us >= cutoff { self.cache.mark_hot(sha256.clone(), part.max_time_us); }
            }
            refs.push(object);
            locals.push(LocalFile {
                part_id: part.part_id.clone(), file,
                path: self.cache.object_path(&sha256), sha256, bytes, sparse: false,
            });
            by_part.insert(part.part_id.clone(), record);
        }
        // Writer paths can disappear during ingest GC, cache eviction or
        // restart sweeping. Publish an independent immutable reader copy;
        // only leased reader paths may escape to footer/native readers.
        for (object, path) in local_sources {
            match self.cache.warm_local(&object, &path).await {
                Ok(()) => {},
                Err(crate::reader_object_cache::ReaderCacheError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {},
                Err(crate::reader_object_cache::ReaderCacheError::Integrity(error)) => {
                    tracing::warn!(%error, "writer copy failed verification; fetching signed object from R2");
                }
                Err(error) if error.retryable() => {},
                Err(error) => return Err(error.into()),
            }
        }
        if let Some(root) = &self.local_root {
            for object in &refs {
                let path = crate::producer_cache::object(root, &object.sha256)?;
                if path.is_file() {
                    match self.cache.warm_local(object, &path).await {
                        Ok(()) => {},
                        Err(crate::reader_object_cache::ReaderCacheError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {},
                        Err(crate::reader_object_cache::ReaderCacheError::Integrity(error)) => {
                            tracing::warn!(%error, "producer copy failed verification; fetching signed object from R2");
                        }
                        Err(error) if error.retryable() => {}, // Normal fetch/admission owns the foreground result.
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
        let lease = if refs.is_empty() { None } else {
            Some(match budget {
                Some(budget) => self.cache.ensure_local_within(&refs, budget).await?,
                None => self.cache.ensure_local(&refs).await?,
            })
        };
        if let Some(lease) = &lease {
            for local in &mut locals {
                local.path = lease.pinned_path(&local.sha256);
            }
        }
        Ok(LocalParts { files: locals, records: by_part, lease, ranged: None })
    }

    /// NAN-3133: lease the data files of `wanted` for a request reading only
    /// `scope`'s columns. A data file with a verified range manifest whose
    /// whole object is not already local is served as a sparse file of the
    /// signed footer and the scope's column chunks; every other file, and
    /// any file whose ranged path fails a check or a transient fetch, is
    /// leased whole. Manifests, ranges and whole files draw on one cold-byte
    /// budget. Non-data files are leased whole.
    ///
    /// `whole_only` (an entity pivot, whose in-file bloom pruning needs the
    /// whole file) leases every file whole under the same budget.
    pub async fn ensure_ranged(&self, wanted: &[(PartRef, PartFile)], scope: &super::range_fetch::ColumnScope, whole_only: bool) -> Result<LocalParts> {
        use super::range_fetch::{self, Fallback, FetchEvidence};
        use futures::{StreamExt, TryStreamExt};
        self.note_raw_scan(wanted);
        let _timer = crate::query_timing::timer(crate::query_timing::Phase::FilePrepare);
        let budget = crate::reader_object_cache::ColdBudget::new(scope.budget(self.cache.query_cold_budget()));
        let mut evidence = FetchEvidence::default();
        let mut whole: Vec<(PartRef, PartFile)> = Vec::new();
        let mut candidates: Vec<(PartRef, usize, Arc<ProvenanceRecord>)> = Vec::new();
        // Records and residency, with bounded concurrency.
        let probes = wanted.iter().cloned().map(|(part, file)| async move {
            let record = self.record(&part).await?;
            let class = match file {
                _ if scope.whole_only() => None,
                PartFile::Data(_) if whole_only => Some(Err(Fallback::EntityPivot)),
                PartFile::Data(index) => match record.files.data.get(index) {
                    None => None,
                    Some(data) if data.parquet_ranges.is_none() => Some(Err(Fallback::NoSidecar)),
                    Some(_) => match self.whole_is_local(&part, &record, index).await {
                        Ok(true) => Some(Ok(false)),
                        Ok(false) => Some(Ok(true)),
                        Err(error) => {
                            tracing::warn!(error = %format!("{error:#}"), "residency probe failed; fetching the whole file");
                            Some(Err(Fallback::FetchFailed))
                        }
                    },
                },
                _ => None,
            };
            Ok::<_, anyhow::Error>((part, file, record, class))
        }).collect::<Vec<_>>();
        let classified = futures::stream::iter(probes).buffered(LOCAL_PATH_CONCURRENCY).try_collect::<Vec<_>>().await?;
        for (part, file, record, class) in classified {
            match (class, file) {
                (Some(Ok(true)), PartFile::Data(index)) => { candidates.push((part, index, record)); continue }
                // Residency wins: the verified whole file costs no fetch.
                (Some(Ok(false)), _) => evidence.resident(),
                (Some(Err(reason)), _) => evidence.fallback(reason),
                _ => {}
            }
            whole.push((part, file));
        }

        // Signed manifests (small sidecars), then the selected ranges.
        let mut plans = Vec::new();
        let mut manifest_lease = None;
        if !candidates.is_empty() {
            let manifests = candidates.iter().map(|(part, index, _)| (part.clone(), PartFile::Ranges(*index))).collect::<Vec<_>>();
            match self.ensure_files_within(&manifests, Some(&budget)).await {
                Ok(local) => {
                    for (part, index, record) in candidates {
                        let data = &record.files.data[index];
                        let ranges = local.path(&part.part_id, PartFile::Ranges(index)).context("range manifest missing")
                            .and_then(|manifest| self.parse_ranges(manifest, data));
                        let ranges = match ranges {
                            Ok(ranges) => ranges,
                            Err(_) => {
                                evidence.fallback(Fallback::SidecarInvalid);
                                whole.push((part, PartFile::Data(index)));
                                continue;
                            }
                        };
                        let selected = range_fetch::select_ranges(&ranges, scope).into_iter().map(|at| {
                            let range = &ranges[at];
                            // Narrow reads authenticate whole predicate chunks;
                            // retaining every payload page hash here wastes memory.
                            crate::parts::parquet_ranges::ParquetRangeDigest { offset: range.offset, bytes: range.bytes,
                                sha256: range.sha256.clone(), row_group: range.row_group, column: range.column.clone(), pages: Vec::new() }
                        }).collect::<Vec<_>>();
                        if !range_fetch::is_narrow(selected.iter().map(|range| range.bytes).sum(), data.bytes) {
                            evidence.fallback(Fallback::NotNarrow);
                            whole.push((part, PartFile::Data(index)));
                            continue;
                        }
                        plans.push((part, index, record, selected));
                    }
                    manifest_lease = Some(local);
                }
                Err(error) => {
                    let reason = if error.downcast_ref::<crate::reader_object_cache::ReaderCacheError>()
                        .is_some_and(|error| matches!(error, crate::reader_object_cache::ReaderCacheError::Integrity(_))) {
                        Fallback::SidecarInvalid
                    } else { Fallback::FetchFailed };
                    tracing::warn!(error = %format!("{error:#}"), files = candidates.len(), "range manifests unavailable; fetching whole files");
                    evidence.fallbacks(reason, candidates.len());
                    whole.extend(candidates.into_iter().map(|(part, index, _)| (part, PartFile::Data(index))));
                }
            }
        }
        let store = if plans.is_empty() { None } else {
            match self.sparse_store().await {
                Ok(store) => Some(store),
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), "sparse directory unavailable; fetching whole files");
                    evidence.fallbacks(Fallback::FetchFailed, plans.len());
                    whole.extend(plans.drain(..).map(|(part, index, _, _)| (part, PartFile::Data(index))));
                    None
                }
            }
        };
        // Reuse a live sparse file with the same digest and ranges.
        let mut sparse = Vec::new();
        let mut locals = Vec::new();
        let mut records = BTreeMap::new();
        let mut reservations = Vec::new();
        let mut serve = |part: &PartRef, index: usize, record: &Arc<ProvenanceRecord>, file: Arc<range_fetch::SparseFile>,
            locals: &mut Vec<LocalFile>, sparse: &mut Vec<Arc<range_fetch::SparseFile>>| {
            let data = &record.files.data[index];
            locals.push(LocalFile {
                part_id: part.part_id.clone(), file: PartFile::Data(index), path: file.path().to_path_buf(),
                sha256: data.sha256.clone(), bytes: data.bytes, sparse: true,
            });
            records.insert(part.part_id.clone(), record.clone());
            sparse.push(file);
        };
        let mut misses = Vec::new();
        if let Some(store) = &store {
            for (part, index, record, selected) in plans {
                let key = range_fetch::sparse_key(&record.files.data[index].sha256, &selected);
                // A reused file is held under a fresh capacity reservation
                // for this query (the memo itself holds none).
                let reused = match store.cached(&key) {
                    Some(file) => {
                        let (cache, bytes) = (self.cache.clone(), file.bytes());
                        match tokio::task::spawn_blocking(move || cache.reserve_scratch(bytes)).await {
                            Ok(Ok(reservation)) => Some((file, reservation)),
                            _ => None,
                        }
                    }
                    None => None,
                };
                match reused {
                    Some((file, reservation)) => {
                        reservations.push(reservation);
                        serve(&part, index, &record, file, &mut locals, &mut sparse);
                    }
                    None => misses.push((part, index, record, selected, key)),
                }
            }
        }
        // Every missing chunk of the selection in one lease.
        let mut refs = Vec::new();
        for (part, index, record, selected, _) in &misses {
            let file_refs = self.range_refs(part, record, *index, selected.iter())?;
            self.import_ranges(part, record, *index, &file_refs).await?;
            refs.extend(file_refs);
        }
        let lease = if refs.is_empty() { None } else {
            match self.cache.ensure_local_within(&refs, &budget).await {
                Ok(lease) => Some(lease),
                Err(error) => {
                    let reason = match &error {
                        crate::reader_object_cache::ReaderCacheError::Integrity(_) => Fallback::VerificationFailed,
                        _ => Fallback::FetchFailed,
                    };
                    tracing::warn!(%error, files = misses.len(), "signed ranges unavailable; fetching whole files");
                    evidence.fallbacks(reason, misses.len());
                    whole.extend(misses.drain(..).map(|(part, index, _, _, _)| (part, PartFile::Data(index))));
                    None
                }
            }
        };
        if let (Some(lease), Some(store)) = (&lease, &store) {
            store.maybe_sweep();
            let builds = misses.into_iter().map(|(part, index, record, selected, key)| {
                let (store, cache) = (store.clone(), self.cache.clone());
                let data = &record.files.data[index];
                let footer = selected.iter().find(|range| range.column.is_none()).cloned();
                let chunks = selected.iter().filter(|range| range.column.is_some())
                    .map(|range| (range.offset, range.bytes, lease.pinned_path(&range.sha256))).collect::<Vec<_>>();
                let footer_path = footer.as_ref().map(|footer| lease.pinned_path(&footer.sha256));
                let file_bytes = data.bytes;
                async move {
                    let built = tokio::task::spawn_blocking(move || {
                        let (footer, footer_path) = footer.zip(footer_path).ok_or_else(||
                            range_fetch::SparseError::Footer(anyhow::anyhow!("selected ranges lack the footer")))?;
                        store.build(&cache, &key, file_bytes, footer.offset, footer.bytes, &footer.sha256, &footer_path, &chunks)
                    }).await.map_err(|error| range_fetch::SparseError::Write(error.to_string())).and_then(|built| built);
                    (part, index, record, built)
                }
            }).collect::<Vec<_>>();
            let built = futures::stream::iter(builds).buffered(LOCAL_PATH_CONCURRENCY).collect::<Vec<_>>().await;
            for (part, index, record, built) in built {
                match built {
                    Ok((file, reservation)) => {
                        reservations.push(reservation);
                        serve(&part, index, &record, file, &mut locals, &mut sparse);
                    }
                    Err(error) => {
                        tracing::warn!(%error, part = %part.part_id, file = index, "sparse file refused; fetching the whole file");
                        evidence.fallback(match error {
                            range_fetch::SparseError::Footer(_) => Fallback::FooterRewrite,
                            range_fetch::SparseError::Write(_) => Fallback::FetchFailed,
                        });
                        whole.push((part, PartFile::Data(index)));
                    }
                }
            }
        }
        drop(manifest_lease);
        let range_bytes = lease.as_ref().map_or(0, ReaderCacheLease::fetched_bytes);
        // The sparse files own copies of their chunks: release the chunk pins.
        drop(lease);
        let whole_parts = self.ensure_files_within(&whole, Some(&budget)).await;
        scope.add_cold_spent(budget.spent());
        let whole_parts = whole_parts?;
        let whole_bytes = whole_parts.lease.as_ref().map_or(0, ReaderCacheLease::fetched_bytes);
        evidence.fetched(sparse.len(), range_bytes, whole_bytes);
        locals.extend(whole_parts.files);
        records.extend(whole_parts.records);
        Ok(LocalParts {
            files: locals, records, lease: whole_parts.lease,
            ranged: Some(RangedHold { evidence, _sparse: sparse, _reservations: reservations }),
        })
    }

    /// Tests: forget the reusable sparse files (the next query starts cold).
    #[cfg(test)]
    pub async fn reset_sparse_memo(&self) {
        self.sparse.lock().await.take();
    }

    /// This process's sparse-file store for the tenant cache: opened once
    /// (single flight), and reopened if its directory was removed.
    async fn sparse_store(&self) -> Result<Arc<super::range_fetch::SparseStore>> {
        let mut slot = self.sparse.lock().await;
        if let Some(store) = slot.as_ref().filter(|store| store.is_live()) {
            return Ok(store.clone());
        }
        let (root, cache_bytes) = (self.cache.scratch_dir("ranged"), self.cache.max_bytes());
        let store = Arc::new(tokio::task::spawn_blocking(move || super::range_fetch::SparseStore::open(&root, cache_bytes)).await??);
        *slot = Some(store.clone());
        Ok(store)
    }

    /// Whether the verified whole data file is already local: reader cache,
    /// writer-local copy or producer copy (any of them costs no fetch).
    /// NAN-3165: which of these data files are whole and local right now
    /// (the reader-cache object at its signed size, or a writer/producer
    /// copy). A stat-only hint for choosing in-file blooms over sidecars:
    /// nothing is verified or hashed here; the lease taken for the data
    /// stage still verifies every byte, and a wrong guess only costs a fetch.
    pub async fn resident_data_files(&self, files: &[(PartRef, usize)]) -> std::collections::BTreeSet<(PartId, usize)> {
        let mut probes = Vec::with_capacity(files.len());
        for (part, index) in files {
            let Ok(record) = self.record(part).await else { continue };
            let Some(data) = record.files.data.get(*index) else { continue };
            let writer = self.local_root.as_ref().and_then(|root| {
                let uri = self.file_uri(part, &record, PartFile::Data(*index)).ok()?;
                let key = crate::hot_tail_cache::parse_s3_uri(&uri).ok()?.1.to_string();
                LocalObjectStore::new(root).ok()?.path(&key).ok()
            });
            let producer = self.local_root.as_ref().and_then(|root| crate::producer_cache::object(root, &data.sha256).ok());
            probes.push(((part.part_id.clone(), *index), self.cache.object_path(&data.sha256), data.bytes, writer, producer));
        }
        tokio::task::spawn_blocking(move || {
            probes.into_iter().filter(|(_, cached, bytes, writer, producer)| {
                std::fs::metadata(cached).is_ok_and(|meta| meta.is_file() && meta.len() == *bytes)
                    || writer.as_ref().is_some_and(|path| path.is_file())
                    || producer.as_ref().is_some_and(|path| path.is_file())
            }).map(|(key, ..)| key).collect()
        }).await.unwrap_or_default()
    }

    async fn whole_is_local(&self, part: &PartRef, record: &ProvenanceRecord, index: usize) -> Result<bool> {
        let data = &record.files.data[index];
        let whole = ReaderObjectRef {
            range: None, source_uri: self.file_uri(part, record, PartFile::Data(index))?,
            sha256: data.sha256.clone(), size_bytes: data.bytes,
        };
        if self.cache.is_local(&whole).await? { return Ok(true) }
        let Some(root) = self.local_root.clone() else { return Ok(false) };
        let (uri, digest) = (whole.source_uri, whole.sha256);
        Ok(tokio::task::spawn_blocking(move || {
            let writer = crate::hot_tail_cache::parse_s3_uri(&uri).ok()
                .and_then(|(_, key)| LocalObjectStore::new(&root).ok()?.path(key).ok())
                .is_some_and(|path| path.is_file());
            writer || crate::producer_cache::object(&root, &digest).is_ok_and(|path| path.is_file())
        }).await?)
    }

    /// Hydrate an object from an already verified record without a second
    /// provenance lookup. Probe writer/producer paths off the async runtime.
    pub(super) async fn hydrate_object(&self, object: &ReaderObjectRef) -> Result<ReaderCacheLease> {
        let local = if let Some(root) = self.local_root.clone() {
            let object = object.clone();
            tokio::task::spawn_blocking(move || -> Result<Option<PathBuf>> {
                let key = crate::hot_tail_cache::parse_s3_uri(&object.source_uri)?.1.to_string();
                let path = LocalObjectStore::new(&root)?.path(&key)?;
                if path.is_file() { return Ok(Some(path)); }
                let producer = crate::producer_cache::object(&root, &object.sha256)?;
                Ok(producer.is_file().then_some(producer))
            }).await??
        } else { None };
        if let Some(path) = local {
            match self.cache.warm_local(object, &path).await {
                Ok(()) => {},
                Err(error) if error.retryable() => {},
                Err(crate::reader_object_cache::ReaderCacheError::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound => {},
                Err(crate::reader_object_cache::ReaderCacheError::Integrity(error)) => {
                    tracing::warn!(%error, "local hot-window copy failed verification; fetching signed object");
                },
                Err(error) => return Err(error.into()),
            }
        }
        Ok(self.cache.ensure_local(std::slice::from_ref(object)).await?)
    }

    /// Metadata bytes are reusable only after ensure_files verified the lease.
    pub(super) fn metadata_bytes(&self, local: &LocalFile) -> Option<std::sync::Arc<Vec<u8>>> {
        self.metadata_bytes.get(&local.path, &local.sha256)
    }

    /// The authenticated range directory (legacy parts return None).
    pub async fn data_ranges(&self, part: &PartRef, index: usize)
        -> Result<Option<Vec<crate::parts::parquet_ranges::ParquetRangeDigest>>> {
        let record = self.record(part).await?;
        let data = record.files.data.get(index).context("data file index out of range")?;
        if data.parquet_ranges.is_none() { return Ok(None) }
        let manifest = self.ensure_files(&[(part.clone(), PartFile::Ranges(index))]).await?;
        let local = manifest.path(&part.part_id, PartFile::Ranges(index)).context("range manifest missing")?;
        Ok(Some(self.parse_ranges(local, data)?))
    }

    /// Parse and validate a leased, digest-verified range manifest.
    fn parse_ranges(&self, manifest: &LocalFile, data: &crate::parts::provenance::DataFileDigest)
        -> Result<Vec<crate::parts::parquet_ranges::ParquetRangeDigest>> {
        let bytes = self.metadata_bytes.get(&manifest.path, &manifest.sha256).context("range manifest unavailable")?;
        let ranges = serde_json::from_slice::<Vec<crate::parts::parquet_ranges::ParquetRangeDigest>>(&bytes)?;
        crate::parts::parquet_ranges::validate(&ranges, data.bytes, data.row_groups)?;
        Ok(ranges)
    }

    /// Cache references of signed ranges of data file `index` (offsets and
    /// digests come only from the verified manifest).
    fn range_refs<'a>(
        &self, part: &PartRef, record: &ProvenanceRecord, index: usize,
        ranges: impl Iterator<Item = &'a crate::parts::parquet_ranges::ParquetRangeDigest>,
    ) -> Result<Vec<ReaderObjectRef>> {
        let source_uri = self.file_uri(part, record, PartFile::Data(index))?;
        ranges.map(|range| Ok(ReaderObjectRef {
            source_uri: source_uri.clone(), sha256: range.sha256.clone(), size_bytes: range.bytes,
            range: Some(range.offset..range.offset.checked_add(range.bytes).context("range overflow")?),
        })).collect()
    }

    /// With a hot window: import signed ranges from a local whole-file reader
    /// hit or producer copy (each keeps its own digest fence), and record
    /// them in the range ledger for retirement.
    async fn import_ranges(&self, part: &PartRef, record: &ProvenanceRecord, index: usize, refs: &[ReaderObjectRef]) -> Result<()> {
        if self.hot_settings.is_none() { return Ok(()) }
        let data = &record.files.data[index];
        let source_uri = self.file_uri(part, record, PartFile::Data(index))?;
        let whole = ReaderObjectRef { range: None, source_uri, sha256: data.sha256.clone(), size_bytes: data.bytes };
        let whole_lease = if self.cache.is_local(&whole).await? { Some(self.cache.ensure_local(&[whole]).await?) } else { None };
        let path = whole_lease.as_ref().map(|lease| lease.pinned_path(&data.sha256))
            .or_else(|| self.local_file_path(part, record, PartFile::Data(index)));
        if let Some(path) = path {
            for object in refs {
                match self.cache.warm_local(object, &path).await {
                    Ok(()) => {},
                    Err(crate::reader_object_cache::ReaderCacheError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {},
                    Err(crate::reader_object_cache::ReaderCacheError::Integrity(_)) => {},
                    Err(e) if e.retryable() => {},
                    Err(e) => return Err(e.into()),
                }
            }
        }
        self.range_objects.lock().expect("range object ledger").entry(part.part_id.clone()).or_default()
            .extend(refs.iter().map(|object| object.sha256.clone()));
        Ok(())
    }

    /// An Arrow-compatible reader whose omitted byte ranges fail closed.
    /// The caller must include the footer and all leaves of its projection.
    pub async fn range_reader(&self, part: &PartRef, index: usize, selected: &[usize])
        -> Result<Option<LeasedRangeReader>> {
        let Some(ranges) = self.data_ranges(part, index).await? else { return Ok(None) };
        let record = self.record(part).await?;
        let lease = self.lease_data_ranges(part, &record, index, &ranges, selected).await?;
        let mut chunks = BTreeMap::new();
        for selected in selected {
            let range = ranges.get(*selected).context("range index out of bounds")?;
            chunks.insert(range.offset, (range.bytes, lease.pinned_path(&range.sha256)));
        }
        Ok(Some(LeasedRangeReader { bytes: record.files.data[index].bytes, chunks, _lease: lease }))
    }

    /// Lease independently authenticated column chunks or the footer. Legacy
    /// records return None so callers must use the verified whole-file path.
    /// A caller can select indices, never supply its own offsets or digests.
    pub async fn ensure_data_ranges(
        &self, part: &PartRef, index: usize, selected: &[usize],
    ) -> Result<Option<ReaderCacheLease>> {
        let record = self.record(part).await?;
        let Some(ranges) = self.data_ranges(part, index).await? else { return Ok(None) };
        Ok(Some(self.lease_data_ranges(part, &record, index, &ranges, selected).await?))
    }

    async fn lease_data_ranges(
        &self, part: &PartRef, record: &ProvenanceRecord, index: usize,
        ranges: &[crate::parts::parquet_ranges::ParquetRangeDigest], selected: &[usize],
    ) -> Result<ReaderCacheLease> {
        let selected = selected.iter().map(|at| ranges.get(*at).context("Parquet range index out of bounds"))
            .collect::<Result<Vec<_>>>()?;
        let refs = self.range_refs(part, record, index, selected.into_iter())?;
        self.import_ranges(part, record, index, &refs).await?;
        Ok(self.cache.ensure_local(&refs).await?)
    }

    /// NAN-3801: the verified owner-signed count record of `part`, if one
    /// is stored. Positive answers are kept per part (the record binds the
    /// part's provenance, so a memo hit is re-bound to the live ref);
    /// absences are re-checked after [`COUNT_RECORD_NEGATIVE_TTL`]. A record
    /// that does not verify is an error (never count authority).
    pub(super) async fn signed_count_record(&self, part: &PartRef) -> Result<Option<Arc<crate::parts::count_record::CountRecord>>> {
        use crate::parts::count_record::{SignedCountRecord, COUNT_RECORD_FILE, MAX_SIGNED_COUNT_RECORD_BYTES};
        let cached = self.count_records.lock().ok().and_then(|memo| memo.get(&part.part_id).cloned());
        match cached {
            Some((Some(record), _)) => {
                record.binds(part, &self.tenant_id)?;
                return Ok(Some(record));
            }
            Some((None, checked)) if checked.elapsed() < COUNT_RECORD_NEGATIVE_TTL => return Ok(None),
            _ => {}
        }
        let key = self.keys_for(part)?.file(COUNT_RECORD_FILE);
        let found = match self.store.get(&key).await? {
            None => None,
            Some(bytes) if bytes.len() > MAX_SIGNED_COUNT_RECORD_BYTES => bail!("count record of part {} exceeds its bound", part.part_id),
            Some(bytes) => Some(Arc::new(SignedCountRecord::verify_bytes(&bytes, part, &self.tenant_id, &self.keys)?.record)),
        };
        if let Ok(mut memo) = self.count_records.lock() {
            if memo.len() >= COUNT_RECORD_MEMO_ENTRIES {
                memo.clear();
            }
            memo.insert(part.part_id.clone(), (found.clone(), std::time::Instant::now()));
        }
        Ok(found)
    }

    /// Prune only after the complete signed partial has been digest verified.
    /// The lease pins every byte consulted by Parquet statistics and decoding.
    pub(super) async fn entity_count_point_reader(
        &self, part: &PartRef, record: &ProvenanceRecord, kind: usize, value: &str,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<Option<(std::fs::File, Vec<usize>, ReaderCacheLease, tokio::sync::OwnedSemaphorePermit)>> {
        anyhow::ensure!(record.tenant_id == self.tenant_id, "count partial tenant differs");
        let Some(partial) = record.files.partials.iter().find(|p| p.kind == PartialKind::EntityRanges) else { return Ok(None) };
        let uri = self.file_uri(part, record, PartFile::Partial(PartialKind::EntityRanges))?;
        let object = ReaderObjectRef { range: None, source_uri: uri, sha256: partial.sha256.clone(), size_bytes: partial.bytes };
        self.entity_count_point_object(object, kind, value, permit).await.map(Some)
    }

    /// [`Self::entity_count_point_reader`] over a verified count record's
    /// count file (NAN-3801): the same v2 layout and the same pruning.
    pub(super) async fn entity_count_record_reader(
        &self, part: &PartRef, record: &crate::parts::count_record::CountRecord, kind: usize, value: &str,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(std::fs::File, Vec<usize>, ReaderCacheLease, tokio::sync::OwnedSemaphorePermit)> {
        record.binds(part, &self.tenant_id)?;
        let key = self.keys_for(part)?.file(&record.file.name);
        let object = ReaderObjectRef { range: None, source_uri: format!("s3://{}/{}", self.bucket, key),
            sha256: record.file.sha256.clone(), size_bytes: record.file.bytes };
        self.entity_count_point_object(object, kind, value, permit).await
    }

    async fn entity_count_point_object(
        &self, object: ReaderObjectRef, kind: usize, value: &str, permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(std::fs::File, Vec<usize>, ReaderCacheLease, tokio::sync::OwnedSemaphorePermit)> {
        use crate::parts::entity_counts::{V2_COVERAGE_PATH, V2_PATH};
        use anyhow::ensure;
        let lease = self.hydrate_object(&object).await?;
        let path = lease.pinned_path(&object.sha256);
        let value = value.to_owned();
        let memo = self.count_footers.clone();
        let digest = object.sha256.clone();
        tokio::task::spawn_blocking(move || -> Result<_> {
            let reader = std::fs::File::open(&path)?;
            let footer = memo.lock().ok().and_then(|memo| memo.get(&digest).cloned());
            let footer = match footer { Some(footer) => footer, None => count_footer(&path)? };
            let metadata = parquet::file::metadata::ParquetMetaDataReader::decode_metadata(&footer)?;
            remember_count_footer(&memo, digest, footer);
            let mut prefix = serde_json::to_string(&(kind, &value))?.into_bytes();
            prefix.pop(); prefix.push(b',');
            let mut upper = prefix.clone(); upper.push(255);
            let intersects = |column: &parquet::file::metadata::ColumnChunkMetaData, lo: &[u8], hi: &[u8]| {
                match column.statistics() {
                    Some(stats) if stats.min_is_exact() && stats.max_is_exact() => {
                        match (stats.min_bytes_opt(), stats.max_bytes_opt()) {
                            (Some(min), Some(max)) => min <= hi && max >= lo,
                            _ => true,
                        }
                    },
                    _ => true,
                }
            };
            ensure!(metadata.file_metadata().schema_descr().columns().iter().map(|c| c.path().string()).collect::<Vec<_>>() == ["path", "value", "first_time", "last_time", "events"], "unexpected count schema");
            let groups = metadata.row_groups().iter().enumerate().filter_map(|(i, group)| {
                let coverage = intersects(group.column(0), V2_COVERAGE_PATH.as_bytes(), V2_COVERAGE_PATH.as_bytes());
                let count = intersects(group.column(0), V2_PATH.as_bytes(), V2_PATH.as_bytes())
                    && intersects(group.column(1), &prefix, &upper);
                (coverage || count).then_some(i)
            }).collect::<Vec<_>>();
            ensure!(groups.iter().try_fold(0_i64, |sum, &g| sum.checked_add(metadata.row_group(g).total_byte_size()))
                .is_some_and(|bytes| bytes <= 8 * 1024 * 1024), "count groups exceed point memory envelope");
            Ok((reader, groups, lease, permit))
        }).await?
    }

    /// Retained for callers using the former in-place verification API.
    /// ReaderObjectCache now owns durable verification proofs.
    pub fn with_state_dir(self, _dir: &std::path::Path) -> Self { self }

    /// Compatibility telemetry: writer files are no longer verified in place.
    pub fn verified_in_place_bytes(&self) -> u64 { 0 }

    /// Use writer-local files as optional sources for verified reader admission.
    pub fn with_local_root(mut self, root: Option<PathBuf>) -> Self {
        self.local_root = root;
        self
    }
}

/// NAN-3801: how long an absent count record stays absent for a reader.
const COUNT_RECORD_NEGATIVE_TTL: std::time::Duration = std::time::Duration::from_secs(300);
const COUNT_RECORD_MEMO_ENTRIES: usize = 65_536;

// Bound optional footer bytes separately from whole sidecar leases.
const COUNT_FOOTER_BYTES: usize = 16 * 1024 * 1024;
fn remember_count_footer(memo: &Mutex<BTreeMap<String, Vec<u8>>>, digest: String, footer: Vec<u8>) {
    if let Ok(mut memo) = memo.lock() {
        if memo.values().map(|v| v.len() + 256).sum::<usize>() + footer.len() + 256 > COUNT_FOOTER_BYTES {
            memo.clear();
        }
        memo.insert(digest, footer);
    }
}
fn count_footer(path: &std::path::Path) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut reader = std::fs::File::open(path)?;
    let bytes = reader.metadata()?.len();
    anyhow::ensure!(bytes >= 8, "short count footer");
    reader.seek(SeekFrom::End(-8))?;
    let mut tail = [0_u8; 8];
    reader.read_exact(&mut tail)?;
    let length = u32::from_le_bytes(tail[..4].try_into()?) as usize;
    anyhow::ensure!(&tail[4..] == b"PAR1" && length <= 8 * 1024 * 1024 && length as u64 <= bytes - 8,
        "count footer exceeds envelope");
    reader.seek(SeekFrom::End(-8 - length as i64))?;
    let mut footer = vec![0; length];
    reader.read_exact(&mut footer)?;
    Ok(footer)
}
fn count_coverage(footer: &[u8]) -> Result<u8> {
    let metadata = parquet::file::metadata::ParquetMetaDataReader::decode_metadata(footer)?;
    Ok(metadata.file_metadata().key_value_metadata().and_then(|items| {
        items.iter().find_map(|item| {
            let version = if item.key == crate::parts::entity_counts::V2_COVERAGE_PATH { 128 }
                else if item.key == crate::parts::entity_counts::COVERAGE_PATH { 0 }
                else { return None };
            let mask = item.value.as_deref()?.parse::<u8>().ok()?;
            (mask < (1 << crate::parts::entity_counts::KINDS.len())).then_some(mask | version)
        })
    }).unwrap_or(0))
}

/// Leased, verified chunks with their original file offsets. No sparse-file
/// zero fill: attempts to read a column that was not fetched return an error.
pub struct LeasedRangeReader {
    bytes: u64,
    chunks: BTreeMap<u64, (u64, PathBuf)>,
    _lease: ReaderCacheLease,
}

impl parquet::file::reader::Length for LeasedRangeReader {
    fn len(&self) -> u64 { self.bytes }
}

impl parquet::file::reader::ChunkReader for LeasedRangeReader {
    type T = std::io::Take<std::fs::File>;
    fn get_read(&self, start: u64) -> parquet::errors::Result<Self::T> {
        use std::io::{Read, Seek, SeekFrom};
        let (offset, (bytes, path)) = self.chunks.range(..=start).next_back()
            .ok_or_else(|| parquet::errors::ParquetError::General("range was not authenticated".into()))?;
        let within = start - offset;
        if within >= *bytes {
            return Err(parquet::errors::ParquetError::General("range was not fetched".into()));
        }
        let mut file = std::fs::File::open(path)?;
        file.seek(SeekFrom::Start(within))?;
        Ok(file.take(bytes - within))
    }
    fn get_bytes(&self, start: u64, length: usize) -> parquet::errors::Result<bytes::Bytes> {
        use std::io::Read;
        let mut reader = self.get_read(start)?;
        if length as u64 > reader.limit() {
            return Err(parquet::errors::ParquetError::General("read crosses authenticated range".into()));
        }
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes)?;
        Ok(bytes.into())
    }
}

/// Stream a local file in 4 MiB chunks (bounded memory at any file size).
pub async fn stream_local_file(
    path: &std::path::Path,
    sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await.with_context(|| format!("open part file {}", path.display()))?;
    let mut buffer = vec![0_u8; 4 * 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        sink(&buffer[..read])?;
    }
}

/// Stream a bounded local range without reading the other columns.
pub async fn stream_local_range(
    path: &std::path::Path, range: Option<std::ops::Range<u64>>,
    sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
) -> Result<()> {
    let Some(range) = range else { return stream_local_file(path, sink).await };
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(path).await?;
    let mut remaining = range.end.checked_sub(range.start).context("invalid read range")?;
    file.seek(std::io::SeekFrom::Start(range.start)).await?;
    let mut buffer = vec![0; 64 * 1024];
    while remaining > 0 {
        let take = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..take]).await?;
        sink(&buffer[..take])?;
        remaining -= take as u64;
    }
    Ok(())
}

/// A [`ReaderObjectSource`] over a part-log [`ObjectStore`] (tests, labs).
/// With `local_root` (the store's directory) it streams files instead of
/// reading whole objects into memory.
pub struct StoreObjectSource {
    bucket: String,
    store: Arc<dyn ObjectStore>,
    local_root: Option<PathBuf>,
}

impl StoreObjectSource {
    pub fn new(bucket: &str, store: Arc<dyn ObjectStore>) -> Self {
        Self { bucket: bucket.to_string(), store, local_root: None }
    }

    /// Stream from the directory of a [`LocalObjectStore`].
    pub fn local(bucket: &str, store: Arc<dyn ObjectStore>, root: PathBuf) -> Self {
        Self { bucket: bucket.to_string(), store, local_root: Some(root) }
    }
}

#[async_trait::async_trait]
impl ReaderObjectSource for StoreObjectSource {
    async fn stream_object(
        &self,
        object: &ReaderObjectRef,
        sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
    ) -> anyhow::Result<()> {
        let (bucket, key) = crate::hot_tail_cache::parse_s3_uri(&object.source_uri)?;
        if bucket != self.bucket {
            bail!("part object is outside the tenant bucket");
        }
        if let Some(root) = &self.local_root {
            return stream_local_range(&LocalObjectStore::new(root)?.path(key)?, object.range.clone(), sink).await;
        }
        let bytes = match &object.range {
            Some(range) => self.store.get_range(key, range.clone()).await?,
            None => self.store.get(key).await?,
        }.context("part object is missing (part object vanished)")?;
        for chunk in bytes.chunks(4 * 1024 * 1024) {
            sink(chunk)?;
        }
        Ok(())
    }
}

/// A read-only [`ObjectStore`] over the tenant's R2 bucket (OpenDAL, the
/// read-only credential). Writes and LIST are refused: the query process
/// never writes and never lists.
pub struct R2ReadStore {
    authority: std::sync::Arc<super::credentials::R2ReadAuthority>,
}

impl R2ReadStore {
    pub fn new(authority: std::sync::Arc<super::credentials::R2ReadAuthority>) -> Self {
        Self { authority }
    }

    async fn read(operator: &opendal::Operator, key: &str) -> opendal::Result<Option<Vec<u8>>> {
        match operator.read(key).await {
            Ok(buffer) => Ok(Some(buffer.to_vec())),
            Err(error) if error.kind() == opendal::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[async_trait::async_trait]
impl ObjectStore for R2ReadStore {
    async fn get_range(&self, key: &str, range: std::ops::Range<u64>) -> Result<Option<Vec<u8>>> {
        use super::credentials::CredentialStale;
        let bytes = range.end.checked_sub(range.start).context("invalid object range")?;
        if bytes == 0 || bytes > crate::parts::format::MAX_OBJECT_BYTES { bail!("invalid object range size") }
        let installed = self.authority.current();
        let read = |operator: opendal::Operator, range: std::ops::Range<u64>| async move {
            match operator.read_with(key).range(range).await {
                Ok(buffer) => Ok(Some(buffer.to_vec())),
                Err(error) if error.kind() == opendal::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        };
        match read(installed.operator.clone(), range.clone()).await {
            Err(error) if error.kind() == opendal::ErrorKind::PermissionDenied => {
                let Some(next) = self.authority.recover(installed.generation).await else {
                    return Err(CredentialStale(error.to_string()).into());
                };
                match read(next.operator.clone(), range).await {
                    Err(error) if error.kind() == opendal::ErrorKind::PermissionDenied => Err(CredentialStale(error.to_string()).into()),
                    other => other.map_err(Into::into),
                }
            }
            other => other.map_err(Into::into),
        }
    }

    /// A `PermissionDenied` (expired credential, NAN-3017) asks for a
    /// refresh and retries once on the refreshed operator; still refused, it
    /// is [`super::credentials::CredentialStale`] (a retryable 503).
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        use super::credentials::CredentialStale;
        let installed = self.authority.current();
        match Self::read(&installed.operator, key).await {
            Err(error) if error.kind() == opendal::ErrorKind::PermissionDenied => {
                let Some(next) = self.authority.recover(installed.generation).await else {
                    return Err(CredentialStale(error.to_string()).into());
                };
                match Self::read(&next.operator, key).await {
                    Err(error) if error.kind() == opendal::ErrorKind::PermissionDenied => Err(CredentialStale(error.to_string()).into()),
                    other => other.map_err(Into::into),
                }
            }
            other => other.map_err(Into::into),
        }
    }
    async fn put_if_absent(&self, _key: &str, _bytes: &[u8]) -> Result<bool> {
        bail!("the query process holds read-only credentials")
    }
    async fn put(&self, _key: &str, _bytes: &[u8]) -> Result<()> {
        bail!("the query process holds read-only credentials")
    }
    async fn delete(&self, _key: &str) -> Result<()> {
        bail!("the query process holds read-only credentials")
    }
    async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
        bail!("the query process never lists (contract section 8)")
    }
}

/// The cache key-prefix fence for a tenant's parts.
pub fn parts_key_prefix(tenant_id: &str) -> Result<String> {
    crate::parts::format::validate_tenant_uuid(tenant_id)?;
    Ok(format!("{}/tenant={tenant_id}/parts", crate::parts::format::PARTS_ROOT))
}

#[cfg(test)]
mod range_tests {
    use super::*;
    use crate::parts::provenance::tests::{sample_record, signer, TENANT};
    use crate::parts::provenance::{FileDigest, PartSigner};
    use crate::reader_object_cache::ReaderObjectCacheSettings;
    use arrow_array::{RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use parquet::arrow::{ArrowWriter, ProjectionMask};
    use parquet::file::reader::ChunkReader;

    async fn count_point_fixture(parts: usize, cardinality: usize) {
        use crate::part_ingest::partials::{EntityRangeRow, PartialRow};
        use crate::parts::entity_counts::{Index, V2_PATH, V2_COVERAGE_PATH};
        use crate::parts::provenance::PartialDigest;
        use futures::StreamExt;
        let root = tempfile::tempdir().unwrap();
        let source_root = root.path().join("source");
        let store = Arc::new(LocalObjectStore::new(&source_root).unwrap());
        let signer = signer(7);
        let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
            root: root.path().join("cache"), max_bytes: 8_u64 << 30, query_max_bytes: 32 << 20,
            fetch_concurrency: 8, fetch_deadline: std::time::Duration::from_secs(60),
        }, TENANT, "bucket", &parts_key_prefix(TENANT).unwrap(),
            Arc::new(StoreObjectSource::local("bucket", store.clone(), source_root))).unwrap();
        let fetcher = PartFetcher::new(TENANT, "bucket", store.clone(), signer.trusted(), cache).unwrap();
        let gate = Arc::new(tokio::sync::Semaphore::new(8));
        let mut fixtures = Vec::new();
        for n in 0..parts {
            let hour = (n % 168) as i64;
            let time = hour * crate::parts::HOUR_US;
            let total = cardinality as u64 + n as u64;
            let mut rows = vec![EntityRangeRow { key: (V2_COVERAGE_PATH.into(), "1".into()),
                first_time: time, last_time: time, events: total }];
            for ip in 0..cardinality {
                let value = format!("10.{}.{}.{}", ip / 65536, (ip / 256) % 256, ip % 256);
                rows.push(EntityRangeRow { key: (V2_PATH.into(), serde_json::to_string(&(0, value, Some("sysmon"), hour, 1)).unwrap()),
                    first_time: time, last_time: time, events: if ip == 1 { n as u64 + 1 } else { 1 } });
            }
            rows.sort_by(|a, b| a.key.cmp(&b.key));
            let file = root.path().join("fixture.parquet");
            let props = parquet::file::properties::WriterProperties::builder()
                .set_compression(parquet::basic::Compression::ZSTD(parquet::basic::ZstdLevel::try_new(6).unwrap()))
                .set_max_row_group_row_count(Some(256)).build();
            let mut writer = ArrowWriter::try_new(std::fs::File::create(&file).unwrap(), EntityRangeRow::schema(), Some(props)).unwrap();
            writer.append_key_value_metadata(parquet::file::metadata::KeyValue::new(V2_COVERAGE_PATH.into(), "1".to_string()));
            for chunk in rows.chunks(4096) { writer.write(&EntityRangeRow::to_batch(chunk).unwrap()).unwrap(); }
            writer.close().unwrap();
            let body = std::fs::read(&file).unwrap();
            let mut record = sample_record();
            record.part_id = PartId::parse(&format!("{}-9f86d081884c7d65", 1790330400123_u64 + n as u64)).unwrap();
            record.rows = total; record.min_time_us = time; record.max_time_us = time;
            record.files.partials = vec![
                PartialDigest { kind: PartialKind::EntityRanges, name: crate::parts::format::PARTIAL_ENTITY_RANGES_FILE.into(),
                    bytes: body.len() as u64, sha256: sha256_hex(&body), rows: rows.len() as u64 },
            ];
            let keys = PartKeys::new(TENANT, record.level, record.event_hour, &record.part_id).unwrap();
            store.put(&keys.file(crate::parts::format::PARTIAL_ENTITY_RANGES_FILE), &body).await.unwrap();
            let part = PartRef::from_record(&record, &"0".repeat(64), true);
            fixtures.push((part, record));
        }
        let started = std::time::Instant::now();
        futures::stream::iter(fixtures.iter().map(|(part, record)| async {
            let partial = &record.files.partials[0];
            let object = ReaderObjectRef { range: None,
                source_uri: fetcher.file_uri(part, record, PartFile::Partial(PartialKind::EntityRanges)).unwrap(),
                sha256: partial.sha256.clone(), size_bytes: partial.bytes };
            let lease = fetcher.hydrate_object(&object).await.unwrap();
            // Background reads require a settled, verified file stamp. Settle
            // the fixture without sleeping, then verify its changed stamp.
            std::fs::File::open(lease.pinned_path(&partial.sha256)).unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))).unwrap();
            drop(lease);
            fetcher.hydrate_object(&object).await.unwrap();
        })).buffer_unordered(8).collect::<Vec<_>>().await;
        let lease_time = started.elapsed();
        for (_, record) in &fixtures {
            let digest = &record.files.partials[0].sha256;
            assert_eq!(fetcher.count_footer_warmer(digest.clone())(), Some(129));
            assert!(fetcher.count_footers.lock().unwrap().contains_key(digest));
        }

        let decode_started = std::time::Instant::now();
        let indexes = futures::stream::iter(fixtures.iter().map(|(part, record)| async {
            let (reader, groups, lease, permit) = fetcher.entity_count_point_reader(part, record, 0, "10.0.0.1", gate.clone().acquire_owned().await.unwrap()).await.unwrap().unwrap();
            assert!(groups.len() <= 3, "point scan should select only coverage and value groups");
            let bounds = (record.rows, record.min_time_us, record.max_time_us);
            tokio::task::spawn_blocking(move || { let _lease = lease; let _permit = permit; Index::from_reader(reader, 0, Some("10.0.0.1".into()), Some(groups),
                bounds.0, bounds.1, bounds.2, None).unwrap().unwrap() }).await.unwrap()
        })).buffer_unordered(8).collect::<Vec<_>>().await;
        let decode_time = decode_started.elapsed();
        let cold = started.elapsed();
        let bytes = fetcher.cache().stats().fetched_bytes;
        let memo = super::super::entity_count::Memo::default();
        for (i, index) in indexes.into_iter().enumerate() { memo.answer(format!("{i}:0:10.0.0.1"), Some(index)); }
        let started = std::time::Instant::now();
        let sum: u64 = (0..parts).map(|i| memo.cached(&format!("{i}:0:10.0.0.1")).unwrap().unwrap()
            .count_from_index((0, 168 * crate::parts::HOUR_US), &[("src_endpoint.ip", "10.0.0.1")]).unwrap()).sum();
        let warm = started.elapsed();
        assert_eq!(sum, (parts * (parts + 1) / 2) as u64);
        println!("count point fixture: {parts} parts x {cardinality} IPs, cold {cold:?}, lease {lease_time:?}, local decode {decode_time:?}, warm {warm:?}, fetched {bytes} bytes");
        let (part, record) = &fixtures[0];
        let mut wrong = record.clone(); wrong.tenant_id = "other-tenant".into();
        assert!(fetcher.entity_count_point_reader(part, &wrong, 0, "10.0.0.1", gate.clone().acquire_owned().await.unwrap()).await.is_err());
        let mut corrupt = record.clone(); corrupt.files.partials[0].sha256 = "f".repeat(64);
        assert!(fetcher.entity_count_point_reader(part, &corrupt, 0, "10.0.0.1", gate.clone().acquire_owned().await.unwrap()).await.is_err());
    }

    #[tokio::test]
    async fn entity_count_point_verified_local_prunes_and_authenticates() { count_point_fixture(2, 1024).await; }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "local 1500-part x 50k-IP performance fixture"]
    async fn entity_count_point_local_scale() { count_point_fixture(1500, 50_000).await; }

    #[tokio::test]
    async fn signed_producer_object_is_a_reader_hit_and_retirement_waits_for_lease() {
        let root = tempfile::tempdir().unwrap();
        let source_root = root.path().join("source");
        let shared = root.path().join("shared");
        let store = Arc::new(LocalObjectStore::new(&source_root).unwrap());
        let body = b"signed producer data";
        let file = root.path().join("data");
        std::fs::write(&file, body).unwrap();
        let mut record = sample_record();
        record.files.data[0].sha256 = sha256_hex(body);
        record.files.data[0].bytes = body.len() as u64;
        let keys = PartKeys::new(TENANT, record.level, record.event_hour, &record.part_id).unwrap();
        let signer = signer(7);
        let signature = signer.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let signed = SignedProvenance::assemble(record.clone(), signature, &signer.trusted()).unwrap().to_bytes().unwrap();
        store.put(&keys.provenance(), &signed).await.unwrap();
        let part = PartRef::from_record(&record, &sha256_hex(&signed), true);
        crate::producer_cache::warm(&shared, &keys.file(&record.files.data[0].name), &file,
            &record.files.data[0].sha256, body.len() as u64, 4 << 20).unwrap();
        // No data object exists in the source store: any accidental GET fails.
        let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
            root: root.path().join("cache"), max_bytes: 4 << 20, query_max_bytes: 4 << 20,
            fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(5),
        }, TENANT, "bucket", &parts_key_prefix(TENANT).unwrap(),
            Arc::new(StoreObjectSource::local("bucket", store.clone(), source_root))).unwrap();
        let fetcher = PartFetcher::new(TENANT, "bucket", store.clone(), signer.trusted(), cache).unwrap().with_local_root(Some(shared.clone()));
        let local = fetcher.ensure_files(&[(part.clone(), PartFile::Data(0))]).await.unwrap();
        assert_eq!(local.lease.as_ref().unwrap().hits(), 1);
        assert_eq!(local.lease.as_ref().unwrap().misses(), 0);
        let path = local.files[0].path.clone();
        assert_eq!(std::fs::read(&path).unwrap(), body);
        fetcher.retire_removed(Some(&Default::default())).await.unwrap();
        assert!(path.exists(), "active query keeps the canonical path");
        drop(local);
        fetcher.retire_removed(None).await.unwrap();
        assert!(!path.exists(), "superseded input is evicted after release");
        // A modified signed reference cannot authorize the producer bytes.
        let mut wrong = part.clone();
        wrong.provenance_sha256 = "0".repeat(64);
        assert!(fetcher.record(&wrong).await.is_err());
        // Hydration reuses the verified record even after its bounded memo
        // entry is retired; neither provenance nor data GET may be required.
        store.delete(&keys.provenance()).await.unwrap();
        let object = ReaderObjectRef { range: None,
            source_uri: fetcher.file_uri(&part, &record, PartFile::Data(0)).unwrap(),
            sha256: record.files.data[0].sha256.clone(), size_bytes: body.len() as u64 };
        let lease = fetcher.hydrate_object(&object).await.unwrap();
        assert_eq!(lease.fetched_bytes(), 0);
        assert_eq!(std::fs::read(lease.pinned_path(&object.sha256)).unwrap(), body);
        assert_eq!(fetcher.cache.evict_unleased(vec![object.sha256.clone()]).await.unwrap(), vec![object.sha256.clone()]);
        drop(lease);
        assert!(fetcher.cache.evict_unleased(vec![object.sha256.clone()]).await.unwrap().is_empty());
        store.put(&keys.provenance(), &signed).await.unwrap();
        // Bit rot in the optional producer tier cannot poison healthy R2
        // bytes: fallback admission still verifies the signed digest.
        store.put(&keys.file(&record.files.data[0].name), body).await.unwrap();
        let producer = crate::producer_cache::object(&shared, &record.files.data[0].sha256).unwrap();
        std::fs::remove_file(&producer).unwrap();
        std::fs::write(&producer, vec![0; body.len()]).unwrap();
        let fallback = fetcher.ensure_files(&[(part, PartFile::Data(0))]).await.unwrap();
        assert_eq!(std::fs::read(&fallback.files[0].path).unwrap(), body);
        assert_eq!(fallback.lease.as_ref().unwrap().misses(), 1);
        assert_eq!(fetcher.cache().stats().integrity_failures, 1);
    }

    #[tokio::test]
    async fn authenticated_projection_matches_full_scan_without_fetching_payload() {
        let root = tempfile::tempdir().unwrap();
        let source_root = root.path().join("source");
        let store = Arc::new(LocalObjectStore::new(&source_root).unwrap());
        let file = root.path().join("fixture.parquet");
        let schema = Arc::new(Schema::new(vec![
            Field::new("nonindexed", DataType::Utf8, true),
            Field::new("ext", DataType::Utf8, true),
        ]));
        let wide = "0123456789abcdef".repeat(16_384);
        let rows = RecordBatch::try_new(schema.clone(), vec![
            Arc::new(StringArray::from(vec![Some("rare"), None])),
            Arc::new(StringArray::from(vec![format!("{{\"payload\":\"{wide}\"}}"), format!("{{\"payload\":\"{wide}x\"}}")]))
        ]).unwrap();
        let mut writer = ArrowWriter::try_new(std::fs::File::create(&file).unwrap(), schema, None).unwrap();
        writer.write(&rows).unwrap();
        writer.close().unwrap();
        let body = std::fs::read(&file).unwrap();
        let ranges = crate::parts::parquet_ranges::build(&file).unwrap();
        let manifest = serde_json::to_vec(&ranges).unwrap();
        let mut record = sample_record();
        record.files.data[0].bytes = body.len() as u64;
        record.files.data[0].sha256 = sha256_hex(&body);
        record.files.data[0].parquet_ranges = Some(FileDigest {
            name: "ranges-00000.json".into(), bytes: manifest.len() as u64, sha256: sha256_hex(&manifest),
        });
        let keys = PartKeys::new(TENANT, record.level, record.event_hour, &record.part_id).unwrap();
        store.put(&keys.file("data-00000.parquet"), &body).await.unwrap();
        store.put(&keys.file("ranges-00000.json"), &manifest).await.unwrap();
        let signer = signer(7);
        let signature = signer.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let signed = SignedProvenance::assemble(record.clone(), signature, &signer.trusted()).unwrap().to_bytes().unwrap();
        store.put(&keys.provenance(), &signed).await.unwrap();
        let part = PartRef::from_record(&record, &sha256_hex(&signed), true);
        let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
            root: root.path().join("cache"), max_bytes: 4 << 20, query_max_bytes: 4 << 20,
            fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(5),
        }, TENANT, "bucket", &parts_key_prefix(TENANT).unwrap(),
            Arc::new(StoreObjectSource::local("bucket", store.clone(), source_root))).unwrap();
        let mut fetcher = PartFetcher::new(TENANT, "bucket", store, signer.trusted(), cache).unwrap();
        let selected = ranges.iter().enumerate().filter_map(|(index, range)|
            (range.column.is_none() || range.column.as_deref() == Some("nonindexed")).then_some(index)).collect::<Vec<_>>();
        let sparse = fetcher.range_reader(&part, 0, &selected).await.unwrap().unwrap();
        let payload = ranges.iter().find(|range| range.column.as_deref() == Some("ext")).unwrap();
        assert!(sparse.get_bytes(payload.offset, 1).is_err(), "omitted bytes cannot become zero-filled data");
        let builder = ParquetRecordBatchReaderBuilder::try_new(sparse).unwrap();
        let projection = ProjectionMask::leaves(builder.parquet_schema(), [0]);
        let actual = builder.with_projection(projection).build().unwrap().next().unwrap().unwrap();
        let builder = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&file).unwrap()).unwrap();
        let projection = ProjectionMask::leaves(builder.parquet_schema(), [0]);
        let expected = builder.with_projection(projection).build().unwrap().next().unwrap().unwrap();
        assert_eq!(actual, expected);
        let stage1 = fetcher.cache().stats().fetched_bytes;
        assert!(stage1 * 10 < body.len() as u64, "predicate bytes {stage1}, full bytes {}", body.len());
        // Enable residency after the cold sparse scan. The payload ranges
        // are still absent; they must be supplied by the verified whole file.
        fetcher.hot_settings = Some(crate::local_hot_window::Settings {
            root: root.path().join("cache"), hours: 168, bytes_per_second: 1 << 20, reserve_bytes: None, max_bytes: crate::local_hot_window::DEFAULT_MAX_BYTES, schedule: Default::default(), persistent: false,
        });
        let whole = ReaderObjectRef { range: None, source_uri: fetcher.file_uri(&part, &record, PartFile::Data(0)).unwrap(), sha256: record.files.data[0].sha256.clone(), size_bytes: record.files.data[0].bytes };
        fetcher.cache.warm_local(&whole, &file).await.unwrap();
        fetcher.store().delete(&keys.file("data-00000.parquet")).await.unwrap();
        let before_hot_read = fetcher.cache.stats().fetched_bytes;
        let all = (0..ranges.len()).collect::<Vec<_>>();
        let complete = fetcher.range_reader(&part, 0, &all).await.unwrap().unwrap();
        let materialized = ParquetRecordBatchReaderBuilder::try_new(complete).unwrap().build().unwrap().next().unwrap().unwrap();
        assert_eq!(materialized, rows);
        assert_eq!(fetcher.cache.stats().fetched_bytes, before_hot_read, "local whole-file residency eliminates all range GETs");
        println!("signed range fixture: predicate {stage1} bytes vs whole {} bytes", body.len());
        // The first query after publication can use producer ranges before
        // the whole file has reached the reader tier; no R2 data exists.
        let shared = root.path().join("producer");
        crate::producer_cache::warm(&shared, &keys.file("data-00000.parquet"), &file,
            &record.files.data[0].sha256, body.len() as u64, 4 << 20).unwrap();
        fetcher.local_root = Some(shared);
        let mut remove = ranges.iter().map(|r| r.sha256.clone()).collect::<Vec<_>>();
        remove.push(record.files.data[0].sha256.clone());
        assert!(fetcher.cache.evict_unleased(remove).await.unwrap().is_empty());
        let producer_read = fetcher.range_reader(&part, 0, &all).await.unwrap().unwrap();
        let producer_rows = ParquetRecordBatchReaderBuilder::try_new(producer_read).unwrap().build().unwrap().next().unwrap().unwrap();
        assert_eq!(producer_rows, rows);
        assert_eq!(fetcher.cache.stats().fetched_bytes, before_hot_read);
        let mut legacy = record;
        legacy.part_id = PartId::parse("1790330400124-9f86d081884c7d65").unwrap();
        legacy.files.data[0].parquet_ranges = None;
        let signature = signer.sign(TENANT, std::slice::from_ref(&legacy)).await.unwrap().remove(0);
        let signed = SignedProvenance::assemble(legacy.clone(), signature, &signer.trusted()).unwrap().to_bytes().unwrap();
        let keys = PartKeys::new(TENANT, legacy.level, legacy.event_hour, &legacy.part_id).unwrap();
        fetcher.store().put(&keys.provenance(), &signed).await.unwrap();
        let legacy_ref = PartRef::from_record(&legacy, &sha256_hex(&signed), true);
        let before = fetcher.cache().stats().fetched_bytes;
        assert!(fetcher.range_reader(&legacy_ref, 0, &selected).await.unwrap().is_none());
        assert_eq!(fetcher.cache().stats().fetched_bytes, before, "legacy fallback never attempts an unauthenticated range");
    }
}
