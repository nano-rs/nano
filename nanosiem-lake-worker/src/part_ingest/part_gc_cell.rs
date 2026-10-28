// SPDX-License-Identifier: AGPL-3.0-or-later

//! The lean cell's sanctioned lake-part GC pass (`lean_part_gc_sanctioned_v1`).
//!
//! `part_gc_gate` decides WHETHER ingest may delete (the tenant's
//! `lake_part_delete_grant` from the credential exchange). This module is
//! the HOW for a lean cell: [`crate::lake_part_gc::run_pass`] over seams a
//! jailed cell can actually reach.
//!
//! - **Owner** `lake-part-deletes:authorize` and `lake-part-log:index` on the
//!   release-pinned owner origin of `part_signing.url` (the :8444 cell-sign
//!   listener), trusting only `part_signing.ca_file`, with the exchange's
//!   `lake_part_gc.owner_delete` bearer (scope `lake-parts:delete`, tenant +
//!   cell + role ingest). The owner has control `lake-part-deletes:attest`
//!   check the grant row, holds, retention and its complete part-log index
//!   before it signs a permit.
//! - **Worker** `/admin/retention/{capabilities,lake-part/prepare,lake-part/retire}`
//!   on the tenant Worker origin from `lake_part_gc.retention_authority`
//!   (live only behind `NANO_LAKE_PART_DELETE_ENABLED` + contract phase). The
//!   Worker verifies the owner signature, fences re-creation, deletes and
//!   answers an exact absence receipt; nothing else counts as a delete.
//! - **Planner input**: the verified part log (every live key and every
//!   adopted object is excluded) and a listing of `parts/` with etag, size and
//!   upload time on the existing `lake_part` credential.
//!
//! Neither seam holds an R2 delete credential. The pass runs on its OWN OS
//! thread and current-thread runtime ([`GcRuntime`]), never on the ingest
//! runtime: folding a long part log (tens of thousands of R2 GETs, parse and
//! SHA-256 each) on ingest's two workers starved the credential exchange
//! until bootstrap tokens and the owner-sign bearer expired (a lean test tenant,
//! 2026-09-29). Its reads are paced ([`ReadPacer`], default
//! [`DEFAULT_LOG_READS_PER_SECOND`]) and its verified log view is persisted
//! in the cell state dir ([`ViewStore`]) so a restart resumes from the last
//! verified entry instead of seq 0. One owned task continues bounded catch-up
//! slices independently of ingest's deletion cadence. Ingest polls completion
//! reports without starting another destructive pass. The route is
//! re-read from every credential refresh: a refresh without it, with a
//! disabled grant, or with an unparsable one makes every further call of an
//! in-flight pass fail before it reaches the owner or Worker.

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use reqwest::Url;
use zeroize::Zeroizing;

use super::cell::OwnerSignBearer;
use super::owner_tls::OwnerTlsClient;
use super::part_gc_gate::{LakePartDeleteGrant, PartObjectLister, SanctionedPartGc};
use super::r2_put::R2PartStore;
use crate::lake_part_gc::delete_control::{DELETE_CONTROL_CONTRACT, DELETE_CONTROL_SCHEMA_VERSION};
use crate::lake_part_gc::store_reader::error_code;
use crate::lake_part_gc::index::{IndexRequest, IndexSyncOutcome};
use crate::lake_part_gc::index::{CheckpointClaim, VerifiedEntryBytes};
use crate::lake_part_gc::{
    GcPolicy, LakePartLogView, IndexStatus, LakePartDeleteAuthority, LakePartDeletePermit, LakePartDeleteReceipt,
    LakePartDeleteRequest, LakePartGcState, LakePartIndexClient, LakePartRefusal, ListedPartObject, PartLogReader,
    PassInput, PassReport, AUTHORIZE_PATH, INDEX_PATH, OPERATION, WORKER_CAPABILITIES_PATH, WORKER_PREPARE_PATH,
    WORKER_RETIRE_PATH,
};
use crate::parts::part_log::PartRef;
use crate::parts::provenance::ProvenanceRecord;

/// The cell feature that advertises this wiring.
pub const FEATURE: &str = "lean_part_gc_sanctioned_v1";
/// Scope of the owner bearer for authorize + index.
pub const OWNER_DELETE_SCOPE: &str = "lake-parts:delete";
/// Most requests one pass plans (each costs an owner and two Worker calls).
pub const MAX_REQUESTS_PER_PASS: usize = 512;
/// A bearer this close to expiry is not presented.
const BEARER_SKEW: chrono::Duration = chrono::Duration::seconds(30);
const OWNER_TIMEOUT: Duration = Duration::from_secs(30);
const WORKER_TIMEOUT: Duration = Duration::from_secs(30);
const AUTHORIZE_REQUEST_LIMIT: usize = 64 * 1024;
const INDEX_REQUEST_LIMIT: usize = 8 * 1024 * 1024;
const RESPONSE_LIMIT: usize = 1024 * 1024;
/// Default ceiling on the pass's part-store reads (log entries, checkpoints,
/// provenance), per second. 30k entries fold in ~5 min, once: the view is
/// persisted, so later passes read only new entries.
pub const DEFAULT_LOG_READS_PER_SECOND: u32 = 100;
/// Highest rate an exchange `policy.log_reads_per_second` may set.
pub const MAX_LOG_READS_PER_SECOND: u32 = 200;
/// Yield to the GC runtime every this many reads.
const READS_PER_YIELD: u64 = 32;
/// Persist the folded view at least every this many new entries.
pub const VIEW_PERSIST_EVERY: u64 = crate::lake_part_gc::executor::MAX_LOG_ENTRIES_PER_PASS;
/// Cooperative CPU/time and input budgets for each catch-up slice.
const CATCH_UP_SLICE: Duration = Duration::from_secs(2);
const CATCH_UP_BYTES: usize = 8 * 1024 * 1024;
const CATCH_UP_YIELD: Duration = Duration::from_millis(10);
const LOG_READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CATCH_UP_RETRIES: u32 = 3;
const MAX_VIEW_BYTES: u64 = 128 * 1024 * 1024;
const MAX_VIEW_PARTS: usize = 262_144;
const READ_AHEAD_WINDOW: usize = 8;
// Per slot: a capped body, one transport chunk, and OpenDAL's final Vec copy.
const RAW_SLOT_BYTES: usize = 3 * crate::parts::format::MAX_LOG_OBJECT_BYTES;
const RAW_READ_AHEAD_BUDGET: usize = READ_AHEAD_WINDOW * RAW_SLOT_BYTES;
// Only one parsed entry exists. The fixed LogEntry/PartRef structures and
// canonical reserialization are bounded by the 4 MiB input; no generic JSON
// values are retained in this format. This allowance excludes the LiveSet,
// which retains its existing independent part/snapshot bounds.
const PARSED_ENTRY_BUDGET: usize = 32 * 1024 * 1024;
/// One bounded eligible set from a complete scan, owned by the catch-up task. New objects are
/// deferred; every candidate still uses the current complete log and authority.
const LISTING_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const INVENTORY_LIFETIME: Duration = Duration::from_secs(30 * 60);
const TASK_LIFETIME: Duration = Duration::from_secs(60 * 60);
/// NAN-3495: control refused a delete because the part log moved past its
/// index while the pass ran (`lake_part_index_incomplete`). The task republishes
/// the index and retries at most this many times, with jittered exponential
/// delays, then ends normally (no back-off) and waits for the next schedule.
/// It used to retry after 10 ms without limit, re-authorizing every candidate
/// each time, until the owner's per-tenant limiter answered 429. Now each
/// retry costs at most one paced authorize (refused keys are remembered, and
/// authorizes are capped per minute), and the counter resets whenever a run
/// deletes, so a busy tenant's commits (one log entry every few seconds)
/// slow deletes down without ending the task after a handful of refusals.
/// The delay stays short (250 ms .. 2 s, jittered): a retry is one index
/// status read plus at most one push and one paced authorize, well inside the
/// owner's per-tenant index (600/min) and authorize (240/min cap) budgets.
const MAX_INDEX_INCOMPLETE_RETRIES: u32 = 32;
const INDEX_INCOMPLETE_RETRY_BASE: Duration = Duration::from_millis(250);
const INDEX_INCOMPLETE_RETRY_MAX: Duration = Duration::from_secs(2);
/// NAN-3495: while the pass is backing off (paused or failed), an index-only
/// task publishes the part log to control's index about this often (doubling
/// on consecutive index failures, up to [`INDEX_ONLY_MAX_INTERVAL`]). Index
/// publication no longer waits out the pass back-off (20 min .. 6 h).
const INDEX_ONLY_INTERVAL: Duration = Duration::from_secs(60);
const INDEX_ONLY_MAX_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// NAN-3459: at most one INFO (or WARN) GC progress line per this interval.
const PROGRESS_LOG_EVERY: Duration = Duration::from_secs(5 * 60);
/// NAN-3459: the progress line is a WARN while control's index trails the
/// part log by more than this (entry time), or has not been caught up for it.
const INDEX_LAG_WARN: Duration = Duration::from_secs(60 * 60);

struct Inventory {
    fence: InventoryFence,
    objects: Vec<ListedPartObject>,
    /// NAN-4162: deletes made and allowed across this inventory's passes.
    budget: crate::lake_part_gc::executor::InventoryBudget,
    checkpoint: Arc<tokio::sync::Mutex<Option<Option<CheckpointClaim>>>>,
}

/// NAN-4162: bounded passes (each at most `max_requests`) one listing feeds.
/// Paced by the executor's authorize pacer (240/min), so a full task of
/// 4 x 512 takes about 8.5 min, inside one pass interval and well inside the
/// inventory lifetime.
pub const PASSES_PER_INVENTORY: usize = 4;

/// Format tag of the persisted view.
pub const VIEW_FORMAT: &str = "nano.lake-part-gc-view.v1";

/// `lake_part_gc` in the ingest credential-exchange response (the platform
/// renders it only for images reporting [`FEATURE`], and only together with
/// an enabled `lake_part_delete_grant`). See LAKE-PART-GC-NANO-MAIN.md.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakePartGcAccess {
    pub schema_version: u8,
    /// Owner bearer for `lake-part-deletes:authorize` + `lake-part-log:index`.
    pub owner_delete: OwnerSignBearer,
    pub retention_authority: RetentionAuthorityAccess,
    /// Optional overrides of the GC policy (spec bounds enforced).
    #[serde(default)]
    pub policy: Option<GcPolicyOverrides>,
}

/// The tenant Worker's retention authority.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionAuthorityAccess {
    /// Exact HTTPS tenant Worker origin (`https://<tenant host>/`).
    pub url: String,
    /// The Worker's retention bearer. It authorizes nothing by itself: every
    /// prepare / retire must carry an owner-signed permit.
    pub token: String,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcPolicyOverrides {
    #[serde(default)]
    pub grace_seconds: Option<u64>,
    #[serde(default)]
    pub orphan_min_age_seconds: Option<u64>,
    /// The tenant's retention (30/90/180/365); absent plans no retention deletes.
    #[serde(default)]
    pub retention_days: Option<u64>,
    #[serde(default)]
    pub max_requests: Option<usize>,
    /// Part-store reads per second for the pass (1..=[`MAX_LOG_READS_PER_SECOND`]);
    /// absent = [`DEFAULT_LOG_READS_PER_SECOND`].
    #[serde(default)]
    pub log_reads_per_second: Option<u32>,
}

impl LakePartGcAccess {
    /// Parse and check. Any failure withholds the route (fail closed); it
    /// never fails the exchange.
    pub fn parse(value: &serde_json::Value) -> Result<Self> {
        let access: Self = serde_json::from_value(value.clone()).context("lake_part_gc")?;
        access.check()?;
        Ok(access)
    }

    /// Every rule [`Self::parse`] enforces.
    pub fn check(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "lake_part_gc schema_version {}", self.schema_version);
        ensure!(
            self.owner_delete.audience == "owner" && self.owner_delete.scope == OWNER_DELETE_SCOPE,
            "lake_part_gc owner bearer scope differs"
        );
        ensure!(!self.owner_delete.token.is_empty(), "lake_part_gc owner bearer is empty");
        ensure!(!self.retention_authority.token.is_empty(), "lake_part_gc retention token is empty");
        self.owner_expires_at()?;
        worker_origin(&self.retention_authority.url)?;
        self.policy()?;
        Ok(())
    }

    pub fn owner_expires_at(&self) -> Result<chrono::DateTime<chrono::Utc>> {
        Ok(chrono::DateTime::parse_from_rfc3339(&self.owner_delete.expires_at)
            .context("lake_part_gc owner bearer expires_at")?
            .with_timezone(&chrono::Utc))
    }

    pub fn policy(&self) -> Result<GcPolicy> {
        let o = self.policy.unwrap_or_default();
        let default = GcPolicy::default();
        let policy = GcPolicy {
            grace_seconds: o.grace_seconds.unwrap_or(default.grace_seconds),
            orphan_min_age_seconds: o.orphan_min_age_seconds.unwrap_or(default.orphan_min_age_seconds),
            retention_days: o.retention_days,
            max_requests: o.max_requests.unwrap_or(MAX_REQUESTS_PER_PASS).min(MAX_REQUESTS_PER_PASS),
        };
        policy.validate()?;
        self.log_reads_per_second()?;
        Ok(policy)
    }

    /// The pass's read pacing from `policy.log_reads_per_second`.
    pub fn log_reads_per_second(&self) -> Result<u32> {
        let rate = self.policy.and_then(|o| o.log_reads_per_second).unwrap_or(DEFAULT_LOG_READS_PER_SECOND);
        ensure!(
            (1..=MAX_LOG_READS_PER_SECOND).contains(&rate),
            "lake_part_gc policy.log_reads_per_second {rate} is outside 1..={MAX_LOG_READS_PER_SECOND}"
        );
        Ok(rate)
    }
}

/// Paces the pass's part-store reads to a rate and yields between batches,
/// so a long log fold never floods R2 or monopolizes a core.
pub struct ReadPacer {
    /// Reads per second; 0 = unpaced (tests).
    per_second: AtomicU32,
    next: tokio::sync::Mutex<Option<tokio::time::Instant>>,
    reads: AtomicU64,
}

impl ReadPacer {
    pub fn new(per_second: u32) -> Self {
        Self { per_second: AtomicU32::new(per_second), next: tokio::sync::Mutex::new(None), reads: AtomicU64::new(0) }
    }

    pub fn set_rate(&self, per_second: u32) {
        self.per_second.store(per_second, Ordering::Relaxed);
    }

    pub fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    /// Wait for `cost` read slots.
    pub async fn acquire(&self, cost: u32) {
        let count = self.reads.load(Ordering::Relaxed);
        if count / READS_PER_YIELD != (count + u64::from(cost)) / READS_PER_YIELD {
            tokio::task::yield_now().await;
        }
        let rate = self.per_second.load(Ordering::Relaxed);
        if rate > 0 {
            let step = Duration::from_secs_f64(f64::from(cost) / f64::from(rate));
            // Serialize grants, not future reservations. A cancelled wait drops
            // the lock; delayed wakes cannot release a burst of overdue slots.
            let mut next = self.next.lock().await;
            if let Some(at) = *next {
                tokio::time::sleep_until(at).await;
            }
            *next = Some(tokio::time::Instant::now() + step);
        }
        self.reads.fetch_add(u64::from(cost), Ordering::Relaxed);
    }
}

/// A [`PartLogReader`] whose every store read goes through a [`ReadPacer`].
pub struct PacedReader {
    inner: Arc<dyn PartLogReader>,
    pacer: Arc<ReadPacer>,
}

impl PacedReader {
    pub fn new(inner: Arc<dyn PartLogReader>, pacer: Arc<ReadPacer>) -> Self {
        Self { inner, pacer }
    }
}

#[async_trait]
impl PartLogReader for PacedReader {
    async fn read_ahead_bytes(&self, seq: u64) -> Result<Option<Vec<u8>>> {
        self.pacer.acquire(1).await;
        self.inner.read_ahead_bytes(seq).await
    }

    async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
        self.pacer.acquire(1).await;
        self.inner.verified_entry(seq).await
    }

    async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>> {
        // A list, the checkpoint and its entry.
        self.pacer.acquire(3).await;
        self.inner.newest_checkpoint().await
    }

    async fn verified_provenance(&self, part: &PartRef) -> Result<ProvenanceRecord> {
        self.pacer.acquire(1).await;
        self.inner.verified_provenance(part).await
    }
}

/// The persisted GC view: the genesis-folded [`LakePartLogView`] through its
/// head entry. Trusted again only after that head entry re-verifies against
/// the store with the same SHA-256 (the log is hash-chained, so the whole
/// prefix is then the one this view folded). Control re-attests every delete
/// against its own index regardless; this file only saves re-reading.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedView {
    format: String,
    tenant_uuid: String,
    view: LakePartLogView,
}

/// Where the cell keeps [`PersistedView`] (`<state_dir>/lake-part-gc/view.json`).
pub struct ViewStore {
    path: PathBuf,
    loaded: AtomicBool,
    dirty: AtomicBool,
    /// NAN-3495: the refused-key markers were loaded (or found absent).
    refused_loaded: AtomicBool,
    /// NAN-3495: the last save failed; retry it before extending the view.
    save_failed: AtomicBool,
    /// NAN-3495: when the view was last written (None: not yet this process).
    last_saved: std::sync::Mutex<Option<tokio::time::Instant>>,
    /// NAN-3495: least time between two writes of an extended view.
    save_every_ms: AtomicU64,
}

/// NAN-3495: the view (with every removed part since genesis) is tens of MB
/// on a busy tenant. Rewriting and fsyncing it at the end of every 2 s fold
/// slice made a genesis fold O(n^2): the load-test tenant's post-restart fold slowed from
/// 39 to ~20 entries/s as the view grew (29.5k entries, ~17 min). Write it at
/// most this often; a restart re-reads at most this much of the log.
pub const VIEW_SAVE_EVERY: Duration = Duration::from_secs(60);

/// Format tag of the persisted refused-key markers.
pub const REFUSED_FORMAT: &str = "nano.lake-part-gc-refused.v1";
/// Largest refused-key file read back.
const MAX_REFUSED_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct PersistedRefused {
    format: String,
    tenant_uuid: String,
    refused: crate::lake_part_gc::executor::RefusedKeys,
}

impl ViewStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("lake-part-gc").join("view.json"),
            loaded: AtomicBool::new(false),
            dirty: AtomicBool::new(false),
            refused_loaded: AtomicBool::new(false),
            save_failed: AtomicBool::new(false),
            last_saved: std::sync::Mutex::new(None),
            save_every_ms: AtomicU64::new(VIEW_SAVE_EVERY.as_millis() as u64),
        }
    }

    /// Whether an extended (dirty) view is written now: its first write in
    /// this process, or [`Self::save_every_ms`] after the last one.
    fn save_due(&self) -> bool {
        let every = Duration::from_millis(self.save_every_ms.load(Ordering::Relaxed));
        let last = *self.last_saved.lock().unwrap_or_else(|p| p.into_inner());
        last.is_none_or(|at| at.elapsed() >= every)
    }

    /// [`Self::save`], tracking failure (retried before the view grows) and
    /// the write time (throttling the next one).
    fn save_tracked(&self, tenant_uuid: &str, view: &LakePartLogView) -> Result<()> {
        self.save_failed.store(true, Ordering::SeqCst);
        self.save(tenant_uuid, view)?;
        self.save_failed.store(false, Ordering::SeqCst);
        self.dirty.store(false, Ordering::SeqCst);
        *self.last_saved.lock().unwrap_or_else(|p| p.into_inner()) = Some(tokio::time::Instant::now());
        Ok(())
    }

    /// NAN-3495: `<state_dir>/lake-part-gc/refused-keys.json`.
    pub fn refused_path(&self) -> PathBuf {
        self.path.with_file_name("refused-keys.json")
    }

    /// Load the durable per-key refusal markers once per process into `state`
    /// (only if nothing was remembered yet). A missing, foreign or unreadable
    /// file only means keys are asked about again.
    fn load_refused_once(&self, tenant_uuid: &str, state: &mut LakePartGcState) {
        if self.refused_loaded.swap(true, Ordering::SeqCst) || !state.refused_keys.is_empty() {
            return;
        }
        let path = self.refused_path();
        let loaded = (|| -> Result<Option<crate::lake_part_gc::executor::RefusedKeys>> {
            let file = match std::fs::File::open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            ensure!(file.metadata()?.len() <= MAX_REFUSED_BYTES, "refused-key file exceeds its byte budget");
            let persisted: PersistedRefused = serde_json::from_reader(std::io::BufReader::new(file))?;
            ensure!(persisted.format == REFUSED_FORMAT && persisted.tenant_uuid == tenant_uuid, "refused-key file is foreign");
            ensure!(persisted.refused.len() <= crate::lake_part_gc::executor::MAX_REFUSED_KEYS, "refused-key file exceeds its key budget");
            Ok(Some(persisted.refused))
        })();
        match loaded {
            Ok(Some(refused)) => {
                tracing::info!(keys = refused.len(), "lake-part GC loaded its refused-key markers");
                state.refused_keys = refused;
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(error = %format!("{error:#}"), "lake-part GC ignored an unreadable refused-key file"),
        }
    }

    /// Persist the markers atomically when they changed.
    fn save_refused(&self, tenant_uuid: &str, state: &mut LakePartGcState, now_ms: i64) {
        state.refused_keys.prune(now_ms);
        if !state.refused_keys.take_dirty() {
            return;
        }
        let saved = (|| -> Result<()> {
            let path = self.refused_path();
            let dir = path.parent().context("refused-key path has no parent")?;
            std::fs::create_dir_all(dir)?;
            #[derive(Serialize)]
            struct Borrowed<'a> {
                format: &'a str,
                tenant_uuid: &'a str,
                refused: &'a crate::lake_part_gc::executor::RefusedKeys,
            }
            let mut temp = tempfile::NamedTempFile::new_in(dir)?;
            serde_json::to_writer(std::io::BufWriter::new(temp.as_file_mut()),
                &Borrowed { format: REFUSED_FORMAT, tenant_uuid, refused: &state.refused_keys })?;
            temp.as_file().sync_all()?;
            temp.persist(&path).map_err(|error| error.error)?;
            Ok(())
        })();
        if let Err(error) = saved {
            tracing::warn!(error = %format!("{error:#}"), "lake-part GC could not persist its refused-key markers");
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self, tenant_uuid: &str) -> Result<Option<LakePartLogView>> {
        let file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("read persisted lake-part GC view"),
        };
        ensure!(
            file.metadata()?.len() <= MAX_VIEW_BYTES,
            "persisted GC view exceeds byte budget"
        );
        let persisted: PersistedView = serde_json::from_reader(std::io::BufReader::new(file))
            .context("parse persisted lake-part GC view")?;
        ensure!(
            persisted.view.part_count() <= MAX_VIEW_PARTS,
            "persisted GC view exceeds part budget"
        );
        ensure!(
            persisted.format == VIEW_FORMAT,
            "persisted view format {}",
            persisted.format
        );
        ensure!(
            persisted.tenant_uuid == tenant_uuid,
            "persisted view names another tenant"
        );
        ensure!(
            persisted.view.from_genesis(),
            "persisted view was not folded from genesis"
        );
        Ok(Some(persisted.view))
    }

    fn save(&self, tenant_uuid: &str, view: &LakePartLogView) -> Result<()> {
        use std::io::Write;
        let dir = self.path.parent().context("view path has no parent")?;
        std::fs::create_dir_all(dir)?;
        // Borrowed: no second copy of a large view while it is written.
        #[derive(Serialize)]
        struct Borrowed<'a> {
            format: &'a str,
            tenant_uuid: &'a str,
            view: &'a LakePartLogView,
        }
        let persisted = Borrowed {
            format: VIEW_FORMAT,
            tenant_uuid,
            view,
        };
        let mut temp = tempfile::NamedTempFile::new_in(dir)?;
        // Limit writes too: a failed save leaves the previous atomic snapshot intact.
        struct Limited<'a> {
            file: &'a mut std::fs::File,
            left: u64,
        }
        impl std::io::Write for Limited<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() as u64 > self.left {
                    return Err(std::io::Error::other("GC view exceeds byte budget"));
                }
                let written = self.file.write(bytes)?;
                self.left -= written as u64;
                Ok(written)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.file.flush()
            }
        }
        {
            let mut writer = std::io::BufWriter::new(Limited {
                file: temp.as_file_mut(), left: MAX_VIEW_BYTES,
            });
            serde_json::to_writer(&mut writer, &persisted)?;
            writer.flush()?;
        }
        temp.as_file_mut().flush()?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path).map_err(|error| error.error)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }
}

/// The GC pass's own OS thread and current-thread runtime. Nothing the pass
/// does (store reads, owner/Worker calls, parse, SHA-256, planning) runs on,
/// or registers I/O with, the ingest runtime. Dropping it stops the thread
/// and cancels a pass in flight.
pub struct GcRuntime {
    handle: tokio::runtime::Handle,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl GcRuntime {
    pub fn start() -> Result<Self> {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (handle_tx, handle_rx) = std::sync::mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("lake-part-gc".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = handle_tx.send(Err(error));
                        return;
                    }
                };
                let _ = handle_tx.send(Ok(runtime.handle().clone()));
                runtime.block_on(async move {
                    let _ = stopped.await;
                });
            })
            .context("spawn the lake-part GC thread")?;
        let handle = handle_rx.recv().context("lake-part GC thread exited")?.context("build the lake-part GC runtime")?;
        Ok(Self { handle, stop: Some(stop), thread: Some(thread) })
    }

    pub fn handle(&self) -> &tokio::runtime::Handle {
        &self.handle
    }
}

impl Drop for GcRuntime {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        // A replacement must not race an old task's synchronous snapshot write.
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The Worker origin: `https`, no credentials, path `/`, no query/fragment.
fn worker_origin(url: &str) -> Result<Url> {
    let url = Url::parse(url).context("retention authority URL")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "retention authority URL is not an exact HTTPS tenant origin"
    );
    Ok(url)
}

/// One delivered route: what the latest exchange carried.
struct Route {
    grant_enabled: bool,
    tenant_slug: String,
    owner_bearer: Zeroizing<String>,
    owner_expires_at: chrono::DateTime<chrono::Utc>,
    grant_expires_at: chrono::DateTime<chrono::Utc>,
    worker_origin: Url,
    worker_token: Zeroizing<String>,
    policy: GcPolicy,
    grant_revision: Option<String>,
}

impl Route {
    fn same_inventory_contract(&self, other: &Self) -> bool {
        self.grant_enabled
            && other.grant_enabled
            && self.tenant_slug == other.tenant_slug
            && self.worker_origin == other.worker_origin
            && self.policy == other.policy
            && self.grant_revision == other.grant_revision
    }
}

/// How the cell builds its pass.
pub struct CellPartGcWiring {
    pub tenant_uuid: String,
    /// `part_signing.url`: its origin is the owner's cell listener.
    pub owner_url: String,
    /// `part_signing.ca_file`: the only trust root for the owner.
    pub owner_ca_file: Option<std::path::PathBuf>,
    pub reader: Arc<dyn PartLogReader>,
    pub lister: Arc<dyn PartObjectLister>,
    /// Persist the folded view under this dir and resume from it (producer
    /// parts: its sibling `parts`). Unguarded constructor only; the guarded
    /// one takes its state and view dirs as arguments.
    pub state_dir: Option<std::path::PathBuf>,
    /// Worker HTTP client override (tests and private-CA Workers only);
    /// `None` uses the platform roots, HTTPS only.
    pub worker_http: Option<reqwest::Client>,
}

struct Shared {
    tenant_uuid: String,
    catalog: RwLock<Option<Arc<super::iceberg_export::lifecycle::TenantCatalog>>>,
    owner_tls: OwnerTlsClient,
    authorize_url: Url,
    index_url: Url,
    worker_http: reqwest::Client,
    /// The wired reader behind [`Self::pacer`].
    reader: Arc<dyn PartLogReader>,
    pacer: Arc<ReadPacer>,
    lister: Arc<dyn PartObjectLister>,
    views: Option<ViewStore>,
    producer_parts: Option<PathBuf>,
    route: RwLock<Option<Arc<Route>>>,
    route_epoch: AtomicU64,
    /// The grant is enabled and the route delivered, as of the latest refresh.
    enabled: AtomicBool,
    refreshing: AtomicBool,
    folded_prefix: std::sync::Mutex<Option<FoldedPrefix>>,
    now: Arc<dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync>,
    generation: tokio::sync::watch::Sender<u64>,
    transport_observation: Arc<crate::r2_ops::GcHttpObservation>,
    /// advance_view's read-ahead window, kept across bounded slices (0 = unset).
    fold_window: std::sync::atomic::AtomicUsize,
    /// NAN-3459: index catch-up progress for the rate-limited progress line.
    progress: std::sync::Mutex<GcProgress>,
    /// NAN-3495: the view's latest fold slice reached the log head.
    view_complete: AtomicBool,
    /// NAN-3495: one index publisher at a time (a pass or index-only), so
    /// neither races the other into a 409 gap / chain disagreement.
    publish_lock: Arc<tokio::sync::Mutex<()>>,
    /// NAN-3495: entries index-only tasks published (pass reports carry
    /// their own; these never reach a pass report).
    index_only_indexed: AtomicU64,
    /// NAN-3810: the ingest log writer's receipted appends; the index sync's
    /// `receipted_through` watermark.
    receipted_appends: Arc<crate::lake_part_gc::index::ReceiptedAppends>,
    /// NAN-4188: index publications the follower started (one per receipted
    /// append, coalesced to [`FOLLOW_MIN_GAP_MS`]).
    follower_publications: AtomicU64,
    /// NAN-4188: catch-up stops on control's NL009 (`lake_part_index_incomplete`).
    index_incomplete_total: AtomicU64,
    /// NAN-4567: earliest start of the next bronze quarantine expiry pass.
    quarantine_due_ms: std::sync::atomic::AtomicI64,
}

/// What the GC progress line reports (NAN-3459). Process-local.
struct GcProgress {
    logged_at: Option<tokio::time::Instant>,
    /// When control's index was last seen caught up to the view head (or
    /// when this process first observed it, before that).
    caught_up_at: tokio::time::Instant,
    index_head_seq: Option<u64>,
    index_head_ms: Option<i64>,
    /// `appended_at_ms` of the newest entry folded into the view.
    log_head_ms: Option<i64>,
    deleted_total: u64,
    indexed_total: u64,
}

impl Default for GcProgress {
    fn default() -> Self {
        Self {
            logged_at: None,
            caught_up_at: tokio::time::Instant::now(),
            index_head_seq: None,
            index_head_ms: None,
            log_head_ms: None,
            deleted_total: 0,
            indexed_total: 0,
        }
    }
}

#[derive(Default)]
struct Runner {
    task: Option<tokio::task::JoinHandle<Result<PassReport>>>,
    /// NAN-3495: the index-only publication task, in its own slot: it runs
    /// beside a pass that is still folding its view (a fresh cell's genesis
    /// fold took ~25 min on the load-test tenant with the index frozen) and while the
    /// pass backs off.
    index_task: Option<tokio::task::JoinHandle<Result<PassReport>>>,
    /// Earliest start of the next index-only task (unix ms).
    next_index_ms: i64,
    /// NAN-3495: the delete gate scheduled a pass with a current route (the
    /// gate's grant is open); index-only publication runs only after that.
    armed: bool,
    /// Consecutive index-only tasks that failed or were refused.
    index_failures: u32,
    /// NAN-3495: the last pass backed off; start the next one at the poll
    /// that reaches `next_allowed_ms`, not at the first 10-min ingest
    /// schedule after it (which added up to 10 min: tenant-a's 20-min back-off
    /// from 13:05:38Z missed the 13:25 tick by seconds and ran at 13:35).
    resume_after_backoff: bool,
    /// Earliest start of the next pass after a back-off (unix ms).
    next_allowed_ms: i64,
    failures: u32,
    /// NAN-3459: the last task ended at its lifetime while still catching
    /// up; start the next one at the next poll, not the next 10-min schedule.
    resume_now: bool,
    /// NAN-4188: the receipted log seq the follower last published for.
    follow_through: Option<u64>,
    /// NAN-4188: earliest start of the next follower publication (unix ms).
    next_follow_ms: i64,
}

/// The sanctioned pass a lean cell wires into its delete gate.
pub struct CellSanctionedPartGc {
    shared: Arc<Shared>,
    state: Arc<tokio::sync::Mutex<LakePartGcState>>,
    runner: tokio::sync::Mutex<Runner>,
    runtime: GcRuntime,
}

impl CellSanctionedPartGc {
    pub fn new(wiring: CellPartGcWiring) -> Result<Self> {
        Self::new_inner(wiring, None, None)
    }

    /// The only unwrapped reader is built here over the exact guarded store.
    pub(crate) fn new_guarded(
        tenant_uuid: &str,
        owner_url: &str,
        owner_ca_file: Option<PathBuf>,
        store: Arc<R2PartStore>,
        trusted: crate::parts::provenance::TenantKeySet,
        state_dir: &Path,
        view_dir: Option<&Path>,
    ) -> Result<Self> {
        let reader = crate::lake_part_gc::StorePartLogReader::new(store.clone(), tenant_uuid, trusted)?.gc_private();
        Self::new_inner(CellPartGcWiring {
            tenant_uuid: tenant_uuid.to_string(),
            owner_url: owner_url.to_string(),
            owner_ca_file,
            reader: Arc::new(reader),
            lister: Arc::new(R2PartLister(store.clone())),
            state_dir: None,
            worker_http: None,
        }, Some((&store, state_dir)), view_dir)
    }

    /// NAN-4194: `view_dir` is taken here, not by a builder, because the
    /// guarded constructor hands the R2 store a weak reference to `Shared`;
    /// after that `Arc::get_mut` fails (it panicked every ingest role on T57).
    /// NAN-4195: every option of `Shared` is likewise set here, before it is
    /// shared; `tests/shared_state_builders_static_contract.rs` refuses a
    /// production `Arc::get_mut(..).expect(..)` builder.
    fn new_inner(wiring: CellPartGcWiring, store: Option<(&R2PartStore, &Path)>, view_dir: Option<&Path>) -> Result<Self> {
        ensure!(uuid::Uuid::parse_str(&wiring.tenant_uuid).is_ok(), "part GC tenant must be a uuid");
        let base = Url::parse(&wiring.owner_url).context("part_signing.url")?;
        let owner_tls = OwnerTlsClient::new(&wiring.owner_url, wiring.owner_ca_file.as_deref(), OWNER_TIMEOUT)?;
        let worker_http = match wiring.worker_http {
            Some(client) => client,
            None => reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(WORKER_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .https_only(true)
                .build()
                .context("build retention authority client")?,
        };
        // Guarded: the R2 state dir (view on `view_dir` when given).
        // Unguarded: the wiring's state dir, if any.
        let view_state: Option<(&Path, &Path)> = match store {
            Some((_, path)) => Some((view_dir.unwrap_or(path), path)),
            None => wiring.state_dir.as_deref().map(|path| (path, path)),
        };
        let pacer = Arc::new(ReadPacer::new(DEFAULT_LOG_READS_PER_SECOND));
        let reader = if store.is_some() {
            wiring.reader
        } else {
            Arc::new(PacedReader::new(wiring.reader, pacer.clone())) as Arc<dyn PartLogReader>
        };
        let shared = Arc::new(Shared {
            tenant_uuid: wiring.tenant_uuid,
            catalog: RwLock::new(None),
            owner_tls,
            authorize_url: base.join(AUTHORIZE_PATH)?,
            index_url: base.join(INDEX_PATH)?,
            worker_http,
            reader,
            pacer,
            lister: wiring.lister,
            views: view_state.map(|(view, _)| ViewStore::new(view)),
            producer_parts: view_state
                .and_then(|(_, state)| state.parent().map(|parent| parent.join("parts"))),
            route: RwLock::new(None),
            route_epoch: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            refreshing: AtomicBool::new(false),
            folded_prefix: std::sync::Mutex::new(None),
            now: Arc::new(chrono::Utc::now),
            generation: tokio::sync::watch::channel(0).0,
            transport_observation: Arc::new(crate::r2_ops::GcHttpObservation::default()),
            fold_window: std::sync::atomic::AtomicUsize::new(0),
            progress: std::sync::Mutex::new(GcProgress::default()),
            view_complete: AtomicBool::new(false),
            publish_lock: Arc::new(tokio::sync::Mutex::new(())),
            index_only_indexed: AtomicU64::new(0),
            follower_publications: AtomicU64::new(0),
            index_incomplete_total: AtomicU64::new(0),
            receipted_appends: Arc::default(),
            quarantine_due_ms: std::sync::atomic::AtomicI64::new(0),
        });
        if let Some((store, _)) = store {
            let weak = Arc::downgrade(&shared);
            store.guard_gc(Arc::new(crate::r2_ops::GcHttpGuard {
                pacer: shared.pacer.clone(),
                generation: shared.generation.clone(),
                observation: shared.transport_observation.clone(),
                current: Box::new(move || {
                    let shared = weak.upgrade().ok_or_else(|| {
                        opendal::Error::new(
                            opendal::ErrorKind::PermissionDenied,
                            "GC owner dropped",
                        )
                    })?;
                    let route = shared.current().map_err(|error| {
                        opendal::Error::new(
                            opendal::ErrorKind::PermissionDenied,
                            "GC route unavailable",
                        ).set_source(error)
                    })?;
                    let expiry = route
                        .grant_expires_at
                        .min(route.owner_expires_at - BEARER_SKEW);
                    (expiry - (shared.now)()).to_std().map_err(|_| {
                        opendal::Error::new(
                            opendal::ErrorKind::PermissionDenied,
                            "GC route expired",
                        )
                    })
                }),
            }))?;
        }
        Ok(Self {
            shared,
            state: Arc::new(tokio::sync::Mutex::new(LakePartGcState::genesis())),
            runner: tokio::sync::Mutex::new(Runner::default()),
            runtime: GcRuntime::start()?,
        })
    }

    /// NAN-4183: keep the folded view and the refused-key markers in `dir`
    /// (`<dir>/lake-part-gc/`) instead of the state dir. Tests only, on the
    /// unguarded constructor: production passes the view dir to
    /// [`Self::new_guarded`] (NAN-4194; `get_mut` fails once the R2 guard
    /// holds its weak reference).
    #[cfg(test)]
    pub(crate) fn with_view_dir(mut self, dir: &Path) -> Self {
        let shared = Arc::get_mut(&mut self.shared).expect("not shared yet");
        let every = shared.views.as_ref().map(|views| views.save_every_ms.load(Ordering::Relaxed));
        let views = ViewStore::new(dir);
        if let Some(every) = every {
            views.save_every_ms.store(every, Ordering::Relaxed);
        }
        shared.views = Some(views);
        self
    }

    /// Override the least time between view writes (tests; default
    /// [`VIEW_SAVE_EVERY`]). No effect without a state dir.
    pub fn with_view_save_interval(self, every: Duration) -> Self {
        if let Some(views) = self.shared.views.as_ref() {
            views.save_every_ms.store(every.as_millis() as u64, Ordering::Relaxed);
        }
        self
    }

    /// Override the read pacing (0 = unpaced; tests). A later exchange
    /// `policy.log_reads_per_second` replaces it.
    pub fn with_log_reads_per_second(self, per_second: u32) -> Self {
        self.shared.pacer.set_rate(per_second);
        self
    }

    /// Part-store reads the pass made so far (through the pacer).
    pub fn reads(&self) -> u64 {
        self.shared.pacer.reads()
    }

    /// The pass's own runtime (tests).
    pub fn runtime_handle(&self) -> &tokio::runtime::Handle {
        self.runtime.handle()
    }

    /// Override the owner authorize pace (tests; default
    /// [`crate::lake_part_gc::executor::MAX_AUTHORIZES_PER_MINUTE`]).
    pub fn with_authorizes_per_minute(self, per_minute: u32) -> Self {
        self.state.try_lock().expect("not shared yet").authorize_pacer =
            crate::lake_part_gc::executor::AuthorizePacer::new(per_minute);
        self
    }

    /// Stop old requests before applying a successful exchange. Preserve the
    /// previous inventory contract until the replacement is validated; an
    /// ordinary credential rotation must not look like withdrawal/re-enable.
    pub(crate) fn suspend_requests(&self) {
        let _route = self.shared.route.write();
        self.shared.refreshing.store(true, Ordering::SeqCst);
        self.shared.generation.send_modify(|generation| *generation = generation.wrapping_add(1));
        self.shared.enabled.store(false, Ordering::SeqCst);
    }

    /// Feed the latest exchange: the `lake_part_gc` route and the raw
    /// `lake_part_delete_grant`. Absent, unreadable or disabled closes the
    /// route for any pass in flight.
    pub fn update(&self, access: Option<&LakePartGcAccess>, grant: Option<&serde_json::Value>) {
        // Readers must observe the old or the complete replacement route,
        // never the temporary disabled state during a valid renewal.
        let mut slot = match self.shared.route.write() {
            Ok(slot) => slot,
            Err(_) => {
                self.shared.generation.send_modify(|generation| *generation = generation.wrapping_add(1));
                self.shared.enabled.store(false, Ordering::SeqCst);
                self.shared.refreshing.store(false, Ordering::SeqCst);
                return;
            }
        };
        self.shared.generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        self.shared.enabled.store(false, Ordering::SeqCst);
        self.shared.owner_tls.reload_ca_logged("lake-part delete");
        let grant = grant.and_then(|value| LakePartDeleteGrant::parse(value, &self.shared.tenant_uuid).ok());
        let route = match (access, &grant) {
            (Some(access), Some(grant)) => match Self::route(access, grant) {
                Ok(route) => Some(Arc::new(route)),
                Err(error) => {
                    tracing::error!(error = %format!("{error:#}"), "lake_part_gc route unreadable; part deletes stay blocked");
                    None
                }
            },
            (Some(_), None) => {
                tracing::warn!("lake_part_gc route delivered without a readable delete grant; not used");
                None
            }
            (None, _) => None,
        };
        if let Some(rate) = access.and_then(|access| access.log_reads_per_second().ok()) {
            self.shared.pacer.set_rate(rate);
        }
        let enabled = route.is_some() && grant.as_ref().is_some_and(|grant| grant.enabled);
        if !slot
            .as_ref()
            .zip(route.as_ref())
            .is_some_and(|(old, new)| old.same_inventory_contract(new))
        {
            self.shared.route_epoch.fetch_add(1, Ordering::SeqCst);
        }
        *slot = route;
        self.shared.refreshing.store(false, Ordering::SeqCst);
        self.shared.enabled.store(enabled, Ordering::SeqCst);
        self.shared
            .generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    fn route(access: &LakePartGcAccess, grant: &LakePartDeleteGrant) -> Result<Route> {
        access.check()?;
        Ok(Route {
            grant_enabled: grant.enabled,
            tenant_slug: grant.tenant_slug.clone(),
            owner_bearer: Zeroizing::new(access.owner_delete.token.clone()),
            owner_expires_at: access.owner_expires_at()?,
            grant_expires_at: chrono::DateTime::parse_from_rfc3339(&grant.expires_at)?
                .with_timezone(&chrono::Utc),
            worker_origin: worker_origin(&access.retention_authority.url)?,
            worker_token: Zeroizing::new(access.retention_authority.token.clone()),
            policy: access.policy()?,
            grant_revision: grant.revision.clone(),
        })
    }

    /// One pass, inline (the background task's body; tests call it directly).
    pub async fn run_pass_now(&self, now_ms: i64) -> Result<PassReport> {
        run_one(self.shared.clone(), self.state.clone(), now_ms, &mut None).await
    }

    /// Entries index-only publication pushed to control so far (process-local).
    /// NAN-3810: hand to the tenant's ingest log writer
    /// ([`super::ingest::Ingestor::set_receipted_appends`]).
    pub fn receipted_appends(&self) -> Arc<crate::lake_part_gc::index::ReceiptedAppends> {
        self.shared.receipted_appends.clone()
    }

    pub fn index_only_indexed(&self) -> u64 {
        self.shared.index_only_indexed.load(Ordering::Relaxed)
    }

    /// Wait for an index-only task in flight to finish (tests).
    pub async fn wait_index_idle(&self) {
        while self.runner.lock().await.index_task.as_ref().is_some_and(|task| !task.is_finished()) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Wait for a pass in flight to finish (tests).
    pub async fn wait_idle(&self) {
        loop {
            let runner = self.runner.lock().await;
            if runner.task.as_ref().is_none_or(|task| task.is_finished())
                && runner.index_task.as_ref().is_none_or(|task| task.is_finished())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

async fn run_one(
    shared: Arc<Shared>,
    state: Arc<tokio::sync::Mutex<LakePartGcState>>,
    now_ms: i64,
    inventory: &mut Option<Inventory>,
) -> Result<PassReport> {
    shared.wait_current().await?;
    if let Some(saved) = inventory.as_ref() {
        saved.fence.wait_current(&shared).await?;
    }
    let mut state = state.lock().await;
    if let Some(views) = shared.views.as_ref() {
        views.load_refused_once(&shared.tenant_uuid, &mut state);
    }
    {
        // Never plan on an incomplete or unverifiable view, even if this
        // instance has no on-disk store (e.g. an in-memory test cell).
        match advance_view(shared.views.as_ref(), &shared, &mut state).await {
            Ok(false) => {
                return Ok(PassReport {
                    paused_reason: Some("log_catching_up".into()),
                    ..PassReport::default()
                })
            }
            Ok(true) => {}
            Err(error) => {
                return Ok(fold_refused(&error, "lake-part GC could not advance its persisted view"));
            }
        }
    }
    let route = shared.wait_current().await?;
    if let Some(saved) = inventory {
        saved.fence.wait_current(&shared).await?;
    } else {
        let prefix = format!(
            "{}/tenant={}/parts/",
            crate::parts::format::PARTS_ROOT,
            shared.tenant_uuid
        );
        let started = tokio::time::Instant::now();
        let fence = InventoryFence {
            route: route.clone(),
            epoch: shared.route_epoch.load(Ordering::SeqCst),
            scope: shared.lister.inventory_scope(),
            deadline: started + INVENTORY_LIFETIME,
        };
        // Resolve ALL live/adopted keys before selecting. Selection uses the
        // complete verified log, never absence from a partial object inventory.
        let live_reader = CompleteViewReader {
            shared: shared.clone(), fence: fence.clone(), head: state.view.head_seq(),
            checkpoint: Arc::new(tokio::sync::Mutex::new(None)),
            advanced: AtomicBool::new(false),
        };
        let live_keys = match crate::lake_part_gc::live_part_keys(
            &shared.tenant_uuid, &mut state.view, &live_reader,
        ).await {
            Ok(keys) => keys,
            // NAN-3852: an arrival above the view is a fold, not a failure.
            Err(error) if routine_fence(&error) == Some(LOG_CATCHING_UP) => {
                return Ok(PassReport { paused_reason: Some(LOG_CATCHING_UP.into()), ..PassReport::default() });
            }
            Err(error) => return Err(error.context("resolve live keys before GC selection")),
        };
        let selection = crate::lake_part_gc::planner::InventorySelection::new(
            &route.tenant_slug, &shared.tenant_uuid, &state.view, &live_keys, now_ms, route.policy,
        )?
        .excluding(&state.refused_keys)
        .retaining(route.policy.max_requests.saturating_mul(PASSES_PER_INVENTORY));
        let budget = selection.limit();
        let mut objects =
            tokio::time::timeout(LISTING_TIMEOUT, shared.lister.list_selected_part_objects(&prefix, &selection))
                .await
                .context("GC candidate scan timed out")?
                .context("list tenant part objects")?;
        fence.wait_current(&shared).await?;
        super::s3_store::check_gc_inventory(&objects)?;
        objects.sort_by(|a, b| a.key.cmp(&b.key));
        ensure!(
            objects.windows(2).all(|pair| pair[0].key != pair[1].key),
            "GC listing repeats an object key"
        );
        ensure!(
            objects.iter().all(|object| object.key.starts_with(&prefix)),
            "GC listing escaped tenant prefix"
        );
        *inventory = Some(Inventory {
            fence,
            objects,
            budget: crate::lake_part_gc::executor::InventoryBudget { deleted: 0, budget },
            checkpoint: Arc::new(tokio::sync::Mutex::new(None)),
        });
        // Arrivals during pagination are folded before any planning. Keep the
        // bounded candidates through subsequent bounded folds/index retries.
        match advance_view(shared.views.as_ref(), &shared, &mut state).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(PassReport {
                    paused_reason: Some("log_catching_up".into()),
                    ..PassReport::default()
                })
            }
            Err(error) => {
                return Ok(fold_refused(&error, "GC post-list fold failed"));
            }
        }
    }
    let saved = inventory.as_ref().expect("inventory initialized");
    let Some(pass_requests) = saved.budget.next_pass(route.policy.max_requests) else {
        return Ok(PassReport::default());
    };
    let objects = &inventory.as_ref().expect("inventory initialized").objects;
    let fence = inventory
        .as_ref()
        .expect("inventory initialized")
        .fence
        .clone();
    let seams = Seams {
        shared: shared.clone(),
        fence: fence.clone(),
        receipted: std::sync::Mutex::new(Vec::new()),
        catalog_pass: Default::default(),
    };
    let reader = CompleteViewReader {
        shared: shared.clone(),
        head: state.view.head_seq(),
        checkpoint: inventory
            .as_ref()
            .expect("inventory initialized")
            .checkpoint
            .clone(),
        fence,
        advanced: AtomicBool::new(false),
    };
    // NAN-3495: never publish beside an index-only task.
    let _publishing = shared.publish_lock.clone().lock_owned().await;
    let mut report = crate::lake_part_gc::executor::run_pass_after_bounded_fold(
        &seams,
        &seams,
        &reader,
        PassInput {
            tenant_id: &route.tenant_slug,
            tenant_uuid: &shared.tenant_uuid,
            state: &mut state,
            objects,
            now_ms,
            receipted: Some(&shared.receipted_appends),
            policy: GcPolicy {
                max_requests: pass_requests,
                ..route.policy
            },
        },
    )
    .await;
    let unauthorizable = state.refused_keys.count(crate::lake_part_gc::executor::OBJECT_NOT_FOUND, now_ms);
    if report.skipped.contains_key(crate::lake_part_gc::executor::OBJECT_NOT_FOUND) {
        tracing::warn!(newly = report.skipped[crate::lake_part_gc::executor::OBJECT_NOT_FOUND], unauthorizable,
            "lake-part GC marked keys unauthorizable: control has no completed writer receipt for them; re-checked daily");
    }
    if let Some(views) = shared.views.as_ref() {
        views.save_refused(&shared.tenant_uuid, &mut state, now_ms);
    }
    {
        let receipted = seams
            .receipted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // NAN-4162: deleted and refused keys leave the inventory; with budget
        // and candidates left the task runs the next bounded pass at once.
        let saved = inventory.as_mut().expect("inventory initialized");
        if saved.budget.after_pass(&mut saved.objects, &receipted, &state.refused_keys, now_ms, &report) {
            report.paused_reason = Some(INVENTORY_CONTINUES.into());
        }
    }
    if reader.advanced.load(Ordering::SeqCst) {
        // The executor stopped before planning. Resume new arrivals through
        // the budgeted/persisted fold, not its separate full-pass fold.
        report.paused_reason = Some("log_catching_up".into());
        report.backoff = false;
    }
    // NAN-4567: after a clean part pass, at most once per interval.
    if report.paused_reason.is_none() && !report.backoff {
        quarantine_expiry_if_due(&shared, &seams, &mut state, &route.tenant_slug, now_ms).await;
        if let Some(views) = shared.views.as_ref() {
            views.save_refused(&shared.tenant_uuid, &mut state, now_ms);
        }
    }
    Ok(report)
}

/// NAN-4567: one bounded bronze quarantine expiry pass, when due. Never
/// fails the part pass: an error is logged and retried next interval.
async fn quarantine_expiry_if_due(
    shared: &Shared, authority: &dyn LakePartDeleteAuthority, state: &mut LakePartGcState,
    tenant_slug: &str, now_ms: i64,
) -> Option<crate::lake_part_gc::quarantine_expiry::QuarantineExpiryReport> {
    use crate::lake_part_gc::quarantine_expiry;
    if shared.quarantine_due_ms.load(Ordering::SeqCst) > now_ms {
        return None;
    }
    shared.quarantine_due_ms.store(now_ms.saturating_add(quarantine_expiry::QUARANTINE_EXPIRY_INTERVAL_MS), Ordering::SeqCst);
    match quarantine_expiry::run(authority, shared.lister.as_ref(), state, tenant_slug, &shared.tenant_uuid, now_ms).await {
        Ok(report) => Some(report),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "bronze quarantine expiry pass failed; retried next interval");
            None
        }
    }
}

const LOG_UNVERIFIABLE: &str = "log_unverifiable";
/// NAN-4162: a pass shrank the inventory and it has budget and candidates
/// left; the task runs the next bounded pass at once. Internal only: never a
/// reported pause.
pub(crate) const INVENTORY_CONTINUES: &str = "inventory_continues";
/// A fold read was fenced by a successful credential exchange (the
/// `suspend_requests` → `update` window). Expected on every refresh while a
/// fold is in flight; retried exactly like an unverifiable log, logged quietly.
pub(crate) const CREDENTIAL_REFRESH: &str = "credential_refresh";
/// The task's retained inventory reached its lifetime or its contract was
/// replaced. The task drops it and lists again (NAN-3459); never a failure.
pub(crate) const INVENTORY_STALE: &str = "inventory_stale";
/// Pause reasons that mean "progressing; continue".
const CATCHING_UP: [&str; 3] = ["log_catching_up", "index_catching_up", crate::lake_part_gc::executor::INDEX_SETTLING];
/// NAN-3852: a pass that met a new arrival above its complete view. Routine
/// under live ingest (every flush appends one): resume the bounded fold.
const LOG_CATCHING_UP: &str = "log_catching_up";
/// NAN-3852: consecutive `index_settling` stops without indexing or deleting
/// before the task ends as `index_catch_up_no_progress` (and backs off).
/// With [`index_settling_retry_delay`] the jittered budget is >= ~84 s, past
/// the 60 s settle gate, so a receipt still in flight (or a receipted run
/// restarted after a gap) settles within one task.
const MAX_INDEX_SETTLING_RETRIES: u32 = 24;
const INDEX_SETTLING_RETRY_BASE: Duration = Duration::from_millis(500);
const INDEX_SETTLING_RETRY_MAX: Duration = Duration::from_secs(8);

/// NAN-3852: the complete-view reader saw an entry above the view head. The
/// pass must not plan on it; the task folds it through the bounded,
/// persisted path and continues. Never a log-integrity failure.
#[derive(Debug, thiserror::Error)]
#[error("GC log advanced during full-pass recheck; resume bounded catch-up")]
pub(crate) struct LogAdvanced;

/// A retained GC inventory may no longer be used (expired, or its route
/// epoch / authority contract / storage scope was replaced).
#[derive(Debug, thiserror::Error)]
#[error("GC inventory {0}")]
struct InventoryStale(&'static str);

/// The pause reason of a routine cell fence in `error`'s chain, if any.
pub(crate) fn routine_fence(error: &anyhow::Error) -> Option<&'static str> {
    if is_refresh_suspended(error) {
        Some(CREDENTIAL_REFRESH)
    } else if error.chain().any(|cause| cause.is::<InventoryStale>()) {
        Some(INVENTORY_STALE)
    } else if error.chain().any(|cause| cause.is::<LogAdvanced>()) {
        Some(LOG_CATCHING_UP)
    } else {
        None
    }
}

/// The paused report for a failed bounded fold. The refresh fence is routine
/// and must not read as a log-integrity warning; anything else still warns.
fn fold_refused(error: &anyhow::Error, what: &'static str) -> PassReport {
    let reason = if is_refresh_suspended(error) {
        tracing::debug!(error = %format!("{error:#}"), "{what}: fenced by a credential refresh; retrying");
        CREDENTIAL_REFRESH
    } else {
        tracing::warn!(error = %format!("{error:#}"), "{what}");
        LOG_UNVERIFIABLE
    };
    PassReport {
        paused_reason: Some(reason.into()),
        backoff: true,
        ..PassReport::default()
    }
}

// The ordinary executor may recheck the head after listing/indexing. It must
// never extend this cell's view outside advance_view's memory/byte/time budget.
#[derive(Clone)]
struct InventoryFence {
    route: Arc<Route>,
    epoch: u64,
    scope: Option<String>,
    deadline: tokio::time::Instant,
}

impl InventoryFence {
    fn capture(shared: &Shared) -> Result<Self> {
        Ok(Self {
            route: shared.current()?,
            epoch: shared.route_epoch.load(Ordering::SeqCst),
            scope: shared.lister.inventory_scope(),
            deadline: tokio::time::Instant::now() + INVENTORY_LIFETIME,
        })
    }

    async fn wait_current(&self, shared: &Shared) -> Result<Arc<Route>> {
        shared.wait_current().await?;
        self.current(shared)
    }

    fn current(&self, shared: &Shared) -> Result<Arc<Route>> {
        let route = shared.current()?;
        if self.epoch != shared.route_epoch.load(Ordering::SeqCst) {
            bail!(InventoryStale("route epoch replaced"));
        }
        if !self.route.same_inventory_contract(&route) {
            bail!(InventoryStale("authority contract replaced"));
        }
        match &self.scope {
            Some(scope) => {
                if shared.lister.inventory_scope().as_ref() != Some(scope) {
                    bail!(InventoryStale("storage scope replaced"));
                }
            }
            None => {
                if !Arc::ptr_eq(&self.route, &route) {
                    bail!(InventoryStale("route replaced"));
                }
            }
        }
        if tokio::time::Instant::now() >= self.deadline {
            bail!(InventoryStale("expired"));
        }
        Ok(route)
    }
}

const FOLDED_PREFIX_BYTES: usize = RAW_SLOT_BYTES;

struct FoldedPrefix {
    fence: InventoryFence,
    entries: std::collections::BTreeMap<u64, (Vec<u8>, String)>,
    bytes: usize,
}

impl FoldedPrefix {
    fn remember(shared: &Shared, fence: &InventoryFence, seq: u64, raw: Vec<u8>, sha: String) {
        // Include conservative per-node/string bookkeeping in the same raw envelope.
        let cost = raw.capacity().saturating_add(256);
        if cost > FOLDED_PREFIX_BYTES || fence.current(shared).is_err() {
            return;
        }
        let mut cache = shared.folded_prefix.lock().unwrap_or_else(|p| p.into_inner());
        if cache.as_ref().is_some_and(|cache| cache.fence.current(shared).is_err()) {
            *cache = None;
        }
        let cache = cache.get_or_insert_with(|| Self {
            fence: fence.clone(), entries: Default::default(), bytes: 0,
        });
        if cache.entries.contains_key(&seq) { return; }
        while cache.bytes.saturating_add(cost) > FOLDED_PREFIX_BYTES
            || cache.entries.len() >= VIEW_PERSIST_EVERY as usize
        {
            let Some((_, (old, _))) = cache.entries.pop_first() else { break };
            cache.bytes -= old.capacity() + 256;
        }
        cache.bytes += cost;
        cache.entries.insert(seq, (raw, sha));
    }

    fn entry(shared: &Shared, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
        let mut cache = shared.folded_prefix.lock().unwrap_or_else(|p| p.into_inner());
        if cache.as_ref().is_some_and(|cache| cache.fence.current(shared).is_err()) {
            *cache = None;
        }
        let Some((raw, sha)) = cache.as_ref().and_then(|cache| cache.entries.get(&seq)) else {
            return Ok(None);
        };
        let entry = gc_parse_entry(raw, &shared.tenant_uuid)?;
        ensure!(entry.seq == seq && crate::parts::sha256_hex(raw) == *sha,
            "GC cached immutable entry identity differs");
        Ok(Some(VerifiedEntryBytes { entry, bytes: raw.clone(), sha256: sha.clone() }))
    }
}

struct CompleteViewReader {
    shared: Arc<Shared>,
    fence: InventoryFence,
    head: Option<u64>,
    checkpoint: Arc<tokio::sync::Mutex<Option<Option<CheckpointClaim>>>>,
    advanced: AtomicBool,
}

#[async_trait]
impl PartLogReader for CompleteViewReader {
    async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
        self.fence.wait_current(&self.shared).await?;
        // Only a successfully applied immutable prefix can be reused. The tail
        // (including all absence and seq > captured head probes) is always fresh.
        if self.head.is_some_and(|head| seq <= head) {
            if let Some(entry) = FoldedPrefix::entry(&self.shared, seq)? {
                self.fence.wait_current(&self.shared).await?;
                return Ok(Some(entry));
            }
        }
        let entry = tokio::time::timeout(LOG_READ_TIMEOUT, self.shared.reader.verified_entry(seq))
            .await
            .context("GC full-pass log read timed out")??;
        self.fence.wait_current(&self.shared).await?;
        if entry.is_some() && self.head.is_none_or(|head| seq > head) {
            self.advanced.store(true, Ordering::SeqCst);
            return Err(LogAdvanced.into());
        }
        Ok(entry)
    }

    async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>> {
        self.fence.wait_current(&self.shared).await?;
        let mut cached = self.checkpoint.lock().await;
        if let Some(checkpoint) = cached.as_ref() {
            return Ok(checkpoint.clone());
        }
        let checkpoint =
            tokio::time::timeout(LOG_READ_TIMEOUT, self.shared.reader.newest_checkpoint())
                .await
                .context("GC checkpoint read timed out")??;
        self.fence.wait_current(&self.shared).await?;
        *cached = Some(checkpoint.clone());
        Ok(checkpoint)
    }

    async fn verified_provenance(&self, part: &PartRef) -> Result<ProvenanceRecord> {
        self.fence.wait_current(&self.shared).await?;
        let record = tokio::time::timeout(
            LOG_READ_TIMEOUT,
            self.shared.reader.verified_provenance(part),
        )
        .await
        .context("GC provenance read timed out")??;
        self.fence.wait_current(&self.shared).await?;
        Ok(record)
    }
}

/// Refuse structurally dense objects before serde builds its typed graph and
/// canonical JSON tree. Reserve four copies of string/input bytes and 512
/// bytes per JSON container/member boundary (typed values, Vec capacity and
/// canonical BTreeMap nodes). Strings are scanned without treating escaped
/// delimiters as structure. Generic ingest parsers retain their contract.
pub(crate) fn gc_parsed_preflight(raw: &[u8]) -> Result<()> {
    let mut quoted = false;
    let mut escaped = false;
    let mut structure = 0_usize;
    for &byte in raw {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if matches!(byte, b'{' | b'[' | b':' | b',') {
            structure += 1;
        }
    }
    ensure!(
        raw.len()
            .saturating_mul(4)
            .saturating_add(structure.saturating_mul(512))
            <= PARSED_ENTRY_BUDGET,
        "GC entry exceeds parsed allocation reservation"
    );
    Ok(())
}

pub(crate) fn gc_parse_entry(raw: &[u8], tenant: &str) -> Result<crate::parts::part_log::LogEntry> {
    gc_parsed_preflight(raw)?;
    crate::parts::part_log::LogEntry::parse_bytes(raw, tenant)
}

/// Resume the view from its persisted copy (once per process), then fold new
/// entries in one chunk of [`VIEW_PERSIST_EVERY`], then persist and yield to
/// the next pass. False means the budget was exhausted: do not plan against
/// a partial live set.
async fn advance_view(
    views: Option<&ViewStore>,
    shared: &Shared,
    state: &mut LakePartGcState,
) -> Result<bool> {
    if let Some(views) = views {
        if !views.loaded.load(Ordering::SeqCst) && state.view.head_seq().is_none() {
            match views.load(&shared.tenant_uuid) {
                Ok(Some(view)) => {
                    let head = view
                        .live()
                        .head()
                        .map(|(seq, sha, _)| (seq, sha.to_string()));
                    let verified = match &head {
                        Some((seq, sha)) => tokio::time::timeout(
                            LOG_READ_TIMEOUT,
                            shared.reader.verified_entry(*seq),
                        )
                        .await
                        .context("GC persisted head read timed out")??
                        .is_some_and(|entry| entry.sha256 == *sha),
                        None => false,
                    };
                    if verified {
                        tracing::info!(head_seq = ?head.map(|(seq, _)| seq), "lake-part GC resumed its persisted view");
                        state.view = view;
                    } else {
                        tracing::warn!("persisted lake-part GC view does not match the part log; folding from genesis");
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), "persisted lake-part GC view unreadable; folding from genesis");
                }
            }
        }
        // A transient head verification failure returned above leaves this
        // false: retry the saved cursor rather than accidentally refolding.
        views.loaded.store(true, Ordering::SeqCst);
        // A failed save must retry before extending the view further. In addition
        // to preserving the cursor, this prevents growth beyond the disk budget.
        // (A save merely deferred by the throttle waits for its interval.)
        if views.dirty.load(Ordering::SeqCst) && views.save_failed.load(Ordering::SeqCst) {
            views.save_tracked(&shared.tenant_uuid, &state.view)?;
        }
    }
    let started = tokio::time::Instant::now();
    let mut bytes = 0;
    let mut complete = false;
    use futures::{StreamExt, stream::FuturesOrdered};
    let max_window = READ_AHEAD_WINDOW.min(
        (RAW_READ_AHEAD_BUDGET - FOLDED_PREFIX_BYTES) / RAW_SLOT_BYTES,
    );
    let cache_fence = InventoryFence::capture(shared)?;
    // A resumed cursor is usually at the live tail. Speculating eight missing
    // entries reserves eight paced attempts and delays the next freshness/index
    // round. Start serially there; a verified backlog restores the bounded window.
    // NAN-3459: the widened window survives the 2 s slice. Resetting it to 1
    // on every call kept a whole backlog serial (~one store RTT per entry, a
    // ~19k-entry genesis refold took most of an hour on the load-test tenant).
    let mut window = match shared.fold_window.load(Ordering::SeqCst) {
        0 if state.view.head_seq().is_some() => 1,
        0 => max_window,
        kept => kept.clamp(1, max_window),
    };
    let mut applied = 0_usize;
    debug_assert!(PARSED_ENTRY_BUDGET >= 8 * crate::parts::format::MAX_LOG_OBJECT_BYTES);
    // Seven raw transport slots plus one bounded immutable-prefix reservation
    // stay within96 MiB including body/chunk/OpenDAL copies. Only the
    // next entry is parsed; never eight concurrent parsed object graphs.
    let mut pending = FuturesOrdered::new();
    let mut admitted = 0_u64;
    let first = state.view.head_seq().map_or(0, |seq| seq + 1);
    let read = |seq| async move {
        tokio::time::timeout(LOG_READ_TIMEOUT, shared.reader.read_ahead_bytes(seq))
            .await
            .context("GC log read timed out")?
    };
    for _ in 0..VIEW_PERSIST_EVERY {
        if started.elapsed() >= CATCH_UP_SLICE || bytes >= CATCH_UP_BYTES {
            break;
        }
        shared.wait_current().await?;
        let seq = state.view.head_seq().map_or(0, |seq| seq + 1);
        while pending.len() < window && admitted < VIEW_PERSIST_EVERY {
            pending.push_back(read(
                first
                    .checked_add(admitted)
                    .context("GC sequence overflow")?,
            ));
            admitted += 1;
        }
        let raw = pending.next().await
            .context("GC read-ahead empty")??;
        // Withdrawal/expiry during a slow read closes the route before applying.
        shared.wait_current().await?;
        let Some(raw) = raw else {
            complete = true;
            break;
        };
        ensure!(
            raw.len() <= crate::parts::format::MAX_LOG_OBJECT_BYTES,
            "GC log entry exceeds object byte budget"
        );
        bytes += raw.len();
        let entry = gc_parse_entry(&raw, &shared.tenant_uuid)?;
        let sha256 = crate::parts::sha256_hex(&raw);
        ensure!(entry.seq == seq, "GC log reader returned wrong sequence");
        ensure!(
            state
                .view
                .part_count()
                .saturating_add(crate::lake_part_gc::index::part_refs(&entry.op))
                <= MAX_VIEW_PARTS,
            "GC view exceeds part budget"
        );
        state.view.apply(&entry, &sha256)?;
        let appended_ms = entry.appended_at_ms;
        // Drop the parsed graph before retaining raw bytes; no parsed graph cache.
        drop(entry);
        if let Ok(mut progress) = shared.progress.lock() {
            progress.log_head_ms = Some(appended_ms);
        }
        FoldedPrefix::remember(shared, &cache_fence, seq, raw, sha256);
        applied += 1;
        if applied >= READ_AHEAD_WINDOW * 4 {
            window = max_window;
        }
        // Apply is synchronous and rolls back refusals. Mark successful changes
        // before yielding, so cancellation keeps the verified prefix dirty but
        // retrying an unchanged invalid entry does not rewrite the large view.
        if let Some(views) = views {
            views.dirty.store(true, Ordering::SeqCst);
        }
        tokio::task::yield_now().await;
    }
    // Drop every speculative future/body before saving or starting another slice.
    drop(pending);
    // At the tail, the next slice starts serially again (no speculative
    // probes past the head); within a backlog it keeps the widened window.
    shared.fold_window.store(if complete { 1 } else { window }, Ordering::SeqCst);
    // Never rewrite an unchanged large view, and an extended one at most every
    // VIEW_SAVE_EVERY (NAN-3495: per-slice rewrites made the fold quadratic).
    if let Some(views) = views {
        if views.dirty.load(Ordering::SeqCst) && views.save_due() {
            views.save_tracked(&shared.tenant_uuid, &state.view)?;
        }
    }
    shared.view_complete.store(complete, Ordering::SeqCst);
    Ok(complete)
}

/// NAN-3495: `delay` scaled into `[delay / 2, delay]`, so cells (and the
/// tenants sharing one owner) that failed together do not retry together.
pub(crate) fn jittered(delay: Duration) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    let half = delay / 2;
    let span = (delay - half).as_millis() as u64;
    if span == 0 {
        return delay;
    }
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    half + Duration::from_millis(hasher.finish() % (span + 1))
}

/// Whether a poll (every ingest tick) starts the pass now rather than leaving
/// it to the 10-min ingest schedule.
fn pass_due_at_poll(runner: &Runner, now_ms: i64) -> bool {
    runner.resume_now || (runner.resume_after_backoff && now_ms >= runner.next_allowed_ms)
}

/// NAN-3495: an index-only task is due when none is in flight, its own
/// cadence allows, and no pass with a complete view is publishing the index
/// itself: between passes (10 min apart, or backing off) and while the pass
/// in flight is still folding its view (every cell restart: the state dir is
/// on an ephemeral volume). The shared publish lock serializes the two.
fn index_only_due(runner: &Runner, now_ms: i64, view_complete: bool) -> bool {
    runner.index_task.is_none()
        && now_ms >= runner.next_index_ms
        && (runner.task.is_none() || !view_complete)
}

/// NAN-4188: control refuses every delete (NL009) from the moment an ingest
/// flush reserves the next log entry until that entry is indexed. The index
/// used to move only at a pass's preparation or an NL009 re-sync, so a busy tenant's
/// gate was closed 56% of the time (index lag p50 8.9 s, p90 198 s after the
/// receipt). The follower publishes as soon as this process's own writer has
/// a receipted append above what it last published: beside a running pass
/// too (they share `publish_lock`; a busy lock just skips). Coalesced to one
/// start per [`FOLLOW_MIN_GAP_MS`], and it keeps the index-only failure
/// back-off. Control load: about one extra status read per log entry; the
/// push itself replaces the one the pass would have made.
fn follow_due(runner: &Runner, now_ms: i64, receipted_through: Option<u64>) -> bool {
    runner.armed
        && runner.index_task.is_none()
        && now_ms >= runner.next_follow_ms
        && receipted_through.is_some_and(|seq| runner.follow_through.is_none_or(|through| seq > through))
}

/// NAN-4188: least time between two follower publications.
const FOLLOW_MIN_GAP_MS: i64 = 2_000;

/// Jittered `INDEX_ONLY_INTERVAL * 2^failures`, capped.
fn index_only_delay(failures: u32) -> Duration {
    jittered(INDEX_ONLY_INTERVAL.saturating_mul(1_u32 << failures.min(16)).min(INDEX_ONLY_MAX_INTERVAL))
}

/// Jittered `INDEX_INCOMPLETE_RETRY_BASE * 2^(retry - 1)`, capped.
fn index_incomplete_retry_delay(retry: u32) -> Duration {
    jittered(
        INDEX_INCOMPLETE_RETRY_BASE
            .saturating_mul(1_u32 << retry.saturating_sub(1).min(16))
            .min(INDEX_INCOMPLETE_RETRY_MAX),
    )
}

/// NAN-3852: the task's answer to an `index_settling` stop. The next entry is
/// young and its receipt not yet seen; that clears with time, so the task
/// waits and retries. A stop that indexed or deleted something is progress
/// and restarts the count. Only [`MAX_INDEX_SETTLING_RETRIES`] stops in a
/// row without either end the task as `index_catch_up_no_progress` (backing
/// off, as before). Returns the wait before the next cycle, or `None` when
/// `report` is not a settling stop (or was turned into the stall).
fn settling_retry(report: &mut PassReport, retries: &mut u32) -> Option<Duration> {
    if report.paused_reason.as_deref() != Some(crate::lake_part_gc::executor::INDEX_SETTLING) {
        return None;
    }
    if report.indexed > 0 || report.deleted > 0 {
        *retries = 0;
    }
    if *retries >= MAX_INDEX_SETTLING_RETRIES {
        report.paused_reason = Some("index_catch_up_no_progress".into());
        report.backoff = true;
        return None;
    }
    *retries += 1;
    Some(index_settling_retry_delay(*retries))
}

/// Jittered `INDEX_SETTLING_RETRY_BASE * 2^(retry - 1)`, capped.
fn index_settling_retry_delay(retry: u32) -> Duration {
    jittered(
        INDEX_SETTLING_RETRY_BASE
            .saturating_mul(1_u32 << retry.saturating_sub(1).min(16))
            .min(INDEX_SETTLING_RETRY_MAX),
    )
}

fn catch_up_retry_delay(failures: u32) -> Duration {
    Duration::from_secs(1_u64 << failures.saturating_sub(1).min(6))
}

/// NAN-3495: publish the part log to control's index from control's own
/// stored head. No view, no listing, no planning, no authorize: deletes stay
/// with the pass (and its back-off and its fold); the index no longer does.
async fn run_index_only(shared: Arc<Shared>) -> Result<PassReport> {
    shared.wait_current().await?;
    // The pass holds this while it publishes; never race it (control would
    // refuse the loser's batch as a gap or chain mismatch).
    let Ok(_publishing) = shared.publish_lock.clone().try_lock_owned() else {
        return Ok(PassReport { paused_reason: Some("index_publication_busy".into()), ..PassReport::default() });
    };
    // NAN-3495: no view needed. Control's stored head is the cursor: read the
    // log from `indexed_through_seq + 1` (each entry verified and chained to
    // control's head sha) and push it, so a cell whose view is cold (every
    // restart: the state dir is on an ephemeral volume) or still folding
    // publishes within a minute instead of after a full genesis fold.
    let fence = InventoryFence::capture(&shared)?;
    let seams = Seams { shared: shared.clone(), fence: fence.clone(), receipted: std::sync::Mutex::new(Vec::new()), catalog_pass: Default::default() };
    let reader = FencedLogReader { shared: shared.clone(), fence };
    let mut report = PassReport::default();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let receipted_through = shared.receipted_appends.receipted_through(now_ms);
    match crate::lake_part_gc::index::sync_index(&seams, &reader, &shared.tenant_uuid, now_ms, receipted_through).await {
        Ok(IndexSyncOutcome::Synced { status, caught_up, pushed, head_appended_ms, .. }) => {
            report.indexed = pushed;
            report.index_head_seq = status.indexed_through_seq;
            report.index_head_appended_ms = head_appended_ms;
            if !caught_up {
                report.paused_reason = Some("index_catching_up".into());
            }
        }
        Ok(IndexSyncOutcome::RouteNotServed) => report.paused_reason = Some("index_route_not_served".into()),
        Ok(IndexSyncOutcome::BackOff(code)) => {
            report.paused_reason = Some(code);
            report.backoff = true;
        }
        Ok(IndexSyncOutcome::Refused(code)) => {
            tracing::warn!(%code, "control refused the part-log index (index-only publication)");
            report.paused_reason = Some(code);
        }
        Err(error) => {
            if let Some(progress) = error.downcast_ref::<crate::lake_part_gc::index::IndexReadProgress>() {
                report.indexed = progress.pushed;
            }
            let reason = routine_fence(&error).unwrap_or(LOG_UNVERIFIABLE);
            tracing::debug!(error = %format!("{error:#}"), reason, "lake-part GC index-only publication stopped");
            report.paused_reason = Some(reason.into());
            report.backoff = true;
        }
    }
    shared.index_only_indexed.fetch_add(report.indexed, Ordering::Relaxed);
    if report.indexed > 0 {
        tracing::debug!(indexed = report.indexed, index_head_seq = ?report.index_head_seq, "lake-part GC index-only publication");
    }
    // The log head is known only when the sync read to its end; otherwise
    // say "at least one more" rather than claim the index caught up.
    let log_head = if report.paused_reason.is_none() {
        report.index_head_seq
    } else {
        report.index_head_seq.map(|seq| seq.saturating_add(1))
    };
    report_progress(&shared, log_head, &report);
    Ok(report)
}

/// The cell's paced, verified log reader behind the current route fence
/// (index-only publication reads the log directly, not through the view).
struct FencedLogReader {
    shared: Arc<Shared>,
    fence: InventoryFence,
}

#[async_trait]
impl PartLogReader for FencedLogReader {
    async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
        self.fence.wait_current(&self.shared).await?;
        tokio::time::timeout(LOG_READ_TIMEOUT, self.shared.reader.verified_entry(seq))
            .await
            .context("GC index-only log read timed out")?
    }

    async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>> {
        self.fence.wait_current(&self.shared).await?;
        tokio::time::timeout(LOG_READ_TIMEOUT, self.shared.reader.newest_checkpoint())
            .await
            .context("GC index-only checkpoint read timed out")?
    }

    async fn verified_provenance(&self, part: &PartRef) -> Result<ProvenanceRecord> {
        self.fence.wait_current(&self.shared).await?;
        tokio::time::timeout(LOG_READ_TIMEOUT, self.shared.reader.verified_provenance(part))
            .await
            .context("GC index-only provenance read timed out")?
    }
}

// One owned task retains a bounded complete inventory across fold/index and
// authoritative-index retries. Exact receipts consume its deletion budget and
// remove candidates; no receipted key is planned again within this task.
async fn run_catch_up(
    shared: Arc<Shared>,
    state: Arc<tokio::sync::Mutex<LakePartGcState>>,
    now_ms: i64,
) -> Result<PassReport> {
    let mut failures = 0;
    let mut index_incomplete = 0;
    let mut settling = 0;
    let started = tokio::time::Instant::now();
    let (mut indexed, mut deleted_reported, mut deleted_dropped, mut deleted, mut planned) = (0, 0, 0, 0, 0);
    let mut inventory: Option<Inventory> = None;
    let mut last_paused: Option<String> = None;
    loop {
        if started.elapsed() >= TASK_LIFETIME {
            // NAN-3459: a task still catching up at its lifetime is healthy.
            // It used to end as an error, which backed the next pass off
            // 20 min .. 6 h right when the index had started to move. End it
            // with its progress; the runner starts the next one at once.
            return Ok(PassReport {
                planned,
                deleted,
                indexed,
                deleted_reported,
                deleted_dropped,
                paused_reason: Some(last_paused.unwrap_or_else(|| "log_catching_up".into())),
                backoff: false,
                ..PassReport::default()
            });
        }
        shared.wait_current().await?;
        if inventory.as_ref().is_some_and(|saved| {
            saved.fence.current(&shared).is_err_and(|error| routine_fence(&error) == Some(INVENTORY_STALE))
        }) {
            // A retained inventory past its lifetime (or contract) is
            // dropped and listed again, never a task failure.
            tracing::debug!("lake-part GC inventory is stale; listing again");
            inventory = None;
        }
        let mut report = run_one(
            shared.clone(),
            state.clone(),
            now_ms.saturating_add(started.elapsed().as_millis() as i64),
            &mut inventory,
        )
        .await?;
        planned += report.planned;
        deleted += report.deleted;
        indexed += report.indexed;
        deleted_reported += report.deleted_reported;
        deleted_dropped += report.deleted_dropped;
        let view_head = state.lock().await.view.head_seq();
        report_progress(&shared, view_head, &report);
        sweep_producer_refs(&shared);
        if report.paused_reason.as_deref() == Some("index_catching_up") && report.indexed == 0 {
            report.paused_reason = Some("index_catch_up_no_progress".into());
            report.backoff = true;
        }
        let settle_delay = settling_retry(&mut report, &mut settling);
        last_paused = report.paused_reason.clone().filter(|reason| reason != INVENTORY_CONTINUES);
        if report.deleted > 0 {
            // NAN-3495: steady deletes under live ingest meet a 409 index
            // incomplete every few seconds; only a run of them without
            // progress ends the task.
            index_incomplete = 0;
        }
        match report.paused_reason.as_deref() {
            Some("log_catching_up" | "index_catching_up") => {
                failures = 0;
                tokio::time::sleep(CATCH_UP_YIELD).await;
            }
            Some(crate::lake_part_gc::executor::INDEX_SETTLING) => {
                failures = 0;
                let delay = settle_delay.unwrap_or(INDEX_SETTLING_RETRY_MAX);
                tracing::debug!(
                    retry = settling,
                    retry_ms = delay.as_millis() as u64,
                    "lake-part GC waits for the newest part-log entry to settle"
                );
                tokio::time::sleep(delay).await;
            }
            Some("lake_part_index_incomplete") if index_incomplete < MAX_INDEX_INCOMPLETE_RETRIES => {
                failures = 0;
                index_incomplete += 1;
                shared.index_incomplete_total.fetch_add(1, Ordering::Relaxed);
                let delay = index_incomplete_retry_delay(index_incomplete);
                tracing::debug!(
                    retry = index_incomplete,
                    retry_ms = delay.as_millis() as u64,
                    "lake-part GC index fell behind the log mid-pass; republishing after a delay"
                );
                tokio::time::sleep(delay).await;
            }
            Some(INVENTORY_STALE) => {
                inventory = None;
                tokio::time::sleep(CATCH_UP_YIELD).await;
            }
            Some(INVENTORY_CONTINUES) => {
                // Only after the candidate set shrank (deleted or newly
                // refused keys left it), so this cannot spin.
                failures = 0;
                tokio::time::sleep(CATCH_UP_YIELD).await;
            }
            Some(reason @ (LOG_UNVERIFIABLE | CREDENTIAL_REFRESH)) if failures < MAX_CATCH_UP_RETRIES => {
                failures += 1;
                let delay = catch_up_retry_delay(failures);
                if reason == CREDENTIAL_REFRESH {
                    tracing::debug!(
                        failures,
                        retry_ms = delay.as_millis() as u64,
                        "GC catch-up retry after a credential-refresh fence"
                    );
                } else {
                    tracing::warn!(
                        failures,
                        retry_ms = delay.as_millis() as u64,
                        "GC catch-up retry after unverifiable log or persistence failure"
                    );
                }
                tokio::time::sleep(delay).await;
            }
            _ => {
                report.planned = planned;
                report.deleted = deleted;
                report.indexed = indexed;
                report.deleted_reported = deleted_reported;
                report.deleted_dropped = deleted_dropped;
                return Ok(report);
            }
        }
    }
}

/// One GC progress observation (NAN-3459).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProgressLine {
    index_head_seq: Option<u64>,
    lag_entries: u64,
    /// Entry-time lag (view head entry vs index head entry), when both known.
    lag_seconds: Option<u64>,
    /// Time since the index was last caught up to the view head.
    behind_seconds: u64,
    lagging: bool,
}

impl GcProgress {
    /// Fold one pass report in and compute the line (no logging).
    fn observe(&mut self, now: tokio::time::Instant, view_head: Option<u64>, report: &PassReport) -> ProgressLine {
        self.deleted_total += report.deleted;
        self.indexed_total += report.indexed;
        if let Some(head) = report.index_head_seq {
            if self.index_head_seq != Some(head) {
                // Keep the entry time only when this pass pushed through `head`.
                self.index_head_ms = report.index_head_appended_ms;
            }
            self.index_head_seq = Some(head);
        }
        let lag_entries = match (view_head, self.index_head_seq) {
            (Some(log), Some(index)) => log.saturating_sub(index),
            (Some(log), None) => log + 1,
            (None, _) => 0,
        };
        let caught_up = lag_entries == 0 && self.index_head_seq.is_some();
        // Only a pass that synced to the view head counts as caught up.
        if caught_up && report.index_head_seq.is_some() {
            self.caught_up_at = now;
        }
        let lag_seconds = if caught_up {
            Some(0)
        } else {
            self.log_head_ms.zip(self.index_head_ms).map(|(log, index)| (log.saturating_sub(index).max(0) / 1000) as u64)
        };
        let behind_seconds = if caught_up { 0 } else { now.saturating_duration_since(self.caught_up_at).as_secs() };
        let lagging = lag_seconds.is_some_and(|lag| lag > INDEX_LAG_WARN.as_secs()) || behind_seconds > INDEX_LAG_WARN.as_secs();
        ProgressLine { index_head_seq: self.index_head_seq, lag_entries, lag_seconds, behind_seconds, lagging }
    }

    /// Whether a line may be logged now (at most one per [`PROGRESS_LOG_EVERY`]).
    fn take_log_slot(&mut self, now: tokio::time::Instant) -> bool {
        if self.logged_at.is_some_and(|at| now.saturating_duration_since(at) < PROGRESS_LOG_EVERY) {
            return false;
        }
        self.logged_at = Some(now);
        true
    }
}

/// NAN-3610 (flag on): the producer tier's stale-reference sweep moved off the
/// ingest flush path to the GC pass (rate-limited inside; blocking I/O on
/// its own thread, never awaited by the pass).
fn sweep_producer_refs(shared: &Shared) {
    // Flag off: warms still sweep inline, as before.
    if !crate::producer_cache::index_enabled() {
        return;
    }
    let Some(parts) = shared.producer_parts.clone() else { return };
    tokio::task::spawn_blocking(move || match crate::producer_cache::sweep_stale_refs(&parts, false) {
        Ok(0) => {}
        Ok(removed) => tracing::debug!(removed, "producer cache stale references swept"),
        Err(error) => tracing::warn!(%error, "producer cache reference sweep failed"),
    });
}

/// NAN-3459: one GC progress line per [`PROGRESS_LOG_EVERY`] — index head,
/// view (log) head, lag in entries and entry time, deletes. WARN instead of
/// INFO while the lag exceeds [`INDEX_LAG_WARN`].
fn report_progress(shared: &Shared, view_head: Option<u64>, report: &PassReport) {
    let Ok(mut progress) = shared.progress.lock() else { return };
    let now = tokio::time::Instant::now();
    let line = progress.observe(now, view_head, report);
    if !progress.take_log_slot(now) {
        return;
    }
    let (deleted_total, indexed_total) = (progress.deleted_total, progress.indexed_total);
    let follower_publications = shared.follower_publications.load(Ordering::Relaxed);
    let index_incomplete_total = shared.index_incomplete_total.load(Ordering::Relaxed);
    let paused = report.paused_reason.as_deref().filter(|reason| *reason != INVENTORY_CONTINUES).unwrap_or("");
    let ProgressLine { index_head_seq, lag_entries, lag_seconds, behind_seconds, lagging } = line;
    if lagging {
        tracing::warn!(index_head_seq = ?index_head_seq, log_head_seq = ?view_head, lag_entries, lag_seconds = ?lag_seconds,
            behind_seconds, deleted_total, indexed_total, follower_publications, index_incomplete_total, paused,
            "lake-part GC index lags the part log by more than 1 h; deletes wait for it");
    } else {
        tracing::info!(index_head_seq = ?index_head_seq, log_head_seq = ?view_head, lag_entries, lag_seconds = ?lag_seconds,
            behind_seconds, deleted_total, indexed_total, follower_publications, index_incomplete_total, paused,
            "lake-part GC progress");
    }
}

// Never take an unfinished handle out of the runner. In particular, cancelling
// the ingest caller cannot detach a still-running task and allow a duplicate.
async fn collect_report(runner: &mut Runner, now_ms: i64) -> Option<Result<PassReport>> {
    let task = runner.task.as_mut()?;
    if !task.is_finished() {
        return None;
    }
    let result = match task.await {
        Ok(result) => result,
        Err(join) => Err(anyhow::anyhow!("lake-part GC pass task failed: {join}")),
    };
    runner.task = None;
    runner.resume_now = result.as_ref().is_ok_and(|report| {
        !report.backoff && report.paused_reason.as_deref().is_some_and(|reason| CATCHING_UP.contains(&reason))
    });
    runner.resume_after_backoff = result.as_ref().map_or(true, |report| report.backoff);
    if result.as_ref().map_or(true, |report| report.backoff) {
        let base = Duration::from_millis(super::ingest::SANCTIONED_GC_INTERVAL_MS as u64);
        // NAN-4769: a task that deleted files and then stopped (under live
        // ingest that is routinely `index_catch_up_no_progress` after NL009
        // races) made progress. It used to count as a failure, so every such
        // task doubled the back-off (20 min .. 6 h) and never reset: one
        // hosted tenant deleted ~900 files/h against ~2k/h superseded and
        // its writer ledger grew ~25k rows/day. Progress waits one ordinary
        // interval and resets the count; only tasks that deleted nothing
        // keep growing the exponential back-off.
        let progressed = result.as_ref().is_ok_and(|report| report.deleted > 0);
        runner.failures = if progressed { 0 } else { runner.failures.saturating_add(1) };
        // NAN-3495: jittered, so passes that failed together spread out.
        let delay = jittered(if progressed {
            base
        } else {
            base.saturating_mul(1_u32 << runner.failures.min(16)).min(crate::lake_part_gc::executor::MAX_BACKOFF)
        });
        runner.next_allowed_ms = now_ms.saturating_add(delay.as_millis() as i64);
    } else {
        runner.failures = 0;
    }
    if result.as_ref().is_ok_and(|report| !report.backoff && report.index_head_seq.is_some()) {
        // NAN-3495: the pass just published the index; index-only resumes
        // its cadence from here rather than re-reading control at once.
        runner.next_index_ms = runner.next_index_ms.max(now_ms.saturating_add(INDEX_ONLY_INTERVAL.as_millis() as i64));
    }
    Some(result)
}

/// NAN-3495: reap a finished index-only task. It never deletes and never
/// touches the pass back-off; its progress line was already logged. Its own
/// failures only slow its own cadence.
async fn collect_index(runner: &mut Runner, now_ms: i64) {
    let Some(task) = runner.index_task.as_mut() else { return };
    if !task.is_finished() {
        return;
    }
    let result = match task.await {
        Ok(result) => result,
        Err(join) => Err(anyhow::anyhow!("lake-part GC index-only task failed: {join}")),
    };
    runner.index_task = None;
    let failed = match &result {
        Ok(report) if report.backoff => {
            tracing::debug!(paused = ?report.paused_reason, "lake-part GC index-only publication paused");
            true
        }
        Ok(_) => false,
        Err(error) => {
            tracing::debug!(error = %format!("{error:#}"), "lake-part GC index-only publication failed");
            true
        }
    };
    runner.index_failures = if failed { runner.index_failures.saturating_add(1) } else { 0 };
    runner.next_index_ms = runner.next_index_ms.max(now_ms.saturating_add(index_only_delay(runner.index_failures).as_millis() as i64));
    if failed {
        // NAN-4188: a refused or failed publication (e.g. control's 503 on
        // lock contention) backs the follower off with the index-only cadence.
        runner.next_follow_ms = runner.next_follow_ms.max(runner.next_index_ms);
    }
}

impl CellSanctionedPartGc {
    /// NAN-3495: publish the part log to control's index on its own cadence
    /// whenever the pass is not doing it: during a pass back-off, and while a
    /// pass is still folding its view (a fresh cell's genesis fold). Before
    /// this the index moved only inside a pass, so a backed-off GC (20 min ..
    /// 6 h) or a cold view (~25 min on the load-test tenant) froze it.
    fn spawn_index_only_if_idle(&self, runner: &mut Runner, now_ms: i64) {
        let view_complete = self.shared.view_complete.load(Ordering::SeqCst);
        let receipted_through = self.shared.receipted_appends.receipted_through(now_ms);
        let scheduled = runner.armed && index_only_due(runner, now_ms, view_complete);
        let follow = !scheduled && follow_due(runner, now_ms, receipted_through);
        if (scheduled || follow) && self.shared.current().is_ok() {
            if scheduled {
                runner.next_index_ms = now_ms.saturating_add(index_only_delay(runner.index_failures).as_millis() as i64);
            } else {
                self.shared.follower_publications.fetch_add(1, Ordering::Relaxed);
            }
            if receipted_through.is_some() {
                runner.follow_through = receipted_through;
            }
            runner.next_follow_ms = now_ms.saturating_add(FOLLOW_MIN_GAP_MS);
            runner.index_task = Some(self.runtime.handle().spawn(run_index_only(self.shared.clone())));
        }
    }

    fn spawn_if_idle(&self, runner: &mut Runner, now_ms: i64) {
        if runner.task.is_none() && now_ms >= runner.next_allowed_ms && self.shared.current().is_ok() {
            runner.resume_now = false;
            runner.resume_after_backoff = false;
            runner.task = Some(self.runtime.handle().spawn(run_catch_up(
                self.shared.clone(),
                self.state.clone(),
                now_ms,
            )));
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("GC successful exchange credentials are being replaced")]
struct RefreshSuspended;

pub(crate) fn is_refresh_suspended(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<RefreshSuspended>())
}

impl Shared {
    async fn wait_current(&self) -> Result<Arc<Route>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut changed = self.generation.subscribe();
        for _ in 0..32 {
            match self.current() {
                Ok(route) => return Ok(route),
                Err(error) if error.downcast_ref::<RefreshSuspended>().is_some() => {
                    tokio::time::timeout_at(deadline, changed.changed())
                        .await.context("GC credential suspension exceeded its bounded lifetime")?
                        .context("GC credential generation closed")?;
                }
                Err(error) => return Err(error),
            }
        }
        bail!("GC credential suspension notification budget exhausted")
    }

    /// The current route, only while the grant is enabled.
    fn current(&self) -> Result<Arc<Route>> {
        let route = self
            .route
            .read()
            .map_err(|_| anyhow::anyhow!("lake_part_gc route lock poisoned"))?;
        let route = route.clone().context("lake_part_gc route was withdrawn")?;
        ensure!(route.grant_enabled, "lake-part delete grant is not enabled");
        ensure!(
            route.grant_expires_at > (self.now)(),
            "lake-part delete grant expired"
        );
        ensure!(
            route.owner_expires_at - BEARER_SKEW > (self.now)(),
            "owner delete bearer expired"
        );
        if !self.enabled.load(Ordering::SeqCst) {
            if self.refreshing.load(Ordering::SeqCst) {
                return Err(RefreshSuspended.into());
            }
            bail!("lake-part delete grant is not enabled");
        }
        Ok(route)
    }
}

#[async_trait]
impl SanctionedPartGc for CellSanctionedPartGc {
    fn attach_catalog(&self, catalog: Arc<super::iceberg_export::lifecycle::TenantCatalog>) -> Result<()> {
        catalog.validate_tenant(&self.shared.tenant_uuid)?;
        let mut slot = self.shared.catalog.write().map_err(|_| anyhow::anyhow!("catalog GC guard poisoned"))?;
        ensure!(slot.as_ref().is_none_or(|current| Arc::ptr_eq(current, &catalog)), "catalog GC custody cannot be replaced");
        *slot = Some(catalog);
        Ok(())
    }
    /// Collect the previous pass's result and start the next one in the
    /// background. While a pass is in flight, an empty report.
    async fn run_pass(&self, now_ms: i64) -> Result<PassReport> {
        self.schedule_pass(now_ms).await.unwrap_or_else(|| Ok(PassReport::default()))
    }

    async fn schedule_pass(&self, now_ms: i64) -> Option<Result<PassReport>> {
        let mut runner = self.runner.lock().await;
        let result = collect_report(&mut runner, now_ms).await;
        // Only the delete gate (grant open) schedules a pass.
        runner.armed |= self.shared.current().is_ok();
        self.spawn_if_idle(&mut runner, now_ms);
        result
    }

    async fn poll_report(&self, now_ms: i64) -> Option<Result<PassReport>> {
        let mut runner = self.runner.lock().await;
        let result = collect_report(&mut runner, now_ms).await;
        collect_index(&mut runner, now_ms).await;
        if pass_due_at_poll(&runner, now_ms) {
            // NAN-3459: a task that ended at its lifetime mid catch-up
            // continues now instead of idling until the next 10-min schedule.
            // NAN-3495: so does a backed-off pass the moment its back-off ends.
            self.spawn_if_idle(&mut runner, now_ms);
        }
        self.spawn_index_only_if_idle(&mut runner, now_ms);
        result
    }

    /// NAN-4601: while ingest holds a recorded catalog (custody unattached)
    /// the delete gate is closed, but the part-log index must keep following
    /// the log: control's NL009 and every later delete need it, and a frozen
    /// head hid the large-tenant hold for a day. Only the index-only task and the
    /// receipted-append follower run here (both publish, neither plans,
    /// authorizes or deletes). A pass is never started, resumed after a
    /// back-off or scheduled; one that finished before the hold is reaped so
    /// its deletes are still counted.
    async fn feed_index_only(&self, now_ms: i64) -> Option<Result<PassReport>> {
        let mut runner = self.runner.lock().await;
        let result = collect_report(&mut runner, now_ms).await;
        collect_index(&mut runner, now_ms).await;
        // The same open-grant condition the gate's schedule arms on.
        runner.armed |= self.shared.current().is_ok();
        self.spawn_index_only_if_idle(&mut runner, now_ms);
        result
    }

    fn deleted_total(&self) -> Option<u64> {
        // Folded per bounded cycle by `report_progress`, so it moves while a
        // task (up to TASK_LIFETIME) is still running.
        self.shared.progress.lock().ok().map(|progress| progress.deleted_total)
    }

    fn unavailable_detail(&self) -> &'static str {
        match self.shared.route.read() {
            Err(_) => "route_lock_poisoned",
            Ok(route) if route.is_none() => "lake_part_gc_not_delivered_or_unreadable",
            Ok(_) => "",
        }
    }

    fn available(&self) -> bool {
        self.shared
            .route
            .read()
            .map(|route| route.is_some())
            .unwrap_or(false)
    }

    /// NAN-4726: the delivered `policy.retention_days` (validated to
    /// 30/90/180/365 at parse), only while the route may delete; a withdrawn,
    /// disabled, expired or refreshing route reads as no policy.
    fn retention_days(&self) -> Option<u64> {
        self.shared.current().ok().and_then(|route| route.policy.retention_days)
    }
}

/// Owner + Worker seams for one pass. Every call re-reads the route, so a
/// refresh that withdraws it (or disables the grant) stops the pass.
struct Seams {
    shared: Arc<Shared>,
    fence: InventoryFence,
    receipted: std::sync::Mutex<Vec<String>>,
    catalog_pass: crate::part_ingest::iceberg_export::lifecycle::CatalogGcPass,
}

impl Seams {
    /// The Worker's retention operations; empty for another contract.
    async fn worker_operations(&self) -> Result<Vec<String>> {
        self.fence.wait_current(&self.shared).await?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Capability {
            schema_version: u8,
            contract: String,
            operations: Vec<String>,
        }
        let capability: Capability = self
            .worker_post(WORKER_CAPABILITIES_PATH, &serde_json::json!({"schema_version": DELETE_CONTROL_SCHEMA_VERSION}))
            .await?;
        if capability.schema_version != DELETE_CONTROL_SCHEMA_VERSION || capability.contract != DELETE_CONTROL_CONTRACT {
            return Ok(Vec::new());
        }
        Ok(capability.operations)
    }

    /// NAN-4567: a bronze quarantine key is no part: the catalog and the
    /// producer cache never hold it.
    fn is_quarantine(permit: &LakePartDeletePermit) -> Result<bool> {
        if permit.request.reason != crate::lake_part_gc::LakePartDeleteReason::QuarantineExpired {
            return Ok(false);
        }
        permit.request.validate()?;
        Ok(true)
    }

    async fn catalog_receipt(&self, permit: &LakePartDeletePermit) -> Result<()> {
        if Self::is_quarantine(permit)? {
            return Ok(());
        }
        let catalog = self.shared.catalog.read().map_err(|_| anyhow::anyhow!("catalog GC guard poisoned"))?.clone();
        if let Some(catalog) = catalog { catalog.guard_delete_in_pass(permit, &self.catalog_pass).await?; }
        Ok(())
    }

    async fn owner_post<T: Serialize + Sync, R: DeserializeOwned>(&self, url: &Url, body: &T, limit: usize) -> Result<R> {
        let route = self.fence.wait_current(&self.shared).await?;
        ensure!(route.owner_expires_at - BEARER_SKEW > (self.shared.now)(), "owner delete bearer expired");
        let body = serde_json::to_vec(body)?;
        ensure!(body.len() <= limit, "owner request is {} bytes, over {limit}", body.len());
        let response = self
            .shared
            .owner_tls
            .client()
            .post(url.clone())
            .bearer_auth(route.owner_bearer.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .with_context(|| format!("owner {}", url.path()))?;
        let status = response.status().as_u16();
        // Delta-seconds only (an HTTP-date is ignored: exponential back-off).
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        let bytes = bounded(response).await?;
        self.fence.wait_current(&self.shared).await?;
        match status {
            200 => Ok(serde_json::from_slice(&bytes).with_context(|| format!("owner {} response", url.path()))?),
            // A rejected bearer is never a per-key refusal: stop the pass.
            401 => Err(crate::lake_part_gc::executor::BearerRefused.into()),
            _ => {
                let text = String::from_utf8_lossy(&bytes);
                Err(anyhow::Error::new(
                    LakePartRefusal::new(Some(status), &error_code(&text, status)).with_retry_after(retry_after),
                ))
            }
        }
    }

    async fn worker_post<T: Serialize + Sync, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let route = self.fence.wait_current(&self.shared).await?;
        let url = route.worker_origin.join(path)?;
        let response = self
            .shared
            .worker_http
            .post(url)
            .bearer_auth(route.worker_token.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(body)?)
            .send()
            .await
            .with_context(|| format!("retention authority {path}"))?;
        let status = response.status().as_u16();
        let bytes = bounded(response).await?;
        self.fence.wait_current(&self.shared).await?;
        if status != 200 {
            let reason = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|body| body.get("reason").and_then(|r| r.as_str()).map(str::to_string))
                .unwrap_or_default();
            bail!("retention authority {path} refused: HTTP {status} {reason}");
        }
        Ok(serde_json::from_slice(&bytes).with_context(|| format!("retention authority {path} response"))?)
    }
}

async fn bounded(response: reqwest::Response) -> Result<Vec<u8>> {
    use futures::TryStreamExt;
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.try_next().await? {
        ensure!(bytes.len() + chunk.len() <= RESPONSE_LIMIT, "response is too large");
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[async_trait]
impl LakePartDeleteAuthority for Seams {
    async fn worker_supports_lake_part_delete(&self) -> Result<bool> {
        Ok(self.worker_operations().await?.iter().any(|op| op == OPERATION))
    }

    async fn worker_supports_quarantine_expiry(&self) -> Result<bool> {
        let operations = self.worker_operations().await?;
        Ok(operations.iter().any(|op| op == OPERATION)
            && operations.iter().any(|op| op == crate::lake_part_gc::quarantine_expiry::QUARANTINE_OPERATION))
    }

    async fn authorize(&self, request: &LakePartDeleteRequest) -> Result<LakePartDeletePermit> {
        request.validate()?;
        self.owner_post(&self.shared.authorize_url, request, AUTHORIZE_REQUEST_LIMIT).await
    }

    async fn prepare(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeletePermit> {
        self.catalog_receipt(permit).await?;
        self.worker_post(WORKER_PREPARE_PATH, permit).await
    }

    async fn retire(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeleteReceipt> {
        self.catalog_receipt(permit).await?;
        let receipt: LakePartDeleteReceipt = self.worker_post(WORKER_RETIRE_PATH, permit).await?;
        if Self::is_quarantine(permit)? {
            return Ok(receipt);
        }
        if receipt.verify(permit).is_ok() {
            self.receipted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(permit.request.key.clone());
        }
        if let Some(parts) = self.shared.producer_parts.as_ref().filter(|_| receipt.verify(permit).is_ok()) {
            if let Err(error) = crate::producer_cache::evict_key(parts, &permit.request.key) {
                tracing::warn!(%error, "producer cache GC eviction failed");
            }
        }
        Ok(receipt)
    }
}

#[async_trait]
impl LakePartIndexClient for Seams {
    async fn index(&self, request: &IndexRequest) -> Result<IndexStatus> {
        self.owner_post(&self.shared.index_url, request, INDEX_REQUEST_LIMIT).await
    }
}

/// [`PartObjectLister`] over the cell's R2 part store (`lake_part` read).
pub struct R2PartLister(pub Arc<R2PartStore>);

#[async_trait]
impl PartObjectLister for R2PartLister {
    fn inventory_scope(&self) -> Option<String> {
        Some(self.0.part_inventory_scope())
    }

    async fn list_part_objects(&self, prefix: &str) -> Result<Vec<ListedPartObject>> {
        self.0.list_part_objects(prefix).await
    }

    async fn get_small_object(&self, key: &str, limit: usize) -> Result<Option<Vec<u8>>> {
        use crate::parts::part_log::ObjectStore;
        let bytes = self.0.get(key).await?;
        ensure!(bytes.as_ref().is_none_or(|bytes| bytes.len() <= limit), "object is over {limit} bytes");
        Ok(bytes)
    }

    async fn list_selected_part_objects(
        &self, prefix: &str,
        selection: &crate::lake_part_gc::planner::InventorySelection<'_>,
    ) -> Result<Vec<ListedPartObject>> {
        self.0.list_selected_part_objects(prefix, selection).await
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(extra: serde_json::Value) -> serde_json::Value {
        let mut value = serde_json::json!({
            "schema_version": 1,
            "owner_delete": {"token": "t", "audience": "owner", "scope": OWNER_DELETE_SCOPE,
                "expires_at": "2099-01-01T00:00:00Z"},
            "retention_authority": {"url": "https://acme.ingest.example/", "token": "w"}
        });
        for (key, field) in extra.as_object().unwrap() {
            value[key] = field.clone();
        }
        value
    }

    #[test]
    fn access_parses_only_the_exact_contract() {
        assert!(LakePartGcAccess::parse(&access(serde_json::json!({}))).is_ok());
        let policy = LakePartGcAccess::parse(&access(serde_json::json!({"policy": {"retention_days": 90}})))
            .unwrap()
            .policy()
            .unwrap();
        assert_eq!((policy.retention_days, policy.max_requests), (Some(90), MAX_REQUESTS_PER_PASS));
        for bad in [
            serde_json::json!({"schema_version": 2}),
            serde_json::json!({"owner_delete": {"token": "t", "audience": "owner", "scope": "lake-parts:sign", "expires_at": "2099-01-01T00:00:00Z"}}),
            serde_json::json!({"retention_authority": {"url": "http://acme.ingest.example/", "token": "w"}}),
            serde_json::json!({"retention_authority": {"url": "https://acme.ingest.example/admin", "token": "w"}}),
            serde_json::json!({"retention_authority": {"url": "https://acme.ingest.example/", "token": ""}}),
            // Grace below the 1 h spec floor (in-flight queries) is refused.
            serde_json::json!({"policy": {"grace_seconds": 60}}),
            serde_json::json!({"policy": {"retention_days": 7}}),
            serde_json::json!({"unknown": true}),
        ] {
            assert!(LakePartGcAccess::parse(&access(bad.clone())).is_err(), "{bad}");
        }
    }

    #[test]
    fn log_read_rate_is_bounded() {
        let access = |rate: serde_json::Value| LakePartGcAccess::parse(&access(serde_json::json!({"policy": {"log_reads_per_second": rate}})));
        assert_eq!(access(serde_json::json!(50)).unwrap().log_reads_per_second().unwrap(), 50);
        assert_eq!(
            LakePartGcAccess::parse(&access_json_default()).unwrap().log_reads_per_second().unwrap(),
            DEFAULT_LOG_READS_PER_SECOND
        );
        assert!(access(serde_json::json!(0)).is_err());
        assert!(access(serde_json::json!(MAX_LOG_READS_PER_SECOND + 1)).is_err());
    }

    fn access_json_default() -> serde_json::Value {
        access(serde_json::json!({}))
    }

    #[tokio::test]
    async fn the_pacer_holds_the_rate() {
        let pacer = ReadPacer::new(100);
        let start = std::time::Instant::now();
        for _ in 0..21 {
            pacer.acquire(1).await;
        }
        // 21 slots at 100/s: the first is immediate, the last 200 ms later.
        assert!(start.elapsed() >= Duration::from_millis(190), "{:?}", start.elapsed());
        assert_eq!(pacer.reads(), 21);
    }

    mod starvation {
        use super::super::*;
        use super::no_pass_in_flight;
        use crate::lake_part_gc::index::tests::ChainReader;
        use crate::lake_part_gc::planner::tests::{Chain, T0};
        use crate::lake_part_gc::request::tests::TENANT_UUID;
        use crate::part_ingest::part_gc_gate::SanctionedPartGc;

        /// Slow R2: every read blocks its thread (a synchronous stand-in for
        /// TLS, parse and SHA-256) on top of the entry's JSON encoding.
        struct SlowReader(ChainReader, Duration);

        #[async_trait]
        impl PartLogReader for SlowReader {
            async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
                std::thread::sleep(self.1);
                self.0.verified_entry(seq).await
            }
            async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>> {
                Ok(None)
            }
            async fn verified_provenance(&self, part: &PartRef) -> Result<ProvenanceRecord> {
                self.0.verified_provenance(part).await
            }
        }

        struct NoObjects;

        #[async_trait]
        impl PartObjectLister for NoObjects {
            async fn list_part_objects(&self, _prefix: &str) -> Result<Vec<ListedPartObject>> {
                Ok(Vec::new())
            }
        }

        fn chain(entries: u64) -> Chain {
            let mut chain = Chain::new();
            for n in 1..entries {
                chain.add(n, T0 + n as i64);
            }
            chain
        }

        fn pass(chain: Chain, state_dir: &Path, delay: Duration) -> CellSanctionedPartGc {
            pass_with_reader(Arc::new(SlowReader(ChainReader { chain, checkpoint: None }, delay)), state_dir)
        }

        fn pass_with_reader(reader: Arc<dyn PartLogReader>, state_dir: &Path) -> CellSanctionedPartGc {
            let pass = CellSanctionedPartGc::new(CellPartGcWiring {
                tenant_uuid: TENANT_UUID.into(),
                // Nothing listens: the pass folds the log, then pauses at
                // the Worker capability probe.
                owner_url: "http://127.0.0.1:1/internal/v1/enterprise-shared/lake-parts:sign".into(),
                owner_ca_file: None,
                reader,
                lister: Arc::new(NoObjects),
                state_dir: Some(state_dir.to_path_buf()),
                worker_http: None,
            })
            .unwrap()
            // Every slice persists (the restart tests count re-reads).
            .with_view_save_interval(Duration::ZERO)
            .with_log_reads_per_second(0);
            let access = LakePartGcAccess::parse(&serde_json::json!({
                "schema_version": 1,
                "owner_delete": {"token": "t", "audience": "owner", "scope": OWNER_DELETE_SCOPE,
                    "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339()},
                "retention_authority": {"url": "https://127.0.0.1:1/", "token": "w"},
                "policy": {"log_reads_per_second": MAX_LOG_READS_PER_SECOND}
            }))
            .unwrap();
            let grant = serde_json::json!({"schema_version": 1, "tenant_id": TENANT_UUID, "tenant_slug": "acme",
                "enabled": true, "revision": "r1", "expires_at": "2099-01-01T00:00:00Z"});
            pass.update(Some(&access), Some(&grant));
            // `update` applied the route's rate; the test runs unpaced.
            pass.with_log_reads_per_second(0)
        }

        /// Async-latency reader recording how many reads were in flight
        /// when each read started.
        struct LatencyReader {
            inner: ChainReader,
            in_flight: std::sync::atomic::AtomicUsize,
            started: std::sync::Mutex<Vec<(u64, usize)>>,
            delay_once: std::sync::Mutex<std::collections::BTreeMap<u64, Duration>>,
        }

        /// Speculative reads are cancelled at a slice boundary. Their fixture
        /// occupancy must fall too, or a serial resume could falsely look parallel.
        struct LatencyFlight<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for LatencyFlight<'_> {
            fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
        }

        #[async_trait]
        impl PartLogReader for LatencyReader {
            async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                let _flight = LatencyFlight(&self.in_flight);
                self.started.lock().unwrap().push((seq, now));
                let delay = self.delay_once.lock().unwrap().remove(&seq).unwrap_or(Duration::from_millis(1));
                tokio::time::sleep(delay).await;
                self.inner.verified_entry(seq).await
            }
            async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>> {
                Ok(None)
            }
            async fn verified_provenance(&self, part: &PartRef) -> Result<ProvenanceRecord> {
                self.inner.verified_provenance(part).await
            }
        }

        /// NAN-3459: a backlog fold keeps its widened read-ahead across
        /// bounded slices. It used to restart serially (window 1) on every
        /// 2 s slice once the view had a head, so a genesis refold of a
        /// ~19k-entry log ran at one store RTT per entry for most of an hour.
        // This case exercises the entry cap. Freeze Tokio time so unrelated CPU
        // load cannot turn it into the separate two-second-deadline case below.
        #[tokio::test(start_paused = true)]
        async fn a_backlog_fold_keeps_its_read_ahead_across_slices() {
            let dir = tempfile::tempdir().unwrap();
            let reader = Arc::new(LatencyReader {
                inner: ChainReader { chain: chain(VIEW_PERSIST_EVERY + 600), checkpoint: None },
                in_flight: Default::default(),
                started: Default::default(),
                delay_once: Default::default(),
            });
            let entry_cap_bytes: usize = reader.inner.chain.entries.iter().take(VIEW_PERSIST_EVERY as usize)
                .map(|(entry, _)| entry.to_bytes().unwrap().len()).sum();
            assert!(entry_cap_bytes < CATCH_UP_BYTES, "this fixture exercises the entry cap, not the byte cap");
            let gc = pass_with_reader(reader.clone(), dir.path());
            let first = gc.run_pass_now(T0).await.unwrap();
            assert_eq!(first.paused_reason.as_deref(), Some("log_catching_up"));
            assert_eq!(gc.state.lock().await.view.head_seq(), Some(VIEW_PERSIST_EVERY - 1));
            assert_eq!(reader.in_flight.load(Ordering::SeqCst), 0);
            let first_slice_reads = reader.started.lock().unwrap().len();
            gc.run_pass_now(T0 + 1).await.unwrap();
            assert_eq!(gc.state.lock().await.view.head_seq(), Some(VIEW_PERSIST_EVERY + 599));
            let started = reader.started.lock().unwrap().clone();
            let second_slice_start = started[first_slice_reads..].iter().filter(|(seq, _)| (VIEW_PERSIST_EVERY..VIEW_PERSIST_EVERY + 8).contains(seq))
                .map(|(_, in_flight)| *in_flight).max().unwrap();
            assert!(second_slice_start > 1, "the second slice resumed serially: {second_slice_start}");
            // At the live tail the next slice starts serially again.
            assert_eq!(gc.shared.fold_window.load(Ordering::SeqCst), 1);
        }

        /// The two-second budget can legitimately stop BEFORE the entry cap.
        /// Prove that this cursor, its parallelism and speculative-read accounting
        /// survive a deadline cut, not just an entry-cap cut.
        #[tokio::test(start_paused = true)]
        async fn a_backlog_fold_keeps_read_ahead_after_time_cut_and_cancels_speculation() {
            let dir = tempfile::tempdir().unwrap();
            let reader = Arc::new(LatencyReader {
                inner: ChainReader { chain: chain(VIEW_PERSIST_EVERY + 600), checkpoint: None },
                in_flight: Default::default(), started: Default::default(),
                delay_once: std::sync::Mutex::new(std::collections::BTreeMap::from([
                    (0, CATCH_UP_SLICE + Duration::from_millis(1)),
                    (1, Duration::from_secs(20)),
                ])),
            });
            let gc = pass_with_reader(reader.clone(), dir.path());
            let began = tokio::time::Instant::now();
            let first = gc.run_pass_now(T0).await.unwrap();
            assert!(began.elapsed() >= CATCH_UP_SLICE && began.elapsed() < LOG_READ_TIMEOUT);
            assert_eq!(first.paused_reason.as_deref(), Some("log_catching_up"));
            assert_eq!(gc.state.lock().await.view.head_seq(), Some(0), "time budget precedes the entry cap");
            assert_eq!(reader.in_flight.load(Ordering::SeqCst), 0, "cancelled speculation holds no fixture slots");
            assert!(gc.shared.fold_window.load(Ordering::SeqCst) > 1);
            let first_slice_reads = reader.started.lock().unwrap().len();
            gc.run_pass_now(T0 + 1).await.unwrap();
            let started = reader.started.lock().unwrap().clone();
            assert!(started[first_slice_reads..].iter().filter(|(seq, _)| (1..9).contains(seq))
                .any(|(_, in_flight)| *in_flight > 1), "resume must really be concurrent, not leaked occupancy");
            assert_eq!(reader.in_flight.load(Ordering::SeqCst), 0);
            gc.run_pass_now(T0 + 2).await.unwrap();
            assert_eq!(gc.state.lock().await.view.head_seq(), Some(VIEW_PERSIST_EVERY + 599));
            assert_eq!(gc.shared.fold_window.load(Ordering::SeqCst), 1);
            assert_eq!(reader.in_flight.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn owned_task_waits_for_explicit_refresh_but_withdrawal_stays_closed() {
            for withdraw in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let gc = pass(chain(8), dir.path(), Duration::ZERO);
                let held = gc.state.lock().await;
                gc.schedule_pass(T0).await;
                tokio::time::sleep(Duration::from_millis(10)).await;
                gc.suspend_requests();
                assert!(is_refresh_suspended(&gc.shared.current().err().unwrap()));
                drop(held);
                let renew = async {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    if withdraw {
                        gc.update(None, None);
                    } else {
                        let access = LakePartGcAccess::parse(&super::access_json_default()).unwrap();
                        let grant = serde_json::json!({"schema_version":1,"tenant_id":TENANT_UUID,
                            "tenant_slug":"acme","enabled":true,"revision":"r1","expires_at":"2099-01-01T00:00:00Z"});
                        gc.update(Some(&access), Some(&grant));
                    }
                };
                tokio::join!(gc.wait_idle(), renew);
                let result = gc.poll_report(T0 + 1).await.unwrap();
                if withdraw {
                    assert!(result.is_err());
                    assert!(gc.shared.current().is_err());
                    assert!(gc.state.lock().await.view.head_seq().is_none());
                } else {
                    let report = result.unwrap();
                    assert_eq!(report.paused_reason.as_deref(), Some("worker_unavailable"));
                    assert_eq!(report.deleted, 0);
                    assert_eq!(gc.state.lock().await.view.head_seq(), Some(7));
                }
            }
            let dir = tempfile::tempdir().unwrap();
            let gc = pass(chain(1), dir.path(), Duration::ZERO);
            gc.suspend_requests();
            assert!(tokio::time::timeout(Duration::from_secs(2), gc.shared.wait_current())
                .await.unwrap().is_err(), "an early-return suspension has a finite closed lifetime");
            assert_eq!(gc.reads(), 0);
        }

        #[tokio::test]
        async fn folded_prefix_reuses_verified_bytes_but_never_absence_or_late_arrivals() {
            let dir = tempfile::tempdir().unwrap();
            let mut gc = pass(chain(10), dir.path(), Duration::ZERO);
            let mut state = gc.state.lock().await;
            assert!(advance_view(None, &gc.shared, &mut state).await.unwrap());
            drop(state);
            let reader = CompleteViewReader {
                shared: gc.shared.clone(), fence: InventoryFence::capture(&gc.shared).unwrap(),
                head: Some(9), checkpoint: Arc::new(tokio::sync::Mutex::new(None)),
                advanced: AtomicBool::new(false),
            };
            let before = gc.reads();
            for seq in 0..10 {
                assert_eq!(reader.verified_entry(seq).await.unwrap().unwrap().entry.seq, seq);
            }
            assert_eq!(gc.reads(), before, "indexing reuses only successfully folded immutable entries");
            assert!(reader.verified_entry(10).await.unwrap().is_none());
            assert_eq!(gc.reads(), before + 1, "absence is always freshly read");
            drop(reader);
            let pacer = gc.shared.pacer.clone();
            Arc::get_mut(&mut gc.shared).unwrap().reader = Arc::new(PacedReader::new(
                Arc::new(SlowReader(ChainReader { chain: chain(11), checkpoint: None }, Duration::ZERO)),
                pacer,
            ));
            let reader = CompleteViewReader {
                shared: gc.shared.clone(), fence: InventoryFence::capture(&gc.shared).unwrap(),
                head: Some(9), checkpoint: Arc::new(tokio::sync::Mutex::new(None)),
                advanced: AtomicBool::new(false),
            };
            assert!(reader.verified_entry(10).await.is_err(), "a newly present tail is refused before planning");
            assert!(reader.advanced.load(Ordering::SeqCst));
            gc.update(None, None);
            assert!(reader.verified_entry(0).await.is_err(), "cached bytes cannot bypass withdrawal");
        }

        #[tokio::test]
        async fn folded_prefix_capacity_eviction_rotation_scope_aba_and_expiry() {
            struct Scope(std::sync::Mutex<String>);
            #[async_trait]
            impl PartObjectLister for Scope {
                fn inventory_scope(&self) -> Option<String> { Some(self.0.lock().unwrap().clone()) }
                async fn list_part_objects(&self, _: &str) -> Result<Vec<ListedPartObject>> { Ok(Vec::new()) }
            }
            let dir = tempfile::tempdir().unwrap();
            let mut gc = pass(chain(5), dir.path(), Duration::ZERO);
            let scope = Arc::new(Scope(std::sync::Mutex::new("1:A".into())));
            Arc::get_mut(&mut gc.shared).unwrap().lister = scope.clone();
            let fence = InventoryFence::capture(&gc.shared).unwrap();
            let source = chain(5);
            let mut view = LakePartLogView::default();
            for (entry, sha) in &source.entries {
                view.apply(entry, sha).unwrap();
                let mut raw = Vec::with_capacity(FOLDED_PREFIX_BYTES / 4);
                raw.extend_from_slice(&entry.to_bytes().unwrap());
                FoldedPrefix::remember(&gc.shared, &fence, entry.seq, raw, sha.clone());
            }
            {
                let cache = gc.shared.folded_prefix.lock().unwrap();
                let cache = cache.as_ref().unwrap();
                assert!(cache.bytes <= FOLDED_PREFIX_BYTES);
                assert_eq!(cache.entries.len(), 3, "allocated capacity and bookkeeping force eviction");
            }
            assert!(FoldedPrefix::entry(&gc.shared, 0).unwrap().is_none());
            assert!(FoldedPrefix::entry(&gc.shared, 4).unwrap().is_some());
            let mut oversized = Vec::with_capacity(FOLDED_PREFIX_BYTES + 1);
            oversized.extend_from_slice(&source.entries[0].0.to_bytes().unwrap());
            FoldedPrefix::remember(&gc.shared, &fence, 0, oversized, source.entries[0].1.clone());
            assert!(FoldedPrefix::entry(&gc.shared, 0).unwrap().is_none(), "oversize capacity is never admitted");
            let route = gc.shared.current().unwrap();
            let access = LakePartGcAccess::parse(&serde_json::json!({"schema_version":1,
                "owner_delete":{"token":"rotated","audience":"owner","scope":OWNER_DELETE_SCOPE,
                    "expires_at":(chrono::Utc::now()+chrono::Duration::minutes(10)).to_rfc3339()},
                "retention_authority":{"url":route.worker_origin.as_str(),"token":"rotated-worker"},
                "policy":{"log_reads_per_second":200}})).unwrap();
            let grant = serde_json::json!({"schema_version":1,"tenant_id":TENANT_UUID,
                "tenant_slug":"acme","enabled":true,"revision":"r1","expires_at":"2099-01-01T00:00:00Z"});
            gc.update(Some(&access), Some(&grant));
            assert!(FoldedPrefix::entry(&gc.shared, 4).unwrap().is_some(), "same-scope rotation retains applied immutable bytes");
            *scope.0.lock().unwrap() = "2:B".into();
            *scope.0.lock().unwrap() = "3:A".into();
            assert!(FoldedPrefix::entry(&gc.shared, 4).unwrap().is_none(), "scope ABA never revives an old prefix");
            let fence = InventoryFence::capture(&gc.shared).unwrap();
            let (entry, sha) = &source.entries[4];
            FoldedPrefix::remember(&gc.shared, &fence, 4, entry.to_bytes().unwrap(), sha.clone());
            assert!(FoldedPrefix::entry(&gc.shared, 4).unwrap().is_some());
            let expires = gc.shared.current().unwrap().owner_expires_at;
            Arc::get_mut(&mut gc.shared).unwrap().now = Arc::new(move || expires);
            gc.suspend_requests();
            let error = gc.shared.wait_current().await.err().unwrap();
            assert!(!is_refresh_suspended(&error), "expiry refuses instead of waiting for suspension");
            assert!(FoldedPrefix::entry(&gc.shared, 4).unwrap().is_none());
        }

        #[tokio::test]
        async fn folded_prefix_entry_limit_evicts_oldest_verified_sequence() {
            let dir = tempfile::tempdir().unwrap();
            let gc = pass(chain(1), dir.path(), Duration::ZERO);
            let fence = InventoryFence::capture(&gc.shared).unwrap();
            let source = chain(VIEW_PERSIST_EVERY + 1);
            let mut view = LakePartLogView::default();
            for (entry, sha) in &source.entries {
                view.apply(entry, sha).unwrap();
                FoldedPrefix::remember(&gc.shared, &fence, entry.seq, entry.to_bytes().unwrap(), sha.clone());
            }
            let cache = gc.shared.folded_prefix.lock().unwrap();
            let cache = cache.as_ref().unwrap();
            assert_eq!(cache.entries.len(), VIEW_PERSIST_EVERY as usize);
            assert!(cache.bytes <= FOLDED_PREFIX_BYTES);
            assert!(!cache.entries.contains_key(&0));
            assert!(cache.entries.contains_key(&VIEW_PERSIST_EVERY));
        }

        #[tokio::test]
        async fn enabled_grant_without_exchange_route_reports_the_missing_input() {
            let dir = tempfile::tempdir().unwrap();
            let gc = Arc::new(pass(chain(1), dir.path(), Duration::ZERO));
            let grant = serde_json::json!({"schema_version": 1, "tenant_id": TENANT_UUID,
                "tenant_slug": "acme", "enabled": true, "expires_at": "2099-01-01T00:00:00Z"});
            gc.update(None, Some(&grant));
            let authority = super::super::super::part_gc_gate::ExchangedGrantAuthority::new(
                TENANT_UUID, Some(gc.clone()),
            );
            authority.update(Some(&grant));
            use super::super::super::part_gc_gate::{PartGcAuthority, PartGcDecision};
            assert!(matches!(authority.decision(T0).await.unwrap(),
                PartGcDecision::Blocked("sanctioned_path_unavailable")));
            assert_eq!(authority.blocked_detail(), "lake_part_gc_not_delivered_or_unreadable");
            let access = LakePartGcAccess::parse(&super::access_json_default()).unwrap();
            gc.update(Some(&access), Some(&grant));
            assert!(matches!(authority.decision(T0).await.unwrap(), PartGcDecision::Sanctioned(_)));
            assert_eq!(authority.blocked_detail(), "");
        }

        /// A 30k-entry part log over slow R2, folded by a GC pass started
        /// through the ingest gate on a CURRENT-THREAD runtime (the worst
        /// case: one worker for ingest, its refresh and its control channel).
        /// The ingest stand-ins (a 20 ms commit tick and a 50 ms refresh
        /// schedule) keep their cadence while the fold runs, because the
        /// pass runs on its own thread. The folded view is persisted; a
        /// restarted pass resumes from it with a single verifying read and
        /// then reads only new entries.
        #[tokio::test(flavor = "current_thread")]
        async fn a_30k_entry_fold_never_starves_ingest_and_resumes_after_restart() {
            const ENTRIES: u64 = 30_000;
            let dir = tempfile::tempdir().unwrap();
            let gc = pass(chain(ENTRIES), dir.path(), Duration::from_micros(100));
            assert!(gc.run_pass(T0).await.unwrap().paused_reason.is_none(), "the first tick only starts the pass");

            let (mut commits, mut refreshes) = (0_u32, 0_u32);
            let (mut worst_commit, mut worst_refresh) = (Duration::ZERO, Duration::ZERO);
            let mut commit = tokio::time::interval(Duration::from_millis(20));
            let mut refresh = tokio::time::interval(Duration::from_millis(50));
            commit.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut reads_while_ticking = 0;
            let started = std::time::Instant::now();
            loop {
                tokio::select! {
                    at = commit.tick() => {
                        worst_commit = worst_commit.max(at.elapsed());
                        commits += 1;
                    }
                    at = refresh.tick() => {
                        worst_refresh = worst_refresh.max(at.elapsed());
                        refreshes += 1;
                    }
                }
                if gc.runner.lock().await.task.as_ref().is_none_or(|task| task.is_finished()) {
                    let report = gc.run_pass(T0 + 1).await.unwrap();
                    if report.paused_reason.as_deref() != Some("log_catching_up") {
                        assert_eq!(report.paused_reason.as_deref(), Some("worker_unavailable"));
                        break;
                    }
                }
                reads_while_ticking = gc.reads();
                assert!(started.elapsed() < Duration::from_secs(300), "the fold did not finish");
            }
            let fold = started.elapsed();
            assert!(reads_while_ticking > ENTRIES / 2, "the fold ran while ingest ticked ({reads_while_ticking} reads)");
            assert!(fold >= Duration::from_secs(3), "30k slow reads take >= 3 s ({fold:?})");
            assert!(commits as u128 >= fold.as_millis() / 20 / 2, "{commits} commits in {fold:?}");
            assert!(refreshes as u128 >= fold.as_millis() / 50 / 2, "{refreshes} refreshes in {fold:?}");
            assert!(worst_commit < Duration::from_millis(250), "a commit tick waited {worst_commit:?}");
            assert!(worst_refresh < Duration::from_millis(250), "a refresh waited {worst_refresh:?}");
            // The pass ended at the (absent) Worker, after the fold.
            gc.wait_idle().await;
            assert_eq!(gc.state.lock().await.view.head_seq(), Some(ENTRIES - 1));
            assert!(dir.path().join("lake-part-gc/view.json").exists());
            drop(gc);

            // Restart: one read re-verifies the persisted head, one finds no
            // newer entry (never 30k again).
            let restarted = pass(chain(ENTRIES), dir.path(), Duration::ZERO);
            restarted.run_pass_now(T0 + 2).await.unwrap();
            assert_eq!(restarted.state.lock().await.view.head_seq(), Some(ENTRIES - 1));
            assert!(restarted.reads() <= 3, "resumed with {} reads", restarted.reads());
            drop(restarted);

            // New entries: only those are read.
            let restarted = pass(chain(ENTRIES + 10), dir.path(), Duration::ZERO);
            restarted.run_pass_now(T0 + 3).await.unwrap();
            assert_eq!(restarted.state.lock().await.view.head_seq(), Some(ENTRIES + 9));
            assert!(restarted.reads() <= 13, "resumed with {} reads", restarted.reads());
        }

        /// NAN-4183: the cell's state dir is per-pod ephemeral, so a view kept
        /// there is gone after a roll and the log refolds from seq 0. With the
        /// view on a dir that survives the pod (the persistent hot volume), a
        /// pod with a FRESH state dir resumes within a couple of reads.
        #[tokio::test(flavor = "current_thread")]
        async fn a_rolled_pod_with_a_fresh_state_dir_resumes_the_view_from_the_hot_volume() {
            let hot = tempfile::tempdir().unwrap();
            let entries = VIEW_PERSIST_EVERY * 2 + 10;
            let first_pod = tempfile::tempdir().unwrap();
            let first = pass(chain(entries), first_pod.path(), Duration::ZERO).with_view_dir(hot.path());
            for at in 0..10 {
                first.run_pass_now(T0 + at).await.unwrap();
                if first.state.lock().await.view.head_seq() == Some(entries - 1) { break; }
            }
            assert_eq!(first.state.lock().await.view.head_seq(), Some(entries - 1));
            assert!(hot.path().join("lake-part-gc/view.json").exists(), "the view is on the hot volume");
            assert!(!first_pod.path().join("lake-part-gc/view.json").exists(), "not in the ephemeral state dir");
            drop(first);
            drop(first_pod);

            // The roll: a new pod, a fresh state dir, the same hot volume.
            let second_pod = tempfile::tempdir().unwrap();
            let rolled = pass(chain(entries + 5), second_pod.path(), Duration::ZERO).with_view_dir(hot.path());
            rolled.run_pass_now(T0 + 20).await.unwrap();
            assert_eq!(rolled.state.lock().await.view.head_seq(), Some(entries + 4));
            assert!(rolled.reads() <= 8, "resumed with {} reads (head re-verify + 5 new + probe)", rolled.reads());
            drop(rolled);

            // Without the hot volume (today's cell) the same roll refolds from seq 0.
            let third_pod = tempfile::tempdir().unwrap();
            let refold = pass(chain(entries + 5), third_pod.path(), Duration::ZERO);
            refold.run_pass_now(T0 + 30).await.unwrap();
            assert_eq!(refold.reads(), VIEW_PERSIST_EVERY, "a fresh state dir starts at genesis");
            assert_eq!(refold.state.lock().await.view.head_seq(), Some(VIEW_PERSIST_EVERY - 1));
        }

        #[tokio::test(flavor = "current_thread")]
        async fn a_bounded_pass_persists_and_restart_continues_the_backlog() {
            let dir = tempfile::tempdir().unwrap();
            let entries = VIEW_PERSIST_EVERY * 2 + 10;
            let first = pass(chain(entries), dir.path(), Duration::ZERO);
            let report = first.run_pass_now(T0).await.unwrap();
            assert_eq!(report.paused_reason.as_deref(), Some("log_catching_up"));
            assert_eq!(first.reads(), VIEW_PERSIST_EVERY);
            assert_eq!(first.state.lock().await.view.head_seq(), Some(VIEW_PERSIST_EVERY - 1));
            drop(first);
            let restarted = pass(chain(entries), dir.path(), Duration::ZERO);
            let report = restarted.run_pass_now(T0 + 1).await.unwrap();
            assert_eq!(report.paused_reason.as_deref(), Some("log_catching_up"));
            assert_eq!(restarted.reads(), VIEW_PERSIST_EVERY + 1);
            assert_eq!(restarted.state.lock().await.view.head_seq(), Some(VIEW_PERSIST_EVERY * 2 - 1));
            restarted.run_pass_now(T0 + 2).await.unwrap();
            assert_eq!(restarted.state.lock().await.view.head_seq(), Some(entries - 1));
        }

        #[tokio::test(flavor = "current_thread")]
        async fn one_start_reaches_full_head_and_delivers_one_final_report() {
            let dir = tempfile::tempdir().unwrap();
            let entries = VIEW_PERSIST_EVERY * 5 + 17;
            use crate::parts::part_log::{LocalObjectStore, ObjectStore};
            use crate::parts::format::LogKeys;
            use crate::parts::provenance::TenantKeySet;
            use crate::lake_part_gc::store_reader::StorePartLogReader;
            let store = Arc::new(LocalObjectStore::new(dir.path().join("objects")).unwrap());
            let keys = LogKeys::new(TENANT_UUID).unwrap();
            for (entry, _) in chain(entries).entries {
                store.put(&keys.entry(entry.seq), &entry.to_bytes().unwrap()).await.unwrap();
            }
            let mut gc = pass(chain(1), dir.path(), Duration::ZERO);
            let shared = Arc::get_mut(&mut gc.shared).unwrap();
            shared.reader = Arc::new(PacedReader::new(Arc::new(StorePartLogReader::new(
                store, TENANT_UUID, TenantKeySet::default(),
            ).unwrap()), shared.pacer.clone()));
            assert!(gc.schedule_pass(T0).await.is_none());
            assert!(gc.schedule_pass(T0 + 1).await.is_none());
            // No repeated run_pass calls driving the backlog.
            tokio::time::timeout(Duration::from_secs(20), gc.wait_idle())
                .await
                .unwrap();
            assert_eq!(gc.state.lock().await.view.head_seq(), Some(entries - 1));
            let report = gc.poll_report(T0 + 1).await.unwrap().unwrap();
            assert_eq!(report.paused_reason.as_deref(), Some("worker_unavailable"));
            assert_eq!(report.deleted, 0);
            assert!(gc.poll_report(T0 + 2).await.is_none());
            assert!(no_pass_in_flight(&*gc.runner.lock().await));
            // Backoff also blocks a fresh-start request.
            gc.run_pass(T0 + 2).await.unwrap();
            assert!(no_pass_in_flight(&*gc.runner.lock().await));
        }

        #[tokio::test(flavor = "current_thread")]
        async fn cancelling_the_caller_keeps_the_actual_task_owned() {
            let dir = tempfile::tempdir().unwrap();
            let gc = Arc::new(pass(chain(1000), dir.path(), Duration::from_millis(1)));
            gc.run_pass(T0).await.unwrap();
            let id = gc.runner.lock().await.task.as_ref().unwrap().id();
            let caller = tokio::spawn({
                let gc = gc.clone();
                async move {
                    for _ in 0..100 {
                        gc.run_pass(T0 + 1).await.unwrap();
                        tokio::task::yield_now().await;
                    }
                }
            });
            caller.abort();
            let _ = caller.await;
            gc.run_pass(T0 + 2).await.unwrap();
            assert_eq!(gc.runner.lock().await.task.as_ref().unwrap().id(), id);
            tokio::time::timeout(Duration::from_secs(10), gc.wait_idle())
                .await
                .unwrap();
            gc.poll_report(T0 + 3).await.unwrap().unwrap();
            assert!(no_pass_in_flight(&*gc.runner.lock().await));
        }

        #[tokio::test(flavor = "current_thread")]
        async fn aborted_task_is_reaped_before_retry_and_fresh_runtime_resumes() {
            let dir = tempfile::tempdir().unwrap();
            let entries = VIEW_PERSIST_EVERY * 4 + 1;
            let gc = pass(chain(entries), dir.path(), Duration::ZERO);
            // Save a prefix, then cancel the actual background task.
            gc.run_pass_now(T0).await.unwrap();
            gc.run_pass(T0 + 1).await.unwrap();
            gc.runner.lock().await.task.as_ref().unwrap().abort();
            tokio::time::timeout(Duration::from_secs(5), gc.wait_idle()).await.unwrap();
            assert!(gc.poll_report(T0 + 2).await.unwrap().is_err());
            assert!(no_pass_in_flight(&*gc.runner.lock().await));
            drop(gc); // joins the old runtime; no detached snapshot writer
            let restarted = pass(chain(entries), dir.path(), Duration::ZERO);
            restarted.run_pass(T0 + 3).await.unwrap();
            tokio::time::timeout(Duration::from_secs(20), restarted.wait_idle()).await.unwrap();
            assert_eq!(restarted.state.lock().await.view.head_seq(), Some(entries - 1));
            assert!(restarted.reads() < entries);
            assert_eq!(restarted.poll_report(T0 + 4).await.unwrap().unwrap().deleted, 0);
        }

        struct CountingLister(Arc<AtomicU64>);
        #[async_trait]
        impl PartObjectLister for CountingLister {
            async fn list_part_objects(&self, _: &str) -> Result<Vec<ListedPartObject>> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn partial_view_never_lists_and_withdrawal_stops_between_reads() {
            let dir = tempfile::tempdir().unwrap();
            let lists = Arc::new(AtomicU64::new(0));
            let mut gc = pass(
                chain(VIEW_PERSIST_EVERY * 4),
                dir.path(),
                Duration::from_millis(1),
            );
            Arc::get_mut(&mut gc.shared).unwrap().lister = Arc::new(CountingLister(lists.clone()));
            gc.run_pass(T0).await.unwrap();
            while gc.reads() < 20 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            gc.update(None, None);
            tokio::time::timeout(Duration::from_secs(3), gc.wait_idle())
                .await
                .unwrap();
            use super::super::super::part_gc_gate::{ExchangedGrantAuthority, PartGcAuthority};
            let gc = Arc::new(gc);
            let authority = ExchangedGrantAuthority::new(TENANT_UUID, Some(gc.clone()));
            authority.update(None);
            assert!(authority.poll_report(T0 + 1).await.unwrap().is_err());
            assert!(authority.poll_report(T0 + 2).await.is_none());
            assert_eq!(lists.load(Ordering::SeqCst), 0);
            assert!(gc.state.lock().await.view.head_seq().unwrap() < VIEW_PERSIST_EVERY);
            let reads = gc.reads();
            gc.run_pass(T0 + 2).await.unwrap();
            assert_eq!(gc.reads(), reads);
        }

        #[tokio::test]
        async fn inventory_survives_valid_rotation_but_not_scope_change_or_withdrawal_epoch() {
            struct ScopedLister(std::sync::Mutex<String>);
            #[async_trait]
            impl PartObjectLister for ScopedLister {
                fn inventory_scope(&self) -> Option<String> {
                    Some(self.0.lock().unwrap().clone())
                }
                async fn list_part_objects(&self, _: &str) -> Result<Vec<ListedPartObject>> {
                    Ok(Vec::new())
                }
            }
            let dir = tempfile::tempdir().unwrap();
            let mut gc = pass(chain(1), dir.path(), Duration::ZERO);
            let lister = Arc::new(ScopedLister(std::sync::Mutex::new("bucket/prefix".into())));
            Arc::get_mut(&mut gc.shared).unwrap().lister = lister.clone();
            let route = gc.shared.current().unwrap();
            let fence = InventoryFence {
                route: route.clone(),
                epoch: gc.shared.route_epoch.load(Ordering::SeqCst),
                scope: Some("bucket/prefix".into()),
                deadline: tokio::time::Instant::now() + INVENTORY_LIFETIME,
            };
            let access = LakePartGcAccess::parse(&serde_json::json!({
                "schema_version": 1,
                "owner_delete": {"token": "rotated", "audience": "owner", "scope": OWNER_DELETE_SCOPE,
                    "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339()},
                "retention_authority": {"url": route.worker_origin.as_str(), "token": "rotated-worker"}
            })).unwrap();
            let grant = serde_json::json!({"schema_version": 1, "tenant_id": TENANT_UUID, "tenant_slug": "acme",
                "enabled": true, "revision": "r1", "expires_at": "2099-01-01T00:00:00Z"});
            let mut requests = gc.shared.generation.subscribe();
            let epoch = gc.shared.route_epoch.load(Ordering::SeqCst);
            gc.suspend_requests();
            assert!(requests.has_changed().unwrap(), "successful exchange cancels old requests immediately");
            requests.borrow_and_update();
            assert!(fence.current(&gc.shared).is_err(), "exchange stays disabled until usable credentials are applied");
            assert_eq!(gc.shared.route_epoch.load(Ordering::SeqCst), epoch);
            gc.update(Some(&access), Some(&grant));
            let renewed = fence.current(&gc.shared).unwrap();
            assert_eq!(renewed.owner_bearer.as_str(), "rotated");
            assert_eq!(renewed.worker_token.as_str(), "rotated-worker");
            *lister.0.lock().unwrap() = "another bucket".into();
            assert!(fence.current(&gc.shared).is_err());
            *lister.0.lock().unwrap() = "bucket/prefix".into();
            gc.update(None, None);
            gc.update(Some(&access), Some(&grant));
            assert!(
                fence.current(&gc.shared).is_err(),
                "withdrawal ends the old inventory epoch permanently"
            );
        }

        #[tokio::test]
        async fn inventory_fence_rejects_refresh_with_identical_credentials_and_expiry() {
            let dir = tempfile::tempdir().unwrap();
            let gc = pass(chain(1), dir.path(), Duration::ZERO);
            let route = gc.shared.current().unwrap();
            let fence = InventoryFence {
                route: route.clone(),
                epoch: gc.shared.route_epoch.load(Ordering::SeqCst),
                scope: None,
                deadline: tokio::time::Instant::now() + INVENTORY_LIFETIME,
            };
            fence.current(&gc.shared).unwrap();
            let expired = InventoryFence {
                route,
                epoch: gc.shared.route_epoch.load(Ordering::SeqCst),
                scope: None,
                deadline: tokio::time::Instant::now(),
            };
            assert!(expired.current(&gc.shared).is_err());
            let access = LakePartGcAccess::parse(&super::access_json_default()).unwrap();
            let grant = serde_json::json!({"schema_version": 1, "tenant_id": TENANT_UUID, "tenant_slug": "acme",
                "enabled": true, "revision": "r1", "expires_at": "2099-01-01T00:00:00Z"});
            gc.update(Some(&access), Some(&grant));
            assert!(fence.current(&gc.shared).is_err());
        }

        #[tokio::test]
        async fn grant_and_bearer_expiry_close_every_seam() {
            let dir = tempfile::tempdir().unwrap();
            let mut gc = pass(chain(10), dir.path(), Duration::ZERO);
            let at = chrono::DateTime::from_timestamp_millis(T0).unwrap();
            Arc::get_mut(&mut gc.shared).unwrap().now = Arc::new(move || at);
            for grant_expired in [true, false] {
                let mut slot = gc.shared.route.write().unwrap();
                let route = Arc::get_mut(slot.as_mut().unwrap()).unwrap();
                route.grant_expires_at = at + chrono::Duration::minutes(10);
                route.owner_expires_at = at + chrono::Duration::minutes(10);
                if grant_expired {
                    route.grant_expires_at = at;
                } else {
                    route.owner_expires_at = at + BEARER_SKEW;
                }
                drop(slot);
                assert!(gc.shared.current().is_err());
                let seams = Seams {
                    shared: gc.shared.clone(),
                    fence: InventoryFence {
                        route: gc.shared.route.read().unwrap().as_ref().unwrap().clone(),
                        epoch: gc.shared.route_epoch.load(Ordering::SeqCst),
                        scope: None,
                        deadline: tokio::time::Instant::now() + INVENTORY_LIFETIME,
                    },
                    receipted: std::sync::Mutex::new(Vec::new()),
                    catalog_pass: Default::default(),
                        };
                assert!(seams.worker_supports_lake_part_delete().await.is_err());
                assert!(gc.run_pass_now(T0).await.is_err());
                assert_eq!(gc.reads(), 0);
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn time_budget_yields_with_a_persisted_prefix_and_unchanged_view_is_not_rewritten() {
            let dir = tempfile::tempdir().unwrap();
            let gc = pass(chain(5000), dir.path(), Duration::from_millis(2));
            let report = gc.run_pass_now(T0).await.unwrap();
            assert_eq!(report.paused_reason.as_deref(), Some("log_catching_up"));
            let head = gc.state.lock().await.view.head_seq().unwrap();
            assert!(head > 0 && head < VIEW_PERSIST_EVERY - 1);
            let persisted = gc
                .shared
                .views
                .as_ref()
                .unwrap()
                .load(TENANT_UUID)
                .unwrap()
                .unwrap();
            assert_eq!(persisted.head_seq(), Some(head));
            drop(gc);
            let gc = pass(chain(10), dir.path(), Duration::ZERO);
            gc.run_pass_now(T0).await.unwrap();
            let path = dir.path().join("lake-part-gc/view.json");
            let before = std::fs::metadata(&path).unwrap().modified().unwrap();
            gc.run_pass_now(T0 + 1).await.unwrap();
            assert_eq!(std::fs::metadata(path).unwrap().modified().unwrap(), before);
        }

        /// NAN-3495: an extended view is rewritten at most once per save
        /// interval (per-slice rewrites of a tens-of-MB view made the load-test tenant's
        /// genesis fold quadratic); a restart re-reads only what followed.
        #[tokio::test(flavor = "current_thread")]
        async fn a_folding_view_is_saved_at_most_once_per_interval() {
            let dir = tempfile::tempdir().unwrap();
            let gc = pass(chain(5000), dir.path(), Duration::from_millis(2))
                .with_view_save_interval(Duration::from_secs(3600));
            let store = |gc: &CellSanctionedPartGc| gc.shared.views.as_ref().unwrap().load(TENANT_UUID).unwrap().unwrap().head_seq();
            assert_eq!(gc.run_pass_now(T0).await.unwrap().paused_reason.as_deref(), Some("log_catching_up"));
            let first = gc.state.lock().await.view.head_seq();
            assert_eq!(store(&gc), first, "the first extension in a process is written at once");
            assert_eq!(gc.run_pass_now(T0 + 1).await.unwrap().paused_reason.as_deref(), Some("log_catching_up"));
            let second = gc.state.lock().await.view.head_seq();
            assert!(second > first);
            assert_eq!(store(&gc), first, "within the interval the extended view stays in memory");
            let gc = gc.with_view_save_interval(Duration::ZERO);
            gc.run_pass_now(T0 + 2).await.unwrap();
            let third = gc.state.lock().await.view.head_seq();
            assert!(third > second);
            assert_eq!(store(&gc), third, "the interval elapsed: written");
        }

        struct ArrivingReader {
            inner: std::sync::Mutex<ChainReader>,
            arrived: AtomicBool,
        }
        #[async_trait]
        impl PartLogReader for ArrivingReader {
            async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
                let mut reader = self.inner.lock().unwrap();
                if seq == VIEW_PERSIST_EVERY && !self.arrived.swap(true, Ordering::SeqCst) {
                    for n in VIEW_PERSIST_EVERY * 3..VIEW_PERSIST_EVERY * 4 + 13 {
                        reader.chain.add(n, T0 + n as i64);
                    }
                }
                Ok(reader
                    .chain
                    .entries
                    .get(seq as usize)
                    .map(|(entry, sha)| VerifiedEntryBytes {
                        bytes: entry.to_bytes().unwrap(),
                        sha256: sha.clone(),
                        entry: entry.clone(),
                    }))
            }
            async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>> {
                Ok(None)
            }
            async fn verified_provenance(&self, _: &PartRef) -> Result<ProvenanceRecord> {
                bail!("unused")
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn arrivals_during_fold_are_included_before_completion() {
            let dir = tempfile::tempdir().unwrap();
            let mut gc = pass(chain(1), dir.path(), Duration::ZERO);
            let reader = Arc::new(ArrivingReader {
                inner: std::sync::Mutex::new(ChainReader {
                    chain: chain(VIEW_PERSIST_EVERY * 3),
                    checkpoint: None,
                }),
                arrived: AtomicBool::new(false),
            });
            let pacer = gc.shared.pacer.clone();
            Arc::get_mut(&mut gc.shared).unwrap().reader =
                Arc::new(PacedReader::new(reader.clone(), pacer));
            gc.run_pass(T0).await.unwrap();
            tokio::time::timeout(Duration::from_secs(20), gc.wait_idle())
                .await
                .unwrap();
            assert!(reader.arrived.load(Ordering::SeqCst));
            assert_eq!(
                gc.state.lock().await.view.head_seq(),
                Some(VIEW_PERSIST_EVERY * 4 + 12)
            );
            assert_eq!(gc.poll_report(T0 + 1).await.unwrap().unwrap().deleted, 0);
        }

        #[tokio::test(flavor = "current_thread")]
        async fn malformed_or_forked_store_entry_retries_with_backoff_and_reports_failure() {
            use crate::lake_part_gc::store_reader::StorePartLogReader;
            use crate::parts::format::LogKeys;
            use crate::parts::part_log::{LocalObjectStore, ObjectStore};
            use crate::parts::provenance::TenantKeySet;
            for malformed in [true, false] {
                let dir = tempfile::tempdir().unwrap();
                let store = Arc::new(LocalObjectStore::new(dir.path().join("objects")).unwrap());
                let keys = LogKeys::new(TENANT_UUID).unwrap();
                for (entry, _) in chain(20).entries {
                    store
                        .put(&keys.entry(entry.seq), &entry.to_bytes().unwrap())
                        .await
                        .unwrap();
                }
                let invalid = if malformed {
                    b"{malformed".to_vec()
                } else {
                    let mut entry = chain(21).entries.pop().unwrap().0;
                    entry.prev_sha256 = "f".repeat(64);
                    entry.to_bytes().unwrap()
                };
                store.put(&keys.entry(20), &invalid).await.unwrap();
                let lists = Arc::new(AtomicU64::new(0));
                let mut gc = pass(chain(1), dir.path(), Duration::ZERO);
                let shared = Arc::get_mut(&mut gc.shared).unwrap();
                shared.reader = Arc::new(PacedReader::new(
                    Arc::new(
                        StorePartLogReader::new(store, TENANT_UUID, TenantKeySet::default())
                            .unwrap(),
                    ),
                    shared.pacer.clone(),
                ));
                shared.lister = Arc::new(CountingLister(lists.clone()));
                let started = std::time::Instant::now();
                gc.run_pass(T0).await.unwrap();
                tokio::time::timeout(Duration::from_secs(20), gc.wait_idle())
                    .await
                    .unwrap();
                assert!(started.elapsed() >= Duration::from_secs(7));
                assert_eq!(gc.reads(), 24); // 20 verified prefix entries + four failed attempts
                assert_eq!(lists.load(Ordering::SeqCst), 0);
                assert_eq!(gc.state.lock().await.view.head_seq(), Some(19));
                let report = gc.poll_report(T0 + 1).await.unwrap().unwrap();
                assert_eq!(report.paused_reason.as_deref(), Some("log_unverifiable"));
                assert!(report.backoff);
                // NAN-3495: the back-off may start one index-only task; it is
                // not a pass. Let it settle, then no pass may read the log.
                tokio::time::timeout(Duration::from_secs(20), gc.wait_idle()).await.unwrap();
                let reads = gc.reads();
                gc.run_pass(T0 + 10_000).await.unwrap();
                assert_eq!(gc.reads(), reads);
                assert!(no_pass_in_flight(&*gc.runner.lock().await));
            }
        }

        struct FailHeadOnce {
            reader: ChainReader,
            failed: AtomicBool,
        }
        #[async_trait]
        impl PartLogReader for FailHeadOnce {
            async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
                if seq == 49 && !self.failed.swap(true, Ordering::SeqCst) {
                    bail!("transient head read failure");
                }
                self.reader.verified_entry(seq).await
            }
            async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>> {
                Ok(None)
            }
            async fn verified_provenance(&self, part: &PartRef) -> Result<ProvenanceRecord> {
                self.reader.verified_provenance(part).await
            }
        }

        #[tokio::test(flavor = "current_thread")]
        async fn transient_persisted_head_failure_retries_the_cursor_instead_of_genesis() {
            let dir = tempfile::tempdir().unwrap();
            let first = pass(chain(50), dir.path(), Duration::ZERO);
            first.run_pass_now(T0).await.unwrap();
            drop(first);
            let mut restarted = pass(chain(1), dir.path(), Duration::ZERO);
            let shared = Arc::get_mut(&mut restarted.shared).unwrap();
            shared.reader = Arc::new(PacedReader::new(
                Arc::new(FailHeadOnce {
                    reader: ChainReader {
                        chain: chain(50),
                        checkpoint: None,
                    },
                    failed: AtomicBool::new(false),
                }),
                shared.pacer.clone(),
            ));
            let failed = restarted.run_pass_now(T0 + 1).await.unwrap();
            assert_eq!(failed.paused_reason.as_deref(), Some("log_unverifiable"));
            assert!(!restarted
                .shared
                .views
                .as_ref()
                .unwrap()
                .loaded
                .load(Ordering::SeqCst));
            restarted.run_pass_now(T0 + 2).await.unwrap();
            assert_eq!(restarted.state.lock().await.view.head_seq(), Some(49));
            assert_eq!(
                restarted.reads(),
                4,
                "failed verifying read + verifying read + head probe + post-list head probe"
            );
        }

        #[tokio::test(flavor = "current_thread")]
        async fn failed_snapshot_save_retries_before_extending_the_view() {
            let dir = tempfile::tempdir().unwrap();
            let gc = pass(
                chain(VIEW_PERSIST_EVERY * 3 + 10),
                dir.path(),
                Duration::ZERO,
            );
            gc.run_pass_now(T0).await.unwrap();
            let path = gc.shared.views.as_ref().unwrap().path();
            let backup = path.with_extension("previous");
            std::fs::rename(path, &backup).unwrap();
            std::fs::create_dir(path).unwrap(); // atomic rename cannot replace a directory
            let failed = gc.run_pass_now(T0 + 1).await.unwrap();
            assert_eq!(failed.paused_reason.as_deref(), Some("log_unverifiable"));
            let before = gc.state.lock().await.view.head_seq();
            let reads = gc.reads();
            gc.run_pass_now(T0 + 2).await.unwrap();
            assert_eq!(gc.state.lock().await.view.head_seq(), before);
            assert_eq!(
                gc.reads(),
                reads,
                "failed persistence must stop further reads/growth"
            );
            std::fs::remove_dir(path).unwrap();
            std::fs::rename(backup, path).unwrap();
            gc.run_pass_now(T0 + 3).await.unwrap();
            assert_eq!(
                gc.state.lock().await.view.head_seq(),
                Some(VIEW_PERSIST_EVERY * 3 - 1)
            );
        }

        /// A persisted view whose head no longer matches the log (a
        /// different chain) is discarded: the pass folds from genesis.
        #[tokio::test(flavor = "current_thread")]
        async fn a_mismatched_persisted_view_is_refolded() {
            let dir = tempfile::tempdir().unwrap();
            let first = pass(chain(50), dir.path(), Duration::ZERO);
            first.run_pass_now(T0).await.unwrap();
            drop(first);
            let mut other = Chain::new();
            for n in 1..50 {
                other.add(n + 1_000, T0 + n as i64);
            }
            let refold = pass(other, dir.path(), Duration::ZERO);
            refold.run_pass_now(T0).await.unwrap();
            assert_eq!(refold.state.lock().await.view.head_seq(), Some(49));
            assert!(refold.reads() >= 50, "refolded from genesis ({} reads)", refold.reads());
        }
    }

    #[test]
    fn oversized_snapshot_is_rejected_before_deserialization() {
        let dir = tempfile::tempdir().unwrap();
        let store = ViewStore::new(dir.path());
        std::fs::create_dir_all(store.path().parent().unwrap()).unwrap();
        let file = std::fs::File::create(store.path()).unwrap();
        file.set_len(MAX_VIEW_BYTES + 1).unwrap();
        assert!(store.load("unused").unwrap_err().to_string().contains("byte budget"));
    }

    #[test]
    fn retry_delay_is_exponential_and_capped() {
        assert_eq!(catch_up_retry_delay(1), Duration::from_secs(1));
        assert_eq!(catch_up_retry_delay(2), Duration::from_secs(2));
        assert_eq!(catch_up_retry_delay(3), Duration::from_secs(4));
        assert_eq!(catch_up_retry_delay(u32::MAX), Duration::from_secs(64));
    }

    #[test]
    fn routine_fences_are_classified_and_everything_else_is_not() {
        let refresh = anyhow::Error::new(RefreshSuspended).context("read entry 7");
        assert_eq!(routine_fence(&refresh), Some(CREDENTIAL_REFRESH));
        let stale = anyhow::Error::new(InventoryStale("expired"))
            .context(crate::lake_part_gc::index::IndexReadProgress { pushed: 3 });
        assert_eq!(routine_fence(&stale), Some(INVENTORY_STALE));
        assert_eq!(routine_fence(&anyhow::anyhow!("GC log entry exceeds object byte budget")), None);
    }

    /// NAN-3852: an arrival above the complete view (every flush under live
    /// ingest) is a fold, never a log-integrity failure with a back-off.
    #[test]
    fn a_log_advance_is_a_routine_catch_up() {
        let advanced = anyhow::Error::new(LogAdvanced)
            .context(crate::lake_part_gc::index::IndexReadProgress { pushed: 0 });
        assert_eq!(routine_fence(&advanced), Some(LOG_CATCHING_UP));
        assert!(CATCHING_UP.contains(&LOG_CATCHING_UP));
        assert_ne!(routine_fence(&advanced), Some(LOG_UNVERIFIABLE));
    }

    /// NAN-3852 (the load-test tenant, 10-14 16:24Z): a task that had deleted 410 keys
    /// ended `index_catch_up_no_progress` (and backed off 10-20 min) the
    /// moment a flush's entry was visible but its receipt not yet recorded.
    /// A settling stop now waits and retries; only a long run of them with
    /// nothing indexed or deleted is a stall.
    #[test]
    fn index_settling_waits_and_only_a_long_idle_run_is_a_stall() {
        let settling = |indexed: u64, deleted: u64| PassReport {
            paused_reason: Some(crate::lake_part_gc::executor::INDEX_SETTLING.into()),
            indexed, deleted, ..PassReport::default()
        };
        let mut retries = 0;
        for n in 1..=MAX_INDEX_SETTLING_RETRIES {
            let mut report = settling(0, 0);
            let delay = settling_retry(&mut report, &mut retries).expect("settling retries");
            assert!(delay <= INDEX_SETTLING_RETRY_MAX && delay >= INDEX_SETTLING_RETRY_BASE / 2);
            assert_eq!(retries, n);
            assert!(!report.backoff);
            assert!(CATCHING_UP.contains(&report.paused_reason.as_deref().unwrap()), "resumes, never a failure");
        }
        let mut stalled = settling(0, 0);
        assert!(settling_retry(&mut stalled, &mut retries).is_none());
        assert_eq!(stalled.paused_reason.as_deref(), Some("index_catch_up_no_progress"));
        assert!(stalled.backoff);
        // Progress (indexed or deleted) restarts the count.
        for progress in [settling(3, 0), settling(0, 7)] {
            let mut retries = MAX_INDEX_SETTLING_RETRIES;
            let mut report = progress;
            assert!(settling_retry(&mut report, &mut retries).is_some());
            assert_eq!(retries, 1);
            assert!(!report.backoff);
        }
        // Other reasons are untouched.
        let mut other = PassReport { paused_reason: Some("index_catching_up".into()), ..PassReport::default() };
        let mut retries = 0;
        assert!(settling_retry(&mut other, &mut retries).is_none());
        assert_eq!((retries, other.paused_reason.as_deref(), other.backoff), (0, Some("index_catching_up"), false));
        // The worst-case jittered wait outlasts the 60 s settle gate.
        let floor: Duration = (1..=MAX_INDEX_SETTLING_RETRIES)
            .map(|n| (INDEX_SETTLING_RETRY_BASE.saturating_mul(1 << (n - 1).min(16)).min(INDEX_SETTLING_RETRY_MAX)) / 2)
            .sum();
        assert!(floor.as_millis() as i64 > crate::lake_part_gc::index::INDEX_SETTLE_MS, "{floor:?}");
    }

    fn progress_report(index_head: Option<u64>, appended_ms: Option<i64>, deleted: u64) -> PassReport {
        PassReport { index_head_seq: index_head, index_head_appended_ms: appended_ms, deleted, ..PassReport::default() }
    }

    /// NAN-3459: the progress line's lag (entries, entry time, time behind),
    /// its 1 h WARN threshold and its 5 min rate limit.
    #[tokio::test(start_paused = true)]
    async fn progress_line_reports_lag_warns_past_an_hour_and_is_rate_limited() {
        let mut progress = GcProgress::default();
        let hour_ms = 3_600_000_i64;
        progress.log_head_ms = Some(T0_MS + 26 * hour_ms);
        let now = tokio::time::Instant::now();
        // Index 6,784 entries / ~25.5 h behind the view head (the load-test tenant 10-10).
        let line = progress.observe(now, Some(25_592), &progress_report(Some(18_808), Some(T0_MS + hour_ms / 2), 0));
        assert_eq!(line.lag_entries, 6_784);
        assert_eq!(line.lag_seconds, Some(25 * 3_600 + 1_800));
        assert!(line.lagging);
        assert!(progress.take_log_slot(now));
        assert!(!progress.take_log_slot(now + Duration::from_secs(299)), "one line per 5 min");
        assert!(progress.take_log_slot(now + PROGRESS_LOG_EVERY));
        // A pass without an index sync keeps the known head and its time.
        let line = progress.observe(now, Some(25_600), &progress_report(None, None, 0));
        assert_eq!((line.index_head_seq, line.lag_entries), (Some(18_808), 6_792));
        // Caught up: no lag, not lagging, deletes accumulate.
        let later = now + Duration::from_secs(600);
        let line = progress.observe(later, Some(25_600), &progress_report(Some(25_600), Some(T0_MS + 26 * hour_ms), 4));
        assert_eq!((line.lag_entries, line.lag_seconds, line.behind_seconds, line.lagging), (0, Some(0), 0, false));
        assert_eq!(progress.deleted_total, 4);
        // Small entry lag but not caught up for over an hour: WARN.
        progress.log_head_ms = Some(T0_MS + 26 * hour_ms + 60_000);
        let line = progress.observe(later + Duration::from_secs(3_601), Some(25_610),
            &progress_report(Some(25_605), Some(T0_MS + 26 * hour_ms + 30_000), 0));
        assert_eq!((line.lag_entries, line.lag_seconds), (5, Some(30)));
        assert!(line.lagging, "{line:?}");
    }

    const T0_MS: i64 = 1_790_000_000_000;

    /// NAN-3459: a task ending at its lifetime mid catch-up is a healthy
    /// report (no back-off) and asks for an immediate resume; failures and
    /// back-off reports keep the exponential delay.
    #[tokio::test]
    async fn lifetime_end_mid_catch_up_resumes_now_without_back_off() {
        async fn finished(result: Result<PassReport>) -> Runner {
            let task = tokio::spawn(async move { result });
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
            Runner { task: Some(task), ..Runner::default() }
        }
        let catching_up = PassReport { paused_reason: Some("index_catching_up".into()), indexed: 9, ..PassReport::default() };
        let mut runner = finished(Ok(catching_up)).await;
        assert!(collect_report(&mut runner, 1_000).await.unwrap().is_ok());
        assert!(runner.resume_now && runner.failures == 0 && runner.next_allowed_ms == 0);
        let mut runner = finished(Err(anyhow::anyhow!("route withdrawn"))).await;
        collect_report(&mut runner, 1_000).await;
        assert!(!runner.resume_now && runner.failures == 1 && runner.next_allowed_ms > 1_000);
        let backoff = PassReport { paused_reason: Some("index_catching_up".into()), backoff: true, ..PassReport::default() };
        let mut runner = finished(Ok(backoff)).await;
        collect_report(&mut runner, 1_000).await;
        assert!(!runner.resume_now);
        let done = PassReport { deleted: 3, ..PassReport::default() };
        let mut runner = finished(Ok(done)).await;
        collect_report(&mut runner, 1_000).await;
        assert!(!runner.resume_now, "a finished deletion pass keeps ingest's cadence");
    }

    /// NAN-4769: the FP shape. Under live ingest a task deletes hundreds of
    /// files and then ends `index_catch_up_no_progress` with back-off. That
    /// is progress: the runner waits one jittered ordinary interval and
    /// never compounds it, however many such tasks run in a row. A task that
    /// deleted nothing still grows the exponential back-off, and the next
    /// productive task resets it.
    #[tokio::test]
    async fn productive_back_off_tasks_never_compound_the_back_off() {
        async fn collect(runner: &mut Runner, report: PassReport, now_ms: i64) {
            let task = tokio::spawn(async move { Ok(report) });
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
            runner.task = Some(task);
            assert!(collect_report(runner, now_ms).await.is_some_and(|result| result.is_ok()));
        }
        let interval = crate::part_ingest::ingest::SANCTIONED_GC_INTERVAL_MS;
        let stalled = |deleted| PassReport {
            paused_reason: Some("index_catch_up_no_progress".into()),
            backoff: true,
            deleted,
            ..PassReport::default()
        };
        let mut runner = Runner { armed: true, ..Runner::default() };
        let mut now = 1_000_000_i64;
        for task in 0..12 {
            collect(&mut runner, stalled(648), now).await;
            assert_eq!(runner.failures, 0, "task {task}: a task that deleted is not a failure");
            let wait = runner.next_allowed_ms - now;
            assert!((interval / 2..=interval).contains(&wait), "task {task}: waited {wait} ms, not one interval");
            assert!(runner.resume_after_backoff && pass_due_at_poll(&runner, runner.next_allowed_ms));
            now = runner.next_allowed_ms + 120_000;
        }
        // Twelve productive tasks used to reach the 6 h cap; one interval each now.
        collect(&mut runner, stalled(0), now).await;
        assert_eq!(runner.failures, 1);
        assert!((interval..=2 * interval).contains(&(runner.next_allowed_ms - now)));
        now = runner.next_allowed_ms;
        collect(&mut runner, stalled(0), now).await;
        assert_eq!(runner.failures, 2, "a task that deleted nothing still compounds");
        assert!((2 * interval..=4 * interval).contains(&(runner.next_allowed_ms - now)));
        now = runner.next_allowed_ms;
        collect(&mut runner, stalled(1), now).await;
        assert_eq!(runner.failures, 0, "the next productive task resets the count");
        assert!((interval / 2..=interval).contains(&(runner.next_allowed_ms - now)));
        // A task error is never progress.
        let task = tokio::spawn(async { Err(anyhow::anyhow!("route withdrawn")) });
        while !task.is_finished() {
            tokio::task::yield_now().await;
        }
        runner.task = Some(task);
        collect_report(&mut runner, now).await;
        assert_eq!(runner.failures, 1);
    }

    /// NAN-3495: unauthorizable-key markers survive a restart on the same
    /// state dir (not re-asked every pass after a cell restart), and a file
    /// for another tenant is ignored.
    #[test]
    fn refused_key_markers_are_durable_and_tenant_bound() {
        use crate::lake_part_gc::executor::OBJECT_NOT_FOUND;
        let dir = tempfile::tempdir().unwrap();
        let tenant = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let key = "lake/parts/v1/tenant=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/parts/l0/2026/10/07/12/1791374788023-cf07b50a714b43f0/data-00000.parquet";
        let store = ViewStore::new(dir.path());
        let mut state = LakePartGcState::genesis();
        state.refused_keys.remember(key, OBJECT_NOT_FOUND, T0_MS);
        store.save_refused(tenant, &mut state, T0_MS);
        assert!(store.refused_path().exists());

        let restarted = ViewStore::new(dir.path());
        let mut fresh = LakePartGcState::genesis();
        restarted.load_refused_once(tenant, &mut fresh);
        assert!(fresh.refused_keys.is_refused(key, T0_MS + 3_600_000));
        assert_eq!(fresh.refused_keys.count(OBJECT_NOT_FOUND, T0_MS), 1);
        // Loaded once per process.
        let mut again = LakePartGcState::genesis();
        restarted.load_refused_once(tenant, &mut again);
        assert!(again.refused_keys.is_empty());

        let foreign = ViewStore::new(dir.path());
        let mut other = LakePartGcState::genesis();
        foreign.load_refused_once("00000000-0000-0000-0000-000000000001", &mut other);
        assert!(other.refused_keys.is_empty(), "another tenant's markers are never used");
    }

    /// No GC pass is in flight (an index-only task may be).
    pub(super) fn no_pass_in_flight(runner: &Runner) -> bool {
        runner.task.is_none()
    }

    /// NAN-3495: retry and back-off delays are jittered into [d/2, d], and the
    /// index-incomplete retry grows exponentially up to its cap.
    #[test]
    fn retry_delays_are_jittered_and_bounded() {
        for _ in 0..256 {
            let d = jittered(Duration::from_secs(1_200));
            assert!(d >= Duration::from_secs(600) && d <= Duration::from_secs(1_200), "{d:?}");
        }
        assert_eq!(jittered(Duration::ZERO), Duration::ZERO);
        assert_eq!(jittered(Duration::from_millis(1)), Duration::from_millis(1));
        let spread = (0..64).map(|_| jittered(Duration::from_secs(600)).as_millis()).collect::<std::collections::BTreeSet<_>>();
        assert!(spread.len() > 1, "jitter must vary");
        for retry in 1..=MAX_INDEX_INCOMPLETE_RETRIES + 8 {
            let full = INDEX_INCOMPLETE_RETRY_BASE.saturating_mul(1 << (retry - 1).min(16)).min(INDEX_INCOMPLETE_RETRY_MAX);
            let d = index_incomplete_retry_delay(retry);
            assert!(d >= full / 2 && d <= full, "retry {retry}: {d:?}");
            assert!(d >= Duration::from_millis(125), "never the old 10 ms hot loop");
        }
    }

    /// NAN-4188: the index follower's due rule and failure back-off.
    #[tokio::test]
    async fn follower_publishes_each_new_receipted_append_once_coalesced_and_backs_off() {
        let armed = || Runner { armed: true, ..Runner::default() };
        assert!(!follow_due(&Runner::default(), 1_000, Some(5)), "never before the delete gate armed the runner");
        assert!(!follow_due(&armed(), 1_000, None), "nothing receipted (or still settling)");
        assert!(follow_due(&armed(), 1_000, Some(5)));
        let followed = Runner { follow_through: Some(5), ..armed() };
        assert!(!follow_due(&followed, 1_000, Some(5)), "published for this append already");
        assert!(follow_due(&followed, 1_000, Some(6)));
        let coalescing = Runner { follow_through: Some(5), next_follow_ms: 3_000, ..armed() };
        assert!(!follow_due(&coalescing, 2_999, Some(9)));
        assert!(follow_due(&coalescing, 3_000, Some(9)));
        let publishing = Runner { index_task: Some(tokio::spawn(async { Ok(PassReport::default()) })), ..armed() };
        assert!(!follow_due(&publishing, 1_000, Some(9)), "one publisher at a time");
        // A beside-the-pass task is allowed (unlike scheduled index-only).
        let pass = Runner { task: Some(tokio::spawn(async { Ok(PassReport::default()) })), ..armed() };
        assert!(follow_due(&pass, 1_000, Some(9)));
        assert!(!index_only_due(&pass, 1_000, true));
        // A refused publication (control 503 on lock contention) backs the
        // follower off with the index-only cadence, not every 2 s.
        let refused = tokio::spawn(async {
            Ok(PassReport { paused_reason: Some("lake_part_index_unavailable".into()), backoff: true, ..PassReport::default() })
        });
        while !refused.is_finished() {
            tokio::task::yield_now().await;
        }
        let mut runner = Runner { index_task: Some(refused), ..armed() };
        collect_index(&mut runner, 1_000).await;
        assert!(runner.next_follow_ms >= 61_000, "{}", runner.next_follow_ms);
        assert!(!follow_due(&runner, 2_000, Some(9)));
    }

    /// NAN-3495: an index-only task's result never resets or extends the pass
    /// back-off, and is not reported as a pass.
    #[tokio::test]
    async fn index_only_results_leave_the_pass_back_off_alone() {
        async fn finished(result: Result<PassReport>, runner: Runner) -> Runner {
            let task = tokio::spawn(async move { result });
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
            Runner { index_task: Some(task), ..runner }
        }
        let backing_off = || Runner { failures: 2, next_allowed_ms: 9_000_000, ..Runner::default() };
        let published = PassReport { indexed: 40, index_head_seq: Some(28_610), ..PassReport::default() };
        let mut runner = finished(Ok(published), backing_off()).await;
        assert!(collect_report(&mut runner, 1_000).await.is_none(), "not a pass report");
        collect_index(&mut runner, 1_000).await;
        assert!(runner.task.is_none() && runner.index_task.is_none());
        assert_eq!((runner.failures, runner.next_allowed_ms), (2, 9_000_000));
        let refused = PassReport { paused_reason: Some("lake_part_index_unavailable".into()), backoff: true, ..PassReport::default() };
        let mut runner = finished(Ok(refused), backing_off()).await;
        assert!(collect_report(&mut runner, 1_000).await.is_none());
        collect_index(&mut runner, 1_000).await;
        assert_eq!((runner.failures, runner.next_allowed_ms), (2, 9_000_000));
        assert_eq!(runner.index_failures, 1);
        assert!((1_000 + 60_000..=1_000 + 120_000).contains(&runner.next_index_ms), "own failures slow only its own cadence");
        let mut runner = finished(Err(anyhow::anyhow!("route withdrawn")), Runner::default()).await;
        assert!(collect_report(&mut runner, 1_000).await.is_none());
        collect_index(&mut runner, 1_000).await;
        assert_eq!((runner.failures, runner.next_allowed_ms), (0, 0));
        assert_eq!(runner.index_failures, 1);

        // Due on its own cadence between passes (backing off or not) and
        // beside a pass whose view is still folding; never beside a pass with
        // a complete view (it publishes the index itself), never twice.
        let idle = Runner { next_allowed_ms: 600_000, next_index_ms: 60_000, ..Runner::default() };
        assert!(!index_only_due(&idle, 59_999, false));
        assert!(index_only_due(&idle, 60_000, false));
        assert!(index_only_due(&idle, 600_000, true));
        assert!(index_only_due(&Runner::default(), 1_000, true), "between passes");
        let pass = || tokio::spawn(async { Ok(PassReport::default()) });
        let folding = Runner { task: Some(pass()), ..Runner::default() };
        assert!(index_only_due(&folding, 1_000, false), "a cold view's fold never freezes the index");
        assert!(!index_only_due(&folding, 1_000, true), "the pass publishes through its complete view");
        let publishing = Runner { index_task: Some(pass()), ..Runner::default() };
        assert!(!index_only_due(&publishing, 1_000, false));
        // A failed pass backs off by a jittered 20 min (base 10 min, 1st failure).
        let task = tokio::spawn(async { Ok(PassReport { paused_reason: Some("http_429".into()), backoff: true, ..PassReport::default() }) });
        while !task.is_finished() {
            tokio::task::yield_now().await;
        }
        let mut runner = Runner { task: Some(task), ..Runner::default() };
        assert!(collect_report(&mut runner, 0).await.is_some());
        assert_eq!(runner.failures, 1);
        assert!((600_000..=1_200_000).contains(&runner.next_allowed_ms), "{}", runner.next_allowed_ms);
        // The pass restarts at the first poll past its back-off deadline, not
        // at the next 10-min ingest schedule.
        assert!(runner.resume_after_backoff);
        assert!(!pass_due_at_poll(&runner, runner.next_allowed_ms - 1));
        assert!(pass_due_at_poll(&runner, runner.next_allowed_ms));
        let ok = tokio::spawn(async { Ok(PassReport { deleted: 1, ..PassReport::default() }) });
        while !ok.is_finished() {
            tokio::task::yield_now().await;
        }
        let mut runner = Runner { task: Some(ok), ..runner };
        collect_report(&mut runner, 2_000_000).await;
        assert!(!runner.resume_after_backoff && !pass_due_at_poll(&runner, 2_000_001), "a clean pass keeps ingest's cadence");
    }

    /// The cell image advertises `lean_part_gc_sanctioned_v1` exactly when
    /// this wiring is in the ingest binary.
    #[test]
    fn cell_feature_lean_part_gc_sanctioned_v1_is_backed() {
        assert!(nanosiem_lake_cell::features::CELL_FEATURES.contains(&FEATURE));
    }
}

#[cfg(test)]
#[path = "part_gc_transport_tests.rs"]
pub(crate) mod transport_tests;
