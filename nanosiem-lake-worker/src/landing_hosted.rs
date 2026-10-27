// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hosted OCSF bucket drop (NAN-3885 design step 3, NAN-4137): the
//! [`Discover`] and [`Emit`] halves `landing[T]` runs the shared landing
//! conversion with.
//!
//! - [`LeaseDiscover`]: files come from the tenant's landing ledger, a
//!   Durable Object (`landing:<tenant>`) the tenant Worker writes when a
//!   sender's PUT (or CompleteMultipartUpload) lands. The converter takes an
//!   epoch-fenced consumer lease, leases files with `next`, and commits each
//!   outcome (`accepted` / `refused` / `retry`) under that epoch. A stale
//!   epoch is answered 409 `fenced` ([`LedgerFenced`]): the process stops
//!   instead of racing a newer consumer. Hosted lean tenants never LIST
//!   their bucket.
//! - [`EdgeAppend`]: converted bronze goes into the tenant edge log through
//!   `POST /edge-log/v1/produce` as segments of at most
//!   [`MAX_SEGMENT_BYTES`], keyed like Vector's single-shard sink
//!   (`bronze-v2/shard=0/tenant_id=<T>/<secs>-<uuid v4>.parquet`), so
//!   ingest[T] admits it unchanged: admission, enrichment, prevalence, the
//!   6 h + 72 h uid dedupe, parts and row metering. Every produce names the
//!   epoch and the landed file it came from; the Worker refuses it unless
//!   that epoch still leases that file.
//!
//! Order per file (TZ-FRONT CONTRACT.md B5): `next`, read, convert, produce
//! each segment, commit, delete the landed object. A crash anywhere before
//! the commit is a reconversion: a new lease fences the old epoch and `next`
//! hands the file out again. Its rows keep their `metadata.uid` (sender's,
//! or `sha256(file):ordinal`), so ingest[T]'s uid window drops the repeats.
//!
//! A file that is held (edge log 503) or failed transiently stays leased by
//! this epoch and is retried locally without spending a ledger attempt;
//! only after [`LOCAL_RETRIES`] transient failures is it handed back with
//! `retry` (the ledger refuses it as `attempts_exhausted` after five).
//!
//! Wire contract: `~/.cache/claude-work/tzfront/CONTRACT.md` §B (TZ-FRONT,
//! NAN-4135); differences are listed in
//! `~/.cache/claude-work/tzcell/CONTRACT-CONFLICTS.md`.

use anyhow::{bail, ensure, Context, Result};
use arrow_array::RecordBatch;
use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use opendal::Operator;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::landing::{
    encode_bronze_batch, move_aside, Backpressure, Candidate, Claim, Claimed, Converted, Discover, Emit, FileRefusal,
    LandingSource, LeasedFile, RefusalDetail, RefusedCopy, BRONZE_PREFIX, LANDING_PREFIX,
};
use crate::parts::provenance::is_edge_segment_key;
use crate::parts::sha256_hex;

/// The edge log's produce cap (`MAX_SEGMENT_BYTES` = 8388608): one segment, one produce.
pub const MAX_SEGMENT_BYTES: usize = 8 * 1024 * 1024;
/// Most files leased per `next` (the ledger accepts `max` 1..16).
pub const MAX_LEASE_FILES: usize = 16;
/// Transient failures of one leased file retried locally (no ledger
/// attempt spent) before it is handed back with `retry`.
pub const LOCAL_RETRIES: u32 = 3;
/// Largest ledger response read.
const MAX_LEDGER_RESPONSE_BYTES: usize = 1024 * 1024;
/// Produces answered 503 are retried this often inside one emit before the
/// file is held (the edge log's admission is full).
const BUSY_RETRIES: u32 = 3;
const BUSY_BACKOFF: Duration = Duration::from_millis(250);
/// Per-source counters kept (a tenant has a handful of sources).
pub const MAX_COUNTED_SOURCES: usize = 256;
/// The Worker accepts segment timestamps in `now - 7 d ..= now + 5 min`;
/// a landed time older than this falls back to now.
const SEGMENT_WINDOW_SECS: i64 = 7 * 24 * 3600 - 3600;
/// Route key used when the ledger does not carry the source's slug.
pub const FALLBACK_ROUTE_KEY: &str = "tenzir_landing";

// ------------------------------------------------------------------ ledger

/// One leased file as `next` returns it (CONTRACT.md B2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerFile {
    pub key: String,
    pub seq: u64,
    pub source_id: Uuid,
    pub bytes: u64,
    #[serde(default)]
    pub etag: Option<String>,
    /// 1 on the first lease; every `next` that hands it out counts one.
    pub attempt: i32,
    /// When the file landed, ms since the Unix epoch.
    #[serde(default)]
    pub landed_at: Option<i64>,
    /// The source's slug (`metadata.log_source`). Not in CONTRACT.md yet
    /// (CONTRACT-CONFLICTS.md C3); [`FALLBACK_ROUTE_KEY`] when absent.
    #[serde(default)]
    pub source_slug: Option<String>,
    /// The landing credential that wrote the file. Not in CONTRACT.md yet
    /// (C3); the nil UUID when absent.
    #[serde(default)]
    pub credential_id: Option<Uuid>,
}

impl LedgerFile {
    /// The source the rows are stamped with. The Worker admitted the sender
    /// against an active authority row when the file landed; the folder
    /// must still agree with `sourceId` (checked by the engine).
    fn landing_source(&self) -> LandingSource {
        let route_key = self
            .source_slug
            .as_deref()
            .map(|slug| slug.replace('-', "_"))
            .filter(|slug| {
                slug.len() <= 100
                    && slug.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                    && slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            })
            .unwrap_or_else(|| FALLBACK_ROUTE_KEY.to_string());
        LandingSource {
            source_id: self.source_id,
            route_key,
            credential_id: self.credential_id.unwrap_or(Uuid::nil()),
            active: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextOutcome {
    Files(Vec<LedgerFile>),
    /// A newer consumer lease exists: this converter must stop.
    Fenced,
    /// The ledger is briefly unavailable; try again next tick.
    Busy,
}

/// A file's outcome, committed under the consumer epoch (CONTRACT.md B3).
/// Exactly the contract's keys: the ledger answers 400 to any other.
///
/// NAN-4321 adds the row accounting keys (`rowsRefused`, `rowReason`,
/// `detail`). A Worker from before them answers 400 to a commit carrying
/// them; [`LeaseDiscover`] then commits again without them
/// ([`LedgerCommit::base`]), so the two can roll in either order.
///
/// NAN-4325 adds `contentSha256` on `accepted`: the ledger decides a file
/// identical to one accepted for the source in the last 72 h `duplicate`
/// (state `duplicate`, not counted as accepted). A Worker from before it
/// answers 400; the commit is retried without the hash first
/// ([`LedgerCommit::without_hash`]), then without the NAN-4321 keys.
///
/// NAN-4336 adds `rowsClamped` on `accepted`. A Worker from before it answers
/// 400; the commit is retried without it first
/// ([`LedgerCommit::without_clamped`]), then as above.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerCommit {
    pub epoch: u64,
    pub key: String,
    /// `accepted`, `refused` or `retry`.
    pub outcome: &'static str,
    /// Rows accepted (`accepted`); 0 for `refused` (its rows are `rows_refused`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<u64>,
    /// Value-free reason code (`[a-z0-9_]{1,64}`); required for `refused`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// Rows of the file that were refused: inside an accepted file, or with a
    /// refused one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_refused: Option<u64>,
    /// `accepted` with refused rows: the (first) row refusal's reason code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_reason: Option<&'static str>,
    /// Where the refusal named by `reason` (refused) or `row_reason`
    /// (accepted) happened: `class_uid=<n> field=<path>`
    /// ([`RefusalDetail::render`]). Value-free.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// `accepted`: sha256 of the landed bytes (lowercase hex), the same
    /// hash the rows' fallback uids derive from (NAN-4325).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    /// NAN-4336: `accepted` rows whose future `time` was clamped to the
    /// conversion time (sent only when non-zero).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_clamped: Option<u64>,
}

impl LedgerCommit {
    /// Does this commit carry any NAN-4321 key?
    pub fn has_row_accounting(&self) -> bool {
        self.rows_refused.is_some() || self.row_reason.is_some() || self.detail.is_some()
    }

    /// The commit as a Worker from before NAN-4336 accepts it.
    pub fn without_clamped(&self) -> Self {
        Self { rows_clamped: None, ..self.clone() }
    }

    /// The commit as a Worker from before NAN-4325 accepts it.
    pub fn without_hash(&self) -> Self {
        Self { content_sha256: None, rows_clamped: None, ..self.clone() }
    }

    /// The commit as a Worker from before NAN-4321 accepts it.
    pub fn base(&self) -> Self {
        Self { rows_refused: None, row_reason: None, detail: None, content_sha256: None, rows_clamped: None, ..self.clone() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerCommitOutcome {
    /// 200 `ok`. `state` is the file's state after the commit: a `retry`
    /// past five attempts comes back `refused` (`attempts_exhausted`).
    Committed { state: Option<String> },
    /// The same decision already landed (an HTTP retry).
    Replayed,
    /// 409 `fenced`: a stale epoch, or the file is not leased by it.
    Fenced,
    /// 409 `conflict`: the file was already decided differently.
    Conflict,
    /// 404: the ledger no longer knows the file (pruned after 7 days).
    Unknown,
    /// 400: the Worker refused the commit's shape (a Worker from before a
    /// key this commit carries).
    Invalid,
}

/// The tenant's landing ledger (`/landing-ledger/v1/*`). A fake implements it in tests.
#[async_trait]
pub trait LandingLedgerTransport: Send + Sync {
    /// Take the consumer lease; returns its epoch (each call fences the previous one).
    async fn lease(&self, consumer_id: &str) -> Result<u64>;
    async fn next(&self, epoch: u64, max: usize) -> Result<NextOutcome>;
    async fn commit(&self, commit: &LedgerCommit) -> Result<LedgerCommitOutcome>;
}

/// The ledger refused this converter's epoch: a newer `landing[T]` holds the
/// lease. The process exits; it never commits under a stale epoch.
pub use crate::landing::Fenced as LedgerFenced;

// ------------------------------------------------------------------ edge log producer

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended { seq: u64 },
    /// The same key and bytes were already appended (an HTTP retry).
    Replayed { seq: u64 },
    /// 503: the edge log's admission is full or briefly unavailable.
    Busy,
    /// 412: the segment key exists with other bytes.
    Conflict,
    /// 409: the epoch is stale, or no longer leases the landed file.
    Fenced,
}

/// One produce (CONTRACT.md B5).
#[derive(Debug, Clone, Copy)]
pub struct Produce<'a> {
    pub epoch: u64,
    /// The landed file the segment came from (leased by `epoch`).
    pub landing_key: &'a str,
    pub segment_key: &'a str,
    pub sha256: &'a str,
    pub bytes: &'a [u8],
}

/// The tenant edge log's producer route. A fake implements it in tests.
#[async_trait]
pub trait EdgeLogProducer: Send + Sync {
    /// The tenant this producer is bound to; every key it sends is that tenant's.
    fn tenant_id(&self) -> &str;
    async fn produce(&self, produce: Produce<'_>) -> Result<AppendOutcome>;
}

/// A produce whose segment or landing key is not this producer's tenant's.
/// Refused before any request leaves.
#[derive(Debug, Clone, thiserror::Error)]
#[error("edge-log produce refused: a key is not this tenant's")]
pub struct CrossTenantAppend;

/// Check a produce's keys against the producer's tenant (the Worker checks them again).
pub fn check_append_key(tenant_id: &str, segment_key: &str, landing_key: &str) -> Result<()> {
    if !is_edge_segment_key(tenant_id, segment_key) || !own_landing_key(tenant_id, landing_key) {
        return Err(CrossTenantAppend.into());
    }
    Ok(())
}

/// Is `key` inside `tenant_id`'s landing folder? Anything else is never
/// read, copied, deleted or named in a produce, whatever the ledger says
/// (the credential would refuse it too: it covers the landing prefixes only).
pub fn own_landing_key(tenant_id: &str, key: &str) -> bool {
    key.strip_prefix(LANDING_PREFIX)
        .and_then(|rest| rest.strip_prefix(&format!("tenant_id={tenant_id}/")))
        .is_some_and(|rest| !rest.is_empty() && !rest.split('/').any(|p| p.is_empty() || p == "." || p == ".."))
        && !key.chars().any(char::is_control)
}

// ------------------------------------------------------------------ counters

/// Landing status since process start, reported in the heartbeat and the
/// cell status push. Reasons are value-free codes, never row values.
#[derive(Debug, Default)]
pub struct LandingCounters {
    pub files_accepted: AtomicU64,
    pub files_refused: AtomicU64,
    pub files_held: AtomicU64,
    pub rows_accepted: AtomicU64,
    pub rows_refused: AtomicU64,
    pub segments_appended: AtomicU64,
    pub bytes_appended: AtomicU64,
    pub ticks_failed: AtomicU64,
    pub last_file_unix_ms: AtomicU64,
    sources: Mutex<BTreeMap<Uuid, nanosiem_lake_cell::contract::LandingSourceStatus>>,
    reasons: Mutex<BTreeMap<String, u64>>,
}

impl LandingCounters {
    fn now_ms() -> u64 {
        chrono::Utc::now().timestamp_millis().max(0) as u64
    }

    fn per_source(&self, source: Option<Uuid>, f: impl FnOnce(&mut nanosiem_lake_cell::contract::LandingSourceStatus)) {
        let Some(source) = source else { return };
        let mut sources = self.sources.lock().expect("landing counters lock");
        if !sources.contains_key(&source) && sources.len() >= MAX_COUNTED_SOURCES {
            return;
        }
        f(sources.entry(source).or_default());
    }

    pub fn accepted(&self, source: Option<Uuid>, rows_accepted: u64, rows_refused: u64) {
        self.files_accepted.fetch_add(1, Ordering::Relaxed);
        self.rows_accepted.fetch_add(rows_accepted, Ordering::Relaxed);
        self.rows_refused.fetch_add(rows_refused, Ordering::Relaxed);
        let now = Self::now_ms();
        self.last_file_unix_ms.store(now, Ordering::Relaxed);
        self.per_source(source, |s| {
            s.files_accepted += 1;
            s.rows_accepted += rows_accepted;
            s.rows_refused += rows_refused;
            s.last_file_unix_ms = now;
        });
    }

    pub fn refused(&self, source: Option<Uuid>, reason: &'static str, rows_refused: u64) {
        self.files_refused.fetch_add(1, Ordering::Relaxed);
        self.rows_refused.fetch_add(rows_refused, Ordering::Relaxed);
        let now = Self::now_ms();
        self.last_file_unix_ms.store(now, Ordering::Relaxed);
        *self.reasons.lock().expect("landing counters lock").entry(reason.to_string()).or_default() += 1;
        self.per_source(source, |s| {
            s.files_refused += 1;
            s.rows_refused += rows_refused;
            s.last_reason = Some(reason.to_string());
            s.last_file_unix_ms = now;
        });
    }

    pub fn held(&self) {
        self.files_held.fetch_add(1, Ordering::Relaxed);
    }

    pub fn status(&self) -> nanosiem_lake_cell::contract::LandingStatus {
        nanosiem_lake_cell::contract::LandingStatus {
            files_accepted: self.files_accepted.load(Ordering::Relaxed),
            files_refused: self.files_refused.load(Ordering::Relaxed),
            files_held: self.files_held.load(Ordering::Relaxed),
            rows_accepted: self.rows_accepted.load(Ordering::Relaxed),
            rows_refused: self.rows_refused.load(Ordering::Relaxed),
            segments_appended: self.segments_appended.load(Ordering::Relaxed),
            bytes_appended: self.bytes_appended.load(Ordering::Relaxed),
            ticks_failed: self.ticks_failed.load(Ordering::Relaxed),
            last_file_unix_ms: self.last_file_unix_ms.load(Ordering::Relaxed),
            refused_by_reason: self.reasons.lock().expect("landing counters lock").clone(),
            sources: self
                .sources
                .lock()
                .expect("landing counters lock")
                .iter()
                .map(|(id, s)| (id.hyphenated().to_string(), s.clone()))
                .collect(),
        }
    }
}

// ------------------------------------------------------------------ discover: DO lease

/// A file this epoch leased and has not decided yet.
struct Outstanding {
    candidate: Candidate,
    failures: u32,
}

/// Hosted discovery: files leased from the tenant's landing ledger.
pub struct LeaseDiscover<T: LandingLedgerTransport> {
    transport: Arc<T>,
    consumer_id: String,
    tenant_id: String,
    epoch: tokio::sync::Mutex<Option<u64>>,
    /// Leased by this epoch, not yet committed. The ledger never hands these
    /// out again under the same epoch, so they are retried from here first.
    outstanding: Mutex<BTreeMap<u64, Outstanding>>,
    counters: Arc<LandingCounters>,
}

impl<T: LandingLedgerTransport> LeaseDiscover<T> {
    pub fn new(transport: Arc<T>, tenant_id: &str, consumer_id: &str, counters: Arc<LandingCounters>) -> Self {
        Self {
            transport,
            consumer_id: consumer_id.to_string(),
            tenant_id: tenant_id.to_string(),
            epoch: tokio::sync::Mutex::new(None),
            outstanding: Mutex::new(BTreeMap::new()),
            counters,
        }
    }

    pub fn transport(&self) -> &Arc<T> {
        &self.transport
    }

    /// Files leased by this epoch and not decided yet.
    pub fn outstanding(&self) -> usize {
        self.outstanding.lock().expect("landing outstanding lock").len()
    }

    /// The consumer epoch, taking the lease on first use.
    pub async fn epoch(&self) -> Result<u64> {
        let mut epoch = self.epoch.lock().await;
        if let Some(epoch) = *epoch {
            return Ok(epoch);
        }
        let leased = self.transport.lease(&self.consumer_id).await.context("take the landing ledger lease")?;
        ensure!(leased > 0, "landing ledger lease returned epoch 0");
        *epoch = Some(leased);
        Ok(leased)
    }

    fn leased<'c>(&self, candidate: &'c Candidate) -> Result<&'c LeasedFile> {
        candidate.leased.as_ref().context("hosted landing candidate carries no lease")
    }

    fn settle(&self, candidate: &Candidate) {
        if let Some(leased) = &candidate.leased {
            self.outstanding.lock().expect("landing outstanding lock").remove(&(leased.id as u64));
        }
    }

    fn commit_of(&self, candidate: &Candidate, outcome: &'static str, rows: Option<u64>, reason: Option<&'static str>)
        -> Result<LedgerCommit> {
        let leased = self.leased(candidate)?;
        Ok(LedgerCommit {
            epoch: leased.epoch,
            key: candidate.key.clone(),
            outcome,
            rows,
            reason,
            rows_refused: None,
            row_reason: None,
            detail: None,
            content_sha256: None,
            rows_clamped: None,
        })
    }

    async fn commit(&self, candidate: &Candidate, commit: LedgerCommit) -> Result<LedgerCommitOutcome> {
        let leased = self.leased(candidate)?;
        let outcome = commit.outcome;
        let mut answer = self.transport.commit(&commit).await?;
        if answer == LedgerCommitOutcome::Invalid && commit.rows_clamped.is_some() {
            // A Worker from before NAN-4336: the clamped rows are still
            // accepted rows (and counted in the cell status push).
            tracing::warn!(outcome, "landing ledger refused the clamped-row count; committing without it");
            answer = self.transport.commit(&commit.without_clamped()).await?;
        }
        if answer == LedgerCommitOutcome::Invalid && commit.content_sha256.is_some() {
            // A Worker from before NAN-4325: no duplicate detection, the
            // file is accepted as before.
            tracing::warn!(outcome, "landing ledger refused the content hash; committing without it");
            answer = self.transport.commit(&commit.without_hash()).await?;
        }
        if answer == LedgerCommitOutcome::Invalid && commit.has_row_accounting() {
            // A Worker from before NAN-4321: the decision matters more than
            // its row accounting, which the cell status push still reports.
            tracing::warn!(outcome, "landing ledger refused the row accounting keys; committing without them");
            answer = self.transport.commit(&commit.base()).await?;
        }
        match &answer {
            LedgerCommitOutcome::Fenced => return Err(LedgerFenced.into()),
            LedgerCommitOutcome::Conflict => {
                tracing::warn!(seq = leased.id, outcome, "landing ledger: the file was already decided differently; leaving it");
            }
            LedgerCommitOutcome::Unknown => {
                tracing::warn!(seq = leased.id, outcome, "landing ledger no longer knows the file; leaving it");
            }
            LedgerCommitOutcome::Invalid => bail!("landing ledger refused the {outcome} commit as invalid"),
            LedgerCommitOutcome::Committed { .. } | LedgerCommitOutcome::Replayed => {}
        }
        Ok(answer)
    }

    /// Delete a finished landed object. Best effort: the commit is the
    /// record, and a lingering object is never leased again.
    async fn delete_landed(&self, store: &Operator, key: &str) {
        if !own_landing_key(&self.tenant_id, key) {
            return;
        }
        if let Err(error) = store.delete(key).await {
            tracing::warn!(error = %error, "finished landed object not deleted");
        }
    }

    /// Move a refused object aside. A missing one (already moved by an
    /// attempt that crashed before its commit) is not an error.
    async fn move_refused(&self, store: &Operator, key: &str) -> Result<()> {
        if !own_landing_key(&self.tenant_id, key) {
            return Ok(());
        }
        match move_aside(store, key).await {
            Ok(()) => Ok(()),
            Err(error) if error.downcast_ref::<opendal::Error>().is_some_and(|e| e.kind() == opendal::ErrorKind::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[async_trait]
impl<T: LandingLedgerTransport> Discover for LeaseDiscover<T> {
    async fn discover(&self, _store: &Operator, tenant_id: &str, max: usize) -> Result<(usize, Vec<Candidate>)> {
        ensure!(tenant_id == self.tenant_id, "landing discover bound to another tenant");
        let epoch = self.epoch().await?;
        let max = max.max(1);
        let mut candidates = self
            .outstanding
            .lock()
            .expect("landing outstanding lock")
            .values()
            .take(max)
            .map(|o| o.candidate.clone())
            .collect::<Vec<_>>();
        if candidates.len() < max {
            let files = match self.transport.next(epoch, (max - candidates.len()).clamp(1, MAX_LEASE_FILES)).await? {
                NextOutcome::Files(files) => files,
                NextOutcome::Busy => Vec::new(),
                NextOutcome::Fenced => return Err(LedgerFenced.into()),
            };
            let mut outstanding = self.outstanding.lock().expect("landing outstanding lock");
            for file in files {
                let candidate = Candidate {
                    key: file.key.clone(),
                    etag: file.etag.clone(),
                    size: file.bytes,
                    leased: Some(LeasedFile {
                        id: i64::try_from(file.seq).context("ledger seq out of range")?,
                        attempt: file.attempt.max(1),
                        epoch,
                        landed_at_ms: file.landed_at,
                        source: Some(file.landing_source()),
                    }),
                };
                outstanding.insert(file.seq, Outstanding { candidate: candidate.clone(), failures: 0 });
                candidates.push(candidate);
            }
        }
        Ok((candidates.len(), candidates))
    }

    async fn claim(&self, _store: &Operator, candidate: &Candidate, _source_id: Option<Uuid>) -> Result<Claimed> {
        // The lease is the claim.
        let leased = self.leased(candidate)?;
        Ok(Claimed { claim: Claim::Owned { id: leased.id, attempt: leased.attempt }, size: candidate.size, preloaded: None })
    }

    async fn source(&self, candidate: &Candidate, source_id: Uuid) -> Result<Option<LandingSource>> {
        // The folder decides the source (NAN-3806); the Worker's resolution
        // must agree, or the file is refused as `source_unknown`.
        Ok(self.leased(candidate)?.source.clone().filter(|source| source.source_id == source_id))
    }

    async fn finish_accepted(&self, store: &Operator, candidate: &Candidate, _id: i64, converted: &Converted, _emitted: &str) -> Result<()> {
        let leased = self.leased(candidate)?;
        let mut commit = self.commit_of(candidate, "accepted", Some(converted.rows_accepted), None)?;
        // NAN-4325: the ledger decides an identical re-upload `duplicate`.
        commit.content_sha256 = Some(converted.content_sha256.clone());
        // NAN-4336: future-dated rows clamped to the conversion time.
        if converted.rows_time_clamped > 0 {
            commit.rows_clamped = Some(converted.rows_time_clamped);
            tracing::warn!(seq = leased.id, rows_clamped = converted.rows_time_clamped, rows = converted.rows_accepted,
                source = leased.source.as_ref().map(|s| s.source_id.hyphenated().to_string()).unwrap_or_default(),
                "landed file had future-dated rows; their time was clamped to the conversion time");
        }
        // NAN-4321: rows refused inside an accepted file are recorded with
        // the file, never dropped silently.
        if converted.rows_refused > 0 {
            commit.rows_refused = Some(converted.rows_refused);
            commit.row_reason = converted.first_refusal.as_ref().map(|refusal| refusal.reason);
            commit.detail = converted.first_refusal_detail.as_ref().map(RefusalDetail::render);
        }
        let answer = self.commit(candidate, commit).await?;
        self.settle(candidate);
        if matches!(answer, LedgerCommitOutcome::Committed { .. } | LedgerCommitOutcome::Replayed) {
            // A duplicate's segments were appended like any file's (ingest[T]'s
            // uid window drops its rows); it is not an accepted file.
            if matches!(&answer, LedgerCommitOutcome::Committed { state: Some(state) } if state == "duplicate") {
                tracing::info!(seq = leased.id, "landing ledger: identical to a file accepted in the last 72 h; counted duplicate");
            } else {
                self.counters.accepted(leased.source.as_ref().map(|s| s.source_id), converted.rows_accepted, converted.rows_refused);
            }
            self.delete_landed(store, &candidate.key).await;
        }
        Ok(())
    }

    async fn finish_refused(
        &self,
        store: &Operator,
        candidate: &Candidate,
        _id: i64,
        refusal: &FileRefusal,
        _sha: Option<&str>,
        // The hosted edge-log output never keeps refused copies itself: this
        // always copies aside before deleting. It never asks to keep a file
        // in place; refuse that rather than delete without a copy.
        copy: RefusedCopy,
    ) -> Result<()> {
        if copy == RefusedCopy::InPlace {
            bail!("hosted landing cannot keep a refused file in place");
        }
        let leased = self.leased(candidate)?;
        // Moved first, then committed: a bad file can never wedge the ledger,
        // and a crash in between re-refuses it (the move tolerates NotFound).
        self.move_refused(store, &candidate.key).await?;
        // `rows` stays 0: the ledger adds it to the source's accepted rows.
        // The refused rows travel as `rowsRefused` (NAN-4321).
        let mut commit = self.commit_of(candidate, "refused", Some(0), Some(refusal.reason))?;
        commit.rows_refused = (refusal.rows > 0).then_some(refusal.rows);
        commit.detail = refusal.detail.as_ref().map(RefusalDetail::render);
        let answer = self.commit(candidate, commit).await?;
        self.settle(candidate);
        if matches!(answer, LedgerCommitOutcome::Committed { .. } | LedgerCommitOutcome::Replayed) {
            self.counters.refused(leased.source.as_ref().map(|s| s.source_id), refusal.reason, refusal.rows);
            self.delete_landed(store, &candidate.key).await;
        }
        Ok(())
    }

    async fn finish_redelivered(&self, _store: &Operator, _candidate: &Candidate, _id: i64) -> Result<()> {
        // The ledger never leases a decided file (the Worker answers a
        // sender's re-PUT itself); a lease is always `Owned`.
        bail!("hosted landing ledger leased a finished file")
    }

    async fn release(&self, _candidate: &Candidate, _id: i64) -> Result<()> {
        // Held: the file stays leased by this epoch and outstanding, and is
        // retried first next tick. No `retry` commit: that would spend one of
        // its five ledger attempts on our own backpressure.
        self.counters.held();
        Ok(())
    }

    async fn failed(&self, store: &Operator, candidate: &Candidate) -> Result<()> {
        let leased = self.leased(candidate)?;
        let seq = leased.id as u64;
        let failures = {
            let mut outstanding = self.outstanding.lock().expect("landing outstanding lock");
            let Some(entry) = outstanding.get_mut(&seq) else { return Ok(()) };
            entry.failures += 1;
            entry.failures
        };
        if failures < LOCAL_RETRIES {
            return Ok(());
        }
        // Hand it back: a later `next` leases it again (one ledger attempt).
        match self.commit(candidate, self.commit_of(candidate, "retry", None, None)?).await? {
            LedgerCommitOutcome::Committed { state: Some(state) } if state == "refused" => {
                // Past five attempts the ledger refused it (`attempts_exhausted`).
                self.move_refused(store, &candidate.key).await?;
                self.counters.refused(leased.source.as_ref().map(|s| s.source_id), "attempts_exhausted", 0);
                self.delete_landed(store, &candidate.key).await;
            }
            _ => {}
        }
        self.settle(candidate);
        Ok(())
    }
}

// ------------------------------------------------------------------ emit: edge-log produce

/// Deterministic key of segment `index` of a landed file (CONTRACT.md B5):
/// timestamp = the landed time (now when unknown or outside the Worker's
/// window), uuid v4 = the first 16 bytes of `sha256(file_sha256 "\n" index)`
/// with the version and variant bits set. A reconversion with identical
/// bytes replays inside the edge log's 1 h retention.
pub fn segment_key(tenant_id: &str, file_sha256: &str, index: usize, landed_at_ms: Option<i64>, now: chrono::DateTime<chrono::Utc>) -> String {
    let now_secs = now.timestamp();
    let secs = landed_at_ms
        .map(|ms| ms.div_euclid(1000))
        .filter(|secs| *secs >= now_secs - SEGMENT_WINDOW_SECS && *secs <= now_secs + 60)
        .unwrap_or(now_secs);
    let digest = Sha256::digest(format!("{file_sha256}\n{index}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    let uuid = uuid::Builder::from_random_bytes(bytes).into_uuid();
    format!("{BRONZE_PREFIX}shard=0/tenant_id={tenant_id}/{secs:010}-{uuid}.parquet")
}

/// A one-off segment key, used when the deterministic one already holds
/// other bytes (the bronze stage stamps `logged_time`/`processed_time` at
/// conversion, so a reconversion's bytes differ): uid dedupe drops the rows.
fn fresh_segment_key(tenant_id: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    format!("{BRONZE_PREFIX}shard=0/tenant_id={tenant_id}/{:010}-{}.parquet", now.timestamp(), Uuid::new_v4())
}

/// Split one encoded bronze object into segments of at most `max` bytes,
/// each a complete bronze Parquet file (the same encoding). An object that
/// fits is passed through unchanged. A single row that does not fit refuses
/// the file (`segment_too_large`).
pub fn split_segments(object: &[u8], rows: u64, max: usize) -> Result<Vec<(Vec<u8>, u64)>> {
    if object.len() <= max {
        return Ok(vec![(object.to_vec(), rows)]);
    }
    let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(object))?.build()?;
    let batches = reader.collect::<Result<Vec<RecordBatch>, _>>()?;
    let Some(first) = batches.first() else { bail!("bronze object has no rows") };
    let batch = arrow_select::concat::concat_batches(&first.schema(), &batches)?;
    let mut out = Vec::new();
    split_batch(&batch, max, &mut out)?;
    Ok(out)
}

fn split_batch(batch: &RecordBatch, max: usize, out: &mut Vec<(Vec<u8>, u64)>) -> Result<()> {
    let encoded = encode_bronze_batch(batch)?;
    if encoded.len() <= max {
        out.push((encoded, batch.num_rows() as u64));
        return Ok(());
    }
    if batch.num_rows() <= 1 {
        return Err(FileRefusal::new("segment_too_large").into());
    }
    let half = batch.num_rows() / 2;
    split_batch(&batch.slice(0, half), max, out)?;
    split_batch(&batch.slice(half, batch.num_rows() - half), max, out)
}

/// Hosted emit: produce the converted bronze into the tenant edge log.
pub struct EdgeAppend<P: EdgeLogProducer> {
    producer: Arc<P>,
    counters: Arc<LandingCounters>,
    max_segment_bytes: usize,
    busy_backoff: Duration,
}

impl<P: EdgeLogProducer> EdgeAppend<P> {
    pub fn new(producer: Arc<P>, counters: Arc<LandingCounters>) -> Self {
        Self { producer, counters, max_segment_bytes: MAX_SEGMENT_BYTES, busy_backoff: BUSY_BACKOFF }
    }

    /// Tests: a smaller segment cap and no backoff.
    pub fn with_limits(mut self, max_segment_bytes: usize, busy_backoff: Duration) -> Self {
        self.max_segment_bytes = max_segment_bytes;
        self.busy_backoff = busy_backoff;
        self
    }

    pub fn producer(&self) -> &Arc<P> {
        &self.producer
    }

    async fn produce_one(&self, produce: Produce<'_>) -> Result<AppendOutcome> {
        let mut busy = 0;
        loop {
            match self.producer.produce(produce).await? {
                AppendOutcome::Busy if busy < BUSY_RETRIES => {
                    busy += 1;
                    tokio::time::sleep(self.busy_backoff * busy).await;
                }
                AppendOutcome::Busy => return Err(Backpressure.into()),
                AppendOutcome::Fenced => return Err(LedgerFenced.into()),
                other => return Ok(other),
            }
        }
    }
}

#[async_trait]
impl<P: EdgeLogProducer> Emit for EdgeAppend<P> {
    async fn emit(&self, _store: &Operator, tenant_id: &str, candidate: &Candidate, converted: &Converted) -> Result<String> {
        ensure!(self.producer.tenant_id() == tenant_id, CrossTenantAppend);
        let leased = candidate.leased.as_ref().context("hosted landing emit without a lease")?;
        // Split everything first: a refusal is decided before any produce.
        let mut segments = Vec::new();
        for (_, body, rows) in &converted.objects {
            segments.extend(split_segments(body, *rows, self.max_segment_bytes)?);
        }
        let now = chrono::Utc::now();
        let mut seqs = Vec::with_capacity(segments.len());
        for (index, (bytes, _rows)) in segments.iter().enumerate() {
            let sha = sha256_hex(bytes);
            let mut key = segment_key(tenant_id, &converted.content_sha256, index, leased.landed_at_ms, now);
            let mut fresh = false;
            let seq = loop {
                check_append_key(tenant_id, &key, &candidate.key)?;
                let produce = Produce { epoch: leased.epoch, landing_key: &candidate.key, segment_key: &key, sha256: &sha, bytes };
                match self.produce_one(produce).await? {
                    AppendOutcome::Appended { seq } | AppendOutcome::Replayed { seq } => break seq,
                    AppendOutcome::Conflict if !fresh => {
                        // An earlier conversion of this file produced other
                        // bytes under the deterministic key.
                        fresh = true;
                        key = fresh_segment_key(tenant_id, now);
                    }
                    AppendOutcome::Conflict => bail!("edge log holds a fresh landing segment key with other bytes"),
                    AppendOutcome::Busy | AppendOutcome::Fenced => unreachable!("handled by produce_one"),
                }
            };
            self.counters.segments_appended.fetch_add(1, Ordering::Relaxed);
            self.counters.bytes_appended.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            seqs.push(seq.to_string());
        }
        Ok(seqs.join(","))
    }
}

// ------------------------------------------------------------------ HTTP transports

/// The tenant Worker origin, checked like the edge-log consumer's.
fn worker_base(base: &str) -> Result<reqwest::Url> {
    let base = reqwest::Url::parse(base).context("landing Worker base URL is invalid")?;
    let loopback = matches!(base.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if base.scheme() != "https" && !(base.scheme() == "http" && loopback) {
        bail!("landing Worker base URL must be https");
    }
    Ok(base)
}

fn check_token(token: &str) -> Result<()> {
    if token.trim().is_empty() || token.contains(char::is_whitespace) {
        bail!("landing Worker token is empty or malformed");
    }
    Ok(())
}

fn http() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

async fn bounded_body(response: reqwest::Response, what: &str) -> Result<Vec<u8>> {
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("{what} response failed"))?;
        if bytes.len() + chunk.len() > MAX_LEDGER_RESPONSE_BYTES {
            bail!("{what} response exceeds its bound");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KindBody {
    kind: String,
    #[serde(default)]
    epoch: Option<u64>,
    #[serde(default)]
    seq: Option<u64>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    files: Option<Vec<LedgerFile>>,
}

fn kind_of(body: &[u8], what: &str) -> Result<KindBody> {
    serde_json::from_slice(body).with_context(|| format!("{what} response does not parse"))
}

/// Never echo a refusal body: it is provider text, not ours.
fn refused(what: &str, status: u16) -> anyhow::Error {
    anyhow::anyhow!("{what} refused with HTTP {status}")
}

/// The credential the Worker checks on every landing route
/// (`NANO_LANDING_AUTH_TOKEN`; one value for the ledger and the producer).
struct Bearer(std::sync::RwLock<Zeroizing<String>>);

impl Bearer {
    fn new(token: Zeroizing<String>) -> Result<Self> {
        check_token(&token)?;
        Ok(Self(std::sync::RwLock::new(token)))
    }

    fn set(&self, token: Zeroizing<String>) -> Result<()> {
        check_token(&token)?;
        *self.0.write().map_err(|_| anyhow::anyhow!("landing token lock is poisoned"))? = token;
        Ok(())
    }

    fn get(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(self.0.read().map_err(|_| anyhow::anyhow!("landing token lock is poisoned"))?.as_str().to_string()))
    }
}

/// HTTPS client for `https://<slug>.ingest.nano.rs/landing-ledger/v1/*` (CONTRACT.md B1-B3).
///
/// - `lease {consumerId}` → 200 `{kind:"ok", epoch, …}`
/// - `next {epoch, max 1..16}` → 200 `{kind:"ok", epoch, files}` · 409 `{kind:"fenced"}` · 503
/// - `commit {epoch, key, outcome, rows?, reason?}` → 200 `{kind:"ok", state}` | `{kind:"replay"}` ·
///   409 `{kind:"fenced"|"conflict"}` · 404 unknown key
pub struct HttpLandingLedger {
    base: reqwest::Url,
    token: Bearer,
    http: reqwest::Client,
}

impl std::fmt::Debug for HttpLandingLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpLandingLedger").field("base", &self.base.as_str()).finish_non_exhaustive()
    }
}

impl HttpLandingLedger {
    pub fn new(base: &str, token: Zeroizing<String>) -> Result<Self> {
        Ok(Self { base: worker_base(base)?, token: Bearer::new(token)?, http: http()? })
    }

    /// Replace the credential (refresh); later requests use it.
    pub fn set_token(&self, token: Zeroizing<String>) -> Result<()> {
        self.token.set(token)
    }

    async fn post(&self, action: &str, body: serde_json::Value) -> Result<(u16, Vec<u8>)> {
        let bearer = self.token.get()?;
        let response = self
            .http
            .post(self.base.join(&format!("/landing-ledger/v1/{action}"))?)
            .bearer_auth(bearer.as_str())
            .json(&body)
            .send()
            .await
            .with_context(|| format!("landing ledger {action} request failed"))?;
        let status = response.status().as_u16();
        Ok((status, bounded_body(response, "landing ledger").await?))
    }
}

#[async_trait]
impl LandingLedgerTransport for HttpLandingLedger {
    async fn lease(&self, consumer_id: &str) -> Result<u64> {
        let (status, body) = self.post("lease", serde_json::json!({ "consumerId": consumer_id })).await?;
        if status != 200 {
            return Err(refused("landing ledger lease", status));
        }
        let kind = kind_of(&body, "landing ledger lease")?;
        ensure!(kind.kind == "ok", "landing ledger lease kind is {}", kind.kind);
        kind.epoch.context("landing ledger lease has no epoch")
    }

    async fn next(&self, epoch: u64, max: usize) -> Result<NextOutcome> {
        let (status, body) = self.post("next", serde_json::json!({ "epoch": epoch, "max": max.clamp(1, MAX_LEASE_FILES) })).await?;
        match status {
            200 => {
                let kind = kind_of(&body, "landing ledger next")?;
                ensure!(kind.kind == "ok", "landing ledger next kind is {}", kind.kind);
                ensure!(kind.epoch.is_none_or(|e| e == epoch), "landing ledger next answered another epoch");
                Ok(NextOutcome::Files(kind.files.unwrap_or_default()))
            }
            409 => {
                let kind = kind_of(&body, "landing ledger next refusal")?;
                ensure!(kind.kind == "fenced", "landing ledger next refused: {}", kind.kind);
                Ok(NextOutcome::Fenced)
            }
            503 => Ok(NextOutcome::Busy),
            _ => Err(refused("landing ledger next", status)),
        }
    }

    async fn commit(&self, commit: &LedgerCommit) -> Result<LedgerCommitOutcome> {
        let (status, body) = self.post("commit", serde_json::to_value(commit)?).await?;
        match status {
            200 | 409 => {
                let kind = kind_of(&body, "landing ledger commit")?;
                Ok(match (status, kind.kind.as_str()) {
                    (200, "ok") => LedgerCommitOutcome::Committed { state: kind.state },
                    (200, "replay") => LedgerCommitOutcome::Replayed,
                    (409, "fenced") => LedgerCommitOutcome::Fenced,
                    (409, "conflict") => LedgerCommitOutcome::Conflict,
                    (_, other) => bail!("landing ledger commit returned {other}"),
                })
            }
            404 => Ok(LedgerCommitOutcome::Unknown),
            400 => Ok(LedgerCommitOutcome::Invalid),
            _ => Err(refused("landing ledger commit", status)),
        }
    }
}

/// HTTPS client for `POST /edge-log/v1/produce` (CONTRACT.md B5): the body
/// is the segment; `x-nano-landing-epoch`, `x-nano-landing-key`,
/// `x-nano-edge-segment-key` and `x-nano-content-sha256` name it.
/// 200 `{kind:"appended"|"replay", seq}` · 409 fenced · 412 conflict · 503
/// busy · anything else refused. The credential is the tenant's landing
/// token: it cannot pull, consume or touch R2.
pub struct HttpEdgeLogProducer {
    base: reqwest::Url,
    tenant_id: String,
    token: Bearer,
    http: reqwest::Client,
}

impl std::fmt::Debug for HttpEdgeLogProducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpEdgeLogProducer").field("base", &self.base.as_str()).finish_non_exhaustive()
    }
}

impl HttpEdgeLogProducer {
    pub fn new(base: &str, tenant_id: &str, token: Zeroizing<String>) -> Result<Self> {
        Ok(Self { base: worker_base(base)?, tenant_id: tenant_id.to_string(), token: Bearer::new(token)?, http: http()? })
    }

    pub fn set_token(&self, token: Zeroizing<String>) -> Result<()> {
        self.token.set(token)
    }
}

#[async_trait]
impl EdgeLogProducer for HttpEdgeLogProducer {
    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    async fn produce(&self, produce: Produce<'_>) -> Result<AppendOutcome> {
        check_append_key(&self.tenant_id, produce.segment_key, produce.landing_key)?;
        ensure!(!produce.bytes.is_empty() && produce.bytes.len() <= MAX_SEGMENT_BYTES, "edge segment size out of bounds");
        let bearer = self.token.get()?;
        let response = self
            .http
            .post(self.base.join("/edge-log/v1/produce")?)
            .bearer_auth(bearer.as_str())
            .header("x-nano-landing-epoch", produce.epoch.to_string())
            .header("x-nano-landing-key", produce.landing_key)
            .header("x-nano-edge-segment-key", produce.segment_key)
            .header("x-nano-content-sha256", produce.sha256)
            .header(reqwest::header::CONTENT_TYPE, "application/vnd.apache.parquet")
            .body(produce.bytes.to_vec())
            .send()
            .await
            .context("edge log produce request failed")?;
        let status = response.status().as_u16();
        let body = bounded_body(response, "edge log produce").await?;
        match status {
            200 => {
                let kind = kind_of(&body, "edge log produce")?;
                Ok(match (kind.kind.as_str(), kind.seq) {
                    ("appended", Some(seq)) => AppendOutcome::Appended { seq },
                    ("replay", Some(seq)) => AppendOutcome::Replayed { seq },
                    (other, _) => bail!("edge log produce returned {other}"),
                })
            }
            409 => Ok(AppendOutcome::Fenced),
            412 => Ok(AppendOutcome::Conflict),
            503 => Ok(AppendOutcome::Busy),
            403 => Err(CrossTenantAppend.into()),
            _ => Err(refused("edge log produce", status)),
        }
    }
}

#[cfg(test)]
#[path = "landing_hosted_tests.rs"]
mod tests;
