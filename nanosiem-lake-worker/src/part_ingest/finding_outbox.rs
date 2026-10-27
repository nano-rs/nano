// SPDX-License-Identifier: AGPL-3.0-or-later

//! Immutable source receipts and durable replay lookup for the tenant
//! finding-outbox drain. A receipt names one finding so a retry can split a
//! partly acknowledged batch without publishing the committed row again.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use sqlx::Row;

use super::finding_append::{FindingAppendRequest, FindingAppendTransport};
use super::finding_attempts::{attempted_receipts, AttemptCache};
use super::finding_floors::{floors_for, put_floor_logged, FloorCache, FLOOR_EVERY};
use super::ingest::FINDING_IO_CONCURRENCY;
use super::schema::{additive_merge, decode, infer_schema};
use super::writer::{publish_parts, sort_by_time_uid, PartDraft, PartWriter, PartialSource};
use crate::part_query::risk::{finding_event, CompactFinding};

use crate::parts::format::{validate_tenant_uuid, LogKeys, PartKeys, PARTS_ROOT};
use crate::parts::levels::Level;
use crate::parts::part_log::{catch_up, load_log, LiveSet, LogEntry, LogOp, ObjectStore, SourceRef, WriteHints, WriterClass, GENESIS_PREV};
use crate::parts::provenance::{canonical_json_bytes, Admission, PartInputs, PartSigner, PartialKind, SignedProvenance, SourceObject, TenantKeySet};
use crate::parts::{event_hour_of, is_sha256_hex, sha256_hex, DedupWindow};

pub const RECEIPT_FORMAT: &str = "nano.finding-outbox-receipt.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingReceipt {
    pub format: String,
    pub tenant_id: String,
    pub finding_id: String,
    pub row_sha256: String,
}

impl FindingReceipt {
    pub fn new(tenant_id: &str, finding_id: &str, compact: &Value, event: &Value) -> Result<Self> {
        validate_tenant_uuid(tenant_id)?;
        ensure!(!finding_id.is_empty() && finding_id.len() <= 512 && !finding_id.chars().any(char::is_control),
            "finding id is malformed");
        let row = serde_json::json!({ "compact_finding": compact, "ocsf_event": event });
        Ok(Self {
            format: RECEIPT_FORMAT.to_owned(),
            tenant_id: tenant_id.to_owned(),
            finding_id: finding_id.to_owned(),
            row_sha256: sha256_hex(&canonical_json_bytes(&row)?),
        })
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate(&self.tenant_id)?;
        canonical_json_bytes(&serde_json::to_value(self)?)
    }

    pub fn source(&self) -> Result<SourceRef> {
        let digest = sha256_hex(&self.bytes()?);
        Ok(SourceRef {
            key: format!("{PARTS_ROOT}/tenant={}/finding-outbox/receipts/{digest}.json", self.tenant_id),
            version: RECEIPT_FORMAT.to_owned(),
            sha256: digest,
        })
    }

    pub fn parse(bytes: &[u8], tenant_id: &str, source: &SourceRef) -> Result<Self> {
        ensure!(sha256_hex(bytes) == source.sha256, "finding receipt digest differs");
        let receipt: Self = serde_json::from_slice(bytes).context("finding receipt is malformed")?;
        receipt.validate(tenant_id)?;
        ensure!(receipt.bytes()? == bytes, "finding receipt is not canonical");
        ensure!(receipt.source()? == *source, "finding receipt key differs");
        Ok(receipt)
    }

    fn validate(&self, tenant_id: &str) -> Result<()> {
        validate_tenant_uuid(tenant_id)?;
        ensure!(self.format == RECEIPT_FORMAT && self.tenant_id == tenant_id, "finding receipt tenant or format differs");
        ensure!(!self.finding_id.is_empty() && self.finding_id.len() <= 512 && !self.finding_id.chars().any(char::is_control),
            "finding receipt id is malformed");
        ensure!(is_sha256_hex(&self.row_sha256), "finding receipt row digest is malformed");
        Ok(())
    }
}

/// Exact signed-log evidence of one consumed receipt. Caller verifies
/// receipt bytes and signed part provenance before ack.
///
/// NAN-4656: the scan resumes after the weakest durable replay floor of the
/// wanted receipts ([`super::finding_floors`]) and records its own progress,
/// so a proof reads only the entries no earlier proof or commit has covered.
/// With no floor for some wanted receipt it reads from genesis, including
/// entries older than the live-set's 48-hour source memory.
pub async fn committed_receipts(
    store: &dyn ObjectStore,
    tenant_id: &str,
    wanted: &[SourceRef],
    trusted: &TenantKeySet,
) -> Result<BTreeMap<String, (u64, String)>> {
    committed_receipts_cached(store, tenant_id, wanted, trusted, &FloorCache::default()).await
}

/// [`committed_receipts`] reusing floor bodies already read.
pub async fn committed_receipts_cached(
    store: &dyn ObjectStore,
    tenant_id: &str,
    wanted_refs: &[SourceRef],
    trusted: &TenantKeySet,
    floor_cache: &FloorCache,
) -> Result<BTreeMap<String, (u64, String)>> {
    validate_tenant_uuid(tenant_id)?;
    let keys = LogKeys::new(tenant_id)?;
    let identity = |source: &SourceRef| (source.key.clone(), source.sha256.clone(), source.version.clone());
    let floors = floors_for(store, tenant_id, wanted_refs, floor_cache).await?;
    // Every wanted receipt is proven absent through the weakest of their
    // floors; one receipt with no floor means genesis.
    let resume = wanted_refs.iter().map(|source| floors.get(&identity(source)).cloned())
        .collect::<Option<Vec<_>>>()
        .and_then(|bounds| bounds.into_iter().min_by_key(|(seq, _)| *seq));
    let wanted = wanted_refs.iter().map(|source| (source.key.as_str(), source.sha256.as_str())).collect::<Vec<_>>();
    let mut committed = BTreeMap::new();
    let mut verified = LiveSet::default();
    let (mut next, mut prev, mut min_epoch) = match &resume {
        Some((seq, sha)) => {
            // Trusted like a checkpoint: the entry it names must exist with
            // the recorded digest; the chain is verified from there on.
            let bytes = store.get(&keys.entry(*seq)).await?.context("finding replay floor names a missing entry")?;
            ensure!(sha256_hex(&bytes) == *sha, "finding replay floor does not match its entry");
            let entry = LogEntry::parse_bytes(&bytes, tenant_id)?;
            ensure!(entry.seq == *seq, "finding replay floor names another entry");
            (seq + 1, sha.clone(), entry.writer_epoch)
        }
        None => (0u64, GENESIS_PREV.to_owned(), 0u64),
    };
    let start = next;
    let started = std::time::Instant::now();
    let mut window = std::collections::VecDeque::new();
    loop {
        // Entries are fetched REPLAY_FETCH_WINDOW at a time, concurrently,
        // and verified strictly in order. One GET at a time was ~10/s on R2:
        // a 30k-entry log took ~50 min per drain pass (the stuck drain).
        if window.is_empty() {
            let fetched = futures::future::try_join_all((next..next + REPLAY_FETCH_WINDOW)
                .map(|seq| { let key = keys.entry(seq); async move { store.get(&key).await } })).await?;
            window.extend(fetched);
        }
        let Some(Some(bytes)) = window.pop_front() else { break };
        let seq = next;
        next += 1;
        if seq > start && (seq - start) % REPLAY_PROGRESS_EVERY == 0 {
            tracing::info!(tenant_id, seq, start, wanted = wanted.len(), found = committed.len(),
                elapsed_s = started.elapsed().as_secs(), "finding replay scanning the part log");
        }
        let entry = LogEntry::parse_bytes(&bytes, tenant_id)?;
        ensure!(entry.seq == seq && entry.prev_sha256 == prev, "finding replay saw a broken part-log chain");
        ensure!(entry.writer_epoch >= min_epoch, "finding replay saw the writer epoch regress");
        min_epoch = entry.writer_epoch;
        let sha = sha256_hex(&bytes);
        if resume.is_none() {
            // From genesis the whole fold is checked too; a resumed scan has
            // no live set to fold into (as after a checkpoint, the chain is).
            verified.apply(&entry, &sha)?;
        }
        if let LogOp::Add { consumed, parts, edge_log } = &entry.op {
            for source in consumed {
                if wanted.iter().any(|(key, digest)| *key == source.key && *digest == source.sha256) {
                    // A floor is a proof of absence: a consumption at or
                    // below it means a floor lied. Fail-stop, never ack.
                    if let Some((floor, _)) = floors.get(&identity(source)) {
                        ensure!(seq > *floor, "finding receipt is consumed at seq {seq}, below its replay floor {floor}");
                    }
                    ensure!(edge_log.is_none(), "finding receipt was consumed as an edge source");
                    let receipt_bytes = store.get(&source.key).await?.context("committed finding receipt is missing")?;
                    FindingReceipt::parse(&receipt_bytes, tenant_id, source)?;
                    let mut attested = false;
                    for part in parts {
                        let keys = PartKeys::new(tenant_id, part.level, part.event_hour, &part.part_id)?;
                        let bytes = store.get(&keys.provenance()).await?.context("committed finding provenance is missing")?;
                        ensure!(sha256_hex(&bytes) == part.provenance_sha256, "committed finding provenance digest differs");
                        let signed = SignedProvenance::verify_bytes(&bytes, tenant_id, trusted)?;
                        part.check_record(&signed.record, &part.provenance_sha256)?;
                        let PartInputs::Sources { sources, edge_log: None } = &signed.record.inputs else {
                            bail!("committed finding part has non-finding inputs");
                        };
                        if sources.iter().any(|item| item.key == source.key && item.sha256 == source.sha256 && item.version == source.version)
                            && signed.record.files.partials.iter().any(|partial| partial.kind == PartialKind::Risk)
                        {
                            attested = true;
                        }
                    }
                    ensure!(attested, "committed finding receipt has no signed risk part");
                    if committed.insert(source.key.clone(), (seq, sha.clone())).is_some() {
                        bail!("finding receipt was committed more than once");
                    }
                }
            }
        }
        prev = sha;
        if (seq + 1 - start) % FLOOR_EVERY == 0 {
            // Durable progress: a proof cut here (deadline, restart, the
            // other role) resumes after `seq`, not at genesis.
            let absent = unfound(wanted_refs, &committed);
            put_floor_logged(store, tenant_id, seq, &prev, &absent).await;
        }
    }
    if next > start && (next - start) % FLOOR_EVERY != 0 {
        let absent = unfound(wanted_refs, &committed);
        put_floor_logged(store, tenant_id, next - 1, &prev, &absent).await;
    }
    tracing::info!(tenant_id, start, entries = next - start, head = next.checked_sub(1), wanted = wanted.len(),
        found = committed.len(), elapsed_ms = started.elapsed().as_millis() as u64, "finding replay scanned the part log");
    Ok(committed)
}

/// The wanted receipts a scan has not found (deduplicated).
fn unfound(wanted: &[SourceRef], committed: &BTreeMap<String, (u64, String)>) -> Vec<SourceRef> {
    let mut seen = std::collections::BTreeSet::new();
    wanted.iter()
        .filter(|source| !committed.contains_key(&source.key) && seen.insert((&source.key, &source.sha256, &source.version)))
        .cloned()
        .collect()
}

/// A drain batch's outbox bytes (compact + OCSF JSON): a few MB per append.
pub const DRAIN_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// Delivered findings stay this long: the seven-day tuning metrics read
/// them from the outbox by event time, and a delivered row's event precedes
/// its delivery, so a row delivered more than 7 days ago is already outside
/// that window. NAN-4668 (FP-INC-1027): 7, was 8; the finding-drain DELETE
/// policy (9015560) allows exactly this window.
pub const OUTBOX_RETENTION_DAYS: i32 = 7;
/// Rows removed per prune statement; a larger backlog drains over passes.
const OUTBOX_PRUNE_BATCH: i64 = 1_000;
/// How often a long-running drain loop prunes.
pub const OUTBOX_PRUNE_EVERY_MS: i64 = 10 * 60 * 1_000;
/// Bound on the failure text recorded on rows a failed pass had claimed.
const LAST_ERROR_MAX_CHARS: usize = 1_000;

/// Concurrent part-log entry GETs during a replay scan.
const REPLAY_FETCH_WINDOW: u64 = 32;
/// Progress log spacing (entries) during a replay scan.
const REPLAY_PROGRESS_EVERY: u64 = 5_000;

/// The pre-existing receipts that may have been committed and so need the
/// log proof. Ingest writes an attempt marker before every `Add` that
/// consumes receipts (one per append since NAN-4181,
/// [`super::finding_attempts`]), and its completion marker proves historical
/// `Add`s were indexed. With that index present, a receipt without a marker was
/// never offered to the log: it is republished directly, with no scan. A
/// receipt left by a failed attempt (missing R2 grant, expired owner bearer,
/// old cell or writer epoch) is the ordinary case, not crash replay.
pub async fn receipts_needing_log_proof(
    store: &dyn ObjectStore,
    tenant_id: &str,
    preexisting: &[SourceRef],
) -> Result<Vec<SourceRef>> {
    receipts_needing_log_proof_cached(store, tenant_id, preexisting, &AttemptCache::default()).await
}

/// [`receipts_needing_log_proof`] reusing marker bodies already read.
pub async fn receipts_needing_log_proof_cached(
    store: &dyn ObjectStore,
    tenant_id: &str,
    preexisting: &[SourceRef],
    attempts: &AttemptCache,
) -> Result<Vec<SourceRef>> {
    if preexisting.is_empty() {
        return Ok(Vec::new());
    }
    let keys = LogKeys::new(tenant_id)?;
    let ready = format!("{}{}", keys.checkpoints_prefix(), super::ingest::FINDING_ATTEMPT_INDEX_READY);
    match store.get(&ready).await? {
        Some(bytes) => ensure!(bytes == super::ingest::FINDING_ATTEMPT_INDEX_READY.as_bytes(),
            "finding attempt index marker differs"),
        // No index yet (ingest never opened this log): only the scan is proof.
        None => return Ok(preexisting.to_vec()),
    }
    let marked = attempted_receipts(store, tenant_id, preexisting, attempts).await?;
    Ok(preexisting.iter()
        .filter(|source| marked.contains(&(source.key.clone(), source.sha256.clone(), source.version.clone())))
        .cloned()
        .collect())
}

/// What one drain pass saw and did. Logged by the caller every pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainPass {
    /// Unpublished outbox rows for the tenant at the start of the pass.
    pub backlog: u64,
    /// `created_at` (unix ms) of the oldest unpublished row, if any.
    pub oldest_created_ms: Option<i64>,
    /// Rows claimed (`FOR UPDATE SKIP LOCKED`, at most one batch).
    pub seen: usize,
    /// Claimed rows whose receipt object already existed (earlier attempt).
    pub preexisting_receipts: usize,
    /// Pre-existing receipts ingest had attempted: these needed the log scan.
    pub replay_checked: usize,
    /// Rows acknowledged from committed log evidence (no new part).
    pub replayed: usize,
    /// Rows published in a new signed `Add` this pass.
    pub published: usize,
    /// Rows acknowledged in the outbox (`replayed + published`).
    pub committed: usize,
    /// Why the pass claimed nothing although rows are pending.
    pub skipped: Option<&'static str>,
    /// Delivered rows past [`OUTBOX_RETENTION_DAYS`] removed this pass.
    pub pruned: u64,
    /// NAN-4610: the retention check made with a scheduled prune; `None` on
    /// passes that did not prune or when the check itself could not be read.
    pub retention: Option<RetentionCheck>,
}

impl DrainPass {
    pub fn oldest_age_ms(&self, now_ms: i64) -> i64 {
        self.oldest_created_ms.map_or(0, |at| now_ms.saturating_sub(at).max(0))
    }
}

/// What the outbox retains after a scheduled prune (NAN-4610). Delivered
/// rows are kept [`OUTBOX_RETENTION_DAYS`] on purpose (the tuning metrics read
/// them), so row count alone cannot tell a full window from a prune that
/// stopped working; the oldest retained delivery can.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionCheck {
    /// `published_at` (unix ms) of this tenant's oldest delivered row still in
    /// the outbox; `None` when none is retained.
    pub oldest_retained_published_ms: Option<i64>,
}

impl RetentionCheck {
    /// How long (ms) the oldest retained delivered row has outlived the
    /// retention window: 0 while retention keeps up. It keeps growing when
    /// the prune fails (a revoked grant, a policy drift) or cannot keep up.
    pub fn overdue_ms(&self, now_ms: i64) -> i64 {
        retention_overdue_ms(self.oldest_retained_published_ms, now_ms)
    }
}

/// [`RetentionCheck::overdue_ms`] for a stored `published_at` (unix ms).
pub fn retention_overdue_ms(oldest_retained_published_ms: Option<i64>, now_ms: i64) -> i64 {
    const DAY_MS: i64 = 86_400_000;
    oldest_retained_published_ms.map_or(0, |at| {
        now_ms.saturating_sub(at).saturating_sub(i64::from(OUTBOX_RETENTION_DAYS) * DAY_MS).max(0)
    })
}

struct PendingFinding {
    id: String,
    source: SourceRef,
    receipt: FindingReceipt,
    event: Value,
}

/// One authenticated tenant batch. The supplied pool must be a principal
/// bound to `finding_drain`; the database binding is checked before rows are
/// read. The caller schedules this in detect[T] and owns its scoped secrets.
pub async fn drain_once(
    pool: &sqlx::PgPool,
    store: &dyn ObjectStore,
    signer: &dyn PartSigner,
    trusted: &TenantKeySet,
    tenant_id: &str,
    writer_epoch: u64,
    transport: &dyn FindingAppendTransport,
    work_dir: &Path,
    now_ms: i64,
) -> Result<usize> {
    Ok(drain_pass(pool, store, signer, trusted, tenant_id, writer_epoch, transport, work_dir, now_ms).await?.committed)
}

/// [`drain_once`] with the pass report. Rows carry no generation or writer
/// epoch: whatever assignment wrote them (an old cell, an earlier epoch),
/// they are published under `writer_epoch`, the current one, which ingest
/// fences against its own.
#[allow(clippy::too_many_arguments)]
pub async fn drain_pass(
    pool: &sqlx::PgPool,
    store: &dyn ObjectStore,
    signer: &dyn PartSigner,
    trusted: &TenantKeySet,
    tenant_id: &str,
    writer_epoch: u64,
    transport: &dyn FindingAppendTransport,
    work_dir: &Path,
    now_ms: i64,
) -> Result<DrainPass> {
    drain_pass_observed(pool, store, signer, trusted, tenant_id, writer_epoch, transport, work_dir, now_ms, &|_, _| {}).await
}

/// The drain's view of the tenant part log, kept across passes (NAN-3096).
///
/// A pass that publishes findings needs the log's current schema. Loading it
/// with [`load_log`] every pass cost one LIST of the checkpoints plus a GET of
/// every entry since the newest checkpoint (up to [`CHECKPOINT_EVERY`]), on
/// every pass with findings: tens of thousands of R2 reads an hour on a busy
/// tenant. The cached set instead advances with [`catch_up`], which reads only
/// the entries appended since the last pass and verifies each one against the
/// hash chain exactly as `load_log`'s own catch-up does. Any catch-up failure,
/// and any pass that fails after taking the set, falls back to a full
/// `load_log` on the next pass. Tenant changes and every checkpoint interval
/// also reload, bounding the historical metadata retained by this cache.
///
/// [`CHECKPOINT_EVERY`]: crate::parts::part_log::CHECKPOINT_EVERY
///
/// It also carries the loop's retention schedule: delivered rows are pruned
/// at most once per [`OUTBOX_PRUNE_EVERY_MS`] (a fresh cache prunes at once).
#[derive(Debug, Default)]
pub struct DrainLogCache {
    live: Option<LiveSet>,
    tenant_id: Option<String>,
    loaded_seq: u64,
    next_prune_ms: i64,
    /// NAN-4181: attempt marker bodies already read (immutable).
    attempts: AttemptCache,
    /// NAN-4656: replay floor bodies already read (immutable).
    floors: FloorCache,
}

impl DrainLogCache {
    /// The live set at the current log head, owned by the caller until it is
    /// handed back with [`DrainLogCache::keep`].
    async fn take_current(&mut self, store: &dyn ObjectStore, tenant_id: &str) -> Result<LiveSet> {
        let same_tenant = self.tenant_id.as_deref() == Some(tenant_id);
        if let Some(mut live) = self.live.take().filter(|live| {
            same_tenant && live.head().map_or(0, |(seq, _, _)| seq)
                .saturating_sub(self.loaded_seq) < crate::parts::part_log::CHECKPOINT_EVERY
        }) {
            match catch_up(store, tenant_id, &mut live).await {
                Ok(_) => return Ok(live),
                Err(error) => tracing::warn!(tenant_id, error = %format!("{error:#}"),
                    "finding drain log view could not catch up; reloading from the checkpoint"),
            }
        }
        let live = load_log(store, tenant_id).await?;
        self.tenant_id = Some(tenant_id.to_owned());
        self.loaded_seq = live.head().map_or(0, |(seq, _, _)| seq);
        Ok(live)
    }

    fn keep(&mut self, live: LiveSet) {
        self.live = Some(live);
    }

    /// Head sequence of the cached view, if any (tests and diagnostics).
    pub fn head_seq(&self) -> Option<u64> {
        self.live.as_ref().and_then(|live| live.head().map(|(seq, _, _)| seq))
    }
}

/// [`drain_pass`] that reports `(backlog, oldest_created_ms)` to `observe`
/// as soon as it is counted, before any object-store work, so a pass that
/// then hangs still exposes the backlog and its growing age.
#[allow(clippy::too_many_arguments)]
pub async fn drain_pass_observed(
    pool: &sqlx::PgPool,
    store: &dyn ObjectStore,
    signer: &dyn PartSigner,
    trusted: &TenantKeySet,
    tenant_id: &str,
    writer_epoch: u64,
    transport: &dyn FindingAppendTransport,
    work_dir: &Path,
    now_ms: i64,
    observe: &(dyn Fn(u64, Option<i64>) + Sync),
) -> Result<DrainPass> {
    drain_pass_cached(pool, store, signer, trusted, tenant_id, writer_epoch, transport, work_dir, now_ms, observe,
        &mut DrainLogCache::default()).await
}

/// [`drain_pass_observed`] reusing `cache` across passes: a long-running drain
/// loop keeps one [`DrainLogCache`] per tenant.
#[allow(clippy::too_many_arguments)]
pub async fn drain_pass_cached(
    pool: &sqlx::PgPool,
    store: &dyn ObjectStore,
    signer: &dyn PartSigner,
    trusted: &TenantKeySet,
    tenant_id: &str,
    writer_epoch: u64,
    transport: &dyn FindingAppendTransport,
    work_dir: &Path,
    now_ms: i64,
    observe: &(dyn Fn(u64, Option<i64>) + Sync),
    cache: &mut DrainLogCache,
) -> Result<DrainPass> {
    drain_pass_authorized(pool, store, signer, trusted, tenant_id, writer_epoch, transport,
        work_dir, now_ms, observe, cache, true).await
}

/// Explicit single-tenant entry point. Only the trusted-local detect bootstrap
/// calls this; hosted callers retain the database-principal binding check.
/// Row predicates, OCSF tenant validation, receipts and epoch fencing are shared.
#[allow(clippy::too_many_arguments)]
pub async fn drain_pass_trusted_local(
    pool: &sqlx::PgPool, store: &dyn ObjectStore, signer: &dyn PartSigner,
    trusted: &TenantKeySet, tenant_id: &str, writer_epoch: u64,
    transport: &dyn FindingAppendTransport, work_dir: &Path, now_ms: i64,
    observe: &(dyn Fn(u64, Option<i64>) + Sync), cache: &mut DrainLogCache,
) -> Result<DrainPass> {
    drain_pass_authorized(pool, store, signer, trusted, tenant_id, writer_epoch, transport,
        work_dir, now_ms, observe, cache, false).await
}

#[allow(clippy::too_many_arguments)]
async fn drain_pass_authorized(
    pool: &sqlx::PgPool, store: &dyn ObjectStore, signer: &dyn PartSigner,
    trusted: &TenantKeySet, tenant_id: &str, writer_epoch: u64,
    transport: &dyn FindingAppendTransport, work_dir: &Path, now_ms: i64,
    observe: &(dyn Fn(u64, Option<i64>) + Sync), cache: &mut DrainLogCache,
    require_hosted_principal: bool,
) -> Result<DrainPass> {
    validate_tenant_uuid(tenant_id)?;
    ensure!(writer_epoch > 0, "finding drain has no writer epoch");
    let tenant_uuid = uuid::Uuid::parse_str(tenant_id)?;
    let mut pruned = 0;
    let mut retention = None;
    if now_ms >= cache.next_prune_ms {
        cache.next_prune_ms = now_ms.saturating_add(OUTBOX_PRUNE_EVERY_MS);
        pruned = prune_delivered(pool, tenant_uuid, tenant_id).await;
        retention = retention_check(pool, tenant_uuid, tenant_id).await;
    }
    let mut tx = pool.begin().await?;
    if require_hosted_principal {
        let binding: (Option<uuid::Uuid>, Option<String>) = sqlx::query_as(
            "SELECT nano_shared.lake_data_path_tenant_id(), nano_shared.lake_data_path_capability()",
        ).fetch_one(&mut *tx).await?;
        ensure!(binding.0 == Some(tenant_uuid) && binding.1.as_deref() == Some("finding_drain"),
            "finding drain database principal is not bound to this tenant and capability");
    }
    let mut pass = DrainPass { pruned, retention, ..DrainPass::default() };
    let (backlog, oldest): (i64, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        "SELECT count(*), min(created_at) FROM detection_finding_lake_outbox \
         WHERE security_tenant_id = $1 AND tenant_id = $2 \
           AND (event_published_at IS NULL OR risk_published_at IS NULL)",
    )
    .bind(tenant_uuid)
    .bind(tenant_id)
    .fetch_one(&mut *tx).await.context("finding outbox backlog")?;
    pass.backlog = backlog.max(0) as u64;
    pass.oldest_created_ms = oldest.map(|at| at.timestamp_millis());
    observe(pass.backlog, pass.oldest_created_ms);
    let rows = sqlx::query(
        "SELECT security_tenant_id, tenant_id, finding_id, compact_finding, ocsf_event \
         FROM detection_finding_lake_outbox \
         WHERE security_tenant_id = $1 AND tenant_id = $2 \
           AND (event_published_at IS NULL OR risk_published_at IS NULL) \
         ORDER BY created_at, finding_id FOR UPDATE SKIP LOCKED LIMIT 512",
    )
    .bind(tenant_uuid)
    .bind(tenant_id)
    .fetch_all(&mut *tx).await?;
    pass.seen = rows.len();
    if rows.is_empty() {
        tx.commit().await?;
        if pass.backlog > 0 {
            // Every pending row is row-locked by another session: a second
            // drain, or a dead one whose transaction the server still holds.
            pass.skipped = Some("pending rows are locked by another drain session");
        }
        return Ok(pass);
    }
    let claimed = rows.iter().map(|row| row.try_get::<String, _>("finding_id")).collect::<Result<Vec<_>, _>>()?;
    match publish_claimed(&mut tx, rows, &mut pass, store, signer, trusted, tenant_id, tenant_uuid,
        writer_epoch, transport, work_dir, now_ms, cache).await
    {
        Ok(()) => {
            tx.commit().await?;
            Ok(pass)
        }
        Err(error) => {
            // The claim (row locks) ends with the transaction; the rows stay
            // pending and the next pass retries them. Record the attempt so
            // a stuck row is visible (attempts climbing, last_error set).
            drop(tx.rollback().await);
            record_failed_attempt(pool, tenant_uuid, tenant_id, &claimed, &error).await;
            Err(error)
        }
    }
}

/// Removes this tenant's delivered rows past the retention window. Best
/// effort: a failure (for example a hosted database without the retention
/// grant yet) never blocks delivery; the next scheduled prune retries.
async fn prune_delivered(pool: &sqlx::PgPool, tenant_uuid: uuid::Uuid, tenant_id: &str) -> u64 {
    let result = sqlx::query(
        "DELETE FROM detection_finding_lake_outbox \
         WHERE (security_tenant_id, tenant_id, finding_id) IN (\
             SELECT security_tenant_id, tenant_id, finding_id FROM detection_finding_lake_outbox \
             WHERE security_tenant_id = $1 AND tenant_id = $2 \
               AND risk_published_at IS NOT NULL AND event_published_at IS NOT NULL \
               AND published_at < NOW() - make_interval(days => $3) \
             ORDER BY published_at, finding_id FOR UPDATE SKIP LOCKED LIMIT $4)",
    )
    .bind(tenant_uuid)
    .bind(tenant_id)
    .bind(OUTBOX_RETENTION_DAYS)
    .bind(OUTBOX_PRUNE_BATCH)
    .execute(pool).await;
    match result {
        Ok(done) => {
            if done.rows_affected() > 0 {
                tracing::info!(tenant_id, pruned = done.rows_affected(), retention_days = OUTBOX_RETENTION_DAYS,
                    "finding outbox pruned delivered rows");
            }
            done.rows_affected()
        }
        Err(error) => {
            tracing::warn!(tenant_id, error = %error, "finding outbox prune failed; delivery continues");
            0
        }
    }
}

/// The oldest delivered row this tenant still retains (NAN-4610). Read after
/// every scheduled prune, whether or not the prune succeeded, so a prune that
/// silently stops deleting shows up as a growing overdue age. Served by the
/// `published_at IS NOT NULL` retention index (310). Best effort: `None` on
/// error, and the caller keeps its previous reading.
async fn retention_check(pool: &sqlx::PgPool, tenant_uuid: uuid::Uuid, tenant_id: &str) -> Option<RetentionCheck> {
    let oldest: Result<Option<chrono::DateTime<chrono::Utc>>, _> = sqlx::query_scalar(
        "SELECT min(published_at) FROM detection_finding_lake_outbox \
         WHERE security_tenant_id = $1 AND tenant_id = $2 AND published_at IS NOT NULL",
    )
    .bind(tenant_uuid)
    .bind(tenant_id)
    .fetch_one(pool).await;
    match oldest {
        Ok(oldest) => Some(RetentionCheck { oldest_retained_published_ms: oldest.map(|at| at.timestamp_millis()) }),
        Err(error) => {
            tracing::warn!(tenant_id, error = %error, "finding outbox retention check failed");
            None
        }
    }
}

/// Stamps the rows a failed pass had claimed. Only the attempt counter and
/// error text change (the hosted ACK guard allows exactly these), and only
/// on rows still pending. Best effort: the pass error is what the caller sees.
async fn record_failed_attempt(pool: &sqlx::PgPool, tenant_uuid: uuid::Uuid, tenant_id: &str,
    claimed: &[String], error: &anyhow::Error) {
    let text = format!("{error:#}").chars().take(LAST_ERROR_MAX_CHARS).collect::<String>();
    let result = sqlx::query(
        "UPDATE detection_finding_lake_outbox \
         SET publish_attempts = publish_attempts + 1, last_error = $4 \
         WHERE security_tenant_id = $1 AND tenant_id = $2 AND finding_id = ANY($3) \
           AND (risk_published_at IS NULL OR event_published_at IS NULL)",
    )
    .bind(tenant_uuid)
    .bind(tenant_id)
    .bind(claimed)
    .bind(text)
    .execute(pool).await;
    if let Err(record) = result {
        tracing::warn!(tenant_id, error = %record, "finding drain could not record the failed attempt");
    }
}

/// The claimed batch: receipts, replay proof, the signed `Add`, and the acks,
/// all inside the claim transaction `tx` (the caller commits).
#[allow(clippy::too_many_arguments)]
async fn publish_claimed(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, rows: Vec<sqlx::postgres::PgRow>, pass: &mut DrainPass,
    store: &dyn ObjectStore, signer: &dyn PartSigner, trusted: &TenantKeySet, tenant_id: &str,
    tenant_uuid: uuid::Uuid, writer_epoch: u64, transport: &dyn FindingAppendTransport, work_dir: &Path,
    now_ms: i64, cache: &mut DrainLogCache,
) -> Result<()> {
    let mut pending = Vec::with_capacity(rows.len());
    // Batches are sized by bytes (DRAIN_BATCH_BYTES) up to 512 rows; rows
    // past the budget stay locked until this pass commits, then the next
    // pass takes them.
    let mut batch_bytes = 0_usize;
    for row in rows {
        if batch_bytes >= DRAIN_BATCH_BYTES {
            break;
        }
        ensure!(row.try_get::<uuid::Uuid, _>("security_tenant_id")? == tenant_uuid
            && row.try_get::<String, _>("tenant_id")? == tenant_id,
            "finding outbox row crossed the tenant boundary");
        let id: String = row.try_get("finding_id")?;
        let compact_raw: Value = row.try_get("compact_finding")?;
        let ocsf: Value = row.try_get("ocsf_event")?;
        batch_bytes += compact_raw.to_string().len() + ocsf.to_string().len();
        let compact: CompactFinding = serde_json::from_value(compact_raw.clone())?;
        ensure!(compact.id == id && compact.timestamp_us > 0, "finding compact identity or time differs");
        let receipt = FindingReceipt::new(tenant_id, &id, &compact_raw, &ocsf)?;
        let source = receipt.source()?;
        let mut event = finding_event(&ocsf, &compact)?;
        ensure!(event.get("metadata").and_then(|m| m.get("tenant_uid")).and_then(Value::as_str) == Some(tenant_id),
            "finding OCSF tenant differs");
        let at = chrono::DateTime::<chrono::Utc>::from_timestamp_micros(compact.timestamp_us)
            .context("finding timestamp is out of range")?;
        event["time"] = Value::String(at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
        pending.push(PendingFinding { id, source, receipt, event });
    }
    pass.seen = pending.len();
    use futures::{StreamExt, TryStreamExt};
    // Object-store round trips run FINDING_IO_CONCURRENCY at a time; one at
    // a time made a 128-finding pass take 80-150 s (NAN-3067).
    let existing = futures::stream::iter(pending.iter())
        .map(|row| async move { Ok::<_, anyhow::Error>((row, store.get(&row.source.key).await?)) })
        .buffered(FINDING_IO_CONCURRENCY)
        .try_collect::<Vec<_>>()
        .await?;
    let mut preexisting = Vec::new();
    for (row, bytes) in existing {
        if let Some(bytes) = bytes {
            let stored = FindingReceipt::parse(&bytes, tenant_id, &row.source)?;
            ensure!(stored == row.receipt, "finding receipt content differs from outbox row");
            preexisting.push(row.source.clone());
        }
    }
    // The ordinary path is O(batch), independent of the tenant log's age.
    // A receipt left by a failed attempt that ingest never saw is
    // republished directly; only a receipt ingest attempted (crash between
    // intent and ack) scans immutable log evidence before republish or ack.
    pass.preexisting_receipts = preexisting.len();
    if cache.tenant_id.as_deref().is_some_and(|cached| cached != tenant_id) {
        cache.attempts = AttemptCache::default();
        cache.floors = FloorCache::default();
    }
    let attempted = receipts_needing_log_proof_cached(store, tenant_id, &preexisting, &cache.attempts).await?;
    pass.replay_checked = attempted.len();
    let committed = if attempted.is_empty() {
        BTreeMap::new()
    } else {
        committed_receipts_cached(store, tenant_id, &attempted, trusted, &cache.floors).await?
    };
    let mut acks = BTreeMap::new();
    let mut fresh = Vec::new();
    for row in pending {
        if let Some(head) = committed.get(&row.source.key) {
            acks.insert(row.id, head.clone());
        } else {
            fresh.push(row);
        }
    }
    let hints = WriteHints {
        class: WriterClass::LakePart,
        event_hour: event_hour_of(now_ms.saturating_mul(1_000)),
        min_time_ms: now_ms,
        max_time_ms: now_ms,
    };
    // NAN-4181: a receipt an earlier pass stored is not PUT again (a
    // conditional PUT answering 412 is still a billed Class A request).
    let stored = preexisting.iter().map(|source| source.key.as_str()).collect::<std::collections::BTreeSet<_>>();
    futures::stream::iter(fresh.iter().filter(|row| !stored.contains(row.source.key.as_str())))
        .map(|row| {
            let hints = &hints;
            async move {
                let bytes = row.receipt.bytes()?;
                if !store.put_if_absent_with(&row.source.key, &bytes, hints).await? {
                    ensure!(store.get(&row.source.key).await?.as_deref() == Some(bytes.as_slice()),
                        "finding receipt key has conflicting bytes");
                }
                Ok::<_, anyhow::Error>(())
            }
        })
        .buffer_unordered(FINDING_IO_CONCURRENCY)
        .try_collect::<Vec<_>>()
        .await?;

    if !fresh.is_empty() {
        // Taken out of the cache: an error before `keep` below leaves it
        // empty, so the next pass reloads from the checkpoint.
        let live = cache.take_current(store, tenant_id).await?;
        let mut schema = live.schema().context("finding part log has no schema")?.to_arrow()?;
        let event_refs = fresh.iter().map(|row| &row.event).collect::<Vec<_>>();
        let inferred = infer_schema(&event_refs)?;
        if let Some(next) = additive_merge(&schema, &inferred)? {
            schema = next;
        }
        let schema = Arc::new(schema);
        let mut by_hour: BTreeMap<i32, Vec<&PendingFinding>> = BTreeMap::new();
        for row in &fresh {
            let time_us = row.event["time"].as_str().context("finding time absent")?
                .parse::<chrono::DateTime<chrono::Utc>>()?.timestamp_micros();
            by_hour.entry(event_hour_of(time_us)).or_default().push(row);
        }
        let mut finished = Vec::new();
        for (hour, rows) in by_hour {
            let sources = rows.iter().map(|row| Ok(SourceObject {
                key: row.source.key.clone(),
                version: row.source.version.clone(),
                bytes: row.receipt.bytes()?.len() as u64,
                sha256: row.source.sha256.clone(),
                rows: 1,
                edge_sha256: None,
            })).collect::<Result<Vec<_>>>()?;
            let events = rows.iter().map(|row| &row.event).collect::<Vec<_>>();
            let batch = sort_by_time_uid(&decode(schema.clone(), &events)?)?;
            let draft = PartDraft {
                tenant_id: tenant_id.to_owned(),
                signer_key_id: signer.key_id().to_owned(),
                level: Level::L0,
                event_hour: hour,
                schema_fingerprint: crate::parts::format::schema_fingerprint(&schema)?,
                schema: schema.clone(),
                inputs: PartInputs::Sources { sources, edge_log: None },
                admission: Some(Admission { ocsf_version: crate::iceberg::OCSF_VERSION.to_owned(),
                    admission_contract: "finding-outbox-v1".to_owned(), feed_pins: BTreeMap::new() }),
                rows_in: batch.num_rows() as u64,
                duplicates_dropped: 0,
                window: DedupWindow::Exact,
                build: format!("nanosiem-lake-worker {}", env!("CARGO_PKG_VERSION")),
            };
            let mut writer = PartWriter::create(work_dir, draft, PartialSource::FromFindings, now_ms, batch.num_rows() as u64)?;
            writer.write(&batch)?;
            finished.push(writer.finish()?);
        }
        let refs = publish_parts(store, signer, trusted, &finished).await?;
        let consumed = fresh.iter().map(|row| row.source.clone()).collect::<Vec<_>>();
        let ack = transport.submit(&FindingAppendRequest {
            tenant_id: tenant_id.to_owned(), writer_epoch,
            schema: crate::parts::part_log::LogSchema::from_arrow(&schema)?,
            parts: refs, receipts: consumed,
            deadline_unix_ms: Some(chrono::Utc::now().timestamp_millis()
                + super::finding_append::COMMIT_DEADLINE.as_millis() as i64),
        }).await?;
        let (seq, entry_sha256) = (ack.seq, ack.entry_sha256);
        // Still at the pre-append head; the next pass catches up past it.
        cache.keep(live);
        pass.published = fresh.len();
        for row in fresh {
            acks.insert(row.id, (seq, entry_sha256.clone()));
        }
    }

    for (id, (seq, digest)) in &acks {
        let marker = format!("parts:{seq}:{digest}");
        let result = sqlx::query(
            "UPDATE detection_finding_lake_outbox \
             SET risk_published_at = NOW(), risk_snapshot_id = $1, \
                 event_published_at = NOW(), event_snapshot_id = $1, \
                 publish_attempts = publish_attempts + 1, last_error = NULL \
             WHERE security_tenant_id = $2 AND tenant_id = $3 AND finding_id = $4 \
               AND (risk_published_at IS NULL OR event_published_at IS NULL)",
        )
        .bind(marker)
        .bind(tenant_uuid)
        .bind(tenant_id)
        .bind(id)
        .execute(&mut **tx).await?;
        ensure!(result.rows_affected() == 1, "finding outbox ack lost its exact row");
    }
    pass.committed = acks.len();
    pass.replayed = pass.committed - pass.published;
    Ok(())
}

#[cfg(test)]
#[path = "finding_outbox_cache_tests.rs"]
mod cache_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ingest::{seed_schema, IngestConfig, Ingestor};
    use super::super::discovery::SpoolQueue;
    use crate::enrichment::BronzeIngestEnricher;
    use crate::parts::part_log::{LocalObjectStore, ObjectStore, LogSchema};
    use crate::parts::provenance::LocalPartSigner;
    use ed25519_dalek::SigningKey;

    const TENANT_A: &str = "00000000-0000-4000-8000-000000000001";
    const TENANT_B: &str = "00000000-0000-4000-8000-000000000002";

    /// NAN-4610: a full 7-day window is healthy (overdue 0); only a delivered
    /// row older than the window counts, and by how much it outlived it.
    #[test]
    fn retention_overdue_counts_only_past_the_window() {
        const DAY: i64 = 86_400_000;
        let now = 1_800_000_000_000;
        assert_eq!(RetentionCheck::default().overdue_ms(now), 0, "nothing retained");
        let within = RetentionCheck { oldest_retained_published_ms: Some(now - 7 * DAY + 1) };
        assert_eq!(within.overdue_ms(now), 0);
        let past = RetentionCheck { oldest_retained_published_ms: Some(now - 8 * DAY - 5_000) };
        assert_eq!(past.overdue_ms(now), DAY + 5_000);
        assert_eq!(retention_overdue_ms(Some(now + DAY), now), 0, "clock skew never goes negative");
        assert_eq!(retention_overdue_ms(Some(i64::MIN), now), i64::MAX - 7 * DAY, "saturates instead of overflowing");
    }

    #[test]
    fn receipt_is_stable_and_refuses_foreign_tenant_or_changed_content() {
        let compact = serde_json::json!({"id":"f1", "score":75});
        let event = serde_json::json!({"class_uid":2004});
        let receipt = FindingReceipt::new(TENANT_A, "f1", &compact, &event).unwrap();
        let bytes = receipt.bytes().unwrap();
        let source = receipt.source().unwrap();
        assert_eq!(FindingReceipt::parse(&bytes, TENANT_A, &source).unwrap(), receipt);
        assert!(FindingReceipt::parse(&bytes, TENANT_B, &source).is_err());
        assert_ne!(FindingReceipt::new(TENANT_A, "f1", &compact, &serde_json::json!({"class_uid":2004,"x":1})).unwrap().source().unwrap(), source);
    }

    #[tokio::test]
    async fn only_receipts_ingest_attempted_need_the_log_proof() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let receipt = FindingReceipt::new(TENANT_A, "f1", &serde_json::json!({"id":"f1"}),
            &serde_json::json!({"class_uid":2004})).unwrap();
        let source = receipt.source().unwrap();
        // No ingest index yet: the scan is the only proof.
        assert_eq!(receipts_needing_log_proof(&store, TENANT_A, &[source.clone()]).await.unwrap(), vec![source.clone()]);
        let signer = LocalPartSigner::new("lab-signer-proof", SigningKey::from_bytes(&[5; 32])).unwrap();
        let queue = SpoolQueue::new(dir.path().join("spool"), TENANT_A).unwrap();
        drop(Ingestor::open(IngestConfig::new(TENANT_A, dir.path().join("ingest")), &store, &store, &queue, &signer,
            signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), 1_000).await.unwrap());
        // Indexed log, receipt left by a failed pass, no attempt: republish.
        assert!(receipts_needing_log_proof(&store, TENANT_A, &[source.clone()]).await.unwrap().is_empty());
        assert!(receipts_needing_log_proof(&store, TENANT_A, &[]).await.unwrap().is_empty());
        // Ingest's durable intent marker: the log decides.
        let marker = super::super::ingest::finding_attempt_key(TENANT_A, &source).unwrap();
        assert!(store.put_if_absent(&marker, &serde_json::to_vec(&source).unwrap()).await.unwrap());
        assert_eq!(receipts_needing_log_proof(&store, TENANT_A, &[source.clone()]).await.unwrap(), vec![source]);
    }

    #[tokio::test]
    async fn signed_finding_add_replays_once_and_stays_tenant_local() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let signer = LocalPartSigner::new("lab-signer-risk", SigningKey::from_bytes(&[7; 32])).unwrap();
        let trusted = signer.trusted();
        let timestamp = chrono::DateTime::parse_from_rfc3339("2026-09-26T18:00:00Z").unwrap().timestamp_micros();
        let compact = serde_json::json!({
            "id":"f1", "timestamp_us":timestamp, "entity":"alice@example.com",
            "stamped_entity_type":"email", "risk_score":75, "rule_id":"r1",
            "rule_name":"test", "severity":"high", "origin_source_types":["auth"], "mitre_tactics":[]
        });
        let ocsf = serde_json::json!({
            "class_uid":2004, "time":timestamp / 1000,
            "metadata":{"uid":"f1","tenant_uid":TENANT_A,"log_source":"detections"},
            "unmapped":{}
        });
        let receipt = FindingReceipt::new(TENANT_A, "f1", &compact, &ocsf).unwrap();
        let source = receipt.source().unwrap();
        let receipt_bytes = receipt.bytes().unwrap();
        assert!(store.put_if_absent(&source.key, &receipt_bytes).await.unwrap());
        let parsed: CompactFinding = serde_json::from_value(compact).unwrap();
        let mut event = finding_event(&ocsf, &parsed).unwrap();
        event["time"] = Value::String("2026-09-26T18:00:00.000000Z".into());
        let schema = infer_schema(&[&event]).unwrap();
        let now_ms = timestamp / 1000;
        let schema = Arc::new(schema);
        let draft = PartDraft {
            tenant_id: TENANT_A.into(), signer_key_id: signer.key_id().into(), level: Level::L0,
            event_hour: event_hour_of(timestamp), schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(),
            schema: schema.clone(),
            inputs: PartInputs::Sources { sources: vec![SourceObject {
                key: source.key.clone(), version: source.version.clone(), sha256: source.sha256.clone(),
                bytes: receipt_bytes.len() as u64, rows: 1, edge_sha256: None,
            }], edge_log: None },
            admission: Some(Admission { ocsf_version: crate::iceberg::OCSF_VERSION.into(),
                admission_contract: "finding-outbox-v1".into(), feed_pins: BTreeMap::new() }),
            rows_in: 1, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
        };
        let batch = decode(schema.clone(), &[&event]).unwrap();
        let mut writer = PartWriter::create(dir.path(), draft, PartialSource::FromFindings, now_ms, 1).unwrap();
        writer.write(&batch).unwrap();
        let finished = writer.finish().unwrap();
        let refs = publish_parts(&store, &signer, &trusted, &[finished]).await.unwrap();
        let queue = SpoolQueue::new(dir.path().join("spool"), TENANT_A).unwrap();
        let cfg = IngestConfig::new(TENANT_A, dir.path().join("ingest"));
        let mut ingest = Ingestor::open(cfg, &store, &store, &queue, &signer, trusted.clone(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.unwrap();
        let request = || super::super::finding_append::FindingAppendRequest {
            tenant_id: TENANT_A.into(), writer_epoch: 1,
            schema: LogSchema::from_arrow(&schema).unwrap(), parts: refs.clone(), receipts: vec![source.clone()],
            deadline_unix_ms: None,
        };
        assert!(ingest.append_finding(super::super::finding_append::FindingAppendRequest {
            writer_epoch: 2, ..request()
        }, now_ms).await.is_err(), "a future Detect epoch cannot append through this owner");
        assert!(ingest.append_finding(super::super::finding_append::FindingAppendRequest {
            writer_epoch: 0, ..request()
        }, now_ms).await.is_err(), "an unassigned Detect epoch cannot append");
        let attempt = format!("{}/tenant={TENANT_A}/finding-outbox/receipts/.ingest-attempts/{}.json",
            crate::parts::format::PARTS_ROOT, sha256_hex(source.key.as_bytes()));
        assert!(store.put_if_absent(&attempt, &serde_json::to_vec(&source).unwrap()).await.unwrap());
        // NAN-3499: validation names every stored object of every part
        // (files + provenance) for writer registration, and an unregistered
        // finding never commits.
        let context = ingest.finding_context();
        let validated = super::super::ingest::validate_finding(&context, request()).await.unwrap();
        let mut stored = Vec::new();
        for part in &refs {
            let keys = PartKeys::new(TENANT_A, part.level, part.event_hour, &part.part_id).unwrap();
            stored.extend(store.list(&keys.file("")).await.unwrap());
        }
        let mut named: Vec<String> = validated.object_keys().into_iter().map(str::to_owned).collect();
        named.sort();
        stored.sort();
        assert!(!stored.is_empty());
        assert_eq!(named, stored);
        assert!(ingest.commit_finding(validated, now_ms).await.unwrap_err().to_string().contains("not registered"));
        // Crash after durable intent but before Add: replay must still append.
        let first = ingest.append_finding(request(), now_ms).await.unwrap();
        drop(ingest); // literal ingest appender restart before PostgreSQL ack
        assert_eq!(committed_receipts(&store, TENANT_A, &[source.clone()], &trusted).await.unwrap().len(), 1);
        assert!(committed_receipts(&store, TENANT_B, &[source.clone()], &trusted).await.unwrap().is_empty());
        let cfg = IngestConfig::new(TENANT_A, dir.path().join("ingest"));
        let mut restarted = Ingestor::open(cfg, &store, &store, &queue, &signer, trusted.clone(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now_ms + 1).await.unwrap();
        let replay = restarted.append_finding(request(), now_ms + 1).await.unwrap();
        assert_eq!((replay.seq, replay.entry_sha256), (first.seq, first.entry_sha256));
        assert_eq!(committed_receipts(&store, TENANT_A, &[source], &trusted).await.unwrap().len(), 1);
    }
}
