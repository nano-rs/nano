// SPDX-License-Identifier: AGPL-3.0-or-later

//! Control part-log index sync (`POST /internal/v1/enterprise-shared/lake-part-log:index`,
//! forwarded by the owner to control).
//!
//! Control attests a delete only against an index that is complete through
//! its head, so the executor pushes every verified entry, in order, from
//! control's `indexed_through_seq + 1` before asking for any permit.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use base64::Engine as _;
use futures::stream::{FuturesOrdered, StreamExt as _};
use serde::{Deserialize, Serialize};

use super::executor::{BearerRefused, LakePartRefusal};
use super::planner::LakePartLogView;
use crate::parts::part_log::{LogEntry, LogOp, PartRef, GENESIS_PREV};
use crate::parts::provenance::{PartInputs, ProvenanceRecord};

/// At most this many entries per index request (spec: 0..=256).
pub const MAX_INDEX_ENTRIES: usize = 256;
/// Leave time for the writer's completion receipt to reach control.
pub const INDEX_SETTLE_MS: i64 = 60_000;
/// Control's completion receipt acceptance window.
const RECEIPT_WINDOW_MS: i64 = 5 * 60_000;

/// NAN-3810: the `receipted_through` watermark [`sync_index`] admits young
/// entries under, fed by the tenant's single part-log writer in the same
/// process. Without it, a log appended every ~20 s always has an entry younger
/// than [`INDEX_SETTLE_MS`]; control refuses every attest while that entry
/// (already receipted) is unindexed (`NL009`), so GC never deletes.
///
/// The writer records only appends whose owner writer completion returned,
/// so control already holds their receipt. The watermark is the end of the
/// latest contiguous run of such appends. Any entry below the run's start
/// was committed some other way (a previous process, an
/// already-committed key, another writer before a fence), so its receipt is
/// unknown. The watermark is withheld until those entries are settled by age:
/// [`INDEX_SETTLE_MS`] after the `appended_at_ms` of the append that started
/// the run. Entries above the watermark, and every entry while it is
/// withheld, still wait out the age gate, as in #6437. The watermark never
/// lets a part through by itself: control re-verifies every entry's receipt
/// and refuses an attest while its index lags a receipted entry.
#[derive(Debug, Default)]
pub struct ReceiptedAppends {
    state: std::sync::Mutex<ReceiptedRun>,
}

#[derive(Debug, Default, Clone, Copy)]
struct ReceiptedRun {
    /// The last seq of the contiguous receipted run.
    through: Option<u64>,
    /// `appended_at_ms` of the append that started the run.
    started_at_ms: i64,
}

impl ReceiptedAppends {
    /// The writer committed `seq` (appended at `appended_at_ms`) and the
    /// owner writer completion (control's receipt) returned.
    pub fn record(&self, seq: u64, appended_at_ms: i64) {
        let mut run = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if run.through.is_none_or(|through| seq != through.saturating_add(1)) {
            // A first append or a gap: entries below `seq` have unknown receipts.
            run.started_at_ms = run.started_at_ms.max(appended_at_ms);
        }
        run.through = Some(seq);
    }

    /// The watermark to pass as `receipted_through` at `now_ms`.
    pub fn receipted_through(&self, now_ms: i64) -> Option<u64> {
        let run = *self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        run.through.filter(|_| now_ms.saturating_sub(run.started_at_ms) >= INDEX_SETTLE_MS)
    }
}
/// Stop filling a batch past this much base64 (spec: ~6 MiB).
pub const MAX_INDEX_BATCH_BASE64_BYTES: usize = 6 * 1024 * 1024;
/// At most this many part references (parts added + removed) per request.
/// NAN-2879 measurement (disposable PG18, loaded host): control indexes
/// ~0.2 ms per part reference (256 x 4-part adds in 0.23 s; one 1,000-part
/// adopt in 0.21 s). 4,096 references is ~1 s there; with a 5x allowance for
/// PlanetScale CPU and one RTT that stays <= ~5 s, well inside the control
/// Envoy's 15 s route timeout. A single entry is never split, so an entry
/// larger than this goes alone (an adopt entry holds at most 1,000 parts).
pub const MAX_INDEX_BATCH_PART_REFS: usize = 4_096;
/// Bound on index requests per sync (one pass): at most 2,048 entries.
pub const MAX_INDEX_REQUESTS_PER_SYNC: usize = 8;
/// NAN-3459: the cell publishes its immutable, already-folded view in ONE
/// sync, batch after batch, until control is caught up to that view head.
/// The bound only caps a pathological sync (262,144 entries).
pub const MAX_VIEW_INDEX_REQUESTS_PER_SYNC: usize = 1_024;
/// NAN-3495: consecutive 409 gaps (no batch accepted in between) one sync
/// recovers from before it yields. Another pusher moving control is resolved
/// by one re-read; a gap that persists is not progress, and 1,024 rounds of
/// it held a pass for minutes.
pub const MAX_CONSECUTIVE_GAP_RECOVERIES: u32 = 8;
/// NAN-3459: verified entries read ahead of the one being batched. Reads are
/// independent store GETs; serial reads ran at one store RTT per entry
/// (~8.5 entries/s on the load-test tenant), slower than a fresh pod's backlog. Results
/// are consumed strictly in sequence order, so the chain check, the batch
/// order and the fail-closed prefix rule are unchanged. The cell's read
/// pacer still bounds the request rate.
pub const INDEX_READ_AHEAD: usize = 8;
/// Retries of one index request after a back-off answer (429, 5xx,
/// `lake_part_index_unavailable`, transport) before the pass backs off.
pub const INDEX_BACKOFF_RETRIES: u32 = 4;
/// First retry delay; doubles per attempt up to [`INDEX_BACKOFF_MAX`].
pub const INDEX_BACKOFF_BASE: Duration = Duration::from_secs(1);
pub const INDEX_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A control `Retry-After` is honoured up to this long.
pub const INDEX_RETRY_AFTER_MAX: Duration = Duration::from_secs(60);

/// Parts an entry adds plus parts it removes: control's per-entry work unit.
pub fn part_refs(op: &LogOp) -> usize {
    match op {
        LogOp::Genesis { .. }
        | LogOp::Schema { .. }
        | LogOp::EdgeFloor { .. }
        | LogOp::Reject { .. }
        | LogOp::EdgeEnd { .. } => 0,
        LogOp::Add { parts, .. } | LogOp::Adopt { parts } => parts.len(),
        LogOp::Merge { supersedes, .. } | LogOp::Rewrite { supersedes, .. } => 1 + supersedes.len(),
        LogOp::Retire { parts, .. } => parts.len(),
    }
}

/// One verified entry and its exact stored bytes.
#[derive(Debug, Clone)]
pub struct VerifiedEntryBytes {
    pub bytes: Vec<u8>,
    /// SHA-256 hex of `bytes`.
    pub sha256: String,
    pub entry: LogEntry,
}

/// The newest checkpoint, as control's index route takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointClaim {
    pub seq: u64,
    /// SHA-256 of the stored checkpoint bytes.
    pub checkpoint_sha256: String,
    /// SHA-256 of entry `seq`.
    pub entry_sha256: String,
}

/// Reads the tenant's part log. Every entry it returns is verified
/// (strict parse, signature or canonical form, tenant) by the implementation;
/// the chain is re-checked by the caller.
#[async_trait]
pub trait PartLogReader: Send + Sync {
    /// Entry `seq`, or `None` past the head.
    async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>>;
    /// GC read-ahead retains raw objects and parses only the ordered next entry.
    /// Default seams retain their own verification and logical pacing.
    async fn read_ahead_bytes(&self, seq: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.verified_entry(seq).await?.map(|entry| entry.bytes))
    }
    /// The newest verified checkpoint, if any.
    async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>>;
    /// The part's owner-signed `provenance.json`, verified (signature,
    /// tenant, SHA-256 = `part.provenance_sha256`, record = `part`).
    async fn verified_provenance(&self, part: &PartRef) -> Result<ProvenanceRecord>;
}

/// Contract 8.1: the original compacted object an adopted part serves in
/// place. Control pins it while the part is live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptedClaim {
    pub part_id: String,
    pub key: String,
    pub sha256: String,
}

impl AdoptedClaim {
    /// `files.data[0].{name, sha256}` of a verified adopted record, which
    /// equal `inputs.objects[0].{key, sha256}`.
    pub fn from_record(part: &PartRef, record: &ProvenanceRecord) -> Result<Self> {
        let (PartInputs::Adopted { objects, .. }, [data]) = (&record.inputs, record.files.data.as_slice()) else {
            anyhow::bail!("part {} added by an adopt entry is not an adopted record", part.part_id);
        };
        anyhow::ensure!(
            record.part_id == part.part_id
                && objects.len() == 1
                && objects[0].key == data.name
                && objects[0].sha256 == data.sha256,
            "adopted record of part {} does not bind one object",
            part.part_id
        );
        Ok(Self { part_id: part.part_id.to_string(), key: data.name.clone(), sha256: data.sha256.clone() })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndexEntry {
    pub seq: u64,
    pub entry_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndexRequest {
    pub request_id: String,
    pub tenant_uuid: String,
    pub entries: Vec<IndexEntry>,
    /// Exactly one claim per part an `adopt` entry in `entries` adds.
    pub adopted: Vec<AdoptedClaim>,
    /// Serialized as `null` when absent.
    pub checkpoint: Option<CheckpointClaim>,
    /// Part files this executor deleted with an exact Worker receipt, so
    /// control can GC their writer receipt rows. Control records one only if
    /// a permit with that `permit_id` for that key exists for the tenant.
    pub deleted: Vec<DeletedKey>,
}

/// Most `deleted` records per index request.
pub const MAX_DELETED_PER_REQUEST: usize = 1_024;

/// A part file deleted under `permit_id`, with the Worker's absence receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletedKey {
    pub key: String,
    pub permit_id: String,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexStatus {
    pub tenant_uuid: String,
    pub indexed_through_seq: Option<u64>,
    pub head_entry_sha256: Option<String>,
    pub checkpoint_seq: Option<u64>,
    pub folded_through_seq: Option<u64>,
}

/// The owner-forwarded index route. Refusals are [`LakePartRefusal`]s
/// (an older owner that does not serve the route answers 404).
#[async_trait]
pub trait LakePartIndexClient: Send + Sync {
    async fn index(&self, request: &IndexRequest) -> Result<IndexStatus>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexSyncOutcome {
    /// `caught_up`: control indexed every entry the reader has.
    /// `head_appended_ms`: `appended_at_ms` of the last entry this sync
    /// pushed (None when it pushed nothing), for the lag report.
    /// `settling` (NAN-3852): not caught up only because the next entry is
    /// younger than [`INDEX_SETTLE_MS`] and not under the receipted
    /// watermark (e.g. visible in the store while the writer's completion is
    /// still in flight). Transient by construction: it clears with time,
    /// unlike a stalled or refusing index.
    Synced { status: IndexStatus, caught_up: bool, pushed: u64, gap_recoveries: u32, head_appended_ms: Option<i64>, settling: bool },
    /// HTTP 404: the owner does not serve the index route. No deletes.
    RouteNotServed,
    /// Rate limit, unavailable or transport fault.
    BackOff(String),
    /// Any other refusal or a chain disagreement. No deletes; alert.
    Refused(String),
}

fn status_read(tenant_uuid: &str) -> IndexRequest {
    IndexRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        tenant_uuid: tenant_uuid.to_string(),
        entries: Vec::new(),
        adopted: Vec::new(),
        checkpoint: None,
        deleted: Vec::new(),
    }
}

/// Successful prefix publication remains reportable when a later read fails.
/// The original error stays in the chain and still prevents deletion.
#[derive(Debug, thiserror::Error)]
#[error("index read interrupted after publishing {pushed} verified entries")]
pub(crate) struct IndexReadProgress {
    pub pushed: u64,
}

/// Report deleted keys to control as status reads carrying only `deleted`,
/// at most [`MAX_DELETED_PER_REQUEST`] each, oldest first. Reported records
/// leave `queue`; on the first failure the rest stay queued (in memory) for
/// the next pass and the refusal code is returned.
///
/// Control prunes permits 1 h after expiry, so a record that is not reported
/// by then is ignored; a record never reported (a crash, or a report that
/// keeps failing) leaks only that key's writer receipt row in control, never
/// an object.
pub async fn report_deleted(
    client: &dyn LakePartIndexClient,
    tenant_uuid: &str,
    queue: &mut Vec<DeletedKey>,
) -> std::result::Result<u64, String> {
    let mut reported = 0;
    while !queue.is_empty() {
        let batch = queue.len().min(MAX_DELETED_PER_REQUEST);
        let request = IndexRequest { deleted: queue[..batch].to_vec(), ..status_read(tenant_uuid) };
        match call(client, &request).await {
            Call::Ok(_) => {
                queue.drain(..batch);
                reported += batch as u64;
            }
            Call::Gap => return Err("lake_part_index_gap".into()),
            Call::Stop(IndexSyncOutcome::RouteNotServed) => return Err("index_route_not_served".into()),
            Call::Stop(IndexSyncOutcome::BackOff(code) | IndexSyncOutcome::Refused(code)) => return Err(code),
            Call::Stop(IndexSyncOutcome::Synced { .. }) => return Err("unexpected".into()),
        }
    }
    Ok(reported)
}

/// Pause reason when the owner refuses the cell's bearer (HTTP 401).
pub const BEARER_REFUSED: &str = "owner_bearer_refused_401";

enum Call {
    Ok(IndexStatus),
    Gap,
    Stop(IndexSyncOutcome),
}

async fn call(client: &dyn LakePartIndexClient, request: &IndexRequest) -> Call {
    match client.index(request).await {
        Ok(status) if status.tenant_uuid == request.tenant_uuid => Call::Ok(status),
        Ok(_) => Call::Stop(IndexSyncOutcome::Refused("index_response_tenant_mismatch".into())),
        Err(error) if error.is::<BearerRefused>() => Call::Stop(IndexSyncOutcome::Refused(BEARER_REFUSED.into())),
        Err(error) => match error.downcast_ref::<LakePartRefusal>() {
            Some(refusal) if refusal.status == Some(404) => Call::Stop(IndexSyncOutcome::RouteNotServed),
            Some(refusal) if refusal.code == "lake_part_index_gap" => Call::Gap,
            Some(refusal) if refusal.is_backoff() => Call::Stop(IndexSyncOutcome::BackOff(refusal.code.clone())),
            Some(refusal) => Call::Stop(IndexSyncOutcome::Refused(refusal.code.clone())),
            None => Call::Stop(IndexSyncOutcome::BackOff(format!("index_call_failed: {error:#}"))),
        },
    }
}

/// The delay before retry `attempt` (1-based): control's `Retry-After` when it
/// sent one (capped), else exponential from [`INDEX_BACKOFF_BASE`].
pub fn index_backoff_delay(attempt: u32, retry_after: Option<Duration>) -> Duration {
    match retry_after {
        Some(after) => after.min(INDEX_RETRY_AFTER_MAX),
        None => INDEX_BACKOFF_BASE
            .saturating_mul(1_u32 << attempt.saturating_sub(1).min(16))
            .min(INDEX_BACKOFF_MAX),
    }
}

/// [`call`], retrying a back-off answer (rate limit, unavailable, 5xx,
/// transport) up to [`INDEX_BACKOFF_RETRIES`] times. Re-sending the same
/// request is safe: an append control already committed answers 409 gap,
/// which the caller resolves by re-reading control's position. Every
/// other answer (refusal, gap, 404) returns at once.
async fn call_retrying(client: &dyn LakePartIndexClient, request: &IndexRequest) -> Call {
    let mut attempt = 0_u32;
    loop {
        let (status, retry_after) = match client.index(request).await {
            Ok(status) if status.tenant_uuid == request.tenant_uuid => return Call::Ok(status),
            Ok(_) => return Call::Stop(IndexSyncOutcome::Refused("index_response_tenant_mismatch".into())),
            // A refused bearer is not a transport fault: never retried.
            Err(error) if error.is::<BearerRefused>() => return Call::Stop(IndexSyncOutcome::Refused(BEARER_REFUSED.into())),
            Err(error) => match error.downcast_ref::<LakePartRefusal>() {
                Some(refusal) if refusal.status == Some(404) => return Call::Stop(IndexSyncOutcome::RouteNotServed),
                Some(refusal) if refusal.code == "lake_part_index_gap" => return Call::Gap,
                Some(refusal) if refusal.is_backoff() => {
                    if attempt >= INDEX_BACKOFF_RETRIES {
                        tracing::warn!(status = ?refusal.status, code = %refusal.code, attempts = attempt + 1,
                            "lake-part GC index append still backing off; pausing the pass");
                        return Call::Stop(IndexSyncOutcome::BackOff(refusal.code.clone()));
                    }
                    (refusal.status, refusal.retry_after)
                }
                Some(refusal) => return Call::Stop(IndexSyncOutcome::Refused(refusal.code.clone())),
                None => {
                    if attempt >= INDEX_BACKOFF_RETRIES {
                        tracing::warn!(error = %format!("{error:#}"), attempts = attempt + 1,
                            "lake-part GC index append transport still failing; pausing the pass");
                        return Call::Stop(IndexSyncOutcome::BackOff(format!("index_call_failed: {error:#}")));
                    }
                    (None, None)
                }
            },
        };
        attempt += 1;
        let delay = index_backoff_delay(attempt, retry_after);
        if attempt >= 2 {
            // Repeated: visible at WARN with the HTTP status (None = transport).
            tracing::warn!(status = ?status, attempt, retry_ms = delay.as_millis() as u64,
                "lake-part GC index append backing off");
        } else {
            tracing::debug!(status = ?status, attempt, retry_ms = delay.as_millis() as u64,
                "lake-part GC index append backing off");
        }
        tokio::time::sleep(delay).await;
    }
}

type EntryRead<'a> = Pin<Box<dyn Future<Output = (u64, Result<Option<VerifiedEntryBytes>>)> + Send + 'a>>;

/// Bounded in-order read-ahead over a [`PartLogReader`] (NAN-3459).
/// At most `window` reads are in flight; results come back strictly in
/// sequence order, and nothing past `limit` (an immutable view head) is
/// ever requested.
struct ReadAhead<'a> {
    reader: &'a dyn PartLogReader,
    pending: FuturesOrdered<EntryRead<'a>>,
    /// The sequence the next completed read yields.
    front: Option<u64>,
    /// The next sequence to request.
    queued: u64,
    limit: Option<u64>,
    window: usize,
    /// One verified entry handed back by [`Self::unread`].
    held: Option<VerifiedEntryBytes>,
}

impl<'a> ReadAhead<'a> {
    fn new(reader: &'a dyn PartLogReader, limit: Option<u64>, window: usize) -> Self {
        Self { reader, pending: FuturesOrdered::new(), front: None, queued: 0, limit, window: window.max(1), held: None }
    }

    /// Entry `seq`. A request for anything but the next expected sequence
    /// (control moved: gap recovery) drops every speculative read first.
    async fn entry(&mut self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
        if let Some(held) = self.held.take() {
            if held.entry.seq == seq {
                return Ok(Some(held));
            }
        }
        if self.front != Some(seq) {
            self.pending = FuturesOrdered::new();
            self.front = Some(seq);
            self.queued = seq;
        }
        while self.pending.len() < self.window && self.limit.is_none_or(|limit| self.queued <= limit) {
            let (next, reader) = (self.queued, self.reader);
            self.pending.push_back(Box::pin(async move { (next, reader.verified_entry(next).await) }));
            self.queued = self.queued.checked_add(1).context("index read-ahead sequence overflow")?;
        }
        let (read, result) = self.pending.next().await.context("index read-ahead is empty")?;
        anyhow::ensure!(read == seq, "index read-ahead returned entry {read} for seq {seq}");
        self.front = seq.checked_add(1);
        result
    }

    /// Hand back the entry just read: it opens the next batch.
    fn unread(&mut self, entry: VerifiedEntryBytes) {
        self.held = Some(entry);
    }

    /// Stop reading (an absent entry or a read error ends the batch).
    fn stop(&mut self) {
        self.pending = FuturesOrdered::new();
        self.front = None;
        self.held = None;
    }
}

fn base64_len(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}

/// Push the reader's verified entries to control until it is caught up (or a
/// bound or an unsettled entry is hit), plus the newest checkpoint claim once
/// control has indexed through it. A 409 gap (another pusher moved control) re-reads the status
/// and resumes from control's new position. `receipted_through`, when supplied,
/// must cover only entries whose writer completion succeeded, never a read head.
pub async fn sync_index(
    client: &dyn LakePartIndexClient,
    reader: &dyn PartLogReader,
    tenant_uuid: &str,
    now_ms: i64,
    receipted_through: Option<u64>,
) -> Result<IndexSyncOutcome> {
    sync_index_inner(client, reader, tenant_uuid, None, now_ms, receipted_through).await
}

/// Publish only the exact complete view already folded by the cell. The cell
/// made a fresh uncached absent-tail read in advance_view. This function does
/// not claim that absence stays current: EVERY owner attestation still checks
/// control's committed next receipt and above-head reservations. Any refusal
/// resumes the cell's bounded fold before another authorization attempt.
/// Avoid spending a paced read slot probing past this immutable target during
/// publication; the returned head/digest must equal that target in executor.
pub(crate) async fn sync_index_through_view(
    client: &dyn LakePartIndexClient,
    reader: &dyn PartLogReader,
    tenant_uuid: &str,
    head: Option<u64>,
    now_ms: i64,
    receipted_through: Option<u64>,
) -> Result<IndexSyncOutcome> {
    sync_index_inner(client, reader, tenant_uuid, Some(head), now_ms, receipted_through).await
}

async fn sync_index_inner(
    client: &dyn LakePartIndexClient,
    reader: &dyn PartLogReader,
    tenant_uuid: &str,
    view_target: Option<Option<u64>>,
    now_ms: i64,
    receipted_through: Option<u64>,
) -> Result<IndexSyncOutcome> {
    let mut status = match call_retrying(client, &status_read(tenant_uuid)).await {
        Call::Ok(status) => status,
        Call::Gap => return Ok(IndexSyncOutcome::Refused("lake_part_index_gap".into())),
        Call::Stop(outcome) => return Ok(outcome),
    };
    let checkpoint = reader.newest_checkpoint().await?;
    let (mut pushed, mut gap_recoveries, mut stalled_gaps) = (0_u64, 0_u32, 0_u32);
    let mut head_appended_ms = None;
    let max_requests = if view_target.is_some() { MAX_VIEW_INDEX_REQUESTS_PER_SYNC } else { MAX_INDEX_REQUESTS_PER_SYNC };
    let mut ahead = ReadAhead::new(reader, view_target.flatten(), INDEX_READ_AHEAD);
    for _ in 0..max_requests {
        let next = status.indexed_through_seq.map_or(0, |seq| seq + 1);
        let mut expected_prev = match (status.indexed_through_seq, status.head_entry_sha256.as_deref()) {
            (None, _) => GENESIS_PREV.to_string(),
            (Some(_), Some(sha)) => sha.to_string(),
            (Some(_), None) => return Ok(IndexSyncOutcome::Refused("index_status_invalid".into())),
        };
        let (mut entries, mut adopted, mut batch_bytes, mut exhausted) = (Vec::new(), Vec::new(), 0_usize, false);
        let mut batch_refs = 0_usize;
        let mut unsettled = false;
        let mut batch_meta = Vec::new();
        let mut read_error = None;
        let mut last: Option<(u64, String, i64)> = None;
        while entries.len() < MAX_INDEX_ENTRIES {
            let seq = next + entries.len() as u64;
            if view_target.is_some_and(|head| head.is_none_or(|head| seq > head)) {
                exhausted = true;
                break;
            }
            let verified = match ahead.entry(seq).await {
                Ok(entry) => entry,
                Err(error) => {
                    // A cell's complete-view guard can discover an arrival
                    // after this batch's verified prefix. Publish that prefix
                    // before returning the error; never plan from it. Otherwise
                    // sustained arrivals prevent every short batch from ever
                    // reaching control, even with a retained object inventory.
                    ahead.stop();
                    read_error = Some(error);
                    break;
                }
            };
            let Some(verified) = verified else {
                ahead.stop();
                if view_target.is_some() {
                    read_error = Some(anyhow::anyhow!("complete_view_entry_missing"));
                    break;
                }
                exhausted = true;
                break;
            };
            if verified.entry.seq != seq || verified.entry.prev_sha256 != expected_prev {
                // Our verified log disagrees with what control indexed.
                return Ok(IndexSyncOutcome::Refused("local_chain_mismatch".into()));
            }
            if now_ms.saturating_sub(verified.entry.appended_at_ms) < INDEX_SETTLE_MS
                && receipted_through.is_none_or(|through| seq > through)
            {
                ahead.stop();
                exhausted = true;
                unsettled = true;
                break;
            }
            // Claims ride in the same request as the entry that adds them.
            let mut claims = Vec::new();
            if let LogOp::Adopt { parts } = &verified.entry.op {
                for part in parts {
                    let record = reader.verified_provenance(part).await?;
                    claims.push(AdoptedClaim::from_record(part, &record)?);
                }
            }
            let size = base64_len(verified.bytes.len())
                + claims.iter().map(|c| c.part_id.len() + c.key.len() + c.sha256.len() + 48).sum::<usize>();
            let refs = part_refs(&verified.entry.op);
            if !entries.is_empty()
                && (batch_bytes + size > MAX_INDEX_BATCH_BASE64_BYTES || batch_refs + refs > MAX_INDEX_BATCH_PART_REFS) {
                // The entry opens the next batch (already verified; the next
                // batch re-checks its chain link against control's new head).
                ahead.unread(verified);
                break;
            }
            batch_bytes += size;
            batch_refs += refs;
            adopted.extend(claims);
            batch_meta.push((seq, verified.sha256.clone(), verified.entry.appended_at_ms, adopted.len()));
            expected_prev = verified.sha256.clone();
            last = Some((seq, verified.sha256, verified.entry.appended_at_ms));
            entries.push(IndexEntry {
                seq,
                entry_base64: base64::engine::general_purpose::STANDARD.encode(&verified.bytes),
            });
        }
        let through = last.as_ref().map(|(seq, _, _)| *seq).or(status.indexed_through_seq);
        let claim = checkpoint.clone().filter(|claim| {
            through.is_some_and(|through| claim.seq <= through)
                && status.checkpoint_seq.is_none_or(|indexed| indexed < claim.seq)
        });
        if entries.is_empty() && claim.is_none() {
            if let Some(error) = read_error {
                return Err(error.context(IndexReadProgress { pushed }));
            }
            return Ok(IndexSyncOutcome::Synced {
                status,
                caught_up: exhausted && !unsettled,
                pushed,
                gap_recoveries,
                head_appended_ms,
                settling: unsettled,
            });
        }
        let mut count = entries.len() as u64;
        let mut request = IndexRequest { entries, adopted, checkpoint: claim, ..status_read(tenant_uuid) };
        let mut answer = call_retrying(client, &request).await;
        if matches!(&answer, Call::Stop(IndexSyncOutcome::Refused(code)) if code == "lake_part_index_receipt_missing") {
            if let Some((seq, _, appended_ms, _)) = batch_meta.last() {
                if now_ms.saturating_sub(*appended_ms) < RECEIPT_WINDOW_MS {
                    if request.entries.len() == 1 {
                        return Ok(IndexSyncOutcome::BackOff("lake_part_index_receipt_pending".into()));
                    }
                    // Refused batches are atomic. Retry a strictly shorter prefix once,
                    // keeping adopt claims and the checkpoint within that prefix.
                    let keep = batch_meta.iter().position(|(_, _, ms, _)|
                        now_ms.saturating_sub(*ms) <= INDEX_SETTLE_MS)
                        .unwrap_or(request.entries.len() - 1);
                    if keep == 0 {
                        return Ok(IndexSyncOutcome::BackOff("lake_part_index_receipt_pending".into()));
                    }
                    request.request_id = uuid::Uuid::new_v4().to_string();
                    request.entries.truncate(keep);
                    batch_meta.truncate(keep);
                    let (seq, sha, ms, claims) = batch_meta.last().unwrap();
                    request.adopted.truncate(*claims);
                    request.checkpoint = request.checkpoint.filter(|claim| claim.seq <= *seq);
                    last = Some((*seq, sha.clone(), *ms));
                    count = keep as u64;
                    exhausted = true;
                    unsettled = true;
                    answer = call_retrying(client, &request).await;
                    if matches!(&answer, Call::Stop(IndexSyncOutcome::Refused(code)) if code == "lake_part_index_receipt_missing")
                        && now_ms.saturating_sub(*ms) < RECEIPT_WINDOW_MS
                    {
                        answer = Call::Stop(IndexSyncOutcome::BackOff("lake_part_index_receipt_pending".into()));
                    }
                } else {
                    tracing::error!(newest_seq = seq, "part-log batch still has a missing writer receipt beyond the receipt window");
                }
            }
        }
        match answer {
            Call::Ok(next_status) => {
                if let Some((seq, sha, _)) = &last {
                    let behind = next_status.indexed_through_seq.is_none_or(|through| through < *seq);
                    let differs = next_status.indexed_through_seq == Some(*seq)
                        && next_status.head_entry_sha256.as_deref() != Some(sha.as_str());
                    if behind || differs {
                        return Ok(IndexSyncOutcome::Refused("index_response_mismatch".into()));
                    }
                }
                pushed += count;
                stalled_gaps = 0;
                if let Some((_, _, appended_ms)) = &last {
                    head_appended_ms = Some(*appended_ms);
                }
                status = next_status;
                if let Some(error) = read_error {
                    return Err(error.context(IndexReadProgress { pushed }));
                }
                if unsettled {
                    return Ok(IndexSyncOutcome::Synced { status, caught_up: false, pushed, gap_recoveries, head_appended_ms, settling: true });
                }
                if exhausted && request.checkpoint.is_none() && count > 0 {
                    // Caught up unless the checkpoint still needs sending.
                    let pending = checkpoint.as_ref().is_some_and(|claim| {
                        status.checkpoint_seq.is_none_or(|indexed| indexed < claim.seq)
                            && status.indexed_through_seq.is_some_and(|through| claim.seq <= through)
                    });
                    if !pending {
                        return Ok(IndexSyncOutcome::Synced { status, caught_up: !unsettled, pushed, gap_recoveries, head_appended_ms, settling: unsettled });
                    }
                }
            }
            Call::Gap => {
                gap_recoveries += 1;
                stalled_gaps += 1;
                if stalled_gaps >= MAX_CONSECUTIVE_GAP_RECOVERIES {
                    break;
                }
                status = match call_retrying(client, &status_read(tenant_uuid)).await {
                    Call::Ok(status) => status,
                    Call::Gap => return Ok(IndexSyncOutcome::Refused("lake_part_index_gap".into())),
                    Call::Stop(outcome) => return Ok(outcome),
                };
            }
            Call::Stop(outcome) => {
                if matches!(&outcome, IndexSyncOutcome::Refused(code) if code == "lake_part_index_receipt_missing") {
                    // The refusal body exposes only a code, so report the batch range
                    // rather than guessing which entry control rejected.
                    tracing::error!(first_seq = ?request.entries.first().map(|entry| entry.seq),
                        last_seq = ?request.entries.last().map(|entry| entry.seq),
                        "control refused part-log entries with missing writer receipts");
                }
                return Ok(outcome);
            }
        }
    }
    Ok(IndexSyncOutcome::Synced { status, caught_up: false, pushed, gap_recoveries, head_appended_ms, settling: false })
}

/// Fold every entry after the view's head into it. O(new entries).
pub async fn catch_up_view(view: &mut LakePartLogView, reader: &dyn PartLogReader) -> Result<u64> {
    catch_up_view_bounded(view, reader, u64::MAX).await
}

/// [`catch_up_view`], at most `limit` entries (a caller persists the view
/// between chunks). Returns the number applied; fewer than `limit` means the
/// view reached the head.
pub async fn catch_up_view_bounded(view: &mut LakePartLogView, reader: &dyn PartLogReader, limit: u64) -> Result<u64> {
    let mut applied = 0;
    while applied < limit {
        let seq = view.head_seq().map_or(0, |seq| seq + 1);
        let Some(verified) = reader.verified_entry(seq).await? else { return Ok(applied) };
        anyhow::ensure!(verified.entry.seq == seq, "part-log reader returned entry {} for seq {seq}", verified.entry.seq);
        view.apply(&verified.entry, &verified.sha256)?;
        applied += 1;
    }
    Ok(applied)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::lake_part_gc::planner::tests::{id, Chain, T0};
    use crate::lake_part_gc::request::tests::TENANT_UUID;
    use std::sync::Mutex;

    /// Serves a [`Chain`]: canonical entry bytes, and the chain's adopted records.
    pub struct ChainReader {
        pub chain: Chain,
        pub checkpoint: Option<CheckpointClaim>,
    }

    #[async_trait]
    impl PartLogReader for ChainReader {
        async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
            Ok(self.chain.entries.get(seq as usize).map(|(entry, sha)| VerifiedEntryBytes {
                bytes: entry.to_bytes().unwrap(),
                sha256: sha.clone(),
                entry: entry.clone(),
            }))
        }

        async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>> {
            Ok(self.checkpoint.clone())
        }

        async fn verified_provenance(&self, part: &PartRef) -> Result<ProvenanceRecord> {
            anyhow::Context::context(self.chain.records.get(&part.part_id).cloned(), "no verified provenance")
        }
    }

    /// A control index: accepts contiguous pushes, 409s gaps.
    pub struct FakeIndex {
        pub shas: Mutex<Vec<String>>,
        pub checkpoint_seq: Mutex<Option<u64>>,
        pub calls: Mutex<Vec<(Vec<u64>, Option<u64>)>>,
        /// Adopted claims per call, as control pinned them.
        pub claims: Mutex<Vec<Vec<AdoptedClaim>>>,
        /// Entries some other pusher indexes right before the Nth call.
        pub concurrent: Mutex<Option<(usize, Vec<String>)>>,
        pub not_served: bool,
        pub missing_receipt: Option<u64>,
        /// `deleted` batches control recorded, per request.
        pub deleted: Mutex<Vec<Vec<DeletedKey>>>,
        /// Answer 503 to any request carrying `deleted`.
        pub refuse_deleted: Mutex<bool>,
        /// Back-off answers for the next index requests, oldest first.
        pub backoff: Mutex<std::collections::VecDeque<LakePartRefusal>>,
    }

    impl FakeIndex {
        pub fn new(shas: Vec<String>) -> Self {
            Self {
                shas: Mutex::new(shas),
                checkpoint_seq: Mutex::new(None),
                calls: Mutex::new(Vec::new()),
                claims: Mutex::new(Vec::new()),
                concurrent: Mutex::new(None),
                not_served: false,
                missing_receipt: None,
                deleted: Mutex::new(Vec::new()),
                refuse_deleted: Mutex::new(false),
                backoff: Mutex::new(Default::default()),
            }
        }

        fn status(&self) -> IndexStatus {
            let shas = self.shas.lock().unwrap();
            IndexStatus {
                tenant_uuid: TENANT_UUID.into(),
                indexed_through_seq: shas.len().checked_sub(1).map(|n| n as u64),
                head_entry_sha256: shas.last().cloned(),
                checkpoint_seq: *self.checkpoint_seq.lock().unwrap(),
                folded_through_seq: None,
            }
        }
    }

    #[async_trait]
    impl LakePartIndexClient for FakeIndex {
        async fn index(&self, request: &IndexRequest) -> Result<IndexStatus> {
            if self.not_served {
                return Err(LakePartRefusal::new(Some(404), "http_404").into());
            }
            if !request.deleted.is_empty() {
                assert!(request.entries.is_empty() && request.checkpoint.is_none() && request.deleted.len() <= MAX_DELETED_PER_REQUEST);
                if *self.refuse_deleted.lock().unwrap() {
                    return Err(LakePartRefusal::new(Some(503), "lake_part_index_unavailable").into());
                }
                self.deleted.lock().unwrap().push(request.deleted.clone());
                return Ok(self.status());
            }
            if self.missing_receipt.is_some_and(|seq| request.entries.iter().any(|entry| entry.seq == seq)) {
                self.calls.lock().unwrap().push((request.entries.iter().map(|e| e.seq).collect(), None));
                return Err(LakePartRefusal::new(Some(409), "lake_part_index_receipt_missing").into());
            }
            if let Some(refusal) = self.backoff.lock().unwrap().pop_front() {
                return Err(refusal.into());
            }
            let n = {
                let mut calls = self.calls.lock().unwrap();
                calls.push((request.entries.iter().map(|e| e.seq).collect(), request.checkpoint.as_ref().map(|c| c.seq)));
                calls.len()
            };
            if let Some((_, extra)) = self.concurrent.lock().unwrap().take_if(|(at, _)| *at == n) {
                self.shas.lock().unwrap().extend(extra);
            }
            self.claims.lock().unwrap().push(request.adopted.clone());
            // Control's adopt rule: one claim per adopted part in the batch,
            // no claim for anything else.
            let mut expected = Vec::new();
            let mut pending = Vec::new();
            {
                let shas = self.shas.lock().unwrap();
                for (offset, entry) in request.entries.iter().enumerate() {
                    if entry.seq != shas.len() as u64 + offset as u64 {
                        return Err(LakePartRefusal::new(Some(409), "lake_part_index_gap").into());
                    }
                    let bytes = base64::engine::general_purpose::STANDARD.decode(&entry.entry_base64).unwrap();
                    let parsed = LogEntry::parse_bytes(&bytes, TENANT_UUID).unwrap();
                    if let LogOp::Adopt { parts } = &parsed.op {
                        for part in parts {
                            if !request.adopted.iter().any(|c| c.part_id == part.part_id.as_str()) {
                                return Err(LakePartRefusal::new(Some(409), "lake_part_index_entry_invalid").into());
                            }
                            expected.push(part.part_id.to_string());
                        }
                    }
                    pending.push(crate::parts::sha256_hex(&bytes));
                }
            }
            if request.adopted.len() != expected.len()
                || request.adopted.iter().any(|c| !expected.contains(&c.part_id))
            {
                return Err(LakePartRefusal::new(Some(400), "lake_part_index_invalid_request").into());
            }
            self.shas.lock().unwrap().extend(pending);
            if let Some(claim) = &request.checkpoint {
                *self.checkpoint_seq.lock().unwrap() = Some(claim.seq);
            }
            Ok(self.status())
        }
    }

    /// Shas as the fake index computes them (of the served bytes).
    pub fn served_shas(chain: &Chain) -> Vec<String> {
        chain.entries.iter().map(|(e, _)| crate::parts::sha256_hex(&e.to_bytes().unwrap())).collect()
    }

    fn chain(entries: u64) -> Chain {
        let mut chain = Chain::new();
        for n in 1..entries {
            chain.add(n, T0 + n as i64);
        }
        chain
    }

    fn tail_reader(age_ms: i64) -> (ChainReader, i64) {
        let now = T0 + 600_000;
        let mut chain = chain(5);
        chain.add(5, now - age_ms);
        (ChainReader { chain, checkpoint: None }, now)
    }

    #[tokio::test]
    async fn young_tail_entry_is_not_indexed_until_settled() {
        let (reader, now) = tail_reader(5_000);
        for bounded in [false, true] {
            let index = FakeIndex::new(Vec::new());
            let outcome = if bounded {
                sync_index_through_view(&index, &reader, TENANT_UUID, Some(5), now, None).await.unwrap()
            } else {
                sync_index(&index, &reader, TENANT_UUID, now, None).await.unwrap()
            };
            assert!(matches!(outcome, IndexSyncOutcome::Synced { caught_up: false, pushed: 5, .. }));
            assert_eq!(index.calls.lock().unwrap()[1].0, vec![0, 1, 2, 3, 4]);
            let next = sync_index(&index, &reader, TENANT_UUID, now + INDEX_SETTLE_MS, None).await.unwrap();
            assert!(matches!(next, IndexSyncOutcome::Synced { caught_up: true, pushed: 1, .. }));
        }
    }

    /// NAN-3852: a sync that stops only at a young unreceipted entry reports
    /// `settling` (transient); one that stops at its request bound, or is
    /// caught up, does not. Only `settling` may be waited out by the cell.
    #[tokio::test]
    async fn only_a_young_unreceipted_head_reports_settling() {
        let (reader, now) = tail_reader(5_000);
        for (pre_indexed, bounded) in [(0, false), (0, true), (5, false), (5, true)] {
            let index = FakeIndex::new(Vec::new());
            if pre_indexed > 0 {
                sync_index(&index, &reader, TENANT_UUID, now, None).await.unwrap();
            }
            let outcome = if bounded {
                sync_index_through_view(&index, &reader, TENANT_UUID, Some(5), now, None).await.unwrap()
            } else {
                sync_index(&index, &reader, TENANT_UUID, now, None).await.unwrap()
            };
            let pushed = 5 - pre_indexed;
            assert!(matches!(outcome, IndexSyncOutcome::Synced { caught_up: false, settling: true, pushed: p, .. } if p == pushed),
                "pre_indexed={pre_indexed} bounded={bounded}: {outcome:?}");
            // The receipted watermark admits it: caught up, not settling.
            let receipted = sync_index(&index, &reader, TENANT_UUID, now, Some(5)).await.unwrap();
            assert!(matches!(receipted, IndexSyncOutcome::Synced { caught_up: true, settling: false, pushed: 1, .. }), "{receipted:?}");
        }
        let long = ChainReader { chain: chain(5_000), checkpoint: None };
        let index = FakeIndex::new(Vec::new());
        let bounded = sync_index(&index, &long, TENANT_UUID, T0 + 86_400_000, None).await.unwrap();
        assert!(matches!(bounded, IndexSyncOutcome::Synced { caught_up: false, settling: false, .. }), "{bounded:?}");
    }

    /// NAN-3810: the writer watermark covers only a contiguous run of
    /// receipted appends, and is withheld until every entry below the run
    /// (unknown receipt) is settled by age.
    #[test]
    fn receipted_appends_watermark_is_contiguous_and_withheld_after_a_gap() {
        let ledger = ReceiptedAppends::default();
        assert_eq!(ledger.receipted_through(T0), None);
        ledger.record(5, T0);
        assert_eq!(ledger.receipted_through(T0 + INDEX_SETTLE_MS - 1), None, "entries below 5 may be young and unreceipted");
        assert_eq!(ledger.receipted_through(T0 + INDEX_SETTLE_MS), Some(5));
        ledger.record(6, T0 + 20_000);
        ledger.record(7, T0 + 40_000);
        assert_eq!(ledger.receipted_through(T0 + INDEX_SETTLE_MS), Some(7), "a contiguous run keeps its start");
        // seq 8 committed without a recorded receipt (e.g. an already-held key).
        ledger.record(9, T0 + 80_000);
        assert_eq!(ledger.receipted_through(T0 + INDEX_SETTLE_MS), None);
        assert_eq!(ledger.receipted_through(T0 + 80_000 + INDEX_SETTLE_MS - 1), None);
        assert_eq!(ledger.receipted_through(T0 + 80_000 + INDEX_SETTLE_MS), Some(9));
    }

    /// NAN-3810: entries the watermark covers are indexed while young; a
    /// young entry above it (no recorded receipt) still waits.
    #[tokio::test]
    async fn writer_watermark_admits_receipted_young_tail_only() {
        let now = T0 + 600_000;
        let mut chain = chain(5);
        for (seq, age) in [(5, 45_000), (6, 25_000), (7, 5_000)] {
            chain.add(seq, now - age);
        }
        let reader = ChainReader { chain, checkpoint: None };
        let ledger = ReceiptedAppends::default();
        // The writer's run started at seq 4 (settled), so the watermark is live.
        ledger.record(4, T0 + 4);
        ledger.record(5, now - 45_000);
        ledger.record(6, now - 25_000);
        let index = FakeIndex::new(Vec::new());
        let outcome = sync_index(&index, &reader, TENANT_UUID, now, ledger.receipted_through(now)).await.unwrap();
        assert!(matches!(outcome, IndexSyncOutcome::Synced { caught_up: false, pushed: 7, .. }), "{outcome:?}");
        assert_eq!(index.shas.lock().unwrap().len(), 7, "seq 7 is young and not receipted");
        ledger.record(7, now - 5_000);
        let outcome = sync_index(&index, &reader, TENANT_UUID, now, ledger.receipted_through(now)).await.unwrap();
        assert!(matches!(outcome, IndexSyncOutcome::Synced { caught_up: true, pushed: 1, .. }), "{outcome:?}");
    }

    #[tokio::test]
    async fn receipted_watermark_admits_young_entries() {
        let (reader, now) = tail_reader(5_000);
        let index = FakeIndex::new(Vec::new());
        let outcome = sync_index(&index, &reader, TENANT_UUID, now, Some(5)).await.unwrap();
        assert!(matches!(outcome, IndexSyncOutcome::Synced { caught_up: true, pushed: 6, .. }));
    }

    #[tokio::test]
    async fn receipt_missing_on_young_tail_publishes_prefix_and_backs_off() {
        for age in [5_000, INDEX_SETTLE_MS + 1] {
            let (mut reader, now) = tail_reader(age);
            reader.checkpoint = Some(CheckpointClaim {
                seq: 5, checkpoint_sha256: "c".repeat(64), entry_sha256: reader.chain.entries[5].1.clone(),
            });
            let mut index = FakeIndex::new(Vec::new());
            index.missing_receipt = Some(5);
            // Exercise both an admitted young tail and a receipt delayed beyond settling.
            let watermark = (age < INDEX_SETTLE_MS).then_some(5);
            let outcome = sync_index(&index, &reader, TENANT_UUID, now, watermark).await.unwrap();
            assert!(matches!(outcome, IndexSyncOutcome::Synced { caught_up: false, pushed: 5, .. }));
            assert_eq!(index.calls.lock().unwrap()[2], (vec![0, 1, 2, 3, 4], None));
            assert_eq!(*index.checkpoint_seq.lock().unwrap(), None);
            let single = sync_index(&index, &reader, TENANT_UUID, now, watermark).await.unwrap();
            assert_eq!(single, IndexSyncOutcome::BackOff("lake_part_index_receipt_pending".into()));
        }
    }

    #[tokio::test]
    async fn receipt_prefix_retry_rejects_another_tenants_response() {
        struct WrongTenant(FakeIndex);
        #[async_trait]
        impl LakePartIndexClient for WrongTenant {
            async fn index(&self, request: &IndexRequest) -> Result<IndexStatus> {
                let mut status = self.0.index(request).await?;
                if !request.entries.is_empty() {
                    status.tenant_uuid = "another-tenant".into();
                }
                Ok(status)
            }
        }
        let (reader, now) = tail_reader(INDEX_SETTLE_MS + 1);
        let mut index = FakeIndex::new(Vec::new());
        index.missing_receipt = Some(5);
        let outcome = sync_index(&WrongTenant(index), &reader, TENANT_UUID, now, None).await.unwrap();
        assert_eq!(outcome, IndexSyncOutcome::Refused("index_response_tenant_mismatch".into()));
    }

    #[tokio::test]
    async fn receipt_missing_on_old_entry_is_a_hard_refusal() {
        let (reader, now) = tail_reader(600_000);
        let mut index = FakeIndex::new(Vec::new());
        index.missing_receipt = Some(5);
        assert_eq!(sync_index(&index, &reader, TENANT_UUID, now, None).await.unwrap(),
            IndexSyncOutcome::Refused("lake_part_index_receipt_missing".into()));
        assert!(index.shas.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn complete_view_publication_never_probes_or_absorbs_above_target() {
        let reader = ChainReader { chain: chain(10), checkpoint: None };
        let index = FakeIndex::new(Vec::new());
        let outcome = sync_index_through_view(&index, &reader, TENANT_UUID, Some(4), T0 + 86_400_000, None).await.unwrap();
        assert!(matches!(outcome, IndexSyncOutcome::Synced { caught_up: true, pushed: 5, .. }));
        assert_eq!(index.shas.lock().unwrap().as_slice(), &served_shas(&reader.chain)[..5]);
        // A target containing missing bytes is a refusal, never partial-view success.
        let missing = sync_index_through_view(&index, &reader, TENANT_UUID, Some(10), T0 + 86_400_000, None).await.unwrap_err();
        assert!(format!("{missing:#}").contains("complete_view_entry_missing"));
        assert_eq!(missing.downcast_ref::<IndexReadProgress>().unwrap().pushed, 5);
    }

    #[tokio::test]
    async fn a_late_read_error_publishes_only_the_verified_prefix_then_stops() {
        struct FailingReader(ChainReader);
        #[async_trait]
        impl PartLogReader for FailingReader {
            async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
                if seq == 4 {
                    anyhow::bail!("late arrival or unverifiable entry");
                }
                self.0.verified_entry(seq).await
            }
            async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>> {
                Ok(None)
            }
            async fn verified_provenance(&self, part: &PartRef) -> Result<ProvenanceRecord> {
                self.0.verified_provenance(part).await
            }
        }
        let reader = FailingReader(ChainReader {
            chain: chain(10),
            checkpoint: None,
        });
        let index = FakeIndex::new(Vec::new());
        let error = sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap_err();
        assert_eq!(error.downcast_ref::<IndexReadProgress>().unwrap().pushed, 4);
        assert!(format!("{error:#}").contains("late arrival or unverifiable entry"));
        assert_eq!(
            index.shas.lock().unwrap().len(),
            4,
            "valid prefix can advance control, never authorize a delete"
        );
        let resumed = sync_index(&index, &reader.0, TENANT_UUID, T0 + 86_400_000, None).await.unwrap();
        assert!(matches!(
            resumed,
            IndexSyncOutcome::Synced {
                caught_up: true,
                pushed: 6,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a_large_owner_index_backlog_resumes_instead_of_replaying() {
        let reader = ChainReader { chain: chain(5_000), checkpoint: None };
        let index = FakeIndex::new(Vec::new());
        for (expected, caught_up) in [(2_048, false), (2_048, false), (904, true)] {
            let outcome = sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap();
            assert!(matches!(outcome, IndexSyncOutcome::Synced {
                pushed, caught_up: actual, ..
            } if pushed == expected && actual == caught_up), "{outcome:?}");
        }
        assert_eq!(*index.shas.lock().unwrap(), served_shas(&reader.chain));
        let calls = index.calls.lock().unwrap();
        let sequences: Vec<_> = calls.iter().flat_map(|(seqs, _)| seqs.iter().copied()).collect();
        assert_eq!(sequences, (0..5_000).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn pushes_in_order_in_bounded_batches_then_the_checkpoint() {
        let chain = chain(600);
        let entry_sha = chain.entries[512].1.clone();
        let reader = ChainReader {
            checkpoint: Some(CheckpointClaim { seq: 512, checkpoint_sha256: "e".repeat(64), entry_sha256: entry_sha }),
            chain,
        };
        assert_eq!(reader.chain.entries.iter().map(|e| e.1.clone()).collect::<Vec<_>>(), served_shas(&reader.chain));
        let index = FakeIndex::new(Vec::new());
        let outcome = sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap();
        let IndexSyncOutcome::Synced { status, caught_up, pushed, .. } = outcome else { panic!("{outcome:?}") };
        assert!(caught_up);
        assert_eq!(pushed, 600);
        assert_eq!(status.indexed_through_seq, Some(599));
        assert_eq!(status.checkpoint_seq, Some(512));
        let calls = index.calls.lock().unwrap().clone();
        // status read, 0..=255, 256..=511, 512..=599 with the checkpoint.
        assert_eq!(calls.len(), 4);
        assert!(calls[0].0.is_empty() && calls[0].1.is_none());
        assert_eq!(calls[1].0, (0..256).collect::<Vec<_>>());
        assert_eq!(calls[1].1, None, "checkpoint 512 is not indexed yet");
        assert_eq!(calls[2].0, (256..512).collect::<Vec<_>>());
        assert_eq!(calls[3].0, (512..600).collect::<Vec<_>>());
        assert_eq!(calls[3].1, Some(512));

        // A second sync is a pure status read.
        let again = sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap();
        assert!(matches!(again, IndexSyncOutcome::Synced { caught_up: true, pushed: 0, .. }));
        assert_eq!(index.calls.lock().unwrap().len(), 5);
    }

    /// NAN-2879: a batch never exceeds MAX_INDEX_BATCH_PART_REFS part
    /// references (the control Envoy's 15 s route budget), except a single
    /// entry larger than the cap, which goes alone and is never split.
    #[tokio::test]
    async fn batches_are_capped_by_part_references() {
        use crate::lake_part_gc::planner::tests::part_ref;
        use crate::parts::levels::Level;
        let mut chain = Chain::new();
        // 20 adds of 300 parts each (6,000 refs), then one 5,000-part add.
        let mut n = 1_u64;
        for e in 0..20_i64 {
            let parts = (0..300).map(|_| { n += 1; part_ref(n, Level::L0) }).collect();
            chain.push(LogOp::Add { parts, consumed: Vec::new(), edge_log: None }, T0 + e);
        }
        let big = (0..5_000).map(|_| { n += 1; part_ref(n, Level::L0) }).collect();
        chain.push(LogOp::Add { parts: big, consumed: Vec::new(), edge_log: None }, T0 + 30);
        let reader = ChainReader { chain, checkpoint: None };
        let index = FakeIndex::new(Vec::new());
        let outcome = sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap();
        assert!(matches!(outcome, IndexSyncOutcome::Synced { caught_up: true, pushed: 22, .. }), "{outcome:?}");
        let calls = index.calls.lock().unwrap().clone();
        let refs = |seqs: &[u64]| seqs.iter().map(|s| part_refs(&reader.chain.entries[*s as usize].0.op)).sum::<usize>();
        for (seqs, _) in calls.iter().filter(|(seqs, _)| !seqs.is_empty()) {
            assert!(refs(seqs) <= MAX_INDEX_BATCH_PART_REFS || seqs.len() == 1, "{seqs:?} carries {} refs", refs(seqs));
        }
        assert!(calls.iter().any(|(seqs, _)| seqs == &vec![21]), "the oversized entry goes alone: {calls:?}");
        assert_eq!(calls.iter().map(|(seqs, _)| seqs.len()).sum::<usize>(), 22);
    }

    #[tokio::test]
    async fn gap_recovery_resumes_from_controls_position() {
        let reader = ChainReader { chain: chain(20), checkpoint: None };
        let shas = served_shas(&reader.chain);
        let index = FakeIndex::new(shas[..5].to_vec());
        // Another pusher indexes 5..=9 right before our first push lands.
        *index.concurrent.lock().unwrap() = Some((2, shas[5..10].to_vec()));
        let outcome = sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap();
        let IndexSyncOutcome::Synced { status, caught_up, gap_recoveries, .. } = outcome else { panic!("{outcome:?}") };
        assert!(caught_up);
        assert_eq!(gap_recoveries, 1);
        assert_eq!(status.indexed_through_seq, Some(19));
        let calls = index.calls.lock().unwrap().clone();
        assert_eq!(calls[1].0.first(), Some(&5));
        assert_eq!(calls[3].0, (10..20).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn chain_disagreement_and_old_owner_stop_the_sync() {
        let reader = ChainReader { chain: chain(5), checkpoint: None };
        let mut shas = served_shas(&reader.chain)[..3].to_vec();
        shas[2] = "f".repeat(64);
        let index = FakeIndex::new(shas);
        assert_eq!(
            sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap(),
            IndexSyncOutcome::Refused("local_chain_mismatch".into())
        );
        let mut old = FakeIndex::new(Vec::new());
        old.not_served = true;
        assert_eq!(sync_index(&old, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap(), IndexSyncOutcome::RouteNotServed);
    }

    #[tokio::test]
    async fn adopt_entries_carry_one_claim_per_part_in_the_same_request() {
        let mut chain = chain(3);
        chain.adopt(10, "warehouse/nano/events/data/a.parquet", T0 + 10);
        chain.add(20, T0 + 20);
        chain.adopt(11, "warehouse/nano/events/data/b.parquet", T0 + 30);
        let reader = ChainReader { chain, checkpoint: None };
        let index = FakeIndex::new(Vec::new());
        let outcome = sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap();
        assert!(matches!(outcome, IndexSyncOutcome::Synced { caught_up: true, pushed: 6, .. }), "{outcome:?}");
        let claims = index.claims.lock().unwrap().clone();
        assert!(claims[0].is_empty(), "status read carries no claims");
        let sent: Vec<_> = claims[1].iter().map(|c| (c.part_id.clone(), c.key.clone(), c.sha256.clone())).collect();
        assert_eq!(
            sent,
            vec![
                (id(10).to_string(), "warehouse/nano/events/data/a.parquet".to_string(), "e".repeat(64)),
                (id(11).to_string(), "warehouse/nano/events/data/b.parquet".to_string(), "e".repeat(64)),
            ]
        );

        // Control refuses an adopt entry without its claim.
        let refused = FakeIndex::new(Vec::new());
        let bare = IndexRequest {
            entries: reader.chain.entries[..4]
                .iter()
                .enumerate()
                .map(|(seq, (entry, _))| IndexEntry {
                    seq: seq as u64,
                    entry_base64: base64::engine::general_purpose::STANDARD.encode(entry.to_bytes().unwrap()),
                })
                .collect(),
            ..status_read(TENANT_UUID)
        };
        let error = refused.index(&bare).await.unwrap_err();
        assert_eq!(error.downcast_ref::<LakePartRefusal>().unwrap().code, "lake_part_index_entry_invalid");
    }

    #[tokio::test]
    async fn adopt_without_verified_provenance_stops_the_sync() {
        let mut chain = chain(2);
        chain.adopt(10, "warehouse/nano/events/data/a.parquet", T0 + 10);
        chain.records.clear();
        let reader = ChainReader { chain, checkpoint: None };
        let index = FakeIndex::new(Vec::new());
        assert!(sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None).await.is_err());
        assert_eq!(index.calls.lock().unwrap().len(), 1, "only the status read; no entry without its claim");
        // A record that is not adopted never yields a claim.
        let part = crate::lake_part_gc::planner::tests::part_ref(12, crate::parts::levels::Level::Hour);
        let mut record = crate::lake_part_gc::planner::tests::adopted_record(12, "warehouse/x.parquet", &"e".repeat(64));
        AdoptedClaim::from_record(&part, &record).unwrap();
        record.files.data[0].sha256 = "f".repeat(64);
        assert!(AdoptedClaim::from_record(&part, &record).is_err());
        let written = crate::parts::provenance::tests::sample_record();
        assert!(AdoptedClaim::from_record(&part, &written).is_err());
    }

    fn deleted_key(n: usize) -> DeletedKey {
        DeletedKey { key: format!("k{n}"), permit_id: format!("lpd_{n}"), receipt_sha256: "a".repeat(64) }
    }

    #[tokio::test]
    async fn deleted_keys_report_in_capped_batches_and_stay_queued_on_failure() {
        let index = FakeIndex::new(Vec::new());
        let mut queue: Vec<_> = (0..2_500).map(deleted_key).collect();
        *index.refuse_deleted.lock().unwrap() = true;
        assert_eq!(
            report_deleted(&index, TENANT_UUID, &mut queue).await,
            Err("lake_part_index_unavailable".to_string())
        );
        assert_eq!(queue.len(), 2_500, "a failed report keeps the queue");
        *index.refuse_deleted.lock().unwrap() = false;
        assert_eq!(report_deleted(&index, TENANT_UUID, &mut queue).await, Ok(2_500));
        assert!(queue.is_empty());
        let batches = index.deleted.lock().unwrap().clone();
        assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), vec![1_024, 1_024, 452]);
        assert_eq!(batches[0][0], deleted_key(0));
        assert_eq!(batches[2][451], deleted_key(2_499));
        let wire = serde_json::to_value(IndexRequest { deleted: vec![deleted_key(1)], ..status_read(TENANT_UUID) }).unwrap();
        assert_eq!(wire["deleted"], serde_json::json!([{"key": "k1", "permit_id": "lpd_1", "receipt_sha256": "a".repeat(64)}]));
        assert_eq!(wire["entries"], serde_json::json!([]));
    }

    /// A reader whose reads take time (async), counting reads in flight.
    struct SlowChainReader {
        inner: ChainReader,
        in_flight: std::sync::atomic::AtomicUsize,
        max_in_flight: std::sync::atomic::AtomicUsize,
        reads: std::sync::atomic::AtomicU64,
    }

    impl SlowChainReader {
        fn new(chain: Chain) -> Self {
            Self {
                inner: ChainReader { chain, checkpoint: None },
                in_flight: Default::default(),
                max_in_flight: Default::default(),
                reads: Default::default(),
            }
        }
    }

    #[async_trait]
    impl PartLogReader for SlowChainReader {
        async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
            use std::sync::atomic::Ordering::SeqCst;
            self.reads.fetch_add(1, SeqCst);
            let now = self.in_flight.fetch_add(1, SeqCst) + 1;
            self.max_in_flight.fetch_max(now, SeqCst);
            tokio::time::sleep(Duration::from_millis(100)).await;
            self.in_flight.fetch_sub(1, SeqCst);
            self.inner.verified_entry(seq).await
        }
        async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>> {
            Ok(None)
        }
        async fn verified_provenance(&self, part: &PartRef) -> Result<ProvenanceRecord> {
            self.inner.verified_provenance(part).await
        }
    }

    /// NAN-3459: a backlog of N x 256 entries drains in ONE cell sync, in
    /// order, with bounded read-ahead and no read past the view head.
    #[tokio::test(start_paused = true)]
    async fn a_backlog_of_many_batches_drains_in_one_view_sync_with_bounded_read_ahead() {
        const BATCHES: u64 = 12;
        let entries = BATCHES * MAX_INDEX_ENTRIES as u64;
        let reader = SlowChainReader::new(chain(entries + 40));
        let index = FakeIndex::new(Vec::new());
        let started = tokio::time::Instant::now();
        let target = entries - 1;
        let outcome = sync_index_through_view(&index, &reader, TENANT_UUID, Some(target), T0 + 86_400_000, None).await.unwrap();
        let IndexSyncOutcome::Synced { status, caught_up, pushed, head_appended_ms, .. } = outcome else { panic!("{outcome:?}") };
        assert!(caught_up, "one sync reaches the view head");
        assert_eq!(pushed, entries);
        assert_eq!(status.indexed_through_seq, Some(target));
        assert_eq!(head_appended_ms, Some(reader.inner.chain.entries[target as usize].0.appended_at_ms));
        // More than the old 8-request (2,048-entry) bound, in one sync.
        assert!(entries > (MAX_INDEX_REQUESTS_PER_SYNC * MAX_INDEX_ENTRIES) as u64);
        assert_eq!(*index.shas.lock().unwrap(), served_shas(&reader.inner.chain)[..entries as usize]);
        let calls = index.calls.lock().unwrap().clone();
        assert_eq!(calls.len() as u64, 1 + BATCHES, "status read + one request per full batch");
        let sequences: Vec<_> = calls.iter().flat_map(|(seqs, _)| seqs.iter().copied()).collect();
        assert_eq!(sequences, (0..entries).collect::<Vec<_>>(), "strict order");
        use std::sync::atomic::Ordering::SeqCst;
        assert_eq!(reader.max_in_flight.load(SeqCst), INDEX_READ_AHEAD, "bounded concurrency");
        assert_eq!(reader.reads.load(SeqCst), entries, "each entry read once; nothing past the view head");
        // 100 ms per read: serial would take entries/10 s; read-ahead ~1/8 of it.
        let serial = Duration::from_millis(100) * entries as u32;
        assert!(started.elapsed() * 6 < serial, "{:?} vs serial {serial:?}", started.elapsed());
    }

    /// A batch cut by the part-reference cap hands its read-ahead entry to
    /// the next batch instead of re-reading it.
    #[tokio::test]
    async fn a_byte_or_ref_cut_batch_reuses_the_read_ahead_entry() {
        use crate::lake_part_gc::planner::tests::part_ref;
        use crate::parts::levels::Level;
        let mut chain = Chain::new();
        let mut n = 1_u64;
        for e in 0..6_i64 {
            let parts = (0..1_500).map(|_| { n += 1; part_ref(n, Level::L0) }).collect();
            chain.push(LogOp::Add { parts, consumed: Vec::new(), edge_log: None }, T0 + e);
        }
        let reader = SlowChainReader::new(chain);
        let index = FakeIndex::new(Vec::new());
        let head = reader.inner.chain.entries.len() as u64 - 1;
        let outcome = sync_index_through_view(&index, &reader, TENANT_UUID, Some(head), T0 + 86_400_000, None).await.unwrap();
        assert!(matches!(outcome, IndexSyncOutcome::Synced { caught_up: true, .. }), "{outcome:?}");
        assert!(index.calls.lock().unwrap().len() > 2, "the ref cap split the backlog");
        assert_eq!(reader.reads.load(std::sync::atomic::Ordering::SeqCst), head + 1);
    }

    #[test]
    fn index_backoff_delay_honours_retry_after_and_caps() {
        assert_eq!(index_backoff_delay(1, None), INDEX_BACKOFF_BASE);
        assert_eq!(index_backoff_delay(3, None), INDEX_BACKOFF_BASE * 4);
        assert_eq!(index_backoff_delay(30, None), INDEX_BACKOFF_MAX);
        assert_eq!(index_backoff_delay(1, Some(Duration::from_secs(7))), Duration::from_secs(7));
        assert_eq!(index_backoff_delay(1, Some(Duration::from_secs(3_600))), INDEX_RETRY_AFTER_MAX);
    }

    /// NAN-3459: 429 / 5xx answers are retried in-pass (Retry-After honoured)
    /// and the sync still completes; only a persistent back-off ends it.
    #[tokio::test(start_paused = true)]
    async fn index_back_off_retries_in_pass_then_gives_up_with_the_code() {
        let reader = ChainReader { chain: chain(600), checkpoint: None };
        let index = FakeIndex::new(Vec::new());
        index.backoff.lock().unwrap().extend([
            LakePartRefusal::new(Some(429), "lake_part_tenant_rate_limit").with_retry_after(Some(Duration::from_secs(5))),
            LakePartRefusal::new(Some(503), "lake_part_index_unavailable"),
        ]);
        let started = tokio::time::Instant::now();
        let outcome = sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap();
        assert!(matches!(outcome, IndexSyncOutcome::Synced { caught_up: true, pushed: 600, .. }), "{outcome:?}");
        // Retry-After 5 s, then the exponential second attempt (2 s).
        assert_eq!(started.elapsed().as_secs(), 7);
        assert_eq!(*index.shas.lock().unwrap(), served_shas(&reader.chain));

        // Persistent: every attempt answers 503 -> BackOff, nothing pushed.
        let stuck = FakeIndex::new(Vec::new());
        stuck.backoff.lock().unwrap().extend(
            (0..=INDEX_BACKOFF_RETRIES).map(|_| LakePartRefusal::new(Some(503), "lake_part_index_unavailable")),
        );
        let started = tokio::time::Instant::now();
        assert_eq!(
            sync_index(&stuck, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap(),
            IndexSyncOutcome::BackOff("lake_part_index_unavailable".into())
        );
        assert_eq!(started.elapsed().as_secs(), 1 + 2 + 4 + 8, "bounded exponential retries");
        assert!(stuck.shas.lock().unwrap().is_empty());
        // A refusal is never retried.
        let refused = FakeIndex::new(Vec::new());
        refused.backoff.lock().unwrap().push_back(LakePartRefusal::new(Some(409), "lake_part_index_entry_invalid"));
        assert_eq!(
            sync_index(&refused, &reader, TENANT_UUID, T0 + 86_400_000, None).await.unwrap(),
            IndexSyncOutcome::Refused("lake_part_index_entry_invalid".into())
        );
    }

    /// Control's index name for every part-log op. The match is exhaustive,
    /// so a new `LogOp` variant fails to compile here until control's index
    /// admits it (NAN-3445: `reject` shipped without it and stopped GC).
    fn control_kind(op: &LogOp) -> &'static str {
        match op {
            LogOp::Genesis { .. } => "genesis",
            LogOp::Schema { .. } => "schema",
            LogOp::Add { .. } => "add",
            LogOp::EdgeFloor { .. } => "edge_floor",
            LogOp::Reject { .. } => "reject",
            LogOp::EdgeEnd { .. } => "edge_end",
            LogOp::Merge { .. } => "merge",
            LogOp::Retire { .. } => "retire",
            LogOp::Rewrite { .. } => "rewrite",
            LogOp::Adopt { .. } => "adopt",
        }
    }

    /// The op-kind list in the newest enterprise migration that (re)defines
    /// `lake_part_log_index_append`'s closed kind check.
    /// `None` in a tree without the enterprise overlay (open-core snapshot).
    fn control_index_kinds() -> Option<(String, std::collections::BTreeSet<String>)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../migrations/postgres-enterprise");
        if !dir.is_dir() {
            return None;
        }
        let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "sql")).collect();
        files.sort();
        const MARK: &str = "OR kind IS NULL OR kind NOT IN (";
        let (file, list) = files.iter().rev().find_map(|path| {
            let text = std::fs::read_to_string(path).unwrap();
            let at = text.rfind(MARK)? + MARK.len();
            let end = at + text[at..].find(')')?;
            Some((path.file_name().unwrap().to_string_lossy().into_owned(), text[at..end].to_string()))
        }).expect("a migration defines the index kind check");
        Some((file, list.split(',').map(|k| k.trim().trim_matches('\'').to_string()).collect()))
    }

    #[test]
    fn control_index_admits_every_part_log_op_kind() {
        let reject = LogOp::Reject { rejections: vec![crate::parts::part_log::Rejection {
            source: crate::parts::part_log::SourceRef { key: "k".into(), version: "v".into(), sha256: "a".repeat(64) },
            scope: "rows".into(), rows_rejected: 1, reason: "admission_invalid".into(), detail: String::new(),
        }] };
        assert_eq!(serde_json::to_value(&reject).unwrap()["kind"], control_kind(&reject));
        let ours: std::collections::BTreeSet<String> = ["genesis", "schema", "add", "edge_floor", "reject", "edge_end", "merge",
            "retire", "rewrite", "adopt"].into_iter().map(String::from).collect();
        let Some((file, control)) = control_index_kinds() else {
            eprintln!("no enterprise migrations in this tree; control index kinds not checked");
            return;
        };
        assert_eq!(control, ours, "{file}: control's part-log index kinds must equal LogOp's (control_kind)");
    }
}
