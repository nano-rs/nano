// SPDX-License-Identifier: AGPL-3.0-or-later

//! `EdgeLogSource`: ingest[T]'s source of edge batches when the tenant Worker
//! runs `NANO_EDGE_LOG_MODE=do` (or `drain`) (NAN-2874).
//!
//! It stands where the notice spool and the bronze object store stand today:
//! `pending` lists pulled, unacknowledged segments (oldest first), `get`
//! returns a segment's verified bytes by key, and `ack` is called after the
//! log entry that consumed them committed. The extra calls map one-to-one to
//! part-log ops (contract r3 + r3.1):
//! - [`EdgeLogSource::range_for_flush`] → the `add` entry's `edge_log` (and
//!   every L0 record's identical copy); its `ack` commits the DO;
//! - [`EdgeLogSource::floor_due`] → `LogOp::EdgeFloor`, then
//!   [`EdgeLogSource::floor_appended`] commits the DO;
//! - [`EdgeLogSource::end_due`] → `LogOp::EdgeEnd`, then ingest[T] stops using
//!   the edge log (the Worker is draining and nothing is left).
//!
//! Exactly once: the part log is the linearization point. The DO is committed
//! only after the op that records the range landed; `check_edge_commit_monotonic`
//! runs before every DO commit. On restart the consumer resumes from the part
//! log's `edge_point()` (or `edge_ended()`), checks its chain against the DO,
//! fails closed on a mismatch, and re-commits a point the DO has not seen.
//! Segments acknowledged without rows (rejected, or all duplicates) become
//! `skipped` entries of the next range, or, past a byte/age threshold with no
//! range to carry them, an `EdgeFloor`; if the process dies first they are
//! redelivered, never lost.
//!
//! Flushes are serial: one `range_for_flush` per flush, with the flush-wide
//! sources, then that flush's `ack`, before the next range.

use anyhow::{bail, ensure, Context, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use tokio::sync::Mutex;

use super::client::EdgeLogTransport;
use super::protocol::{CommitOutcome, CommitRequest, PullOutcome, Segment, MAX_PULL_BYTES, MAX_PULL_SEGMENTS, MAX_SEQ};
use crate::parts::part_log::{check_edge_commit_monotonic, EdgePoint, LogOp};
use crate::parts::provenance::SourceObject;
use crate::parts::{
    edge_log_genesis, edge_log_seq_of_version, EdgeLogRange, EdgeSkipReason, EdgeSkippedSegment, EDGE_LOG_CONTRACT,
};

/// Raised when a newer consumer holds the lease. ingest[T] must exit; the
/// supervisor restarts it and the new instance reconciles.
#[derive(Debug, thiserror::Error)]
#[error("edge log consumer was fenced by a newer lease")]
pub struct EdgeLogFenced;

#[derive(Debug, Clone)]
pub struct EdgeLogSourceConfig {
    /// Stop pulling while this many bytes are pulled and unacknowledged. Soft
    /// by at most one segment: a pull under the bound returns at least one.
    pub max_buffered_bytes: u64,
    pub pull_max_bytes: u64,
    pub pull_max_segments: u32,
    /// A skip-only tail (segments acknowledged without rows, with no range to
    /// carry them) becomes an `EdgeFloor` past either threshold, so it never
    /// pins the DO's resident bytes.
    pub skip_floor_bytes: u64,
    pub skip_floor_age_ms: i64,
    /// Ranges issued and not yet acknowledged at once (NAN-3619). 1 is the
    /// serial contract; 2 lets ingest seal the next flush while the previous
    /// one still publishes. Ranges stay contiguous and are acknowledged
    /// (committed to the DO) strictly in issue order.
    pub max_issued_ranges: usize,
}

impl Default for EdgeLogSourceConfig {
    fn default() -> Self {
        Self {
            max_buffered_bytes: 64 * 1024 * 1024,
            pull_max_bytes: MAX_PULL_BYTES,
            pull_max_segments: MAX_PULL_SEGMENTS,
            skip_floor_bytes: 16 * 1024 * 1024,
            skip_floor_age_ms: 60_000,
            max_issued_ranges: 1,
        }
    }
}

/// What ingest[T] sees for one pulled segment (the `SourceNotice` fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeNotice {
    /// Stable, sortable handle: the zero-padded sequence.
    pub handle: String,
    pub seq: u64,
    pub key: String,
    /// `edge-log-v1:<seq>`: the `SourceObject.version` to record.
    pub version: String,
    pub bytes: u64,
    pub sha256: String,
    pub received_at_ms: i64,
}

/// A segment acknowledged without an `add` ([`EdgeLogSource::ack_skipped`]):
/// rejected by admission, every row a duplicate, or missing. All of its rows
/// are accounted as rejected or duplicate; it becomes a `skipped` entry of the
/// next range (or part of an `EdgeFloor`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeAck {
    pub handle: String,
    pub rows: u64,
    pub rows_rejected: u64,
    pub rows_duplicate: u64,
}

/// A part-log op the consumer asks ingest[T] to append before the DO moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgePointRequest {
    pub through_seq: u64,
    pub through_chain: String,
    pub reason: String,
}

impl EdgePointRequest {
    /// `LogOp::EdgeFloor` (contract r3 5.1).
    pub fn floor_op(&self) -> LogOp {
        LogOp::EdgeFloor { through_seq: self.through_seq, through_chain: self.through_chain.clone(), reason: self.reason.clone() }
    }

    /// `LogOp::EdgeEnd` (contract r3.1).
    pub fn end_op(&self) -> LogOp {
        LogOp::EdgeEnd { through_seq: self.through_seq, through_chain: self.through_chain.clone(), reason: self.reason.clone() }
    }
}

pub fn handle_of(seq: u64) -> String {
    format!("{seq:020}")
}

fn seq_of_handle(handle: &str) -> Result<u64> {
    ensure!(handle.len() == 20 && handle.bytes().all(|b| b.is_ascii_digit()), "edge notice handle is malformed");
    let seq: u64 = handle.parse()?;
    ensure!(seq <= MAX_SEQ, "edge notice handle is out of bounds");
    Ok(seq)
}

#[derive(Debug, Clone)]
struct Issued {
    through: u64,
    chain: String,
}

/// A segment acknowledged without rows: what the chain and accounting need.
#[derive(Debug, Clone)]
struct Skip {
    key: String,
    sha256: String,
    length: u64,
    chain: String,
    received_at_ms: i64,
    rows: u64,
    rows_rejected: u64,
    rows_duplicate: u64,
}

#[derive(Debug)]
struct State {
    epoch: u64,
    /// End of the last range, floor or reconcile the DO committed.
    through: u64,
    chain: String,
    /// Pulled and not yet acknowledged, by seq (bytes held).
    pulled: BTreeMap<u64, Segment>,
    by_key: HashMap<String, u64>,
    buffered_bytes: u64,
    /// Acknowledged without rows and not yet carried by a range or floor
    /// (bytes released at acknowledgement).
    skipped: BTreeMap<u64, Skip>,
    /// Issued and not yet acknowledged, oldest first (at most
    /// `max_issued_ranges`; each starts right after the previous one).
    issued: VecDeque<Issued>,
    last_pulled: u64,
    /// Set at open when the DO committed past the part log: the consumer
    /// must record it (EdgeFloor) before anything else.
    pending_floor: Option<EdgePointRequest>,
    /// Last seen from the Worker: mode, head and overflow objects.
    mode: String,
    head: u64,
    overflow_objects: u64,
    ended: bool,
    stats: PullStats,
}

/// Pull outcomes since open (NAN-2964): an empty edge log, a DO pull slot
/// stuck busy and a DO head the pulls never reach all look identical from
/// outside (no R2 op, no error), so `pending` counts them and logs a
/// periodic [`EdgeLogStatus`].
#[derive(Debug, Default, Clone)]
struct PullStats {
    with_segments: u64,
    empty: u64,
    busy: u64,
    /// Consecutive busy pulls (reset by any batch).
    busy_streak: u64,
    /// Consecutive empty batches whose `head` is past what this consumer
    /// pulled: the DO says there is data but serves none.
    empty_behind_head_streak: u64,
    segments: u64,
    last_status: Option<std::time::Instant>,
}

/// A snapshot of the consumer for logs and health (NAN-2964).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EdgeLogStatus {
    pub epoch: u64,
    pub mode: String,
    pub head: u64,
    pub committed_through: u64,
    pub last_pulled: u64,
    pub pulled_pending: usize,
    pub buffered_bytes: u64,
    pub overflow_objects: u64,
    pub pulls_with_segments: u64,
    pub pulls_empty: u64,
    pub pulls_busy: u64,
    pub busy_streak: u64,
    pub empty_behind_head_streak: u64,
    pub segments_pulled: u64,
}

impl EdgeLogStatus {
    /// Why this consumer is not making progress, if it can tell: the DO pull
    /// slot answers busy on every pull, or the DO head is past the consumer
    /// but pulls return nothing. `None` when idle-and-empty or progressing.
    pub fn stall(&self) -> Option<&'static str> {
        if self.busy_streak >= STALL_STREAK {
            Some("edge log pulls keep answering busy (503): the DO pull slot may be stuck")
        } else if self.empty_behind_head_streak >= STALL_STREAK {
            Some("edge log head is past this consumer but pulls return no segments")
        } else {
            None
        }
    }
}

/// Consecutive pulls (about one per second) before a stall is reported.
pub const STALL_STREAK: u64 = 30;
/// Interval of the periodic `edge_log_status` line.
pub const STATUS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

pub struct EdgeLogSource<T: EdgeLogTransport> {
    transport: T,
    tenant_id: String,
    config: EdgeLogSourceConfig,
    state: Mutex<State>,
}

impl<T: EdgeLogTransport> EdgeLogSource<T> {
    /// Lease the tenant's edge log and reconcile it with the part log.
    ///
    /// `point` is `LiveSet::edge_point().or(LiveSet::edge_ended())`; `None`
    /// starts at genesis (the first pull asks for seq 1).
    /// - part log ahead of the DO: find the DO chain at the point, fail closed
    ///   on a mismatch, then commit the point;
    /// - equal: the chains must match (fail closed);
    /// - part log behind the DO: fail closed, unless the DO attests a purge
    ///   that moved it exactly to its committed point (and the chain at the
    ///   point still agrees where the DO knows it); then that point becomes a
    ///   pending `EdgeFloor` ([`Self::floor_due`]) recorded before pulling.
    pub async fn open(
        transport: T,
        tenant_id: &str,
        consumer_id: &str,
        point: Option<&EdgePoint>,
        config: EdgeLogSourceConfig,
    ) -> Result<Self> {
        let log = format!("edgelog:{tenant_id}");
        let genesis = edge_log_genesis(tenant_id);
        let (resume, resume_chain) = match point {
            Some(point) => {
                ensure!(point.log == log, "edge point names another edge log");
                ensure!(point.through_seq <= MAX_SEQ, "edge point is out of bounds");
                (point.through_seq, point.through_chain.clone())
            }
            None => (0, genesis),
        };
        let lease = transport.lease(consumer_id, Some(resume)).await?;
        ensure!(lease.committed_through <= MAX_SEQ && lease.head <= MAX_SEQ, "edge lease is out of bounds");
        let mut through = resume;
        let mut chain = resume_chain.clone();
        let mut pending_floor = None;
        if resume > lease.committed_through {
            // The op that recorded `resume` landed but its DO commit did not:
            // find the DO's chain at `resume`, check it, then commit.
            let mut after = lease.committed_through;
            let mut found = None;
            let mut busy = 0_u32;
            while found.is_none() {
                let batch = match transport.pull(lease.epoch, after, config.pull_max_bytes, config.pull_max_segments).await? {
                    PullOutcome::Batch(batch) => batch,
                    PullOutcome::Fenced => return Err(EdgeLogFenced.into()),
                    PullOutcome::Busy => {
                        busy += 1;
                        ensure!(busy <= 50, "edge log stayed busy while reconciling");
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        continue;
                    }
                    PullOutcome::Behind { committed_through, .. } => {
                        bail!("edge log moved to {committed_through} while reconciling")
                    }
                };
                ensure!(!batch.segments.is_empty(), "edge log ends at {} before the part log point {resume}", batch.head);
                for segment in batch.segments {
                    after = segment.seq;
                    if segment.seq == resume {
                        found = Some(segment.chain);
                        break;
                    }
                }
            }
            let observed = found.expect("loop exits with a chain");
            ensure!(observed == resume_chain, "edge log chain at {resume} differs from the part log: refusing to resume");
            check_edge_commit_monotonic(lease.committed_through, resume)?;
            match transport.commit(&CommitRequest::for_range(lease.epoch, resume, &resume_chain)).await? {
                CommitOutcome::Committed | CommitOutcome::Replayed => {}
                CommitOutcome::Fenced => return Err(EdgeLogFenced.into()),
                CommitOutcome::Conflict { committed_through } => {
                    bail!("edge log refused the reconcile commit at {resume} (committed {committed_through})")
                }
            }
        } else if resume == lease.committed_through {
            ensure!(
                lease.committed_chain == resume_chain,
                "edge log chain at {resume} differs from the part log: refusing to resume"
            );
        } else {
            // The DO is ahead of the part log. That is legitimate only after an
            // attested purge (offboarding) that moved it exactly here; anything
            // else is a lost or rolled-back part log, or committed segments that
            // never became parts. Fail closed: never skip data silently.
            let attested = lease.purge_seq == Some(lease.committed_through)
                && lease.purge_chain.as_deref() == Some(lease.committed_chain.as_str());
            ensure!(
                attested,
                "edge log committed {} but the part log resumes at {resume} and the DO attests no purge: refusing (lost part log?)",
                lease.committed_through
            );
            if let Some(at_chain) = &lease.at_chain {
                ensure!(*at_chain == resume_chain, "edge log chain at {resume} differs from the part log: refusing to resume");
            }
            pending_floor = Some(EdgePointRequest {
                through_seq: lease.committed_through,
                through_chain: lease.committed_chain.clone(),
                reason: "edge log purged".to_string(),
            });
            through = lease.committed_through;
            chain = lease.committed_chain.clone();
        }
        let source = Self {
            transport,
            tenant_id: tenant_id.to_string(),
            config,
            state: Mutex::new(State {
                epoch: lease.epoch,
                through,
                chain,
                pulled: BTreeMap::new(),
                by_key: HashMap::new(),
                buffered_bytes: 0,
                skipped: BTreeMap::new(),
                issued: VecDeque::new(),
                last_pulled: through,
                pending_floor,
                mode: lease.mode,
                head: lease.head,
                overflow_objects: lease.overflow_objects,
                ended: false,
                stats: PullStats::default(),
            }),
        };
        let status = source.status_locked(&*source.state.lock().await);
        tracing::info!(tenant = %tenant_id, consumer = %consumer_id, resume, ?status, "edge log leased");
        Ok(source)
    }

    /// The transport, e.g. to rotate an `HttpEdgeLogClient`'s token
    /// (`source.transport().set_token(..)`).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub async fn epoch(&self) -> u64 {
        self.state.lock().await.epoch
    }

    /// Up to `max` pulled, unacknowledged segments, oldest first. Pulls more
    /// from the Worker while under the buffered-bytes bound. Nothing is pulled
    /// while an `EdgeFloor` from reconcile is pending.
    pub async fn pending(&self, max: usize) -> Result<Vec<EdgeNotice>> {
        let mut state = self.state.lock().await;
        ensure!(!state.ended, "edge log mode ended");
        if state.pending_floor.is_none() && state.pulled.len() < max && state.buffered_bytes < self.config.max_buffered_bytes {
            let want = u32::try_from(max - state.pulled.len()).unwrap_or(u32::MAX).min(self.config.pull_max_segments);
            let budget = (self.config.max_buffered_bytes - state.buffered_bytes).min(self.config.pull_max_bytes);
            match self.transport.pull(state.epoch, state.last_pulled, budget, want).await? {
                PullOutcome::Batch(batch) => {
                    state.mode = batch.mode;
                    state.head = batch.head;
                    state.overflow_objects = batch.overflow_objects;
                    state.stats.busy_streak = 0;
                    if batch.segments.is_empty() {
                        state.stats.empty += 1;
                        if state.head > state.last_pulled {
                            state.stats.empty_behind_head_streak += 1;
                        } else {
                            state.stats.empty_behind_head_streak = 0;
                        }
                    } else {
                        state.stats.with_segments += 1;
                        state.stats.empty_behind_head_streak = 0;
                        state.stats.segments += batch.segments.len() as u64;
                        if state.stats.with_segments == 1 {
                            tracing::info!(first_seq = batch.segments[0].seq, count = batch.segments.len(), head = state.head,
                                "edge log: first segments pulled");
                        }
                    }
                    for segment in batch.segments {
                        let next = state.last_pulled.checked_add(1).context("edge sequence overflow")?;
                        ensure!(segment.seq == next, "edge pull skipped a sequence");
                        ensure!(!state.by_key.contains_key(&segment.key), "edge log returned a key twice");
                        state.last_pulled = segment.seq;
                        state.buffered_bytes = state.buffered_bytes.checked_add(segment.length).context("byte overflow")?;
                        state.by_key.insert(segment.key.clone(), segment.seq);
                        state.pulled.insert(segment.seq, segment);
                    }
                }
                PullOutcome::Busy => {
                    state.stats.busy += 1;
                    state.stats.busy_streak += 1;
                }
                PullOutcome::Fenced => return Err(EdgeLogFenced.into()),
                PullOutcome::Behind { committed_through, .. } => {
                    bail!("edge log committed {committed_through} past this consumer: another consumer is active")
                }
            }
        }
        self.log_status_locked(&mut state);
        Ok(state
            .pulled
            .values()
            .take(max)
            .map(|segment| EdgeNotice {
                handle: handle_of(segment.seq),
                seq: segment.seq,
                key: segment.key.clone(),
                version: segment.version(),
                bytes: segment.length,
                sha256: segment.sha256.clone(),
                received_at_ms: segment.received_at_ms,
            })
            .collect())
    }

    /// The verified bytes of a pulled segment (the bronze object body).
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        let state = self.state.lock().await;
        let seq = state.by_key.get(key)?;
        state.pulled.get(seq).map(|segment| segment.bytes.clone())
    }

    /// Called once per flush, with the flush-wide sources, while building the
    /// `add` entry. Returns its `edge_log` (every L0 record of the entry
    /// carries the same copy), or None when no source came from the edge log.
    /// `rows_rejected` / `rows_duplicate` are the flush's own counts for its
    /// source segments; skipped segments add theirs. Arms the commit that the
    /// flush's `ack` performs. Flushes are serial.
    pub async fn range_for_flush(
        &self,
        sources: &[SourceObject],
        rows_rejected: u64,
        rows_duplicate: u64,
    ) -> Result<Option<EdgeLogRange>> {
        let mut state = self.state.lock().await;
        ensure!(
            state.issued.len() < self.config.max_issued_ranges.max(1),
            "an edge range is already issued: flush and ack are serial (at most {} outstanding)",
            self.config.max_issued_ranges.max(1)
        );
        ensure!(state.pending_floor.is_none(), "record the pending edge floor before the next range");
        // The next range starts after the last issued one (still unacked)
        // or, with none outstanding, after the committed point.
        let (after, after_chain) = match state.issued.back() {
            Some(last) => (last.through, last.chain.clone()),
            None => (state.through, state.chain.clone()),
        };
        let seqs = sources.iter().filter_map(|s| edge_log_seq_of_version(&s.version)).collect::<BTreeSet<_>>();
        if seqs.is_empty() {
            return Ok(None);
        }
        ensure!(seqs.len() == sources.len(), "a flush mixes edge-log and other sources");
        let first = after.checked_add(1).context("edge sequence overflow")?;
        let through = *seqs.iter().next_back().expect("non-empty");
        ensure!(*seqs.iter().next().expect("non-empty") >= first, "a flush source is already committed");
        let mut skipped = Vec::new();
        let (mut rows_in, mut rejected, mut duplicate) = (0_u64, rows_rejected, rows_duplicate);
        for source in sources {
            rows_in = rows_in.checked_add(source.rows).context("row overflow")?;
        }
        for seq in first..=through {
            if seqs.contains(&seq) {
                let segment = state.pulled.get(&seq).with_context(|| format!("edge segment {seq} was not pulled"))?;
                let source = sources.iter().find(|s| edge_log_seq_of_version(&s.version) == Some(seq)).expect("present");
                ensure!(
                    source.key == segment.key && source.sha256 == segment.sha256 && source.bytes == segment.length,
                    "flush source {seq} differs from the pulled segment"
                );
            } else if let Some(skip) = state.skipped.get(&seq) {
                rows_in = rows_in.checked_add(skip.rows).context("row overflow")?;
                rejected = rejected.checked_add(skip.rows_rejected).context("row overflow")?;
                duplicate = duplicate.checked_add(skip.rows_duplicate).context("row overflow")?;
                skipped.push(EdgeSkippedSegment {
                    seq,
                    key: skip.key.clone(),
                    sha256: skip.sha256.clone(),
                    length: skip.length,
                    reason: EdgeSkipReason::ConsumedWithoutRows,
                    rows: skip.rows,
                    rows_rejected: skip.rows_rejected,
                    rows_duplicate: skip.rows_duplicate,
                });
            } else {
                bail!("edge segment {seq} is neither in this flush nor acknowledged");
            }
        }
        let through_chain = state.pulled[&through].chain.clone();
        let range = EdgeLogRange {
            log: format!("edgelog:{}", self.tenant_id),
            contract: EDGE_LOG_CONTRACT.to_string(),
            first_seq: first,
            through_seq: through,
            prev_chain: after_chain,
            through_chain: through_chain.clone(),
            skipped,
            rows_in,
            rows_rejected: rejected,
            rows_duplicate: duplicate,
        };
        range.validate(&self.tenant_id, sources)?;
        state.issued.push_back(Issued { through, chain: through_chain });
        Ok(Some(range))
    }

    /// The flush's `add` entry landed: commit its issued range to the edge
    /// log. Only for the oldest outstanding range (the handles include its
    /// through-seq); anything else is an error, never a silent skip.
    pub async fn ack(&self, handles: &[String]) -> Result<()> {
        let seqs = handles.iter().map(|handle| seq_of_handle(handle)).collect::<Result<Vec<_>>>()?;
        let mut state = self.state.lock().await;
        let issued = state.issued.front().cloned().context("ack without an issued range: use ack_skipped for segments without rows")?;
        ensure!(seqs.contains(&issued.through), "ack does not name the issued range's last segment");
        ensure!(seqs.iter().all(|seq| *seq <= issued.through), "flush acknowledgement exceeds its range");
        self.commit_locked(&mut state, issued.through, &issued.chain).await?;
        state.issued.pop_front();
        Ok(())
    }

    /// Segments acknowledged without an `add`: rejected by admission, every
    /// row a duplicate, or missing. Records each segment's row counts,
    /// releases its bytes, and makes it a skip of the next range or floor.
    pub async fn ack_skipped(&self, acks: &[EdgeAck]) -> Result<()> {
        let seqs = acks.iter().map(|ack| seq_of_handle(&ack.handle)).collect::<Result<Vec<_>>>()?;
        let mut state = self.state.lock().await;
        for (ack, seq) in acks.iter().zip(seqs) {
            if seq <= state.through {
                continue; // already committed: a repeated ack
            }
            ensure!(
                ack.rows_rejected.checked_add(ack.rows_duplicate) == Some(ack.rows),
                "a segment acknowledged without rows must account every row as rejected or duplicate"
            );
            let Some(segment) = state.pulled.remove(&seq) else {
                ensure!(state.skipped.contains_key(&seq), "acknowledged edge segment {seq} was never pulled");
                continue;
            };
            state.by_key.remove(&segment.key);
            state.buffered_bytes = state.buffered_bytes.saturating_sub(segment.length);
            state.skipped.insert(seq, Skip {
                key: segment.key,
                sha256: segment.sha256,
                length: segment.length,
                chain: segment.chain,
                received_at_ms: segment.received_at_ms,
                rows: ack.rows,
                rows_rejected: ack.rows_rejected,
                rows_duplicate: ack.rows_duplicate,
            });
        }
        Ok(())
    }

    /// An `EdgeFloor` ingest[T] must append now: the reconcile floor from
    /// `open`, or a skip-only tail (contiguous from the committed point) past
    /// its byte or age threshold. After the append, call
    /// [`Self::floor_appended`].
    pub async fn floor_due(&self, now_ms: i64) -> Option<EdgePointRequest> {
        let state = self.state.lock().await;
        if let Some(floor) = &state.pending_floor {
            return Some(floor.clone());
        }
        if !state.issued.is_empty() {
            return None;
        }
        let mut seq = state.through;
        let (mut bytes, mut oldest, mut last) = (0_u64, i64::MAX, None);
        while let Some(skip) = state.skipped.get(&(seq + 1)) {
            seq += 1;
            bytes = bytes.saturating_add(skip.length);
            oldest = oldest.min(skip.received_at_ms);
            last = Some(skip);
        }
        let last = last?;
        let due = bytes >= self.config.skip_floor_bytes || now_ms.saturating_sub(oldest) >= self.config.skip_floor_age_ms;
        due.then(|| EdgePointRequest {
            through_seq: seq,
            through_chain: last.chain.clone(),
            reason: "edge segments consumed without rows".to_string(),
        })
    }

    /// The `EdgeFloor` from [`Self::floor_due`] landed in the part log: move
    /// the DO's committed point to it (unless the DO is already there).
    pub async fn floor_appended(&self, floor: &EdgePointRequest) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.pending_floor.as_ref() == Some(floor) {
            // The DO already committed this point; only the part log caught up.
            state.pending_floor = None;
            return Ok(());
        }
        ensure!(state.issued.is_empty(), "an edge range is issued: finish the flush first");
        ensure!(
            state.skipped.get(&floor.through_seq).is_some_and(|skip| skip.chain == floor.through_chain),
            "edge floor does not end on a skipped segment"
        );
        self.commit_locked(&mut state, floor.through_seq, &floor.through_chain).await
    }

    /// `Some` when the Worker is draining and the edge log is empty past the
    /// committed point: ingest[T] appends `LogOp::EdgeEnd` and stops using the
    /// edge log (then calls [`Self::end_appended`]). Reads the DO's current
    /// head, mode and overflow count (a fresh pull), never a stale view.
    pub async fn end_due(&self) -> Result<Option<EdgePointRequest>> {
        let mut state = self.state.lock().await;
        let local_idle = state.pulled.is_empty()
            && state.skipped.is_empty()
            && state.issued.is_empty()
            && state.pending_floor.is_none()
            && !state.ended;
        if !local_idle {
            return Ok(None);
        }
        match self.transport.pull(state.epoch, state.through, self.config.pull_max_bytes, 1).await? {
            PullOutcome::Batch(batch) => {
                state.mode = batch.mode;
                state.head = batch.head;
                state.overflow_objects = batch.overflow_objects;
                for segment in batch.segments {
                    // Not drained after all: keep what arrived for `pending`.
                    ensure!(segment.seq == state.last_pulled + 1, "edge pull skipped a sequence");
                    state.last_pulled = segment.seq;
                    state.buffered_bytes = state.buffered_bytes.saturating_add(segment.length);
                    state.by_key.insert(segment.key.clone(), segment.seq);
                    state.pulled.insert(segment.seq, segment);
                }
            }
            PullOutcome::Busy => return Ok(None),
            PullOutcome::Fenced => return Err(EdgeLogFenced.into()),
            PullOutcome::Behind { committed_through, .. } => {
                bail!("edge log committed {committed_through} past this consumer: another consumer is active")
            }
        }
        let drained = state.mode == "drain" && state.head == state.through && state.overflow_objects == 0 && state.pulled.is_empty();
        Ok(drained.then(|| EdgePointRequest {
            through_seq: state.through,
            through_chain: state.chain.clone(),
            reason: "edge log drained".to_string(),
        }))
    }

    pub async fn end_appended(&self, end: &EdgePointRequest) -> Result<()> {
        let mut state = self.state.lock().await;
        ensure!(end.through_seq == state.through && end.through_chain == state.chain, "edge end differs from the committed point");
        state.ended = true;
        Ok(())
    }

    async fn commit_locked(&self, state: &mut State, through: u64, chain: &str) -> Result<()> {
        check_edge_commit_monotonic(state.through, through)?;
        match self.transport.commit(&CommitRequest::for_range(state.epoch, through, chain)).await? {
            CommitOutcome::Committed | CommitOutcome::Replayed => {}
            CommitOutcome::Fenced => return Err(EdgeLogFenced.into()),
            CommitOutcome::Conflict { committed_through } => {
                bail!("edge log refused commit {through} (committed {committed_through})")
            }
        }
        let keep = state.pulled.split_off(&(through + 1));
        let dropped = std::mem::replace(&mut state.pulled, keep);
        for segment in dropped.values() {
            state.by_key.remove(&segment.key);
            state.buffered_bytes = state.buffered_bytes.saturating_sub(segment.length);
        }
        state.skipped = state.skipped.split_off(&(through + 1));
        state.through = through;
        state.chain = chain.to_string();
        Ok(())
    }

    /// The DO's mode as of the last pull (`do` / `drain` / `r2`). Cheap: a
    /// caller gates [`Self::end_due`] (which pulls) on it being `drain`.
    pub async fn mode(&self) -> String {
        self.state.lock().await.mode.clone()
    }

    /// Ranges this source lets be outstanding at once (NAN-3619).
    pub fn max_issued_ranges(&self) -> usize {
        self.config.max_issued_ranges.max(1)
    }

    /// Counters and position (NAN-2964).
    pub async fn status(&self) -> EdgeLogStatus {
        self.status_locked(&*self.state.lock().await)
    }

    /// [`Self::status`] without waiting: `None` while a pull or commit holds
    /// the state (the stall watchdog must never block on a wedged consumer).
    pub fn try_status(&self) -> Option<EdgeLogStatus> {
        self.state.try_lock().ok().map(|state| self.status_locked(&state))
    }

    fn status_locked(&self, state: &State) -> EdgeLogStatus {
        EdgeLogStatus {
            epoch: state.epoch,
            mode: state.mode.clone(),
            head: state.head,
            committed_through: state.through,
            last_pulled: state.last_pulled,
            pulled_pending: state.pulled.len(),
            buffered_bytes: state.buffered_bytes,
            overflow_objects: state.overflow_objects,
            pulls_with_segments: state.stats.with_segments,
            pulls_empty: state.stats.empty,
            pulls_busy: state.stats.busy,
            busy_streak: state.stats.busy_streak,
            empty_behind_head_streak: state.stats.empty_behind_head_streak,
            segments_pulled: state.stats.segments,
        }
    }

    /// One `edge log status` line per [`STATUS_INTERVAL`] (INFO), WARN while
    /// a stall is visible, so an idle tenant and a wedged one differ in logs.
    fn log_status_locked(&self, state: &mut State) {
        let now = std::time::Instant::now();
        if state.stats.last_status.is_some_and(|at| now.duration_since(at) < STATUS_INTERVAL) {
            return;
        }
        state.stats.last_status = Some(now);
        let status = self.status_locked(state);
        let json = serde_json::to_string(&status).unwrap_or_default();
        match status.stall() {
            Some(stall) => tracing::warn!(tenant = %self.tenant_id, status = %json, stall, "edge log status"),
            None => tracing::info!(tenant = %self.tenant_id, status = %json, "edge log status"),
        }
    }

    /// Committed point, buffered bytes and pending count (for health.json).
    pub async fn position(&self) -> (u64, u64, usize) {
        let state = self.state.lock().await;
        (state.through, state.buffered_bytes, state.pulled.len())
    }
}
