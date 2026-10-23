// SPDX-License-Identifier: AGPL-3.0-or-later

use super::client::EdgeLogTransport;
use super::protocol::*;
use super::source::*;
use crate::parts::part_log::{EdgePoint, LogOp};
use crate::parts::provenance::SourceObject;
use crate::parts::{edge_log_genesis, edge_log_next_chain, sha256_hex, EdgeLogRange};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

const TENANT: &str = "23610000-0000-4000-8000-00000000000a";

/// A faithful in-memory model of the edge-log DO's consumer semantics
/// (`src/edge-log.js`): epoch fencing, monotonic chain-checked commits,
/// contiguous pulls after the committed point, the resume-point chain, the
/// Worker mode and overflow count.
struct FakeLog {
    segments: Vec<Segment>,
    epoch: u64,
    committed: u64,
    commits: Vec<(u64, String)>,
    mode: String,
    overflow_objects: u64,
    busy_pulls: u32,
    /// Serve empty batches while still reporting the real head (NAN-2964).
    withhold: bool,
    /// The DO's purge attestation (seq, chain).
    purge: Option<(u64, String)>,
}

impl Default for FakeLog {
    fn default() -> Self {
        Self { segments: Vec::new(), epoch: 0, committed: 0, commits: Vec::new(), mode: "do".into(), overflow_objects: 0, busy_pulls: 0, withhold: false, purge: None }
    }
}

#[derive(Clone, Default)]
struct FakeEdge(Arc<Mutex<FakeLog>>);

fn key(index: usize) -> String {
    format!("bronze-v2/shard=0/tenant_id={TENANT}/k{index}.parquet")
}

impl FakeEdge {
    fn append(&self, key: &str, body: &[u8]) {
        let mut log = self.0.lock().unwrap();
        let seq = log.segments.len() as u64 + 1;
        let prev = log.segments.last().map(|s| s.chain.clone()).unwrap_or_else(|| edge_log_genesis(TENANT));
        let sha = sha256_hex(body);
        let chain = edge_log_next_chain(&prev, seq, key, &sha, body.len() as u64);
        log.segments.push(Segment {
            seq, key: key.into(), sha256: sha, length: body.len() as u64, prev_chain: prev, chain,
            received_at_ms: 1_000, bytes: body.to_vec(),
        });
    }
    fn committed(&self) -> u64 {
        self.0.lock().unwrap().committed
    }
    fn chain_at(&self, seq: u64) -> String {
        let log = self.0.lock().unwrap();
        if seq == 0 { edge_log_genesis(TENANT) } else { log.segments[seq as usize - 1].chain.clone() }
    }
    fn point(&self, seq: u64) -> EdgePoint {
        EdgePoint { log: format!("edgelog:{TENANT}"), through_seq: seq, through_chain: self.chain_at(seq) }
    }
    fn set(&self, f: impl FnOnce(&mut FakeLog)) {
        f(&mut self.0.lock().unwrap());
    }
}

#[async_trait]
impl EdgeLogTransport for FakeEdge {
    async fn lease(&self, _consumer_id: &str, at: Option<u64>) -> Result<Lease> {
        let mut log = self.0.lock().unwrap();
        log.epoch += 1;
        let chain_at = |seq: u64| if seq == 0 { Some(edge_log_genesis(TENANT)) } else { log.segments.get(seq as usize - 1).map(|s| s.chain.clone()) };
        let committed = log.committed;
        Ok(Lease {
            backlog_skip: None,
            kind: "ok".into(), epoch: log.epoch, committed_through: committed,
            committed_chain: chain_at(committed).unwrap(), last_part_id: None, head: log.segments.len() as u64,
            floor_seq: 0, floor_chain: edge_log_genesis(TENANT), mode: log.mode.clone(),
            overflow_objects: log.overflow_objects, at_chain: at.and_then(chain_at),
            purge_seq: log.purge.as_ref().map(|(seq, _)| *seq), purge_chain: log.purge.as_ref().map(|(_, chain)| chain.clone()),
        })
    }
    async fn pull(&self, epoch: u64, after: u64, max_bytes: u64, max_segments: u32) -> Result<PullOutcome> {
        let mut log = self.0.lock().unwrap();
        if epoch != log.epoch { return Ok(PullOutcome::Fenced); }
        if log.busy_pulls > 0 { log.busy_pulls -= 1; return Ok(PullOutcome::Busy); }
        if after < log.committed {
            let chain = log.segments[log.committed as usize - 1].chain.clone();
            return Ok(PullOutcome::Behind { committed_through: log.committed, committed_chain: chain });
        }
        let mut out = Vec::new();
        let mut total = 0;
        let served = if log.withhold { 0 } else { max_segments as usize };
        for segment in log.segments.iter().skip(after as usize).take(served) {
            if !out.is_empty() && total + segment.length > max_bytes { break; }
            total += segment.length;
            out.push(segment.clone());
        }
        // Round-trip through the wire framing so decode_pull is exercised.
        let batch = PullBatch { committed_through: log.committed, head: log.segments.len() as u64, mode: log.mode.clone(),
            overflow_objects: log.overflow_objects, segments: out };
        Ok(PullOutcome::Batch(decode_pull(&encode_pull(&batch), after)?))
    }
    async fn commit(&self, request: &CommitRequest) -> Result<CommitOutcome> {
        let mut log = self.0.lock().unwrap();
        if request.epoch != log.epoch { return Ok(CommitOutcome::Fenced); }
        if request.through == log.committed {
            let same = log.commits.last().is_some_and(|(t, id)| *t == request.through && *id == request.part_id);
            return Ok(if same { CommitOutcome::Replayed } else { CommitOutcome::Conflict { committed_through: log.committed } });
        }
        let chain_ok = log.segments.get(request.through as usize - 1).is_some_and(|s| s.chain == request.through_chain);
        if request.through < log.committed || !chain_ok {
            return Ok(CommitOutcome::Conflict { committed_through: log.committed });
        }
        log.committed = request.through;
        log.commits.push((request.through, request.part_id.clone()));
        Ok(CommitOutcome::Committed)
    }
}

fn source_of(notice: &EdgeNotice) -> SourceObject {
    SourceObject { key: notice.key.clone(), version: notice.version.clone(), bytes: notice.bytes,
        sha256: notice.sha256.clone(), rows: 2, edge_sha256: None }
}

fn seeded(count: usize) -> FakeEdge {
    let edge = FakeEdge::default();
    for index in 1..=count {
        edge.append(&key(index), format!("rows-{index}").as_bytes());
    }
    edge
}

async fn open(edge: &FakeEdge, point: Option<EdgePoint>) -> Result<EdgeLogSource<FakeEdge>> {
    EdgeLogSource::open(edge.clone(), TENANT, "ingest", point.as_ref(), EdgeLogSourceConfig::default()).await
}

fn handles(notices: &[EdgeNotice]) -> Vec<String> {
    notices.iter().map(|n| n.handle.clone()).collect()
}

/// One ingest[T] flush: range (flush-wide), (append lands), ack.
async fn flush(source: &EdgeLogSource<FakeEdge>, notices: &[EdgeNotice]) -> EdgeLogRange {
    let mut sources = notices.iter().map(source_of).collect::<Vec<_>>();
    sources.sort(); // phase 2 sorts sources by key
    let range = source.range_for_flush(&sources, 0, 1).await.unwrap().expect("edge range");
    range.validate(TENANT, &sources).unwrap();
    source.ack(&handles(notices)).await.unwrap();
    range
}

#[tokio::test]
async fn pulls_flushes_and_commits_after_the_append() {
    let edge = seeded(5);
    let source = open(&edge, None).await.unwrap();
    let pending = source.pending(3).await.unwrap();
    assert_eq!(pending.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert_eq!(source.get(&pending[0].key).await.unwrap(), b"rows-1");
    let first = flush(&source, &pending).await;
    assert_eq!((first.first_seq, first.through_seq, edge.committed()), (1, 3, 3));
    assert_eq!(first.prev_chain, edge_log_genesis(TENANT));
    assert_eq!((first.rows_in, first.rows_rejected, first.rows_duplicate), (6, 0, 1));
    let rest = source.pending(10).await.unwrap();
    assert_eq!(rest.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![4, 5]);
    let second = flush(&source, &rest).await;
    second.follows(&first).unwrap();
    assert_eq!(edge.committed(), 5);
    assert_eq!(source.position().await, (5, 0, 0));
}

#[tokio::test]
async fn skipped_segments_carry_their_rows_into_the_next_range() {
    let edge = seeded(5);
    let source = open(&edge, None).await.unwrap();
    let pending = source.pending(10).await.unwrap();
    // Segment 1: all 3 rows duplicate; 3: 4 rows rejected.
    source.ack_skipped(&[EdgeAck { handle: pending[0].handle.clone(), rows: 3, rows_rejected: 0, rows_duplicate: 3 }]).await.unwrap();
    source.ack_skipped(&[EdgeAck { handle: pending[2].handle.clone(), rows: 4, rows_rejected: 4, rows_duplicate: 0 }]).await.unwrap();
    assert_eq!(edge.committed(), 0, "no commit without an add entry");
    let left = source.pending(10).await.unwrap().iter().map(|n| n.seq).collect::<Vec<_>>();
    assert_eq!(left, vec![2, 4, 5]);
    assert_eq!(source.position().await.1, pending[1].bytes + pending[3].bytes + pending[4].bytes, "skip bytes are released");
    let range = flush(&source, &[pending[1].clone(), pending[3].clone()]).await;
    assert_eq!((range.first_seq, range.through_seq), (1, 4));
    assert_eq!(range.skipped.iter().map(|s| (s.seq, s.rows)).collect::<Vec<_>>(), vec![(1, 3), (3, 4)]);
    // rows_in = sources (2 x 2) + skipped (3 + 4); lost = flush dup 1 + 3 + 4.
    assert_eq!((range.rows_in, range.rows_rejected, range.rows_duplicate), (11, 4, 4));
    // A skip must account every row.
    let bad = EdgeAck { handle: pending[4].handle.clone(), rows: 2, rows_rejected: 1, rows_duplicate: 0 };
    assert!(source.ack_skipped(&[bad]).await.is_err());
}

#[tokio::test]
async fn flushes_are_serial_and_ranges_are_flush_wide() {
    let edge = seeded(4);
    let source = open(&edge, None).await.unwrap();
    let pending = source.pending(10).await.unwrap();
    let sources = pending[..2].iter().map(source_of).collect::<Vec<_>>();
    source.range_for_flush(&sources, 0, 0).await.unwrap().unwrap();
    let error = source.range_for_flush(&pending[2..].iter().map(source_of).collect::<Vec<_>>(), 0, 0).await.unwrap_err();
    assert!(error.to_string().contains("serial"), "{error}");
    source.ack(&handles(&pending[..2])).await.unwrap();
    assert_eq!(edge.committed(), 2);
}

/// NAN-3619: with two ranges allowed outstanding, the second starts right
/// after the first (chained to its through-chain), a third is refused, and
/// acks commit strictly in issue order.
#[tokio::test]
async fn two_outstanding_ranges_chain_and_commit_in_issue_order() {
    let edge = seeded(6);
    let config = EdgeLogSourceConfig { max_issued_ranges: 2, ..EdgeLogSourceConfig::default() };
    let source = EdgeLogSource::open(edge.clone(), TENANT, "ingest", None, config).await.unwrap();
    assert_eq!(source.max_issued_ranges(), 2);
    let pending = source.pending(10).await.unwrap();
    // Segment 3 is skipped by the second flush (its rows all duplicates).
    let first = source.range_for_flush(&pending[..2].iter().map(source_of).collect::<Vec<_>>(), 0, 0).await.unwrap().unwrap();
    source.ack_skipped(&[EdgeAck { handle: pending[2].handle.clone(), rows: 1, rows_rejected: 0, rows_duplicate: 1 }]).await.unwrap();
    let second = source.range_for_flush(&pending[3..5].iter().map(source_of).collect::<Vec<_>>(), 0, 0).await.unwrap().unwrap();
    assert_eq!((first.first_seq, first.through_seq), (1, 2));
    assert_eq!((second.first_seq, second.through_seq), (3, 5));
    assert_eq!(second.skipped.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![3]);
    second.follows(&first).unwrap();
    let error = source.range_for_flush(&[source_of(&pending[5])], 0, 0).await.unwrap_err();
    assert!(error.to_string().contains("serial"), "{error}");
    // Out of order: the second range's ack is refused while the first is outstanding.
    assert!(source.ack(&handles(&pending[3..5])).await.is_err());
    assert_eq!(edge.committed(), 0, "nothing commits ahead of the first range");
    assert!(source.floor_due(i64::MAX).await.is_none(), "no floor while ranges are outstanding");
    source.ack(&handles(&pending[..2])).await.unwrap();
    assert_eq!(edge.committed(), 2);
    source.ack(&handles(&pending[3..5])).await.unwrap();
    assert_eq!(edge.committed(), 5);
    assert!(source.ack(&handles(&pending[3..5])).await.is_err(), "no range left to ack");
    // Back to one outstanding: the next range follows the second.
    let third = source.range_for_flush(&[source_of(&pending[5])], 0, 0).await.unwrap().unwrap();
    third.follows(&second).unwrap();
}

#[tokio::test]
async fn a_flush_with_an_unaccounted_segment_is_refused() {
    let edge = seeded(3);
    let source = open(&edge, None).await.unwrap();
    let pending = source.pending(10).await.unwrap();
    let sources = vec![source_of(&pending[0]), source_of(&pending[2])];
    assert!(source.range_for_flush(&sources, 0, 0).await.is_err(), "segment 2 is neither flushed nor acknowledged");
    let mut forged = source_of(&pending[0]);
    forged.sha256 = "0".repeat(64);
    assert!(source.range_for_flush(&[forged], 0, 0).await.is_err());
    let plain = SourceObject { key: "k".into(), version: "v".into(), bytes: 1, sha256: "0".repeat(64), rows: 1, edge_sha256: None };
    assert!(source.range_for_flush(&[plain], 0, 0).await.unwrap().is_none());
}

#[tokio::test]
async fn resume_from_the_part_log_point_reconciles_and_fails_closed_on_a_chain_mismatch() {
    let edge = seeded(6);
    // The add entry for 1..=4 landed; its DO commit did not.
    let restarted = open(&edge, Some(edge.point(4))).await.unwrap();
    assert_eq!(edge.committed(), 4, "the reconcile commit precedes any pull");
    let next = restarted.pending(10).await.unwrap();
    assert_eq!(next.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![5, 6], "nothing is re-emitted");
    let after = flush(&restarted, &next).await;
    after.follows_point(&format!("edgelog:{TENANT}"), 4, &edge.chain_at(4)).unwrap();
    // A part log whose chain differs from the DO's is refused, ahead or equal.
    let other = seeded(6);
    let mut forged = other.point(5);
    forged.through_chain = "f".repeat(64);
    assert!(open(&other, Some(forged.clone())).await.is_err(), "ahead of the DO");
    other.set(|log| log.committed = 5);
    assert!(open(&other, Some(forged)).await.is_err(), "equal to the DO");
    // With no point, the consumer starts at genesis (seq 1).
    let fresh = seeded(2);
    assert_eq!(open(&fresh, None).await.unwrap().pending(10).await.unwrap()[0].seq, 1);
    // Another tenant's log is refused.
    let mut foreign = fresh.point(0);
    foreign.log = "edgelog:00000000-0000-4000-8000-000000000000".into();
    assert!(open(&fresh, Some(foreign)).await.is_err());
}

#[tokio::test]
async fn a_part_log_behind_the_do_fails_closed_unless_the_do_attests_a_purge() {
    // Committed segments 2..=3 never became parts in this log: refused, even
    // though the DO still agrees on the chain at the resume point.
    let edge = seeded(5);
    edge.set(|log| { log.committed = 3; log.commits.push((3, "edge-through-3".into())); });
    let error = open(&edge, Some(edge.point(1))).await.err().expect("refused");
    assert!(error.to_string().contains("attests no purge"), "{error}");
    // The same, with a purge attested exactly at the DO's committed point.
    let chain3 = edge.chain_at(3);
    edge.set(|log| log.purge = Some((3, chain3.clone())));
    let source = open(&edge, Some(edge.point(1))).await.unwrap();
    let floor = source.floor_due(0).await.expect("reconcile floor");
    assert_eq!((floor.through_seq, floor.through_chain.clone(), floor.reason.as_str()), (3, edge.chain_at(3), "edge log purged"));
    assert!(matches!(floor.floor_op(), LogOp::EdgeFloor { through_seq: 3, .. }));
    assert!(source.pending(10).await.unwrap().is_empty(), "nothing is pulled before the floor lands");
    source.floor_appended(&floor).await.unwrap();
    assert_eq!(source.pending(10).await.unwrap().iter().map(|n| n.seq).collect::<Vec<_>>(), vec![4, 5]);
    // A purge attestation at another point does not cover this gap.
    let other = seeded(5);
    let chain2 = other.chain_at(2);
    other.set(|log| { log.committed = 3; log.purge = Some((2, chain2)); });
    assert!(open(&other, Some(other.point(1))).await.is_err());
    // A mismatching chain at a point the DO still knows is refused even with a purge.
    let mut forged = edge.point(1);
    forged.through_chain = "e".repeat(64);
    assert!(open(&edge, Some(forged)).await.is_err());
}

#[tokio::test]
async fn a_lost_part_log_fails_closed() {
    // The part log is gone (no edge point) but the DO committed 1..=4.
    let edge = seeded(6);
    edge.set(|log| { log.committed = 4; log.commits.push((4, "edge-through-4".into())); });
    let error = open(&edge, None).await.err().expect("a lost part log must not get a floor");
    assert!(error.to_string().contains("lost part log"), "{error}");
    assert_eq!(edge.committed(), 4, "nothing moved");
}

#[tokio::test]
async fn a_plain_ack_never_becomes_a_skip() {
    let edge = seeded(3);
    let source = open(&edge, None).await.unwrap();
    let pending = source.pending(10).await.unwrap();
    let error = source.ack(&handles(&pending[..1])).await.unwrap_err();
    assert!(error.to_string().contains("ack_skipped"), "{error}");
    assert_eq!(source.pending(10).await.unwrap().len(), 3, "the segment is still pending, not skipped");
    let mut sources = pending[..2].iter().map(source_of).collect::<Vec<_>>();
    sources.sort();
    source.range_for_flush(&sources, 0, 0).await.unwrap();
    assert!(source.ack(&handles(&pending[..1])).await.is_err(), "the ack must name the range's last segment");
    source.ack(&handles(&pending[..2])).await.unwrap();
    assert_eq!(edge.committed(), 2);
}

#[tokio::test]
async fn a_skip_only_tail_becomes_an_edge_floor_and_releases_the_do() {
    let edge = seeded(3);
    let source = open(&edge, None).await.unwrap();
    let pending = source.pending(10).await.unwrap();
    for notice in &pending[..2] {
        source.ack_skipped(&[EdgeAck { handle: notice.handle.clone(), rows: 1, rows_rejected: 1, rows_duplicate: 0 }]).await.unwrap();
    }
    assert!(source.floor_due(1_000).await.is_none(), "under both thresholds");
    let floor = source.floor_due(1_000 + 60_000).await.expect("age threshold");
    assert_eq!(floor.through_seq, 2);
    source.floor_appended(&floor).await.unwrap();
    assert_eq!(edge.committed(), 2, "the DO moves to the floor after the append");
    assert!(source.floor_due(i64::MAX).await.is_none());
    // The next range starts after the floor.
    let range = flush(&source, &pending[2..]).await;
    range.follows_point(&format!("edgelog:{TENANT}"), 2, &edge.chain_at(2)).unwrap();
    // A floor that does not end on a skip is refused.
    let bogus = EdgePointRequest { through_seq: 3, through_chain: edge.chain_at(3), reason: "x".into() };
    assert!(source.floor_appended(&bogus).await.is_err());
}

#[tokio::test]
async fn a_draining_worker_ends_edge_mode_once_everything_is_committed() {
    let edge = seeded(2);
    edge.set(|log| log.mode = "drain".into());
    let source = open(&edge, None).await.unwrap();
    let pending = source.pending(10).await.unwrap();
    assert!(source.end_due().await.unwrap().is_none(), "segments are still pending");
    flush(&source, &pending).await;
    source.pending(10).await.unwrap(); // observes head == committed
    edge.set(|log| log.overflow_objects = 1);
    source.pending(10).await.unwrap();
    assert!(source.end_due().await.unwrap().is_none(), "overflow objects remain");
    edge.set(|log| log.overflow_objects = 0);
    source.pending(10).await.unwrap();
    let end = source.end_due().await.unwrap().expect("drained");
    assert_eq!((end.through_seq, end.through_chain.clone()), (2, edge.chain_at(2)));
    assert!(matches!(end.end_op(), LogOp::EdgeEnd { through_seq: 2, .. }));
    source.end_appended(&end).await.unwrap();
    // A fresh read, not the last pull: a segment that arrives after the last
    // pull keeps a second source from ending.
    let later = seeded(2);
    later.set(|log| log.mode = "drain".into());
    let second = open(&later, None).await.unwrap();
    let batch = second.pending(10).await.unwrap();
    flush(&second, &batch).await;
    later.append(&key(3), b"late");
    assert!(second.end_due().await.unwrap().is_none(), "the late segment is seen");
    assert_eq!(second.pending(10).await.unwrap().iter().map(|n| n.seq).collect::<Vec<_>>(), vec![3]);
    assert!(source.pending(1).await.is_err(), "the source is closed after the end");
}

#[tokio::test]
async fn busy_pulls_are_retried_and_restarts_redeliver() {
    let edge = seeded(3);
    edge.set(|log| log.busy_pulls = 1);
    let source = open(&edge, None).await.unwrap();
    assert!(source.pending(10).await.unwrap().is_empty(), "a busy DO yields nothing this round");
    let pending = source.pending(10).await.unwrap();
    assert_eq!(pending.len(), 3);
    source.ack_skipped(&[EdgeAck { handle: pending[0].handle.clone(), rows: 0, rows_rejected: 0, rows_duplicate: 0 }]).await.unwrap();
    drop(source);
    let restarted = open(&edge, None).await.unwrap();
    assert_eq!(restarted.pending(10).await.unwrap().len(), 3, "uncommitted segments, skips included, come back");
}

#[tokio::test]
async fn an_older_consumer_is_fenced_and_a_lost_part_log_fails_closed() {
    let edge = seeded(4);
    let old = open(&edge, None).await.unwrap();
    let pending = old.pending(2).await.unwrap();
    let new = open(&edge, None).await.unwrap();
    let mut sources = pending.iter().map(source_of).collect::<Vec<_>>();
    sources.sort();
    old.range_for_flush(&sources, 0, 0).await.unwrap();
    let error = old.ack(&handles(&pending)).await.unwrap_err();
    assert!(error.downcast_ref::<EdgeLogFenced>().is_some());
    assert!(old.pending(10).await.unwrap_err().downcast_ref::<EdgeLogFenced>().is_some());
    let fresh = new.pending(2).await.unwrap();
    flush(&new, &fresh).await;
}

#[tokio::test]
async fn pulls_stay_under_the_buffered_bytes_bound() {
    let edge = FakeEdge::default();
    for index in 1..=10 {
        edge.append(&key(index), &[b'x'; 100]);
    }
    let config = EdgeLogSourceConfig { max_buffered_bytes: 250, ..EdgeLogSourceConfig::default() };
    let source = EdgeLogSource::open(edge, TENANT, "ingest", None, config).await.unwrap();
    assert_eq!(source.pending(10).await.unwrap().len(), 2);
    // Under the bound a pull returns at least one segment, so the bound is
    // soft by at most one segment (<= 16 MiB); at or over it, nothing is pulled.
    assert_eq!(source.pending(10).await.unwrap().len(), 3);
    assert_eq!(source.pending(10).await.unwrap().len(), 3, "no further pull while over the bound");
}

#[test]
fn decode_pull_rejects_tampering_gaps_trailing_bytes_and_out_of_bounds_sequences() {
    let edge = seeded(3);
    let segments = edge.0.lock().unwrap().segments.clone();
    let batch = PullBatch { committed_through: 0, head: 3, mode: "do".into(), overflow_objects: 0, segments };
    let good = encode_pull(&batch);
    assert_eq!(decode_pull(&good, 0).unwrap(), batch);
    let mut flipped = good.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert!(decode_pull(&flipped, 0).is_err(), "bytes");
    let mut trailing = good.clone();
    trailing.push(b'x');
    assert!(decode_pull(&trailing, 0).is_err(), "trailing");
    assert!(decode_pull(&good, 1).is_err(), "not contiguous from after");
    let mut forged = batch.clone();
    forged.segments[1].chain = "a".repeat(64);
    assert!(decode_pull(&encode_pull(&forged), 0).is_err(), "chain");
    let mut gap = batch.clone();
    gap.segments.remove(1);
    assert!(decode_pull(&encode_pull(&gap), 0).is_err(), "gap");
    assert!(decode_pull(&good, MAX_SEQ).is_err(), "sequence past 2^53 - 1");
    assert_eq!(MAX_PULL_BYTES, 16 * 1024 * 1024, "the DO memory budget's pull cap");
}

/// The JS Worker's `streamSegments` output for one segment, pinned.
#[test]
fn decode_pull_reads_the_worker_framing() {
    let genesis = edge_log_genesis(TENANT);
    let a = b"alpha\n";
    let sha = sha256_hex(a);
    let chain = edge_log_next_chain(&genesis, 1, "k1", &sha, a.len() as u64);
    let header = format!(
        r#"{{"kind":"ok","committedThrough":0,"head":1,"mode":"drain","overflowObjects":0,"floorSeq":0,"floorChain":"{genesis}","segments":[{{"seq":1,"key":"k1","sha256":"{sha}","length":6,"prevChain":"{genesis}","chain":"{chain}","receivedAt":5}}]}}"#
    );
    let mut body = header.into_bytes();
    body.push(b'\n');
    body.extend_from_slice(a);
    let decoded = decode_pull(&body, 0).unwrap();
    assert_eq!(decoded.segments[0].bytes, a);
    assert_eq!(decoded.mode, "drain");
    assert_eq!(decoded.segments[0].version(), "edge-log-v1:1");
}

#[tokio::test]
async fn http_client_speaks_the_worker_route() {
    use axum::{body::Bytes, extract::State, http::{HeaderMap, StatusCode}, routing::post, Router};
    #[derive(Clone)]
    struct App(Arc<Mutex<Vec<(String, String)>>>, Vec<u8>);
    async fn handle(action: &'static str, State(app): State<App>, headers: HeaderMap, body: Bytes) -> (StatusCode, Vec<u8>) {
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let count = {
            let mut calls = app.0.lock().unwrap();
            calls.push((action.to_string(), String::from_utf8_lossy(&body).into_owned()));
            calls.iter().filter(|(a, _)| a == action).count()
        };
        if auth != "Bearer consumer-token-for-tests" {
            return (StatusCode::UNAUTHORIZED, b"unauthorized".to_vec());
        }
        match action {
            "lease" => (StatusCode::OK, br#"{"kind":"ok","epoch":7,"committedThrough":0,"committedChain":"x","lastPartId":null,"head":2,"atChain":"y"}"#.to_vec()),
            "pull" if count == 1 => (StatusCode::SERVICE_UNAVAILABLE, br#"{"kind":"busy"}"#.to_vec()),
            "pull" if count == 2 => (StatusCode::CONFLICT, br#"{"kind":"behind","committedThrough":3,"committedChain":"z"}"#.to_vec()),
            "pull" => (StatusCode::OK, app.1.clone()),
            _ => (StatusCode::CONFLICT, br#"{"kind":"fenced"}"#.to_vec()),
        }
    }
    let edge = seeded(2);
    let frame = encode_pull(&PullBatch { committed_through: 0, head: 2, mode: "do".into(), overflow_objects: 0,
        segments: edge.0.lock().unwrap().segments.clone() });
    let app = App(Arc::new(Mutex::new(Vec::new())), frame);
    let router = Router::new()
        .route("/edge-log/v1/lease", post(|s, h, b| handle("lease", s, h, b)))
        .route("/edge-log/v1/pull", post(|s, h, b| handle("pull", s, h, b)))
        .route("/edge-log/v1/commit", post(|s, h, b| handle("commit", s, h, b)))
        .with_state(app.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let base = format!("http://127.0.0.1:{}", address.port());

    let client = super::HttpEdgeLogClient::new(&base, zeroize::Zeroizing::new("consumer-token-for-tests".into())).unwrap();
    let lease = client.lease("ingest", Some(4)).await.unwrap();
    assert_eq!((lease.epoch, lease.at_chain.as_deref()), (7, Some("y")));
    assert_eq!(client.pull(7, 0, u64::MAX, u32::MAX).await.unwrap(), PullOutcome::Busy);
    assert_eq!(client.pull(7, 0, 1, 1).await.unwrap(),
        PullOutcome::Behind { committed_through: 3, committed_chain: "z".into() });
    match client.pull(7, 0, u64::MAX, u32::MAX).await.unwrap() {
        PullOutcome::Batch(batch) => assert_eq!(batch.segments.len(), 2),
        other => panic!("unexpected {other:?}"),
    }
    let commit = CommitRequest::for_range(7, 2, &"a".repeat(64));
    assert_eq!(client.commit(&commit).await.unwrap(), CommitOutcome::Fenced);
    let calls = app.0.lock().unwrap().clone();
    let lease_body: serde_json::Value = serde_json::from_str(&calls[0].1).unwrap();
    assert_eq!(lease_body["at"], 4);
    let pull_body: serde_json::Value = serde_json::from_str(&calls[1].1).unwrap();
    assert_eq!(pull_body["maxBytes"], MAX_PULL_BYTES, "pull size is clamped client-side too");
    assert_eq!(pull_body["maxSegments"], MAX_PULL_SEGMENTS);
    let commit_body: serde_json::Value = serde_json::from_str(&calls.last().unwrap().1).unwrap();
    assert_eq!(commit_body["partId"], "edge-through-2");

    let wrong = super::HttpEdgeLogClient::new(&base, zeroize::Zeroizing::new("other-token".into())).unwrap();
    assert!(wrong.lease("ingest", None).await.is_err());
    // A rotated token takes effect on the next request; a malformed one is refused.
    wrong.set_token(zeroize::Zeroizing::new("consumer-token-for-tests".into())).unwrap();
    assert!(wrong.lease("ingest", None).await.is_ok());
    assert!(wrong.set_token(zeroize::Zeroizing::new("has space".into())).is_err());
    assert!(super::HttpEdgeLogClient::new("http://example.com", zeroize::Zeroizing::new("t".into())).is_err(),
        "plain http only for loopback");
}

/// Cross-language end to end: the Rust consumer against the real Worker and
/// edge-log DO (`edge-log-probe/probe.sh` with `RUN_RUST_E2E=1`, local
/// `wrangler dev` or the scratch deploy). Appends through the Container-bridge
/// stand-in, then consumes with `EdgeLogSource` over HTTPS.
#[tokio::test]
#[ignore = "needs a running edge-log probe Worker (NANO_EDGE_LOG_E2E_*)"]
async fn e2e_rust_consumer_against_the_worker() {
    // Credentials come from 0600 files in the probe's private state dir
    // (secret-bearing env vars do not reach sandboxed test harnesses).
    let dir = std::path::PathBuf::from(std::env::var("NANO_EDGE_LOG_E2E_DIR").unwrap());
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap().trim().to_string();
    let (base, probe, consumer) = (read("base"), read("probe-token"), read("consumer-token"));
    let tenant = "23610000-0000-4000-8000-00000000000b";
    let http = reqwest::Client::new();
    let run = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut keys = Vec::new();
    for index in 1..=5_u32 {
        let key = format!("bronze-v2/shard=0/tenant_id={tenant}/{run}-00000000-0000-4000-8000-{:012}.parquet", 900 + index);
        let body = format!("{key}#rust\n").into_bytes();
        let response = http
            .put(format!("{base}/probe/sink?tenant={tenant}&key={key}"))
            .bearer_auth(&probe)
            .header("x-amz-content-sha256", sha256_hex(&body))
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "sink append");
        keys.push(key);
    }
    let client = || super::HttpEdgeLogClient::new(&base, zeroize::Zeroizing::new(consumer.clone())).unwrap();
    // The JS probe leaves tenant B's log uncommitted, so a genesis start is exact.
    let source = EdgeLogSource::open(client(), tenant, "rust-e2e", None, EdgeLogSourceConfig::default()).await.unwrap();
    let mut pending = Vec::new();
    for _ in 0..20 {
        pending = source.pending(100).await.unwrap();
        if keys.iter().all(|key| pending.iter().any(|n| &n.key == key)) {
            break;
        }
    }
    for key in &keys {
        assert!(pending.iter().any(|n| &n.key == key), "appended segment is pending");
    }
    let (first, rest) = pending.split_at(pending.len() / 2);
    let mut point = None;
    let mut previous: Option<EdgeLogRange> = None;
    for batch in [first, rest] {
        let mut sources = batch.iter().map(source_of).collect::<Vec<_>>();
        sources.sort();
        let range = source.range_for_flush(&sources, 0, 0).await.unwrap().unwrap();
        range.validate(tenant, &sources).unwrap();
        if let Some(previous) = &previous {
            range.follows(previous).unwrap();
        }
        source.ack(&handles(batch)).await.unwrap();
        point = Some(EdgePoint { log: range.log.clone(), through_seq: range.through_seq, through_chain: range.through_chain.clone() });
        previous = Some(range);
    }
    let point = point.unwrap();
    assert_eq!(source.position().await.0, point.through_seq);
    // A restarted consumer resumes after the committed point: nothing re-emitted.
    let restarted = EdgeLogSource::open(client(), tenant, "rust-e2e-2", Some(&point), EdgeLogSourceConfig::default()).await.unwrap();
    assert!(restarted.pending(100).await.unwrap().iter().all(|n| n.seq > point.through_seq));
    // A forged point is refused (fail closed against the DO's chain).
    let forged = EdgePoint { through_chain: "f".repeat(64), ..point.clone() };
    assert!(EdgeLogSource::open(client(), tenant, "rust-e2e-3", Some(&forged), EdgeLogSourceConfig::default()).await.is_err());
    // The first consumer is fenced by the newer leases.
    assert!(source.pending(1).await.unwrap_err().downcast_ref::<EdgeLogFenced>().is_some());
}

/// NAN-2964: a lean tenant's ingest stayed silent for hours: an empty edge
/// log, a DO pull slot stuck busy and a head the pulls never reach were
/// indistinguishable. `status()` tells them apart.
#[tokio::test]
async fn status_tells_an_empty_log_from_a_busy_or_withholding_do() {
    // Empty edge log: pulls succeed with nothing; no stall.
    let edge = FakeEdge::default();
    let source = open(&edge, None).await.unwrap();
    for _ in 0..(STALL_STREAK + 5) {
        assert!(source.pending(8).await.unwrap().is_empty());
    }
    let status = source.status().await;
    assert_eq!((status.head, status.pulls_empty, status.pulls_busy, status.segments_pulled), (0, STALL_STREAK + 5, 0, 0));
    assert_eq!(status.stall(), None);

    // Pull slot answers busy on every pull: a stall.
    let edge = seeded(2);
    let source = open(&edge, None).await.unwrap();
    edge.set(|log| log.busy_pulls = u32::try_from(STALL_STREAK).unwrap());
    for _ in 0..STALL_STREAK {
        assert!(source.pending(8).await.unwrap().is_empty());
    }
    let status = source.status().await;
    assert_eq!((status.pulls_busy, status.busy_streak), (STALL_STREAK, STALL_STREAK));
    assert!(status.stall().unwrap().contains("busy"));
    // The slot frees: the segments arrive and the streak resets.
    assert_eq!(source.pending(8).await.unwrap().len(), 2);
    let status = source.status().await;
    assert_eq!((status.busy_streak, status.pulls_with_segments, status.segments_pulled, status.last_pulled, status.head), (0, 1, 2, 2, 2));
    assert_eq!(status.stall(), None);

    // Head is past the consumer but pulls return nothing: a stall.
    let edge = seeded(3);
    edge.set(|log| log.withhold = true);
    let source = open(&edge, None).await.unwrap();
    for _ in 0..STALL_STREAK {
        assert!(source.pending(8).await.unwrap().is_empty());
    }
    let status = source.status().await;
    assert_eq!((status.head, status.last_pulled, status.empty_behind_head_streak), (3, 0, STALL_STREAK));
    assert!(status.stall().unwrap().contains("head"));
}

// Recovery uses real Parquet, the real source's signed-range accounting, and
// an otherwise faithful DO transport. The operator deliberately includes a
// mixed segment to prove runtime revalidation keeps it even in a bad plan.
#[derive(Clone)]
struct RecoveryEdge(FakeEdge, super::backlog::BacklogSkipPlan);
#[async_trait]
impl EdgeLogTransport for RecoveryEdge {
    async fn lease(&self, id: &str, at: Option<u64>) -> Result<Lease> {
        let mut lease = self.0.lease(id, at).await?;
        if lease.committed_through == 0 { lease.committed_chain = edge_log_genesis(super::backlog::tests::RECOVERY_TENANT); }
        if at == Some(0) { lease.at_chain = Some(edge_log_genesis(super::backlog::tests::RECOVERY_TENANT)); }
        lease.backlog_skip = Some(self.1.clone());
        Ok(lease)
    }
    async fn pull(&self, epoch: u64, after: u64, bytes: u64, count: u32) -> Result<PullOutcome> {
        self.0.pull(epoch, after, bytes, count).await
    }
    async fn commit(&self, request: &CommitRequest) -> Result<CommitOutcome> { self.0.commit(request).await }
}

fn recovery_fixture() -> RecoveryEdge {
    use super::backlog::{BacklogSkipPlan, BacklogSummary, tests::RECOVERY_TENANT};
    let cutoff = chrono::Utc::now().timestamp_millis() - 3_600_000;
    let edge = FakeEdge::default();
    for (i, times) in [vec![Some(1)], vec![Some(1), Some(cutoff)], vec![Some(1)], vec![None], vec![Some(1)]].into_iter().enumerate() {
        edge.append(&format!("bronze-v2/shard=0/tenant_id={RECOVERY_TENANT}/k{}.parquet", i + 1), &super::backlog::tests::parquet(times));
    }
    edge.set(|log| {
        let mut previous = edge_log_genesis(RECOVERY_TENANT);
        for segment in &mut log.segments {
            segment.prev_chain = previous;
            segment.chain = edge_log_next_chain(&segment.prev_chain, segment.seq, &segment.key, &segment.sha256, segment.length);
            previous = segment.chain.clone();
        }
    });
    let mut plan = BacklogSkipPlan { version: 1, tenant_uuid: RECOVERY_TENANT.into(), cutoff_ms: cutoff, first_seq: 1, through_seq: 4,
        summary: BacklogSummary { segments: 3, bytes: 0, rows: 4, kept: 1, ranges: vec![[1, 3]], manifest_sha256: "a".repeat(64) },
        plan_hash: String::new(), at: cutoff + 3_600_000 };
    plan.plan_hash = plan.canonical_hash().unwrap();
    RecoveryEdge(edge, plan)
}

#[tokio::test]
async fn backlog_recovery_preserves_mixed_unknown_unplanned_and_commits_only_after_durable_range() {
    use super::backlog::tests::RECOVERY_TENANT;
    let edge = recovery_fixture();
    let source = EdgeLogSource::open(edge.clone(), RECOVERY_TENANT, "ingest", None, EdgeLogSourceConfig::default()).await.unwrap();
    let pending = source.pending(10).await.unwrap();
    assert_eq!(pending.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![2, 4, 5]);
    assert_eq!(edge.0.committed(), 0);
    let floor = source.floor_due(0).await.unwrap();
    assert_eq!(floor.through_seq, 1, "retained sequence2 is a hard barrier");
    assert!(floor.reason.contains(&edge.1.plan_hash));
    assert!(floor.reason.contains("rows=1"));
    // Crash before EdgeFloor append: everything is replayed and no DO ACK.
    drop(source);
    let restarted = EdgeLogSource::open(edge.clone(), RECOVERY_TENANT, "restart", None, EdgeLogSourceConfig::default()).await.unwrap();
    let pending = restarted.pending(10).await.unwrap();
    assert_eq!(pending.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![2, 4, 5]);
    let floor = restarted.floor_due(0).await.unwrap();
    assert_eq!(edge.0.committed(), 0);
    restarted.floor_appended(&floor).await.unwrap(); // simulate durable EdgeFloor
    assert_eq!(edge.0.committed(), 1);
    let sources = pending[..2].iter().map(source_of).collect::<Vec<_>>();
    let range = restarted.range_for_flush(&sources, 0, 0).await.unwrap().unwrap();
    range.validate(RECOVERY_TENANT, &sources).unwrap();
    assert_eq!((range.first_seq, range.through_seq), (2, 4));
    assert_eq!(range.skipped.iter().map(|s| (s.seq, s.rows, s.rows_rejected)).collect::<Vec<_>>(), vec![(3, 1, 1)]);
    assert_eq!(edge.0.committed(), 1, "range issuance must not acknowledge");
    // Crash after durable Add but before DO ACK; reopen reconciles that
    // exact chain point rather than publishing the retained rows twice.
    let point = EdgePoint { log: format!("edgelog:{RECOVERY_TENANT}"), through_seq: 4, through_chain: range.through_chain };
    drop(restarted);
    let final_source = EdgeLogSource::open(edge.clone(), RECOVERY_TENANT, "after-add", Some(&point), EdgeLogSourceConfig::default()).await.unwrap();
    assert_eq!(edge.0.committed(), 4);
    assert_eq!(final_source.pending(10).await.unwrap().iter().map(|n| n.seq).collect::<Vec<_>>(), vec![5]);
}

#[tokio::test]
async fn backlog_recovery_rejects_cross_tenant_and_modified_plan() {
    let edge = recovery_fixture();
    assert!(EdgeLogSource::open(edge.clone(), TENANT, "wrong", None, EdgeLogSourceConfig::default()).await.is_err());
    let mut tampered = edge.clone(); tampered.1.cutoff_ms -= 1;
    assert!(EdgeLogSource::open(tampered, super::backlog::tests::RECOVERY_TENANT, "bad-hash", None, EdgeLogSourceConfig::default()).await.is_err());
}

// Production open path: the lease's plan must name the consuming tenant. A
// correctly hashed plan for another tenant, served on this tenant's otherwise
// valid log, is refused before any segment is pulled or skipped.
#[tokio::test]
async fn backlog_recovery_refuses_plan_bound_to_another_tenant() {
    let mut edge = recovery_fixture();
    edge.1.tenant_uuid = TENANT.into();
    edge.1.plan_hash = edge.1.canonical_hash().unwrap();
    let err = EdgeLogSource::open(edge.clone(), super::backlog::tests::RECOVERY_TENANT, "other", None,
        EdgeLogSourceConfig::default()).await.err().expect("cross-tenant plan must be refused");
    assert!(err.to_string().contains("not bound to this tenant"), "{err:#}");
    assert_eq!(edge.0.committed(), 0);
}
