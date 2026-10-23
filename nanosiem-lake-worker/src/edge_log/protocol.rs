// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire types of the tenant Worker's edge-log consumer route
//! (`/edge-log/v1/{lease,pull,commit}`, `src/edge-log-route.js`) and the
//! verified decoding of a pull response.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

use crate::parts::{edge_log_next_chain, is_sha256_hex, sha256_hex, EDGE_LOG_VERSION_PREFIX};

/// Largest pull the Worker returns (16 MiB of segments; the first segment of
/// a pull is always served and is at most 16 MiB) plus header headroom.
pub const MAX_PULL_RESPONSE_BYTES: usize = 17 * 1024 * 1024;
/// Worker-side clamps (`PULL_MAX_BYTES` in `src/edge-log.js`, the DO memory budget).
pub const MAX_PULL_BYTES: u64 = 16 * 1024 * 1024;
/// Sequences stay exact in the Worker's JS numbers (contract r3).
pub const MAX_SEQ: u64 = (1 << 53) - 1;
pub const MAX_PULL_SEGMENTS: u32 = 512;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lease {
    pub kind: String,
    pub epoch: u64,
    pub committed_through: u64,
    pub committed_chain: String,
    pub last_part_id: Option<String>,
    pub head: u64,
    /// The DO's sweep floor (segments at or below it are gone).
    #[serde(default)]
    pub floor_seq: u64,
    #[serde(default)]
    pub floor_chain: String,
    /// `do`, `drain` or `r2` (the tenant Worker's `NANO_EDGE_LOG_MODE`).
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub overflow_objects: u64,
    /// The chain value at the requested resume point, when the DO knows it.
    #[serde(default)]
    pub at_chain: Option<String>,
    /// The DO's last purge (offboarding): the only attested reason the edge
    /// log may be ahead of the consumer's part log.
    #[serde(default)]
    pub purge_seq: Option<u64>,
    #[serde(default)]
    pub purge_chain: Option<String>,
    #[serde(default)]
    pub backlog_skip: Option<super::backlog::BacklogSkipPlan>,
}

/// One verified edge segment: the exact bytes the Container's Vector sink PUT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub seq: u64,
    pub key: String,
    pub sha256: String,
    pub length: u64,
    pub prev_chain: String,
    pub chain: String,
    pub received_at_ms: i64,
    pub bytes: Vec<u8>,
}

impl Segment {
    /// `SourceObject.version` / `SourceNotice.version` for this segment.
    pub fn version(&self) -> String {
        format!("{EDGE_LOG_VERSION_PREFIX}{}", self.seq)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullBatch {
    pub committed_through: u64,
    pub head: u64,
    /// The Worker's mode when it served the pull (`drain` ends edge mode).
    pub mode: String,
    pub overflow_objects: u64,
    pub segments: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullOutcome {
    Batch(PullBatch),
    /// A newer lease exists: this consumer must stop.
    Fenced,
    /// `after` is below the committed point: another consumer committed past
    /// this one; the DO's committed point and chain are reported.
    Behind { committed_through: u64, committed_chain: String },
    /// The DO is serving another pull or raced a sweep; retry shortly.
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitRequest {
    pub epoch: u64,
    pub through: u64,
    pub through_chain: String,
    pub part_id: String,
    pub part_sha256: String,
}

impl CommitRequest {
    /// The commit for `through`. The DO's part id is an idempotency token:
    /// the binding to the part is the signed `inputs.edge_log` in its
    /// provenance, so it is derived from the range, stable across restarts.
    pub fn for_range(epoch: u64, through: u64, through_chain: &str) -> Self {
        Self {
            epoch,
            through,
            through_chain: through_chain.to_string(),
            part_id: format!("edge-through-{through}"),
            part_sha256: sha256_hex(format!("nano-edge-log-v1-commit\n{through}\n{through_chain}").as_bytes()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    Committed,
    /// The same commit already landed (a retry).
    Replayed,
    Fenced,
    Conflict { committed_through: u64 },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KindBody {
    pub kind: String,
    #[serde(default)]
    pub committed_through: Option<u64>,
    #[serde(default)]
    pub committed_chain: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PullHeader {
    kind: String,
    committed_through: u64,
    head: u64,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    overflow_objects: u64,
    #[serde(default)]
    floor_seq: u64,
    #[serde(default)]
    #[allow(dead_code)]
    floor_chain: String,
    segments: Vec<SegmentHeader>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SegmentHeader {
    seq: u64,
    key: String,
    sha256: String,
    length: u64,
    prev_chain: String,
    chain: String,
    received_at: i64,
}

/// Decode and verify a pull response: one JSON header line, then the segment
/// bytes back to back. Every segment's SHA-256 and chain link is checked,
/// and the batch must be contiguous from `after + 1`.
pub fn decode_pull(body: &[u8], after: u64) -> Result<PullBatch> {
    ensure!(body.len() <= MAX_PULL_RESPONSE_BYTES, "edge pull response exceeds its bound");
    let newline = body.iter().position(|b| *b == b'\n').context("edge pull response has no header")?;
    let header: PullHeader = serde_json::from_slice(&body[..newline]).context("edge pull header does not parse")?;
    ensure!(header.kind == "ok", "edge pull header kind is {}", header.kind);
    ensure!(header.head <= MAX_SEQ && header.committed_through <= MAX_SEQ && header.floor_seq <= MAX_SEQ,
        "edge pull header sequence is out of bounds");
    let first = after.checked_add(1).filter(|seq| *seq <= MAX_SEQ).context("edge pull sequence overflow")?;
    let mut offset = newline + 1;
    let mut segments = Vec::with_capacity(header.segments.len());
    let mut previous: Option<String> = None;
    for (expected_seq, meta) in (first..).zip(header.segments) {
        ensure!(meta.seq == expected_seq, "edge pull is not contiguous at {}", meta.seq);
        ensure!(is_sha256_hex(&meta.sha256) && is_sha256_hex(&meta.chain) && is_sha256_hex(&meta.prev_chain),
            "edge segment {} digests are malformed", meta.seq);
        let length = usize::try_from(meta.length).context("edge segment length overflows")?;
        let end = offset.checked_add(length).context("edge segment length overflows")?;
        ensure!(end <= body.len(), "edge pull body is truncated at segment {}", meta.seq);
        let bytes = body[offset..end].to_vec();
        offset = end;
        if sha256_hex(&bytes) != meta.sha256 {
            bail!("edge segment {} failed SHA-256 verification", meta.seq);
        }
        if let Some(previous) = &previous {
            ensure!(*previous == meta.prev_chain, "edge chain breaks at segment {}", meta.seq);
        }
        if edge_log_next_chain(&meta.prev_chain, meta.seq, &meta.key, &meta.sha256, meta.length) != meta.chain {
            bail!("edge chain does not recompute at segment {}", meta.seq);
        }
        previous = Some(meta.chain.clone());
        segments.push(Segment {
            seq: meta.seq,
            key: meta.key,
            sha256: meta.sha256,
            length: meta.length,
            prev_chain: meta.prev_chain,
            chain: meta.chain,
            received_at_ms: meta.received_at,
            bytes,
        });
    }
    ensure!(offset == body.len(), "edge pull response has trailing bytes");
    Ok(PullBatch {
        committed_through: header.committed_through,
        head: header.head,
        mode: header.mode,
        overflow_objects: header.overflow_objects,
        segments,
    })
}

/// Test and tooling helper: the Worker's framing (`encodeSegments`).
pub fn encode_pull(batch: &PullBatch) -> Vec<u8> {
    let header = serde_json::json!({
        "kind": "ok",
        "committedThrough": batch.committed_through,
        "head": batch.head,
        "mode": batch.mode,
        "overflowObjects": batch.overflow_objects,
        "segments": batch.segments.iter().map(|s| serde_json::json!({
            "seq": s.seq, "key": s.key, "sha256": s.sha256, "length": s.length,
            "prevChain": s.prev_chain, "chain": s.chain, "receivedAt": s.received_at_ms,
        })).collect::<Vec<_>>(),
    });
    let mut body = serde_json::to_vec(&header).expect("header serializes");
    body.push(b'\n');
    for segment in &batch.segments {
        body.extend_from_slice(&segment.bytes);
    }
    body
}
