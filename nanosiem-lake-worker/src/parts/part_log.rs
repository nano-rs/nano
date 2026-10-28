// SPDX-License-Identifier: AGPL-3.0-or-later

//! The per-tenant part log: format, append protocol and verification
//! (contract section 5).
//!
//! The log is append-only and hash-chained. Each entry is canonical JSON,
//! committed by one conditional single-PUT create of
//! `log/entries/{seq:020}.json` through the owner-authorized `lake_part_log`
//! writer class; that create is the only commit point for parts, merges,
//! retirements and consumed sources. Entries carry no signature of their own:
//! every part they name is owner-signed (its provenance record), and the
//! chain binds each entry to all entries before it.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::format::{LogKeys, PartId, MAX_LOG_OBJECT_BYTES};
use super::levels::Level;
use super::provenance::canonical_json_bytes;
use super::{event_hour_of, is_sha256_hex, sha256_hex};

pub const LOG_FORMAT: &str = "nano.part-log.v1";
pub const CHECKPOINT_FORMAT: &str = "nano.part-log-checkpoint.v1";
/// Write a checkpoint at least every this many entries.
pub const CHECKPOINT_EVERY: u64 = 1_024;
pub const MAX_ENTRY_BYTES: usize = MAX_LOG_OBJECT_BYTES;
pub const MAX_CHECKPOINT_BYTES: usize = MAX_LOG_OBJECT_BYTES;
/// How long the live set remembers added and removed part ids (for the
/// add-once rule and supersession GC). Bounds its memory to ~2 days of parts.
pub const ID_MEMORY_MS: i64 = 48 * 3_600_000;
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What a planner needs about a live part without fetching its record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartRef {
    pub part_id: PartId,
    pub level: Level,
    pub event_hour: i32,
    pub event_day: Option<i32>,
    pub rows: u64,
    pub min_time_us: i64,
    pub max_time_us: i64,
    pub schema_fingerprint: String,
    pub provenance_sha256: String,
    pub merkle_root: String,
    /// Sorted by `(time, metadata.uid)`; false only for adopted parts.
    pub sorted: bool,
    /// Total bytes over the part's data files.
    pub data_bytes: u64,
    pub row_groups: u32,
    /// Number of `data-NNNNN.parquet` files.
    pub data_files: u32,
}

impl PartRef {
    fn validate(&self) -> Result<()> {
        if self.rows == 0 || self.min_time_us > self.max_time_us || self.row_groups == 0 || self.data_files == 0 {
            bail!("part reference bounds are invalid");
        }
        for digest in [&self.schema_fingerprint, &self.provenance_sha256, &self.merkle_root] {
            if !is_sha256_hex(digest) {
                bail!("part reference digest is malformed");
            }
        }
        if (self.level == Level::Day) != self.event_day.is_some() {
            bail!("part reference day binding is invalid");
        }
        Ok(())
    }

    /// Contract 4.5: the log's reference must equal the owner-signed record
    /// on every shared field.
    pub fn check_record(&self, record: &super::provenance::ProvenanceRecord, provenance_sha256: &str) -> Result<()> {
        let same = self.part_id == record.part_id
            && self.level == record.level
            && self.event_hour == record.event_hour
            && self.event_day == record.event_day
            && self.rows == record.rows
            && self.min_time_us == record.min_time_us
            && self.max_time_us == record.max_time_us
            && self.schema_fingerprint == record.schema_fingerprint
            && self.merkle_root == record.merkle_root
            && self.provenance_sha256 == provenance_sha256
            && self.data_files as usize == record.files.data.len()
            && self.row_groups == record.files.row_groups()
            && self.data_bytes == record.files.data_bytes();
        if !same {
            bail!("log part reference {} differs from its signed record", self.part_id);
        }
        Ok(())
    }

    /// Build the reference for a signed record.
    pub fn from_record(record: &super::provenance::ProvenanceRecord, provenance_sha256: &str, sorted: bool) -> Self {
        Self {
            part_id: record.part_id.clone(),
            level: record.level,
            event_hour: record.event_hour,
            event_day: record.event_day,
            rows: record.rows,
            min_time_us: record.min_time_us,
            max_time_us: record.max_time_us,
            schema_fingerprint: record.schema_fingerprint.clone(),
            provenance_sha256: provenance_sha256.to_string(),
            merkle_root: record.merkle_root.clone(),
            sorted,
            data_bytes: record.files.data_bytes(),
            row_groups: record.files.row_groups(),
            data_files: record.files.data.len() as u32,
        }
    }

    /// True when the part's rows may intersect `[from_us, to_us]`.
    pub fn overlaps(&self, from_us: i64, to_us: i64) -> bool {
        self.min_time_us <= to_us && self.max_time_us >= from_us
    }
}

/// Contract 4.5: every L0 record of an `add` carries exactly the entry's
/// `edge_log` (both absent, or equal).
pub fn check_add_edge_log(entry_edge_log: Option<&super::provenance::EdgeLogRange>, record: &super::provenance::ProvenanceRecord) -> Result<()> {
    let record_edge = match &record.inputs {
        super::provenance::PartInputs::Sources { edge_log, .. } => edge_log.as_ref(),
        _ => bail!("add entry names a part without source inputs"),
    };
    if record_edge != entry_edge_log {
        bail!("record edge_log differs from its add entry");
    }
    Ok(())
}

/// Contract 4.5: a `merge`/`rewrite` must supersede exactly the output
/// record's input parts.
pub fn check_supersedes(supersedes: &[PartId], output: &super::provenance::ProvenanceRecord) -> Result<()> {
    let super::provenance::PartInputs::Parts { parts } = &output.inputs else {
        bail!("merge output record has no part inputs");
    };
    let mut expected = parts.iter().map(|p| &p.part_id).collect::<Vec<_>>();
    let mut actual = supersedes.iter().collect::<Vec<_>>();
    expected.sort();
    actual.sort();
    if expected != actual {
        bail!("merge supersedes parts other than its record's inputs");
    }
    Ok(())
}

/// One refused source object or its refused rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rejection {
    pub source: SourceRef,
    /// `object` (the whole object was refused, its notice acknowledged) or
    /// `rows` (only `rows_rejected` rows were refused; the rest were
    /// admitted in the same flush).
    pub scope: String,
    pub rows_rejected: u64,
    /// Stable code: `admission_invalid`, `shape_drift`, `int_truncation`,
    /// `digest_mismatch`, `missing`.
    pub reason: String,
    /// Bounded, secret-free detail (≤ 512 bytes).
    pub detail: String,
}

/// One consumed source object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub key: String,
    pub version: String,
    pub sha256: String,
}

/// A finding add is the only non-edge add allowed while the edge cursor is
/// active. Its source is an immutable receipt in this tenant's prefix.
fn finding_receipts_only(tenant_id: &str, sources: &[SourceRef]) -> bool {
    let prefix = format!("lake/parts/v1/tenant={tenant_id}/finding-outbox/receipts/");
    !sources.is_empty()
        && sources.iter().all(|source| {
            source.version == "nano.finding-outbox-receipt.v1"
                && is_sha256_hex(&source.sha256)
                && source.key == format!("{prefix}{}.json", source.sha256)
        })
}

/// NAN-3643: the source `version` of a refused bronze object re-admitted
/// from the tenant's quarantine by an operator replay.
pub const QUARANTINE_REPLAY_VERSION: &str = "nano.bronze-quarantine-replay.v1";

/// NAN-3643: the source key a quarantine replay is consumed under. It names
/// the tenant and the object's SHA-256, never another tenant's object, and
/// it is outside every bronze prefix (nothing lists or retires it).
pub fn quarantine_replay_key(tenant_id: &str, sha256: &str) -> String {
    format!("bronze-quarantine/tenant_id={tenant_id}/{sha256}.parquet")
}

/// NAN-3643: an operator replay of quarantined bronze objects of THIS tenant
/// (flushed on its own, never beside edge segments). Like a finding add, it
/// is allowed while the edge cursor is active and leaves the cursor alone.
pub fn quarantine_replays_only(tenant_id: &str, sources: &[SourceRef]) -> bool {
    !sources.is_empty()
        && sources.iter().all(|source| {
            source.version == QUARANTINE_REPLAY_VERSION
                && is_sha256_hex(&source.sha256)
                && source.key == quarantine_replay_key(tenant_id, &source.sha256)
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetireReason {
    Retention,
    Erasure,
}

/// The read schema carried in the log: the Arrow schema as the base64 of
/// an empty Parquet file written with it (the portable, lossless Arrow
/// schema encoding the parquet crate already carries), plus its fingerprint
/// (`format::schema_fingerprint`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSchema {
    pub parquet_base64: String,
    pub fingerprint: String,
}

impl LogSchema {
    pub fn from_arrow(schema: &arrow_schema::Schema) -> Result<Self> {
        use base64::Engine as _;
        let mut bytes = Vec::new();
        let writer = parquet::arrow::ArrowWriter::try_new(&mut bytes, std::sync::Arc::new(schema.clone()), None)?;
        writer.close()?;
        Ok(Self {
            parquet_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            fingerprint: super::format::schema_fingerprint(schema)?,
        })
    }

    pub fn to_arrow(&self) -> Result<arrow_schema::Schema> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.parquet_base64)
            .context("log schema is not base64")?;
        let builder = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
            .context("log schema does not decode")?;
        let schema = builder.schema().as_ref().clone();
        if super::format::schema_fingerprint(&schema)? != self.fingerprint {
            bail!("log schema fingerprint does not match its schema");
        }
        Ok(schema)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LogOp {
    Genesis { schema: LogSchema },
    Schema { schema: LogSchema },
    Add {
        parts: Vec<PartRef>,
        consumed: Vec<SourceRef>,
        /// The edge-log range this flush consumed (contract 4.1.1). Every L0
        /// record of the entry carries an identical copy in
        /// `inputs.edge_log`. Omitted when absent (r3 additive field).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        edge_log: Option<super::provenance::EdgeLogRange>,
    },
    /// The edge log's sweep floor moved past the last consumed point (the DO
    /// dropped segments this tenant never consumed, e.g. after a long
    /// outage). Recorded in the chain so the next range may start there;
    /// never moves backwards (contract 5.1).
    EdgeFloor { through_seq: u64, through_chain: String, reason: String },
    /// Source objects (or rows of them) consumed without contributing: the
    /// durable, auditable record that data was refused (contract 5.1).
    Reject { rejections: Vec<Rejection> },
    /// Leave edge-log mode (do → drain → r2), exactly at the consumed point:
    /// the consumer has committed the DO through it and seen nothing pending.
    /// Plain adds are allowed again; re-entry continues from this point
    /// (contract 4.1.1).
    EdgeEnd { through_seq: u64, through_chain: String, reason: String },
    Merge { output: PartRef, supersedes: Vec<PartId> },
    Retire { parts: Vec<PartId>, reason: RetireReason, deletion_unit: String },
    Rewrite { output: PartRef, supersedes: Vec<PartId>, deletion_unit: String },
    Adopt { parts: Vec<PartRef> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub format: String,
    pub tenant_id: String,
    pub seq: u64,
    pub prev_sha256: String,
    pub writer_epoch: u64,
    pub appended_at_ms: i64,
    pub op: LogOp,
}

impl LogEntry {
    /// Stored bytes: canonical JSON (the same canonical form as provenance
    /// records, contract 4.3).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let bytes = canonical_json_bytes(&serde_json::to_value(self)?)?;
        if bytes.len() > MAX_ENTRY_BYTES {
            bail!("log entry exceeds {MAX_ENTRY_BYTES} bytes");
        }
        Ok(bytes)
    }

    /// Parse stored bytes strictly: bounded, canonical, this tenant's.
    pub fn parse_bytes(bytes: &[u8], tenant_id: &str) -> Result<Self> {
        if bytes.len() > MAX_ENTRY_BYTES {
            bail!("log entry exceeds its byte bound");
        }
        let entry: Self = serde_json::from_slice(bytes).context("log entry does not parse")?;
        if entry.format != LOG_FORMAT || entry.tenant_id != tenant_id {
            bail!("log entry format or tenant is wrong");
        }
        if entry.to_bytes()? != bytes {
            bail!("log entry is not in canonical form");
        }
        Ok(entry)
    }
}

/// `log/checkpoints/{seq}.json`: the live set and schema at entry `seq`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub format: String,
    pub tenant_id: String,
    pub seq: u64,
    pub entry_sha256: String,
    pub writer_epoch: u64,
    pub schema: LogSchema,
    pub live: Vec<PartRef>,
    /// The edge-log point at `seq` (restart continuity). Omitted when the
    /// log never consumed from an edge log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_log: Option<EdgePoint>,
    /// Where edge mode last ended (re-entry resume point). Omitted when never
    /// ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_ended: Option<EdgePoint>,
}

/// A point on a tenant's edge-log chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgePoint {
    pub log: String,
    pub through_seq: u64,
    pub through_chain: String,
}

/// The edge-log consumer's commit to the DO must never move backwards: the
/// next committed `through_seq` is at least the last one.
pub fn check_edge_commit_monotonic(last_committed: u64, next: u64) -> Result<()> {
    if next < last_committed {
        bail!("edge log commit would regress from {last_committed} to {next}");
    }
    Ok(())
}

impl Checkpoint {
    /// Canonical bytes, or `None` when the live set does not fit one object.
    pub fn to_bytes(&self) -> Result<Option<Vec<u8>>> {
        let bytes = canonical_json_bytes(&serde_json::to_value(self)?)?;
        Ok((bytes.len() <= MAX_CHECKPOINT_BYTES).then_some(bytes))
    }

    pub fn parse_bytes(bytes: &[u8], tenant_id: &str) -> Result<Self> {
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            bail!("checkpoint exceeds its byte bound");
        }
        let checkpoint: Self = serde_json::from_slice(bytes).context("checkpoint does not parse")?;
        if checkpoint.format != CHECKPOINT_FORMAT || checkpoint.tenant_id != tenant_id {
            bail!("checkpoint format or tenant is wrong");
        }
        Ok(checkpoint)
    }
}

/// Totals over the live part set ([`LiveSet::totals`]), served on query[T]'s
/// `GET /v1/status` as `live_parts`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LivePartTotals {
    pub parts: u64,
    pub rows: u64,
    pub data_bytes: u64,
    pub data_files: u64,
    /// Event-time bounds over the live parts.
    pub min_time_us: Option<i64>,
    pub max_time_us: Option<i64>,
    /// Newest `appended_at_ms` of an entry that added a still-live part.
    pub last_added_at_ms: Option<i64>,
}

/// The live part set folded from verified entries.
///
/// Serializable so a consumer that folds the whole log (the sanctioned
/// lake-part GC view) can persist its position instead of re-reading from
/// seq 0 on every start; a persisted set is only trusted again after its
/// head entry re-verifies against the store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveSet {
    live: BTreeMap<PartId, PartRef>,
    /// Every part id ever added (a part may be added exactly once).
    seen: BTreeSet<PartId>,
    /// part id → (seq, appended_at_ms) of the entry that removed it.
    removed: BTreeMap<PartId, (u64, i64)>,
    /// The references of removed parts (for GC to find their keys).
    removed_refs: BTreeMap<PartId, PartRef>,
    /// part id → appended_at_ms of the entry that added it.
    added_at: BTreeMap<PartId, i64>,
    schema: Option<LogSchema>,
    head: Option<(u64, String, u64)>,
    /// Last edge-log point; once set, every `add` must carry a continuing
    /// `edge_log` (no bypass by interleaving plain adds).
    edge: Option<EdgePoint>,
    /// Set by `edge_end`; a later edge range must continue it.
    edge_ended: Option<EdgePoint>,
    /// Sources consumed by `add` entries applied since the last checkpoint,
    /// within the id memory window: identity → appended_at_ms. Backs the
    /// writer's double-consume guard ([`LiveSet::check_consumes`]); not a
    /// reader rule, since a checkpoint does not carry it (contract r3.3).
    #[serde(with = "consumed_serde")]
    consumed: BTreeMap<[u8; 16], i64>,
}

/// `consumed` as `[[hex identity, appended_at_ms], ...]` (JSON map keys must
/// be strings).
mod consumed_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S: Serializer>(map: &BTreeMap<[u8; 16], i64>, s: S) -> Result<S::Ok, S::Error> {
        map.iter().map(|(id, at)| (hex::encode(id), *at)).collect::<Vec<_>>().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<[u8; 16], i64>, D::Error> {
        let pairs = Vec::<(String, i64)>::deserialize(d)?;
        let mut map = BTreeMap::new();
        for (id, at) in pairs {
            let mut out = [0_u8; 16];
            hex::decode_to_slice(&id, &mut out).map_err(serde::de::Error::custom)?;
            map.insert(out, at);
        }
        Ok(map)
    }
}

/// One mutation [`LiveSet::apply`] made, so a refused entry can be undone
/// without cloning the whole set per entry (the clone made folding a long
/// log quadratic: NAN part-GC starvation).
enum Undo {
    Seen(PartId),
    Live(PartId, Option<PartRef>),
    Unlive(PartId, PartRef),
    AddedAt(PartId, Option<i64>),
    Removed(PartId, Option<(u64, i64)>),
    RemovedRef(PartId, Option<PartRef>),
    Consumed([u8; 16], Option<i64>),
}

fn source_identity(source: &SourceRef) -> [u8; 16] {
    let digest = sha256_hex(format!("{}\0{}\0{}", source.key, source.version, source.sha256).as_bytes());
    let mut out = [0_u8; 16];
    hex::decode_to_slice(&digest[..32], &mut out).expect("hex digest");
    out
}

/// An `add` would consume a source the log already consumed (B2): a retry
/// re-committing rows under new part ids. Fail-stop, never appended.
#[derive(Debug, thiserror::Error)]
#[error("add entry consumes source {key} twice")]
pub struct DoubleConsume {
    pub key: String,
}

impl LiveSet {
    pub fn from_checkpoint(checkpoint: &Checkpoint) -> Result<Self> {
        let mut set = Self::default();
        for part in &checkpoint.live {
            part.validate()?;
            if set.live.insert(part.part_id.clone(), part.clone()).is_some() {
                bail!("checkpoint repeats a part");
            }
            set.seen.insert(part.part_id.clone());
            set.added_at.insert(part.part_id.clone(), part.part_id.created_unix_ms());
        }
        set.edge = checkpoint.edge_log.clone();
        set.edge_ended = checkpoint.edge_ended.clone();
        set.schema = Some(checkpoint.schema.clone());
        set.head = Some((checkpoint.seq, checkpoint.entry_sha256.clone(), checkpoint.writer_epoch));
        Ok(set)
    }

    pub fn parts(&self) -> impl Iterator<Item = &PartRef> {
        self.live.values()
    }

    /// What the live set holds right now (NAN-3020): the lean tenant's
    /// storage facts, read from the verified log instead of any control-DB
    /// ledger. Data files only: sidecars, provenance records and superseded
    /// parts still waiting for GC are not counted.
    pub fn totals(&self) -> LivePartTotals {
        let mut totals = LivePartTotals::default();
        for part in self.live.values() {
            totals.parts += 1;
            totals.rows = totals.rows.saturating_add(part.rows);
            totals.data_bytes = totals.data_bytes.saturating_add(part.data_bytes);
            totals.data_files = totals.data_files.saturating_add(u64::from(part.data_files));
            totals.min_time_us = Some(totals.min_time_us.map_or(part.min_time_us, |t| t.min(part.min_time_us)));
            totals.max_time_us = Some(totals.max_time_us.map_or(part.max_time_us, |t| t.max(part.max_time_us)));
            if let Some(at) = self.added_at.get(&part.part_id) {
                totals.last_added_at_ms = Some(totals.last_added_at_ms.map_or(*at, |t| t.max(*at)));
            }
        }
        totals
    }

    pub fn get(&self, id: &PartId) -> Option<&PartRef> {
        self.live.get(id)
    }

    /// The last edge-log point (the consumer's restart resume point).
    pub fn edge_point(&self) -> Option<&EdgePoint> {
        self.edge.as_ref()
    }

    /// Where edge mode last ended: the resume point for re-entry.
    pub fn edge_ended(&self) -> Option<&EdgePoint> {
        self.edge_ended.as_ref()
    }

    pub fn schema(&self) -> Option<&LogSchema> {
        self.schema.as_ref()
    }

    /// `(seq, entry sha256, writer_epoch)` of the last applied entry.
    pub fn head(&self) -> Option<(u64, &str, u64)> {
        self.head.as_ref().map(|(seq, sha, epoch)| (*seq, sha.as_str(), *epoch))
    }

    /// Was this source consumed by an `add` applied since the last
    /// checkpoint (within the id memory window)?
    pub fn consumed(&self, source: &SourceRef) -> bool {
        self.consumed.contains_key(&source_identity(source))
    }

    /// Writer-side guard: refuse an `add` whose `consumed` repeats a source
    /// or overlaps sources the log already consumed.
    pub fn check_consumes(&self, op: &LogOp) -> Result<()> {
        let LogOp::Add { consumed, .. } = op else { return Ok(()) };
        let mut within = BTreeSet::new();
        for source in consumed {
            let id = source_identity(source);
            if !within.insert(id) || self.consumed.contains_key(&id) {
                return Err(DoubleConsume { key: source.key.clone() }.into());
            }
        }
        Ok(())
    }

    /// True when the log added this part id within the id memory window.
    pub fn knows(&self, id: &PartId) -> bool {
        self.seen.contains(id)
    }

    pub fn added_at_ms(&self, id: &PartId) -> Option<i64> {
        self.added_at.get(id).copied()
    }

    /// Parts removed at or before `before_ms` (for supersession GC).
    /// The reference a removed part had while live.
    pub fn removed_ref(&self, id: &PartId) -> Option<&PartRef> {
        self.removed_refs.get(id)
    }

    /// Is this id among the remembered removed parts?
    pub fn is_removed(&self, id: &PartId) -> bool {
        self.removed.contains_key(id)
    }

    pub fn removed_before(&self, before_ms: i64) -> impl Iterator<Item = &PartId> {
        self.removed.iter().filter(move |(_, (_, at))| *at <= before_ms).map(|(id, _)| id)
    }

    fn add(&mut self, part: &PartRef, at_ms: i64, undo: &mut Vec<Undo>) -> Result<()> {
        part.validate()?;
        if part.part_id.created_unix_ms() < at_ms.saturating_sub(ID_MEMORY_MS) {
            bail!("log adds part {} created outside the id memory window", part.part_id);
        }
        if !self.seen.insert(part.part_id.clone()) {
            bail!("log adds part {} twice", part.part_id);
        }
        undo.push(Undo::Seen(part.part_id.clone()));
        let previous = self.live.insert(part.part_id.clone(), part.clone());
        undo.push(Undo::Live(part.part_id.clone(), previous));
        let previous = self.added_at.insert(part.part_id.clone(), at_ms);
        undo.push(Undo::AddedAt(part.part_id.clone(), previous));
        Ok(())
    }

    fn remove(&mut self, id: &PartId, seq: u64, at_ms: i64, undo: &mut Vec<Undo>) -> Result<()> {
        let Some(part) = self.live.remove(id) else {
            bail!("log removes part {id} that is not live");
        };
        let previous = self.removed_refs.insert(id.clone(), part.clone());
        undo.push(Undo::Unlive(id.clone(), part));
        undo.push(Undo::RemovedRef(id.clone(), previous));
        let previous = self.removed.insert(id.clone(), (seq, at_ms));
        undo.push(Undo::Removed(id.clone(), previous));
        Ok(())
    }

    fn consume(&mut self, source: &SourceRef, at_ms: i64, undo: &mut Vec<Undo>) {
        let id = source_identity(source);
        let previous = self.consumed.insert(id, at_ms);
        undo.push(Undo::Consumed(id, previous));
    }

    /// Revert `undo` (newest first): the set is exactly as before the entry.
    fn rollback(&mut self, undo: Vec<Undo>) {
        fn restore<K: Ord, V>(map: &mut BTreeMap<K, V>, key: K, previous: Option<V>) {
            match previous {
                Some(value) => {
                    map.insert(key, value);
                }
                None => {
                    map.remove(&key);
                }
            }
        }
        for step in undo.into_iter().rev() {
            match step {
                Undo::Seen(id) => {
                    self.seen.remove(&id);
                }
                Undo::Live(id, previous) => restore(&mut self.live, id, previous),
                Undo::Unlive(id, part) => {
                    self.live.insert(id, part);
                }
                Undo::AddedAt(id, previous) => restore(&mut self.added_at, id, previous),
                Undo::Removed(id, previous) => restore(&mut self.removed, id, previous),
                Undo::RemovedRef(id, previous) => restore(&mut self.removed_refs, id, previous),
                Undo::Consumed(id, previous) => restore(&mut self.consumed, id, previous),
            }
        }
    }

    /// Apply one verified entry; `entry_sha256` is SHA-256 of its bytes.
    pub fn apply(&mut self, entry: &LogEntry, entry_sha256: &str) -> Result<()> {
        let expected_seq = self.head.as_ref().map_or(0, |(seq, _, _)| seq + 1);
        let expected_prev = self.head.as_ref().map_or(GENESIS_PREV, |(_, sha, _)| sha.as_str());
        let min_epoch = self.head.as_ref().map_or(0, |(_, _, epoch)| *epoch);
        if entry.seq != expected_seq || entry.prev_sha256 != expected_prev {
            bail!("log chain is broken at seq {}", entry.seq);
        }
        if entry.writer_epoch < min_epoch {
            bail!("log entry {} regresses the writer epoch", entry.seq);
        }
        // A bad entry leaves the set unchanged: every mutation is journaled
        // and undone on refusal (no per-entry clone of the whole set).
        let saved = (self.schema.clone(), self.edge.clone(), self.edge_ended.clone());
        let mut undo = Vec::new();
        if let Err(error) = self.apply_op(entry, &mut undo) {
            self.rollback(undo);
            (self.schema, self.edge, self.edge_ended) = saved;
            return Err(error);
        }
        let at = entry.appended_at_ms;
        let next = self;
        next.head = Some((entry.seq, entry_sha256.to_string(), entry.writer_epoch));
        let horizon = at.saturating_sub(ID_MEMORY_MS);
        if next.seen.first().is_some_and(|id| id.created_unix_ms() < horizon) {
            let live = &next.live;
            next.seen.retain(|id| id.created_unix_ms() >= horizon || live.contains_key(id));
            next.removed.retain(|_, (_, removed_at)| *removed_at >= horizon);
            let removed = &next.removed;
            next.removed_refs.retain(|id, _| removed.contains_key(id));
            next.added_at.retain(|id, _| live.contains_key(id));
            next.consumed.retain(|_, consumed_at| *consumed_at >= horizon);
        }
        Ok(())
    }

    /// The op of one entry, journaled into `undo` (see [`Self::apply`]).
    fn apply_op(&mut self, entry: &LogEntry, undo: &mut Vec<Undo>) -> Result<()> {
        let next = self;
        let (seq, at) = (entry.seq, entry.appended_at_ms);
        match (&entry.op, entry.seq) {
            (LogOp::Genesis { schema }, 0) => {
                schema.to_arrow()?;
                next.schema = Some(schema.clone());
            }
            (LogOp::Genesis { .. }, _) => bail!("genesis after seq 0"),
            (_, 0) => bail!("seq 0 must be genesis"),
            (LogOp::Schema { schema }, _) => {
                schema.to_arrow()?;
                next.schema = Some(schema.clone());
            }
            (LogOp::Add { parts, consumed, edge_log }, _) => {
                if parts.is_empty() || consumed.is_empty() {
                    bail!("add entry has no parts or no sources");
                }
                match (edge_log, &next.edge) {
                    (Some(range), Some(point)) => range.follows_point(&point.log, point.through_seq, &point.through_chain)?,
                    (Some(range), None) => match &next.edge_ended {
                        // Re-entry continues where edge mode ended.
                        Some(ended) => range.follows_point(&ended.log, ended.through_seq, &ended.through_chain)?,
                        // The first range starts the chain at genesis.
                        None => {
                            let genesis = super::provenance::edge_log_genesis(&entry.tenant_id);
                            range.follows_point(&format!("edgelog:{}", entry.tenant_id), 0, &genesis)?;
                        }
                    },
                    (None, Some(_))
                        if !finding_receipts_only(&entry.tenant_id, consumed)
                            && !quarantine_replays_only(&entry.tenant_id, consumed) =>
                    {
                        bail!("add without edge_log after the log consumed from an edge log")
                    }
                    (None, Some(_)) => {}
                    (None, None) => {}
                }
                if let Some(range) = edge_log {
                    if range.log != format!("edgelog:{}", entry.tenant_id) {
                        bail!("edge log range names another tenant");
                    }
                    next.edge = Some(EdgePoint {
                        log: range.log.clone(),
                        through_seq: range.through_seq,
                        through_chain: range.through_chain.clone(),
                    });
                }
                for part in parts {
                    if part.level != Level::L0 || !part.sorted {
                        bail!("add entry carries a non-L0 part");
                    }
                    next.add(part, at, undo)?;
                }
                for source in consumed {
                    next.consume(source, at, undo);
                }
            }
            (LogOp::Merge { output, supersedes }, _) | (LogOp::Rewrite { output, supersedes, .. }, _) => {
                if supersedes.is_empty() {
                    bail!("merge entry supersedes nothing");
                }
                for id in supersedes {
                    next.remove(id, seq, at, undo)?;
                }
                next.add(output, at, undo)?;
            }
            (LogOp::EdgeFloor { through_seq, through_chain, reason }, _) => {
                if !is_sha256_hex(through_chain) || reason.is_empty() || reason.len() > 256 {
                    bail!("edge floor entry is malformed");
                }
                if next.edge.as_ref().is_some_and(|point| *through_seq < point.through_seq) {
                    bail!("edge floor moves backwards");
                }
                if next.edge.is_none() && next.edge_ended.is_some() {
                    bail!("edge floor after edge mode ended");
                }
                next.edge = Some(EdgePoint {
                    log: format!("edgelog:{}", entry.tenant_id),
                    through_seq: *through_seq,
                    through_chain: through_chain.clone(),
                });
            }
            (LogOp::Reject { rejections }, _) => {
                if rejections.is_empty() || rejections.len() > 1_000 {
                    bail!("reject entry has no or too many rejections");
                }
                for r in rejections {
                    let ok = matches!(r.scope.as_str(), "object" | "rows")
                        && matches!(
                            r.reason.as_str(),
                            "admission_invalid" | "shape_drift" | "int_truncation" | "digest_mismatch" | "missing"
                        )
                        && r.detail.len() <= 512
                        && is_sha256_hex(&r.source.sha256)
                        && (r.scope == "object" || r.rows_rejected > 0);
                    if !ok {
                        bail!("reject entry is malformed");
                    }
                }
            }
            (LogOp::EdgeEnd { through_seq, through_chain, reason }, _) => {
                if !is_sha256_hex(through_chain) || reason.is_empty() || reason.len() > 256 {
                    bail!("edge end entry is malformed");
                }
                let point = next.edge.take().context("edge end outside edge mode")?;
                if point.through_seq != *through_seq || point.through_chain != *through_chain {
                    bail!("edge end is not at the consumed point");
                }
                next.edge_ended = Some(point);
            }
            (LogOp::Retire { parts, .. }, _) => {
                if parts.is_empty() {
                    bail!("retire entry names no part");
                }
                for id in parts {
                    next.remove(id, seq, at, undo)?;
                }
            }
            (LogOp::Adopt { parts }, _) => {
                if parts.is_empty() {
                    bail!("adopt entry names no part");
                }
                for part in parts {
                    if !matches!(part.level, Level::Hour | Level::Day) {
                        bail!("adopted parts must be hour or day parts");
                    }
                    // Adopted parts keep their original layout: never sorted,
                    // so never merge inputs (contract 8.1).
                    if part.sorted {
                        bail!("adopt entry carries a sorted part");
                    }
                    next.add(part, at, undo)?;
                }
            }
        }
        Ok(())
    }

    pub fn checkpoint(&self, tenant_id: &str) -> Result<Checkpoint> {
        let (seq, sha, epoch) = self.head.clone().context("empty log has no checkpoint")?;
        Ok(Checkpoint {
            format: CHECKPOINT_FORMAT.to_string(),
            tenant_id: tenant_id.to_string(),
            seq,
            entry_sha256: sha,
            writer_epoch: epoch,
            schema: self.schema.clone().context("log has no schema")?,
            live: self.live.values().cloned().collect(),
            edge_log: self.edge.clone(),
            edge_ended: self.edge_ended.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Object store seam
// ---------------------------------------------------------------------------

/// Owner writer class of an object (the platform).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriterClass {
    /// Part files and `log/checkpoints/…`.
    LakePart,
    /// `log/entries/{seq:020}.json`: create-if-absent, single PUT only.
    LakePartLog,
}

/// What the owner authorization of one write needs besides the key and bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteHints {
    pub class: WriterClass,
    /// Parts: the part's event hour (a day part: its first hour). Log
    /// entries and checkpoints: the APPEND hour, `event_hour_of(appended_at)`.
    pub event_hour: i32,
    pub min_time_ms: i64,
    pub max_time_ms: i64,
}

/// The owner refused an authorization with 409: the log sequence number is
/// already taken by another writer. Treated exactly like a lost conditional
/// create: the appender is fenced.
#[derive(Debug, thiserror::Error)]
#[error("owner reported a writer conflict for {key}")]
pub struct OwnerConflict {
    pub key: String,
}

/// How long a part-log entry or checkpoint reservation must sit idle before
/// the owner lets a different request take its key over (enterprise
/// migration 9010560; NAN-3181). Kept in lockstep with that migration.
pub const LOG_KEY_TAKEOVER_IDLE: std::time::Duration = std::time::Duration::from_secs(90);

/// The owner refused to authorize a part-log entry or checkpoint key with
/// 409 because an earlier attempt's reservation of that key is still open:
/// typically one whose process died, or whose PUT failed, between reserve and
/// complete. NOT a fence: nobody committed the key (a commit is the
/// conditional create, and a lost one is [`Fenced`]). The owner hands the key
/// to a new request once the old reservation has been idle for
/// [`LOG_KEY_TAKEOVER_IDLE`], so the caller retries in-process.
///
/// The owner sends the same 409 for a key that is already completed (never
/// taken over). [`PartLogWriter::append`] tells the two apart by probing the
/// key (NAN-3493): an existing entry fences instead of retrying forever.
#[derive(Debug, thiserror::Error)]
#[error("part-log key {key} is held by an unfinished earlier reservation; retrying in-process (the owner hands it over after {} s idle)", LOG_KEY_TAKEOVER_IDLE.as_secs())]
pub struct LogKeyHeld {
    pub key: String,
}

/// The storage operations the part model needs. Production: the tenant
/// bucket through the owner writer authority (`lake_part` / `lake_part_log`
/// classes, conditional single PUT). Tests and the lab use
/// [`LocalObjectStore`].
/// Largest single [`ObjectStore::get_range`] the ingest S3 store serves (the
/// Iceberg-export budget). Callers that need more (counts-only column
/// chunks, count-hint footers: NAN-3801) read consecutive ranges of at most
/// this size, so memory stays bounded by one chunk per read in flight.
pub const MAX_RANGE_GET_BYTES: u64 = 4 * 1024 * 1024;

#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Optional local producer tier, called only after owner-signature verification.
    async fn warm_signed_file(&self, _key: &str, _path: &Path, _sha256: &str, _bytes: u64) -> Result<bool> { Ok(false) }
    /// A bounded read. Unsupported stores fail instead of downloading the
    /// entire object behind a ranged-read caller's byte budget.
    async fn get_range(&self, _key: &str, _range: std::ops::Range<u64>) -> Result<Option<Vec<u8>>> {
        bail!("object store does not support ranged reads")
    }
    /// Exact immutable object length for bounded export verification.
    async fn object_size(&self, _key: &str) -> Result<Option<u64>> { bail!("object size unsupported") }
    /// NAN-4614: the object's strong identity (its ETag, or a local
    /// equivalent that changes whenever the object is replaced) and length,
    /// in one HEAD. `None` when the object is absent OR the store cannot
    /// tell; callers must treat `None` as unknown (and verify in full).
    async fn object_identity(&self, _key: &str) -> Result<Option<(String, u64)>> { Ok(None) }
    /// NAN-4181: the object's Last-Modified time (unix ms). `None` when the
    /// object is absent OR the store cannot tell; callers must treat `None`
    /// as "unknown" (finding attempt lookups then list every marker).
    async fn modified_ms(&self, _key: &str) -> Result<Option<i64>> { Ok(None) }
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    /// Stream an object to a local file; `Ok(false)` when it does not exist.
    /// Stores override this to avoid holding large objects in memory.
    async fn get_to_file(&self, key: &str, path: &Path) -> Result<bool> {
        match self.get(key).await? {
            Some(bytes) => {
                std::fs::write(path, bytes)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
    /// Conditional create (`If-None-Match: *`, one PUT). `Ok(false)` when the
    /// key already exists; the existing bytes are never replaced. An owner
    /// 409 is `Err(OwnerConflict)`.
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool>;
    /// [`Self::put_if_absent`] with the owner authorization hints. Stores
    /// without an owner plane ignore them.
    async fn put_if_absent_with(&self, key: &str, bytes: &[u8], _hints: &WriteHints) -> Result<bool> {
        self.put_if_absent(key, bytes).await
    }
    /// Conditional create streaming a local file whose SHA-256 (lowercase
    /// hex) and size are known. The checksummed R2 store sends the digest as
    /// `x-amz-checksum-sha256` (NAN-2884); others read the file.
    async fn put_file_if_absent_with(
        &self,
        key: &str,
        path: &Path,
        sha256_hex: &str,
        bytes: u64,
        hints: &WriteHints,
    ) -> Result<bool> {
        let body = std::fs::read(path)?;
        if body.len() as u64 != bytes || super::sha256_hex(&body) != sha256_hex {
            bail!("local file changed before upload");
        }
        self.put_if_absent_with(key, &body, hints).await
    }
    /// Customer export upload seam. Serving writers retain their existing
    /// authorization and upload behavior; export stores may stream privately
    /// staged files through a separate conditional single-PUT transport.
    async fn put_export_file_if_absent(
        &self, key: &str, path: &Path, sha256_hex: &str, bytes: u64, hints: &WriteHints,
    ) -> Result<bool> {
        self.put_file_if_absent_with(key, path, sha256_hex, bytes, hints).await
    }
    /// NAN-3499: register an object ANOTHER principal already stored (the
    /// detect finding drain PUTs finding parts with its own credential) with
    /// the owner writer authority: authorize, provider HEAD, complete. The
    /// completion receipt is what control's lake_part delete attestor needs;
    /// a committed part file without one is undeletable (NL007, 404).
    /// `Ok(true)`: the authority holds a completion receipt for exactly
    /// these bytes. `Ok(false)`: this store has no writer authority (lab,
    /// tests). Never writes the object.
    async fn register_existing_with(&self, _key: &str, _sha256_hex: &str, _bytes: u64, _hints: &WriteHints) -> Result<bool> {
        Ok(false)
    }
    /// Unconditional overwrite. The part log never uses it; production
    /// part stores refuse it.
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
    /// Keys under a prefix. Used by GC and checkpoint discovery only; never
    /// by the read path.
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
    /// NAN-4160: one bounded page of [`Self::list`]: at most `limit` keys
    /// under `prefix` strictly after `start_after`, in key order. Paged
    /// stores override it so a caller never pays for the whole prefix; the
    /// default (lab/test stores) filters a full listing.
    async fn list_page(&self, prefix: &str, start_after: Option<&str>, limit: usize) -> Result<Vec<String>> {
        let mut keys = self.list(prefix).await?;
        keys.retain(|key| start_after.is_none_or(|after| key.as_str() > after));
        keys.sort_unstable();
        keys.truncate(limit);
        Ok(keys)
    }
}

/// A directory-backed store with atomic conditional create (`O_EXCL` on a
/// fully written temp file via `link`). Lab and tests only: it keeps every
/// object forever and shares inodes with ingest's cache (so cache eviction
/// frees nothing); production cells use `R2PartStore`.
///
/// A setgid root is a lake cell's shared `<T>/parts` (ingest-owned, mode
/// 02770): trusted-local detect[T] runs under its own uid with the tenant gid
/// and stages finding parts and receipts there. Every role jails with umask
/// 027, so directories it creates would be group read-only and the other role
/// could never write beneath them. Under a setgid root the store therefore
/// creates the directories leading to `tenant=<T>/` and the detect-writable
/// leaves (`parts/`, `finding-outbox/`) group-writable; `log/` and every
/// other subtree keep the umask (detect never appends the log).
#[derive(Debug, Clone)]
pub struct LocalObjectStore {
    root: PathBuf,
    shared_group: bool,
}

/// Mode for directories a setgid store shares with the tenant gid.
const SHARED_DIR_MODE: u32 = 0o2770;
/// `tenant=<T>/` children the detect role stages into (NAN-2916 leaves).
const SHARED_TENANT_LEAVES: [&str; 2] = ["parts", "finding-outbox"];

impl LocalObjectStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(root.as_ref())?;
        let shared_group = std::fs::metadata(root.as_ref())?.permissions().mode() & 0o2000 != 0;
        Ok(Self { root: root.as_ref().to_path_buf(), shared_group })
    }

    /// Create `path`'s parent directories; see the type docs for the
    /// group-shared layout under a setgid root.
    fn create_parent(&self, path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let parent = path.parent().context("object key has no parent")?;
        if !self.shared_group {
            std::fs::create_dir_all(parent)?;
            return Ok(());
        }
        let relative = parent.strip_prefix(&self.root).context("object path is outside the store root")?;
        let parts = relative.iter().collect::<Vec<_>>();
        let tenant_at = parts.iter().position(|c| c.to_str().is_some_and(|c| c.starts_with("tenant=")));
        let mut dir = self.root.clone();
        for (depth, component) in parts.iter().enumerate() {
            dir.push(component);
            let shared = tenant_at.is_some_and(|at| depth <= at
                || parts.get(at + 1).and_then(|c| c.to_str()).is_some_and(|c| SHARED_TENANT_LEAVES.contains(&c)));
            match std::fs::create_dir(&dir) {
                // umask strips group write from the mkdir mode; set it explicitly.
                Ok(()) if shared => std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(SHARED_DIR_MODE))?,
                Ok(()) => {}
                // Repair a tree created before the shared layout: only the
                // owner may chmod, so the other role skips it (EPERM).
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if shared && std::fs::metadata(&dir)?.permissions().mode() & 0o070 != 0o070 {
                        match std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(SHARED_DIR_MODE)) {
                            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
                            other => other?,
                        }
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub fn path(&self, key: &str) -> Result<PathBuf> {
        if key.is_empty() || key.starts_with('/') || key.split('/').any(|s| s.is_empty() || s == "." || s == "..") {
            bail!("object key is invalid");
        }
        Ok(self.root.join(key))
    }

    /// NAN-4766: where [`ObjectStore::list`] starts its walk: the deepest
    /// directory the prefix names, so listing one part directory (or the GC
    /// tombstones) no longer walks the tenant's whole store. Every key under
    /// `prefix` lives below it; the walk still filters by `prefix`. Falls
    /// back to the root for a prefix with no valid directory, and for one
    /// whose directory path crosses a symlink (the root walk never followed
    /// symlinked directories, so neither does this).
    fn list_base(&self, prefix: &str) -> PathBuf {
        let Some((dir, _)) = prefix.rsplit_once('/') else { return self.root.clone() };
        let Ok(base) = self.path(dir) else { return self.root.clone() };
        let mut current = self.root.clone();
        for component in Path::new(dir).components() {
            current.push(component);
            match std::fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_dir() => {}
                // Absent: nothing under the prefix (the walk lists nothing).
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return base,
                _ => return self.root.clone(),
            }
        }
        base
    }

    fn temp_path(&self, path: &Path) -> PathBuf {
        let name = format!(".tmp-{}", uuid::Uuid::new_v4().simple());
        path.with_file_name(name)
    }

    fn write_temp(&self, path: &Path, bytes: &[u8]) -> Result<PathBuf> {
        use std::io::Write;
        self.create_parent(path)?;
        let temp = self.temp_path(path);
        let mut file = std::fs::File::create_new(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(temp)
    }
}

#[async_trait]
impl ObjectStore for LocalObjectStore {
    async fn object_size(&self, key: &str) -> Result<Option<u64>> {
        match std::fs::metadata(self.path(key)?) {
            Ok(meta) => Ok(Some(meta.len())),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    async fn object_identity(&self, key: &str) -> Result<Option<(String, u64)>> {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(self.path(key)?) {
            // Any rewrite or replacement moves the inode or a timestamp.
            Ok(meta) => Ok(Some((
                format!("\"{:x}-{:x}-{:x}.{:x}-{:x}.{:x}\"", meta.ino(), meta.len(), meta.mtime(), meta.mtime_nsec(), meta.ctime(), meta.ctime_nsec()),
                meta.len(),
            ))),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    async fn modified_ms(&self, key: &str) -> Result<Option<i64>> {
        match std::fs::metadata(self.path(key)?) {
            Ok(meta) => Ok(meta.modified().ok()
                .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|at| at.as_millis() as i64)),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    async fn get_range(&self, key: &str, range: std::ops::Range<u64>) -> Result<Option<Vec<u8>>> {
        let path = self.path(key)?;
        // Footer probes run under a short optional-evidence budget. Parts
        // can live on a network mount; a synchronous read on a Tokio worker
        // would prevent the timeout (and native fallback) from being polled.
        tokio::task::spawn_blocking(move || {
            use std::io::{Read, Seek, SeekFrom};
            let mut file = match std::fs::File::open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let bytes = range.end.checked_sub(range.start).context("invalid object range")?;
            if bytes > super::format::MAX_OBJECT_BYTES { bail!("object range exceeds size cap") }
            if range.end > file.metadata()?.len() { bail!("object range exceeds file") }
            file.seek(SeekFrom::Start(range.start))?;
            let mut body = vec![0; usize::try_from(bytes)?];
            file.read_exact(&mut body)?;
            Ok(Some(body))
        }).await?
    }

    async fn get_to_file(&self, key: &str, path: &Path) -> Result<bool> {
        match std::fs::copy(self.path(key)?, path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.path(key)?) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let path = self.path(key)?;
        let temp = self.write_temp(&path, bytes)?;
        // hard_link fails with AlreadyExists atomically: the conditional create.
        let result = std::fs::hard_link(&temp, &path);
        let _ = std::fs::remove_file(&temp);
        match result {
            Ok(()) => {
                sync_parent(&path)?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Hard-link the local file in (no second copy on the same filesystem),
    /// falling back to a copy across filesystems.
    async fn put_file_if_absent_with(
        &self,
        key: &str,
        source: &Path,
        sha256_hex: &str,
        bytes: u64,
        _hints: &WriteHints,
    ) -> Result<bool> {
        let (len, digest) = file_sha256(source)?;
        if len != bytes || digest != sha256_hex {
            bail!("local file changed before upload");
        }
        let path = self.path(key)?;
        self.create_parent(&path)?;
        // Durable before it becomes visible under its key.
        std::fs::File::open(source)?.sync_all()?;
        let result = match std::fs::hard_link(source, &path) {
            Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                let temp = self.temp_path(&path);
                std::fs::copy(source, &temp)?;
                std::fs::File::open(&temp)?.sync_all()?;
                let linked = std::fs::hard_link(&temp, &path);
                let _ = std::fs::remove_file(&temp);
                linked
            }
            other => other,
        };
        match result {
            Ok(()) => {
                sync_parent(&path)?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        let path = self.path(key)?;
        let temp = self.write_temp(&path, bytes)?;
        std::fs::rename(&temp, &path)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        match std::fs::remove_file(self.path(key)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut stack = vec![self.list_base(prefix)];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if entry.file_type()?.is_dir() {
                    stack.push(path);
                } else if let Ok(relative) = path.strip_prefix(&self.root) {
                    let key = relative.to_string_lossy().replace('\\', "/");
                    if key.starts_with(prefix) && !key.rsplit('/').next().unwrap_or("").starts_with(".tmp-") {
                        keys.push(key);
                    }
                }
            }
        }
        keys.sort();
        Ok(keys)
    }
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn file_sha256(path: &Path) -> Result<(u64, String)> {
    use sha2::Digest as _;
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((total, hex::encode(hasher.finalize())))
}

// ---------------------------------------------------------------------------
// Reader and writer
// ---------------------------------------------------------------------------

/// Read and verify a tenant's log, starting from the newest checkpoint.
/// Returns the live set at the head. O(entries after the checkpoint).
///
/// A checkpoint is trusted only if the entry it names exists with the
/// recorded SHA-256; every part a reader then fetches is verified against
/// its owner-signed provenance record.
pub(crate) fn is_snapshot_checkpoint_key(key: &str) -> bool {
    key.rsplit('/').next().is_some_and(|name| name.len() == 25
        && name.ends_with(".json") && name.as_bytes()[..20].iter().all(u8::is_ascii_digit))
}

pub async fn load_log(store: &dyn ObjectStore, tenant_id: &str) -> Result<LiveSet> {
    let log_keys = LogKeys::new(tenant_id)?;
    let mut set = LiveSet::default();
    let checkpoints = store.list(&log_keys.checkpoints_prefix()).await?;
    for key in checkpoints.iter().rev() {
        // Other ingest-owned checkpoint-side metadata is not a log snapshot.
        if !is_snapshot_checkpoint_key(key) {
            continue;
        }
        let Some(bytes) = store.get(key).await? else { continue };
        match Checkpoint::parse_bytes(&bytes, tenant_id) {
            Ok(checkpoint) => {
                let entry_bytes = store
                    .get(&log_keys.entry(checkpoint.seq))
                    .await?
                    .context("checkpoint names a missing entry")?;
                if sha256_hex(&entry_bytes) != checkpoint.entry_sha256 {
                    bail!("checkpoint does not match its entry");
                }
                set = LiveSet::from_checkpoint(&checkpoint)?;
                break;
            }
            Err(error) => tracing::warn!(%key, error = %error, "skipping unreadable part-log checkpoint"),
        }
    }
    catch_up(store, tenant_id, &mut set).await?;
    Ok(set)
}

/// Apply every entry after the set's head. O(new entries).
///
/// Entries are fetched in windows that double from 1 to
/// [`CATCH_UP_MAX_WINDOW`] while every entry of a window exists, and are
/// applied strictly in order: a short tail costs a few GETs, a long one
/// (up to [`CHECKPOINT_EVERY`] entries after a checkpoint) is no longer one
/// serial round trip per entry (NAN-3067: every finding drain pass loads
/// the log).
pub async fn catch_up(store: &dyn ObjectStore, tenant_id: &str, set: &mut LiveSet) -> Result<u64> {
    let log_keys = LogKeys::new(tenant_id)?;
    let mut applied = 0;
    let mut window = 1_u64;
    loop {
        let first = set.head().map_or(0, |(seq, _, _)| seq + 1);
        let fetched = futures::future::try_join_all((first..first + window)
            .map(|seq| { let key = log_keys.entry(seq); async move { store.get(&key).await } })).await?;
        let complete = fetched.iter().all(Option::is_some);
        for bytes in fetched {
            let Some(bytes) = bytes else { return Ok(applied) };
            let entry = LogEntry::parse_bytes(&bytes, tenant_id)?;
            set.apply(&entry, &sha256_hex(&bytes))?;
            applied += 1;
            crate::part_ingest::startup::advance("part-log catch-up");
        }
        if complete {
            window = (window * 2).min(CATCH_UP_MAX_WINDOW);
        }
    }
}

/// Most entry GETs [`catch_up`] has in flight.
pub const CATCH_UP_MAX_WINDOW: u64 = 32;

/// NAN-4691: the part log's head and its schema there, and nothing else.
///
/// The finding drain publishes parts in the log's current schema; it never
/// reads the live set. Folding a [`LiveSet`] (every live part, plus the
/// ids, removals and consumptions inside the id memory horizon) made its
/// memory grow with the tenant's log: with the live set, and with the whole
/// history inside the 48 h horizon wherever no checkpoint fits one log
/// object or a replay proof starts at genesis. The drain-only detect[T] runs
/// at 256 MiB-1 GiB (NAN-4690). This view is O(schema + one fetch window),
/// whatever the log's length or live set.
///
/// It verifies exactly what a reader must: the checkpoint's entry digest,
/// then every later entry's sequence, hash chain and writer epoch, and every
/// schema it adopts (`LogSchema::to_arrow` checks the fingerprint). It does
/// not re-check the live-set rules of `Add`/`Merge`/...: the drain never
/// relies on them, and the owner (ingest[T]) checks its append against its
/// own folded log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogSchemaView {
    head: Option<(u64, String, u64)>,
    schema: Option<LogSchema>,
}

impl LogSchemaView {
    pub fn head(&self) -> Option<(u64, &str, u64)> {
        self.head.as_ref().map(|(seq, sha, epoch)| (*seq, sha.as_str(), *epoch))
    }

    pub fn schema(&self) -> Option<&LogSchema> {
        self.schema.as_ref()
    }

    /// Apply one entry; `entry_sha256` is SHA-256 of its bytes. A refused
    /// entry leaves the view unchanged.
    pub fn apply(&mut self, entry: &LogEntry, entry_sha256: &str) -> Result<()> {
        let expected_seq = self.head.as_ref().map_or(0, |(seq, _, _)| seq + 1);
        let expected_prev = self.head.as_ref().map_or(GENESIS_PREV, |(_, sha, _)| sha.as_str());
        let min_epoch = self.head.as_ref().map_or(0, |(_, _, epoch)| *epoch);
        if entry.seq != expected_seq || entry.prev_sha256 != expected_prev {
            bail!("log chain is broken at seq {}", entry.seq);
        }
        if entry.writer_epoch < min_epoch {
            bail!("log entry {} regresses the writer epoch", entry.seq);
        }
        match (&entry.op, entry.seq) {
            (LogOp::Genesis { schema }, 0) => {
                schema.to_arrow()?;
                self.schema = Some(schema.clone());
            }
            (LogOp::Genesis { .. }, _) => bail!("genesis after seq 0"),
            (_, 0) => bail!("seq 0 must be genesis"),
            (LogOp::Schema { schema }, _) => {
                schema.to_arrow()?;
                self.schema = Some(schema.clone());
            }
            _ => {}
        }
        self.head = Some((entry.seq, entry_sha256.to_owned(), entry.writer_epoch));
        Ok(())
    }
}

/// A checkpoint's head and schema; its live list is skipped while parsing
/// (`IgnoredAny` allocates nothing for it).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointSchemaOnly {
    format: String,
    tenant_id: String,
    seq: u64,
    entry_sha256: String,
    writer_epoch: u64,
    schema: LogSchema,
    #[allow(dead_code)]
    live: serde::de::IgnoredAny,
    #[allow(dead_code)]
    #[serde(default)]
    edge_log: Option<serde::de::IgnoredAny>,
    #[allow(dead_code)]
    #[serde(default)]
    edge_ended: Option<serde::de::IgnoredAny>,
}

/// [`load_log`] for a consumer that needs only the head and the schema
/// ([`LogSchemaView`]): the same newest-valid-checkpoint choice and digest
/// check, then [`catch_up_schema`]. Memory is bounded by one checkpoint
/// object ([`MAX_CHECKPOINT_BYTES`]) and one fetch window, never by the
/// log's history.
pub async fn load_log_schema(store: &dyn ObjectStore, tenant_id: &str) -> Result<LogSchemaView> {
    let log_keys = LogKeys::new(tenant_id)?;
    let mut view = LogSchemaView::default();
    let checkpoints = store.list(&log_keys.checkpoints_prefix()).await?;
    for key in checkpoints.iter().rev() {
        if !is_snapshot_checkpoint_key(key) {
            continue;
        }
        let Some(bytes) = store.get(key).await? else { continue };
        let parsed = (|| -> Result<CheckpointSchemaOnly> {
            if bytes.len() > MAX_CHECKPOINT_BYTES {
                bail!("checkpoint exceeds its byte bound");
            }
            let checkpoint: CheckpointSchemaOnly = serde_json::from_slice(&bytes).context("checkpoint does not parse")?;
            if checkpoint.format != CHECKPOINT_FORMAT || checkpoint.tenant_id != tenant_id {
                bail!("checkpoint format or tenant is wrong");
            }
            checkpoint.schema.to_arrow()?;
            Ok(checkpoint)
        })();
        drop(bytes);
        match parsed {
            Ok(checkpoint) => {
                let entry_bytes = store
                    .get(&log_keys.entry(checkpoint.seq))
                    .await?
                    .context("checkpoint names a missing entry")?;
                if sha256_hex(&entry_bytes) != checkpoint.entry_sha256 {
                    bail!("checkpoint does not match its entry");
                }
                view.head = Some((checkpoint.seq, checkpoint.entry_sha256, checkpoint.writer_epoch));
                view.schema = Some(checkpoint.schema);
                break;
            }
            Err(error) => tracing::warn!(%key, error = %error, "skipping unreadable part-log checkpoint"),
        }
    }
    catch_up_schema(store, tenant_id, &mut view).await?;
    Ok(view)
}

/// [`catch_up`] for a [`LogSchemaView`]: the same doubling fetch windows,
/// each entry verified in order and dropped once applied.
pub async fn catch_up_schema(store: &dyn ObjectStore, tenant_id: &str, view: &mut LogSchemaView) -> Result<u64> {
    let log_keys = LogKeys::new(tenant_id)?;
    let mut applied = 0;
    let mut window = 1_u64;
    loop {
        let first = view.head().map_or(0, |(seq, _, _)| seq + 1);
        let fetched = futures::future::try_join_all((first..first + window)
            .map(|seq| { let key = log_keys.entry(seq); async move { store.get(&key).await } })).await?;
        let complete = fetched.iter().all(Option::is_some);
        for bytes in fetched {
            let Some(bytes) = bytes else { return Ok(applied) };
            let entry = LogEntry::parse_bytes(&bytes, tenant_id)?;
            view.apply(&entry, &sha256_hex(&bytes))?;
            applied += 1;
        }
        if complete {
            window = (window * 2).min(CATCH_UP_MAX_WINDOW);
        }
    }
}

/// Result of an append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendOutcome {
    Committed { seq: u64, entry_sha256: String },
}

/// The writer was fenced: another writer committed this sequence number.
/// The caller must drop derived state, reload, and exit.
#[derive(Debug, thiserror::Error)]
#[error("part log seq {seq} was committed by another writer")]
pub struct Fenced {
    pub seq: u64,
}

/// NAN-4052: an authority every append must pass right before its commit
/// (the cell writer lease, `part_ingest::writer_lease`). Refusing stops the
/// writer before it can race a successor; the storage fences stay the last
/// line.
pub trait AppendGate: Send + Sync {
    fn check_append(&self) -> Result<()>;
}

/// The single appender for one tenant (contract 5.2).
pub struct PartLogWriter<'a> {
    store: &'a dyn ObjectStore,
    tenant_id: String,
    log_keys: LogKeys,
    writer_epoch: u64,
    set: LiveSet,
    /// Appends refused with [`LogKeyHeld`] since open (health counter).
    key_held_total: u64,
    /// NAN-3810: appends whose owner writer completion returned (control
    /// holds their receipt), for the GC index watermark. Only stores whose
    /// `Ok(true)` create includes that completion may set it.
    receipted: Option<std::sync::Arc<crate::lake_part_gc::index::ReceiptedAppends>>,
    /// NAN-4052: checked before every commit.
    gate: Option<std::sync::Arc<dyn AppendGate>>,
    /// NAN-4444: the last attempted entry whose create outcome is unknown (an
    /// error, a timeout or a cancelled append after the PUT may have been
    /// sent). Set before the create and cleared on every definite outcome. A
    /// retry of the same op at the same head re-sends these IDENTICAL bytes
    /// (same `appended_at_ms`, hence the same owner request), so an earlier
    /// PUT that landed resolves as this append instead of a foreign writer.
    pending: Option<LogEntry>,
}

impl<'a> PartLogWriter<'a> {
    /// Open the log (creating genesis with `initial_schema` when empty).
    pub async fn open(
        store: &'a dyn ObjectStore,
        tenant_id: &str,
        writer_epoch: u64,
        initial_schema: &arrow_schema::Schema,
        now_ms: i64,
    ) -> Result<Self> {
        let set = load_log(store, tenant_id).await?;
        if let Some((_, _, epoch)) = set.head() {
            if epoch > writer_epoch {
                bail!("writer epoch {writer_epoch} is older than the log's {epoch}");
            }
        }
        let mut writer =
            Self { store, tenant_id: tenant_id.to_string(), log_keys: LogKeys::new(tenant_id)?, writer_epoch, set, key_held_total: 0, receipted: None, gate: None, pending: None };
        if writer.set.head().is_none() {
            writer.append(LogOp::Genesis { schema: LogSchema::from_arrow(initial_schema)? }, now_ms).await?;
        }
        Ok(writer)
    }

    pub fn live(&self) -> &LiveSet {
        &self.set
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// NAN-3810: record every append committed by a completed owner write
    /// (a create that returned `Ok(true)`) into `receipted`. Only wire this
    /// when the store's `Ok(true)` means the writer completion receipt was
    /// accepted (the native-writer R2 store); other commit paths are never
    /// recorded.
    pub fn set_receipted_appends(&mut self, receipted: std::sync::Arc<crate::lake_part_gc::index::ReceiptedAppends>) {
        self.receipted = Some(receipted);
    }

    /// NAN-4052: refuse every later append unless `gate` admits it.
    pub fn set_append_gate(&mut self, gate: std::sync::Arc<dyn AppendGate>) {
        self.gate = Some(gate);
    }

    /// Appends refused because an earlier reservation still held the entry
    /// key ([`LogKeyHeld`]) since this writer opened.
    pub fn log_key_held_total(&self) -> u64 {
        self.key_held_total
    }

    fn log_hints(now_ms: i64) -> WriteHints {
        WriteHints {
            class: WriterClass::LakePartLog,
            event_hour: event_hour_of(now_ms.saturating_mul(1_000)),
            min_time_ms: now_ms,
            max_time_ms: now_ms,
        }
    }

    /// Append one op. The conditional single-PUT create of the entry is the
    /// commit. A lost create (412 or owner 409 with ANOTHER writer's entry)
    /// fences. NAN-4444: an entry this writer itself landed under an
    /// ambiguous earlier attempt (R2 500 or a timeout after the bytes were
    /// stored) is adopted, never fenced: see [`Self::is_own_entry`].
    pub async fn append(&mut self, op: LogOp, now_ms: i64) -> Result<AppendOutcome> {
        loop {
            let (seq, prev) = match self.set.head() {
                Some((seq, sha, _)) => (seq + 1, sha.to_string()),
                None => (0, GENESIS_PREV.to_string()),
            };
            // An unresolved attempt at another head is moot: the head moved.
            let pending = self.pending.take().filter(|pending| pending.seq == seq && pending.prev_sha256 == prev);
            let entry = match pending {
                // The same op again: re-send the identical bytes.
                Some(pending) if pending.op == op => pending,
                // A different op while an earlier one is unresolved: settle
                // the earlier one first (one GET) so a landed earlier entry is
                // adopted instead of fencing this append.
                Some(pending) => {
                    if self.settle_pending(pending, now_ms).await? {
                        continue;
                    }
                    self.new_entry(seq, prev, op.clone(), now_ms)
                }
                None => self.new_entry(seq, prev, op.clone(), now_ms),
            };
            return self.create(entry, now_ms).await;
        }
    }

    fn new_entry(&self, seq: u64, prev_sha256: String, op: LogOp, now_ms: i64) -> LogEntry {
        LogEntry {
            format: LOG_FORMAT.to_string(),
            tenant_id: self.tenant_id.clone(),
            seq,
            prev_sha256,
            writer_epoch: self.writer_epoch,
            appended_at_ms: now_ms,
            op,
        }
    }

    /// One conditional create of `entry` (its own `appended_at_ms` drives the
    /// owner hints, so a re-send is the same owner request).
    async fn create(&mut self, entry: LogEntry, now_ms: i64) -> Result<AppendOutcome> {
        let seq = entry.seq;
        let bytes = entry.to_bytes()?;
        let sha = sha256_hex(&bytes);
        // Validate against a scratch copy before committing anything.
        self.set.check_consumes(&entry.op)?;
        let mut next = self.set.clone();
        next.apply(&entry, &sha)?;
        let key = self.log_keys.entry(seq);
        if let Some(gate) = &self.gate {
            gate.check_append()?;
        }
        let hints = Self::log_hints(entry.appended_at_ms);
        // Survives an error AND a cancelled future: the PUT may land either way.
        self.pending = Some(entry.clone());
        match self.store.put_if_absent_with(&key, &bytes, &hints).await {
            Ok(true) => {
                self.pending = None;
                if let Some(receipted) = &self.receipted {
                    receipted.record(seq, entry.appended_at_ms);
                }
            }
            Ok(false) => {
                let existing = self.store.get(&key).await?.context("conflicting entry vanished")?;
                self.pending = None;
                if existing != bytes {
                    return self.adopt_or_fence(&entry, &existing, now_ms).await;
                }
            }
            Err(error) if error.downcast_ref::<OwnerConflict>().is_some() => {
                // R2 409 (a concurrent conditional write won): under a degraded
                // provider that write can be this writer's own earlier attempt.
                self.pending = None;
                return match self.store.get(&key).await {
                    Ok(Some(existing)) if existing == bytes => self.committed(seq, next, sha, now_ms).await,
                    Ok(Some(existing)) => self.adopt_or_fence(&entry, &existing, now_ms).await,
                    Ok(None) | Err(_) => Err(Fenced { seq }.into()),
                };
            }
            Err(error) => {
                if error.chain().any(|cause| cause.downcast_ref::<LogKeyHeld>().is_some()) {
                    self.key_held_total = self.key_held_total.saturating_add(1);
                    // NAN-3493: the owner also answers 409 for a key that is
                    // already COMPLETED, and a completed key is never taken
                    // over. Probe the key: an entry holding these bytes is
                    // this append; one this writer landed earlier (NAN-4444)
                    // is adopted; any other writer's entry fences (reload and
                    // respawn). A probe failure keeps the retry.
                    match self.store.get(&key).await {
                        Ok(Some(existing)) if existing == bytes => {
                            self.pending = None;
                            tracing::warn!(seq, key = %key, "part-log entry key held but already holds this entry; committed");
                            return self.committed(seq, next, sha, now_ms).await;
                        }
                        Ok(Some(existing)) => {
                            self.pending = None;
                            return self.adopt_or_fence(&entry, &existing, now_ms).await;
                        }
                        Ok(None) => {}
                        Err(probe) => tracing::warn!(seq, key = %key, error = %format!("{probe:#}"),
                            "part-log held-key probe failed; retrying"),
                    }
                    tracing::warn!(seq, key = %key, held_total = self.key_held_total,
                        takeover_idle_s = LOG_KEY_TAKEOVER_IDLE.as_secs(),
                        "part-log entry key held by an unfinished earlier reservation; not fenced, retrying in-process");
                } else if error.chain().any(|cause| cause.downcast_ref::<crate::part_ingest::native_writer::NativePutUnresolved>().is_some()) {
                    // The read-back found no object: that attempt did not land
                    // (yet). Its owner request can never be retried, so the
                    // next append builds a fresh entry (the owner hands the
                    // key over once the old reservation idles). If the old PUT
                    // lands late, the fresh create meets it and adopts it.
                    self.pending = None;
                } else {
                    tracing::warn!(seq, key = %key, error = %format!("{error:#}"),
                        "part-log append outcome unknown; the next append re-sends the identical entry");
                }
                return Err(error);
            }
        }
        self.committed(seq, next, sha, now_ms).await
    }

    /// NAN-4444: `existing` is this writer's own entry for `entry`'s slot:
    /// the same seq, writer epoch, predecessor and op. Only `appended_at_ms`
    /// may differ (an earlier attempt of the same append). Any other entry is
    /// another writer's (or a different epoch's) and must fence.
    fn is_own_entry(existing: &LogEntry, entry: &LogEntry) -> bool {
        existing.seq == entry.seq
            && existing.writer_epoch == entry.writer_epoch
            && existing.prev_sha256 == entry.prev_sha256
            && existing.op == entry.op
    }

    /// The key for `entry` already holds other bytes. Adopt them when they
    /// are this writer's own earlier attempt of the same append; fence
    /// otherwise.
    async fn adopt_or_fence(&mut self, entry: &LogEntry, existing: &[u8], now_ms: i64) -> Result<AppendOutcome> {
        let seq = entry.seq;
        let decoded = match LogEntry::parse_bytes(existing, &self.tenant_id) {
            Ok(decoded) if Self::is_own_entry(&decoded, entry) => decoded,
            Ok(decoded) => {
                tracing::warn!(seq, existing_epoch = decoded.writer_epoch, our_epoch = entry.writer_epoch,
                    same_prev = decoded.prev_sha256 == entry.prev_sha256, same_op = decoded.op == entry.op,
                    "part-log seq committed by another writer; fencing");
                return Err(Fenced { seq }.into());
            }
            Err(error) => {
                tracing::warn!(seq, error = %format!("{error:#}"), "part-log seq holds an undecodable entry; fencing");
                return Err(Fenced { seq }.into());
            }
        };
        self.adopt(decoded, existing, now_ms).await
    }

    /// Advance the head to this writer's own landed entry `entry` (stored as
    /// `bytes`). The receipt: re-send those exact bytes under the original
    /// attempt's hints, which is the original owner request; the native store
    /// resolves it by reading the object back and completing the owner
    /// receipt (`Ok(true)`). Only that records a receipt; anything else
    /// leaves it unknown (never claimed).
    async fn adopt(&mut self, entry: LogEntry, bytes: &[u8], now_ms: i64) -> Result<AppendOutcome> {
        let seq = entry.seq;
        let sha = sha256_hex(bytes);
        self.set.check_consumes(&entry.op)?;
        let mut next = self.set.clone();
        next.apply(&entry, &sha)?;
        let key = self.log_keys.entry(seq);
        let receipted = match self.store.put_if_absent_with(&key, bytes, &Self::log_hints(entry.appended_at_ms)).await {
            Ok(true) => {
                if let Some(receipted) = &self.receipted {
                    receipted.record(seq, entry.appended_at_ms);
                }
                true
            }
            Ok(false) => false,
            Err(error) => {
                tracing::warn!(seq, key = %key, error = %format!("{error:#}"),
                    "part-log adopted entry's receipt not confirmed; receipt unknown");
                false
            }
        };
        tracing::warn!(seq, key = %key, appended_at_ms = entry.appended_at_ms, receipted,
            "part-log entry landed by this writer's earlier ambiguous attempt; adopted, not fenced");
        self.committed(seq, next, sha, now_ms).await
    }

    /// An earlier attempt (`pending`, a different op) is unresolved at the
    /// current head: `Ok(true)` when it had landed and is now adopted (the
    /// head moved), `Ok(false)` when its key is empty (that attempt is
    /// dropped). Another writer's entry fences.
    async fn settle_pending(&mut self, pending: LogEntry, now_ms: i64) -> Result<bool> {
        let key = self.log_keys.entry(pending.seq);
        let existing = match self.store.get(&key).await {
            Ok(existing) => existing,
            Err(error) => {
                self.pending = Some(pending);
                return Err(error);
            }
        };
        let Some(existing) = existing else { return Ok(false) };
        self.adopt_or_fence(&pending, &existing, now_ms).await?;
        Ok(true)
    }

    /// Adopt a committed append: advance the head, then checkpoint on
    /// schedule.
    async fn committed(&mut self, seq: u64, next: LiveSet, sha: String, now_ms: i64) -> Result<AppendOutcome> {
        self.set = next;
        // No `log/HEAD` hint: no ingest credential scope covers it (the platform
        // mints `parts/`, `log/checkpoints/`, `log/entries/` only), and
        // readers find the head by probing entries (`probe_head`).
        // Past the commit point: a failed checkpoint must not look like a
        // failed append (a retry would re-commit, B2). Readers fall back to
        // the previous checkpoint plus entries.
        if seq > 0 && seq % CHECKPOINT_EVERY == 0 {
            if let Err(error) = self.write_checkpoint(now_ms).await {
                tracing::warn!(seq, error = %format!("{error:#}"), "part-log checkpoint failed after commit; continuing");
            }
        }
        Ok(AppendOutcome::Committed { seq, entry_sha256: sha })
    }

    /// Write a checkpoint at the current head (skipped, with a warning, when
    /// the live set exceeds one log object).
    pub async fn write_checkpoint(&self, now_ms: i64) -> Result<()> {
        let checkpoint = self.set.checkpoint(&self.tenant_id)?;
        let seq = checkpoint.seq;
        let Some(bytes) = checkpoint.to_bytes()? else {
            tracing::warn!(seq, live = checkpoint.live.len(), "checkpoint exceeds one log object; skipped");
            return Ok(());
        };
        let hints = WriteHints { class: WriterClass::LakePart, ..Self::log_hints(now_ms) };
        // A checkpoint for the same seq is identical content; exists is fine.
        self.store.put_if_absent_with(&self.log_keys.checkpoint(seq), &bytes, &hints).await?;
        Ok(())
    }

    /// Re-read the log (used after a [`Fenced`] error before exiting).
    pub async fn reload(&mut self) -> Result<()> {
        self.pending = None;
        self.set = load_log(self.store, &self.tenant_id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::provenance::tests::TENANT;
    use arrow_schema::{DataType, Field, Schema, TimeUnit};

    #[tokio::test]
    async fn local_listing_preserves_partial_prefixes_and_missing_directories() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        for key in ["parts/one/data", "parts/one/partials/rollup", "parts/one-more/data",
            "parts/one.json", "parts/one/.tmp-hidden", "other/data"] {
            store.put(key, b"x").await.unwrap();
        }
        let cases: &[(&str, &[&str])] = &[
            ("", &["other/data", "parts/one-more/data", "parts/one.json", "parts/one/data", "parts/one/partials/rollup"]),
            ("parts/one", &["parts/one-more/data", "parts/one.json", "parts/one/data", "parts/one/partials/rollup"]),
            ("parts/one/", &["parts/one/data", "parts/one/partials/rollup"]),
            ("parts/one/d", &["parts/one/data"]),
            ("parts/one/partials/", &["parts/one/partials/rollup"]),
            ("parts/missing/", &[]),
            ("parts/one/data/", &[]),
        ];
        for (prefix, expected) in cases {
            assert_eq!(store.list(prefix).await.unwrap(), *expected, "prefix={prefix:?}");
        }
        // An unrelated unreadable tree must not be walked by a scoped
        // listing. This also detects a regression to whole-store traversal.
        use std::os::unix::fs::PermissionsExt;
        let unrelated = dir.path().join("unreadable");
        std::fs::create_dir(&unrelated).unwrap();
        std::fs::set_permissions(&unrelated, std::fs::Permissions::from_mode(0)).unwrap();
        // Root can read mode-000 directories; exercise the refusal where
        // filesystem permissions are enforced for this test process.
        let refused = std::fs::read_dir(&unrelated).is_err();
        let scoped = store.list("parts/one/").await;
        let whole = store.list("").await;
        std::fs::set_permissions(&unrelated, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(scoped.unwrap(), ["parts/one/data", "parts/one/partials/rollup"]);
        if refused {
            assert!(whole.is_err());
        }
    }

    #[tokio::test]
    async fn local_listing_never_descends_through_symlinked_directories() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        std::fs::write(outside.path().join("data"), b"outside").unwrap();
        store.put("parts/plain/data", b"inside").await.unwrap();
        symlink(outside.path(), dir.path().join("linked")).unwrap();
        symlink(outside.path(), dir.path().join("parts/linked")).unwrap();
        symlink(outside.path().join("data"), dir.path().join("parts/file")).unwrap();
        symlink(dir.path(), dir.path().join("parts/cycle")).unwrap();

        for prefix in ["linked/", "linked/missing/", "parts/linked/", "parts/cycle/"] {
            assert!(store.list(prefix).await.unwrap().is_empty(), "prefix={prefix}");
        }
        // Symlinks themselves stay visible to callers that reject them.
        assert_eq!(store.list("linked").await.unwrap(), ["linked"]);
        assert_eq!(store.list("parts/").await.unwrap(),
            ["parts/cycle", "parts/file", "parts/linked", "parts/plain/data"]);
        assert_eq!(std::fs::read(outside.path().join("data")).unwrap(), b"outside");
    }

    #[tokio::test]
    async fn setgid_root_shares_tenant_and_detect_leaves_but_not_log() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o2770)).unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let tenant = "lake/parts/v1/tenant=t";
        for key in ["log/entries/a", "parts/h/p.parquet", "finding-outbox/receipts/r.json", "checkpoint/c"] {
            assert!(store.put_if_absent(&format!("{tenant}/{key}"), b"x").await.unwrap());
        }
        let root = dir.path();
        for shared in ["lake", "lake/parts/v1", tenant, &format!("{tenant}/parts/h"),
            &format!("{tenant}/finding-outbox/receipts")] {
            assert_eq!(mode(&root.join(shared)), 0o2770, "{shared}");
        }
        for private in ["log", "log/entries", "checkpoint"] {
            assert_eq!(mode(&root.join(tenant).join(private)) & 0o020, 0, "{private}");
        }
        // A tree created before the shared layout is repaired by its owner.
        std::fs::set_permissions(root.join(tenant).join("parts"), std::fs::Permissions::from_mode(0o2750)).unwrap();
        assert!(store.put_if_absent(&format!("{tenant}/parts/h/q.parquet"), b"y").await.unwrap());
        assert_eq!(mode(&root.join(tenant).join("parts")), 0o2770);

        // A plain root keeps the process umask everywhere.
        let plain = tempfile::tempdir().unwrap();
        std::fs::set_permissions(plain.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let store = LocalObjectStore::new(plain.path()).unwrap();
        assert!(store.put_if_absent(&format!("{tenant}/parts/h/p.parquet"), b"x").await.unwrap());
        assert_eq!(mode(&plain.path().join(tenant)) & 0o2000, 0);
    }

    fn schema() -> Schema {
        Schema::new(vec![
            Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())), false),
            Field::new("message", DataType::Utf8, true),
        ])
    }

    fn part(n: u64, level: Level) -> PartRef {
        PartRef {
            part_id: PartId::parse(&format!("{:013}-{:016x}", 1_000 + n, n)).unwrap(),
            level,
            event_hour: 10,
            event_day: (level == Level::Day).then_some(0),
            rows: 5,
            min_time_us: 1,
            max_time_us: 2,
            schema_fingerprint: "a".repeat(64),
            provenance_sha256: "b".repeat(64),
            merkle_root: "c".repeat(64),
            sorted: true,
            data_bytes: 10,
            row_groups: 1,
            data_files: 1,
        }
    }

    #[tokio::test]
    async fn adopt_entries_carry_only_unsorted_hour_or_day_parts() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        let unsorted = |n, level| PartRef { sorted: false, ..part(n, level) };
        assert!(writer.append(LogOp::Adopt { parts: vec![part(1, Level::Hour)] }, 2).await.is_err(), "sorted adopted part");
        assert!(writer.append(LogOp::Adopt { parts: vec![] }, 2).await.is_err(), "empty adopt");
        assert!(writer.append(LogOp::Adopt { parts: vec![unsorted(2, Level::L0)] }, 2).await.is_err(), "L0 adopted part");
        writer.append(LogOp::Adopt { parts: vec![unsorted(3, Level::Hour), unsorted(4, Level::Day)] }, 2).await.unwrap();
        assert_eq!(writer.live().parts().count(), 2);
    }

    fn source(n: u64) -> SourceRef {
        SourceRef { key: format!("bronze/{n}.parquet"), version: "1".into(), sha256: "d".repeat(64) }
    }

    /// NAN-4052: a refusing gate (a lost cell writer lease) stops the
    /// commit before the entry is written; an admitting one changes nothing.
    #[tokio::test]
    async fn the_append_gate_refuses_before_the_commit() {
        struct Gate(std::sync::atomic::AtomicBool);
        impl AppendGate for Gate {
            fn check_append(&self) -> Result<()> {
                anyhow::ensure!(self.0.load(std::sync::atomic::Ordering::SeqCst), "writer lease lost");
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        let gate = std::sync::Arc::new(Gate(std::sync::atomic::AtomicBool::new(true)));
        writer.set_append_gate(gate.clone());
        writer.append(LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: None }, 2).await.unwrap();
        gate.0.store(false, std::sync::atomic::Ordering::SeqCst);
        let refused = writer.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: None }, 3).await;
        assert!(refused.is_err());
        assert_eq!(writer.live().head().unwrap().0, 1, "nothing appended");
        assert!(store.get(&LogKeys::new(TENANT).unwrap().entry(2)).await.unwrap().is_none(), "no entry object written");
    }

    #[tokio::test]
    async fn an_add_never_consumes_a_source_twice() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        writer.append(LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: None }, 2).await.unwrap();
        assert!(writer.live().consumed(&source(1)));
        let again = writer.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2), source(1)], edge_log: None }, 3).await;
        assert!(again.unwrap_err().downcast_ref::<DoubleConsume>().is_some(), "overlap with an earlier add");
        let within = writer.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2), source(2)], edge_log: None }, 3).await;
        assert!(within.unwrap_err().downcast_ref::<DoubleConsume>().is_some(), "repeat within one add");
        assert_eq!(writer.live().head().unwrap().0, 1, "nothing appended");
        writer.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: None }, 3).await.unwrap();
    }

    #[tokio::test]
    async fn startup_progress_tracks_real_catch_up_backlog() {
        use crate::part_ingest::startup::{StartupProgress, PROGRESS};
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        for n in 1..=300 {
            writer.append(LogOp::Add { parts: vec![part(n, Level::L0)],
                consumed: vec![source(n)], edge_log: None }, n as i64 + 1).await.unwrap();
        }
        let progress = StartupProgress::new();
        let before = progress.snapshot().startup_progress.unwrap();
        let live = PROGRESS.scope(progress.clone(), load_log(&store, TENANT)).await.unwrap();
        assert_eq!(live.parts().count(), 300);
        assert_eq!(progress.snapshot().startup_progress.unwrap() - before, 301);
    }

    #[tokio::test]
    async fn append_merge_supersede_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        writer.append(LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: None }, 2).await.unwrap();
        writer.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: None }, 3).await.unwrap();
        writer
            .append(LogOp::Merge { output: part(3, Level::Minute), supersedes: vec![part(1, Level::L0).part_id, part(2, Level::L0).part_id] }, 4)
            .await
            .unwrap();
        // Double supersede is refused and leaves the set unchanged.
        assert!(writer.append(LogOp::Retire { parts: vec![part(1, Level::L0).part_id], reason: RetireReason::Retention, deletion_unit: "u".into() }, 5).await.is_err());
        assert_eq!(writer.live().parts().count(), 1);
        writer.write_checkpoint(6).await.unwrap();

        let reloaded = load_log(&store, TENANT).await.unwrap();
        assert_eq!(reloaded.parts().map(|p| p.part_id.clone()).collect::<Vec<_>>(), vec![part(3, Level::Minute).part_id]);
        assert_eq!(reloaded.head().unwrap().0, 3);
    }

    /// NAN-4691: the drain's head+schema view is exactly the `LiveSet`
    /// fold's head and schema, through schema evolution, merges, retires,
    /// checkpoints and the empty log; and from genesis without a checkpoint.
    #[tokio::test]
    async fn the_schema_view_matches_the_live_set_head_and_schema() {
        async fn same(store: &LocalObjectStore) {
            let full = load_log(store, TENANT).await.unwrap();
            let view = load_log_schema(store, TENANT).await.unwrap();
            assert_eq!(view.head(), full.head());
            assert_eq!(view.schema(), full.schema());
            let mut genesis = LogSchemaView::default();
            catch_up_schema(store, TENANT, &mut genesis).await.unwrap();
            assert_eq!(genesis, view, "a genesis fold reaches the same view as the checkpoint");
        }
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        // Empty log: no head, no schema, on both.
        same(&store).await;
        assert_eq!(load_log_schema(&store, TENANT).await.unwrap(), LogSchemaView::default());

        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        same(&store).await;
        let mut fields = schema().fields().iter().map(|field| field.as_ref().clone()).collect::<Vec<_>>();
        let mut evolve = |name: &str| {
            fields.push(Field::new(name, DataType::Utf8, true));
            LogSchema::from_arrow(&Schema::new(fields.clone())).unwrap()
        };
        writer.append(LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: None }, 2).await.unwrap();
        writer.append(LogOp::Schema { schema: evolve("a") }, 3).await.unwrap();
        writer.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: None }, 4).await.unwrap();
        same(&store).await;
        writer
            .append(LogOp::Merge { output: part(3, Level::Minute), supersedes: vec![part(1, Level::L0).part_id, part(2, Level::L0).part_id] }, 5)
            .await
            .unwrap();
        writer.append(LogOp::Retire { parts: vec![part(3, Level::Minute).part_id], reason: RetireReason::Retention, deletion_unit: "u".into() }, 6).await.unwrap();
        writer.write_checkpoint(7).await.unwrap();
        same(&store).await;
        // Evolution after the checkpoint, then a second checkpoint.
        writer.append(LogOp::Add { parts: vec![part(4, Level::L0)], consumed: vec![source(4)], edge_log: None }, 8).await.unwrap();
        let widened = evolve("b");
        writer.append(LogOp::Schema { schema: widened.clone() }, 9).await.unwrap();
        same(&store).await;
        assert_eq!(load_log_schema(&store, TENANT).await.unwrap().schema(), Some(&widened));
        writer.write_checkpoint(10).await.unwrap();
        writer.append(LogOp::Add { parts: vec![part(5, Level::L0)], consumed: vec![source(5)], edge_log: None }, 11).await.unwrap();
        same(&store).await;

        // A checkpoint whose entry digest differs fails both, as before.
        let keys = LogKeys::new(TENANT).unwrap();
        let newest = store.list(&keys.checkpoints_prefix()).await.unwrap().into_iter().filter(|key| is_snapshot_checkpoint_key(key)).last().unwrap();
        let mut forged: serde_json::Value = serde_json::from_slice(&store.get(&newest).await.unwrap().unwrap()).unwrap();
        forged["entry_sha256"] = serde_json::Value::String("0".repeat(64));
        store.put(&newest, &serde_json::to_vec(&forged).unwrap()).await.unwrap();
        assert!(load_log(&store, TENANT).await.is_err());
        assert!(load_log_schema(&store, TENANT).await.is_err());
    }

    #[tokio::test]
    async fn live_totals_count_only_live_parts() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        assert_eq!(writer.live().totals(), LivePartTotals::default());
        let wide = |n, min, max| PartRef { min_time_us: min, max_time_us: max, ..part(n, Level::L0) };
        writer.append(LogOp::Add { parts: vec![wide(1, 100, 200)], consumed: vec![source(1)], edge_log: None }, 2).await.unwrap();
        writer.append(LogOp::Add { parts: vec![wide(2, 50, 150)], consumed: vec![source(2)], edge_log: None }, 7).await.unwrap();
        let totals = writer.live().totals();
        assert_eq!((totals.parts, totals.rows, totals.data_bytes, totals.data_files), (2, 10, 20, 2));
        assert_eq!((totals.min_time_us, totals.max_time_us, totals.last_added_at_ms), (Some(50), Some(200), Some(7)));
        // A merge replaces its inputs: the superseded parts stop counting.
        let merged = PartRef { rows: 10, data_bytes: 12, min_time_us: 50, max_time_us: 200, ..part(3, Level::Minute) };
        writer
            .append(LogOp::Merge { output: merged, supersedes: vec![part(1, Level::L0).part_id, part(2, Level::L0).part_id] }, 9)
            .await
            .unwrap();
        let totals = writer.live().totals();
        assert_eq!((totals.parts, totals.rows, totals.data_bytes, totals.data_files), (1, 10, 12, 1));
        assert_eq!(totals.last_added_at_ms, Some(9));
    }

    #[tokio::test]
    async fn a_second_writer_is_fenced_not_merged() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut a = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        let mut b = PartLogWriter::open(&store, TENANT, 2, &schema(), 1).await.unwrap();
        a.append(LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: None }, 2).await.unwrap();
        let error = b.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: None }, 2).await.unwrap_err();
        assert!(error.downcast_ref::<Fenced>().is_some());
        // A writer with an older epoch than the log cannot open.
        b.reload().await.unwrap();
        b.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: None }, 3).await.unwrap();
        assert!(PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.is_err());
    }

    /// Refuses the next `held` entry creates the way the owner refuses a
    /// key an earlier attempt still reserves (409 -> [`LogKeyHeld`]).
    struct HeldKeyStore {
        inner: LocalObjectStore,
        held: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl ObjectStore for HeldKeyStore {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.inner.get(key).await
        }
        async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
            use std::sync::atomic::Ordering;
            if key.contains("/log/entries/")
                && self.held.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok()
            {
                return Err(LogKeyHeld { key: key.to_string() }.into());
            }
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

    #[test]
    fn takeover_idle_constant_matches_its_migration() {
        // Runtime read, not `include_str!`: the open-core mirror strips
        // the enterprise migrations (NAN-2169, NAN-3307). Skip only when
        // the file is genuinely absent; any other IO error fails.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../migrations/postgres-enterprise/9010560_writer_log_key_idle_takeover.sql"
        );
        let migration = match std::fs::read_to_string(path) {
            Ok(migration) => migration,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping: {path} is absent (open-core tree)");
                return;
            }
            Err(err) => panic!("read {path}: {err}"),
        };
        let interval = format!("+ INTERVAL '{} seconds' > clock_timestamp())", LOG_KEY_TAKEOVER_IDLE.as_secs());
        assert_eq!(migration.matches(&interval).count(), 1, "9010560 and LOG_KEY_TAKEOVER_IDLE moved apart");
    }

    /// Models the owner plane for entry keys (NAN-3493): `complete_fails`
    /// lets the conditional create land but fails the call the way an owner
    /// 503 on `complete` does; afterwards the owner answers 409 for the
    /// (completed) key, never a 412, and never hands it over.
    struct CompletedKeyStore {
        inner: LocalObjectStore,
        complete_fails: std::sync::atomic::AtomicBool,
        authorize_calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl ObjectStore for CompletedKeyStore {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.inner.get(key).await
        }
        async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
            use std::sync::atomic::Ordering;
            if !key.contains("/log/entries/") {
                return self.inner.put_if_absent(key, bytes).await;
            }
            self.authorize_calls.fetch_add(1, Ordering::SeqCst);
            if self.inner.get(key).await?.is_some() {
                return Err(LogKeyHeld { key: key.to_string() }.into());
            }
            let created = self.inner.put_if_absent(key, bytes).await?;
            if self.complete_fails.swap(false, Ordering::SeqCst) {
                bail!("native writer owner refused HTTP 503");
            }
            Ok(created)
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

    /// NAN-3493 regression (the load-test tenant, 2026-10-10): the owner went away
    /// between an entry's PUT and its `complete`. The entry is committed, so
    /// the owner refuses every retry with 409 and never hands the key over.
    /// NAN-4444: the retry of the same op re-sends the identical entry, so
    /// the held-key probe finds exactly these bytes and commits: no fence,
    /// no livelock, the first attempt's entry exactly once.
    #[tokio::test]
    async fn an_entry_committed_before_an_owner_outage_commits_on_the_identical_resend() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let store = CompletedKeyStore {
            inner: LocalObjectStore::new(dir.path()).unwrap(),
            complete_fails: Default::default(),
            authorize_calls: Default::default(),
        };
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        let genesis_calls = store.authorize_calls.load(Ordering::SeqCst);
        store.complete_fails.store(true, Ordering::SeqCst);
        let op = |n| LogOp::Add { parts: vec![part(n, Level::L0)], consumed: vec![source(n)], edge_log: None };
        // The owner outage: the PUT landed, the call failed, nothing applied.
        let error = writer.append(op(1), 10).await.unwrap_err();
        assert!(error.downcast_ref::<Fenced>().is_none() && error.downcast_ref::<LogKeyHeld>().is_none(), "{error:#}");
        assert_eq!(writer.live().head().map(|(seq, _, _)| seq), Some(0));
        // The retry (later clock) re-sends the first attempt's bytes; the
        // owner refuses it as held and the probe finds those bytes.
        let AppendOutcome::Committed { seq, .. } = writer.append(op(1), 25).await.unwrap();
        assert_eq!(seq, 1);
        assert_eq!(writer.log_key_held_total(), 1);
        assert_eq!(store.authorize_calls.load(Ordering::SeqCst) - genesis_calls, 2, "one refused retry, no livelock");
        assert!(writer.live().consumed(&source(1)));
        let AppendOutcome::Committed { seq, .. } = writer.append(op(2), 40).await.unwrap();
        assert_eq!(seq, 2);
        let reloaded = load_log(&store.inner, TENANT).await.unwrap();
        assert_eq!(reloaded.head().map(|(seq, _, _)| seq), Some(2));
        let entry = LogEntry::parse_bytes(&store.inner.get(&LogKeys::new(TENANT).unwrap().entry(1)).await.unwrap().unwrap(), TENANT).unwrap();
        assert_eq!(entry.appended_at_ms, 10, "the first attempt's entry is the committed one");
    }

    /// NAN-4444: a store whose next entry create is ambiguous: `land` stores
    /// the bytes and still fails the call (R2 500 after the write landed),
    /// otherwise it fails without storing (a timeout that never landed).
    /// `unresolved` makes the next create fail the way the native store does
    /// when its read-back finds no object.
    struct AmbiguousPutStore {
        inner: LocalObjectStore,
        fail_next: std::sync::atomic::AtomicBool,
        land: std::sync::atomic::AtomicBool,
        unresolved_next: std::sync::atomic::AtomicBool,
        entry_puts: std::sync::atomic::AtomicUsize,
    }

    impl AmbiguousPutStore {
        fn new(dir: &Path) -> Self {
            Self { inner: LocalObjectStore::new(dir).unwrap(), fail_next: Default::default(), land: Default::default(),
                unresolved_next: Default::default(), entry_puts: Default::default() }
        }
        fn fail_next(&self, land: bool) {
            use std::sync::atomic::Ordering;
            self.land.store(land, Ordering::SeqCst);
            self.fail_next.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl ObjectStore for AmbiguousPutStore {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.inner.get(key).await
        }
        async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
            use std::sync::atomic::Ordering;
            if !key.contains("/log/entries/") {
                return self.inner.put_if_absent(key, bytes).await;
            }
            self.entry_puts.fetch_add(1, Ordering::SeqCst);
            if self.unresolved_next.swap(false, Ordering::SeqCst) {
                return Err(crate::part_ingest::native_writer::NativePutUnresolved { key: key.to_string() }.into());
            }
            if self.fail_next.swap(false, Ordering::SeqCst) {
                if self.land.load(Ordering::SeqCst) {
                    self.inner.put_if_absent(key, bytes).await?;
                }
                bail!("R2 PUT {key}: HTTP 500 InternalError");
            }
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

    fn add(n: u64) -> LogOp {
        LogOp::Add { parts: vec![part(n, Level::L0)], consumed: vec![source(n)], edge_log: None }
    }

    /// NAN-4444 (cell-us-1, 2026-10-23): R2 answered 500 to an entry PUT
    /// that landed. The retry re-sends the identical entry: committed once,
    /// never "committed by another writer".
    #[tokio::test]
    async fn a_put_that_landed_then_failed_commits_on_the_retry_not_fenced() {
        let dir = tempfile::tempdir().unwrap();
        let store = AmbiguousPutStore::new(dir.path());
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        store.fail_next(true);
        let error = writer.append(add(1), 10).await.unwrap_err();
        assert!(error.downcast_ref::<Fenced>().is_none(), "{error:#}");
        let AppendOutcome::Committed { seq, entry_sha256 } = writer.append(add(1), 99).await.unwrap();
        assert_eq!(seq, 1);
        let stored = store.inner.get(&LogKeys::new(TENANT).unwrap().entry(1)).await.unwrap().unwrap();
        assert_eq!(entry_sha256, sha256_hex(&stored));
        assert_eq!(LogEntry::parse_bytes(&stored, TENANT).unwrap().appended_at_ms, 10, "identical bytes re-sent");
        let AppendOutcome::Committed { seq, .. } = writer.append(add(2), 100).await.unwrap();
        assert_eq!(seq, 2);
        assert_eq!(load_log(&store.inner, TENANT).await.unwrap().head().map(|(seq, _, _)| seq), Some(2));
    }

    /// A different op after an ambiguous attempt that landed: the earlier
    /// entry is adopted first, then the new op commits at the next seq.
    #[tokio::test]
    async fn a_different_op_after_a_landed_ambiguous_attempt_adopts_it_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = AmbiguousPutStore::new(dir.path());
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        store.fail_next(true);
        writer.append(add(1), 10).await.unwrap_err();
        let AppendOutcome::Committed { seq, .. } = writer.append(add(2), 20).await.unwrap();
        assert_eq!(seq, 2);
        assert!(writer.live().consumed(&source(1)) && writer.live().consumed(&source(2)));
        // A different op after an attempt that did NOT land: dropped, the
        // new op takes the slot.
        store.fail_next(false);
        writer.append(add(3), 30).await.unwrap_err();
        let AppendOutcome::Committed { seq, .. } = writer.append(add(4), 40).await.unwrap();
        assert_eq!(seq, 3);
        assert!(!writer.live().consumed(&source(3)));
    }

    /// The native read-back found nothing (the attempt never landed): the
    /// next append is a fresh entry; when the old PUT lands late anyway, the
    /// fresh create meets this writer's own entry and adopts it.
    #[tokio::test]
    async fn an_own_entry_landing_late_under_a_fresh_attempt_is_adopted() {
        use crate::lake_part_gc::index::{ReceiptedAppends, INDEX_SETTLE_MS};
        let dir = tempfile::tempdir().unwrap();
        let store = AmbiguousPutStore::new(dir.path());
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        let ledger = std::sync::Arc::new(ReceiptedAppends::default());
        writer.set_receipted_appends(ledger.clone());
        store.fail_next(false);
        writer.append(add(1), 10).await.unwrap_err();
        store.unresolved_next.store(true, std::sync::atomic::Ordering::SeqCst);
        writer.append(add(1), 20).await.unwrap_err();
        // The first attempt (appended_at 10) lands late.
        let late = LogEntry { format: LOG_FORMAT.into(), tenant_id: TENANT.into(), seq: 1,
            prev_sha256: writer.live().head().unwrap().1.to_string(), writer_epoch: 1, appended_at_ms: 10, op: add(1) };
        store.inner.put_if_absent(&LogKeys::new(TENANT).unwrap().entry(1), &late.to_bytes().unwrap()).await.unwrap();
        let AppendOutcome::Committed { seq, entry_sha256 } = writer.append(add(1), 30).await.unwrap();
        assert_eq!(seq, 1);
        assert_eq!(entry_sha256, sha256_hex(&late.to_bytes().unwrap()), "the landed entry is the head");
        // The local store has no writer authority: the receipt stays unknown.
        assert_eq!(ledger.receipted_through(30 + INDEX_SETTLE_MS), None);
        assert_eq!(load_log(&store.inner, TENANT).await.unwrap().head().map(|(seq, _, _)| seq), Some(1));
    }

    /// The safety property: an ambiguous attempt never adopts another
    /// writer's entry. A different epoch at that seq fences.
    #[tokio::test]
    async fn an_ambiguous_retry_meeting_a_foreign_writers_entry_is_fenced() {
        let dir = tempfile::tempdir().unwrap();
        let store = AmbiguousPutStore::new(dir.path());
        let mut ours = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        store.fail_next(false);
        ours.append(add(1), 10).await.unwrap_err();
        // A successor (epoch 2) commits seq 1, even with the very same op.
        let mut theirs = PartLogWriter::open(&store, TENANT, 2, &schema(), 1).await.unwrap();
        theirs.append(add(1), 11).await.unwrap();
        let error = ours.append(add(1), 20).await.unwrap_err();
        assert_eq!(error.downcast_ref::<Fenced>().map(|fenced| fenced.seq), Some(1), "{error:#}");
        assert!(!ours.live().knows(&part(1, Level::L0).part_id));
    }

    /// Same epoch and op but another predecessor is not this writer's entry.
    #[tokio::test]
    async fn an_ambiguous_retry_meeting_another_chain_is_fenced() {
        let dir = tempfile::tempdir().unwrap();
        let store = AmbiguousPutStore::new(dir.path());
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        store.fail_next(false);
        writer.append(add(1), 10).await.unwrap_err();
        let other = LogEntry { format: LOG_FORMAT.into(), tenant_id: TENANT.into(), seq: 1,
            prev_sha256: "f".repeat(64), writer_epoch: 1, appended_at_ms: 10, op: add(1) };
        store.inner.put_if_absent(&LogKeys::new(TENANT).unwrap().entry(1), &other.to_bytes().unwrap()).await.unwrap();
        let error = writer.append(add(1), 20).await.unwrap_err();
        assert_eq!(error.downcast_ref::<Fenced>().map(|fenced| fenced.seq), Some(1), "{error:#}");
        assert!(!writer.live().consumed(&source(1)));
    }

    /// The probe is no fence for an identical entry: a held key that already
    /// holds exactly these bytes is this append, committed.
    #[tokio::test]
    async fn a_held_key_holding_these_exact_bytes_is_committed() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let store = CompletedKeyStore {
            inner: LocalObjectStore::new(dir.path()).unwrap(),
            complete_fails: Default::default(),
            authorize_calls: Default::default(),
        };
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        store.complete_fails.store(true, Ordering::SeqCst);
        let op = LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: None };
        writer.append(op.clone(), 10).await.unwrap_err();
        let AppendOutcome::Committed { seq, .. } = writer.append(op, 10).await.unwrap();
        assert_eq!(seq, 1);
        assert!(writer.live().consumed(&source(1)));
    }

    /// NAN-3810: only creates that returned `Ok(true)` (owner completion,
    /// hence control's receipt) feed the GC watermark. A held key already
    /// holding this entry is committed with an unknown receipt: it breaks the
    /// run, so the watermark is withheld until that entry is settled by age.
    #[tokio::test]
    async fn only_completed_creates_feed_the_receipted_watermark() {
        use crate::lake_part_gc::index::{ReceiptedAppends, INDEX_SETTLE_MS};
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let store = CompletedKeyStore {
            inner: LocalObjectStore::new(dir.path()).unwrap(),
            complete_fails: Default::default(),
            authorize_calls: Default::default(),
        };
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        let ledger = std::sync::Arc::new(ReceiptedAppends::default());
        writer.set_receipted_appends(ledger.clone());
        let op = |n| LogOp::Add { parts: vec![part(n, Level::L0)], consumed: vec![source(n)], edge_log: None };
        writer.append(op(1), 10).await.unwrap();
        writer.append(op(2), 20).await.unwrap();
        assert_eq!(ledger.receipted_through(10 + INDEX_SETTLE_MS), Some(2));
        // seq 3: the create landed, completion failed; the retry commits it
        // through the held-key probe, receipt unknown.
        store.complete_fails.store(true, Ordering::SeqCst);
        writer.append(op(3), 30).await.unwrap_err();
        writer.append(op(3), 30).await.unwrap();
        assert_eq!(ledger.receipted_through(10 + INDEX_SETTLE_MS), Some(2), "seq 3 is not recorded");
        writer.append(op(4), 40).await.unwrap();
        assert_eq!(ledger.receipted_through(40 + INDEX_SETTLE_MS - 1), None, "seq 3's receipt is unknown");
        assert_eq!(ledger.receipted_through(40 + INDEX_SETTLE_MS), Some(4));
    }

    /// A different writer's entry under a held key fences too (a crashed or
    /// superseded writer never commits over it).
    #[tokio::test]
    async fn a_held_key_committed_by_another_writer_fences() {
        let dir = tempfile::tempdir().unwrap();
        let store = CompletedKeyStore {
            inner: LocalObjectStore::new(dir.path()).unwrap(),
            complete_fails: Default::default(),
            authorize_calls: Default::default(),
        };
        let mut ours = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        let mut theirs = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        theirs.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: None }, 5).await.unwrap();
        let op = LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: None };
        let error = ours.append(op, 10).await.unwrap_err();
        assert_eq!(error.downcast_ref::<Fenced>().map(|fenced| fenced.seq), Some(1), "{error:#}");
        assert!(!ours.live().knows(&part(1, Level::L0).part_id));
    }

    /// NAN-3181: a held entry key is retried in-process (not a fence); the
    /// rebuilt entry (new appended_at_ms) commits the same seq once the
    /// owner hands the key over.
    #[tokio::test]
    async fn a_held_entry_key_is_retried_not_fenced() {
        let dir = tempfile::tempdir().unwrap();
        let store = HeldKeyStore { inner: LocalObjectStore::new(dir.path()).unwrap(), held: Default::default() };
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        store.held.store(3, std::sync::atomic::Ordering::SeqCst);
        let head = writer.live().head().map(|(seq, sha, _)| (seq, sha.to_string()));
        for attempt in 0..3_i64 {
            let op = LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: None };
            let error = writer.append(op, 10 + attempt).await.unwrap_err();
            assert!(error.downcast_ref::<LogKeyHeld>().is_some(), "{error:#}");
            assert!(error.downcast_ref::<Fenced>().is_none());
            assert_eq!(writer.live().head().map(|(seq, sha, _)| (seq, sha.to_string())), head, "nothing applied");
        }
        assert_eq!(writer.log_key_held_total(), 3);
        let op = LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: None };
        let AppendOutcome::Committed { seq, .. } = writer.append(op, 20).await.unwrap();
        assert_eq!(seq, 1);
        assert!(writer.live().knows(&part(1, Level::L0).part_id));
        // A fresh reader sees exactly one committed entry for that seq.
        let reloaded = load_log(&store.inner, TENANT).await.unwrap();
        assert_eq!(reloaded.head().map(|(seq, _, _)| seq), Some(1));
    }

    #[tokio::test]
    async fn tampered_chain_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        writer.append(LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: None }, 2).await.unwrap();
        writer.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: None }, 3).await.unwrap();
        let path = store.path(&LogKeys::new(TENANT).unwrap().entry(1)).unwrap();
        let original = std::fs::read_to_string(&path).unwrap();
        let text = original.replace("\"rows\":5", "\"rows\":6");
        assert_ne!(text, original);
        std::fs::write(&path, &text).unwrap();
        // The next entry's prev_sha256 no longer matches.
        assert!(load_log(&store, TENANT).await.is_err());
        // A non-canonical (pretty) rewrite of the same entry is refused too.
        let pretty = serde_json::to_vec_pretty(&serde_json::from_str::<serde_json::Value>(&original).unwrap()).unwrap();
        std::fs::write(&path, pretty).unwrap();
        assert!(load_log(&store, TENANT).await.is_err());
        std::fs::write(&path, original).unwrap();
        assert_eq!(load_log(&store, TENANT).await.unwrap().head().unwrap().0, 2);
    }

    fn range(first: u64, through: u64, prev: &str, through_chain: &str) -> crate::parts::provenance::EdgeLogRange {
        crate::parts::provenance::EdgeLogRange {
            log: format!("edgelog:{TENANT}"),
            contract: crate::parts::provenance::EDGE_LOG_CONTRACT.into(),
            first_seq: first,
            through_seq: through,
            prev_chain: prev.into(),
            through_chain: through_chain.into(),
            skipped: vec![],
            rows_in: 1,
            rows_rejected: 0,
            rows_duplicate: 0,
        }
    }

    #[tokio::test]
    async fn edge_log_ranges_chain_across_adds_floors_and_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        let genesis = crate::parts::provenance::edge_log_genesis(TENANT);
        let (c2, c3, c9) = ("2".repeat(64), "3".repeat(64), "9".repeat(64));
        // The first range must start at genesis.
        let bad_start = LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: Some(range(5, 6, &genesis, &c2)) };
        assert!(writer.append(bad_start, 2).await.is_err());
        writer
            .append(LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: Some(range(1, 2, &genesis, &c2)) }, 2)
            .await
            .unwrap();
        // No bypass: a plain add after edge mode, or a gap, is refused.
        assert!(writer.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: None }, 3).await.is_err());
        let digest = "a".repeat(64);
        let receipt = SourceRef {
            key: format!("lake/parts/v1/tenant={TENANT}/finding-outbox/receipts/{digest}.json"),
            version: "nano.finding-outbox-receipt.v1".into(),
            sha256: digest,
        };
        writer.append(LogOp::Add { parts: vec![part(9, Level::L0)], consumed: vec![receipt.clone()], edge_log: None }, 3).await.unwrap();
        assert!(writer.append(LogOp::Add { parts: vec![part(10, Level::L0)], consumed: vec![receipt.clone()], edge_log: None }, 3).await.is_err());
        let foreign = SourceRef { key: receipt.key.replace(TENANT, "00000000-0000-4000-8000-000000000001"), ..receipt };
        assert!(writer.append(LogOp::Add { parts: vec![part(10, Level::L0)], consumed: vec![foreign], edge_log: None }, 3).await.is_err());
        assert!(writer
            .append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: Some(range(4, 4, &c2, &c3)) }, 3)
            .await
            .is_err());
        writer
            .append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: Some(range(3, 3, &c2, &c3)) }, 3)
            .await
            .unwrap();
        // A floor may skip ahead but never back.
        let back = LogOp::EdgeFloor { through_seq: 1, through_chain: c9.clone(), reason: "sweep".into() };
        assert!(writer.append(back, 4).await.is_err());
        writer.append(LogOp::EdgeFloor { through_seq: 8, through_chain: c9.clone(), reason: "sweep".into() }, 4).await.unwrap();
        writer
            .append(LogOp::Add { parts: vec![part(3, Level::L0)], consumed: vec![source(3)], edge_log: Some(range(9, 9, &c9, &c2)) }, 5)
            .await
            .unwrap();
        // The checkpoint carries the point; a reload from it resumes there.
        writer.write_checkpoint(6).await.unwrap();
        let reloaded = load_log(&store, TENANT).await.unwrap();
        let point = reloaded.edge_point().unwrap();
        assert_eq!((point.through_seq, point.through_chain.as_str()), (9, c2.as_str()));
        assert!(check_edge_commit_monotonic(9, 8).is_err());
        check_edge_commit_monotonic(9, 9).unwrap();
    }

    /// NAN-3643: an operator replay of this tenant's quarantined object is
    /// an add without an edge range that leaves the edge point alone; any
    /// other tenant's key, a mixed add, or a second consume is refused.
    #[tokio::test]
    async fn quarantine_replay_adds_beside_edge_mode_for_this_tenant_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        let genesis = crate::parts::provenance::edge_log_genesis(TENANT);
        let (c2, c3) = ("2".repeat(64), "3".repeat(64));
        writer
            .append(LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: Some(range(1, 2, &genesis, &c2)) }, 2)
            .await
            .unwrap();
        let id = "b".repeat(64);
        let replay = SourceRef { key: quarantine_replay_key(TENANT, &id), version: QUARANTINE_REPLAY_VERSION.into(), sha256: id.clone() };
        assert!(quarantine_replays_only(TENANT, std::slice::from_ref(&replay)));
        let foreign_tenant = "00000000-0000-4000-8000-000000000001";
        let foreign = SourceRef { key: quarantine_replay_key(foreign_tenant, &id), ..replay.clone() };
        assert!(writer.append(LogOp::Add { parts: vec![part(8, Level::L0)], consumed: vec![foreign], edge_log: None }, 3).await.is_err());
        let wrong_digest = SourceRef { sha256: "c".repeat(64), ..replay.clone() };
        assert!(writer.append(LogOp::Add { parts: vec![part(8, Level::L0)], consumed: vec![wrong_digest], edge_log: None }, 3).await.is_err());
        let mixed = vec![replay.clone(), source(2)];
        assert!(writer.append(LogOp::Add { parts: vec![part(8, Level::L0)], consumed: mixed, edge_log: None }, 3).await.is_err());
        writer.append(LogOp::Add { parts: vec![part(8, Level::L0)], consumed: vec![replay.clone()], edge_log: None }, 3).await.unwrap();
        assert!(writer.append(LogOp::Add { parts: vec![part(9, Level::L0)], consumed: vec![replay], edge_log: None }, 3).await.is_err(),
            "a replay is consumed once");
        // The edge chain continues from the point the replay left alone.
        writer
            .append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: Some(range(3, 3, &c2, &c3)) }, 4)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn edge_mode_ends_at_the_consumed_point_and_reentry_continues_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), 1).await.unwrap();
        let genesis = crate::parts::provenance::edge_log_genesis(TENANT);
        let (c2, c3, c4) = ("2".repeat(64), "3".repeat(64), "4".repeat(64));
        writer
            .append(LogOp::Add { parts: vec![part(1, Level::L0)], consumed: vec![source(1)], edge_log: Some(range(1, 2, &genesis, &c2)) }, 2)
            .await
            .unwrap();
        // End only at the consumed point.
        let wrong = LogOp::EdgeEnd { through_seq: 1, through_chain: c2.clone(), reason: "drain".into() };
        assert!(writer.append(wrong, 3).await.is_err());
        writer.append(LogOp::EdgeEnd { through_seq: 2, through_chain: c2.clone(), reason: "do to r2".into() }, 3).await.unwrap();
        // Plain adds are fine again; a floor is not.
        writer.append(LogOp::Add { parts: vec![part(2, Level::L0)], consumed: vec![source(2)], edge_log: None }, 4).await.unwrap();
        let floor = LogOp::EdgeFloor { through_seq: 9, through_chain: c3.clone(), reason: "sweep".into() };
        assert!(writer.append(floor, 5).await.is_err());
        // Re-entry must continue the ended point, not genesis.
        let from_genesis =
            LogOp::Add { parts: vec![part(3, Level::L0)], consumed: vec![source(3)], edge_log: Some(range(1, 1, &genesis, &c3)) };
        assert!(writer.append(from_genesis, 5).await.is_err());
        writer
            .append(LogOp::Add { parts: vec![part(3, Level::L0)], consumed: vec![source(3)], edge_log: Some(range(3, 4, &c2, &c4)) }, 5)
            .await
            .unwrap();
        writer.append(LogOp::EdgeEnd { through_seq: 4, through_chain: c4.clone(), reason: "again".into() }, 6).await.unwrap();
        writer.write_checkpoint(7).await.unwrap();
        let reloaded = load_log(&store, TENANT).await.unwrap();
        assert!(reloaded.edge_point().is_none());
        assert_eq!(reloaded.edge_ended().unwrap().through_seq, 4);
    }
}
