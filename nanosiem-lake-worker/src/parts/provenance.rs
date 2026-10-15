// SPDX-License-Identifier: AGPL-3.0-or-later

//! The signed per-part provenance record and its Merkle root (contract
//! section 4).

use anyhow::{bail, Context, Result};
use arrow_array::RecordBatch;
use arrow_json::LineDelimitedWriter;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::format::PartId;
use super::levels::Level;
use super::{is_sha256_hex, sha256_hex};

pub const PROVENANCE_FORMAT: &str = "nano.part.provenance.v1";
/// The owner signs `PROVENANCE_SIGNATURE_DOMAIN || canonical_record_bytes`.
pub const PROVENANCE_SIGNATURE_DOMAIN: &[u8] = b"nano-lake-part-provenance-v1\0";
/// Largest integer every canonical number must fit (JSON-safe in JS).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
/// `lake-parts:sign` batch bound.
pub const SIGN_BATCH_MAX: usize = 16;
/// Owner route that signs part provenance records.
pub const OWNER_PART_SIGN_PATH: &str = "/internal/v1/enterprise-shared/lake-parts:sign";
/// Admission contract recorded on L0 parts.
pub const ADMISSION_CONTRACT: &str = "nano-bronze-admission-v2";
/// Fields whose stored spelling admission v2 guarantees as trimmed ASCII lowercase.
pub const LOWERCASED_AT_REST: &[&str] = &[
    "dst_endpoint.hostname",
    "dst_endpoint.ip",
    "dst_endpoint.mac",
    "metadata.log_source",
    "src_endpoint.hostname",
    "src_endpoint.ip",
    "src_endpoint.mac",
];
/// Upper bound on a stored record, so a hostile object cannot exhaust memory.
pub const MAX_PROVENANCE_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Merkle root (4.2)
// ---------------------------------------------------------------------------

/// RFC 6962 leaf: `SHA-256(0x00 || u32_be(len(uid)) || uid || row_digest)`.
pub fn leaf_hash(uid: &str, row_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0_u8]);
    hasher.update((uid.len() as u32).to_be_bytes());
    hasher.update(uid.as_bytes());
    hasher.update(row_digest);
    hasher.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1_u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Streaming RFC 6962 Merkle Tree Hash with an O(log n) stack. Leaves must be
/// pushed in `(time, metadata.uid)` order.
#[derive(Debug, Clone, Default)]
pub struct MerkleBuilder {
    /// (height, hash) of complete perfect subtrees, left to right.
    stack: Vec<(u32, [u8; 32])>,
    leaves: u64,
}

impl MerkleBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_leaf(&mut self, leaf: [u8; 32]) {
        self.leaves += 1;
        let mut current = (0_u32, leaf);
        while let Some(&(height, left)) = self.stack.last() {
            if height != current.0 {
                break;
            }
            self.stack.pop();
            current = (height + 1, node_hash(&left, &current.1));
        }
        self.stack.push(current);
    }

    pub fn push_row(&mut self, uid: &str, row_digest: &[u8; 32]) {
        self.push_leaf(leaf_hash(uid, row_digest));
    }

    pub fn leaves(&self) -> u64 {
        self.leaves
    }

    /// The root; `None` for an empty tree (parts are never empty).
    pub fn root(&self) -> Option<[u8; 32]> {
        let mut iter = self.stack.iter().rev();
        let mut acc = iter.next()?.1;
        for (_, left) in iter {
            acc = node_hash(left, &acc);
        }
        Some(acc)
    }

    pub fn root_hex(&self) -> Option<String> {
        self.root().map(hex::encode)
    }
}

/// Canonical row digests of a batch (contract 4.2): each row is encoded by
/// `arrow_json` (explicit nulls off), re-parsed, and re-serialized with
/// object keys sorted bytewise at every level, so neither schema field order
/// nor additive all-null leaves change a row's digest.
pub fn row_digests(batch: &RecordBatch) -> Result<Vec<[u8; 32]>> {
    row_digests_serial(batch)
}

/// [`row_digests`] for merges: large batches are digested in row slices on
/// the small, low-priority merge pool ([`merge_digest_pool`]), never on the
/// global rayon pool (admission) or the async runtime. Byte-identical to
/// [`row_digests`]; every merged row is digested, and a 300-eps hour seal
/// is ~1 M rows (NAN-3056).
pub fn row_digests_for_merge(batch: &RecordBatch) -> Result<Vec<[u8; 32]>> {
    use rayon::prelude::*;
    let rows = batch.num_rows();
    if rows <= ROW_DIGEST_CHUNK_ROWS || !PARALLEL_MERGE_DIGESTS.load(std::sync::atomic::Ordering::Relaxed) {
        return row_digests_serial(batch);
    }
    let charge_cpu = crate::part_ingest::merge_quota::active_on_this_thread();
    let digests = merge_digest_pool()
        .install(|| {
            (0..rows)
                .step_by(ROW_DIGEST_CHUNK_ROWS)
                .collect::<Vec<_>>()
                .into_par_iter()
                .map(|start| {
                    let cpu_start = crate::part_ingest::merge_quota::thread_cpu_ns();
                    let result = row_digests_serial(&batch.slice(start, ROW_DIGEST_CHUNK_ROWS.min(rows - start)));
                    if charge_cpu { crate::part_ingest::merge_quota::charge_parallel_cpu(crate::part_ingest::merge_quota::thread_cpu_ns().saturating_sub(cpu_start)); }
                    result
                })
                .collect::<Result<Vec<_>>>()
        })?
        .concat();
    if digests.len() != rows {
        bail!("row digest count does not match the batch");
    }
    Ok(digests)
}

static PARALLEL_MERGE_DIGESTS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Benchmarks: digest merge rows serially (the pre-NAN-3056 cost).
pub fn set_parallel_merge_digests(on: bool) {
    PARALLEL_MERGE_DIGESTS.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Rows per parallel [`row_digests_for_merge`] slice.
const ROW_DIGEST_CHUNK_ROWS: usize = 512;
/// Threads of the merge digest pool: ingest[T] has 2 vCPU, and the tick,
/// the credential refresher and admission must keep running beside a merge.
pub const MERGE_DIGEST_THREADS: usize = 2;
/// `nice` of the merge digest threads: the scheduler prefers everything
/// else in the process (tick, credentials) over them.
const MERGE_DIGEST_NICE: i32 = 10;

/// The dedicated merge digest pool: [`MERGE_DIGEST_THREADS`] threads at
/// `nice` [`MERGE_DIGEST_NICE`], created on first use.
pub fn merge_digest_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(MERGE_DIGEST_THREADS)
            .thread_name(|index| format!("merge-digest-{index}"))
            .start_handler(|_| {
                // Linux niceness is per thread (a tid is a PRIO_PROCESS who).
                // SAFETY: plain syscalls on this thread's own id.
                unsafe {
                    let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
                    libc::setpriority(libc::PRIO_PROCESS, tid, MERGE_DIGEST_NICE);
                }
            })
            .build()
            .expect("merge digest pool")
    })
}

fn row_digests_serial(batch: &RecordBatch) -> Result<Vec<[u8; 32]>> {
    let mut writer = LineDelimitedWriter::new(Vec::with_capacity(batch.num_rows() * 256));
    writer.write(batch).context("encode rows for digest")?;
    writer.finish()?;
    let bytes = writer.into_inner();
    let mut canonical = Vec::with_capacity(1024);
    let mut digests = Vec::with_capacity(batch.num_rows());
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let value: serde_json::Value = serde_json::from_slice(line).context("re-parse row for digest")?;
        canonical.clear();
        write_canonical_json(&value, &mut canonical)?;
        digests.push(Sha256::digest(&canonical).into());
    }
    if digests.len() != batch.num_rows() {
        bail!("row digest count does not match the batch");
    }
    Ok(digests)
}

/// JSON with object keys sorted bytewise at every level; everything else as
/// `serde_json` writes it.
pub fn write_canonical_json(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key)?;
                out.push(b':');
                write_canonical_json(value, out)?;
            }
            out.push(b'}');
        }
        Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_json(value, out)?;
            }
            out.push(b']');
        }
        scalar => serde_json::to_writer(&mut *out, scalar)?,
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Record (4.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HourDigest {
    pub event_hour: i32,
    pub rows: u64,
    pub min_time_us: i64,
    pub max_time_us: i64,
    pub merkle_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileDigest {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

/// One `data-NNNNN.parquet` of a part, with its token index. Files hold
/// consecutive rows of the file family's `(time, uid)` order; row groups
/// never span files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataFileDigest {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
    pub rows: u64,
    pub row_groups: u32,
    pub min_time_us: i64,
    pub max_time_us: i64,
    /// Exact non-null log sources in this file. Absent on legacy and overflow files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_sources: Option<Vec<String>>,
    /// Signed digest of the UID bloom sidecar, one bitset per row group.
    /// Absent on legacy parts; an unavailable bloom keeps its group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_blooms: Option<FileDigest>,
    /// Signed per-field row-group blooms; absent on legacy parts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_blooms: Option<FileDigest>,
    /// Signed Parquet footer and column chunk ranges (optional rollout).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parquet_ranges: Option<FileDigest>,
    /// Exact scalar entity row offsets, authenticated with the data inventory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_locators: Option<FileDigest>,
    /// Class of a dedicated source/class file family; absent on legacy files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_id: Option<i64>,
    pub tokens: FileDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialKind {
    Rollup,
    Prevalence,
    EntityRanges,
    Risk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartialDigest {
    pub kind: PartialKind,
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
    pub rows: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartFiles {
    pub data: Vec<DataFileDigest>,
    pub partials: Vec<PartialDigest>,
}

impl PartFiles {
    /// Every (relative name, sha256, bytes) a reader must verify.
    pub fn all(&self) -> Vec<(&str, &str, u64)> {
        let mut files = Vec::new();
        for data in &self.data {
            files.push((data.name.as_str(), data.sha256.as_str(), data.bytes));
            files.push((data.tokens.name.as_str(), data.tokens.sha256.as_str(), data.tokens.bytes));
            if let Some(ranges) = &data.parquet_ranges {
                files.push((ranges.name.as_str(), ranges.sha256.as_str(), ranges.bytes));
            }
            if let Some(locator) = &data.entity_locators {
                files.push((locator.name.as_str(), locator.sha256.as_str(), locator.bytes));
            }
            if let Some(entity) = &data.entity_blooms {
                files.push((entity.name.as_str(), entity.sha256.as_str(), entity.bytes));
            }
            if let Some(uid) = &data.uid_blooms {
                files.push((uid.name.as_str(), uid.sha256.as_str(), uid.bytes));
            }
        }
        files.extend(self.partials.iter().map(|p| (p.name.as_str(), p.sha256.as_str(), p.bytes)));
        files
    }

    pub fn row_groups(&self) -> u32 {
        self.data.iter().map(|d| d.row_groups).sum()
    }

    pub fn data_bytes(&self) -> u64 {
        self.data.iter().map(|d| d.bytes).sum()
    }

    /// `adopted_key`: for an adopted part (contract 8.1) its single data
    /// file is the original object, named by its bucket key.
    fn validate(&self, rows: u64, adopted_key: Option<&str>) -> Result<()> {
        use super::format::{data_file_name, tokens_file_name, MAX_DATA_FILES, MAX_OBJECT_BYTES};
        if self.data.is_empty() || self.data.len() > MAX_DATA_FILES {
            bail!("part data file count is out of bounds");
        }
        if adopted_key.is_some() && self.data.len() != 1 {
            bail!("an adopted part has exactly one data file");
        }
        let mut total = 0_u64;
        for (index, data) in self.data.iter().enumerate() {
            let data_name_ok = match adopted_key {
                Some(key) => data.name == key,
                None => data.name == data_file_name(index),
            };
            if !data_name_ok || data.tokens.name != tokens_file_name(index) {
                bail!("part data files are not named in order");
            }
            if data.entity_locators.as_ref().is_some_and(|locator| locator.name != format!("locators-{index:05}.json")) {
                bail!("part entity locator is not named in order");
            }
            if data.entity_blooms.as_ref().is_some_and(|entity| entity.name != format!("entities-{index:05}.json")) {
                bail!("part entity sidecar is not named in order");
            }
            if data.uid_blooms.as_ref().is_some_and(|uid| uid.name != format!("uids-{index:05}.json")) {
                bail!("part UID sidecar is not named in order");
            }
            if data.parquet_ranges.as_ref().is_some_and(|ranges| ranges.name != format!("ranges-{index:05}.json")
                || ranges.bytes > super::parquet_ranges::MAX_MANIFEST_BYTES) {
                bail!("invalid Parquet range manifest");
            }
            if data.rows == 0 || data.row_groups == 0 || data.min_time_us > data.max_time_us {
                bail!("part data file bounds are invalid");
            }
            if data.class_id.is_some() && data.log_sources.is_none() {
                bail!("class family requires an exact source family");
            }
            if data.log_sources.as_ref().is_some_and(|sources| sources.is_empty()
                || sources.windows(2).any(|pair| pair[0] >= pair[1])) {
                bail!("part data file log sources are invalid");
            }
            if index > 0 && self.data[index - 1].log_sources == data.log_sources
                && self.data[index - 1].class_id == data.class_id
                && self.data[index - 1].max_time_us > data.min_time_us {
                bail!("part data files are not in time order");
            }
            total = total.checked_add(data.rows).context("part rows overflow")?;
        }
        if total != rows {
            bail!("part data file rows do not sum to the part rows");
        }
        for (name, sha, bytes) in self.all() {
            if !is_sha256_hex(sha) || bytes == 0 || bytes > MAX_OBJECT_BYTES {
                bail!("part file {name} digest or size is invalid");
            }
        }
        Ok(())
    }
}

/// One consumed source object (a Vector bronze object in the tenant bucket).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceObject {
    pub key: String,
    pub version: String,
    pub bytes: u64,
    pub sha256: String,
    pub rows: u64,
    /// SHA-256 of the raw edge object, when the notification carried it.
    pub edge_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputPart {
    pub part_id: PartId,
    pub level: Level,
    pub provenance_sha256: String,
    pub rows: u64,
    pub merkle_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptedObject {
    pub key: String,
    pub bytes: u64,
    pub sha256: String,
    pub rows: u64,
    /// SHA-256 of the old signed object stamp this adoption references.
    pub stamp_sha256: String,
}

/// Edge-log contract version (NAN-2874).
pub const EDGE_LOG_CONTRACT: &str = "nano-edge-log-v1";
/// `SourceObject.version` prefix for a segment consumed from the edge log.
pub const EDGE_LOG_VERSION_PREFIX: &str = "edge-log-v1:";

/// The contiguous edge-log range an L0 part consumed (contract 4.1.1). The
/// sources are that range's segments in sequence order, and the chain ends let
/// a verifier prove, from provenance alone, that consecutive L0 parts neither
/// skip nor insert an edge batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeLogRange {
    /// `edgelog:<tenant_uuid>`.
    pub log: String,
    /// [`EDGE_LOG_CONTRACT`].
    pub contract: String,
    pub first_seq: u64,
    pub through_seq: u64,
    /// Chain value before `first_seq` (genesis, the sweep floor, or the previous part's `through_chain`).
    pub prev_chain: String,
    /// Chain value at `through_seq`.
    pub through_chain: String,
    /// Segments in the range that contributed no rows: the admission
    /// rejected them, or every row was a duplicate. They carry what the chain
    /// needs, so the range still recomputes. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<EdgeSkippedSegment>,
    /// Row accounting for the whole `add` entry this range belongs to
    /// (contract 4.1.1, M4): every row read from every segment of the range
    /// (sources and skipped) is either in one of the entry's parts, rejected
    /// by admission, or a duplicate: `rows_in = Σ part.rows + rows_rejected +
    /// rows_duplicate`.
    pub rows_in: u64,
    pub rows_rejected: u64,
    pub rows_duplicate: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeSkipReason {
    /// Acknowledged without contributing rows (rejected by admission, or all
    /// rows were duplicates of committed data).
    ConsumedWithoutRows,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeSkippedSegment {
    pub seq: u64,
    pub key: String,
    pub sha256: String,
    pub length: u64,
    pub reason: EdgeSkipReason,
    /// Rows the segment held; all of them rejected or duplicate.
    pub rows: u64,
    pub rows_rejected: u64,
    pub rows_duplicate: u64,
}

/// An edge-log segment key: `bronze-v2/shard=<n>/tenant_id=<tenant>/<file>`,
/// this tenant's, with no control characters (newlines would forge chain
/// fields).
pub fn is_edge_segment_key(tenant_id: &str, key: &str) -> bool {
    let mut parts = key.split('/');
    let ok = parts.next() == Some("bronze-v2")
        && parts.next().is_some_and(|s| s.strip_prefix("shard=").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())))
        && parts.next() == Some(format!("tenant_id={tenant_id}").as_str())
        && parts.next().is_some_and(|f| !f.is_empty() && f != "." && f != "..")
        && parts.next().is_none();
    ok && key.len() <= 1_024 && !key.chars().any(char::is_control)
}

/// The edge-log sequence of a source `version` (`edge-log-v1:<seq>`).
pub fn edge_log_seq_of_version(version: &str) -> Option<u64> {
    let digits = version.strip_prefix(EDGE_LOG_VERSION_PREFIX)?;
    if digits.is_empty() || digits.len() > 20 || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.starts_with('0') {
        return None;
    }
    digits.parse().ok().filter(|seq| *seq <= MAX_SAFE_INTEGER as u64)
}

/// `SHA-256("nano-edge-log-v1\n" || tenant_uuid)`.
pub fn edge_log_genesis(tenant_id: &str) -> String {
    sha256_hex(format!("{EDGE_LOG_CONTRACT}\n{tenant_id}").as_bytes())
}

/// `chain_n = SHA-256(chain_{n-1} \n seq \n key \n sha256 \n length)`, as the edge-log DO computes it.
pub fn edge_log_next_chain(previous: &str, seq: u64, key: &str, sha256: &str, length: u64) -> String {
    sha256_hex(format!("{previous}\n{seq}\n{key}\n{sha256}\n{length}").as_bytes())
}

impl EdgeLogRange {
    /// Recomputes the chain over `sources` and checks the range binding.
    pub fn validate(&self, tenant_id: &str, sources: &[SourceObject]) -> Result<()> {
        if self.log != format!("edgelog:{tenant_id}") || self.contract != EDGE_LOG_CONTRACT {
            bail!("edge log range names another log or contract");
        }
        if self.first_seq == 0 || self.through_seq < self.first_seq || self.through_seq > MAX_SAFE_INTEGER as u64 {
            bail!("edge log range is empty, inverted or out of bounds");
        }
        for source in sources {
            if !is_sha256_hex(&source.sha256) || !is_edge_segment_key(tenant_id, &source.key) {
                bail!("edge log source digest or key is invalid");
            }
        }
        for skipped in &self.skipped {
            if !is_edge_segment_key(tenant_id, &skipped.key)
                || skipped.rows.checked_sub(skipped.rows_rejected).and_then(|r| r.checked_sub(skipped.rows_duplicate)) != Some(0)
            {
                bail!("edge log skipped segment key or row accounting is invalid");
            }
        }
        let source_rows = sources.iter().try_fold(0_u64, |acc, s| acc.checked_add(s.rows)).context("row overflow")?;
        let skipped_rows = self.skipped.iter().try_fold(0_u64, |acc, s| acc.checked_add(s.rows)).context("row overflow")?;
        if source_rows.checked_add(skipped_rows) != Some(self.rows_in)
            || self.rows_rejected.checked_add(self.rows_duplicate).is_none_or(|lost| lost > self.rows_in)
        {
            bail!("edge log range row accounting does not add up");
        }
        if !is_sha256_hex(&self.prev_chain) || !is_sha256_hex(&self.through_chain) {
            bail!("edge log chain is malformed");
        }
        // Sources (in any order; writers may sort them) plus skipped segments
        // must be exactly first_seq..=through_seq, each once.
        let mut segments: Vec<(u64, &str, &str, u64)> = Vec::with_capacity(sources.len() + self.skipped.len());
        for source in sources {
            let seq = edge_log_seq_of_version(&source.version).context("edge log source version is malformed")?;
            segments.push((seq, &source.key, &source.sha256, source.bytes));
        }
        for skipped in &self.skipped {
            if !is_sha256_hex(&skipped.sha256) {
                bail!("edge log skipped segment digest is malformed");
            }
            segments.push((skipped.seq, &skipped.key, &skipped.sha256, skipped.length));
        }
        segments.sort_by_key(|segment| segment.0);
        let count = self.through_seq - self.first_seq + 1;
        if segments.len() as u64 != count
            || segments.iter().enumerate().any(|(offset, segment)| segment.0 != self.first_seq + offset as u64)
        {
            bail!("edge log sources and skipped segments do not cover the range exactly");
        }
        if let Some(last) = sources.iter().filter_map(|s| edge_log_seq_of_version(&s.version)).max() {
            if last != self.through_seq {
                bail!("edge log range must end at its last source");
            }
        }
        let mut chain = self.prev_chain.clone();
        for (seq, key, sha256, length) in segments {
            chain = edge_log_next_chain(&chain, seq, key, sha256, length);
        }
        if chain != self.through_chain {
            bail!("edge log chain does not recompute to through_chain");
        }
        Ok(())
    }

    /// Consecutive L0 parts (in part-log order) must link without a gap.
    pub fn follows(&self, previous: &EdgeLogRange) -> Result<()> {
        self.follows_point(&previous.log, previous.through_seq, &previous.through_chain)
    }

    /// Continue from a chain point: the previous range's end, a checkpoint's
    /// `edge_log` point, or an `edge_floor` entry (contract 5.1).
    pub fn follows_point(&self, log: &str, through_seq: u64, through_chain: &str) -> Result<()> {
        let next = through_seq.checked_add(1).context("edge log sequence overflow")?;
        if self.log != log || self.first_seq != next || self.prev_chain != through_chain {
            bail!("edge log range does not continue the previous range");
        }
        Ok(())
    }
}

/// The owner-signed generation whose object-stamp ledger vouches for the
/// adopted objects (phase 4, contract 8.1). Chain of custody: the bundle
/// signature covers `object_stamp_manifest_sha256`; that ledger holds the
/// stamp whose SHA-256 is `AdoptedObject::stamp_sha256`; the stamp pins the
/// object's SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptionAnchor {
    pub generation_id: String,
    /// Iceberg snapshot ids use the full 63-bit range (tenant1's is
    /// 8632004097115334317 > 2^53), so the signed form is a decimal STRING
    /// (contract 4.3, "u64 identifiers").
    #[serde(with = "u64_decimal")]
    pub snapshot_id: u64,
    pub bundle_identity_sha256: String,
    pub object_stamp_manifest_sha256: String,
    /// Key of the signed bundle manifest in the tenant bucket.
    pub bundle_manifest_key: String,
    /// SHA-256 of the signed bundle manifest bytes at that key.
    pub bundle_manifest_sha256: String,
    /// The bundle signature's key id.
    pub signer_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PartInputs {
    Sources {
        sources: Vec<SourceObject>,
        /// Present when the sources came from the edge log (NAN-2874,
        /// contract 4.1.1). Omitted when absent (r3 additive field), so
        /// records without it are byte-identical to r2.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        edge_log: Option<EdgeLogRange>,
    },
    Parts { parts: Vec<InputPart> },
    Adopted { anchor: AdoptionAnchor, objects: Vec<AdoptedObject> },
}

/// A bucket-relative key of an adopted object: non-empty, no scheme, no
/// leading slash, no empty/`.`/`..` segment, never inside the parts root.
pub fn is_adopted_object_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 1_024
        && !key.contains("://")
        && !key.starts_with('/')
        && !key.chars().any(char::is_control)
        && !key.split('/').any(|segment| segment.is_empty() || segment == "." || segment == "..")
        // Nothing under `lake/parts/` (any version) is an adoptable original.
        && key.split('/').take(2).collect::<Vec<_>>() != ["lake", "parts"]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub ocsf_version: String,
    pub admission_contract: String,
    /// `ipinfo`, `ioc`, `ip_context` → snapshot SHA-256 (None when unpinned).
    pub feed_pins: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DedupStats {
    pub rows_in: u64,
    pub duplicates_dropped: u64,
    pub window: super::DedupWindow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterInfo {
    pub role: String,
    pub build: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRecord {
    pub format: String,
    /// The owner release signer key id that signs this record.
    pub signer_key_id: String,
    pub tenant_id: String,
    pub part_id: PartId,
    pub level: Level,
    pub created_at_ms: i64,
    pub event_hour: i32,
    pub event_day: Option<i32>,
    pub rows: u64,
    pub min_time_us: i64,
    pub max_time_us: i64,
    pub schema_fingerprint: String,
    pub merkle_root: String,
    pub hours: Vec<HourDigest>,
    pub files: PartFiles,
    pub inputs: PartInputs,
    pub admission: Option<Admission>,
    /// Guaranteed lowercase fields. Empty on legacy and adopted records;
    /// merges carry the intersection of their inputs' guarantees.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lowercased_at_rest: Vec<String>,
    pub dedup: DedupStats,
    pub writer: WriterInfo,
}

impl ProvenanceRecord {
    /// Structural checks every reader and writer applies.
    pub fn validate(&self) -> Result<()> {
        super::format::validate_tenant_uuid(&self.tenant_id)?;
        if self.format != PROVENANCE_FORMAT {
            bail!("provenance format is unsupported");
        }
        if self.rows == 0 || self.min_time_us > self.max_time_us {
            bail!("provenance row count or time bounds are invalid");
        }
        for digest in [&self.schema_fingerprint, &self.merkle_root] {
            if !is_sha256_hex(digest) {
                bail!("provenance digest is malformed");
            }
        }
        if !valid_key_id(&self.signer_key_id) {
            bail!("provenance signer key id is malformed");
        }
        if self.lowercased_at_rest.windows(2).any(|pair| pair[0] >= pair[1])
            || self.lowercased_at_rest.iter().any(|path| !LOWERCASED_AT_REST.contains(&path.as_str()))
        {
            bail!("provenance lowercase field set is invalid");
        }
        if let Some(admission) = &self.admission {
            if admission.admission_contract == ADMISSION_CONTRACT
                && self.lowercased_at_rest.iter().map(String::as_str).collect::<Vec<_>>() != LOWERCASED_AT_REST
            {
                bail!("admission v2 must attest every lowercased field");
            }
        }
        let adopted_key = match &self.inputs {
            PartInputs::Adopted { objects, .. } => Some(objects.first().context("adopted part names no object")?.key.as_str()),
            _ => None,
        };
        self.files.validate(self.rows, adopted_key)?;
        if !matches!(self.level, Level::Minute | Level::Hour) && self.files.data.iter().any(|file| file.log_sources.is_some()) {
            bail!("only minute/hour parts can attest per-file log sources");
        }
        match self.level {
            Level::Day => {
                let day = self.event_day.context("day part has no event day")?;
                if self.event_hour != day * 24 || self.hours.is_empty() || self.hours.len() > 24 {
                    bail!("day part hour binding is invalid");
                }
            }
            _ => {
                if self.event_day.is_some() || self.hours.len() != 1 || self.hours[0].event_hour != self.event_hour {
                    bail!("hourly part hour binding is invalid");
                }
            }
        }
        let hour_rows: u64 = self.hours.iter().map(|h| h.rows).sum();
        if hour_rows != self.rows {
            bail!("provenance hour rows do not sum to the part rows");
        }
        if self.hours.windows(2).any(|w| w[0].event_hour >= w[1].event_hour) {
            bail!("provenance hours are not strictly ordered");
        }
        match (&self.inputs, self.level, &self.admission) {
            (PartInputs::Sources { sources, edge_log }, Level::L0, Some(_)) if !sources.is_empty() => {
                if let Some(range) = edge_log {
                    range.validate(&self.tenant_id, sources)?;
                }
            }
            (PartInputs::Parts { parts }, Level::Minute | Level::Hour | Level::Day, None) if !parts.is_empty() => {}
            (PartInputs::Adopted { anchor, objects }, Level::Hour | Level::Day, None) => {
                // One adopted part is exactly one original object, served in
                // place: its single data file IS that object (contract 8.1).
                let [object] = objects.as_slice() else {
                    bail!("an adopted part references exactly one object");
                };
                let data = &self.files.data[0];
                if object.sha256 != data.sha256
                    || object.bytes != data.bytes
                    || object.rows != self.rows
                    || !is_adopted_object_key(&object.key)
                    || !is_sha256_hex(&object.sha256)
                    || !is_sha256_hex(&object.stamp_sha256)
                {
                    bail!("adopted object does not match the part's data file");
                }
                for digest in [
                    &anchor.bundle_identity_sha256,
                    &anchor.object_stamp_manifest_sha256,
                    &anchor.bundle_manifest_sha256,
                ] {
                    if !is_sha256_hex(digest) {
                        bail!("adoption anchor digest is malformed");
                    }
                }
                if anchor.generation_id.is_empty()
                    || anchor.generation_id.len() > 256
                    || !is_adopted_object_key(&anchor.bundle_manifest_key)
                    || anchor.snapshot_id == 0
                    || !valid_key_id(&anchor.signer_key_id)
                {
                    bail!("adoption anchor identity is invalid");
                }
            }
            _ => bail!("provenance inputs do not match the part level"),
        }
        Ok(())
    }

    /// True for adopted parts (served from their original object in place).
    pub fn is_adopted(&self) -> bool {
        matches!(self.inputs, PartInputs::Adopted { .. })
    }

    /// Bucket key of data file `index`. Written parts keep
    /// `data-{i:05}.parquet` in the part directory; an adopted part's single
    /// data file is its original object, whose bucket key is its name.
    pub fn data_key(&self, keys: &super::format::PartKeys, index: usize) -> Option<String> {
        let data = self.files.data.get(index)?;
        Some(if self.is_adopted() { data.name.clone() } else { keys.file(&data.name) })
    }

    /// Canonical bytes (contract 4.3): JSON with object keys sorted by
    /// byte order at every level, no insignificant whitespace, `null` for
    /// absent optional fields, integers only in `[-(2^53-1), 2^53-1]`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json_bytes(&serde_json::to_value(self)?)
    }

    /// The exact message the owner signs.
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        let mut message = PROVENANCE_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&self.canonical_bytes()?);
        Ok(message)
    }
}

/// Canonical JSON (contract 4.3). Fails on a non-integer or unsafe number.
/// Serde adapter for u64 identifiers that may exceed 2^53 - 1: the canonical
/// form is a JSON string of decimal digits (no sign, no leading zeros, "0"
/// alone for zero, at most 20 digits) that parses to a u64. Anything else is
/// refused on read, so a record has exactly one canonical spelling.
pub mod u64_decimal {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        parse(&text).ok_or_else(|| D::Error::custom("u64 identifier is not a canonical decimal string"))
    }

    /// The strict parser (also used by verifiers of other languages' output).
    pub fn parse(text: &str) -> Option<u64> {
        let canonical = !text.is_empty()
            && text.len() <= 20
            && text.bytes().all(|b| b.is_ascii_digit())
            && (text == "0" || !text.starts_with('0'));
        if !canonical {
            return None;
        }
        text.parse().ok()
    }
}

pub fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    fn check(value: &serde_json::Value) -> Result<()> {
        match value {
            serde_json::Value::Number(n) => {
                let ok = n.as_i64().is_some_and(|v| v.abs() <= MAX_SAFE_INTEGER)
                    || n.as_u64().is_some_and(|v| v <= MAX_SAFE_INTEGER as u64);
                if !ok {
                    bail!("canonical JSON allows only safe integers");
                }
                Ok(())
            }
            serde_json::Value::Array(values) => values.iter().try_for_each(check),
            serde_json::Value::Object(map) => map.values().try_for_each(check),
            _ => Ok(()),
        }
    }
    check(value)?;
    let mut out = Vec::with_capacity(1024);
    write_canonical_json(value, &mut out)?;
    Ok(out)
}

/// Owner key ids: 8–128 of `[A-Za-z0-9._:-]` (the release signer format).
pub fn valid_key_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

// ---------------------------------------------------------------------------
// Signature (4.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519Signature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

/// The public keys trusted to sign this tenant's parts, by owner key id
/// (the owner release signer; rotated keys stay listed while their parts
/// are retained).
#[derive(Debug, Clone, Default)]
pub struct TenantKeySet {
    keys: BTreeMap<String, VerifyingKey>,
}

impl TenantKeySet {
    pub fn new(keys: impl IntoIterator<Item = (String, VerifyingKey)>) -> Self {
        Self { keys: keys.into_iter().collect() }
    }

    pub(crate) fn verify(&self, signature: &Ed25519Signature, message: &[u8]) -> Result<()> {
        if signature.alg != "ed25519" {
            bail!("signature algorithm is unsupported");
        }
        let key = self.keys.get(&signature.key_id).context("signature key is not trusted for this tenant")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&signature.sig)
            .context("signature is not base64")?;
        let signature = Signature::from_slice(&bytes).context("signature is malformed")?;
        key.verify_strict(message, &signature).context("signature does not verify")?;
        Ok(())
    }
}

/// `provenance.json`: `{"record": …, "signature": …}` in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProvenance {
    pub record: ProvenanceRecord,
    pub signature: Ed25519Signature,
}

impl SignedProvenance {
    /// Attach an owner signature after checking it.
    pub fn assemble(record: ProvenanceRecord, signature: Ed25519Signature, keys: &TenantKeySet) -> Result<Self> {
        record.validate()?;
        if signature.key_id != record.signer_key_id {
            bail!("signature key id differs from the record's signer");
        }
        keys.verify(&signature, &record.signing_message()?)?;
        Ok(Self { record, signature })
    }

    /// Stored bytes: canonical JSON of the envelope.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        canonical_json_bytes(&serde_json::to_value(self)?)
    }

    /// Parse and verify stored bytes for `tenant_id`.
    pub fn verify_bytes(bytes: &[u8], tenant_id: &str, keys: &TenantKeySet) -> Result<Self> {
        if bytes.len() > MAX_PROVENANCE_BYTES {
            bail!("provenance record exceeds its byte bound");
        }
        let signed: Self = serde_json::from_slice(bytes).context("provenance record does not parse")?;
        if signed.record.tenant_id != tenant_id {
            bail!("provenance record belongs to another tenant");
        }
        signed.record.validate()?;
        if signed.signature.key_id != signed.record.signer_key_id {
            bail!("signature key id differs from the record's signer");
        }
        keys.verify(&signed.signature, &signed.record.signing_message()?)?;
        Ok(signed)
    }
}

// ---------------------------------------------------------------------------
// Owner signing (4.4): `lake-parts:sign`
// ---------------------------------------------------------------------------

/// One record to sign: its canonical bytes (base64) and their SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequestPart {
    pub part_id: PartId,
    pub record_sha256: String,
    /// Inline canonical record bytes (base64). Exactly one of this and
    /// `record_ref` is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_base64: Option<String>,
    /// The canonical record bytes staged at
    /// `{part_dir}/provenance.pending.json` (records whose base64 exceeds
    /// [`INLINE_RECORD_MAX_BASE64`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_ref: Option<RecordRef>,
}

/// A by-reference sign request's staged record (contract 4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordRef {
    /// Bucket key: `{part_dir}/provenance.pending.{record_sha256}.json`.
    pub key: String,
    /// SHA-256 of the staged bytes (= `record_sha256`).
    pub sha256: String,
    pub size_bytes: u64,
}

/// The owner's largest accepted inline `record_base64` (≈47 KiB); a longer
/// one is refused `record_inline_too_large`. The owner-side bound only: the
/// cell sends by reference sooner ([`CELL_INLINE_RECORD_MAX_BASE64`]).
pub const INLINE_RECORD_MAX_BASE64: usize = 47 * 1024;

/// the platform's `MAX_LAKE_PARTS_SIGN_BODY_BYTES`: the owner refuses a larger
/// `lake-parts:sign` body whole (413), so nothing in it is signed. Never
/// raised; the cell must fit (NAN-3006).
pub const OWNER_SIGN_BODY_MAX_BYTES: usize = 64 * 1024;

/// The cell's byte budget for one `lake-parts:sign` body, with margin under
/// [`OWNER_SIGN_BODY_MAX_BYTES`]. [`plan_sign_requests`] splits every batch
/// to fit it.
pub const SIGN_REQUEST_BUDGET_BYTES: usize = 48 * 1024;

/// The cell sends a record by reference once its base64 exceeds this, so
/// one inline part plus the request envelope always fits
/// [`SIGN_REQUEST_BUDGET_BYTES`] (the owner accepts either form for any
/// record up to [`INLINE_RECORD_MAX_BASE64`] inline).
pub const CELL_INLINE_RECORD_MAX_BASE64: usize = 40 * 1024;

/// How one record travels to `lake-parts:sign`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignPayload {
    pub canonical: Vec<u8>,
    /// `Some` when the record must be staged at `RecordRef::key` first.
    pub record_ref: Option<RecordRef>,
}

impl SignPayload {
    pub fn for_record(record: &ProvenanceRecord) -> Result<Self> {
        record.validate()?;
        let canonical = record.canonical_bytes()?;
        let base64_len = canonical.len().div_ceil(3) * 4;
        let record_ref = if base64_len > CELL_INLINE_RECORD_MAX_BASE64 {
            let keys = super::format::PartKeys::new(&record.tenant_id, record.level, record.event_hour, &record.part_id)?;
            let sha256 = sha256_hex(&canonical);
            Some(RecordRef { key: keys.provenance_pending(&sha256), sha256, size_bytes: canonical.len() as u64 })
        } else {
            None
        };
        Ok(Self { canonical, record_ref })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub schema_version: u8,
    pub request_id: String,
    pub tenant_id: String,
    pub parts: Vec<SignRequestPart>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignResult {
    pub part_id: PartId,
    pub record_sha256: String,
    /// Present on success.
    pub signature: Option<Ed25519Signature>,
    /// Present on refusal (stable, secret-free code).
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignResponse {
    pub schema_version: u8,
    pub request_id: String,
    pub results: Vec<SignResult>,
}

impl SignRequest {
    pub fn new(tenant_id: &str, records: &[ProvenanceRecord]) -> Result<Self> {
        if records.is_empty() || records.len() > SIGN_BATCH_MAX {
            bail!("a sign request carries 1..={SIGN_BATCH_MAX} records");
        }
        let parts = records.iter().map(|record| SignRequestPart::for_record(tenant_id, record)).collect::<Result<Vec<_>>>()?;
        Ok(Self::from_parts(tenant_id, parts))
    }

    fn from_parts(tenant_id: &str, parts: Vec<SignRequestPart>) -> Self {
        Self { schema_version: 1, request_id: uuid::Uuid::new_v4().to_string(), tenant_id: tenant_id.to_string(), parts }
    }

    /// The serialized body length: what the owner's body fence measures.
    pub fn body_bytes(&self) -> Result<usize> {
        Ok(serde_json::to_vec(self)?.len())
    }
}

impl SignRequestPart {
    fn for_record(tenant_id: &str, record: &ProvenanceRecord) -> Result<Self> {
        if record.tenant_id != tenant_id {
            bail!("sign request mixes tenants");
        }
        let payload = SignPayload::for_record(record)?;
        let record_sha256 = sha256_hex(&payload.canonical);
        Ok(match payload.record_ref {
            Some(record_ref) => Self { part_id: record.part_id.clone(), record_sha256, record_base64: None, record_ref: Some(record_ref) },
            None => Self {
                part_id: record.part_id.clone(),
                record_sha256,
                record_base64: Some(base64::engine::general_purpose::STANDARD.encode(&payload.canonical)),
                record_ref: None,
            },
        })
    }
}

/// One planned `lake-parts:sign` call: the records it covers (a range of
/// the caller's slice, in order) and its request.
#[derive(Debug, Clone)]
pub struct PlannedSignRequest {
    pub records: std::ops::Range<usize>,
    pub request: SignRequest,
    /// `request.body_bytes()`, computed once.
    pub body_bytes: usize,
}

/// Split `records` into `lake-parts:sign` calls of at most
/// [`SIGN_BATCH_MAX`] parts and at most `budget_bytes` of body each, keeping
/// order (NAN-3006). The owner refuses an over-cap body whole (413), and
/// every L0 record of one flush carries the flush's full source list, so a
/// count-only split of a multi-hour flush exceeds the fence.
///
/// A single part never exceeds the budget: records whose base64 would not
/// fit go by reference ([`CELL_INLINE_RECORD_MAX_BASE64`]); a part that
/// still did would travel alone, and [`OWNER_SIGN_BODY_MAX_BYTES`] is the
/// caller's hard check.
pub fn plan_sign_requests(tenant_id: &str, records: &[ProvenanceRecord], budget_bytes: usize) -> Result<Vec<PlannedSignRequest>> {
    let parts = records.iter().map(|record| SignRequestPart::for_record(tenant_id, record)).collect::<Result<Vec<_>>>()?;
    // `{"schema_version":1,"request_id":"<uuid>","tenant_id":"…","parts":[]}`:
    // the uuid is fixed-width, so the empty envelope's length is exact.
    let envelope = SignRequest::from_parts(tenant_id, Vec::new()).body_bytes()?;
    let sizes = parts.iter().map(|part| Ok(serde_json::to_vec(part)?.len())).collect::<Result<Vec<_>>>()?;
    let mut plans = Vec::new();
    let mut start = 0;
    while start < parts.len() {
        let mut end = start + 1;
        let mut body = envelope + sizes[start];
        while end < parts.len() && end - start < SIGN_BATCH_MAX && body + 1 + sizes[end] <= budget_bytes {
            body += 1 + sizes[end];
            end += 1;
        }
        let request = SignRequest::from_parts(tenant_id, parts[start..end].to_vec());
        plans.push(PlannedSignRequest { records: start..end, request, body_bytes: body });
        start = end;
    }
    Ok(plans)
}

/// Who is calling `lake-parts:sign` (contract 4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerCaller {
    /// A service identity on the owner's mTLS channel (ingest jobs, the
    /// phase-4 adoption job).
    Service,
    /// A cell `ingest[T]` presenting its owner-sign bearer. Never adopts.
    CellBearer,
}

/// The single error code for every failure before the staged bytes are
/// verified, so the route is not an existence or size oracle (H1).
pub const RECORD_REF_INVALID: &str = "record_ref_invalid";

/// Owner step 0 for a by-reference part, BEFORE any read: the key must be
/// exactly `lake/parts/v1/tenant={tenant}/parts/{l0|m|h|d}/{yyyy}/{mm}/{dd}/{hh}/{part_id}/provenance.pending.{record_sha256}.json`
/// and the declared size at most [`MAX_PROVENANCE_BYTES`]. The owner then
/// reads at most `size_bytes + 1` bytes.
pub fn owner_precheck_ref(tenant_id: &str, part: &SignRequestPart) -> Result<()> {
    let ok = (|| {
        let reference = part.record_ref.as_ref()?;
        if part.record_base64.is_some()
            || reference.sha256 != part.record_sha256
            || !is_sha256_hex(&reference.sha256)
            || reference.size_bytes == 0
            || reference.size_bytes > MAX_PROVENANCE_BYTES as u64
        {
            return None;
        }
        let rest = reference.key.strip_prefix(&format!("{}/tenant={tenant_id}/parts/", super::format::PARTS_ROOT))?;
        let segments = rest.split('/').collect::<Vec<_>>();
        let [level, yyyy, mm, dd, hh, part_id, file] = segments.as_slice() else { return None };
        let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
        let ok = matches!(*level, "l0" | "m" | "h" | "d")
            && digits(yyyy, 4)
            && digits(mm, 2)
            && digits(dd, 2)
            && digits(hh, 2)
            && *part_id == part.part_id.as_str()
            && *file == super::format::provenance_pending_file(&part.record_sha256);
        ok.then_some(())
    })();
    ok.context(RECORD_REF_INVALID)
}

/// Owner-side reference checks for one request part (contract 4.4). For a
/// by-reference part the owner runs [`owner_precheck_ref`] first, reads at
/// most `size_bytes + 1` bytes at `record_ref.key`, and passes them here;
/// for an inline part, `None`. The platform implements the same checks; this
/// is the executable spec. File checks follow in [`owner_verify_files`].
pub fn owner_check_part(
    tenant_id: &str,
    part: &SignRequestPart,
    fetched: Option<&[u8]>,
    signer_key_id: &str,
    caller: OwnerCaller,
) -> Result<ProvenanceRecord> {
    let bytes = match (&part.record_base64, &part.record_ref, fetched) {
        (Some(inline), None, None) => {
            if inline.len() > INLINE_RECORD_MAX_BASE64 {
                bail!("record_inline_too_large");
            }
            base64::engine::general_purpose::STANDARD.decode(inline).context("record_invalid")?
        }
        (None, Some(reference), Some(bytes)) => {
            owner_precheck_ref(tenant_id, part)?;
            if reference.size_bytes != bytes.len() as u64 || sha256_hex(bytes) != reference.sha256 {
                bail!(RECORD_REF_INVALID);
            }
            bytes.to_vec()
        }
        _ => bail!("record_payload_invalid"),
    };
    if sha256_hex(&bytes) != part.record_sha256 || bytes.len() > MAX_PROVENANCE_BYTES {
        bail!("record_digest_mismatch");
    }
    let record: ProvenanceRecord = serde_json::from_slice(&bytes).context("record_invalid")?;
    if record.canonical_bytes()? != bytes {
        bail!("record_not_canonical");
    }
    if record.tenant_id != tenant_id || record.part_id != part.part_id {
        bail!("record_binding_mismatch");
    }
    if let Some(reference) = &part.record_ref {
        let keys = super::format::PartKeys::new(&record.tenant_id, record.level, record.event_hour, &record.part_id)?;
        if reference.key != keys.provenance_pending(&part.record_sha256) {
            bail!(RECORD_REF_INVALID);
        }
    }
    if record.signer_key_id != signer_key_id {
        bail!("record_signer_mismatch");
    }
    if caller == OwnerCaller::CellBearer && record.is_adopted() {
        bail!("adopted_not_allowed");
    }
    record.validate().context("record_invalid")?;
    Ok(record)
}

/// Which path wrote an object, per the owner's completion receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptWriter {
    /// Worker / mTLS writer path: the owner streamed-verified the SHA-256 at
    /// PUT and re-hashed at completion (server-verified).
    WorkerMtls,
    /// Written with cell credentials: no server-verified digest.
    Cell,
}

/// The owner's completed writer receipt for one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterReceipt {
    pub bytes: u64,
    pub sha256: String,
    pub etag: String,
    pub writer: ReceiptWriter,
}

/// What the owner can observe about the tenant bucket (contract 4.4 step 6).
pub trait OwnerObjectView {
    fn receipt(&self, key: &str) -> Option<WriterReceipt>;
    /// Length and strong ETag of the live object, if it exists.
    fn live(&self, key: &str) -> Option<(u64, String)>;
    /// Stream-hash the live object, reading at most `max_bytes + 1`.
    fn rehash(&self, key: &str, max_bytes: u64) -> Option<(u64, String)>;
    /// Adopted objects only: the key and digest are in the anchor
    /// generation's object-stamp ledger for this tenant.
    fn adopted_in_ledger(&self, anchor: &AdoptionAnchor, key: &str, sha256: &str) -> bool;
}

/// Owner step 6 (contract 4.4, H2): every file the record names exists as
/// recorded. A receipt skips the re-hash only when it came from the
/// server-verified Worker/mTLS path AND the live object still has the
/// receipt's length and strong ETag; otherwise the object is re-hashed. A
/// caller-declared digest is never evidence. Missing or different:
/// `file_unverified`.
pub fn owner_verify_files(record: &ProvenanceRecord, view: &dyn OwnerObjectView) -> Result<()> {
    let keys = super::format::PartKeys::new(&record.tenant_id, record.level, record.event_hour, &record.part_id)?;
    let mut files: Vec<(String, &str, u64)> = Vec::new();
    for (index, data) in record.files.data.iter().enumerate() {
        files.push((record.data_key(&keys, index).context("data key")?, &data.sha256, data.bytes));
        files.push((keys.file(&data.tokens.name), &data.tokens.sha256, data.tokens.bytes));
        if let Some(ranges) = &data.parquet_ranges {
            files.push((keys.file(&ranges.name), &ranges.sha256, ranges.bytes));
        }
        if let Some(locator) = &data.entity_locators {
            files.push((keys.file(&locator.name), &locator.sha256, locator.bytes));
        }
        if let Some(entity) = &data.entity_blooms {
            files.push((keys.file(&entity.name), &entity.sha256, entity.bytes));
        }
        if let Some(uid) = &data.uid_blooms {
            files.push((keys.file(&uid.name), &uid.sha256, uid.bytes));
        }
    }
    for partial in &record.files.partials {
        files.push((keys.file(&partial.name), &partial.sha256, partial.bytes));
    }
    if let PartInputs::Adopted { anchor, objects } = &record.inputs {
        let object = objects.first().context("adopted part names no object")?;
        if !view.adopted_in_ledger(anchor, &object.key, &object.sha256) {
            bail!("adopted_object_unanchored");
        }
    }
    for (key, sha256, bytes) in files {
        let receipted = view.receipt(&key).filter(|receipt| {
            receipt.writer == ReceiptWriter::WorkerMtls
                && receipt.bytes == bytes
                && receipt.sha256 == sha256
                && view.live(&key) == Some((receipt.bytes, receipt.etag.clone()))
        });
        if receipted.is_some() {
            continue;
        }
        match view.rehash(&key, bytes) {
            Some((len, digest)) if len == bytes && digest == sha256 => {}
            _ => bail!("file_unverified"),
        }
    }
    Ok(())
}

/// Signs provenance records (contract 4.4). Ingest holds no signing key:
/// production is the owner route; [`LocalPartSigner`] is for tests and labs.
#[async_trait::async_trait]
pub trait PartSigner: Send + Sync {
    /// The key id records must name as `signer_key_id`.
    fn key_id(&self) -> &str;
    /// One signature per record, in order.
    async fn sign(&self, tenant_id: &str, records: &[ProvenanceRecord]) -> Result<Vec<Ed25519Signature>>;
    /// NAN-3801: one owner signature per count record, in order. A signer
    /// (or owner release) without the route returns
    /// [`CountSigningUnsupported`]; callers then fall back to a full count
    /// rewrite.
    async fn sign_counts(&self, _tenant_id: &str, _records: &[super::count_record::CountRecord]) -> Result<Vec<Ed25519Signature>> {
        Err(CountSigningUnsupported.into())
    }
}

/// The signer cannot sign count records (owner release predates
/// `lake-part-counts:sign`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("count record signing is unsupported by this owner")]
pub struct CountSigningUnsupported;

/// Sign `records` in as many `signer.sign` calls as
/// [`plan_sign_requests`] needs to keep every call's body within
/// [`SIGN_REQUEST_BUDGET_BYTES`]. One signature per record, in order.
pub async fn sign_within_budget(signer: &dyn PartSigner, tenant_id: &str, records: &[ProvenanceRecord]) -> Result<Vec<Ed25519Signature>> {
    let mut signatures = Vec::with_capacity(records.len());
    for plan in plan_sign_requests(tenant_id, records, SIGN_REQUEST_BUDGET_BYTES)? {
        let batch = &records[plan.records.clone()];
        let signed = signer.sign(tenant_id, batch).await?;
        if signed.len() != batch.len() {
            bail!("owner returned a partial signature batch");
        }
        signatures.extend(signed);
    }
    Ok(signatures)
}

/// An in-process signer that plays the owner (tests, lab).
pub struct LocalPartSigner {
    key_id: String,
    key: SigningKey,
}

impl LocalPartSigner {
    pub fn new(key_id: &str, key: SigningKey) -> Result<Self> {
        if !valid_key_id(key_id) {
            bail!("signer key id is malformed");
        }
        Ok(Self { key_id: key_id.to_string(), key })
    }

    pub fn trusted(&self) -> TenantKeySet {
        TenantKeySet::new([(self.key_id.clone(), self.key.verifying_key())])
    }
}

#[async_trait::async_trait]
impl PartSigner for LocalPartSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn sign(&self, tenant_id: &str, records: &[ProvenanceRecord]) -> Result<Vec<Ed25519Signature>> {
        let request = SignRequest::new(tenant_id, records)?;
        request
            .parts
            .iter()
            .zip(records)
            .map(|(part, record)| {
                // The local stand-in has the record in hand for by-ref parts.
                let staged = part.record_ref.as_ref().map(|_| record.canonical_bytes()).transpose()?;
                let record = owner_check_part(tenant_id, part, staged.as_deref(), &self.key_id, OwnerCaller::Service)?;
                Ok(Ed25519Signature {
                    alg: "ed25519".into(),
                    key_id: self.key_id.clone(),
                    sig: base64::engine::general_purpose::STANDARD
                        .encode(self.key.sign(&record.signing_message()?).to_bytes()),
                })
            })
            .collect()
    }

    async fn sign_counts(&self, tenant_id: &str, records: &[super::count_record::CountRecord]) -> Result<Vec<Ed25519Signature>> {
        // The owner's record checks (the platform), minus the object HEADs.
        records.iter().map(|record| {
            record.validate()?;
            if record.tenant_id != tenant_id {
                bail!("record_binding_mismatch");
            }
            if record.signer_key_id != self.key_id {
                bail!("record_signer_mismatch");
            }
            Ok(Ed25519Signature {
                alg: "ed25519".into(),
                key_id: self.key_id.clone(),
                sig: base64::engine::general_purpose::STANDARD.encode(self.key.sign(&record.signing_message()?).to_bytes()),
            })
        }).collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
    pub const SIGNER: &str = "platform-release-test";

    pub fn signer(seed: u8) -> LocalPartSigner {
        LocalPartSigner::new(SIGNER, test_key(seed)).unwrap()
    }

    pub fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub fn sample_record() -> ProvenanceRecord {
        let zero = "0".repeat(64);
        ProvenanceRecord {
            format: PROVENANCE_FORMAT.to_string(),
            signer_key_id: SIGNER.to_string(),
            tenant_id: TENANT.to_string(),
            part_id: PartId::parse("1790330400123-9f86d081884c7d65").unwrap(),
            level: Level::L0,
            created_at_ms: 1_790_330_400_123,
            event_hour: 497_314,
            event_day: None,
            rows: 2,
            min_time_us: 1,
            max_time_us: 2,
            schema_fingerprint: zero.clone(),
            merkle_root: zero.clone(),
            hours: vec![HourDigest { event_hour: 497_314, rows: 2, min_time_us: 1, max_time_us: 2, merkle_root: zero.clone() }],
            files: PartFiles {
                data: vec![DataFileDigest {
                    name: "data-00000.parquet".into(),
                    bytes: 1,
                    sha256: zero.clone(),
                    rows: 2,
                    row_groups: 1,
                    min_time_us: 1,
                    max_time_us: 2,
                    log_sources: None,
                    uid_blooms: None,
                    entity_blooms: None,
                    parquet_ranges: None,
                    entity_locators: None,
                    class_id: None,
                    tokens: FileDigest { name: "tokens-00000.nti".into(), bytes: 1, sha256: zero.clone() },
                }],
                partials: vec![],
            },
            inputs: PartInputs::Sources {
                sources: vec![SourceObject { key: "k".into(), version: "v".into(), bytes: 1, sha256: zero, rows: 2, edge_sha256: None }],
                edge_log: None,
            },
            admission: Some(Admission {
                ocsf_version: "1.9.0".into(),
                admission_contract: "nano-bronze-admission-v1".into(),
                feed_pins: BTreeMap::new(),
            }),
            lowercased_at_rest: Vec::new(),
            dedup: DedupStats { rows_in: 2, duplicates_dropped: 0, window: super::super::DedupWindow::Exact },
            writer: WriterInfo { role: "ingest".into(), build: "test".into() },
        }
    }

    pub fn adopted_record() -> ProvenanceRecord {
        let mut record = sample_record();
        let sha = "e".repeat(64);
        record.level = Level::Hour;
        record.admission = None;
        record.files.data[0].name = "warehouse/nano/events/data/a.parquet".into();
        record.files.data[0].sha256 = sha.clone();
        record.inputs = PartInputs::Adopted {
            anchor: AdoptionAnchor {
                generation_id: "lake-42-x".into(),
                snapshot_id: 42,
                bundle_identity_sha256: "1".repeat(64),
                object_stamp_manifest_sha256: "2".repeat(64),
                bundle_manifest_key: "bundles/m.json".into(),
                bundle_manifest_sha256: "3".repeat(64),
                signer_key_id: "platform-bundle-2026-01".into(),
            },
            objects: vec![AdoptedObject {
                key: "warehouse/nano/events/data/a.parquet".into(),
                bytes: 1,
                sha256: sha,
                rows: 2,
                stamp_sha256: "4".repeat(64),
            }],
        };
        record
    }

    #[tokio::test]
    async fn uid_sidecar_digest_is_signed_and_names_are_bounded() {
        let mut record = sample_record();
        record.files.data[0].uid_blooms = Some(FileDigest {
            name: "uids-00000.json".into(), bytes: 64, sha256: "a".repeat(64),
        });
        record.validate().unwrap();
        assert!(record.files.all().iter().any(|(name, _, _)| *name == "uids-00000.json"));
        let owner = signer(1);
        let signature = owner.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let bytes = SignedProvenance::assemble(record.clone(), signature, &owner.trusted()).unwrap().to_bytes().unwrap();
        SignedProvenance::verify_bytes(&bytes, TENANT, &owner.trusted()).unwrap();
        let tampered = String::from_utf8(bytes).unwrap().replace(&"a".repeat(64), &"b".repeat(64));
        assert!(SignedProvenance::verify_bytes(tampered.as_bytes(), TENANT, &owner.trusted()).is_err());
        record.files.data[0].uid_blooms.as_mut().unwrap().name = "../uids-00000.json".into();
        assert!(record.validate().is_err());
    }

    #[tokio::test]
    async fn entity_sidecar_digest_is_signed_and_names_are_bounded() {
        let mut record = sample_record();
        record.files.data[0].entity_blooms = Some(FileDigest {
            name: "entities-00000.json".into(), bytes: 64, sha256: "a".repeat(64),
        });
        record.validate().unwrap();
        assert!(record.files.all().iter().any(|(name, _, _)| *name == "entities-00000.json"));
        let owner = signer(1);
        let signature = owner.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let bytes = SignedProvenance::assemble(record.clone(), signature, &owner.trusted()).unwrap().to_bytes().unwrap();
        SignedProvenance::verify_bytes(&bytes, TENANT, &owner.trusted()).unwrap();
        let tampered = String::from_utf8(bytes).unwrap().replace(&"a".repeat(64), &"b".repeat(64));
        assert!(SignedProvenance::verify_bytes(tampered.as_bytes(), TENANT, &owner.trusted()).is_err());
        record.files.data[0].entity_blooms.as_mut().unwrap().name = "../entities-00000.json".into();
        assert!(record.validate().is_err());
    }

    #[tokio::test]
    async fn entity_locator_digest_and_class_are_signed_tenant_bound_and_bounded() {
        let mut record = sample_record();
        record.files.data[0].entity_locators = Some(FileDigest {
            name: "locators-00000.json".into(), bytes: 64, sha256: "a".repeat(64),
        });
        record.level = Level::Hour;
        record.admission = None;
        record.inputs = PartInputs::Parts { parts: vec![InputPart {
            part_id: PartId::new(1).unwrap(), level: Level::Minute, provenance_sha256: "0".repeat(64), rows: 2, merkle_root: "0".repeat(64),
        }] };
        record.files.data[0].log_sources = Some(vec!["sysmon".into()]);
        record.files.data[0].class_id = Some(1007);
        record.validate().unwrap();
        assert!(record.files.all().iter().any(|(name, _, _)| *name == "locators-00000.json"));
        let owner = signer(1);
        let signature = owner.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let bytes = SignedProvenance::assemble(record.clone(), signature, &owner.trusted()).unwrap().to_bytes().unwrap();
        SignedProvenance::verify_bytes(&bytes, TENANT, &owner.trusted()).unwrap();
        for (from, to) in [("a".repeat(64), "b".repeat(64)), ("1007".into(), "1008".into())] {
            let tampered = String::from_utf8(bytes.clone()).unwrap().replace(&from, &to);
            assert!(SignedProvenance::verify_bytes(tampered.as_bytes(), TENANT, &owner.trusted()).is_err());
        }
        assert!(SignedProvenance::verify_bytes(&bytes, "00000000-0000-0000-0000-000000000001", &owner.trusted()).is_err());
        record.files.data[0].entity_locators.as_mut().unwrap().name = "../locators-00000.json".into();
        assert!(record.validate().is_err());
    }

    #[tokio::test]
    async fn adopted_records_bind_the_original_object_as_their_data_file() {
        let record = adopted_record();
        record.validate().unwrap();
        assert!(record.is_adopted());
        let keys = super::super::format::PartKeys::new(TENANT, Level::Hour, 497_314, &record.part_id).unwrap();
        assert_eq!(record.data_key(&keys, 0).unwrap(), "warehouse/nano/events/data/a.parquet");
        assert_eq!(sample_record().data_key(&keys, 0).unwrap(), keys.data(0));
        // Owner-signed like any record; the anchor is covered by the signature.
        let owner = signer(1);
        let signature = owner.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let bytes = SignedProvenance::assemble(record.clone(), signature, &owner.trusted()).unwrap().to_bytes().unwrap();
        SignedProvenance::verify_bytes(&bytes, TENANT, &owner.trusted()).unwrap();
        let tampered = String::from_utf8(bytes).unwrap().replace("lake-42-x", "lake-43-x");
        assert!(SignedProvenance::verify_bytes(tampered.as_bytes(), TENANT, &owner.trusted()).is_err());

        let mut wrong = record.clone();
        wrong.files.data[0].name = "data-00000.parquet".into();
        assert!(wrong.validate().is_err(), "the data file must be the adopted object");
        let mut wrong = record.clone();
        wrong.files.data[0].sha256 = "f".repeat(64);
        assert!(wrong.validate().is_err());
        let mut wrong = record.clone();
        if let PartInputs::Adopted { objects, .. } = &mut wrong.inputs {
            objects.push(objects[0].clone());
        }
        assert!(wrong.validate().is_err());
        let mut wrong = record.clone();
        wrong.files.data[0].name = "lake/parts/v1/x.parquet".into();
        if let PartInputs::Adopted { objects, .. } = &mut wrong.inputs {
            objects[0].key = "lake/parts/v1/x.parquet".into();
        }
        assert!(wrong.validate().is_err(), "an adopted key may not point into the parts root");
        for key in ["lake/parts/v2/x.parquet", "lake/parts/x", "/a", "a//b", "a/../b", "s3://b/a"] {
            assert!(!is_adopted_object_key(key), "{key}");
        }
        assert!(is_adopted_object_key("lake/partsx/a.parquet"));
        assert!(is_adopted_object_key("warehouse/nano/events/data/event_hour=1/a.parquet"));
        // A written part may not name a foreign key as its data file.
        let mut wrong = sample_record();
        wrong.files.data[0].name = "warehouse/nano/events/data/a.parquet".into();
        assert!(wrong.validate().is_err());
    }

    /// Vectors computed by the edge-log DO prototype (`src/edge-log.js`).
    #[test]
    fn edge_log_chain_matches_the_durable_object() {
        let genesis = edge_log_genesis(TENANT);
        assert_eq!(genesis, "5498f6b51d4c9bb958a35a4ab559be12a86a5698b697455056b2572bf4281447");
        let c1 = edge_log_next_chain(&genesis, 1, "k1", &"a".repeat(64), 10);
        assert_eq!(c1, "689e2284a723c1b4ab492f5e4062e21431500615315cc59a6be420c153fd4e8c");
        let c2 = edge_log_next_chain(&c1, 2, "k2", &"b".repeat(64), 20);
        assert_eq!(c2, "39b4d1a0cd64d1ed6d33b9cc2a2e6addb05d0a6eb62c88c2d7d5a8b76dc0015e");
    }

    fn edge_record() -> (ProvenanceRecord, EdgeLogRange) {
        let genesis = edge_log_genesis(TENANT);
        let k1 = format!("bronze-v2/shard=0/tenant_id={TENANT}/1790330400-a.parquet");
        let k2 = format!("bronze-v2/shard=1/tenant_id={TENANT}/1790330401-b.parquet");
        let sources = vec![
            SourceObject { key: k1.clone(), version: "edge-log-v1:1".into(), bytes: 10, sha256: "a".repeat(64), rows: 1, edge_sha256: None },
            SourceObject { key: k2.clone(), version: "edge-log-v1:2".into(), bytes: 20, sha256: "b".repeat(64), rows: 1, edge_sha256: None },
        ];
        let c1 = edge_log_next_chain(&genesis, 1, &k1, &"a".repeat(64), 10);
        let range = EdgeLogRange {
            log: format!("edgelog:{TENANT}"),
            contract: EDGE_LOG_CONTRACT.into(),
            first_seq: 1,
            through_seq: 2,
            prev_chain: genesis,
            through_chain: edge_log_next_chain(&c1, 2, &k2, &"b".repeat(64), 20),
            skipped: vec![],
            rows_in: 2,
            rows_rejected: 0,
            rows_duplicate: 0,
        };
        let mut record = sample_record();
        record.inputs = PartInputs::Sources { sources, edge_log: Some(range.clone()) };
        (record, range)
    }

    #[test]
    fn edge_log_range_is_signed_and_recomputed() {
        let owner = signer(1);
        let (record, _) = edge_record();
        let signature = futures::executor::block_on(owner.sign(TENANT, std::slice::from_ref(&record))).unwrap().remove(0);
        let bytes = SignedProvenance::assemble(record, signature, &owner.trusted()).unwrap().to_bytes().unwrap();
        assert!(SignedProvenance::verify_bytes(&bytes, TENANT, &owner.trusted()).is_ok());

        // A dropped, reordered or altered segment no longer recomputes.
        let (mut record, _) = edge_record();
        if let PartInputs::Sources { sources, .. } = &mut record.inputs {
            sources[1].sha256 = "c".repeat(64);
        }
        assert!(record.validate().is_err());
        let (mut record, _) = edge_record();
        if let PartInputs::Sources { sources, .. } = &mut record.inputs {
            sources.pop();
        }
        assert!(record.validate().is_err());
        let (mut record, _) = edge_record();
        if let PartInputs::Sources { edge_log: Some(range), .. } = &mut record.inputs {
            range.log = "edgelog:00000000-0000-4000-8000-000000000000".into();
        }
        assert!(record.validate().is_err());
    }

    #[test]
    fn edge_log_accepts_sorted_sources_and_explicit_skips() {
        // Writers sort sources by key; validation orders by seq.
        let (mut record, _) = edge_record();
        if let PartInputs::Sources { sources, .. } = &mut record.inputs {
            sources.reverse();
        }
        assert!(record.validate().is_ok());
        // Segment 1 rejected by admission: it is a skip, not a source.
        let (mut record, _) = edge_record();
        if let PartInputs::Sources { sources, edge_log: Some(range) } = &mut record.inputs {
            let first = sources.remove(0);
            range.skipped.push(EdgeSkippedSegment {
                seq: 1, key: first.key, sha256: first.sha256, length: first.bytes, reason: EdgeSkipReason::ConsumedWithoutRows,
                rows: 1, rows_rejected: 1, rows_duplicate: 0,
            });
            range.rows_rejected = 1;
        }
        assert!(record.validate().is_ok());
        // A range may not end on a skip, and a segment may not be both.
        let (mut record, _) = edge_record();
        if let PartInputs::Sources { sources, edge_log: Some(range) } = &mut record.inputs {
            let last = sources[1].clone();
            range.skipped.push(EdgeSkippedSegment {
                seq: 2, key: last.key, sha256: last.sha256, length: last.bytes, reason: EdgeSkipReason::ConsumedWithoutRows,
                rows: 1, rows_rejected: 0, rows_duplicate: 1,
            });
        }
        assert!(record.validate().is_err());
        assert_eq!(edge_log_seq_of_version("edge-log-v1:42"), Some(42));
        for bad in ["edge-log-v1:", "edge-log-v1:042", "edge-log-v1:4x", "v1:4", "edge-log-v1:0"] {
            assert_eq!(edge_log_seq_of_version(bad), None, "{bad}");
        }
    }

    #[test]
    fn edge_log_rejects_foreign_keys_bad_digests_and_unbalanced_rows() {
        let (mut record, _) = edge_record();
        if let PartInputs::Sources { sources, .. } = &mut record.inputs {
            sources[0].key = "bronze-v2/shard=0/tenant_id=00000000-0000-4000-8000-000000000000/x.parquet".into();
        }
        assert!(record.validate().is_err(), "another tenant's segment");
        let (mut record, _) = edge_record();
        if let PartInputs::Sources { sources, .. } = &mut record.inputs {
            sources[0].key.push('\n');
        }
        assert!(record.validate().is_err(), "newline in a chained key");
        let (mut record, _) = edge_record();
        if let PartInputs::Sources { sources, .. } = &mut record.inputs {
            sources[0].sha256 = "Z".repeat(64);
        }
        assert!(record.validate().is_err());
        let (mut record, _) = edge_record();
        if let PartInputs::Sources { edge_log: Some(range), .. } = &mut record.inputs {
            range.rows_in = 3;
        }
        assert!(record.validate().is_err(), "rows_in must equal the segments' rows");
        assert_eq!(edge_log_seq_of_version("edge-log-v1:9007199254740992"), None);
        let (_, range) = edge_record();
        let max = EdgeLogRange { through_seq: u64::MAX, ..range.clone() };
        let next = EdgeLogRange { first_seq: 1, ..range };
        assert!(next.follows(&max).is_err(), "no overflow on +1");
    }

    #[test]
    fn edge_log_is_additive_and_parts_must_link() {
        // Records without edge_log serialize without the key (signatures unchanged).
        let plain = serde_json::to_string(&sample_record()).unwrap();
        assert!(!plain.contains("edge_log"));
        let (_, first) = edge_record();
        let next = EdgeLogRange { first_seq: 3, through_seq: 3, prev_chain: first.through_chain.clone(), ..first.clone() };
        assert!(next.follows(&first).is_ok());
        let gap = EdgeLogRange { first_seq: 4, ..next.clone() };
        assert!(gap.follows(&first).is_err());
        let forged = EdgeLogRange { prev_chain: "d".repeat(64), ..next };
        assert!(forged.follows(&first).is_err());
    }

    #[tokio::test]
    async fn large_records_sign_by_reference_to_the_staged_pending_file() {
        let mut record = sample_record();
        // ~600 sources push the canonical record past the inline budget.
        if let PartInputs::Sources { sources, .. } = &mut record.inputs {
            let one = sources[0].clone();
            *sources = (0..600).map(|i| SourceObject { key: format!("bronze/object-{i:06}.parquet"), ..one.clone() }).collect();
        }
        let payload = SignPayload::for_record(&record).unwrap();
        let reference = payload.record_ref.clone().expect("by reference");
        let keys = super::super::format::PartKeys::new(TENANT, record.level, record.event_hour, &record.part_id).unwrap();
        assert_eq!(reference.key, keys.provenance_pending(&reference.sha256));
        assert!(reference.key.ends_with(&format!("/provenance.pending.{}.json", reference.sha256)));
        owner_precheck_ref(TENANT, &SignRequest::new(TENANT, std::slice::from_ref(&record)).unwrap().parts[0]).unwrap();
        let request = SignRequest::new(TENANT, std::slice::from_ref(&record)).unwrap();
        let part = &request.parts[0];
        assert!(part.record_base64.is_none());
        assert!(owner_check_part(TENANT, part, Some(&payload.canonical), SIGNER, OwnerCaller::Service).is_ok());
        assert!(owner_check_part(TENANT, part, None, SIGNER, OwnerCaller::Service).is_err(), "by-ref needs the staged bytes");
        // H1: every pre-read failure is one code, and nothing outside the
        // record's own pending key (or over the size bound) is ever read.
        for mutate in [
            |p: &mut SignRequestPart| p.record_ref.as_mut().unwrap().key = "lake/parts/v1/tenant=other/x.json".into(),
            |p: &mut SignRequestPart| p.record_ref.as_mut().unwrap().key = "bronze-v2/secret.parquet".into(),
            |p: &mut SignRequestPart| p.record_ref.as_mut().unwrap().size_bytes = 3 * 1024 * 1024 * 1024,
            |p: &mut SignRequestPart| p.record_ref.as_mut().unwrap().sha256 = "f".repeat(64),
        ] {
            let mut probe = part.clone();
            mutate(&mut probe);
            let error = owner_precheck_ref(TENANT, &probe).unwrap_err();
            assert_eq!(error.to_string(), RECORD_REF_INVALID);
        }
        let mut wrong_key = part.clone();
        wrong_key.record_ref.as_mut().unwrap().key = keys.file(&super::super::format::provenance_pending_file(&"0".repeat(64)));
        assert!(owner_check_part(TENANT, &wrong_key, Some(&payload.canonical), SIGNER, OwnerCaller::Service).is_err());
        let mut tampered = payload.canonical.clone();
        tampered[10] ^= 1;
        assert!(owner_check_part(TENANT, part, Some(&tampered), SIGNER, OwnerCaller::Service).is_err());
        // The local signer signs it all the same.
        let owner = signer(1);
        let signature = owner.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
        SignedProvenance::assemble(record, signature, &owner.trusted()).unwrap();
        // Small records stay inline.
        assert!(SignPayload::for_record(&sample_record()).unwrap().record_ref.is_none());
    }

    /// Reference recursive RFC 6962 MTH.
    fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let mut k = 1;
        while k * 2 < leaves.len() {
            k *= 2;
        }
        node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
    }

    #[test]
    fn streaming_merkle_matches_rfc6962_for_every_size() {
        for n in 1..=70_usize {
            let leaves = (0..n).map(|i| leaf_hash(&format!("u{i}"), &[i as u8; 32])).collect::<Vec<_>>();
            let mut builder = MerkleBuilder::new();
            leaves.iter().for_each(|leaf| builder.push_leaf(*leaf));
            assert_eq!(builder.root().unwrap(), mth(&leaves), "n = {n}");
        }
        assert!(MerkleBuilder::new().root().is_none());
    }

    #[test]
    fn leaf_is_length_prefixed() {
        let d = [7_u8; 32];
        assert_ne!(leaf_hash("ab", &d), leaf_hash("a", &d));
    }

    async fn sign_one(signer: &LocalPartSigner, record: ProvenanceRecord) -> SignedProvenance {
        let signature = signer.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
        SignedProvenance::assemble(record, signature, &signer.trusted()).unwrap()
    }

    #[tokio::test]
    async fn signed_record_verifies_and_rejects_tampering() {
        let signer = signer(1);
        let keys = signer.trusted();
        let signed = sign_one(&signer, sample_record()).await;
        let bytes = signed.to_bytes().unwrap();
        assert_eq!(SignedProvenance::verify_bytes(&bytes, TENANT, &keys).unwrap(), signed);
        // Stored bytes are canonical: sorted keys, compact.
        assert_eq!(bytes, canonical_json_bytes(&serde_json::from_slice(&bytes).unwrap()).unwrap());
        assert!(String::from_utf8(bytes.clone()).unwrap().starts_with("{\"record\":{\"admission\":"));

        let tampered = String::from_utf8(bytes.clone()).unwrap().replace("\"rows\":2,\"schema", "\"rows\":3,\"schema");
        assert_ne!(tampered.as_bytes(), bytes.as_slice());
        assert!(SignedProvenance::verify_bytes(tampered.as_bytes(), TENANT, &keys).is_err());
        // Wrong tenant, untrusted key, unknown field.
        assert!(SignedProvenance::verify_bytes(&bytes, "00000000-0000-0000-0000-000000000000", &keys).is_err());
        assert!(SignedProvenance::verify_bytes(&bytes, TENANT, &self::signer(2).trusted()).is_err());
        let extra = String::from_utf8(bytes).unwrap().replacen("{", "{\"extra\":1,", 1);
        assert!(SignedProvenance::verify_bytes(extra.as_bytes(), TENANT, &keys).is_err());
    }

    #[test]
    fn signing_message_is_domain_then_canonical_bytes() {
        let record = sample_record();
        let message = record.signing_message().unwrap();
        assert!(message.starts_with(b"nano-lake-part-provenance-v1\0{"));
        assert_eq!(&message[PROVENANCE_SIGNATURE_DOMAIN.len()..], record.canonical_bytes().unwrap().as_slice());
        // Pinned canonical form of a small value (the owner must match it).
        let value = serde_json::json!({"b": [2, null, "x\u{1}é"], "a": {"d": true, "c": -3}});
        assert_eq!(
            String::from_utf8(canonical_json_bytes(&value).unwrap()).unwrap(),
            "{\"a\":{\"c\":-3,\"d\":true},\"b\":[2,null,\"x\\u0001é\"]}"
        );
        assert!(canonical_json_bytes(&serde_json::json!({"f": 1.5})).is_err());
        assert!(canonical_json_bytes(&serde_json::json!({"n": 9_007_199_254_740_992_u64})).is_err());
    }

    #[test]
    fn owner_check_refuses_non_canonical_or_foreign_records() {
        let record = sample_record();
        let request = SignRequest::new(TENANT, std::slice::from_ref(&record)).unwrap();
        assert!(owner_check_part(TENANT, &request.parts[0], None, SIGNER, OwnerCaller::Service).is_ok());
        assert!(owner_check_part(TENANT, &request.parts[0], None, "other-signer-key", OwnerCaller::Service).is_err());
        let mut pretty = request.parts[0].clone();
        let bytes = serde_json::to_vec_pretty(&record).unwrap();
        pretty.record_sha256 = sha256_hex(&bytes);
        pretty.record_base64 = Some(base64::engine::general_purpose::STANDARD.encode(&bytes));
        assert!(owner_check_part(TENANT, &pretty, None, SIGNER, OwnerCaller::Service).is_err());
        assert!(SignRequest::new(TENANT, &vec![record; SIGN_BATCH_MAX + 1]).is_err());
    }

    #[test]
    fn record_validation_binds_inputs_to_level() {
        let mut record = sample_record();
        record.level = Level::Hour;
        assert!(record.validate().is_err());
        let mut record = sample_record();
        record.hours[0].rows = 1;
        assert!(record.validate().is_err());
    }

    #[test]
    fn row_digest_ignores_additive_null_columns() {
        use arrow_array::{ArrayRef, Int64Array, StringArray};
        use arrow_schema::{DataType, Field, Schema};
        use std::sync::Arc;
        let a = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new("x", DataType::Int64, true)])),
            vec![Arc::new(Int64Array::from(vec![1, 2])) as ArrayRef],
        )
        .unwrap();
        let b = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new("x", DataType::Int64, true), Field::new("y", DataType::Utf8, true)])),
            vec![
                Arc::new(Int64Array::from(vec![1, 2])) as ArrayRef,
                Arc::new(StringArray::from(vec![None::<&str>, None])) as ArrayRef,
            ],
        )
        .unwrap();
        assert_eq!(row_digests(&a).unwrap(), row_digests(&b).unwrap());
        let c = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new("y", DataType::Utf8, true), Field::new("x", DataType::Int64, true)])),
            vec![
                Arc::new(StringArray::from(vec![None::<&str>, None])) as ArrayRef,
                Arc::new(Int64Array::from(vec![1, 2])) as ArrayRef,
            ],
        )
        .unwrap();
        assert_eq!(row_digests(&a).unwrap(), row_digests(&c).unwrap());
    }

    // -----------------------------------------------------------------------
    // NAN-3006: byte-bounded `lake-parts:sign` requests
    // -----------------------------------------------------------------------

    /// A production-shaped edge segment source (`bronze-v2/shard=<n>/tenant_id=<t>/<file>`).
    fn edge_source(seq: u64, key_len: usize) -> SourceObject {
        let prefix = format!("bronze-v2/shard=0/tenant_id={TENANT}/");
        let stem = format!("{:010}-{seq:08}-", 1_790_330_400 + seq);
        let pad = key_len.saturating_sub(prefix.len() + stem.len() + ".parquet".len());
        SourceObject {
            key: format!("{prefix}{stem}{}.parquet", "f".repeat(pad)),
            version: format!("{EDGE_LOG_VERSION_PREFIX}{seq}"),
            bytes: 184_000,
            sha256: format!("{:064x}", seq),
            rows: 750,
            edge_sha256: None,
        }
    }

    /// An L0 record of `hour` naming `sources` edge segments, with every
    /// partial kind, like a live flush.
    fn flush_record(hour_offset: i32, sources: usize, key_len: usize) -> ProvenanceRecord {
        let mut record = sample_record();
        record.part_id = PartId::parse(&format!("17903304001{:02}-9f86d081884c7d{:02x}", hour_offset, hour_offset)).unwrap();
        record.event_hour += hour_offset;
        record.hours[0].event_hour = record.event_hour;
        record.files.partials = [PartialKind::Rollup, PartialKind::Prevalence, PartialKind::EntityRanges, PartialKind::Risk]
            .into_iter()
            .map(|kind| PartialDigest { kind, name: format!("partial-{kind:?}.parquet").to_lowercase(), bytes: 4_096, sha256: "c".repeat(64), rows: 100 })
            .collect();
        record.inputs = PartInputs::Sources { sources: (0..sources as u64).map(|seq| edge_source(5_989 + seq, key_len)).collect(), edge_log: None };
        record
    }

    fn check_plans(records: &[ProvenanceRecord], plans: &[PlannedSignRequest]) {
        let mut next = 0;
        for plan in plans {
            assert_eq!(plan.records.start, next, "plans cover the records in order");
            assert!(!plan.records.is_empty() && plan.records.len() <= SIGN_BATCH_MAX);
            assert_eq!(plan.body_bytes, plan.request.body_bytes().unwrap(), "planned size is the wire size");
            assert!(plan.body_bytes <= SIGN_REQUEST_BUDGET_BYTES, "{} > budget", plan.body_bytes);
            let ids = plan.request.parts.iter().map(|p| p.part_id.clone()).collect::<Vec<_>>();
            let want = records[plan.records.clone()].iter().map(|r| r.part_id.clone()).collect::<Vec<_>>();
            assert_eq!(ids, want);
            next = plan.records.end;
        }
        assert_eq!(next, records.len());
    }

    /// The incident shape (INGEST-STALL-D3C1): a restart backlog of ~110 edge
    /// segments flushed while it straddles an hour boundary makes one L0 part
    /// per hour, each naming every segment. Split by count only, the two
    /// inline records are one ~90 KB body the owner refuses (413) forever.
    #[test]
    fn a_multi_hour_backlog_flush_splits_under_the_owner_cap() {
        for sources in [64, 87, 108, 114] {
            let records = (0..3).map(|hour| flush_record(hour, sources, 120)).collect::<Vec<_>>();
            let plans = plan_sign_requests(TENANT, &records, SIGN_REQUEST_BUDGET_BYTES).unwrap();
            check_plans(&records, &plans);
            assert!(plans.iter().all(|p| p.body_bytes <= OWNER_SIGN_BODY_MAX_BYTES));
        }
        // The count-only request the stalled image sent: > the owner cap.
        // (Pre-fix the cell inlined up to 47 KiB of base64 per record.)
        let records = (0..2).map(|hour| flush_record(hour, 108, 120)).collect::<Vec<_>>();
        let inline = records
            .iter()
            .map(|record| {
                let canonical = record.canonical_bytes().unwrap();
                let base64 = base64::engine::general_purpose::STANDARD.encode(&canonical);
                assert!(base64.len() <= INLINE_RECORD_MAX_BASE64, "inline under the pre-fix threshold");
                SignRequestPart { part_id: record.part_id.clone(), record_sha256: sha256_hex(&canonical), record_base64: Some(base64), record_ref: None }
            })
            .collect::<Vec<_>>();
        let legacy = SignRequest::from_parts(TENANT, inline).body_bytes().unwrap();
        assert!(legacy > OWNER_SIGN_BODY_MAX_BYTES, "the pre-fix request was {legacy} bytes");
    }

    #[test]
    fn the_splitter_keeps_the_count_bound_and_packs_small_records() {
        let small = (0..40).map(|i| {
            let mut record = sample_record();
            record.part_id = PartId::parse(&format!("1790330400{i:03}-9f86d081884c7d65")).unwrap();
            record
        }).collect::<Vec<_>>();
        let plans = plan_sign_requests(TENANT, &small, SIGN_REQUEST_BUDGET_BYTES).unwrap();
        check_plans(&small, &plans);
        assert_eq!(plans.iter().map(|p| p.records.len()).collect::<Vec<_>>(), vec![16, 16, 8]);
        // Mixed sizes: every call stays in budget; a tiny budget sends one per call.
        let mixed = (0..6).map(|i| flush_record(i, [2, 60, 5, 90, 1, 40][i as usize], 120)).collect::<Vec<_>>();
        check_plans(&mixed, &plan_sign_requests(TENANT, &mixed, SIGN_REQUEST_BUDGET_BYTES).unwrap());
        let one_each = plan_sign_requests(TENANT, &mixed, 1).unwrap();
        assert_eq!(one_each.len(), mixed.len());
        assert!(plan_sign_requests(TENANT, &[], SIGN_REQUEST_BUDGET_BYTES).unwrap().is_empty());
        let mut foreign = sample_record();
        foreign.tenant_id = "0f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00".into();
        assert!(plan_sign_requests(TENANT, &[foreign], SIGN_REQUEST_BUDGET_BYTES).is_err());
    }

    /// Guard: the largest record the cell still sends inline, and the
    /// largest by-reference part, each fit the budget alone. Whatever a flush
    /// holds, no single part can push a body past the owner cap.
    #[test]
    fn the_worst_case_single_part_body_stays_under_the_budget() {
        // Grow the source list until the record just stops being inline.
        let mut last_inline = None;
        for sources in 1..400 {
            let record = flush_record(0, sources, 1_024);
            let request = SignRequest::new(TENANT, std::slice::from_ref(&record)).unwrap();
            if request.parts[0].record_base64.is_some() {
                last_inline = Some(request.body_bytes().unwrap());
            } else {
                let by_ref = request.body_bytes().unwrap();
                assert!(by_ref < 1_024, "a by-reference part is small: {by_ref}");
                break;
            }
        }
        let worst = last_inline.expect("some record is inline");
        assert!(worst > CELL_INLINE_RECORD_MAX_BASE64 - 2 * 1_400, "the probe reached the inline threshold: {worst}");
        assert!(worst <= SIGN_REQUEST_BUDGET_BYTES, "worst inline body {worst} > budget");
        // Maximum-width identifiers: the envelope and a by-ref part.
        let mut record = flush_record(0, 600, 1_024);
        record.part_id = PartId::parse("1790330400999-ffffffffffffffff").unwrap();
        let request = SignRequest::new(TENANT, std::slice::from_ref(&record)).unwrap();
        assert!(request.parts[0].record_ref.is_some());
        assert!(request.body_bytes().unwrap() <= SIGN_REQUEST_BUDGET_BYTES);
        // A full batch of by-ref parts still fits one call.
        let refs = (0..SIGN_BATCH_MAX as i32).map(|h| flush_record(h, 600, 1_024)).collect::<Vec<_>>();
        let plans = plan_sign_requests(TENANT, &refs, SIGN_REQUEST_BUDGET_BYTES).unwrap();
        check_plans(&refs, &plans);
        assert_eq!(plans.len(), 1);
    }

    /// Guard for the ingest flush cap (`MAX_FLUSH_OBJECTS` = 512): a record
    /// naming 512 sources at the 1 KiB key maximum stays a valid by-ref record.
    #[test]
    fn a_full_flush_record_stays_under_the_provenance_cap() {
        let record = flush_record(0, 512, 1_024);
        let canonical = record.canonical_bytes().unwrap();
        assert!(canonical.len() <= MAX_PROVENANCE_BYTES * 3 / 4, "{} bytes", canonical.len());
        let owner = signer(1);
        futures::executor::block_on(owner.sign(TENANT, std::slice::from_ref(&record))).unwrap();
    }
}

#[cfg(test)]
mod owner_vector_tests {
    use super::*;

    #[tokio::test]
    async fn source_family_r35_provenance_vector() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lake-part-provenance-source-family-r3.5.json");
        let signer = vector_signer();
        let mut record = super::tests::sample_record();
        record.signer_key_id = VECTOR_KEY_ID.into();
        record.level = Level::Hour;
        record.admission = None;
        record.inputs = PartInputs::Parts { parts: vec![InputPart {
            part_id: PartId::parse("1790330400122-0000000000000001").unwrap(), level: Level::Minute,
            provenance_sha256: "1".repeat(64), rows: 2, merkle_root: "2".repeat(64),
        }] };
        record.files.data[0].log_sources = Some(vec!["windows_security".into()]);
        record.validate().unwrap();
        let signature = signer.sign(&record.tenant_id, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let signed = SignedProvenance::assemble(record.clone(), signature, &signer.trusted()).unwrap();
        let vector = serde_json::json!({
            "domain": "nano-lake-part-provenance-v1",
            "record_canonical": String::from_utf8(record.canonical_bytes().unwrap()).unwrap(),
            "stored_provenance_json": String::from_utf8(signed.to_bytes().unwrap()).unwrap(),
        });
        if std::env::var("NANO_WRITE_SOURCE_FAMILY_VECTOR").is_ok() {
            std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&vector).unwrap())).unwrap();
            return;
        }
        let expected: serde_json::Value = serde_json::from_str(include_str!("../../tests/fixtures/lake-part-provenance-source-family-r3.5.json")).unwrap();
        assert_eq!(vector, expected);
        assert_eq!(SignedProvenance::verify_bytes(&signed.to_bytes().unwrap(), &record.tenant_id, &signer.trusted()).unwrap().record, record);
        let mut invalid = record;
        invalid.files.data[0].log_sources = Some(vec!["z".into(), "a".into()]);
        assert!(invalid.validate().is_err());
    }

    /// Regenerate with `NANO_WRITE_ADMISSION_V2_VECTOR=1`; the signer uses a
    /// public test seed, never a release key.
    #[tokio::test]
    async fn admission_v2_lowercase_provenance_vector() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lake-part-provenance-admission-v2.json");
        let signer = vector_signer();
        let mut record = super::tests::sample_record();
        record.signer_key_id = VECTOR_KEY_ID.into();
        record.admission.as_mut().unwrap().admission_contract = ADMISSION_CONTRACT.into();
        record.lowercased_at_rest = LOWERCASED_AT_REST.iter().map(|path| (*path).into()).collect();
        let signature = signer.sign(&record.tenant_id, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let signed = SignedProvenance::assemble(record.clone(), signature, &signer.trusted()).unwrap();
        let vector = serde_json::json!({
            "domain": "nano-lake-part-provenance-v1",
            "record_canonical": String::from_utf8(record.canonical_bytes().unwrap()).unwrap(),
            "stored_provenance_json": String::from_utf8(signed.to_bytes().unwrap()).unwrap(),
        });
        if std::env::var("NANO_WRITE_ADMISSION_V2_VECTOR").is_ok() {
            std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&vector).unwrap())).unwrap();
            return;
        }
        let expected: serde_json::Value = serde_json::from_str(include_str!("../../tests/fixtures/lake-part-provenance-admission-v2.json")).unwrap();
        assert_eq!(vector, expected);
        assert_eq!(SignedProvenance::verify_bytes(&signed.to_bytes().unwrap(), &record.tenant_id, &signer.trusted()).unwrap().record, record);
        let mut wrong = record;
        wrong.lowercased_at_rest.pop();
        assert!(wrong.validate().is_err());
    }

    /// the platform's owner signer (lake-part-sign.ts, #1551) signed this vector;
    /// the Rust canonical form and verifier must agree with it byte for byte.
    #[test]
    fn nano_main_owner_signed_vector_verifies() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/lake-part-provenance-owner-signed-v1.json")).unwrap();
        let text = |k: &str| vector[k].as_str().unwrap().to_string();
        let public: [u8; 32] = hex::decode(text("public_key_hex")).unwrap().try_into().unwrap();
        let keys = TenantKeySet::new([(text("signer_key_id"), VerifyingKey::from_bytes(&public).unwrap())]);
        let record: ProvenanceRecord = serde_json::from_str(&text("record_canonical")).unwrap();
        assert_eq!(String::from_utf8(record.canonical_bytes().unwrap()).unwrap(), text("record_canonical"));
        assert_eq!(sha256_hex(text("record_canonical").as_bytes()), text("record_sha256"));
        let stored = text("stored_provenance_json");
        let signed = SignedProvenance::verify_bytes(stored.as_bytes(), &record.tenant_id, &keys).unwrap();
        assert_eq!(signed.to_bytes().unwrap(), stored.as_bytes());
        assert_eq!(signed.record, record);
        // r3 is additive: the r2 vector has no edge_log and still round-trips.
        assert!(!text("record_canonical").contains("edge_log"));
    }

    const TENANT1: &str = "b464ceb9-28a6-4249-8e29-3489627ac5f6";
    /// tenant1's real generation snapshot (2026-09-25), > 2^53.
    const TENANT1_SNAPSHOT: u64 = 8_632_004_097_115_334_317;
    const VECTOR_KEY_ID: &str = "writer-owner-scale04-20260829";

    /// An adopted record shaped exactly like tenant1's first real ledger
    /// object (non-secret identifiers from the read-only bundle).
    fn tenant1_adopted_record(snapshot_id: u64) -> ProvenanceRecord {
        let key = "__r2_data_catalog/tenant1/events/data/tail/tenant_sha256=23fa15cc8395ccdf632e61579760274fd29068f9c14437e45c4cf033ff09d35e/event_hour=497104/pack-621e65dd98c5233faae597985e94a61a8cc0923aea32beda85c0903322c6b809-67220120fd03fd77e88670f149835312cba52a6bc5e0d61990753960abd6ddba.parquet";
        let object_sha = "67220120fd03fd77e88670f149835312cba52a6bc5e0d61990753960abd6ddba";
        let hour_start = 497_104_i64 * 3_600_000_000;
        ProvenanceRecord {
            format: PROVENANCE_FORMAT.into(),
            signer_key_id: VECTOR_KEY_ID.into(),
            tenant_id: TENANT1.into(),
            part_id: PartId::parse("1790350000000-0123456789abcdef").unwrap(),
            level: Level::Hour,
            created_at_ms: 1_790_350_000_000,
            event_hour: 497_104,
            event_day: None,
            rows: 211,
            min_time_us: hour_start + 1_000,
            max_time_us: hour_start + 3_599_000_000,
            schema_fingerprint: "5".repeat(64),
            merkle_root: "6".repeat(64),
            hours: vec![HourDigest {
                event_hour: 497_104,
                rows: 211,
                min_time_us: hour_start + 1_000,
                max_time_us: hour_start + 3_599_000_000,
                merkle_root: "6".repeat(64),
            }],
            files: PartFiles {
                data: vec![DataFileDigest {
                    name: key.into(),
                    bytes: 32_410,
                    sha256: object_sha.into(),
                    rows: 211,
                    row_groups: 1,
                    min_time_us: hour_start + 1_000,
                    max_time_us: hour_start + 3_599_000_000,
                    log_sources: None,
                    uid_blooms: None,
                    entity_blooms: None,
                    parquet_ranges: None,
                    entity_locators: None,
                    class_id: None,
                    tokens: FileDigest { name: "tokens-00000.nti".into(), bytes: 1_234, sha256: "7".repeat(64) },
                }],
                partials: vec![PartialDigest {
                    kind: PartialKind::Rollup,
                    name: "partials/rollup.parquet".into(),
                    bytes: 999,
                    sha256: "8".repeat(64),
                    rows: 40,
                }],
            },
            inputs: PartInputs::Adopted {
                anchor: AdoptionAnchor {
                    generation_id: "lake-8632004097115334317-e8df30a7c4b3662a066e7cdc".into(),
                    snapshot_id,
                    bundle_identity_sha256: "e8df30a7c4b3662a066e7cdc683f0be1306a064ccf220477872a7a1d379a2139".into(),
                    object_stamp_manifest_sha256: "f5e57cebc48da2e00bcdee6bf22c3830b7cc92bf66efd37604cd30b8eb861c27".into(),
                    bundle_manifest_key: "b464ceb9-28a6-4249-8e29-3489627ac5f6/retained-generation/v1/bundles/01a0aae8-19d9-7363-8141-5ddcc28dbab8/8632004097115334317-6abd53e92958ca5f/e8df30a7c4b3662a/manifest-3baad32aef0e27def1f9bb954da2dbca2d44364510d637782f810cacc8eb45dd.json".into(),
                    bundle_manifest_sha256: "3baad32aef0e27def1f9bb954da2dbca2d44364510d637782f810cacc8eb45dd".into(),
                    // mirror-gate: wire (signed golden vector)
                    signer_key_id: "futureprod-release-20260908".into(),
                },
                objects: vec![AdoptedObject {
                    key: key.into(),
                    bytes: 32_410,
                    sha256: object_sha.into(),
                    rows: 211,
                    stamp_sha256: "42492ee481d31d2354291e9f18cd8cbf08c95ff26b0501364a228d27de1a2632".into(),
                }],
            },
            admission: None,
            lowercased_at_rest: Vec::new(),
            dedup: DedupStats { rows_in: 211, duplicates_dropped: 0, window: super::super::DedupWindow::Exact },
            writer: WriterInfo { role: "adopt".into(), build: "git:vector".into() },
        }
    }

    fn vector_signer() -> LocalPartSigner {
        LocalPartSigner::new(VECTOR_KEY_ID, SigningKey::from_bytes(&[7; 32])).unwrap()
    }

    #[tokio::test]
    async fn sixty_three_bit_snapshot_ids_sign_and_verify_as_decimal_strings() {
        let signer = vector_signer();
        for snapshot in [TENANT1_SNAPSHOT, u64::MAX, 1] {
            let record = tenant1_adopted_record(snapshot);
            record.validate().unwrap();
            let canonical = String::from_utf8(record.canonical_bytes().unwrap()).unwrap();
            assert!(canonical.contains(&format!("\"snapshot_id\":\"{snapshot}\"")), "{canonical}");
            let signature = signer.sign(TENANT1, std::slice::from_ref(&record)).await.unwrap().remove(0);
            let stored = SignedProvenance::assemble(record.clone(), signature, &signer.trusted()).unwrap().to_bytes().unwrap();
            let verified = SignedProvenance::verify_bytes(&stored, TENANT1, &signer.trusted()).unwrap();
            assert_eq!(verified.record, record);
            assert_eq!(verified.to_bytes().unwrap(), stored);
        }
        // The old integer spelling (and every non-canonical string) is refused.
        let canonical = String::from_utf8(tenant1_adopted_record(42).canonical_bytes().unwrap()).unwrap();
        for bad in ["42", "\"042\"", "\"+42\"", "\"4.2\"", "\"\"", "\"18446744073709551616\"", "\" 42\""] {
            let text = canonical.replace("\"snapshot_id\":\"42\"", &format!("\"snapshot_id\":{bad}"));
            assert!(serde_json::from_str::<ProvenanceRecord>(&text).is_err(), "{bad}");
        }
        assert_eq!(u64_decimal::parse("0"), Some(0));
        assert_eq!(u64_decimal::parse("18446744073709551615"), Some(u64::MAX));
        assert_eq!(u64_decimal::parse("00"), None);
        // Zero is not a snapshot id.
        assert!(tenant1_adopted_record(0).validate().is_err());
    }

    /// Golden vector for the platform's owner (#1557 schema change): an adopted
    /// record with tenant1's real 63-bit snapshot id. Regenerate with
    /// `NANO_WRITE_ADOPTED_VECTOR=1` (test key only: seed = 32 x 0x07).
    #[tokio::test]
    async fn adopted_record_vector_with_tenant1_snapshot_id() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lake-part-provenance-adopted-v1.json");
        let signer = vector_signer();
        let record = tenant1_adopted_record(TENANT1_SNAPSHOT);
        let signature = signer.sign(TENANT1, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let signed = SignedProvenance::assemble(record.clone(), signature, &signer.trusted()).unwrap();
        let canonical = String::from_utf8(record.canonical_bytes().unwrap()).unwrap();
        if std::env::var("NANO_WRITE_ADOPTED_VECTOR").is_ok() {
            let vector = serde_json::json!({
                "note": "NAN-2865 adopted-part provenance vector (contract r3.2 4.3: u64 identifiers as decimal strings; 8.1 adopted parts). Identifiers mirror tenant1's real generation (non-secret); sidecar digests are placeholders. TEST KEY ONLY: ed25519 seed = 32 bytes of 0x07. Verify signature.sig over domain || 0x00 || record_canonical.",
                "domain": "nano-lake-part-provenance-v1",
                "signer_key_id": VECTOR_KEY_ID,
                "public_key_hex": hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes()),
                "record_canonical": canonical,
                "record_sha256": sha256_hex(canonical.as_bytes()),
                "signature": signed.signature,
                "stored_provenance_json": String::from_utf8(signed.to_bytes().unwrap()).unwrap(),
            });
            std::fs::write(path, serde_json::to_string_pretty(&vector).unwrap() + "\n").unwrap();
        }
        let vector: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let text = |k: &str| vector[k].as_str().unwrap().to_string();
        assert_eq!(text("record_canonical"), canonical);
        assert!(canonical.contains("\"snapshot_id\":\"8632004097115334317\""));
        assert_eq!(text("record_sha256"), sha256_hex(canonical.as_bytes()));
        let public: [u8; 32] = hex::decode(text("public_key_hex")).unwrap().try_into().unwrap();
        let keys = TenantKeySet::new([(text("signer_key_id"), VerifyingKey::from_bytes(&public).unwrap())]);
        let stored = text("stored_provenance_json");
        let verified = SignedProvenance::verify_bytes(stored.as_bytes(), TENANT1, &keys).unwrap();
        assert_eq!(verified.record, record);
        assert_eq!(stored.as_bytes(), signed.to_bytes().unwrap());
    }
}
