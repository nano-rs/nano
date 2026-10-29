// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact HMAC entity sidecar lookup. The sidecar is only a candidate superset;
//! every returned block is rechecked by the full compiler-owned event query.

use crate::planner::{CandidateBlock, SourceManifest};
use chrono::DateTime;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// v1 stores the full 32-byte HMAC per posting row; v2 stores its leading
/// `value_hash_bytes` prefix. Both are served: probing a prefix column with
/// the identically truncated probe hash selects a SUPERSET of the full-hash
/// matches (a prefix collision can only add a candidate, and every candidate
/// block is rechecked by the exact compiler-owned event query), so
/// under-selection is impossible in either layout.
const INDEX_VERSION_V1: &str = "ocsf-entity-block-v1";
const INDEX_VERSION_V2: &str = "ocsf-entity-block-v2";
const INDEX_VERSION_V2_VALUE_HASH_BYTES: usize = 16;
const NORMALIZATION_VERSION: &str = "ocsf-entity-v1";
const MAX_CANDIDATE_BLOCKS: usize = 4_096;
/// Upper bound on probe parallelism. A wide-window probe opens hundreds of
/// per-object index fragments and each open pays a Parquet footer read before
/// any pruning happens, so a single-threaded probe is O(index_objects) wall
/// time — measured ~1.7ms per fragment on the deployed volume, ~0.46s at a
/// 24-hour window. Eight readers bound concurrent memory while collapsing that
/// serial open cost; the per-probe `max_memory_usage` fence still applies.
const MAX_PROBE_THREADS: usize = 8;
const PROBE_CACHE_MAX_ENTRIES: usize = 64;
const PROBE_CACHE_MAX_BYTES: usize = 8 * 1_024 * 1_024;

#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    #[error("entity sidecar is invalid: {0}")]
    Invalid(String),
    #[error("failed to read entity sidecar: {0}")]
    Read(#[source] std::io::Error),
    #[error("failed to decode entity sidecar: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("entity sidecar exceeded the candidate block bound")]
    CandidateBound {
        candidate_blocks: usize,
        candidate_objects: usize,
    },
}

type Result<T> = std::result::Result<T, SidecarError>;

#[derive(Debug, Deserialize)]
struct EntityManifest {
    index_version: String,
    /// Stored byte width of the `value_hash` column. Declared by v2
    /// manifests; v1 predates the key and always stored the full 32 bytes.
    #[serde(default)]
    value_hash_bytes: Option<usize>,
    tenant_id: String,
    key_id: String,
    normalization_version: String,
    hash_algorithm: String,
    plaintext_values: bool,
    source_files: usize,
    source_bytes: u64,
    event_rows: u64,
    index_rows: u64,
    index_bytes: u64,
    field_specs: Vec<FieldSpec>,
    object_builds: Vec<ObjectBuild>,
    objects: Vec<SidecarObject>,
}

#[derive(Debug, Clone, Deserialize)]
struct FieldSpec {
    field_id: u8,
    source_path: String,
    kind: String,
}

#[derive(Debug, Deserialize)]
struct ObjectBuild {
    object_id: u32,
    rows: u64,
    bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct SidecarObject {
    object_id: u32,
    /// Position of this object in the manifest's path-sorted object array,
    /// which is also its artifact filename (`object-{position:04}.parquet`).
    /// Derived at load time — object_id is a STABLE identity and stops being
    /// positional once any object has ever been retired or inserted.
    #[serde(skip)]
    position: u32,
    event_object_key: String,
    event_object_version: String,
    event_object_bytes: u64,
    rows: u64,
    row_group_ranges: Vec<RowGroupRange>,
}

#[derive(Debug, Clone, Deserialize)]
struct RowGroupRange {
    row_group: u32,
    row_start: u64,
    row_end: u64,
}

pub struct EntitySidecar {
    key_id: String,
    key: Vec<u8>,
    index_directory: PathBuf,
    index_pattern: PathBuf,
    /// Stored byte width of the `value_hash` column this generation was built
    /// with; the probe hash is truncated to exactly this width.
    value_hash_bytes: usize,
    fields: BTreeMap<String, FieldSpec>,
    objects: BTreeMap<u32, SidecarObject>,
}

pub struct SidecarQuery {
    pub sql: String,
    pub params: Vec<(String, String)>,
    pub source_path: String,
    /// Number of per-object index fragments this probe opens. A full-generation
    /// probe opens one per generation object, so this is the planner's only
    /// visible signal that window pruning took effect.
    pub index_objects: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EntityPlannerEvidence {
    pub kind: &'static str,
    pub source_path: String,
    pub candidate_blocks: usize,
    pub candidate_objects: usize,
    pub exact_recheck: bool,
    pub key_id: String,
    /// Index fragments opened by the probe, and the total the generation holds.
    /// `index_objects < index_objects_total` proves the probe was pruned to the
    /// request window instead of globbing every historical fragment.
    pub index_objects: usize,
    pub index_objects_total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    /// Set by the caller when the probe's engine output was served from the
    /// generation-scoped probe cache instead of re-opening index fragments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_cache_hit: Option<bool>,
}

impl EntitySidecar {
    pub fn load(
        manifest_path: &Path,
        key_path: &Path,
        index_files: Vec<PathBuf>,
        tenant_id: &str,
        source_manifest: &SourceManifest,
    ) -> Result<Self> {
        let manifest_bytes = std::fs::read(manifest_path).map_err(SidecarError::Read)?;
        let manifest: EntityManifest =
            serde_json::from_slice(&manifest_bytes).map_err(SidecarError::Decode)?;
        let key = trim_ascii(&std::fs::read(key_path).map_err(SidecarError::Read)?).to_vec();
        let value_hash_bytes = match (
            manifest.index_version.as_str(),
            manifest.value_hash_bytes,
        ) {
            // v1 stored the full HMAC and never declared a width.
            (INDEX_VERSION_V1, None) => 32_usize,
            // v2 must declare exactly the width this reader understands; any
            // other declared width is a format this code cannot probe safely.
            (INDEX_VERSION_V2, Some(INDEX_VERSION_V2_VALUE_HASH_BYTES)) => {
                INDEX_VERSION_V2_VALUE_HASH_BYTES
            }
            _ => {
                return Err(SidecarError::Invalid(
                    "entity index version or value hash width is unsupported".to_string(),
                ));
            }
        };
        if manifest.normalization_version != NORMALIZATION_VERSION
            || manifest.hash_algorithm != "hmac-sha256"
            || manifest.plaintext_values
            || manifest.tenant_id != tenant_id
            || manifest.key_id.is_empty()
            || key.len() < 32
            || manifest.objects.is_empty()
            || manifest.source_files != manifest.objects.len()
            || manifest.source_files != index_files.len()
        {
            return Err(SidecarError::Invalid(
                "version, tenant, key, privacy, or object cardinality failed".to_string(),
            ));
        }
        let source_objects = source_manifest
            .objects
            .iter()
            .map(|object| (object.event_object_key.as_str(), object))
            .collect::<BTreeMap<_, _>>();
        let mut objects = BTreeMap::new();
        let mut object_ids_in_order = Vec::with_capacity(manifest.objects.len());
        let mut source_bytes = 0_u64;
        let mut event_rows = 0_u64;
        for (position, mut object) in manifest.objects.into_iter().enumerate() {
            object.position = u32::try_from(position).map_err(|_| {
                SidecarError::Invalid("sidecar object position overflowed".to_string())
            })?;
            let object = object;
            let source = source_objects
                .get(object.event_object_key.as_str())
                .ok_or_else(|| {
                    SidecarError::Invalid(
                        "sidecar object is outside the source manifest".to_string(),
                    )
                })?;
            if object.event_object_version != source.event_object_version
                || object.event_object_bytes != source.event_object_bytes
                || object.rows != source.rows
                || object.row_group_ranges.is_empty()
                || object
                    .row_group_ranges
                    .iter()
                    .any(|range| range.row_start >= range.row_end || range.row_end > object.rows)
                || objects.insert(object.object_id, object.clone()).is_some()
            {
                return Err(SidecarError::Invalid(
                    "sidecar object version, size, rows, ranges, or ID failed".to_string(),
                ));
            }
            object_ids_in_order.push(object.object_id);
            source_bytes = source_bytes.saturating_add(object.event_object_bytes);
            event_rows = event_rows.saturating_add(object.rows);
        }
        if objects.len() != source_objects.len()
            || source_bytes != manifest.source_bytes
            || event_rows != manifest.event_rows
        {
            return Err(SidecarError::Invalid(
                "sidecar source totals do not match the publication".to_string(),
            ));
        }
        // Builds, objects, and index files share one path-sorted order; the
        // stable object_id is the join key between an artifact's rows and its
        // manifest entry, while the POSITION names the file on disk.
        if manifest.object_builds.len() != index_files.len() {
            return Err(SidecarError::Invalid(
                "sidecar build list does not match index files".to_string(),
            ));
        }
        let mut actual_index_bytes = 0_u64;
        let mut actual_index_rows = 0_u64;
        let index_directory = index_files
            .first()
            .and_then(|path| path.parent())
            .ok_or_else(|| {
                SidecarError::Invalid("entity index has no parent directory".to_string())
            })?;
        for (position, path) in index_files.iter().enumerate() {
            let expected_name = format!("object-{position:04}.parquet");
            if path.parent() != Some(index_directory)
                || path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
            {
                return Err(SidecarError::Invalid(
                    "index directory or filename does not match its object ID".to_string(),
                ));
            }
            let build = manifest.object_builds.get(position).ok_or_else(|| {
                SidecarError::Invalid("index file has no build record".to_string())
            })?;
            if object_ids_in_order.get(position) != Some(&build.object_id) {
                return Err(SidecarError::Invalid(
                    "sidecar build object id does not match its manifest object".to_string(),
                ));
            }

            let bytes = path.metadata().map_err(SidecarError::Read)?.len();
            if bytes != build.bytes || build.rows == 0 {
                return Err(SidecarError::Invalid(
                    "index file size or row count does not match its build record".to_string(),
                ));
            }
            actual_index_bytes = actual_index_bytes.saturating_add(bytes);
            actual_index_rows = actual_index_rows.saturating_add(build.rows);
        }
        if actual_index_bytes != manifest.index_bytes || actual_index_rows != manifest.index_rows {
            return Err(SidecarError::Invalid(
                "sidecar index totals do not match files".to_string(),
            ));
        }
        // One file() source keeps chDB's query graph bounded as a generation
        // grows. A UNION ALL branch per immutable object caused the planner to
        // hold hundreds of Parquet readers concurrently and could exceed the
        // query memory fence before the Bloom-pruned lookup returned a row.
        // The loader has already proved the directory, contiguous filenames,
        // sizes, and config digests, so this range names that same exact set.
        let index_pattern = if index_files.len() == 1 {
            index_files[0].clone()
        } else {
            index_directory.join(format!(
                "object-{{0000..{:04}}}.parquet",
                index_files.len() - 1
            ))
        };
        let mut fields = BTreeMap::new();
        let mut field_ids = BTreeSet::new();
        for field in manifest.field_specs {
            if field.source_path.is_empty()
                || !matches!(field.kind.as_str(), "text" | "ip")
                || !field_ids.insert(field.field_id)
                || fields.insert(field.source_path.clone(), field).is_some()
            {
                return Err(SidecarError::Invalid(
                    "sidecar field definition is ambiguous".to_string(),
                ));
            }
        }
        Ok(Self {
            key_id: manifest.key_id,
            key,
            index_directory: index_directory.to_path_buf(),
            index_pattern,
            value_hash_bytes,
            fields,
            objects,
        })
    }

    /// NAN-2361 wave 8: the entity sidecar of the zero-snapshot bootstrap
    /// generation. It covers no field and holds no object, so every planner
    /// hint falls through to the (empty) base and the signed hot tail. The
    /// HMAC key is still bound because the tail signer and prevalence
    /// stamping share it.
    pub fn empty(key_id: &str, key: Vec<u8>, index_directory: &Path) -> Result<Self> {
        if key_id.is_empty() || key.len() < 32 {
            return Err(SidecarError::Invalid(
                "empty entity sidecar requires a key ID and a 32-byte key".to_string(),
            ));
        }
        Ok(Self {
            key_id: key_id.to_string(),
            key,
            index_directory: index_directory.to_path_buf(),
            index_pattern: index_directory.join("object-{0000..0000}.parquet"),
            value_hash_bytes: INDEX_VERSION_V2_VALUE_HASH_BYTES,
            fields: BTreeMap::new(),
            objects: BTreeMap::new(),
        })
    }

    pub fn covers(&self, source_path: &str) -> bool {
        self.fields.contains_key(source_path)
    }

    pub fn query(&self, source_path: &str, value: &str) -> Result<SidecarQuery> {
        self.query_with_pattern(source_path, value, &self.index_pattern, self.objects.len())
    }

    /// Total per-object index fragments this generation holds. A probe that
    /// opens all of them costs O(generation), which grows with retention.
    pub fn index_objects_total(&self) -> usize {
        self.objects.len()
    }

    /// Limit an entity lookup to index fragments whose immutable event objects
    /// overlap the request's time window. Row expansion passes a two-second
    /// window around the visible event, so this avoids opening every historical
    /// sidecar fragment merely to locate one event ID. Missing hour partitions
    /// remain conservative and are always included.
    pub fn query_for_window(
        &self,
        source_path: &str,
        value: &str,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<Option<SidecarQuery>> {
        if start_ms >= end_ms {
            return Err(SidecarError::Invalid(
                "entity sidecar time window is not increasing".to_string(),
            ));
        }
        // Files are named by POSITION, not by stable object id.
        let positions = self
            .objects
            .values()
            .filter(|object| object_overlaps_window(&object.event_object_key, start_ms, end_ms))
            .map(|object| object.position)
            .collect::<Vec<_>>();
        if positions.is_empty() {
            return Ok(None);
        }
        if positions.len() == self.objects.len() {
            return self.query(source_path, value).map(Some);
        }
        let pattern = if positions.len() == 1 {
            self.index_directory
                .join(format!("object-{:04}.parquet", positions[0]))
        } else {
            let names = positions
                .iter()
                .map(|position| format!("{position:04}"))
                .collect::<Vec<_>>()
                .join(",");
            self.index_directory
                .join(format!("object-{{{names}}}.parquet"))
        };
        self.query_with_pattern(source_path, value, &pattern, positions.len())
            .map(Some)
    }

    fn query_with_pattern(
        &self,
        source_path: &str,
        value: &str,
        index_pattern: &Path,
        index_objects: usize,
    ) -> Result<SidecarQuery> {
        let field = self.fields.get(source_path).ok_or_else(|| {
            SidecarError::Invalid("entity field is not covered by this generation".to_string())
        })?;
        let canonical = canonicalize(value, &field.kind);
        if canonical.is_empty() {
            return Err(SidecarError::Invalid(
                "entity value is empty after normalization".to_string(),
            ));
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| SidecarError::Invalid("HMAC key is invalid".to_string()))?;
        mac.update(NORMALIZATION_VERSION.as_bytes());
        mac.update(&[0]);
        mac.update(canonical.as_bytes());
        // The stored column holds the leading `value_hash_bytes` of the full
        // HMAC (all 32 in v1). Truncating the probe hash identically keeps
        // exact equality on everything stored: any row built from this value
        // matches, so the candidate set is a superset of the full-hash set.
        let value_hash =
            hex::encode(&mac.finalize().into_bytes()[..self.value_hash_bytes]);
        let params = vec![
            ("value_hash_hex".to_string(), value_hash),
            ("field_id".to_string(), field.field_id.to_string()),
            (
                "entity_index".to_string(),
                index_pattern.display().to_string(),
            ),
        ];
        let sql = format!(
            "SELECT object_id, block_id, matches, max_time \
             FROM file({{entity_index:String}}, Parquet) \
             WHERE value_hash = CAST(unhex({{value_hash_hex:String}}), 'FixedString({})') \
             AND field_id = {{field_id:UInt8}} \
             ORDER BY max_time DESC, object_id ASC, block_id ASC LIMIT {} \
             SETTINGS max_threads={}, max_execution_time=5, max_bytes_to_read=67108864, \
             max_memory_usage=268435456, use_query_cache=0",
            self.value_hash_bytes,
            MAX_CANDIDATE_BLOCKS + 1,
            // Scale reader parallelism with the fragments this probe actually
            // opens: a two-second row-expansion probe stays at one thread, a
            // 24-hour hunt gets the full bound instead of serial file opens.
            index_objects.clamp(1, MAX_PROBE_THREADS),
        );
        Ok(SidecarQuery {
            sql,
            params,
            source_path: source_path.to_string(),
            index_objects,
        })
    }

    pub fn candidates(
        &self,
        source_path: &str,
        data: &[u8],
    ) -> Result<(Vec<CandidateBlock>, EntityPlannerEvidence)> {
        if !self.covers(source_path) {
            return Err(SidecarError::Invalid(
                "entity field is not covered by this generation".to_string(),
            ));
        }
        let mut candidates = Vec::new();
        let mut candidate_objects = BTreeSet::new();
        for line in data
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let row: CandidateRow = serde_json::from_slice(line).map_err(SidecarError::Decode)?;
            let object = self.objects.get(&row.object_id).ok_or_else(|| {
                SidecarError::Invalid("candidate references an unknown object".to_string())
            })?;
            let range = object
                .row_group_ranges
                .iter()
                .find(|range| range.row_group == row.block_id)
                .ok_or_else(|| {
                    SidecarError::Invalid("candidate references an unknown row group".to_string())
                })?;
            if row.matches == 0 {
                return Err(SidecarError::Invalid(
                    "candidate has a zero exact match count".to_string(),
                ));
            }
            candidate_objects.insert(object.object_id);
            candidates.push(CandidateBlock {
                event_object_key: object.event_object_key.clone(),
                event_object_bytes: object.event_object_bytes,
                row_start: range.row_start,
                row_end: range.row_end,
                max_time_ms: Some(row.max_time),
                time_range_us: None,
            });
        }
        if candidates.len() > MAX_CANDIDATE_BLOCKS {
            return Err(SidecarError::CandidateBound {
                candidate_blocks: candidates.len(),
                candidate_objects: candidate_objects.len(),
            });
        }
        let candidate_blocks = candidates.len();
        Ok((
            candidates,
            EntityPlannerEvidence {
                kind: "entity",
                source_path: source_path.to_string(),
                candidate_blocks,
                candidate_objects: candidate_objects.len(),
                exact_recheck: true,
                key_id: self.key_id.clone(),
                index_objects: self.objects.len(),
                index_objects_total: self.objects.len(),
                fallback_reason: None,
                probe_cache_hit: None,
            },
        ))
    }

    pub fn fallback_evidence(
        &self,
        source_path: &str,
        candidate_blocks: usize,
        candidate_objects: usize,
    ) -> EntityPlannerEvidence {
        EntityPlannerEvidence {
            kind: "entity",
            source_path: source_path.to_string(),
            candidate_blocks,
            candidate_objects,
            exact_recheck: true,
            key_id: self.key_id.clone(),
            index_objects: self.objects.len(),
            index_objects_total: self.objects.len(),
            fallback_reason: Some("entity candidate block bound was exceeded".to_string()),
            probe_cache_hit: None,
        }
    }

    /// Scope an entity probe to a compiled request window expressed as RFC3339
    /// bounds.
    ///
    /// An unscoped probe opens one index fragment per generation object, so its
    /// cost grows with retention rather than with the query — the same
    /// O(total objects) shape window pruning already removed from the base
    /// snapshot source. A time-fenced query cannot return a row from an object
    /// outside its window, so opening only the overlapping fragments is exact.
    ///
    /// A window that is absent, unparseable, or not increasing falls back to the
    /// full probe, and objects without a trusted `event_hour=` segment stay
    /// included, so this can only ever read too much — never too little.
    ///
    /// `Ok(None)` means no generation object overlaps the window at all.
    pub fn query_for_rfc3339_window(
        &self,
        source_path: &str,
        value: &str,
        start: &str,
        end: &str,
    ) -> Result<Option<SidecarQuery>> {
        let window = DateTime::parse_from_rfc3339(start)
            .ok()
            .zip(DateTime::parse_from_rfc3339(end).ok())
            .filter(|(start, end)| start < end)
            .map(|(start, end)| (start.timestamp_millis(), end.timestamp_millis()));
        match window {
            Some((start_ms, end_ms)) => {
                self.query_for_window(source_path, value, start_ms, end_ms)
            }
            None => self.query(source_path, value).map(Some),
        }
    }

    /// Evidence for a probe that was pruned to zero index fragments: no
    /// immutable generation object overlaps the request window, so the
    /// generation cannot contribute a row and is not read at all.
    pub fn empty_window_evidence(&self, source_path: &str) -> EntityPlannerEvidence {
        EntityPlannerEvidence {
            kind: "entity",
            source_path: source_path.to_string(),
            candidate_blocks: 0,
            candidate_objects: 0,
            exact_recheck: true,
            key_id: self.key_id.clone(),
            index_objects: 0,
            index_objects_total: self.objects.len(),
            fallback_reason: None,
            probe_cache_hit: None,
        }
    }
}

/// Cache key for one probe's engine output. The SQL embeds the settings and
/// row limit; the parameters carry the value hash, field ID, and the exact
/// index-fragment pattern the window pruned to — everything the output is a
/// function of. Two probes with the same key read the same immutable files
/// with the same predicate and are byte-identical by construction.
pub fn probe_cache_key(query: &SidecarQuery) -> String {
    let mut key = query.sql.clone();
    for (name, value) in &query.params {
        key.push('\u{1f}');
        key.push_str(name);
        key.push('\u{1f}');
        key.push_str(value);
    }
    key
}

struct ProbeCacheEntry {
    data: std::sync::Arc<[u8]>,
    bytes: usize,
}

/// Generation-scoped LRU over raw entity-probe engine output.
///
/// The keyword sidecar answers its planning question from an in-process
/// tantivy index (microseconds, plus a `FragmentExpansionCache`); the entity
/// probe re-opens every window-overlapping Parquet fragment through the engine
/// on each call (~1.7ms per fragment on the deployed volume). Repeated and
/// refined hunts over the same window re-run a byte-identical probe, so a hunt
/// loop pays that open cost every iteration. Index fragments are immutable for
/// the life of a generation and the cache is dropped with the generation, so a
/// hit can never observe stale data.
#[derive(Default)]
pub struct EntityProbeCache {
    entries: BTreeMap<String, ProbeCacheEntry>,
    lru: std::collections::VecDeque<String>,
    bytes: usize,
}

impl EntityProbeCache {
    pub fn get(&mut self, key: &str) -> Option<std::sync::Arc<[u8]>> {
        let data = self.entries.get(key)?.data.clone();
        self.touch(key);
        Some(data)
    }

    pub fn insert(&mut self, key: String, data: std::sync::Arc<[u8]>) {
        let bytes = key.len() + data.len() + std::mem::size_of::<ProbeCacheEntry>();
        if bytes > PROBE_CACHE_MAX_BYTES {
            return;
        }
        self.remove(&key);
        self.bytes = self.bytes.saturating_add(bytes);
        self.lru.push_back(key.clone());
        self.entries.insert(key, ProbeCacheEntry { data, bytes });
        while self.entries.len() > PROBE_CACHE_MAX_ENTRIES || self.bytes > PROBE_CACHE_MAX_BYTES {
            let Some(oldest) = self.lru.pop_front() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(entry.bytes);
            }
        }
    }

    fn touch(&mut self, key: &str) {
        if let Some(position) = self.lru.iter().position(|entry| entry == key) {
            self.lru.remove(position);
            self.lru.push_back(key.to_string());
        }
    }

    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            self.bytes = self.bytes.saturating_sub(entry.bytes);
        }
        if let Some(position) = self.lru.iter().position(|entry| entry == key) {
            self.lru.remove(position);
        }
    }
}

fn object_overlaps_window(path: &str, start_ms: i64, end_ms: i64) -> bool {
    let Some(hour) = path
        .split('/')
        .find_map(|segment| segment.strip_prefix("event_hour="))
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return true;
    };
    let Some(hour_start_ms) = hour.checked_mul(3_600_000) else {
        return true;
    };
    let Some(hour_end_ms) = hour_start_ms.checked_add(3_600_000) else {
        return true;
    };
    hour_start_ms <= end_ms && hour_end_ms > start_ms
}

#[derive(Debug, Deserialize)]
struct CandidateRow {
    object_id: u32,
    block_id: u32,
    matches: u64,
    max_time: u64,
}

fn canonicalize(value: &str, kind: &str) -> String {
    let value = value.trim();
    if kind == "ip" {
        if let Ok(address) = value.parse::<IpAddr>() {
            return match address {
                IpAddr::V4(address) => address.to_string(),
                IpAddr::V6(address) => address
                    .to_ipv4_mapped()
                    .map_or_else(|| address.to_string(), |address| address.to_string()),
            }
            .to_lowercase();
        }
    }
    value.to_lowercase()
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|byte| !byte.is_ascii_whitespace());
    let end = bytes.iter().rposition(|byte| !byte.is_ascii_whitespace());
    match (start, end) {
        (Some(start), Some(end)) => &bytes[start..=end],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires digest-verified native chDB"]
    fn native_or_entity_indexes_resolve_both_branches_before_event_reads() {
        let runtime = crate::native::NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        std::mem::forget(runtime.clone());
        let connection = runtime.connect(&[]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut sidecar = EntitySidecar {
            key_id:"test-key".into(), key:vec![7;32], index_directory:dir.path().into(),
            value_hash_bytes:16, index_pattern:dir.path().join("object-{0000..0002}.parquet"),
            fields:[("actor.user.name", 1), ("user.name", 2)].into_iter().map(|(path,id)| (path.into(), FieldSpec {
                field_id:id, source_path:path.into(), kind:"text".into(),
            })).collect(),
            objects:(0..3).map(|id| (id, SidecarObject {
                object_id:id, position:id, event_object_key:format!("s3://bucket/table/data/part-{id}.parquet"),
                event_object_version:"v1".into(), event_object_bytes:1000, rows:20,
                row_group_ranges:vec![RowGroupRange { row_group:0, row_start:0, row_end:10 }, RowGroupRange { row_group:1, row_start:10, row_end:20 }],
            })).collect(),
        };
        let event_schema = "time DateTime64(6, 'UTC'), metadata Tuple(uid String), actor Tuple(user Tuple(name String)), user Tuple(name String)";
        let mut cached = BTreeMap::new();
        for id in 0..3 {
            let path = dir.path().join(format!("events-{id}.parquet"));
            let output = path.display().to_string();
            connection.query_with_params(&format!("INSERT INTO FUNCTION file({{output:String}}, Parquet) SELECT toDateTime64('2026-09-21 14:00:00', 6, 'UTC') + toIntervalMicrosecond(number * 3 + {id}) AS time, CAST(tuple(concat('event-{id}-', toString(number))), 'Tuple(uid String)') AS metadata, CAST(tuple(tuple(if({id}=0 AND number>=10, 'JSmith', 'other'))), 'Tuple(user Tuple(name String))') AS actor, CAST(tuple(if({id}=1 AND number>=10, 'jsmith', 'other')), 'Tuple(name String)') AS user FROM numbers(20)"), "JSONEachRow", &[("output", output.as_str())]).unwrap();
            let object = sidecar.objects.get_mut(&id).unwrap();
            object.event_object_bytes = path.metadata().unwrap().len();
            cached.insert(object.event_object_key.clone(), crate::planner::SnapshotCacheObject {
                version_id:"v1".into(), bytes:object.event_object_bytes, path,
            });
        }
        for (id,path,value) in [(0,"actor.user.name","jsmith"), (1,"user.name","jsmith"), (2,"user.name","other")] {
            let probe = sidecar.query(path, value).unwrap();
            let mut params = probe.params.clone();
            params.push(("output".into(), dir.path().join(format!("object-{id:04}.parquet")).display().to_string()));
            params.push(("id".into(), id.to_string()));
            let params = params.iter().map(|(k,v)| (k.as_str(),v.as_str())).collect::<Vec<_>>();
            connection.query_with_params("INSERT INTO FUNCTION file({output:String}, Parquet) SELECT CAST(unhex({value_hash_hex:String}), 'FixedString(16)') AS value_hash, {field_id:UInt8} AS field_id, {id:UInt32} AS object_id, toUInt32(1) AS block_id, toUInt64(1) AS matches, toUInt64(1000) AS max_time", "JSONEachRow", &params).unwrap();
        }
        let mut sets = Vec::new();
        for path in ["actor.user.name", "user.name"] {
            let probe = sidecar.query(path, "JSmith").unwrap();
            assert!(probe.sql.contains("value_hash ="));
            let params = probe.params.iter().map(|(k,v)| (k.as_str(),v.as_str())).collect::<Vec<_>>();
            let start = std::time::Instant::now();
            let output = connection.query_with_params(&probe.sql, "JSONEachRow", &params).unwrap();
            eprintln!("NAN-2523 entity {path} index_ms={:.3}", start.elapsed().as_secs_f64()*1000.0);
            sets.push(sidecar.candidates(path, &output.data).unwrap().0);
        }
        let union = crate::planner::union_candidate_blocks(&sets).unwrap().unwrap();
        assert_eq!(union.len(), 2);
        assert_eq!(union[0].event_object_key, "s3://bucket/table/data/part-0.parquet");
        assert_eq!(union[1].event_object_key, "s3://bucket/table/data/part-1.parquet");
        assert!(union.iter().all(|block| block.row_start == 10 && block.row_end == 20));
        let manifest: SourceManifest = serde_json::from_value(serde_json::json!({
            "tenant_id":"tenant-a", "objects":sidecar.objects.values().map(|object| serde_json::json!({
                "event_object_key":object.event_object_key, "event_object_version":"v1",
                "event_object_bytes":object.event_object_bytes, "rows":20,
                "available_paths":["time","metadata.uid","actor.user.name","user.name"],
                "field_types":{"time":"timestamp","metadata.uid":"string","actor.user.name":"string","user.name":"string"}
            })).collect::<Vec<_>>()
        })).unwrap();
        let tenant = crate::planner::TenantQueryConfig {
            tenant_id:"tenant-a".into(), source:"https://object.test/bucket/table".into(),
            iceberg_metadata_file_path:"metadata/00001.json".into(), max_query_bytes:100_000_000,
            max_memory_bytes:1_000_000_000, max_execution_seconds:30, threads:8,
            credentials:crate::planner::ObjectStoreCredentials::DefaultChain,
            snapshot_cache:Some(crate::planner::SnapshotCache {
                source_spec:dir.path().join("events-{0..2}.parquet").display().to_string(),
                bytes:cached.values().map(|o| o.bytes).sum(), objects:cached,
                read_schema:Some(event_schema.into()), bootstrap:false,
            }),
        };
        let query: crate::planner::CompiledQuery = serde_json::from_value(serde_json::json!({
            "schema_version":1,"profile":"ocsf","dataset":"logs","source_placeholder":"__nano_lake_source__",
            "query_sha256":"a".repeat(64),"start":"2026-09-21T13:00:00Z","end":"2026-09-21T15:00:00Z",
            "limit":100,"table_view":true,"newest_first_event_rows":true,
            "required_columns":[{"name":"time","field_type":"timestamp"},{"name":"metadata.uid","field_type":"string"},{"name":"actor.user.name","field_type":"string"},{"name":"user.name","field_type":"string"}],
            "projected_scan_columns":["time","actor.user.name","user.name"],
            "sql":"SELECT time, \"metadata.uid\", \"actor.user.name\", \"user.name\" FROM __nano_lake_source__ WHERE (lower(\"actor.user.name\") = 'jsmith' OR lower(\"user.name\") = 'jsmith') ORDER BY time DESC LIMIT 101"
        })).unwrap();
        let mut expected = None;
        for (label,candidates) in [("scan",None),("indexed",Some(union.as_slice()))] {
            let plan = crate::planner::plan_broad_log_query_with_candidates_and_tail(&tenant, &manifest, &query, candidates, None).unwrap();
            if candidates.is_some() {
                // Exact spelling: since NAN-3179 (#5368) the fence defaults to
                // the set form. Both files are cut into 10-row granules, so
                // keys 4/5 are granule 1 (rows 10..20) of file ids 1/2 (key
                // width 3); `NANO_LAKE_FENCE_SET=0` restores the OR terms.
                let exact = if crate::planner::fence_set_enabled() {
                    "(intDiv(_row_number, transform(_path, [{candidate_path_0:String},{candidate_path_1:String}], [10,10], 1)) * 3 + transform(_path, [{candidate_path_0:String},{candidate_path_1:String}], [1,2], 0)) IN (4,5)".to_string()
                } else {
                    "(_path = {candidate_path_0:String} AND _row_number >= 10 AND _row_number < 20) OR (_path = {candidate_path_1:String} AND _row_number >= 10 AND _row_number < 20)".to_string()
                };
                assert!(plan.sql.contains(&exact), "{}", plan.sql);
                assert!(!plan.params.iter().any(|(_,v)| v.contains("events-2")));
                // Semantic: evaluate the fence per row the way chDB does. It
                // admits exactly rows [10, 20) of events-0 and events-1 and
                // nothing of events-2 or rows outside the candidate range.
                let terms = crate::planner::fence_eval::parse_fence(&exact, &plan.params);
                for id in 0..3 {
                    let path = dir.path().join(format!("events-{id}.parquet")).display().to_string();
                    for row in 0..sidecar.objects[&id].rows {
                        let want = id < 2 && (10..20).contains(&row);
                        assert_eq!(crate::planner::fence_eval::fence_matches(&terms, &path, row), want, "{path} row {row}: {exact}");
                    }
                }
            }
            let params = plan.params.iter().map(|(k,v)| (k.as_str(),v.as_str())).collect::<Vec<_>>();
            let start = std::time::Instant::now();
            let result = connection.query_with_params(&plan.sql, "JSONEachRow", &params).unwrap();
            eprintln!("NAN-2523 generation {label} chdb_ms={:.3} bytes={}", start.elapsed().as_secs_f64()*1000.0, result.storage_bytes_read);
            if let Some(expected) = expected.as_ref() { assert_eq!(&result.data, expected); }
            else { assert_eq!(String::from_utf8_lossy(&result.data).lines().count(), 20); expected = Some(result.data); }
        }

    }

    #[test]
    fn normalization_matches_the_sidecar_contract() {
        assert_eq!(canonicalize("  HOST.Example  ", "text"), "host.example");
        assert_eq!(canonicalize("::ffff:192.0.2.1", "ip"), "192.0.2.1");
        assert_eq!(canonicalize("not-an-ip", "ip"), "not-an-ip");
    }

    #[test]
    fn lookup_uses_one_bounded_file_source_instead_of_union_fanout() {
        let sidecar = EntitySidecar {
            key_id: "key-v1".to_string(),
            key: vec![7; 32],
            index_directory: PathBuf::from("/trusted"),
            value_hash_bytes: INDEX_VERSION_V2_VALUE_HASH_BYTES,
            index_pattern: PathBuf::from("/trusted/object-{0000..0467}.parquet"),
            fields: BTreeMap::from([(
                "device.hostname".to_string(),
                FieldSpec {
                    field_id: 1,
                    source_path: "device.hostname".to_string(),
                    kind: "text".to_string(),
                },
            )]),
            objects: BTreeMap::new(),
        };

        let query = sidecar
            .query("device.hostname", "SRV-WEB02.CORP.LOCAL")
            .expect("sidecar lookup");

        assert_eq!(query.sql.matches("FROM file(").count(), 1);
        assert!(!query.sql.contains("UNION ALL"));
        assert_eq!(
            query
                .params
                .iter()
                .find(|(name, _)| name == "entity_index")
                .map(|(_, value)| value.as_str()),
            Some("/trusted/object-{0000..0467}.parquet")
        );
    }

    #[test]
    fn narrow_window_names_only_overlapping_index_fragments() {
        let object = |object_id: u32, hour: i64| SidecarObject {
            object_id,
            position: object_id,
            event_object_key: format!(
                "s3://bucket/table/data/event_hour={hour}/part-{object_id}.parquet"
            ),
            event_object_version: format!("version-{object_id}"),
            event_object_bytes: 100,
            rows: 1,
            row_group_ranges: vec![RowGroupRange {
                row_group: 0,
                row_start: 0,
                row_end: 1,
            }],
        };
        let sidecar = EntitySidecar {
            key_id: "key-v1".to_string(),
            key: vec![7; 32],
            index_directory: PathBuf::from("/trusted"),
            value_hash_bytes: INDEX_VERSION_V2_VALUE_HASH_BYTES,
            index_pattern: PathBuf::from("/trusted/object-{0000..0003}.parquet"),
            fields: BTreeMap::from([(
                "metadata.uid".to_string(),
                FieldSpec {
                    field_id: 1,
                    source_path: "metadata.uid".to_string(),
                    kind: "text".to_string(),
                },
            )]),
            objects: BTreeMap::from([
                (0, object(0, 100)),
                (1, object(1, 101)),
                (2, object(2, 101)),
                (3, object(3, 102)),
            ]),
        };

        let query = sidecar
            .query_for_window(
                "metadata.uid",
                "event-1",
                101 * 3_600_000 + 1,
                102 * 3_600_000 - 1,
            )
            .expect("scoped lookup")
            .expect("overlapping sidecar files");
        assert_eq!(
            query
                .params
                .iter()
                .find(|(name, _)| name == "entity_index")
                .map(|(_, value)| value.as_str()),
            Some("/trusted/object-{0001,0002}.parquet")
        );
        assert!(
            sidecar
                .query_for_window("metadata.uid", "event-1", 200 * 3_600_000, 201 * 3_600_000,)
                .expect("empty scoped lookup")
                .is_none()
        );
    }

    fn windowed_sidecar(objects: &[(u32, i64)]) -> EntitySidecar {
        let object = |object_id: u32, hour: i64| SidecarObject {
            object_id,
            position: object_id,
            event_object_key: format!(
                "s3://bucket/table/data/event_hour={hour}/part-{object_id}.parquet"
            ),
            event_object_version: format!("version-{object_id}"),
            event_object_bytes: 100,
            rows: 1,
            row_group_ranges: vec![RowGroupRange {
                row_group: 0,
                row_start: 0,
                row_end: 1,
            }],
        };
        let last = objects.len().saturating_sub(1);
        EntitySidecar {
            key_id: "key-v1".to_string(),
            key: vec![7; 32],
            index_directory: PathBuf::from("/trusted"),
            value_hash_bytes: INDEX_VERSION_V2_VALUE_HASH_BYTES,
            index_pattern: PathBuf::from(format!("/trusted/object-{{0000..{last:04}}}.parquet")),
            fields: BTreeMap::from([(
                "actor.process.name".to_string(),
                FieldSpec {
                    field_id: 1,
                    source_path: "actor.process.name".to_string(),
                    kind: "text".to_string(),
                },
            )]),
            objects: objects
                .iter()
                .map(|(object_id, hour)| (*object_id, object(*object_id, *hour)))
                .collect(),
        }
    }

    fn entity_index_param(query: &SidecarQuery) -> &str {
        query
            .params
            .iter()
            .find(|(name, _)| name == "entity_index")
            .map(|(_, value)| value.as_str())
            .expect("entity index parameter")
    }

    /// A one-hour search must not pay for a year of retention. Before window
    /// scoping reached the broad search path, every entity term opened one index
    /// fragment per generation object, so the constant per-query cost grew with
    /// the table instead of with the request.
    #[test]
    fn a_narrow_search_window_opens_only_the_fragments_it_can_match() {
        let sidecar = windowed_sidecar(&[(0, 100), (1, 101), (2, 102), (3, 103), (4, 104)]);

        let scoped = sidecar
            .query_for_rfc3339_window(
                "actor.process.name",
                "svchost.exe",
                "1970-01-05T05:30:00Z",
                "1970-01-05T06:30:00Z",
            )
            .expect("scoped probe")
            .expect("overlapping fragments");

        // Hours 101 and 102 only: 2 of 5 fragments.
        assert_eq!(entity_index_param(&scoped), "/trusted/object-{0001,0002}.parquet");
        assert_eq!(scoped.index_objects, 2);
        assert_eq!(sidecar.index_objects_total(), 5);
    }

    /// Pruning is an optimization, never a filter: anything that makes the
    /// window untrustworthy must widen the probe back to the whole generation
    /// rather than silently drop candidate objects.
    #[test]
    fn an_unusable_window_falls_back_to_the_whole_generation() {
        let sidecar = windowed_sidecar(&[(0, 100), (1, 101), (2, 102), (3, 103), (4, 104)]);

        for (start, end) in [
            ("", ""),
            ("not-a-timestamp", "1970-01-05T06:30:00Z"),
            ("1970-01-05T06:30:00Z", "not-a-timestamp"),
            // Non-increasing window: the compiler should never emit one, and a
            // narrowed probe here would be a correctness bug, not a saving.
            ("1970-01-05T06:30:00Z", "1970-01-05T05:30:00Z"),
            ("1970-01-05T06:30:00Z", "1970-01-05T06:30:00Z"),
        ] {
            let probe = sidecar
                .query_for_rfc3339_window("actor.process.name", "svchost.exe", start, end)
                .expect("fallback probe")
                .expect("full generation probe");
            assert_eq!(
                entity_index_param(&probe),
                "/trusted/object-{0000..0004}.parquet",
                "window ({start:?}, {end:?}) must not narrow the probe"
            );
            assert_eq!(probe.index_objects, 5);
        }
    }

    /// A window that no object overlaps proves the generation cannot contribute
    /// a row. The caller turns this into an empty candidate set, which fences
    /// the base source to nothing instead of scanning it.
    #[test]
    fn a_window_no_object_overlaps_yields_no_probe_at_all() {
        let sidecar = windowed_sidecar(&[(0, 100), (1, 101)]);

        assert!(
            sidecar
                .query_for_rfc3339_window(
                    "actor.process.name",
                    "svchost.exe",
                    "1970-01-09T00:00:00Z",
                    "1970-01-09T01:00:00Z",
                )
                .expect("scoped probe")
                .is_none()
        );

        let evidence = sidecar.empty_window_evidence("actor.process.name");
        assert_eq!(evidence.index_objects, 0);
        assert_eq!(evidence.index_objects_total, 2);
        assert_eq!(evidence.candidate_blocks, 0);
        assert!(evidence.exact_recheck);
    }

    /// An object whose key carries no trusted hour partition cannot be placed in
    /// time, so it must stay in every probe.
    #[test]
    fn an_object_without_a_trusted_hour_partition_is_never_pruned_away() {
        let mut sidecar = windowed_sidecar(&[(0, 100), (1, 101)]);
        sidecar.objects.insert(
            2,
            SidecarObject {
                object_id: 2,
                position: 2,
                event_object_key: "s3://bucket/table/data/legacy/part-2.parquet".to_string(),
                event_object_version: "version-2".to_string(),
                event_object_bytes: 100,
                rows: 1,
                row_group_ranges: vec![RowGroupRange {
                    row_group: 0,
                    row_start: 0,
                    row_end: 1,
                }],
            },
        );

        let probe = sidecar
            .query_for_rfc3339_window(
                "actor.process.name",
                "svchost.exe",
                "1970-01-05T05:30:00Z",
                "1970-01-05T06:30:00Z",
            )
            .expect("scoped probe")
            .expect("overlapping fragments");

        assert_eq!(entity_index_param(&probe), "/trusted/object-{0001,0002}.parquet");
    }

    #[test]
    fn common_entity_candidate_overflow_is_a_direct_scan_fallback() {
        let sidecar = EntitySidecar {
            key_id: "key-v1".to_string(),
            key: vec![7; 32],
            index_directory: PathBuf::from("/trusted"),
            value_hash_bytes: INDEX_VERSION_V2_VALUE_HASH_BYTES,
            index_pattern: PathBuf::from("/trusted/object-0000.parquet"),
            fields: BTreeMap::from([(
                "device.hostname".to_string(),
                FieldSpec {
                    field_id: 1,
                    source_path: "device.hostname".to_string(),
                    kind: "text".to_string(),
                },
            )]),
            objects: BTreeMap::from([(
                0,
                SidecarObject {
                    object_id: 0,
                    position: 0,
                    event_object_key: "s3://bucket/table/data/object.parquet".to_string(),
                    event_object_version: "version-1".to_string(),
                    event_object_bytes: 100,
                    rows: (MAX_CANDIDATE_BLOCKS + 1) as u64,
                    row_group_ranges: (0..=MAX_CANDIDATE_BLOCKS as u32)
                        .map(|row_group| RowGroupRange {
                            row_group,
                            row_start: u64::from(row_group),
                            row_end: u64::from(row_group) + 1,
                        })
                        .collect(),
                },
            )]),
        };
        let data = (0..=MAX_CANDIDATE_BLOCKS as u32)
            .map(|block_id| {
                format!(
                    "{{\"object_id\":0,\"block_id\":{block_id},\"matches\":1,\"max_time\":{block_id}}}\n"
                )
            })
            .collect::<String>();

        let error = sidecar
            .candidates("device.hostname", data.as_bytes())
            .expect_err("overflow must choose fallback");
        let SidecarError::CandidateBound {
            candidate_blocks,
            candidate_objects,
        } = error
        else {
            panic!("unexpected overflow error: {error}");
        };
        let evidence =
            sidecar.fallback_evidence("device.hostname", candidate_blocks, candidate_objects);
        assert_eq!(evidence.candidate_blocks, MAX_CANDIDATE_BLOCKS + 1);
        assert_eq!(evidence.candidate_objects, 1);
        assert!(evidence.fallback_reason.is_some());
    }

    #[test]
    fn wide_window_probe_parallelizes_fragment_opens_but_stays_bounded() {
        // Failure this prevents: a probe over hundreds of index fragments
        // regressing to max_threads=1, where each Parquet footer read is
        // serial and the probe is O(index_objects) wall time (~0.46s at a
        // 24-hour window on the deployed volume, the 2x exact-vs-regex gap).
        let objects: Vec<(u32, i64)> = (0..300).map(|id| (id, 500_000 + i64::from(id))).collect();
        let sidecar = windowed_sidecar(&objects);
        let query = sidecar
            .query("actor.process.name", "svchost.exe")
            .expect("probe");
        assert_eq!(query.index_objects, 300);
        assert!(
            query.sql.contains("max_threads=8"),
            "wide probe must use the full thread bound, got: {}",
            query.sql
        );

        // And the bound must hold: unbounded parallelism was the reason the
        // original UNION ALL fan-out exceeded the probe memory fence.
        assert!(!query.sql.contains("max_threads=300"));
    }

    #[test]
    fn narrow_probe_stays_serial_so_row_expansion_probes_spawn_no_extra_threads() {
        // Failure this prevents: a two-second row-expansion probe (one or two
        // fragments) paying thread spawn overhead for parallelism it cannot
        // use.
        let sidecar = windowed_sidecar(&[(0, 500_000)]);
        let query = sidecar
            .query("actor.process.name", "svchost.exe")
            .expect("probe");
        assert!(
            query.sql.contains("max_threads=1"),
            "single-fragment probe must stay serial, got: {}",
            query.sql
        );
    }

    #[test]
    fn probe_cache_key_covers_value_field_and_fragment_pattern() {
        // Failure this prevents: two different probes colliding in the cache
        // and one hunt being answered with another hunt's candidate blocks.
        // The key must change when the value hash, the field, or the
        // window-pruned fragment pattern changes.
        let sidecar = windowed_sidecar(&[(0, 500_000), (1, 500_001), (2, 500_002)]);
        let full = sidecar
            .query("actor.process.name", "svchost.exe")
            .expect("probe");
        let other_value = sidecar
            .query("actor.process.name", "lsass.exe")
            .expect("probe");
        let window_start_ms = 500_001_i64 * 3_600_000;
        let windowed = sidecar
            .query_for_window(
                "actor.process.name",
                "svchost.exe",
                window_start_ms,
                window_start_ms + 1,
            )
            .expect("probe")
            .expect("window overlaps one object");
        assert_ne!(probe_cache_key(&full), probe_cache_key(&other_value));
        assert_ne!(probe_cache_key(&full), probe_cache_key(&windowed));
        // Identical probes must share a key, or the cache never hits.
        let full_again = sidecar
            .query("actor.process.name", "svchost.exe")
            .expect("probe");
        assert_eq!(probe_cache_key(&full), probe_cache_key(&full_again));
    }

    #[test]
    fn probe_cache_returns_the_exact_bytes_that_were_inserted() {
        // Failure this prevents: a hit returning anything other than the
        // byte-identical engine output, which would silently change the
        // candidate block set a hunt is fenced to.
        let mut cache = EntityProbeCache::default();
        let data: std::sync::Arc<[u8]> = b"{\"object_id\":1}\n".to_vec().into();
        cache.insert("probe-a".to_string(), data.clone());
        assert_eq!(cache.get("probe-a").as_deref(), Some(data.as_ref()));
        assert!(cache.get("probe-b").is_none());
    }

    #[test]
    fn probe_cache_evicts_oldest_entries_and_never_exceeds_its_bounds() {
        // Failure this prevents: the probe cache growing without bound across
        // a generation's lifetime and holding candidate output for every value
        // ever hunted.
        let mut cache = EntityProbeCache::default();
        for index in 0..(PROBE_CACHE_MAX_ENTRIES + 8) {
            cache.insert(format!("probe-{index}"), b"data".to_vec().into());
        }
        assert!(cache.entries.len() <= PROBE_CACHE_MAX_ENTRIES);
        assert!(cache.get("probe-0").is_none(), "oldest entry must be gone");
        assert!(cache
            .get(&format!("probe-{}", PROBE_CACHE_MAX_ENTRIES + 7))
            .is_some());

        // An entry larger than the whole budget is refused outright instead of
        // evicting everything else to make room.
        let mut cache = EntityProbeCache::default();
        cache.insert("small".to_string(), b"data".to_vec().into());
        cache.insert(
            "huge".to_string(),
            vec![0_u8; PROBE_CACHE_MAX_BYTES + 1].into(),
        );
        assert!(cache.get("huge").is_none());
        assert!(cache.get("small").is_some());
    }
}
