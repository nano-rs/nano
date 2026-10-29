// SPDX-License-Identifier: AGPL-3.0-or-later

//! Turn trusted compiler output and an immutable publication manifest into a
//! bounded native chDB query. Analyst input never enters this layer as SQL.

use chrono::DateTime;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::bounds::HOT_TAIL_OBJECT_FORMAT_CEILING;
use crate::generation::HotTailManifest;

const LOG_SOURCE_PLACEHOLDER: &str = "__nano_lake_source__";
pub const DEFAULT_QUERY_MEMORY_BYTES: u64 = 4_294_967_296;
const MIN_QUERY_MEMORY_BYTES: u64 = 67_108_864;
pub(crate) const MAX_QUERY_MEMORY_BYTES: u64 = 68_719_476_736;
pub const DASHBOARD_BREAKDOWN_FIELD: &str = "__nano.dashboard_breakdown";
pub const DASHBOARD_BREAKDOWN_COMPONENTS: &[&str] =
    &["severity", "class_name", "metadata.log_source"];

#[derive(Debug, thiserror::Error)]
pub enum QueryPlanError {
    #[error("source manifest tenant does not match the assigned tenant")]
    TenantMismatch,
    #[error("source manifest contains no immutable objects")]
    EmptyManifest,
    #[error("source manifest object is invalid: {0}")]
    InvalidManifest(String),
    #[error("compiled query contract is invalid: {0}")]
    InvalidCompilerOutput(String),
    #[error("tenant query configuration is invalid: {0}")]
    InvalidTenantConfig(String),
    #[error("query scan budget rejected {estimated_bytes} bytes above {max_bytes}")]
    BudgetRejected {
        estimated_bytes: u64,
        max_bytes: u64,
    },
}

type Result<T> = std::result::Result<T, QueryPlanError>;

#[derive(Debug, Clone)]
pub struct TenantQueryConfig {
    pub tenant_id: String,
    pub source: String,
    pub iceberg_metadata_file_path: String,
    pub max_query_bytes: u64,
    /// Applies independently to every admitted native executor lane.
    pub max_memory_bytes: u64,
    pub max_execution_seconds: u64,
    pub threads: u64,
    pub credentials: ObjectStoreCredentials,
    pub snapshot_cache: Option<SnapshotCache>,
}

#[derive(Debug, Clone)]
pub struct SnapshotCache {
    pub source_spec: String,
    pub objects: BTreeMap<String, SnapshotCacheObject>,
    pub bytes: u64,
    /// Catalog-owned union schema for every immutable Parquet object in this
    /// serving generation. Supplying it explicitly makes older objects
    /// materialize additive nested OCSF leaves as null instead of allowing
    /// chDB to infer incompatible Tuple/Variant shapes across files.
    pub read_schema: Option<String>,
    /// NAN-2361 wave 8: the zero-snapshot bootstrap generation. `objects` is
    /// empty, `bytes` is 0, `source_spec` is empty, and `read_schema` is
    /// mandatory. The base source is a schema-shaped empty relation instead
    /// of an object-storage read, so every query answers from the signed hot
    /// tail alone. Only `config::load_snapshot_cache` sets this.
    pub bootstrap: bool,
}

#[derive(Debug, Clone)]
pub struct SnapshotCacheObject {
    pub version_id: String,
    pub bytes: u64,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub enum ObjectStoreCredentials {
    /// Let chDB's S3 client resolve the standard AWS provider chain. This is
    /// the production workload-identity mode for EC2, ECS, and IRSA. It is
    /// explicit so an unset static secret never silently broadens into an
    /// ambient process identity.
    DefaultChain,
    Static {
        access_key: String,
        secret_key: String,
        session_token: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledQuery {
    pub schema_version: u64,
    pub profile: String,
    pub dataset: String,
    pub source_placeholder: String,
    pub query_sha256: String,
    pub start: String,
    pub end: String,
    pub limit: usize,
    pub table_view: bool,
    #[serde(default)]
    pub newest_first_event_rows: bool,
    #[serde(default)]
    pub stats_page: bool,
    #[serde(default)]
    pub candidate_hints: Vec<CandidateHint>,
    pub required_columns: Vec<RequiredColumn>,
    #[serde(default)]
    pub projected_scan_columns: Vec<String>,
    pub sql: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredColumn {
    pub name: String,
    pub field_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CandidateHint {
    Entity { source_path: String, value: String },
    SourceFamily { value: String },
    /// NAN-3188: a top-level-AND `class_uid = value`. Only decides whole data
    /// files whose signed `class_id` names another class; every other stage
    /// keeps on it, and the compiled SQL still filters every row.
    Class { value: i64 },
    Keyword { mode: String, value: String },
    Any { alternatives: Vec<CandidateHint> },
}

fn deserialize_shared_paths<'de, D>(deserializer: D) -> std::result::Result<Arc<[String]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let paths = Vec::<String>::deserialize(deserializer)?;
    Ok(Arc::from(paths))
}

#[derive(Debug, Default, Deserialize)]
pub struct SourceManifest {
    pub tenant_id: String,
    pub objects: Vec<ManifestObject>,
    /// Derived facts, computed on first use and then reused for the life of the
    /// generation. Never deserialized: a manifest read from disk starts empty.
    #[serde(skip)]
    facts: OnceLock<ManifestFacts>,
    /// NAN-3081: the queryable paths of a bootstrap (empty-relation) base
    /// that has no hot tail to carry its read contract. The part engine plans
    /// a selection whose every file was pruned as `null(<read schema>)`; the
    /// columns of that relation are real (typed, zero rows), not missing.
    #[serde(skip)]
    bootstrap_available_paths: BTreeSet<String>,
    /// NAN-3366: the bootstrap generation's catalog field types (leaf path ->
    /// type), written by the generation manager. A bootstrap base has no
    /// object to derive its schema from, so without these the legacy worker
    /// path counted every required column as missing (the NAN-3081 `Block
    /// structure mismatch`, here on the readiness canary) and served an empty
    /// field inventory that readers refuse. Only honored on an empty manifest.
    #[serde(default)]
    bootstrap_field_types: BTreeMap<String, String>,
}

/// Everything the planner derives from a manifest that cannot change while the
/// generation is loaded.
///
/// Each request used to re-walk every object's `available_paths` and
/// `field_types` — about 150,000 entries on a 714-object generation — three
/// times over: once to build the available-path set, once to validate the field
/// types, and once more to merge them for the query compiler. The merge alone
/// measured 25.4 ms in release, which grows with retention and was roughly a
/// fifth of what an entity query cost end to end.
#[derive(Debug)]
struct ManifestFacts {
    available_paths: BTreeSet<String>,
    field_types: BTreeMap<String, String>,
    estimated_bytes: u64,
}

impl SourceManifest {
    /// A manifest built in process rather than read from a generation (the
    /// NAN-2869 part query path builds one per query from verified parts).
    pub fn from_objects(tenant_id: impl Into<String>, objects: Vec<ManifestObject>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            objects,
            facts: OnceLock::new(),
            bootstrap_available_paths: BTreeSet::new(),
            bootstrap_field_types: BTreeMap::new(),
        }
    }

    /// NAN-3081: an empty manifest over a bootstrap base whose typed empty
    /// relation (`null(<read schema>)`) exposes `paths`. Without this every
    /// required column counted as missing and was re-materialized as a typed
    /// NULL constant beside the relation's own column of the same name; a
    /// full-row query then failed in chDB with `Block structure mismatch
    /// (time DateTime64 vs Nullable(DateTime64) Const)`.
    pub fn empty_with_bootstrap_paths(tenant_id: impl Into<String>, paths: impl IntoIterator<Item = String>) -> Self {
        let mut manifest = Self::from_objects(tenant_id, Vec::new());
        manifest.bootstrap_available_paths = paths.into_iter().collect();
        manifest
    }

    /// Derive the facts, then drop the per-object schema copies they subsume.
    ///
    /// The manifest carries `field_types` once per object — the same ~211 keys
    /// repeated for every object in the generation, because each object records
    /// the schema it was written against. Measured on a 714-object generation:
    /// 150,974 entries, about a third of the manifest's per-object payload. Once
    /// the merged map exists in [`ManifestFacts`], nothing reads the per-object
    /// copies again (the only reader is the derivation itself), so holding them
    /// for the life of the generation is pure overhead — and it is overhead that
    /// grows with object count, which is the axis that bounds how long a table
    /// can live rather than how much data it holds.
    ///
    /// Derives eagerly on purpose: the facts must exist before the copies go, or
    /// a later `facts()` call would rebuild them from emptied objects and
    /// silently return an empty field-type map.
    fn release_derived_object_schema(&mut self) -> Result<()> {
        self.facts()?;
        // Objects only differ in schema where the schema evolved, so the same
        // few path lists repeat across the whole generation. Point every object
        // carrying an identical list at one shared allocation: measured at 714
        // objects holding 16 distinct shapes, which turns 150,974 stored paths
        // into ~3,400 and makes this term grow with schema history rather than
        // with object count.
        let mut shapes: BTreeMap<Arc<[String]>, Arc<[String]>> = BTreeMap::new();
        for object in &mut self.objects {
            let shared = shapes
                .entry(object.available_paths.clone())
                .or_insert_with(|| object.available_paths.clone())
                .clone();
            object.available_paths = shared;
            object.field_types = BTreeMap::new();
        }
        Ok(())
    }

    /// How many distinct schema shapes the objects share between them, and how
    /// many path entries that stores. Reported so the saving is observable
    /// rather than asserted.
    pub fn shared_schema_shapes(&self) -> (usize, usize) {
        let mut distinct: BTreeSet<*const String> = BTreeSet::new();
        let mut stored = 0_usize;
        for object in &self.objects {
            if distinct.insert(object.available_paths.as_ptr()) {
                stored += object.available_paths.len();
            }
        }
        (distinct.len(), stored)
    }

    /// The derived facts, computing them once. Validation errors are not cached:
    /// an invalid manifest returns the same error on every call, and a caller
    /// must never see a manifest that failed validation treated as valid.
    fn facts(&self) -> Result<&ManifestFacts> {
        if let Some(facts) = self.facts.get() {
            return Ok(facts);
        }
        let computed = compute_manifest_facts(self)?;
        // A concurrent caller may have won the race; either value is identical.
        Ok(self.facts.get_or_init(|| computed))
    }
}

/// Validate every object's immutable identity and schema, and derive the facts.
///
/// This is the manifest-only half of what `validate_manifest` used to do inline;
/// the tenant-dependent half stays per request because it depends on the caller.
fn compute_manifest_facts(manifest: &SourceManifest) -> Result<ManifestFacts> {
    let mut available_paths = BTreeSet::new();
    let mut field_types = BTreeMap::<String, String>::new();
    let mut object_keys = BTreeSet::new();
    let mut estimated_bytes = 0_u64;
    for object in &manifest.objects {
        if object.event_object_key.is_empty()
            || object.event_object_version.is_empty()
            || object.event_object_version == "unversioned"
            || object.event_object_version.starts_with("etag:")
            || object.event_object_bytes == 0
            || object.available_paths.is_empty()
        {
            return Err(QueryPlanError::InvalidManifest(
                "object lacks an exact version, positive size, or schema".to_string(),
            ));
        }
        if !object_keys.insert(&object.event_object_key) {
            return Err(QueryPlanError::InvalidManifest(
                "object key is duplicated".to_string(),
            ));
        }
        estimated_bytes = estimated_bytes
            .checked_add(object.event_object_bytes)
            .ok_or_else(|| {
                QueryPlanError::InvalidManifest("object byte total overflowed".to_string())
            })?;
        for path in object.available_paths.iter() {
            insert_addressable_path(&mut available_paths, path)?;
        }
        for (path, field_type) in &object.field_types {
            // NAN-3422: a producer key that is not a query identifier stays in
            // the stored row (its root is still projected) but is not a typed,
            // addressable leaf.
            if !is_addressable_path(path) {
                continue;
            }
            default_expression(field_type)?;
            if let Some(prior) = field_types.get(path) {
                if prior != field_type {
                    return Err(QueryPlanError::InvalidManifest(format!(
                        "snapshot has conflicting types for {path}"
                    )));
                }
            } else {
                field_types.insert(path.clone(), field_type.clone());
            }
        }
    }
    Ok(ManifestFacts {
        available_paths,
        field_types,
        estimated_bytes,
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManifestObject {
    pub event_object_key: String,
    pub event_object_version: String,
    pub event_object_bytes: u64,
    pub rows: u64,
    /// Shared with every other object of the same schema shape. A generation
    /// records this list once per object, but objects only differ when the
    /// schema evolved: measured at 714 objects carrying 16 distinct shapes, so
    /// 150,974 stored paths collapse to ~3,400 once they are shared. That is
    /// the difference between this term growing with object count and growing
    /// with schema history.
    #[serde(deserialize_with = "deserialize_shared_paths")]
    pub available_paths: Arc<[String]>,
    #[serde(default)]
    pub field_types: BTreeMap<String, String>,
    #[serde(default)]
    pub column_compressed_bytes: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateBlock {
    pub event_object_key: String,
    pub event_object_bytes: u64,
    pub row_start: u64,
    pub row_end: u64,
    /// Inclusive upper bound for event time in this block, in Unix
    /// milliseconds. `None` keeps older index generations conservative.
    pub max_time_ms: Option<u64>,
    /// Inclusive `[min, max]` event time of the block's rows in Unix
    /// microseconds, from the Parquet row-group statistics (parts only).
    /// The `_row_number` fence is exact but is evaluated after the reader
    /// has decoded every row group of the file; a `time` range lets the
    /// reader's statistics filter skip the row groups outside every kept
    /// block. `None` emits no range.
    pub time_range_us: Option<(i64, i64)>,
}

/// Can this candidate block contribute a row to `[start_ms, end_ms]`?
///
/// Progressive paging fences each chunk to its own window, so a block that
/// cannot contain a row in that window is pure re-read. The block's index
/// `max_time_ms` bounds it from below; the object's trusted `event_hour=`
/// partition bounds it from above, which is the half that was missing.
///
/// Without the upper bound, chunk N kept every block belonging to chunks
/// 1..N-1 — their `max_time_ms` is necessarily at or after an older chunk's
/// start — so each chunk re-read every newer chunk's blocks and the SQL time
/// fence then discarded the rows. That is quadratic in chunks executed: on a
/// 24-hour hunt it grew from 17,339 rows scanned at ~25 candidate objects to
/// 382,569 at 101, purely because the generation accumulated objects.
///
/// Conservative in the same direction as everything else here: a block whose
/// object carries no parseable hour segment is always kept.
/// NAN-2869: rows a newest-first page can ever return. A timeline with
/// `head N` compiles to `… ORDER BY time DESC LIMIT N`, which caps the page
/// below the request's `limit`. Progressive paging concatenates chunk results
/// newest-first, so the global page is the first `N` rows and the walk can stop
/// there; without the cap it kept walking (and returned up to `N` rows per
/// chunk). Conservative: `None` unless the statement ends in exactly that
/// shape (an optional trailing `SETTINGS …` aside).
pub fn newest_first_row_cap(sql: &str) -> Option<usize> {
    newest_first_limit_span(sql).map(|(_, limit)| limit)
}

/// The byte range of the trailing newest-first `LIMIT n` digits and `n`.
fn newest_first_limit_span(sql: &str) -> Option<(std::ops::Range<usize>, usize)> {
    let body = match sql.rfind(" SETTINGS ") {
        Some(at) if !sql[at..].contains(')') || sql[at..].matches('(').count() == sql[at..].matches(')').count() => &sql[..at],
        _ => sql,
    };
    let trimmed = body.trim_end();
    let (head, limit_text) = trimmed.rsplit_once(" LIMIT ")?;
    let limit = limit_text.trim().parse::<usize>().ok()?;
    let digits_start = head.len() + " LIMIT ".len() + (limit_text.len() - limit_text.trim_start().len());
    let span = digits_start..trimmed.len();
    let order = head.trim_end();
    // The compiler's deterministic event order adds a `metadata.uid`
    // tiebreak; progressive chunks are disjoint in time, so the tiebreak never
    // reorders rows across chunks and the cap stays exact.
    let order = order
        .strip_suffix(", \"metadata.uid\" DESC")
        .unwrap_or(order)
        .trim_end();
    (order.ends_with("ORDER BY time DESC") || order.ends_with("ORDER BY \"time\" DESC")).then_some((span, limit))
}

/// NAN-3265: `compiled` with its trailing newest-first `LIMIT` lowered to
/// `cap` (statement and `limit` alike), or `None` for any other shape. The
/// top `cap` rows of a newest-first statement are a prefix of its top `n`,
/// so a progressive chunk read under a smaller cap returns a prefix of the
/// rows it would have returned, in the same order.
pub fn with_newest_first_row_cap(compiled: &CompiledQuery, cap: usize) -> Option<CompiledQuery> {
    let (span, limit) = newest_first_limit_span(&compiled.sql)?;
    let mut capped = compiled.clone();
    if cap == 0 || cap >= limit {
        return Some(capped);
    }
    capped.sql.replace_range(span, &cap.to_string());
    capped.limit = capped.limit.min(cap);
    Some(capped)
}

pub fn candidate_block_overlaps_window(block: &CandidateBlock, start_ms: u64, end_ms: u64) -> bool {
    let (Ok(start_ms), Ok(end_ms)) = (i64::try_from(start_ms), i64::try_from(end_ms)) else {
        // Unrepresentable bounds cannot prove anything; keep the block.
        return true;
    };
    let after_start = block
        .max_time_ms
        .is_none_or(|max_time| i64::try_from(max_time).is_ok_and(|max| max >= start_ms));
    if !after_start {
        return false;
    }
    object_path_overlaps_window(
        &block.event_object_key,
        ObjectTimeWindow { start_ms, end_ms },
    )
}

/// Intersect compiler-proven candidate supersets for mandatory `AND`
/// predicates. Sidecars are allowed to use different block boundaries, so the
/// intersection is calculated by overlapping row ranges rather than assuming
/// identical row-group identities. The complete compiled predicate is still
/// evaluated against the result.
pub fn intersect_candidate_blocks(
    candidate_sets: &[Vec<CandidateBlock>],
) -> Result<Vec<CandidateBlock>> {
    if candidate_sets.is_empty() {
        return Ok(Vec::new());
    }
    let mut intersection = normalize_candidate_blocks(candidate_sets[0].clone())?;
    for candidates in &candidate_sets[1..] {
        let candidates = normalize_candidate_blocks(candidates.clone())?;
        let mut next = Vec::new();
        let (mut left, mut right) = (0, 0);
        while left < intersection.len() && right < candidates.len() {
            let a = &intersection[left];
            let b = &candidates[right];
            match a.event_object_key.cmp(&b.event_object_key) {
                std::cmp::Ordering::Less => {
                    left += 1;
                    continue;
                }
                std::cmp::Ordering::Greater => {
                    right += 1;
                    continue;
                }
                std::cmp::Ordering::Equal => {}
            }
            if a.event_object_bytes != b.event_object_bytes {
                return Err(QueryPlanError::InvalidManifest(
                    "candidate intersections disagree on immutable object size".to_string(),
                ));
            }
            let row_start = a.row_start.max(b.row_start);
            let row_end = a.row_end.min(b.row_end);
            if row_start < row_end {
                next.push(CandidateBlock {
                    event_object_key: a.event_object_key.clone(),
                    event_object_bytes: a.event_object_bytes,
                    row_start,
                    row_end,
                    max_time_ms: match (a.max_time_ms, b.max_time_ms) {
                        (Some(left), Some(right)) => Some(left.min(right)),
                        (Some(value), None) | (None, Some(value)) => Some(value),
                        (None, None) => None,
                    },
                    time_range_us: None,
                });
            }
            if a.row_end <= b.row_end {
                left += 1;
            }
            if b.row_end <= a.row_end {
                right += 1;
            }
        }
        intersection = normalize_candidate_blocks(next)?;
        if intersection.is_empty() {
            break;
        }
    }
    Ok(intersection)
}

/// Union complete OR supersets, merging overlapping row ranges from distinct
/// indexes. Unknown time bounds remain unknown. Bound overflow falls back.
pub fn union_candidate_blocks(sets: &[Vec<CandidateBlock>]) -> Result<Option<Vec<CandidateBlock>>> {
    if sets.iter().map(Vec::len).sum::<usize>() > 4096 { return Ok(None); }
    let mut blocks = sets.iter().flatten().cloned().collect::<Vec<_>>();
    blocks.sort_by(|a, b| (&a.event_object_key, a.row_start).cmp(&(&b.event_object_key, b.row_start)));
    let mut result: Vec<CandidateBlock> = Vec::new();
    for block in blocks {
        if let Some(last) = result.last_mut() {
            if last.event_object_key == block.event_object_key
                && last.event_object_bytes != block.event_object_bytes {
                return Ok(None);
            }
            if last.event_object_key == block.event_object_key && block.row_start <= last.row_end {
                last.row_end = last.row_end.max(block.row_end);
                last.max_time_ms = last.max_time_ms.zip(block.max_time_ms).map(|(a,b)| a.max(b));
                continue;
            }
        }
        result.push(block);
    }
    normalize_candidate_blocks(result).map(Some)
}

/// A narrow locator for the proven table-view shape, retaining only producer
/// predicate/order columns. One scan finds the page across all tail objects.
pub fn table_view_locator(compiled: &CompiledQuery) -> Option<CompiledQuery> {
    let mut clause = table_view_page_clause(compiled)?;
    // The locator returns only timestamps. A time-only top-k still includes
    // the cutoff timestamp even when more than k rows tie there; the full
    // query rechecks every row at that instant and applies the UID tie key.
    // Avoid sorting UID strings across every locator scan.
    clause = clause.replace("ORDER BY time DESC, \"metadata.uid\" DESC LIMIT", "ORDER BY time DESC LIMIT");
    let mut locator = compiled.clone();
    locator.required_columns.retain(|column| compiled.projected_scan_columns.contains(&column.name) || column.name == "metadata.uid");
    if locator.required_columns.iter().any(|column| column.name == "metadata.uid")
        && !locator.projected_scan_columns.iter().any(|path| path == "metadata.uid") {
        locator.projected_scan_columns.push("metadata.uid".into());
    }
    if !locator.required_columns.iter().any(|column| column.name == "time") { return None; }
    locator.sql = format!("SELECT time AS __nano_locator_time FROM __nano_lake_source__ {clause}");
    locator.newest_first_event_rows = false;
    Some(locator)
}

/// NAN-3221: whether full-event pages may run a narrow locator
/// (`NANO_LAKE_FULL_EVENT_LOCATOR=0` restores the one-pass full-width read).
pub fn full_event_locator_enabled() -> bool {
    crate::perf_overrides::probe_flag("full_event_locator", std::env::var("NANO_LAKE_FULL_EVENT_LOCATOR").map_or(true, |value| value != "0"))
}

/// NAN-3221: the narrow locator of a full-event newest-first page
/// (`SELECT * FROM src WHERE p ORDER BY time DESC, uid DESC LIMIT n`).
///
/// Such a page used to be read in one full-width statement: every root of
/// every row of every kept row group, decoded under the bounded payload
/// settings (one thread, 128-row blocks), only to keep `n` rows. A needle (an entity and a keyword that each occur
/// in every row group, together in a few hundred rows an hour) spent 4–6 s
/// there. The locator reads only the columns `p` names, returns the instants
/// of the page's rows, and the full-width statement then reads exactly those
/// instants (the progressive walk's exact time fence, as for table pages).
///
/// Exactness: the locator applies the compiled predicate `p` unchanged to
/// the same rows, and keeps every row tied at its last instant (the payload
/// re-applies `p`, the uid tie key and the limit). Stored enrichment is read
/// as plain columns (NAN-4168), so every field reads the same in both
/// passes. It is refused for any order other than the compiler's event
/// order, any nested statement or pipeline stage.
pub fn full_event_locator(compiled: &CompiledQuery) -> Option<CompiledQuery> {
    if compiled.table_view
        || !compiled.newest_first_event_rows
        || compiled.stats_page
        || !preserves_full_event_shape(&compiled.sql)
        || select_pattern()
            .find_iter(&blank_quoted_regions(&compiled.sql))
            .count()
            != 1
    {
        return None;
    }
    if !compiled
        .required_columns
        .iter()
        .any(|column| column.name == "time")
        || compiled
            .required_columns
            .iter()
            .any(|column| validate_path(&column.name).is_err())
    {
        return None;
    }
    static SHAPE: OnceLock<Regex> = OnceLock::new();
    let shape = SHAPE.get_or_init(|| {
        Regex::new(r#"(?s)^SELECT \* FROM __nano_lake_source__ (WHERE .+) ORDER BY time DESC, "metadata\.uid" DESC (LIMIT [0-9]+)(?: SETTINGS .+)?$"#)
            .expect("static regex")
    });
    let captures = shape.captures(&compiled.sql)?;
    let (predicate, limit) = (captures.get(1)?.as_str(), captures.get(2)?.as_str());
    static PIPELINE: OnceLock<Regex> = OnceLock::new();
    if PIPELINE
        .get_or_init(|| {
            Regex::new(r"(?i)\b(SELECT|UNION|OFFSET|GROUP|HAVING|QUALIFY|LIMIT|ORDER|SETTINGS|ARRAY\s+JOIN|JOIN)\b")
                .expect("static regex")
        })
        .is_match(&blank_quoted_regions(predicate))
    {
        return None;
    }
    let mut locator = compiled.clone();
    // Uid only for a cursor fence; the locator itself orders by time alone
    // (see `table_view_locator`).
    locator.projected_scan_columns = locator
        .required_columns
        .iter()
        .map(|column| column.name.clone())
        .collect();
    locator.sql = format!("SELECT time AS __nano_locator_time FROM __nano_lake_source__ {predicate} ORDER BY time DESC {limit}");
    locator.newest_first_event_rows = false;
    Some(locator)
}

/// The narrow locator of a newest-first page, table view or full event.
pub fn page_locator(compiled: &CompiledQuery) -> Option<CompiledQuery> {
    table_view_locator(compiled).or_else(|| {
        full_event_locator_enabled()
            .then(|| full_event_locator(compiled))
            .flatten()
    })
}

fn normalize_candidate_blocks(mut candidates: Vec<CandidateBlock>) -> Result<Vec<CandidateBlock>> {
    if candidates.len() > 4_096 {
        return Err(QueryPlanError::InvalidManifest(
            "candidate sidecar exceeded 4096 blocks".to_string(),
        ));
    }
    candidates.sort_by(|left, right| {
        (
            left.event_object_key.as_str(),
            left.row_start,
            left.row_end,
            left.event_object_bytes,
            left.max_time_ms,
        )
            .cmp(&(
                right.event_object_key.as_str(),
                right.row_start,
                right.row_end,
                right.event_object_bytes,
                right.max_time_ms,
            ))
    });
    candidates.dedup();
    for candidate in &candidates {
        if candidate.event_object_key.is_empty()
            || candidate.event_object_bytes == 0
            || candidate.row_start >= candidate.row_end
        {
            return Err(QueryPlanError::InvalidManifest(
                "candidate sidecar returned an invalid block".to_string(),
            ));
        }
    }
    let mut normalized = Vec::<CandidateBlock>::with_capacity(candidates.len());
    for candidate in candidates {
        let Some(previous) = normalized.last_mut() else {
            normalized.push(candidate);
            continue;
        };
        if previous.event_object_key != candidate.event_object_key {
            normalized.push(candidate);
            continue;
        }
        if previous.event_object_bytes != candidate.event_object_bytes
            || candidate.row_start < previous.row_end
        {
            return Err(QueryPlanError::InvalidManifest(
                "candidate sidecar returned overlapping or conflicting blocks".to_string(),
            ));
        }
        if candidate.row_start == previous.row_end {
            previous.row_end = candidate.row_end;
            previous.max_time_ms = match (previous.max_time_ms, candidate.max_time_ms) {
                (Some(left), Some(right)) => Some(left.max(right)),
                (Some(value), None) | (None, Some(value)) => Some(value),
                (None, None) => None,
            };
        } else {
            normalized.push(candidate);
        }
    }
    Ok(normalized)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryBudget {
    pub candidate_objects: usize,
    pub estimated_scan_bytes: u64,
    pub max_query_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct NativeQueryPlan {
    pub query_sha256: String,
    pub sql: String,
    pub params: Vec<(String, String)>,
    pub budget: QueryBudget,
    pub native_event_rows: bool,
    pub temporary_aliases: BTreeSet<String>,
    pub schema_defaults: Vec<String>,
    /// NAN-3393: how wide the statement's Parquet reader is, for the
    /// interactive lane router. Never changes the SQL.
    pub reader: ReaderShape,
}

/// NAN-3393: what the interactive lane router (`part_query::lanes`) needs
/// about a statement's Parquet reader memory. Peak memory is decoded row
/// groups in flight x their projected width, which the scan-byte estimate
/// does not see: a bareword hash verifies against `message`/`raw_data` and
/// reads a few hundred MB, yet eight threads decoding those columns at once
/// outgrow a 256 MiB small lane.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReaderShape {
    /// Wide free-text columns the statement decodes: `message`, `raw_data`
    /// and an explicitly projected `enrichments` array.
    pub wide_columns: u64,
    /// Upper bound of row groups (candidate blocks) it may decode.
    pub row_groups: u64,
    /// Width class of the query window: log2 of its whole hours (1 h = 0,
    /// 24 h = 5, 7 d = 8), so a lane outcome is remembered per window size.
    pub window_class: u8,
    /// Fingerprint of the projected scan columns (one per statement shape
    /// of a query: a stats statement and its companions differ).
    pub columns_key: u64,
    /// NAN-4174: the statement groups by a string column other than a
    /// known low-cardinality label ([`groups_by_string`]).
    pub string_group_by: bool,
}

/// NAN-4174: string columns whose GROUP BY stays small whatever the window
/// (enumerated labels), so they never route a statement to the large lane.
const LOW_CARDINALITY_GROUP_COLUMNS: [&str; 10] = [
    "metadata.log_source", "metadata.product.name", "metadata.product.vendor_name", "class_name",
    "category_name", "activity_name", "type_name", "severity", "status", "disposition",
];

/// NAN-4174: whether `compiled` groups by a `string` required column (a
/// quoted identifier inside a `GROUP BY` clause) that is not a known
/// low-cardinality label. A routing hint only: a miss runs where it always
/// did, a false hit starts on the large lane.
pub fn groups_by_string(compiled: &CompiledQuery) -> bool {
    static GROUP_BY: std::sync::OnceLock<[regex::Regex; 3]> = std::sync::OnceLock::new();
    let [group_by, clause_end, identifier] = GROUP_BY.get_or_init(|| [
        regex::Regex::new(r"(?i)\bGROUP\s+BY\b").expect("static regex"),
        regex::Regex::new(r"(?i)\b(?:ORDER\s+BY|LIMIT|HAVING|SETTINGS|UNION|WITH\s+(?:TOTALS|ROLLUP|CUBE)|FORMAT)\b").expect("static regex"),
        regex::Regex::new(r#""([^"]+)"|`([^`]+)`"#).expect("static regex"),
    ]);
    let strings = compiled.required_columns.iter()
        .filter(|column| column.field_type == "string" && !LOW_CARDINALITY_GROUP_COLUMNS.contains(&column.name.as_str()))
        .map(|column| column.name.as_str())
        .collect::<BTreeSet<_>>();
    if strings.is_empty() {
        return false;
    }
    group_by.find_iter(&compiled.sql).any(|found| {
        let rest = &compiled.sql[found.end()..];
        // The clause ends at the subquery's closing parenthesis ...
        let mut depth = 0_i32;
        let end = rest.char_indices().find(|(_, c)| {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            depth < 0
        }).map_or(rest.len(), |(index, _)| index);
        // ... or at the next clause.
        let clause = &rest[..clause_end.find(&rest[..end]).map_or(end, |next| next.start())];
        identifier.captures_iter(clause)
            .filter_map(|captures| captures.get(1).or_else(|| captures.get(2)))
            .any(|name| strings.contains(name.as_str()))
    })
}

/// The free-text leaves whose decoded width dominates a statement's reader
/// memory (both are [`crate::text_sidecar::KEYWORD_BODY_FIELDS`]).
pub const WIDE_TEXT_COLUMNS: [&str; 2] = ["message", "raw_data"];

/// The [`ReaderShape`] of a compiled statement over `manifest` (and its
/// candidate blocks, when selected).
pub fn reader_shape(compiled: &CompiledQuery, manifest: &SourceManifest, candidates: Option<&[CandidateBlock]>) -> ReaderShape {
    let columns = &compiled.projected_scan_columns;
    let text = columns.iter().filter(|column| WIDE_TEXT_COLUMNS.contains(&column.as_str())).count() as u64;
    // Only an explicit `enrichments` projection reads the array.
    let enrichments = columns.iter().any(|column| column == "enrichments" || column.starts_with("enrichments."));
    let row_groups = match candidates {
        Some(blocks) => blocks.len() as u64,
        None => manifest.objects.iter()
            .map(|object| object.rows.div_ceil(crate::parts::format::ROW_GROUP_ROWS as u64).max(1))
            .sum(),
    };
    let hours = match (parse_rfc3339_us(&compiled.start), parse_rfc3339_us(&compiled.end)) {
        (Some(start), Some(end)) if end > start => (((end - start) as u64).div_ceil(3_600_000_000)).max(1),
        _ => 1,
    };
    let mut sorted = columns.iter().map(String::as_str).collect::<Vec<_>>();
    sorted.sort_unstable();
    let digest = Sha256::digest(sorted.join("\0").as_bytes());
    ReaderShape {
        wide_columns: text + u64::from(enrichments),
        row_groups,
        window_class: hours.next_power_of_two().trailing_zeros() as u8,
        columns_key: u64::from_be_bytes(digest[..8].try_into().expect("sha256 prefix")),
        string_group_by: groups_by_string(compiled),
    }
}

fn parse_rfc3339_us(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value).ok().map(|time| time.timestamp_micros())
}

pub struct FetchLogPlanRequest<'a> {
    pub event_id: &'a str,
    pub start: Option<&'a str>,
    pub end: Option<&'a str>,
    pub log_source: Option<&'a str>,
    pub deny_source_types: &'a BTreeSet<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum CountAggregateSource<'a> {
    Base,
    HotTail(&'a HotTailManifest),
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CountPredicateKind {
    Eq,
    Ne,
    Contains,
    NotContains,
    Regex,
    NotRegex,
    StartsWith,
    NotStartsWith,
    EndsWith,
    NotEndsWith,
    In,
    NotIn,
    IsNull,
    IsNotNull,
    CidrIn,
    CidrNotIn,
    /// NAN-3153: Nano's dotless host-entity equality (`host="ws-1"` means
    /// `lower(v) = 'ws-1' OR startsWith(lower(v), 'ws-1.')`, so a short name
    /// also matches its FQDNs). One value, which must contain no dot.
    HostEq,
}

/// The value column a typed count groups its rows by.
pub fn count_source_group_expression(log_source: &str) -> String {
    // The count rollup keys every row by its first non-blank log source and
    // stores '' when there is none; a raw fragment must group identically.
    format!("if(empty(trimBoth(ifNull(toString({log_source}), ''))), CAST(NULL AS Nullable(String)), toString({log_source}))")
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CountPredicate {
    pub kind: CountPredicateKind,
    #[serde(default)]
    pub values: Vec<String>,
}

pub struct CountAggregatePlanRequest<'a> {
    pub group_field: &'a str,
    pub group_results: bool,
    pub multi_value: bool,
    pub predicate: Option<&'a CountPredicate>,
    pub bucket_span_us: Option<i64>,
    pub start_us: i64,
    pub end_exclusive_us: i64,
    pub source_filter: Option<&'a str>,
    pub deny_source_types: &'a BTreeSet<String>,
    pub source: CountAggregateSource<'a>,
    /// NAN-3153: group by `metadata.log_source` while the predicate applies
    /// to `group_field` (`F=v | stats count by metadata.log_source`).
    pub group_by_source: bool,
}

/// Plan one fixed-shape raw count fragment used to complete an hourly rollup.
/// The caller chooses only a schema-validated field and bound values. Storage,
/// credentials, SQL shape, resource settings, and generation identity remain
/// worker-owned.
pub fn plan_count_aggregate_query(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    request: &CountAggregatePlanRequest<'_>,
) -> Result<Option<NativeQueryPlan>> {
    validate_tenant(tenant)?;
    let (mut available, full_budget) = validate_manifest(tenant, manifest)?;
    // The bootstrap generation has no compacted object: its base fragment is
    // provably zero rows and is not worth an engine round-trip. (Its base
    // also exposes no path, so the field contract below could never be met;
    // the tail fragment of the same request still validates it in full.)
    if matches!(request.source, CountAggregateSource::Base) && tenant_is_bootstrap(tenant) {
        return Ok(None);
    }
    if let CountAggregateSource::HotTail(tail) = request.source {
        extend_available_with_tail_contract(&mut available, tail)?;
    }
    let dashboard_breakdown = request.group_field == DASHBOARD_BREAKDOWN_FIELD;
    if !dashboard_breakdown {
        validate_path(request.group_field)?;
    }
    if (!dashboard_breakdown && !available.contains(request.group_field))
        || (dashboard_breakdown
            && (!request.group_results
                || request.predicate.is_some()
                || DASHBOARD_BREAKDOWN_COMPONENTS
                    .iter()
                    .any(|field| !available.contains(*field))))
        || !available.contains("time")
        || !available.contains("metadata.log_source")
        || request.start_us >= request.end_exclusive_us
        || request.source_filter.is_some_and(|source| {
            source.is_empty() || source.len() > 512 || source.chars().any(char::is_control)
        })
        || request.deny_source_types.iter().any(|source| {
            source.is_empty() || source.len() > 512 || source.chars().any(char::is_control)
        })
        || request
            .bucket_span_us
            .is_some_and(|span| span <= 0 || span > 31_622_400_000_000)
        || (request.group_by_source
            && (request.group_results
                || dashboard_breakdown
                || request.group_field == "metadata.log_source"))
        || (request.multi_value
            && (request.group_results
                || request
                    .predicate
                    .is_none_or(|predicate| predicate.kind != CountPredicateKind::Eq)))
    {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "typed count fragment violates its field, time, or source-scope contract".to_string(),
        ));
    }
    let window = ObjectTimeWindow {
        start_ms: request.start_us.div_euclid(1_000),
        end_ms: request.end_exclusive_us.saturating_sub(1).div_euclid(1_000),
    };
    let (source, mut params, budget) = match request.source {
        CountAggregateSource::Base => {
            let budget = time_scoped_manifest_budget(
                tenant,
                manifest,
                full_budget,
                Some(window),
                None,
                BudgetEnforcement::Reject,
            )?;
            // NAN-2361: prune the base source to the window's objects (see
            // `scoped_snapshot_source_spec`) — the budget above already
            // computed this overlap.
            let (base, base_params, overlap) =
                base_snapshot_source_for_window(tenant, Some(window))?;
            let guard = base_window_guard(overlap);
            let mut params = object_store_params(tenant);
            params.extend(base_params);
            (
                format!("(SELECT {} FROM {base} WHERE {guard})", root_projection_for_paths(available.iter().map(String::as_str))?),
                params,
                budget,
            )
        }
        CountAggregateSource::HotTail(tail) => {
            let mut scoped = tail.clone();
            retain_hot_tail_objects(&mut scoped, |object| {
                object_path_overlaps_window(&object.source_uri, window)
            })?;
            if scoped.objects.is_empty() {
                return Ok(None);
            }
            let mut count_paths =
                BTreeSet::from(["time".to_string(), "metadata.log_source".to_string()]);
            if dashboard_breakdown {
                count_paths.extend(
                    DASHBOARD_BREAKDOWN_COMPONENTS
                        .iter()
                        .map(|field| (*field).to_string()),
                );
            } else {
                count_paths.insert(request.group_field.to_string());
            }
            if available.iter().any(|p| p.starts_with("enrichments.")) {
                count_paths.insert("enrichments".into());
            }
            let projection = root_projection_for_paths(count_paths.iter().map(String::as_str))?;
            let (source, tail_params, budget) =
                hot_tail_source(tenant, &scoped, BudgetEnforcement::Reject, &projection)?;
            let mut params = object_store_params(tenant);
            params.extend(tail_params);
            (source, params, budget)
        }
    };
    let group = if dashboard_breakdown {
        let components = DASHBOARD_BREAKDOWN_COMPONENTS
            .iter()
            .map(|field| nested_expression(field))
            .collect::<Result<Vec<_>>>()?;
        format!("toJSONString(tuple({}))", components.join(", "))
    } else {
        nested_expression(request.group_field)?
    };
    let event_time = nested_expression("time")?;
    let log_source = nested_expression("metadata.log_source")?;
    let mut predicates = vec![
        format!("{event_time} >= fromUnixTimestamp64Micro({{count_start_us:Int64}}, 'UTC')"),
        format!("{event_time} < fromUnixTimestamp64Micro({{count_end_us:Int64}}, 'UTC')"),
    ];
    params.push(("count_start_us".to_string(), request.start_us.to_string()));
    params.push((
        "count_end_us".to_string(),
        request.end_exclusive_us.to_string(),
    ));
    if let Some(source_filter) = request.source_filter {
        predicates.push(format!(
            "lower(toString({log_source})) = lower({{count_source:String}})"
        ));
        params.push(("count_source".to_string(), source_filter.to_string()));
    }
    for (index, source) in request.deny_source_types.iter().enumerate() {
        let name = format!("count_deny_source_{index}");
        predicates.push(format!(
            "lower(toString({log_source})) != lower({{{name}:String}})"
        ));
        params.push((name, source.clone()));
    }
    append_count_predicate(
        &mut predicates,
        &mut params,
        &group,
        request.predicate,
        "raw_count_predicate",
        request.multi_value,
    )?;
    let mut projections = Vec::new();
    let mut groupings = Vec::new();
    if let Some(span) = request.bucket_span_us {
        projections.push(format!(
            "intDiv(toUnixTimestamp64Micro({event_time}), {span}) * {span} AS bucket_start_us"
        ));
        groupings.push("bucket_start_us");
    }
    if request.group_by_source {
        projections.push(format!("{} AS value", count_source_group_expression(&log_source)));
        groupings.push("value");
    } else if request.group_results {
        // The count cube stores one canonical textual key for every scalar
        // field. Cast raw edge buckets and the hot tail to the same wire type
        // before merging, otherwise numeric OCSF IDs split into JSON number
        // and string groups at bucket boundaries.
        projections.push(format!("toString({group}) AS value"));
        groupings.push("value");
    } else {
        projections.push("CAST(NULL AS Nullable(String)) AS value".to_string());
    }
    let grouping = if groupings.is_empty() {
        String::new()
    } else {
        format!(" GROUP BY {}", groupings.join(", "))
    };
    let sql = harden_settings(
        format!(
            "SELECT {}, toUInt64(count()) AS events FROM {source} WHERE {}{grouping}",
            projections.join(", "),
            predicates.join(" AND "),
        ),
        tenant,
    )?;
    let query_sha256 = hex::encode(Sha256::digest(format!(
        "typed-count-v1\0{}\0{}\0{}{}",
        request.group_field,
        request.start_us,
        request.end_exclusive_us,
        if request.group_by_source { "\0by-source" } else { "" },
    )));
    Ok(Some(NativeQueryPlan {
        query_sha256,
        sql,
        params,
        budget,
        native_event_rows: false,
        temporary_aliases: BTreeSet::new(),
        schema_defaults: Vec::new(), reader: Default::default(),
    }))
}

pub fn append_count_predicate(
    predicates: &mut Vec<String>,
    params: &mut Vec<(String, String)>,
    value_sql: &str,
    predicate: Option<&CountPredicate>,
    parameter_prefix: &str,
    multi_value: bool,
) -> Result<()> {
    let Some(predicate) = predicate else {
        return Ok(());
    };
    if predicate.values.len() > 64
        || predicate
            .values
            .iter()
            .any(|value| value.len() > 2_048 || value.chars().any(char::is_control))
    {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "typed count predicate exceeds its value bound".to_string(),
        ));
    }
    let expected_values = match predicate.kind {
        CountPredicateKind::IsNull | CountPredicateKind::IsNotNull => 0,
        CountPredicateKind::In | CountPredicateKind::NotIn => {
            if predicate.values.is_empty() {
                return Err(QueryPlanError::InvalidCompilerOutput(
                    "typed count set predicate is empty".to_string(),
                ));
            }
            predicate.values.len()
        }
        _ => 1,
    };
    if predicate.values.len() != expected_values {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "typed count predicate has the wrong value cardinality".to_string(),
        ));
    }
    let parameter = |index: usize| format!("{parameter_prefix}_{index}");
    if multi_value && predicate.kind != CountPredicateKind::Eq {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "multi-value count predicates only support exact membership".to_string(),
        ));
    }
    let scalar_value = if multi_value { "item" } else { value_sql };
    // chDB 4.2 embeds ClickHouse without the lowerUTF8 alias. `lower` is the
    // engine-supported Unicode-aware lowercase function in this runtime and
    // matches the canonical lowercase normalization used by Nano's indexes.
    let lowered = format!("lower(toString({scalar_value}))");
    let expression = match predicate.kind {
        CountPredicateKind::Eq | CountPredicateKind::Ne => {
            let name = parameter(0);
            params.push((name.clone(), predicate.values[0].to_lowercase()));
            let operator = if predicate.kind == CountPredicateKind::Eq {
                "="
            } else {
                "!="
            };
            format!("{lowered} {operator} {{{name}:String}}")
        }
        CountPredicateKind::Contains | CountPredicateKind::NotContains => {
            let name = parameter(0);
            params.push((name.clone(), predicate.values[0].to_lowercase()));
            let operator = if predicate.kind == CountPredicateKind::Contains {
                "> 0"
            } else {
                "= 0"
            };
            format!("positionUTF8({lowered}, {{{name}:String}}) {operator}")
        }
        CountPredicateKind::Regex | CountPredicateKind::NotRegex => {
            let name = parameter(0);
            // Nano regex predicates are case-insensitive unless the pattern
            // already carries an explicit global flag. The broad nPL compiler
            // applies the same contract (including its prefix/suffix
            // rewrites); the typed count/rollup lane must not count a
            // different set merely because it bypasses that SQL generator.
            let pattern = if predicate.values[0].starts_with("(?i)") {
                predicate.values[0].clone()
            } else {
                format!("(?i){}", predicate.values[0])
            };
            params.push((name.clone(), pattern));
            let operator = if predicate.kind == CountPredicateKind::Regex {
                "= 1"
            } else {
                "= 0"
            };
            format!("match(toString({value_sql}), {{{name}:String}}) {operator}")
        }
        CountPredicateKind::StartsWith | CountPredicateKind::NotStartsWith => {
            let name = parameter(0);
            params.push((name.clone(), predicate.values[0].to_lowercase()));
            let operator = if predicate.kind == CountPredicateKind::StartsWith {
                "= 1"
            } else {
                "= 0"
            };
            format!("startsWith({lowered}, {{{name}:String}}) {operator}")
        }
        CountPredicateKind::EndsWith | CountPredicateKind::NotEndsWith => {
            let name = parameter(0);
            params.push((name.clone(), predicate.values[0].to_lowercase()));
            let operator = if predicate.kind == CountPredicateKind::EndsWith {
                "= 1"
            } else {
                "= 0"
            };
            format!("endsWith({lowered}, {{{name}:String}}) {operator}")
        }
        CountPredicateKind::In | CountPredicateKind::NotIn => {
            let mut names = Vec::with_capacity(predicate.values.len());
            for (index, value) in predicate.values.iter().enumerate() {
                let name = parameter(index);
                params.push((name.clone(), value.to_lowercase()));
                names.push(format!("{{{name}:String}}"));
            }
            let operator = if predicate.kind == CountPredicateKind::In {
                "IN"
            } else {
                "NOT IN"
            };
            format!("{lowered} {operator} ({})", names.join(", "))
        }
        CountPredicateKind::IsNull | CountPredicateKind::IsNotNull => {
            let operator = if predicate.kind == CountPredicateKind::IsNull {
                "isNull"
            } else {
                "isNotNull"
            };
            format!("{operator}({value_sql})")
        }
        CountPredicateKind::HostEq => {
            let value = predicate.values[0].to_lowercase();
            if value.is_empty() || value.contains('.') {
                return Err(QueryPlanError::InvalidCompilerOutput(
                    "host equality takes one dotless host name".to_string(),
                ));
            }
            let exact = parameter(0);
            let prefix = format!("{parameter_prefix}_prefix_0");
            params.push((exact.clone(), value.clone()));
            params.push((prefix.clone(), format!("{value}.")));
            format!("({lowered} = {{{exact}:String}} OR startsWith({lowered}, {{{prefix}:String}}))")
        }
        CountPredicateKind::CidrIn | CountPredicateKind::CidrNotIn => {
            let name = parameter(0);
            params.push((name.clone(), predicate.values[0].clone()));
            let operator = if predicate.kind == CountPredicateKind::CidrIn {
                "= 1"
            } else {
                "= 0"
            };
            format!("isIPAddressInRange(toString({value_sql}), {{{name}:String}}) {operator}")
        }
    };
    predicates.push(if multi_value {
        format!("arrayExists(item -> {expression}, {value_sql})")
    } else {
        expression
    });
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct SourceTimeFence<'a> {
    pub start: &'a str,
    pub end: &'a str,
    /// The newest chunk includes the analyst's exact upper bound. Older
    /// chunks use an exclusive upper bound so adjacent chunks never overlap.
    pub end_inclusive: bool,
    /// Locate-then-fetch: event times (in [`exact_fence_time`] form) a narrow
    /// locator proved hold the chunk's page. The full-width read keeps only
    /// rows at exactly these instants, so Parquet page statistics on `time`
    /// skip every other page. The complete predicate is still re-evaluated.
    pub exact_times: Option<&'a [String]>,
}

/// Most instants one exact time fence may name.
pub const MAX_EXACT_FENCE_TIMES: usize = 4_096;

/// The canonical form of an exact fence instant (`YYYY-MM-DD hh:mm:ss.ffffff`,
/// UTC), or `None` when `value` is not an RFC3339/ClickHouse timestamp.
pub fn exact_fence_time(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('Z');
    let parsed = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S%.f")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%.f"))
        .ok()?;
    Some(parsed.format("%Y-%m-%d %H:%M:%S%.6f").to_string())
}

fn exact_times_clause(fence: Option<SourceTimeFence<'_>>) -> &'static str {
    match fence.and_then(|fence| fence.exact_times) {
        Some(_) => " AND time IN {nano_chunk_times:Array(DateTime64(6, 'UTC'))}",
        None => "",
    }
}

fn exact_times_param(fence: SourceTimeFence<'_>) -> Option<(String, String)> {
    fence.exact_times.map(|times| {
        let values = times.iter().map(|time| format!("'{time}'")).collect::<Vec<_>>().join(",");
        ("nano_chunk_times".to_string(), format!("[{values}]"))
    })
}

#[derive(Clone, Copy, Debug)]
pub struct SourceCursorFence<'a> {
    pub time: &'a str,
    pub event_uid: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ObjectTimeWindow {
    start_ms: i64,
    end_ms: i64,
}

pub fn plan_broad_log_query(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    compiled: &CompiledQuery,
) -> Result<NativeQueryPlan> {
    plan_broad_log_query_with_candidates_and_tail(tenant, manifest, compiled, None, None)
}

/// Bind compiler-owned risk nPL to the generation-pinned findings aggregate.
/// The aggregate SQL and parameters are built by `RiskService`, never supplied
/// by an HTTP request.
pub fn plan_broad_risk_query(
    tenant: &TenantQueryConfig,
    compiled: &CompiledQuery,
    risk_source: &str,
    params: Vec<(String, String)>,
    risk_bytes: u64,
) -> Result<NativeQueryPlan> {
    const RISK_SOURCE_PLACEHOLDER: &str = "__nano_risk_source__";
    validate_tenant(tenant)?;
    if compiled.schema_version != 1
        || compiled.profile != "risk"
        || compiled.dataset != "risk"
        || compiled.source_placeholder != RISK_SOURCE_PLACEHOLDER
        || compiled.sql.matches(RISK_SOURCE_PLACEHOLDER).count() == 0
        || compiled.query_sha256.len() != 64
        || !compiled
            .query_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || contains_statement_separator(&compiled.sql)
        || !compiled.candidate_hints.is_empty()
        || risk_bytes == 0
        || risk_bytes > tenant.max_query_bytes
    {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "risk compiler identity, source binding, or byte fence failed".to_string(),
        ));
    }
    // Same read-only allow-list as the event path: a compiler defect must not
    // become table-function reach with the worker's credentials.
    reject_non_read_statement(&compiled.sql)?;
    let sql = compiled.sql.replace(RISK_SOURCE_PLACEHOLDER, risk_source);
    let sql = harden_settings(sql, tenant)?;
    // The trusted risk aggregate applies a parameterized per-entity clear
    // boundary. chDB's Parquet V3 PREWHERE optimizer can mistake that derived
    // expression for a physical file column. Risk snapshots are compact, so
    // fence both pushdown paths here just as the typed Risk route does; event
    // plans retain their normal Parquet pruning.
    let sql =
        format!("{sql}, input_format_parquet_filter_push_down=0, optimize_move_to_prewhere=0");
    Ok(NativeQueryPlan {
        query_sha256: compiled.query_sha256.clone(),
        sql,
        params,
        budget: QueryBudget {
            candidate_objects: 1,
            estimated_scan_bytes: risk_bytes,
            max_query_bytes: tenant.max_query_bytes,
        },
        native_event_rows: false,
        temporary_aliases: BTreeSet::new(),
        schema_defaults: Vec::new(), reader: Default::default(),
    })
}

/// Build the dedicated, typed event-expansion query. Request values are native
/// parameters; callers cannot smuggle nPL, SQL, or storage coordinates through
/// this route.
pub fn plan_fetch_log(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    request: &FetchLogPlanRequest<'_>,
) -> Result<NativeQueryPlan> {
    plan_fetch_log_inner(tenant, manifest, None, None, request)
}

pub fn plan_fetch_log_with_tail(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    tail: Option<&HotTailManifest>,
    candidates: Option<&[CandidateBlock]>,
    request: &FetchLogPlanRequest<'_>,
) -> Result<NativeQueryPlan> {
    plan_fetch_log_inner(tenant, manifest, tail, candidates, request)
}

fn plan_fetch_log_inner(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    tail: Option<&HotTailManifest>,
    candidates: Option<&[CandidateBlock]>,
    request: &FetchLogPlanRequest<'_>,
) -> Result<NativeQueryPlan> {
    if request.event_id.is_empty()
        || request.event_id.len() > 1_024
        || request.event_id.chars().any(char::is_control)
        || request.log_source.is_some_and(|source| {
            source.is_empty() || source.len() > 512 || source.chars().any(char::is_control)
        })
        || request
            .deny_source_types
            .iter()
            .any(|source| source.is_empty() || source.len() > 512)
        || request.start.is_some() != request.end.is_some()
    {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "fetch-log request violates its ID, source, scope, or time contract".to_string(),
        ));
    }
    let mut predicates = vec!["\"metadata.uid\" = {fetch_event_id:String}".to_string()];
    let mut params = vec![("fetch_event_id".to_string(), request.event_id.to_string())];
    if let Some(source) = request.log_source {
        predicates.push("\"metadata.log_source\" = {fetch_log_source:String}".to_string());
        params.push(("fetch_log_source".to_string(), source.to_string()));
    }
    for (index, source) in request.deny_source_types.iter().enumerate() {
        let parameter = format!("fetch_deny_source_{index}");
        predicates.push(format!(
            "lower(\"metadata.log_source\") != lower({{{parameter}:String}})"
        ));
        params.push((parameter, source.clone()));
    }
    let mut required_columns = vec![RequiredColumn {
        name: "metadata.uid".to_string(),
        field_type: "string".to_string(),
    }];
    if request.log_source.is_some() || !request.deny_source_types.is_empty() {
        required_columns.push(RequiredColumn {
            name: "metadata.log_source".to_string(),
            field_type: "string".to_string(),
        });
    }
    if let (Some(start), Some(end)) = (request.start, request.end) {
        let start_time = DateTime::parse_from_rfc3339(start).map_err(|_| {
            QueryPlanError::InvalidCompilerOutput(
                "fetch-log time range must be increasing RFC3339 timestamps".to_string(),
            )
        })?;
        let end_time = DateTime::parse_from_rfc3339(end).map_err(|_| {
            QueryPlanError::InvalidCompilerOutput(
                "fetch-log time range must be increasing RFC3339 timestamps".to_string(),
            )
        })?;
        if start_time >= end_time {
            return Err(QueryPlanError::InvalidCompilerOutput(
                "fetch-log time range must be increasing RFC3339 timestamps".to_string(),
            ));
        }
        predicates.push(
            "\"time\" BETWEEN parseDateTime64BestEffort({fetch_start:String}, 6, 'UTC') \
             AND parseDateTime64BestEffort({fetch_end:String}, 6, 'UTC')"
                .to_string(),
        );
        params.push(("fetch_start".to_string(), start.to_string()));
        params.push(("fetch_end".to_string(), end.to_string()));
        required_columns.push(RequiredColumn {
            name: "time".to_string(),
            field_type: "timestamp".to_string(),
        });
    }
    let binding = serde_json::to_vec(&(
        request.event_id,
        request.start,
        request.end,
        request.log_source,
        request.deny_source_types,
    ))
    .map_err(|error| {
        QueryPlanError::InvalidCompilerOutput(format!(
            "fetch-log binding cannot be hashed: {error}"
        ))
    })?;
    let compiled = CompiledQuery {
        stats_page: false,
        schema_version: 1,
        profile: "ocsf".to_string(),
        dataset: "logs".to_string(),
        source_placeholder: LOG_SOURCE_PLACEHOLDER.to_string(),
        query_sha256: hex::encode(Sha256::digest(binding)),
        start: request.start.unwrap_or_default().to_string(),
        end: request.end.unwrap_or_default().to_string(),
        limit: 1,
        table_view: false,
        newest_first_event_rows: false,
        candidate_hints: Vec::new(),
        required_columns,
        projected_scan_columns: Vec::new(),
        sql: format!(
            "SELECT * FROM {LOG_SOURCE_PLACEHOLDER} WHERE {} LIMIT 1 \
             SETTINGS enable_optimize_predicate_expression=0, max_threads={}, \
             max_execution_time={}",
            predicates.join(" AND "),
            tenant.threads,
            crate::query_timing::execution_seconds(tenant.max_execution_seconds)
        ),
    };
    let mut plan = plan_broad_log_query_with_candidates_and_tail(
        tenant, manifest, &compiled, candidates, tail,
    )?;
    plan.params.extend(params);
    Ok(plan)
}

pub fn plan_broad_log_query_with_candidates(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    compiled: &CompiledQuery,
    candidates: Option<&[CandidateBlock]>,
) -> Result<NativeQueryPlan> {
    plan_broad_log_query_with_candidates_and_tail(tenant, manifest, compiled, candidates, None)
}

pub fn plan_broad_log_query_with_candidates_and_tail(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    compiled: &CompiledQuery,
    candidates: Option<&[CandidateBlock]>,
    tail: Option<&HotTailManifest>,
) -> Result<NativeQueryPlan> {
    plan_broad_log_query_with_candidates_tail_time_and_budget(
        tenant,
        manifest,
        compiled,
        candidates,
        tail,
        None,
        None,
        BudgetEnforcement::Reject,
    )
}

/// Build a full-range plan for deciding whether a proven newest-first event
/// query must use progressive source windows. The returned SQL retains the
/// tenant's hard chDB `max_bytes_to_read` setting, but the planner reports an
/// over-budget range instead of rejecting it before the worker can split it.
/// Callers must never execute an over-budget plan directly.
pub fn plan_broad_log_query_for_progressive_decision(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    compiled: &CompiledQuery,
    candidates: Option<&[CandidateBlock]>,
    tail: Option<&HotTailManifest>,
) -> Result<NativeQueryPlan> {
    plan_broad_log_query_with_candidates_tail_time_and_budget(
        tenant,
        manifest,
        compiled,
        candidates,
        tail,
        None,
        None,
        BudgetEnforcement::ReportOnly,
    )
}

pub fn plan_broad_log_query_with_candidates_tail_and_time(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    compiled: &CompiledQuery,
    candidates: Option<&[CandidateBlock]>,
    tail: Option<&HotTailManifest>,
    time_fence: Option<SourceTimeFence<'_>>,
) -> Result<NativeQueryPlan> {
    plan_broad_log_query_with_candidates_tail_time_and_budget(
        tenant,
        manifest,
        compiled,
        candidates,
        tail,
        time_fence,
        None,
        BudgetEnforcement::Reject,
    )
}

pub fn plan_broad_log_query_with_candidates_tail_time_and_cursor(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    compiled: &CompiledQuery,
    candidates: Option<&[CandidateBlock]>,
    tail: Option<&HotTailManifest>,
    time_fence: Option<SourceTimeFence<'_>>,
    cursor_fence: SourceCursorFence<'_>,
) -> Result<NativeQueryPlan> {
    plan_broad_log_query_with_candidates_tail_time_and_budget(
        tenant,
        manifest,
        compiled,
        candidates,
        tail,
        time_fence,
        Some(cursor_fence),
        BudgetEnforcement::Reject,
    )
}

pub fn plan_broad_log_query_for_progressive_decision_with_cursor(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    compiled: &CompiledQuery,
    candidates: Option<&[CandidateBlock]>,
    tail: Option<&HotTailManifest>,
    cursor_fence: SourceCursorFence<'_>,
) -> Result<NativeQueryPlan> {
    plan_broad_log_query_with_candidates_tail_time_and_budget(
        tenant,
        manifest,
        compiled,
        candidates,
        tail,
        None,
        Some(cursor_fence),
        BudgetEnforcement::ReportOnly,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BudgetEnforcement {
    Reject,
    ReportOnly,
}

fn plan_broad_log_query_with_candidates_tail_time_and_budget(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    compiled: &CompiledQuery,
    candidates: Option<&[CandidateBlock]>,
    tail: Option<&HotTailManifest>,
    time_fence: Option<SourceTimeFence<'_>>,
    cursor_fence: Option<SourceCursorFence<'_>>,
    budget_enforcement: BudgetEnforcement,
) -> Result<NativeQueryPlan> {
    validate_tenant(tenant)?;
    let (mut available_paths, full_budget) = validate_manifest(tenant, manifest)?;
    let source_tenant = tenant_with_tail_read_contract(tenant, tail, &mut available_paths)?;
    validate_compiler_output(compiled)?;
    if let Some(fence) = time_fence {
        validate_source_time_fence(compiled, fence)?;
    }
    if let Some(cursor) = cursor_fence {
        validate_source_cursor_fence(compiled, cursor)?;
    }
    let object_time_window = effective_object_time_window(compiled, time_fence, cursor_fence)?;
    let required = required_columns(compiled)?;
    if cursor_fence.is_some()
        && (!required.contains_key("time") || !required.contains_key("metadata.uid"))
    {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "cursor-paged query must project time and metadata.uid".to_string(),
        ));
    }
    if compiled
        .projected_scan_columns
        .iter()
        .any(|column| validate_path(column).is_err() || !required.contains_key(column))
    {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "projected scan column is invalid or absent from the typed projection".to_string(),
        ));
    }
    let native_event_rows = preserves_full_event_shape(&compiled.sql);
    let projected_columns = (!native_event_rows && !compiled.projected_scan_columns.is_empty())
        .then(|| {
            compiled
                .projected_scan_columns
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        });
    // Leaves a statement reads, for its scan estimate (`None`: every leaf).
    // NAN-3159: a transforming statement reads the compiler's scan columns
    // (chDB prunes a stage's unused selections), not its whole projection.
    // An event-row page also reads the columns it returns.
    let budget_columns = projected_columns.clone().filter(|_| !compiled.newest_first_event_rows)
        .or_else(|| (!native_event_rows || compiled.table_view)
        .then(|| required.keys().filter(|name| !is_row_identity_column(name)).cloned().collect::<BTreeSet<_>>()));
    let full_budget = time_scoped_manifest_budget(
        tenant,
        manifest,
        full_budget,
        object_time_window,
        projected_columns.as_ref(),
        // Admit only after combining the pruned base and tail estimates.
        BudgetEnforcement::ReportOnly,
    )?;
    let missing = required
        .iter()
        .filter(|(name, _)| !available_paths.contains(name.as_str()) && !is_row_identity_column(name))
        .map(|(name, field_type)| (name.clone(), field_type.clone()))
        .collect::<BTreeMap<_, _>>();
    // NAN-2374: a transforming query reads through a leaf projection. That
    // projection must be the FIRST select over the object-storage table
    // function, never a second select stacked on a `SELECT *` wrapper.
    //
    // WHY. When a `SELECT *` layer sits between the Parquet read and the leaf
    // extraction, ClickHouse's filter merge + move-to-prewhere rewrites a
    // pushed-down predicate back onto the *storage* column
    // (`getSubcolumn(http_request, 'url.url_string')`) while the read step's
    // header still carries only the parent struct, and execution dies with
    // NOT_FOUND_COLUMN_IN_BLOCK. It needs a nested-subcolumn predicate that is
    // referenced from more than one filter stage, so any pipeline that repeats
    // a nested field across an `OR` and a later `where` hits it.
    //
    // Fusing the leaf projection into the read select keeps the predicate and
    // the column it names in the same plan step, and reads strictly fewer
    // columns than the wrapper form did: measured byte-identical to a
    // hand-written direct query (26,336,313 bytes) where the merge-filter
    // workaround read 59,643,344.
    // The compiler's table view is a flat 25-column SELECT, not SELECT *.
    let page_clause = table_view_page_clause(compiled);
    let page_roots = page_clause.as_ref().map(|_| {
        let mut roots = roots_for_paths(required.keys().map(String::as_str))?;
        let available_roots = roots_for_available_paths(available_paths.iter().map(String::as_str));
        roots.retain(|root| available_roots.contains(root));
        roots.insert("time".into());
        roots.iter().map(|root| quoted_identifier(root)).collect::<Result<Vec<_>>>()
            .map(|roots| roots.join(", "))
    }).transpose()?;
    let leaf_projection = if let Some(roots) = &page_roots {
        Some(roots.clone())
    } else if native_event_rows {
        // Table-view output, filters and ordering are compiler-owned. Use the
        // same minimal roots even in an empty candidate arm; the tail's read
        // schema supplies their types and Parquet default-fills absent roots.
        // Full-event output still needs every physical root it returns.
        if compiled.table_view {
            Some(required_root_projection(&required, &available_paths)?)
        } else if tail.is_some_and(|tail| !tail.objects.is_empty() && tail.read_schema.is_some()) {
            Some(root_projection_for_paths(available_paths.iter().map(String::as_str))?)
        } else {
            None
        }
    } else {
        Some(projected_columns_sql(&required, &missing)?)
    };
    let (source, base_params, base_overlap) =
        base_snapshot_source_for_window(&source_tenant, object_time_window)?;
    let scoped_candidates = candidates.map(|candidates| {
        candidates
            .iter()
            .filter(|candidate| {
                object_time_window.is_none_or(|window| {
                    object_path_overlaps_window(&candidate.event_object_key, window)
                })
            })
            .cloned()
            .collect::<Vec<_>>()
    });
    let (source, candidate_params, budget, source_is_path_fenced) =
        match scoped_candidates.as_deref() {
            Some(candidates) => {
                let (source, params, budget) = candidate_source(
                    &source_tenant,
                    manifest,
                    candidates,
                    BudgetEnforcement::ReportOnly,
                    leaf_projection.as_deref(),
                )?;
                (source, params, budget, true)
            }
            None => (source, base_params, full_budget, false),
        };
    // NAN-3789: the selection kept a strict subset of some file's rows, so
    // the source carries a `_row_number` row fence (see [`row_fence`]).
    let source_is_row_fenced = source_is_path_fenced && source.contains("_row_number");
    // NAN-3155: a part selection records, per file, the bytes of each leaf in
    // the row groups it keeps. Charge the leaves this statement reads, not
    // whole files. NAN-3159: full-event rows read every leaf, but only in
    // the kept row groups (never the footer, blooms or page index).
    let budget = {
        let keys = match scoped_candidates.as_deref() {
            Some(candidates) => candidates.iter().map(|block| block.event_object_key.as_str()).collect::<BTreeSet<_>>(),
            None => manifest.objects.iter()
                .filter(|object| object_time_window.is_none_or(|window| object_path_overlaps_window(&object.event_object_key, window)))
                .map(|object| object.event_object_key.as_str()).collect(),
        };
        let estimate = manifest.objects.iter()
            .filter(|object| keys.contains(object.event_object_key.as_str()))
            .try_fold(0_u64, |sum, object| {
                let charged = match budget_columns.as_ref() {
                    Some(columns) => projected_object_bytes(object, columns),
                    None => all_leaf_object_bytes(object),
                };
                sum.checked_add(charged.unwrap_or(object.event_object_bytes))
            });
        match estimate {
            // Each object's charge is capped at its file size, so this never
            // exceeds the whole-file estimate it replaces (no new refusals).
            Some(estimated_scan_bytes) if !keys.is_empty() => QueryBudget { estimated_scan_bytes, ..budget },
            _ => budget,
        }
    };
    let guarded_base = if source_is_path_fenced {
        source
    } else {
        let guard = base_window_guard(base_overlap);
        let projection = leaf_projection.as_deref().unwrap_or("*");
        format!("(SELECT {projection} FROM {source} WHERE {guard})")
    };
    let bound_page = |source: String| -> Result<String> {
        match (&page_clause, &page_roots) {
            (Some(clause), Some(roots)) => {
                // Fences must precede top-K or a progressive/cursor page can
                // discard qualifying rows behind an out-of-window prefix.
                let mut fences = Vec::new();
                if let Some(fence) = time_fence {
                    let end_operator = if fence.end_inclusive { "<=" } else { "<" };
                    fences.push(format!("time >= parseDateTime64BestEffort({{nano_chunk_start:String}}, 6, 'UTC') AND time {end_operator} parseDateTime64BestEffort({{nano_chunk_end:String}}, 6, 'UTC'){}", exact_times_clause(Some(fence))));
                }
                if cursor_fence.is_some() {
                    let uid = if let Some(kind) = missing.get("metadata.uid") {
                        missing_expression("metadata.uid", kind)?.to_string()
                    } else {
                        nested_expression("metadata.uid")?
                    };
                    fences.push(format!("(time < parseDateTime64BestEffort({{nano_cursor_time:String}}, 6, 'UTC') OR (time = parseDateTime64BestEffort({{nano_cursor_time:String}}, 6, 'UTC') AND toString({uid}) < {{nano_cursor_event_uid:String}}))"));
                }
                let source = if fences.is_empty() { source } else {
                    format!("(SELECT * FROM {source} WHERE {})", fences.join(" AND "))
                };
                let (source, aliases) = native_event_source(clause, &source, &required, &missing)?;
                let mut clause = clause.clone();
                for (name, alias) in aliases {
                    clause = clause.replace(&double_quoted_identifier(&name), &alias);
                    clause = clause.replace(&quoted_identifier(&name)?, &alias);
                }
                Ok(format!("(SELECT {roots} FROM {source} {clause})"))
            }
            _ => Ok(source),
        }
    };
    let guarded_base = bound_page(guarded_base)?;
    let mut tail_objects_considered = 0;
    let (guarded_source, tail_params, tail_budget, source_is_projected) = match tail {
        Some(tail) if !tail.objects.is_empty() => {
            let base_paths = manifest
                .objects
                .iter()
                .map(|object| object.event_object_key.as_str())
                .collect::<BTreeSet<_>>();
            if tail
                .objects
                .iter()
                .any(|object| base_paths.contains(object.source_uri.as_str()))
            {
                return Err(QueryPlanError::InvalidManifest(
                    "hot tail overlaps the fully indexed generation".to_string(),
                ));
            }
            let mut scoped_tail = tail.clone();
            if let Some(window) = object_time_window {
                retain_hot_tail_objects(&mut scoped_tail, |object| {
                    hot_tail_object_overlaps_window(object, window)
                })?;
            }
            crate::tail_predicate::prune(&mut scoped_tail, &compiled.candidate_hints);
            tail_objects_considered = scoped_tail.objects.len();
            if scoped_tail.objects.is_empty() {
                (guarded_base, Vec::new(), None, leaf_projection.is_some())
            } else {
                // A staged object is encoded against the Iceberg schema
                // current at its publication time. During additive schema
                // evolution, adjacent exact objects can therefore have a
                // different physical column count. Project every exact object
                // before UNION, rather than wrapping an already-invalid
                // `SELECT *` union. Use top-level roots here so the repeated
                // exact-object SQL remains bounded; the normal outer
                // projection still narrows transforming queries to their
                // compiler-owned leaf contract.
                // A transforming query unions two arms that each already
                // carry the compiler-owned leaf contract, emitted in the same
                // deterministic order by `projected_columns_sql`. Projecting
                // roots here and re-extracting the leaves above the union is
                // what stacked a `SELECT *` between the Parquet read and the
                // leaf, and NAN-2374 died on exactly that shape.
                let projection = match leaf_projection.as_deref() {
                    Some(leaf) => leaf.to_string(),
                    None if scoped_tail.read_schema.is_some() => root_projection_for_paths(
                        scoped_tail.available_paths.iter().map(String::as_str),
                    )?,
                    // A bootstrap generation has no object to derive roots
                    // from; only a tail carrying its read contract (every
                    // schema-2+ staged tail does) can name the projection.
                    None if manifest.objects.is_empty() => {
                        return Err(QueryPlanError::InvalidManifest(
                            "bootstrap generation requires a hot-tail read contract".to_string(),
                        ));
                    }
                    None => generation_root_projection(manifest, scoped_candidates.as_deref())?,
                };
                let (tail_source, params, budget) = hot_tail_source(
                    &source_tenant,
                    &scoped_tail,
                    BudgetEnforcement::ReportOnly,
                    &projection,
                )?;
                let tail_source = bound_page(tail_source)?;
                let base = if leaf_projection.is_some() {
                    guarded_base
                } else {
                    projected_source_sql(&guarded_base, &projection)
                };
                (
                    format!("(SELECT * FROM {base} UNION ALL SELECT * FROM {tail_source})"),
                    params,
                    Some(budget),
                    native_event_rows || leaf_projection.is_some(),
                )
            }
        }
        _ => (guarded_base, Vec::new(), None, leaf_projection.is_some()),
    };
    let guarded_source = if page_clause.is_some() {
        // Keep the raw root scan and its producer predicate pushdown; the
        // displayed leaves are projected after each arm's top-K.
        let projection = required.keys().map(|name| {
            let quoted = quoted_identifier(name)?;
            let expression = if let Some(kind) = missing.get(name) {
                missing_expression(name, kind)?.to_string()
            } else if name.starts_with("src_endpoint.") || name.starts_with("dst_endpoint.") {
                nested_expression(name)?
            } else {
                nested_projection(name)?
            };
            Ok(format!("{expression} AS {quoted}"))
        }).collect::<Result<Vec<_>>>()?.join(", ");
        projected_source_sql(&guarded_source, &projection)
    } else {
        guarded_source
    };
    let (guarded_source, time_params) = if let Some(fence) = time_fence {
        let end_operator = if fence.end_inclusive { "<=" } else { "<" };
        (
            format!(
                "(SELECT * FROM {guarded_source} WHERE \"time\" >= \
                 parseDateTime64BestEffort({{nano_chunk_start:String}}, 6, 'UTC') AND \
                 \"time\" {end_operator} parseDateTime64BestEffort({{nano_chunk_end:String}}, 6, 'UTC'){})",
                exact_times_clause(Some(fence))
            ),
            [
                ("nano_chunk_start".to_string(), fence.start.to_string()),
                ("nano_chunk_end".to_string(), fence.end.to_string()),
            ]
            .into_iter()
            .chain(exact_times_param(fence))
            .collect(),
        )
    } else {
        (guarded_source, Vec::new())
    };
    let budget = if let Some(tail_budget) = tail_budget {
        let estimated_scan_bytes = budget
            .estimated_scan_bytes
            .checked_add(tail_budget.estimated_scan_bytes)
            .ok_or_else(|| {
                QueryPlanError::InvalidManifest("combined source byte total overflowed".to_string())
            })?;
        QueryBudget {
            candidate_objects: budget
                .candidate_objects
                .checked_add(tail_budget.candidate_objects)
                .ok_or_else(|| {
                    QueryPlanError::InvalidManifest(
                        "combined source object count overflowed".to_string(),
                    )
                })?,
            estimated_scan_bytes,
            max_query_bytes: tenant.max_query_bytes,
        }
    } else {
        budget
    };
    crate::query_timing::record(|p| {
        p.budget_bytes = Some(tenant.max_query_bytes);
        p.estimated_bytes = Some(budget.estimated_scan_bytes);
        p.tail_objects_considered = tail_objects_considered;
    });
    if budget_enforcement == BudgetEnforcement::Reject
        && budget.estimated_scan_bytes > tenant.max_query_bytes
    {
        return Err(QueryPlanError::BudgetRejected {
            estimated_bytes: budget.estimated_scan_bytes,
            max_bytes: tenant.max_query_bytes,
        });
    }
    let (mut replacement, aliases) = if native_event_rows {
        native_event_source(&compiled.sql, &guarded_source, &required, &missing)?
    } else if source_is_projected {
        (guarded_source, BTreeMap::new())
    } else {
        (
            projected_source(&guarded_source, &required, &missing)?,
            BTreeMap::new(),
        )
    };
    let mut cursor_params = Vec::new();
    if let Some(cursor) = cursor_fence {
        replacement = format!(
            "(SELECT * FROM {replacement} WHERE \"time\" < \
             parseDateTime64BestEffort({{nano_cursor_time:String}}, 6, 'UTC') OR \
             (\"time\" = parseDateTime64BestEffort({{nano_cursor_time:String}}, 6, 'UTC') \
             AND toString(\"metadata.uid\") < {{nano_cursor_event_uid:String}}))"
        );
        cursor_params.push(("nano_cursor_time".to_string(), cursor.time.to_string()));
        cursor_params.push((
            "nano_cursor_event_uid".to_string(),
            cursor.event_uid.to_string(),
        ));
    }
    let mut sql = compiled.sql.clone();
    for (name, alias) in &aliases {
        sql = sql.replace(&double_quoted_identifier(name), alias);
        sql = sql.replace(&quoted_identifier(name)?, alias);
    }
    // Rewrite analyst-facing column references before inserting the trusted
    // source. Otherwise a physical expression such as `time AS
    // __nano_path_2` can be rewritten into a self-reference.
    sql = sql.replace(LOG_SOURCE_PLACEHOLDER, &replacement);
    for name in missing.keys() {
        if let Some(tail) = typed_tail_sql_path(name)? {
            sql = sql.replace(&tail, &quoted_identifier(name)?);
        }
    }
    sql = harden_settings(sql, tenant)?;
    if native_event_rows && !compiled.table_view {
        sql = bounded_payload_settings(sql, tenant.threads, tenant.max_memory_bytes);
    }
    if source_is_row_fenced && text_after_fence_enabled() && tests_wide_text(&compiled.sql) {
        sql = crate::executor::with_setting(&sql, TEXT_AFTER_FENCE_SETTING);
    }

    let mut params = object_store_params(tenant);
    params.extend(candidate_params);
    params.extend(tail_params);
    params.extend(time_params);
    params.extend(cursor_params);
    // A compiler-proven producer-only table page reads exactly these roots.
    // Avoid making chDB analyze every unrelated root in a wide OCSF schema.
    // Keep whole Tuple/Array types so subcolumn typing and masks are unchanged.
    #[cfg(feature = "part-lab")]
    let prune_page_schema = std::env::var("BENCH_BASELINE_PARENT_OVERHEAD").as_deref() != Ok("1");
    #[cfg(not(feature = "part-lab"))]
    let prune_page_schema = true;
    // Transforming queries and table views read compiler-owned roots. Keep
    // whole physical tuples and mask dependencies, but do not make COUNT,
    // histograms or grouped stats analyze unrelated roots in the union schema.
    // Full-event output still requires every returned physical root.
    let narrow_aggregates = crate::perf_overrides::probe_flag("narrow_aggregate_schema",
        std::env::var("NANO_LAKE_NARROW_AGGREGATE_SCHEMA").is_ok_and(|value| value == "1"));
    // NAN-3155: both statements of a two-pass row query (they name the
    // virtual row identity) read compiler-owned leaves only.
    let two_pass_statement = required.keys().any(|name| is_row_identity_column(name));
    let table_read_roots = if (native_event_rows && compiled.table_view) || (!native_event_rows && (narrow_aggregates || two_pass_statement)) {
        Some(required_read_roots(&required, &available_paths)?.iter()
            .map(|root| quoted_identifier(root)).collect::<Result<Vec<_>>>()?.join(", "))
    } else { None };
    if let Some(projection) = page_roots.as_ref().or(table_read_roots.as_ref()).filter(|_| prune_page_schema) {
        for (name, schema) in &mut params {
            if name.ends_with("_read_schema") {
                if let Some(projected) = page_read_schema(schema, projection) {
                    // NAN-3155: and within each read root, only the leaves
                    // the statement names (the page path used to decode
                    // every leaf of `device`, `metadata`, `actor`, ...).
                    *schema = leaf_read_schema(&projected, &required).unwrap_or(projected);
                }
            }
        }
    }
    // NAN-3386 (A/B switch, default off): read entity filter leaves as flat
    // top-level Parquet columns so chDB can PREWHERE them. See
    // [`flat_scalar_leaves`]. A table-view page reads whole roots in its
    // `file()` select; its only leaf projection sits above the page bound,
    // where a flat read buys no PREWHERE, so it is left as is.
    if flat_filter_leaves_enabled() && page_clause.is_none() {
        if let Some(flat) = flat_scalar_leaves(&sql, &mut params, &required) {
            sql = flat;
        }
    }
    Ok(NativeQueryPlan {
        query_sha256: compiled.query_sha256.clone(),
        sql,
        params,
        budget,
        native_event_rows,
        temporary_aliases: aliases.into_values().collect(),
        schema_defaults: missing.into_keys().collect(),
        // A full-event payload is already reader-bounded above.
        reader: if native_event_rows && !compiled.table_view {
            ReaderShape { wide_columns: 0, ..reader_shape(compiled, manifest, candidates) }
        } else {
            reader_shape(compiled, manifest, candidates)
        },
    })
}

/// NAN-3411: the payload statement's floor reader threads (NAN-3077's
/// value; what a role of three cores or less still gets, see
/// [`payload_role_defaults`]).
pub const PAYLOAD_DEFAULT_THREADS: u64 = 1;
/// NAN-3411: the payload statement's floor block rows (NAN-3077's value;
/// a statement capped below [`PAYLOAD_ROLE_ROWS_MIN_MEMORY_BYTES`] keeps it).
pub const PAYLOAD_DEFAULT_BLOCK_ROWS: u64 = 128;
/// NAN-4694: the role-derived block rows of a payload statement with at
/// least [`PAYLOAD_ROLE_ROWS_MIN_MEMORY_BYTES`]. Measured: 512 cut a broad
/// regex payload scan 44% and left needle hunts flat; 1024 and 8192 cost
/// needle hunts 27-32%.
pub const PAYLOAD_ROLE_BLOCK_ROWS: u64 = 512;
/// NAN-4694: the per-statement memory from which a payload statement takes
/// [`PAYLOAD_ROLE_BLOCK_ROWS`] (query[T]'s small-lane statement cap).
pub const PAYLOAD_ROLE_ROWS_MIN_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
/// NAN-4694: per-statement memory set aside per payload reader thread: two
/// of its 32 MiB Parquet watermarks, so the threads a statement's cap can
/// hold never outgrow it.
pub const PAYLOAD_READER_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
/// NAN-3411: the most block rows a payload knob may ask for (the small
/// lanes' bounded wide-text reader's block, `lanes::bounded_reader_sql`).
pub const PAYLOAD_MAX_BLOCK_ROWS: u64 = 8_192;
/// NAN-3411 cell env: the payload statement's reader threads (unset: 1).
pub const PAYLOAD_MAX_THREADS_ENV: &str = "NANO_LAKE_PAYLOAD_MAX_THREADS";
/// NAN-3411 cell env: the payload statement's block rows (unset: 128).
pub const PAYLOAD_BLOCK_ROWS_ENV: &str = "NANO_LAKE_PAYLOAD_BLOCK_ROWS";

fn positive_env(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|value| value.trim().parse::<u64>().ok()).filter(|value| *value > 0)
}

/// `NANO_LAKE_PAYLOAD_MAX_THREADS` (a positive integer, else unset).
pub(crate) fn payload_max_threads_env() -> Option<u64> {
    positive_env(PAYLOAD_MAX_THREADS_ENV)
}

/// `NANO_LAKE_PAYLOAD_BLOCK_ROWS` (a positive integer, else unset).
pub(crate) fn payload_block_rows_env() -> Option<u64> {
    positive_env(PAYLOAD_BLOCK_ROWS_ENV)
}

/// NAN-4694 / NAN-4751: the payload statement's `(threads, block rows)`
/// derived from the query role for an analyst's statement: the role's whole
/// thread budget (`tenant_threads`, the role's cores; the process thread
/// budget then lowers it to the statement's share at start), at most one
/// thread per [`PAYLOAD_READER_MEMORY_BYTES`] of the statement's memory cap;
/// 512-row blocks from a 256 MiB cap. A statement capped under 256 MiB keeps
/// NAN-3077's 128-row blocks.
///
/// NAN-4751 lifted the threads from half the role (at most the 4-thread
/// interactive cap): the bakeoff ran 352 one-thread payload statements.
/// Block rows stay at NAN-4694's measured 512 (1024 and 8192 cost needle
/// hunts 27-32%).
pub fn payload_role_defaults(tenant_threads: u64, max_memory_bytes: u64) -> (u64, u64) {
    let by_memory = (max_memory_bytes / PAYLOAD_READER_MEMORY_BYTES).max(1);
    (tenant_threads.max(1).min(by_memory), payload_role_rows(max_memory_bytes))
}

/// NAN-4751: [`payload_role_defaults`] for an agent-class statement
/// (NAN-4738), unchanged from NAN-4694: half the role, at most the 4-thread
/// interactive cap; a role of three cores or less keeps one reader thread.
/// Agents never take the analysts' lifted payload threads.
pub fn payload_agent_role_defaults(tenant_threads: u64, max_memory_bytes: u64) -> (u64, u64) {
    let by_memory = (max_memory_bytes / PAYLOAD_READER_MEMORY_BYTES).max(1);
    let threads = (tenant_threads / 2)
        .clamp(PAYLOAD_DEFAULT_THREADS, crate::part_query::lanes::INTERACTIVE_MAX_THREADS)
        .min(by_memory);
    (threads, payload_role_rows(max_memory_bytes))
}

fn payload_role_rows(max_memory_bytes: u64) -> u64 {
    if max_memory_bytes >= PAYLOAD_ROLE_ROWS_MIN_MEMORY_BYTES {
        PAYLOAD_ROLE_BLOCK_ROWS
    } else {
        PAYLOAD_DEFAULT_BLOCK_ROWS
    }
}

/// NAN-3411: the payload statement's effective `(threads, block rows)`
/// from the requested values (override else env; `None`: the role-derived
/// [`payload_role_defaults`], NAN-4694) for an analyst's statement. Threads
/// are clamped to `1..=tenant_threads` (NAN-4751: the role's thread grant;
/// the process thread budget lowers a statement to its share), rows to
/// `128..=8192`. Neither touches a memory bound: the reader watermark
/// (32 MiB per reader), the 1 MiB preferred block bytes, the 64 MiB sort
/// spill and the statement's lane cap stay, and a memory refusal escalates
/// lanes as before.
pub fn payload_read_settings(
    threads: Option<u64>,
    block_rows: Option<u64>,
    tenant_threads: u64,
    max_memory_bytes: u64,
) -> (u64, u64) {
    payload_read_settings_for(threads, block_rows, tenant_threads, max_memory_bytes, false)
}

/// [`payload_read_settings`] for a statement of the given class. An agent
/// statement (`agent`) keeps NAN-4694's settings: its role defaults are
/// [`payload_agent_role_defaults`] and its threads stay clamped to
/// `1..=min(4, tenant_threads)`.
pub fn payload_read_settings_for(
    threads: Option<u64>,
    block_rows: Option<u64>,
    tenant_threads: u64,
    max_memory_bytes: u64,
    agent: bool,
) -> (u64, u64) {
    let (max_threads, (role_threads, role_rows)) = if agent {
        (
            crate::part_query::lanes::INTERACTIVE_MAX_THREADS.min(tenant_threads.max(1)),
            payload_agent_role_defaults(tenant_threads, max_memory_bytes),
        )
    } else {
        (tenant_threads.max(1), payload_role_defaults(tenant_threads, max_memory_bytes))
    };
    (
        threads.unwrap_or(role_threads).clamp(1, max_threads),
        block_rows.unwrap_or(role_rows).clamp(PAYLOAD_DEFAULT_BLOCK_ROWS, PAYLOAD_MAX_BLOCK_ROWS),
    )
}

/// Bound full-event materialization before the first native execution.
/// Narrow table pages, locators and aggregates retain their normal settings.
/// Keep top-K remerge enabled even when a wide block reduces by less than 2x.
/// This changes no memory ceiling and introduces no failure/retry cycle.
///
/// NAN-3411: reader threads and block rows come from
/// `NANO_LAKE_PAYLOAD_MAX_THREADS` / `NANO_LAKE_PAYLOAD_BLOCK_ROWS` or this
/// request's `payload_threads` / `payload_block_rows` override, clamped by
/// [`payload_read_settings`]; with neither, from the role (`threads`, the
/// tenant's thread budget, and `max_memory_bytes`, its statement cap; see
/// [`payload_role_defaults`]).
pub fn bounded_payload_settings(sql: String, threads: u64, max_memory_bytes: u64) -> String {
    let (requested_threads, requested_rows) =
        crate::perf_overrides::payload_read(payload_max_threads_env(), payload_block_rows_env());
    // NAN-4751: an agent statement (NAN-4738) keeps NAN-4694's settings.
    let agent = crate::thread_budget::Priority::current() == crate::thread_budget::Priority::Agent;
    let (threads, rows) = payload_read_settings_for(requested_threads, requested_rows, threads, max_memory_bytes, agent);
    bounded_payload_settings_with(sql, threads, rows)
}

/// [`bounded_payload_settings`] at explicit (already clamped) values.
fn bounded_payload_settings_with(mut sql: String, threads: u64, rows: u64) -> String {
    static SETTINGS: OnceLock<[Regex; 9]> = OnceLock::new();
    const NAMES: [&str; 9] = [
        "max_threads", "max_block_size", "preferred_block_size_bytes",
        "input_format_parquet_max_block_size", "input_format_parquet_prefer_block_bytes",
        "input_format_parquet_memory_high_watermark", "max_bytes_before_external_sort",
        "max_bytes_before_remerge_sort", "remerge_sort_lowered_memory_bytes_ratio",
    ];
    let patterns = SETTINGS.get_or_init(|| NAMES.map(|name| {
        Regex::new(&format!(r"\b{name}\s*=\s*\d+\b")).expect("static setting regex")
    }));
    let values = [threads, rows, 1_048_576, rows, 1_048_576, 33_554_432, 67_108_864, 1_048_576, 0];
    for ((name, pattern), value) in NAMES.iter().zip(patterns).zip(values) {
        let setting = format!("{name}={value}");
        if let Some(clause) = crate::executor::statement_settings(&sql) {
            if pattern.is_match(clause) {
                let start = sql.len() - clause.len();
                sql = format!("{}{}", &sql[..start], pattern.replace_all(clause, setting.as_str()));
                continue;
            }
        }
        sql = crate::executor::with_setting(&sql, &setting);
    }
    // Disable the native sort ratio guard so the explicit spill bound
    // takes effect independently of the process-wide available memory.
    crate::executor::with_setting(&sql, "max_bytes_ratio_before_external_sort=0")
}

/// Restrict the canonical writer's schema to quoted top-level page roots.
/// Unknown syntax falls back to the original schema. Never prune tuple leaves:
/// the full physical root type is needed for nested expressions and masks.
fn page_read_schema(schema: &str, projection: &str) -> Option<String> {
    let roots = projection.split(", ").map(|root| {
        root.strip_prefix('`')?.strip_suffix('`')
    }).collect::<Option<BTreeSet<_>>>()?;
    let mut depth = 0_usize;
    let mut quote = None;
    let mut escaped = false;
    let mut start = 0;
    let mut fields = Vec::new();
    for (offset, ch) in schema.char_indices() {
        if escaped { escaped = false; continue; }
        if let Some(delimiter) = quote {
            if ch == '\\' { escaped = true; }
            else if ch == delimiter { quote = None; }
            continue;
        }
        match ch {
            '\'' | '`' | '"' => quote = Some(ch),
            '(' => depth = depth.checked_add(1)?,
            ')' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                fields.push(schema[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
    }
    if quote.is_some() || escaped || depth != 0 { return None; }
    fields.push(schema[start..].trim());
    let mut selected = Vec::new();
    let mut found = BTreeSet::new();
    for field in fields {
        let (name, ty) = field.strip_prefix('`')?.split_once('`')?;
        if !ty.starts_with(' ') || ty.trim().is_empty() { return None; }
        if roots.contains(name) {
            if !found.insert(name) { return None; }
            selected.push(field);
        }
    }
    (found == roots && !selected.is_empty()).then(|| selected.join(", "))
}

/// `NANO_LAKE_FLAT_FILTER_LEAVES=1` turns on [`flat_scalar_leaves`] for this
/// process (NAN-3386 live A/B; default off, read per plan like
/// `NANO_LAKE_NARROW_AGGREGATE_SCHEMA`).
pub(crate) fn flat_filter_leaves_env() -> bool {
    std::env::var("NANO_LAKE_FLAT_FILTER_LEAVES").is_ok_and(|value| value == "1")
}

/// [`flat_filter_leaves_env`], or this request's `flat_filter_leaves`
/// override (NAN-3406, see [`crate::perf_overrides`]).
pub(crate) fn flat_filter_leaves_enabled() -> bool {
    crate::perf_overrides::flat_filter_leaves(flat_filter_leaves_env())
}

/// NAN-3386: chDB 26.7 rejects a Tuple subcolumn in a `file()` PREWHERE
/// ("does not support column device.hostname in PREWHERE"), so an entity
/// equality over `` `device`.`hostname` `` never becomes a PREWHERE: every
/// projected column of every kept row group is decoded for every row, and
/// the WHERE drops ~all of them afterwards. The same leaf named as a flat
/// dotted column in the explicit read schema (`` `device.hostname` Nullable(String) ``)
/// is a top-level Parquet column, `optimize_move_to_prewhere` moves the
/// equality into PREWHERE, and the v3 reader decodes the other columns
/// only for passing rows. Measured on the real load-test tenant hour parts with the
/// lake-cell libchdb (live statement shape, identical results): rows out of
/// storage 3.55M -> 552; stats CPU -24 to -36%; a `raw_data` row shape 3.3x
/// less CPU and no longer exceeds the 256 MiB small lane.
///
/// Additive: each `*_read_schema` that types the leaf as a scalar under
/// Tuple-only ancestors gets a flat sibling entry; the Tuple root stays, so
/// every other expression binds unchanged. Only the exact leaf projection
/// `` `a`.`b` AS `a.b` `` is rewritten to `` `a.b` AS `a.b` ``. Declines (`None`,
/// plan unchanged) when any Parquet source lacks an explicit read schema, or
/// when schemas disagree on the leaf's type. Array/map leaves are never
/// flattened.
fn flat_scalar_leaves(
    sql: &str,
    params: &mut [(String, String)],
    required: &BTreeMap<String, String>,
) -> Option<String> {
    // Every file() source must carry an explicit read schema; a flat dotted
    // name means a subcolumn under schema inference.
    if !sql.contains("file({") || sql.contains(", Parquet)") || sql.contains("iceberg") {
        return None;
    }
    // A `SELECT *` straight over a storage function would return the appended
    // flat sibling as an extra output column. No planned shape pairs one with
    // a leaf projection today; decline rather than depend on that.
    static STAR_OVER_STORAGE: OnceLock<Regex> = OnceLock::new();
    if STAR_OVER_STORAGE
        .get_or_init(|| Regex::new(r"(?i)\bSELECT\s+\*[^()]*\bFROM\s+(file|s3)\(").expect("static regex"))
        .is_match(sql)
    {
        return None;
    }
    let mut sql = sql.to_string();
    let mut changed = false;
    for path in required.keys() {
        if is_row_identity_column(path) || path.contains(".^") || !path.contains('.') {
            continue;
        }
        let (Ok(nested), Ok(flat)) = (nested_projection(path), quoted_identifier(path)) else { continue };
        let pattern = format!("{nested} AS {flat}");
        if !sql.contains(&pattern) {
            continue;
        }
        let mut leaf_type: Option<String> = None;
        let mut targets = Vec::new();
        let mut consistent = true;
        for (index, (name, schema)) in params.iter().enumerate() {
            if !name.ends_with("_read_schema") {
                continue;
            }
            match scalar_leaf_type(schema, path) {
                Some(LeafType::Scalar(ty)) => {
                    if leaf_type.as_ref().is_some_and(|known| *known != ty) {
                        consistent = false;
                    }
                    leaf_type = Some(ty);
                    targets.push(index);
                }
                Some(LeafType::AlreadyFlat) => {}
                Some(LeafType::Absent) => {}
                None => consistent = false,
            }
        }
        let Some(ty) = leaf_type.filter(|_| consistent && !targets.is_empty()) else { continue };
        for index in targets {
            let schema = &mut params[index].1;
            schema.push_str(&format!(", {flat} {ty}"));
        }
        sql = sql.replace(&pattern, &format!("{flat} AS {flat}"));
        changed = true;
    }
    changed.then_some(sql)
}

enum LeafType {
    /// A scalar under Tuple-only ancestors, with its ClickHouse type.
    Scalar(String),
    /// The schema already names the flat dotted column.
    AlreadyFlat,
    /// The schema does not have the root or the leaf (missing column).
    Absent,
}

/// The leaf type of `path` in an explicit read schema. `None` when the leaf
/// is not a plain scalar (array, map, tuple) or the schema does not parse.
fn scalar_leaf_type(schema: &str, path: &str) -> Option<LeafType> {
    let mut segments = path.split('.');
    let root = segments.next()?;
    let mut current = None;
    for field in split_top_level(schema)? {
        let (name, ty) = split_schema_field(field)?;
        if name == path {
            return Some(LeafType::AlreadyFlat);
        }
        if name == root {
            current = Some(ty.trim());
        }
    }
    let Some(mut ty) = current else { return Some(LeafType::Absent) };
    for segment in segments {
        let inner = ty.strip_prefix("Tuple(")?.strip_suffix(')')?;
        let mut next = None;
        for field in split_top_level(inner)? {
            let (name, field_type) = split_schema_field(field)?;
            if name == segment {
                next = Some(field_type.trim());
            }
        }
        let Some(found) = next else { return Some(LeafType::Absent) };
        ty = found;
    }
    let scalar = !["Tuple(", "Array(", "Map(", "Nested(", "Object(", "JSON", "Variant(", "Dynamic"]
        .iter()
        .any(|prefix| ty.starts_with(prefix) || ty.starts_with(&format!("Nullable({prefix}")) || ty.starts_with(&format!("LowCardinality({prefix}")));
    scalar.then(|| LeafType::Scalar(ty.to_string()))
}

/// NAN-3155: narrow every Tuple root of an explicit read schema to the leaves
/// in `required` (`metadata.uid` keeps `metadata Tuple(uid …)` only; an
/// `Array(Tuple(…))` keeps the element leaves). chDB's Parquet reader then
/// decodes only those column chunks, and every nested expression over the
/// root (`tupleElement`, `` `root`.`leaf` ``) still binds, with the same types.
///
/// Conservative: a root named whole, a leaf the type does not show (map keys, an unparseable type) keeps the
/// field's whole type. `None` only when the schema itself does not parse.
fn leaf_read_schema(schema: &str, required: &BTreeMap<String, String>) -> Option<String> {
    let mut fields = Vec::new();
    for field in split_top_level(schema)? {
        let (name, ty) = split_schema_field(field)?;
        let leaves = required
            .keys()
            .filter(|path| !is_row_identity_column(path))
            .filter_map(|path| {
                let path = path.replace(".^", ".");
                if path == name { Some(String::new()) }
                else { path.strip_prefix(name.as_str()).and_then(|rest| rest.strip_prefix('.')).map(str::to_string) }
            })
            .collect::<BTreeSet<_>>();
        let pruned = if leaves.is_empty() || leaves.contains("") {
            None
        } else {
            prune_type(ty, &leaves)
        };
        fields.push(format!("`{}` {}", name.replace('`', "``"), pruned.as_deref().unwrap_or(ty)));
    }
    Some(fields.join(", "))
}

/// `ty` narrowed to `leaves` (dotted paths relative to it), or `None` to keep
/// it whole.
fn prune_type(ty: &str, leaves: &BTreeSet<String>) -> Option<String> {
    let ty = ty.trim();
    if leaves.contains("") {
        return None;
    }
    if let Some(element) = ty.strip_prefix("Array(").and_then(|rest| rest.strip_suffix(')')) {
        return prune_type(element, leaves).map(|element| format!("Array({element})"));
    }
    let inner = ty.strip_prefix("Tuple(")?.strip_suffix(')')?;
    let mut kept = Vec::new();
    let mut found = BTreeSet::new();
    for field in split_top_level(inner)? {
        let (name, field_type) = split_schema_field(field)?;
        let sub = leaves
            .iter()
            .filter_map(|leaf| {
                if *leaf == name { Some(String::new()) }
                else { leaf.strip_prefix(name.as_str()).and_then(|rest| rest.strip_prefix('.')).map(str::to_string) }
            })
            .collect::<BTreeSet<_>>();
        if sub.is_empty() {
            continue;
        }
        for leaf in leaves {
            if *leaf == name || leaf.starts_with(&format!("{name}.")) {
                found.insert(leaf.clone());
            }
        }
        let narrowed = prune_type(field_type, &sub);
        kept.push(format!("`{}` {}", name.replace('`', "``"), narrowed.as_deref().unwrap_or(field_type.trim())));
    }
    // A leaf this type does not show: keep the whole type.
    (found.len() == leaves.len() && !kept.is_empty()).then(|| format!("Tuple({})", kept.join(", ")))
}

/// Top-level comma split of a schema or Tuple body (quotes and parentheses
/// respected). `None` when unbalanced.
fn split_top_level(text: &str) -> Option<Vec<&str>> {
    let (mut depth, mut quote, mut escaped, mut start) = (0_usize, None, false, 0);
    let mut parts = Vec::new();
    for (offset, ch) in text.char_indices() {
        if escaped { escaped = false; continue; }
        if let Some(delimiter) = quote {
            if ch == '\\' { escaped = true; } else if ch == delimiter { quote = None; }
            continue;
        }
        match ch {
            '\'' | '`' | '"' => quote = Some(ch),
            '(' => depth = depth.checked_add(1)?,
            ')' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                parts.push(text[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
    }
    if quote.is_some() || escaped || depth != 0 { return None; }
    parts.push(text[start..].trim());
    Some(parts)
}

/// `` `name` Type `` (or `name Type`) into its unescaped name and type.
fn split_schema_field(field: &str) -> Option<(String, &str)> {
    let field = field.trim();
    if let Some(rest) = field.strip_prefix('`') {
        let mut name = String::new();
        let mut chars = rest.char_indices().peekable();
        while let Some((offset, ch)) = chars.next() {
            if ch == '`' {
                if chars.peek().is_some_and(|(_, next)| *next == '`') { chars.next(); name.push('`'); continue; }
                let ty = rest[offset + 1..].trim();
                return (!name.is_empty() && !ty.is_empty()).then_some((name, ty));
            }
            name.push(ch);
        }
        None
    } else {
        let (name, ty) = field.split_once(char::is_whitespace)?;
        let ty = ty.trim();
        (!name.is_empty() && !ty.is_empty()).then(|| (name.to_string(), ty))
    }
}

fn validate_source_time_fence(compiled: &CompiledQuery, fence: SourceTimeFence<'_>) -> Result<()> {
    let (compiled_start, compiled_end) = compiled_window_micros(compiled)?;
    let start = DateTime::parse_from_rfc3339(fence.start).map_err(|_| {
        QueryPlanError::InvalidCompilerOutput(
            "source time fence is not an RFC3339 timestamp".to_string(),
        )
    })?;
    let end = DateTime::parse_from_rfc3339(fence.end).map_err(|_| {
        QueryPlanError::InvalidCompilerOutput(
            "source time fence is not an RFC3339 timestamp".to_string(),
        )
    })?;
    // Fences are microsecond instants (event time's precision); the compiled
    // window may carry nanoseconds from the caller's RFC3339 bounds.
    if start >= end || start.timestamp_micros() < compiled_start || end.timestamp_micros() > compiled_end {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "source time fence escapes the compiled query window".to_string(),
        ));
    }
    if let Some(times) = fence.exact_times {
        // Only canonical instants inside the fence reach the SQL parameter.
        let (start_ms, end_ms) = (start.timestamp_micros(), end.timestamp_micros());
        let valid = !times.is_empty()
            && times.len() <= MAX_EXACT_FENCE_TIMES
            && times.iter().all(|time| {
                exact_fence_time(time).as_deref() == Some(time.as_str())
                    && chrono::NaiveDateTime::parse_from_str(time, "%Y-%m-%d %H:%M:%S%.f")
                        .map(|parsed| parsed.and_utc().timestamp_micros())
                        .is_ok_and(|micros| micros >= start_ms && micros <= end_ms)
            });
        if !valid {
            return Err(QueryPlanError::InvalidCompilerOutput(
                "source exact time fence is invalid".to_string(),
            ));
        }
    }
    Ok(())
}

/// The compiled window in whole microseconds: the start floored and the
/// end ceiled, so a nanosecond-precision request window admits every
/// microsecond fence inside it (a sub-second `now` used to 400).
fn compiled_window_micros(compiled: &CompiledQuery) -> Result<(i64, i64)> {
    let parse = |value: &str, what: &str| {
        DateTime::parse_from_rfc3339(value).map_err(|_| {
            QueryPlanError::InvalidCompilerOutput(format!("compiled query {what} is not an RFC3339 timestamp"))
        })
    };
    let start = parse(&compiled.start, "start")?;
    let end = parse(&compiled.end, "end")?;
    let ceil = |time: DateTime<chrono::FixedOffset>| {
        time.timestamp_micros() + i64::from(time.timestamp_subsec_nanos() % 1_000 != 0)
    };
    Ok((start.timestamp_micros(), ceil(end)))
}

fn validate_source_cursor_fence(
    compiled: &CompiledQuery,
    cursor: SourceCursorFence<'_>,
) -> Result<()> {
    if cursor.event_uid.is_empty()
        || cursor.event_uid.len() > 2_048
        || cursor.event_uid.chars().any(char::is_control)
    {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "source cursor event UID is invalid".to_string(),
        ));
    }
    let (compiled_start, compiled_end) = compiled_window_micros(compiled)?;
    let cursor_time = DateTime::parse_from_rfc3339(cursor.time).map_err(|_| {
        QueryPlanError::InvalidCompilerOutput(
            "source cursor time is not an RFC3339 timestamp".to_string(),
        )
    })?;
    let cursor_time = cursor_time.timestamp_micros();
    if cursor_time <= compiled_start || cursor_time > compiled_end {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "source cursor time escapes the compiled query window".to_string(),
        ));
    }
    Ok(())
}

fn effective_object_time_window(
    compiled: &CompiledQuery,
    fence: Option<SourceTimeFence<'_>>,
    cursor: Option<SourceCursorFence<'_>>,
) -> Result<Option<ObjectTimeWindow>> {
    let (start, end) = match fence {
        Some(fence) => (fence.start, fence.end),
        None if compiled.start.is_empty() && compiled.end.is_empty() => return Ok(None),
        None => (compiled.start.as_str(), compiled.end.as_str()),
    };
    let start = DateTime::parse_from_rfc3339(start).map_err(|_| {
        QueryPlanError::InvalidCompilerOutput(
            "compiled query start is not an RFC3339 timestamp".to_string(),
        )
    })?;
    let mut end = DateTime::parse_from_rfc3339(end).map_err(|_| {
        QueryPlanError::InvalidCompilerOutput(
            "compiled query end is not an RFC3339 timestamp".to_string(),
        )
    })?;
    if let Some(cursor) = cursor {
        let cursor_time = DateTime::parse_from_rfc3339(cursor.time).map_err(|_| {
            QueryPlanError::InvalidCompilerOutput(
                "source cursor time is not an RFC3339 timestamp".to_string(),
            )
        })?;
        end = end.min(cursor_time);
    }
    if start >= end {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "compiled query time range must be increasing".to_string(),
        ));
    }
    Ok(Some(ObjectTimeWindow {
        start_ms: start.timestamp_millis(),
        end_ms: end.timestamp_millis(),
    }))
}

/// The trusted `event_hour=` partition of an object path, if it has one.
fn object_path_event_hour(path: &str) -> Option<i64> {
    path.split('/')
        .find_map(|segment| segment.strip_prefix("event_hour="))
        .and_then(|value| value.parse::<i64>().ok())
}

fn object_path_overlaps_window(path: &str, window: ObjectTimeWindow) -> bool {
    let Some(hour) = path
        .split('/')
        .find_map(|segment| segment.strip_prefix("event_hour="))
        .and_then(|value| value.parse::<i64>().ok())
    else {
        // Older/external layouts without the trusted hour partition remain
        // conservative and count toward every query window.
        return true;
    };
    let Some(hour_start_ms) = hour.checked_mul(3_600_000) else {
        return true;
    };
    let Some(hour_end_ms) = hour_start_ms.checked_add(3_600_000) else {
        return true;
    };
    hour_start_ms <= window.end_ms && hour_end_ms > window.start_ms
}

fn hot_tail_object_overlaps_window(
    object: &crate::generation::HotTailObject,
    window: ObjectTimeWindow,
) -> bool {
    // Both are trusted bounds. A broad manifest bound must not disable the
    // tighter hour partition (nor may a partition disable tighter row bounds).
    if !object_path_overlaps_window(&object.source_uri, window) {
        return false;
    }
    match (object.min_time_ms, object.max_time_ms) {
        (Some(minimum), Some(maximum)) if maximum >= minimum => {
            minimum <= window.end_ms && maximum >= window.start_ms
        }
        _ => true,
    }
}

/// Keep the schema-v4 cache path at the same index as its signed object while
/// time-scoping a query. Older manifests have no process-local path array.
fn retain_hot_tail_objects(
    tail: &mut HotTailManifest,
    mut retain: impl FnMut(&crate::generation::HotTailObject) -> bool,
) -> Result<()> {
    if tail.schema_version != 4 {
        tail.objects.retain(retain);
        return Ok(());
    }
    if tail.objects.len() != tail.local_paths.len() {
        return Err(QueryPlanError::InvalidManifest(
            "schema-v4 hot tail is not completely hydrated".to_string(),
        ));
    }
    let mut objects = Vec::with_capacity(tail.objects.len());
    let mut local_paths = Vec::with_capacity(tail.local_paths.len());
    for (object, local_path) in std::mem::take(&mut tail.objects)
        .into_iter()
        .zip(std::mem::take(&mut tail.local_paths))
    {
        if retain(&object) {
            objects.push(object);
            local_paths.push(local_path);
        }
    }
    tail.objects = objects;
    tail.local_paths = local_paths;
    Ok(())
}

fn time_scoped_manifest_budget(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    full_budget: QueryBudget,
    window: Option<ObjectTimeWindow>,
    projected_columns: Option<&BTreeSet<String>>,
    budget_enforcement: BudgetEnforcement,
) -> Result<QueryBudget> {
    let Some(window) = window else {
        if budget_enforcement == BudgetEnforcement::Reject
            && full_budget.estimated_scan_bytes > tenant.max_query_bytes
        {
            return Err(QueryPlanError::BudgetRejected {
                estimated_bytes: full_budget.estimated_scan_bytes,
                max_bytes: tenant.max_query_bytes,
            });
        }
        return Ok(full_budget);
    };
    let mut candidate_objects = 0_usize;
    let mut estimated_scan_bytes = 0_u64;
    for object in &manifest.objects {
        if !object_path_overlaps_window(&object.event_object_key, window) {
            continue;
        }
        candidate_objects = candidate_objects.checked_add(1).ok_or_else(|| {
            QueryPlanError::InvalidManifest("time-scoped object count overflowed".to_string())
        })?;
        let object_bytes = projected_columns
            .and_then(|columns| projected_object_bytes(object, columns))
            .unwrap_or(object.event_object_bytes);
        estimated_scan_bytes = estimated_scan_bytes
            .checked_add(object_bytes)
            .ok_or_else(|| {
                QueryPlanError::InvalidManifest("time-scoped byte total overflowed".to_string())
            })?;
    }
    if budget_enforcement == BudgetEnforcement::Reject
        && estimated_scan_bytes > tenant.max_query_bytes
    {
        return Err(QueryPlanError::BudgetRejected {
            estimated_bytes: estimated_scan_bytes,
            max_bytes: tenant.max_query_bytes,
        });
    }
    Ok(QueryBudget {
        candidate_objects,
        estimated_scan_bytes,
        max_query_bytes: tenant.max_query_bytes,
    })
}

fn projected_object_bytes(object: &ManifestObject, columns: &BTreeSet<String>) -> Option<u64> {
    if columns.is_empty() || object.column_compressed_bytes.is_empty() {
        return None;
    }
    let mut bytes = 0_u64;
    for column in columns {
        if is_row_identity_column(column) {
            continue;
        }
        // A leaf charges its own chunk; a whole root (or Tuple) charges every
        // leaf under it (NAN-3155: part selections key bytes per leaf).
        let prefix = format!("{column}.");
        let nested = object.column_compressed_bytes.range(prefix.clone()..)
            .take_while(|(path, _)| path.starts_with(&prefix))
            .try_fold((0_u64, false), |(sum, _), (_, bytes)| sum.checked_add(*bytes).map(|sum| (sum, true)))?;
        let charged = match (object.column_compressed_bytes.get(column), nested) {
            (Some(exact), _) => *exact,
            (None, (sum, true)) => sum,
            (None, (_, false)) if object.available_paths.iter().any(|path| path == column) => return None,
            (None, (_, false)) => continue,
        };
        bytes = bytes.checked_add(charged)?;
    }
    // Footer/page-index reads and remote range granularity are not represented
    // in Parquet column chunks. Keep a fixed per-object allowance plus 10% so
    // admission remains conservative without charging every unreferenced leaf.
    with_read_margin(object, bytes)
}

/// NAN-3159: a full-event read decodes every leaf, but only the column
/// chunks (of the row groups a part selection kept), not the footer, bloom
/// filters or page index. `None` without per-column bytes.
fn all_leaf_object_bytes(object: &ManifestObject) -> Option<u64> {
    if object.column_compressed_bytes.is_empty() {
        return None;
    }
    let bytes = object.column_compressed_bytes.values().try_fold(0_u64, |sum, bytes| sum.checked_add(*bytes))?;
    with_read_margin(object, bytes)
}

fn with_read_margin(object: &ManifestObject, bytes: u64) -> Option<u64> {
    let with_margin = bytes.checked_add(bytes / 10)?.checked_add(64 * 1_024)?;
    Some(with_margin.min(object.event_object_bytes))
}

fn hot_tail_source(
    tenant: &TenantQueryConfig,
    tail: &HotTailManifest,
    budget_enforcement: BudgetEnforcement,
    projection: &str,
) -> Result<(String, Vec<(String, String)>, QueryBudget)> {
    if !matches!(tail.schema_version, 1 | 2 | 3 | 4)
        || tail.tenant_id != tenant.tenant_id
        || tail.objects.is_empty()
        || tail.objects.len() > HOT_TAIL_OBJECT_FORMAT_CEILING as usize
    {
        return Err(QueryPlanError::InvalidManifest(
            "hot-tail tenant, schema, or object bound is invalid".to_string(),
        ));
    }
    let metadata_prefix = tail
        .head_metadata_location
        .strip_suffix(&tail.iceberg_metadata_file_path)
        .filter(|prefix| prefix.starts_with("s3://") && prefix.ends_with('/'))
        .ok_or_else(|| {
            QueryPlanError::InvalidManifest(
                "hot-tail metadata path is outside its table".to_string(),
            )
        })?;
    let data_prefix = format!("{}data/", metadata_prefix);
    let staged_prefix = format!(
        "{}tail/tenant_sha256={}/",
        data_prefix,
        hex::encode(Sha256::digest(tenant.tenant_id.as_bytes()))
    );
    let mut bytes = 0_u64;
    let mut paths = BTreeSet::new();
    for object in &tail.objects {
        let staged_tail_object = object
            .source_uri
            .starts_with(&format!("{data_prefix}tail/"));
        if object.version_id.is_empty()
            || object.version_id == "unversioned"
            || object.size_bytes == 0
            || object.rows == 0
            || !object.source_uri.starts_with(&data_prefix)
            || (matches!(tail.schema_version, 2 | 3 | 4)
                && staged_tail_object
                && !object.source_uri.starts_with(&staged_prefix))
            || !paths.insert(object.source_uri.as_str())
        {
            return Err(QueryPlanError::InvalidManifest(
                "hot-tail object identity is invalid".to_string(),
            ));
        }
        bytes = bytes.checked_add(object.size_bytes).ok_or_else(|| {
            QueryPlanError::InvalidManifest("hot-tail byte total overflowed".to_string())
        })?;
    }
    if budget_enforcement == BudgetEnforcement::Reject && bytes > tenant.max_query_bytes {
        return Err(QueryPlanError::BudgetRejected {
            estimated_bytes: bytes,
            max_bytes: tenant.max_query_bytes,
        });
    }
    if projection.trim().is_empty() {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "hot-tail projection is empty".to_string(),
        ));
    }
    let (source, source_params) = if tail.schema_version == 4 {
        cached_hot_tail_source(tail, "hot_tail_source", projection)?
    } else {
        exact_versioned_parquet_source(
            tenant,
            &tail.objects,
            "hot_tail_source",
            projection,
            tail.read_schema.as_deref(),
        )?
    };
    Ok((
        source,
        source_params,
        QueryBudget {
            candidate_objects: tail.objects.len(),
            estimated_scan_bytes: bytes,
            max_query_bytes: tenant.max_query_bytes,
        },
    ))
}

/// Bind a fully hydrated schema-v4 tail through one local table-function leaf.
/// The potentially long brace specification is a native parameter value, not
/// SQL text, so object count no longer grows the parsed query AST.
fn cached_hot_tail_source(
    tail: &HotTailManifest,
    parameter: &str,
    projection: &str,
) -> Result<(String, Vec<(String, String)>)> {
    if tail.local_paths.len() != tail.objects.len()
        || tail.local_paths.is_empty()
        || tail.local_paths.len() > HOT_TAIL_OBJECT_FORMAT_CEILING as usize
    {
        return Err(QueryPlanError::InvalidManifest(
            "schema-v4 hot tail is not completely hydrated".to_string(),
        ));
    }
    let mut paths = tail
        .local_paths
        .iter()
        .map(|path| {
            path.to_str().map(ToOwned::to_owned).ok_or_else(|| {
                QueryPlanError::InvalidManifest(
                    "hot-tail cache path is not valid UTF-8".to_string(),
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if paths.iter().any(|path| {
        !path.starts_with('/')
            || path
                .chars()
                .any(|character| character.is_control() || matches!(character, '{' | '}' | ','))
    }) {
        return Err(QueryPlanError::InvalidManifest(
            "hot-tail cache path violates its local-file contract".to_string(),
        ));
    }
    let source_spec = local_path_spec(&mut paths)?;
    let mut params = vec![(parameter.to_string(), source_spec)];
    let table = if let Some(schema) = tail.read_schema.as_ref() {
        let schema_parameter = format!("{parameter}_read_schema");
        params.push((schema_parameter.clone(), schema.clone()));
        format!("file({{{parameter}:String}}, Parquet, {{{schema_parameter}:String}})")
    } else {
        format!("file({{{parameter}:String}}, Parquet)")
    };
    Ok((format!("(SELECT {projection} FROM {table})"), params))
}

fn exact_versioned_parquet_source(
    tenant: &TenantQueryConfig,
    objects: &[crate::generation::HotTailObject],
    parameter_prefix: &str,
    projection: &str,
    read_schema_override: Option<&str>,
) -> Result<(String, Vec<(String, String)>)> {
    if objects.is_empty() || objects.len() > HOT_TAIL_OBJECT_FORMAT_CEILING as usize {
        return Err(QueryPlanError::InvalidManifest(
            "exact-version Parquet source violates its object bound".to_string(),
        ));
    }
    let arguments = |parameter: &str| {
        match &tenant.credentials {
        ObjectStoreCredentials::DefaultChain => format!("{{{parameter}:String}}"),
        ObjectStoreCredentials::Static {
            session_token: Some(_),
            ..
        } => format!(
            "{{{parameter}:String}}, {{iceberg_access_key:String}}, {{iceberg_secret_key:String}}, {{iceberg_session_token:String}}"
        ),
        ObjectStoreCredentials::Static { .. } => format!(
            "{{{parameter}:String}}, {{iceberg_access_key:String}}, {{iceberg_secret_key:String}}"
        ),
    }
    };
    let mut selects = Vec::with_capacity(objects.len());
    let mut params = Vec::with_capacity(objects.len());
    let read_schema = read_schema_override.or_else(|| {
        tenant
            .snapshot_cache
            .as_ref()
            .and_then(|cache| cache.read_schema.as_deref())
    });
    let read_schema_parameter = read_schema.map(|schema| {
        let parameter = format!("{parameter_prefix}_read_schema");
        params.push((parameter.clone(), schema.to_string()));
        parameter
    });
    for (index, object) in objects.iter().enumerate() {
        let parameter = format!("{parameter_prefix}_{index}");
        let (_, source_params) =
            exact_parquet_source(tenant, &[object.source_uri.as_str()], &parameter)?;
        let source = source_params
            .iter()
            .find(|(name, _)| name == &parameter)
            .map(|(_, value)| value.clone())
            .ok_or_else(|| {
                QueryPlanError::InvalidManifest(
                    "exact Parquet source omitted its bound URL".to_string(),
                )
            })?;
        let source = format!(
            "{source}?versionId={}",
            percent_encode_query_value(&object.version_id)
        );
        let table = if let Some(schema_parameter) = read_schema_parameter.as_ref() {
            format!(
                "s3({}, Parquet, {{{schema_parameter}:String}})",
                arguments(&parameter)
            )
        } else {
            format!("s3({}, Parquet)", arguments(&parameter))
        };
        selects.push(format!("SELECT {projection} FROM {table}"));
        params.push((parameter, source));
    }
    Ok((format!("({})", selects.join(" UNION ALL ")), params))
}

fn percent_encode_query_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

/// Objects whose candidate blocks cover every row (NAN-3149). Only with an
/// explicit read schema (both branches of the split source must have the
/// same columns) and a glob-free cache path (a literal `*`/`?`/`[` in a
/// path would widen an unfenced `file()` read beyond the exact object).
fn whole_file_candidates<'a>(
    tenant: &TenantQueryConfig,
    manifest_objects: &BTreeMap<&str, &ManifestObject>,
    candidates: &'a [CandidateBlock],
) -> BTreeSet<&'a str> {
    let Some(cache) = tenant.snapshot_cache.as_ref().filter(|cache| cache.read_schema.is_some()) else {
        return BTreeSet::new();
    };
    let mut ranges: BTreeMap<&str, Vec<(u64, u64)>> = BTreeMap::new();
    for candidate in candidates {
        ranges.entry(candidate.event_object_key.as_str()).or_default().push((candidate.row_start, candidate.row_end));
    }
    ranges
        .into_iter()
        .filter(|(key, ranges)| {
            let Some(object) = manifest_objects.get(key) else { return false };
            let glob_free = cache.objects.get(*key).is_some_and(|cached| {
                cached.path.to_str().is_some_and(|path| !path.contains(['*', '?', '[', ']', '{', '}']))
            });
            if !glob_free || object.rows == 0 {
                return false;
            }
            let mut ranges = ranges.clone();
            ranges.sort_unstable();
            let mut covered = 0_u64;
            for (start, end) in ranges {
                if start > covered {
                    return false;
                }
                covered = covered.max(end);
            }
            covered == object.rows
        })
        .map(|(key, _)| key)
        .collect()
}

/// One candidate block that keeps a per-row fence (its file is not read whole).
struct FencedBlock<'a> {
    /// The candidate's position in the selection (stable parameter names).
    index: usize,
    object_key: &'a str,
    object_rows: u64,
    row_start: u64,
    row_end: u64,
}

/// NAN-3179: most granule keys one set fence carries. With the time guard's
/// buckets this keeps the statement well inside chDB's 256 KiB
/// `max_query_size` (keys are ~6-10 bytes of SQL); files past the budget
/// keep the OR form.
const MAX_FENCE_SET_KEYS: u64 = 8_192;

/// NAN-3179: the set-membership fence; `NANO_LAKE_FENCE_SET=0` restores the
/// per-block OR list.
pub(crate) fn fence_set_enabled() -> bool {
    crate::perf_overrides::probe_flag("fence_set", !std::env::var("NANO_LAKE_FENCE_SET").is_ok_and(|value| value == "0"))
}

/// NAN-3179: a gap between two time-guard ranges narrower than the ranges'
/// mean length over this divisor is merged away.
const TIME_GUARD_GAP_DIVISOR: i64 = 16;
/// NAN-3179: past this many ranges the evaluated time guard is a bucket set
/// (see [`time_guard_buckets`]); up to it, plain comparisons.
const MAX_EXACT_TIME_GUARD_RANGES: usize = 8;
/// NAN-3179: most time buckets one guard carries (11-17 bytes of SQL each).
const MAX_TIME_GUARD_BUCKETS: usize = 2_048;
/// NAN-3179: most ranges in the guard's `indexHint` (~62 bytes each);
/// past it the smallest gaps merge (see [`cap_time_ranges`]).
const MAX_TIME_GUARD_HINT_RANGES: usize = 1_024;

/// Merges sorted, disjoint `ranges` across their smallest gaps until at most
/// `cap` remain: a coarser superset that keeps the widest gaps.
fn cap_time_ranges(ranges: Vec<(i64, i64)>, cap: usize) -> Vec<(i64, i64)> {
    if ranges.len() <= cap || cap == 0 {
        return ranges;
    }
    let mut gaps = (1..ranges.len()).collect::<Vec<_>>();
    // Widest gaps first; ties toward the earlier gap (deterministic).
    gaps.sort_by_key(|&i| (std::cmp::Reverse(i128::from(ranges[i].0) - i128::from(ranges[i - 1].1)), i));
    let kept = gaps.into_iter().take(cap - 1).collect::<BTreeSet<_>>();
    let mut capped: Vec<(i64, i64)> = Vec::with_capacity(cap);
    for (i, range) in ranges.into_iter().enumerate() {
        match capped.last_mut() {
            Some(last) if !kept.contains(&i) => last.1 = last.1.max(range.1),
            _ => capped.push(range),
        }
    }
    capped
}

/// The smallest power-of-two bucket width (microseconds) whose buckets
/// touching `ranges` (sorted, inclusive) number at most
/// [`MAX_TIME_GUARD_BUCKETS`], and those buckets, sorted. Every instant of
/// every range falls in a listed bucket: a superset of the guard.
/// On the NAN-3171 fixture's 144 run ranges (1 s buckets) the bucket set
/// cost 0.27 CPU-s against 0.57 for the comparisons and 0.33 unfenced.
fn time_guard_buckets(ranges: &[(i64, i64)]) -> (i64, Vec<i64>) {
    let count = |width: i64| {
        ranges
            .iter()
            .map(|(start, end)| (end.div_euclid(width) - start.div_euclid(width) + 1) as u128)
            .sum::<u128>()
    };
    let mut width = 1_i64;
    while count(width) > MAX_TIME_GUARD_BUCKETS as u128 && width < (1 << 62) {
        width <<= 1;
    }
    let mut buckets = ranges
        .iter()
        .flat_map(|(start, end)| start.div_euclid(width)..=end.div_euclid(width))
        .collect::<Vec<_>>();
    buckets.sort_unstable();
    buckets.dedup();
    (width, buckets)
}

/// Merges sorted, disjoint guard `ranges` across gaps much narrower than
/// the ranges themselves. The guard is evaluated per row like the fence:
/// kept row groups of a time-sorted file are one range each, separated by
/// one inter-event gap (~300 ranges on a dense host's day made the
/// set-fenced statement 6.7x the unfenced scan on real parts). A merged
/// range only widens the guard (still a superset of the fence), and wide
/// gaps (skipped groups, sparse block runs) are kept: there the evaluated
/// guard filters `time` before the wide columns are decoded.
fn merge_close_time_ranges(ranges: Vec<(i64, i64)>) -> Vec<(i64, i64)> {
    if ranges.len() < 2 {
        return ranges;
    }
    let total = ranges.iter().map(|(start, end)| i128::from(*end) - i128::from(*start)).sum::<i128>();
    let tolerance = total / ranges.len() as i128 / i128::from(TIME_GUARD_GAP_DIVISOR);
    let mut merged: Vec<(i64, i64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if i128::from(start) - i128::from(last.1) <= tolerance => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// The exact row fence over `fenced` (every block's file, with its
/// `_path` bound as a parameter pushed onto `params`).
///
/// The OR form is one `(_path = p AND _row_number >= a AND _row_number < b)`
/// term per block, and chDB evaluates every term on every decoded row: 394
/// terms over a day of real H parts (3.1 M rows) cost 1.28 CPU-s against
/// 0.19 unfenced (NAN-3179), and past ~3,000 terms the statement outgrows
/// chDB's 256 KiB `max_query_size`. The set form costs two dictionary
/// lookups on the `LowCardinality` `_path` and one hash probe per row,
/// whatever the block count (0.21 CPU-s on the same statement):
///
/// ```text
/// (intDiv(_row_number, transform(_path, [p1, ..], [g1, ..], 1)) * F
///    + transform(_path, [p1, ..], [1, ..], 0)) IN (k1, ..)
/// ```
///
/// Each file is cut into granules of `g`, the GCD of its block boundaries
/// (a file's end is no boundary: no row lies past it), so every block is
/// exactly a union of granules and the key set is exact, not a superset.
/// `F` is one more than the set files, so `key % F` names the file and a
/// path outside the list (file id 0) matches no key. Files whose granules
/// would overflow [`MAX_FENCE_SET_KEYS`] keep exact OR terms over their
/// merged ranges.
fn row_fence(
    tenant: &TenantQueryConfig,
    fenced: &[FencedBlock<'_>],
    set: bool,
    params: &mut Vec<(String, String)>,
) -> Result<String> {
    row_fence_with(fenced, set, &mut |name, key| {
        params.push((name, candidate_virtual_path(tenant, key)?));
        Ok(())
    })
}

/// [`row_fence`]'s text; `param` receives each file's parameter name and
/// object key (the caller binds the path).
fn row_fence_with(
    fenced: &[FencedBlock<'_>],
    set: bool,
    param: &mut dyn FnMut(String, &str) -> Result<()>,
) -> Result<String> {
    if !set {
        let mut terms = Vec::with_capacity(fenced.len());
        for block in fenced {
            let name = format!("candidate_path_{}", block.index);
            param(name.clone(), block.object_key)?;
            terms.push(format!(
                "(_path = {{{name}:String}} AND _row_number >= {} AND _row_number < {})",
                block.row_start, block.row_end
            ));
        }
        return Ok(terms.join(" OR "));
    }
    // Per file, in first-candidate order: its parameter and merged ranges.
    let mut order: Vec<&str> = Vec::new();
    let mut files: BTreeMap<&str, (String, u64, Vec<(u64, u64)>)> = BTreeMap::new();
    for block in fenced {
        let file = files.entry(block.object_key).or_insert_with(|| {
            order.push(block.object_key);
            (format!("candidate_path_{}", block.index), block.object_rows, Vec::new())
        });
        file.2.push((block.row_start, block.row_end));
    }
    let mut set_files = Vec::new();
    let mut residual = Vec::new();
    let mut budget = 0_u64;
    for key in order {
        let (name, rows, mut ranges) = files.remove(key).expect("ordered file");
        param(name.clone(), key)?;
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        let granule = merged
            .iter()
            .fold(0, |g, (start, end)| gcd(if *end == rows { g } else { gcd(g, *end) }, *start));
        // Only `[0, rows)` leaves no boundary: one granule spans the file.
        let granule = if granule == 0 { rows.max(1) } else { granule };
        let keys = merged.iter().map(|(start, end)| end.div_ceil(granule) - start / granule).sum::<u64>();
        if budget + keys <= MAX_FENCE_SET_KEYS {
            budget += keys;
            set_files.push((name, granule, merged));
        } else {
            for (start, end) in merged {
                residual.push(format!(
                    "(_path = {{{name}:String}} AND _row_number >= {start} AND _row_number < {end})"
                ));
            }
        }
    }
    let mut terms = Vec::with_capacity(residual.len() + 1);
    if !set_files.is_empty() {
        let width = set_files.len() as u64 + 1;
        let mut keys = Vec::with_capacity(budget as usize);
        for (id, (_, granule, merged)) in set_files.iter().enumerate() {
            for (start, end) in merged {
                keys.extend((start / granule..end.div_ceil(*granule)).map(|g| g * width + id as u64 + 1));
            }
        }
        keys.sort_unstable();
        keys.dedup();
        let join = |items: Vec<String>| items.join(",");
        let paths = join(set_files.iter().map(|(name, _, _)| format!("{{{name}:String}}")).collect());
        let granules = join(set_files.iter().map(|(_, granule, _)| granule.to_string()).collect());
        let ids = join((1..=set_files.len()).map(|id| id.to_string()).collect());
        terms.push(format!(
            "(intDiv(_row_number, transform(_path, [{paths}], [{granules}], 1)) * {width} + transform(_path, [{paths}], [{ids}], 0)) IN ({})",
            join(keys.iter().map(u64::to_string).collect())
        ));
    }
    terms.extend(residual);
    Ok(terms.join(" OR "))
}

/// The time guard over the fenced blocks' time ranges: a superset of the
/// row-number fence (every kept row lies inside its block's own time range),
/// so results are unchanged; it only lets the Parquet statistics filter skip
/// unselected row groups.
fn time_guard_sql(mut ranges: Vec<(i64, i64)>, set_fence: bool) -> Option<String> {
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_unstable();
    let mut merged: Vec<(i64, i64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let literal = |micros: i64| {
        DateTime::from_timestamp_micros(micros)
            .map(|time| time.format("%Y-%m-%d %H:%M:%S%.6f").to_string())
    };
    if set_fence {
        merged = merge_close_time_ranges(merged);
    }
    let ranges = |ranges: &[(i64, i64)]| {
        ranges
            .iter()
            .map(|(start, end)| Some(format!("(time >= '{}' AND time <= '{}')", literal(*start)?, literal(*end)?)))
            .collect::<Option<Vec<_>>>()
            .map(|ranges| ranges.join(" OR "))
    };
    if !set_fence || merged.len() <= MAX_EXACT_TIME_GUARD_RANGES {
        return ranges(&merged);
    }
    let exact = ranges(&cap_time_ranges(merged.clone(), MAX_TIME_GUARD_HINT_RANGES))?;
    // NAN-3179: many ranges (sparse block runs) cost one comparison
    // each per row, like the OR fence. The statistics and page filter
    // keep the exact ranges through `indexHint` (analysed, never
    // evaluated per row); rows are filtered by a superset of the
    // guard, one hash probe on time buckets of `width` microseconds.
    let (width, buckets) = time_guard_buckets(&merged);
    Some(format!(
        "indexHint({exact}) AND intDiv(toUnixTimestamp64Micro(time), {width}) IN ({})",
        buckets.iter().map(i64::to_string).collect::<Vec<_>>().join(",")
    ))
}

/// NAN-4211: most bytes of SQL a candidate selection's row fence plus time
/// guard may add to one statement. chDB rejects a statement past its 256 KiB
/// `max_query_size`; the rest of the statement (projection, filters, tail)
/// keeps the remainder.
pub const MAX_FENCE_SQL_BYTES: usize = 192 * 1024;

/// NAN-4211: the bytes of SQL [`candidate_source`] would render for the row
/// fence and time guard over `candidates`, every file fenced (an upper bound:
/// files read whole drop their fence). `object_rows` names each file's row
/// count; a file it does not know is fenced as if its rows ended at its last
/// block. A selection with many sparse files (an entity index's exact runs
/// over one-row-group files) costs a `transform` entry per file plus its
/// keys, which `MAX_CANDIDATE_BLOCKS` alone does not bound.
pub fn candidate_fence_sql_bytes(candidates: &[CandidateBlock], object_rows: &dyn Fn(&str) -> Option<u64>) -> usize {
    let mut time_ranges = Some(Vec::with_capacity(candidates.len()));
    let fenced = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            match (candidate.time_range_us, time_ranges.as_mut()) {
                (Some(range), Some(ranges)) => ranges.push(range),
                _ => time_ranges = None,
            }
            FencedBlock {
                index,
                object_key: candidate.event_object_key.as_str(),
                object_rows: object_rows(&candidate.event_object_key).unwrap_or(candidate.row_end).max(candidate.row_end),
                row_start: candidate.row_start,
                row_end: candidate.row_end,
            }
        })
        .collect::<Vec<_>>();
    let set_fence = fence_set_enabled();
    let fence = row_fence_with(&fenced, set_fence, &mut |_, _| Ok(())).map_or(usize::MAX, |fence| fence.len());
    let guard = time_ranges.and_then(|ranges| time_guard_sql(ranges, set_fence)).map_or(0, |guard| guard.len());
    fence.saturating_add(guard)
}

fn candidate_source(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
    candidates: &[CandidateBlock],
    budget_enforcement: BudgetEnforcement,
    projection: Option<&str>,
) -> Result<(String, Vec<(String, String)>, QueryBudget)> {
    if candidates.len() > 4_096 {
        return Err(QueryPlanError::InvalidManifest(
            "candidate sidecar exceeded 4096 blocks".to_string(),
        ));
    }
    if tenant_is_bootstrap(tenant) {
        // No compacted object exists, so no candidate can name one; the
        // fenced source is the typed empty base, never the Iceberg table.
        if !candidates.is_empty() {
            return Err(QueryPlanError::InvalidManifest(
                "candidate object is outside the empty bootstrap generation".to_string(),
            ));
        }
        let (source, params) = bootstrap_base_source(tenant)?;
        let projection = projection.unwrap_or("*");
        return Ok((
            format!("(SELECT {projection} FROM {source} WHERE {EMPTY_GENERATION_BASE_GUARD})"),
            params,
            QueryBudget {
                candidate_objects: 0,
                estimated_scan_bytes: 0,
                max_query_bytes: tenant.max_query_bytes,
            },
        ));
    }
    let manifest_objects = manifest
        .objects
        .iter()
        .map(|object| (object.event_object_key.as_str(), object))
        .collect::<BTreeMap<_, _>>();
    let mut fenced = Vec::new();
    let mut params = Vec::new();
    let mut unique_objects = BTreeMap::new();
    let mut time_ranges = Some(Vec::with_capacity(candidates.len()));
    let whole = whole_file_candidates(tenant, &manifest_objects, candidates);
    for (index, candidate) in candidates.iter().enumerate() {
        let object = manifest_objects
            .get(candidate.event_object_key.as_str())
            .ok_or_else(|| {
                QueryPlanError::InvalidManifest(
                    "candidate object is outside the immutable manifest".to_string(),
                )
            })?;
        if candidate.event_object_bytes != object.event_object_bytes
            || candidate.row_start >= candidate.row_end
            || candidate.row_end > object.rows
        {
            return Err(QueryPlanError::InvalidManifest(
                "candidate block does not match its immutable object".to_string(),
            ));
        }
        unique_objects.insert(
            candidate.event_object_key.as_str(),
            candidate.event_object_bytes,
        );
        if whole.contains(candidate.event_object_key.as_str()) {
            // Read whole below: no per-row fence, no time guard.
            continue;
        }
        fenced.push(FencedBlock {
            index,
            object_key: candidate.event_object_key.as_str(),
            object_rows: object.rows,
            row_start: candidate.row_start,
            row_end: candidate.row_end,
        });
        match (candidate.time_range_us, time_ranges.as_mut()) {
            (Some(range), Some(ranges)) => ranges.push(range),
            _ => time_ranges = None,
        }
    }
    let set_fence = fence_set_enabled();
    let fence = (!fenced.is_empty())
        .then(|| row_fence(tenant, &fenced, set_fence, &mut params))
        .transpose()?;
    // A superset of the row-number fence (every kept row lies inside its
    // block's own time range), so results are unchanged; it only lets the
    // Parquet statistics filter skip unselected row groups.
    let time_guard = time_ranges.and_then(|ranges| time_guard_sql(ranges, set_fence));
    let estimated_scan_bytes = unique_objects.values().copied().sum::<u64>();
    if budget_enforcement == BudgetEnforcement::Reject
        && estimated_scan_bytes > tenant.max_query_bytes
    {
        return Err(QueryPlanError::BudgetRejected {
            estimated_bytes: estimated_scan_bytes,
            max_bytes: tenant.max_query_bytes,
        });
    }
    let (source, source_params) = if unique_objects.is_empty() {
        // A mandatory sidecar that matched nothing is a proof that no row can
        // come from the generation, and the predicate below is already constant
        // false. Handing chDB the whole Iceberg table anyway is what made an
        // empty result the most expensive thing the system could ask for —
        // measured at 1.0-2.9s against 0.12s for the same query shape returning
        // 17,000 rows. Name one object so the source keeps its schema.
        match newest_manifest_object(manifest) {
            Some(object) => {
                let (source, source_params) =
                    exact_parquet_source(tenant, &[object], "candidate_source")?;
                (source, Some(source_params))
            }
            None => (iceberg_source(tenant)?, None),
        }
    } else if !whole.is_empty() {
        // NAN-3149: a file whose every row group survived pruning is read
        // whole. Its `_path`/`_row_number` fence and time guard are
        // tautologies there, yet chDB evaluates them per row (and the OR of
        // per-file terms first): on a day of entity-pivot data with one row
        // group pruned that was ~3x the scan's CPU for identical rows. Only
        // files that kept a strict subset of their rows retain the exact
        // fence, in a separate branch over the same explicit read schema.
        let whole_uris = unique_objects.keys().copied().filter(|uri| whole.contains(uri)).collect::<Vec<_>>();
        let partial_uris = unique_objects.keys().copied().filter(|uri| !whole.contains(uri)).collect::<Vec<_>>();
        let projection = projection.unwrap_or("*");
        let (whole_source, whole_params) =
            exact_parquet_source(tenant, &whole_uris, "candidate_source")?;
        params.extend(whole_params);
        let mut branches = vec![format!("SELECT {projection} FROM {whole_source} WHERE {NON_EMPTY_BASE_GUARD}")];
        if !partial_uris.is_empty() {
            let (partial_source, partial_params) =
                exact_parquet_source(tenant, &partial_uris, "candidate_partial_source")?;
            params.extend(partial_params);
            let fence = fence.unwrap_or_else(|| "0".to_string());
            let predicate = match time_guard {
                Some(guard) => format!("({guard}) AND ({fence})"),
                None => fence,
            };
            branches.push(format!("SELECT {projection} FROM {partial_source} WHERE {predicate}"));
        }
        return Ok((
            format!("({})", branches.join(" UNION ALL ")),
            params,
            QueryBudget {
                candidate_objects: unique_objects.len(),
                estimated_scan_bytes,
                max_query_bytes: tenant.max_query_bytes,
            },
        ));
    } else {
        let object_uris = unique_objects.keys().copied().collect::<Vec<_>>();
        let (source, source_params) =
            exact_parquet_source(tenant, &object_uris, "candidate_source")?;
        (source, Some(source_params))
    };
    if let Some(source_params) = source_params {
        params.extend(source_params);
    }
    let predicate = match (fence, time_guard) {
        (None, _) => "0".to_string(),
        (Some(fence), Some(guard)) => format!("({guard}) AND ({fence})"),
        (Some(fence), None) => fence,
    };
    // Fuse the leaf projection with the row-range predicate: `_path` and
    // `_row_number` stay resolvable in the same select, and no `SELECT *`
    // layer is left between the Parquet read and the leaf (NAN-2374).
    let projection = projection.unwrap_or("*");
    Ok((
        format!("(SELECT {projection} FROM {source} WHERE {predicate})"),
        params,
        QueryBudget {
            candidate_objects: unique_objects.len(),
            estimated_scan_bytes,
            max_query_bytes: tenant.max_query_bytes,
        },
    ))
}

/// The newest object in the manifest, used as a schema carrier for a source that
/// is fenced to zero rows. Newest because additive schema evolution means it
/// holds the most complete physical schema.
fn newest_manifest_object(manifest: &SourceManifest) -> Option<&str> {
    manifest
        .objects
        .iter()
        .map(|object| object.event_object_key.as_str())
        .max_by_key(|key| (object_path_event_hour(key), *key))
}

fn exact_parquet_source(
    tenant: &TenantQueryConfig,
    object_uris: &[&str],
    parameter: &str,
) -> Result<(String, Vec<(String, String)>)> {
    if object_uris.is_empty()
        || object_uris.len() > 4_096
        || parameter.is_empty()
        || !parameter
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(QueryPlanError::InvalidManifest(
            "exact Parquet source violates its object or parameter bound".to_string(),
        ));
    }
    if let Some(cache) = &tenant.snapshot_cache {
        let cached = object_uris
            .iter()
            .map(|uri| cache.objects.get(*uri))
            .collect::<Option<Vec<_>>>();
        if let Some(cached) = cached {
            let mut paths = cached
                .into_iter()
                .map(|object| {
                    object.path.to_str().map(ToOwned::to_owned).ok_or_else(|| {
                        QueryPlanError::InvalidManifest(
                            "snapshot cache path is not UTF-8".to_string(),
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            if paths.iter().any(|path| {
                path.chars()
                    .any(|character| matches!(character, '{' | '}' | ',') || character.is_control())
            }) {
                return Err(QueryPlanError::InvalidManifest(
                    "snapshot cache path contains an unsupported character".to_string(),
                ));
            }
            let source = local_path_spec(&mut paths)?;
            let mut params = vec![(parameter.to_string(), source)];
            let table = if let Some(schema) = cache.read_schema.as_ref() {
                let schema_parameter = format!("{parameter}_read_schema");
                params.push((schema_parameter.clone(), schema.clone()));
                format!("file({{{parameter}:String}}, Parquet, {{{schema_parameter}:String}})")
            } else {
                format!("file({{{parameter}:String}}, Parquet)")
            };
            return Ok((table, params));
        }
    }
    let mut assigned_table = None;
    let mut relative_paths = Vec::with_capacity(object_uris.len());
    for uri in object_uris {
        let remainder = uri.strip_prefix("s3://").ok_or_else(|| {
            QueryPlanError::InvalidManifest("exact Parquet object is not an S3 URI".to_string())
        })?;
        let (table, relative) = remainder.split_once("/data/").ok_or_else(|| {
            QueryPlanError::InvalidManifest(
                "exact Parquet object is outside an Iceberg data directory".to_string(),
            )
        })?;
        if assigned_table
            .replace(table)
            .is_some_and(|prior| prior != table)
            || relative.is_empty()
            || !relative
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.=".contains(&byte))
        {
            return Err(QueryPlanError::InvalidManifest(
                "exact Parquet objects cross a table or contain an unsupported path".to_string(),
            ));
        }
        relative_paths.push(format!("data/{relative}"));
    }
    let assigned_table = assigned_table.expect("non-empty object list");
    if !tenant
        .source
        .trim_end_matches('/')
        .ends_with(assigned_table)
    {
        return Err(QueryPlanError::InvalidManifest(
            "exact Parquet endpoint differs from the assigned table".to_string(),
        ));
    }
    let object_spec = if relative_paths.len() == 1 {
        relative_paths.remove(0)
    } else {
        format!("{{{}}}", relative_paths.join(","))
    };
    let source = format!("{}/{}", tenant.source.trim_end_matches('/'), object_spec);
    let arguments = match &tenant.credentials {
        ObjectStoreCredentials::DefaultChain => format!("{{{parameter}:String}}"),
        ObjectStoreCredentials::Static {
            session_token: Some(_),
            ..
        } => format!(
            "{{{parameter}:String}}, {{iceberg_access_key:String}}, {{iceberg_secret_key:String}}, {{iceberg_session_token:String}}"
        ),
        ObjectStoreCredentials::Static { .. } => format!(
            "{{{parameter}:String}}, {{iceberg_access_key:String}}, {{iceberg_secret_key:String}}"
        ),
    };
    let mut params = vec![(parameter.to_string(), source)];
    let table = if let Some(schema) = tenant
        .snapshot_cache
        .as_ref()
        .and_then(|cache| cache.read_schema.as_ref())
    {
        let schema_parameter = format!("{parameter}_read_schema");
        params.push((schema_parameter.clone(), schema.clone()));
        format!("s3({arguments}, Parquet, {{{schema_parameter}:String}})")
    } else {
        format!("s3({arguments}, Parquet)")
    };
    Ok((table, params))
}

pub fn local_path_spec(paths: &mut Vec<String>) -> Result<String> {
    if paths.is_empty() {
        return Err(QueryPlanError::InvalidManifest(
            "snapshot cache path set is empty".to_string(),
        ));
    }
    paths.sort();
    if paths.len() == 1 {
        return Ok(paths.remove(0));
    }
    let path_values = paths.iter().map(PathBuf::from).collect::<Vec<_>>();
    let mut root = path_values[0].parent().ok_or_else(|| {
        QueryPlanError::InvalidManifest("snapshot cache path has no parent".to_string())
    })?;
    while !path_values.iter().all(|path| path.starts_with(root)) {
        root = root.parent().ok_or_else(|| {
            QueryPlanError::InvalidManifest(
                "snapshot cache paths have no common directory".to_string(),
            )
        })?;
    }
    let root = root.to_str().ok_or_else(|| {
        QueryPlanError::InvalidManifest("snapshot cache root is not UTF-8".to_string())
    })?;
    let relatives = path_values
        .iter()
        .map(|path| {
            path.strip_prefix(root)
                .ok()
                .and_then(|path| path.to_str())
                .filter(|path| !path.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    QueryPlanError::InvalidManifest(
                        "snapshot cache relative path is invalid".to_string(),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(format!("{root}/{{{}}}", relatives.join(",")))
}

fn candidate_virtual_path(tenant: &TenantQueryConfig, source: &str) -> Result<String> {
    if let Some(path) = tenant
        .snapshot_cache
        .as_ref()
        .and_then(|cache| cache.objects.get(source))
        .map(|object| &object.path)
    {
        return path.to_str().map(ToOwned::to_owned).ok_or_else(|| {
            QueryPlanError::InvalidManifest("snapshot cache path is not UTF-8".to_string())
        });
    }
    iceberg_virtual_path(source)
}

fn iceberg_virtual_path(source: &str) -> Result<String> {
    let remainder = source.strip_prefix("s3://").ok_or_else(|| {
        QueryPlanError::InvalidManifest("candidate object is not an S3 URI".to_string())
    })?;
    let (bucket, key) = remainder.split_once('/').ok_or_else(|| {
        QueryPlanError::InvalidManifest("candidate S3 object has no key".to_string())
    })?;
    if bucket.is_empty()
        || key.is_empty()
        || remainder.contains('@')
        || remainder.contains('?')
        || remainder.contains('#')
    {
        return Err(QueryPlanError::InvalidManifest(
            "candidate S3 object URI is invalid".to_string(),
        ));
    }
    Ok(format!("{bucket}/{key}"))
}

pub fn validate_tenant(tenant: &TenantQueryConfig) -> Result<()> {
    if tenant.tenant_id.trim().is_empty()
        || tenant.source.trim().is_empty()
        || tenant.max_query_bytes == 0
        || !(MIN_QUERY_MEMORY_BYTES..=MAX_QUERY_MEMORY_BYTES).contains(&tenant.max_memory_bytes)
        || tenant.max_execution_seconds == 0
        || tenant.threads == 0
    {
        return Err(QueryPlanError::InvalidTenantConfig(
            "required tenant query values must be non-empty".to_string(),
        ));
    }
    if let ObjectStoreCredentials::Static {
        access_key,
        secret_key,
        session_token,
    } = &tenant.credentials
    {
        if access_key.is_empty()
            || secret_key.is_empty()
            || session_token.as_deref().is_some_and(str::is_empty)
        {
            return Err(QueryPlanError::InvalidTenantConfig(
                "static object-store credentials must be non-empty".to_string(),
            ));
        }
    }
    if tenant.iceberg_metadata_file_path.is_empty()
        || !tenant
            .iceberg_metadata_file_path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
    {
        return Err(QueryPlanError::InvalidTenantConfig(
            "Iceberg metadata path contains an unsupported character".to_string(),
        ));
    }
    Ok(())
}

fn extend_available_with_tail_contract(
    available: &mut BTreeSet<String>,
    tail: &HotTailManifest,
) -> Result<()> {
    if tail.objects.is_empty() {
        return Ok(());
    }
    match (&tail.read_schema, tail.available_paths.is_empty()) {
        (None, true) => return Ok(()),
        (Some(schema), false)
            if !schema.is_empty()
                && schema.len() <= 1_048_576
                && !schema.chars().any(char::is_control)
                && tail.available_paths.len() <= 100_000 => {}
        _ => {
            return Err(QueryPlanError::InvalidManifest(
                "hot-tail read contract is incomplete or invalid".to_string(),
            ));
        }
    }
    let mut tail_available = BTreeSet::new();
    for path in &tail.available_paths {
        insert_addressable_path(&mut tail_available, path)?;
    }
    if !available.is_subset(&tail_available) {
        return Err(QueryPlanError::InvalidManifest(
            "hot-tail catalog schema is not an additive superset of the active generation"
                .to_string(),
        ));
    }
    available.extend(tail_available);
    Ok(())
}

fn tenant_with_tail_read_contract(
    tenant: &TenantQueryConfig,
    tail: Option<&HotTailManifest>,
    available: &mut BTreeSet<String>,
) -> Result<TenantQueryConfig> {
    let mut source_tenant = tenant.clone();
    let Some(tail) = tail.filter(|tail| !tail.objects.is_empty()) else {
        return Ok(source_tenant);
    };
    let previous = available.clone();
    extend_available_with_tail_contract(available, tail)?;
    let Some(read_schema) = tail.read_schema.as_ref() else {
        return Ok(source_tenant);
    };
    if let Some(cache) = source_tenant.snapshot_cache.as_mut() {
        // Even when the path inventory is unchanged, use identical physical
        // types/order for the base and tail (including nested Tuple leaves).
        cache.read_schema = Some(read_schema.clone());
    } else if available != &previous {
        return Err(QueryPlanError::InvalidTenantConfig(
            "additive hot-tail schemas require the explicit snapshot cache source".to_string(),
        ));
    }
    Ok(source_tenant)
}

fn validate_manifest(
    tenant: &TenantQueryConfig,
    manifest: &SourceManifest,
) -> Result<(BTreeSet<String>, QueryBudget)> {
    if manifest.tenant_id != tenant.tenant_id {
        return Err(QueryPlanError::TenantMismatch);
    }
    if tenant_is_bootstrap(tenant) {
        // The empty Iceberg side is a proof, not a gap: the manifest must be
        // empty too, and the budget it contributes is zero.
        if !manifest.objects.is_empty() {
            return Err(QueryPlanError::InvalidManifest(
                "bootstrap generation manifest must be empty".to_string(),
            ));
        }
        return Ok((
            manifest.bootstrap_available_paths.clone(),
            QueryBudget {
                candidate_objects: 0,
                estimated_scan_bytes: 0,
                max_query_bytes: tenant.max_query_bytes,
            },
        ));
    }
    if manifest.objects.is_empty() {
        return Err(QueryPlanError::EmptyManifest);
    }
    if tenant.snapshot_cache.as_ref().is_some_and(|cache| {
        cache.source_spec.is_empty()
            || cache.objects.len() != manifest.objects.len()
            || cache.bytes == 0
    }) {
        return Err(QueryPlanError::InvalidManifest(
            "snapshot cache cardinality or byte fence is invalid".to_string(),
        ));
    }
    let facts = manifest.facts()?;
    // Only the tenant-dependent half runs per request: one lookup per object
    // against this caller's snapshot cache, not a walk of every field in every
    // object.
    if let Some(cache) = &tenant.snapshot_cache {
        for object in &manifest.objects {
            let cached = cache.objects.get(&object.event_object_key).ok_or_else(|| {
                QueryPlanError::InvalidManifest(
                    "snapshot cache omits an immutable event object".to_string(),
                )
            })?;
            if cached.version_id != object.event_object_version
                || cached.bytes != object.event_object_bytes
                || !cached.path.is_absolute()
            {
                return Err(QueryPlanError::InvalidManifest(
                    "snapshot cache object identity differs from the serving manifest".to_string(),
                ));
            }
        }
        if cache.bytes != facts.estimated_bytes {
            return Err(QueryPlanError::InvalidManifest(
                "snapshot cache byte total differs from the serving manifest".to_string(),
            ));
        }
    }
    Ok((
        facts.available_paths.clone(),
        QueryBudget {
            candidate_objects: manifest.objects.len(),
            estimated_scan_bytes: facts.estimated_bytes,
            max_query_bytes: tenant.max_query_bytes,
        },
    ))
}

/// The merged field types of an immutable manifest, computed once per
/// generation and cloned per caller. The map is small (one entry per distinct
/// leaf); it was building it that cost, not holding it.
pub fn snapshot_field_types(manifest: &SourceManifest) -> Result<BTreeMap<String, String>> {
    if manifest.objects.is_empty() && !manifest.bootstrap_field_types.is_empty() {
        return Ok(manifest.bootstrap_field_types.clone());
    }
    Ok(manifest.facts()?.field_types.clone())
}

fn validate_compiler_output(compiled: &CompiledQuery) -> Result<()> {
    if compiled.schema_version != 1
        || compiled.profile != "ocsf"
        || compiled.dataset != "logs"
        || compiled.source_placeholder != LOG_SOURCE_PLACEHOLDER
        || compiled.sql.matches(LOG_SOURCE_PLACEHOLDER).count() == 0
        || compiled.query_sha256.len() != 64
        || !compiled
            .query_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || contains_statement_separator(&compiled.sql)
    {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "compiler identity, source binding, query digest, or statement shape failed"
                .to_string(),
        ));
    }
    reject_non_read_statement(&compiled.sql)?;
    Ok(())
}

/// Read-only allow-list applied to the pinned compiler's SQL AFTER it is
/// trusted for identity and shape (NAN-2361). The compiler is a pinned binary
/// whose digest is part of the generation identity, but a defect in it must
/// not become `s3()`/`url()`/`remote()` reach with the Pod's bucket
/// credentials, nor DML/DDL against the embedded engine. The worker itself
/// binds every source (`file()`/`s3()` over the placeholder) after this check,
/// so compiler output must contain no table function at all.
///
/// Quoted regions (`'…'`, `"…"`, `` `…` ``) are blanked before scanning so a
/// literal or a quoted identifier can neither trigger nor hide a keyword.
fn reject_non_read_statement(sql: &str) -> Result<()> {
    // Comments are never part of compiler output. A quote inside a comment
    // would desynchronise the quote scanner below, and a trailing `--` would
    // swallow the `SETTINGS readonly=2` the executor appends.
    if let Some(marker) = sql_comment_marker(sql) {
        return Err(QueryPlanError::InvalidCompilerOutput(format!(
            "compiled statement carries a comment ({marker})"
        )));
    }
    // ClickHouse accepts a quoted identifier as a function name, so
    // `` `url`('…') `` / `"s3"(…)` would survive the blanked scan below.
    if quoted_identifier_call(sql) {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "compiled statement calls a function through a quoted identifier".to_string(),
        ));
    }
    let unquoted = blank_quoted_regions(sql);
    let mut tokens = unquoted
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty());
    let leading = tokens.next().map(str::to_ascii_uppercase);
    if !matches!(leading.as_deref(), Some("SELECT" | "WITH")) {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "compiled statement is not a SELECT".to_string(),
        ));
    }
    if let Some(keyword) = forbidden_statement_keyword(&unquoted) {
        return Err(QueryPlanError::InvalidCompilerOutput(format!(
            "compiled statement carries a write or control keyword ({keyword})"
        )));
    }
    if let Some(function) = table_function_call(&unquoted) {
        return Err(QueryPlanError::InvalidCompilerOutput(format!(
            "compiled statement calls the table function {function}()"
        )));
    }
    Ok(())
}

/// The table placeholder an operator SQL probe's statement reads (NAN-3715);
/// the planner binds it to the verified part files exactly as it binds the
/// compiler's.
pub const PROBE_SOURCE_PLACEHOLDER: &str = LOG_SOURCE_PLACEHOLDER;

/// Longest operator SQL probe statement (NAN-3715).
pub const MAX_PROBE_SQL_BYTES: usize = 64 * 1024;

/// Bare tokens a probe statement may not carry beyond the compiler-output
/// rules: its own `SETTINGS` (limits come from the planner, extra settings
/// only from the probe's allowlist), output redirection, and formats.
const PROBE_FORBIDDEN_TOKENS: &[&str] = &["SETTINGS", "OUTFILE", "INFILE", "FORMAT", "COMPRESSION"];

/// NAN-3715: validate an operator's hand-written statement for the SQL probe.
/// It is held to the engine's own compiler-output rules
/// ([`reject_non_read_statement`]: SELECT/WITH only, no write or control
/// keyword, no table function, no comment, no quoted-identifier call; one
/// statement) and, beyond them, must read [`PROBE_SOURCE_PLACEHOLDER`], may
/// not name a `system.` table, and may not carry the tokens in
/// [`PROBE_FORBIDDEN_TOKENS`]. The planner then validates it again as
/// compiler output when it binds the source.
pub fn validate_probe_sql(sql: &str) -> Result<()> {
    let refuse = |why: &str| Err(QueryPlanError::InvalidCompilerOutput(format!("probe SQL refused: {why}")));
    if sql.len() > MAX_PROBE_SQL_BYTES {
        return refuse("longer than the probe limit");
    }
    if sql.matches(PROBE_SOURCE_PLACEHOLDER).count() == 0 {
        return refuse("it must read the source placeholder __nano_lake_source__");
    }
    if contains_statement_separator(sql) {
        return refuse("more than one statement");
    }
    reject_non_read_statement(sql)?;
    // Raw text, so a quoted `"system"."x"` is caught too (a literal that
    // merely looks like one is refused as well; rename it).
    static SYSTEM_TABLE: OnceLock<Regex> = OnceLock::new();
    if SYSTEM_TABLE.get_or_init(|| Regex::new(r#"(?i)(?:^|[^.\w"`])["`]?system["`]?\s*\."#).expect("static regex")).is_match(sql) {
        return refuse("it names a system table");
    }
    let unquoted = blank_quoted_regions(sql);
    let bytes = unquoted.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
                index += 1;
            }
            let qualified = start > 0 && bytes[start - 1] == b'.';
            let token = unquoted[start..index].to_ascii_uppercase();
            if !qualified && PROBE_FORBIDDEN_TOKENS.contains(&token.as_str()) {
                return refuse(&format!("it carries {token}"));
            }
        } else if byte.is_ascii_digit() {
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'.') {
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    Ok(())
}

/// Statement keywords that never appear in a compiled read query outside a
/// quoted region. `SETTINGS`/`SET` differ as whole tokens, so query-level
/// settings clauses are unaffected.
const FORBIDDEN_STATEMENT_KEYWORDS: &[&str] = &[
    "INSERT", "CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME", "ATTACH", "DETACH", "OPTIMIZE",
    "SYSTEM", "KILL", "GRANT", "REVOKE", "EXCHANGE", "UNDROP", "BACKUP", "RESTORE", "DELETE",
    "UPDATE", "SET", "SHOW", "DESCRIBE", "EXPLAIN",
];

/// First bare token (not the member of a dotted path such as `ext.update`)
/// that is a forbidden statement keyword, upper-cased.
fn forbidden_statement_keyword(unquoted: &str) -> Option<String> {
    let bytes = unquoted.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
                index += 1;
            }
            let qualified = start > 0 && bytes[start - 1] == b'.';
            if !qualified {
                let upper = unquoted[start..index].to_ascii_uppercase();
                if FORBIDDEN_STATEMENT_KEYWORDS.contains(&upper.as_str()) {
                    return Some(upper);
                }
            }
        } else if byte.is_ascii_digit() {
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'.') {
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    None
}

/// Table functions the pinned compiler must never emit: anything that reads
/// external or process-local storage, another server, or the engine itself.
/// Names with a legitimate scalar homonym (`format`) are deliberately absent;
/// the remaining names have no scalar form in ClickHouse.
const FORBIDDEN_TABLE_FUNCTIONS: &[&str] = &[
    "s3", "s3cluster", "s3queue", "gcs", "oss", "cosn", "hdfs", "hdfscluster", "azure",
    "azureblobstorage", "azureblobstoragecluster", "url", "urlcluster", "file", "filecluster",
    "remote", "remotesecure", "cluster", "clusterallreplicas", "mysql", "postgresql", "mongodb",
    "redis", "sqlite", "jdbc", "odbc", "iceberg", "icebergs3", "icebergs3cluster",
    "iceberglocal", "icebergazure", "iceberghdfs", "deltalake", "deltalakes3",
    "deltalakecluster", "hudi", "hudicluster", "executable", "dictionary", "input", "values",
    "view", "merge", "null", "numbers", "numbers_mt", "zeros", "zeros_mt", "generaterandom",
    "generate_series", "generateseries", "fuzzjson", "fuzzquery", "loop", "mergetreeindex",
    "mergetreeprojection", "timeseriesdata", "timeseriestags", "timeseriesmetrics",
    "ytsaurus", "arrowflight", "kafka", "paimon", "paimons3", "paimoncluster",
];

/// First identifier that is immediately followed by `(` (whitespace allowed)
/// and names a forbidden table function, case-insensitively.
fn table_function_call(unquoted: &str) -> Option<String> {
    let bytes = unquoted.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
                index += 1;
            }
            // `a.b(` is a qualified name; a preceding `.` means this token is
            // not a bare function name.
            let qualified = start > 0 && bytes[start - 1] == b'.';
            let mut after = index;
            while after < bytes.len() && bytes[after].is_ascii_whitespace() {
                after += 1;
            }
            if !qualified && after < bytes.len() && bytes[after] == b'(' {
                let name = unquoted[start..index].to_ascii_lowercase();
                if FORBIDDEN_TABLE_FUNCTIONS.contains(&name.as_str()) {
                    return Some(unquoted[start..index].to_string());
                }
            }
        } else if byte.is_ascii_digit() {
            // Skip numeric literals (including `1e5`) so their letters do not
            // start an identifier.
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'.') {
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    None
}

/// Quote-aware scan for a closing `"`/`` ` `` followed by optional whitespace
/// and `(`: a function call through a quoted identifier. Single-quoted
/// strings cannot name a function and are only tracked for quote state.
fn quoted_identifier_call(sql: &str) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut chars = sql.chars().peekable();
    while let Some(character) = chars.next() {
        match quote {
            None if matches!(character, '\'' | '"' | '`') => quote = Some(character),
            None => {}
            Some('\'') if escaped => escaped = false,
            Some('\'') if character == '\\' => escaped = true,
            Some(delimiter) if character == delimiter => {
                if chars.peek() == Some(&delimiter) {
                    chars.next();
                    continue;
                }
                quote = None;
                if delimiter != '\'' {
                    let mut lookahead = chars.clone();
                    while let Some(next) = lookahead.peek() {
                        if next.is_ascii_whitespace() {
                            lookahead.next();
                        } else {
                            break;
                        }
                    }
                    if lookahead.peek() == Some(&'(') {
                        return true;
                    }
                }
            }
            Some(_) => {}
        }
    }
    false
}

/// First SQL comment marker (`--`, `#`, `/*`) outside a quoted region.
fn sql_comment_marker(sql: &str) -> Option<&'static str> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut chars = sql.chars().peekable();
    while let Some(character) = chars.next() {
        match quote {
            None if matches!(character, '\'' | '"' | '`') => quote = Some(character),
            None if character == '-' && chars.peek() == Some(&'-') => return Some("--"),
            None if character == '#' => return Some("#"),
            None if character == '/' && chars.peek() == Some(&'*') => return Some("/*"),
            None => {}
            Some('\'') if escaped => escaped = false,
            Some('\'') if character == '\\' => escaped = true,
            Some(delimiter) if character == delimiter => {
                if chars.peek() == Some(&delimiter) {
                    chars.next();
                } else {
                    quote = None;
                }
            }
            Some(_) => {}
        }
    }
    None
}

/// Replace every quoted region with a single space so keyword and function
/// scans see only structural SQL. Mirrors the quoting rules of
/// [`contains_statement_separator`]: `''`/`""`/` `` ` doubling and backslash
/// escapes inside single quotes.
fn blank_quoted_regions(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut chars = sql.chars().peekable();
    while let Some(character) = chars.next() {
        match quote {
            None if matches!(character, '\'' | '"' | '`') => {
                quote = Some(character);
                out.push(' ');
            }
            None => out.push(character),
            Some('\'') if escaped => escaped = false,
            Some('\'') if character == '\\' => escaped = true,
            Some(delimiter) if character == delimiter => {
                if chars.peek() == Some(&delimiter) {
                    chars.next();
                } else {
                    quote = None;
                }
            }
            Some(_) => {}
        }
    }
    out
}

fn required_columns(compiled: &CompiledQuery) -> Result<BTreeMap<String, String>> {
    let mut required = BTreeMap::new();
    for column in &compiled.required_columns {
        validate_path(&column.name)?;
        default_expression(&column.field_type)?;
        if let Some(prior) = required.insert(column.name.clone(), column.field_type.clone()) {
            if prior != column.field_type {
                return Err(QueryPlanError::InvalidCompilerOutput(
                    "required column has conflicting types".to_string(),
                ));
            }
        }
    }
    if required.is_empty() {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "required column projection is empty".to_string(),
        ));
    }
    Ok(required)
}

fn iceberg_source(tenant: &TenantQueryConfig) -> Result<String> {
    let arguments = match &tenant.credentials {
        ObjectStoreCredentials::DefaultChain => "{source:String}",
        ObjectStoreCredentials::Static {
            session_token: Some(_),
            ..
        } => {
            "{source:String}, {iceberg_access_key:String}, {iceberg_secret_key:String}, {iceberg_session_token:String}"
        }
        ObjectStoreCredentials::Static { .. } => {
            "{source:String}, {iceberg_access_key:String}, {iceberg_secret_key:String}"
        }
    };
    Ok(format!(
        "icebergS3({arguments}, SETTINGS iceberg_metadata_file_path='{}')",
        tenant.iceberg_metadata_file_path
    ))
}

/// NAN-2361: narrow the snapshot-cache source to the objects whose `event_hour=`
/// partition can overlap the query window.
///
/// WHY THIS EXISTS. `cache.source_spec` is a single brace-glob naming EVERY
/// object in the generation. chDB must open and footer-check each one to prune
/// it, because the time bound reaches it only as a `WHERE` clause. Measured on a
/// 689-object generation: a query whose window overlaps ZERO objects and scans
/// ZERO rows still cost 0.569s, and the cost tracked the glob size at roughly
/// 1ms per object. That is a per-query tax proportional to the size of the whole
/// table — so it grew with retention, not with what the query asked for. At the
/// 50-100 GB/day design target with 365-day retention it extrapolates to tens of
/// seconds on every query.
///
/// The overlap set was already being computed for budget accounting
/// (`time_scoped_manifest_budget`); it simply was never handed to chDB. The hot
/// tail has always pruned this way (`CountAggregateSource::HotTail` retains on
/// the same predicate) — this brings the base snapshot in line with it.
///
/// SAFETY. Pruning uses `object_path_overlaps_window`, which is deliberately
/// conservative: an object whose path carries no trusted `event_hour=` segment
/// counts as overlapping every window and is always retained. Returning `None`
/// falls back to the full generation spec, so every failure mode is "read more
/// than necessary", never "read less". Correctness cannot regress; only cost.
/// What window pruning proved about the base snapshot for one query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BaseWindowOverlap {
    /// At least one object overlaps the window, or there was no usable window.
    Possible,
    /// No object can contribute a row. `object_path_overlaps_window` keeps every
    /// path whose `event_hour=` segment is missing or unparseable, so an empty
    /// overlap set means every object carried a trusted hour and all of them
    /// fell outside the window — a proof, not a guess.
    ProvenEmpty,
    /// NAN-2361 wave 8: the bootstrap generation has no object at all. The
    /// base is a typed empty relation without `_path`, so its guard is a
    /// plain constant-false predicate.
    EmptyGeneration,
}

fn scoped_snapshot_source_spec(
    cache: &SnapshotCache,
    window: Option<ObjectTimeWindow>,
) -> (Option<String>, BaseWindowOverlap) {
    let Some(window) = window else {
        return (None, BaseWindowOverlap::Possible);
    };
    let mut paths = cache
        .objects
        .values()
        .filter_map(|object| object.path.to_str())
        .filter(|path| object_path_overlaps_window(path, window))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    // Nothing in this window. Naming the whole generation here and letting the
    // time filter discard every row is what made a "last 5 minutes" search cost
    // several times a "last hour" search: the newest hour is still in the hot
    // tail, so the base overlap is empty and the fallback re-globbed the entire
    // table. Name one object so the source keeps its schema and let the caller
    // fence it to zero rows.
    if paths.is_empty() {
        // Name the newest object specifically: under additive schema evolution
        // it carries the most complete physical schema, so a deployment without
        // an explicit read schema still resolves every projected column.
        let mut newest = cache
            .objects
            .values()
            .filter_map(|object| object.path.to_str())
            .max_by_key(|path| (object_path_event_hour(path), *path))
            .map(ToOwned::to_owned)
            .into_iter()
            .collect::<Vec<_>>();
        return match local_path_spec(&mut newest) {
            Ok(spec) => (Some(spec), BaseWindowOverlap::ProvenEmpty),
            // Without a nameable object, fall back to the full generation: it
            // reads too much, which is a cost bug, never a missing event.
            Err(_) => (None, BaseWindowOverlap::Possible),
        };
    }
    // Nothing was pruned — keep the precomputed spec instead of rebuilding an
    // identical (and very large) string on every query.
    if paths.len() == cache.objects.len() {
        return (None, BaseWindowOverlap::Possible);
    }
    (
        local_path_spec(&mut paths).ok(),
        BaseWindowOverlap::Possible,
    )
}

/// NAN-2361 wave 8: true when the tenant serves the zero-snapshot bootstrap
/// generation (no compacted Iceberg objects; hot tail only).
pub fn tenant_is_bootstrap(tenant: &TenantQueryConfig) -> bool {
    tenant
        .snapshot_cache
        .as_ref()
        .is_some_and(|cache| cache.bootstrap)
}

/// The base relation of the bootstrap generation: zero rows in the exact
/// catalog column shape (`null(<structure>)` is ClickHouse's typed empty table
/// function). It carries no `_path` virtual column, so the caller fences it
/// with a constant-false guard instead of the object-path guard.
fn bootstrap_base_source(tenant: &TenantQueryConfig) -> Result<(String, Vec<(String, String)>)> {
    let cache = tenant.snapshot_cache.as_ref().filter(|cache| cache.bootstrap).ok_or_else(|| {
        QueryPlanError::InvalidTenantConfig("bootstrap base requires the bootstrap cache".to_string())
    })?;
    let schema = cache.read_schema.as_deref().filter(|schema| !schema.is_empty()).ok_or_else(|| {
        QueryPlanError::InvalidTenantConfig(
            "bootstrap generation requires the catalog read schema".to_string(),
        )
    })?;
    Ok((
        "null({snapshot_cache_read_schema:String})".to_string(),
        vec![("snapshot_cache_read_schema".to_string(), schema.to_string())],
    ))
}

fn base_snapshot_source(tenant: &TenantQueryConfig) -> Result<(String, Vec<(String, String)>)> {
    base_snapshot_source_for_window(tenant, None).map(|(source, params, _)| (source, params))
}

/// The predicate that fences a base source the window proved cannot match.
/// `_path` is never empty for a real object, so this is a constant-false guard
/// with the same shape as the normal one.
const PROVEN_EMPTY_BASE_GUARD: &str = "_path = ''";
const NON_EMPTY_BASE_GUARD: &str = "_path != ''";
const EMPTY_GENERATION_BASE_GUARD: &str = "1 = 0";

fn base_window_guard(overlap: BaseWindowOverlap) -> &'static str {
    match overlap {
        BaseWindowOverlap::Possible => NON_EMPTY_BASE_GUARD,
        BaseWindowOverlap::ProvenEmpty => PROVEN_EMPTY_BASE_GUARD,
        BaseWindowOverlap::EmptyGeneration => EMPTY_GENERATION_BASE_GUARD,
    }
}

fn base_snapshot_source_for_window(
    tenant: &TenantQueryConfig,
    window: Option<ObjectTimeWindow>,
) -> Result<(String, Vec<(String, String)>, BaseWindowOverlap)> {
    if tenant_is_bootstrap(tenant) {
        let (source, params) = bootstrap_base_source(tenant)?;
        return Ok((source, params, BaseWindowOverlap::EmptyGeneration));
    }
    if let Some(cache) = &tenant.snapshot_cache {
        if cache.source_spec.is_empty()
            || cache.source_spec.chars().any(char::is_control)
            || cache.objects.is_empty()
            || cache.bytes == 0
        {
            return Err(QueryPlanError::InvalidTenantConfig(
                "snapshot cache source is empty or invalid".to_string(),
            ));
        }
        let (scoped_spec, overlap) = scoped_snapshot_source_spec(cache, window);
        let source_spec = scoped_spec.unwrap_or_else(|| cache.source_spec.clone());
        let mut params = vec![("snapshot_cache_source".to_string(), source_spec)];
        let table = if let Some(schema) = cache.read_schema.as_ref() {
            params.push(("snapshot_cache_read_schema".to_string(), schema.clone()));
            "file({snapshot_cache_source:String}, Parquet, {snapshot_cache_read_schema:String})"
                .to_string()
        } else {
            "file({snapshot_cache_source:String}, Parquet)".to_string()
        };
        return Ok((table, params, overlap));
    }
    Ok((
        iceberg_source(tenant)?,
        Vec::new(),
        BaseWindowOverlap::Possible,
    ))
}

/// Resolve the trusted, credential-bound Iceberg table used by fixed worker
/// routes such as prevalence facets. Request data never controls these storage
/// coordinates.
pub fn trusted_iceberg_source(
    tenant: &TenantQueryConfig,
) -> Result<(String, Vec<(String, String)>)> {
    validate_tenant(tenant)?;
    let (base, base_params) = base_snapshot_source(tenant)?;
    let source = format!("(SELECT * FROM {base} WHERE _path != '')");
    let mut params = object_store_params(tenant);
    params.extend(base_params);
    Ok((source, params))
}

fn object_store_params(tenant: &TenantQueryConfig) -> Vec<(String, String)> {
    let mut params = vec![("source".to_string(), tenant.source.clone())];
    if let ObjectStoreCredentials::Static {
        access_key,
        secret_key,
        session_token,
    } = &tenant.credentials
    {
        params.push(("iceberg_access_key".to_string(), access_key.clone()));
        params.push(("iceberg_secret_key".to_string(), secret_key.clone()));
        if let Some(token) = session_token {
            params.push(("iceberg_session_token".to_string(), token.clone()));
        }
    }
    params
}

fn native_event_source(
    sql: &str,
    source: &str,
    required: &BTreeMap<String, String>,
    missing: &BTreeMap<String, String>,
) -> Result<(String, BTreeMap<String, String>)> {
    let mut aliases = BTreeMap::new();
    let mut additions = Vec::new();
    for (name, field_type) in required.iter().chain(missing.iter()) {
        if aliases.contains_key(name) {
            continue;
        }
        let quoted = quoted_identifier(name)?;
        let double_quoted = double_quoted_identifier(name);
        if missing.contains_key(name) && !name.contains('.') {
            // NAN-2982: the compiler names top-level columns bare (a bare
            // keyword reads `lower(message)`), so the quoted-form rewrite
            // below never sees them. A column the source lacks cannot clash
            // with `SELECT *`, so its typed default takes the column's own
            // name; recording it as a temporary alias strips it from the
            // event rows, which never carried it.
            additions.push(format!("{} AS {quoted}", missing_expression(name, field_type)?));
            aliases.insert(name.clone(), name.clone());
            continue;
        }
        if !sql.contains(&quoted) && !sql.contains(&double_quoted) {
            continue;
        }
        let alias = format!("__nano_path_{}", aliases.len());
        let expression = if missing.contains_key(name) {
            missing_expression(name, field_type)?.to_string()
        } else if native_leaf_reads_as_subcolumn(name) {
            nested_projection(name)?
        } else {
            nested_expression(name)?
        };
        additions.push(format!("{expression} AS {alias}"));
        aliases.insert(name.clone(), alias);
    }
    let replacement = if additions.is_empty() {
        source.to_string()
    } else {
        format!("(SELECT *, {} FROM {source})", additions.join(", "))
    };
    Ok((replacement, aliases))
}

/// A leaf two or more Tuple levels below a full-row root is read as a storage
/// subcolumn (`` `http_request`.`url`.`path` ``), not as nested
/// `tupleElement(tupleElement(http_request, 'url'), 'path')`.
///
/// dns_over_https: the full-row pipeline `where url.url_string … OR … | where
/// … | where url.path …` projects the whole `http_request` root and filters
/// on two of its grandchildren in separate stages. chDB's filter merge +
/// move-to-prewhere then pushes the nested tupleElement onto the read step,
/// whose header carries only the parent root, and the query dies with
/// `Not found column tupleElement(http_request, 'url') in block`
/// (NOT_FOUND_COLUMN_IN_BLOCK, the NAN-2374 family). The subcolumn form reads
/// the leaf directly and keeps PREWHERE. Endpoint roots and `enrichments`
/// keep the nested tupleElement form their plans were verified with.
fn native_leaf_reads_as_subcolumn(path: &str) -> bool {
    let mut segments = path.split('.');
    let root = segments.next().unwrap_or_default();
    segments.count() >= 2 && !matches!(root, "src_endpoint" | "dst_endpoint" | "enrichments")
}

fn projected_source(
    source: &str,
    required: &BTreeMap<String, String>,
    missing: &BTreeMap<String, String>,
) -> Result<String> {
    Ok(projected_source_sql(
        source,
        &projected_columns_sql(required, missing)?,
    ))
}

fn projected_columns_sql(
    required: &BTreeMap<String, String>,
    missing: &BTreeMap<String, String>,
) -> Result<String> {
    let mut projection = Vec::new();
    for name in required.keys() {
        if missing.contains_key(name) {
            continue;
        }
        projection.push(format!("{} AS {}", nested_projection(name)?, quoted_identifier(name)?));
    }
    for (name, field_type) in missing {
        projection.push(format!(
            "{} AS {}",
            missing_expression(name, field_type)?,
            quoted_identifier(name)?
        ));
    }
    if projection.is_empty() {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "Iceberg input projection is empty".to_string(),
        ));
    }
    Ok(projection.join(", "))
}

fn projected_source_sql(source: &str, projection: &str) -> String {
    format!("(SELECT {projection} FROM {source})")
}

fn generation_root_projection(
    manifest: &SourceManifest,
    candidates: Option<&[CandidateBlock]>,
) -> Result<String> {
    let candidate_keys = candidates.map(|candidates| {
        candidates
            .iter()
            .map(|candidate| candidate.event_object_key.as_str())
            .collect::<BTreeSet<_>>()
    });
    let objects = manifest
        .objects
        .iter()
        .filter(|object| {
            candidate_keys
                .as_ref()
                .is_none_or(|keys| keys.contains(object.event_object_key.as_str()))
        })
        .collect::<Vec<_>>();
    if objects.is_empty() {
        // An empty proven candidate set deliberately suppresses the indexed
        // generation while the exact hot tail is still checked. Use the
        // union of generation roots so both zero-row and tail branches
        // retain a stable physical shape across additive schema versions.
        return union_root_projection(manifest.objects.iter());
    }
    union_root_projection(objects.into_iter())
}

fn union_root_projection<'a>(
    mut objects: impl Iterator<Item = &'a ManifestObject>,
) -> Result<String> {
    let first = objects.next().ok_or(QueryPlanError::EmptyManifest)?;
    let mut roots = roots_for_available_paths(first.available_paths.iter().map(String::as_str));
    for object in objects {
        roots.extend(roots_for_available_paths(object.available_paths.iter().map(String::as_str)));
    }
    root_projection_for_roots(roots)
}

/// Roots projected for the stored event columns `paths` (manifest or tail
/// schema leaves). NAN-3422: only the root reaches SQL, so a leaf such as
/// `unmapped.@timestamp` still contributes `unmapped`; a root that is not a
/// query identifier is skipped rather than failing every query.
fn root_projection_for_paths<'a>(paths: impl Iterator<Item = &'a str>) -> Result<String> {
    root_projection_for_roots(roots_for_available_paths(paths))
}

fn required_root_projection(
    required: &BTreeMap<String, String>,
    available_paths: &BTreeSet<String>,
) -> Result<String> {
    root_projection_for_roots(required_read_roots(required, available_paths)?)
}

fn required_read_roots(
    required: &BTreeMap<String, String>,
    available_paths: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let available_roots = roots_for_available_paths(available_paths.iter().map(String::as_str));
    // projected_scan_columns is validated above as a subset of required.
    // Absent paths keep their typed defaults in native_event_source; never
    // ask the storage function for a root absent from its read contract.
    let mut roots = roots_for_paths(required.keys().map(String::as_str))?;
    roots.retain(|root| available_roots.contains(root));
    roots.insert("time".into());
    Ok(roots)
}

/// NAN-3155: the storage function's virtual row identity (`_path`, the file a
/// row was read from, and `_row_number`, its 0-based row within that file).
/// A two-pass row query names them as required columns: they are projected
/// from the `file()` read select like any leaf, are never "missing", and own
/// no physical root.
pub const ROW_PATH_COLUMN: &str = "_path";
pub const ROW_NUMBER_COLUMN: &str = "_row_number";

pub fn is_row_identity_column(name: &str) -> bool {
    name == ROW_PATH_COLUMN || name == ROW_NUMBER_COLUMN
}

fn roots_for_paths<'a>(paths: impl Iterator<Item = &'a str>) -> Result<BTreeSet<String>> {
    let mut roots = BTreeSet::new();
    for path in paths {
        validate_path(path)?;
        let root = path.split('.').next().ok_or_else(|| {
            QueryPlanError::InvalidManifest("event field path has no root".to_string())
        })?;
        if is_row_identity_column(root) {
            continue;
        }
        roots.insert(root.to_string());
    }
    Ok(roots)
}

/// [`roots_for_paths`] for stored schema leaves: tolerant of producer keys
/// that are not query identifiers (NAN-3422). Only a valid root is kept.
fn roots_for_available_paths<'a>(paths: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
    paths
        .filter_map(|path| path.split('.').next())
        .filter(|root| validate_segment(root).is_ok() && !is_row_identity_column(root))
        .map(str::to_string)
        .collect()
}

/// Insert `path` and its ancestors into an available-path set, keeping only
/// the addressable prefix: `unmapped.@timestamp` contributes `unmapped`, so
/// the stored root is still projected while the odd leaf itself never reaches
/// SQL (NAN-3422). Producer keys are data, never a reason to fail a plan.
fn insert_addressable_path(available: &mut BTreeSet<String>, path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(QueryPlanError::InvalidManifest("event field path is empty".to_string()));
    }
    let segments = path.split('.').collect::<Vec<_>>();
    // A map tail (`root.^key`) validates as its plain segment.
    let addressable = segments
        .iter()
        .enumerate()
        .take_while(|(index, segment)| {
            let plain = if *index > 0 { segment.strip_prefix('^').unwrap_or(segment) } else { segment };
            validate_segment(plain).is_ok()
        })
        .count();
    if addressable == segments.len() {
        available.insert(path.to_string());
    }
    for length in 1..=addressable.min(segments.len() - 1) {
        available.insert(segments[..length].join("."));
    }
    Ok(())
}

/// Whether `path` is a query identifier path the planner may render as SQL.
fn is_addressable_path(path: &str) -> bool {
    validate_path(path).is_ok()
}

fn root_projection_for_roots(roots: BTreeSet<String>) -> Result<String> {
    if roots.is_empty() {
        return Err(QueryPlanError::InvalidManifest(
            "active generation exposes no event columns".to_string(),
        ));
    }
    roots
        .iter()
        .map(|root| quoted_identifier(root))
        .collect::<Result<Vec<_>>>()
        .map(|columns| columns.join(", "))
}

/// Bound stateful operators below their hard per-lane memory fence without
/// forcing healthy analytical queries to spill after only a few scan blocks.
/// ClickHouse's external GROUP BY merge can consume roughly as much memory as
/// the aggregation phase, so half the lane limit is the largest safe trigger.
pub(crate) fn external_processing_limits(max_memory_bytes: u64) -> (u64, u64) {
    (max_memory_bytes / 2, max_memory_bytes.saturating_mul(4))
}

/// Guard every compiler-emitted keyword token test with a substring prefilter.
///
/// Parts carry no per-row text index (gen1's `lower(col)` text index), so a
/// bare keyword evaluates `hasAllTokens(lower(col), 'needle')` on every row
/// that survives row-group pruning: it lower-cases and tokenizes the whole
/// value (`raw_data` is ~0.9 KB per OCSF event). A row can only hold every
/// token if it holds every token's characters as a substring, which
/// `positionCaseInsensitive` answers with a SIMD search and no allocation.
/// `lower` and `positionCaseInsensitive` both fold ASCII only, so for an
/// ASCII-alphanumeric piece the prefilter is a necessary condition of the
/// original test, which is still evaluated on the rows it admits: results
/// are unchanged, only rows that cannot match skip the tokenizer.
///
/// Rewritten only when the needle is plain ASCII (letters, digits and a few
/// separators) so no SQL escape or non-ASCII case rule is involved.
///
/// NAN-3789: a needle that is exactly ONE lowercase ASCII-alphanumeric
/// token (a hash, `currentversion`, `powershell`) becomes
/// `hasTokenCaseInsensitive(col, 'needle')` instead (see
/// [`single_token_case_insensitive`]); every other needle keeps the guarded
/// `hasAllTokens` form.
///
/// Also drops the redundant `lower()` under `iLike` (see below).
pub(crate) fn prefilter_token_predicates(sql: &str) -> String {
    prefilter_token_predicates_with(sql, token_case_insensitive_enabled())
}

/// NAN-3789: the setting that keeps wide text tests out of PREWHERE.
const TEXT_AFTER_FENCE_SETTING: &str = "move_all_conditions_to_prewhere=0";

/// NAN-3789: whether a row-fenced statement that tests a wide text column
/// carries [`TEXT_AFTER_FENCE_SETTING`]. Always on; only the operator SQL
/// probe's `text_after_fence` knob turns it off, for one call (A/B).
///
/// A rare keyword (a bare hash) keeps a few v2 block runs in each of
/// hundreds of row groups. The compiled text test sits in the outer query
/// and the planner's time guard and `_row_number` fence in the source select
/// below it. With chDB's default `move_all_conditions_to_prewhere=1` the
/// pushed-down text test leads ONE PREWHERE over every row of every kept
/// group (`_row_number` is virtual and stays in the later Filter), so
/// `message`/`raw_data` were tokenized for ~28 M rows to verify ~1 M fenced
/// ones. With it off, PREWHERE holds the cheap time guard alone and the text
/// test runs in the Filter after the fence (EXPLAIN, tenant-a 7 d bare SHA256:
/// 12.4-15.7 s -> 6.6-7.1 s, identical rows). A setting only moves where
/// conditions are evaluated, never what they are, so results are unchanged.
/// Statements without a row fence (whole files: nothing narrower to apply
/// first) or without a wide text test keep chDB's default.
fn text_after_fence_enabled() -> bool {
    crate::perf_overrides::probe_flag("text_after_fence", true)
}

/// NAN-3789: whether compiled SQL tests one of [`WIDE_TEXT_COLUMNS`] in a
/// predicate (a token / substring / regex function over it, or `LIKE`), as
/// opposed to only returning it.
fn tests_wide_text(sql: &str) -> bool {
    static TEXT_TEST: OnceLock<Regex> = OnceLock::new();
    TEXT_TEST
        .get_or_init(|| {
            Regex::new(concat!(
                r#"(?i)\b(?:hasAllTokens|hasAnyTokens|hasToken\w*|position\w*|match|like|ilike|notLike|notILike|multiSearch\w*)\(\s*(?:lower\(\s*)?"?(?:message|raw_data)\b"#,
                r#"|\b(?:lower\(\s*)?"?(?:message|raw_data)"?\)?\s+(?:NOT\s+)?(?:i?like)\b"#,
            ))
            .expect("static regex")
        })
        .is_match(sql)
}

/// NAN-3789: whether a single-token keyword test is evaluated with
/// `hasTokenCaseInsensitive`. Always on; only the operator SQL probe's
/// `token_case_insensitive` knob restores the guarded
/// `hasAllTokens(lower(col), …)` form, for one call (A/B).
fn token_case_insensitive_enabled() -> bool {
    crate::perf_overrides::probe_flag("token_case_insensitive", true)
}

/// NAN-3789: `hasTokenCaseInsensitive(col, n)` is exactly
/// `hasAllTokens(lower(col), n)` when `n` is one non-empty run of lowercase
/// ASCII letters and digits:
///
/// - both tokenize the haystack the same way: ClickHouse's `splitByNonAlpha`
///   (the `hasAllTokens` default) and `hasToken*`'s token searcher both treat
///   ASCII alphanumerics and every byte >= 0x80 as token bytes and every
///   other ASCII byte as a separator (the same rule
///   [`crate::parts::token_counts::ch_tokens`] reproduces for the v3 counts);
/// - `lower` folds ASCII only, and the case-insensitive searcher compares
///   ASCII letters case-folded and every other byte exactly;
/// - the needle is a single token, so "every needle token is a haystack
///   token" and "the needle occurs bounded by separators" are one condition;
/// - a NULL haystack is NULL in both (default NULL handling), which WHERE
///   treats as false.
///
/// An uppercase letter in the needle is excluded on purpose:
/// `hasAllTokens(lower(col), 'X')` can never match (the haystack's tokens
/// are lowercase) while the case-insensitive search would. The compiler
/// lowercases keyword needles, so this is the live shape.
///
/// Measured live on tenant-a over 7 d (NAN-3789, same selection, identical rows):
/// the bare SHA256 search 12.4 s -> 7.1 s, the `CurrentVersion` registry hunt
/// 22.5 s -> 19.5 s. `positionCaseInsensitive` + `lower` + tokenize was
/// ~40% of the scan; the token searcher is one pass with no allocation.
fn single_token_case_insensitive(needle: &str) -> bool {
    !needle.is_empty() && needle.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn prefilter_token_predicates_with(sql: &str, token_case_insensitive: bool) -> String {
    static TOKEN_TEST: OnceLock<Regex> = OnceLock::new();
    let pattern = TOKEN_TEST.get_or_init(|| {
        Regex::new(r#"hasAllTokens\(lower\(("[A-Za-z0-9_.]+"|[A-Za-z_][A-Za-z0-9_]*)\), '([A-Za-z0-9 ._:/@,=+-]{1,256})'\)"#)
            .expect("static regex")
    });
    static LOWERED_ILIKE: OnceLock<Regex> = OnceLock::new();
    // `iLike` already matches case-insensitively, and ASCII `lower` never
    // moves a character out of its case class, so `lower(col) iLike p` and
    // `col iLike p` agree on every value. The `lower` form only exists to hit
    // gen1's text index by expression; over parts it just allocates a
    // lowered copy of every value (~40% of a contains scan).
    let lowered_ilike = LOWERED_ILIKE.get_or_init(|| {
        Regex::new(r#"\blower\(("[A-Za-z0-9_.]+"|[A-Za-z_][A-Za-z0-9_]*)\) (iLike|NOT iLike) '"#).expect("static regex")
    });
    let sql = lowered_ilike.replace_all(sql, "$1 $2 '");
    pattern
        .replace_all(&sql, |captures: &regex::Captures<'_>| {
            let original = captures[0].to_string();
            let column = &captures[1];
            if token_case_insensitive && single_token_case_insensitive(&captures[2]) {
                return format!("hasTokenCaseInsensitive({column}, '{}')", &captures[2]);
            }
            let mut pieces = captures[2]
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|piece| !piece.is_empty())
                .map(str::to_ascii_lowercase)
                .collect::<Vec<_>>();
            pieces.sort();
            pieces.dedup();
            if pieces.is_empty() {
                return original;
            }
            let guards = pieces
                .iter()
                .map(|piece| format!("positionCaseInsensitive({column}, '{piece}') > 0"))
                .collect::<Vec<_>>()
                .join(" AND ");
            format!("({guards} AND {original})")
        })
        .into_owned()
}

fn harden_settings(mut sql: String, tenant: &TenantQueryConfig) -> Result<String> {
    sql = prefilter_token_predicates(&sql);
    static MAX_THREADS: OnceLock<Regex> = OnceLock::new();
    let max_threads = MAX_THREADS.get_or_init(|| Regex::new(r"max_threads\s*=\s*\d+").expect("static regex"));
    static MAX_EXECUTION: OnceLock<Regex> = OnceLock::new();
    let max_execution = MAX_EXECUTION.get_or_init(|| Regex::new(r"max_execution_time\s*=\s*\d+").expect("static regex"));
    sql = max_threads
        .replace_all(&sql, format!("max_threads={}", tenant.threads))
        .into_owned();
    sql = max_execution
        .replace_all(
            &sql,
            format!("max_execution_time={}", crate::query_timing::execution_seconds(tenant.max_execution_seconds)),
        )
        .into_owned();
    // Iceberg table functions carry their own nested `SETTINGS
    // iceberg_metadata_file_path=...`. That is not the query-level resource
    // clause. Key this decision to the compiler-owned max_threads setting so
    // a typed route cannot accidentally append limits as GROUP BY columns.
    if !max_threads.is_match(&sql) {
        sql.push_str(&format!(
            " SETTINGS max_threads={}, max_execution_time={}",
            tenant.threads, crate::query_timing::execution_seconds(tenant.max_execution_seconds)
        ));
    }
    // Stateful nPL operators such as sort, dedup, transaction, and streamstats
    // can legitimately span more state than one worker lane may retain in
    // memory. Spill before the hard memory fence instead of turning a bounded
    // query into a user-visible MEMORY_LIMIT_EXCEEDED response. The disk fence
    // remains derived from the tenant-owned memory ceiling, so neither the
    // compiler nor a request can opt into unbounded temporary storage.
    let (external_threshold, temporary_disk_bytes) =
        external_processing_limits(tenant.max_memory_bytes);
    // NAN-3154: row-group bloom push-down. The compiler compares
    // ingest-lowercased identity paths RAW (`"src_endpoint.ip" = '10.0.0.1'`),
    // which chDB's KeyCondition can test against the part writer's column
    // blooms (fpp 1e-4); a sparse value then skips row groups inside chDB
    // instead of being decoded. Blooms are read only for columns an `=`/`IN`
    // condition names, so unhinted scans pay nothing, and sparse column-range
    // files carry no bloom offsets (`range_fetch::sanitized_footer`), so
    // they never read a hole.
    sql.push_str(&format!(
        ", max_bytes_to_read={}, max_memory_usage={}, max_bytes_before_external_sort={}, \
         max_bytes_before_external_group_by={}, max_temporary_data_on_disk_size_for_query={}, \
         max_block_size=8192, preferred_block_size_bytes=8388608, max_insert_threads=1, use_query_cache=0, \
         use_hive_partitioning=0, prefer_column_name_to_alias=1, input_format_parquet_allow_missing_columns=1, input_format_parquet_filter_push_down=1, \
         input_format_parquet_bloom_filter_push_down=1",
        tenant.max_query_bytes,
        tenant.max_memory_bytes,
        external_threshold,
        external_threshold,
        temporary_disk_bytes,
    ));
    if contains_statement_separator(&sql) {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "hardened SQL contains a statement separator".to_string(),
        ));
    }
    Ok(sql)
}

// Only the compiler's single-stage timeline can move its top-K below the
// leaf projection. Never truncate a pipeline or an offset page. Whole
// endpoint roots and `enrichments` keep the full-width path.
fn table_view_page_clause(compiled: &CompiledQuery) -> Option<String> {
    if !compiled.table_view || !compiled.newest_first_event_rows
        || compiled.projected_scan_columns.is_empty()
    {
        return None;
    }
    let whole_width = |path: &str| path.starts_with("enrichments") || matches!(path, "src_endpoint" | "dst_endpoint");
    if compiled.required_columns.iter().any(|column| whole_width(&column.name))
        || compiled.projected_scan_columns.iter().any(|path| whole_width(path))
    {
        return None;
    }
    if preserves_full_event_shape(&compiled.sql)
        || select_pattern().find_iter(&compiled.sql).count() != 1
    {
        return None;
    }
    static SHAPE: OnceLock<Regex> = OnceLock::new();
    let shape = SHAPE.get_or_init(|| Regex::new(r"(?s)^SELECT [^;]+ FROM __nano_lake_source__ (WHERE .+ ORDER BY .+ LIMIT [0-9]+)(?: SETTINGS .+)?$").expect("static regex"));
    let clause = shape.captures(&compiled.sql)?.get(1)?.as_str();
    // Reject nested selects and pipeline operators even if metadata claims a
    // newest-first result. LIMIT must be the final operation before settings.
    static PIPELINE: OnceLock<Regex> = OnceLock::new();
    if PIPELINE.get_or_init(|| Regex::new(r"(?i)\b(SELECT|UNION|OFFSET|GROUP|HAVING|QUALIFY|LIMIT BY)\b")
        .expect("static regex")).is_match(clause)
    {
        return None;
    }
    Some(clause.to_string())
}

fn select_pattern() -> &'static Regex {
    static SELECT: OnceLock<Regex> = OnceLock::new();
    SELECT.get_or_init(|| Regex::new(r"(?i)\bSELECT\b").expect("static regex"))
}

pub(crate) fn preserves_full_event_shape(sql: &str) -> bool {
    if !sql.contains(&format!("SELECT * FROM {LOG_SOURCE_PLACEHOLDER}")) {
        return false;
    }
    let selects = select_pattern().find_iter(sql).count();
    static FULL_ROWS: OnceLock<Regex> = OnceLock::new();
    let full_rows = FULL_ROWS.get_or_init(|| Regex::new(r"(?i)\bSELECT\s+\*\s+FROM\b")
        .expect("static regex")).find_iter(sql).count();
    selects > 0 && selects == full_rows
}

fn nested_expression(path: &str) -> Result<String> {
    let mut segments = path.split('.');
    let first = segments.next().expect("validated non-empty path");
    validate_segment(first)?;
    let mut expression = quoted_segment(first);
    for segment in segments {
        validate_segment(segment)?;
        expression = format!("tupleElement({expression}, '{segment}')");
    }
    Ok(expression)
}

fn nested_projection(path: &str) -> Result<String> {
    path.split('.')
        .map(|segment| {
            validate_segment(segment)?;
            Ok(quoted_segment(segment))
        })
        .collect::<Result<Vec<_>>>()
        .map(|segments| segments.join("."))
}

fn missing_expression(name: &str, field_type: &str) -> Result<&'static str> {
    if name.contains(".^") {
        Ok("CAST(map() AS Map(String, String))")
    } else {
        default_expression(field_type)
    }
}

fn default_expression(field_type: &str) -> Result<&'static str> {
    match field_type {
        "string" => Ok("CAST(NULL AS Nullable(String))"),
        "integer" | "long" => Ok("CAST(NULL AS Nullable(Int64))"),
        "float" => Ok("CAST(NULL AS Nullable(Float64))"),
        "boolean" => Ok("CAST(NULL AS Nullable(Bool))"),
        "ip_address" => Ok("CAST(NULL AS Nullable(String))"),
        "timestamp" => Ok("CAST(NULL AS Nullable(DateTime64(6, 'UTC')))"),
        "array" => Ok("CAST([] AS Array(String))"),
        "uuid" => Ok("CAST(NULL AS Nullable(UUID))"),
        "object" => Ok("CAST(map() AS Map(String, String))"),
        other => Err(QueryPlanError::InvalidCompilerOutput(format!(
            "unsupported field type {other}"
        ))),
    }
}

fn typed_tail_sql_path(name: &str) -> Result<Option<String>> {
    let (root, path, separator) = if let Some((root, path)) = name.split_once(".^") {
        (root, path, ".^")
    } else if let Some((root, path)) = name.split_once('.') {
        (root, path, ".")
    } else {
        return Ok(None);
    };
    if !matches!(root, "unmapped" | "ext" | "event") {
        return Ok(None);
    }
    let segments = path
        .split('.')
        .map(|segment| {
            validate_segment(segment)?;
            Ok(format!("\"{segment}\""))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(format!("{root}{separator}{}", segments.join("."))))
}

fn quoted_identifier(path: &str) -> Result<String> {
    validate_path(path)?;
    Ok(format!("`{path}`"))
}

fn double_quoted_identifier(path: &str) -> String {
    format!("\"{}\"", path.replace('"', "\"\""))
}

fn quoted_segment(segment: &str) -> String {
    format!("`{segment}`")
}

fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(QueryPlanError::InvalidCompilerOutput(
            "column path is empty".to_string(),
        ));
    }
    let normalized = path.replace(".^", ".");
    for segment in normalized.split('.') {
        validate_segment(segment)?;
    }
    Ok(())
}

fn validate_segment(segment: &str) -> Result<()> {
    let mut bytes = segment.bytes();
    if !matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(QueryPlanError::InvalidCompilerOutput(format!(
            "column path segment is invalid: {segment}"
        )));
    }
    Ok(())
}

fn contains_statement_separator(sql: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    let mut chars = sql.chars().peekable();
    while let Some(character) = chars.next() {
        match quote {
            None if matches!(character, '\'' | '"' | '`') => quote = Some(character),
            None if character == ';' => return true,
            Some('\'') if escaped => escaped = false,
            Some('\'') if character == '\\' => escaped = true,
            Some(delimiter) if character == delimiter => {
                if chars.peek() == Some(&delimiter) {
                    chars.next();
                } else {
                    quote = None;
                }
            }
            _ => {}
        }
    }
    false
}

pub fn read_manifest(path: impl Into<PathBuf>) -> Result<SourceManifest> {
    let path = path.into();
    let bytes = std::fs::read(&path).map_err(|error| {
        QueryPlanError::InvalidManifest(format!("failed to read {}: {error}", path.display()))
    })?;
    let mut manifest: SourceManifest = serde_json::from_slice(&bytes).map_err(|error| {
        QueryPlanError::InvalidManifest(format!("failed to decode {}: {error}", path.display()))
    })?;
    manifest.release_derived_object_schema()?;
    if manifest.objects.is_empty() {
        manifest.bootstrap_available_paths = manifest.bootstrap_field_types.keys().cloned().collect();
    } else {
        manifest.bootstrap_field_types.clear();
    }
    Ok(manifest)
}

#[cfg(test)]
mod newest_first_cap_tests {
    use super::newest_first_row_cap;

    #[test]
    fn caps_only_a_trailing_newest_first_limit() {
        assert_eq!(newest_first_row_cap("SELECT a FROM x WHERE b ORDER BY time DESC LIMIT 5 SETTINGS max_threads=16, optimize_read_in_order=1"), Some(5));
        assert_eq!(newest_first_row_cap("SELECT a FROM x ORDER BY time DESC LIMIT 201"), Some(201));
        assert_eq!(newest_first_row_cap("SELECT a FROM x ORDER BY time ASC LIMIT 5"), None);
        assert_eq!(newest_first_row_cap("SELECT a FROM (SELECT b FROM x ORDER BY time DESC LIMIT 5) ORDER BY a LIMIT 7"), None);
        assert_eq!(newest_first_row_cap("SELECT a FROM x"), None);
        // The compiler's uid tiebreak keeps the cap (chunks are time-disjoint).
        assert_eq!(
            newest_first_row_cap("SELECT a FROM x ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 7 SETTINGS max_threads=16"),
            Some(7)
        );
        // Staged `sort -time | head N`: the compiler clamps the outer LIMIT.
        assert_eq!(
            newest_first_row_cap("WITH stage_0 AS (SELECT * FROM x ORDER BY time DESC), stage_1 AS (SELECT * FROM stage_0 LIMIT 7) SELECT * FROM stage_1 ORDER BY time DESC LIMIT 7"),
            Some(7)
        );
        assert_eq!(newest_first_row_cap("SELECT a FROM x ORDER BY time DESC, a DESC LIMIT 7"), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::fence_eval::{fence_matches, parse_fence};

    #[test]
    fn page_schema_keeps_whole_nested_types_and_authority_roots() {
        let schema = "`time` DateTime64(6, 'UTC'), `device` Tuple(`hostname` String, `note` Enum8('a,b' = 1)), `unused` Array(Tuple(`value` String)), `enrichments` Array(Tuple(`owned_fields` Array(String)))";
        let projected = page_read_schema(schema, "`time`, `device`, `enrichments`").unwrap();
        assert_eq!(projected, "`time` DateTime64(6, 'UTC'), `device` Tuple(`hostname` String, `note` Enum8('a,b' = 1)), `enrichments` Array(Tuple(`owned_fields` Array(String)))");
        assert!(page_read_schema(schema, "`missing`").is_none());
        for malformed in ["time Int64", "`time`", "`time` Tuple(`x` String", "`time` String, `time` Int64", "`time` String)"] {
            assert!(page_read_schema(malformed, "`time`").is_none(), "{malformed}");
        }
    }

    #[test]
    fn leaf_read_schema_keeps_only_named_leaves() {
        let schema = "`time` DateTime64(6, 'UTC'), `metadata` Tuple(`uid` Nullable(String), `product` Tuple(`name` Nullable(String), `vendor_name` Nullable(String)), `profiles` Array(Nullable(String))), `device` Tuple(`hostname` Nullable(String), `type_id` Nullable(Int64)), `process` Tuple(`file` Tuple(`hashes` Array(Tuple(`algorithm` Nullable(String), `value` Nullable(String))), `path` Nullable(String))), `src_endpoint` Tuple(`ip` Nullable(String), `port` Nullable(Int64)), `unmapped` Map(String, String), `odd``name` Tuple(`a` String, `b` String)";
        let required = ["time", "metadata.uid", "metadata.product.name", "device", "process.file.hashes.value", "src_endpoint.ip", "unmapped.^key", "odd`name.b"]
            .into_iter().map(|name| (name.to_string(), "string".to_string())).collect::<BTreeMap<_, _>>();
        assert_eq!(
            leaf_read_schema(schema, &required).unwrap(),
            "`time` DateTime64(6, 'UTC'), `metadata` Tuple(`uid` Nullable(String), `product` Tuple(`name` Nullable(String))), `device` Tuple(`hostname` Nullable(String), `type_id` Nullable(Int64)), `process` Tuple(`file` Tuple(`hashes` Array(Tuple(`value` Nullable(String))))), `src_endpoint` Tuple(`ip` Nullable(String)), `unmapped` Map(String, String), `odd``name` Tuple(`b` String)"
        );
        // A leaf the type does not show keeps the whole root (never drops a
        // column a statement reads); the identity columns own no root.
        let required = ["metadata.absent", "metadata.uid", "_path", "_row_number"]
            .into_iter().map(|name| (name.to_string(), "string".to_string())).collect::<BTreeMap<_, _>>();
        assert!(leaf_read_schema(schema, &required).unwrap().contains("`metadata` Tuple(`uid` Nullable(String), `product` Tuple(`name`"));
        assert!(leaf_read_schema("`time` Tuple(`x` String", &required).is_none());
    }

    #[test]
    fn page_plan_reads_leaf_pruned_roots_and_charges_leaf_bytes() {
        let mut configured = tenant();
        configured.max_query_bytes = 10_000_000;
        let schema = "`time` DateTime64(6, 'UTC'), `metadata` Tuple(`uid` Nullable(String), `log_source` Nullable(String), `original` Nullable(String)), `device` Tuple(`hostname` Nullable(String), `type_id` Nullable(Int64)), `raw_data` Nullable(String)";
        configured.snapshot_cache = Some(SnapshotCache {
            source_spec: "/cache/data.parquet".into(),
            objects: BTreeMap::from([("s3://bucket/table/data/one.parquet".into(), SnapshotCacheObject {
                version_id: "version-1".into(), bytes: 900_000, path: "/cache/data.parquet".into(),
            })]), bytes: 900_000,
            read_schema: Some(schema.into()), bootstrap: false,
        });
        let mut source = manifest();
        source.objects[0].available_paths = vec!["time".into(), "metadata.uid".into(), "metadata.log_source".into(), "metadata.original".into(),
            "device.hostname".into(), "device.type_id".into(), "raw_data".into()].into();
        source.objects[0].event_object_bytes = 900_000;
        source.objects[0].column_compressed_bytes = BTreeMap::from([
            ("time".into(), 10_000), ("metadata.uid".into(), 20_000), ("metadata.log_source".into(), 1_000),
            ("metadata.original".into(), 300_000), ("device.hostname".into(), 2_000), ("device.type_id".into(), 1_000),
            ("raw_data".into(), 500_000),
        ]);
        let query = compiled(
            "SELECT time, \"metadata.uid\", \"device.hostname\" FROM __nano_lake_source__ WHERE \"device.hostname\" = 'h' ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 50",
            vec![column("time", "timestamp"), column("metadata.uid", "string"), column("device.hostname", "string")],
        );
        let mut query = query;
        query.newest_first_event_rows = true;
        query.projected_scan_columns = vec!["device.hostname".into(), "time".into()];
        let plan = plan_broad_log_query(&configured, &source, &query).unwrap();
        let read = &plan.params.iter().find(|(name, _)| name == "snapshot_cache_read_schema").unwrap().1;
        assert_eq!(read, "`time` DateTime64(6, 'UTC'), `metadata` Tuple(`uid` Nullable(String)), `device` Tuple(`hostname` Nullable(String))");
        // Leaves read (32 KB) plus the per-object margin, not 900 KB.
        assert_eq!(plan.budget.estimated_scan_bytes, 32_000 + 3_200 + 65_536);
    }

    /// NAN-3159: a full-event read charges every leaf's column chunks (of
    /// the kept row groups the selection recorded), not the whole file with
    /// its footer, blooms and page index; never more than the file.
    #[test]
    fn full_event_plan_charges_every_leaf_not_the_whole_file() {
        let mut configured = tenant();
        configured.max_query_bytes = 10_000_000;
        let mut source = manifest();
        source.objects[0].event_object_bytes = 900_000;
        source.objects[0].column_compressed_bytes = BTreeMap::from([
            ("time".into(), 10_000), ("metadata.uid".into(), 20_000), ("raw_data".into(), 170_000),
        ]);
        let mut query = compiled("SELECT * FROM __nano_lake_source__ ORDER BY time DESC LIMIT 11", vec![column("time", "timestamp")]);
        query.table_view = false;
        assert!(preserves_full_event_shape(&query.sql));
        let plan = plan_broad_log_query(&configured, &source, &query).unwrap();
        assert_eq!(plan.budget.estimated_scan_bytes, 200_000 + 20_000 + 65_536);
        // Leaves that nearly fill the file are capped at its size.
        source.objects[0].column_compressed_bytes.insert("raw_data".into(), 860_000);
        let plan = plan_broad_log_query(&configured, &source, &query).unwrap();
        assert_eq!(plan.budget.estimated_scan_bytes, 900_000);
        // Without per-column bytes the whole file is charged, as before.
        source.objects[0].column_compressed_bytes.clear();
        let plan = plan_broad_log_query(&configured, &source, &query).unwrap();
        assert_eq!(plan.budget.estimated_scan_bytes, 900_000);
        // A budget the whole file exceeds admits the leaf charge.
        source.objects[0].column_compressed_bytes = BTreeMap::from([("time".into(), 10_000), ("raw_data".into(), 90_000)]);
        configured.max_query_bytes = 500_000;
        assert_eq!(plan_broad_log_query(&configured, &source, &query).unwrap().budget.estimated_scan_bytes, 100_000 + 10_000 + 65_536);
    }

    #[test]
    fn aggregate_read_schema_keeps_leaves_defaults_and_full_event_output() {
        let mut configured = tenant();
        let schema = "`time` DateTime64(6, 'UTC'), `metadata` Tuple(`uid` Nullable(String), `log_source` Nullable(String)), `src_endpoint` Tuple(`ip` Nullable(String), `location` Tuple(`country` Nullable(String))), `enrichments` Array(Tuple(`owned_fields` Array(String))), `unused` String";
        configured.snapshot_cache = Some(SnapshotCache {
            source_spec: "/cache/data.parquet".into(),
            objects: BTreeMap::from([("s3://bucket/table/data/one.parquet".into(), SnapshotCacheObject {
                version_id: "version-1".into(), bytes: 900, path: "/cache/data.parquet".into(),
            })]), bytes: 900,
            read_schema: Some(schema.into()), bootstrap: false,
        });
        let mut source = manifest();
        source.objects[0].available_paths = vec!["time".into(), "metadata.uid".into(), "metadata.log_source".into(), "src_endpoint.ip".into(), "src_endpoint.location.country".into(), "enrichments.owned_fields".into(), "unused".into()].into();
        source.objects[0].field_types.insert("src_endpoint.location.country".into(), "string".into());
        let mut query = compiled(
            "SELECT count() FROM __nano_lake_source__ WHERE `src_endpoint.location.country` = 'US' AND `absent.value` IS NULL",
            vec![column("time", "timestamp"), column("src_endpoint.location.country", "string"), column("absent.value", "string")],
        );
        query.table_view = false;
        let plan = plan_broad_log_query(&configured, &source, &query).unwrap();
        let actual = &plan.params.iter().find(|(name, _)| name == "snapshot_cache_read_schema").unwrap().1;
        if std::env::var("NANO_LAKE_NARROW_AGGREGATE_SCHEMA").as_deref() != Ok("1") {
            assert_eq!(actual, schema, "aggregate pruning defaults off");
            query.table_view = true;
            let unpruned = plan_broad_log_query(&configured, &source, &query).unwrap();
            assert_eq!(unpruned.params.iter().find(|(name, _)| name == "snapshot_cache_read_schema").unwrap().1,
                schema, "a table-view request must not enable transforming-query pruning");
            // Exercise the opt-in planner in its own process, without mutating
            // the concurrent test runner's environment.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "planner::tests::aggregate_read_schema_keeps_leaves_defaults_and_full_event_output"])
                .env("NANO_LAKE_NARROW_AGGREGATE_SCHEMA", "1").output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
            return;
        }
        // NAN-4168: the country leaf alone; no endpoint root, no stamps.
        assert!(actual.contains("`src_endpoint` Tuple(`location` Tuple(`country` Nullable(String)))"), "{actual}");
        assert!(!actual.contains("`enrichments`"), "{actual}");
        assert!(actual.contains("`time` DateTime64"));
        assert!(!actual.contains("`unused`"));
        assert!(!actual.contains("`metadata`"));
        assert!(plan.schema_defaults.contains(&"absent.value".to_string()));
        let mut full = query;
        full.sql = "SELECT * FROM __nano_lake_source__".into();
        let plan = plan_broad_log_query(&configured, &source, &full).unwrap();
        assert_eq!(plan.params.iter().find(|(name, _)| name == "snapshot_cache_read_schema").unwrap().1, schema);
    }

    /// NAN-4168: enrichment leaves are plain columns. A 7 d `stats count by
    /// src_endpoint.location.country` reads the location leaf alone: no
    /// `enrichments` decode, no mask, no per-file split, and the endpoint
    /// root's read schema is pruned to that leaf, over files of any stamp
    /// state (NAN-3800 used to decode `enrichments` for every file once a few
    /// had expired or denied stamps).
    #[test]
    fn stats_by_country_plans_a_plain_leaf_read() {
        let schema = "`time` DateTime64(6, 'UTC'), `metadata` Tuple(`uid` Nullable(String)), `src_endpoint` Tuple(`ip` Nullable(String), `location` Tuple(`country` Nullable(String), `continent` Nullable(String)), `autonomous_system` Tuple(`number` Nullable(Int64))), `enrichments` Array(Tuple(`provider` Nullable(String), `owned_fields` Array(String)))";
        let mut source = manifest();
        source.objects[0].available_paths = vec!["time".into(), "metadata.uid".into(), "src_endpoint.ip".into(), "src_endpoint.location.country".into(), "src_endpoint.location.continent".into(), "src_endpoint.autonomous_system.number".into(), "enrichments.provider".into(), "enrichments.owned_fields".into()].into();
        source.objects[0].field_types.insert("src_endpoint.location.country".into(), "string".into());
        let mut second = source.objects[0].clone();
        second.event_object_key = "s3://bucket/table/data/two.parquet".into();
        source.objects.push(second);
        let mut configured = tenant();
        configured.max_query_bytes = 4_000;
        configured.snapshot_cache = Some(SnapshotCache {
            source_spec: "/cache/{a,b}.parquet".into(),
            objects: source.objects.iter().zip(["/cache/a.parquet", "/cache/b.parquet"]).map(|(object, path)| (
                object.event_object_key.clone(),
                SnapshotCacheObject { version_id: object.event_object_version.clone(), bytes: object.event_object_bytes, path: path.into() },
            )).collect(),
            bytes: 1800,
            read_schema: Some(schema.into()),
            bootstrap: false,
        });
        let mut query = compiled(
            "SELECT `src_endpoint.location.country`, count() FROM __nano_lake_source__ GROUP BY `src_endpoint.location.country`",
            vec![column("time", "timestamp"), column("src_endpoint.location.country", "string")],
        );
        query.table_view = false;
        query.start = "2026-08-04T00:00:00Z".into();
        let plan = plan_broad_log_query(&configured, &source, &query).unwrap();
        assert!(!plan.sql.contains("enrichments"), "{}", plan.sql);
        assert!(!plan.sql.contains("UNION ALL"), "{}", plan.sql);
        assert!(!plan.sql.contains("arrayExists"), "{}", plan.sql);
        assert!(!plan.sql.contains("owned_fields"), "{}", plan.sql);
        assert!(plan.params.iter().all(|(name, _)| name != "nano_enrichment_authority"));
        // The read schema of an aggregate is narrowed only under
        // NANO_LAKE_NARROW_AGGREGATE_SCHEMA (see
        // `aggregate_read_schema_keeps_leaves_defaults_and_full_event_output`);
        // Parquet reads only the columns the SQL names, and it names none of
        // the stamps.

        // Perf review F2: a 7d `stats count by src_endpoint.ip` projects the
        // endpoint leaf; neither shape names (and so reads) `enrichments`.
        for table_view in [false, true] {
            let mut by_ip = compiled(
                "SELECT `src_endpoint.ip`, count() FROM __nano_lake_source__ GROUP BY `src_endpoint.ip`",
                vec![column("time", "timestamp"), column("src_endpoint.ip", "string")],
            );
            by_ip.table_view = table_view;
            by_ip.start = "2026-08-04T00:00:00Z".into();
            let plan = plan_broad_log_query(&configured, &source, &by_ip).unwrap();
            assert!(!plan.sql.contains("enrichments"), "table_view={table_view}: {}", plan.sql);
            assert!(!plan.sql.contains("arrayFilter"), "table_view={table_view}: {}", plan.sql);
            assert!(plan.sql.contains("`src_endpoint`.`ip`") || plan.sql.contains("`src_endpoint.ip`"), "{}", plan.sql);
        }

        // Full-event rows return every root as stored, `enrichments` included.
        let mut rows = query.clone();
        rows.sql = "SELECT * FROM __nano_lake_source__".into();
        let rows = plan_broad_log_query(&configured, &source, &rows).unwrap();
        assert!(!rows.sql.contains("arrayExists"), "{}", rows.sql);
        assert!(!rows.sql.contains("owned_fields"), "{}", rows.sql);
    }

    /// NAN-3406: a per-request `flat_filter_leaves` override flips the read
    /// select either way, whatever the process value; without one the plan
    /// is byte-identical to the process value's.
    #[test]
    fn flat_filter_leaves_override_flips_the_plan_per_request() {
        use crate::perf_overrides::{sync_scoped, Overrides};
        let mut configured = tenant();
        let schema = "`time` DateTime64(6, 'UTC'), `device` Tuple(`hostname` Nullable(String), `type_id` Nullable(Int64))";
        configured.snapshot_cache = Some(SnapshotCache {
            source_spec: "/cache/data.parquet".into(),
            objects: BTreeMap::from([("s3://bucket/table/data/one.parquet".into(), SnapshotCacheObject {
                version_id: "version-1".into(), bytes: 900, path: "/cache/data.parquet".into(),
            })]), bytes: 900,
            read_schema: Some(schema.into()), bootstrap: false,
        });
        let mut source = manifest();
        source.objects[0].available_paths = vec!["time".into(), "device.hostname".into(), "device.type_id".into()].into();
        let mut query = compiled(
            "SELECT count() FROM __nano_lake_source__ WHERE `device.hostname` = 'h'",
            vec![column("time", "timestamp"), column("device.hostname", "string")],
        );
        query.table_view = false;
        let plan = |overrides: Overrides| sync_scoped(overrides, || plan_broad_log_query(&configured, &source, &query).unwrap());
        let flat = |plan: &NativeQueryPlan| plan.sql.contains("`device.hostname` AS `device.hostname`")
            && plan.params.iter().any(|(name, value)| name.ends_with("_read_schema") && value.contains("`device.hostname` Nullable(String)"));
        let on = plan(Overrides { flat_filter_leaves: Some(true), ..Overrides::default() });
        let off = plan(Overrides { flat_filter_leaves: Some(false), ..Overrides::default() });
        assert!(flat(&on), "{}", on.sql);
        assert!(!flat(&off) && off.sql.contains("`device`.`hostname` AS `device.hostname`"), "{}", off.sql);
        // No override (other switches overridden, or no scope at all): the process value's plan, byte for byte.
        let process = if flat_filter_leaves_env() { &on } else { &off };
        let unscoped = plan_broad_log_query(&configured, &source, &query).unwrap();
        let others = plan(Overrides { lane_routing_v2: Some(false), identity_merged_index: Some(false), ..Overrides::default() });
        for same in [&unscoped, &others] {
            assert_eq!((&same.sql, &same.params), (&process.sql, &process.params));
        }
    }

    /// NAN-3386: `NANO_LAKE_FLAT_FILTER_LEAVES` off leaves the plan exactly as
    /// before; on, scalar entity leaves (endpoint leaves included, NAN-4168)
    /// are read flat while full-event output stays nested.
    #[test]
    fn flat_filter_leaves_switch_rewrites_only_scalar_entity_leaves() {
        let mut configured = tenant();
        let schema = "`time` DateTime64(6, 'UTC'), `device` Tuple(`hostname` Nullable(String), `type_id` Nullable(Int64)), `src_endpoint` Tuple(`ip` Nullable(String))";
        configured.snapshot_cache = Some(SnapshotCache {
            source_spec: "/cache/data.parquet".into(),
            objects: BTreeMap::from([("s3://bucket/table/data/one.parquet".into(), SnapshotCacheObject {
                version_id: "version-1".into(), bytes: 900, path: "/cache/data.parquet".into(),
            })]), bytes: 900,
            read_schema: Some(schema.into()), bootstrap: false,
        });
        let mut source = manifest();
        source.objects[0].available_paths = vec!["time".into(), "device.hostname".into(), "device.type_id".into(), "src_endpoint.ip".into()].into();
        let mut query = compiled(
            "SELECT count() FROM __nano_lake_source__ WHERE `device.hostname` = 'h' AND `src_endpoint.ip` = '10.0.0.1'",
            vec![column("time", "timestamp"), column("device.hostname", "string"), column("src_endpoint.ip", "string")],
        );
        query.table_view = false;
        let plan = plan_broad_log_query(&configured, &source, &query).unwrap();
        let read = &plan.params.iter().find(|(name, _)| name == "snapshot_cache_read_schema").unwrap().1;
        if std::env::var("NANO_LAKE_FLAT_FILTER_LEAVES").as_deref() != Ok("1") {
            assert!(plan.sql.contains("`src_endpoint`.`ip` AS `src_endpoint.ip`"), "{}", plan.sql);
            assert!(plan.sql.contains("`device`.`hostname` AS `device.hostname`"), "{}", plan.sql);
            assert!(!read.contains("`device.hostname`"), "flat leaves default off: {read}");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "planner::tests::flat_filter_leaves_switch_rewrites_only_scalar_entity_leaves"])
                .env("NANO_LAKE_FLAT_FILTER_LEAVES", "1").output().unwrap();
            assert!(output.status.success(), "{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return;
        }
        assert!(plan.sql.contains("`device.hostname` AS `device.hostname`"), "{}", plan.sql);
        assert!(!plan.sql.contains("`device`.`hostname` AS"), "{}", plan.sql);
        assert_eq!(read.matches("`device.hostname` Nullable(String)").count(), 1, "{read}");
        // NAN-4168: endpoint leaves are plain scalar leaves too.
        assert_eq!(read.matches("`src_endpoint.ip` Nullable(String)").count(), 1, "{read}");
        // A table-view page reads whole roots under its page bound: unchanged.
        let mut page = compiled(
            "SELECT time, \"device.hostname\" FROM __nano_lake_source__ WHERE \"device.hostname\" = 'h' ORDER BY time DESC LIMIT 50",
            vec![column("time", "timestamp"), column("device.hostname", "string")],
        );
        page.newest_first_event_rows = true;
        page.projected_scan_columns = vec!["device.hostname".into(), "time".into()];
        let paged = plan_broad_log_query(&configured, &source, &page).unwrap();
        assert!(paged.sql.contains("`device`.`hostname` AS `device.hostname`"), "{}", paged.sql);
        assert!(!paged.params.iter().any(|(name, value)| name.ends_with("_read_schema") && value.contains("`device.hostname`")));
        // Full-event output reads physical roots: nothing to flatten.
        let mut full = query;
        full.sql = "SELECT * FROM __nano_lake_source__ WHERE `device.hostname` = 'h'".into();
        let plan = plan_broad_log_query(&configured, &source, &full).unwrap();
        assert!(!plan.params.iter().any(|(name, value)| name.ends_with("_read_schema") && value.contains("`device.hostname`")));
    }

    #[test]
    #[ignore = "requires digest-verified native runtime"]
    fn page_schema_native_wide_parquet_preserves_rows() {
        let native = crate::native::NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        std::mem::forget(native.clone());
        let connection = native.connect(&["--memory_worker_use_cgroup=0", "--memory_worker_dynamic_hard_limit=0"]).unwrap();
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("wide.parquet");
        let path = path.to_str().unwrap();
        let unused = (0..400).map(|n| format!("number AS extra_{n}")).collect::<Vec<_>>().join(", ");
        let sql = format!("INSERT INTO FUNCTION file({{out:String}}, Parquet) SELECT number AS time, CAST(tuple(concat('host-', toString(number))), 'Tuple(hostname String)') AS device, CAST([], 'Array(Tuple(owned_fields Array(String)))') AS enrichments, {unused} FROM numbers(1000) SETTINGS max_threads=2");
        connection.query_with_params(&sql, "Null", &[("out", path)]).unwrap();
        let mut schema = "`time` UInt64, `device` Tuple(`hostname` String), `enrichments` Array(Tuple(`owned_fields` Array(String)))".to_string();
        for n in 0..400 { schema.push_str(&format!(", `extra_{n}` UInt64")); }
        let projected = page_read_schema(&schema, "`time`, `device`, `enrichments`").unwrap();
        let sql = "SELECT time, device, enrichments FROM file({source:String}, Parquet, {schema:String}) WHERE time >= 900 ORDER BY time DESC LIMIT 100 SETTINGS max_threads=2, readonly=2";
        // Live interactive reads initialize a stream on a resident lane.
        // Separate statement initialization from fetch; a materialized query's
        // total duration cannot explain the live native_init_ms measurement.
        let streamed = |schema: &str| {
            let started = std::time::Instant::now();
            let mut stream = connection.stream_query_with_params(sql, "JSONEachRow", &[("source", path), ("schema", schema)]).unwrap();
            let init_ms = started.elapsed().as_secs_f64() * 1000.0;
            let fetch_started = std::time::Instant::now();
            let mut data = Vec::new();
            while let Some(block) = stream.fetch().unwrap() { data.extend(block.data); }
            (data, init_ms, fetch_started.elapsed().as_secs_f64() * 1000.0)
        };
        for run in 0..3 {
            let before = std::time::Instant::now();
            let full = connection.query_with_params(sql, "JSONEachRow", &[("source", path), ("schema", &schema)]).unwrap();
            let before_ms = before.elapsed().as_secs_f64() * 1000.0;
            let after = std::time::Instant::now();
            let page = connection.query_with_params(sql, "JSONEachRow", &[("source", path), ("schema", &projected)]).unwrap();
            let after_ms = after.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(full.data, page.data);
            assert_eq!(page.data.iter().filter(|b| **b == b'\n').count(), 100);
            eprintln!("wide schema run {run}: full={before_ms:.3}ms projected={after_ms:.3}ms");
            let (full_stream, full_init, full_fetch) = streamed(&schema);
            let (page_stream, page_init, page_fetch) = streamed(&projected);
            assert_eq!(full_stream, full.data);
            assert_eq!(page_stream, full.data);
            eprintln!("resident stream run {run}: full_init_ms={full_init:.3} full_fetch_ms={full_fetch:.3} projected_init_ms={page_init:.3} projected_fetch_ms={page_fetch:.3}");
        }
    }

    fn stamped_manifest() -> SourceManifest {
        let mut source = manifest();
        for path in ["enrichments.data.valid_until", "enrichments.provider"] {
            let mut paths = source.objects[0].available_paths.to_vec();
            paths.push(path.into());
            source.objects[0].available_paths = paths.into();
            source.objects[0].field_types.insert(path.into(), "array".into());
        }
        source
    }

    #[tokio::test]
    async fn planner_interactive_and_durable_execution_budgets_are_deterministic() {
        let mut configured = tenant();
        configured.max_execution_seconds = 300;
        let query = compiled("SELECT count() FROM __nano_lake_source__ SETTINGS max_threads=1, max_execution_time=300", vec![column("time", "timestamp")]);
        let durable = plan_broad_log_query(&configured, &stamped_manifest(), &query).unwrap();
        assert!(durable.sql.contains("max_execution_time=300"));
        crate::query_timing::measure("budget-test", async {
            let expected = crate::query_timing::interactive_execution_seconds();
            let first = plan_broad_log_query(&configured, &stamped_manifest(), &query).unwrap();
            let second = plan_broad_log_query(&configured, &stamped_manifest(), &query).unwrap();
            assert!(first.sql.contains(&format!("max_execution_time={expected}")));
            assert_eq!(first.sql, second.sql);
            let mut stricter = configured.clone();
            stricter.max_execution_seconds = 1;
            assert!(harden_settings("SELECT 1".into(), &stricter).unwrap().contains("max_execution_time=1"));
            Ok::<_, ()>(())
        }).await.unwrap();
        assert_eq!(plan_broad_log_query(&configured, &stamped_manifest(), &query).unwrap().sql, durable.sql);
    }

    #[test]
    fn enrichment_single_pass_main_plan() {
        let plan = plan_broad_log_query(&tenant(), &stamped_manifest(),
            &compiled("SELECT count() FROM __nano_lake_source__", vec![column("time", "timestamp")])).unwrap();
        assert!(!plan.sql.contains("minOrNull(expiry)"));
        assert!(!plan.sql.contains("arrayJoin(arrayMap"));
    }

    #[test]
    fn enrichment_single_pass_typed_count() {
        let plan = plan_count_aggregate_query(&tenant(), &stamped_manifest(), &CountAggregatePlanRequest {
            group_field: "metadata.log_source", group_results: false, multi_value: false,
            predicate: None, bucket_span_us: None, start_us: 1, end_exclusive_us: 2,
            source_filter: None, deny_source_types: &BTreeSet::new(), source: CountAggregateSource::Base, group_by_source: false,
        }).unwrap().unwrap();
        assert!(!plan.sql.contains("minOrNull(expiry)"));
        assert!(!plan.sql.contains("arrayJoin(arrayMap"));
    }

    #[test]
    fn iceberg_table_settings_do_not_mask_query_resource_settings() {
        let sql = "SELECT value, count() FROM icebergS3({source:String}, SETTINGS iceberg_metadata_file_path='metadata/v1.json') GROUP BY value".to_string();
        let hardened = harden_settings(sql, &tenant()).unwrap();
        assert!(hardened.contains("GROUP BY value SETTINGS max_threads="));
        assert!(!hardened.contains("GROUP BY value, max_bytes_to_read"));
    }

    /// NAN-3789: exactly one lowercase ASCII-alphanumeric token becomes
    /// `hasTokenCaseInsensitive`; multi-token, uppercase, escaped and
    /// non-ASCII needles keep the guarded `hasAllTokens` form, and the switch
    /// restores the old SQL byte for byte.
    #[test]
    fn single_token_keyword_tests_use_the_case_insensitive_token_search() {
        let hash = "0faafb1b35275f3912da163319c87e224985b26b36e662f813897f22445e187e";
        let sql = format!("WHERE (hasAllTokens(lower(message), '{hash}') OR hasAllTokens(lower(raw_data), '{hash}'))");
        assert_eq!(
            prefilter_token_predicates_with(&sql, true),
            format!("WHERE (hasTokenCaseInsensitive(message, '{hash}') OR hasTokenCaseInsensitive(raw_data, '{hash}'))")
        );
        assert_eq!(
            prefilter_token_predicates_with(r#"hasAllTokens(lower("process.cmd_line"), 'currentversion')"#, true),
            r#"hasTokenCaseInsensitive("process.cmd_line", 'currentversion')"#
        );
        // Off: the guarded form, unchanged.
        assert_eq!(
            prefilter_token_predicates_with(&sql, false),
            format!(
                "WHERE ((positionCaseInsensitive(message, '{hash}') > 0 AND hasAllTokens(lower(message), '{hash}')) \
                 OR (positionCaseInsensitive(raw_data, '{hash}') > 0 AND hasAllTokens(lower(raw_data), '{hash}')))"
            )
        );
        // Several tokens, an uppercase letter (can never match a lowered
        // haystack, so must not become a case-insensitive search), escapes
        // and non-ASCII keep the hasAllTokens test.
        for kept in [
            "hasAllTokens(lower(raw_data), 'svchost.exe')",
            "hasAllTokens(lower(raw_data), 'failed login')",
            "hasAllTokens(lower(raw_data), 'CurrentVersion')",
        ] {
            let out = prefilter_token_predicates_with(kept, true);
            assert!(out.contains(kept) && !out.contains("hasTokenCaseInsensitive"), "{out}");
        }
        for untouched in [r"hasAllTokens(lower(raw_data), 'o''brien')", "hasAllTokens(lower(raw_data), 'straße')"] {
            assert_eq!(prefilter_token_predicates_with(untouched, true), untouched);
        }
        assert!(single_token_case_insensitive("abc123") && !single_token_case_insensitive("") && !single_token_case_insensitive("a_b"));
    }

    /// NAN-3789: only predicates over `message` / `raw_data` count as wide
    /// text tests; returning the columns, or testing other columns, does not.
    #[test]
    fn wide_text_tests_are_recognized_in_compiled_predicates() {
        for tested in [
            "WHERE (hasAllTokens(lower(message), 'x') OR hasAllTokens(lower(raw_data), 'x'))",
            "WHERE lower(message) iLike '%x%'",
            "WHERE raw_data NOT iLike '%x%'",
            "WHERE match(raw_data, '(?i)currentversion')",
            "WHERE positionCaseInsensitive(message, 'x') > 0",
        ] {
            assert!(tests_wide_text(tested), "{tested}");
        }
        for untested in [
            "SELECT message, raw_data, time FROM s WHERE \"device.hostname\" = 'ws1'",
            "WHERE hasAllTokens(lower(\"process.cmd_line\"), 'x')",
            "WHERE lower(message_id) iLike '%x%'",
        ] {
            assert!(!tests_wide_text(untested), "{untested}");
        }
    }

    #[test]
    fn keyword_token_tests_gain_a_substring_prefilter() {
        let sql = "SELECT count() FROM s WHERE (hasAllTokens(lower(message), 'svchost.exe') OR hasAllTokens(lower(raw_data), 'svchost.exe'))";
        assert_eq!(
            prefilter_token_predicates(sql),
            "SELECT count() FROM s WHERE ((positionCaseInsensitive(message, 'exe') > 0 AND positionCaseInsensitive(message, 'svchost') > 0 AND hasAllTokens(lower(message), 'svchost.exe')) OR (positionCaseInsensitive(raw_data, 'exe') > 0 AND positionCaseInsensitive(raw_data, 'svchost') > 0 AND hasAllTokens(lower(raw_data), 'svchost.exe')))"
        );
        let quoted = r#"hasAllTokens(lower("process.cmd_line"), 'aa8d33751db6')"#;
        assert_eq!(
            prefilter_token_predicates_with(quoted, false),
            r#"(positionCaseInsensitive("process.cmd_line", 'aa8d33751db6') > 0 AND hasAllTokens(lower("process.cmd_line"), 'aa8d33751db6'))"#
        );
        // Escaped, non-ASCII or separator-only needles are left alone.
        for untouched in [
            r"hasAllTokens(lower(raw_data), 'o''brien')",
            "hasAllTokens(lower(raw_data), 'straße')",
            "hasAllTokens(lower(raw_data), '...')",
            r"hasAllTokens(lower(raw_data), 'c:\\windows')",
        ] {
            assert_eq!(prefilter_token_predicates(untouched), untouched);
        }
        assert!(harden_settings(sql.to_string(), &tenant()).unwrap().contains("positionCaseInsensitive(raw_data, 'svchost') > 0 AND"));
        assert_eq!(
            prefilter_token_predicates(r#"WHERE (lower("process.name") iLike '%shell%') AND NOT (lower(raw_data) iLike '%x\\%') AND flower(a) iLike 'b'"#),
            r#"WHERE ("process.name" iLike '%shell%') AND NOT (raw_data iLike '%x\\%') AND flower(a) iLike 'b'"#
        );
    }

    #[test]
    fn tenant_memory_ceiling_is_applied_and_bounded() {
        let mut configured = tenant();
        configured.max_memory_bytes = 536_870_912;
        let hardened = harden_settings(
            "SELECT count() FROM __nano_lake_source__".to_string(),
            &configured,
        )
        .unwrap();
        assert!(hardened.contains("max_memory_usage=536870912"));
        assert!(hardened.contains("max_bytes_before_external_sort=268435456"));
        assert!(hardened.contains("max_bytes_before_external_group_by=268435456"));
        assert!(hardened.contains("max_temporary_data_on_disk_size_for_query=2147483648"));
        assert!(hardened.contains("max_block_size=8192"));
        assert!(hardened.contains("preferred_block_size_bytes=8388608"));
        assert!(hardened.contains("max_insert_threads=1"));

        configured.max_memory_bytes = MIN_QUERY_MEMORY_BYTES - 1;
        assert!(matches!(
            validate_tenant(&configured),
            Err(QueryPlanError::InvalidTenantConfig(_))
        ));
        configured.max_memory_bytes = MAX_QUERY_MEMORY_BYTES + 1;
        assert!(matches!(
            validate_tenant(&configured),
            Err(QueryPlanError::InvalidTenantConfig(_))
        ));
    }

    /// NAN-4168: every endpoint and enrichment path projects as a plain
    /// column read, never through a mask over `enrichments`.
    #[test]
    fn endpoint_and_enrichment_paths_project_as_plain_columns() {
        for root in ["src_endpoint", "dst_endpoint"] {
            for suffix in ["", ".ip", ".port", ".location", ".location.country", ".autonomous_system", ".autonomous_system.number"] {
                let path = format!("{root}{suffix}");
                let required = BTreeMap::from([(path.clone(), "object".into())]);
                let sql = projected_columns_sql(&required, &BTreeMap::new()).unwrap();
                assert_eq!(sql, format!("{} AS {}", nested_projection(&path).unwrap(), quoted_identifier(&path).unwrap()));
                assert!(!sql.contains("enrichments") && !sql.contains("arrayExists") && !sql.contains("owned_fields"), "{sql}");
            }
        }
        let required = BTreeMap::from([("enrichments.provider".into(), "array".into())]);
        let sql = projected_columns_sql(&required, &BTreeMap::new()).unwrap();
        assert!(!sql.contains("arrayFilter") && !sql.contains("arrayExists"), "{sql}");
    }

    #[test]
    fn typed_ungrouped_count_keeps_values_parameterized() {
        let predicate = CountPredicate {
            kind: CountPredicateKind::Contains,
            values: vec!["Windows'Sysmon".to_string()],
        };
        let plan = plan_count_aggregate_query(
            &tenant(),
            &manifest(),
            &CountAggregatePlanRequest {
                group_field: "metadata.log_source",
                group_results: false,
                multi_value: false,
                predicate: Some(&predicate),
                bucket_span_us: None,
                start_us: 1,
                end_exclusive_us: 2,
                source_filter: None,
                deny_source_types: &BTreeSet::new(),
                source: CountAggregateSource::Base,
                group_by_source: false,
            },
        )
        .unwrap()
        .unwrap();
        assert!(plan.sql.contains("CAST(NULL AS Nullable(String)) AS value"));
        assert!(!plan.sql.contains("GROUP BY value"));
        assert!(!plan.sql.contains("Windows'Sysmon"));
        assert!(plan.sql.contains("{raw_count_predicate_0:String}"));
        assert!(plan
            .params
            .iter()
            .any(|(name, value)| { name == "raw_count_predicate_0" && value == "windows'sysmon" }));
    }

    /// NAN-3166: search plans a scoped caller's count metrics (and, since
    /// NAN-3163, its count rollups) from the query without the injected
    /// source-scope gate, so the raw edge fragment that completes a rollup
    /// must itself drop every denied source (case-insensitively), in every
    /// shape those routes request.
    #[test]
    fn raw_count_fragments_exclude_every_denied_source() {
        let deny = BTreeSet::from(["audit".to_string(), "Windows_Security".to_string()]);
        let eq = CountPredicate { kind: CountPredicateKind::Eq, values: vec!["u-1".to_string()] };
        let shapes: [(&str, bool, Option<&CountPredicate>, Option<&str>, bool); 4] = [
            // `count()` metric and the plain count rollup.
            ("metadata.log_source", false, None, None, false),
            // A predicate metric under a user-written source filter.
            ("metadata.uid", false, Some(&eq), Some("windows_sysmon"), false),
            // A grouped count rollup page.
            ("metadata.uid", true, None, None, false),
            // A source-grouped page (NAN-3153).
            ("metadata.uid", false, Some(&eq), None, true),
        ];
        for (group_field, group_results, predicate, source_filter, group_by_source) in shapes {
            let plan = plan_count_aggregate_query(
                &tenant(),
                &manifest(),
                &CountAggregatePlanRequest {
                    group_field,
                    group_results,
                    multi_value: false,
                    predicate,
                    bucket_span_us: None,
                    start_us: 1,
                    end_exclusive_us: 2,
                    source_filter,
                    deny_source_types: &deny,
                    source: CountAggregateSource::Base,
                    group_by_source,
                },
            )
            .unwrap()
            .unwrap();
            let log_source = nested_expression("metadata.log_source").unwrap();
            for (index, source) in deny.iter().enumerate() {
                let name = format!("count_deny_source_{index}");
                assert!(
                    plan.sql.contains(&format!(
                        "lower(toString({log_source})) != lower({{{name}:String}})"
                    )),
                    "{group_field}: {}",
                    plan.sql
                );
                assert!(plan.params.contains(&(name, source.clone())), "{:?}", plan.params);
            }
            // The user's own source filter stays beside the exclusions.
            if let Some(source) = source_filter {
                assert!(plan.sql.contains("lower({count_source:String})"), "{}", plan.sql);
                assert!(plan.params.contains(&("count_source".to_string(), source.to_string())));
            }
        }
    }

    #[test]
    fn typed_regex_count_preserves_nano_case_insensitive_semantics() {
        let predicate = CountPredicate {
            kind: CountPredicateKind::Regex,
            values: vec![r"WINDOWS_.*".to_string()],
        };
        let plan = plan_count_aggregate_query(
            &tenant(),
            &manifest(),
            &CountAggregatePlanRequest {
                group_field: "metadata.log_source",
                group_results: false,
                multi_value: false,
                predicate: Some(&predicate),
                bucket_span_us: None,
                start_us: 1,
                end_exclusive_us: 2,
                source_filter: None,
                deny_source_types: &BTreeSet::new(),
                source: CountAggregateSource::Base,
                group_by_source: false,
            },
        )
        .unwrap()
        .unwrap();
        assert!(plan.sql.contains("match(toString("));
        assert!(plan.params.iter().any(|(name, value)| {
            name == "raw_count_predicate_0" && value == r"(?i)WINDOWS_.*"
        }));
    }

    /// NAN-3153: a source-grouped raw fragment applies the predicate to the
    /// requested field, groups by the row's log source exactly as the count
    /// rollup keys it (blank → NULL), and dotless host equality keeps Nano's
    /// FQDN expansion as bound parameters.
    #[test]
    fn typed_source_grouped_host_count_mirrors_the_rollup_contract() {
        let predicate = CountPredicate {
            kind: CountPredicateKind::HostEq,
            values: vec!["WS-Fin-011".to_string()],
        };
        let deny = BTreeSet::new();
        let request = |group_results: bool, group_field: &'static str| CountAggregatePlanRequest {
            group_field,
            group_results,
            multi_value: false,
            predicate: Some(&predicate),
            bucket_span_us: Some(600_000_000),
            start_us: 1,
            end_exclusive_us: 2,
            source_filter: None,
            deny_source_types: &deny,
            source: CountAggregateSource::Base,
            group_by_source: true,
        };
        let plan = plan_count_aggregate_query(&tenant(), &manifest(), &request(false, "metadata.uid"))
            .unwrap()
            .unwrap();
        assert!(plan.sql.contains(&format!(
            "{} AS value",
            count_source_group_expression(&nested_expression("metadata.log_source").unwrap())
        )));
        assert!(plan.sql.contains("GROUP BY bucket_start_us, value"));
        let uid = nested_expression("metadata.uid").unwrap();
        assert!(plan.sql.contains(&format!(
            "(lower(toString({uid})) = {{raw_count_predicate_0:String}} OR startsWith(lower(toString({uid})), {{raw_count_predicate_prefix_0:String}}))"
        )));
        assert!(plan.params.contains(&("raw_count_predicate_0".to_string(), "ws-fin-011".to_string())));
        assert!(plan.params.contains(&("raw_count_predicate_prefix_0".to_string(), "ws-fin-011.".to_string())));
        assert!(!plan.sql.contains("WS-Fin"));
        // Never with value grouping or on the source field itself.
        assert!(plan_count_aggregate_query(&tenant(), &manifest(), &request(true, "metadata.uid")).is_err());
        assert!(plan_count_aggregate_query(&tenant(), &manifest(), &request(false, "metadata.log_source")).is_err());
        // A host equality with a dot is already exact: refuse the expansion.
        let dotted = CountPredicate { kind: CountPredicateKind::HostEq, values: vec!["ws.corp".into()] };
        let mut predicates = Vec::new();
        assert!(append_count_predicate(&mut predicates, &mut Vec::new(), "v", Some(&dotted), "p", false).is_err());
        assert!(append_count_predicate(&mut predicates, &mut Vec::new(), "v", Some(&predicate), "p", true).is_err());
        let wire: CountPredicate = serde_json::from_str(r#"{"kind":"host_eq","values":["h"]}"#).unwrap();
        assert_eq!(wire.kind, CountPredicateKind::HostEq);
    }

    #[test]
    fn typed_grouped_count_retains_grouping_without_a_predicate() {
        let plan = plan_count_aggregate_query(
            &tenant(),
            &manifest(),
            &CountAggregatePlanRequest {
                group_field: "metadata.log_source",
                group_results: true,
                multi_value: false,
                predicate: None,
                bucket_span_us: None,
                start_us: 1,
                end_exclusive_us: 2,
                source_filter: None,
                deny_source_types: &BTreeSet::new(),
                source: CountAggregateSource::Base,
                group_by_source: false,
            },
        )
        .unwrap()
        .unwrap();
        assert!(plan.sql.contains("AS value"));
        assert!(plan.sql.contains("GROUP BY value SETTINGS"));
    }

    #[test]
    fn immutable_snapshot_cache_replaces_remote_base_and_candidate_reads() {
        let cache_path = PathBuf::from("/cache/generation/data/one.parquet");
        let mut cached_tenant = tenant();
        cached_tenant.snapshot_cache = Some(SnapshotCache {
            source_spec: cache_path.display().to_string(),
            objects: BTreeMap::from([(
                "s3://bucket/table/data/one.parquet".to_string(),
                SnapshotCacheObject {
                    version_id: "version-1".to_string(),
                    bytes: 900,
                    path: cache_path.clone(),
                },
            )]),
            bytes: 900,
            read_schema: Some(
                "`time` DateTime64(6, 'UTC'), `metadata` Tuple(`log_source` Nullable(String))"
                    .to_string(),
            ),
            bootstrap: false,
        });
        let query = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE `metadata.log_source` = 'sysmon'",
            vec![
                column("metadata.log_source", "string"),
                column("time", "timestamp"),
            ],
        );
        let broad = plan_broad_log_query(&cached_tenant, &manifest(), &query).unwrap();
        assert!(broad.sql.contains(
            "file({snapshot_cache_source:String}, Parquet, {snapshot_cache_read_schema:String})"
        ));
        assert!(broad.params.iter().any(|(name, value)| {
            name == "snapshot_cache_source" && value == cache_path.to_str().unwrap()
        }));
        assert!(broad.params.iter().any(|(name, value)| {
            name == "snapshot_cache_read_schema" && value.contains("`metadata` Tuple")
        }));

        let candidate = CandidateBlock {
            event_object_key: "s3://bucket/table/data/one.parquet".to_string(),
            event_object_bytes: 900,
            row_start: 0,
            row_end: 10,
            max_time_ms: None,
            time_range_us: None,
        };
        let selective = plan_broad_log_query_with_candidates(
            &cached_tenant,
            &manifest(),
            &query,
            Some(&[candidate]),
        )
        .unwrap();
        assert!(selective.sql.contains(
            "file({candidate_source:String}, Parquet, {candidate_source_read_schema:String})"
        ));
        assert!(selective.params.iter().any(|(name, value)| {
            name == "candidate_path_0" && value == cache_path.to_str().unwrap()
        }));
    }

    #[test]
    fn snapshot_cache_identity_mismatch_fails_closed() {
        let mut cached_tenant = tenant();
        cached_tenant.snapshot_cache = Some(SnapshotCache {
            source_spec: "/cache/one.parquet".to_string(),
            objects: BTreeMap::from([(
                "s3://bucket/table/data/one.parquet".to_string(),
                SnapshotCacheObject {
                    version_id: "wrong-version".to_string(),
                    bytes: 900,
                    path: PathBuf::from("/cache/one.parquet"),
                },
            )]),
            bytes: 900,
            read_schema: None,
            bootstrap: false,
        });
        assert!(matches!(
            validate_manifest(&cached_tenant, &manifest()),
            Err(QueryPlanError::InvalidManifest(_))
        ));
    }

    fn tenant() -> TenantQueryConfig {
        TenantQueryConfig {
            tenant_id: "tenant-a".to_string(),
            source: "https://object.test/bucket/table".to_string(),
            iceberg_metadata_file_path: "metadata/00001.metadata.json".to_string(),
            max_query_bytes: 1_000,
            max_memory_bytes: DEFAULT_QUERY_MEMORY_BYTES,
            max_execution_seconds: 30,
            threads: 4,
            credentials: ObjectStoreCredentials::Static {
                access_key: "access".to_string(),
                secret_key: "secret".to_string(),
                session_token: None,
            },
            snapshot_cache: None,
        }
    }

    fn manifest() -> SourceManifest {
        SourceManifest {
            tenant_id: "tenant-a".to_string(),
            objects: vec![ManifestObject {
                event_object_key: "s3://bucket/table/data/one.parquet".to_string(),
                event_object_version: "version-1".to_string(),
                event_object_bytes: 900,
                rows: 100,
                available_paths: vec![
                    "time".to_string(),
                    "resources.hostname".to_string(),
                    "metadata.log_source".to_string(),
                    "metadata.uid".to_string(),
                ]
                .into(),
                field_types: BTreeMap::from([
                    ("time".to_string(), "timestamp".to_string()),
                    ("resources.hostname".to_string(), "array".to_string()),
                    ("metadata.log_source".to_string(), "string".to_string()),
                    ("metadata.uid".to_string(), "string".to_string()),
                ]),
                column_compressed_bytes: BTreeMap::new(),
            }],
            ..Default::default()
        }
    }

    /// NAN-3149: an entity pivot over time-sorted parts keeps nearly every
    /// row group (a host appears in every 65,536-row group), so one pruned
    /// group made every file carry a per-row `_path`/`_row_number` fence and
    /// time guard: ~3x the scan CPU for identical rows. Whole-kept files are
    /// read unfenced; only the partially kept file keeps its exact fence.
    #[test]
    fn whole_kept_files_drop_per_row_fences_and_partial_files_keep_them() {
        let object = |name: &str| ManifestObject {
            event_object_key: format!("s3://bucket/table/data/{name}.parquet"),
            event_object_version: format!("v-{name}"),
            event_object_bytes: 900,
            rows: 100,
            ..manifest().objects[0].clone()
        };
        let manifest = SourceManifest { objects: vec![object("one"), object("two"), object("three")], ..manifest() };
        let mut cached = tenant();
        cached.snapshot_cache = Some(SnapshotCache {
            source_spec: "/cache/objects/{one,two,three}.bin".into(),
            objects: ["one", "two", "three"].iter().map(|name| (format!("s3://bucket/table/data/{name}.parquet"), SnapshotCacheObject {
                version_id: format!("v-{name}"), bytes: 900, path: format!("/cache/objects/{name}.bin").into(),
            })).collect(),
            bytes: 2_700,
            read_schema: Some("`time` DateTime64(6, 'UTC')".into()),
            bootstrap: false,
        });
        let block = |name: &str, start: u64, end: u64| CandidateBlock {
            event_object_key: format!("s3://bucket/table/data/{name}.parquet"), event_object_bytes: 900,
            row_start: start, row_end: end, max_time_ms: None, time_range_us: Some((start as i64, end as i64)) };
        // Every file kept whole (two of them as adjacent blocks): no fence at all.
        let (source, params, budget) = candidate_source(&cached, &manifest,
            &[block("one", 0, 100), block("two", 0, 40), block("two", 40, 100)], BudgetEnforcement::ReportOnly, Some("time")).unwrap();
        assert!(!source.contains("_row_number") && !source.contains("_path =") && !source.contains("time >="), "{source}");
        assert!(!source.contains("UNION ALL"), "{source}");
        assert_eq!(budget.candidate_objects, 2);
        let whole = &params.iter().find(|(name, _)| name == "candidate_source").unwrap().1;
        assert!(whole.contains("one.bin") && whole.contains("two.bin") && !whole.contains("three"), "{whole}");
        // One file with a pruned group: only it keeps the exact fence.
        let (source, params, budget) = candidate_source(&cached, &manifest,
            &[block("one", 0, 100), block("two", 0, 100), block("three", 0, 30), block("three", 60, 100)], BudgetEnforcement::ReportOnly, Some("time")).unwrap();
        assert_eq!(source.matches("UNION ALL").count(), 1, "{source}");
        // Only the partial file is fenced: [0, 30) and [60, 100) of 100 rows
        // are granules 0, 2 and 3 of 30 rows (keys g * 2 + 1).
        assert!(source.contains("transform(_path, [{candidate_path_2:String}], [30], 1)) * 2 + transform(_path, [{candidate_path_2:String}], [1], 0)) IN (1,5,7)"), "{source}");
        assert!(!source.contains("candidate_path_0") && !source.contains("candidate_path_1"), "{source}");
        assert_eq!(budget.candidate_objects, 3);
        let partial = &params.iter().find(|(name, _)| name == "candidate_partial_source").unwrap().1;
        assert!(partial.ends_with("three.bin"), "{partial}");
        let whole = &params.iter().find(|(name, _)| name == "candidate_source").unwrap().1;
        assert!(!whole.contains("three"), "{whole}");
        // A gap means partial even when the ends are covered.
        let (source, _, _) = candidate_source(&cached, &manifest,
            &[block("one", 0, 50), block("one", 51, 100)], BudgetEnforcement::ReportOnly, Some("time")).unwrap();
        assert!(source.contains("_row_number") && !source.contains("UNION ALL"), "{source}");
        // Without an explicit read schema the branches could disagree: keep the fence.
        let mut inferred = cached.clone();
        inferred.snapshot_cache.as_mut().unwrap().read_schema = None;
        let (source, _, _) = candidate_source(&inferred, &manifest, &[block("one", 0, 100)], BudgetEnforcement::ReportOnly, Some("time")).unwrap();
        assert!(source.contains("_row_number"), "{source}");
        // A glob-shaped cache path keeps its exact file guard.
        let mut glob = cached.clone();
        glob.snapshot_cache.as_mut().unwrap().objects.get_mut("s3://bucket/table/data/one.parquet").unwrap().path = "/cache/one*.bin".into();
        let (source, _, _) = candidate_source(&glob, &manifest, &[block("one", 0, 100)], BudgetEnforcement::ReportOnly, Some("time")).unwrap();
        assert!(source.contains("transform(_path, [{candidate_path_0:String}]"), "{source}");
    }

    #[test]
    fn set_fence_is_exact_on_every_row_and_one_probe_per_row() {
        let key = |name: &str| format!("s3://bucket/table/data/{name}.parquet");
        let (one, two, three, four) = (key("one"), key("two"), key("three"), key("four"));
        // Aligned 8,192-row groups and 1,024-row runs, an irregular
        // byte-capped group, overlapping and adjacent blocks, a file end
        // that is no multiple of anything, and a single row.
        let blocks = [
            (&one, 50_000_u64, 0_u64, 8_192_u64), (&one, 50_000, 16_384, 17_408), (&one, 50_000, 40_960, 50_000),
            (&two, 30_001, 1_024, 2_048), (&two, 30_001, 1_500, 4_096), (&two, 30_001, 4_096, 5_120), (&two, 30_001, 29_000, 30_001),
            (&three, 10_000, 7_777, 7_778),
            (&four, 9_000, 0, 9_000),
        ];
        let fenced = blocks.iter().enumerate().map(|(index, (key, rows, start, end))| FencedBlock {
            index, object_key: key.as_str(), object_rows: *rows, row_start: *start, row_end: *end,
        }).collect::<Vec<_>>();
        for set in [true, false] {
            let mut params = Vec::new();
            let fence = row_fence(&tenant(), &fenced, set, &mut params).unwrap();
            if set {
                assert_eq!(fence.matches(" IN (").count(), 1, "{fence}");
                assert!(!fence.contains(" OR "), "every file fits the set: {fence}");
                assert_eq!(fence.matches("transform(_path").count(), 2, "{fence}");
                assert_eq!(params.len(), 4, "one path parameter per file: {params:?}");
            } else {
                assert_eq!(fence.matches("_path = ").count(), blocks.len(), "{fence}");
            }
            let terms = parse_fence(&fence, &params);
            for (key, rows) in [(&one, 50_000_u64), (&two, 30_001), (&three, 10_000), (&four, 9_000), (&key("other"), 50_000)] {
                let path = iceberg_virtual_path(key).unwrap();
                // Rows past a file's end do not exist; every row that does is exact.
                for row in 0..rows {
                    let want = blocks.iter().any(|(k, _, s, e)| *k == key && (*s..*e).contains(&row));
                    assert_eq!(fence_matches(&terms, &path, row), want, "set={set} {key} row {row}");
                }
            }
        }
    }

    /// NAN-3179: adjacent row groups of a time-sorted file are one guard
    /// range each with an inter-event gap between them; those merge, while
    /// gaps as wide as the ranges (skipped groups) stay.
    #[test]
    fn time_guard_merges_only_gaps_much_narrower_than_its_ranges() {
        assert_eq!(merge_close_time_ranges(vec![(0, 1_000)]), vec![(0, 1_000)]);
        // Mean length 1,000: gaps up to 62 merge.
        let ranges = vec![(0, 1_000), (1_050, 2_050), (2_112, 3_112), (3_175, 4_175), (9_000, 10_000)];
        assert_eq!(merge_close_time_ranges(ranges), vec![(0, 3_112), (3_175, 4_175), (9_000, 10_000)]);
        // Sparse runs: every gap wider than the runs stays exact.
        let runs = (0..144_i64).map(|i| (i * 600, i * 600 + 26)).collect::<Vec<_>>();
        assert_eq!(merge_close_time_ranges(runs.clone()), runs);
        // A dense day of 8,192-row groups (~2 min each, 3 ms apart): one range.
        let dense = (0..300_i64).map(|i| (i * 120_003, i * 120_003 + 120_000)).collect::<Vec<_>>();
        assert_eq!(merge_close_time_ranges(dense), vec![(0, 299 * 120_003 + 120_000)]);
        // Point ranges (single-row blocks) never merge across a gap.
        assert_eq!(merge_close_time_ranges(vec![(5, 5), (7, 7)]), vec![(5, 5), (7, 7)]);
    }

    /// The fenced source stays inside chDB's 256 KiB `max_query_size` at the
    /// planner's 4,096-block bound for granule-aligned blocks (row groups,
    /// 1,024-row runs) with sparse times; the OR form passed it at ~3,000
    /// blocks. (Blocks with no common granule spill to OR terms, as before.)
    #[test]
    fn set_fenced_source_fits_the_query_size_at_the_block_bound() {
        let big = SourceManifest {
            objects: vec![ManifestObject { rows: 300_000_000, ..manifest().objects[0].clone() }],
            ..manifest()
        };
        let t0 = 1_790_640_000_000_000_i64;
        for (stride, offset) in [(8_192_u64, 0_u64), (65_536, 2_048)] {
            let blocks = (0..4_096_u64).map(|i| CandidateBlock {
                event_object_key: "s3://bucket/table/data/one.parquet".to_string(),
                event_object_bytes: 900,
                row_start: i * stride + offset,
                row_end: i * stride + offset + 1_024,
                max_time_ms: None,
                time_range_us: Some((t0 + i as i64 * 600_000_000, t0 + i as i64 * 600_000_000 + 26_000_000)),
            }).collect::<Vec<_>>();
            let (source, _, _) = candidate_source(&tenant(), &big, &blocks, BudgetEnforcement::ReportOnly, Some("time")).unwrap();
            assert!(source.len() < 200_000, "stride {stride}: {} bytes", source.len());
            assert!(source.contains("indexHint(") && source.contains("toUnixTimestamp64Micro"), "stride {stride}");
        }
    }

    /// NAN-4211: the window entity index's exact runs over a busy host's 7d
    /// (live: ~3,000 runs in ~2,500 one-row-group files) fence every
    /// file; the rendered source outgrew chDB's 256 KiB `max_query_size`.
    /// The estimate bounds the rendered fence and guard (so the engine can
    /// decline that selection), and stays under budget at the one-file
    /// block bound above.
    #[test]
    fn fence_estimate_bounds_the_rendered_source_and_flags_many_file_selections() {
        let t0 = 1_790_640_000_000_000_i64;
        let files = 3_000_u64;
        let key = |file: u64| format!("s3://bucket/table/data/2026/10/{file:05}-0123456789abcdef.parquet");
        let objects = (0..files)
            .map(|file| ManifestObject { event_object_key: key(file), rows: 100_000, ..manifest().objects[0].clone() })
            .collect::<Vec<_>>();
        let big = SourceManifest { objects, ..manifest() };
        let blocks = (0..files)
            .map(|file| CandidateBlock {
                event_object_key: key(file),
                event_object_bytes: 900,
                row_start: 3_072 + file % 7 * 1_024,
                row_end: 4_096 + file % 7 * 1_024,
                max_time_ms: None,
                time_range_us: Some((t0 + file as i64 * 240_000_000, t0 + file as i64 * 240_000_000 + 9_000_000)),
            })
            .collect::<Vec<_>>();
        let rows = |key: &str| big.objects.iter().find(|object| object.event_object_key == key).map(|object| object.rows);
        let estimate = candidate_fence_sql_bytes(&blocks, &rows);
        let (source, _, _) = candidate_source(&tenant(), &big, &blocks, BudgetEnforcement::ReportOnly, Some("time")).unwrap();
        assert!(estimate > MAX_FENCE_SQL_BYTES, "many-file selection must be flagged: {estimate} bytes");
        assert!(source.len() > 256 * 1024, "the fixture reproduces the overflow: {} bytes", source.len());
        assert!(source.len() <= estimate + 64 * 1024, "estimate tracks the rendered fence: {estimate} vs {}", source.len());

        // The one-file 4,096-block bound still fits (fine runs stay usable).
        let one = SourceManifest { objects: vec![ManifestObject { rows: 300_000_000, ..manifest().objects[0].clone() }], ..manifest() };
        let blocks = (0..4_096_u64)
            .map(|i| CandidateBlock {
                event_object_key: "s3://bucket/table/data/one.parquet".to_string(),
                event_object_bytes: 900,
                row_start: i * 8_192,
                row_end: i * 8_192 + 1_024,
                max_time_ms: None,
                time_range_us: Some((t0 + i as i64 * 600_000_000, t0 + i as i64 * 600_000_000 + 26_000_000)),
            })
            .collect::<Vec<_>>();
        let rows = |key: &str| one.objects.iter().find(|object| object.event_object_key == key).map(|object| object.rows);
        let estimate = candidate_fence_sql_bytes(&blocks, &rows);
        let (source, _, _) = candidate_source(&tenant(), &one, &blocks, BudgetEnforcement::ReportOnly, Some("time")).unwrap();
        assert!(estimate <= MAX_FENCE_SQL_BYTES, "{estimate}");
        assert!(estimate <= source.len(), "the estimate is the fence and guard inside the source: {estimate} vs {}", source.len());
    }

    #[test]
    fn time_range_cap_merges_the_smallest_gaps() {
        let ranges = vec![(0, 10), (11, 20), (1_000, 1_010), (1_012, 1_020), (5_000, 5_001)];
        assert_eq!(cap_time_ranges(ranges.clone(), 5), ranges);
        assert_eq!(cap_time_ranges(ranges.clone(), 3), vec![(0, 20), (1_000, 1_020), (5_000, 5_001)]);
        assert_eq!(cap_time_ranges(ranges.clone(), 2), vec![(0, 1_020), (5_000, 5_001)]);
        assert_eq!(cap_time_ranges(ranges, 1), vec![(0, 5_001)]);
        let many = (0..3_000_i64).map(|i| (i * 100, i * 100 + 40 + i % 7)).collect::<Vec<_>>();
        let capped = cap_time_ranges(many.clone(), MAX_TIME_GUARD_HINT_RANGES);
        assert_eq!(capped.len(), MAX_TIME_GUARD_HINT_RANGES);
        assert!(many.iter().all(|(s, e)| capped.iter().any(|(cs, ce)| cs <= s && e <= ce)));
    }

    #[test]
    fn time_guard_buckets_cover_every_instant_within_the_budget() {
        let runs = (0..144_i64).map(|i| (1_790_640_000_000_000 + i * 600_000_000, 1_790_640_000_000_000 + i * 600_000_000 + 26_000_000)).collect::<Vec<_>>();
        let (width, buckets) = time_guard_buckets(&runs);
        assert!(buckets.len() <= MAX_TIME_GUARD_BUCKETS && width.count_ones() == 1, "{width} {}", buckets.len());
        // The narrowest width within budget: half of it would not fit.
        assert!(width == 1 || runs.iter().map(|(s, e)| (e / (width / 2) - s / (width / 2) + 1) as usize).sum::<usize>() > MAX_TIME_GUARD_BUCKETS);
        let set = buckets.iter().copied().collect::<BTreeSet<_>>();
        for (start, end) in &runs {
            for t in [*start, start + 1, (start + end) / 2, end - 1, *end] {
                assert!(set.contains(&t.div_euclid(width)), "{t}");
            }
        }
        // Points far from every range fall outside.
        assert!(!set.contains(&(runs[0].1 + 300_000_000).div_euclid(width)));
        // Small ranges keep microsecond buckets.
        assert_eq!(time_guard_buckets(&[(10, 12), (20, 20)]), (1, vec![10, 11, 12, 20]));
    }

    /// NAN-3422: a Beats-shaped source left `unmapped.@timestamp`,
    /// `unmapped.@version` and `unmapped.@metadata.beat` in the stored schema.
    /// The planner refused the whole manifest ("column path segment is
    /// invalid: @timestamp"), so a search on any other source failed. Those
    /// leaves are now unaddressable but the stored `unmapped` root is still
    /// projected, and every other query plans.
    #[test]
    fn nan3422_unaddressable_stored_leaves_never_fail_unrelated_queries() {
        let mut source = manifest();
        let object = &mut source.objects[0];
        let mut paths = object.available_paths.to_vec();
        for path in ["unmapped.@timestamp", "unmapped.@version", "unmapped.@metadata.beat", "unmapped.winlog.event_id"] {
            paths.push(path.to_string());
            object.field_types.insert(path.to_string(), "string".to_string());
        }
        object.available_paths = paths.into();

        let types = snapshot_field_types(&source).unwrap();
        assert!(types.contains_key("unmapped.winlog.event_id"));
        assert!(!types.keys().any(|path| path.contains('@')), "{types:?}");

        let filtered = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE `metadata.log_source` = 'conduit_proxy'",
            vec![column("metadata.log_source", "string"), column("time", "timestamp")],
        );
        let plan = plan_broad_log_query(&tenant(), &source, &filtered).unwrap();
        assert!(!plan.sql.contains('@'), "{}", plan.sql);

        let full = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE `unmapped.winlog.event_id` = '1'",
            vec![column("unmapped.winlog.event_id", "string"), column("time", "timestamp")],
        );
        let plan = plan_broad_log_query(&tenant(), &source, &full).unwrap();
        assert!(plan.sql.contains("`unmapped`"), "the stored root stays projected: {}", plan.sql);
        assert!(!plan.sql.contains('@'), "{}", plan.sql);

        let mut available = BTreeSet::new();
        insert_addressable_path(&mut available, "unmapped.@metadata.beat").unwrap();
        insert_addressable_path(&mut available, "@timestamp").unwrap();
        assert_eq!(available, BTreeSet::from(["unmapped".to_string()]));
        assert_eq!(
            roots_for_available_paths(["@timestamp", "unmapped.@version", "time"].into_iter()),
            BTreeSet::from(["time".to_string(), "unmapped".to_string()])
        );
    }

    #[test]
    fn many_sparse_time_ranges_emit_an_index_hint_and_a_bucket_guard() {
        let query = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE \"resources.hostname\" = 'host'",
            vec![column("resources.hostname", "array"), column("time", "timestamp")],
        );
        let t0 = 1_790_640_000_000_000_i64;
        let block = |n: i64| CandidateBlock {
            event_object_key: "s3://bucket/table/data/one.parquet".to_string(),
            event_object_bytes: 900,
            row_start: n as u64,
            row_end: n as u64 + 1,
            max_time_ms: None,
            time_range_us: Some((t0 + n * 600_000_000, t0 + n * 600_000_000 + 26_000_000)),
        };
        let few = (0..MAX_EXACT_TIME_GUARD_RANGES as i64).map(block).collect::<Vec<_>>();
        let plan = plan_broad_log_query_with_candidates(&tenant(), &manifest(), &query, Some(&few)).unwrap();
        assert!(!plan.sql.contains("indexHint") && !plan.sql.contains("toUnixTimestamp64Micro"), "{}", plan.sql);
        assert_eq!(plan.sql.matches("(time >= '").count(), MAX_EXACT_TIME_GUARD_RANGES);
        let many = (0..90).map(block).collect::<Vec<_>>();
        let plan = plan_broad_log_query_with_candidates(&tenant(), &manifest(), &query, Some(&many)).unwrap();
        let hint = plan.sql.find("(indexHint(").expect("hint");
        let buckets = plan.sql.find(") AND intDiv(toUnixTimestamp64Micro(time), ").expect("bucket guard");
        assert_eq!(plan.sql[hint..buckets].matches("(time >= '").count(), 90, "{}", plan.sql);
        assert!(plan.sql[buckets..].starts_with(") AND intDiv(toUnixTimestamp64Micro(time), 2097152) IN ("), "{}", &plan.sql[buckets..]);
    }

    /// The emitted guard is the merged one under the set fence and the
    /// per-range one under the kill switch's OR fence (exercised through
    /// `row_fence(.., false, ..)` only, the environment being process-wide).
    #[test]
    fn dense_candidates_emit_one_guard_range() {
        let query = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE \"resources.hostname\" = 'host'",
            vec![column("resources.hostname", "array"), column("time", "timestamp")],
        );
        let t0 = 1_790_640_000_000_000_i64;
        let block = |n: i64| CandidateBlock {
            event_object_key: "s3://bucket/table/data/one.parquet".to_string(),
            event_object_bytes: 900,
            row_start: n as u64,
            row_end: n as u64 + 1,
            max_time_ms: None,
            time_range_us: Some((t0 + n * 10_000_003, t0 + n * 10_000_003 + 10_000_000)),
        };
        let dense = (0..90).map(block).collect::<Vec<_>>();
        let plan = plan_broad_log_query_with_candidates(&tenant(), &manifest(), &query, Some(&dense)).unwrap();
        assert_eq!(plan.sql.matches("(time >= '").count(), 1, "{}", plan.sql);
    }

    #[test]
    fn or_fence_kill_switch_keeps_one_term_per_block() {
        let key = "s3://bucket/table/data/one.parquet";
        let fenced = [(10, 20), (40, 50)].iter().enumerate().map(|(index, (start, end))| FencedBlock {
            index, object_key: key, object_rows: 100, row_start: *start, row_end: *end,
        }).collect::<Vec<_>>();
        let mut params = Vec::new();
        let fence = row_fence(&tenant(), &fenced, false, &mut params).unwrap();
        assert_eq!(fence, "(_path = {candidate_path_0:String} AND _row_number >= 10 AND _row_number < 20) OR (_path = {candidate_path_1:String} AND _row_number >= 40 AND _row_number < 50)");
        assert_eq!(params.len(), 2);
    }

    /// A file whose granules would pass the key budget keeps exact OR
    /// terms over its merged ranges; the others stay in the set.
    #[test]
    fn set_fence_spills_files_past_the_key_budget_to_or_terms() {
        let (small, big) = ("s3://bucket/table/data/small.parquet", "s3://bucket/table/data/big.parquet");
        // gcd(3, 3 + 3 * MAX) = 3: MAX + 1 keys for `big`.
        let big_end = 3 + 3 * MAX_FENCE_SET_KEYS;
        let fenced = vec![
            FencedBlock { index: 0, object_key: small, object_rows: 100, row_start: 0, row_end: 10 },
            FencedBlock { index: 1, object_key: big, object_rows: big_end + 7, row_start: 3, row_end: big_end / 2 },
            FencedBlock { index: 2, object_key: big, object_rows: big_end + 7, row_start: big_end / 2, row_end: big_end + 3 },
        ];
        let mut params = Vec::new();
        let fence = row_fence(&tenant(), &fenced, true, &mut params).unwrap();
        assert!(fence.contains("[{candidate_path_0:String}], [10], 1)"), "{fence}");
        assert!(fence.ends_with(&format!(" OR (_path = {{candidate_path_1:String}} AND _row_number >= 3 AND _row_number < {})", big_end + 3)), "{fence}");
        let path = iceberg_virtual_path(big).unwrap();
        for row in [0, 2, 3, big_end / 2, big_end + 2, big_end + 3] {
            assert_eq!(fence_matches(&parse_fence(&fence, &params), &path, row), (3..big_end + 3).contains(&row), "row {row}");
        }
    }

    #[test]
    fn whole_file_candidates_keep_exact_source_and_virtual_row_fences() {
        let block = CandidateBlock { event_object_key: "s3://bucket/table/data/one.parquet".into(),
            event_object_bytes: 900, row_start: 0, row_end: 100, max_time_ms: None,
            time_range_us: Some((1, 2)) };
        let (source, params, budget) = candidate_source(&tenant(), &manifest(), &[block.clone()], BudgetEnforcement::ReportOnly, Some("time")).unwrap();
        assert!(source.contains("_row_number"), "{source}");
        assert!(source.contains("transform(_path, [{candidate_path_0:String}]"), "{source}");
        assert!(source.contains("time >="));
        assert_eq!(budget.candidate_objects, 1);
        assert!(params.iter().any(|(name, path)| name == "candidate_source" && path.ends_with("one.parquet")));
        let mut partial = block;
        partial.row_end = 99;
        let (source, _, _) = candidate_source(&tenant(), &manifest(), &[partial.clone()], BudgetEnforcement::ReportOnly, Some("time")).unwrap();
        assert!(source.contains("[99], 1)) * 2 + transform(_path, [{candidate_path_0:String}], [1], 0)) IN (1)"), "partial groups still need their exact row fence: {source}");
        // A literal wildcard filename must not widen an exact object read.
        let mut cached = tenant();
        cached.snapshot_cache = Some(SnapshotCache { source_spec: "/cache/one*.parquet".into(),
            objects: BTreeMap::from([("s3://bucket/table/data/one.parquet".into(), SnapshotCacheObject {
                version_id: "version-1".into(), bytes: 900, path: "/cache/one*.parquet".into(),
            })]), bytes: 900, read_schema: None, bootstrap: false });
        partial.row_end = 100;
        let (source, _, _) = candidate_source(&cached, &manifest(), &[partial], BudgetEnforcement::ReportOnly, Some("time")).unwrap();
        assert!(source.contains("transform(_path, [{candidate_path_0:String}]"), "retain the file guard for glob-shaped cache paths: {source}");
    }

    /// A mandatory sidecar that matched nothing proves the generation cannot
    /// contribute a row — the predicate is already constant false. Naming the
    /// whole Iceberg table anyway made "no results" the most expensive answer
    /// the system could give: 1.0-2.9s, against 0.12s for the same query shape
    /// returning 17,000 rows.
    #[test]
    fn an_empty_candidate_set_never_names_the_whole_iceberg_table() {
        let (source, _params, budget) =
            candidate_source(&tenant(), &manifest(), &[], BudgetEnforcement::Reject, None)
                .expect("empty candidate source");

        assert!(
            source.contains("WHERE 0"),
            "an empty candidate set must read no rows: {source}"
        );
        assert!(
            !source.contains("icebergS3") && !source.contains("iceberg("),
            "an empty candidate set must not resolve the Iceberg table: {source}"
        );
        assert_eq!(budget.candidate_objects, 0);
        assert_eq!(budget.estimated_scan_bytes, 0);
    }

    /// The manifest cannot change while a generation is loaded, so the planner
    /// derives its facts once. Measured before this: 25.4ms per merge in
    /// release on a 714-object generation, paid two to three times per request.
    #[test]
    fn manifest_facts_are_derived_once_and_reused() {
        let manifest = manifest();
        let first = manifest.facts().expect("facts") as *const ManifestFacts;
        let second = manifest.facts().expect("facts") as *const ManifestFacts;
        assert_eq!(first, second, "a second call must reuse the derived facts");

        let (available, budget) = validate_manifest(&tenant(), &manifest).expect("validate");
        assert!(available.contains("metadata.log_source"));
        assert!(
            available.contains("metadata"),
            "dotted prefixes must still be expanded"
        );
        assert_eq!(budget.estimated_scan_bytes, 900);
        assert_eq!(
            snapshot_field_types(&manifest).expect("field types")["metadata.uid"],
            "string"
        );
    }

    /// Progressive paging fences each chunk to its own window, so a chunk must
    /// only read blocks that can contain a row in that window.
    ///
    /// Failure this prevents: filtering on the chunk's start alone. Every block
    /// belonging to a *newer* chunk necessarily has `max_time_ms` at or after an
    /// older chunk's start, so each chunk re-read all of them and the SQL time
    /// fence then threw the rows away — quadratic in chunks executed. Measured
    /// on a 24-hour hunt as the generation accumulated objects: 17,339 rows
    /// scanned at ~25 candidate objects, 382,569 at 101, same query, same plan.
    #[test]
    fn a_chunk_reads_only_blocks_its_own_window_can_contain() {
        const HOUR_MS: u64 = 3_600_000;
        let block = |hour: u64, max_time_ms: Option<u64>| CandidateBlock {
            event_object_key: format!(
                "s3://bucket/table/data/event_hour={hour}/part-{hour}.parquet"
            ),
            event_object_bytes: 100,
            row_start: 0,
            row_end: 10,
            max_time_ms,
            time_range_us: None,
        };
        // A chunk covering hour 500_010 only.
        let (start, end) = (500_010 * HOUR_MS, 500_011 * HOUR_MS - 1);

        assert!(
            candidate_block_overlaps_window(&block(500_010, Some(start + 5)), start, end),
            "a block inside the chunk must be read"
        );
        assert!(
            !candidate_block_overlaps_window(&block(500_020, Some(500_020 * HOUR_MS)), start, end),
            "a block from a NEWER chunk must not be re-read — this is the quadratic bug"
        );
        assert!(
            !candidate_block_overlaps_window(&block(500_001, Some(500_001 * HOUR_MS)), start, end),
            "a block wholly older than the chunk stays excluded"
        );
    }

    /// Both fences stay conservative: anything unprovable is still read, time_range_us: None, because
    /// dropping a block that could hold a matching row loses events.
    #[test]
    fn an_unprovable_candidate_block_is_still_read() {
        const HOUR_MS: u64 = 3_600_000;
        let (start, end) = (500_010 * HOUR_MS, 500_011 * HOUR_MS - 1);
        let untrusted = CandidateBlock {
            event_object_key: "s3://bucket/table/data/legacy-flat.parquet".to_string(),
            event_object_bytes: 100,
            row_start: 0,
            row_end: 10,
            max_time_ms: None,
            time_range_us: None,
        };
        assert!(
            candidate_block_overlaps_window(&untrusted, start, end),
            "no hour partition and no max_time means unknown coverage: keep it"
        );
        let no_max_time = CandidateBlock {
            event_object_key: format!("s3://b/t/data/event_hour=500010/p.parquet"),
            event_object_bytes: 100,
            row_start: 0,
            row_end: 10,
            max_time_ms: None,
            time_range_us: None,
        };
        assert!(candidate_block_overlaps_window(&no_max_time, start, end));
    }

    /// The per-object schema copies are dead weight once the facts exist, and
    /// they are the term that grows with object count — 714 objects carried
    /// 150,974 field-type entries, ~211 identical keys repeated per object.
    ///
    /// Failure this prevents: releasing them before the facts are derived, which
    /// would leave `facts()` to rebuild from emptied objects and silently return
    /// an empty field-type map — a query compiler with no schema, not an error.
    #[test]
    fn releasing_per_object_schema_keeps_the_derived_facts_intact() {
        let mut manifest = manifest();
        let before = snapshot_field_types(&manifest).expect("field types");
        assert!(before.contains_key("metadata.uid"));
        assert!(!manifest.objects[0].field_types.is_empty());

        manifest
            .release_derived_object_schema()
            .expect("release per-object schema");

        assert!(
            manifest.objects[0].field_types.is_empty(),
            "the per-object copies must actually be released"
        );
        assert_eq!(
            snapshot_field_types(&manifest).expect("field types after release"),
            before,
            "the merged view must be unchanged by releasing what it subsumes"
        );
        let (available, budget) = validate_manifest(&tenant(), &manifest).expect("validate");
        assert!(available.contains("metadata.log_source"));
        assert_eq!(budget.estimated_scan_bytes, 900);
    }

    /// Objects only differ in schema where the schema evolved, so the same few
    /// path lists repeat across a whole generation. Sharing them makes this term
    /// grow with schema history instead of object count — the axis that decides
    /// how long a table can live rather than how much data it holds.
    ///
    /// Failure this prevents: storing one copy per object. Measured on a real
    /// 714-object generation, 16 distinct shapes accounted for all 150,974
    /// stored paths.
    #[test]
    fn objects_of_the_same_schema_share_one_path_list() {
        let mut manifest = manifest();
        let second = ManifestObject {
            event_object_key: "s3://bucket/table/data/two.parquet".to_string(),
            event_object_version: "version-2".to_string(),
            event_object_bytes: 900,
            rows: 100,
            available_paths: manifest.objects[0].available_paths.to_vec().into(),
            field_types: manifest.objects[0].field_types.clone(),
            column_compressed_bytes: BTreeMap::new(),
        };
        manifest.objects.push(second);
        let before = snapshot_field_types(&manifest).expect("field types");
        assert_eq!(
            manifest.shared_schema_shapes().0,
            2,
            "identical lists start as separate allocations"
        );

        manifest
            .release_derived_object_schema()
            .expect("release schema");

        let (shapes, stored) = manifest.shared_schema_shapes();
        assert_eq!(shapes, 1, "identical schemas must end up sharing one list");
        assert_eq!(
            stored,
            manifest.objects[0].available_paths.len(),
            "the shared list is stored once, not once per object"
        );
        assert_eq!(
            manifest.objects[0].available_paths, manifest.objects[1].available_paths,
            "sharing must not change what either object reports"
        );
        assert_eq!(
            snapshot_field_types(&manifest).expect("after"),
            before,
            "the derived view is unchanged"
        );
    }

    /// Objects whose schemas genuinely differ must keep their own lists — an
    /// object claiming a column it does not have would mis-plan a projection.
    #[test]
    fn objects_with_different_schemas_keep_distinct_path_lists() {
        let mut manifest = manifest();
        let mut divergent = ManifestObject {
            event_object_key: "s3://bucket/table/data/three.parquet".to_string(),
            event_object_version: "version-3".to_string(),
            event_object_bytes: 900,
            rows: 100,
            available_paths: manifest.objects[0].available_paths.to_vec().into(),
            field_types: manifest.objects[0].field_types.clone(),
            column_compressed_bytes: BTreeMap::new(),
        };
        let mut paths = divergent.available_paths.to_vec();
        paths.push("metadata.extra".to_string());
        divergent.available_paths = paths.into();
        divergent
            .field_types
            .insert("metadata.extra".to_string(), "string".to_string());
        manifest.objects.push(divergent);

        manifest
            .release_derived_object_schema()
            .expect("release schema");

        assert_eq!(
            manifest.shared_schema_shapes().0,
            2,
            "different schemas must not be collapsed together"
        );
        assert!(
            manifest.objects[1]
                .available_paths
                .iter()
                .any(|path| path == "metadata.extra"),
            "the evolved object keeps its own column"
        );
        assert!(
            !manifest.objects[0]
                .available_paths
                .iter()
                .any(|path| path == "metadata.extra"),
            "and the older object must not gain it"
        );
    }

    /// An invalid manifest must still be rejected at load, not silently emptied
    /// and accepted.
    #[test]
    fn releasing_schema_on_an_invalid_manifest_fails_instead_of_emptying_it() {
        let mut broken = manifest();
        broken.objects[0]
            .field_types
            .insert("metadata.extra".to_string(), "not_a_type".to_string());
        assert!(broken.release_derived_object_schema().is_err());
        assert!(
            !broken.objects[0].field_types.is_empty(),
            "a rejected manifest must not be left half-processed"
        );
    }

    /// A manifest that fails validation must fail every time. Caching the
    /// failure — or worse, caching partial facts as if they were valid — would
    /// turn a rejected manifest into a served one.
    #[test]
    fn an_invalid_manifest_is_rejected_on_every_call() {
        let mut broken = manifest();
        let mut paths = broken.objects[0].available_paths.to_vec();
        // NAN-3422: an unaddressable producer key is data, not an invalid
        // manifest; an empty path still is.
        paths.push(String::new());
        broken.objects[0].available_paths = paths.into();

        for attempt in 0..3 {
            assert!(
                broken.facts().is_err(),
                "attempt {attempt} must reject the manifest"
            );
            assert!(validate_manifest(&tenant(), &broken).is_err());
            assert!(snapshot_field_types(&broken).is_err());
        }
    }

    /// Conflicting types for one path are a manifest-level contradiction and
    /// must still be caught now that the merge happens once.
    #[test]
    fn conflicting_field_types_across_objects_are_still_rejected() {
        let mut conflicted = manifest();
        let mut second = ManifestObject {
            event_object_key: "s3://bucket/table/data/two.parquet".to_string(),
            event_object_version: "version-2".to_string(),
            event_object_bytes: 900,
            rows: 100,
            available_paths: conflicted.objects[0].available_paths.clone(),
            field_types: conflicted.objects[0].field_types.clone(),
            column_compressed_bytes: BTreeMap::new(),
        };
        second
            .field_types
            .insert("metadata.uid".to_string(), "timestamp".to_string());
        conflicted.objects.push(second);

        let error = conflicted.facts().expect_err("conflicting types");
        assert!(
            error
                .to_string()
                .contains("conflicting types for metadata.uid"),
            "unexpected error: {error}"
        );
    }

    /// NAN-3393: the lane router's view of a statement's reader.
    #[test]
    fn reader_shape_counts_wide_text_row_groups_and_window_class() {
        let mut query = compiled("SELECT 1", Vec::new());
        query.projected_scan_columns = vec!["raw_data".into(), "metadata.event_code".into(), "message".into()];
        let mut source = manifest();
        source.objects[0].rows = 200_000;
        // 24 h window, 200,000 rows = 4 row groups of 65,536.
        let shape = reader_shape(&query, &source, None);
        assert_eq!((shape.wide_columns, shape.row_groups, shape.window_class), (2, 4, 5));
        for column in WIDE_TEXT_COLUMNS {
            assert!(crate::text_sidecar::KEYWORD_BODY_FIELDS.contains(&column));
        }
        // Selected candidate blocks bound the row groups instead.
        let block = CandidateBlock { event_object_key: source.objects[0].event_object_key.clone(), event_object_bytes: 900,
            row_start: 0, row_end: 10, max_time_ms: None, time_range_us: None };
        assert_eq!(reader_shape(&query, &source, Some(&[block.clone(), block.clone(), block])).row_groups, 3);
        // Window classes: 1 h, 7 d.
        query.end = "2026-08-10T01:00:00Z".into();
        assert_eq!(reader_shape(&query, &source, None).window_class, 0);
        query.end = "2026-08-17T00:00:00Z".into();
        assert_eq!(reader_shape(&query, &source, None).window_class, 8);
        // The enrichments array counts once; narrow statements count none.
        let key = reader_shape(&query, &source, None).columns_key;
        query.projected_scan_columns = vec!["message".into(), "metadata.event_code".into(), "raw_data".into()];
        assert_eq!(reader_shape(&query, &source, None).columns_key, key, "column order is not a statement shape");
        query.projected_scan_columns = vec!["enrichments".into(), "enrichments.owned_fields".into(), "time".into()];
        assert_eq!(reader_shape(&query, &source, None).wide_columns, 1);
        query.projected_scan_columns = vec!["src_endpoint.ip".into(), "src_endpoint".into(), "time".into()];
        assert_eq!(reader_shape(&query, &source, None).wide_columns, 0, "masked entity leaves stay unbounded");
        query.projected_scan_columns = vec!["device.hostname".into(), "time".into()];
        let narrow = reader_shape(&query, &source, None);
        assert_eq!(narrow.wide_columns, 0);
        assert_ne!(narrow.columns_key, key);
        assert!(!narrow.string_group_by);
    }

    /// NAN-4174: the lane router's large-aggregate hint: a GROUP BY naming a
    /// string column (not an enumerated label), in any subquery.
    #[test]
    fn groups_by_string_sees_string_group_keys_only() {
        let columns = |names: &[(&str, &str)]| names.iter().map(|(name, kind)| column(name, kind)).collect::<Vec<_>>();
        let by_ip = compiled(
            "SELECT \"dst_endpoint.ip\", count() AS count FROM __nano_lake_source__ WHERE time >= 'a' AND time < 'b' \
             GROUP BY \"dst_endpoint.ip\" ORDER BY count DESC LIMIT 100 SETTINGS max_threads=6",
            columns(&[("dst_endpoint.ip", "string"), ("time", "timestamp")]),
        );
        assert!(groups_by_string(&by_ip));
        // Nested: the clause ends at the subquery's parenthesis, backticks count too.
        let nested = compiled(
            "SELECT * FROM (SELECT `user.name` AS u, `metadata.log_source` AS s, count() AS n FROM __nano_lake_source__ \
             GROUP BY `user.name`, `metadata.log_source`) WHERE n > 3 ORDER BY n DESC",
            columns(&[("user.name", "string"), ("metadata.log_source", "string")]),
        );
        assert!(groups_by_string(&nested));
        // A low-cardinality label, a non-string key, or a string only in the
        // select list / ORDER BY is not a large aggregate.
        let by_source = compiled(
            "SELECT \"metadata.log_source\", count() FROM __nano_lake_source__ GROUP BY \"metadata.log_source\" ORDER BY \"user.name\"",
            columns(&[("metadata.log_source", "string"), ("user.name", "string")]),
        );
        assert!(!groups_by_string(&by_source));
        let by_port = compiled(
            "SELECT \"dst_endpoint.port\", any(\"user.name\") FROM __nano_lake_source__ GROUP BY \"dst_endpoint.port\"",
            columns(&[("dst_endpoint.port", "int"), ("user.name", "string")]),
        );
        assert!(!groups_by_string(&by_port));
        let rows = compiled("SELECT * FROM __nano_lake_source__ WHERE \"user.name\" = 'a' ORDER BY time DESC LIMIT 100",
            columns(&[("user.name", "string")]));
        assert!(!groups_by_string(&rows));
        // The reader shape carries it.
        let mut source = manifest();
        source.objects[0].rows = 10;
        assert!(reader_shape(&by_ip, &source, None).string_group_by);
        assert!(!reader_shape(&by_source, &source, None).string_group_by);
    }

    fn compiled(sql: &str, required_columns: Vec<RequiredColumn>) -> CompiledQuery {
        CompiledQuery {
            stats_page: false,
            schema_version: 1,
            profile: "ocsf".to_string(),
            dataset: "logs".to_string(),
            source_placeholder: LOG_SOURCE_PLACEHOLDER.to_string(),
            query_sha256: "a".repeat(64),
            start: "2026-08-10T00:00:00Z".to_string(),
            end: "2026-08-11T00:00:00Z".to_string(),
            limit: 100,
            table_view: true,
            newest_first_event_rows: true,
            candidate_hints: Vec::new(),
            required_columns,
            projected_scan_columns: Vec::new(),
            sql: sql.to_string(),
        }
    }

    #[test]
    fn sub_second_windows_admit_microsecond_fences() {
        let mut query = compiled("SELECT 1", Vec::new());
        query.start = "2026-08-10T00:00:00.123456789Z".to_string();
        query.end = "2026-08-11T00:00:00.987654321Z".to_string();
        let fence = |start: &'static str, end: &'static str| SourceTimeFence { start, end, end_inclusive: true, exact_times: None };
        // Progressive chunks format the window at microseconds (truncated).
        assert!(validate_source_time_fence(&query, fence("2026-08-10T00:00:00.123456Z", "2026-08-11T00:00:00.987654Z")).is_ok());
        assert!(validate_source_time_fence(&query, fence("2026-08-10T00:00:00.123456Z", "2026-08-11T00:00:00.987655Z")).is_ok());
        assert!(validate_source_time_fence(&query, fence("2026-08-10T00:00:00.123455Z", "2026-08-11T00:00:00.9Z")).is_err());
        assert!(validate_source_time_fence(&query, fence("2026-08-10T00:00:01Z", "2026-08-11T00:00:00.987656Z")).is_err());
        let cursor = |time: &'static str| SourceCursorFence { time, event_uid: "e1" };
        assert!(validate_source_cursor_fence(&query, cursor("2026-08-11T00:00:00.987654Z")).is_ok());
        assert!(validate_source_cursor_fence(&query, cursor("2026-08-10T00:00:00.123456Z")).is_err());
    }

    fn column(name: &str, field_type: &str) -> RequiredColumn {
        RequiredColumn {
            name: name.to_string(),
            field_type: field_type.to_string(),
        }
    }

    fn hot_tail() -> HotTailManifest {
        HotTailManifest {
            schema_version: 1,
            tenant_id: "tenant-a".to_string(),
            table: "nano.events".to_string(),
            base_snapshot_id: 10,
            head_snapshot_id: 11,
            tail_id: None,
            head_metadata_location: "s3://bucket/table/metadata/00002.metadata.json".to_string(),
            iceberg_metadata_file_path: "metadata/00002.metadata.json".to_string(),
            read_schema: None,
            available_paths: Vec::new(),
            objects: vec![crate::generation::HotTailObject {
                source_uri: "s3://bucket/table/data/two.parquet".to_string(),
                version_id: "version-2".to_string(),
                etag: None,
                size_bytes: 50,
                rows: 5,
                sha256: None,
                min_time_ms: None,
                max_time_ms: None,
                committed: false,
            }],
            local_paths: Vec::new(),
        }
    }

    #[test]
    fn schema_v4_tail_has_one_plan_leaf_at_the_full_object_ceiling() {
        let mut tail = hot_tail();
        tail.schema_version = 4;
        tail.head_snapshot_id = tail.base_snapshot_id;
        tail.tail_id = Some("d".repeat(64));
        tail.objects.clear();
        tail.local_paths.clear();
        let tenant_hash = hex::encode(Sha256::digest(b"tenant-a"));
        for index in 0..4_096 {
            tail.objects.push(crate::generation::HotTailObject {
                source_uri: format!(
                    "s3://bucket/table/data/tail/tenant_sha256={tenant_hash}/object-{index}.parquet"
                ),
                version_id: format!("version-{index}"),
                etag: None,
                size_bytes: 1,
                rows: 1,
                sha256: Some(format!("{index:064x}")),
                min_time_ms: Some(1),
                max_time_ms: Some(1),
                committed: false,
            });
            tail.local_paths.push(PathBuf::from(format!(
                "/var/lib/nano-lake/hot-tail-cache/pins/lease/\
                 {index:04}.parquet"
            )));
        }
        let (source, params, budget) =
            hot_tail_source(&tenant(), &tail, BudgetEnforcement::ReportOnly, "*").unwrap();
        assert_eq!(source.matches("file(").count(), 1);
        assert!(!source.contains("UNION ALL"));
        assert!(!source.contains("s3("));
        assert!(source.len() < 1_024);
        assert_eq!(params.len(), 1);
        assert!(params[0].1.len() < 128 * 1_024);
        assert_eq!(budget.candidate_objects, 4_096);
        // Stable content-addressed cache names are longer than lease indexes,
        // but still travel as one native value rather than 4,096 SQL leaves.
        for (index, path) in tail.local_paths.iter_mut().enumerate() {
            *path = PathBuf::from(format!("/cache/objects/{index:064x}.parquet"));
            tail.objects[index].committed = true;
        }
        let (source, params, budget) =
            hot_tail_source(&tenant(), &tail, BudgetEnforcement::ReportOnly, "*").unwrap();
        assert_eq!(source.matches("file(").count(), 1);
        assert!(!source.contains("UNION ALL"));
        assert_eq!(params.len(), 1);
        assert!(params[0].1.len() < 512 * 1_024);
        assert_eq!(budget.candidate_objects, 4_096);
    }

    #[test]
    fn product_cursor_is_a_typed_source_fence_not_an_npl_string_comparison() {
        let query = compiled(
            "SELECT \"time\", \"metadata.uid\" FROM __nano_lake_source__ ORDER BY \"time\" DESC, \"metadata.uid\" DESC LIMIT 51",
            vec![
                column("time", "timestamp"),
                column("metadata.uid", "string"),
            ],
        );
        let plan = plan_broad_log_query_with_candidates_tail_time_and_cursor(
            &tenant(),
            &manifest(),
            &query,
            None,
            None,
            None,
            SourceCursorFence {
                time: "2026-08-10T12:00:00.123456Z",
                event_uid: "event-0002",
            },
        )
        .expect("cursor plan");

        assert!(plan
            .sql
            .contains("\"time\" < parseDateTime64BestEffort({nano_cursor_time:String}, 6, 'UTC')"));
        assert!(plan
            .sql
            .contains("toString(\"metadata.uid\") < {nano_cursor_event_uid:String}"));
        assert!(plan.params.iter().any(|(name, value)| {
            name == "nano_cursor_time" && value == "2026-08-10T12:00:00.123456Z"
        }));
        assert!(plan
            .params
            .iter()
            .any(|(name, value)| { name == "nano_cursor_event_uid" && value == "event-0002" }));
    }

    #[test]
    fn staged_hot_tail_is_scoped_to_the_assigned_tenant_prefix() {
        let mut tail = hot_tail();
        tail.schema_version = 2;
        tail.head_snapshot_id = tail.base_snapshot_id;
        tail.tail_id = Some("a".repeat(64));
        let tenant_hash = hex::encode(Sha256::digest(b"tenant-a"));
        tail.objects[0].source_uri = format!(
            "s3://bucket/table/data/tail/tenant_sha256={tenant_hash}/event_hour=1/new.parquet"
        );
        assert!(hot_tail_source(&tenant(), &tail, BudgetEnforcement::Reject, "`time`").is_ok());

        tail.objects[0].source_uri =
            "s3://bucket/table/data/tail/tenant_sha256=other/new.parquet".to_string();
        assert!(hot_tail_source(&tenant(), &tail, BudgetEnforcement::Reject, "`time`").is_err());
    }

    #[test]
    fn staged_hot_tail_accepts_catalog_committed_product_objects_inside_the_table() {
        let mut tail = hot_tail();
        tail.schema_version = 2;
        tail.head_snapshot_id = tail.base_snapshot_id;
        tail.tail_id = Some("a".repeat(64));
        tail.objects[0].source_uri = "s3://bucket/table/data/signal.parquet".to_string();
        assert!(hot_tail_source(&tenant(), &tail, BudgetEnforcement::Reject, "`time`").is_ok());

        tail.objects[0].source_uri =
            "s3://bucket/another/data/event_hour=1/signal.parquet".to_string();
        assert!(hot_tail_source(&tenant(), &tail, BudgetEnforcement::Reject, "`time`").is_err());
    }

    #[test]
    fn exact_tail_reads_pin_and_escape_each_object_version() {
        let mut tail = hot_tail();
        tail.objects[0].version_id = "v/one+two=".to_string();
        let (source, params, _) =
            hot_tail_source(&tenant(), &tail, BudgetEnforcement::Reject, "`time`").unwrap();
        assert!(source.contains("hot_tail_source_0"));
        assert!(source.contains("SELECT `time` FROM s3("));
        assert!(!source.contains("SELECT * FROM s3("));
        assert_eq!(
            params[0].1,
            "https://object.test/bucket/table/data/two.parquet?versionId=v%2Fone%2Btwo%3D"
        );
    }

    #[test]
    fn hot_tail_is_unioned_inside_the_compiled_query_and_budget() {
        let query = compiled(
            "SELECT count() AS count FROM __nano_lake_source__",
            vec![column("time", "timestamp")],
        );
        let plan = plan_broad_log_query_with_candidates_and_tail(
            &tenant(),
            &manifest(),
            &query,
            None,
            Some(&hot_tail()),
        )
        .unwrap();
        assert!(plan.sql.contains("UNION ALL"));
        assert!(plan.sql.contains("s3({hot_tail_source_0:String}"));
        assert!(plan
            .params
            .iter()
            .any(|(name, value)| name == "hot_tail_source_0"
                && value.ends_with("data/two.parquet?versionId=version-2")));
        assert_eq!(plan.budget.candidate_objects, 2);
        assert_eq!(plan.budget.estimated_scan_bytes, 950);
    }

    #[test]
    fn rolling_schema_tail_projects_each_exact_object_before_union() {
        let mut tail = hot_tail();
        let mut second = tail.objects[0].clone();
        second.source_uri = "s3://bucket/table/data/three.parquet".to_string();
        second.version_id = "version-3".to_string();
        tail.objects.push(second);
        let query = compiled(
            "SELECT count() AS count FROM __nano_lake_source__",
            vec![
                column("time", "timestamp"),
                column("metadata.log_source", "string"),
            ],
        );
        let plan = plan_broad_log_query_with_candidates_and_tail(
            &tenant(),
            &manifest(),
            &query,
            None,
            Some(&tail),
        )
        .unwrap();
        assert_eq!(plan.sql.matches("FROM s3({hot_tail_source_").count(), 2);
        assert!(!plan.sql.contains("SELECT * FROM s3({hot_tail_source_"));
        // NAN-2374: a transforming query projects the compiler-owned leaves in
        // the same select that reads the object, so no `SELECT *` layer can
        // stand between the Parquet read and a nested subcolumn predicate.
        assert_eq!(
            plan.sql
                .matches(
                    "SELECT `metadata`.`log_source` AS `metadata.log_source`, `time` AS `time` \
                     FROM s3("
                )
                .count(),
            2
        );
        assert!(plan
            .sql
            .contains("`metadata`.`log_source` AS `metadata.log_source`"));
    }

    /// NAN-2374. The invariant: every column named by a pushed-down predicate
    /// must survive into the select that reads the object.
    ///
    /// chDB merges adjacent filter steps and moves the result into PREWHERE on
    /// the object-storage read. If a `SELECT *` layer stands between the
    /// Parquet read and the leaf extraction, that rewrite lands a nested
    /// subcolumn expression (`getSubcolumn(http_request, 'url.url_string')`) on
    /// a read step whose header carries only the parent struct, and the query
    /// dies with NOT_FOUND_COLUMN_IN_BLOCK. It needs a nested field referenced
    /// from more than one filter stage, so any pipeline repeating a subcolumn
    /// across an `OR` and a later `where` reaches it.
    ///
    /// Assert the shape, not the one query: for EVERY storage table function
    /// in the plan, the select reading it directly must already project every
    /// required leaf.
    #[test]
    fn every_predicate_column_survives_into_every_object_read() {
        fn source_projections(sql: &str) -> Vec<String> {
            let mut projections = Vec::new();
            for marker in ["FROM file(", "FROM s3(", "FROM icebergS3("] {
                let mut cursor = 0;
                while let Some(offset) = sql[cursor..].find(marker) {
                    let position = cursor + offset;
                    let head = &sql[..position];
                    let select = head
                        .rfind("SELECT ")
                        .expect("a storage read must sit under a SELECT");
                    projections.push(head[select + "SELECT ".len()..].trim().to_string());
                    cursor = position + marker.len();
                }
            }
            assert!(
                !projections.is_empty(),
                "the plan must read at least one object: {sql}"
            );
            projections
        }

        let leaves = [
            ("class_uid", "long"),
            ("dst_endpoint.ip", "string"),
            ("http_request.url.url_string", "string"),
            ("time", "timestamp"),
        ];
        let mut nested = manifest();
        let paths = leaves
            .iter()
            .map(|(name, _)| (*name).to_string())
            .collect::<Vec<_>>();
        nested.objects[0].field_types = leaves
            .iter()
            .map(|(name, kind)| ((*name).to_string(), (*kind).to_string()))
            .collect::<BTreeMap<_, _>>();
        nested.objects[0].available_paths = paths.into();

        // The shape the compiler emits for
        //   class_uid=4002
        //   | where http_request.url.url_string CONTAINS "dns-query"
        //         OR dst_endpoint.ip="1.1.1.1"
        //   | where http_request.url.url_string CONTAINS "dns-query"
        //   | table time
        // — a nested subcolumn inside an OR, the same subcolumn again in a
        // later filter stage, then a projection stage.
        let query = compiled(
            "WITH stage_0 AS (SELECT * FROM __nano_lake_source__ WHERE (\"class_uid\" = 4002)), \
             stage_1 AS (SELECT * FROM stage_0 WHERE \
             (toString(\"http_request.url.url_string\") iLike '%dns-query%' \
             OR \"dst_endpoint.ip\" = '1.1.1.1')), \
             stage_2 AS (SELECT * FROM stage_1 WHERE \
             toString(\"http_request.url.url_string\") iLike '%dns-query%') \
             SELECT \"time\" FROM stage_2 LIMIT 100",
            leaves
                .iter()
                .map(|(name, kind)| column(name, kind))
                .collect(),
        );

        let cache_path = PathBuf::from("/cache/generation/data/one.parquet");
        let mut cached_tenant = tenant();
        cached_tenant.max_query_bytes = 100_000;
        cached_tenant.snapshot_cache = Some(SnapshotCache {
            source_spec: cache_path.display().to_string(),
            objects: BTreeMap::from([(
                "s3://bucket/table/data/one.parquet".to_string(),
                SnapshotCacheObject {
                    version_id: "version-1".to_string(),
                    bytes: 900,
                    path: cache_path.clone(),
                },
            )]),
            bytes: 900,
            read_schema: Some("`time` DateTime64(6, 'UTC')".to_string()),
            bootstrap: false,
        });
        let mut remote_tenant = tenant();
        remote_tenant.max_query_bytes = 100_000;
        let candidate = [CandidateBlock {
            event_object_key: "s3://bucket/table/data/one.parquet".to_string(),
            event_object_bytes: 900,
            row_start: 0,
            row_end: 10,
            max_time_ms: None,
            time_range_us: None,
        }];

        let plans = [
            (
                "remote base",
                plan_broad_log_query(&remote_tenant, &nested, &query),
            ),
            (
                "cached base",
                plan_broad_log_query(&cached_tenant, &nested, &query),
            ),
            (
                "cached base and hot tail",
                plan_broad_log_query_with_candidates_and_tail(
                    &cached_tenant,
                    &nested,
                    &query,
                    None,
                    Some(&hot_tail()),
                ),
            ),
            (
                "candidate blocks and hot tail",
                plan_broad_log_query_with_candidates_and_tail(
                    &cached_tenant,
                    &nested,
                    &query,
                    Some(&candidate),
                    Some(&hot_tail()),
                ),
            ),
        ];

        for (label, plan) in plans {
            let plan = plan.unwrap_or_else(|error| panic!("{label} must plan: {error}"));
            for projection in source_projections(&plan.sql) {
                assert!(
                    !projection.starts_with('*'),
                    "{label}: a transforming query must never read an object through \
                     `SELECT *`, or a merged filter can be moved onto a read step that \
                     carries only the parent struct: {projection}"
                );
                for (name, _) in leaves {
                    assert!(
                        projection.contains(&format!("AS `{name}`")),
                        "{label}: object read drops predicate column {name}: {projection}"
                    );
                }
            }
        }
    }

    #[test]
    fn hot_tail_cannot_overlap_the_indexed_generation() {
        let mut tail = hot_tail();
        tail.objects[0].source_uri = manifest().objects[0].event_object_key.clone();
        let query = compiled(
            "SELECT count() AS count FROM __nano_lake_source__",
            vec![column("time", "timestamp")],
        );
        assert!(plan_broad_log_query_with_candidates_and_tail(
            &tenant(),
            &manifest(),
            &query,
            None,
            Some(&tail),
        )
        .is_err());
    }

    #[test]
    fn fetch_log_retains_native_bindings_with_the_hot_tail() {
        let denied = BTreeSet::new();
        let request = FetchLogPlanRequest {
            event_id: "event-1",
            start: None,
            end: None,
            log_source: None,
            deny_source_types: &denied,
        };
        let plan =
            plan_fetch_log_with_tail(&tenant(), &manifest(), Some(&hot_tail()), None, &request)
                .unwrap();
        assert!(plan.sql.contains("UNION ALL"));
        assert!(plan
            .sql
            .contains("SELECT `metadata`, `resources`, `time` FROM s3("));
        assert!(!plan.sql.contains("SELECT * FROM s3({hot_tail_source_"));
        assert!(plan
            .params
            .iter()
            .any(|(name, value)| name == "fetch_event_id" && value == "event-1"));
    }

    #[test]
    fn fetch_log_candidate_uses_the_selected_objects_physical_roots() {
        let mut source_manifest = manifest();
        let mut newer = ManifestObject {
            event_object_key: "s3://bucket/table/data/newer.parquet".to_string(),
            event_object_version: "version-newer".to_string(),
            event_object_bytes: 800,
            rows: 50,
            available_paths: vec![
                "answers.rdata".to_string(),
                "metadata.log_source".to_string(),
                "metadata.uid".to_string(),
                "time".to_string(),
            ]
            .into(),
            field_types: BTreeMap::new(),
            column_compressed_bytes: BTreeMap::new(),
        };
        newer.field_types = newer
            .available_paths
            .iter()
            .map(|path| {
                (
                    path.clone(),
                    if path == "time" {
                        "timestamp"
                    } else {
                        "string"
                    }
                    .to_string(),
                )
            })
            .collect();
        source_manifest.objects.push(newer);
        let candidates = vec![CandidateBlock {
            event_object_key: source_manifest.objects[0].event_object_key.clone(),
            event_object_bytes: source_manifest.objects[0].event_object_bytes,
            row_start: 7,
            row_end: 8,
            max_time_ms: None,
            time_range_us: None,
        }];
        let denied = BTreeSet::new();
        let request = FetchLogPlanRequest {
            event_id: "event-1",
            start: None,
            end: None,
            log_source: None,
            deny_source_types: &denied,
        };

        let plan = plan_fetch_log_with_tail(
            &tenant(),
            &source_manifest,
            Some(&hot_tail()),
            Some(&candidates),
            &request,
        )
        .unwrap();

        assert!(plan.sql.contains("SELECT `metadata`, `resources`, `time`"));
        assert!(!plan.sql.contains("`answers`"));
        assert_eq!(plan.budget.candidate_objects, 2);
        assert_eq!(plan.budget.estimated_scan_bytes, 950);
    }

    #[test]
    fn risk_npl_binds_only_the_trusted_aggregate_and_byte_fence() {
        let query = CompiledQuery {
            stats_page: false,
            schema_version: 1,
            profile: "risk".to_string(),
            dataset: "risk".to_string(),
            source_placeholder: "__nano_risk_source__".to_string(),
            query_sha256: "b".repeat(64),
            start: "2026-08-10T00:00:00Z".to_string(),
            end: "2026-08-11T00:00:00Z".to_string(),
            limit: 100,
            table_view: true,
            newest_first_event_rows: false,
            candidate_hints: Vec::new(),
            required_columns: Vec::new(),
            projected_scan_columns: Vec::new(),
            sql: "SELECT entity, score_7d FROM __nano_risk_source__ WHERE score_7d > 5".to_string(),
        };
        let plan = plan_broad_risk_query(
            &tenant(),
            &query,
            "(SELECT entity, score_7d FROM trusted_risk_aggregate)",
            vec![(
                "risk_source".to_string(),
                "/trusted/risk.parquet".to_string(),
            )],
            700,
        )
        .expect("plan risk nPL");
        assert!(!plan.sql.contains("__nano_risk_source__"));
        assert!(plan.sql.contains("trusted_risk_aggregate"));
        assert!(plan.sql.contains("max_bytes_to_read=1000"));
        assert!(plan.sql.contains("input_format_parquet_filter_push_down=0"));
        assert!(plan.sql.contains("optimize_move_to_prewhere=0"));
        assert_eq!(plan.params.len(), 1);
        assert_eq!(plan.budget.estimated_scan_bytes, 700);

        assert!(
            plan_broad_risk_query(&tenant(), &query, "(SELECT 1)", Vec::new(), 1_001,).is_err()
        );
    }

    #[test]
    fn full_payload_bounds_do_not_affect_table_pages_or_aggregates() {
        let mut configured = tenant();
        configured.threads = 8;
        configured.max_memory_bytes = 1_610_612_736;
        let mut query = compiled("SELECT * FROM __nano_lake_source__", vec![column("time", "timestamp")]);
        query.table_view = false;
        let payload = plan_broad_log_query(&configured, &manifest(), &query).unwrap();
        for setting in [
            // NAN-4751: an 8-core role's analyst payload reads with all 8.
            "max_threads=8,", "max_block_size=512,", "preferred_block_size_bytes=1048576",
            "input_format_parquet_max_block_size=512,", "input_format_parquet_prefer_block_bytes=1048576",
            "input_format_parquet_memory_high_watermark=33554432", "max_bytes_before_external_sort=67108864",
            "max_bytes_ratio_before_external_sort=0", "max_memory_usage=1610612736",
            "max_bytes_before_remerge_sort=1048576", "remerge_sort_lowered_memory_bytes_ratio=0",
        ] {
            assert!(payload.sql.contains(setting), "missing {setting}");
        }
        configured.threads = 1;
        assert!(plan_broad_log_query(&configured, &manifest(), &query).unwrap().sql.contains("max_threads=1"));
        configured.threads = 8;
        query.table_view = true;
        let table = plan_broad_log_query(&configured, &manifest(), &query).unwrap();
        query.table_view = false;
        query.sql = "SELECT count() FROM __nano_lake_source__".into();
        let aggregate = plan_broad_log_query(&configured, &manifest(), &query).unwrap();
        for plan in [table, aggregate] {
            assert!(plan.sql.contains("max_threads=8"));
            assert!(plan.sql.contains("max_block_size=8192"));
            assert!(plan.sql.contains("preferred_block_size_bytes=8388608"));
            assert!(!plan.sql.contains("input_format_parquet_memory_high_watermark"));
            assert!(!plan.sql.contains("max_bytes_ratio_before_external_sort"));
            assert!(!plan.sql.contains("max_bytes_before_remerge_sort"));
            assert!(!plan.sql.contains("remerge_sort_lowered_memory_bytes_ratio"));
        }
    }

    /// NAN-4694 / NAN-4751: with no `NANO_LAKE_PAYLOAD_*` env and no
    /// override, the payload reader's threads and rows come from the role:
    /// an analyst's statement gets the role's threads (one per 64 MiB of its
    /// cap), an agent's keeps NAN-4694's half-the-role, at most four. Every
    /// memory bound is the same at any size.
    #[test]
    fn payload_defaults_derive_from_the_query_role() {
        assert!(payload_max_threads_env().is_none() && payload_block_rows_env().is_none(), "run without NANO_LAKE_PAYLOAD_* set");
        const MIB: u64 = 1024 * 1024;
        let input = "SELECT * FROM t SETTINGS max_threads=8, max_block_size=8192, preferred_block_size_bytes=8388608";
        let statement = |threads: u64, rows: u64| format!(
            "SELECT * FROM t SETTINGS max_threads={threads}, max_block_size={rows}, preferred_block_size_bytes=1048576, \
            input_format_parquet_max_block_size={rows}, input_format_parquet_prefer_block_bytes=1048576, \
            input_format_parquet_memory_high_watermark=33554432, max_bytes_before_external_sort=67108864, \
            max_bytes_before_remerge_sort=1048576, remerge_sort_lowered_memory_bytes_ratio=0, \
            max_bytes_ratio_before_external_sort=0");
        let as_agent = |threads: u64, memory: u64| {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(crate::query_timing::measure(
                "agent-0192-p0",
                async { Ok::<_, ()>(bounded_payload_settings(input.into(), threads, memory)) },
            )).unwrap()
        };
        // (role threads, statement cap) -> analyst (threads, rows), agent (threads, rows).
        for (threads, memory, analyst, agent) in [
            (0, 128 * MIB, (1, 128), (1, 128)),
            (1, 128 * MIB, (1, 128), (1, 128)),
            (3, 128 * MIB, (2, 128), (1, 128)),
            (1, 256 * MIB, (1, 512), (1, 512)),
            (2, 256 * MIB, (2, 512), (1, 512)),
            (4, 256 * MIB, (4, 512), (2, 512)),
            (6, 256 * MIB, (4, 512), (3, 512)),
            (8, 256 * MIB, (4, 512), (4, 512)),
            (6, 512 * MIB, (6, 512), (3, 512)),
            (8, DEFAULT_QUERY_MEMORY_BYTES, (8, 512), (4, 512)),
            (16, DEFAULT_QUERY_MEMORY_BYTES, (16, 512), (4, 512)),
            // The statement cap bounds the readers: one per 64 MiB.
            (8, 128 * MIB, (2, 128), (2, 128)),
            (8, 64 * MIB, (1, 128), (1, 128)),
            (8, 0, (1, 128), (1, 128)),
        ] {
            assert_eq!(payload_role_defaults(threads, memory), analyst, "{threads} threads, {memory} bytes");
            assert_eq!(payload_read_settings(None, None, threads, memory), analyst);
            assert_eq!(bounded_payload_settings(input.into(), threads, memory), statement(analyst.0, analyst.1));
            assert_eq!(payload_agent_role_defaults(threads, memory), agent, "agent: {threads} threads, {memory} bytes");
            assert_eq!(payload_read_settings_for(None, None, threads, memory, true), agent);
            assert_eq!(as_agent(threads, memory), statement(agent.0, agent.1), "agent: {threads} threads, {memory} bytes");
            assert!(agent.0 <= analyst.0, "an agent never reads with more threads than an analyst");
        }
        // A debug scope with other overrides only changes nothing here either.
        let scoped = crate::perf_overrides::sync_scoped(
            crate::perf_overrides::Overrides { flat_filter_leaves: Some(true), ..Default::default() },
            || bounded_payload_settings(input.into(), 6, 256 * MIB),
        );
        assert_eq!(scoped, statement(4, 512));
    }

    /// NAN-4694 / NAN-4751 on the production path: query[T]'s statement
    /// limits as `open_engine_timed` derives them (`role_statement_limits`
    /// over the size-classed memory budget), through `limits_tenant`'s
    /// fields into the planner, for an analyst's request and an agent's. A
    /// 1-core role keeps one reader thread; an analyst's statement gets the
    /// role's threads within its cap; an agent's keeps NAN-4694's; no role's
    /// payload reader outgrows its statement cap.
    #[test]
    fn payload_defaults_follow_production_role_limits() {
        use crate::part_query::memory_budget::{QueryMemoryBudget, GIB};
        let mut query = compiled("SELECT * FROM __nano_lake_source__", vec![column("time", "timestamp")]);
        query.table_view = false;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        for (cpu_millis, role_bytes, agent_threads) in [
            (1_000, GIB, 1),
            (2_000, 2 * GIB, 1),
            (4_000, 3 * GIB, 2),
            (6_000, 8 * GIB, 3),
            (8_000, 16 * GIB, 4),
            (16_000, 32 * GIB, 4),
            (32_000, 64 * GIB, 4),
        ] {
            let (budget, classes) = QueryMemoryBudget::derive_for_role(role_bytes, None, cpu_millis).with_classes();
            let (threads, memory) = crate::part_query::server::role_statement_limits(&budget, classes);
            let mut configured = tenant();
            configured.threads = threads;
            configured.max_memory_bytes = memory;
            let in_request = |request_id: &'static str| {
                runtime.block_on(crate::query_timing::measure(request_id, async {
                    Ok::<_, ()>(plan_broad_log_query(&configured, &manifest(), &query).unwrap())
                })).unwrap()
            };
            for (request_id, (reader_threads, rows)) in [
                ("0192-analyst", payload_role_defaults(threads, memory)),
                ("agent-0192", payload_agent_role_defaults(threads, memory)),
            ] {
                let plan = in_request(request_id);
                assert!(reader_threads * PAYLOAD_READER_MEMORY_BYTES <= memory.max(PAYLOAD_READER_MEMORY_BYTES), "{cpu_millis}m / {role_bytes}");
                assert!(plan.sql.contains(&format!("max_threads={reader_threads},")), "{request_id}: {}", plan.sql);
                assert!(plan.sql.contains(&format!(" max_block_size={rows},")), "{}", plan.sql);
                assert!(plan.sql.contains("input_format_parquet_memory_high_watermark=33554432"), "{}", plan.sql);
                assert!(plan.sql.contains("preferred_block_size_bytes=1048576"), "{}", plan.sql);
            }
            assert_eq!(payload_agent_role_defaults(threads, memory).0, agent_threads, "agent: {cpu_millis}m / {role_bytes}");
            let analyst = payload_role_defaults(threads, memory).0;
            assert_eq!(analyst, threads.min(memory / PAYLOAD_READER_MEMORY_BYTES).max(1), "{cpu_millis}m / {role_bytes}");
            assert!(analyst >= agent_threads);
            // Outside any request (a durable job): the analyst defaults; the
            // process thread budget lowers background statements at start.
            assert!(plan_broad_log_query(&configured, &manifest(), &query).unwrap().sql.contains(&format!("max_threads={analyst},")));
        }
    }

    /// NAN-3411: a `payload_threads` / `payload_block_rows` override sets
    /// the payload reader's threads and rows, clamped; every memory bound
    /// stays, and table pages / aggregates are untouched.
    #[test]
    fn payload_read_override_sets_clamped_threads_and_rows_only() {
        use crate::perf_overrides::{sync_scoped, Overrides};
        let input = "SELECT * FROM t SETTINGS max_threads=8, max_block_size=8192";
        let with = |threads: Option<u64>, rows: Option<u64>, tenant: u64| sync_scoped(
            Overrides { payload_threads: threads, payload_block_rows: rows, ..Overrides::default() },
            || bounded_payload_settings(input.into(), tenant, 268_435_456),
        );
        let four = with(Some(4), Some(1024), 8);
        assert_eq!(four, "SELECT * FROM t SETTINGS max_threads=4, max_block_size=1024, preferred_block_size_bytes=1048576, \
            input_format_parquet_max_block_size=1024, input_format_parquet_prefer_block_bytes=1048576, \
            input_format_parquet_memory_high_watermark=33554432, max_bytes_before_external_sort=67108864, \
            max_bytes_before_remerge_sort=1048576, remerge_sort_lowered_memory_bytes_ratio=0, \
            max_bytes_ratio_before_external_sort=0");
        // Threads alone: rows keep the role default (512 at a 256 MiB cap).
        let threads_only = with(Some(2), None, 8);
        assert!(threads_only.contains("max_threads=2,") && threads_only.contains(" max_block_size=512,")
            && threads_only.contains("input_format_parquet_max_block_size=512,"), "{threads_only}");
        // Clamps: never past the tenant's thread budget (NAN-4751: an
        // analyst's; an agent's stays at most the 4-thread cap); rows 128..=8192.
        assert!(with(Some(64), None, 16).contains("max_threads=16,"));
        assert_eq!(payload_read_settings_for(Some(64), None, 16, 268_435_456, true).0, 4);
        assert!(with(Some(4), None, 2).contains("max_threads=2,"));
        assert!(with(Some(4), None, 0).contains("max_threads=1,"));
        assert!(with(None, Some(10), 8).contains(" max_block_size=128,"));
        assert!(with(None, Some(1_000_000), 8).contains(" max_block_size=8192,"));
        assert_eq!(payload_read_settings(Some(3), Some(512), 8, 268_435_456), (3, 512));
        assert_eq!(payload_read_settings(Some(0), Some(0), 8, 268_435_456), (1, 128));
        // An override wins over the role in both directions.
        assert_eq!(payload_read_settings(Some(1), Some(128), 8, 268_435_456), (1, 128));

        // Through the planner: the payload statement takes it, table pages and aggregates do not.
        let mut configured = tenant();
        configured.threads = 8;
        let mut query = compiled("SELECT * FROM __nano_lake_source__", vec![column("time", "timestamp")]);
        query.table_view = false;
        let overrides = Overrides { payload_threads: Some(4), payload_block_rows: Some(2048), ..Overrides::default() };
        let payload = sync_scoped(overrides, || plan_broad_log_query(&configured, &manifest(), &query).unwrap());
        assert!(payload.sql.contains("max_threads=4") && payload.sql.contains("max_block_size=2048")
            && payload.sql.contains("input_format_parquet_memory_high_watermark=33554432"), "{}", payload.sql);
        query.table_view = true;
        let table = sync_scoped(overrides, || plan_broad_log_query(&configured, &manifest(), &query).unwrap());
        assert!(table.sql.contains("max_threads=8") && table.sql.contains("max_block_size=8192"), "{}", table.sql);
        // Lane routing v2 caps interactive threads at 4: a 4-thread payload passes unchanged.
        assert_eq!(crate::part_query::lanes::cap_threads(&payload.sql, crate::part_query::lanes::INTERACTIVE_MAX_THREADS), payload.sql);
    }

    #[test]
    fn payload_settings_survive_existing_large_lane_fallback() {
        let mut configured = tenant();
        configured.max_memory_bytes = 268_435_456;
        let mut query = compiled("SELECT * FROM __nano_lake_source__", vec![column("time", "timestamp")]);
        query.table_view = false;
        let plan = plan_broad_log_query(&configured, &manifest(), &query).unwrap();
        let large = crate::part_query::engine::with_memory_cap(plan, 1_610_612_736);
        assert!(large.sql.contains("max_memory_usage=1610612736"));
        assert!(large.sql.contains("max_bytes_ratio_before_external_sort=0"));
        assert!(large.sql.contains("max_bytes_before_external_sort=67108864"));
        assert!(large.sql.contains("input_format_parquet_memory_high_watermark=33554432"));
        // NAN-4694 / NAN-4751: the 4-core role's payload readers (4 x 512 rows) survive too.
        assert!(large.sql.contains(" max_block_size=512,"), "{}", large.sql);
        assert!(large.sql.contains("max_threads=4,"), "{}", large.sql);
        assert!(large.sql.contains("remerge_sort_lowered_memory_bytes_ratio=0"));
        query.sql = "SELECT count() FROM __nano_lake_source__".into();
        let aggregate = plan_broad_log_query(&configured, &manifest(), &query).unwrap();
        let large = crate::part_query::engine::with_memory_cap(aggregate, 1_610_612_736);
        assert!(large.sql.contains("max_bytes_before_external_sort=805306368"));
    }

    #[test]
    fn full_event_query_keeps_native_row_and_uses_guarded_aliases() {
        let query = compiled(
            "WITH s AS (SELECT * FROM __nano_lake_source__ WHERE \"resources.hostname\" = 'host') SELECT * FROM s",
            vec![
                column("resources.hostname", "array"),
                column("time", "timestamp"),
            ],
        );
        let plan = plan_broad_log_query(&tenant(), &manifest(), &query).expect("plan");
        assert!(plan.native_event_rows);
        assert!(plan.sql.contains("WHERE _path != ''"));
        assert!(plan
            .sql
            .contains("tupleElement(`resources`, 'hostname') AS __nano_path_0"));
        assert!(plan.sql.contains("__nano_path_0 = 'host'"));
        assert!(plan.temporary_aliases.contains("__nano_path_0"));
        assert_eq!(plan.budget.estimated_scan_bytes, 900);
        assert_eq!(plan.params.len(), 3);
    }

    /// dns_over_https: a full-row pipeline that filters on grandchildren of a
    /// root in separate stages reads them as storage subcolumns. The nested
    /// tupleElement form died in chDB with `Not found column
    /// tupleElement(http_request, 'url')` (native repro:
    /// tests/npl_rule_shapes_native.rs).
    #[test]
    fn full_event_query_reads_deep_leaves_as_subcolumns() {
        let mut source = manifest();
        let object = &mut source.objects[0];
        let mut paths = object.available_paths.to_vec();
        paths.extend([
            "http_request.url.path".to_string(),
            "http_request.url.url_string".to_string(),
        ]);
        object.available_paths = paths.into();
        object
            .field_types
            .insert("http_request.url.path".into(), "string".into());
        object
            .field_types
            .insert("http_request.url.url_string".into(), "string".into());
        let query = compiled(
            "WITH s AS (SELECT * FROM __nano_lake_source__ WHERE \"http_request.url.url_string\" iLike '%dns%'), \
             t AS (SELECT * FROM s WHERE \"http_request.url.path\" iLike '%dns%') SELECT * FROM t",
            vec![
                column("http_request.url.path", "string"),
                column("http_request.url.url_string", "string"),
                column("time", "timestamp"),
            ],
        );
        let plan = plan_broad_log_query(&tenant(), &source, &query).expect("plan");
        assert!(plan.native_event_rows);
        assert!(
            plan.sql
                .contains("`http_request`.`url`.`path` AS __nano_path_"),
            "{}",
            plan.sql
        );
        assert!(
            plan.sql
                .contains("`http_request`.`url`.`url_string` AS __nano_path_"),
            "{}",
            plan.sql
        );
        assert!(
            !plan
                .sql
                .contains("tupleElement(tupleElement(`http_request`"),
            "{}",
            plan.sql
        );
        assert!(native_leaf_reads_as_subcolumn("actor.process.name"));
        assert!(!native_leaf_reads_as_subcolumn("metadata.uid"));
        assert!(!native_leaf_reads_as_subcolumn(
            "src_endpoint.location.country"
        ));
        assert!(!native_leaf_reads_as_subcolumn(
            "enrichments.data.host_count"
        ));
    }

    /// NAN-2982: a bare keyword compiles to `lower(message)` with the
    /// top-level column unquoted. When the source has no `message`, the
    /// native event source must still define it (typed NULL) and the rows
    /// must not gain it.
    #[test]
    fn full_event_query_defines_missing_bare_top_level_columns() {
        let query = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE (hasAllTokens(lower(message), 'claude') OR hasAllTokens(lower(raw_data), 'claude')) ORDER BY time DESC LIMIT 11",
            vec![
                column("message", "string"),
                column("raw_data", "string"),
                column("time", "timestamp"),
            ],
        );
        let plan = plan_broad_log_query(&tenant(), &manifest(), &query).expect("plan");
        assert!(plan.native_event_rows);
        assert!(plan.sql.contains("CAST(NULL AS Nullable(String)) AS `message`"), "{}", plan.sql);
        assert!(plan.sql.contains("CAST(NULL AS Nullable(String)) AS `raw_data`"), "{}", plan.sql);
        // NAN-3789: a single-token needle is a case-insensitive token search.
        assert!(plan.sql.contains("hasTokenCaseInsensitive(message, 'claude')"), "{}", plan.sql);
        assert!(plan.temporary_aliases.contains("message"));
        assert!(plan.temporary_aliases.contains("raw_data"));
        // A present top-level column is read from the source as-is.
        assert!(!plan.sql.contains("AS `time`"), "{}", plan.sql);
        assert!(!plan.temporary_aliases.contains("time"));
    }

    #[test]
    fn transforming_query_gets_only_declared_projection_and_sparse_defaults() {
        let query = compiled(
            "SELECT \"metadata.log_source\", count() FROM __nano_lake_source__ GROUP BY \"metadata.log_source\"",
            vec![
                column("metadata.log_source", "string"),
                column("unmapped.optional", "string"),
            ],
        );
        let plan = plan_broad_log_query(&tenant(), &manifest(), &query).expect("plan");
        assert!(!plan.native_event_rows);
        assert!(plan
            .sql
            .contains("`metadata`.`log_source` AS `metadata.log_source`"));
        assert!(plan
            .sql
            .contains("CAST(NULL AS Nullable(String)) AS `unmapped.optional`"));
        assert!(plan.sql.contains("max_bytes_to_read=1000"));
        assert_eq!(plan.schema_defaults, vec!["unmapped.optional"]);
    }

    #[test]
    fn signed_hot_tail_schema_exposes_additive_product_event_fields_immediately() {
        let cache_path = PathBuf::from("/cache/generation/data/one.parquet");
        let mut configured = tenant();
        configured.snapshot_cache = Some(SnapshotCache {
            source_spec: cache_path.display().to_string(),
            objects: BTreeMap::from([(
                "s3://bucket/table/data/one.parquet".to_string(),
                SnapshotCacheObject {
                    version_id: "version-1".to_string(),
                    bytes: 900,
                    path: cache_path,
                },
            )]),
            bytes: 900,
            read_schema: Some(
                "`time` DateTime64(6, 'UTC'), `metadata` Tuple(`uid` Nullable(String), `log_source` Nullable(String)), `resources` Tuple(`hostname` Array(String))"
                    .to_string(),
            ),
            bootstrap: false,
        });
        let mut tail = hot_tail();
        tail.schema_version = 2;
        tail.head_snapshot_id = tail.base_snapshot_id;
        tail.tail_id = Some("a".repeat(64));
        tail.objects[0].source_uri = "s3://bucket/table/data/signal-additive.parquet".to_string();
        tail.read_schema = Some(
            "`time` DateTime64(6, 'UTC'), `metadata` Tuple(`uid` Nullable(String), `log_source` Nullable(String)), `resources` Tuple(`hostname` Array(String)), `finding_info` Tuple(`analytic` Tuple(`name` Nullable(String)))"
                .to_string(),
        );
        tail.available_paths = vec![
            "finding_info.analytic.name".to_string(),
            "metadata.log_source".to_string(),
            "metadata.uid".to_string(),
            "resources.hostname".to_string(),
            "time".to_string(),
        ];
        let query = compiled(
            "SELECT \"finding_info.analytic.name\" FROM __nano_lake_source__",
            vec![column("finding_info.analytic.name", "string")],
        );

        let plan = plan_broad_log_query_with_candidates_and_tail(
            &configured,
            &manifest(),
            &query,
            None,
            Some(&tail),
        )
        .expect("plan additive signal field");

        assert!(plan.schema_defaults.is_empty());
        assert!(plan.sql.contains("`finding_info`.`analytic`.`name`"));
        assert!(plan.params.iter().any(|(name, value)| {
            name == "snapshot_cache_read_schema" && value.contains("`finding_info` Tuple")
        }));
        assert!(
            plan.params.iter().any(|(name, value)| {
                name == "hot_tail_source_read_schema" && value.contains("`finding_info` Tuple")
            }),
            "params={:?}",
            plan.params
        );
    }

    #[test]
    fn heterogeneous_tail_keeps_uniform_contract_in_every_native_branch() {
        let mut source = manifest();
        let mut network = manifest().objects.remove(0);
        network.event_object_key = "s3://bucket/table/data/network.parquet".into();
        let mut paths = network.available_paths.to_vec();
        paths.push("src_endpoint.location.country".into());
        network.available_paths = paths.into();
        network.field_types.insert("src_endpoint.location.country".into(), "string".into());
        source.objects.push(network);
        let mut configured = tenant();
        configured.max_query_bytes = 10_000;
        configured.snapshot_cache = Some(SnapshotCache {
            source_spec: "/cache/{one,network}.parquet".into(),
            objects: source.objects.iter().enumerate().map(|(i, object)| (
                object.event_object_key.clone(),
                SnapshotCacheObject {
                    version_id: object.event_object_version.clone(),
                    bytes: object.event_object_bytes,
                    path: PathBuf::from(format!("/cache/base-{i}.parquet")),
                },
            )).collect(),
            bytes: 1800,
            read_schema: Some("`time` DateTime64(6, 'UTC')".into()),
            bootstrap: false,
        });
        let mut tail = hot_tail();
        tail.schema_version = 3;
        tail.tail_id = Some("a".repeat(64));
        tail.read_schema = Some("`time` DateTime64(6, 'UTC'), `metadata` Tuple(`uid` Nullable(String), `log_source` Nullable(String)), `resources` Tuple(`hostname` Array(String)), `src_endpoint` Tuple(`location` Tuple(`country` Nullable(String))), `enrichments` Array(Tuple(`provider` Nullable(String)))".into());
        tail.available_paths = source.objects[1].available_paths.to_vec();
        tail.available_paths.push("enrichments.provider".into());
        let mut second = tail.objects[0].clone();
        second.source_uri = "s3://bucket/table/data/tail-network.parquet".into();
        tail.objects.push(second);
        // Equal logical paths must still bind the same physical structure;
        // otherwise differing Tuple types/order can disagree across the arms.
        let mut already_available = BTreeSet::new();
        extend_available_with_tail_contract(&mut already_available, &tail).unwrap();
        let unified = tenant_with_tail_read_contract(&configured, Some(&tail), &mut already_available).unwrap();
        assert_eq!(unified.snapshot_cache.unwrap().read_schema, tail.read_schema);
        let selected = [CandidateBlock {
            event_object_key: source.objects[0].event_object_key.clone(),
            event_object_bytes: source.objects[0].event_object_bytes,
            row_start: 0, row_end: 1, max_time_ms: None, time_range_us: None,
        }];
        for version in [3, 4] {
            tail.schema_version = version;
            tail.local_paths = if version == 4 {
                vec!["/cache/tail-cloudtrail.parquet".into(), "/cache/tail-network.parquet".into()]
            } else { Vec::new() };
            for candidates in [None, Some([].as_slice()), Some(selected.as_slice())] {
                for (path, kind) in [("enrichments.provider", "array"), ("src_endpoint.location.country", "string")] {
                    // Native row shape also used by progressive filter scans:
                    // the outer tupleElement must see both roots after UNION.
                    let query = compiled(
                        &format!("SELECT * FROM __nano_lake_source__ WHERE isNotNull(\"{path}\")"),
                        vec![column(path, kind)],
                    );
                    let plan = plan_broad_log_query_with_candidates_and_tail(
                        &configured, &source, &query, candidates, Some(&tail),
                    ).unwrap();
                    let projection = required_root_projection(&required_columns(&query).unwrap(), &already_available).unwrap();
                    // NAN-4168: only the queried root; no stamps beside an endpoint.
                    assert_eq!(projection.contains("`enrichments`"), path.starts_with("enrichments"), "{projection}");
                    assert_eq!(projection.contains("`src_endpoint`"), path.starts_with("src_endpoint"), "{projection}");
                    assert!(!projection.contains("`resources`"));
                    assert!(!projection.contains("`metadata`"));
                    let branches = if version == 4 { 2 } else { 3 };
                    assert_eq!(plan.sql.matches(&format!("SELECT {projection} FROM ")).count(), branches, "{}", plan.sql);
                    assert!(plan.sql.contains("tupleElement("));
                    assert!(plan.sql.contains("input_format_parquet_allow_missing_columns=1"));
                    if candidates.is_some_and(|rows| rows.is_empty()) { assert!(plan.sql.contains("WHERE 0")); }
                    let schemas = plan.params.iter().filter(|(name, _)| name.ends_with("read_schema")).collect::<Vec<_>>();
                    assert_eq!(schemas.len(), 2);
                    let read_roots = required_read_roots(&required_columns(&query).unwrap(), &already_available).unwrap()
                        .iter().map(|root| quoted_identifier(root).unwrap()).collect::<Vec<_>>().join(", ");
                    let expected = page_read_schema(tail.read_schema.as_ref().unwrap(), &read_roots).unwrap();
                    assert!(schemas.iter().all(|(_, schema)| **schema == expected));
                    assert!(!plan.sql.contains("/cache/"));
                    assert!(plan.schema_defaults.is_empty());
                }
            }
        }
    }

    /// NAN-3052 (rdp_lateral_movement): `where is_private_ip(src_endpoint.ip)
    /// AND is_private_ip(dst_endpoint.ip)` over enrichment-stamped parts.
    /// NAN-4168: endpoint roots are plain columns, so every predicate leaf is
    /// a plain `tupleElement` path and nothing reads `enrichments`.
    #[test]
    fn full_event_endpoint_predicates_read_plain_roots() {
        let mut source = manifest();
        let object = &mut source.objects[0];
        let extra = [
            ("class_uid", "long"), ("src_endpoint.ip", "string"), ("src_endpoint.hostname", "string"),
            ("dst_endpoint.ip", "string"), ("dst_endpoint.port", "long"),
            ("dst_endpoint.location.country", "string"), ("enrichments.provider", "array"),
        ];
        let mut paths = object.available_paths.to_vec();
        paths.extend(extra.iter().map(|(p, _)| p.to_string()));
        object.available_paths = paths.into();
        object.field_types.extend(extra.iter().map(|(p, t)| (p.to_string(), t.to_string())));
        let mut query = compiled(
            "WITH stage_0 AS (SELECT * FROM __nano_lake_source__ WHERE class_uid = 4001 AND \"dst_endpoint.port\" = 3389), \
             stage_1 AS (SELECT * FROM stage_0 WHERE isIPAddressInRange(toString(\"src_endpoint.ip\"), '10.0.0.0/8') \
             AND isIPAddressInRange(toString(\"dst_endpoint.ip\"), '10.0.0.0/8') AND isNotNull(\"dst_endpoint.location.country\")) \
             SELECT * FROM stage_1 ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 101",
            vec![
                column("class_uid", "long"), column("dst_endpoint.ip", "string"), column("dst_endpoint.port", "long"),
                column("dst_endpoint.location.country", "string"), column("metadata.uid", "string"),
                column("src_endpoint.ip", "string"), column("time", "timestamp"),
            ],
        );
        query.table_view = false;
        query.newest_first_event_rows = false;
        let plan = plan_broad_log_query(&tenant(), &source, &query).expect("plan");
        assert!(plan.native_event_rows);
        for leaf in ["tupleElement(`dst_endpoint`, 'ip') AS __nano_path", "tupleElement(`dst_endpoint`, 'port') AS __nano_path",
            "tupleElement(`src_endpoint`, 'ip') AS __nano_path",
            "tupleElement(tupleElement(`dst_endpoint`, 'location'), 'country') AS __nano_path"] {
            assert!(plan.sql.contains(leaf), "{leaf}: {}", plan.sql);
        }
        assert!(!plan.sql.contains("__nano_raw_"), "{}", plan.sql);
        assert!(!plan.sql.contains("arrayExists") && !plan.sql.contains("owned_fields"), "{}", plan.sql);
    }

    #[test]
    fn generation_roots_are_uniform_even_when_candidates_are_empty() {
        let mut source = manifest();
        let mut second = manifest().objects.remove(0);
        second.event_object_key = "s3://bucket/table/data/network.parquet".into();
        second.available_paths = vec!["time".into(), "src_endpoint.location.country".into(), "enrichments.provider".into()].into();
        source.objects.push(second);
        let query = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE isNotNull(\"src_endpoint.location.country\")",
            vec![column("src_endpoint.location.country", "string")],
        );
        let mut configured = tenant();
        configured.max_query_bytes = 10_000;
        for candidates in [None, Some([].as_slice())] {
            let plan = plan_broad_log_query_with_candidates_and_tail(
                &configured, &source, &query, candidates, None,
            ).unwrap();
            let (available, _) = validate_manifest(&configured, &source).unwrap();
            let projection = required_root_projection(&required_columns(&query).unwrap(), &available).unwrap();
            for root in ["time", "src_endpoint"] {
                assert!(projection.contains(&format!("`{root}`")), "{projection}");
            }
            // NAN-4168: no mask, so `enrichments` is not read for a location leaf.
            assert!(!projection.contains("`enrichments`"), "{projection}");
            assert!(!projection.contains("`resources`"));
            assert!(plan.sql.contains(&format!("SELECT {projection} FROM ")));
            if candidates.is_some() { assert!(plan.sql.contains("WHERE 0")); }
        }
    }

    #[test]
    fn required_roots_are_plain_and_skip_missing_ones() {
        let available = ["time", "src_endpoint.ip", "enrichments.provider"]
            .map(str::to_string).into_iter().collect();
        let missing = BTreeMap::from([("dst_endpoint.location.country".into(), "string".into())]);
        assert_eq!(required_root_projection(&missing, &available).unwrap(), "`time`");
        let producer = BTreeMap::from([("src_endpoint.ip".into(), "string".into())]);
        // NAN-4168: the endpoint root is read as stored; no `enrichments` root.
        assert_eq!(required_root_projection(&producer, &available).unwrap(), "`src_endpoint`, `time`");
    }

    #[test]
    fn table_view_user_hunt_projects_only_required_uniform_roots() {
        let mut source = manifest();
        let mut paths = source.objects[0].available_paths.to_vec();
        paths.extend(["actor.user.name", "user.name", "http_request.url", "enrichments.provider", "file.name", "process.name"].map(str::to_string));
        source.objects[0].available_paths = paths.clone().into();
        let mut tail = hot_tail();
        tail.available_paths = paths;
        tail.read_schema = Some("`time` DateTime64(6, 'UTC'), `actor` Tuple(user Tuple(name Nullable(String))), `user` Tuple(name Nullable(String)), `metadata` Tuple(uid Nullable(String)), `http_request` Tuple(url Nullable(String)), `enrichments` Array(Tuple(provider Nullable(String))), `file` Tuple(name Nullable(String)), `process` Tuple(name Nullable(String))".into());
        let query = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE (\"actor.user.name\" = 'jsmith' OR \"user.name\" = 'jsmith') ORDER BY \"time\" DESC LIMIT 50",
            vec![column("actor.user.name", "string"), column("user.name", "string"), column("time", "timestamp"), column("metadata.uid", "string")],
        );
        let mut configured = tenant();
        configured.max_query_bytes = 10_000;
        for candidates in [None, Some([].as_slice())] {
            let plan = plan_broad_log_query_with_candidates_and_tail(
                &configured, &source, &query, candidates, Some(&tail),
            ).unwrap();
            assert_eq!(plan.sql.matches("SELECT `actor`, `metadata`, `time`, `user` FROM ").count(), 2, "{}", plan.sql);
            for root in ["http_request", "enrichments", "file", "process", "resources"] {
                assert!(!plan.sql.contains(&format!("`{root}`")), "{}", plan.sql);
            }
            assert!(!plan.sql.contains("SELECT * FROM s3("));
            assert!(plan.sql.contains("input_format_parquet_allow_missing_columns=1"));
            let schema = plan.params.iter().find(|(name, _)| name.ends_with("_read_schema")).unwrap().1.as_str();
            for root in ["actor", "metadata", "time", "user"] {
                assert!(schema.contains(&format!("`{root}`")), "{schema}");
            }
            for root in ["http_request", "enrichments", "file", "process"] {
                assert!(!schema.contains(&format!("`{root}`")), "{schema}");
            }
        }
    }

    #[test]
    fn compiler_table_view_bounds_each_arm() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/nan2469-live-tail-read-schema.json")).unwrap();
        let paths: Vec<String> = serde_json::from_value(fixture["available_paths"].clone()).unwrap();
        let mut source = manifest();
        source.objects[0].available_paths = paths.clone().into();
        let mut tail = hot_tail();
        tail.available_paths = paths;
        tail.read_schema = Some(fixture["read_schema"].as_str().unwrap().into());
        let query: CompiledQuery = serde_json::from_str(include_str!(
            "../tests/fixtures/nan2523-leaf-compiled.json")).unwrap();
        assert_eq!(query.required_columns.len(), 25);
        let roots = "`activity_name`, `actor`, `class_uid`, `connection_info`, `dst_endpoint`, `message`, `metadata`, `process`, `severity`, `src_endpoint`, `status`, `time`, `user`";
        let mut configured = tenant();
        configured.max_query_bytes = 10_000;
        for candidates in [None, Some([].as_slice())] {
            let plan = plan_broad_log_query_with_candidates_and_tail(
                &configured, &source, &query, candidates, Some(&tail),
            ).unwrap();
            assert!(!plan.native_event_rows);
            // One per bounded arm; no outer display-mask select (NAN-4168).
            assert_eq!(plan.sql.matches(&format!("SELECT {roots} FROM")).count(), 4, "{}", plan.sql);
            // NAN-4168: no stamps read and no display masks.
            assert!(!plan.sql.contains("enrichments") && !plan.sql.contains("owned_fields"), "{}", plan.sql);
            // Each arm (snapshot, tail) bounded, then the merged page; no
            // outer display-mask layer bounding again (NAN-4168).
            assert_eq!(plan.sql.matches("LIMIT 101").count(), 3, "{}", plan.sql);
            assert_eq!(plan.sql.matches("ORDER BY time DESC LIMIT 101").count(), 3, "{}", plan.sql);
            assert!(!plan.sql.contains("`raw_data`"));
            assert!(!plan.sql.contains("`http_request`"));
            assert!(!plan.sql.contains("`file`"));
            let union = plan.sql.find(" UNION ALL ").unwrap();
            assert!(plan.sql[..union].contains("LIMIT 101"));
            assert!(plan.sql[union..].contains("LIMIT 101"));
            eprintln!("NAN-2523 leaf SQL: {}", plan.sql);
        }
        for fixture in [include_str!("../tests/fixtures/nan2523-leaf-compiled.json"),
            include_str!("../tests/fixtures/nan2523-aggregate-compiled.json")] {
            let mut query: CompiledQuery = serde_json::from_str(fixture).unwrap();
            query.newest_first_event_rows = false;
            let plan = plan_broad_log_query_with_candidates_and_tail(
                &configured, &source, &query, None, Some(&tail),
            ).unwrap();
            eprintln!("NAN-2523 baseline/aggregate columns: {:?} SQL: {}", query.required_columns, plan.sql);
        }
    }

    #[test]
    fn table_view_locator_scans_predicates_once_with_parallel_readers() {
        let query: CompiledQuery = serde_json::from_str(include_str!("../tests/fixtures/nan2523-leaf-compiled.json")).unwrap();
        let locator = table_view_locator(&query).unwrap();
        assert_eq!(locator.required_columns.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), vec!["actor.user.name", "metadata.uid", "time", "user.name"]);
        assert!(locator.sql.contains("ORDER BY time DESC LIMIT 101"));
        assert!(!locator.sql.contains("autonomous_system"));
        let sql = harden_settings(locator.sql, &tenant()).unwrap();
        assert!(sql.contains(&format!("max_threads={}", tenant().threads)));
        // NAN-3154: every hardened read lane pushes row-group blooms down.
        assert!(sql.contains("input_format_parquet_bloom_filter_push_down=1"));
    }

    #[test]
    fn table_view_locator_defers_uid_tie_sort_to_full_query() {
        let mut query: CompiledQuery = serde_json::from_str(include_str!("../tests/fixtures/nan2523-leaf-compiled.json")).unwrap();
        query.sql = query.sql.replace("ORDER BY time DESC LIMIT", "ORDER BY time DESC, \"metadata.uid\" DESC LIMIT");
        let locator = table_view_locator(&query).unwrap();
        assert!(query.sql.contains("ORDER BY time DESC, \"metadata.uid\" DESC LIMIT"));
        assert!(locator.sql.contains("ORDER BY time DESC LIMIT"));
        assert!(!locator.sql.contains("ORDER BY time DESC, \"metadata.uid\" DESC"));
    }

    /// NAN-3221: the compiler's full-event needle page (`metadata.log_source
    /// = conduit_proxy src_endpoint.ip="10.1.4.63" github`, table_view off),
    /// exactly as `lake_query_compile` emits it.
    fn full_event_needle() -> CompiledQuery {
        let mut query = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE time >= '2026-08-10 00:00:00.000000' AND time < '2026-08-11 00:00:00.000000' \
             AND (((lower(\"metadata.log_source\") = 'conduit_proxy' AND \"src_endpoint.ip\" = '10.1.4.63') \
             AND (hasAllTokens(lower(message), 'github') OR hasAllTokens(lower(raw_data), 'github')))) \
             ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 101 SETTINGS max_threads=16, max_execution_time=300, \
             optimize_read_in_order=0, optimize_aggregation_in_order=1",
            ["message", "metadata.log_source", "metadata.uid", "raw_data", "src_endpoint.ip"]
                .into_iter()
                .map(|name| column(name, "string"))
                .chain([column("time", "timestamp")])
                .collect(),
        );
        query.table_view = false;
        query.limit = 101;
        query
    }

    /// NAN-3265: a deep page's progressive chunk reads under a lowered
    /// trailing cap; the statement keeps its shape (and so stays locatable),
    /// and only the trailing newest-first limit changes.
    #[test]
    fn row_cap_lowers_only_the_trailing_newest_first_limit() {
        let mut query = full_event_needle();
        query.sql = query.sql.replace("LIMIT 101", "LIMIT 50001");
        query.limit = 50_001;
        let capped = with_newest_first_row_cap(&query, 4_096).expect("newest-first shape");
        assert_eq!(capped.limit, 4_096);
        assert_eq!(newest_first_row_cap(&capped.sql), Some(4_096));
        assert_eq!(capped.sql, query.sql.replace("LIMIT 50001", "LIMIT 4096"));
        assert!(capped.sql.ends_with("optimize_aggregation_in_order=1"));
        // A cap at or above the statement's own limit changes nothing.
        let same = with_newest_first_row_cap(&query, 60_000).unwrap();
        assert_eq!((same.sql.as_str(), same.limit), (query.sql.as_str(), 50_001));
        // Not a newest-first statement: no cap.
        let mut other = query.clone();
        other.sql = other.sql.replace("ORDER BY time DESC, \"metadata.uid\" DESC", "ORDER BY time ASC");
        assert!(with_newest_first_row_cap(&other, 10).is_none());
        // The capped statement's locator is within the exact-fence bound.
        if let Some(locator) = full_event_locator(&capped) {
            assert_eq!(locator.limit, 4_096);
            assert!(locator.sql.ends_with("LIMIT 4096"));
        }
    }

    #[test]
    fn full_event_locator_reads_only_the_predicate_columns_with_the_same_predicate() {
        let query = full_event_needle();
        assert!(
            table_view_locator(&query).is_none(),
            "full-event rows never had a locator"
        );
        let locator = full_event_locator(&query).expect("needle page is locatable");
        let predicate = query
            .sql
            .split(" ORDER BY ")
            .next()
            .unwrap()
            .strip_prefix("SELECT * FROM __nano_lake_source__ ")
            .unwrap();
        assert_eq!(
            locator.sql,
            format!("SELECT time AS __nano_locator_time FROM __nano_lake_source__ {predicate} ORDER BY time DESC LIMIT 101")
        );
        assert!(!locator.newest_first_event_rows && !locator.table_view);
        assert_eq!(locator.limit, 101);
        // Every predicate column, plus time and the cursor tie key.
        let names =
            |columns: &[RequiredColumn]| columns.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
        assert_eq!(
            names(&locator.required_columns),
            names(&query.required_columns)
        );
        assert_eq!(
            locator.projected_scan_columns,
            names(&query.required_columns)
        );
        assert_eq!(locator.candidate_hints, query.candidate_hints);
        assert_eq!(
            page_locator(&query).map(|l| l.sql),
            Some(locator.sql.clone())
        );
    }

    #[test]
    fn full_event_locator_plans_a_narrow_statement_without_payload_bounds() {
        let mut source = manifest();
        let object = &mut source.objects[0];
        let mut paths = object.available_paths.to_vec();
        for path in [
            "message",
            "raw_data",
            "src_endpoint.ip",
            "enrichments.provider",
        ] {
            paths.push(path.into());
            object.field_types.insert(
                path.into(),
                if path.starts_with("enrichments") {
                    "array"
                } else {
                    "string"
                }
                .into(),
            );
        }
        object.available_paths = paths.into();
        let query = full_event_needle();
        let full = plan_broad_log_query(&tenant(), &source, &query).unwrap();
        assert!(full.native_event_rows);
        // NAN-4694 / NAN-4751: the 4-core test role's payload reader: 4 threads x 512 rows.
        assert!(full.sql.contains("max_threads=4,") && full.sql.contains(" max_block_size=512,"), "{}", full.sql);
        let locator =
            plan_broad_log_query(&tenant(), &source, &full_event_locator(&query).unwrap()).unwrap();
        assert!(!locator.native_event_rows);
        assert!(
            locator
                .sql
                .contains(&format!("max_threads={}", tenant().threads)),
            "{}",
            locator.sql
        );
        assert!(
            !locator.sql.contains(" max_block_size=512,"),
            "{}",
            locator.sql
        );
        // No authorization mask or unrelated root is decoded to locate.
        assert!(!locator.sql.contains("enrichments"), "{}", locator.sql);
        assert!(!locator.sql.contains("`resources`"), "{}", locator.sql);
        assert!(locator.sql.contains("'10.1.4.63'") && locator.sql.contains("'github'"));
    }

    #[test]
    fn full_event_locator_accepts_enrichment_predicates_and_refuses_other_shapes() {
        let base = full_event_needle();
        // NAN-4168: enrichment leaves read the same in both passes.
        for path in [
            "src_endpoint.location.country",
            "dst_endpoint.autonomous_system.number",
            "src_endpoint",
            "enrichments.provider",
        ] {
            let mut query = base.clone();
            query.required_columns.push(column(path, "string"));
            assert!(full_event_locator(&query).is_some(), "{path}");
        }
        let refused = |edit: &dyn Fn(&mut CompiledQuery)| {
            let mut query = base.clone();
            edit(&mut query);
            full_event_locator(&query)
        };
        assert!(refused(&|q| q.table_view = true).is_none());
        assert!(refused(&|q| q.newest_first_event_rows = false).is_none());
        assert!(refused(&|q| q.stats_page = true).is_none());
        assert!(refused(&|q| q.required_columns.retain(|c| c.name != "time")).is_none());
        // Any order but the compiler's event order.
        assert!(refused(&|q| q.sql = q.sql.replace(
            "ORDER BY time DESC, \"metadata.uid\" DESC",
            "ORDER BY time ASC, \"metadata.uid\" ASC"
        ))
        .is_none());
        assert!(refused(&|q| q.sql = q.sql.replace(
            "ORDER BY time DESC, \"metadata.uid\" DESC",
            "ORDER BY severity DESC, \"metadata.uid\" DESC"
        ))
        .is_none());
        // Pipelines, nested statements and projections.
        assert!(refused(&|q| q.sql = q.sql.replace(
            "SELECT * FROM __nano_lake_source__",
            "WITH s AS (SELECT * FROM __nano_lake_source__) SELECT * FROM s"
        ))
        .is_none());
        assert!(refused(&|q| q.sql = q.sql.replace("SELECT *", "SELECT time")).is_none());
        assert!(
            refused(&|q| q.sql = q.sql.replace("'github'", "'github') GROUP BY (time")).is_none()
        );
        // A keyword spelled like SQL is only a literal.
        let literal = refused(&|q| q.sql = q.sql.replace("'github'", "'order by limit join'"))
            .expect("literal is data");
        assert!(literal.sql.contains("'order by limit join'"));
    }

    #[test]
    fn or_candidate_union_drops_hint_when_object_sizes_disagree() {
        let block = |bytes, start, end| CandidateBlock {
            event_object_key: "s3://b/object".into(), event_object_bytes: bytes,
            row_start: start, row_end: end, max_time_ms: None, time_range_us: None,
        };
        for start in [0, 5, 10, 20] {
            assert!(union_candidate_blocks(&[
                vec![block(100, 0, 10)], vec![block(101, start, start + 10)],
            ]).unwrap().is_none());
        }
    }

    #[test]
    fn or_candidate_union_preserves_overlapping_and_disjoint_rows() {
        let block = |start, end, time| CandidateBlock { event_object_key:"s3://b/object".into(), event_object_bytes:100, row_start:start, row_end:end, max_time_ms:time , time_range_us: None};
        let union = union_candidate_blocks(&[vec![block(0, 10, Some(1))], vec![block(5, 15, None), block(20, 30, Some(3))]]).unwrap().unwrap();
        assert_eq!(union, vec![block(0, 15, None), block(20, 30, Some(3))]);
        assert!(union_candidate_blocks(&[vec![block(0, 1, None); 4097]]).unwrap().is_none());
    }

    #[test]
    fn table_view_top_k_keeps_whole_roots_and_pipelines_out() {
        let query: CompiledQuery = serde_json::from_str(include_str!(
            "../tests/fixtures/nan2523-leaf-compiled.json")).unwrap();
        assert!(table_view_page_clause(&query).is_some());
        // NAN-4168: location/AS leaves are plain columns and may page.
        for path in ["src_endpoint.location.country", "dst_endpoint.autonomous_system.number"] {
            let mut leaf: CompiledQuery = serde_json::from_str(include_str!("../tests/fixtures/nan2523-leaf-compiled.json")).unwrap();
            leaf.projected_scan_columns.push(path.into());
            assert!(table_view_page_clause(&leaf).is_some(), "{path}");
        }
        for path in ["enrichments.provider", "src_endpoint"] {
            let mut whole: CompiledQuery = serde_json::from_str(include_str!("../tests/fixtures/nan2523-leaf-compiled.json")).unwrap();
            whole.projected_scan_columns.push(path.into());
            assert!(table_view_page_clause(&whole).is_none(), "{path}");
        }
        for suffix in [" OFFSET 10", " UNION ALL SELECT * FROM other"] {
            let mut pipeline: CompiledQuery = serde_json::from_str(include_str!("../tests/fixtures/nan2523-leaf-compiled.json")).unwrap();
            pipeline.sql = query.sql.split(" SETTINGS ").next().unwrap().to_string() + suffix;
            assert!(table_view_page_clause(&pipeline).is_none());
        }
    }

    #[test]
    fn exact_object_versions_and_budget_are_mandatory() {
        let query = compiled(
            "SELECT \"time\" FROM __nano_lake_source__",
            vec![column("time", "timestamp")],
        );
        let mut bad_manifest = manifest();
        bad_manifest.objects[0].event_object_version = "etag:abc".to_string();
        assert!(matches!(
            plan_broad_log_query(&tenant(), &bad_manifest, &query),
            Err(QueryPlanError::InvalidManifest(_))
        ));
        let mut small_budget = tenant();
        small_budget.max_query_bytes = 899;
        assert!(matches!(
            plan_broad_log_query(&small_budget, &manifest(), &query),
            Err(QueryPlanError::BudgetRejected { .. })
        ));

        let progressive = plan_broad_log_query_for_progressive_decision(
            &small_budget,
            &manifest(),
            &query,
            None,
            None,
        )
        .expect("report over-budget range for progressive planning");
        assert_eq!(progressive.budget.estimated_scan_bytes, 900);
        assert_eq!(progressive.budget.max_query_bytes, 899);
        assert!(progressive.sql.contains("max_bytes_to_read=899"));
    }

    #[test]
    fn query_budget_counts_only_overlapping_hour_partitions() {
        let query = compiled(
            "SELECT \"time\" FROM __nano_lake_source__",
            vec![column("time", "timestamp")],
        );
        let inside_hour = DateTime::parse_from_rfc3339(&query.start)
            .unwrap()
            .timestamp()
            / 3_600;
        let mut inside = manifest().objects.remove(0);
        inside.event_object_key =
            format!("s3://bucket/table/data/event_hour={inside_hour}/inside.parquet");
        inside.event_object_bytes = 700;
        let mut outside = manifest().objects.remove(0);
        outside.event_object_key = format!(
            "s3://bucket/table/data/event_hour={}/outside.parquet",
            inside_hour - 48
        );
        outside.event_object_version = "version-2".to_string();
        outside.event_object_bytes = 700;
        let partitioned = SourceManifest {
            tenant_id: "tenant-a".to_string(),
            objects: vec![inside, outside],
            ..Default::default()
        };

        let plan = plan_broad_log_query(&tenant(), &partitioned, &query).unwrap();
        assert_eq!(plan.budget.candidate_objects, 1);
        assert_eq!(plan.budget.estimated_scan_bytes, 700);
    }

    #[tokio::test]
    async fn hour_partitioned_tail_budget_and_scan_shrink_together() {
        crate::query_timing::measure("partition-budget", async {
            let mut query = compiled(
                "SELECT \"time\" FROM __nano_lake_source__",
                vec![column("time", "timestamp")],
            );
            let start = DateTime::parse_from_rfc3339(&query.start).unwrap();
            let hour = start.timestamp() / 3_600;
            let mut tail = hot_tail();
            let prototype = tail.objects[0].clone();
            tail.objects = (0..4)
                .map(|offset| {
                    let mut object = prototype.clone();
                    object.source_uri = format!(
                        "s3://bucket/table/data/event_hour={}/pack-{offset}.parquet",
                        hour + offset
                    );
                    object.version_id = format!("version-{offset}");
                    object.size_bytes = 100;
                    object.committed = true;
                    // Broad bounds must not override the tighter hour partition.
                    object.min_time_ms = Some(start.timestamp_millis());
                    object.max_time_ms = Some(start.timestamp_millis() + 4 * 3_600_000);
                    object
                })
                .collect();
            let mut config = tenant();
            config.max_query_bytes = 1_100;
            let wide = plan_broad_log_query_with_candidates_and_tail(
                &config,
                &manifest(),
                &query,
                None,
                Some(&tail),
            );
            assert!(matches!(
                wide,
                Err(QueryPlanError::BudgetRejected {
                    estimated_bytes: 1_300,
                    max_bytes: 1_100
                })
            ));
            query.end = (start + chrono::Duration::minutes(59)).to_rfc3339();
            let narrow = plan_broad_log_query_with_candidates_and_tail(
                &config,
                &manifest(),
                &query,
                None,
                Some(&tail),
            )
            .unwrap();
            assert_eq!(narrow.budget.estimated_scan_bytes, 1_000);
            assert!(
                narrow
                    .params
                    .iter()
                    .any(|(_, value)| value.contains("pack-0.parquet"))
            );
            for offset in 1..4 {
                assert!(
                    !narrow
                        .params
                        .iter()
                        .any(|(_, value)| value.contains(&format!("pack-{offset}.parquet")))
                );
            }
            let phases = crate::query_timing::current().unwrap();
            let phases = phases.lock().unwrap();
            assert_eq!(phases.tail_objects_considered, 1);
            assert_eq!(phases.estimated_bytes, Some(1_000));
            assert_eq!(phases.budget_bytes, Some(1_100));
            Ok::<_, ()>(())
        })
        .await
        .unwrap();
    }

    #[test]
    fn query_window_drops_non_overlapping_staged_tail_objects() {
        let query = compiled(
            "SELECT \"time\" FROM __nano_lake_source__",
            vec![column("time", "timestamp")],
        );
        let inside_hour = DateTime::parse_from_rfc3339(&query.start)
            .unwrap()
            .timestamp()
            / 3_600;
        let mut partitioned = manifest();
        partitioned.objects[0].event_object_key =
            format!("s3://bucket/table/data/event_hour={inside_hour}/inside.parquet");
        let mut tail = hot_tail();
        tail.objects[0].source_uri = format!(
            "s3://bucket/table/data/event_hour={}/outside.parquet",
            inside_hour - 48
        );
        tail.objects[0].size_bytes = 200;

        let plan = plan_broad_log_query_with_candidates_and_tail(
            &tenant(),
            &partitioned,
            &query,
            None,
            Some(&tail),
        )
        .unwrap();
        assert!(!plan.sql.contains("UNION ALL"));
        assert_eq!(plan.budget.estimated_scan_bytes, 900);
    }

    #[test]
    fn schema_v4_query_window_keeps_object_and_cache_path_paired() {
        let query = compiled(
            "SELECT \"time\" FROM __nano_lake_source__",
            vec![column("time", "timestamp")],
        );
        let start_ms = DateTime::parse_from_rfc3339(&query.start)
            .unwrap()
            .timestamp_millis();
        let mut tail = hot_tail();
        tail.schema_version = 4;
        tail.head_snapshot_id = tail.base_snapshot_id;
        tail.tail_id = Some("d".repeat(64));
        tail.objects[0].source_uri = format!(
            "s3://bucket/table/data/event_hour={}/inside.parquet",
            start_ms / 3_600_000
        );
        tail.objects[0].sha256 = Some("a".repeat(64));
        tail.objects[0].min_time_ms = Some(start_ms + 1_000);
        tail.objects[0].max_time_ms = Some(start_ms + 2_000);
        tail.local_paths = vec![PathBuf::from("/cache/inside.parquet")];

        let mut outside = tail.objects[0].clone();
        outside.source_uri = "s3://bucket/table/data/event_hour=496056/outside.parquet".to_string();
        outside.version_id = "version-outside".to_string();
        outside.sha256 = Some("b".repeat(64));
        outside.min_time_ms = Some(start_ms - 48 * 3_600_000);
        outside.max_time_ms = Some(start_ms - 48 * 3_600_000 + 1_000);
        tail.objects.push(outside);
        tail.local_paths
            .push(PathBuf::from("/cache/outside.parquet"));

        let plan = plan_broad_log_query_with_candidates_and_tail(
            &tenant(),
            &manifest(),
            &query,
            None,
            Some(&tail),
        )
        .expect("a scoped schema-v4 tail must retain its matching cache path");
        let source = plan
            .params
            .iter()
            .find_map(|(name, value)| (name == "hot_tail_source").then_some(value))
            .expect("schema-v4 tail source parameter");
        assert!(source.contains("/cache/inside.parquet"));
        assert!(!source.contains("/cache/outside.parquet"));
        assert_eq!(plan.budget.candidate_objects, 2);
    }

    // -- NAN-2361 two-tier hot tail ------------------------------------------

    /// A schema-3 tail: one staged object plus committed (Tier B) objects of
    /// the given sizes, all time-bounded inside the compiled query's window.
    fn committed_tier_tail(query: &CompiledQuery, committed_sizes: &[u64]) -> HotTailManifest {
        let start_ms = DateTime::parse_from_rfc3339(&query.start)
            .unwrap()
            .timestamp_millis();
        let mut tail = hot_tail();
        tail.schema_version = 3;
        tail.head_snapshot_id = tail.base_snapshot_id;
        tail.tail_id = Some("a".repeat(64));
        tail.objects[0].min_time_ms = Some(start_ms + 1_000);
        tail.objects[0].max_time_ms = Some(start_ms + 2_000);
        for (index, size) in committed_sizes.iter().enumerate() {
            tail.objects.push(crate::generation::HotTailObject {
                source_uri: format!("s3://bucket/table/data/pack-{index}.parquet"),
                version_id: format!("version-pack-{index}"),
                etag: None,
                size_bytes: *size,
                rows: 1_000,
                sha256: None,
                min_time_ms: Some(start_ms + 1_000),
                max_time_ms: Some(start_ms + 2_000),
                committed: true,
            });
        }
        tail
    }

    /// A committed tier far past the 1 GiB envelope still PLANS — its cost is
    /// charged to the per-query scan budget exactly like the base, where
    /// Reject enforcement (not publication refusal) is the backpressure.
    /// Mutations caught: reintroducing a byte cap on the committed tier in the
    /// planner (first half fails), and dropping the tail bytes from the
    /// budget charge (second half fails).
    #[test]
    fn a_committed_tier_far_over_a_gib_still_plans_and_charges_the_budget() {
        let query = compiled(
            "SELECT count() AS count FROM __nano_lake_source__",
            vec![column("time", "timestamp")],
        );
        let five_gib = 5 * 1_073_741_824_u64;
        let tail = committed_tier_tail(&query, &[five_gib, five_gib]);
        let mut wide = tenant();
        wide.max_query_bytes = 100 * 1_073_741_824;
        let plan = plan_broad_log_query_with_candidates_and_tail(
            &wide,
            &manifest(),
            &query,
            None,
            Some(&tail),
        )
        .expect("a 10 GiB committed tier must plan");
        assert!(plan.sql.contains("UNION ALL"));
        // 900 (base) + 50 (staged, from hot_tail()) + 2 x 5 GiB (committed).
        assert_eq!(plan.budget.estimated_scan_bytes, 900 + 50 + 2 * five_gib);
        assert_eq!(plan.budget.candidate_objects, 4);

        // The same plan under the default 1_000-byte budget is REJECTED by
        // admission — degraded latency budgeting, never a publication outage.
        let error = plan_broad_log_query_with_candidates_and_tail(
            &tenant(),
            &manifest(),
            &query,
            None,
            Some(&tail),
        )
        .expect_err("scan budget must still reject");
        assert!(matches!(error, QueryPlanError::BudgetRejected { .. }));
    }

    /// Per-object min/max_time_ms pruning applies to the committed tier, so a
    /// time-scoped query does not pay for non-overlapping committed packs.
    /// Mutation caught: skipping the window retain for committed objects.
    #[test]
    fn query_window_drops_non_overlapping_committed_tier_objects() {
        let query = compiled(
            "SELECT \"time\" FROM __nano_lake_source__",
            vec![column("time", "timestamp")],
        );
        let five_gib = 5 * 1_073_741_824_u64;
        let mut tail = committed_tier_tail(&query, &[five_gib]);
        // Move the committed pack fully before the query window.
        let start_ms = DateTime::parse_from_rfc3339(&query.start)
            .unwrap()
            .timestamp_millis();
        tail.objects[1].min_time_ms = Some(start_ms - 100_000);
        tail.objects[1].max_time_ms = Some(start_ms - 90_000);
        let plan = plan_broad_log_query_with_candidates_and_tail(
            &tenant(),
            &manifest(),
            &query,
            None,
            Some(&tail),
        )
        .expect("the pruned committed pack must not be charged");
        // Only base (900) + the staged tail object (50) remain.
        assert_eq!(plan.budget.estimated_scan_bytes, 950);
        assert!(
            !plan
                .params
                .iter()
                .any(|(_, value)| value.contains("pack-0.parquet")),
            "a non-overlapping committed object must not be read"
        );
    }

    /// The empty-candidate proof fences ONLY the pinned base at the indexed
    /// snapshot; the tail — committed tier included — is still scanned
    /// unfenced, because the sidecar proof is valid only for the exact
    /// snapshot it was built over. Mutation caught: applying the candidate
    /// fence (or its WHERE 0 collapse) to the tail arm.
    #[test]
    fn empty_candidate_proof_fences_only_the_pinned_base_never_the_tail() {
        let query = compiled(
            "SELECT \"time\" FROM __nano_lake_source__",
            vec![column("time", "timestamp")],
        );
        let tail = committed_tier_tail(&query, &[512]);
        let plan = plan_broad_log_query_with_candidates_and_tail(
            &tenant(),
            &manifest(),
            &query,
            Some(&[]),
            Some(&tail),
        )
        .expect("empty-proof base plus unfenced tail must plan");
        assert!(
            plan.sql.contains("WHERE 0"),
            "the proven-empty base must be fenced to zero rows: {}",
            plan.sql
        );
        assert!(plan.sql.contains("UNION ALL"));
        for (index, uri) in [(0, "two.parquet"), (1, "pack-0.parquet")] {
            assert!(
                plan.params.iter().any(|(name, value)| {
                    name == &format!("hot_tail_source_{index}") && value.contains(uri)
                }),
                "tail object {uri} must still be scanned unfenced"
            );
        }
        // The budget charges the fenced base as zero and the tail in full.
        assert_eq!(plan.budget.estimated_scan_bytes, 50 + 512);
    }

    #[test]
    fn narrow_query_prunes_staged_objects_within_the_same_hour() {
        let mut query = compiled(
            "SELECT \"time\" FROM __nano_lake_source__",
            vec![column("time", "timestamp")],
        );
        query.start = "2026-08-10T00:30:00Z".to_string();
        query.end = "2026-08-10T00:30:02Z".to_string();
        let hour = DateTime::parse_from_rfc3339(&query.start)
            .unwrap()
            .timestamp()
            .div_euclid(3_600);
        let mut partitioned = manifest();
        partitioned.objects[0].event_object_key =
            format!("s3://bucket/table/data/event_hour={hour}/inside.parquet");
        let mut tail = hot_tail();
        tail.objects[0].source_uri =
            format!("s3://bucket/table/data/event_hour={hour}/outside.parquet");
        tail.objects[0].min_time_ms = Some(
            DateTime::parse_from_rfc3339("2026-08-10T00:10:00Z")
                .unwrap()
                .timestamp_millis(),
        );
        tail.objects[0].max_time_ms = Some(
            DateTime::parse_from_rfc3339("2026-08-10T00:10:05Z")
                .unwrap()
                .timestamp_millis(),
        );

        let plan = plan_broad_log_query_with_candidates_and_tail(
            &tenant(),
            &partitioned,
            &query,
            None,
            Some(&tail),
        )
        .unwrap();
        assert!(!plan.sql.contains("UNION ALL"));
        assert_eq!(plan.budget.estimated_scan_bytes, 900);
    }

    #[test]
    fn compiler_output_is_allow_listed_to_read_statements() {
        for sql in [
            "INSERT INTO t SELECT * FROM __nano_lake_source__",
            "CREATE TABLE t AS SELECT * FROM __nano_lake_source__",
            "SELECT * FROM __nano_lake_source__ WHERE x IN (SELECT 1 FROM s3('http://x/y', Parquet))",
            "SELECT * FROM __nano_lake_source__ UNION ALL SELECT * FROM url('http://x', JSONEachRow)",
            "SELECT * FROM __nano_lake_source__ JOIN remote('h:9000', db.t) USING (x)",
            "SELECT * FROM __nano_lake_source__ JOIN file ( 'a.parquet' ) USING (x)",
            "SELECT * FROM __nano_lake_source__ JOIN numbers(10) AS n ON 1",
            "WITH (SELECT count() FROM system.tables) AS c SELECT c FROM __nano_lake_source__ SETTINGS max_threads=1 ; SYSTEM FLUSH LOGS",
            "SELECT * FROM __nano_lake_source__ SETTINGS max_threads=1 KILL QUERY WHERE 1",
            "SELECT * FROM icebergS3('s3://b/t') WHERE __nano_lake_source__ = 1",
        ] {
            let query = compiled(sql, vec![column("time", "timestamp")]);
            assert!(
                matches!(
                    plan_broad_log_query(&tenant(), &manifest(), &query),
                    Err(QueryPlanError::InvalidCompilerOutput(_))
                ),
                "{sql}"
            );
        }
        // Keywords and function names inside quoted regions are data, and
        // scalar homonyms (`format`, `mapValues`, `isNull`) are not table
        // functions.
        for sql in [
            "SELECT \"time\", 'DROP TABLE x' AS note, `insert` FROM __nano_lake_source__ WHERE message = 's3(\\'x\\')' LIMIT 10",
            "SELECT format('{}', \"time\"), mapValues(m), isNull(x), \"time\" FROM __nano_lake_source__ SETTINGS max_threads=1",
            "WITH 1 AS one SELECT one, \"time\" FROM __nano_lake_source__ WHERE metadata.uid = 'x' ORDER BY \"time\" DESC",
            "SELECT ext.update, ext.delete, ext.set, \"time\" FROM __nano_lake_source__ WHERE EXISTS (SELECT 1) LIMIT 1e3",
        ] {
            let query = compiled(sql, vec![column("time", "timestamp")]);
            assert!(
                !matches!(
                    plan_broad_log_query(&tenant(), &manifest(), &query),
                    Err(QueryPlanError::InvalidCompilerOutput(_))
                ),
                "{sql}"
            );
        }
        assert_eq!(
            blank_quoted_regions("a 'b''c' d \"e\" `f` 'g\\'h'"),
            "a   d      "
        );
    }

    #[test]
    fn quoted_identifier_function_calls_are_rejected() {
        assert!(quoted_identifier_call("SELECT * FROM `url`('http://x')"));
        assert!(quoted_identifier_call("SELECT * FROM \"s3\" ('b')"));
        assert!(!quoted_identifier_call("SELECT `a`, \"b\" FROM t WHERE c = '(x)'"));
        assert!(!quoted_identifier_call("SELECT 'it''s' FROM t"));
        assert!(reject_non_read_statement("SELECT * FROM `url`('http://x')").is_err());
        assert!(reject_non_read_statement("SELECT * FROM \"s3\"('b') SETTINGS x=1").is_err());
        assert!(reject_non_read_statement("SELECT `a` FROM t").is_ok());
    }

    #[test]
    fn comments_in_compiler_output_are_rejected() {
        assert_eq!(sql_comment_marker("SELECT 1 -- x"), Some("--"));
        assert_eq!(sql_comment_marker("SELECT 1 /* x */"), Some("/*"));
        assert_eq!(sql_comment_marker("SELECT 1 # x"), Some("#"));
        assert_eq!(sql_comment_marker("SELECT '--' , \"/*\", `#` FROM t"), None);
        assert!(reject_non_read_statement("SELECT 1 -- 'trailing").is_err());
        assert!(reject_non_read_statement("SELECT '-- not a comment' FROM t").is_ok());
    }

    #[test]
    fn compiler_statement_and_metadata_injection_fail_closed() {
        let query = compiled(
            "SELECT \"time\" FROM __nano_lake_source__; DROP TABLE x",
            vec![column("time", "timestamp")],
        );
        assert!(matches!(
            plan_broad_log_query(&tenant(), &manifest(), &query),
            Err(QueryPlanError::InvalidCompilerOutput(_))
        ));
        let mut bad_tenant = tenant();
        bad_tenant.iceberg_metadata_file_path = "metadata/x' OR 1=1".to_string();
        assert!(matches!(
            plan_broad_log_query(
                &bad_tenant,
                &manifest(),
                &compiled(
                    "SELECT \"time\" FROM __nano_lake_source__",
                    vec![column("time", "timestamp")]
                )
            ),
            Err(QueryPlanError::InvalidTenantConfig(_))
        ));
    }

    /// NAN-3789: a row-fenced statement that tests `message` / `raw_data`
    /// keeps the text test out of PREWHERE; a whole-file read, an entity
    /// test, or the switch off keep chDB's default placement.
    #[test]
    fn row_fenced_text_tests_run_after_the_fence() {
        let block = |start: u64, end: u64| CandidateBlock {
            event_object_key: "s3://bucket/table/data/one.parquet".to_string(),
            event_object_bytes: 900,
            row_start: start,
            row_end: end,
            max_time_ms: None,
            time_range_us: None,
        };
        let keyword = compiled(
            "SELECT count() AS n FROM __nano_lake_source__ WHERE (hasAllTokens(lower(message), 'abc') OR hasAllTokens(lower(raw_data), 'abc')) \
             SETTINGS max_threads=16, max_execution_time=300",
            vec![column("message", "string"), column("raw_data", "string"), column("time", "timestamp")],
        );
        let entity = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE \"resources.hostname\" = 'host'",
            vec![column("resources.hostname", "array"), column("time", "timestamp")],
        );
        let fenced = plan_broad_log_query_with_candidates(&tenant(), &manifest(), &keyword, Some(&[block(0, 10), block(40, 50)])).unwrap();
        assert!(fenced.sql.contains("_row_number"), "{}", fenced.sql);
        assert_eq!(fenced.sql.matches(TEXT_AFTER_FENCE_SETTING).count(), 1, "{}", fenced.sql);
        assert!(fenced.sql.contains("hasTokenCaseInsensitive(message, 'abc')"), "{}", fenced.sql);
        // A whole-file read needs the snapshot cache's explicit read schema
        // (NAN-3149); without one the planner keeps an exact fence even over
        // every row, so the whole-file case plans against a cached tenant.
        let mut cached = tenant();
        cached.snapshot_cache = Some(SnapshotCache {
            source_spec: "/cache/objects/one.bin".into(),
            objects: [("s3://bucket/table/data/one.parquet".to_string(), SnapshotCacheObject {
                version_id: manifest().objects[0].event_object_version.clone(), bytes: 900, path: "/cache/objects/one.bin".into(),
            })].into_iter().collect(),
            bytes: 900,
            read_schema: Some("`time` DateTime64(6, 'UTC')".into()),
            bootstrap: false,
        });
        let whole = plan_broad_log_query_with_candidates(&cached, &manifest(), &keyword, Some(&[block(0, 100)])).unwrap();
        assert!(!whole.sql.contains("_row_number") && !whole.sql.contains(TEXT_AFTER_FENCE_SETTING), "{}", whole.sql);
        let unhinted = plan_broad_log_query(&tenant(), &manifest(), &keyword).unwrap();
        assert!(!unhinted.sql.contains(TEXT_AFTER_FENCE_SETTING), "{}", unhinted.sql);
        let pivot = plan_broad_log_query_with_candidates(&tenant(), &manifest(), &entity, Some(&[block(0, 10)])).unwrap();
        assert!(pivot.sql.contains("_row_number") && !pivot.sql.contains(TEXT_AFTER_FENCE_SETTING), "{}", pivot.sql);
        // The probe knob turns it off for one call.
        let scope = crate::perf_overrides::Parsed {
            probe: Some(crate::perf_overrides::Probe {
                knobs: [("text_after_fence", 0), ("token_case_insensitive", 0)].into_iter().collect(),
                settings: Vec::new(),
            }),
            ..Default::default()
        };
        let off = futures::executor::block_on(crate::perf_overrides::scoped(Some(std::sync::Arc::new(scope)), async {
            plan_broad_log_query_with_candidates(&tenant(), &manifest(), &keyword, Some(&[block(0, 10), block(40, 50)])).unwrap()
        }));
        assert!(!off.sql.contains(TEXT_AFTER_FENCE_SETTING), "{}", off.sql);
        assert!(off.sql.contains("hasAllTokens(lower(message), 'abc')") && !off.sql.contains("hasTokenCaseInsensitive"), "{}", off.sql);
    }

    #[test]
    fn timed_candidates_add_a_statistics_prunable_time_guard() {
        let query = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE \"resources.hostname\" = 'host'",
            vec![column("resources.hostname", "array"), column("time", "timestamp")],
        );
        let block = |start: u64, end: u64, time: Option<(i64, i64)>| CandidateBlock {
            event_object_key: "s3://bucket/table/data/one.parquet".to_string(),
            event_object_bytes: 900,
            row_start: start,
            row_end: end,
            max_time_ms: None,
            time_range_us: time,
        };
        // 2026-09-29T00:00:00Z = 1790640000 s; adjacent ranges merge.
        let t0 = 1_790_640_000_000_000_i64;
        let candidates = vec![
            block(0, 10, Some((t0, t0 + 1_000_000))),
            block(20, 30, Some((t0 + 1_000_001, t0 + 2_000_000))),
            block(40, 50, Some((t0 + 60_000_000, t0 + 61_000_000))),
        ];
        let plan = plan_broad_log_query_with_candidates(&tenant(), &manifest(), &query, Some(&candidates)).unwrap();
        assert!(plan.sql.contains(
            "((time >= '2026-09-29 00:00:00.000000' AND time <= '2026-09-29 00:00:02.000000') OR (time >= '2026-09-29 00:01:00.000000' AND time <= '2026-09-29 00:01:01.000000')) AND ((intDiv(_row_number"
        ), "{}", plan.sql);
        // One block without bounds keeps the exact row fence only.
        let mixed = vec![block(0, 10, Some((t0, t0))), block(20, 30, None)];
        let plan = plan_broad_log_query_with_candidates(&tenant(), &manifest(), &query, Some(&mixed)).unwrap();
        assert!(!plan.sql.contains("time >= '"));
        assert!(plan.sql.contains("[10], 1)) * 2 + transform(_path, [{candidate_path_0:String}], [1], 0)) IN (1,5)"), "{}", plan.sql);
    }

    #[test]
    fn entity_candidates_bind_exact_object_and_row_ranges() {
        let query = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE \"resources.hostname\" = 'host'",
            vec![
                column("resources.hostname", "array"),
                column("time", "timestamp"),
            ],
        );
        let candidates = vec![CandidateBlock {
            event_object_key: "s3://bucket/table/data/one.parquet".to_string(),
            event_object_bytes: 900,
            row_start: 10,
            row_end: 20,
            max_time_ms: None,
            time_range_us: None,
        }];
        let plan =
            plan_broad_log_query_with_candidates(&tenant(), &manifest(), &query, Some(&candidates))
                .expect("candidate plan");
        // [10, 20): granule 1 of 10 rows, the one set file (key 1 * 2 + 1).
        assert!(plan.sql.contains("(intDiv(_row_number, transform(_path, [{candidate_path_0:String}], [10], 1)) * 2 + transform(_path, [{candidate_path_0:String}], [1], 0)) IN (3)"), "{}", plan.sql);
        assert_eq!(
            plan.params
                .iter()
                .find(|(name, _)| name == "candidate_path_0")
                .map(|(_, value)| value.as_str()),
            Some("bucket/table/data/one.parquet")
        );
        assert!(plan.sql.contains("s3({candidate_source:String}"));
        assert_eq!(
            plan.params
                .iter()
                .find(|(name, _)| name == "candidate_source")
                .map(|(_, value)| value.as_str()),
            Some("https://object.test/bucket/table/data/one.parquet")
        );
        assert_eq!(plan.budget.candidate_objects, 1);
        assert_eq!(plan.budget.estimated_scan_bytes, 900);
        assert!(!plan.sql.contains("WHERE _path != '')"));
    }

    #[test]
    fn conjunctive_candidates_intersect_overlapping_row_ranges() {
        let object = "s3://bucket/table/data/one.parquet";
        let first = vec![
            CandidateBlock {
                event_object_key: object.to_string(),
                event_object_bytes: 900,
                row_start: 0,
                row_end: 50,
                max_time_ms: Some(100),
                time_range_us: None,
            },
            CandidateBlock {
                event_object_key: object.to_string(),
                event_object_bytes: 900,
                row_start: 50,
                row_end: 100,
                max_time_ms: Some(90),
                time_range_us: None,
            },
        ];
        let second = vec![CandidateBlock {
            event_object_key: object.to_string(),
            event_object_bytes: 900,
            row_start: 25,
            row_end: 75,
            max_time_ms: Some(95),
            time_range_us: None,
        }];
        assert_eq!(
            intersect_candidate_blocks(&[first, second]).unwrap(),
            vec![CandidateBlock {
                event_object_key: object.to_string(),
                event_object_bytes: 900,
                row_start: 25,
                row_end: 75,
                max_time_ms: Some(95),
                time_range_us: None,
            }]
        );
    }

    #[test]
    fn conjunctive_candidates_reject_conflicting_object_identity() {
        let object = "s3://bucket/table/data/one.parquet";
        let first = vec![CandidateBlock {
            event_object_key: object.to_string(),
            event_object_bytes: 900,
            row_start: 0,
            row_end: 50,
            max_time_ms: None,
            time_range_us: None,
        }];
        let second = vec![CandidateBlock {
            event_object_key: object.to_string(),
            event_object_bytes: 901,
            row_start: 0,
            row_end: 50,
            max_time_ms: None,
            time_range_us: None,
        }];
        assert!(intersect_candidate_blocks(&[first, second]).is_err());
    }

    #[test]
    fn contiguous_candidate_blocks_coalesce_before_sql_rendering() {
        let object = "s3://bucket/table/data/one.parquet";
        let candidates = (0..4_096_u64)
            .map(|block| CandidateBlock {
                event_object_key: object.to_string(),
                event_object_bytes: 900,
                row_start: block * 10,
                row_end: (block + 1) * 10,
                max_time_ms: Some(block),
                time_range_us: None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            intersect_candidate_blocks(&[candidates]).unwrap(),
            vec![CandidateBlock {
                event_object_key: object.to_string(),
                event_object_bytes: 900,
                row_start: 0,
                row_end: 40_960,
                max_time_ms: Some(4_095),
                time_range_us: None,
            }]
        );
    }

    #[test]
    fn progressive_source_time_fence_is_bound_and_cannot_escape_query_window() {
        let query = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE \"time\" >= now() - INTERVAL 1 DAY",
            vec![column("time", "timestamp")],
        );
        let plan = plan_broad_log_query_with_candidates_tail_and_time(
            &tenant(),
            &manifest(),
            &query,
            None,
            None,
            Some(SourceTimeFence {
                start: "2026-08-10T23:00:00Z",
                end: "2026-08-11T00:00:00Z",
                end_inclusive: true,
                exact_times: None,
            }),
        )
        .expect("bounded progressive plan");
        assert!(plan.sql.contains("{nano_chunk_start:String}"));
        assert!(plan.sql.contains("{nano_chunk_end:String}"));
        assert!(plan.params.iter().any(|(name, value)| {
            name == "nano_chunk_start" && value == "2026-08-10T23:00:00Z"
        }));

        assert!(plan_broad_log_query_with_candidates_tail_and_time(
            &tenant(),
            &manifest(),
            &query,
            None,
            None,
            Some(SourceTimeFence {
                start: "2026-08-09T23:00:00Z",
                end: "2026-08-10T00:00:00Z",
                end_inclusive: false,
                exact_times: None,
            }),
        )
        .is_err());
    }

    #[test]
    fn projected_budget_charges_only_required_physical_columns_with_margin() {
        let object = ManifestObject {
            event_object_key: "s3://bucket/table/data/event_hour=496248/one.parquet".to_string(),
            event_object_version: "version-1".to_string(),
            event_object_bytes: 900_000,
            rows: 100,
            available_paths: vec![
                "time".to_string(),
                "metadata.log_source".to_string(),
                "message".to_string(),
            ]
            .into(),
            field_types: BTreeMap::new(),
            column_compressed_bytes: BTreeMap::from([
                ("time".to_string(), 10_000),
                ("metadata.log_source".to_string(), 20_000),
                ("message".to_string(), 700_000),
            ]),
        };
        let columns = BTreeSet::from(["time".to_string(), "metadata.log_source".to_string()]);
        assert_eq!(projected_object_bytes(&object, &columns), Some(98_536));
        assert_eq!(
            projected_object_bytes(&object, &BTreeSet::from(["message".to_string()])),
            Some(835_536)
        );
        assert_eq!(
            projected_object_bytes(&object, &BTreeSet::from(["unknown".to_string()])),
            Some(65_536)
        );
    }

    #[test]
    fn exact_object_source_cannot_cross_the_assigned_table() {
        let mut assigned = tenant();
        assigned.source = "https://object.test/other/table".to_string();
        assert!(exact_parquet_source(
            &assigned,
            &["s3://bucket/table/data/one.parquet"],
            "candidate_source",
        )
        .is_err());
    }

    #[test]
    fn empty_exact_candidate_set_is_a_zero_scan() {
        let query = compiled(
            "SELECT * FROM __nano_lake_source__ WHERE \"resources.hostname\" = 'absent'",
            vec![
                column("resources.hostname", "array"),
                column("time", "timestamp"),
            ],
        );
        let plan = plan_broad_log_query_with_candidates(&tenant(), &manifest(), &query, Some(&[]))
            .expect("empty candidate plan");
        assert!(plan.sql.contains("WHERE 0"));
        assert_eq!(plan.budget.candidate_objects, 0);
        assert_eq!(plan.budget.estimated_scan_bytes, 0);
    }

    #[test]
    fn fetch_log_uses_typed_bindings_and_full_event_shape() {
        let denied = BTreeSet::from(["blocked-source".to_string()]);
        let plan = plan_fetch_log(
            &tenant(),
            &manifest(),
            &FetchLogPlanRequest {
                event_id: "event-'quoted'",
                start: Some("2026-08-10T00:00:00Z"),
                end: Some("2026-08-10T00:00:02Z"),
                log_source: Some("sysmon"),
                deny_source_types: &denied,
            },
        )
        .expect("fetch plan");
        assert!(plan.native_event_rows);
        assert!(plan.sql.contains("input_format_parquet_memory_high_watermark=33554432"));
        assert!(!plan.sql.contains("event-'quoted'"));
        assert!(plan.sql.contains("{fetch_event_id:String}"));
        assert!(plan.sql.contains("{fetch_log_source:String}"));
        assert!(plan.sql.contains("{fetch_deny_source_0:String}"));
        assert!(plan.sql.contains("{fetch_start:String}"));
        assert!(plan.sql.contains("{fetch_end:String}"));
        assert_eq!(
            plan.params
                .iter()
                .find(|(name, _)| name == "fetch_event_id")
                .map(|(_, value)| value.as_str()),
            Some("event-'quoted'")
        );
        assert_eq!(plan.budget.estimated_scan_bytes, 900);
    }

    #[test]
    fn fetch_log_rejects_partial_or_reversed_time_ranges() {
        let denied = BTreeSet::new();
        for (start, end) in [
            (Some("2026-08-10T00:00:00Z"), None),
            (Some("2026-08-10T00:00:02Z"), Some("2026-08-10T00:00:00Z")),
        ] {
            assert!(matches!(
                plan_fetch_log(
                    &tenant(),
                    &manifest(),
                    &FetchLogPlanRequest {
                        event_id: "event-1",
                        start,
                        end,
                        log_source: None,
                        deny_source_types: &denied,
                    },
                ),
                Err(QueryPlanError::InvalidCompilerOutput(_))
            ));
        }
    }

    #[test]
    fn explicit_default_chain_omits_static_secrets_from_chdb_query() {
        let mut workload_tenant = tenant();
        workload_tenant.credentials = ObjectStoreCredentials::DefaultChain;
        let (source, params) = trusted_iceberg_source(&workload_tenant).expect("trusted source");
        assert!(source.contains("icebergS3({source:String}, SETTINGS"));
        assert!(!source.contains("iceberg_access_key"));
        assert_eq!(
            params,
            vec![("source".to_string(), workload_tenant.source.clone())]
        );
    }

    #[test]
    fn empty_static_credentials_fail_instead_of_falling_back_to_ambient_identity() {
        let mut invalid = tenant();
        invalid.credentials = ObjectStoreCredentials::Static {
            access_key: String::new(),
            secret_key: String::new(),
            session_token: None,
        };
        assert!(matches!(
            trusted_iceberg_source(&invalid),
            Err(QueryPlanError::InvalidTenantConfig(_))
        ));
    }
}

#[cfg(test)]
mod scoped_snapshot_source_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// Hour 496_000 starts at 496_000 * 3_600_000 ms.
    const HOUR: i64 = 3_600_000;

    fn cache_with_hours(hours: &[i64]) -> SnapshotCache {
        let objects = hours
            .iter()
            .map(|hour| {
                let path = format!("/cache/gen/data/event_hour={hour}/part-{hour}.parquet");
                (
                    format!("s3://bucket/table/data/event_hour={hour}/part-{hour}.parquet"),
                    SnapshotCacheObject {
                        version_id: format!("v{hour}"),
                        bytes: 1_000,
                        path: PathBuf::from(path),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        SnapshotCache {
            source_spec: "/cache/gen/data/{ALL}".to_string(),
            objects,
            bytes: 1_000 * hours.len() as u64,
            read_schema: None,
            bootstrap: false,
        }
    }

    fn window_for_hours(start_hour: i64, end_hour: i64) -> ObjectTimeWindow {
        ObjectTimeWindow {
            start_ms: start_hour * HOUR,
            end_ms: end_hour * HOUR + (HOUR - 1),
        }
    }

    /// The whole point of the change: a narrow window must not hand chDB the
    /// entire generation. Before this, every query opened all 689 objects of the
    /// table regardless of window — a zero-row query still cost 0.569s.
    #[test]
    fn a_narrow_window_prunes_the_source_to_its_own_hours() {
        let cache = cache_with_hours(&[496_000, 496_001, 496_002, 496_003, 496_004]);
        let (spec, overlap) =
            scoped_snapshot_source_spec(&cache, Some(window_for_hours(496_001, 496_002)));
        assert_eq!(overlap, BaseWindowOverlap::Possible);
        let spec = spec.expect("a partial overlap must produce a narrowed spec");
        for included in ["496001", "496002"] {
            assert!(
                spec.contains(included),
                "hour {included} overlaps the window and must be present: {spec}"
            );
        }
        for excluded in ["496000", "496003", "496004"] {
            assert!(
                !spec.contains(excluded),
                "hour {excluded} is outside the window and must be pruned: {spec}"
            );
        }
    }

    /// Fail-safe direction. Every fallback path must widen to the full
    /// generation, never narrow it — reading too much is a cost bug, reading too
    /// little is a correctness bug that silently loses security events.
    #[test]
    fn every_fallback_widens_to_the_full_generation_rather_than_narrowing() {
        let cache = cache_with_hours(&[496_000, 496_001]);
        let (spec, overlap) = scoped_snapshot_source_spec(&cache, None);
        assert!(
            spec.is_none(),
            "no window means no pruning information, so the full spec must be used"
        );
        assert_eq!(overlap, BaseWindowOverlap::Possible);
        // Everything overlaps -> reuse the precomputed spec rather than rebuild.
        let everything = window_for_hours(496_000, 496_001);
        let (spec, overlap) = scoped_snapshot_source_spec(&cache, Some(everything));
        assert!(
            spec.is_none(),
            "when nothing is pruned the existing spec must be reused"
        );
        assert_eq!(overlap, BaseWindowOverlap::Possible);
    }

    /// A window no object overlaps is a proof, not an unknown: every path here
    /// carries a trusted hour, and untrusted paths are always kept, so an empty
    /// overlap set means the generation cannot contribute a row.
    ///
    /// This is what made short recent searches slower than long ones. The newest
    /// hour is still in the hot tail, so "last 5 minutes" overlapped no base
    /// object, fell back to the whole generation, and cost ~3x a "last hour"
    /// search over 12x the rows.
    #[test]
    fn a_window_no_object_overlaps_names_one_object_and_reads_none() {
        let cache = cache_with_hours(&[496_000, 496_001]);

        let (spec, overlap) =
            scoped_snapshot_source_spec(&cache, Some(window_for_hours(999_000, 999_001)));
        assert_eq!(overlap, BaseWindowOverlap::ProvenEmpty);
        let spec = spec.expect("a proven-empty window still names a source for its schema");
        assert!(
            !spec.contains("496000"),
            "only one object is named, and no data is read from it: {spec}"
        );
        assert!(
            spec.contains("496001"),
            "the named object must exist: {spec}"
        );
        assert_eq!(
            base_window_guard(overlap),
            "_path = ''",
            "a proven-empty base must be fenced to zero rows"
        );
        assert_eq!(
            base_window_guard(BaseWindowOverlap::Possible),
            "_path != ''"
        );
    }

    /// The proof depends on every object being placeable in time. One object
    /// without a trusted hour segment makes the empty overlap unprovable, and
    /// the query must widen back to the full generation.
    #[test]
    fn an_unpartitioned_object_prevents_the_proven_empty_shortcut() {
        let mut cache = cache_with_hours(&[496_000, 496_001]);
        cache.objects.insert(
            "s3://bucket/table/data/legacy-flat.parquet".to_string(),
            SnapshotCacheObject {
                version_id: "legacy".to_string(),
                bytes: 1_000,
                path: PathBuf::from("/cache/gen/data/legacy-flat.parquet"),
            },
        );

        let (spec, overlap) =
            scoped_snapshot_source_spec(&cache, Some(window_for_hours(999_000, 999_001)));
        assert_eq!(overlap, BaseWindowOverlap::Possible);
        let spec = spec.expect("the untrusted object still narrows the source");
        assert!(
            spec.contains("legacy-flat.parquet"),
            "an object of unknown coverage must still be read: {spec}"
        );
    }

    /// An object whose path carries no trusted `event_hour=` segment has unknown
    /// coverage, so it must be treated as overlapping every window and always
    /// retained — otherwise pruning could drop real events.
    #[test]
    fn an_unpartitioned_object_is_never_pruned_away() {
        let mut cache = cache_with_hours(&[496_000, 496_001, 496_002]);
        cache.objects.insert(
            "s3://bucket/table/data/legacy-flat.parquet".to_string(),
            SnapshotCacheObject {
                version_id: "legacy".to_string(),
                bytes: 1_000,
                path: PathBuf::from("/cache/gen/data/legacy-flat.parquet"),
            },
        );
        let spec = scoped_snapshot_source_spec(&cache, Some(window_for_hours(496_000, 496_000)))
            .0
            .expect("a partial overlap must still narrow");
        assert!(
            spec.contains("legacy-flat.parquet"),
            "an object with no trusted hour partition must be retained: {spec}"
        );
    }
}

/// Cost probe for the per-request manifest sweeps.
///
/// Skipped unless `NANO_LAKE_MANIFEST_COST_FIXTURE` names a real generation
/// manifest, because the shape that matters (hundreds of objects, ~150k field
/// entries) only exists on a running deployment.
#[cfg(test)]
mod manifest_cost_tests {
    use super::*;

    #[test]
    fn report_per_request_manifest_sweep_cost() {
        let Ok(path) = std::env::var("NANO_LAKE_MANIFEST_COST_FIXTURE") else {
            eprintln!("manifest cost probe skipped; set NANO_LAKE_MANIFEST_COST_FIXTURE");
            return;
        };
        let bytes = std::fs::read(&path).expect("read manifest fixture");
        let manifest: SourceManifest =
            serde_json::from_slice(&bytes).expect("decode manifest fixture");
        let entries: usize = manifest
            .objects
            .iter()
            .map(|object| object.field_types.len())
            .sum();
        eprintln!(
            "manifest: {} objects, {} field-type entries",
            manifest.objects.len(),
            entries
        );

        // Cost of deriving the facts once, which is what a generation load now
        // pays and a request no longer does.
        let cold = std::time::Instant::now();
        let facts = compute_manifest_facts(&manifest).expect("facts");
        let cold = cold.elapsed().as_secs_f64() * 1_000.0;
        std::hint::black_box(&facts);
        eprintln!("compute_manifest_facts (once per generation): {cold:.3} ms");

        // Cost per request now: the memo lookup plus the clones the callers get.
        let warm = std::time::Instant::now();
        for _ in 0..100 {
            let types = snapshot_field_types(&manifest).expect("field types");
            std::hint::black_box(types);
        }
        eprintln!(
            "snapshot_field_types: {:.4} ms per call",
            warm.elapsed().as_secs_f64() * 10.0
        );

        let tenant = TenantQueryConfig {
            tenant_id: manifest.tenant_id.clone(),
            source: "https://object.test/bucket/table".to_string(),
            iceberg_metadata_file_path: "metadata/00001.metadata.json".to_string(),
            max_query_bytes: u64::MAX,
            max_memory_bytes: DEFAULT_QUERY_MEMORY_BYTES,
            max_execution_seconds: 30,
            threads: 4,
            credentials: ObjectStoreCredentials::Static {
                access_key: "access".to_string(),
                secret_key: "secret".to_string(),
                session_token: None,
            },
            snapshot_cache: None,
        };
        let validate = std::time::Instant::now();
        for _ in 0..100 {
            let out = validate_manifest(&tenant, &manifest).expect("validate");
            std::hint::black_box(out);
        }
        eprintln!(
            "validate_manifest: {:.4} ms per call",
            validate.elapsed().as_secs_f64() * 10.0
        );

        // What releasing the per-object schema copies actually buys, on the
        // structure the worker holds for the life of a generation.
        let retained_before: usize = manifest
            .objects
            .iter()
            .map(|object| object.field_types.len())
            .sum();
        let mut released: SourceManifest =
            serde_json::from_slice(&std::fs::read(&path).expect("re-read")).expect("decode");
        released
            .release_derived_object_schema()
            .expect("release schema");
        let retained_after: usize = released
            .objects
            .iter()
            .map(|object| object.field_types.len())
            .sum();
        eprintln!("per-object field_type entries retained: {retained_before} -> {retained_after}");
        let paths_before: usize = manifest
            .objects
            .iter()
            .map(|object| object.available_paths.len())
            .sum();
        let (shapes, paths_after) = released.shared_schema_shapes();
        eprintln!(
            "available_path entries stored: {paths_before} -> {paths_after} across {shapes} shared shapes"
        );
        assert_eq!(
            snapshot_field_types(&released).expect("released facts"),
            snapshot_field_types(&manifest).expect("facts"),
            "the merged field-type view must survive the release"
        );
    }
}

#[cfg(test)]
mod flat_filter_leaf_tests {
    use super::*;

    const SCHEMA: &str = "`count` Nullable(Int64), `device` Tuple(`hostname` Nullable(String), `type_id` Nullable(Int64)), `metadata` Tuple(`uid` Nullable(String), `event_code` Nullable(String)), `resources` Array(Tuple(`hostname` Nullable(String))), `src_endpoint` Tuple(`ip` Nullable(String)), `time` DateTime64(6, 'UTC')";

    fn required(paths: &[&str]) -> BTreeMap<String, String> {
        paths.iter().map(|path| (path.to_string(), "string".to_string())).collect()
    }

    fn statement(projection: &str) -> String {
        format!(
            "SELECT {projection} FROM file({{candidate_source:String}}, Parquet, {{candidate_source_read_schema:String}}) WHERE 1 \
             UNION ALL SELECT {projection} FROM file({{candidate_partial_source:String}}, Parquet, {{candidate_partial_source_read_schema:String}}) WHERE 1"
        )
    }

    fn params() -> Vec<(String, String)> {
        vec![
            ("candidate_source".into(), "/c/a.parquet".into()),
            ("candidate_source_read_schema".into(), SCHEMA.into()),
            ("candidate_partial_source_read_schema".into(), SCHEMA.into()),
        ]
    }

    #[test]
    fn scalar_struct_leaves_become_flat_prewhere_columns() {
        let sql = statement("`device`.`hostname` AS `device.hostname`, `metadata`.`event_code` AS `metadata.event_code`, `time` AS `time`");
        let mut params = params();
        let flat = flat_scalar_leaves(&sql, &mut params, &required(&["device.hostname", "metadata.event_code", "time"])).unwrap();
        assert_eq!(flat.matches("`device.hostname` AS `device.hostname`").count(), 2);
        assert_eq!(flat.matches("`metadata.event_code` AS `metadata.event_code`").count(), 2);
        assert!(!flat.contains("`device`.`hostname`"));
        for (name, schema) in &params {
            if name.ends_with("_read_schema") {
                // Additive: the Tuple root stays, the flat sibling is appended once.
                assert!(schema.starts_with(SCHEMA));
                assert_eq!(schema.matches(", `device.hostname` Nullable(String)").count(), 1);
                assert_eq!(schema.matches(", `metadata.event_code` Nullable(String)").count(), 1);
            }
        }
    }

    #[test]
    fn array_leaves_and_unprojected_paths_stay_nested() {
        let sql = statement("`resources`.`hostname` AS `resources.hostname`");
        let mut params = params();
        assert!(flat_scalar_leaves(&sql, &mut params, &required(&["resources.hostname", "device.hostname"])).is_none());
        assert!(params.iter().all(|(name, schema)| !name.ends_with("_read_schema") || schema == SCHEMA));
    }

    /// NAN-4168: endpoint leaves are plain scalar leaves like any other.
    #[test]
    fn endpoint_leaves_flatten_like_any_scalar_leaf() {
        let sql = statement("`src_endpoint`.`ip` AS `src_endpoint.ip`");
        let mut params = params();
        let flat = flat_scalar_leaves(&sql, &mut params, &required(&["src_endpoint.ip"])).unwrap();
        assert!(!flat.contains("`src_endpoint`.`ip`"), "{flat}");
    }

    #[test]
    fn select_star_over_a_storage_function_declines() {
        let sql = format!(
            "{} UNION ALL SELECT * FROM file({{candidate_partial_source:String}}, Parquet, {{candidate_partial_source_read_schema:String}})",
            statement("`device`.`hostname` AS `device.hostname`").split(" UNION ALL ").next().unwrap()
        );
        let mut params = params();
        assert!(flat_scalar_leaves(&sql, &mut params, &required(&["device.hostname"])).is_none());
        assert!(params.iter().all(|(name, schema)| !name.ends_with("_read_schema") || schema == SCHEMA));
        // `SELECT *` over a subquery (fences, masks) does not decline.
        let sql = format!("SELECT * FROM ({}) WHERE 1", statement("`device`.`hostname` AS `device.hostname`"));
        assert!(flat_scalar_leaves(&sql, &mut params, &required(&["device.hostname"])).is_some());
    }

    #[test]
    fn a_source_without_an_explicit_schema_declines() {
        let sql = "SELECT `device`.`hostname` AS `device.hostname` FROM file({candidate_source:String}, Parquet) WHERE 1";
        let mut params = params();
        assert!(flat_scalar_leaves(sql, &mut params, &required(&["device.hostname"])).is_none());
    }

    #[test]
    fn schemas_that_disagree_on_the_leaf_type_decline() {
        let sql = statement("`device`.`hostname` AS `device.hostname`");
        let mut params = params();
        params[2].1 = SCHEMA.replace("`hostname` Nullable(String), `type_id`", "`hostname` Nullable(Int64), `type_id`");
        assert!(flat_scalar_leaves(&sql, &mut params, &required(&["device.hostname"])).is_none());
    }

    #[test]
    fn a_schema_missing_the_root_keeps_its_type_and_the_others_get_the_leaf() {
        let sql = statement("`device`.`hostname` AS `device.hostname`");
        let mut params = params();
        params[2].1 = "`time` DateTime64(6, 'UTC')".into();
        let flat = flat_scalar_leaves(&sql, &mut params, &required(&["device.hostname"])).unwrap();
        assert!(flat.contains("`device.hostname` AS `device.hostname`"));
        assert!(params[1].1.ends_with(", `device.hostname` Nullable(String)"));
        assert_eq!(params[2].1, "`time` DateTime64(6, 'UTC')");
    }
}

/// NAN-3179: a [`super::row_fence`] parsed back and evaluated per row the way chDB
/// would, shared by the planner and sidecar tests so a fence assertion checks
/// the rows it admits rather than one SQL spelling.
#[cfg(test)]
pub(crate) mod fence_eval {
    use regex::Regex;
    use std::collections::{BTreeMap, BTreeSet};

    pub(crate) enum FenceTerm {
        Range(String, u64, u64),
        /// path -> (granule, file id), key width, keys.
        Set(BTreeMap<String, (u64, u64)>, u64, BTreeSet<u64>),
    }

    pub(crate) fn parse_fence(fence: &str, params: &[(String, String)]) -> Vec<FenceTerm> {
        let set = Regex::new(r"^\(intDiv\(_row_number, transform\(_path, \[([^\]]*)\], \[([^\]]*)\], 1\)\) \* (\d+) \+ transform\(_path, \[([^\]]*)\], \[([^\]]*)\], 0\)\) IN \(([^)]*)\)$").unwrap();
        let term = Regex::new(r"^\(_path = \{(\w+):String\} AND _row_number >= (\d+) AND _row_number < (\d+)\)$").unwrap();
        let param = |name: &str| params.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone()).unwrap();
        let list = |text: &str| text.split(',').map(str::to_string).collect::<Vec<_>>();
        let number = |text: &str| text.parse::<u64>().unwrap();
        fence.split(" OR ").map(|part| {
            if let Some(c) = term.captures(part) {
                return FenceTerm::Range(param(&c[1]), number(&c[2]), number(&c[3]));
            }
            let c = set.captures(part).unwrap_or_else(|| panic!("unexpected fence term {part}"));
            assert_eq!(list(&c[1]), list(&c[4]));
            let files = list(&c[1]).iter().zip(list(&c[2])).zip(list(&c[5]))
                .map(|((name, granule), id)| (param(name.trim_start_matches('{').trim_end_matches(":String}")), (number(&granule), number(&id))))
                .collect();
            FenceTerm::Set(files, number(&c[3]), list(&c[6]).iter().map(|k| number(k)).collect())
        }).collect()
    }

    pub(crate) fn fence_matches(terms: &[FenceTerm], path: &str, row: u64) -> bool {
        terms.iter().any(|term| match term {
            FenceTerm::Range(p, start, end) => p == path && (*start..*end).contains(&row),
            FenceTerm::Set(files, width, keys) => {
                let (granule, id) = files.get(path).copied().unwrap_or((1, 0));
                keys.contains(&(row / granule * width + id))
            }
        })
    }
}
