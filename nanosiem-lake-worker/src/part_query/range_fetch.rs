// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3133: range-aware cold fetch for interactive search.
//!
//! A search reads a handful of columns, yet a cold data file used to be
//! fetched whole (~64–91 MB) to read ~1 MB of them. Parts written with
//! `NANO_LAKE_PARQUET_RANGE_WRITE` carry a signed range manifest
//! (`ranges-NNNNN.json`, contract §4.2): the SHA-256 of every column chunk
//! and of the footer. With `NANO_LAKE_SEARCH_RANGE_FETCH=1` a search whose
//! compiled shape names its columns fetches only
//!
//! - the footer range, and
//! - every column chunk (all row groups) of the Parquet roots it can read,
//!
//! each through the reader cache under its own signed digest, and hands chDB
//! a per-query **sparse file**: the chunks at their original offsets, holes
//! everywhere else, and the signed footer minus its page-index and bloom
//! references (see [`sanitized_footer`]). chDB reads only projected chunks
//! (verified with the real library: a hole is never read as data; any read
//! of one fails with a Thrift error), so results are those of the whole file.
//!
//! Fail closed, to the existing whole-file path: the flag off, a full-event
//! shape (`SELECT *` raw rows), an entity pivot (its in-file bloom pruning
//! needs bytes no range signs), a legacy part without a manifest, a manifest
//! or chunk that does not verify or cannot be fetched now, a footer that
//! cannot be rewritten exactly, a column set that is not narrow, no scratch
//! capacity, and a whole file already local (hot window, writer or producer
//! copy: residency wins). A chDB read of a hole (a Parquet decode error) on a
//! request that read a sparse file reruns it once on whole files, drawing on
//! what is left of the cold budget the ranged attempt used.
//!
//! One cold-byte budget per selection covers its manifests, ranges and
//! whole-file fallbacks ([`crate::reader_object_cache::ColdBudget`]).
//!
//! A sparse file is never admitted to the reader cache or keyed by the whole
//! file's digest. It lives under `<tenant cache>/ranged/<process>/` with a
//! capacity reservation, is reused by later queries with the same column
//! set while it stays in a small LRU, and is removed when the last query
//! using it ends. A process's directory is removed by the next process that
//! finds its lock free. Range chunks are cached under their own digests.

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::parts::parquet_ranges::ParquetRangeDigest;
use crate::planner::CompiledQuery;

pub(super) const LATE_FALLBACK: &str = "late materialization needs the verified whole-file path";

/// The runtime flag (default off).
pub const FLAG: &str = "NANO_LAKE_SEARCH_RANGE_FETCH";

/// A ranged read is used only when its chunks are at most this fraction of
/// the data file (denominator); otherwise the whole file is fetched and
/// becomes reusable by every later query.
const NARROW_DENOMINATOR: u64 = 2;

/// How often a live process re-sweeps other processes' sparse directories.
const SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(600);
/// Signed footers kept rewritten in memory, and sparse files kept for reuse.
const FOOTER_MEMO_ENTRIES: usize = 4_096;
const SPARSE_MEMO_ENTRIES: usize = 1_024;

pub fn enabled() -> bool {
    crate::perf_overrides::probe_flag("range_fetch", flag_value(std::env::var(FLAG).ok().as_deref()))
}

/// [`NARROW_DENOMINATOR`], or an SQL probe's `range_narrow_denominator`.
fn narrow_denominator() -> u64 {
    crate::perf_overrides::probe_count("range_narrow_denominator").unwrap_or(NARROW_DENOMINATOR)
}

fn flag_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

/// Why a data file (or a whole request) took the whole-file path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fallback {
    /// The compiled shape returns full event rows (every root).
    WideShape,
    /// A legacy part: no signed range manifest.
    NoSidecar,
    /// The signed manifest failed its digest, schema or bounds checks.
    SidecarInvalid,
    /// A range chunk failed verification against its signed digest.
    VerificationFailed,
    /// The signed footer could not be rewritten byte-exactly.
    FooterRewrite,
    /// The selected chunks are not a narrow fraction of the file.
    NotNarrow,
    /// chDB failed on a request that read a sparse file; rerun whole.
    NativeError,
    /// A range manifest or range fetch, residency probe or scratch write
    /// failed transiently (timeout, unavailable, saturated, budget, I/O).
    FetchFailed,
    /// An entity pivot prunes row groups with in-file blooms, which no
    /// signed range covers: the whole file keeps that pruning.
    EntityPivot,
}

impl Fallback {
    pub const ALL: [Fallback; 9] = [Fallback::WideShape, Fallback::NoSidecar, Fallback::SidecarInvalid,
        Fallback::VerificationFailed, Fallback::FooterRewrite, Fallback::NotNarrow, Fallback::NativeError,
        Fallback::FetchFailed, Fallback::EntityPivot];

    pub fn as_str(self) -> &'static str {
        match self {
            Fallback::WideShape => "wide_shape",
            Fallback::NoSidecar => "no_sidecar",
            Fallback::SidecarInvalid => "sidecar_invalid",
            Fallback::VerificationFailed => "verification_failed",
            Fallback::FooterRewrite => "footer_rewrite",
            Fallback::NotNarrow => "not_narrow",
            Fallback::NativeError => "native_error",
            Fallback::FetchFailed => "fetch_failed",
            Fallback::EntityPivot => "entity_pivot",
        }
    }
}

#[derive(Default)]
struct Counters {
    range_fetched_bytes: AtomicU64,
    whole_fetched_bytes: AtomicU64,
    range_files: AtomicU64,
    resident_files: AtomicU64,
    fallbacks: [AtomicU64; Fallback::ALL.len()],
}

static COUNTERS: std::sync::LazyLock<Counters> = std::sync::LazyLock::new(Counters::default);

pub fn record_fallback(reason: Fallback, files: u64) {
    COUNTERS.fallbacks[reason as usize].fetch_add(files, Ordering::Relaxed);
}

/// Process counters for `/v1/status` (`range_fetch`).
pub fn stats_json() -> Value {
    let fallbacks = Fallback::ALL.iter()
        .map(|reason| (reason.as_str().to_string(), json!(COUNTERS.fallbacks[*reason as usize].load(Ordering::Relaxed))))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "enabled": enabled(),
        "range_fetched_bytes": COUNTERS.range_fetched_bytes.load(Ordering::Relaxed),
        "whole_fetched_bytes": COUNTERS.whole_fetched_bytes.load(Ordering::Relaxed),
        "range_files": COUNTERS.range_files.load(Ordering::Relaxed),
        "resident_files": COUNTERS.resident_files.load(Ordering::Relaxed),
        "range_fallbacks": fallbacks,
    })
}

/// One data-stage fetch's range evidence (per query, in planner evidence).
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FetchEvidence {
    pub range_files: usize,
    pub resident_files: usize,
    pub range_fetched_bytes: u64,
    pub whole_fetched_bytes: u64,
    pub range_fallbacks: BTreeMap<&'static str, usize>,
}

impl FetchEvidence {
    pub fn fallback(&mut self, reason: Fallback) {
        self.fallbacks(reason, 1);
    }

    pub fn fallbacks(&mut self, reason: Fallback, files: usize) {
        if files == 0 { return }
        *self.range_fallbacks.entry(reason.as_str()).or_default() += files;
        record_fallback(reason, files as u64);
    }

    pub fn resident(&mut self) {
        self.resident_files += 1;
        COUNTERS.resident_files.fetch_add(1, Ordering::Relaxed);
    }

    /// Publish the fetched bytes of this data stage.
    pub fn fetched(&mut self, range_files: usize, range_bytes: u64, whole_bytes: u64) {
        self.range_files += range_files;
        self.range_fetched_bytes += range_bytes;
        self.whole_fetched_bytes += whole_bytes;
        COUNTERS.range_files.fetch_add(range_files as u64, Ordering::Relaxed);
        COUNTERS.range_fetched_bytes.fetch_add(range_bytes, Ordering::Relaxed);
        COUNTERS.whole_fetched_bytes.fetch_add(whole_bytes, Ordering::Relaxed);
    }

    pub fn absorb(&mut self, other: &FetchEvidence) {
        self.range_files += other.range_files;
        self.resident_files += other.resident_files;
        self.range_fetched_bytes += other.range_fetched_bytes;
        self.whole_fetched_bytes += other.whole_fetched_bytes;
        for (reason, count) in &other.range_fallbacks {
            *self.range_fallbacks.entry(reason).or_default() += count;
        }
    }
}

/// The Parquet columns one compiled search can read (see [`derive_scope`]):
/// whole roots, plus leaf paths (a leaf or the prefix of a subtree).
#[derive(Debug)]
pub struct ColumnScope {
    pub roots: BTreeSet<String>,
    pub leaves: BTreeSet<String>,
    /// Set once any selection of the request handed chDB a sparse file.
    sparse_used: AtomicBool,
    /// Cold bytes the request's selections drew (ranges and whole files).
    cold_spent: AtomicU64,
    /// A rerun: whole files only, each selection's budget reduced by
    /// `debit` (what the failed ranged attempt already fetched).
    whole_only: bool,
    debit: u64,
    late_materialization: bool,
    /// Newly enabled full-event/projection shapes stay within the measured
    /// footprint until other row-group layouts demonstrate a setup-cost win.
    guard_two_pass_groups: bool,
    two_pass_groups_refused: AtomicBool,
    two_pass_warm_refused: AtomicBool,
}

impl ColumnScope {
    pub fn new(roots: BTreeSet<String>, leaves: BTreeSet<String>) -> Self {
        Self { roots, leaves, sparse_used: AtomicBool::new(false), cold_spent: AtomicU64::new(0), whole_only: false, debit: 0, late_materialization: false,
            guard_two_pass_groups: false, two_pass_groups_refused: AtomicBool::new(false), two_pass_warm_refused: AtomicBool::new(false) }
    }

    /// The scope of a whole-file rerun of this request: no ranged reads,
    /// and the cold bytes this attempt fetched count against its budget.
    pub fn rerun(&self) -> Self {
        Self { roots: BTreeSet::new(), leaves: BTreeSet::new(), sparse_used: AtomicBool::new(false),
            cold_spent: AtomicU64::new(0), whole_only: true, debit: self.cold_spent(), late_materialization: false,
            guard_two_pass_groups: false, two_pass_groups_refused: AtomicBool::new(false), two_pass_warm_refused: AtomicBool::new(false) }
    }

    pub fn late_materialization(&self) -> bool { self.late_materialization && self.two_pass_refusal().is_none() }

    /// Called with verified survivor metadata before any narrow data fetch.
    /// 1k groups regressed H1/H10 by 69%/50%; the measured winning layout has
    /// one 40k group per selected file. Unknown layouts keep the prior reader.
    pub fn choose_two_pass_groups(&self, groups: impl Iterator<Item = (u64, u32)>) {
        if self.guard_two_pass_groups && groups.into_iter().any(|(rows, groups)| groups != 1 || rows < 40_000) {
            self.two_pass_groups_refused.store(true, Ordering::Relaxed);
            crate::query_timing::record(|p| p.funnel.two_pass_reason = self.two_pass_refusal());
        }
    }

    pub fn two_pass_refusal(&self) -> Option<&'static str> {
        if self.two_pass_groups_refused.load(Ordering::Relaxed) { Some("small_or_unmeasured_row_groups") }
        else { self.two_pass_warm_refused.load(Ordering::Relaxed).then_some("warm_row_page") }
    }

    /// Only choose before this request has fetched its first narrow source.
    /// Its own newly cached manifests must not change the route mid-query.
    pub fn should_choose_warm_path(&self) -> bool {
        self.guard_two_pass_groups && self.late_materialization()
            && !self.sparse_used() && self.cold_spent() == 0
    }

    pub fn prefer_warm_native(&self, missing_whole_bytes: u64, whole_budget: u64) {
        if missing_whole_bytes > self.budget(whole_budget).saturating_sub(self.cold_spent()) { return }
        self.two_pass_warm_refused.store(true, Ordering::Relaxed);
        crate::query_timing::record(|p| p.funnel.two_pass_reason = self.two_pass_refusal());
    }

    pub fn whole_only(&self) -> bool {
        self.whole_only || self.two_pass_refusal().is_some()
    }

    /// A selection's cold-byte budget under this scope.
    pub fn budget(&self, query_max_bytes: u64) -> u64 {
        query_max_bytes.saturating_sub(self.debit)
    }

    pub fn add_cold_spent(&self, bytes: u64) {
        self.cold_spent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn cold_spent(&self) -> u64 {
        self.cold_spent.load(Ordering::Relaxed)
    }

    /// Whether the Parquet leaf `column` (a manifest column path) is read.
    /// A repeated subtree (`list`/`key_value` levels in the physical path)
    /// is taken whole once any leaf of its root is read: logical OCSF paths
    /// omit those levels.
    pub fn covers(&self, column: &str) -> bool {
        let root = column.split('.').next().unwrap_or(column);
        if self.roots.contains(root) {
            return true;
        }
        if column.split('.').any(|segment| matches!(segment, "list" | "key_value")) {
            return self.leaves.iter().any(|leaf| leaf.split('.').next() == Some(root));
        }
        self.leaves.iter().any(|leaf| column == leaf
            || (column.starts_with(leaf.as_str()) && column.as_bytes().get(leaf.len()) == Some(&b'.')))
    }

    pub fn mark_sparse_used(&self) {
        self.sparse_used.store(true, Ordering::Relaxed);
    }

    pub fn sparse_used(&self) -> bool {
        self.sparse_used.load(Ordering::Relaxed)
    }
}

tokio::task_local! {
    static SCOPE: Option<Arc<ColumnScope>>;
}

/// Run `work` with `scope` as the request's column scope (`None`: whole files).
pub async fn with_scope<F: std::future::Future>(scope: Option<Arc<ColumnScope>>, work: F) -> F::Output {
    SCOPE.scope(scope, Box::pin(work)).await
}

/// The column scope of the calling request, if it may read ranged files.
pub fn current() -> Option<Arc<ColumnScope>> {
    SCOPE.try_with(Clone::clone).ok().flatten()
}

/// The request's scope when the flag is on and the shape names its columns.
pub fn scope_for(compiled: &CompiledQuery, field_types: &BTreeMap<String, String>) -> Option<Arc<ColumnScope>> {
    let schema_roots = field_types.keys().filter_map(|path| path.split('.').next()).map(str::to_owned).collect();
    // Selective row pages always fetch predicate/order columns first. Other
    // shapes retain their existing whole-file or opt-in column-range path.
    if !compiled.candidate_hints.is_empty() {
        if let Some(two) = super::two_pass::plan(compiled) {
            if let Ok(mut scope) = derive_scope(&two.narrow_cursor, &schema_roots) {
                scope.late_materialization = true;
                scope.guard_two_pass_groups = two.guard_groups;
                return Some(Arc::new(scope));
            }
        }
    }
    if !enabled() { return None }
    match derive_scope(compiled, &schema_roots) {
        Ok(scope) => Some(Arc::new(scope)),
        Err(reason) => {
            record_fallback(reason, 1);
            None
        }
    }
}

/// The Parquet columns the planned statements of `compiled` read, derived
/// from the compiler's typed contract and the planner's read shapes.
///
/// - A shape returning full event rows reads every root: `WideShape`.
/// - A table view is read through whole roots (the planner's root
///   projection): the roots of `required_columns`, plus `metadata` (the
///   `(time, metadata.uid)` order, cursor and locator).
/// - Any other shape reads leaves through the planner's leaf projection.
///   The compiler's `projected_scan_columns` names the physical fields the
///   pipeline references (filters, group-by, sort, eval inputs); its
///   `required_columns` also lists stage-0 pass-through columns (`message`,
///   `raw_data`) that chDB's analyzer prunes before reading (measured: a
///   `stats count by` over required `message` reads 27 KB of a 7 MB file).
///   The scope is the projected set when the compiler supplies one, else
///   `required_columns`, plus `metadata.log_source` (source deny filters).
/// - Always `time` (source time fences). Endpoint and enrichment paths are
///   plain leaves like any other (NAN-4168: no read-time enrichment masks).
///
/// Absent roots are typed defaults, never read from the file, and are
/// dropped. A miss is never silent: chDB fails on a hole (an unfetched
/// chunk decodes as an invalid page header) and the request reruns once on
/// whole files (`range_fallbacks.native_error`).
pub fn derive_scope(compiled: &CompiledQuery, schema_roots: &BTreeSet<String>) -> Result<ColumnScope, Fallback> {
    if crate::planner::preserves_full_event_shape(&compiled.sql) && !compiled.table_view {
        return Err(Fallback::WideShape);
    }
    let root_of = |path: &str| path.split('.').next().unwrap_or(path).to_string();
    let required = compiled.required_columns.iter().map(|column| column.name.clone()).collect::<BTreeSet<_>>();
    let mut roots = BTreeSet::from([crate::parts::format::TIME_COLUMN.to_string()]);
    let mut leaves = BTreeSet::new();
    if compiled.table_view {
        roots.extend(required.iter().map(|path| root_of(path)));
        roots.insert("metadata".to_string());
    } else if compiled.projected_scan_columns.is_empty() {
        leaves.extend(required);
    } else {
        leaves.extend(compiled.projected_scan_columns.iter().cloned());
        leaves.insert("metadata.log_source".to_string());
    }
    roots.retain(|root| schema_roots.contains(root));
    leaves.retain(|leaf| schema_roots.contains(&root_of(leaf)) && !roots.contains(&root_of(leaf)));
    #[cfg(test)]
    if let Some(excluded) = *TEST_ROOT_EXCLUSION.lock().unwrap() {
        roots.remove(excluded);
        leaves.retain(|leaf| root_of(leaf) != excluded);
    }
    Ok(ColumnScope::new(roots, leaves))
}

/// Whether a native error text can be chDB reading a hole of a sparse file.
/// A hole decodes as an all-zero page header (measured: `TProtocolException
/// … read stage: ColumnData` / `OffsetIndex` from `ParquetV3BlockInputFormat`);
/// treat Parquet decode/corruption errors alike. Never a type, identifier,
/// syntax, budget or memory error: those reproduce on whole files.
pub fn is_hole_read(text: &str) -> bool {
    if text.contains("TProtocolException") {
        return true;
    }
    text.contains("Parquet") && ["INCORRECT_DATA", "CANNOT_DECOMPRESS", "CORRUPTED_DATA", "CANNOT_READ_ALL_DATA",
        "CHECKSUM_DOESNT_MATCH", "Invalid data", "Corrupt"].iter().any(|kind| text.contains(kind))
}

/// The manifest indices to fetch for `scope`: the footer and every column
/// chunk it covers (all row groups: a candidate row fence is a
/// `_row_number` predicate, not a read skip).
pub fn select_ranges(ranges: &[ParquetRangeDigest], scope: &ColumnScope) -> Vec<usize> {
    ranges.iter().enumerate().filter(|(_, range)| match &range.column {
        None => true,
        Some(column) => scope.covers(column),
    }).map(|(index, _)| index).collect()
}

/// Whether `selected` bytes are narrow enough to beat a whole-file fetch.
pub fn is_narrow(selected: u64, file_bytes: u64) -> bool {
    selected.saturating_mul(narrow_denominator()) <= file_bytes
}

/// The verified footer (FileMetaData + length + `PAR1`) without page-index
/// and bloom-filter references. Those structures live outside the signed
/// ranges, so a sparse file holds holes there; chDB's v3 reader reads the
/// OffsetIndex of PREWHERE columns even with
/// `input_format_parquet_use_offset_index=0` (measured, chDB 26.7.0).
///
/// The edit is surgical: a Thrift compact-protocol walk copies every byte of
/// the signed footer except `ColumnChunk` fields 4-7 (offset/column index
/// offset and length) and `ColumnMetaData` fields 14-15 (bloom filter offset
/// and length); only the field-id deltas of the following fields are
/// re-encoded. Statistics, encodings and schema stay byte-identical (a
/// parquet-rs re-encode would drop the legacy min/max statistics). Fails
/// closed unless parquet-rs decodes the result to exactly the original
/// metadata minus those references.
pub fn sanitized_footer(footer: &[u8]) -> Result<Vec<u8>> {
    use parquet::file::metadata::{ParquetMetaData, ParquetMetaDataOptions, ParquetMetaDataReader};
    ensure!(footer.len() >= 8 && &footer[footer.len() - 4..] == b"PAR1", "invalid Parquet footer");
    let length = u32::from_le_bytes(footer[footer.len() - 8..footer.len() - 4].try_into()?) as usize;
    ensure!(length + 8 == footer.len(), "footer range is not exactly the metadata");
    let mut walker = thrift::Walker { input: &footer[..length], at: 0, out: Vec::with_capacity(length) };
    walker.structure(thrift::Struct::FileMetaData, 0)?;
    ensure!(walker.at == length, "trailing bytes after the Parquet FileMetaData");
    let mut sanitized = walker.out;
    let metadata_bytes = u32::try_from(sanitized.len())?;
    sanitized.extend_from_slice(&metadata_bytes.to_le_bytes());
    sanitized.extend_from_slice(b"PAR1");

    let options = ParquetMetaDataOptions::new().with_encoding_stats_as_mask(false);
    let decode = |bytes: &[u8]| ParquetMetaDataReader::decode_metadata_with_options(bytes, Some(&options));
    let original = decode(&footer[..length])?;
    let mut groups = Vec::with_capacity(original.num_row_groups());
    for group in original.row_groups() {
        let columns = group.columns().iter().map(|column| column.clone().into_builder()
            .set_offset_index_offset(None).set_offset_index_length(None)
            .set_column_index_offset(None).set_column_index_length(None)
            .set_bloom_filter_offset(None).set_bloom_filter_length(None)
            .build()).collect::<parquet::errors::Result<Vec<_>>>()?;
        groups.push(group.clone().into_builder().set_column_metadata(columns).build()?);
    }
    let stripped: ParquetMetaData = original.into_builder().set_row_groups(groups).build();
    let decoded = decode(&sanitized[..sanitized.len() - 8])?;
    ensure!(decoded == stripped, "sanitized footer does not decode to the stripped metadata");
    Ok(sanitized)
}

/// A minimal Thrift compact-protocol copier for [`sanitized_footer`].
mod thrift {
    use anyhow::{bail, ensure, Context, Result};

    const MAX_DEPTH: usize = 64;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Struct { FileMetaData, RowGroup, ColumnChunk, ColumnMetaData, Other }

    impl Struct {
        /// The struct type of field `id` of `self` (for the path we edit).
        fn child(self, id: i16) -> Struct {
            match (self, id) {
                (Struct::FileMetaData, 4) => Struct::RowGroup,
                (Struct::RowGroup, 1) => Struct::ColumnChunk,
                (Struct::ColumnChunk, 3) => Struct::ColumnMetaData,
                _ => Struct::Other,
            }
        }

        fn dropped(self, id: i16) -> bool {
            matches!((self, id), (Struct::ColumnChunk, 4..=7) | (Struct::ColumnMetaData, 14 | 15))
        }
    }

    pub struct Walker<'a> {
        pub input: &'a [u8],
        pub at: usize,
        pub out: Vec<u8>,
    }

    impl Walker<'_> {
        fn byte(&mut self) -> Result<u8> {
            let byte = *self.input.get(self.at).context("truncated Thrift footer")?;
            self.at += 1;
            Ok(byte)
        }

        fn varint(&mut self) -> Result<u64> {
            let mut value = 0_u64;
            for shift in (0..64).step_by(7) {
                let byte = self.byte()?;
                value |= u64::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 { return Ok(value) }
            }
            bail!("overlong Thrift varint")
        }

        fn take(&mut self, bytes: usize) -> Result<()> {
            ensure!(self.input.len() - self.at >= bytes, "truncated Thrift footer");
            self.at += bytes;
            Ok(())
        }

        /// Skip one value of compact type `kind`; the caller copies the span.
        fn skip(&mut self, kind: u8, depth: usize) -> Result<()> {
            ensure!(depth < MAX_DEPTH, "Thrift footer nests too deeply");
            match kind {
                1 | 2 => Ok(()),
                3 => self.take(1),
                4..=6 => self.varint().map(drop),
                7 => self.take(8),
                8 => { let bytes = usize::try_from(self.varint()?)?; self.take(bytes) }
                9 | 10 => {
                    let header = self.byte()?;
                    let size = if header >> 4 == 15 { usize::try_from(self.varint()?)? } else { usize::from(header >> 4) };
                    let element = header & 0x0f;
                    for _ in 0..size {
                        if matches!(element, 1 | 2) { self.take(1)?; } else { self.skip(element, depth + 1)?; }
                    }
                    Ok(())
                }
                11 => {
                    let size = usize::try_from(self.varint()?)?;
                    if size == 0 { return Ok(()) }
                    let types = self.byte()?;
                    for _ in 0..size {
                        for element in [types >> 4, types & 0x0f] {
                            if matches!(element, 1 | 2) { self.take(1)?; } else { self.skip(element, depth + 1)?; }
                        }
                    }
                    Ok(())
                }
                12 => self.skip_struct(depth + 1),
                other => bail!("unknown Thrift compact type {other}"),
            }
        }

        fn skip_struct(&mut self, depth: usize) -> Result<()> {
            let mut last = 0_i16;
            loop {
                let (id, kind) = match self.field_header(last)? { Some(field) => field, None => return Ok(()) };
                last = id;
                self.skip(kind, depth)?;
            }
        }

        /// The next field header (`None` at the struct's stop byte).
        fn field_header(&mut self, last: i16) -> Result<Option<(i16, u8)>> {
            let header = self.byte()?;
            if header == 0 { return Ok(None) }
            let kind = header & 0x0f;
            let id = match header >> 4 {
                0 => {
                    let raw = self.varint()?;
                    i16::try_from((raw >> 1) as i64 ^ -((raw & 1) as i64)).context("Thrift field id out of range")?
                }
                delta => last.checked_add(i16::from(delta)).context("Thrift field id overflow")?,
            };
            Ok(Some((id, kind)))
        }

        fn write_header(&mut self, last: i16, id: i16, kind: u8) {
            match id.checked_sub(last) {
                Some(delta @ 1..=15) => self.out.push(((delta as u8) << 4) | kind),
                _ => {
                    self.out.push(kind);
                    let zigzag = ((i64::from(id) << 1) ^ (i64::from(id) >> 63)) as u64;
                    let mut value = zigzag;
                    loop {
                        let byte = (value & 0x7f) as u8;
                        value >>= 7;
                        if value == 0 { self.out.push(byte); break }
                        self.out.push(byte | 0x80);
                    }
                }
            }
        }

        /// Copy struct `which`, dropping its edited fields.
        pub fn structure(&mut self, which: Struct, depth: usize) -> Result<()> {
            ensure!(depth < MAX_DEPTH, "Thrift footer nests too deeply");
            let (mut last_in, mut last_out) = (0_i16, 0_i16);
            loop {
                let Some((id, kind)) = self.field_header(last_in)? else {
                    self.out.push(0);
                    return Ok(());
                };
                last_in = id;
                if which.dropped(id) {
                    ensure!(matches!(kind, 5 | 6), "unexpected type of an index reference");
                    self.skip(kind, depth)?;
                    continue;
                }
                self.write_header(last_out, id, kind);
                last_out = id;
                let child = which.child(id);
                match (kind, child) {
                    (12, Struct::ColumnMetaData) => self.structure(child, depth + 1)?,
                    (9, Struct::RowGroup | Struct::ColumnChunk) => {
                        let header = self.byte()?;
                        self.out.push(header);
                        ensure!(header & 0x0f == 12, "expected a list of structs");
                        let size = if header >> 4 == 15 {
                            let start = self.at;
                            let size = usize::try_from(self.varint()?)?;
                            self.out.extend_from_slice(&self.input[start..self.at]);
                            size
                        } else { usize::from(header >> 4) };
                        for _ in 0..size { self.structure(child, depth + 1)?; }
                    }
                    _ => {
                        let start = self.at;
                        self.skip(kind, depth)?;
                        self.out.extend_from_slice(&self.input[start..self.at]);
                    }
                }
            }
        }
    }
}

/// A sparse Parquet file; removed when the last holder drops it. A query
/// using it holds a reader-cache capacity reservation of `bytes`; the reuse
/// memo holds none (its files are bounded by a byte cap instead), so cache
/// pressure never meets capacity it cannot evict.
#[derive(Debug)]
pub struct SparseFile {
    path: PathBuf,
    bytes: u64,
}

impl SparseFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The disk bytes accounted to this file (its capacity reservation).
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for SparseFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A tenant's sparse-file directory for this process, the rewritten-footer
/// memo and the reusable sparse files.
#[derive(Debug)]
pub struct SparseStore {
    root: PathBuf,
    dir: PathBuf,
    // The lock marks `dir` live; another process removes it once free.
    _lock: std::fs::File,
    last_sweep: std::sync::Mutex<std::time::Instant>,
    footers: std::sync::Mutex<Memo<Arc<Vec<u8>>>>,
    files: std::sync::Mutex<Memo<Arc<SparseFile>>>,
    sequence: AtomicU64,
}

/// A bounded insertion-ordered memo (oldest out first), capped by entries
/// and by the summed weight of its values.
#[derive(Debug)]
pub struct Memo<T> {
    entries: BTreeMap<String, (T, u64)>,
    order: std::collections::VecDeque<String>,
    capacity: usize,
    max_bytes: u64,
    bytes: u64,
}

impl<T: Clone> Memo<T> {
    fn new(capacity: usize, max_bytes: u64) -> Self {
        Self { entries: BTreeMap::new(), order: Default::default(), capacity, max_bytes, bytes: 0 }
    }

    fn get(&self, key: &str) -> Option<T> {
        self.entries.get(key).map(|(value, _)| value.clone())
    }

    fn insert(&mut self, key: String, value: T, weight: u64) {
        if weight > self.max_bytes {
            return;
        }
        match self.entries.insert(key.clone(), (value, weight)) {
            Some((_, old)) => self.bytes = self.bytes.saturating_sub(old),
            None => self.order.push_back(key),
        }
        self.bytes += weight;
        while self.order.len() > self.capacity || self.bytes > self.max_bytes {
            let Some(old) = self.order.pop_front() else { break };
            if let Some((_, weight)) = self.entries.remove(&old) {
                self.bytes = self.bytes.saturating_sub(weight);
            }
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn weight(&self) -> u64 {
        self.bytes
    }
}

/// Footer memo byte cap (rewritten footers are tens of KB each).
const FOOTER_MEMO_BYTES: u64 = 64 << 20;
/// Sparse files the memo keeps (unreserved): this fraction of cache capacity.
const SPARSE_MEMO_FRACTION: u64 = 16;
/// A temporary or lockless directory younger than this may be a live
/// process mid-open: never swept.
const SWEEP_GRACE: std::time::Duration = std::time::Duration::from_secs(600);

impl SparseStore {
    /// Open `root/<pid>-<nanos>/` and remove every other process directory
    /// whose lock is free (a previous process, whatever its age).
    ///
    /// The directory becomes visible already locked: it is created as
    /// `.tmp-<name>/` with its `.lock` held, then renamed into place.
    /// `cache_bytes` sizes the reuse memo.
    pub fn open(root: &Path, cache_bytes: u64) -> Result<Self> {
        use fs2::FileExt;
        static OPENS: AtomicU64 = AtomicU64::new(0);
        std::fs::create_dir_all(root).with_context(|| format!("create {}", root.display()))?;
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        let name = format!("{}-{nanos}-{}", std::process::id(), OPENS.fetch_add(1, Ordering::Relaxed));
        let staging = root.join(format!(".tmp-{name}"));
        std::fs::create_dir(&staging)?;
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(staging.join(".lock"))?;
        lock.try_lock_exclusive().context("lock the sparse directory")?;
        let dir = root.join(&name);
        std::fs::rename(&staging, &dir).context("publish the sparse directory")?;
        let store = Self {
            root: root.to_path_buf(), dir, _lock: lock,
            last_sweep: std::sync::Mutex::new(std::time::Instant::now()),
            footers: std::sync::Mutex::new(Memo::new(FOOTER_MEMO_ENTRIES, FOOTER_MEMO_BYTES)),
            files: std::sync::Mutex::new(Memo::new(SPARSE_MEMO_ENTRIES, cache_bytes / SPARSE_MEMO_FRACTION)),
            sequence: AtomicU64::new(0),
        };
        store.sweep();
        Ok(store)
    }

    /// Remove dead processes' directories: a published directory whose lock
    /// is free, or anything else (staging directory, lockless directory,
    /// loose file) older than [`SWEEP_GRACE`].
    pub fn sweep(&self) {
        use fs2::FileExt;
        let Ok(entries) = std::fs::read_dir(&self.root) else { return };
        let old = |path: &Path| std::fs::symlink_metadata(path).ok().and_then(|meta| meta.modified().ok())
            .and_then(|modified| modified.elapsed().ok()).is_some_and(|age| age > SWEEP_GRACE);
        for entry in entries.flatten() {
            let path = entry.path();
            if path == self.dir {
                continue;
            }
            let staging = entry.file_name().to_str().is_some_and(|name| name.starts_with(".tmp-"));
            if !path.is_dir() {
                if old(&path) { let _ = std::fs::remove_file(&path); }
                continue;
            }
            let dead = if staging {
                old(&path)
            } else {
                match std::fs::OpenOptions::new().write(true).open(path.join(".lock")) {
                    Ok(lock) => lock.try_lock_exclusive().is_ok(),
                    Err(_) => old(&path),
                }
            };
            if dead {
                let _ = std::fs::remove_dir_all(&path);
            }
        }
        *self.last_sweep.lock().expect("sweep clock") = std::time::Instant::now();
    }

    /// Sweep when the last sweep is older than [`SWEEP_EVERY`].
    pub fn maybe_sweep(&self) {
        let due = self.last_sweep.lock().expect("sweep clock").elapsed() >= SWEEP_EVERY;
        if due {
            self.sweep();
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether the directory still exists (an operator may remove it).
    pub fn is_live(&self) -> bool {
        self.dir.is_dir()
    }

    /// The reusable sparse file of `key` (data digest + selected ranges).
    pub fn cached(&self, key: &str) -> Option<Arc<SparseFile>> {
        self.files.lock().expect("sparse memo").get(key).filter(|file| file.path.is_file())
    }

    pub fn cached_files(&self) -> usize {
        self.files.lock().expect("sparse memo").len()
    }

    /// Bytes of the sparse files the memo keeps.
    pub fn cached_bytes(&self) -> u64 {
        self.files.lock().expect("sparse memo").weight()
    }

    /// The rewritten footer of the signed footer at `path` (`sha256`).
    pub fn footer(&self, sha256: &str, path: &Path) -> Result<Arc<Vec<u8>>> {
        if let Some(footer) = self.footers.lock().expect("footer memo").get(sha256) {
            return Ok(footer);
        }
        let footer = Arc::new(sanitized_footer(&std::fs::read(path)?)?);
        self.footers.lock().expect("footer memo").insert(sha256.to_string(), footer.clone(), footer.len() as u64);
        Ok(footer)
    }

    /// Build (blocking) the sparse copy of a data file of `file_bytes` from
    /// leased, digest-verified chunks (`chunks`: original offset, path), the
    /// signed footer range at `footer_offset`, under a capacity reservation
    /// of the bytes it writes (returned for the query to hold); remember it
    /// for reuse under `key`.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        &self, cache: &crate::reader_object_cache::ReaderObjectCache, key: &str, file_bytes: u64,
        footer_offset: u64, footer_bytes: u64, footer_sha256: &str, footer_path: &Path, chunks: &[(u64, u64, PathBuf)],
    ) -> std::result::Result<(Arc<SparseFile>, crate::reader_object_cache::ScratchReservation), SparseError> {
        if footer_offset.checked_add(footer_bytes) != Some(file_bytes) {
            return Err(SparseError::Footer(anyhow::anyhow!("footer range does not end the file")));
        }
        let footer = self.footer(footer_sha256, footer_path).map_err(SparseError::Footer)?;
        // Named by the data digest first: a selection's files sort (and are
        // handed to chDB) in the same order as their whole-file paths
        // (`<sha256>.bin`), so an unordered `| table … | head` picks the
        // same rows either way.
        let digest = key.split(':').next().unwrap_or(key);
        let path = self.dir.join(format!("{digest}-{}.parquet", self.sequence.fetch_add(1, Ordering::Relaxed)));
        let written = chunks.iter().map(|(_, bytes, _)| bytes).sum::<u64>() + footer.len() as u64 + 4;
        let block = 4_096;
        let accounted = written.div_ceil(block).saturating_add(chunks.len() as u64 + 2).saturating_mul(block);
        let refs = chunks.iter().map(|(offset, _, path)| (*offset, path.as_path())).collect::<Vec<_>>();
        let (_, reservation) = cache.scratch_write(accounted, || {
            write_sparse(&path, &refs, footer_offset, &footer).map_err(|error| std::io::Error::other(format!("{error:#}")))
        }).map_err(|error| {
            let _ = std::fs::remove_file(&path);
            SparseError::Write(error.to_string())
        })?;
        let file = Arc::new(SparseFile { path, bytes: accounted });
        self.files.lock().expect("sparse memo").insert(key.to_string(), file.clone(), accounted);
        Ok((file, reservation))
    }
}

/// Why a sparse file was not built.
#[derive(Debug, thiserror::Error)]
pub enum SparseError {
    /// The signed footer cannot be rewritten exactly.
    #[error("sparse footer refused: {0:#}")]
    Footer(anyhow::Error),
    /// No scratch capacity or an I/O failure.
    #[error("sparse write failed: {0}")]
    Write(String),
}

/// The reuse key of a sparse file: its data digest and selected ranges.
pub fn sparse_key(data_sha256: &str, selected: &[ParquetRangeDigest]) -> String {
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    for range in selected {
        digest.update(range.offset.to_le_bytes());
        digest.update(range.sha256.as_bytes());
    }
    format!("{data_sha256}:{}", hex::encode(digest.finalize()))
}

/// Write a sparse copy of a Parquet file: column `chunks` at their original
/// offsets, holes everywhere else, then `footer` at `footer_offset` (the
/// original footer position, after every column chunk). Returns the file
/// length.
pub fn write_sparse(dest: &Path, chunks: &[(u64, &Path)], footer_offset: u64, footer: &[u8]) -> Result<u64> {
    use std::io::{Seek, SeekFrom, Write};
    let mut out = std::fs::OpenOptions::new().write(true).create_new(true).open(dest)
        .with_context(|| format!("create sparse file {}", dest.display()))?;
    out.write_all(b"PAR1")?;
    for (offset, path) in chunks {
        ensure!(*offset >= 4, "chunk overlaps the Parquet magic");
        let mut input = std::fs::File::open(path)?;
        out.seek(SeekFrom::Start(*offset))?;
        let copied = std::io::copy(&mut input, &mut out)?;
        ensure!(offset.checked_add(copied).is_some_and(|end| end <= footer_offset), "chunk overlaps the footer");
    }
    out.seek(SeekFrom::Start(footer_offset))?;
    out.write_all(footer)?;
    let length = footer_offset + footer.len() as u64;
    out.set_len(length)?;
    Ok(length)
}

#[cfg(test)]
static TEST_ROOT_EXCLUSION: std::sync::Mutex<Option<&'static str>> = std::sync::Mutex::new(None);

/// Tests only: drop `root` from every derived scope (a deliberately wrong scope).
#[cfg(test)]
pub(crate) fn set_test_root_exclusion(root: Option<&'static str>) {
    *TEST_ROOT_EXCLUSION.lock().unwrap() = root;
}

#[cfg(test)]
#[path = "range_fetch_native_tests.rs"]
mod native;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_two_pass_shapes_decline_small_and_unmeasured_groups_before_reading() {
        let scope = || {
            let mut scope = ColumnScope::new(BTreeSet::new(), BTreeSet::new());
            scope.late_materialization = true;
            scope.guard_two_pass_groups = true;
            scope
        };
        let large = scope();
        large.choose_two_pass_groups([(40_000, 1), (40_000, 1)].into_iter());
        assert!(large.late_materialization());
        assert!(!large.whole_only());
        assert!(large.should_choose_warm_path());
        large.mark_sparse_used();
        assert!(!large.should_choose_warm_path(), "never switch after a narrow source is leased");
        let warm = scope();
        warm.prefer_warm_native(10, 10);
        assert!(warm.whole_only());
        assert!(!warm.late_materialization());
        assert_eq!(warm.two_pass_refusal(), Some("warm_row_page"));
        let bounded = scope();
        bounded.add_cold_spent(1);
        bounded.prefer_warm_native(10, 10);
        assert!(bounded.late_materialization(), "promotion must not reject an affordable narrow query");
        assert!(!bounded.whole_only());
        for layout in [(1_000, 1), (0, 0), (80_000, 2)] {
            let small = scope();
            small.choose_two_pass_groups([(40_000, 1), layout].into_iter());
            assert!(!small.late_materialization());
            assert!(small.whole_only());
            assert_eq!(small.two_pass_refusal(), Some("small_or_unmeasured_row_groups"));
            assert_eq!(small.cold_spent(), 0);
            assert!(!small.sparse_used());
            // A later selection cannot re-enable a partially fetched request.
            small.choose_two_pass_groups([(40_000, 1)].into_iter());
            assert!(small.whole_only());
        }
        let mut existing = scope();
        existing.guard_two_pass_groups = false;
        existing.choose_two_pass_groups([(1_000, 1)].into_iter());
        assert!(existing.late_materialization());
    }
    use crate::part_query::fetch::{parts_key_prefix, PartFetcher, PartFile, StoreObjectSource};
    use crate::parts::format::PartKeys;
    use crate::parts::part_log::{LocalObjectStore, ObjectStore, PartRef};
    use crate::parts::provenance::tests::{sample_record, signer, TENANT};
    use crate::parts::provenance::{FileDigest, PartSigner, SignedProvenance};
    use crate::parts::sha256_hex;
    use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
    use arrow_array::{ArrayRef, Int64Array, RecordBatch, StringArray, StructArray};
    use arrow_schema::{DataType, Field, Fields, Schema};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use parquet::arrow::ProjectionMask;

    fn compiled(sql: &str, required: &[&str], table_view: bool, newest_first: bool) -> CompiledQuery {
        serde_json::from_value(json!({
            "schema_version": 1, "profile": "ocsf", "dataset": "logs", "source_placeholder": "__nano_lake_source__",
            "query_sha256": "a".repeat(64), "start": "2026-10-01T00:00:00Z", "end": "2026-10-02T00:00:00Z",
            "limit": 100, "table_view": table_view, "newest_first_event_rows": newest_first,
            "required_columns": required.iter().map(|name| json!({"name": name, "field_type": "Nullable(String)"})).collect::<Vec<_>>(),
            "sql": sql,
        })).unwrap()
    }

    fn schema_roots() -> BTreeSet<String> {
        ["time", "metadata", "actor", "api", "cloud", "src_endpoint", "dst_endpoint", "enrichments", "raw_data", "unmapped", "message"]
            .iter().map(|root| root.to_string()).collect()
    }

    fn set(roots: &[&str]) -> BTreeSet<String> {
        roots.iter().map(|root| root.to_string()).collect()
    }

    #[test]
    fn the_flag_is_off_unless_explicitly_on() {
        assert!(!flag_value(None));
        assert!(!flag_value(Some("0")));
        assert!(!flag_value(Some("yes")));
        assert!(flag_value(Some("1")));
        assert!(flag_value(Some("TRUE")));
    }

    fn scope_of(compiled: &CompiledQuery) -> (BTreeSet<String>, BTreeSet<String>) {
        let scope = derive_scope(compiled, &schema_roots()).unwrap();
        (scope.roots, scope.leaves)
    }

    #[test]
    fn column_scope_follows_each_query_shape() {
        // Filter + stats by: the compiler's projected fields, not the stage-0
        // pass-through columns of its required contract.
        let mut stats = compiled("SELECT `actor.user.name`, count() AS count FROM (SELECT * FROM __nano_lake_source__) WHERE `api.operation` = 'ListRoles' GROUP BY `actor.user.name`",
            &["actor.user.name", "api.operation", "message", "metadata.uid", "time"], false, false);
        stats.projected_scan_columns = vec!["actor.user.name".into(), "api.operation".into(), "count".into(), "time".into()];
        assert_eq!(scope_of(&stats), (set(&["time"]), set(&["actor.user.name", "api.operation", "metadata.log_source"])));
        // Without a projected set, the required contract.
        let count = compiled("SELECT count() AS count FROM (SELECT * FROM __nano_lake_source__)", &["time", "message"], false, false);
        assert_eq!(scope_of(&count), (set(&["time"]), set(&["message"])));
        // Full event rows read every root.
        let raw = compiled("SELECT * FROM __nano_lake_source__ WHERE `api.operation` = 'GetObject' ORDER BY time DESC",
            &["api.operation", "time", "metadata.uid"], false, true);
        assert_eq!(derive_scope(&raw, &schema_roots()).err(), Some(Fallback::WideShape));
        // The compiler's table view projects whole roots; event order needs metadata.
        let table = compiled("SELECT * FROM __nano_lake_source__ WHERE `api.operation` = 'GetObject'",
            &["api.operation", "time", "actor.user.name"], true, true);
        assert_eq!(scope_of(&table), (set(&["actor", "api", "metadata", "time"]), set(&[])));
        // Endpoint enrichment leaves are plain leaves (NAN-4168); absent
        // roots are dropped.
        let endpoints = compiled("SELECT `src_endpoint.location.country`, `dst_endpoint.ip`, count() FROM (SELECT * FROM __nano_lake_source__) GROUP BY 1, 2",
            &["src_endpoint.location.country", "dst_endpoint.ip", "time", "nonexistent.leaf"], false, false);
        assert_eq!(scope_of(&endpoints), (set(&["time"]), set(&["dst_endpoint.ip", "src_endpoint.location.country"])));
    }

    #[test]
    fn a_scope_covers_leaves_subtrees_and_repeated_roots() {
        let scope = ColumnScope::new(set(&["time"]), set(&["actor.user", "api.operation", "resources.type"]));
        assert!(scope.covers("time"));
        assert!(scope.covers("actor.user.name") && scope.covers("actor.user.uid"));
        assert!(!scope.covers("actor.process.name") && !scope.covers("actor.username"));
        assert!(scope.covers("api.operation") && !scope.covers("api.operation_id") && !scope.covers("api.request.data"));
        // Physical list levels are not in logical paths: the repeated root is whole.
        assert!(scope.covers("resources.list.element.uid"));
        assert!(!scope.covers("raw_data"));
    }

    fn range(offset: u64, bytes: u64, column: Option<&str>) -> ParquetRangeDigest {
        ParquetRangeDigest { offset, bytes, sha256: "b".repeat(64), row_group: column.map(|_| 0), column: column.map(str::to_owned), pages: Vec::new() }
    }

    #[test]
    fn selected_ranges_are_the_footer_and_every_leaf_of_the_scope() {
        let ranges = vec![range(4, 10, Some("actor.user.name")), range(14, 1_000, Some("raw_data")),
            range(1_014, 10, Some("time")), range(1_024, 30, Some("actor.user.uid")), range(1_054, 20, None)];
        assert_eq!(select_ranges(&ranges, &ColumnScope::new(set(&["actor", "time"]), set(&[]))), vec![0, 2, 3, 4]);
        assert_eq!(select_ranges(&ranges, &ColumnScope::new(set(&["time"]), set(&["actor.user.uid"]))), vec![2, 3, 4]);
        assert_eq!(select_ranges(&ranges, &ColumnScope::new(set(&[]), set(&[]))), vec![4]);
        assert!(is_narrow(50, 100) && !is_narrow(51, 100));
    }

    /// A Parquet file written with the part writer's properties (page index,
    /// bloom filters on identity paths), several row groups and a wide payload.
    fn write_parts_file(path: &Path, rows: usize) -> RecordBatch {
        let user = Fields::from(vec![Field::new("name", DataType::Utf8, true), Field::new("uid", DataType::Utf8, true)]);
        let actor = Fields::from(vec![Field::new("user", DataType::Struct(user.clone()), true)]);
        let schema = Arc::new(Schema::new(vec![
            Field::new("time", DataType::Int64, false),
            Field::new("actor", DataType::Struct(actor.clone()), true),
            Field::new("raw_data", DataType::Utf8, true),
        ]));
        let names = StringArray::from((0..rows).map(|i| Some(format!("user{}", i % 7))).collect::<Vec<_>>());
        let uids = StringArray::from((0..rows).map(|i| Some(format!("uid-{i}"))).collect::<Vec<_>>());
        let user_array = StructArray::new(user, vec![Arc::new(names) as ArrayRef, Arc::new(uids)], None);
        let actor_array = StructArray::new(actor, vec![Arc::new(user_array) as ArrayRef], None);
        // Incompressible payload: the column a narrow search never reads.
        let raw = StringArray::from((0..rows).map(|i| {
            let mut seed = i as u64 + 1;
            Some((0..40).map(|_| {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                format!("{seed:016x}")
            }).collect::<String>())
        }).collect::<Vec<_>>());
        let batch = RecordBatch::try_new(schema.clone(), vec![
            Arc::new(Int64Array::from((0..rows as i64).collect::<Vec<_>>())), Arc::new(actor_array), Arc::new(raw),
        ]).unwrap();
        let mut settings = crate::parts::format::ParquetSettings::for_level(crate::parts::levels::Level::L0);
        settings.row_group_rows = rows / 4;
        let id = crate::parts::format::PartId::parse("1790330400123-9f86d081884c7d65").unwrap();
        let props = settings.writer_properties(rows as u64, &id, crate::parts::levels::Level::L0, TENANT, "f").unwrap();
        let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(path).unwrap(), schema, Some(props)).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        batch
    }

    #[test]
    fn the_sanitized_footer_only_drops_index_and_bloom_references() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.parquet");
        write_parts_file(&path, 4_000);
        let body = std::fs::read(&path).unwrap();
        let ranges = crate::parts::parquet_ranges::build(&path).unwrap();
        let footer = ranges.iter().find(|range| range.column.is_none()).unwrap();
        let original = &body[footer.offset as usize..];
        let sanitized = sanitized_footer(original).unwrap();
        assert!(sanitized.len() < original.len(), "index and bloom references were present and removed");
        let decoded = parquet::file::metadata::ParquetMetaDataReader::decode_metadata(&sanitized[..sanitized.len() - 8]).unwrap();
        let before = parquet::file::metadata::ParquetMetaDataReader::decode_metadata(&original[..original.len() - 8]).unwrap();
        assert!(before.row_groups().iter().flat_map(|group| group.columns()).any(|column| column.offset_index_offset().is_some()));
        assert!(before.row_groups().iter().flat_map(|group| group.columns()).any(|column| column.bloom_filter_offset().is_some()));
        assert_eq!(decoded.num_row_groups(), before.num_row_groups());
        for (group, original) in decoded.row_groups().iter().zip(before.row_groups()) {
            for (column, original) in group.columns().iter().zip(original.columns()) {
                assert_eq!(column.offset_index_offset(), None);
                assert_eq!(column.column_index_offset(), None);
                assert_eq!(column.bloom_filter_offset(), None);
                assert_eq!(column.byte_range(), original.byte_range());
                assert_eq!(column.statistics(), original.statistics());
            }
        }
        // Idempotent, and anything that is not a well-formed footer is refused.
        assert_eq!(sanitized_footer(&sanitized).unwrap(), sanitized);
        let mut truncated = original.to_vec();
        truncated.remove(10);
        assert!(sanitized_footer(&truncated).is_err());
        let mut flipped = original.to_vec();
        flipped[20] ^= 0xff;
        assert!(sanitized_footer(&flipped).is_err());
        assert!(sanitized_footer(b"PAR1").is_err());
    }

    #[test]
    fn a_sparse_file_serves_its_projection_and_refuses_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.parquet");
        let batch = write_parts_file(&path, 4_000);
        let body = std::fs::read(&path).unwrap();
        let ranges = crate::parts::parquet_ranges::build(&path).unwrap();
        let selected = select_ranges(&ranges, &ColumnScope::new(set(&["time", "actor"]), set(&[])));
        let footer = ranges.iter().find(|range| range.column.is_none()).unwrap();
        let mut chunks = Vec::new();
        for index in selected.iter().filter(|index| ranges[**index].column.is_some()) {
            let range = &ranges[*index];
            let chunk = dir.path().join(format!("chunk-{index}"));
            std::fs::write(&chunk, &body[range.offset as usize..(range.offset + range.bytes) as usize]).unwrap();
            chunks.push((range.offset, chunk));
        }
        let footer_path = dir.path().join("footer");
        std::fs::write(&footer_path, &body[footer.offset as usize..]).unwrap();
        let sparse_dir = dir.path().join("ranged");
        // A dead process's (unlocked) directory is swept at once.
        std::fs::create_dir_all(sparse_dir.join("1-1")).unwrap();
        std::fs::write(sparse_dir.join("1-1/.lock"), b"").unwrap();
        std::fs::write(sparse_dir.join("1-1/0.parquet"), b"x").unwrap();
        let store = Arc::new(SparseStore::open(&sparse_dir, 64 << 20).unwrap());
        assert_eq!(std::fs::read_dir(&sparse_dir).unwrap().count(), 1, "only the live process directory remains");
        // A live process's directory (lock held) survives another's sweep.
        let other = SparseStore::open(&sparse_dir, 64 << 20).unwrap();
        store.sweep();
        assert!(other.dir().exists());
        drop(other);
        store.sweep();
        assert_eq!(std::fs::read_dir(&sparse_dir).unwrap().count(), 1);
        let cache = test_cache(dir.path());
        let chunks = chunks.into_iter().map(|(offset, path)| (offset, std::fs::metadata(&path).unwrap().len(), path)).collect::<Vec<_>>();
        let (sparse, reservation) = store.build(&cache, "key", body.len() as u64, footer.offset, footer.bytes, &footer.sha256, &footer_path, &chunks).unwrap();
        drop(reservation);
        assert!(Arc::ptr_eq(&store.cached("key").unwrap(), &sparse), "a built sparse file is reused");
        let projected = |file: &Path, leaves: &[usize]| {
            let builder = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(file).unwrap()).unwrap();
            let mask = ProjectionMask::leaves(builder.parquet_schema(), leaves.iter().copied());
            builder.with_projection(mask).build().unwrap().collect::<std::result::Result<Vec<_>, _>>()
        };
        // Leaves: 0 time, 1 actor.user.name, 2 actor.user.uid, 3 raw_data.
        assert_eq!(projected(sparse.path(), &[0, 1, 2]).unwrap(), projected(&path, &[0, 1, 2]).unwrap());
        assert_eq!(arrow_select::concat::concat_batches(&batch.project(&[0, 1]).unwrap().schema(),
            &projected(sparse.path(), &[0, 1, 2]).unwrap()).unwrap(), batch.project(&[0, 1]).unwrap());
        assert!(projected(sparse.path(), &[3]).is_err(), "an unfetched chunk is a hole that fails to decode");
        let stored = { use std::os::unix::fs::MetadataExt; std::fs::metadata(sparse.path()).unwrap().blocks() * 512 };
        assert!(stored * 5 < body.len() as u64, "holes are not allocated: {stored} of {}", body.len());
        let kept = sparse.path().to_path_buf();
        drop(sparse);
        assert!(kept.exists(), "the reuse memo keeps it");
        drop(store);
        assert!(!kept.exists(), "the last holder removes it");
    }

    fn test_cache(root: &Path) -> ReaderObjectCache {
        let source = root.join("empty-source");
        let store = Arc::new(LocalObjectStore::new(&source).unwrap());
        ReaderObjectCache::open(ReaderObjectCacheSettings {
            root: root.join("scratch-cache"), max_bytes: 64 << 20, query_max_bytes: 64 << 20,
            fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(5),
        }, TENANT, "bucket", &parts_key_prefix(TENANT).unwrap(), Arc::new(StoreObjectSource::local("bucket", store, source))).unwrap()
    }

    struct Fixture {
        _root: tempfile::TempDir,
        fetcher: PartFetcher,
        store: Arc<LocalObjectStore>,
        body: Vec<u8>,
        ranges: Vec<ParquetRangeDigest>,
        signer: crate::parts::provenance::LocalPartSigner,
        source_root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_budget(64 << 20)
        }

        fn with_budget(query_max_bytes: u64) -> Self {
            let root = tempfile::tempdir().unwrap();
            let source_root = root.path().join("source");
            let store = Arc::new(LocalObjectStore::new(&source_root).unwrap());
            let file = root.path().join("fixture.parquet");
            write_parts_file(&file, 4_000);
            let body = std::fs::read(&file).unwrap();
            let ranges = crate::parts::parquet_ranges::build(&file).unwrap();
            let signer = signer(7);
            let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
                root: root.path().join("cache"), max_bytes: 64 << 20, query_max_bytes,
                fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(5),
            }, TENANT, "bucket", &parts_key_prefix(TENANT).unwrap(),
                Arc::new(StoreObjectSource::local("bucket", store.clone(), source_root.clone()))).unwrap();
            let fetcher = PartFetcher::new(TENANT, "bucket", store.clone(), signer.trusted(), cache).unwrap();
            Self { _root: root, fetcher, store, body, ranges, signer, source_root }
        }

        /// Publish one signed part whose manifest is `manifest` (None: legacy).
        async fn part(&self, id: &str, manifest: Option<&[ParquetRangeDigest]>) -> PartRef {
            let mut record = sample_record();
            record.part_id = crate::parts::format::PartId::parse(id).unwrap();
            record.files.data[0].bytes = self.body.len() as u64;
            record.files.data[0].sha256 = sha256_hex(&self.body);
            record.files.data[0].row_groups = 4;
            let keys = PartKeys::new(TENANT, record.level, record.event_hour, &record.part_id).unwrap();
            self.store.put(&keys.file("data-00000.parquet"), &self.body).await.unwrap();
            record.files.data[0].parquet_ranges = match manifest {
                Some(manifest) => {
                    let manifest = serde_json::to_vec(manifest).unwrap();
                    self.store.put(&keys.file("ranges-00000.json"), &manifest).await.unwrap();
                    Some(FileDigest { name: "ranges-00000.json".into(), bytes: manifest.len() as u64, sha256: sha256_hex(&manifest) })
                }
                None => None,
            };
            let signature = self.signer.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
            let signed = SignedProvenance::assemble(record.clone(), signature, &self.signer.trusted()).unwrap().to_bytes().unwrap();
            self.store.put(&keys.provenance(), &signed).await.unwrap();
            PartRef::from_record(&record, &sha256_hex(&signed), true)
        }

        async fn fetch(&self, part: &PartRef, roots: &[&str]) -> (crate::part_query::fetch::LocalParts, u64) {
            let before = self.fetcher.cache().stats().fetched_bytes;
            let local = self.fetcher.ensure_ranged(&[(part.clone(), PartFile::Data(0))], &ColumnScope::new(set(roots), set(&[])), false).await.unwrap();
            (local, self.fetcher.cache().stats().fetched_bytes - before)
        }
    }

    #[tokio::test]
    async fn a_ranged_fetch_reads_the_scope_and_every_doubt_reads_the_whole_file() {
        let fixture = Fixture::new();
        let whole_bytes = fixture.body.len() as u64;
        let read = |path: &Path| {
            let builder = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path).unwrap()).unwrap();
            let mask = ProjectionMask::leaves(builder.parquet_schema(), [0, 1]);
            builder.with_projection(mask).build().unwrap().map(Result::unwrap).collect::<Vec<_>>()
        };

        // Signed manifest: footer + `time`/`actor` chunks only.
        let part = fixture.part("1790330400123-9f86d081884c7d65", Some(&fixture.ranges)).await;
        let (local, fetched) = fixture.fetch(&part, &["time", "actor"]).await;
        let file = local.path(&part.part_id, PartFile::Data(0)).unwrap();
        assert!(file.sparse);
        assert_eq!((file.sha256.as_str(), file.bytes), (sha256_hex(&fixture.body).as_str(), whole_bytes));
        let evidence = &local.ranged.as_ref().unwrap().evidence;
        assert_eq!(evidence.range_files, 1);
        assert_eq!(evidence.whole_fetched_bytes, 0);
        let manifest_bytes = serde_json::to_vec(&fixture.ranges).unwrap().len() as u64;
        assert_eq!(evidence.range_fetched_bytes + manifest_bytes, fetched, "the budget sees exactly the fetched ranges");
        assert!(fetched * 10 < whole_bytes, "ranged {fetched} vs whole {whole_bytes}");
        let whole_path = fixture.source_root.join(PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap().file("data-00000.parquet"));
        assert_eq!(read(&file.path), read(&whole_path));
        // The whole object was never admitted under its digest.
        let whole_ref = crate::reader_object_cache::ReaderObjectRef { range: None,
            source_uri: format!("s3://bucket/{}", PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap().file("data-00000.parquet")),
            sha256: sha256_hex(&fixture.body), size_bytes: whole_bytes };
        assert!(!fixture.fetcher.cache().is_local(&whole_ref).await.unwrap());
        let sparse_path = file.path.clone();
        drop(local);
        // A warm repeat reuses the sparse file: nothing is fetched or copied.
        let (local, fetched) = fixture.fetch(&part, &["time", "actor"]).await;
        assert_eq!((local.files[0].path.clone(), fetched), (sparse_path.clone(), 0));
        drop(local);
        assert!(sparse_path.exists(), "the reuse memo keeps the sparse file");

        // A scope that is not narrow fetches the whole file.
        let (local, fetched) = fixture.fetch(&part, &["time", "actor", "raw_data"]).await;
        assert!(!local.files[0].sparse);
        assert_eq!(local.ranged.as_ref().unwrap().evidence.range_fallbacks.get("not_narrow"), Some(&1));
        assert_eq!(fetched, whole_bytes);
        drop(local);

        // Residency wins: the whole file is now local, nothing is fetched.
        let (local, fetched) = fixture.fetch(&part, &["time"]).await;
        assert!(!local.files[0].sparse);
        assert_eq!((local.ranged.as_ref().unwrap().evidence.resident_files, fetched), (1, 0));
        drop(local);

        // Legacy part: no manifest.
        let legacy = fixture.part("1790330400124-9f86d081884c7d65", None).await;
        let (local, _) = fixture.fetch(&legacy, &["time"]).await;
        assert!(!local.files[0].sparse);
        assert_eq!(local.ranged.as_ref().unwrap().evidence.range_fallbacks.get("no_sidecar"), Some(&1));
        drop(local);

        // A signed manifest whose chunk digest is wrong: the chunk fails
        // verification and the whole (signed) file is read instead.
        let mut forged = fixture.ranges.clone();
        let time = forged.iter_mut().find(|range| range.column.as_deref() == Some("time")).unwrap();
        time.sha256 = "d".repeat(64);
        let bad = fixture.part("1790330400125-9f86d081884c7d65", Some(&forged)).await;
        let evict = || fixture.fetcher.cache().evict_unleased(vec![sha256_hex(&fixture.body)]);
        assert!(evict().await.unwrap().is_empty());
        let (local, _) = fixture.fetch(&bad, &["time"]).await;
        assert!(!local.files[0].sparse);
        assert_eq!(local.ranged.as_ref().unwrap().evidence.range_fallbacks.get("verification_failed"), Some(&1));
        assert_eq!(read(&local.files[0].path), read(&whole_path));
        drop(local);

        // A manifest that fails its schema/bounds checks.
        let mut unbounded = fixture.ranges.clone();
        unbounded.last_mut().unwrap().bytes += 1;
        let invalid = fixture.part("1790330400126-9f86d081884c7d65", Some(&unbounded)).await;
        assert!(evict().await.unwrap().is_empty());
        let (local, _) = fixture.fetch(&invalid, &["time"]).await;
        assert!(!local.files[0].sparse);
        assert_eq!(local.ranged.as_ref().unwrap().evidence.range_fallbacks.get("sidecar_invalid"), Some(&1));
    }

    #[tokio::test]
    async fn one_cold_budget_covers_manifests_ranges_and_whole_fallbacks() {
        // The budget fits the narrow ranges but not a whole file.
        let probe = Fixture::new();
        let whole_bytes = probe.body.len() as u64;
        let fixture = Fixture::with_budget(whole_bytes / 4);
        let first = fixture.part("1790330400123-9f86d081884c7d65", Some(&fixture.ranges)).await;
        let (local, fetched) = fixture.fetch(&first, &["time"]).await;
        assert!(local.files[0].sparse && fetched < whole_bytes / 4);
        drop(local);
        // A file whose ranged path fails (not narrow) falls back whole, over
        // the one budget's threshold. NAN-3644: that is no longer refused;
        // the whole fallback runs on a heavy cold-read slot.
        let second = fixture.part("1790330400124-9f86d081884c7d65", Some(&fixture.ranges)).await;
        let scope = ColumnScope::new(set(&["time", "raw_data"]), set(&[]));
        let local = fixture.fetcher.ensure_ranged(&[(second.clone(), PartFile::Data(0))], &scope, false).await.unwrap();
        assert!(!local.files[0].sparse);
        assert!(scope.cold_spent() >= whole_bytes, "the whole file was read, over the threshold");
        drop(local);
        // A rerun is charged what the ranged attempt already spent.
        let spent = ColumnScope::new(set(&["time"]), set(&[]));
        spent.add_cold_spent(whole_bytes / 4);
        assert_eq!(spent.rerun().budget(whole_bytes / 4), 0);
        assert!(spent.rerun().whole_only());
    }

    #[test]
    fn only_parquet_decode_errors_rerun_on_whole_files() {
        assert!(is_hole_read("Code: 1001. DB::Exception: apache::thrift::protocol::TProtocolException: TProtocolException: Invalid data: read stage: ColumnData: column: raw_data: (in file/uri [PARAM]): While executing ParquetV3BlockInputFormat"));
        assert!(is_hole_read("Code: 117. DB::Exception: INCORRECT_DATA while reading Parquet page"));
        for deterministic in [
            "Code: 43. DB::Exception: Illegal type String of argument of function plus. (ILLEGAL_TYPE_OF_ARGUMENT)",
            "Code: 47. DB::Exception: Unknown expression identifier `nope`. (UNKNOWN_IDENTIFIER)",
            "Code: 241. DB::Exception: (total) memory limit exceeded ... While executing ParquetV3BlockInputFormat (MEMORY_LIMIT_EXCEEDED)",
            "Code: 159. DB::Exception: Timeout exceeded: elapsed 300 seconds (TIMEOUT_EXCEEDED)",
        ] {
            assert!(!is_hole_read(deterministic), "{deterministic}");
        }
    }

    #[test]
    fn concurrent_opens_and_sweeps_never_remove_a_live_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ranged");
        // A young lockless directory or staging directory may be a process
        // mid-open: kept. Another process's live directory: kept.
        std::fs::create_dir_all(root.join("7-7")).unwrap();
        std::fs::create_dir_all(root.join(".tmp-8-8")).unwrap();
        let stores = std::thread::scope(|scope| {
            let handles = (0..8).map(|_| scope.spawn(|| {
                let store = SparseStore::open(&root, 64 << 20).unwrap();
                store.sweep();
                store
            })).collect::<Vec<_>>();
            handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>()
        });
        for store in &stores {
            store.sweep();
        }
        assert!(stores.iter().all(SparseStore::is_live), "a sibling sweep removed a live directory");
        assert!(root.join("7-7").is_dir() && root.join(".tmp-8-8").is_dir(), "young directories survive");
        let gone = stores[0].dir().to_path_buf();
        drop(stores);
        let survivor = SparseStore::open(&root, 64 << 20).unwrap();
        assert!(!gone.exists(), "a closed store's directory is swept by the next open");
        // A removed directory is noticed (the fetcher then reopens).
        std::fs::remove_dir_all(survivor.dir()).unwrap();
        assert!(!survivor.is_live());
    }

    #[test]
    fn memoized_sparse_files_never_saturate_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.parquet");
        write_parts_file(&path, 4_000);
        let body = std::fs::read(&path).unwrap();
        let ranges = crate::parts::parquet_ranges::build(&path).unwrap();
        let footer = ranges.iter().find(|range| range.column.is_none()).unwrap();
        let footer_path = dir.path().join("footer");
        std::fs::write(&footer_path, &body[footer.offset as usize..]).unwrap();
        let chunks = ranges.iter().filter(|range| range.column.is_some()).map(|range| {
            let chunk = dir.path().join(format!("chunk-{}", range.offset));
            std::fs::write(&chunk, &body[range.offset as usize..(range.offset + range.bytes) as usize]).unwrap();
            (range.offset, range.bytes, chunk)
        }).collect::<Vec<_>>();
        // A cache only a few sparse files large.
        let source = dir.path().join("source");
        let store_objects = Arc::new(LocalObjectStore::new(&source).unwrap());
        let capacity = body.len() as u64 * 3;
        let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
            root: dir.path().join("cache"), max_bytes: capacity, query_max_bytes: capacity,
            fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(5),
        }, TENANT, "bucket", &parts_key_prefix(TENANT).unwrap(),
            Arc::new(StoreObjectSource::local("bucket", store_objects.clone(), source.clone()))).unwrap();
        let sparse = SparseStore::open(&dir.path().join("ranged"), capacity).unwrap();
        for i in 0..32 {
            let (file, reservation) = sparse.build(&cache, &format!("{i}:k"), body.len() as u64, footer.offset, footer.bytes,
                &footer.sha256, &footer_path, &chunks).unwrap();
            drop((file, reservation));
        }
        assert!(sparse.cached_bytes() <= capacity / SPARSE_MEMO_FRACTION, "the memo is byte-capped: {}", sparse.cached_bytes());
        // A whole-object admission of two thirds of capacity still fits.
        let key = "lake/parts/v1/whole.bin";
        let object = vec![7_u8; (capacity * 2 / 3) as usize];
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            store_objects.put(&format!("{}/{key}", parts_key_prefix(TENANT).unwrap()), &object).await.unwrap();
            let whole = crate::reader_object_cache::ReaderObjectRef { range: None,
                source_uri: format!("s3://bucket/{}/{key}", parts_key_prefix(TENANT).unwrap()),
                sha256: sha256_hex(&object), size_bytes: object.len() as u64 };
            cache.ensure_local(&[whole]).await.expect("memoized sparse files hold no capacity");
        });
    }

    #[tokio::test]
    async fn a_failed_lease_refunds_its_cold_budget() {
        let fixture = Fixture::new();
        let whole_bytes = fixture.body.len() as u64;
        let budget = crate::reader_object_cache::ColdBudget::new(whole_bytes);
        // A transient failure (the object is not in the store).
        let missing = crate::reader_object_cache::ReaderObjectRef { range: None,
            source_uri: format!("s3://bucket/{}/missing.bin", parts_key_prefix(TENANT).unwrap()),
            sha256: "e".repeat(64), size_bytes: whole_bytes };
        assert!(fixture.fetcher.cache().ensure_local_within(&[missing], &budget).await.is_err());
        assert_eq!(budget.spent(), 0, "a failed lease is refunded");
        // The whole-file fallback still fits the same budget.
        let part = fixture.part("1790330400123-9f86d081884c7d65", Some(&fixture.ranges)).await;
        let local = fixture.fetcher.ensure_files_within(&[(part, PartFile::Data(0))], Some(&budget)).await.unwrap();
        assert_eq!(budget.spent(), whole_bytes);
        drop(local);
    }
}
