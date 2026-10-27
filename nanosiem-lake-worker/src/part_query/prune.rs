// SPDX-License-Identifier: AGPL-3.0-or-later

//! Row-group pruning over parts (contract 3.1 token index, section 2 blooms).
//!
//! Every function here is a candidate filter: it may keep a row group that
//! holds no match, never drop one that does. The compiler-owned predicate is
//! always re-evaluated over the surviving rows, so pruning changes cost,
//! never results. Unknown (missing index, corrupt bytes, unsupported hint,
//! over-long token, too many case spellings) always means "keep".
//!
//! Hint semantics match the reader (`tail_predicate`, `text_sidecar`): the
//! top-level hints are AND-ed, `Any` is an OR over its alternatives,
//! `Entity` is an equality on an identity path, and `Keyword` with mode
//! `token` requires every query token. `contains`/`regex_guard` keywords are
//! substring guards the token index cannot decide, so they keep everything.

use parquet::bloom_filter::Sbbf;
use parquet::file::reader::FileReader;
use parquet::file::serialized_reader::SerializedFileReader;
use parquet::file::statistics::Statistics;
use std::fs::File;
use std::path::Path;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::planner::CandidateHint;
use crate::parts::sidecar::{decode_leased_token_index, decode_token_index, TokenGroup, TOKEN_MAX_BYTES};

/// Per-row-group keep mask. `None` = no information (keep every group).
pub type Mask = Option<Vec<bool>>;

/// Retain a bounded number of opened, verified Parquet footers (for bloom
/// reads) and a much larger number of compact footer summaries (row ranges
/// and per-group event-time bounds). The key is the signed content digest,
/// shared across verified immutable lease paths. Different content cannot
/// inherit metadata from its predecessor.
///
/// NAN-3077: the summary is all a keyword, source-family or time-membership
/// selection needs. Before it, every selection held the full parsed footer
/// of every file, 256 at most, and a selection over more than 256 files
/// (a ~26 h window at 300 eps) re-read and re-parsed every wide OCSF footer
/// on every query, the likely cause of the measured ~26 h 3 s -> 15 s cliff
/// (~20 ms per 401-column footer in a debug build). A 24 h query plus its histogram
/// companion also thrashed the shared 256. Summaries are a few hundred bytes
/// and hold no descriptor, so a week of files stays resident.
#[derive(Default)]
pub struct FileMetadataCache {
    entries: Mutex<VecDeque<(MetadataKey, Arc<OpenedFile>)>>,
    summaries: Mutex<SummaryCache>,
    blooms: Mutex<ParsedBloomCache>,
}

// Callers supply signed-digest verified immutable leases. Link-count changes
// and a verified re-fetch of identical bytes must not invalidate a footer.
type MetadataKey = String;

fn metadata_key(path: &Path, digest: &str) -> Option<MetadataKey> {
    std::fs::metadata(path).ok()?;
    Some(digest.to_owned())
}

struct OpenedFile {
    reader: SerializedFileReader<File>,
    summary: Arc<FileSummary>,
}

/// What selection needs from a data file's footer when no bloom is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSummary {
    /// `[start, end)` rows of every row group.
    pub ranges: Vec<(u64, u64)>,
    /// Exact `[min, max]` event time (µs) per row group (`None` where the
    /// statistics are missing or inexact); `None` without a time column.
    pub group_times: Option<Vec<Option<(i64, i64)>>>,
    /// NAN-3077: per bloom path present in the file (flat columns only), each
    /// row group's statistics and bloom location, so entity (host, IP, user,
    /// process, uid) evidence needs no opened footer.
    pub entities: Vec<(Box<str>, Vec<EntityGroup>)>,
    /// False when some bloom has an offset but no recorded length: that file
    /// answers entity evidence from its opened footer, as before.
    pub entities_located: bool,
    /// NAN-3155: compressed bytes of every leaf column chunk, per row group,
    /// keyed by its dotted event path (list wrapper levels dropped), so a
    /// statement's scan estimate counts the leaves and row groups it reads.
    pub column_bytes: ColumnBytes,
    /// NAN-3221: each row group's exact `metadata.log_source` statistics
    /// (empty without that flat column), so a source-family hint prunes
    /// files whose family is not signed (L0/M parts) by their value range.
    pub source_family: Vec<EntityGroup>,
    /// NAN-4664: the file carries the derived IOC indicator columns (its
    /// footer marker names the current derivation). Their per-group
    /// statistics and blooms are in `entities` under the column names.
    pub indicators: bool,
}

/// NAN-4171: a file's leaf inventory and per-group compressed bytes. The
/// dotted leaf paths are interned: every file written with the same schema
/// shares one path list, and the file keeps only its flat byte counts
/// (column-major, `paths.len() * groups` entries). Before it each summary
/// owned ~401 path strings (~30 KiB per wide OCSF file), so a 7d window of
/// ~2,234 files (~67 MiB) overran the 64 MiB summary bound and every 7d
/// entity hunt re-parsed every footer (9-17 s `footer_read`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ColumnBytes {
    paths: Option<Arc<[Box<str>]>>,
    bytes: Box<[u32]>,
}

/// Interned path lists, keyed by content hash. Held weakly: a list lives as
/// long as some summary references it. Distinct schemas are few (one per
/// schema revision), so the table stays small; dead entries are swept when
/// it grows.
static INTERNED_PATHS: std::sync::LazyLock<Mutex<std::collections::HashMap<u64, Vec<std::sync::Weak<[Box<str>]>>>>> =
    std::sync::LazyLock::new(Default::default);
const INTERNED_SWEEP_AT: usize = 256;

fn intern_paths(paths: Vec<Box<str>>) -> Arc<[Box<str>]> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    paths.hash(&mut hasher);
    let key = hasher.finish();
    let Ok(mut table) = INTERNED_PATHS.lock() else { return paths.into() };
    if let Some(found) = table.get(&key).into_iter().flatten().filter_map(std::sync::Weak::upgrade).find(|list| **list == *paths) {
        return found;
    }
    if table.len() >= INTERNED_SWEEP_AT {
        table.retain(|_, lists| {
            lists.retain(|list| list.strong_count() > 0);
            !lists.is_empty()
        });
    }
    let list: Arc<[Box<str>]> = paths.into();
    table.entry(key).or_default().push(Arc::downgrade(&list));
    list
}

impl ColumnBytes {
    /// `(leaf path, bytes per row group)` pairs; every pair must have the
    /// same number of groups (a ragged inventory is dropped: no evidence).
    pub fn new(columns: Vec<(Box<str>, Box<[u32]>)>) -> Self {
        let Some(groups) = columns.first().map(|(_, bytes)| bytes.len()) else { return Self::default() };
        if columns.iter().any(|(_, bytes)| bytes.len() != groups) {
            return Self::default();
        }
        let mut flat = Vec::with_capacity(columns.len() * groups);
        let mut paths = Vec::with_capacity(columns.len());
        for (path, bytes) in columns {
            paths.push(path);
            flat.extend_from_slice(&bytes);
        }
        Self { paths: Some(intern_paths(paths)), bytes: flat.into() }
    }

    pub fn is_empty(&self) -> bool {
        self.paths.as_ref().is_none_or(|paths| paths.is_empty())
    }

    fn paths(&self) -> &[Box<str>] {
        self.paths.as_deref().unwrap_or(&[])
    }

    /// `(leaf path, bytes per row group)`.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u32])> {
        let paths = self.paths();
        let groups = if paths.is_empty() { 0 } else { self.bytes.len() / paths.len() };
        paths.iter().enumerate().map(move |(i, path)| (&**path, &self.bytes[i * groups..(i + 1) * groups]))
    }

    /// Resident bytes owned by this file; the shared path list is charged
    /// once per distinct list by [`SummaryCache`] (see [`Self::shared`]).
    fn owned_bytes(&self) -> usize {
        40 + self.bytes.len() * 4
    }

    /// `(identity, resident bytes)` of the shared path list.
    fn shared(&self) -> Option<(usize, usize)> {
        let paths = self.paths.as_ref()?;
        let bytes = 32 + paths.iter().map(|path| path.len() + 16).sum::<usize>();
        Some((Arc::as_ptr(paths) as *const Box<str> as usize, bytes))
    }
}

/// One row group of one bloom path: exact statistics (kept when short) and
/// where its bloom lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityGroup {
    min: Option<Box<[u8]>>,
    max: Option<Box<[u8]>>,
    bloom: BloomAt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BloomAt {
    Absent,
    /// `(offset, length)` of the serialized filter (header + bitset).
    At(u64, usize),
    /// An offset without a recorded length (header must be parsed in place).
    Unlocated,
}

/// Statistics longer than this are not kept (a range check on them is
/// only an optimization; missing statistics mean "keep").
const ENTITY_STAT_MAX_BYTES: usize = 128;

impl EntityGroup {
    fn of(column: &parquet::file::metadata::ColumnChunkMetaData) -> Self {
        let (min, max) = match column.statistics() {
            Some(Statistics::ByteArray(stats)) if stats.min_is_exact() && stats.max_is_exact() => {
                let keep = |value: Option<&parquet::data_type::ByteArray>| {
                    value.map(|v| v.data()).filter(|v| v.len() <= ENTITY_STAT_MAX_BYTES).map(Box::<[u8]>::from)
                };
                (keep(stats.min_opt()), keep(stats.max_opt()))
            }
            _ => (None, None),
        };
        let bloom = match (column.bloom_filter_offset(), column.bloom_filter_length()) {
            (None, _) => BloomAt::Absent,
            (Some(offset), Some(length)) => match (u64::try_from(offset), usize::try_from(length)) {
                (Ok(offset), Ok(length)) => BloomAt::At(offset, length),
                _ => BloomAt::Unlocated,
            },
            (Some(_), None) => BloomAt::Unlocated,
        };
        Self { min, max, bloom }
    }

    fn bytes(&self) -> usize {
        48 + self.min.as_ref().map_or(0, |v| v.len()) + self.max.as_ref().map_or(0, |v| v.len())
    }
}

impl FileSummary {
    fn of(reader: &SerializedFileReader<File>) -> Option<Self> {
        let metadata = reader.metadata();
        let mut start = 0_u64;
        let mut ranges = Vec::with_capacity(metadata.num_row_groups());
        for group in metadata.row_groups() {
            let rows = u64::try_from(group.num_rows()).ok()?;
            let end = start.checked_add(rows)?;
            ranges.push((start, end));
            start = end;
        }
        let time_index = metadata
            .file_metadata()
            .schema_descr()
            .columns()
            .iter()
            .position(|column| column.path().string() == crate::parts::format::TIME_COLUMN);
        let group_times = time_index.map(|index| {
            metadata
                .row_groups()
                .iter()
                .map(|group| match group.column(index).statistics() {
                    Some(Statistics::Int64(stats)) if stats.min_is_exact() && stats.max_is_exact() => {
                        Some((*stats.min_opt()?, *stats.max_opt()?))
                    }
                    _ => None,
                })
                .collect()
        });
        let mut entities = Vec::new();
        let mut entities_located = true;
        let indicators = has_indicator_marker(metadata.file_metadata());
        for (index, column) in metadata.file_metadata().schema_descr().columns().iter().enumerate() {
            let mut path = column.path().string();
            if indicators && column.max_rep_level() == 1 {
                if let Some(kind) = indicator_leaf_kind(column.path().parts()) {
                    path = kind.column().to_string();
                    let groups = metadata.row_groups().iter().map(|group| EntityGroup::of(group.column(index))).collect::<Vec<_>>();
                    entities_located &= groups.iter().all(|group| group.bloom != BloomAt::Unlocated);
                    entities.push((path.into_boxed_str(), groups));
                    continue;
                }
            }
            if column.max_rep_level() != 0 || !crate::parts::format::BLOOM_PATHS.contains(&path.as_str()) {
                continue;
            }
            let groups = metadata.row_groups().iter().map(|group| EntityGroup::of(group.column(index))).collect::<Vec<_>>();
            entities_located &= groups.iter().all(|group| group.bloom != BloomAt::Unlocated);
            entities.push((path.into_boxed_str(), groups));
        }
        let source_family = metadata.file_metadata().schema_descr().columns().iter()
            .position(|column| column.max_rep_level() == 0 && column.path().string() == SOURCE_FAMILY_PATH)
            .map(|index| metadata.row_groups().iter().map(|group| EntityGroup::of(group.column(index))).collect())
            .unwrap_or_default();
        let column_bytes = metadata.file_metadata().schema_descr().columns().iter().enumerate()
            .map(|(index, column)| {
                let bytes = metadata.row_groups().iter()
                    .map(|group| u32::try_from(group.column(index).compressed_size()).unwrap_or(u32::MAX))
                    .collect::<Box<[u32]>>();
                (leaf_event_path(column.path().parts()).into_boxed_str(), bytes)
            })
            .collect();
        let column_bytes = ColumnBytes::new(column_bytes);
        Some(Self { ranges, group_times, entities, entities_located, column_bytes, source_family, indicators })
    }

    /// Compressed bytes per event leaf over the row groups `kept` (every
    /// group when `None` or when the mask does not fit the file).
    pub fn leaf_bytes(&self, kept: Option<&[bool]>) -> BTreeMap<String, u64> {
        let kept = kept.filter(|mask| mask.len() == self.ranges.len());
        let mut out = BTreeMap::<String, u64>::new();
        for (path, groups) in self.column_bytes.iter() {
            let bytes = groups.iter().enumerate()
                .filter(|(group, _)| kept.is_none_or(|mask| mask[*group]))
                .map(|(_, bytes)| u64::from(*bytes))
                .sum::<u64>();
            *out.entry(path.to_string()).or_default() += bytes;
        }
        out
    }

    /// NAN-3159: [`Self::leaf_bytes`] over `kept`, plus the whole-file
    /// charge when `kept` actually drops a group (`None` otherwise: the two
    /// are equal).
    pub fn kept_and_whole_leaf_bytes(&self, kept: Option<&[bool]>) -> (BTreeMap<String, u64>, Option<BTreeMap<String, u64>>) {
        let drops = kept.is_some_and(|mask| mask.len() == self.ranges.len() && mask.contains(&false));
        (self.leaf_bytes(kept), drops.then(|| self.leaf_bytes(None)))
    }

    /// Approximate resident bytes owned by this summary (for the caches'
    /// byte bounds); the shared column path list is not included.
    fn bytes(&self) -> usize {
        96 + self.ranges.len() * 16
            + self.group_times.as_ref().map_or(0, |times| times.len() * 24)
            + self.entities.iter().map(|(path, groups)| path.len() + 24 + groups.iter().map(EntityGroup::bytes).sum::<usize>()).sum::<usize>()
            + self.column_bytes.owned_bytes()
            + self.source_family.iter().map(EntityGroup::bytes).sum::<usize>()
    }

    /// NAN-3221: per row group, whether its exact `metadata.log_source`
    /// range can hold a value every source-family hint accepts; `None` when
    /// no hint names a family (or the file has no such column).
    fn source_family_mask(&self, hints: &[CandidateHint]) -> Mask {
        if !uses_source_family(hints) || self.source_family.len() != self.ranges.len() {
            return None;
        }
        Some(self.source_family.iter().map(|group| hints.iter().all(|hint| family_range_hint(group, hint))).collect())
    }

    fn entity(&self, path: &str) -> Option<&[EntityGroup]> {
        self.entities.iter().find(|(name, _)| &**name == path).map(|(_, groups)| groups.as_slice())
    }

    /// NAN-3694: the file stores no leaf at, above or below `path`, so an
    /// equality on it cannot match (the reader fills a missing column with
    /// NULL). A summary without column inventory proves nothing.
    fn lacks_leaf(&self, path: &str) -> bool {
        !self.column_bytes.is_empty() && leaf_absent(self.column_bytes.iter().map(|(leaf, _)| leaf), path)
    }

    /// Row groups whose exact time bounds touch a membership bucket (groups
    /// without exact bounds are kept); `None` without a time column.
    fn time_mask(&self, buckets: &std::collections::BTreeSet<i64>) -> Mask {
        Some(
            self.group_times
                .as_ref()?
                .iter()
                .map(|bounds| bounds.is_none_or(|(min, max)| super::membership::Membership::touches(buckets, min, max)))
                .collect(),
        )
    }

    /// Exact bounds of every row group; `None` if any group lacks them.
    fn time_bounds(&self) -> Option<Vec<(i64, i64)>> {
        self.group_times.as_ref()?.iter().copied().collect()
    }
}

/// NAN-4664: the footer marks the current IOC indicator derivation.
fn has_indicator_marker(metadata: &parquet::file::metadata::FileMetaData) -> bool {
    crate::parts::indicators::is_marked(metadata)
}

/// The indicator kind of a `<column>.list.item` Parquet leaf.
fn indicator_leaf_kind(parts: &[String]) -> Option<nanosiem_core::search::lake_indicators::Kind> {
    use nanosiem_core::search::lake_indicators::Kind;
    match parts {
        [column, list, item] if list == "list" && item == "item" => Kind::of_column(column),
        _ => None,
    }
}

/// NAN-3694: no stored leaf (list wrappers dropped) is `path`, an ancestor
/// of it, or below it. A tenant with no `device.ip` anywhere used to keep
/// every row group for a `device.ip` pivot leg, and since an OR prunes only
/// when each leg can, the whole IP pivot read every file. An ancestor or
/// descendant leaf (a scalar `device`, a repeated or nested form) is never
/// taken as absence.
fn leaf_absent<'a>(mut leaves: impl Iterator<Item = &'a str>, path: &str) -> bool {
    !leaves.any(|leaf| {
        leaf == path
            || path.strip_prefix(leaf).is_some_and(|rest| rest.starts_with('.'))
            || leaf.strip_prefix(path).is_some_and(|rest| rest.starts_with('.'))
    })
}

/// The dotted event path of a Parquet leaf column: the LIST wrapper levels
/// (`<name>.list.element`, `<name>.list.item`) are dropped, so
/// `process.file.hashes.list.element.value` is `process.file.hashes.value`.
pub fn leaf_event_path(parts: &[String]) -> String {
    let mut out: Vec<&str> = Vec::with_capacity(parts.len());
    let mut skip_next = false;
    for part in parts {
        if skip_next { skip_next = false; continue; }
        if part == "list" { skip_next = true; continue; }
        out.push(part);
    }
    out.join(".")
}

/// A live hour of L0/M parts is ~55 data files at 300 eps and a day ~65+
/// after merges, so 32 footers thrashed: every select re-opened and
/// re-parsed every wide OCSF footer (NAN-2996). Each entry holds one fd.
/// Only bloom (entity) evidence needs an opened footer (NAN-3077).
pub const MAX_OPEN_FOOTERS: usize = 256;
/// Bound parsed open footers independently of the compact summaries.
pub const MAX_OPEN_FOOTER_BYTES: usize = 64 * 1024 * 1024;

/// Compact footer summaries kept (NAN-3077): ~2 weeks of files at 300 eps,
/// no descriptors.
pub const MAX_FILE_SUMMARIES: usize = 16_384;
/// ...and at most this many resident bytes (identity statistics included;
/// a wide OCSF file is ~7 KiB once its column path list is shared,
/// NAN-4171, so a week of ~2,234 files is ~16 MiB).
pub const MAX_SUMMARY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
struct SummaryCache {
    map: std::collections::HashMap<MetadataKey, (u64, Arc<FileSummary>)>,
    tick: u64,
    bytes: usize,
    /// NAN-4171: resident shared column path lists, `identity -> (summaries
    /// referencing it, bytes)`, each charged to `bytes` once.
    shared: std::collections::HashMap<usize, (usize, usize)>,
}

impl SummaryCache {
    /// Resident bytes `summary` adds: its own, plus its path list when no
    /// resident summary shares it yet.
    fn charge(&mut self, summary: &FileSummary) {
        self.bytes = self.bytes.saturating_add(summary.bytes());
        if let Some((identity, bytes)) = summary.column_bytes.shared() {
            let entry = self.shared.entry(identity).or_insert((0, bytes));
            if entry.0 == 0 { self.bytes = self.bytes.saturating_add(bytes); }
            entry.0 += 1;
        }
    }

    fn discharge(&mut self, summary: &FileSummary) {
        self.bytes = self.bytes.saturating_sub(summary.bytes());
        if let Some((identity, _)) = summary.column_bytes.shared() {
            if let Some(entry) = self.shared.get_mut(&identity) {
                entry.0 -= 1;
                if entry.0 == 0 {
                    self.bytes = self.bytes.saturating_sub(entry.1);
                    self.shared.remove(&identity);
                }
            }
        }
    }

    /// What `summary` would add if inserted now.
    fn cost(&self, summary: &FileSummary) -> usize {
        summary.bytes() + summary.column_bytes.shared()
            .filter(|(identity, _)| !self.shared.contains_key(identity))
            .map_or(0, |(_, bytes)| bytes)
    }

    fn get(&mut self, key: &MetadataKey) -> Option<Arc<FileSummary>> {
        self.tick += 1;
        let tick = self.tick;
        self.map.get_mut(key).map(|(used, summary)| {
            *used = tick;
            summary.clone()
        })
    }

    fn insert(&mut self, key: MetadataKey, summary: Arc<FileSummary>) {
        self.tick += 1;
        if let Some((_, previous)) = self.map.remove(&key) {
            self.discharge(&previous);
        }
        if self.cost(&summary) > MAX_SUMMARY_BYTES { return; }
        while (self.map.len() >= MAX_FILE_SUMMARIES || self.bytes.saturating_add(self.cost(&summary)) > MAX_SUMMARY_BYTES)
            && !self.map.is_empty()
        {
            // Evict the least recently used eighth at once, so a sweep over
            // more files than fit costs one scan per 2k inserts, not per insert.
            let mut ages = self.map.values().map(|(used, _)| *used).collect::<Vec<_>>();
            let cut = ages.len() / 8;
            let (_, threshold, _) = ages.select_nth_unstable(cut);
            let threshold = *threshold;
            self.map.retain(|_, (used, _)| *used > threshold);
            self.bytes = 0;
            self.shared.clear();
            let resident = self.map.values().map(|(_, summary)| summary.clone()).collect::<Vec<_>>();
            for summary in resident { self.charge(&summary); }
        }
        self.charge(&summary);
        if let Some((_, previous)) = self.map.insert(key, (self.tick, summary)) {
            self.discharge(&previous);
        }
    }
}

/// Measured tenant-a blooms average about 36 KiB per row group (20.6 MiB across
/// 586 row groups); its seven-day window of about 3,804 groups needs roughly
/// 134 MiB before accounting overhead. 320 MiB leaves headroom at 10.5% of
/// the 3,044 MiB query reservation and 4.6% of the 6,884 MiB cap. No file
/// readers or descriptors are retained; summaries have a separate 64 MiB bound.
pub const MAX_PARSED_BLOOM_BYTES: usize = 320 * 1024 * 1024;

struct ParsedBlooms {
    fields: Vec<(Box<str>, Vec<Option<Arc<Sbbf>>>)>,
    bytes: usize,
}

/// LRU over signed digests. NAN-4171: keyed (was a `VecDeque` scanned per
/// file and hint, O(files^2) string compares on a 7d hunt).
#[derive(Default)]
struct ParsedBloomCache {
    entries: std::collections::HashMap<String, (u64, Arc<ParsedBlooms>)>,
    /// Use tick -> digest, oldest first.
    order: BTreeMap<u64, String>,
    tick: u64,
    bytes: usize,
}

fn parsed_bloom_bytes(digest: &str, value: &ParsedBlooms) -> usize {
    value.bytes.saturating_add(digest.len()).saturating_add(96)
}

impl ParsedBloomCache {
    fn touch(&mut self, digest: &str) -> Option<Arc<ParsedBlooms>> {
        self.tick += 1;
        let tick = self.tick;
        let (used, value) = self.entries.get_mut(digest)?;
        let previous = std::mem::replace(used, tick);
        let value = value.clone();
        if let Some(key) = self.order.remove(&previous) { self.order.insert(tick, key); }
        Some(value)
    }

    fn get(&mut self, digest: &str) -> Option<Arc<ParsedBlooms>> {
        self.touch(digest)
    }

    fn contains(&self, digest: &str) -> bool {
        self.entries.contains_key(digest)
    }

    fn resident_bytes(&self, digest: &str) -> Option<usize> {
        self.entries.get(digest).map(|(_, value)| parsed_bloom_bytes(digest, value))
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn insert(&mut self, digest: String, value: Arc<ParsedBlooms>, limit: usize) -> bool {
        let bytes = parsed_bloom_bytes(&digest, &value);
        if bytes > limit { return false; }
        if self.touch(&digest).is_some() { return true; }
        while self.bytes.saturating_add(bytes) > limit {
            let Some((_, key)) = self.order.pop_first() else { break };
            if let Some((_, old)) = self.entries.remove(&key) {
                self.bytes = self.bytes.saturating_sub(parsed_bloom_bytes(&key, &old));
            }
        }
        self.tick += 1;
        self.bytes += bytes;
        self.order.insert(self.tick, digest.clone());
        self.entries.insert(digest, (self.tick, value));
        true
    }

    fn retain(&mut self, live: &std::collections::HashSet<&str>) {
        self.entries.retain(|digest, _| live.contains(digest.as_str()));
        let entries = &self.entries;
        self.order.retain(|_, digest| entries.contains_key(digest));
        self.bytes = self.entries.iter().map(|(digest, (_, value))| parsed_bloom_bytes(digest, value)).sum();
    }

    /// Re-rank so the newest digests are evicted last (unranked first).
    fn order_oldest_first(&mut self, newest_first: &[&str]) {
        let rank = newest_first.iter().enumerate().map(|(i, digest)| (*digest, i)).collect::<std::collections::HashMap<_, _>>();
        let mut digests = self.entries.keys().cloned().collect::<Vec<_>>();
        digests.sort_by_key(|digest| std::cmp::Reverse(rank.get(digest.as_str()).copied().unwrap_or(usize::MAX)));
        self.order.clear();
        for digest in digests {
            self.tick += 1;
            if let Some((used, _)) = self.entries.get_mut(&digest) { *used = self.tick; }
            self.order.insert(self.tick, digest);
        }
    }
}

impl FileMetadataCache {
    pub fn summary_stats(&self) -> (usize, usize) {
        self.summaries.lock().map(|cache| (cache.map.len(), cache.bytes)).unwrap_or_default()
    }

    pub fn bloom_stats(&self) -> (usize, usize) {
        self.blooms.lock().map(|cache| (cache.len(), cache.bytes)).unwrap_or_default()
    }

    pub fn has_blooms(&self, digest: &str) -> bool {
        self.blooms.lock().map(|cache| cache.contains(digest)).unwrap_or(false)
    }

    pub fn retain_blooms(&self, live: &std::collections::HashSet<&str>) {
        if let Ok(mut cache) = self.blooms.lock() {
            cache.retain(live);
        }
    }

    /// Called only with a signed-digest verified full-file lease. Reads one
    /// file at a time outside cache locks. Malformed evidence stays unknown.
    pub fn prewarm(&self, path: &Path, digest: &str) -> bool {
        let mut remaining = MAX_PARSED_BLOOM_BYTES;
        self.prewarm_with_budget(path, digest, &mut remaining)
    }

    pub fn resident_bloom_bytes(&self, digest: &str) -> Option<usize> {
        self.blooms.lock().ok()?.resident_bytes(digest)
    }

    pub fn order_blooms_oldest_first(&self, newest_first: &[&str]) {
        if let Ok(mut cache) = self.blooms.lock() {
            cache.order_oldest_first(newest_first);
        }
    }

    pub fn prewarm_with_budget(&self, path: &Path, digest: &str, remaining: &mut usize) -> bool {
        if let Some(bytes) = self.resident_bloom_bytes(digest) {
            if bytes > *remaining { return false; }
            *remaining -= bytes;
            return true;
        }
        let Some(summary) = self.summary(path, digest) else { return false };
        if !summary.entities_located { return false; }
        let mut estimated = 64usize;
        for (path, groups) in &summary.entities {
            estimated = estimated.saturating_add(path.len() + 48 + groups.len() * 32);
            for group in groups {
                if let BloomAt::At(_, length) = group.bloom {
                    estimated = estimated.saturating_add(length).saturating_add(64);
                }
            }
        }
        if estimated.saturating_add(digest.len() + 96) > *remaining { return false; }
        let Ok(file) = File::open(path) else { return false };
        let mut bytes = 64usize;
        let fields = summary.entities.iter().map(|(path, groups)| {
            bytes = bytes.saturating_add(path.len() + 48 + groups.len() * 32);
            let blooms = groups.iter().map(|group| match group.bloom {
                BloomAt::At(offset, length) => {
                    bytes = bytes.saturating_add(length + 64);
                    read_bloom_at(&file, offset, length).map(Arc::new)
                }
                _ => None,
            }).collect();
            (path.clone(), blooms)
        }).collect();
        self.blooms.lock().map(|mut cache| {
            let size = bytes + digest.len() + 96;
            let inserted = cache.insert(digest.to_owned(), Arc::new(ParsedBlooms { fields, bytes }), MAX_PARSED_BLOOM_BYTES);
            if inserted { *remaining = remaining.saturating_sub(size); }
            inserted
        }).unwrap_or(false)
    }

    fn open(&self, path: &Path, sha256: &str) -> Option<Arc<OpenedFile>> {
        let key = metadata_key(path, sha256)?;
        {
            let mut entries = self.entries.lock().ok()?;
            if let Some(index) = entries.iter().position(|(cached, _)| cached == &key) {
                let entry = entries.remove(index)?;
                let opened = entry.1.clone();
                entries.push_back(entry);
                return Some(opened);
            }
        }
        let opened = Self::read(path).or_else(|| Self::read(path))?;
        self.remember(key.clone(), opened.summary.clone());
        let mut entries = self.entries.lock().ok()?;
        if let Some((_, existing)) = entries.iter().find(|(cached, _)| cached == &key) {
            return Some(existing.clone());
        }
        let size = opened.reader.metadata().memory_size() + opened.summary.bytes();
        if size > MAX_OPEN_FOOTER_BYTES { return Some(opened); }
        let mut bytes = entries.iter().map(|(_, value)| value.reader.metadata().memory_size() + value.summary.bytes()).sum::<usize>();
        while entries.len() >= MAX_OPEN_FOOTERS || bytes.saturating_add(size) > MAX_OPEN_FOOTER_BYTES {
            let (_, old) = entries.pop_front()?;
            bytes = bytes.saturating_sub(old.reader.metadata().memory_size() + old.summary.bytes());
        }
        entries.push_back((key, opened.clone()));
        Some(opened)
    }

    fn read(path: &Path) -> Option<Arc<OpenedFile>> {
        let _timer = crate::query_timing::timer(crate::query_timing::Phase::FooterRead);
        let reader = SerializedFileReader::new(File::open(path).ok()?).ok()?;
        let summary = Arc::new(FileSummary::of(&reader)?);
        Some(Arc::new(OpenedFile { reader, summary }))
    }

    fn remember(&self, key: MetadataKey, summary: Arc<FileSummary>) {
        if let Ok(mut summaries) = self.summaries.lock() {
            summaries.insert(key, summary);
        }
    }

    /// The file's footer summary, parsing the footer only on a miss.
    pub fn summary(&self, path: &Path, sha256: &str) -> Option<Arc<FileSummary>> {
        let key = metadata_key(path, sha256)?;
        if let Some(summary) = self.summaries.lock().ok()?.get(&key) {
            return Some(summary);
        }
        let opened = Self::read(path).or_else(|| Self::read(path))?;
        let summary = opened.summary.clone();
        self.remember(key, summary.clone());
        Some(summary)
    }

    /// Footer summaries resident (for tests and evidence).
    pub fn summaries(&self) -> usize {
        self.summaries.lock().map(|summaries| summaries.map.len()).unwrap_or(0)
    }

    pub fn evidence(
        &self, path: &Path, sha256: &str, hints: &[CandidateHint],
        index_bytes: Option<&[u8]>, combined: bool, cache_footer: bool,
        buckets: Option<&std::collections::BTreeSet<i64>>,
    ) -> Option<(Mask, Mask, Vec<(u64, u64)>, Option<Vec<(i64, i64)>>)> {
        let tokens = if combined { index_bytes.and_then(|bytes| decode_leased_token_index(bytes).ok()) } else { None };
        self.evidence_of_tokens(path, sha256, hints, tokens.as_deref(), combined, cache_footer, buckets)
    }

    pub fn evidence_of_tokens(
        &self, path: &Path, sha256: &str, hints: &[CandidateHint],
        tokens: Option<&[TokenGroup]>, combined: bool, cache_footer: bool,
        buckets: Option<&std::collections::BTreeSet<i64>>,
    ) -> Option<(Mask, Mask, Vec<(u64, u64)>, Option<Vec<(i64, i64)>>)> {
        // NAN-3077: every piece of evidence, bloom reads included, comes from
        // the compact summary; only a file whose blooms lack a recorded
        // length is answered from its opened footer, as before.
        let blooms = uses_entities(hints);
        let summary = self.summary(path, sha256)?;
        let mut parsed = if blooms { self.blooms.lock().ok()?.get(sha256) } else { None };
        // NAN-4171 (review F8): a bloom read at query time is kept. Before,
        // only the background prewarm filled the parsed cache, and a file it
        // had not reached re-read and re-parsed its blooms on every hunt.
        if blooms && parsed.is_none() && summary.entities_located
            && summary.entities.iter().any(|(_, groups)| groups.iter().any(|group| matches!(group.bloom, BloomAt::At(..))))
            && self.prewarm(path, sha256)
        {
            parsed = self.blooms.lock().ok()?.get(sha256);
        }
        let opened = match (blooms && parsed.is_none() && !summary.entities_located, cache_footer) {
            (false, _) => None,
            (true, true) => Some(self.open(path, sha256)?),
            (true, false) => Some(Self::read(path)?),
        };
        // Bloom reads use an independent descriptor: concurrent queries must
        // not share a seek cursor.
        let file = if blooms && parsed.is_none() { Some(File::open(path).ok()?) } else { None };
        let evidence = match (&parsed, &opened, &file) {
            (Some(parsed), _, _) => Some(Blooms::Parsed(&summary, parsed)),
            (_, Some(opened), Some(file)) => Some(Blooms::Footer(&opened.reader, file)),
            (_, None, Some(file)) => Some(Blooms::Summary(&summary, file)),
            _ => None,
        };
        let groups = summary.ranges.len();
        let hint_mask = if combined && (blooms || uses_tokens(hints)) {
            // Tokens come from a leased, signed-digest verified token file.
            let tokens = tokens.filter(|tokens| tokens.len() == groups);
            Some((0..groups).map(|group| hints.iter().all(|hint| {
                combined_hint(evidence, group, tokens.map(|tokens| &tokens[group]), hint)
            })).collect())
        } else if let Some(evidence) = evidence {
            Some((0..groups).map(|group| hints.iter().all(|hint| entity_hint(evidence, group, hint))).collect())
        } else { None };
        let hint_mask = and(hint_mask, summary.source_family_mask(hints));
        let time_mask = buckets.and_then(|buckets| summary.time_mask(buckets));
        Some((hint_mask, time_mask, summary.ranges.clone(), summary.time_bounds()))
    }
}

fn is_hash_array(path: &str) -> bool {
    matches!(path, "file.hashes.value" | "process.file.hashes.value" | "actor.process.file.hashes.value")
}

/// A signed file family is the exact set of source values in that file. An
/// ASCII case-insensitive equality cannot match a file when none of its
/// ASCII labels match. Legacy/overflow or non-ASCII labels scan: Unicode
/// case folding is wider than ASCII folding.
pub fn source_family_may_match(
    log_sources: Option<&[String]>,
    hints: &[CandidateHint],
) -> bool {
    let Some(log_sources) = log_sources else { return true };
    hints.iter().all(|hint| source_family_hint(log_sources, hint))
}

fn source_family_hint(log_sources: &[String], hint: &CandidateHint) -> bool {
    match hint {
        CandidateHint::SourceFamily { value } => {
            if !value.is_ascii() || log_sources.iter().any(|source| !source.is_ascii()) { return true; }
            log_sources.iter().any(|source| source.eq_ignore_ascii_case(value))
        }
        CandidateHint::Any { alternatives } => {
            alternatives.is_empty()
                || alternatives.iter().any(|alternative| source_family_hint(log_sources, alternative))
        }
        _ => true,
    }
}

/// The flat column a source-family hint compares (`lower(col) = v`).
pub const SOURCE_FAMILY_PATH: &str = "metadata.log_source";

fn uses_source_family(hints: &[CandidateHint]) -> bool {
    hints.iter().any(|hint| match hint {
        CandidateHint::SourceFamily { .. } => true,
        CandidateHint::Any { alternatives } => uses_source_family(alternatives),
        _ => false,
    })
}

/// NAN-3221: can a row group whose exact `metadata.log_source` statistics
/// are `[min, max]` hold a value equal to `value` under ASCII case folding?
///
/// Exactly when some ASCII case spelling of `value` lies in `[min, max]`
/// bytewise (ClickHouse `lower` folds ASCII only, so a non-ASCII byte never
/// folds to an ASCII one, and every match is such a spelling). Missing or
/// inexact statistics, and non-ASCII values, keep the group. Any other hint
/// keeps.
fn family_range_hint(group: &EntityGroup, hint: &CandidateHint) -> bool {
    match hint {
        CandidateHint::SourceFamily { value } => family_range_may_match(group, value),
        CandidateHint::Any { alternatives } => {
            alternatives.is_empty() || alternatives.iter().any(|alternative| family_range_hint(group, alternative))
        }
        _ => true,
    }
}

fn family_range_may_match(group: &EntityGroup, value: &str) -> bool {
    let (Some(min), Some(max)) = (&group.min, &group.max) else { return true };
    if !value.is_ascii() {
        return true;
    }
    spelling_in_range(value.as_bytes(), min, max)
}

/// Whether some ASCII case spelling `s` of `value` has `min <= s <= max`
/// (bytewise). Walks `value` once, tracking for each surviving spelling
/// prefix whether it still equals `min`'s prefix (`low`) and `max`'s
/// (`high`); a prefix strictly inside both bounds proves a spelling.
fn spelling_in_range(value: &[u8], min: &[u8], max: &[u8]) -> bool {
    // States `(low, high)`: the prefix equals min's / max's prefix so far.
    let mut states = vec![(true, true)];
    for (index, byte) in value.iter().enumerate() {
        let mut choices = vec![byte.to_ascii_lowercase(), byte.to_ascii_uppercase()];
        choices.dedup();
        let mut next = Vec::with_capacity(4);
        for &(low, high) in &states {
            if !low && !high {
                return true;
            }
            for &choice in &choices {
                // Against min: a prefix equal to all of min is already >= min.
                let low = match (low, min.get(index)) {
                    (false, _) | (true, None) => Some(false),
                    (true, Some(bound)) if choice > *bound => Some(false),
                    (true, Some(bound)) if choice == *bound => Some(true),
                    _ => None,
                };
                // Against max: a prefix equal to all of max, extended, is > max.
                let high = match (high, max.get(index)) {
                    (false, _) => Some(false),
                    (true, None) => None,
                    (true, Some(bound)) if choice < *bound => Some(false),
                    (true, Some(bound)) if choice == *bound => Some(true),
                    _ => None,
                };
                if let (Some(low), Some(high)) = (low, high) {
                    if !next.contains(&(low, high)) {
                        next.push((low, high));
                    }
                }
            }
        }
        if next.is_empty() {
            return false;
        }
        states = next;
    }
    // The whole spelling: still equal to min's prefix means >= min only when
    // min is no longer; a max-prefix spelling is <= max.
    states.iter().any(|&(low, _)| !low || min.len() <= value.len())
}

/// NAN-3188: a dedicated source/class family file holds exactly one
/// `class_uid` (its signed `class_id`). A top-level-AND `class_uid = v` cannot
/// match a file whose class is another value. Legacy, overflow and
/// source-only files (`None`) always scan; the SQL still filters every row.
pub fn class_may_match(class_id: Option<i64>, hints: &[CandidateHint]) -> bool {
    let Some(class_id) = class_id else { return true };
    hints.iter().all(|hint| class_hint(class_id, hint))
}

fn class_hint(class_id: i64, hint: &CandidateHint) -> bool {
    match hint {
        CandidateHint::Class { value } => *value == class_id,
        CandidateHint::Any { alternatives } => {
            alternatives.is_empty() || alternatives.iter().any(|alternative| class_hint(class_id, alternative))
        }
        _ => true,
    }
}

/// The signed per-file family stage: source family and, for a source/class
/// family file, its class. Keep-on-unknown in both dimensions.
pub fn file_family_may_match(log_sources: Option<&[String]>, class_id: Option<i64>, hints: &[CandidateHint]) -> bool {
    source_family_may_match(log_sources, hints) && class_may_match(class_id, hints)
}

/// True when any hint can be decided by the token index.
pub fn uses_tokens(hints: &[CandidateHint]) -> bool {
    hints.iter().any(|hint| match hint {
        CandidateHint::Keyword { mode, value } => {
            required_tokens(mode, value).is_some_and(|tokens| !tokens.is_empty()) || !required_trigrams(mode, value).is_empty()
        }
        CandidateHint::Any { alternatives } => uses_tokens(alternatives),
        CandidateHint::Entity { source_path, .. } => is_hash_array(source_path),
        CandidateHint::SourceFamily { .. } | CandidateHint::Class { .. } => false,
    })
}

/// True when any hint can be decided by entity blooms/statistics.
pub fn uses_entities(hints: &[CandidateHint]) -> bool {
    hints.iter().any(|hint| match hint {
        CandidateHint::Entity { .. } => true,
        CandidateHint::SourceFamily { .. } | CandidateHint::Class { .. } => false,
        CandidateHint::Any { alternatives } => uses_entities(alternatives),
        CandidateHint::Keyword { .. } => false,
    })
}

/// Separate masks lose information only when an OR mixes evidence sources.
pub fn needs_combined(hints: &[CandidateHint]) -> bool {
    hints.iter().any(|hint| match hint {
        CandidateHint::Any { alternatives } =>
            (uses_tokens(alternatives) && uses_entities(alternatives)) || needs_combined(alternatives),
        _ => false,
    })
}

/// Progressive paging already consults these indexes on each chunk. Its
/// rollup-membership query would scan every partial before it can start the
/// same selective search. A hint is useful here only if every OR branch has
/// an index path; the SQL predicate still checks every surviving row.
///
/// A source family is NOT such a hint (NAN-2996): only Hour parts attest
/// per-file `log_sources`, so on the L0/M parts of the live hours every chunk
/// leased and opened every file (`metadata.log_source=audit` over 1 h: 59
/// files, ~2 s, zero rows). The rollup partial's field 0 is the log source,
/// so membership prunes those parts before any data file is fetched.
pub fn has_progressive_index_hint(hints: &[CandidateHint]) -> bool {
    hints.iter().any(progressive_index_hint)
}

fn progressive_index_hint(hint: &CandidateHint) -> bool {
    match hint {
        CandidateHint::Entity { .. } => true,
        CandidateHint::SourceFamily { .. } | CandidateHint::Class { .. } => false,
        CandidateHint::Keyword { mode, value } => {
            required_tokens(mode, value).is_some_and(|tokens| !tokens.is_empty()) || !required_trigrams(mode, value).is_empty()
        }
        CandidateHint::Any { alternatives } => !alternatives.is_empty()
            && alternatives.iter().all(progressive_index_hint),
    }
}

/// Tokens every matching row must hold, for a keyword hint of `mode`.
///
/// - `token` (`hasAllTokens(lower(col), v)`): every token of `v`.
/// - `token` carrying `*`/`?` (the SQL is a wildcard `iLike`, NAN-3032: the
///   old path required `svch` for `svch*` and pruned every `svchost` row),
///   `contains` and `regex_guard` (substring guards): only the
///   [`interior_tokens`] of `v`.
///
/// `None` or empty = undecidable (keep).
fn required_tokens(mode: &str, value: &str) -> Option<Vec<String>> {
    match mode {
        "token" if !value.contains(['*', '?']) => query_tokens(value),
        "token" | "contains" | "regex_guard" => Some(interior_tokens(value)),
        _ => None,
    }
}

/// NAN-4164: adjacent token pairs every matching row must hold, for a v5
/// pair bloom. Only a plain `token` needle (no `*`/`?`) qualifies: the lake
/// compiler matches it as a term, the needle's characters in order with an
/// ASCII non-alphanumeric (or edge) on each side, so in a matching value its
/// pieces are whole, adjacent [`crate::parts::sidecar::tokenize`] tokens.
/// Non-ASCII needles are left to the token bloom: RE2 case folding and
/// `to_lowercase` disagree on a few letters. Empty = no pair evidence.
fn required_pairs(mode: &str, value: &str) -> Vec<[u8; 8]> {
    if mode != "token" || value.contains(['*', '?']) || !value.is_ascii() {
        return Vec::new();
    }
    let mut pairs = Vec::new();
    crate::parts::sidecar::adjacent_pairs(value.trim(), |a, b| pairs.push(crate::parts::sidecar::pair_key(a, b)));
    pairs.sort_unstable();
    pairs.dedup();
    pairs
}

/// NAN-4217: the whole-address token every row matching a plain `token`
/// needle holds in a v6 index, when the needle is exactly one IP address
/// with two or more pieces (so the lake compiles it to the exact term
/// regex, see [`crate::parts::sidecar::address_tokens`]). `None` for
/// wildcards, other modes and anything else.
fn required_address(mode: &str, value: &str) -> Option<String> {
    if mode != "token" || value.contains(['*', '?']) {
        return None;
    }
    let address = crate::parts::sidecar::address_needle(value)?;
    let pieces = address.split(|c: char| !c.is_ascii_alphanumeric()).filter(|piece| !piece.is_empty()).count();
    (pieces >= 2).then_some(address)
}

/// Pieces of a substring needle that any containing text must hold as whole
/// tokens: runs of ASCII alphanumerics with an ASCII non-alphanumeric,
/// non-wildcard character on BOTH sides inside the needle. In the text those
/// neighbours are separators, so the run is a complete `nano_split_lower_v1`
/// token there. Edge runs (`dll32` in `*dll32*`), runs next to `*`/`?`
/// (which match anything, letters included) and runs with non-ASCII
/// characters (whose case folding differs between engines) are never
/// required. Sorted, deduplicated, lowercase.
pub fn interior_tokens(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    let boundary = |b: u8| b.is_ascii() && !b.is_ascii_alphanumeric() && b != b'*' && b != b'?';
    let separator = |b: u8| b.is_ascii() && !b.is_ascii_alphanumeric();
    let mut tokens = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if separator(bytes[start]) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && !separator(bytes[end]) {
            end += 1;
        }
        let piece = &value[start..end];
        if start > 0
            && end < bytes.len()
            && boundary(bytes[start - 1])
            && boundary(bytes[end])
            && piece.bytes().all(|b| b.is_ascii_alphanumeric())
            && piece.len() <= TOKEN_MAX_BYTES
        {
            tokens.push(piece.to_ascii_lowercase());
        }
        start = end;
    }
    tokens.sort();
    tokens.dedup();
    tokens
}

/// Query tokens under `nano_split_lower_v1`; `None` when a token cannot be
/// represented in the index (over 128 bytes), so the hint is undecidable.
fn query_tokens(value: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    for piece in value.trim().split(|c: char| !c.is_alphanumeric()) {
        if piece.is_empty() {
            continue;
        }
        let lower = piece.to_lowercase();
        if lower.len() > TOKEN_MAX_BYTES {
            return None;
        }
        tokens.push(lower);
    }
    tokens.sort();
    tokens.dedup();
    Some(tokens)
}

/// Keep mask from `tokens.nti`. `expected_groups` is the part's row-group
/// count from its signed record; a mismatching index is ignored.
pub fn token_mask(index_bytes: Option<&[u8]>, expected_groups: usize, hints: &[CandidateHint]) -> Mask {
    if !uses_tokens(hints) {
        return None;
    }
    let groups = decode_token_index(index_bytes?).ok()?;
    if groups.len() != expected_groups {
        return None;
    }
    let mut mask = vec![true; groups.len()];
    for hint in hints {
        for (keep, group) in mask.iter_mut().zip(&groups) {
            // An excluded group cannot be resurrected by another AND term.
            if *keep {
                *keep = token_hint(group, hint);
            }
        }
    }
    Some(mask)
}

fn required_trigrams(mode: &str, value: &str) -> Vec<[u8; 3]> {
    if !matches!(mode, "contains" | "regex_guard") && !(mode == "token" && value.contains(['*', '?'])) {
        return Vec::new();
    }
    let mut grams = Vec::new();
    crate::parts::sidecar::ascii_trigrams(value, |gram| grams.push(gram));
    grams.sort_unstable();
    grams.dedup();
    grams
}

/// The blooms of one token-index row group that token hints read: a decoded
/// [`TokenGroup`], or (NAN-4164) a group read in place from its file by
/// [`super::token_probe`].
pub(crate) trait GroupBlooms {
    /// May every token be in the group? An empty token bloom holds none.
    fn tokens_may_contain_all(&self, tokens: &[String]) -> bool;
    /// `None`: the group has no trigram bloom (v3 and older).
    fn trigrams_may_contain_all(&self, grams: &[[u8; 3]]) -> Option<bool>;
    /// `None`: the group has no pair bloom (v4 and older).
    fn pairs_may_contain_all(&self, pairs: &[[u8; 8]]) -> Option<bool>;
    /// v6: the token bloom also holds every whole address of the group.
    fn holds_addresses(&self) -> bool;
}

impl GroupBlooms for TokenGroup {
    fn tokens_may_contain_all(&self, tokens: &[String]) -> bool {
        self.may_contain_all(tokens)
    }

    fn trigrams_may_contain_all(&self, grams: &[[u8; 3]]) -> Option<bool> {
        let bytes = self.trigrams.as_ref()?;
        let filter = parquet::bloom_filter::Sbbf::new(bytes);
        Some(grams.iter().all(|gram| filter.check(gram.as_slice())))
    }

    fn pairs_may_contain_all(&self, pairs: &[[u8; 8]]) -> Option<bool> {
        Some(self.pairs.as_ref()?.may_contain_all(pairs))
    }

    fn holds_addresses(&self) -> bool {
        self.addresses
    }
}

pub(crate) fn token_hint<G: GroupBlooms + ?Sized>(group: &G, hint: &CandidateHint) -> bool {
    match hint {
        CandidateHint::Entity { source_path, value } if is_hash_array(source_path) =>
            query_tokens(value).is_none_or(|tokens| tokens.is_empty() || group.tokens_may_contain_all(&tokens)),
        CandidateHint::Keyword { mode, value } => {
            // NAN-4217: in a v6 group a bare IP is one whole token, as rare
            // as the address; checked first, it decides most groups alone.
            if group.holds_addresses() {
                if let Some(address) = required_address(mode, value) {
                    if !group.tokens_may_contain_all(std::slice::from_ref(&address)) {
                        return false;
                    }
                }
            }
            let tokens_keep = required_tokens(mode, value).is_none_or(|tokens| group.tokens_may_contain_all(&tokens));
            if !tokens_keep { return false; }
            let pairs = required_pairs(mode, value);
            if !pairs.is_empty() && group.pairs_may_contain_all(&pairs) == Some(false) {
                return false;
            }
            let grams = required_trigrams(mode, value);
            grams.is_empty() || group.trigrams_may_contain_all(&grams) != Some(false)
        },
        CandidateHint::Any { alternatives } => {
            alternatives.is_empty() || alternatives.iter().any(|alternative| token_hint(group, alternative))
        }
        _ => true,
    }
}

/// Group-relative candidate rows of one row group: `[start, end)` with the
/// exact `[min, max]` event time (µs) of those rows.
pub type BlockRuns = Vec<(u64, u64, (i64, i64))>;

/// v2 evidence of one data file, per row group: `Some(runs)` when only those
/// rows can match (empty = none can), `None` when the whole group is read.
pub type FineBlocks = Vec<Option<BlockRuns>>;

/// Decode a file's `tokens.nti` once: the v1 row-group keep mask and, for a
/// v2 index, the per-group candidate block runs. Groups the v2 section
/// proves empty are also cleared in the mask, so such a file is pruned
/// before its data is fetched.
pub fn token_evidence(index_bytes: Option<&[u8]>, expected_groups: usize, hints: &[CandidateHint]) -> (Mask, Option<FineBlocks>) {
    if !uses_tokens(hints) {
        return (None, None);
    }
    let Some(groups) = index_bytes.and_then(|bytes| decode_token_index(bytes).ok()) else { return (None, None) };
    token_evidence_of(&groups, expected_groups, hints)
}

/// [`token_evidence`] over a leased (signed-digest verified) index file
/// (see [`crate::parts::sidecar::decode_leased_token_index`]).
pub fn leased_token_evidence(index_bytes: Option<&[u8]>, expected_groups: usize, hints: &[CandidateHint]) -> (Mask, Option<FineBlocks>) {
    if !uses_tokens(hints) {
        return (None, None);
    }
    let Some(groups) = index_bytes.and_then(|bytes| decode_leased_token_index(bytes).ok()) else { return (None, None) };
    token_evidence_of(&groups, expected_groups, hints)
}

/// [`token_evidence`] over an already decoded index.
pub fn token_evidence_of(groups: &[TokenGroup], expected_groups: usize, hints: &[CandidateHint]) -> (Mask, Option<FineBlocks>) {
    if !uses_tokens(hints) || groups.len() != expected_groups {
        return (None, None);
    }
    let mut mask = vec![true; groups.len()];
    for hint in hints {
        for (keep, group) in mask.iter_mut().zip(groups) {
            // An excluded group cannot be resurrected by another AND term.
            if *keep {
                *keep = token_hint(group, hint);
            }
        }
    }
    let fine = fine_blocks(groups, hints);
    if let Some(fine) = &fine {
        for (keep, runs) in mask.iter_mut().zip(fine) {
            if runs.as_ref().is_some_and(Vec::is_empty) {
                *keep = false;
            }
        }
    }
    (Some(mask), fine)
}

/// Per-group candidate block runs of a v2 index (see [`token_evidence`]).
/// `None` when any group lacks a block section. A group whose candidates
/// cover more than 1/`COMMON_DIVISOR` of its blocks is read whole: past that
/// density the OR of per-block fences costs more than the scan it saves
/// (measured on real parts, NAN-3032).
pub fn fine_blocks(groups: &[TokenGroup], hints: &[CandidateHint]) -> Option<FineBlocks> {
    if groups.iter().any(|group| group.blocks.is_none()) {
        return None;
    }
    Some(
        groups
            .iter()
            .map(|group| {
                let index = group.blocks.as_ref().expect("checked above");
                let keep = hints.iter().fold(None, |acc: Option<Vec<bool>>, hint| {
                    and_blocks(acc, block_hint(index, hint, group.addresses))
                })?;
                let kept = keep.iter().filter(|keep| **keep).count();
                if kept * crate::parts::block_index::COMMON_DIVISOR > keep.len() {
                    return None;
                }
                let mut runs: BlockRuns = Vec::new();
                for (block, _) in keep.iter().enumerate().filter(|(_, keep)| **keep) {
                    let (start, end) = index.block_rows_range(block, group.rows);
                    let time = index.times[block];
                    match runs.last_mut() {
                        Some(last) if last.1 == start => {
                            last.1 = end;
                            last.2 = (last.2 .0.min(time.0), last.2 .1.max(time.1));
                        }
                        _ => runs.push((start, end, time)),
                    }
                }
                Some(runs)
            })
            .collect(),
    )
}

/// `None` = every block.
fn and_blocks(left: Option<Vec<bool>>, right: Option<Vec<bool>>) -> Option<Vec<bool>> {
    match (left, right) {
        (None, other) | (other, None) => other,
        (Some(left), Some(right)) => Some(left.iter().zip(&right).map(|(a, b)| *a && *b).collect()),
    }
}

/// Blocks of one group that may satisfy `hint`; `None` = every block.
/// `addresses`: the group's index holds whole-address tokens (v6).
fn block_hint(index: &crate::parts::block_index::BlockIndex, hint: &CandidateHint, addresses: bool) -> Option<Vec<bool>> {
    match hint {
        CandidateHint::Keyword { mode, value } => {
            let mut tokens = required_tokens(mode, value).unwrap_or_default();
            // NAN-4217: the whole address is a rare `fine` key where its
            // number pieces are `common` (every block), so it fences the
            // rows to the blocks that hold the IP.
            if let Some(address) = required_address(mode, value).filter(|_| addresses) {
                tokens.push(address);
            }
            (!tokens.is_empty()).then_some(tokens).and_then(|tokens| index.blocks_with_all(&tokens))
        }
        CandidateHint::Entity { source_path, value } if is_hash_array(source_path) => {
            query_tokens(value).filter(|tokens| !tokens.is_empty()).and_then(|tokens| index.blocks_with_all(&tokens))
        }
        CandidateHint::Any { alternatives } => {
            if alternatives.is_empty() {
                return None;
            }
            let mut union = vec![false; index.blocks()];
            for alternative in alternatives {
                // One undecidable branch makes the whole OR undecidable.
                let blocks = block_hint(index, alternative, addresses)?;
                for (keep, block) in union.iter_mut().zip(blocks) {
                    *keep |= block;
                }
            }
            Some(union)
        }
        _ => None,
    }
}

/// Keep mask from the Parquet row-group statistics and bloom filters of a
/// local, verified `data.parquet`.
pub fn entity_mask(path: &Path, hints: &[CandidateHint]) -> Mask {
    if !uses_entities(hints) {
        return None;
    }
    let file = File::open(path).ok()?;
    let reader = SerializedFileReader::new(file.try_clone().ok()?).ok()?;
    let groups = reader.metadata().num_row_groups();
    let mut mask = vec![true; groups];
    for (group, keep) in mask.iter_mut().enumerate() {
        *keep = hints.iter().all(|hint| entity_hint(Blooms::Footer(&reader, &file), group, hint));
    }
    Some(mask)
}

/// Combine all available row-group evidence before evaluating an OR. Separate
/// token and Parquet masks each have to keep an OR with an unknown branch;
/// evaluating both branches together can prove the whole OR absent.
pub fn combined_mask(path: &Path, index_bytes: Option<&[u8]>, hints: &[CandidateHint]) -> Mask {
    if !uses_entities(hints) && !uses_tokens(hints) {
        return None;
    }
    let file = File::open(path).ok()?;
    let reader = SerializedFileReader::new(file.try_clone().ok()?).ok()?;
    let groups = reader.metadata().num_row_groups();
    let tokens = index_bytes
        .and_then(|bytes| decode_token_index(bytes).ok())
        .filter(|tokens| tokens.len() == groups);
    Some((0..groups).map(|group| hints.iter().all(|hint| {
        combined_hint(Some(Blooms::Footer(&reader, &file)), group, tokens.as_ref().map(|tokens| &tokens[group]), hint)
    })).collect())
}

/// Where a file's entity evidence comes from: its opened footer, or its
/// compact summary (NAN-3077). Either way the bloom is read with the file's
/// own descriptor.
#[derive(Clone, Copy)]
enum Blooms<'a> {
    Footer(&'a SerializedFileReader<File>, &'a File),
    Summary(&'a FileSummary, &'a File),
    Parsed(&'a FileSummary, &'a ParsedBlooms),
}

impl Blooms<'_> {
    /// `Some(false)` only when statistics or the bloom prove absence.
    fn may_contain(self, group: usize, path: &str, value: &str) -> Option<bool> {
        if !crate::parts::format::BLOOM_PATHS.contains(&path) || !value.is_ascii() {
            return None;
        }
        match self {
            Blooms::Footer(reader, file) => {
                let metadata = reader.metadata();
                let columns = metadata.file_metadata().schema_descr().columns();
                let Some(index) = columns
                    .iter()
                    .position(|column| column.path().string() == path && column.max_rep_level() == 0)
                else {
                    let leaves = columns.iter().map(|column| leaf_event_path(column.path().parts())).collect::<Vec<_>>();
                    return (!leaves.is_empty() && leaf_absent(leaves.iter().map(String::as_str), path)).then_some(false);
                };
                let column = metadata.row_group(group).column(index);
                may_contain(&EntityGroup::of(column), path, value, || Sbbf::read_from_column_chunk(column, file).ok().flatten().map(Arc::new))
            }
            Blooms::Parsed(summary, parsed) => {
                let Some(groups) = summary.entity(path) else {
                    return summary.lacks_leaf(path).then_some(false);
                };
                let entity = groups.get(group)?;
                may_contain(entity, path, value, || parsed.fields.iter()
                    .find(|(name, _)| &**name == path)
                    .and_then(|(_, groups)| groups.get(group)).cloned().flatten())
            }
            Blooms::Summary(summary, file) => {
                let Some(groups) = summary.entity(path) else {
                    return summary.lacks_leaf(path).then_some(false);
                };
                let entity = groups.get(group)?;
                may_contain(entity, path, value, || match entity.bloom {
                    BloomAt::At(offset, length) => read_bloom_at(file, offset, length).map(Arc::new),
                    _ => None,
                })
            }
        }
    }
}

impl Blooms<'_> {
    /// NAN-4664: `Some(false)` only when the file's indicator column of
    /// `kind` proves no row of the group holds `value` (ASCII case-folded);
    /// `None` for a file without the columns or a literal the column cannot
    /// decide (non-ASCII: the SQL lowers it with Unicode rules), never proof
    /// of absence.
    fn indicator_may_contain(self, group: usize, kind: nanosiem_core::search::lake_indicators::Kind, value: &str) -> Option<bool> {
        let probe = nanosiem_core::search::lake_indicators::probe(value)?;
        let column = kind.column();
        match self {
            Blooms::Footer(reader, file) => {
                let metadata = reader.metadata();
                if !has_indicator_marker(metadata.file_metadata()) {
                    return None;
                }
                let index = metadata.file_metadata().schema_descr().columns().iter()
                    .position(|leaf| leaf.max_rep_level() == 1 && indicator_leaf_kind(leaf.path().parts()) == Some(kind))?;
                let chunk = metadata.row_group(group).column(index);
                indicator_contains(&EntityGroup::of(chunk), probe.as_bytes(), || Sbbf::read_from_column_chunk(chunk, file).ok().flatten().map(Arc::new))
            }
            Blooms::Parsed(summary, parsed) => {
                if !summary.indicators {
                    return None;
                }
                let entity = summary.entity(column)?.get(group)?;
                indicator_contains(entity, probe.as_bytes(), || parsed.fields.iter()
                    .find(|(name, _)| &**name == column)
                    .and_then(|(_, groups)| groups.get(group)).cloned().flatten())
            }
            Blooms::Summary(summary, file) => {
                if !summary.indicators {
                    return None;
                }
                let entity = summary.entity(column)?.get(group)?;
                indicator_contains(entity, probe.as_bytes(), || match entity.bloom {
                    BloomAt::At(offset, length) => read_bloom_at(file, offset, length).map(Arc::new),
                    _ => None,
                })
            }
        }
    }

    /// Entity evidence: the hinted leaf's own statistics and bloom, then
    /// (NAN-4664) the indicator column covering that leaf. Both are safe
    /// supersets, so either proving absence prunes the group.
    fn entity_keep(self, group: usize, path: &str, value: &str) -> bool {
        if self.may_contain(group, path, value) == Some(false) {
            return false;
        }
        nanosiem_core::search::lake_indicators::classify(path)
            .is_none_or(|kind| self.indicator_may_contain(group, kind, value) != Some(false))
    }
}

/// One indicator decision: the column holds exactly the lowercased values,
/// so `probe` is its only spelling. Missing statistics or an unreadable
/// bloom keep the group.
fn indicator_contains(group: &EntityGroup, probe: &[u8], bloom: impl FnOnce() -> Option<Arc<Sbbf>>) -> Option<bool> {
    if group.min.as_ref().is_some_and(|min| probe < &**min) || group.max.as_ref().is_some_and(|max| probe > &**max) {
        return Some(false);
    }
    if group.bloom == BloomAt::Absent {
        return Some(true);
    }
    Some(bloom().is_none_or(|bloom| bloom.check(probe)))
}

/// A serialized bloom (header + bitset) at `offset`.
fn read_bloom_at(file: &File, offset: u64, length: usize) -> Option<Sbbf> {
    use std::os::unix::fs::FileExt;
    if length > 64 * 1024 * 1024 {
        return None;
    }
    let mut bytes = vec![0; length];
    file.read_exact_at(&mut bytes, offset).ok()?;
    Sbbf::from_bytes(&bytes).ok()
}

/// The one entity decision over a row group's statistics and bloom (a
/// missing or unreadable bloom is unknown, never proof of absence).
fn may_contain(group: &EntityGroup, path: &str, value: &str, bloom: impl FnOnce() -> Option<Arc<Sbbf>>) -> Option<bool> {
    if let (Some(min), Some(max)) = (&group.min, &group.max) {
        if min == max && min.is_ascii() && !min.eq_ignore_ascii_case(value.as_bytes()) {
            return Some(false);
        }
    }
    let variants = spellings_for(path, value)?;
    let remaining = variants
        .iter()
        .filter(|variant| {
            group.min.as_ref().is_none_or(|min| variant.as_slice() >= &**min)
                && group.max.as_ref().is_none_or(|max| variant.as_slice() <= &**max)
        })
        .collect::<Vec<_>>();
    if remaining.is_empty() {
        return Some(false);
    }
    if group.bloom == BloomAt::Absent {
        return Some(true);
    }
    let bloom = bloom();
    Some(remaining.iter().any(|variant| bloom.as_ref().is_none_or(|bloom| bloom.check(variant.as_slice()))))
}

/// `bloom` is `None` only when no hint reads a bloom ([`uses_entities`] is
/// false), in which case an entity branch cannot occur; it keeps anyway.
fn combined_hint(bloom: Option<Blooms<'_>>, group: usize, tokens: Option<&TokenGroup>, hint: &CandidateHint) -> bool {
    match hint {
        CandidateHint::Entity { source_path, value } =>
            bloom.is_none_or(|bloom| bloom.entity_keep(group, source_path, value))
                && tokens.is_none_or(|tokens| token_hint(tokens, hint)),
        CandidateHint::SourceFamily { .. } | CandidateHint::Class { .. } => true,
        CandidateHint::Keyword { .. } => tokens.is_none_or(|tokens| token_hint(tokens, hint)),
        CandidateHint::Any { alternatives } => alternatives.is_empty()
            || alternatives.iter().any(|hint| combined_hint(bloom, group, tokens, hint)),
    }
}

fn entity_hint(bloom: Blooms<'_>, group: usize, hint: &CandidateHint) -> bool {
    match hint {
        CandidateHint::Entity { source_path, value } => bloom.entity_keep(group, source_path, value),
        CandidateHint::SourceFamily { .. } | CandidateHint::Class { .. } => true,
        CandidateHint::Any { alternatives } => {
            alternatives.is_empty() || alternatives.iter().any(|alternative| entity_hint(bloom, group, alternative))
        }
        CandidateHint::Keyword { .. } => true,
    }
}

/// Every bounded ASCII case spelling of `value` (the blooms hold raw values
/// while nPL compares case-insensitively). `None` past 8 letters: unknown.
fn spellings(value: &str) -> Option<Vec<Vec<u8>>> {
    if !value.is_ascii() || value.bytes().filter(u8::is_ascii_alphabetic).count() > 8 {
        return None;
    }
    let mut values = vec![value.as_bytes().to_ascii_lowercase()];
    for (index, byte) in value.bytes().enumerate() {
        if byte.is_ascii_alphabetic() {
            let upper = values
                .iter()
                .map(|spelling| {
                    let mut spelling = spelling.clone();
                    spelling[index] = byte.to_ascii_uppercase();
                    spelling
                })
                .collect::<Vec<_>>();
            values.extend(upper);
        }
    }
    Some(values)
}

/// Bloom paths the OCSF lake compiler compares RAW against the lowered
/// literal (`"src_endpoint.hostname" = 'ws-1.corp.local'`: the column is
/// lowercase-normalized at ingest, CLAUDE.md "ingest-lowercased columns
/// compare RAW"). A row matches such a predicate only if its stored bytes
/// equal the lowercase literal, so probing that one spelling is exact with
/// respect to the emitted SQL, whatever the stored case. NAN-3077: without
/// this, a hostname (always > 8 letters) could not be probed at all, and a
/// host pivot decoded every row group of the source in the window. Kept in
/// step with the compiler's profile by
/// `ingest_lowercased_bloom_paths_match_the_lake_profile`.
pub const INGEST_LOWERCASED_BLOOM_PATHS: &[&str] = &[
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "src_endpoint.hostname",
    "dst_endpoint.hostname",
    "device.hostname",
    "src_endpoint.mac",
    "dst_endpoint.mac",
];

/// The spellings a bloom must be probed with for an equality on `path`.
fn spellings_for(path: &str, value: &str) -> Option<Vec<Vec<u8>>> {
    if INGEST_LOWERCASED_BLOOM_PATHS.contains(&path) {
        return value.is_ascii().then(|| vec![value.as_bytes().to_ascii_lowercase()]);
    }
    spellings(value)
}

/// Intersect two masks (`None` is all-true).
pub fn and(left: Mask, right: Mask) -> Mask {
    match (left, right) {
        (None, other) | (other, None) => other,
        (Some(left), Some(right)) if left.len() == right.len() => {
            Some(left.iter().zip(&right).map(|(a, b)| *a && *b).collect())
        }
        // Disagreeing group counts: trust neither.
        _ => None,
    }
}

/// Row-group row ranges `[start, end)` of a Parquet file, in group order.
pub fn row_group_ranges(path: &Path) -> Option<Vec<(u64, u64)>> {
    let reader = SerializedFileReader::new(File::open(path).ok()?).ok()?;
    let mut start = 0_u64;
    let mut ranges = Vec::new();
    for group in reader.metadata().row_groups() {
        let rows = u64::try_from(group.num_rows()).ok()?;
        ranges.push((start, start + rows));
        start += rows;
    }
    Some(ranges)
}

/// Keep mask from the row groups' `time` statistics: a group survives when
/// its `[min, max]` touches a matching 5-minute bucket. Missing or inexact
/// statistics keep the group.
pub fn time_mask(path: &Path, buckets: &std::collections::BTreeSet<i64>) -> Mask {
    let reader = SerializedFileReader::new(File::open(path).ok()?).ok()?;
    FileSummary::of(&reader)?.time_mask(buckets)
}

/// [`kept_ranges`] with each merged range's `[min, max]` event time, when
/// every row group's bounds are known.
pub fn kept_ranges_with_time(
    mask: &[bool],
    ranges: &[(u64, u64)],
    times: Option<&[(i64, i64)]>,
) -> Vec<(u64, u64, Option<(i64, i64)>)> {
    let times = times.filter(|times| times.len() == ranges.len());
    let mut out: Vec<(u64, u64, Option<(i64, i64)>)> = Vec::new();
    for (index, (keep, (start, end))) in mask.iter().zip(ranges).enumerate() {
        if !keep {
            continue;
        }
        let time = times.map(|times| times[index]);
        match out.last_mut() {
            Some(last) if last.1 == *start => {
                last.1 = *end;
                last.2 = match (last.2, time) {
                    (Some((a, b)), Some((c, d))) => Some((a.min(c), b.max(d))),
                    _ => None,
                };
            }
            _ => out.push((*start, *end, time)),
        }
    }
    out
}

/// Merge adjacent kept groups into `[start, end)` row ranges.
pub fn kept_ranges(mask: &[bool], ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (keep, (start, end)) in mask.iter().zip(ranges) {
        if !keep {
            continue;
        }
        match out.last_mut() {
            Some(last) if last.1 == *start => last.1 = *end,
            _ => out.push((*start, *end)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::sidecar::{encode_token_index, TokenGroupBuilder};
    use arrow_array::{ArrayRef, RecordBatch, StringArray, StructArray};
    use arrow_schema::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;
    use parquet::file::properties::WriterProperties;
    use parquet::schema::types::ColumnPath;
    use std::sync::Arc;

    fn keyword(mode: &str, value: &str) -> CandidateHint {
        CandidateHint::Keyword { mode: mode.into(), value: value.into() }
    }

    fn entity(path: &str, value: &str) -> CandidateHint {
        CandidateHint::Entity { source_path: path.into(), value: value.into() }
    }

    /// NAN-3188: a class hint skips only a source/class family file of
    /// another class; legacy/overflow (`None`) and matching files are kept,
    /// and no other stage treats the hint as evidence.
    #[test]
    fn class_hint_prunes_only_signed_files_of_another_class() {
        let class = CandidateHint::Class { value: 4001 };
        let sysmon = vec!["windows_sysmon".to_string()];
        assert!(!class_may_match(Some(1001), &[class.clone()]), "differing class pruned");
        assert!(class_may_match(Some(4001), &[class.clone()]), "matching class kept");
        assert!(class_may_match(None, &[class.clone()]), "overflow/legacy kept");
        assert!(class_may_match(Some(1001), &[keyword("token", "run")]), "no class hint: kept");
        assert!(class_may_match(Some(1001), &[CandidateHint::Any { alternatives: vec![] }]));
        assert!(!file_family_may_match(Some(&sysmon), Some(1001), &[class.clone()]));
        assert!(file_family_may_match(Some(&sysmon), Some(4001), &[class.clone()]));
        assert!(file_family_may_match(None, None, &[class.clone()]));
        // Both dimensions must allow the file.
        let cloud = CandidateHint::SourceFamily { value: "aws_cloudtrail".into() };
        assert!(!file_family_may_match(Some(&sysmon), Some(4001), &[class.clone(), cloud]));
        assert!(!uses_tokens(&[class.clone()]) && !uses_entities(&[class.clone()]));
        assert!(!has_progressive_index_hint(&[class.clone()]));
    }

    /// An older worker must never see the hint (it ships in the same image
    /// as its compiler); this pins the wire form the compiler emits.
    #[test]
    fn class_hint_wire_form() {
        let hint: CandidateHint = serde_json::from_value(serde_json::json!({"kind": "class", "value": 201002})).unwrap();
        assert_eq!(hint, CandidateHint::Class { value: 201002 });
    }

    #[test]
    fn source_family_requires_signed_coverage_and_preserves_or() {
        let sources = vec!["conduit_proxy".into(), "windows_sysmon".into()];
        let sysmon = CandidateHint::SourceFamily { value: "WINDOWS_SYSMON".into() };
        let cloud = CandidateHint::SourceFamily { value: "aws_cloudtrail".into() };
        assert!(source_family_may_match(Some(&sources), &[sysmon.clone()]));
        assert!(!source_family_may_match(Some(&sources), &[cloud.clone()]));
        assert!(source_family_may_match(None, &[cloud.clone()]));
        assert!(source_family_may_match(Some(&["MixedCase".into()]), &[CandidateHint::SourceFamily { value: "mixedcase".into() }]));
        assert!(!source_family_may_match(Some(&["MixedCase".into()]), &[cloud.clone()]));
        assert!(source_family_may_match(Some(&["Événement".into()]), &[cloud.clone()]));
        assert!(source_family_may_match(
            Some(&sources),
            &[CandidateHint::Any { alternatives: vec![cloud.clone(), sysmon] }],
        ));
        assert!(source_family_may_match(
            Some(&sources),
            &[CandidateHint::Any { alternatives: vec![cloud, entity("user.name", "alice")] }],
        ));
        assert!(has_progressive_index_hint(&[CandidateHint::Any { alternatives: vec![
            entity("file.hashes.sha256", "def"),
            entity("file.hashes.value", "abc"),
        ] }]));
        // A source family has no per-chunk index on L0/M parts: membership runs.
        assert!(!has_progressive_index_hint(&[CandidateHint::SourceFamily { value: "audit".into() }]));
        assert!(!has_progressive_index_hint(&[CandidateHint::Any { alternatives: vec![
            CandidateHint::SourceFamily { value: "audit".into() },
            entity("file.hashes.value", "abc"),
        ] }]));
        assert!(!has_progressive_index_hint(&[CandidateHint::Any { alternatives: vec![
            CandidateHint::SourceFamily { value: "audit".into() },
            keyword("contains", "abc"),
        ] }]));
    }

    fn index(texts: &[&str]) -> Vec<u8> {
        let groups = texts
            .iter()
            .map(|text| {
                let mut builder = TokenGroupBuilder::new();
                builder.add_row();
                builder.add_text(text);
                builder.finish().unwrap()
            })
            .collect::<Vec<_>>();
        encode_token_index(&groups).unwrap()
    }

    #[test]
    fn token_mask_prunes_only_token_mode_and_keeps_on_unknowns() {
        let bytes = index(&["Mimikatz sekurlsa::logonpasswords", "GET /index.html 200", ""]);
        assert_eq!(token_mask(Some(&bytes), 3, &[keyword("token", "MIMIKATZ")]), Some(vec![true, false, false]));
        // Substring guards keep every group when a legacy index lacks trigrams.
        assert_eq!(token_mask(Some(&bytes), 3, &[keyword("regex_guard", "katz")]), Some(vec![true; 3]));
        assert_eq!(token_mask(Some(&bytes), 3, &[keyword("contains", "mimi")]), Some(vec![true; 3]));
        // Any = OR; AND across hints.
        let any = CandidateHint::Any { alternatives: vec![keyword("token", "index"), keyword("token", "mimikatz")] };
        assert_eq!(token_mask(Some(&bytes), 3, &[any.clone()]), Some(vec![true, true, false]));
        assert_eq!(token_mask(Some(&bytes), 3, &[any, keyword("token", "200")]), Some(vec![false, true, false]));
        // An Any holding an undecidable branch keeps its groups.
        let open = CandidateHint::Any { alternatives: vec![keyword("token", "nomatch"), keyword("contains", "x")] };
        assert_eq!(token_mask(Some(&bytes), 3, &[open]), Some(vec![true, true, true]));
        // Wrong group count, corrupt bytes, missing index, over-long token: keep.
        assert_eq!(token_mask(Some(&bytes), 2, &[keyword("token", "mimikatz")]), None);
        let mut corrupt = bytes.clone();
        corrupt[30] ^= 1;
        assert_eq!(token_mask(Some(&corrupt), 3, &[keyword("token", "mimikatz")]), None);
        assert_eq!(token_mask(None, 3, &[keyword("token", "mimikatz")]), None);
        let long = "a".repeat(200);
        // Undecidable (no representable token): no mask, every group kept.
        assert_eq!(token_mask(Some(&bytes), 3, &[keyword("token", &long)]), None);
        // Entity-only hints never consult the token index.
        assert_eq!(token_mask(Some(&bytes), 3, &[entity("user.name", "bob")]), None);
        assert_eq!(token_mask(Some(&bytes), 3, &[entity("file.hashes.value", "mimikatz")]), Some(vec![true, false, false]));
    }

    /// NAN-4164: on a v5 index a multi-token `token` needle needs its
    /// adjacent pairs; scattered pieces no longer keep a group. Wildcards,
    /// substring guards and non-ASCII needles never consult pairs.
    #[test]
    fn v5_pairs_prune_scattered_pieces_and_keep_terms() {
        let encode = |texts: &[&str], pairs: bool| {
            let groups = texts.iter().map(|text| {
                let mut builder = if pairs { TokenGroupBuilder::with_pairs(8) } else { TokenGroupBuilder::with_trigrams(8) };
                builder.add_row_at(0);
                builder.add_text(text);
                builder.finish().unwrap()
            }).collect::<Vec<_>>();
            crate::parts::sidecar::encode_token_index(&groups).unwrap()
        };
        let texts = [
            "2026-10-01T04:20:10 host 10.1.9.4",
            "src=10.1.4.20 dst=8.8.8.8",
            "sshd: Failed password for root",
            "password failed",
        ];
        let v4 = encode(&texts, false);
        let v5 = encode(&texts, true);
        for (hint, v4_mask, v5_mask) in [
            (keyword("token", "10.1.4.20"), vec![true, true, false, false], vec![false, true, false, false]),
            (keyword("token", "Failed Password"), vec![false, false, true, true], vec![false, false, true, false]),
            (keyword("token", "sysmon"), vec![false; 4], vec![false; 4]),
            (keyword("contains", "10.1.4.2"), vec![false, true, false, false], vec![false, true, false, false]),
            (keyword("token", "10.1.4.2*"), vec![false, true, false, false], vec![false, true, false, false]),
        ] {
            let masks = |bytes: &[u8]| token_mask(Some(bytes), 4, std::slice::from_ref(&hint)).unwrap_or(vec![true; 4]);
            assert_eq!(masks(&v4), v4_mask, "v4 {hint:?}");
            assert_eq!(masks(&v5), v5_mask, "v5 {hint:?}");
        }
        assert!(required_pairs("token", "über alles").is_empty());
        assert!(required_pairs("token", "sysmon").is_empty());
        assert_eq!(required_pairs("token", " a.b ").len(), 1);
    }

    /// NAN-4217: a v6 group answers a bare IP on its whole-address token:
    /// groups whose number pieces (and even adjacent pairs) are all present
    /// are pruned unless the address itself is, and the block index fences
    /// the rows to the blocks holding it. Non-address needles and v5 groups
    /// are judged exactly as before.
    #[test]
    fn v6_address_tokens_prune_ips_and_fence_blocks() {
        let groups_of = |rows: &[&[&str]], v6: bool| {
            rows.iter().map(|texts| {
                let mut builder = if v6 { TokenGroupBuilder::with_addresses(1) } else { TokenGroupBuilder::with_pairs(1) };
                for (row, text) in texts.iter().enumerate() {
                    builder.add_row_at(row as i64);
                    builder.add_text(text);
                }
                builder.finish().unwrap()
            }).collect::<Vec<_>>()
        };
        // Group 0 holds every piece and every adjacent pair of 48.170.34.111
        // but never the address; group 1 holds it in row 5 of 8.
        let rows: [&[&str]; 3] = [
            &["148.170.34.1119 48.170.34.11 34.111.0.1 170.34.9.9", "10:48:170 x"],
            &["48.170.1.1", "1.170.34.2", "34.111.2.2", "48 170 34 111", "x48.170.34.1110", "src=48.170.34.111:443", "48-170-34-111", "h"],
            &["fe80::1 10.0.0.5"],
        ];
        let (v5, v6) = (groups_of(&rows, false), groups_of(&rows, true));
        for (needle, v5_mask, v6_mask) in [
            ("48.170.34.111", vec![true, true, false], vec![false, true, false]),
            ("10.0.0.5", vec![false, false, true], vec![false, false, true]),
            ("FE80::1", vec![false, false, true], vec![false, false, true]),
            ("48.170.34.11", vec![true, false, false], vec![true, false, false]),
            ("170.34", vec![true, true, false], vec![true, true, false]),
            ("sysmon", vec![false; 3], vec![false; 3]),
        ] {
            let hint = [keyword("token", needle)];
            assert_eq!(token_evidence_of(&v5, 3, &hint).0.unwrap(), v5_mask, "v5 {needle}");
            assert_eq!(token_evidence_of(&v6, 3, &hint).0.unwrap(), v6_mask, "v6 {needle}");
        }
        // The fine runs of group 1 shrink to the IP's block (row 5).
        let (_, fine) = token_evidence_of(&v6, 3, &[keyword("token", "48.170.34.111")]);
        assert_eq!(fine.unwrap()[1].as_ref().map(|runs| runs.iter().map(|r| (r.0, r.1)).collect::<Vec<_>>()), Some(vec![(5, 6)]));
        let (_, fine) = token_evidence_of(&v5, 3, &[keyword("token", "48.170.34.111")]);
        assert!(fine.unwrap()[1].is_none(), "v5: the number pieces keep every block");
        // An OR leg and wildcards keep their old meaning.
        let any = CandidateHint::Any { alternatives: vec![keyword("token", "48.170.34.111"), keyword("token", "10.0.0.5")] };
        assert_eq!(token_evidence_of(&v6, 3, &[any]).0.unwrap(), vec![false, true, true]);
        assert_eq!(required_address("token", "48.170.34.1*"), None);
        assert_eq!(required_address("contains", "48.170.34.111"), None);
        assert_eq!(required_address("token", "fe80::"), None, "one piece: the SQL is a token search, not the term");
        assert_eq!(required_address("token", " 10.0.0.5 ").as_deref(), Some("10.0.0.5"));
    }

    fn parquet_with_users(groups: &[&[Option<&str>]]) -> tempfile::NamedTempFile {
        let fields: arrow_schema::Fields = vec![Field::new("name", DataType::Utf8, true)].into();
        let schema = Arc::new(Schema::new(vec![Field::new("user", DataType::Struct(fields.clone()), true)]));
        let file = tempfile::NamedTempFile::new().unwrap();
        let props = WriterProperties::builder()
            .set_column_bloom_filter_enabled(ColumnPath::new(vec!["user".into(), "name".into()]), true)
            .set_max_row_group_row_count(Some(1_000))
            .build();
        let mut writer = ArrowWriter::try_new(file.reopen().unwrap(), schema.clone(), Some(props)).unwrap();
        for values in groups {
            let names = StructArray::new(fields.clone(), vec![Arc::new(StringArray::from(values.to_vec())) as ArrayRef], None);
            writer.write(&RecordBatch::try_new(schema.clone(), vec![Arc::new(names)]).unwrap()).unwrap();
            writer.flush().unwrap();
        }
        writer.close().unwrap();
        file
    }

    #[test]
    fn combined_mask_prunes_an_or_only_when_both_evidence_sources_exclude_it() {
        // The file stores the hash leaf without a bloom, so only the token
        // index can decide that branch (a file without the leaf at all would
        // prove it absent, NAN-3694).
        let fields: arrow_schema::Fields = vec![Field::new("name", DataType::Utf8, true)].into();
        let value: arrow_schema::Fields = vec![Field::new("value", DataType::Utf8, true)].into();
        let hashes: arrow_schema::Fields = vec![Field::new("hashes", DataType::Struct(value.clone()), true)].into();
        let schema = Arc::new(Schema::new(vec![
            Field::new("user", DataType::Struct(fields.clone()), true),
            Field::new("file", DataType::Struct(hashes.clone()), true),
        ]));
        let file = tempfile::NamedTempFile::new().unwrap();
        let props = WriterProperties::builder()
            .set_column_bloom_filter_enabled(ColumnPath::new(vec!["user".into(), "name".into()]), true)
            .set_max_row_group_row_count(Some(1_000))
            .build();
        let mut writer = ArrowWriter::try_new(file.reopen().unwrap(), schema.clone(), Some(props)).unwrap();
        for (name, hash) in [("alice", Some("rare_hash")), ("bob", None), ("carol", None)] {
            let names = StructArray::new(fields.clone(), vec![Arc::new(StringArray::from(vec![Some(name)])) as ArrayRef], None);
            let inner = StructArray::new(value.clone(), vec![Arc::new(StringArray::from(vec![hash])) as ArrayRef], None);
            let file_column = StructArray::new(hashes.clone(), vec![Arc::new(inner) as ArrayRef], None);
            writer.write(&RecordBatch::try_new(schema.clone(), vec![Arc::new(names), Arc::new(file_column)]).unwrap()).unwrap();
            writer.flush().unwrap();
        }
        writer.close().unwrap();
        let bytes = index(&["rare_hash", "other", "other"]);
        let hint = CandidateHint::Any { alternatives: vec![
            entity("user.name", "bob"),
            entity("file.hashes.value", "rare_hash"),
        ] };
        assert_eq!(combined_mask(file.path(), Some(&bytes), &[hint.clone()]), Some(vec![true, true, false]));
        // A missing or invalid token index keeps the undecidable branch.
        assert_eq!(combined_mask(file.path(), None, &[hint]), Some(vec![true, true, true]));
    }

    #[test]
    fn entity_mask_uses_stats_and_blooms_per_group_case_insensitively() {
        let file = parquet_with_users(&[&[Some("JSmith"), Some("alice")], &[Some("bob"), None], &[Some("Carol"), Some("carol")]]);
        let path = file.path();
        assert_eq!(row_group_ranges(path).unwrap(), vec![(0, 2), (2, 4), (4, 6)]);
        assert_eq!(entity_mask(path, &[entity("user.name", "jsmith")]), Some(vec![true, false, false]));
        assert_eq!(entity_mask(path, &[entity("user.name", "CAROL")]), Some(vec![false, false, true]));
        let any = CandidateHint::Any { alternatives: vec![entity("user.name", "bob"), entity("user.name", "alice")] };
        assert_eq!(entity_mask(path, &[any]), Some(vec![true, true, false]));
        // Non-identity paths and non-ASCII values are unknown: keep.
        assert_eq!(entity_mask(path, &[entity("message", "bob")]), Some(vec![true, true, true]));
        assert_eq!(entity_mask(path, &[entity("user.name", "İ")]), Some(vec![true, true, true]));
        assert_eq!(kept_ranges(&[true, false, true], &[(0, 2), (2, 4), (4, 6)]), vec![(0, 2), (4, 6)]);
        assert_eq!(kept_ranges(&[true, true, false], &[(0, 2), (2, 4), (4, 6)]), vec![(0, 4)]);
        assert_eq!(and(Some(vec![true, true]), Some(vec![false, true])), Some(vec![false, true]));
        assert_eq!(and(None, Some(vec![false])), Some(vec![false]));
        assert_eq!(and(Some(vec![true]), Some(vec![false, true])), None);
    }

    #[test]
    fn ingest_lowercased_bloom_paths_match_the_lake_profile() {
        use nanosiem_core::schema::{OcsfProfile, SchemaProfile};
        let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(Default::default()).unwrap();
        for path in INGEST_LOWERCASED_BLOOM_PATHS {
            assert!(crate::parts::format::BLOOM_PATHS.contains(path), "{path} has no bloom");
            assert!(profile.is_lowercased_at_ingest(path), "{path} is not compared raw by the compiler");
            assert!(profile.class_split_value_sql(path).is_none(), "{path} is class-split (compared lowered)");
        }
        // Mixed-case identity paths keep every spelling.
        assert!(!profile.is_lowercased_at_ingest("user.name"));
        assert!(!INGEST_LOWERCASED_BLOOM_PATHS.contains(&"user.name"));
    }

    fn parquet_with_path(path: &[&str], groups: &[&[Option<&str>]]) -> tempfile::NamedTempFile {
        parquet_with_path_bloom(path, groups, true)
    }

    fn parquet_with_path_bloom(path: &[&str], groups: &[&[Option<&str>]], bloom: bool) -> tempfile::NamedTempFile {
        // A nested struct path (`src_endpoint.hostname`), with or without a bloom.
        let leaf = Field::new(path[1], DataType::Utf8, true);
        let fields: arrow_schema::Fields = vec![leaf].into();
        let schema = Arc::new(Schema::new(vec![Field::new(path[0], DataType::Struct(fields.clone()), true)]));
        let file = tempfile::NamedTempFile::new().unwrap();
        let props = WriterProperties::builder()
            .set_column_bloom_filter_enabled(ColumnPath::new(path.iter().map(|p| p.to_string()).collect()), bloom)
            .set_max_row_group_row_count(Some(1_000))
            .build();
        let mut writer = ArrowWriter::try_new(file.reopen().unwrap(), schema.clone(), Some(props)).unwrap();
        for values in groups {
            let column = StructArray::new(fields.clone(), vec![Arc::new(StringArray::from(values.to_vec())) as ArrayRef], None);
            writer.write(&RecordBatch::try_new(schema.clone(), vec![Arc::new(column)]).unwrap()).unwrap();
            writer.flush().unwrap();
        }
        writer.close().unwrap();
        file
    }

    #[test]
    fn a_long_hostname_pivot_prunes_by_bloom() {
        // NAN-3077: `ws-mkt-068.corp.local` has 14 letters; the case-spelling
        // enumeration gave up past 8 and every group was read.
        let hosts: Vec<String> = (0..40).map(|i| format!("ws-mkt-{i:03}.corp.local")).collect();
        // Interleaved, so every group's min/max spans the needle: only the
        // bloom can decide.
        let group = |rest: usize| (0..40).filter(|i| i % 3 == rest).map(|i| Some(hosts[i].as_str())).collect::<Vec<_>>();
        let (a, b, c) = (group(0), group(1), group(2));
        let file = parquet_with_path(&["src_endpoint", "hostname"], &[&a, &b, &c]);
        let hint = [entity("src_endpoint.hostname", "WS-MKT-025.corp.local")];
        assert_eq!(entity_mask(file.path(), &hint), Some(vec![false, true, false]));
        // A mixed-case identity path still refuses to guess past 8 letters.
        let users = parquet_with_path(&["user", "name"], &[&a, &b, &c]);
        assert_eq!(entity_mask(users.path(), &[entity("user.name", "ws-mkt-025.corp.local")]), Some(vec![true, true, true]));
    }

    /// NAN-3694: a `device.ip` leg prunes by its new bloom, while a part
    /// written before the bloom existed (same column, no bloom) keeps every
    /// group: absent evidence is unknown, never "not here".
    #[test]
    fn asset_identity_blooms_prune_and_pre_bloom_parts_keep_rows() {
        let ips: Vec<String> = (0..40).map(|i| format!("10.1.{}.{}", i % 7, i)).collect();
        // Every group spans the same min/max, so only the bloom can decide.
        let group = |rest: usize| {
            let mut values = vec![Some("0.0.0.0")];
            values.extend((0..40).filter(|i| i % 3 == rest).map(|i| Some(ips[i].as_str())));
            values.push(Some("99.9.9.9"));
            values
        };
        let (a, b, c) = (group(0), group(1), group(2));
        let needle = [entity("device.ip", &ips[25])];
        let indexed = parquet_with_path(&["device", "ip"], &[&a, &b, &c]);
        assert_eq!(entity_mask(indexed.path(), &needle), Some(vec![false, true, false]));
        let legacy = parquet_with_path_bloom(&["device", "ip"], &[&a, &b, &c], false);
        assert_eq!(entity_mask(legacy.path(), &needle), Some(vec![true, true, true]));
        // An IP pivot OR prunes only when every leg can: the new leg no
        // longer forces a full read.
        let pivot = [CandidateHint::Any { alternatives: vec![entity("src_endpoint.ip", &ips[25]), entity("device.ip", &ips[25])] }];
        assert_eq!(entity_mask(indexed.path(), &pivot), Some(vec![false, true, false]));
        // Short mixed-case values enumerate spellings; a long email stays
        // unknown (the raw bloom is case-sensitive).
        let emails = parquet_with_path(&["user", "email_addr"], &[
            &[Some("A@a.io"), Some("Bo@Ex.io"), Some("zz@zz.io")],
            &[Some("A@a.io"), Some("al@ex.io"), Some("zz@zz.io")],
        ]);
        assert_eq!(entity_mask(emails.path(), &[entity("user.email_addr", "bo@ex.io")]), Some(vec![true, false]));
        assert_eq!(entity_mask(emails.path(), &[entity("user.email_addr", "alice.smith@example.com")]), Some(vec![true, true]));
    }

    /// NAN-3694: a file storing no leaf for an identity path cannot match an
    /// equality on it, so a pivot leg on a field the tenant never writes (an
    /// IP pivot's `device.ip`) no longer keeps every group. A file with an
    /// ancestor, descendant or repeated form of the path proves nothing.
    #[test]
    fn a_file_without_the_leaf_proves_the_leg_absent() {
        let ips: Vec<Option<&str>> = vec![Some("10.1.4.63"), Some("10.9.9.9")];
        let other = vec![Some("10.7.7.7"), Some("10.8.8.8")];
        let file = parquet_with_path(&["src_endpoint", "ip"], &[&ips, &other]);
        assert_eq!(entity_mask(file.path(), &[entity("device.hostname", "ws-1")]), Some(vec![false, false]));
        let pivot = [CandidateHint::Any { alternatives: vec![entity("src_endpoint.ip", "10.1.4.63"), entity("device.hostname", "10.1.4.63")] }];
        assert_eq!(entity_mask(file.path(), &pivot), Some(vec![true, false]));
        // A path without bloom evidence at all stays unknown.
        assert_eq!(entity_mask(file.path(), &[entity("message", "x")]), Some(vec![true, true]));
        // The same file, its evidence from the compact summary.
        let reader = SerializedFileReader::new(File::open(file.path()).unwrap()).unwrap();
        let summary = FileSummary::of(&reader).expect("summary");
        assert!(summary.lacks_leaf("device.ip"));
        assert!(!summary.lacks_leaf("src_endpoint.ip"));
        assert!(!summary.lacks_leaf("src_endpoint"), "an ancestor of a stored leaf");
        assert!(!summary.lacks_leaf("src_endpoint.ip.raw"), "below a stored leaf");
        assert!(leaf_absent(["file.hashes.value"].into_iter(), "file.hashes.algorithm"));
        assert!(!leaf_absent(["file.hashes.value"].into_iter(), "file.hashes.value"), "a repeated leaf is present");
        assert!(!leaf_absent(["device"].into_iter(), "device.ip"), "a scalar ancestor");
        assert!(leaf_absent(["device.ip_v6"].into_iter(), "device.ip"), "a sibling prefix is not the leaf");
        let empty = FileSummary { column_bytes: ColumnBytes::default(), ..summary };
        assert!(!empty.lacks_leaf("device.ip"), "no inventory proves nothing");
    }

    /// A part-shaped file with a flat `metadata.log_source` column, one row
    /// group per slice (no blooms: only the statistics decide).
    fn parquet_with_sources(groups: &[&[Option<&str>]]) -> tempfile::NamedTempFile {
        let schema = Arc::new(Schema::new(vec![Field::new(SOURCE_FAMILY_PATH, DataType::Utf8, true)]));
        let file = tempfile::NamedTempFile::new().unwrap();
        let props = WriterProperties::builder().set_max_row_group_row_count(Some(1_000)).build();
        let mut writer = ArrowWriter::try_new(file.reopen().unwrap(), schema.clone(), Some(props)).unwrap();
        for values in groups {
            writer.write(&RecordBatch::try_new(schema.clone(), vec![Arc::new(StringArray::from(values.to_vec())) as ArrayRef]).unwrap()).unwrap();
            writer.flush().unwrap();
        }
        writer.close().unwrap();
        file
    }

    fn family(value: &str) -> CandidateHint {
        CandidateHint::SourceFamily { value: value.into() }
    }

    /// NAN-3221: an unsigned (L0/M) file's `metadata.log_source` statistics
    /// prune a source-family hint whose every ASCII spelling lies outside a
    /// row group's range; a group holding the value in any spelling is never
    /// pruned.
    #[test]
    fn source_family_statistics_prune_only_groups_that_cannot_hold_the_value() {
        let file = parquet_with_sources(&[
            &[Some("aws_cloudtrail"), Some("conduit_proxy"), Some("windows_sysmon")],
            &[Some("conduit_proxy")],
            &[Some("Audit"), Some("windows_sysmon")],
            &[None, None],
        ]);
        let cache = FileMetadataCache::default();
        let mask = |hints: &[CandidateHint]| cache.evidence(file.path(), "digest-sources", hints, None, false, true, None).unwrap().0;
        // `audit` sorts below `aws_cloudtrail`: only the group holding
        // `Audit` (another spelling) and the all-NULL group (no statistics)
        // are kept.
        assert_eq!(mask(&[family("audit")]), Some(vec![false, false, true, true]));
        assert_eq!(mask(&[family("AUDIT")]), Some(vec![false, false, true, true]));
        // Present values are never pruned, in any spelling.
        assert_eq!(mask(&[family("conduit_proxy")]), Some(vec![true, true, true, true]));
        assert_eq!(mask(&[family("Conduit_PROXY")]), Some(vec![true, true, true, true]));
        assert_eq!(mask(&[family("windows_sysmon")]), Some(vec![true, false, true, true]));
        // An OR keeps a group either branch may match; a non-family branch keeps all.
        assert_eq!(mask(&[CandidateHint::Any { alternatives: vec![family("audit"), family("conduit_proxy")] }]), Some(vec![true, true, true, true]));
        assert_eq!(mask(&[CandidateHint::Any { alternatives: vec![family("audit"), entity("user.name", "x")] }]), Some(vec![true, true, true, true]));
        // A non-ASCII value is undecidable; no family hint, no mask.
        assert_eq!(mask(&[family("audít")]), Some(vec![true, true, true, true]));
        assert_eq!(mask(&[CandidateHint::Keyword { mode: "token".into(), value: "audit".into() }]), None);
        // A value inside a mixed group's range is kept even when absent.
        assert_eq!(mask(&[family("b_absent")]), Some(vec![true, false, true, true]));
    }

    /// Exhaustive negative check of the range rule: for every short value
    /// and every spelling of it placed in a group, that group is kept.
    #[test]
    fn source_family_range_never_prunes_a_group_holding_any_spelling() {
        let values = ["a", "ab", "a_b", "zz", "Mixed", "x9"];
        let spellings = |value: &str| -> Vec<String> {
            let letters = value.char_indices().filter(|(_, c)| c.is_ascii_alphabetic()).map(|(i, _)| i).collect::<Vec<_>>();
            (0..1_u32 << letters.len()).map(|bits| value.char_indices().map(|(i, c)| {
                match letters.iter().position(|l| *l == i) {
                    Some(n) if bits & (1 << n) != 0 => c.to_ascii_uppercase(),
                    Some(_) => c.to_ascii_lowercase(),
                    None => c,
                }
            }).collect()).collect()
        };
        for value in values {
            for held in spellings(value) {
                for (low, high) in [(held.clone(), held.clone()), ("A".to_string(), held.clone()), (held.clone(), "~".to_string()), ("0".into(), "~".into())] {
                    let group = EntityGroup { min: Some(low.as_bytes().into()), max: Some(high.as_bytes().into()), bloom: BloomAt::Absent };
                    for query in spellings(value) {
                        assert!(family_range_may_match(&group, &query), "{query} vs group [{low}, {high}] holding {held}");
                    }
                }
            }
        }
        let missing = EntityGroup { min: None, max: Some(b"a".as_slice().into()), bloom: BloomAt::Absent };
        assert!(family_range_may_match(&missing, "zzz"));
        // Exactness against brute force: every bound pair over a small
        // alphabet, every value; pruned iff no spelling lies in the range.
        let alphabet = ["", "a", "A", "b", "B", "_", "aa", "aB", "Ab", "ba", "a_", "B_", "zz", "Z", "ab_", "AB_"];
        for low in alphabet {
            for high in alphabet {
                if low > high { continue; }
                let group = EntityGroup { min: Some(low.as_bytes().into()), max: Some(high.as_bytes().into()), bloom: BloomAt::Absent };
                for value in ["a", "ab", "AB", "b_", "ba", "z", "a_b", "_"] {
                    let truth = spellings(value).iter().any(|s| low <= s.as_str() && s.as_str() <= high);
                    assert_eq!(family_range_may_match(&group, value), truth, "{value} in [{low:?}, {high:?}]");
                }
            }
        }
    }

    #[test]
    fn cached_footer_is_bound_to_signed_content() {
        let first = parquet_with_users(&[&[Some("alice")]]);
        let cache = FileMetadataCache::default();
        let hint = [entity("user.name", "alice")];
        let initial = cache.evidence(first.path(), "digest-a", &hint, None, false, true, None).unwrap();
        assert_eq!(initial.0, Some(vec![true]));
        assert_eq!(initial.2, vec![(0, 1)]);
        assert_eq!(cache.evidence(first.path(), "digest-a", &hint, None, false, true, None).unwrap(), initial);

        let replacement = parquet_with_users(&[&[Some("bob")], &[Some("carol")]]);
        std::fs::copy(replacement.path(), first.path()).unwrap();
        let updated = cache.evidence(first.path(), "digest-b", &hint, None, false, true, None).unwrap();
        assert_eq!(updated.0, Some(vec![false, false]));
        assert_eq!(updated.2, vec![(0, 1), (1, 2)]);
    }
    /// A part-shaped file: `time` (µs) per row group plus `extra` wide
    /// string columns (an OCSF footer has hundreds).
    fn parquet_with_times(groups: &[&[i64]], extra: usize) -> tempfile::NamedTempFile {
        let mut fields = vec![Field::new(crate::parts::format::TIME_COLUMN, DataType::Int64, false)];
        fields.extend((0..extra).map(|i| Field::new(format!("col_{i:03}"), DataType::Utf8, true)));
        let schema = Arc::new(Schema::new(fields));
        let file = tempfile::NamedTempFile::new().unwrap();
        let props = WriterProperties::builder().set_max_row_group_row_count(Some(1_000)).build();
        let mut writer = ArrowWriter::try_new(file.reopen().unwrap(), schema.clone(), Some(props)).unwrap();
        for times in groups {
            let mut columns: Vec<ArrayRef> = vec![Arc::new(arrow_array::Int64Array::from(times.to_vec()))];
            columns.extend((0..extra).map(|i| Arc::new(StringArray::from(vec![Some(format!("v{i}")); times.len()])) as ArrayRef));
            writer.write(&RecordBatch::try_new(schema.clone(), columns).unwrap()).unwrap();
            writer.flush().unwrap();
        }
        writer.close().unwrap();
        file
    }

    #[test]
    fn non_bloom_selection_reads_the_footer_once_and_opens_none() {
        // NAN-3077: keyword / source / time evidence comes from the summary.
        let file = parquet_with_times(&[&[100, 200], &[300, 400], &[1_000, 1_100]], 2);
        let cache = FileMetadataCache::default();
        let buckets = std::collections::BTreeSet::from([0_i64]);
        let (hint_mask, time_mask, ranges, times) =
            cache.evidence(file.path(), "d", &[keyword("token", "x")], None, false, true, Some(&buckets)).unwrap();
        assert_eq!(hint_mask, None);
        assert_eq!(ranges, vec![(0, 2), (2, 4), (4, 6)]);
        assert_eq!(times, Some(vec![(100, 200), (300, 400), (1_000, 1_100)]));
        // Identical to the reader-based time mask.
        assert_eq!(time_mask, super::time_mask(file.path(), &buckets));
        assert_eq!(cache.entries.lock().unwrap().len(), 0, "no opened footer for a non-bloom selection");
        assert_eq!(cache.summaries(), 1);
        // Served from the summary afterwards: the file itself is no longer read.
        let path = file.path().to_path_buf();
        drop(file);
        assert!(!path.exists());
        assert!(cache.evidence(&path, "d", &[keyword("token", "x")], None, false, false, Some(&buckets)).is_none(), "deleted files must not serve cached metadata");
        // A different signed digest is a different file: a miss.
        assert!(cache.evidence(&path, "other", &[keyword("token", "x")], None, false, false, None).is_none());
    }

    /// NAN-3159: the kept groups' leaf bytes, plus the whole-file charge
    /// only when the mask drops a group (an ill-fitting mask keeps all).
    #[test]
    fn kept_leaf_bytes_keep_the_whole_file_charge_aside_when_groups_drop() {
        let summary = FileSummary {
            ranges: vec![(0, 10), (10, 20), (20, 30)], group_times: None, entities: vec![], entities_located: true,
            column_bytes: ColumnBytes::new(vec![("time".into(), vec![1, 2, 4].into()), ("raw_data".into(), vec![10, 20, 40].into())]),
            source_family: Vec::new(),
            indicators: false,
        };
        let whole = BTreeMap::from([("raw_data".to_string(), 70), ("time".to_string(), 7)]);
        let (kept, aside) = summary.kept_and_whole_leaf_bytes(Some(&[true, false, true]));
        assert_eq!(kept, BTreeMap::from([("raw_data".to_string(), 50), ("time".to_string(), 5)]));
        assert_eq!(aside, Some(whole.clone()));
        for mask in [None, Some(&[true, true, true][..]), Some(&[false, true][..])] {
            assert_eq!(summary.kept_and_whole_leaf_bytes(mask), (whole.clone(), None), "{mask:?}");
        }
    }

    #[test]
    fn summary_cache_rejects_oversized_replacements_and_remains_byte_bounded() {
        let small = Arc::new(FileSummary { ranges: vec![(0, 1)], group_times: None, entities: vec![], entities_located: true, column_bytes: ColumnBytes::default(), source_family: Vec::new(), indicators: false });
        let big = Arc::new(FileSummary { ranges: vec![(0, 1); MAX_SUMMARY_BYTES / 16 + 1], group_times: None, entities: vec![], entities_located: true, column_bytes: ColumnBytes::default(), source_family: Vec::new(), indicators: false });
        let mut cache = SummaryCache::default();
        let key = "signed-digest".to_string();
        cache.insert(key.clone(), small);
        assert!(cache.get(&key).is_some());
        cache.insert(key.clone(), big);
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.bytes, 0);
        assert!(cache.bytes <= MAX_SUMMARY_BYTES);
    }

    #[test]
    fn selections_wider_than_the_open_footer_cap_keep_their_summaries() {
        // The ~26 h cliff: > MAX_OPEN_FOOTERS files meant every footer was
        // re-parsed on every query. Now each is parsed once.
        let files = (0..MAX_OPEN_FOOTERS + 40).map(|i| parquet_with_times(&[&[i as i64]], 0)).collect::<Vec<_>>();
        let cache = FileMetadataCache::default();
        for (i, file) in files.iter().enumerate() {
            let cache_footer = files.len() <= MAX_OPEN_FOOTERS;
            let evidence = cache.evidence(file.path(), &format!("d{i}"), &[keyword("token", "x")], None, false, cache_footer, None).unwrap();
            assert_eq!(evidence.3, Some(vec![(i as i64, i as i64)]));
        }
        assert_eq!(cache.summaries(), files.len());
        let paths = files.iter().map(|file| file.path().to_path_buf()).collect::<Vec<_>>();
        drop(files);
        for (i, path) in paths.iter().enumerate() {
            assert!(cache.evidence(path, &format!("d{i}"), &[keyword("token", "x")], None, false, false, None).is_none(), "GC must invalidate summaries");
        }
        // Bloom evidence still needs the file (and still reads it).
        assert!(cache.evidence(&paths[0], "d0", &[entity("user.name", "bob")], None, false, false, None).is_none());
    }

    #[test]
    fn concurrent_lease_links_and_verified_inode_replacement_reuse_digest_summary() {
        let file = parquet_with_users(&[&[Some("alice")]]);
        let cache = FileMetadataCache::default();
        let first = cache.summary(file.path(), "verified-digest").unwrap();
        let pins = tempfile::tempdir().unwrap();
        for i in 0..100 {
            let pin = pins.path().join(i.to_string());
            std::fs::hard_link(file.path(), &pin).unwrap();
            assert!(Arc::ptr_eq(&first, &cache.summary(&pin, "verified-digest").unwrap()));
            std::fs::remove_file(pin).unwrap();
        }
        let replacement = pins.path().join("refetch");
        std::fs::copy(file.path(), &replacement).unwrap();
        std::fs::rename(&replacement, file.path()).unwrap();
        assert!(Arc::ptr_eq(&first, &cache.summary(file.path(), "verified-digest").unwrap()));
    }

    #[test]
    fn replaced_file_never_inherits_a_cached_footer() {
        let file = parquet_with_users(&[&[Some("alice")]]);
        let replacement = parquet_with_users(&[&[Some("bob"), Some("carol")]]);
        let cache = FileMetadataCache::default();
        let first = cache.summary(file.path(), "same-digest").unwrap();
        assert_eq!(first.ranges, vec![(0, 1)]);
        std::fs::copy(replacement.path(), file.path()).unwrap();
        let second = cache.summary(file.path(), "replacement-digest").unwrap();
        assert_eq!(second.ranges, vec![(0, 2)]);
        assert!(!Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn prewarm_pass_budget_keeps_newest_evidence_and_retires_expired_digests() {
        let newest = parquet_with_users(&[&[Some("alice"), Some("bob")]]);
        let older = parquet_with_users(&[&[Some("carol"), Some("dan")]]);
        let cache = FileMetadataCache::default();
        assert!(cache.prewarm(newest.path(), "new"));
        let size = cache.resident_bloom_bytes("new").unwrap();
        let mut remaining = size;
        assert!(cache.prewarm_with_budget(newest.path(), "new", &mut remaining));
        assert_eq!(remaining, 0);
        assert!(!cache.prewarm_with_budget(older.path(), "old", &mut remaining));
        assert!(cache.has_blooms("new"));
        assert!(!cache.has_blooms("old"));
        cache.retain_blooms(&std::collections::HashSet::new());
        assert_eq!(cache.bloom_stats(), (0, 0));
    }

    /// NAN-4171 (F8): a query-time bloom read is kept, so the next hunt on
    /// any identity path answers from parsed blooms; the answer is the same.
    #[test]
    fn query_time_bloom_reads_are_cached() {
        let file = parquet_with_users(&[&[Some("alice"), Some("bob")], &[Some("carol"), None]]);
        let cache = FileMetadataCache::default();
        assert!(!cache.has_blooms("d"));
        let first = cache.evidence(file.path(), "d", &[entity("user.name", "bob")], None, false, false, None).unwrap().0;
        assert_eq!(first, Some(vec![true, false]));
        assert!(cache.has_blooms("d"), "the hunt left its file's blooms parsed");
        let again = cache.evidence(file.path(), "d", &[entity("user.name", "bob")], None, false, false, None).unwrap().0;
        assert_eq!(again, first);
        let carol = cache.evidence(file.path(), "d", &[entity("user.name", "carol")], None, false, false, None).unwrap().0;
        assert_eq!(carol, Some(vec![false, true]));
        assert_eq!(cache.bloom_stats().0, 1, "one parsed entry per file");
    }

    #[test]
    fn parsed_blooms_reorder_newest_last_and_retain_live() {
        let mut cache = ParsedBloomCache::default();
        let value = || Arc::new(ParsedBlooms { fields: Vec::new(), bytes: 100 });
        for key in ["a", "b", "c"] { assert!(cache.insert(key.into(), value(), 1_000)); }
        cache.order_oldest_first(&["a", "b"]);
        // "c" is unranked (evicted first), then "b", then "a".
        assert!(cache.insert("d".into(), value(), 3 * parsed_bloom_bytes("a", &value())));
        assert!(!cache.contains("c") && cache.contains("a") && cache.contains("b"));
        cache.retain(&["a"].into_iter().collect());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.bytes, parsed_bloom_bytes("a", &value()));
        assert_eq!(cache.order.len(), 1);
    }

    #[test]
    fn parsed_blooms_are_byte_bounded_and_evict_oldest() {
        let mut cache = ParsedBloomCache::default();
        let value = || Arc::new(ParsedBlooms { fields: Vec::new(), bytes: 100 });
        assert!(cache.insert("a".into(), value(), 400));
        assert!(cache.insert("b".into(), value(), 400));
        assert!(cache.get("a").is_some());
        assert!(cache.insert("c".into(), value(), 400));
        assert!(cache.bytes <= 400);
        assert!(cache.get("b").is_none());
        assert!(cache.get("a").is_some());
        assert!(!cache.insert("oversized".into(), Arc::new(ParsedBlooms { fields: Vec::new(), bytes: 401 }), 400));
        assert!(cache.get("a").is_some(), "oversize insert must not evict resident evidence");
    }

    #[test]
    fn summary_entity_evidence_equals_the_footer_path() {
        // NAN-3077: bloom and statistics evidence from the compact summary
        // must decide exactly as the opened footer does.
        let users = parquet_with_users(&[&[Some("JSmith"), Some("alice")], &[Some("bob"), None], &[Some("Carol"), Some("carol")], &[None, None]]);
        let hosts: Vec<String> = (0..40).map(|i| format!("ws-mkt-{i:03}.corp.local")).collect();
        let group = |rest: usize| (0..40).filter(|i| i % 3 == rest).map(|i| Some(hosts[i].as_str())).collect::<Vec<_>>();
        let (a, b, c) = (group(0), group(1), group(2));
        let host_file = parquet_with_path(&["src_endpoint", "hostname"], &[&a, &b, &c]);
        let cases: Vec<(&tempfile::NamedTempFile, Vec<CandidateHint>)> = vec![
            (&users, vec![entity("user.name", "jsmith")]),
            (&users, vec![entity("user.name", "CAROL")]),
            (&users, vec![entity("user.name", "nobody")]),
            (&users, vec![CandidateHint::Any { alternatives: vec![entity("user.name", "bob"), entity("user.name", "alice")] }]),
            (&users, vec![entity("message", "bob")]),
            (&host_file, vec![entity("src_endpoint.hostname", "WS-MKT-025.corp.local")]),
            (&host_file, vec![entity("src_endpoint.hostname", "absent.corp.local")]),
            (&host_file, vec![entity("user.name", "x")]),
        ];
        let cache = FileMetadataCache::default();
        for (index, (file, hints)) in cases.iter().enumerate() {
            let footer = entity_mask(file.path(), hints);
            let summary = cache.evidence(file.path(), &format!("d{}", file.path().display()), hints, None, false, true, None).unwrap().0;
            assert_eq!(summary, footer, "case {index}: {hints:?}");
            assert!(cache.prewarm(file.path(), &format!("d{}", file.path().display())));
            cache.entries.lock().unwrap().clear();
            let warmed = cache.evidence(file.path(), &format!("d{}", file.path().display()), hints, None, false, true, None).unwrap().0;
            assert_eq!(warmed, footer, "parsed blooms survive footer-reader eviction");
        }
        assert_eq!(cache.entries.lock().unwrap().len(), 0, "bloom evidence opened no footer");
    }

    #[test]
    fn bloom_evidence_over_many_files_parses_each_footer_once() {
        let hosts = ["a.corp.local", "b.corp.local"];
        let files = (0..MAX_OPEN_FOOTERS + 20)
            .map(|i| parquet_with_path(&["src_endpoint", "hostname"], &[&[Some(hosts[i % 2])]]))
            .collect::<Vec<_>>();
        let cache = FileMetadataCache::default();
        let hint = [entity("src_endpoint.hostname", "a.corp.local")];
        let mut kept = 0;
        for (i, file) in files.iter().enumerate() {
            let mask = cache.evidence(file.path(), &format!("d{i}"), &hint, None, false, false, None).unwrap().0.unwrap();
            kept += usize::from(mask[0]);
        }
        assert_eq!(kept, files.len() / 2, "exactly the files holding the host are kept");
        assert_eq!(cache.entries.lock().unwrap().len(), 0);
        assert_eq!(cache.summaries(), files.len());
    }

    #[test]
    fn summary_cache_respects_its_byte_bound() {
        let mut cache = SummaryCache::default();
        let big = Arc::new(FileSummary {
            ranges: vec![(0, 1)],
            group_times: None,
            entities: vec![("user.name".into(), vec![EntityGroup { min: Some(vec![b'a'; 100].into()), max: Some(vec![b'z'; 100].into()), bloom: BloomAt::Absent }; 4096])],
            entities_located: true,
            column_bytes: ColumnBytes::default(),
            source_family: Vec::new(),
            indicators: false,
        });
        let per = big.bytes();
        let fits = MAX_SUMMARY_BYTES / per;
        for i in 0..fits + 50 {
            cache.insert(format!("digest-{i}"), big.clone());
            assert!(cache.bytes <= MAX_SUMMARY_BYTES, "insert {i}: {} bytes", cache.bytes);
        }
        assert!(cache.map.len() <= fits);
    }

    /// NAN-4171: a large tenant's 7d window (2,234 wide files, 401 leaves, two
    /// row groups, every identity path with short statistics) stays resident,
    /// so a repeated sweep re-parses no footer.
    #[test]
    fn a_week_of_wide_summaries_stays_resident_across_sweeps() {
        const FILES: usize = 2_234;
        let wide = |i: usize| {
            let columns = (0..401).map(|c| (format!("ocsf.leaf_{c:03}.value").into_boxed_str(), vec![1_000 + i as u32, 2_000].into_boxed_slice())).collect();
            let group = EntityGroup { min: Some(vec![b'a'; 24].into()), max: Some(vec![b'z'; 24].into()), bloom: BloomAt::At(0, 4096) };
            Arc::new(FileSummary {
                ranges: vec![(0, 65_536), (65_536, 131_072)],
                group_times: Some(vec![Some((0, 1)), Some((1, 2))]),
                entities: crate::parts::format::BLOOM_PATHS.iter().map(|path| ((*path).into(), vec![group.clone(); 2])).collect(),
                entities_located: true,
                column_bytes: ColumnBytes::new(columns),
                source_family: vec![group.clone(); 2],
                indicators: false,
            })
        };
        let mut cache = SummaryCache::default();
        for i in 0..FILES { cache.insert(format!("digest-{i}"), wide(i)); }
        assert_eq!(cache.map.len(), FILES);
        assert!(cache.bytes < MAX_SUMMARY_BYTES / 2, "{} bytes", cache.bytes);
        assert_eq!(cache.shared.len(), 1, "one schema, one path list");
        for i in 0..FILES { assert!(cache.get(&format!("digest-{i}")).is_some(), "second sweep, file {i}"); }
    }

    #[test]
    fn column_paths_are_shared_and_charged_once() {
        let columns = || vec![("time".into(), vec![1, 2].into()), ("device.hostname".into(), vec![3, 4].into())];
        let (a, b) = (ColumnBytes::new(columns()), ColumnBytes::new(columns()));
        assert!(Arc::ptr_eq(a.paths.as_ref().unwrap(), b.paths.as_ref().unwrap()));
        assert_eq!(a.iter().collect::<Vec<_>>(), vec![("time", &[1, 2][..]), ("device.hostname", &[3, 4][..])]);
        assert!(ColumnBytes::new(vec![("a".into(), vec![1].into()), ("b".into(), vec![1, 2].into())]).is_empty(), "ragged is no evidence");
        let summary = |column_bytes| Arc::new(FileSummary { ranges: vec![(0, 1), (1, 2)], group_times: None, entities: vec![], entities_located: true, column_bytes, source_family: vec![], indicators: false });
        let (one, two) = (summary(a), summary(b));
        let shared = one.column_bytes.shared().unwrap().1;
        let mut cache = SummaryCache::default();
        cache.insert("one".into(), one.clone());
        assert_eq!(cache.bytes, one.bytes() + shared);
        cache.insert("two".into(), two.clone());
        assert_eq!(cache.bytes, one.bytes() + two.bytes() + shared, "the path list is charged once");
        cache.insert("one".into(), summary(ColumnBytes::default()));
        cache.insert("two".into(), summary(ColumnBytes::default()));
        assert!(cache.shared.is_empty());
        assert_eq!(cache.bytes, 2 * summary(ColumnBytes::default()).bytes(), "released with its last summary");
    }

    #[test]
    fn summary_cache_evicts_the_least_recently_used_at_its_bound() {
        let mut cache = SummaryCache::default();
        let summary = Arc::new(FileSummary { ranges: vec![(0, 1)], group_times: None, entities: Vec::new(), entities_located: true, column_bytes: ColumnBytes::default(), source_family: Vec::new(), indicators: false });
        let key = |i: usize| format!("digest-{i}");
        for i in 0..MAX_FILE_SUMMARIES {
            cache.insert(key(i), summary.clone());
        }
        assert!(cache.get(&key(0)).is_some(), "touch the oldest");
        cache.insert(key(MAX_FILE_SUMMARIES), summary.clone());
        assert!(cache.map.len() <= MAX_FILE_SUMMARIES);
        assert!(cache.get(&key(0)).is_some(), "recently used survives");
        assert!(cache.get(&key(1)).is_none(), "least recently used is evicted");
        assert!(cache.get(&key(MAX_FILE_SUMMARIES)).is_some());
    }

    /// `cargo test -p nanosiem-lake-worker --release footer_parse_cost -- --ignored --nocapture`
    #[test]
    #[ignore = "micro-benchmark"]
    fn footer_parse_cost_against_summary_hits() {
        let groups: Vec<Vec<i64>> = (0..18).map(|g| (0..64).map(|r| g * 1_000 + r).collect()).collect();
        let refs = groups.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let file = parquet_with_times(&refs, 400);
        let rounds = 200;
        let started = std::time::Instant::now();
        for _ in 0..rounds {
            let reader = SerializedFileReader::new(File::open(file.path()).unwrap()).unwrap();
            std::hint::black_box(FileSummary::of(&reader).unwrap());
        }
        let parse = started.elapsed() / rounds;
        let cache = FileMetadataCache::default();
        cache.summary(file.path(), "d").unwrap();
        let started = std::time::Instant::now();
        for _ in 0..rounds {
            std::hint::black_box(cache.evidence(file.path(), "d", &[keyword("token", "x")], None, false, false, None).unwrap());
        }
        let hit = started.elapsed() / rounds;
        let bytes = std::fs::metadata(file.path()).unwrap().len();
        eprintln!("401-column, 18-group footer ({bytes} B file): parse {parse:?} per file, summary hit {hit:?} per file");
    }

    // ---- NAN-3032: v2 block index -------------------------------------

    #[test]
    fn interior_tokens_are_only_the_fully_bounded_ascii_runs() {
        assert!(interior_tokens("dll32").is_empty());
        assert!(interior_tokens("*dll32*").is_empty());
        assert_eq!(interior_tokens(r"*\powershell.exe*"), vec!["powershell"]);
        assert_eq!(interior_tokens(r"C:\Windows\System32\cmd.exe"), vec!["cmd", "system32", "windows"]);
        assert_eq!(interior_tokens("a b c"), vec!["b"]);
        // Next to a wildcard is not a boundary; non-ASCII runs are skipped.
        assert!(interior_tokens("x*mid.y").is_empty());
        assert!(interior_tokens("x.Ümlaut.y").is_empty());
        assert_eq!(interior_tokens("x.MiXeD.y"), vec!["mixed"]);
    }

    #[test]
    fn a_wildcard_keyword_never_requires_its_partial_token() {
        // Live bug (2026-09-29): `svch*` token-pruned every file and
        // returned 0 over svchost data.
        let bytes = index(&["svchost.exe started", "other"]);
        assert_eq!(token_mask(Some(&bytes), 2, &[keyword("token", "svch*")]), Some(vec![true; 2]));
        assert_eq!(token_mask(Some(&bytes), 2, &[keyword("token", "*vchos*")]), Some(vec![true; 2]));
        assert_eq!(token_mask(Some(&bytes), 2, &[keyword("token", "svchost")]), Some(vec![true, false]));
        assert_eq!(token_mask(Some(&bytes), 2, &[keyword("token", "*.svchost.*")]), Some(vec![true, false]));
        assert!(has_progressive_index_hint(&[keyword("token", "svch*")]), "v4 trigrams provide candidate evidence; legacy indexes still keep all rows");
    }

    /// splitmix64: a deterministic generator for the property tests.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
            &items[self.below(items.len())]
        }
    }

    const WORDS: &[&str] = &[
        "powershell", "PowerShell", "svchost", "rundll32", "cmd", "exe", "System32", "Windows", "mimikatz",
        "sekurlsa", "10", "0", "1", "443", "admin", "Admin", "corp", "local", "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "GET", "index", "html", "Ümlaut", "naïve", "x", "q9", "logon", "LOGON", "failed", "user_1",
    ];
    const SEPARATORS: &[&str] = &[" ", ".", "-", "_", "/", "\\", ":", "@", ",", "=", "|", "™", "—", " \"", "("];

    /// A rare token: one of 400 ids, so most appear in a few rows only.
    fn rare(rng: &mut Rng) -> String {
        format!("id{:x}", 0xa000 + rng.below(400))
    }

    fn random_text(rng: &mut Rng) -> String {
        let words = 1 + rng.below(8);
        let mut text = String::new();
        for i in 0..words {
            if i > 0 || rng.below(4) == 0 {
                text.push_str(rng.pick(SEPARATORS));
            }
            if rng.below(10) == 0 {
                text.push_str(&rare(rng));
            } else {
                text.push_str(rng.pick(WORDS));
            }
        }
        if rng.below(4) == 0 {
            text.push_str(rng.pick(SEPARATORS));
        }
        text
    }

    /// ClickHouse `splitByNonAlpha` over ClickHouse `lower` (ASCII only):
    /// separators are ASCII non-alphanumerics, other bytes are token bytes.
    fn ch_tokens(text: &str) -> Vec<String> {
        text.to_ascii_lowercase()
            .split(|c: char| c.is_ascii() && !c.is_ascii_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// `iLike` with `%`/`_` wildcards, case-folded both sides.
    fn ilike(text: &str, pattern: &str) -> bool {
        fn go(t: &[char], p: &[char]) -> bool {
            match p.split_first() {
                None => t.is_empty(),
                Some(('%', rest)) => (0..=t.len()).any(|i| go(&t[i..], rest)),
                Some(('_', rest)) => !t.is_empty() && go(&t[1..], rest),
                Some((c, rest)) => t.first() == Some(c) && go(&t[1..], rest),
            }
        }
        let t = text.to_lowercase().chars().collect::<Vec<_>>();
        let p = pattern.to_lowercase().chars().collect::<Vec<_>>();
        go(&t, &p)
    }

    /// What the compiled SQL decides for one hint over one row (the
    /// reference; see `bare_keyword_predicate_for_column`).
    fn reference(text: &str, hint: &CandidateHint) -> bool {
        match hint {
            CandidateHint::Keyword { mode, value } if mode == "token" => {
                let needle = value.to_lowercase();
                if needle.contains(['*', '?']) {
                    ilike(text, &needle.replace('*', "%").replace('?', "_"))
                } else {
                    let row = ch_tokens(text);
                    let wanted = ch_tokens(&needle);
                    if wanted.is_empty() {
                        text.to_lowercase().contains(&needle)
                    } else {
                        wanted.iter().all(|t| row.contains(t))
                    }
                }
            }
            CandidateHint::Keyword { value, .. } => text.to_lowercase().contains(&value.to_lowercase()),
            // Rows here are one text standing for every field: a hash-array
            // equality holds when the value is one of the row's whole tokens.
            CandidateHint::Entity { value, .. } => ch_tokens(text).contains(&value.to_lowercase()),
            CandidateHint::Any { alternatives } => alternatives.iter().any(|h| reference(text, h)),
            _ => true,
        }
    }

    fn random_hint(rng: &mut Rng, rows: &[String], depth: usize) -> CandidateHint {
        match rng.below(if depth > 0 { 8 } else { 7 }) {
            0 => keyword("token", rng.pick(WORDS)),
            6 => {
                let id = rare(rng);
                match rng.below(3) {
                    0 => keyword("token", &id),
                    1 => keyword("contains", &format!(".{id}.")),
                    _ => entity("file.hashes.value", &id),
                }
            }
            1 => {
                let a = rng.pick(WORDS).to_string();
                keyword("token", &format!("{a}{}{}", rng.pick(SEPARATORS), rng.pick(WORDS)))
            }
            2 | 3 => {
                // A substring of a real row (so matches exist), sometimes as a
                // wildcard keyword, sometimes as a contains guard.
                let row = rng.pick(rows).chars().collect::<Vec<_>>();
                let start = rng.below(row.len());
                let end = start + 1 + rng.below(row.len() - start);
                let piece = row[start..end].iter().collect::<String>();
                if rng.below(2) == 0 { keyword("contains", &piece) } else { keyword("token", &format!("*{piece}*")) }
            }
            4 => {
                let word = rng.pick(WORDS);
                let cut = 1 + rng.below(word.chars().count());
                keyword("token", &format!("{}*", word.chars().take(cut).collect::<String>()))
            }
            5 => keyword("regex_guard", rng.pick(WORDS)),
            _ => CandidateHint::Any { alternatives: (0..2).map(|_| random_hint(rng, rows, depth - 1)).collect() },
        }
    }

    fn v2_index(rows: &[String], group_rows: usize, block_rows: u32) -> (Vec<u8>, Vec<(u64, u64)>) {
        build_index(rows, group_rows, block_rows, false)
    }

    fn build_index(rows: &[String], group_rows: usize, block_rows: u32, v4: bool) -> (Vec<u8>, Vec<(u64, u64)>) {
        let mut groups = Vec::new();
        let mut ranges = Vec::new();
        for (g, chunk) in rows.chunks(group_rows).enumerate() {
            let mut builder = if v4 { TokenGroupBuilder::with_trigrams(block_rows) } else { TokenGroupBuilder::with_blocks(block_rows) };
            for (i, text) in chunk.iter().enumerate() {
                builder.add_row_at((g * group_rows + i) as i64);
                builder.add_text(text);
            }
            groups.push(builder.finish().unwrap());
            ranges.push(((g * group_rows) as u64, (g * group_rows + chunk.len()) as u64));
        }
        (encode_token_index(&groups).unwrap(), ranges)
    }

    /// Rows the selection would hand chDB (before the SQL recheck).
    fn candidate_rows(bytes: &[u8], ranges: &[(u64, u64)], hints: &[CandidateHint]) -> Vec<bool> {
        let total = ranges.last().unwrap().1 as usize;
        let (mask, fine) = token_evidence(Some(bytes), ranges.len(), hints);
        let mut keep = vec![false; total];
        for (g, (start, end)) in ranges.iter().enumerate() {
            if mask.as_ref().is_some_and(|mask| !mask[g]) {
                continue;
            }
            match fine.as_ref().and_then(|fine| fine[g].as_ref()) {
                Some(runs) => {
                    for (s, e, (tmin, tmax)) in runs {
                        for row in (start + s)..(start + e) {
                            keep[row as usize] = true;
                            // Run times bound the rows they cover.
                            assert!((row as i64) >= *tmin && (row as i64) <= *tmax);
                        }
                    }
                }
                None => keep[*start as usize..*end as usize].iter_mut().for_each(|k| *k = true),
            }
        }
        keep
    }

    #[test]
    fn signed_v4_candidates_preserve_rows_counts_and_masks_in_120_and_chains() {
        let rows = ["PowerShell.EXE", "rundll32.exe", "svchost.exe", "Überabc", "", "éxéc", "POWERSHELL", "dll32_suffix"]
            .iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let groups = rows.iter().enumerate().map(|(i, row)| {
            let mut builder = TokenGroupBuilder::with_trigrams(4);
            builder.add_row_at(i as i64);
            builder.add_text(row);
            builder.add_body(row);
            builder.finish().unwrap()
        }).collect::<Vec<_>>();
        let bytes = encode_token_index(&groups).unwrap();
        let ranges = (0..rows.len()).map(|i| (i as u64, i as u64 + 1)).collect::<Vec<_>>();
        // A substring with no complete token now excludes groups, while the
        // v3 reader path conservatively keeps them.
        let hint = keyword("contains", "dll32");
        let keep = candidate_rows(&bytes, &ranges, &[hint]);
        assert!(keep.iter().filter(|k| **k).count() < rows.len());
        assert!(keep[1] && keep[7]);
        let legacy = groups.iter().cloned().map(|mut g| { g.trigrams = None; g }).collect::<Vec<_>>();
        let legacy_bytes = encode_token_index(&legacy).unwrap();
        let before = candidate_rows(&legacy_bytes, &ranges, &[keyword("contains", "dll32")]);
        assert!(before.iter().all(|k| *k));
        eprintln!("dll32 candidate groups: v3 {} -> v4 {}", before.iter().filter(|k| **k).count(), keep.iter().filter(|k| **k).count());
        let pool = [keyword("contains", "dll32"), keyword("token", "*shell*"), keyword("regex_guard", "svch"),
            keyword("contains", "éxé"), keyword("contains", "ab"), keyword("contains", ""),
            CandidateHint::Any { alternatives: vec![keyword("contains", "dll32"), keyword("contains", "shell")] }];
        let mut rng = Rng(0x3077);
        for _ in 0..120 {
            let mut chain = Vec::new();
            let mut parent = vec![true; rows.len()];
            for _ in 0..4 {
                chain.push(rng.pick(&pool).clone());
                let keep = candidate_rows(&bytes, &ranges, &chain);
                assert!(keep.iter().zip(&parent).all(|(k, p)| !k || *p));
                let expected = rows.iter().enumerate().filter(|(_, row)| chain.iter().all(|h| reference(row, h)))
                    .map(|(i, _)| (i, i % 3)).collect::<Vec<_>>(); // fixture authorization masks
                let actual = rows.iter().enumerate().filter(|(i, row)| keep[*i] && chain.iter().all(|h| reference(row, h)))
                    .map(|(i, _)| (i, i % 3)).collect::<Vec<_>>();
                assert_eq!(actual, expected, "{chain:?}");
                assert_eq!(actual.len(), expected.len());
                parent = keep;
            }
        }
        let mut corrupt = bytes;
        corrupt[50] ^= 1;
        assert!(token_evidence(Some(&corrupt), rows.len(), &pool).0.is_none());
    }

    #[test]
    fn block_index_never_drops_a_matching_row() {
        let mut rng = Rng(0x3032);
        let (mut checked, mut pruned_rows, mut matched) = (0_usize, 0_usize, 0_usize);
        for round in 0..12 {
            let rows = (0..600 + rng.below(900)).map(|_| random_text(&mut rng)).collect::<Vec<_>>();
            let block_rows = [4_u32, 16, 64][round % 3];
            let (bytes, ranges) = build_index(&rows, 97 + rng.below(200), block_rows, round % 2 == 0);
            for _ in 0..150 {
                let hints = (0..1 + rng.below(2)).map(|_| random_hint(&mut rng, &rows, 2)).collect::<Vec<_>>();
                let keep = candidate_rows(&bytes, &ranges, &hints);
                for (row, text) in rows.iter().enumerate() {
                    let matches = hints.iter().all(|hint| reference(text, hint));
                    if matches {
                        matched += 1;
                        assert!(keep[row], "false negative: row {row} {text:?} hints {hints:?}");
                    } else if !keep[row] {
                        pruned_rows += 1;
                    }
                }
                checked += 1;
            }
        }
        // The property is only meaningful if the index actually prunes.
        assert!(matched > 10_000 && pruned_rows > 50_000, "checked {checked}, matched {matched}, pruned {pruned_rows}");
    }

    /// Actual Parquet fixture sizes under the candidate mask, independent of
    /// native scan heuristics. This proves monotonic candidate work, not wall
    /// time or total native bytes (additional predicate columns cost bytes).
    #[test]
    fn and_chains_never_increase_fixture_candidate_work() {
        let fixtures = (0..8).map(|part| {
            let host = format!("ws-{part}.corp.local");
            let other = format!("ws-{}.corp.local", (part + 1) % 8);
            let file = parquet_with_path(&["src_endpoint", "hostname"], &[
                &[Some(&host), Some(&host)], &[Some(&other), Some(&other)],
                &[Some(&host), Some(&other)], &[None, None],
            ]);
            let bytes = index(&["powershell error", "powershell success", "curl error", "curl success"]);
            (file, bytes)
        }).collect::<Vec<_>>();
        let hints = vec![
            entity("src_endpoint.hostname", "ws-0.corp.local"),
            entity("src_endpoint.hostname", "ws-1.corp.local"),
            keyword("token", "powershell"), keyword("token", "error"),
            keyword("token", "curl"),
            // Unsupported fields must keep candidates, even inside an OR.
            entity("unmapped.Image", "powershell.exe"),
            entity("http_response.code", "500"),
            CandidateHint::Any { alternatives: vec![keyword("token", "error"), keyword("token", "success")] },
        ];
        let cache = FileMetadataCache::default();
        let work = |chain: &[CandidateHint]| {
            let (mut parts, mut groups, mut bytes) = (0_u64, 0_u64, 0_u64);
            for (file, tokens) in &fixtures {
                let reader = SerializedFileReader::new(file.reopen().unwrap()).unwrap();
                let count = reader.metadata().num_row_groups();
                let (entity, _, _, _) = cache.evidence(file.path(), &file.path().display().to_string(), chain,
                    Some(tokens), needs_combined(chain), true, None).unwrap();
                let mask = and(token_mask(Some(tokens), count, chain), entity);
                let mut kept = 0;
                for (group, metadata) in reader.metadata().row_groups().iter().enumerate() {
                    if mask.as_ref().is_none_or(|mask| mask[group]) {
                        kept += 1;
                        groups += 1;
                        bytes += metadata.columns().iter().map(|column| column.compressed_size() as u64).sum::<u64>();
                    }
                }
                parts += u64::from(kept > 0);
            }
            (parts, groups, bytes)
        };
        let mut rng = Rng(0x3077);
        for _ in 0..512 {
            let chain = (0..3).map(|_| rng.pick(&hints).clone()).collect::<Vec<_>>();
            let parent = work(&chain[..1]);
            let child = work(&chain[..2]);
            let grandchild = work(&chain);
            for (broad, narrow) in [(parent, child), (child, grandchild)] {
                assert!(narrow.0 <= broad.0 && narrow.1 <= broad.1 && narrow.2 <= broad.2,
                    "candidate work grew: {broad:?} -> {narrow:?}, {chain:?}");
            }
        }
        let chain = [keyword("token", "powershell"), keyword("token", "error"),
            entity("src_endpoint.hostname", "ws-0.corp.local")];
        let counters = [work(&chain[..1]), work(&chain[..2]), work(&chain)];
        println!("fixture candidate (parts, row groups, compressed bytes): {counters:?}");
        assert_eq!((counters[0].0, counters[0].1), (8, 16));
        assert_eq!((counters[1].0, counters[1].1), (8, 8));
        assert_eq!((counters[2].0, counters[2].1), (1, 1));
        // Every true host match must survive the combined keyword evidence.
        let host = [entity("src_endpoint.hostname", "ws-0.corp.local")];
        let (mask, _, _, _) = cache.evidence(fixtures[0].0.path(), &fixtures[0].0.path().display().to_string(), &host, None, false, true, None).unwrap();
        assert!(mask.unwrap()[0]);
    }

    /// Recheck the full predicate over real multi-column Parquet fixtures after
    /// pruning, and compare row identities with a full scan. Unsupported paths
    /// deliberately participate: absence of index evidence must never exclude.
    #[test]
    fn and_chain_results_equal_unpruned_fixture_scan() {
        fixture_result_parity(false);
    }

    #[test]
    #[ignore = "requires NANO_CHDB_LIBRARY_PATH and NANO_CHDB_LIBRARY_SHA256"]
    fn and_chain_results_equal_unpruned_native_scan() {
        fixture_result_parity(true);
    }

    fn fixture_result_parity(native: bool) {
        use arrow_json::reader::infer_json_schema_from_seekable;
        use arrow_json::ReaderBuilder;
        use std::io::Cursor;
        let runtime = native.then(|| crate::native::NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap());
        // chDB owns process-global state; keep its library loaded through exit,
        // matching the existing native integration fixtures.
        if let Some(runtime) = &runtime { std::mem::forget(runtime.clone()); }
        let connection = runtime.as_ref().map(|runtime| runtime.connect(&[]).unwrap());
        let mut fixtures = Vec::new();
        for part in 0..8 {
            let rows = (0..16).map(|row| serde_json::json!({
                "id": part * 16 + row,
                "metadata": {"log_source": if part % 2 == 0 { "windows_sysmon" } else { "linux" }},
                "device": {"hostname": if row % 3 == 0 { "ws-support-115.corp.local" } else { "other" }},
                "src_endpoint": {"hostname": if part == 0 { "ws-mkt-068.corp.local" } else { "other" }},
                "user": {"name": if row % 2 == 0 { "Admin" } else { "guest" }},
                "ext": serde_json::json!({"Image": if row % 4 == 0 { "PowerShell.exe" } else { "curl" }}).to_string(),
                "severity": if row % 2 == 0 { "High" } else { "low" },
                "class_uid": if part % 2 == 0 { 4001 } else { 1007 },
                "raw_data": if row % 2 == 0 { "powershell error" } else { "curl success" }
            })).collect::<Vec<_>>();
            let mut input = Vec::new();
            for row in &rows {
                serde_json::to_writer(&mut input, row).unwrap();
                input.push(b'\n');
            }
            let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(&input), None).unwrap();
            let reader = ReaderBuilder::new(Arc::new(schema)).with_batch_size(4).build(Cursor::new(input)).unwrap();
            let file = tempfile::NamedTempFile::new().unwrap();
            let mut writer = None;
            for batch in reader {
                let batch = batch.unwrap();
                let writer = writer.get_or_insert_with(|| ArrowWriter::try_new(file.reopen().unwrap(), batch.schema(), None).unwrap());
                writer.write(&batch).unwrap();
                writer.flush().unwrap();
            }
            writer.unwrap().close().unwrap();
            let texts = rows.iter().map(|r| r["raw_data"].as_str().unwrap().to_string()).collect::<Vec<_>>();
            let (tokens, _) = v2_index(&texts, 4, 4);
            fixtures.push((file, tokens, rows));
        }
        let hints = vec![
            entity("metadata.log_source", "windows_sysmon"),
            entity("device.hostname", "ws-support-115.corp.local"),
            entity("src_endpoint.hostname", "WS-MKT-068.corp.local"),
            entity("user.name", "ADMIN"), entity("ext.Image", "powershell.exe"),
            entity("device.hostname", "absent"), keyword("token", "powershell"),
            entity("severity", "HIGH"), entity("class_uid", "4001"),
        ];
        let matches = |row: &serde_json::Value, hint: &CandidateHint| match hint {
            CandidateHint::Entity { source_path, value } => {
                let ext: serde_json::Value = serde_json::from_str(row["ext"].as_str().unwrap()).unwrap();
                let found = if let Some(key) = source_path.strip_prefix("ext.") {
                    &ext[key]
                } else {
                    source_path.split('.').fold(row, |v, key| &v[key])
                };
                found.as_str().map_or_else(|| found.as_i64().is_some_and(|v| v.to_string() == *value), |v| v.eq_ignore_ascii_case(value))
            }
            CandidateHint::Keyword { value, .. } => row["raw_data"].as_str().unwrap().split_whitespace().any(|word| word.eq_ignore_ascii_case(value)),
            _ => panic!("unexpected fixture hint"),
        };
        let cache = FileMetadataCache::default();
        let mut rng = Rng(0x3077);
        let mut nonempty = 0;
        let token_files = fixtures.iter().map(|(_, tokens, _)| {
            use std::io::Write;
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(tokens).unwrap();
            file
        }).collect::<Vec<_>>();
        let token_cache = super::super::token_cache::TokenCache::default();
        for round in 0..if native { 122 } else { 514 } {
            let chain = if round < 2 {
                vec![hints[0].clone(), hints[round + 1].clone()]
            } else {
                (0..3).map(|_| rng.pick(&hints).clone()).collect::<Vec<_>>()
            };
            for length in 1..=chain.len() {
                let chain = &chain[..length];
                let (mut full, mut pruned) = (Vec::new(), Vec::new());
                for ((file, tokens, rows), token_file) in fixtures.iter().zip(&token_files) {
                    use sha2::Digest;
                    let digest = format!("{:x}", sha2::Sha256::digest(tokens));
                    let groups = SerializedFileReader::new(file.reopen().unwrap()).unwrap().metadata().num_row_groups();
                    let cold_tokens = super::super::token_cache::TokenCache::default().evidence(token_file.path(), &digest, groups, chain);
                    let warm_tokens = token_cache.evidence(token_file.path(), &digest, groups, chain);
                    assert_eq!(cold_tokens, warm_tokens, "cached predicate evidence must equal a fresh decode");
                    assert_eq!(warm_tokens.0, token_mask(Some(tokens), groups, chain));
                    let cold = FileMetadataCache::default().evidence(file.path(), &file.path().display().to_string(), chain, Some(tokens), needs_combined(chain), true, None).unwrap();
                    let warm = cache.evidence(file.path(), &file.path().display().to_string(), chain, Some(tokens), needs_combined(chain), true, None).unwrap();
                    assert_eq!(cold, warm, "cold/warm masks, ranges and counts must agree");
                    let decoded = token_cache.get(token_file.path(), &digest).unwrap();
                    assert_eq!(warm, cache.evidence_of_tokens(file.path(), &file.path().display().to_string(), chain, Some(&decoded), needs_combined(chain), true, None).unwrap());
                    let (entities, _, ranges, _) = warm;
                    let mask = and(token_mask(Some(tokens), ranges.len(), chain), entities);
                    if let Some(connection) = &connection {
                        let predicate = chain.iter().map(|hint| match hint {
                            CandidateHint::Entity { source_path, value } => {
                                let column = if let Some(key) = source_path.strip_prefix("ext.") {
                                    format!("JSONExtractString(ext, '{key}')")
                                } else { format!("toString(\"{source_path}\")") };
                                format!("lower({column}) = '{}'", value.to_lowercase())
                            },
                            CandidateHint::Keyword { value, .. } => format!("hasToken(lower(raw_data), '{value}')"),
                            _ => unreachable!(),
                        }).collect::<Vec<_>>().join(" AND ");
                        let kept = ranges.iter().enumerate().filter(|(group, _)| mask.as_ref().is_none_or(|m| m[*group]))
                            .map(|(_, (start, end))| format!("(id % 16 >= {start} AND id % 16 < {end})"))
                            .collect::<Vec<_>>();
                        let kept = if kept.is_empty() { "0".to_string() } else { kept.join(" OR ") };
                        let scan = |guard: &str| {
                            let sql = format!("SELECT id FROM file('{}', Parquet) WHERE ({predicate}) AND ({guard}) ORDER BY id", file.path().display());
                            let output = connection.query_with_params(&sql, "JSONEachRow", &[]).unwrap();
                            String::from_utf8(output.data).unwrap().lines().map(|line| {
                                serde_json::from_str::<serde_json::Value>(line).unwrap()["id"].as_u64().unwrap()
                            }).collect::<Vec<_>>()
                        };
                        full.extend(scan("1"));
                        pruned.extend(scan(&kept));
                    } else {
                        for (group, (start, end)) in ranges.iter().enumerate() {
                            for row in &rows[*start as usize..*end as usize] {
                                if chain.iter().all(|hint| matches(row, hint)) {
                                    full.push(row["id"].as_u64().unwrap());
                                    if mask.as_ref().is_none_or(|m| m[group]) {
                                        pruned.push(row["id"].as_u64().unwrap());
                                    }
                                }
                            }
                        }
                    }
                }
                nonempty += usize::from(!full.is_empty());
                assert_eq!(pruned, full, "result mismatch for {chain:?}");
                if round < 2 { assert!(!full.is_empty(), "live regression shape must match"); }
            }
        }
        assert!(nonempty > if native { 50 } else { 500 });
    }

    #[test]
    fn fine_blocks_select_only_the_rare_rows_and_leave_common_tokens_whole() {
        let rows = (0..8_192)
            .map(|i| if i == 5_000 { "needle powershell".to_string() } else { format!("powershell noise {}", i % 50) })
            .collect::<Vec<_>>();
        let (bytes, _) = v2_index(&rows, 4_096, 1_024);
        let (mask, fine) = token_evidence(Some(&bytes), 2, &[keyword("token", "needle")]);
        assert_eq!(mask, Some(vec![false, true]));
        let fine = fine.unwrap();
        assert_eq!(fine[1], Some(vec![(0, 1_024, (4_096, 5_119))]));
        // A common token decides nothing below the group.
        let (_, fine) = token_evidence(Some(&bytes), 2, &[keyword("token", "powershell")]);
        assert_eq!(fine.unwrap(), vec![None, None]);
        // AND with a common token keeps the rare token's block.
        let (_, fine) = token_evidence(Some(&bytes), 2, &[keyword("token", "needle"), keyword("token", "powershell")]);
        assert_eq!(fine.unwrap()[1], Some(vec![(0, 1_024, (4_096, 5_119))]));
        // A token in every other block is too dense: the group is read whole.
        let dense = (0..4_096).map(|i| if (i / 1_024) % 2 == 0 { "dense".to_string() } else { "x".to_string() }).collect::<Vec<_>>();
        let (bytes, _) = v2_index(&dense, 4_096, 1_024);
        assert_eq!(token_evidence(Some(&bytes), 1, &[keyword("token", "dense")]).1.unwrap(), vec![None]);
        // An OR with an undecidable branch decides nothing below the group.
        let (bytes, _) = v2_index(&rows, 4_096, 1_024);
        let any = CandidateHint::Any { alternatives: vec![keyword("token", "needle"), entity("user.name", "bob")] };
        assert_eq!(token_evidence(Some(&bytes), 2, &[any]).1.unwrap(), vec![None, None]);
        // v1 bytes carry no block section.
        assert_eq!(token_evidence(Some(&index(&["needle"])), 1, &[keyword("token", "needle")]).1, None);
    }

    #[test]
    fn v2_index_round_trips_and_still_answers_v1_questions() {
        let rows = (0..3_000).map(|i| format!("event {i} mimikatz{}", i % 7)).collect::<Vec<_>>();
        let (bytes, _) = v2_index(&rows, 1_000, 256);
        assert_eq!(&bytes[..8], b"NANOTKI2");
        let groups = decode_token_index(&bytes).unwrap();
        assert_eq!(groups.len(), 3);
        assert!(groups.iter().all(|g| g.blocks.as_ref().is_some_and(|b| b.blocks() == 4)));
        assert_eq!(encode_token_index(&groups).unwrap(), bytes);
        assert_eq!(token_mask(Some(&bytes), 3, &[keyword("token", "2500")]), Some(vec![false, false, true]));
        let mut corrupt = bytes.clone();
        let at = corrupt.len() / 2;
        corrupt[at] ^= 1;
        assert!(decode_token_index(&corrupt).is_err());
        // Mixing v1 and v2 groups is refused.
        let mut mixed = groups.clone();
        mixed[1].blocks = None;
        assert!(encode_token_index(&mixed).is_err());
    }
}

/// Per-field evidence verified against the signed record. Unknown fields,
/// case variants, malformed bitsets and missing groups always keep rows.
pub type EntityBlooms = std::collections::BTreeMap<String, Vec<Option<String>>>;

/// NAN-3165: decode only the `wanted` fields of an entity bloom sidecar (hex
/// for every field x row group); the rest are skipped with `IgnoredAny`. A
/// field left out is absent, which [`entity_summary_mask`] keeps.
pub fn decode_entity_blooms(bytes: &[u8], wanted: &std::collections::BTreeSet<String>) -> Option<EntityBlooms> {
    use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
    struct Projected<'a>(&'a std::collections::BTreeSet<String>);
    impl<'de> DeserializeSeed<'de> for Projected<'_> {
        type Value = EntityBlooms;
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for Projected<'_> {
        type Value = EntityBlooms;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str("entity blooms") }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut out = EntityBlooms::new();
            while let Some(path) = map.next_key::<String>()? {
                if self.0.contains(&path) {
                    let groups = map.next_value::<Vec<Option<String>>>()?;
                    out.insert(path, groups);
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(out)
        }
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = Projected(wanted).deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    Some(value)
}

/// NAN-3694: an entity sidecar may also hold, per row group, a bloom over
/// the ASCII-lowercased values of a mixed-case identity path under
/// `lower:<path>`. It answers a case-insensitive equality with one probe of
/// the lowercased literal, whatever its length (the raw bloom gives up past
/// 8 letters). An absent folded key is today's behavior, never a prune.
/// A group entry of [`FOLDED_SAME_AS_RAW`] says every stored value of that
/// group is already lowercase, so the raw bloom probed with the lowercased
/// literal is exact (and the folded bitset is not repeated).
pub const FOLDED_BLOOM_PREFIX: &str = "lower:";

/// Folded group entry: the group's raw bloom already holds the folded values.
pub const FOLDED_SAME_AS_RAW: &str = "=";

/// The sidecar key of `path`'s folded bloom.
pub fn folded_bloom_key(path: &str) -> String {
    format!("{FOLDED_BLOOM_PREFIX}{path}")
}

/// Identity paths whose sidecar may carry a folded bloom: bloom paths that
/// are not compared raw (an ingest-lowercased path's raw bloom is already
/// exact) and not the uid.
pub fn foldable(path: &str) -> bool {
    path != crate::parts::format::UID_PATH
        && crate::parts::format::BLOOM_PATHS.contains(&path)
        && !INGEST_LOWERCASED_BLOOM_PATHS.contains(&path)
}

/// Whether some hint can be decided only by folded evidence (a foldable
/// path whose value has too many letters to enumerate its spellings).
pub fn needs_folded_blooms(hints: &[CandidateHint]) -> bool {
    hints.iter().any(|hint| match hint {
        CandidateHint::Entity { source_path, value } => {
            foldable(source_path) && value.is_ascii() && spellings_for(source_path, value).is_none()
        }
        CandidateHint::Any { alternatives } => needs_folded_blooms(alternatives),
        _ => false,
    })
}

/// The sidecar keys a query decodes: each hinted field and, for a foldable
/// one, its folded bloom.
pub fn entity_bloom_fields(hints: &[CandidateHint]) -> std::collections::BTreeSet<String> {
    let mut fields = crate::parts::entity_locators::hinted_fields(hints);
    let folded = fields.iter().filter(|path| foldable(path)).map(|path| folded_bloom_key(path)).collect::<Vec<_>>();
    fields.extend(folded);
    fields
}

/// Fetch a sidecar only when at least one hint can actually use its evidence.
pub fn uses_entity_sidecars(hints: &[CandidateHint]) -> bool {
    hints.iter().any(|hint| match hint {
        CandidateHint::Entity { source_path, value } => source_path != crate::parts::format::UID_PATH
            && crate::parts::format::BLOOM_PATHS.contains(&source_path.as_str())
            && (spellings_for(source_path, value).is_some() || (foldable(source_path) && value.is_ascii())),
        CandidateHint::Any { alternatives } => uses_entity_sidecars(alternatives),
        _ => false,
    })
}

/// One row group's bitset under `key`, when well-formed.
fn sidecar_bloom(blooms: &EntityBlooms, key: &str, groups: usize, group: usize) -> Option<Vec<u8>> {
    blooms.get(key).filter(|values| values.len() == groups)
        .and_then(|values| values[group].as_ref())
        .and_then(|encoded| hex::decode(encoded).ok())
        .filter(|bytes| bytes.len() >= 32 && bytes.len().is_power_of_two())
}

pub fn entity_summary_mask(blooms: Option<&EntityBlooms>, groups: usize, hints: &[CandidateHint]) -> Mask {
    let blooms = blooms?;
    fn keep(blooms: &EntityBlooms, groups: usize, group: usize, hint: &CandidateHint) -> bool {
        match hint {
            CandidateHint::Entity { source_path, value } => {
                if !crate::parts::format::BLOOM_PATHS.contains(&source_path.as_str()) { return true; }
                // NAN-3694: folded evidence decides a foldable path in one
                // probe; without it (older sidecars) fall through unchanged.
                if foldable(source_path) && value.is_ascii() {
                    let folded = folded_bloom_key(source_path);
                    let lowered = value.to_ascii_lowercase();
                    let same_as_raw = blooms.get(&folded).filter(|values| values.len() == groups)
                        .is_some_and(|values| values[group].as_deref() == Some(FOLDED_SAME_AS_RAW));
                    let bytes = if same_as_raw { sidecar_bloom(blooms, source_path, groups, group) } else { sidecar_bloom(blooms, &folded, groups, group) };
                    if let Some(bytes) = bytes {
                        return Sbbf::new(&bytes).check(lowered.as_bytes());
                    }
                }
                let Some(variants) = spellings_for(source_path, value) else { return true };
                let bytes = sidecar_bloom(blooms, source_path, groups, group);
                bytes.is_none_or(|bytes| {
                    let bloom = Sbbf::new(&bytes);
                    variants.iter().any(|value| bloom.check(value.as_slice()))
                })
            }
            CandidateHint::Any { alternatives } => alternatives.is_empty()
                || alternatives.iter().any(|hint| keep(blooms, groups, group, hint)),
            _ => true,
        }
    }
    Some((0..groups).map(|group| hints.iter().all(|hint| keep(blooms, groups, group, hint))).collect())
}

/// UID evidence from a sidecar verified against the signed record. Legacy or malformed evidence
/// cannot exclude a row group.
pub fn uid_summary_mask(blooms: Option<&[Option<String>]>, groups: usize, hints: &[CandidateHint]) -> Mask {
    let id = hints.iter().find_map(|hint| match hint {
        CandidateHint::Entity { source_path, value } if source_path == crate::parts::format::UID_PATH => Some(value),
        _ => None,
    })?;
    let blooms = blooms.filter(|blooms| blooms.len() == groups)?;
    Some(blooms.iter().map(|encoded| {
        encoded.as_ref().and_then(|encoded| hex::decode(encoded).ok())
            .filter(|bytes| bytes.len() >= 32 && bytes.len().is_power_of_two())
            .is_none_or(|bytes| Sbbf::new(&bytes).check(id.as_str()))
    }).collect())
}

#[cfg(test)]
mod uid_summary_tests {
    use super::*;

    #[test]
    fn entity_sidecar_eligibility_avoids_uid_and_unsupported_predicates() {
        let hint = |path: &str, value: &str| CandidateHint::Entity { source_path: path.into(), value: value.into() };
        assert!(!uses_entity_sidecars(&[hint("metadata.uid", "target")]));
        assert!(!uses_entity_sidecars(&[hint("unknown", "x")]));
        // NAN-3694: a long mixed-case value may be answered by a folded bloom.
        assert!(uses_entity_sidecars(&[hint("user.name", "long-username")]));
        assert!(!uses_entity_sidecars(&[hint("user.name", "İnstanbul-username")]), "non-ASCII stays unknown");
        assert!(uses_entity_sidecars(&[hint("device.hostname", "ws-support-115.corp.local")]));
        assert!(uses_entity_sidecars(&[CandidateHint::Any { alternatives: vec![hint("unknown", "x"), hint("src_endpoint.ip", "10.0.0.1")] }]));
    }

    #[test]
    fn missing_malformed_and_unknown_entity_evidence_keeps_rows() {
        let entity = CandidateHint::Entity { source_path: "device.hostname".into(), value: "target.corp.local".into() };
        assert_eq!(entity_summary_mask(None, 3, &[entity.clone()]), None);
        let mut blooms = EntityBlooms::new();
        blooms.insert("device.hostname".into(), vec![None, Some("00".into()), Some("invalid".into())]);
        assert_eq!(entity_summary_mask(Some(&blooms), 3, &[entity.clone()]), Some(vec![true; 3]));
        assert_eq!(entity_summary_mask(Some(&blooms), 2, &[entity.clone()]), Some(vec![true; 2]));
        blooms.insert("device.hostname".into(), vec![Some("00".repeat(32)); 3]);
        assert_eq!(entity_summary_mask(Some(&blooms), 3, &[entity.clone()]), Some(vec![false; 3]));
        let unicode = CandidateHint::Entity { source_path: "device.hostname".into(), value: "İ".into() };
        assert_eq!(entity_summary_mask(Some(&blooms), 3, &[unicode]), Some(vec![true; 3]));
        let any = CandidateHint::Any { alternatives: vec![entity, CandidateHint::Entity { source_path: "unknown".into(), value: "x".into() }] };
        assert_eq!(entity_summary_mask(Some(&blooms), 3, &[any]), Some(vec![true; 3]));
    }

    /// NAN-3165: the projected bloom decode answers its fields exactly as
    /// the full decode; other fields are absent (kept).
    #[test]
    fn projected_bloom_decode_matches_the_full_decode() {
        let entity = CandidateHint::Entity { source_path: "device.hostname".into(), value: "target.corp.local".into() };
        let mut blooms = EntityBlooms::new();
        blooms.insert("device.hostname".into(), vec![Some("00".repeat(32)), None]);
        blooms.insert("user.name".into(), vec![Some("ff".repeat(32)), Some("00".repeat(32))]);
        let bytes = serde_json::to_vec(&blooms).unwrap();
        let wanted = std::collections::BTreeSet::from(["device.hostname".to_string()]);
        let projected = decode_entity_blooms(&bytes, &wanted).unwrap();
        assert_eq!(projected.keys().collect::<Vec<_>>(), vec!["device.hostname"]);
        assert_eq!(entity_summary_mask(Some(&projected), 2, &[entity.clone()]), entity_summary_mask(Some(&blooms), 2, &[entity]));
        assert!(decode_entity_blooms(b"{\"a\":[]} trailing", &wanted).is_none());
    }

    fn folded(groups: &[&[&str]]) -> Vec<Option<String>> {
        groups.iter().map(|values| {
            let mut bloom = Sbbf::new_with_ndv_fpp(values.len().max(1) as u64, 0.0001).unwrap();
            values.iter().for_each(|value| bloom.insert(value.to_ascii_lowercase().as_bytes()));
            let mut bytes = Vec::new();
            bloom.write_bitset(&mut bytes).unwrap();
            Some(hex::encode(bytes))
        }).collect()
    }

    /// NAN-3694: a folded bloom answers a long mixed-case value with one
    /// probe; an absent folded key is today's behavior, never a prune.
    #[test]
    fn folded_blooms_decide_long_values_and_absence_changes_nothing() {
        let email = |value: &str| CandidateHint::Entity { source_path: "user.email_addr".into(), value: value.into() };
        let long = email("Alice.Smith@Example.com");
        let mut blooms = EntityBlooms::new();
        // No folded key: exactly the pre-folded answers (a long value keeps).
        let before = entity_summary_mask(Some(&blooms), 2, &[long.clone()]);
        assert_eq!(before, Some(vec![true, true]));
        blooms.insert(folded_bloom_key("user.email_addr"), folded(&[&["alice.smith@EXAMPLE.com", "bob@x.io"], &["carol@x.io"]]));
        assert_eq!(entity_summary_mask(Some(&blooms), 2, &[long.clone()]), Some(vec![true, false]));
        // A pivot OR prunes once every leg can.
        let any = CandidateHint::Any { alternatives: vec![long.clone(), CandidateHint::Entity { source_path: "actor.user.email_addr".into(), value: "Alice.Smith@Example.com".into() }] };
        assert_eq!(entity_summary_mask(Some(&blooms), 2, &[any.clone()]), Some(vec![true, true]), "other leg has no folded key");
        blooms.insert(folded_bloom_key("actor.user.email_addr"), folded(&[&["x@y.io"], &["z@y.io"]]));
        assert_eq!(entity_summary_mask(Some(&blooms), 2, &[any]), Some(vec![true, false]));
        // Malformed or misaligned folded evidence falls through to the raw path.
        let mut bad = EntityBlooms::new();
        bad.insert(folded_bloom_key("user.email_addr"), vec![Some("zz".into()), None]);
        assert_eq!(entity_summary_mask(Some(&bad), 2, &[long.clone()]), before);
        bad.insert(folded_bloom_key("user.email_addr"), folded(&[&["carol@x.io"]]));
        assert_eq!(entity_summary_mask(Some(&bad), 2, &[long.clone()]), before, "group count differs");
        // "=": the group's values are all lowercase, so the raw bloom probed
        // with the lowercased literal decides it; without a raw bloom, keep.
        let mut same = EntityBlooms::new();
        same.insert(folded_bloom_key("user.email_addr"), vec![Some(FOLDED_SAME_AS_RAW.into()), Some(FOLDED_SAME_AS_RAW.into())]);
        same.insert("user.email_addr".into(), folded(&[&["alice.smith@example.com"], &["carol@x.io"]]));
        assert_eq!(entity_summary_mask(Some(&same), 2, &[long.clone()]), Some(vec![true, false]));
        same.insert("user.email_addr".into(), vec![None, None]);
        assert_eq!(entity_summary_mask(Some(&same), 2, &[long.clone()]), before);
        // Ingest-lowercased paths and the uid never read a folded key.
        let mut host = EntityBlooms::new();
        host.insert(folded_bloom_key("device.hostname"), folded(&[&["other"]]));
        let hostname = CandidateHint::Entity { source_path: "device.hostname".into(), value: "ws-support-115.corp.local".into() };
        assert_eq!(entity_summary_mask(Some(&host), 1, &[hostname]), Some(vec![true]));
        assert!(!foldable("device.hostname") && !foldable("metadata.uid") && !foldable("message"));
        assert!(foldable("user.name") && foldable("user.email_addr") && foldable("actor.process.user.name"));
        // Non-ASCII values stay unknown.
        assert_eq!(entity_summary_mask(Some(&blooms), 2, &[email("İ@x.io")]), Some(vec![true, true]));
    }

    #[test]
    fn folded_keys_are_decoded_only_for_hinted_foldable_paths() {
        let hints = [CandidateHint::Any { alternatives: vec![
            CandidateHint::Entity { source_path: "user.name".into(), value: "bsmith@corp.local".into() },
            CandidateHint::Entity { source_path: "src_endpoint.ip".into(), value: "10.0.0.1".into() },
        ] }];
        let fields = entity_bloom_fields(&hints);
        assert_eq!(fields, ["lower:user.name", "src_endpoint.ip", "user.name"].into_iter().map(String::from).collect());
        assert!(needs_folded_blooms(&hints));
        assert!(!needs_folded_blooms(&[CandidateHint::Entity { source_path: "user.name".into(), value: "bsmith".into() }]));
        let mut blooms = EntityBlooms::new();
        blooms.insert(folded_bloom_key("user.name"), folded(&[&["x"]]));
        blooms.insert(folded_bloom_key("process.name"), folded(&[&["x"]]));
        let decoded = decode_entity_blooms(&serde_json::to_vec(&blooms).unwrap(), &fields).unwrap();
        assert_eq!(decoded.keys().collect::<Vec<_>>(), vec!["lower:user.name"]);
    }

    #[test]
    fn missing_and_malformed_uid_evidence_keeps_rows() {
        let hints = [CandidateHint::Entity { source_path: "metadata.uid".into(), value: "target".into() }];
        assert_eq!(uid_summary_mask(None, 1, &hints), None);
        assert_eq!(uid_summary_mask(Some(&[]), 1, &hints), None);
        assert_eq!(uid_summary_mask(Some(&[None, Some("00".into()), Some("invalid".into())]), 3, &hints), Some(vec![true; 3]));
    }
}
