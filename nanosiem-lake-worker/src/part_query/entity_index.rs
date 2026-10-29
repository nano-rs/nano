// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4190: one worker-local window entity index (exact row runs).
//!
//! A single-host hunt over a 7-day lean window (`device.hostname=X |
//! timechart ...`) used to answer entity evidence per data file. Resident
//! files read one Parquet bloom per (row group, hinted path), which cost 5-9 s
//! of select time over ~2,200 files, and a host seen every few minutes is in
//! most 65,536-row groups, so even a perfect group mask leaves chDB to decode
//! ~60% of the window (7-15 s) to find a few thousand rows.
//!
//! This index folds the window's resident data files into one local file
//! keyed by `(path, value)`. Per `(file, row group)` it holds the value's
//! [`BLOCK_ROWS`]-aligned row runs and the exact `[min, max]` event time of
//! the matching rows in each run (or "whole group" when the value is dense
//! there). A lookup is a few reads of one sorted file; its runs go to the
//! existing fine-runs path (`prune::FineBlocks`), whose `time` guard lets
//! chDB's Parquet reader skip every page outside them. A dense host is then
//! decoded run by run, not group by group.
//!
//! Soundness (every answer is a candidate superset; unknown means keep):
//! - inputs are only data files of live parts, leased through the fetcher
//!   (signed record, verified digest) and already resident (the build never
//!   fetches cold data); a source is keyed by `(part, file, data sha256)`;
//! - a lookup serves only the live candidate files of the query that the
//!   file covers (a source that left the window or was superseded is never
//!   read), exactly as `identity_merged`: files it does not cover yet (the
//!   tail) take the per-file evidence path unchanged;
//! - a field is "known" in a group only when every value of it there was a
//!   scalar ASCII string (as the entity locators): otherwise the group keeps
//!   every row for that field. In a known group, no record means no row has
//!   the value. A value is keyed by a 64-bit hash of `(path, normalized
//!   value)`: a collision only adds candidates;
//! - runs are widened to whole [`BLOCK_ROWS`] blocks, their times cover every
//!   matching row, and an AND of hints intersects them (a row matching both
//!   lies in both runs and both time ranges); final SQL still filters rows.
//!
//! The build runs only while every query slot is free and no durable job
//! runs, incrementally (still-live records of the previous file plus up to
//! [`MAX_TAIL_FILES`] new sources per pass), and a failure backs off.
//!
//! NAN-4772: on by default on every query role (hosted, sovereign, open
//! core), with no switch. It ran behind `NANO_LAKE_ENTITY_INDEX=1` on the
//! hosted cells since NAN-4190/4211; open core and sovereign had it off, so
//! a single-host pivot there decoded every bloom-kept 65,536-row group
//! (Mythos 1.0.12 H9: ~33x ClickHouse). A process without an index (before
//! its first build), and the files the index does not cover yet (the tail,
//! a superseded source), take the per-file evidence path: same rows. The
//! `entity_index` per-request override (`x-nano-perf-overrides`) still
//! turns lookups off for one request (live A/B).
//!
//! Per-tenant resource envelope (no new tuning knobs): a generation is
//! <= 1 GiB; a build/retiring reader can keep one other generation, so peak
//! disk is <= 2 GiB. A reader retaining the retired generation prevents
//! another build. Each generation has <= 8,192 sources / 65,536 groups and
//! <= 3.6 MiB of sparse seek points. Extraction, the accumulated build tail,
//! and each admitted lookup each have a separate 64 MiB record allowance
//! (512 bytes per record, including vector/map overhead). Extraction also
//! bounds each group's compressed and uncompressed projection to 16 MiB
//! each, and its row/field value positions to 262,144. Values/maps, decoded
//! Arrow buffers and matching times are additional bounded working sets;
//! these allowances are not a process-RSS limit. Concurrent lookup cost
//! scales with the existing per-tenant query admission limit. Reader-cache
//! leases, signed-view metadata and the existing worker cgroup remain under
//! their own budgets. Exceeding an index budget leaves sources uncovered
//! or declines the lookup: the normal scan remains authoritative.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use super::engine::{PartQueryEngine, QueryResult};
use super::prune::{BlockRuns, FineBlocks};
use crate::parts::format::PartId;
use crate::planner::CandidateHint;

/// Comma-separated indexed paths (a subset of the bloom paths, uid excluded).
pub const FIELDS_FLAG: &str = "NANO_LAKE_ENTITY_INDEX_FIELDS";
/// Host and user pivots: the single-entity hunts this index is for.
pub const DEFAULT_FIELDS: &[&str] = &["actor.user.name", "device.hostname", "src_endpoint.hostname", "user.name"];
/// Row granularity of a run: one v2 token block (~one data page), so the
/// set fence's granule stays a block and chDB's page index can skip.
pub const BLOCK_ROWS: u64 = crate::parts::block_index::BLOCK_ROWS as u64;
/// A value in more than 1/`DENSE_DIVISOR` of a group's blocks is recorded
/// as "whole group" (runs would cost more than the scan they save).
pub const DENSE_DIVISOR: usize = 4;
/// Most runs one `(value, group)` record keeps; the narrowest gaps merge.
pub const MAX_RUNS: usize = 8;
/// Window the build covers (a 7-day hunt plus slack).
pub const WINDOW_US: i64 = 8 * 24 * 3_600 * 1_000_000;
/// New sources folded in per pass (bounds a pass's memory and CPU).
pub const MAX_TAIL_FILES: usize = 64;
/// Rebuild once this many resident live files are outside the index, or
/// once this many (and at least a quarter) of its sources left the window.
/// NAN-4213: every rebuild rewrites the whole file (~730 MB on a large tenant over
/// ~2,470 sources), so 8 meant a full rewrite every ~5 min (~91x write
/// amplification); untracked tail files take the per-file evidence path
/// meanwhile (same rows), so 32 amortizes rewrites 4x.
pub const REBUILD_FILES: usize = 32;
/// The first build starts once this many resident files are local (no
/// index yet: nothing to amortize).
pub const FIRST_BUILD_FILES: usize = 8;
/// NAN-4213: a merge drops the pages it streamed (old file read, new file
/// written) from the page cache every this many bytes. The merge runs in
/// query[T]'s cgroup: a 730 MB read plus a 730 MB write evicted ~950 MB of
/// the analysts' page cache per merge. Lookups fault in only the pages
/// they touch.
const DROP_CACHE_EVERY: u64 = 32 << 20;
/// After a failed build, passes skip it this long.
pub const FAILURE_BACKOFF: Duration = Duration::from_secs(15 * 60);
/// Each generation is at most this size. At most two generations (current
/// plus a build or a retiring reader) exist: 2 GiB peak disk per tenant.
pub const MAX_INDEX_BYTES: u64 = 1 << 30;
/// Bound metadata even for sources containing no indexed values.
pub const MAX_INDEX_SOURCES: usize = 8_192;
pub const MAX_INDEX_GROUPS: usize = 65_536;
/// Heap record allowance, separately for one extraction, the accumulated
/// build tail, and one lookup. Includes Vec capacity and map-node overhead.
pub const MAX_RECORD_MEMORY: usize = 64 << 20;
const RECORD_MEMORY_BYTES: usize = 512;
const MAX_RECORDS: usize = MAX_RECORD_MEMORY / RECORD_MEMORY_BYTES;
/// Bound a group's decoder and normalized-value maps before decoding it.
/// Oversized groups/files are simply not covered (queries scan them).
pub const MAX_PROJECTED_GROUP_BYTES: i64 = 16 << 20;
pub const MAX_GROUP_VALUES: usize = 262_144;
const MAX_LOOKUP_LEAVES: usize = 32;
/// Pass interval while the index is current, and while a backlog remains.
pub const INTERVAL: Duration = Duration::from_secs(60);
pub const BUSY_POLL: Duration = Duration::from_secs(5);
/// Every this many records, the in-memory sparse index keeps a seek point.
const SPARSE_EVERY: usize = 256;
/// Most records one key's lookup reads before it gives up (unknown).
const MAX_KEY_RECORDS: usize = 1 << 20;

pub const DIR: &str = "entity-index/window-v1";
const PREFIX: &str = "entity-";

fn internal(error: impl std::fmt::Display) -> super::engine::PartQueryError {
    super::engine::internal_text(error.to_string())
}

/// Whether the build and lookups are on for this process: always, since
/// NAN-4772 (the per-request override can still turn lookups off).
pub const fn enabled() -> bool {
    true
}

/// The indexed paths: [`FIELDS_FLAG`] or [`DEFAULT_FIELDS`], restricted to
/// bloom paths (never the uid), sorted, at most 32.
pub fn fields() -> Vec<String> {
    fields_from(std::env::var(FIELDS_FLAG).ok().as_deref())
}

fn fields_from(value: Option<&str>) -> Vec<String> {
    let mut fields = match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => value.split(',').map(str::trim).map(str::to_owned).collect::<Vec<_>>(),
        None => DEFAULT_FIELDS.iter().map(|field| (*field).to_owned()).collect(),
    };
    fields.retain(|field| field != crate::parts::format::UID_PATH && crate::parts::format::BLOOM_PATHS.contains(&field.as_str()));
    fields.sort_unstable();
    fields.dedup();
    fields.truncate(32);
    fields
}

/// One indexed data file: a live part's data file at its signed digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceKey {
    pub part: PartId,
    pub index: usize,
    pub sha256: String,
}

/// One row group of an indexed source: its rows and which fields (bit `i`
/// = `fields[i]`) are known exactly there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupCoverage {
    pub rows: u32,
    pub known: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    pub src: u32,
    pub groups: Vec<GroupCoverage>,
}

/// One `(value, source, row group)` record. `runs` empty with `whole` false
/// never occurs (no record is written for an absent value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub hash: u64,
    pub src: u32,
    pub group: u32,
    pub whole: bool,
    /// Group-relative `[start, end)` block-aligned runs with the `[min, max]`
    /// event time (µs) of the matching rows inside each.
    pub runs: BlockRuns,
}

/// The 64-bit key of `(path, normalized value)`.
pub fn key_hash(path: &str, normalized: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"nano.entity-index.v1\0");
    hash.update(path.as_bytes());
    hash.update([0]);
    hash.update(normalized.as_bytes());
    let digest = hash.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"))
}

fn write_record(out: &mut impl Write, record: &Record) -> std::io::Result<u64> {
    out.write_all(&record.hash.to_le_bytes())?;
    out.write_all(&record.src.to_le_bytes())?;
    out.write_all(&record.group.to_le_bytes())?;
    out.write_all(&[u8::from(record.whole), record.runs.len() as u8])?;
    for (start, end, (min, max)) in &record.runs {
        out.write_all(&(*start as u32).to_le_bytes())?;
        out.write_all(&(*end as u32).to_le_bytes())?;
        out.write_all(&min.to_le_bytes())?;
        out.write_all(&max.to_le_bytes())?;
    }
    Ok(18 + 24 * record.runs.len() as u64)
}

fn read_record(input: &mut impl Read) -> std::io::Result<Option<Record>> {
    let mut head = [0_u8; 18];
    // EOF is clean only between records. A partial header is corruption,
    // never proof that a value is absent.
    if input.read(&mut head[..1])? == 0 {
        return Ok(None);
    }
    input.read_exact(&mut head[1..])?;
    if head[16] > 1 || head[17] as usize > MAX_RUNS
        || (head[16] == 1) != (head[17] == 0)
    {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid entity index record"));
    }
    let hash = u64::from_le_bytes(head[0..8].try_into().expect("8"));
    let src = u32::from_le_bytes(head[8..12].try_into().expect("4"));
    let group = u32::from_le_bytes(head[12..16].try_into().expect("4"));
    let whole = head[16] != 0;
    let mut runs = Vec::with_capacity(head[17] as usize);
    let mut run = [0_u8; 24];
    for _ in 0..head[17] {
        input.read_exact(&mut run)?;
        runs.push((
            u64::from(u32::from_le_bytes(run[0..4].try_into().expect("4"))),
            u64::from(u32::from_le_bytes(run[4..8].try_into().expect("4"))),
            (i64::from_le_bytes(run[8..16].try_into().expect("8")), i64::from_le_bytes(run[16..24].try_into().expect("8"))),
        ));
    }
    Ok(Some(Record { hash, src, group, whole, runs }))
}

/// One built index file and what it covers. Removed when the last reader
/// drops it.
#[derive(Debug)]
pub struct EntityIndex {
    path: PathBuf,
    fields: Vec<String>,
    sources: BTreeMap<SourceKey, Coverage>,
    /// `(hash, byte offset)` of every [`SPARSE_EVERY`]-th record.
    sparse: Vec<(u64, u64)>,
    bytes: u64,
}

impl Drop for EntityIndex {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// One candidate file's index evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvidence {
    pub mask: Vec<bool>,
    /// Per group: the candidate runs (`None` = the whole group).
    pub fine: FineBlocks,
    /// Every hinted indexed field is known in every group of the file: the
    /// file's in-file blooms cannot prune those hints any further.
    pub answered: bool,
}

/// One hint leaf the index can answer.
fn eligible<'a>(fields: &[String], hint: &'a CandidateHint) -> Option<(&'a str, &'a str, usize)> {
    match hint {
        CandidateHint::Entity { source_path, value } if value.is_ascii() => {
            fields.iter().position(|field| field == source_path).map(|bit| (source_path.as_str(), value.as_str(), bit))
        }
        _ => None,
    }
}

/// Row evidence of one hint in one group.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rows {
    /// Every row may match.
    All,
    /// Only these sorted, disjoint runs may match (empty: none).
    Runs(BlockRuns),
}

fn intersect(left: &BlockRuns, right: &BlockRuns) -> BlockRuns {
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < left.len() && j < right.len() {
        let (a, b) = (&left[i], &right[j]);
        let (start, end) = (a.0.max(b.0), a.1.min(b.1));
        let (min, max) = (a.2 .0.max(b.2 .0), a.2 .1.min(b.2 .1));
        // A row matching both lies in both runs and both time ranges.
        if start < end && min <= max {
            out.push((start, end, (min, max)));
        }
        if a.1 <= b.1 { i += 1 } else { j += 1 }
    }
    out
}

fn union(mut runs: BlockRuns) -> BlockRuns {
    runs.sort_unstable_by_key(|run| (run.0, run.1));
    let mut out: BlockRuns = Vec::with_capacity(runs.len());
    for (start, end, (min, max)) in runs {
        match out.last_mut() {
            Some(last) if start <= last.1 => {
                last.1 = last.1.max(end);
                last.2 = (last.2 .0.min(min), last.2 .1.max(max));
            }
            _ => out.push((start, end, (min, max))),
        }
    }
    out
}

/// One run per group: the hull of `runs` (fewer fence blocks, still a superset).
pub fn hull(runs: &BlockRuns) -> BlockRuns {
    match (runs.first(), runs.last()) {
        (Some(first), Some(last)) => vec![(
            first.0,
            last.1,
            (runs.iter().map(|run| run.2 .0).min().expect("non-empty"), runs.iter().map(|run| run.2 .1).max().expect("non-empty")),
        )],
        _ => Vec::new(),
    }
}

/// Merge `runs` (sorted, disjoint) across their narrowest gaps until at most
/// `cap` remain.
fn cap_runs(mut runs: BlockRuns, cap: usize) -> BlockRuns {
    while runs.len() > cap.max(1) {
        let narrowest = (1..runs.len()).min_by_key(|&i| (runs[i].0 - runs[i - 1].1, i)).expect("two runs");
        let next = runs.remove(narrowest);
        let last = &mut runs[narrowest - 1];
        last.1 = next.1;
        last.2 = (last.2 .0.min(next.2 .0), last.2 .1.max(next.2 .1));
    }
    runs
}

/// The fine runs of one file from its token index (`token`) and the window
/// entity index (`index`): per group, the intersection where both have runs
/// (both are supersets of the matching rows), else whichever has them.
pub fn and_fine(token: Option<FineBlocks>, index: Option<FineBlocks>) -> Option<FineBlocks> {
    match (token, index) {
        (None, other) | (other, None) => other,
        (Some(token), Some(index)) if token.len() == index.len() => Some(
            token
                .into_iter()
                .zip(index)
                .map(|pair| match pair {
                    (None, other) | (other, None) => other,
                    (Some(left), Some(right)) => Some(intersect(&left, &right)),
                })
                .collect(),
        ),
        // Shapes disagree: one is wrong for the file; the footer check
        // decides the token runs as before.
        (Some(token), Some(_)) => Some(token),
    }
}

/// Keep a selection's index runs within `budget` fence blocks: past it,
/// every group's runs collapse to their hull (one block per group).
pub fn fit_run_budget(files: &mut BTreeMap<(String, usize), FineBlocks>, budget: usize) {
    let runs = files.values().flatten().map(|group| group.as_ref().map_or(1, Vec::len)).sum::<usize>();
    if runs <= budget {
        return;
    }
    for group in files.values_mut().flatten().flatten() {
        if group.len() > 1 {
            *group = hull(group);
        }
    }
}

impl EntityIndex {
    /// `hints` without the top-level leaves this index answers (for a file
    /// whose every group knows them: their blooms cannot prune further).
    pub fn strip_answered(&self, hints: &[CandidateHint]) -> Vec<CandidateHint> {
        hints.iter().filter(|hint| eligible(&self.fields, hint).is_none()).cloned().collect()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn sources(&self) -> &BTreeMap<SourceKey, Coverage> {
        &self.sources
    }

    pub fn fields(&self) -> &[String] {
        &self.fields
    }

    /// Whether any hint (or alternative) is a leaf this index answers.
    pub fn answers(&self, hints: &[CandidateHint]) -> bool {
        hints.iter().any(|hint| match hint {
            CandidateHint::Any { alternatives } => self.answers(alternatives),
            hint => eligible(&self.fields, hint).is_some(),
        })
    }

    /// Every record of `hash` (sorted by source, then group); `None` when
    /// the file cannot be read (callers keep everything).
    fn records_of(&self, hash: u64, remaining: &mut usize) -> Option<Vec<Record>> {
        let at = self.sparse.partition_point(|(key, _)| *key < hash);
        let offset = if at == 0 { 0 } else { self.sparse[at - 1].1 };
        let mut file = std::fs::File::open(&self.path).ok()?;
        if file.metadata().ok()?.len() != self.bytes {
            return None;
        }
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut reader = BufReader::with_capacity(64 * 1024, file.take(self.bytes.saturating_sub(offset)));
        let mut out = Vec::new();
        let mut read = 0_usize;
        loop {
            let Some(record) = read_record(&mut reader).ok()? else {
                if reader.get_ref().limit() != 0 {
                    return None;
                }
                break;
            };
            read += 1;
            if read > MAX_KEY_RECORDS {
                return None;
            }
            if record.hash > hash {
                break;
            }
            if record.hash == hash {
                *remaining = remaining.checked_sub(1)?;
                out.push(record);
            }
        }
        Some(out)
    }

    /// Evidence for each of `files` (`(source, row groups, rows)`): `None`
    /// for a file this index does not cover (or covers under another shape),
    /// which keeps the per-file path. `None` overall when the file cannot be
    /// read.
    pub fn evidence(&self, hints: &[CandidateHint], files: &[(SourceKey, usize, u64)]) -> Option<Vec<Option<FileEvidence>>> {
        // Each eligible leaf's records: src -> group -> record.
        let mut leaves: BTreeMap<(String, String), BTreeMap<(u32, u32), Record>> = BTreeMap::new();
        fn collect<'a>(fields: &[String], hint: &'a CandidateHint, out: &mut Vec<(&'a str, &'a str, usize)>) {
            match hint {
                CandidateHint::Any { alternatives } => alternatives.iter().for_each(|hint| collect(fields, hint, out)),
                hint => out.extend(eligible(fields, hint)),
            }
        }
        let mut wanted = Vec::new();
        hints.iter().for_each(|hint| collect(&self.fields, hint, &mut wanted));
        if wanted.len() > MAX_LOOKUP_LEAVES {
            return None;
        }
        let mut remaining = MAX_RECORDS;
        for (path, value, _) in &wanted {
            let key = (path.to_string(), value.to_ascii_lowercase());
            if leaves.contains_key(&key) {
                continue;
            }
            let records = self.records_of(key_hash(path, &key.1), &mut remaining)?;
            leaves.insert(key, records.into_iter().map(|record| ((record.src, record.group), record)).collect());
        }
        let bits = wanted.iter().fold(0_u32, |bits, (_, _, bit)| bits | (1 << bit));
        Some(files.iter().map(|(source, groups, rows)| {
            let coverage = self.sources.get(source)?;
            if coverage.groups.len() != *groups || coverage.groups.iter().map(|group| u64::from(group.rows)).sum::<u64>() != *rows {
                return None;
            }
            let mut mask = Vec::with_capacity(*groups);
            let mut fine = Vec::with_capacity(*groups);
            for (group, cover) in coverage.groups.iter().enumerate() {
                let rows = hints.iter().fold(Rows::All, |acc, hint| {
                    let rows = self.hint_rows(hint, &leaves, coverage.src, group as u32, cover);
                    match (acc, rows) {
                        (Rows::All, other) | (other, Rows::All) => other,
                        (Rows::Runs(left), Rows::Runs(right)) => Rows::Runs(intersect(&left, &right)),
                    }
                });
                match rows {
                    Rows::All => {
                        mask.push(true);
                        fine.push(None);
                    }
                    Rows::Runs(runs) => {
                        mask.push(!runs.is_empty());
                        fine.push(Some(runs));
                    }
                }
            }
            let answered = coverage.groups.iter().all(|group| group.known & bits == bits);
            Some(FileEvidence { mask, fine, answered })
        }).collect())
    }

    fn hint_rows(
        &self,
        hint: &CandidateHint,
        leaves: &BTreeMap<(String, String), BTreeMap<(u32, u32), Record>>,
        src: u32,
        group: u32,
        cover: &GroupCoverage,
    ) -> Rows {
        match hint {
            CandidateHint::Any { alternatives } if !alternatives.is_empty() => {
                let mut runs = Vec::new();
                for alternative in alternatives {
                    match self.hint_rows(alternative, leaves, src, group, cover) {
                        Rows::All => return Rows::All,
                        Rows::Runs(more) => runs.extend(more),
                    }
                }
                Rows::Runs(union(runs))
            }
            hint => {
                let Some((path, value, bit)) = eligible(&self.fields, hint) else { return Rows::All };
                if cover.known & (1 << bit) == 0 {
                    return Rows::All;
                }
                let Some(records) = leaves.get(&(path.to_string(), value.to_ascii_lowercase())) else { return Rows::All };
                match records.get(&(src, group)) {
                    None => Rows::Runs(Vec::new()),
                    Some(record) if record.whole => Rows::All,
                    Some(record) => Rows::Runs(record.runs.clone()),
                }
            }
        }
    }
}

/// The engine's current index (none until the first build).
#[derive(Debug, Default)]
pub struct Slot {
    current: Mutex<Option<Arc<EntityIndex>>>,
    // Do not build a third generation while a query retains the old one.
    retired: Mutex<Weak<EntityIndex>>,
    swept: AtomicBool,
    build: tokio::sync::Mutex<()>,
    failed_at: Mutex<Option<Instant>>,
}

impl Slot {
    pub fn current(&self) -> Option<Arc<EntityIndex>> {
        self.current.lock().expect("entity index slot").clone()
    }

    /// The index a query may read: none while switched off for this request
    /// (the process value, or the `entity_index` override).
    pub fn for_query(&self) -> Option<Arc<EntityIndex>> {
        if crate::perf_overrides::entity_index(enabled()) { self.current() } else { None }
    }

    fn replace(&self, next: EntityIndex) {
        let previous = self.current.lock().expect("entity index slot").replace(Arc::new(next));
        *self.retired.lock().expect("entity index retired") = previous.as_ref().map_or_else(Weak::new, Arc::downgrade);
        drop(previous);
    }

    fn clear(&self) {
        let previous = self.current.lock().expect("entity index slot").take();
        if let Some(previous) = &previous {
            *self.retired.lock().expect("entity index retired") = Arc::downgrade(previous);
        }
        drop(previous);
    }

    fn backing_off(&self, now: Instant) -> bool {
        self.failed_at.lock().expect("entity index failure").is_some_and(|at| now.saturating_duration_since(at) < FAILURE_BACKOFF)
    }

    fn record_failure(&self, now: Option<Instant>) {
        *self.failed_at.lock().expect("entity index failure") = now;
    }
}

/// Whether a build over `live` (every data file of the window's live parts)
/// with `resident` of them local is due.
pub fn needs_rebuild(current: Option<&EntityIndex>, live: &BTreeSet<SourceKey>, resident: &BTreeSet<SourceKey>) -> bool {
    let tail = resident.iter().filter(|key| current.is_none_or(|index| !index.sources.contains_key(key))).count();
    let Some(current) = current else { return tail >= FIRST_BUILD_FILES };
    let stale = current.sources.keys().filter(|key| !live.contains(*key)).count();
    tail >= REBUILD_FILES || stale >= REBUILD_FILES.max(current.sources.len() / 4)
}

/// The records and coverage of one data file at `path`, whose row groups
/// must be `groups` (the signed record's). Fields that are not scalar string
/// columns are unknown in every group.
pub fn extract(path: &Path, fields: &[String], groups: usize) -> anyhow::Result<(Vec<Record>, Vec<GroupCoverage>)> {
    use crate::generation::{event_time_us_from_array, CompiledStringPath};
    use crate::parts::entity_locators::normalized;
    use parquet::arrow::arrow_reader::{ArrowReaderOptions, ParquetRecordBatchReaderBuilder};
    let builder = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?;
    let metadata = builder.metadata().clone();
    // Utf8View retains dictionary/page buffers instead of expanding a
    // repeated long value for every row. The projected Parquet byte cap
    // alone cannot bound the size of an ordinary Utf8 batch.
    fn viewed(field: &arrow_schema::Field) -> arrow_schema::Field {
        use arrow_schema::DataType;
        let data_type = match field.data_type() {
            DataType::Utf8 | DataType::LargeUtf8 => DataType::Utf8View,
            DataType::Struct(fields) => DataType::Struct(fields.iter().map(|field| Arc::new(viewed(field))).collect()),
            other => other.clone(),
        };
        field.clone().with_data_type(data_type)
    }
    let view_schema = Arc::new(arrow_schema::Schema::new(builder.schema().fields().iter().map(|field| viewed(field)).collect::<Vec<_>>()));
    anyhow::ensure!(metadata.num_row_groups() == groups, "data file row groups differ from its record");
    let schema = metadata.file_metadata().schema_descr();
    let scalar = |field: &str| schema.columns().iter().any(|column| {
        column.path().string() == field
            && column.max_rep_level() == 0
            && column.physical_type() == parquet::basic::Type::BYTE_ARRAY
            && column.logical_type_ref() == Some(&parquet::basic::LogicalType::String)
    });
    let indexed = fields.iter().enumerate().filter(|(_, field)| scalar(field)).map(|(bit, field)| (bit, field.clone())).collect::<Vec<_>>();
    let leaves = schema.columns().iter().enumerate()
        .filter(|(_, column)| {
            let name = column.path().string();
            name == crate::parts::format::TIME_COLUMN || indexed.iter().any(|(_, field)| *field == name)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let mut records = Vec::new();
    anyhow::ensure!(groups <= MAX_INDEX_GROUPS, "entity index source exceeds group budget");
    let mut coverage = Vec::with_capacity(groups);
    for group in 0..groups {
        let group_rows = usize::try_from(metadata.row_group(group).num_rows())?;
        anyhow::ensure!(group_rows > 0 && group_rows <= crate::parts::format::MAX_ROW_GROUP_ROWS
            && group_rows.saturating_mul(indexed.len().max(1)) <= MAX_GROUP_VALUES,
            "entity index group exceeds value budget");
        let projected = leaves.iter().try_fold((0_i64, 0_i64), |(raw, compressed), &leaf| {
            let column = metadata.row_group(group).column(leaf);
            Some((raw.checked_add(column.uncompressed_size())?, compressed.checked_add(column.compressed_size())?))
        });
        anyhow::ensure!(projected.is_some_and(|(raw, compressed)|
            (0..=MAX_PROJECTED_GROUP_BYTES).contains(&raw)
                && (0..=MAX_PROJECTED_GROUP_BYTES).contains(&compressed)),
            "entity index group exceeds decoder byte budget");
        let projection = parquet::arrow::ProjectionMask::leaves(schema, leaves.clone());
        let options = ArrowReaderOptions::new().with_schema(view_schema.clone());
        let reader = ParquetRecordBatchReaderBuilder::try_new_with_options(std::fs::File::open(path)?, options)?
            .with_projection(projection)
            .with_row_groups(vec![group])
            .with_batch_size(8_192)
            .build()?;
        let mut times = Vec::with_capacity(group_rows);
        // bit -> normalized value -> rows (ascending)
        let mut values: BTreeMap<usize, std::collections::HashMap<String, Vec<u32>>> = BTreeMap::new();
        let mut unknown = BTreeSet::new();
        for batch in reader {
            let batch = batch?;
            let base = times.len() as u32;
            let time = batch.column_by_name(crate::parts::format::TIME_COLUMN).ok_or_else(|| anyhow::anyhow!("data file has no time"))?;
            for row in 0..batch.num_rows() {
                times.push(event_time_us_from_array(time.as_ref(), row).ok_or_else(|| anyhow::anyhow!("data row has no time"))?);
            }
            for (bit, field) in &indexed {
                if unknown.contains(bit) {
                    continue;
                }
                let Some(compiled) = CompiledStringPath::new(&batch, field) else {
                    unknown.insert(*bit);
                    continue;
                };
                let map = values.entry(*bit).or_default();
                'rows: for row in 0..batch.num_rows() {
                    for value in compiled.strings(row) {
                        if !value.is_ascii() {
                            unknown.insert(*bit);
                            break 'rows;
                        }
                        let rows = map.entry(normalized(field, &value)).or_default();
                        let at = base + row as u32;
                        if rows.last() != Some(&at) {
                            rows.push(at);
                        }
                    }
                }
            }
        }
        anyhow::ensure!(times.len() == group_rows, "row group rows differ from its footer");
        let mut known = 0_u32;
        for (bit, _) in &indexed {
            if !unknown.contains(bit) {
                known |= 1 << bit;
            }
        }
        coverage.push(GroupCoverage { rows: group_rows as u32, known });
        let blocks = group_rows.div_ceil(BLOCK_ROWS as usize);
        for (bit, map) in values {
            if unknown.contains(&bit) {
                continue;
            }
            for (value, rows) in map {
                let hash = key_hash(&fields[bit], &value);
                let mut runs: BlockRuns = Vec::new();
                for row in rows {
                    let block = u64::from(row) / BLOCK_ROWS;
                    let (start, end) = (block * BLOCK_ROWS, ((block + 1) * BLOCK_ROWS).min(group_rows as u64));
                    let time = times[row as usize];
                    match runs.last_mut() {
                        Some(last) if last.1 >= start => {
                            last.1 = last.1.max(end);
                            last.2 = (last.2 .0.min(time), last.2 .1.max(time));
                        }
                        _ => runs.push((start, end, (time, time))),
                    }
                }
                let covered_blocks = runs.iter().map(|(start, end, _)| (end - start).div_ceil(BLOCK_ROWS)).sum::<u64>() as usize;
                let whole = covered_blocks * DENSE_DIVISOR > blocks;
                anyhow::ensure!(records.len() < MAX_RECORDS, "entity index source exceeds record memory budget");
                records.push(Record {
                    hash,
                    src: 0,
                    group: group as u32,
                    whole,
                    runs: if whole { Vec::new() } else { cap_runs(runs, MAX_RUNS) },
                });
            }
        }
    }
    Ok((records, coverage))
}

/// Write `records` (sorted by `(hash, src, group)`) to `path`; returns the
/// sparse seek index and the byte length.
/// NAN-4213: drop `[0, end)` of `file` from the page cache (clean pages
/// only: written ranges are synced first). Advisory; errors are ignored.
fn drop_cached(file: &std::fs::File, end: u64) {
    use std::os::fd::AsRawFd;
    // SAFETY: a valid open descriptor; posix_fadvise reads no memory.
    let _ = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, end as libc::off_t, libc::POSIX_FADV_DONTNEED) };
}

/// A sequential reader that drops what it has read from the page cache
/// every [`DROP_CACHE_EVERY`] bytes (NAN-4213).
struct UncachedReader {
    file: std::fs::File,
    read: u64,
    dropped: u64,
}

impl Read for UncachedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.file.read(buf)?;
        self.read += n as u64;
        if n == 0 || self.read - self.dropped >= DROP_CACHE_EVERY {
            drop_cached(&self.file, self.read);
            self.dropped = self.read;
        }
        Ok(n)
    }
}

fn write_sorted(path: &Path, records: impl Iterator<Item = anyhow::Result<Record>>) -> anyhow::Result<(Vec<(u64, u64)>, u64)> {
    let mut out = BufWriter::with_capacity(256 * 1024, std::fs::File::create(path)?);
    let (mut sparse, mut offset, mut count) = (Vec::new(), 0_u64, 0_usize);
    let mut dropped = 0_u64;
    let mut previous: Option<(u64, u32, u32)> = None;
    for record in records {
        let record = record?;
        let key = (record.hash, record.src, record.group);
        anyhow::ensure!(previous.is_none_or(|previous| previous < key), "entity index records out of order");
        previous = Some(key);
        if count.is_multiple_of(SPARSE_EVERY) {
            sparse.push((record.hash, offset));
        }
        anyhow::ensure!(offset.saturating_add(18 + 24 * record.runs.len() as u64) <= MAX_INDEX_BYTES,
            "entity index exceeds disk budget");
        offset += write_record(&mut out, &record)?;
        count += 1;
        if offset - dropped >= DROP_CACHE_EVERY {
            // Written pages are dirty until synced; only clean pages drop.
            out.flush()?;
            out.get_ref().sync_data()?;
            drop_cached(out.get_ref(), offset);
            dropped = offset;
        }
    }
    let file = out.into_inner().map_err(|error| anyhow::anyhow!("{error}"))?;
    file.sync_all()?;
    drop_cached(&file, offset);
    Ok((sparse, offset))
}

/// Merge the previous file's still-live records (renumbered by `renumber`,
/// which is monotone) with `tail` (sorted) into one sorted stream.
fn merged_stream(
    previous: Option<(&Path, BTreeMap<u32, u32>, u64)>,
    tail: Vec<Record>,
) -> anyhow::Result<impl Iterator<Item = anyhow::Result<Record>>> {
    let mut old = match previous {
        Some((path, renumber, expected_bytes)) => {
            let file = std::fs::File::open(path)?;
            anyhow::ensure!(file.metadata()?.len() == expected_bytes, "entity index length changed before rebuild");
            let mut reader = BufReader::with_capacity(256 * 1024, UncachedReader { file, read: 0, dropped: 0 });
            let mut consumed = 0_u64;
            Some(std::iter::from_fn(move || loop {
                match read_record(&mut reader) {
                    Ok(None) if consumed != expected_bytes => return Some(Err(anyhow::anyhow!("entity index truncated during rebuild"))),
                    Ok(None) => return None,
                    Err(error) => return Some(Err(anyhow::Error::from(error))),
                    Ok(Some(mut record)) => {
                        consumed += 18 + 24 * record.runs.len() as u64;
                        match renumber.get(&record.src) {
                            Some(new) => {
                                record.src = *new;
                                return Some(Ok(record));
                            }
                            None => continue,
                        }
                    }
                }
            }).peekable())
        }
        None => None,
    };
    let mut tail = tail.into_iter().peekable();
    Ok(std::iter::from_fn(move || {
        let take_old = match (old.as_mut().and_then(|old| old.peek()), tail.peek()) {
            (None, None) => return None,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (Some(Err(_)), _) => true,
            (Some(Ok(a)), Some(b)) => (a.hash, a.src, a.group) <= (b.hash, b.src, b.group),
        };
        if take_old { old.as_mut().and_then(Iterator::next) } else { tail.next().map(Ok) }
    }))
}

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub built: bool,
    pub sources: usize,
    pub tail: usize,
    pub bytes: u64,
}

fn path_text(path: &Path) -> QueryResult<String> {
    path.to_str().map(ToOwned::to_owned).ok_or_else(|| internal("entity index path is not UTF-8"))
}

/// One pass over the window ending at `now_us`: fold up to
/// [`MAX_TAIL_FILES`] resident live data files outside the index (and drop
/// the sources that left the window) when [`needs_rebuild`] says so.
/// Single-flight; starts only while every query slot is free and no durable
/// job runs; the extraction runs on the blocking pool.
pub async fn merge_once(engine: &PartQueryEngine, state_dir: &Path, now_us: i64) -> QueryResult<MergeReport> {
    let slot = engine.entity_index();
    let Ok(_build) = slot.build.try_lock() else {
        return Ok(MergeReport::default());
    };
    let dir = state_dir.join(DIR);
    if !slot.swept.swap(true, Ordering::SeqCst) {
        // An earlier process's coverage lived in its memory: never read.
        let _ = std::fs::remove_dir_all(&dir);
    }
    let current = slot.current();
    let unchanged = |current: &Option<Arc<EntityIndex>>| MergeReport {
        sources: current.as_ref().map_or(0, |index| index.sources.len()),
        bytes: current.as_ref().map_or(0, |index| index.bytes),
        ..MergeReport::default()
    };
    if slot.backing_off(Instant::now()) || engine.job_running()
        || slot.retired.lock().expect("entity index retired").strong_count() > 0
    {
        return Ok(unchanged(&current));
    }
    let Some(admission) = engine.try_admit_idle() else {
        return Ok(unchanged(&current));
    };
    let (parts, _, _, _) = engine.snapshot(now_us.saturating_sub(WINDOW_US), now_us).await?;
    // A larger window remains queryable; only this bounded prefix is
    // considered for index coverage. The rest uses per-file evidence.
    let parts = parts.into_iter().take(MAX_INDEX_SOURCES).collect::<Vec<_>>();
    let records = engine.fetcher().records(&parts).await.map_err(|error| internal(format!("{error:#}")))?;
    let mut live = BTreeSet::new();
    let mut files = Vec::new();
    let mut shapes = BTreeMap::new();
    'sources: for (part, record) in parts.iter().zip(&records) {
        for (index, data) in record.files.data.iter().enumerate() {
            let key = SourceKey { part: part.part_id.clone(), index, sha256: data.sha256.clone() };
            live.insert(key.clone());
            shapes.insert(key, (part.clone(), data.row_groups as usize, data.rows));
            files.push((part.clone(), index));
            if live.len() >= MAX_INDEX_SOURCES {
                break 'sources;
            }
        }
    }
    if live.is_empty() {
        drop(current);
        slot.clear();
        return Ok(MergeReport::default());
    }
    let resident_ids = engine.fetcher().resident_data_files(&files).await;
    let resident = live.iter().filter(|key| resident_ids.contains(&(key.part.clone(), key.index))).cloned().collect::<BTreeSet<_>>();
    if !needs_rebuild(current.as_deref(), &live, &resident) {
        return Ok(unchanged(&current));
    }
    // New numbering: the previous file's live sources first (old order),
    // then the tail.
    let mut covered = BTreeMap::new();
    let mut renumber = BTreeMap::new();
    if let Some(index) = &current {
        let mut kept = index.sources.iter().filter(|(key, _)| live.contains(*key)).collect::<Vec<_>>();
        kept.sort_by_key(|(_, coverage)| coverage.src);
        for (key, coverage) in kept {
            let src = covered.len() as u32 + 1;
            renumber.insert(coverage.src, src);
            covered.insert(key.clone(), Coverage { src, groups: coverage.groups.clone() });
        }
    }
    let remaining_sources = MAX_INDEX_SOURCES.saturating_sub(covered.len());
    let tail_keys = resident.iter().filter(|key| !covered.contains_key(*key)).take(MAX_TAIL_FILES.min(remaining_sources)).cloned().collect::<Vec<_>>();
    let wanted = tail_keys.iter().map(|key| (shapes[key].0.clone(), super::fetch::PartFile::Data(key.index))).collect::<Vec<_>>();
    // Resident files: leasing them fetches nothing (an eviction race costs
    // one fetch, as for a query).
    let leases = engine.fetcher().ensure_files(&wanted).await.map_err(|error| internal(format!("{error:#}")))?;
    let mut tail_inputs = Vec::new();
    for key in &tail_keys {
        let Some(local) = leases.path(&key.part, super::fetch::PartFile::Data(key.index)) else { continue };
        if local.sha256 != key.sha256 || local.sparse {
            continue;
        }
        tail_inputs.push((key.clone(), local.path.clone(), shapes[key].1, shapes[key].2));
    }
    // The slot only gated the start.
    drop(admission);
    let fields = current.as_ref().map_or_else(fields, |index| index.fields.clone());
    if current.as_ref().is_some_and(|index| index.fields != self::fields()) {
        // A changed field list rebuilds from scratch (old records are keyed
        // by the old bit numbering).
        renumber.clear();
        covered.clear();
    }
    let fields = if covered.is_empty() { self::fields() } else { fields };
    if fields.is_empty() {
        slot.clear();
        return Ok(MergeReport::default());
    }
    let previous = match &current {
        Some(index) if !renumber.is_empty() => Some((index.path.clone(), renumber, index.bytes)),
        _ => None,
    };
    std::fs::create_dir_all(&dir).map_err(internal)?;
    let id = uuid::Uuid::new_v4().simple();
    let temporary = dir.join(format!(".{PREFIX}{id}.tmp"));
    let target = dir.join(format!("{PREFIX}{id}.bin"));
    let started = Instant::now();
    let first_id = covered.len() as u32 + 1;
    let covered_groups = covered.values().map(|coverage| coverage.groups.len()).sum::<usize>();
    let build_fields = fields.clone();
    let budget = MAX_INDEX_BYTES.saturating_sub(current.as_ref().map_or(0, |index| index.bytes));
    let temp = temporary.clone();
    let removed_sources = current.as_ref().is_some_and(|index| index.sources.len() != covered.len());
    let built = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<(Vec<(SourceKey, Coverage)>, Vec<(u64, u64)>, u64)>> {
        let mut tail = Vec::new();
        let mut added = Vec::new();
        let mut estimate = 0_u64;
        let mut total_groups = covered_groups;
        for (offset, (key, path, groups, rows)) in tail_inputs.into_iter().enumerate() {
            if total_groups.saturating_add(groups) > MAX_INDEX_GROUPS {
                continue;
            }
            let src = first_id + offset as u32;
            let (mut records, coverage) = match extract(&path, &build_fields, groups) {
                Ok(extracted) => extracted,
                Err(error) => {
                    tracing::warn!(part = %key.part, file = key.index, error = %error, "entity index skipped a data file");
                    continue;
                }
            };
            if coverage.iter().map(|group| u64::from(group.rows)).sum::<u64>() != rows {
                continue;
            }
            estimate += records.iter().map(|record| 18 + 24 * record.runs.len() as u64).sum::<u64>();
            if estimate > budget || tail.len().saturating_add(records.len()) > MAX_RECORDS {
                break;
            }
            total_groups += coverage.len();
            records.iter_mut().for_each(|record| record.src = src);
            tail.extend(records);
            added.push((key, Coverage { src, groups: coverage }));
        }
        // A saturated or unindexable tail must not rewrite up to 1 GiB
        // every minute without gaining coverage.
        if added.is_empty() && !removed_sources {
            return Ok(None);
        }
        tail.sort_unstable_by_key(|record| (record.hash, record.src, record.group));
        let (sparse, bytes) = write_sorted(&temp, merged_stream(previous.as_ref().map(|(path, map, bytes)| (path.as_path(), map.clone(), *bytes)), tail)?)?;
        Ok(Some((added, sparse, bytes)))
    })
    .await
    .map_err(internal)
    .and_then(|built| built.map_err(|error| internal(format!("{error:#}"))))
    .and_then(|built| match built {
        Some(built) => std::fs::rename(&temporary, &target).map_err(internal).map(|()| Some(built)),
        None => Ok(None),
    });
    drop(leases);
    let (added, sparse, bytes) = match built {
        Ok(Some(built)) => built,
        Ok(None) => {
            slot.record_failure(Some(Instant::now()));
            return Ok(unchanged(&current));
        }
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            slot.record_failure(Some(Instant::now()));
            return Err(error);
        }
    };
    slot.record_failure(None);
    let tail = added.len();
    covered.extend(added);
    let report = MergeReport { built: true, sources: covered.len(), tail, bytes };
    tracing::info!(sources = report.sources, tail = report.tail, bytes = report.bytes, wall_ms = started.elapsed().as_millis() as u64,
        path = %path_text(&target).unwrap_or_default(), "window entity index merged");
    slot.replace(EntityIndex { path: target, fields, sources: covered, sparse, bytes });
    drop(current);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity(path: &str, value: &str) -> CandidateHint {
        CandidateHint::Entity { source_path: path.into(), value: value.into() }
    }

    fn part(name: &str) -> PartId {
        let digest = crate::parts::sha256_hex(name.as_bytes());
        PartId::parse(&format!("{:013}-{}", 1, &digest[..16])).unwrap()
    }

    fn key(name: &str) -> SourceKey {
        SourceKey { part: part(name), index: 0, sha256: crate::parts::sha256_hex(format!("data {name}").as_bytes()) }
    }

    const FIELDS: [&str; 2] = ["device.hostname", "user.name"];

    fn index_of(dir: &Path, records: Vec<Record>, sources: Vec<(SourceKey, Coverage)>) -> EntityIndex {
        let path = dir.join(format!("{PREFIX}{}.bin", uuid::Uuid::new_v4().simple()));
        let mut records = records;
        records.sort_unstable_by_key(|record| (record.hash, record.src, record.group));
        let (sparse, bytes) = write_sorted(&path, records.into_iter().map(Ok)).unwrap();
        EntityIndex { path, fields: FIELDS.iter().map(|f| f.to_string()).collect(), sources: sources.into_iter().collect(), sparse, bytes }
    }

    fn record(path: &str, value: &str, src: u32, group: u32, runs: BlockRuns) -> Record {
        Record { hash: key_hash(path, value), src, group, whole: false, runs }
    }

    fn cover(src: u32, groups: &[(u32, u32)]) -> Coverage {
        Coverage { src, groups: groups.iter().map(|(rows, known)| GroupCoverage { rows: *rows, known: *known }).collect() }
    }

    #[test]
    fn on_by_default_and_fields_are_bloom_paths() {
        // NAN-4772: no switch; a cell that still sets the old variable
        // (hosted feature env) changes nothing.
        assert!(enabled());
        assert_eq!(fields_from(None), DEFAULT_FIELDS.iter().map(|f| f.to_string()).collect::<Vec<_>>());
        assert_eq!(fields_from(Some("user.name, metadata.uid, bogus, device.hostname, user.name")), vec!["device.hostname", "user.name"]);
    }

    #[test]
    fn exact_runs_unknown_groups_keep_and_absent_values_prune() {
        let dir = tempfile::tempdir().unwrap();
        // Source a: two groups, both fields known. Source b: hostname unknown
        // in group 1. Source c: not covered.
        let (a, b, c) = (key("a"), key("b"), key("c"));
        let index = index_of(dir.path(), vec![
            record("device.hostname", "ws-1", 1, 0, vec![(1_024, 2_048, (10, 20))]),
            record("device.hostname", "ws-1", 2, 0, vec![(0, 1_024, (5, 6)), (4_096, 5_120, (50, 60))]),
            record("user.name", "alice", 2, 0, vec![(4_096, 6_144, (55, 70))]),
            Record { hash: key_hash("device.hostname", "ws-1"), src: 1, group: 1, whole: true, runs: Vec::new() },
            record("device.hostname", "other", 1, 1, vec![(0, 1_024, (1, 2))]),
        ], vec![(a.clone(), cover(1, &[(8_192, 3), (8_192, 3)])), (b.clone(), cover(2, &[(8_192, 3), (8_192, 2)]))]);
        let files = vec![(a.clone(), 2, 16_384), (b.clone(), 2, 16_384), (c.clone(), 1, 10), (a.clone(), 3, 16_384)];
        let got = index.evidence(&[entity("device.hostname", "WS-1")], &files).unwrap();
        let ea = got[0].as_ref().unwrap();
        assert_eq!(ea.mask, vec![true, true]);
        assert_eq!(ea.fine, vec![Some(vec![(1_024, 2_048, (10, 20))]), None], "dense group is read whole");
        assert!(ea.answered);
        let eb = got[1].as_ref().unwrap();
        assert_eq!(eb.mask, vec![true, true]);
        assert_eq!(eb.fine[1], None, "unknown field keeps the group");
        assert!(!eb.answered);
        assert!(got[2].is_none(), "uncovered file: per-file path");
        assert!(got[3].is_none(), "shape mismatch: per-file path");
        // An absent value prunes known groups only.
        let absent = index.evidence(&[entity("device.hostname", "nobody")], &files).unwrap();
        assert_eq!(absent[0].as_ref().unwrap().mask, vec![false, false]);
        assert_eq!(absent[1].as_ref().unwrap().mask, vec![false, true]);
        // AND intersects runs and times; OR unions; non-indexed hints keep.
        let both = index.evidence(&[entity("device.hostname", "ws-1"), entity("user.name", "alice")], &files).unwrap();
        assert_eq!(both[1].as_ref().unwrap().fine[0], Some(vec![(4_096, 5_120, (55, 60))]));
        assert_eq!(both[0].as_ref().unwrap().mask, vec![false, false], "alice is in no group of a");
        let any = CandidateHint::Any { alternatives: vec![entity("device.hostname", "other"), entity("device.hostname", "ws-1")] };
        let either = index.evidence(&[any], &files).unwrap();
        assert_eq!(either[0].as_ref().unwrap().fine, vec![Some(vec![(1_024, 2_048, (10, 20))]), None]);
        let unknown_alt = CandidateHint::Any { alternatives: vec![entity("src_endpoint.ip", "10.0.0.1"), entity("device.hostname", "ws-1")] };
        assert_eq!(index.evidence(&[unknown_alt], &files).unwrap()[0].as_ref().unwrap().fine, vec![None, None]);
        let keyword = CandidateHint::Keyword { mode: Default::default(), value: "x".into() };
        let mixed = index.evidence(&[keyword, entity("device.hostname", "ws-1")], &files).unwrap();
        assert_eq!(mixed[0].as_ref().unwrap().fine[0], Some(vec![(1_024, 2_048, (10, 20))]));
        assert!(!index.answers(&[entity("src_endpoint.ip", "10.0.0.1")]));
        assert!(index.answers(&[entity("user.name", "x")]));
        assert!(!index.answers(&[entity("user.name", "Älice")]));
    }

    #[test]
    fn incomplete_index_and_changed_source_fail_open() {
        let dir = tempfile::tempdir().unwrap();
        let source = key("a");
        let index = index_of(dir.path(), vec![
            record("device.hostname", "host", 1, 0, vec![(0, 1_024, (1, 2))]),
        ], vec![(source.clone(), cover(1, &[(8_192, 3)]))]);
        let hint = [entity("device.hostname", "host")];
        let mut changed = source.clone();
        changed.sha256 = crate::parts::sha256_hex(b"replacement");
        assert!(index.evidence(&hint, &[(changed, 1, 8_192)]).unwrap()[0].is_none());
        for bytes in [0, 1, 17, 18, index.bytes - 1] {
            std::fs::OpenOptions::new().write(true).open(index.path()).unwrap().set_len(bytes).unwrap();
            assert!(index.evidence(&hint, &[(source.clone(), 1, 8_192)]).is_none(), "partial file {bytes}: scan");
        }
        assert!(merged_stream(Some((index.path(), BTreeMap::from([(1, 1)]), index.bytes)), Vec::new()).is_err(),
            "a truncated generation cannot be copied into a supposedly complete rebuild");
        std::fs::remove_file(index.path()).unwrap();
        assert!(index.evidence(&hint, &[(source, 1, 8_192)]).is_none(), "missing file: scan");
        assert!(read_record(&mut &[][..]).unwrap().is_none());
        assert!(read_record(&mut &[0_u8; 17][..]).is_err(), "partial header is an error");
    }

    #[test]
    fn lookup_budget_returns_unknown_instead_of_partial_records() {
        let dir = tempfile::tempdir().unwrap();
        let index = index_of(dir.path(), vec![
            record("user.name", "alice", 1, 0, vec![(0, 1_024, (1, 2))]),
            record("user.name", "alice", 2, 0, vec![(0, 1_024, (1, 2))]),
        ], Vec::new());
        assert!(index.records_of(key_hash("user.name", "alice"), &mut 1).is_none());
        assert_eq!(index.records_of(key_hash("user.name", "alice"), &mut 2).unwrap().len(), 2);
        let hints = vec![entity("user.name", "alice"); MAX_LOOKUP_LEAVES + 1];
        assert!(index.evidence(&hints, &[]).is_none());
    }

    #[test]
    fn many_keys_seek_through_the_sparse_index() {
        let dir = tempfile::tempdir().unwrap();
        let records = (0..5_000).map(|n| record("user.name", &format!("u{n}"), 1, 0, vec![(0, 1_024, (n, n))])).collect::<Vec<_>>();
        let index = index_of(dir.path(), records, vec![(key("a"), cover(1, &[(1_024, 3)]))]);
        assert!(index.sparse.len() > 10);
        for n in [0_i64, 1, 255, 256, 257, 4_999] {
            let got = index.evidence(&[entity("user.name", &format!("U{n}"))], &[(key("a"), 1, 1_024)]).unwrap();
            assert_eq!(got[0].as_ref().unwrap().fine, vec![Some(vec![(0, 1_024, (n, n))])], "u{n}");
        }
    }

    #[test]
    fn merge_keeps_live_renumbered_records_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let previous = index_of(dir.path(), vec![
            record("user.name", "a", 1, 0, vec![(0, 1_024, (1, 1))]),
            record("user.name", "a", 2, 0, vec![(0, 1_024, (2, 2))]),
            record("user.name", "a", 3, 0, vec![(0, 1_024, (3, 3))]),
        ], Vec::new());
        // Source 2 left the window: 1 -> 1, 3 -> 2; the tail is source 3.
        let tail = vec![record("user.name", "a", 3, 0, vec![(0, 1_024, (4, 4))])];
        let renumber = BTreeMap::from([(1, 1), (3, 2)]);
        let merged = merged_stream(Some((previous.path(), renumber, previous.bytes)), tail).unwrap().collect::<anyhow::Result<Vec<_>>>().unwrap();
        assert_eq!(merged.iter().map(|record| (record.src, record.runs[0].2 .0)).collect::<Vec<_>>(), vec![(1, 1), (2, 3), (3, 4)]);
        let out = dir.path().join("out.bin");
        assert!(write_sorted(&out, merged.into_iter().rev().map(Ok)).is_err(), "out-of-order records fail the build");
    }

    #[test]
    fn runs_cap_and_hull_stay_supersets() {
        let runs = vec![(0, 1_024, (1, 2)), (2_048, 3_072, (5, 6)), (3_072 * 4, 3_072 * 4 + 1_024, (9, 9))];
        assert_eq!(cap_runs(runs.clone(), 2), vec![(0, 3_072, (1, 6)), (12_288, 13_312, (9, 9))]);
        assert_eq!(hull(&runs), vec![(0, 13_312, (1, 9))]);
        assert_eq!(intersect(&vec![(0, 2_048, (1, 5))], &vec![(1_024, 4_096, (6, 9))]), Vec::new(), "disjoint times: no row matches both");
        assert_eq!(union(vec![(1_024, 2_048, (3, 4)), (0, 1_024, (1, 2))]), vec![(0, 2_048, (1, 4))]);
    }

    #[test]
    fn rebuild_when_tail_or_stale_share_grows() {
        let dir = tempfile::tempdir().unwrap();
        // `indexed` sources in the index, `total` live: a tail of exactly
        // REBUILD_FILES fits, and REBUILD_FILES stale sources are at least
        // a quarter of the index.
        let (indexed, total) = (4 * REBUILD_FILES, 5 * REBUILD_FILES);
        let keys = (0..total).map(|n| key(&format!("s{n}"))).collect::<Vec<_>>();
        let set = |range: std::ops::Range<usize>| keys[range].iter().cloned().collect::<BTreeSet<_>>();
        assert!(!needs_rebuild(None, &set(0..total), &set(0..FIRST_BUILD_FILES - 1)));
        assert!(needs_rebuild(None, &set(0..total), &set(0..FIRST_BUILD_FILES)));
        let index = index_of(dir.path(), Vec::new(), keys[..indexed].iter().enumerate().map(|(n, key)| (key.clone(), cover(n as u32 + 1, &[(1, 0)]))).collect());
        assert!(!needs_rebuild(Some(&index), &set(0..total), &set(0..indexed)));
        assert!(!needs_rebuild(Some(&index), &set(0..total), &set(0..indexed + REBUILD_FILES - 1)), "a short tail waits");
        assert!(needs_rebuild(Some(&index), &set(0..total), &set(0..indexed + REBUILD_FILES)), "tail");
        assert!(!needs_rebuild(Some(&index), &set(REBUILD_FILES - 1..total), &set(REBUILD_FILES..indexed)), "a non-resident live source is not stale");
        assert!(needs_rebuild(Some(&index), &set(REBUILD_FILES..total), &set(REBUILD_FILES..indexed)), "stale");
    }

    #[test]
    fn a_replaced_index_file_is_removed_after_its_last_reader() {
        let dir = tempfile::tempdir().unwrap();
        let slot = Slot::default();
        let first = index_of(dir.path(), Vec::new(), Vec::new());
        let first_path = first.path.clone();
        slot.replace(first);
        let reader = slot.current().unwrap();
        slot.replace(index_of(dir.path(), Vec::new(), Vec::new()));
        assert!(first_path.is_file());
        assert_eq!(slot.retired.lock().unwrap().strong_count(), 1, "a reader blocks the next rebuild");
        drop(reader);
        assert_eq!(slot.retired.lock().unwrap().strong_count(), 0, "rebuild may resume");
        assert!(!first_path.exists());
        slot.clear();
        assert!(slot.current().is_none());
    }

    #[test]
    fn oversized_decodes_and_source_records_are_not_covered() {
        use arrow_array::{RecordBatch, StringArray, TimestampMicrosecondArray};
        use arrow_schema::{DataType, Field, Schema, TimeUnit};
        let dir = tempfile::tempdir().unwrap();
        let schema = Arc::new(Schema::new(vec![
            Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())), false),
            Field::new("host", DataType::Utf8, false),
        ]));
        for (name, rows, wide) in [("bytes", 2_000, true), ("records", MAX_RECORDS + 1, false)] {
            let path = dir.path().join(format!("{name}.parquet"));
            let hosts = StringArray::from((0..rows).map(|n| if wide { "x".repeat(10_000) } else { format!("host-{n}") }).collect::<Vec<_>>());
            let batch = RecordBatch::try_new(schema.clone(), vec![
                Arc::new(TimestampMicrosecondArray::from((0..rows as i64).collect::<Vec<_>>()).with_timezone("UTC")),
                Arc::new(hosts),
            ]).unwrap();
            let props = parquet::file::properties::WriterProperties::builder()
                .set_max_row_group_row_count(Some(65_536)).set_dictionary_enabled(!wide).build();
            let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), schema.clone(), Some(props)).unwrap();
            writer.write(&batch).unwrap();
            writer.close().unwrap();
            let error = extract(&path, &["host".into()], rows.div_ceil(65_536)).unwrap_err();
            assert!(error.to_string().contains(if wide { "decoder byte budget" } else { "record memory budget" }), "{name}: {error}");
            if wide {
                // The same long value, dictionary encoded, is safe with
                // the production Utf8View reader and still indexes exactly.
                let path = dir.path().join("dictionary.parquet");
                let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), schema.clone(), None).unwrap();
                writer.write(&batch).unwrap();
                writer.close().unwrap();
                let (records, groups) = extract(&path, &["host".into()], 1).unwrap();
                assert_eq!(records.len(), 1);
                assert_eq!(groups, vec![GroupCoverage { rows: rows as u32, known: 1 }]);
                assert!(records[0].whole);
            }
        }
    }

    #[test]
    fn extract_records_block_runs_with_matching_row_times() {
        use arrow_array::{RecordBatch, StringArray, StructArray, TimestampMicrosecondArray};
        use arrow_schema::{DataType, Field, Fields, Schema, TimeUnit};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.parquet");
        let rows = 40_000_usize;
        let host = |i: usize| if i % 9_000 < 2 { "ws-rare.corp".to_string() } else if i % 2 == 0 { "busy".to_string() } else { format!("h{}", i % 50) };
        let device = Fields::from(vec![Field::new("hostname", DataType::Utf8, true)]);
        let schema = Arc::new(Schema::new(vec![
            Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())), false),
            Field::new("device", DataType::Struct(device.clone()), true),
        ]));
        let hosts = StringArray::from((0..rows).map(host).collect::<Vec<_>>());
        let batch = RecordBatch::try_new(schema.clone(), vec![
            Arc::new(TimestampMicrosecondArray::from((0..rows as i64).map(|i| i * 10).collect::<Vec<_>>()).with_timezone("UTC")),
            Arc::new(StructArray::new(device, vec![Arc::new(hosts)], None)),
        ]).unwrap();
        let props = parquet::file::properties::WriterProperties::builder().set_max_row_group_row_count(Some(32_768)).build();
        let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), schema, Some(props)).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        let fields = vec!["device.hostname".to_string(), "user.name".to_string()];
        let (records, coverage) = extract(&path, &fields, 2).unwrap();
        assert_eq!(coverage, vec![GroupCoverage { rows: 32_768, known: 1 }, GroupCoverage { rows: 7_232, known: 1 }]);
        let rare = records.iter().filter(|record| record.hash == key_hash("device.hostname", "ws-rare.corp")).collect::<Vec<_>>();
        // Rows 0,1 / 9000,9001 / 18000,18001 / 27000,27001 in group 0;
        // 36000,36001 in group 1 (its rows 3232,3233).
        assert_eq!(rare.len(), 2);
        assert_eq!(rare[0].runs, vec![(0, 1_024, (0, 10)), (8_192, 9_216, (90_000, 90_010)), (17_408, 18_432, (180_000, 180_010)), (26_624, 27_648, (270_000, 270_010))]);
        assert_eq!(rare[1].runs, vec![(3_072, 4_096, (360_000, 360_010))]);
        let busy = records.iter().find(|record| record.hash == key_hash("device.hostname", "busy") && record.group == 0).unwrap();
        assert!(busy.whole && busy.runs.is_empty(), "dense value: whole group");
        assert!(extract(&path, &fields, 3).is_err(), "group count must match the signed record");
        let wide_fields = vec!["device.hostname".to_string(); 9];
        assert!(extract(&path, &wide_fields, 2).is_err(), "row/field working set is bounded before decoding");
    }
}
