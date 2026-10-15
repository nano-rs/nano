// SPDX-License-Identifier: AGPL-3.0-or-later

//! Newest-first progressive paging over parts (the reader's
//! `progressive_newest_first` path, same constants and chunk walk).
//!
//! A bounded newest-first event page (`… | head N`, a timeline) is answered
//! from geometrically widening time windows walked back from the newest data:
//! 1 minute, 2, 4, … (each probe at most half the remainder, at most 12
//! chunks), stopping once the page is full. Chunks are disjoint and each is
//! fenced by the planner's own `SourceTimeFence`, so concatenating chunk
//! results newest-first is exactly the full-range result. Part selection is
//! per chunk, so only the files a chunk can touch are fetched. A chunk that
//! exhausts chDB memory is bisected and retried, as in the reader.

//!
//! NAN-3265: every newest-first page walks, whatever its offset + limit. The
//! walk used to be limited to offset + limit <= 1,000; a deeper page (an
//! offset 800 + limit 200 scroll, a 2,000-row page, a 50k export) planned its
//! whole window as one statement and decoded every matching wide OCSF row,
//! so latency jumped from ~0.8 s to >30 s (or "Interactive query exhausted
//! its memory budget") at that line. Deeper pages now walk the same chunks,
//! with every statement bounded by [`CHUNK_ROW_CAP`] rows: a chunk holding
//! more continues inside itself from its last row's `(time, metadata.uid)`
//! cursor ([`continuation`]). Rows kept are exactly offset + limit (+1), the
//! work done is roughly linear in them, and no statement ever decodes more
//! than one cap of wide rows.

use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};

/// The walk serves every page the request contract admits (offset + limit
/// within the one-million-row result envelope, plus its sentinel row).
pub const MAX_PROGRESSIVE_RESULT_LIMIT: usize = 1_000_001;
/// NAN-3265: most rows one progressive statement returns. Equal to the
/// exact-fence instant bound, so every capped chunk stays locatable (narrow
/// locate, then a full-width read of exactly the page's instants). At the
/// measured ~8 KB per decoded wide row this is ~32 MB of result per
/// statement, far below the interactive per-statement budget.
pub const CHUNK_ROW_CAP: usize = 4_096;
pub const NEWEST_CHUNK_MINUTES: i64 = 1;
pub const CHUNK_GROWTH: i32 = 2;
pub const MAX_SEED_CHUNKS: usize = 12;
pub const MAX_PLAN_ATTEMPTS: usize = 4_096;
pub const MIN_CHUNK_WIDTH_US: i64 = 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub start: String,
    pub end: String,
    pub start_us: i64,
    pub end_us: i64,
    pub end_inclusive: bool,
    /// NAN-3265: the `(time, metadata.uid)` of the last row already kept
    /// from this chunk's range; only rows strictly after it (in the event
    /// order `time DESC, metadata.uid DESC`) remain to be read.
    pub after: Option<(String, String)>,
    /// NAN-3265: read with the whole remaining page as the statement limit
    /// (no [`CHUNK_ROW_CAP`]); the fallback when a capped chunk cannot be
    /// continued from its last row.
    pub uncapped: bool,
}

/// Every newest-first log page walks (NAN-3265: no 1,000-row line).
pub fn eligible(dataset: &str, newest_first_event_rows: bool, offset: usize, limit: usize) -> bool {
    dataset == "logs" && newest_first_event_rows && offset.saturating_add(limit) < MAX_PROGRESSIVE_RESULT_LIMIT
}

/// Whether a walk for `limit` rows caps its statements (pages within one
/// cap keep their single-statement chunks exactly as before).
pub fn row_capped(limit: usize) -> bool {
    limit > CHUNK_ROW_CAP
}

/// The statement limit of a chunk read once `kept` of `limit` rows are in.
pub fn chunk_row_limit(limit: usize, kept: usize, uncapped: bool) -> usize {
    let remaining = limit.saturating_sub(kept);
    if uncapped || !row_capped(limit) { remaining } else { remaining.min(CHUNK_ROW_CAP) }
}

/// The row target chunk sizing aims at: the page, or one more cap of rows
/// when the page is deeper. Density seeds and re-tiling then size chunks
/// for about a statement's worth of rows instead of the whole page.
pub fn step_target(kept: usize, limit: usize) -> usize {
    limit.min(kept.saturating_add(CHUNK_ROW_CAP))
}

/// A row's event time as RFC3339 microseconds (UTC), from either the
/// RFC3339 or the ClickHouse `YYYY-MM-DD hh:mm:ss[.f]` text form.
pub fn row_time_us(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.timestamp_micros())
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value.trim().trim_end_matches('Z'), "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|time| time.and_utc().timestamp_micros())
        })
}

/// NAN-3265: the rest of a chunk whose capped statement came back full.
/// Rows are in event order, so every row of the chunk not yet kept is at or
/// before the last kept row's instant and after it in the order: the range
/// `[chunk.start, last]` (inclusive) under the cursor `(last, uid)`. `None`
/// when the instant is unreadable or outside the chunk; the caller then
/// rereads the chunk uncapped.
pub fn continuation(chunk: &Chunk, last_time: &str, last_uid: &str) -> Option<Chunk> {
    let last_us = row_time_us(last_time)?;
    let upper = if chunk.end_inclusive { chunk.end_us } else { chunk.end_us - 1 };
    // The planner's cursor fence admits a non-empty, printable uid of at
    // most 2,048 bytes.
    let usable_uid = !last_uid.is_empty() && last_uid.len() <= 2_048 && !last_uid.chars().any(char::is_control);
    if !usable_uid || last_us < chunk.start_us || last_us > upper {
        return None;
    }
    let start = DateTime::<Utc>::from_timestamp_micros(chunk.start_us)?;
    let last = DateTime::<Utc>::from_timestamp_micros(last_us)?;
    let mut next = chunk_after(start, last, true, None);
    next.after = Some((next.end.clone(), last_uid.to_string()));
    Some(next)
}

fn chunk(start: DateTime<Utc>, end: DateTime<Utc>, end_inclusive: bool) -> Chunk {
    chunk_after(start, end, end_inclusive, None)
}

fn chunk_after(start: DateTime<Utc>, end: DateTime<Utc>, end_inclusive: bool, after: Option<(String, String)>) -> Chunk {
    Chunk {
        start: start.to_rfc3339_opts(SecondsFormat::Micros, true),
        end: end.to_rfc3339_opts(SecondsFormat::Micros, true),
        start_us: start.timestamp_micros(),
        end_us: end.timestamp_micros(),
        end_inclusive,
        after,
        uncapped: false,
    }
}

/// The reader's `progressive_seed_chunks`, newest first.
pub fn seed_chunks(start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    if start >= end {
        return vec![chunk(start, end, true)];
    }
    let mut boundary = end;
    let mut width = ChronoDuration::minutes(NEWEST_CHUNK_MINUTES);
    let mut newest = true;
    while boundary > start {
        if chunks.len() + 1 >= MAX_SEED_CHUNKS {
            chunks.push(chunk(start, boundary, newest));
            break;
        }
        let remaining = boundary.signed_duration_since(start);
        let half_remaining = remaining / 2;
        let capped_at_half = width >= half_remaining;
        let probe_width = width.min(half_remaining);
        if probe_width <= ChronoDuration::zero() {
            chunks.push(chunk(start, boundary, newest));
            break;
        }
        let next = boundary - probe_width;
        chunks.push(chunk(next, boundary, newest));
        boundary = next;
        newest = false;
        if capped_at_half {
            chunks.push(chunk(start, boundary, false));
            break;
        }
        width = width.checked_mul(CHUNK_GROWTH).unwrap_or(ChronoDuration::days(365));
    }
    if chunks.is_empty() {
        chunks.push(chunk(start, end, true));
    }
    chunks
}

/// Re-tile the unread older range `[start_us, boundary_us)` after a chunk,
/// sized from the density seen so far: `rows` page rows over the
/// `scanned_us` already walked (newest first). The next chunk is sized to
/// fill the rest of the page with a 25% margin (or, with no row yet, to
/// quadruple the walked width), then chunks double. A predicate that
/// matches ~20 rows a minute fills a 100-row page in two chunks instead of
/// four or five geometric ones, and every chunk is a locate plus a read.
/// Chunks stay disjoint and tile the range, so results never change.
pub fn reseed(start_us: i64, boundary_us: i64, scanned_us: i64, rows: usize, limit: usize) -> Vec<Chunk> {
    let remaining = boundary_us.saturating_sub(start_us);
    if remaining <= 0 {
        return Vec::new();
    }
    let minimum = NEWEST_CHUNK_MINUTES * 60_000_000;
    let scanned = scanned_us.max(1) as i128;
    let wanted = if rows == 0 {
        scanned * 3
    } else {
        let need = limit.saturating_sub(rows).max(1) as i128;
        scanned * need * 5 / (rows as i128 * 4)
    };
    let mut width = wanted.clamp(i128::from(minimum), i128::from(i64::MAX)) as i64;
    let mut chunks = Vec::new();
    let mut boundary = boundary_us;
    while boundary > start_us {
        let left = boundary - start_us;
        // The last chunk takes the rest once it would be most of it anyway.
        let take = if chunks.len() + 1 >= MAX_SEED_CHUNKS || width.saturating_mul(4) >= left.saturating_mul(3) { left } else { width };
        let next = boundary - take;
        chunks.push(chunk_us(next, boundary));
        boundary = next;
        width = width.saturating_mul(i64::from(CHUNK_GROWTH));
    }
    chunks
}

fn chunk_us(start_us: i64, end_us: i64) -> Chunk {
    let at = |micros: i64| DateTime::<Utc>::from_timestamp_micros(micros).expect("chunk bounds come from valid times");
    chunk(at(start_us), at(end_us), false)
}

/// One bounded probe, with the same inclusive upper fence as the newest seed.
/// The caller may still bisect it if planning or execution exceeds budget.
pub fn whole_window_chunk(start: DateTime<Utc>, end: DateTime<Utc>) -> Chunk {
    chunk(start, end, true)
}

/// Row groups a whole-window pre-selection may keep and still be read as
/// one chunk (NAN-3077): ~2 M rows at 65,536-row groups.
pub const SELECTIVE_WINDOW_MAX_GROUPS: usize = 32;

/// NAN-3158: the seeds of a walk whose newest chunk was sized from the
/// entity-ranges density: `[first_start_us, end]` (inclusive, as the newest
/// seed) and the older remainder, which the walk re-tiles after the first
/// chunk from the rows it found ([`reseed`]). A start at or before `start`
/// reads the window whole. Chunks tile the window exactly as the default
/// seeds do, so results never change.
pub fn density_seed(start: DateTime<Utc>, end: DateTime<Utc>, first_start_us: i64) -> Vec<Chunk> {
    let Some(first) = DateTime::<Utc>::from_timestamp_micros(first_start_us).filter(|first| *first > start && *first < end) else {
        return vec![whole_window_chunk(start, end)];
    };
    vec![chunk(first, end, true), chunk(start, first, false)]
}

/// Whether an entity pivot's whole-window selection pruned so far that one
/// fenced read of what survives beats walking widening chunks (each with
/// its own selection, locate and execute): at most
/// [`SELECTIVE_WINDOW_MAX_GROUPS`] row groups kept, and at most a quarter of
/// the groups the time/source/token stages left. A rare pivot then costs
/// one selection and one read instead of up to [`MAX_SEED_CHUNKS`] rounds,
/// so a narrower query is never slower than the broad one it narrows.
/// NAN-3270: share of the executor's result budget a progressive page may
/// hold; the rest is headroom for the response envelope and estimate misses.
pub const PAGE_BYTE_HEADROOM_PERCENT: u64 = 75;
/// NAN-3270: the decoded width assumed for a row before any row of the walk
/// has been seen (decoded wide OCSF rows measure ~8-10 KB).
pub const DEFAULT_ROW_BYTES: u64 = 16 * 1024;
/// NAN-3270: a walk holding page rows stops (byte cut) rather than issue a
/// statement for fewer rows than this; the caller continues from the cursor.
pub const MIN_BYTE_STEP_ROWS: usize = 64;

/// NAN-3270: what the byte side of a walk allows for its next statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteStep {
    /// Read at most this many rows.
    Rows(usize),
    /// The page holds all the bytes it may: stop and return a continuation.
    Cut,
}

/// NAN-3270: a progressive page bounded by the bytes it holds as well as by
/// rows. Rows before the page offset are kept only as `(time, uid)` stubs
/// (the walk needs their count and the last one's cursor, never their
/// payload), so they never count against the budget. Page rows are held
/// until they would exceed the budget; then the walk stops early with the
/// rows that fit and the caller continues from the last row's cursor.
#[derive(Debug, Clone)]
pub struct ByteBudget {
    /// Bytes of page rows a walk may hold (`None`: unbounded).
    budget: Option<u64>,
    /// The page offset: rows before it are stubbed.
    skip: usize,
    held_bytes: u64,
    held_rows: usize,
    /// Every decoded row (offset rows too), for the width estimate.
    seen_bytes: u64,
    seen_rows: u64,
}

/// How many of a statement's rows [`ByteBudget::admit`] kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    pub kept: usize,
    /// Rows were dropped for bytes: the walk must stop here.
    pub cut: bool,
}

impl ByteBudget {
    /// A budget of [`PAGE_BYTE_HEADROOM_PERCENT`] of `result_limit_bytes`
    /// for a page whose first `skip` rows are its offset.
    pub fn new(result_limit_bytes: Option<u64>, skip: usize) -> Self {
        Self {
            budget: result_limit_bytes.map(|limit| limit / 100 * PAGE_BYTE_HEADROOM_PERCENT),
            skip,
            held_bytes: 0,
            held_rows: 0,
            seen_bytes: 0,
            seen_rows: 0,
        }
    }

    pub fn held_bytes(&self) -> u64 {
        self.held_bytes
    }

    /// The width planned per row: the mean decoded width seen so far plus a
    /// quarter, or [`DEFAULT_ROW_BYTES`] before the first row.
    pub fn row_bytes_estimate(&self) -> u64 {
        if self.seen_rows == 0 {
            DEFAULT_ROW_BYTES
        } else {
            (self.seen_bytes / self.seen_rows).saturating_mul(5) / 4
        }
        .max(1)
    }

    /// The next statement's row limit once `kept` rows (stubs included) are
    /// in, given the row side's limit `rows`. In the offset the statement
    /// may use the whole budget (its rows are not held); past it, what the
    /// held page rows left.
    pub fn step(&self, kept: usize, rows: usize) -> ByteStep {
        let Some(budget) = self.budget else { return ByteStep::Rows(rows) };
        let room = if kept < self.skip { budget } else { budget.saturating_sub(self.held_bytes) };
        let fit = usize::try_from(room / self.row_bytes_estimate()).unwrap_or(usize::MAX);
        if fit >= rows {
            return ByteStep::Rows(rows);
        }
        if self.held_rows > 0 && fit < MIN_BYTE_STEP_ROWS {
            return ByteStep::Cut;
        }
        ByteStep::Rows(fit.max(1))
    }

    /// Admit a statement's decoded `rows` (with their raw byte sizes) after
    /// `kept` rows already in: offset rows become stubs, page rows are held
    /// while they fit. The first page row is always held (it already fit
    /// the executor's own per-statement result cap); any row after one that
    /// does not fit is dropped and the walk is cut there.
    pub fn admit(&mut self, kept: usize, rows: &mut Vec<serde_json::Value>, sizes: &[u64]) -> Admitted {
        debug_assert_eq!(rows.len(), sizes.len());
        for (index, size) in sizes.iter().enumerate() {
            self.seen_rows += 1;
            self.seen_bytes = self.seen_bytes.saturating_add(*size);
            if kept + index < self.skip {
                stub(&mut rows[index]);
                continue;
            }
            let over = self.budget.is_some_and(|budget| self.held_bytes.saturating_add(*size) > budget);
            if over && self.held_rows > 0 {
                rows.truncate(index);
                return Admitted { kept: index, cut: true };
            }
            self.held_bytes = self.held_bytes.saturating_add(*size);
            self.held_rows += 1;
            if over {
                // A lone row wider than the budget: hold it, then stop.
                rows.truncate(index + 1);
                return Admitted { kept: index + 1, cut: true };
            }
        }
        Admitted { kept: rows.len(), cut: false }
    }
}

/// An offset row reduced to what the walk reads from it: the event order
/// key `(time, metadata.uid)`.
fn stub(row: &mut serde_json::Value) {
    let field = |row: &serde_json::Value, path: &str| {
        row.get(path).or_else(|| path.split('.').try_fold(row, |value, part| value.get(part))).cloned()
    };
    let mut kept = serde_json::Map::new();
    for path in ["time", "metadata.uid"] {
        if let Some(value) = field(row, path) {
            kept.insert(path.to_string(), value);
        }
    }
    *row = serde_json::Value::Object(kept);
}

/// The raw byte size of each row of a native NDJSON result (its line plus
/// the newline), in [`super::engine::decode_rows`] order.
pub fn line_sizes(data: &[u8]) -> Vec<u64> {
    data.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).map(|line| line.len() as u64 + 1).collect()
}

pub fn selective_window(kept_row_groups: usize, row_groups: usize) -> bool {
    kept_row_groups <= SELECTIVE_WINDOW_MAX_GROUPS && kept_row_groups.saturating_mul(4) <= row_groups
}

/// Bisect a chunk (newer half first); `None` at the minimum width.
pub fn split(chunk_to_split: &Chunk) -> Option<(Chunk, Chunk)> {
    let width = chunk_to_split.end_us - chunk_to_split.start_us;
    if width <= MIN_CHUNK_WIDTH_US {
        return None;
    }
    let start = DateTime::<Utc>::from_timestamp_micros(chunk_to_split.start_us)?;
    let end = DateTime::<Utc>::from_timestamp_micros(chunk_to_split.end_us)?;
    let midpoint = start + ChronoDuration::microseconds(width / 2);
    // The cursor (at the end instant) only constrains the newer half; the
    // older half lies wholly before it.
    let mut newer = chunk_after(midpoint, end, chunk_to_split.end_inclusive, chunk_to_split.after.clone());
    let mut older = chunk(start, midpoint, false);
    newer.uncapped = chunk_to_split.uncapped;
    older.uncapped = chunk_to_split.uncapped;
    Some((newer, older))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progressive_walk_matches_global_page() {
        let end = DateTime::parse_from_rfc3339("2026-09-29T12:00:00Z").unwrap().with_timezone(&Utc);
        let start = end - ChronoDuration::hours(1);
        // Include an event exactly at the boundary and duplicate timestamps.
        let boundary = end.timestamp_micros() - 60_000_000;
        for density in [0, 12, 100, 400, 12_000] {
            let mut times: Vec<i64> = (0..density).map(|n| start.timestamp_micros() + n * 3_600_000_000 / density.max(1)).collect();
            times.extend([boundary, boundary, end.timestamp_micros()]);
            times.sort_unstable_by(|a, b| b.cmp(a));
            let mut pending = std::collections::VecDeque::from(seed_chunks(start, end));
            let (mut rows, mut probes) = (Vec::new(), 0);
            while let Some(chunk) = pending.pop_front() {
                let upper = if chunk.end_inclusive { chunk.end_us } else { chunk.end_us - 1 };
                let found: Vec<_> = times.iter().copied().filter(|t| *t >= chunk.start_us && *t <= upper).take(100).collect();
                probes += 1;
                rows.extend(found);
                if rows.len() >= 100 { rows.truncate(100); break; }
                pending = reseed(start.timestamp_micros(), chunk.start_us, end.timestamp_micros() - chunk.start_us, rows.len(), 100).into();
            }
            assert_eq!(rows, times[..times.len().min(100)]);
            if density == 12_000 { assert_eq!(probes, 1, "dense page stays on the first chunk"); }
        }
    }

    /// NAN-3158: a density-seeded walk tiles the window, returns exactly the
    /// global newest-first top N, and fills a dense page in one chunk.
    #[test]
    fn density_seeded_walk_equals_global_top_n() {
        let end = DateTime::parse_from_rfc3339("2026-09-29T12:00:00Z").unwrap().with_timezone(&Utc);
        let start = end - ChronoDuration::hours(24);
        let (start_us, end_us) = (start.timestamp_micros(), end.timestamp_micros());
        assert_eq!(density_seed(start, end, start_us), vec![whole_window_chunk(start, end)]);
        assert_eq!(density_seed(start, end, end_us), vec![whole_window_chunk(start, end)]);
        let seeded = density_seed(start, end, end_us - 90_000_000);
        assert!(seeded[0].end_inclusive && !seeded[1].end_inclusive);
        assert_eq!((seeded[0].end_us, seeded[0].start_us, seeded[1].end_us, seeded[1].start_us),
            (end_us, end_us - 90_000_000, end_us - 90_000_000, start_us));
        let mut seed = 0x9e37_79b9_u64;
        for density in [50_usize, 2_000, 200_000] {
            let mut times: Vec<i64> = (0..density)
                .map(|_| {
                    seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                    start_us + (seed >> 11) as i64 % (end_us - start_us)
                })
                .collect();
            // Events exactly at the inclusive upper fence and at a boundary.
            times.extend([end_us, end_us, end_us - 1_000_000]);
            times.sort_unstable_by(|a, b| b.cmp(a));
            let per_us = times.len() as f64 / (end_us - start_us) as f64;
            for head in [1_usize, 50, 200] {
                // What the density estimate picks (uniform, 2x margin), and
                // two deliberately wrong first chunks.
                let estimated = end_us - ((2 * head) as f64 / per_us) as i64;
                for first_start in [estimated, end_us - 1_000_000, start_us] {
                    let mut pending = std::collections::VecDeque::from(density_seed(start, end, first_start));
                    let (mut rows, mut executed) = (Vec::new(), 0);
                    while let Some(chunk) = pending.pop_front() {
                        let upper = if chunk.end_inclusive { chunk.end_us } else { chunk.end_us - 1 };
                        rows.extend(times.iter().copied().filter(|t| *t >= chunk.start_us && *t <= upper).take(head));
                        executed += 1;
                        if rows.len() >= head {
                            rows.truncate(head);
                            break;
                        }
                        pending = reseed(start_us, chunk.start_us, end_us - chunk.start_us, rows.len(), head).into();
                    }
                    assert_eq!(rows, times[..head.min(times.len())].to_vec(), "density {density} head {head} first {first_start}");
                    if density == 200_000 && first_start == estimated {
                        assert_eq!(executed, 1, "a dense page fills its density-sized first chunk (head {head})");
                    }
                }
            }
        }
    }

    #[test]
    fn only_a_strongly_pruned_window_is_read_whole() {
        assert!(selective_window(0, 0), "nothing survives: one empty read");
        assert!(selective_window(3, 400));
        assert!(selective_window(32, 128));
        assert!(!selective_window(33, 10_000), "too many groups for one read");
        assert!(!selective_window(10, 20), "pruning too weak: keep the newest-first walk");
    }

    #[test]
    fn seed_chunks_tile_the_range_newest_first() {
        let end = DateTime::parse_from_rfc3339("2026-09-25T00:00:00Z").unwrap().with_timezone(&Utc);
        let start = end - ChronoDuration::hours(24);
        let chunks = seed_chunks(start, end);
        assert!(chunks.len() <= MAX_SEED_CHUNKS);
        assert_eq!(chunks[0].end_us, end.timestamp_micros());
        assert!(chunks[0].end_inclusive && chunks[1..].iter().all(|c| !c.end_inclusive));
        assert_eq!(chunks[0].end_us - chunks[0].start_us, 60_000_000);
        for pair in chunks.windows(2) {
            assert_eq!(pair[0].start_us, pair[1].end_us);
        }
        assert_eq!(chunks.last().unwrap().start_us, start.timestamp_micros());
        let (newer, older) = split(&chunks[0]).unwrap();
        assert!(newer.end_inclusive && !older.end_inclusive && newer.start_us == older.end_us);
    }

    /// Adaptive re-seeding tiles the unread range exactly, newest first, and
    /// a walk that re-seeds after every chunk returns the global top N with
    /// fewer chunks than the fixed geometric seeds.
    #[test]
    fn reseeded_walk_tiles_the_range_and_equals_global_top_n() {
        let end = DateTime::parse_from_rfc3339("2026-09-29T12:00:00Z").unwrap().with_timezone(&Utc);
        let start = end - ChronoDuration::hours(24);
        for (boundary_off, scanned, rows, limit) in [(60, 60, 0, 100), (60, 60, 23, 100), (3_600, 3_600, 99, 100), (86_000, 86_000, 0, 100), (86_399, 86_399, 5, 100)] {
            let boundary = end.timestamp_micros() - boundary_off * 1_000_000;
            let chunks = reseed(start.timestamp_micros(), boundary, scanned * 1_000_000, rows, limit);
            assert!(!chunks.is_empty() && chunks.len() <= MAX_SEED_CHUNKS);
            assert_eq!(chunks[0].end_us, boundary);
            assert_eq!(chunks.last().unwrap().start_us, start.timestamp_micros());
            assert!(chunks.iter().all(|c| !c.end_inclusive && c.start_us < c.end_us));
            for pair in chunks.windows(2) {
                assert_eq!(pair[0].start_us, pair[1].end_us);
            }
        }
        assert!(reseed(10, 10, 5, 0, 100).is_empty());
        // Density: 23 rows in the newest minute sizes the next chunk to ~4.2
        // more minutes, enough for the 77 rows still missing.
        let next = &reseed(start.timestamp_micros(), end.timestamp_micros() - 60_000_000, 60_000_000, 23, 100)[0];
        assert_eq!(next.end_us - next.start_us, 60_000_000 * 77 * 5 / (23 * 4));

        let mut seed = 0x2545_f491_u64;
        for density in [300_usize, 3_000, 30_000] {
            let mut times: Vec<i64> = (0..density)
                .map(|_| {
                    seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                    start.timestamp_micros() + (seed >> 11) as i64 % (end - start).num_microseconds().unwrap()
                })
                .collect();
            times.sort_unstable_by(|a, b| b.cmp(a));
            for head in [1_usize, 50, 100] {
                let walk = |adaptive: bool| {
                    let mut pending = std::collections::VecDeque::from(seed_chunks(start, end));
                    let (mut rows, mut executed) = (Vec::new(), 0);
                    while let Some(chunk) = pending.pop_front() {
                        let upper = if chunk.end_inclusive { chunk.end_us } else { chunk.end_us - 1 };
                        rows.extend(times.iter().copied().filter(|t| *t >= chunk.start_us && *t <= upper).take(head));
                        executed += 1;
                        if rows.len() >= head {
                            rows.truncate(head);
                            break;
                        }
                        if adaptive {
                            pending = reseed(start.timestamp_micros(), chunk.start_us, end.timestamp_micros() - chunk.start_us, rows.len(), head).into();
                        }
                    }
                    (rows, executed)
                };
                let (fixed, fixed_chunks) = walk(false);
                let (adaptive, adaptive_chunks) = walk(true);
                assert_eq!(fixed, times[..head.min(times.len())].to_vec(), "density {density} head {head}");
                assert_eq!(adaptive, fixed, "density {density} head {head}");
                assert!(adaptive_chunks <= fixed_chunks, "density {density} head {head}: {adaptive_chunks} > {fixed_chunks}");
            }
        }
    }

    /// Audit #3: a `head N` timeline paged across chunks must equal the
    /// global newest-first top N. Simulates the engine loop: each chunk runs
    /// the compiled statement (`ORDER BY time DESC LIMIT n`) over its own
    /// fenced rows, results concatenate newest-first, and the walk stops at
    /// the cap the worker reads off the statement. The broken shape (outer
    /// LIMIT = page limit, head inside a stage) returned k*N rows.
    #[test]
    fn multi_chunk_head_page_equals_global_top_n() {
        let end = DateTime::parse_from_rfc3339("2026-09-29T12:00:00Z").unwrap().with_timezone(&Utc);
        let start = end - ChronoDuration::hours(24);
        // Sparse events spread over the day (a deterministic LCG), so the
        // newest minute alone never fills the page and many chunks run.
        let mut seed = 0x2545_f491_u64;
        let mut times: Vec<i64> = (0..600)
            .map(|_| {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                start.timestamp_micros() + (seed >> 11) as i64 % (end - start).num_microseconds().unwrap()
            })
            .collect();
        times.sort_unstable_by(|a, b| b.cmp(a));
        let run = |sql: &str, page_limit: usize| -> (Vec<i64>, usize) {
            let per_chunk = crate::planner::newest_first_row_cap(sql).unwrap_or(page_limit);
            let cap = per_chunk.min(page_limit);
            let mut rows = Vec::new();
            let mut executed = 0;
            for chunk in seed_chunks(start, end) {
                let upper = if chunk.end_inclusive { chunk.end_us } else { chunk.end_us - 1 };
                rows.extend(
                    times.iter().copied().filter(|t| *t >= chunk.start_us && *t <= upper).take(per_chunk),
                );
                executed += 1;
                if rows.len() >= cap {
                    rows.truncate(cap);
                    break;
                }
            }
            (rows, executed)
        };
        for head in [1_usize, 7, 50, 99] {
            let fixed = format!(
                "WITH s0 AS (SELECT * FROM src ORDER BY time DESC), s1 AS (SELECT * FROM s0 LIMIT {head}) \
                 SELECT * FROM s1 ORDER BY time DESC, \"metadata.uid\" DESC LIMIT {head} SETTINGS max_threads=16"
            );
            let (rows, executed) = run(&fixed, 101);
            assert_eq!(rows, times[..head].to_vec(), "head {head}");
            assert!(head < 7 || executed > 1, "the fixture must exercise several chunks (head {head})");
        }
        // The pre-fix statement kept the page limit as its outer LIMIT, so
        // the cap was the page and each chunk contributed its own `head 7`.
        let broken = "WITH s0 AS (SELECT * FROM src ORDER BY time DESC), s1 AS (SELECT * FROM s0 LIMIT 7) \
                      SELECT * FROM s1 ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 101";
        assert_eq!(crate::planner::newest_first_row_cap(broken), Some(101));
        let mut leaked = Vec::new();
        for chunk in seed_chunks(start, end) {
            let upper = if chunk.end_inclusive { chunk.end_us } else { chunk.end_us - 1 };
            leaked.extend(times.iter().copied().filter(|t| *t >= chunk.start_us && *t <= upper).take(7));
            if leaked.len() >= 101 {
                break;
            }
        }
        assert!(leaked.len() > 7, "the fixture reproduces the k*N leak");
    }
}
