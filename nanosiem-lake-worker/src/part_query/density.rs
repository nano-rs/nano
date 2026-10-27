// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3158: density-seeded progressive pivots.
//!
//! A hinted newest-first page (`host=X | sort -time | head N`) used to run a
//! whole-window bloom preselect and then walk geometrically widening chunks
//! from a one-minute seed, each a locate plus a payload statement. Every part
//! already carries `partials/entity_ranges.parquet`: per `(path, value)` the
//! events, first and last time in that part. Read newest part first, those
//! counts say how wide the newest chunk must be to hold the page, and whether
//! the value is dense enough that blooms cannot prune (then the whole-window
//! preselect only fetches and probes every file of the window for nothing).
//!
//! - The first chunk is sized so the estimated matches in it reach
//!   [`DENSITY_MARGIN`] x the page (dense values fill the page in chunk 1).
//! - When matches are more than [`DENSE_DIVISOR`]⁻¹ of the rows consulted, the
//!   whole-window preselect is skipped (each chunk selects its own files).
//!
//! Correctness never depends on the estimate: chunks still tile the window,
//! each is fenced by the planner's time fence and the walk re-seeds after
//! every chunk from the rows it actually found. A wrong estimate costs only
//! an extra chunk or a wider read. The partials are read in-process (Parquet
//! row-group statistics on `path`/`value`, then a filtered decode), never as
//! a chDB statement, and memoized per immutable part.
//!
//! Kill switch: `NANO_LAKE_DENSITY_SEED=0` (default on).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::part_ingest::partials::{EntityRangeRow, PartialRow};
use crate::parts::format::{PartId, ENTITY_RANGE_PATHS, UID_PATH};
use crate::parts::part_log::PartRef;
use crate::parts::provenance::PartialKind;
use crate::planner::CandidateHint;

use super::engine::{PartQueryEngine, QueryResult};
use super::fetch::FileSet;

/// Kill switch (default on): `NANO_LAKE_DENSITY_SEED=0` (or `false`).
pub const FLAG: &str = "NANO_LAKE_DENSITY_SEED";

pub fn enabled() -> bool {
    !std::env::var(FLAG).is_ok_and(|value| matches!(value.as_str(), "0" | "false"))
}

/// Matches above `rows / DENSE_DIVISOR` leave nearly every row group holding
/// one (65k-row groups: ~2k matches each), so blooms prune nothing.
pub const DENSE_DIVISOR: u64 = 32;
/// The first chunk targets this multiple of the page: the uniform-in-time
/// estimate is coarse, and the non-hint filters of the query thin it out.
pub const DENSITY_MARGIN: u64 = 2;
/// The first chunk is never narrower than this (µs).
pub const MIN_FIRST_CHUNK_US: i64 = 1_000_000;
/// Parts whose partials the first batch fetches (newest first); each later
/// batch doubles, up to [`MAX_BATCH_PARTS`]. A dense value is answered by
/// the newest part or two.
const FIRST_BATCH_PARTS: usize = 2;
const MAX_BATCH_PARTS: usize = 8;
/// Most partials one estimate may fetch (memo hits are free). Past it the
/// estimate is extrapolated from the newest parts consulted.
pub const MAX_FETCH_PARTS: usize = 24;
/// Memoized (part, term) answers per process (immutable parts).
const MEMO_ENTRIES: usize = 65_536;

/// One `(path, lowercased value)` lookup term.
pub type Term = (String, String);

/// The hint terms that bound a row's presence: AND of groups, each an OR of
/// terms. Non-entity conjuncts (keywords, source families) are left out,
/// which only over-estimates the matches. `None`: nothing to estimate from.
pub fn term_groups(hints: &[CandidateHint]) -> Option<Vec<Vec<Term>>> {
    fn term(hint: &CandidateHint) -> Option<Term> {
        match hint {
            CandidateHint::Entity { source_path, value }
                if source_path != UID_PATH
                    // Only paths with entity-range rows can be counted.
                    && ENTITY_RANGE_PATHS.contains(&source_path.as_str())
                    && !value.is_empty() =>
            {
                Some((source_path.clone(), lower(value)))
            }
            _ => None,
        }
    }
    let mut groups = Vec::new();
    for hint in hints {
        match hint {
            CandidateHint::Entity { .. } => groups.extend(term(hint).map(|term| vec![term])),
            CandidateHint::Any { alternatives } if !alternatives.is_empty() => {
                // An OR is bounded only when every leg is a countable entity.
                if let Some(mut terms) = alternatives.iter().map(term).collect::<Option<Vec<_>>>() {
                    terms.sort();
                    terms.dedup();
                    groups.push(terms);
                }
            }
            _ => {}
        }
    }
    (!groups.is_empty()).then_some(groups)
}

fn lower(value: &str) -> String {
    if value.is_ascii() {
        value.to_ascii_lowercase()
    } else {
        value.to_lowercase()
    }
}

/// One term's activity in one part: events, first and last time (µs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activity {
    pub events: u64,
    pub first_us: i64,
    pub last_us: i64,
}

impl Activity {
    fn absorb(&mut self, other: Activity) {
        self.events = self.events.saturating_add(other.events);
        self.first_us = self.first_us.min(other.first_us);
        self.last_us = self.last_us.max(other.last_us);
    }
}

/// One consulted part: its bounds and rows, and the hint's activity in it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PartDensity {
    pub min_us: i64,
    pub max_us: i64,
    pub rows: u64,
    pub activity: Option<Activity>,
}

/// The fraction of `[from, to]` (inclusive) that `[lo, hi]` covers, under a
/// uniform spread; an instant (`lo == hi`) is all or nothing.
fn overlap(lo: i64, hi: i64, from: i64, to: i64) -> f64 {
    if hi < from || lo > to {
        return 0.0;
    }
    if hi <= lo {
        return 1.0;
    }
    let (a, b) = (lo.max(from), hi.min(to));
    if b < a {
        0.0
    } else {
        (b - a) as f64 / (hi - lo) as f64
    }
}

/// Estimated matching events in `[from, to]`.
pub(super) fn events_in(parts: &[PartDensity], from: i64, to: i64) -> f64 {
    parts
        .iter()
        .filter_map(|part| {
            part.activity
                .map(|a| a.events as f64 * overlap(a.first_us, a.last_us, from, to))
        })
        .sum()
}

/// Estimated rows of the consulted parts in `[from, to]`.
fn rows_in(parts: &[PartDensity], from: i64, to: i64) -> f64 {
    parts
        .iter()
        .map(|part| part.rows as f64 * overlap(part.min_us, part.max_us, from, to))
        .sum()
}

/// What the consulted partials say about one window.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Estimate {
    /// Estimated matches and rows in the window over the consulted parts.
    pub events: f64,
    pub rows: f64,
    pub consulted_parts: usize,
    pub window_parts: usize,
    pub fetched_parts: usize,
    /// Every part of the window was consulted (`events` is the whole window).
    pub complete: bool,
    /// Start (µs) of the newest chunk; `None` keeps the default seeds.
    pub first_start_us: Option<i64>,
}

impl Estimate {
    /// Matches above 1/[`DENSE_DIVISOR`] of the rows: the whole-window
    /// preselect cannot prune and is skipped.
    pub fn dense(&self) -> bool {
        self.rows > 0.0 && self.events * DENSE_DIVISOR as f64 > self.rows
    }
}

/// Size the newest chunk of `[start_us, end_us]` from `parts` (newest
/// first, a prefix of the window's parts unless `complete`): the latest
/// start whose estimate still reaches `target` matches. When the whole
/// window holds fewer, the page needs all of it (`complete`) or, from a
/// prefix, the consulted span is scaled up by the missing share.
pub fn plan(
    parts: &[PartDensity],
    start_us: i64,
    end_us: i64,
    target: u64,
    complete: bool,
) -> (f64, f64, Option<i64>) {
    let events = events_in(parts, start_us, end_us);
    let rows = rows_in(parts, start_us, end_us);
    if end_us <= start_us || parts.is_empty() {
        return (events, rows, None);
    }
    let target = target.max(1) as f64;
    let latest_start = end_us.saturating_sub(MIN_FIRST_CHUNK_US).max(start_us);
    let first = if events >= target {
        // f(t) = events in [t, end] is non-increasing in t: find the latest
        // t with f(t) >= target.
        let (mut lo, mut hi) = (start_us, latest_start);
        if events_in(parts, hi, end_us) >= target {
            Some(hi)
        } else {
            while hi - lo > 1 {
                let mid = lo + (hi - lo) / 2;
                if events_in(parts, mid, end_us) >= target {
                    lo = mid
                } else {
                    hi = mid
                }
            }
            Some(lo)
        }
    } else if complete {
        Some(start_us)
    } else if events > 0.0 {
        let span_start = parts
            .iter()
            .map(|part| part.min_us.max(start_us))
            .min()
            .unwrap_or(start_us);
        let width = (end_us - span_start) as f64 * target / events;
        Some(((end_us as f64 - width).max(start_us as f64) as i64).min(latest_start))
    } else {
        None
    };
    (events, rows, first)
}

type MemoKey = (String, PartId, Term);

fn memo() -> &'static std::sync::Mutex<BTreeMap<MemoKey, Option<Activity>>> {
    static MEMO: std::sync::OnceLock<std::sync::Mutex<BTreeMap<MemoKey, Option<Activity>>>> =
        std::sync::OnceLock::new();
    MEMO.get_or_init(Default::default)
}

/// The activity of each term in one entity-ranges partial (case-insensitive
/// on the stored value, as nPL compares). Row groups whose `path`/`value`
/// statistics exclude every term are not decoded (the file is sorted by
/// `(path, value)`; for an ASCII term any stored case spelling lies between
/// its upper- and lowercase forms).
pub fn read_partial(path: &Path, terms: &[Term]) -> anyhow::Result<Vec<Option<Activity>>> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let builder = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?;
    let metadata = builder.metadata().clone();
    let columns = metadata.file_metadata().schema_descr();
    let index = |name: &str| {
        columns
            .columns()
            .iter()
            .position(|column| column.path().string() == name)
    };
    let (path_index, value_index) = (index("path"), index("value"));
    let bounds = |group: usize, column: Option<usize>| -> Option<(Vec<u8>, Vec<u8>)> {
        let statistics = metadata.row_group(group).column(column?).statistics()?;
        Some((
            statistics.min_bytes_opt()?.to_vec(),
            statistics.max_bytes_opt()?.to_vec(),
        ))
    };
    let groups = (0..metadata.num_row_groups())
        .filter(|group| {
            let paths = bounds(*group, path_index);
            let values = bounds(*group, value_index);
            terms.iter().any(|(term_path, term_value)| {
                paths.as_ref().is_none_or(|(min, max)| {
                    min.as_slice() <= term_path.as_bytes() && term_path.as_bytes() <= max.as_slice()
                }) && (!term_value.is_ascii()
                    || values.as_ref().is_none_or(|(min, max)| {
                        min.as_slice() <= term_value.as_bytes()
                            && term_value.to_ascii_uppercase().as_bytes() <= max.as_slice()
                    }))
            })
        })
        .collect::<Vec<_>>();
    let mut found = vec![None::<Activity>; terms.len()];
    if groups.is_empty() {
        return Ok(found);
    }
    for batch in builder.with_row_groups(groups).build()? {
        for row in EntityRangeRow::from_batch(&batch?)? {
            let (row_path, row_value) = &row.key;
            if !terms.iter().any(|(term_path, _)| term_path == row_path) {
                continue;
            }
            let lowered = lower(row_value);
            for (slot, (term_path, term_value)) in found.iter_mut().zip(terms) {
                if term_path == row_path && *term_value == lowered {
                    let activity = Activity {
                        events: row.events,
                        first_us: row.first_time,
                        last_us: row.last_time,
                    };
                    match slot {
                        Some(existing) => existing.absorb(activity),
                        None => *slot = Some(activity),
                    }
                }
            }
        }
    }
    Ok(found)
}

/// A part's bound on matching rows: the sparsest AND group, each group the
/// sum of its OR terms. `None` per term means the part never holds it.
fn part_activity(
    groups: &[Vec<Term>],
    answers: &BTreeMap<&Term, Option<Activity>>,
) -> Option<Option<Activity>> {
    let mut best: Option<Option<Activity>> = None;
    for group in groups {
        let mut sum: Option<Activity> = None;
        for term in group {
            if let Some(activity) = *answers.get(term)? {
                match sum.as_mut() {
                    Some(existing) => existing.absorb(activity),
                    None => sum = Some(activity),
                }
            }
        }
        let events = |activity: &Option<Activity>| activity.map_or(0, |a| a.events);
        if best.as_ref().is_none_or(|best| events(&sum) < events(best)) {
            best = Some(sum);
        }
    }
    best
}

/// Estimate the hint's density over `[start_us, end_us]` from the window's
/// entity-ranges partials, newest part first, stopping once the consulted
/// parts hold `target` matches. `Ok(None)`: no countable hint, or the newest
/// part has no partial (nothing to seed from).
pub async fn estimate(
    engine: &PartQueryEngine,
    hints: &[CandidateHint],
    start_us: i64,
    end_us: i64,
    target: u64,
) -> QueryResult<Option<Estimate>> {
    let Some(groups) = term_groups(hints) else {
        return Ok(None);
    };
    let terms = groups
        .iter()
        .flatten()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let tenant = engine.settings().tenant_id.clone();
    let (mut parts, ..) = engine.snapshot(start_us, end_us).await?;
    parts.sort_by(|a, b| {
        b.max_time_us
            .cmp(&a.max_time_us)
            .then(b.min_time_us.cmp(&a.min_time_us))
    });
    let window_parts = parts.len();
    let mut consulted = Vec::new();
    let mut fetched_parts = 0_usize;
    let mut exhausted = false;
    let mut batches = Vec::new();
    let (mut at, mut size) = (0, FIRST_BATCH_PARTS);
    while at < parts.len() {
        let end = (at + size).min(parts.len());
        batches.push(&parts[at..end]);
        (at, size) = (end, (size * 2).min(MAX_BATCH_PARTS));
    }
    'batches: for batch in batches {
        let missing = {
            let memo = memo().lock().expect("density memo");
            batch
                .iter()
                .filter(|part| {
                    terms.iter().any(|term| {
                        !memo.contains_key(&(tenant.clone(), part.part_id.clone(), term.clone()))
                    })
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        if !missing.is_empty() {
            if fetched_parts + missing.len() > MAX_FETCH_PARTS {
                exhausted = true;
                break;
            }
            fetched_parts += missing.len();
            if !Box::pin(fill(engine, &tenant, &missing, &terms)).await? {
                // A part without a verified partial: stop at what is known.
                exhausted = true;
            }
        }
        let memo = memo().lock().expect("density memo");
        for part in batch {
            let answers = terms
                .iter()
                .filter_map(|term| {
                    memo.get(&(tenant.clone(), part.part_id.clone(), term.clone()))
                        .map(|answer| (term, *answer))
                })
                .collect::<BTreeMap<_, _>>();
            let Some(activity) = part_activity(&groups, &answers) else {
                exhausted = true;
                break 'batches;
            };
            consulted.push(PartDensity {
                min_us: part.min_time_us,
                max_us: part.max_time_us,
                rows: part.rows,
                activity,
            });
            if events_in(&consulted, start_us, end_us) >= target as f64 {
                break 'batches;
            }
        }
        if exhausted {
            break;
        }
    }
    if consulted.is_empty() {
        return Ok(None);
    }
    let complete = !exhausted && consulted.len() == window_parts;
    let (events, rows, first_start_us) = plan(&consulted, start_us, end_us, target, complete);
    Ok(Some(Estimate {
        events,
        rows,
        consulted_parts: consulted.len(),
        window_parts,
        fetched_parts,
        complete,
        first_start_us,
    }))
}

/// Fetch and read the partials of `parts` into the memo. `false` when one
/// of them has no verified entity-ranges partial (nothing is memoized for it).
async fn fill(
    engine: &PartQueryEngine,
    tenant: &str,
    parts: &[PartRef],
    terms: &[Term],
) -> QueryResult<bool> {
    let unavailable =
        |error: anyhow::Error| super::engine::PartQueryError::Unavailable(format!("{error:#}"));
    let records = engine.fetcher().records(parts).await.map_err(unavailable)?;
    let with_partial = parts
        .iter()
        .zip(&records)
        .filter(|(_, record)| {
            record
                .files
                .partials
                .iter()
                .any(|partial| partial.kind == PartialKind::EntityRanges)
        })
        .map(|(part, _)| part.clone())
        .collect::<Vec<_>>();
    let complete = with_partial.len() == parts.len();
    if with_partial.is_empty() {
        return Ok(complete);
    }
    let local = engine
        .fetcher()
        .ensure(
            &with_partial,
            &[FileSet::Partial(PartialKind::EntityRanges)],
        )
        .await
        .map_err(unavailable)?;
    let files = local
        .of(FileSet::Partial(PartialKind::EntityRanges))
        .map(|file| (file.part_id.clone(), file.path.clone()))
        .collect::<Vec<(PartId, PathBuf)>>();
    let owned_terms = terms.to_vec();
    let read = tokio::task::spawn_blocking(move || {
        files
            .into_iter()
            .map(|(part, path)| read_partial(&path, &owned_terms).map(|found| (part, found)))
            .collect::<anyhow::Result<Vec<_>>>()
    })
    .await
    .map_err(|error| {
        super::engine::PartQueryError::Unavailable(format!("density partial read: {error}"))
    })?
    .map_err(unavailable)?;
    drop(local);
    let read_all = read.len() == with_partial.len();
    let mut memo = memo().lock().expect("density memo");
    if memo.len() + read.len() * terms.len() > MEMO_ENTRIES {
        memo.clear();
    }
    for (part, found) in read {
        for (term, activity) in terms.iter().zip(found) {
            memo.insert((tenant.to_string(), part.clone(), term.clone()), activity);
        }
    }
    Ok(complete && read_all)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60_000_000;

    fn entity(path: &str, value: &str) -> CandidateHint {
        CandidateHint::Entity {
            source_path: path.into(),
            value: value.into(),
        }
    }

    #[test]
    fn term_groups_bound_rows_by_entity_conjuncts_only() {
        assert_eq!(
            term_groups(&[entity("src_endpoint.ip", "10.0.0.1")]),
            Some(vec![vec![("src_endpoint.ip".into(), "10.0.0.1".into())]])
        );
        assert_eq!(
            term_groups(&[
                CandidateHint::Any {
                    alternatives: vec![
                        entity("device.hostname", "WS-1.Corp"),
                        entity("src_endpoint.hostname", "ws-1.corp")
                    ]
                },
                CandidateHint::Keyword {
                    mode: "token".into(),
                    value: "x".into()
                },
            ]),
            Some(vec![vec![
                ("device.hostname".into(), "ws-1.corp".into()),
                ("src_endpoint.hostname".into(), "ws-1.corp".into())
            ]])
        );
        // An OR with a keyword leg is unbounded; uid has no entity range.
        assert_eq!(
            term_groups(&[CandidateHint::Any {
                alternatives: vec![
                    entity("src_endpoint.ip", "1.1.1.1"),
                    CandidateHint::Keyword {
                        mode: "token".into(),
                        value: "x".into()
                    }
                ]
            }]),
            None
        );
        assert_eq!(term_groups(&[entity(UID_PATH, "u")]), None);
        assert_eq!(
            term_groups(&[CandidateHint::SourceFamily { value: "x".into() }]),
            None
        );
    }

    fn part(min_us: i64, max_us: i64, rows: u64, events: u64) -> PartDensity {
        PartDensity {
            min_us,
            max_us,
            rows,
            activity: (events > 0).then_some(Activity {
                events,
                first_us: min_us,
                last_us: max_us,
            }),
        }
    }

    #[test]
    fn dense_value_fills_the_page_in_a_short_first_chunk() {
        // One hour part, 600k rows, the host in 60k of them (1 000/min).
        let end = 3_600 * 1_000_000;
        let parts = [part(0, end, 600_000, 60_000)];
        let (events, rows, first) = plan(&parts, 0, end, 200, true);
        let estimate = Estimate {
            events,
            rows,
            consulted_parts: 1,
            window_parts: 1,
            fetched_parts: 1,
            complete: true,
            first_start_us: first,
        };
        assert!(estimate.dense());
        let width = end - first.unwrap();
        // 200 matches at 1 000/min: ~12 s.
        assert!((11_000_000..=13_000_000).contains(&width), "{width}");
        assert!(events_in(&parts, first.unwrap(), end) >= 200.0);
    }

    #[test]
    fn sparse_values_are_not_dense_and_size_from_the_whole_window() {
        let end = 24 * 60 * MIN;
        let parts = (0..24)
            .rev()
            .map(|h| part(h * 60 * MIN, (h + 1) * 60 * MIN - 1, 1_000_000, 3))
            .collect::<Vec<_>>();
        let (events, rows, first) = plan(&parts, 0, end, 100, true);
        assert!(events < 100.0);
        assert!(!Estimate {
            events,
            rows,
            consulted_parts: 24,
            window_parts: 24,
            fetched_parts: 0,
            complete: true,
            first_start_us: first
        }
        .dense());
        // Fewer matches than the page in the whole window: read it whole.
        assert_eq!(first, Some(0));
        // From a prefix (newest 2 h, 6 matches) the span scales by 100/6.
        let (_, _, first) = plan(&parts[..2], 0, end, 100, false);
        let width = end - first.unwrap();
        assert!(width > 20 * 60 * MIN, "{width}");
        // No match in the consulted prefix: keep the default seeds.
        let none = [part(23 * 60 * MIN, end, 1_000, 0)];
        assert_eq!(plan(&none, 0, end, 100, false).2, None);
    }

    #[test]
    fn the_first_chunk_is_never_empty_width_and_never_leaves_the_window() {
        let parts = [part(0, 10 * MIN, 10_000, 10_000)];
        let first = plan(&parts, 0, 10 * MIN, 1, true).2.unwrap();
        assert_eq!(first, 10 * MIN - MIN_FIRST_CHUNK_US);
        // The value was last seen long before the window's end.
        let old = [PartDensity {
            min_us: 0,
            max_us: 60 * MIN,
            rows: 1_000,
            activity: Some(Activity {
                events: 500,
                first_us: 0,
                last_us: 10 * MIN,
            }),
        }];
        let first = plan(&old, 0, 60 * MIN, 100, true).2.unwrap();
        assert!(first < 10 * MIN && first > 0, "{first}");
        assert_eq!(plan(&parts, 5, 5, 10, true).2, None);
    }

    #[test]
    fn part_activity_takes_the_sparsest_and_group() {
        let a: Term = ("src_endpoint.ip".into(), "1".into());
        let b: Term = ("dst_endpoint.ip".into(), "2".into());
        let c: Term = ("device.hostname".into(), "h".into());
        let act = |events| {
            Some(Activity {
                events,
                first_us: 0,
                last_us: 10,
            })
        };
        let answers = BTreeMap::from([(&a, act(5)), (&b, act(7)), (&c, act(100))]);
        // (a OR b) AND c: min(12, 100).
        let got = part_activity(&[vec![a.clone(), b.clone()], vec![c.clone()]], &answers)
            .unwrap()
            .unwrap();
        assert_eq!(got.events, 12);
        // A term absent from the part bounds it at zero.
        let answers = BTreeMap::from([(&a, None), (&c, act(3))]);
        assert_eq!(
            part_activity(&[vec![a.clone()], vec![c.clone()]], &answers),
            Some(None)
        );
        // An unknown answer is no bound.
        assert_eq!(part_activity(&[vec![b]], &answers), None);
    }

    /// The partial reader matches case-insensitively, combines spellings,
    /// and its row-group statistics pruning never drops a match.
    #[test]
    fn partial_reader_matches_every_spelling_across_row_groups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entity_ranges.parquet");
        let mut rows = Vec::new();
        for n in 0..150_000_u64 {
            rows.push(EntityRangeRow {
                key: (
                    "src_endpoint.ip".into(),
                    format!("10.{}.{}.{}", n / 65_536, (n / 256) % 256, n % 256),
                ),
                first_time: n as i64,
                last_time: n as i64 + 5,
                events: 1,
            });
        }
        for (value, events, first) in [
            ("WS-1.Corp.Local", 3, 100),
            ("ws-1.corp.local", 4, 50),
            ("ws-2.corp.local", 9, 1),
        ] {
            rows.push(EntityRangeRow {
                key: ("device.hostname".into(), value.into()),
                first_time: first,
                last_time: first + 1_000,
                events,
            });
        }
        crate::part_ingest::partials::write_sorted(rows, &path).unwrap();
        let terms: Vec<Term> = vec![
            ("device.hostname".into(), "ws-1.corp.local".into()),
            ("src_endpoint.ip".into(), "10.2.0.7".into()),
            ("src_endpoint.ip".into(), "10.9.9.9".into()),
            ("dst_endpoint.ip".into(), "10.2.0.7".into()),
        ];
        let found = read_partial(&path, &terms).unwrap();
        assert_eq!(
            found[0],
            Some(Activity {
                events: 7,
                first_us: 50,
                last_us: 1_100
            })
        );
        assert_eq!(
            found[1],
            Some(Activity {
                events: 1,
                first_us: 131_079,
                last_us: 131_084
            })
        );
        assert_eq!(found[2], None);
        assert_eq!(found[3], None);
    }
}

#[cfg(test)]
#[path = "density_native_tests.rs"]
pub(super) mod native;

#[cfg(test)]
#[path = "bareword_native_tests.rs"]
mod bareword_native;

#[cfg(test)]
#[path = "sidecar_native_tests.rs"]
mod sidecar_native;

#[cfg(test)]
#[path = "bareword_hash_native_tests.rs"]
mod bareword_hash_native;

#[cfg(test)]
#[path = "host_timeline_native_tests.rs"]
mod host_timeline_native;

#[cfg(test)]
#[path = "bareword_spread_native_tests.rs"]
mod bareword_spread_native;

#[cfg(test)]
#[path = "entity_index_native_tests.rs"]
mod entity_index_native;

#[cfg(test)]
#[path = "ioc_indicator_native_tests.rs"]
mod ioc_indicator_native;
