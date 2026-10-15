// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3170: the token-index density seed of a keyword-only progressive
//! walk (a bareword `<hash> | head 100`), the counterpart of the entity
//! density seed ([`super::density`]).
//!
//! A keyword-only hint used to walk the default geometric chunks (1 minute,
//! then 3, 6, 12, … minutes): a rare token whose hundred matches span most
//! of a day took four or more chunks, each its own selection, locate and
//! payload statement over the newest-to-oldest kept row groups. The per-file
//! token indexes already say where the token may be: their v2 block runs
//! (each a candidate 1,024-row block with exact time bounds) are a cheap,
//! newest-first estimate of the matches. From them:
//!
//! * the newest chunk is sized to hold `limit × DENSITY_MARGIN` estimated
//!   matches, so the page is usually filled by the first chunk; and
//! * when every file of the window was consulted and the token keeps only a
//!   few row groups ([`super::progressive::selective_window`]), the walk takes
//!   the whole-window preselect (one selection, one fenced read), exactly as
//!   an entity pivot does (NAN-3077).
//!
//! Only seeds change: chunks still tile the window and are each fenced, so
//! rows, counts, ordering and paging are those of the default walk. A token
//! that is common in the newest data estimates its page within
//! [`DEFAULT_SEED_SPAN_US`] from the newest file or two and keeps the default
//! seeds. Membership is not consulted, which only over-estimates (a narrower
//! seed, never a preselect a real selection would refuse: the preselect
//! re-checks its own evidence). Kill switch: `NANO_LAKE_DENSITY_SEED=0`.

use super::density::{self, Activity, PartDensity};
use super::engine::{map_fetch_error, PartQueryEngine, QueryResult};
use super::fetch::PartFile;
use super::prune;
use crate::parts::block_index::{BLOCK_ROWS, COMMON_DIVISOR};
use crate::parts::part_log::PartRef;
use crate::parts::sidecar::TokenGroup;
use crate::planner::CandidateHint;

/// Files whose token indexes the first batch reads (newest first); each
/// later batch doubles, up to [`MAX_BATCH_FILES`].
const FIRST_BATCH_FILES: usize = 4;
const MAX_BATCH_FILES: usize = 64;
/// Most token indexes one estimate may read. Past it the estimate is
/// extrapolated from the newest files read (and never takes the
/// whole-window preselect).
pub const MAX_FETCH_FILES: usize = 512;

/// A newest chunk the estimate would start later than this before the end
/// of the window (µs) is left to the default seeds (1 minute, then sized
/// from the rows found): the page needs no more than a chunk or two there.
pub const DEFAULT_SEED_SPAN_US: i64 = 3 * 60_000_000;

/// What the consulted token indexes say about one window.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct TokenEstimate {
    /// Estimated matches in the window over the consulted files.
    pub events: f64,
    pub consulted_files: usize,
    pub window_files: usize,
    /// Every file of the window was consulted.
    pub complete: bool,
    /// Row groups of the consulted files, and those the token keeps.
    pub row_groups: usize,
    pub kept_row_groups: usize,
    /// Start (µs) of the newest chunk; `None` keeps the default seeds.
    pub first_start_us: Option<i64>,
}

impl TokenEstimate {
    /// The whole window was consulted and the token keeps so few row groups
    /// that one fenced read beats walking chunks.
    pub fn selective(&self) -> bool {
        self.complete && super::progressive::selective_window(self.kept_row_groups, self.row_groups)
    }
}

/// Keyword-only hints: a token stage and no entity stage (an entity pivot
/// has its own density seed and preselect).
pub fn applies(hints: &[CandidateHint]) -> bool {
    prune::uses_tokens(hints) && !prune::uses_entities(hints)
}

/// Estimate the hint's matches in `[start_us, end_us]` from the token
/// indexes, newest file first, stopping once `target` matches are
/// estimated. `Ok(None)`: no file has a v2 (block) token index to estimate
/// from, or the window holds no file.
pub async fn estimate(
    engine: &PartQueryEngine,
    hints: &[CandidateHint],
    start_us: i64,
    end_us: i64,
    target: u64,
) -> QueryResult<Option<TokenEstimate>> {
    if !applies(hints) || end_us <= start_us {
        return Ok(None);
    }
    let (parts, ..) = engine.snapshot(start_us, end_us).await?;
    let records = engine
        .fetcher()
        .records(&parts)
        .await
        .map_err(map_fetch_error)?;
    // Every data file the time and source-family stages keep, newest first.
    let mut files: Vec<(PartRef, usize, i64, i64, u64, usize)> = Vec::new();
    for (part, record) in parts.iter().zip(&records) {
        for (index, data) in record.files.data.iter().enumerate() {
            if data.min_time_us <= end_us
                && data.max_time_us >= start_us
                && prune::file_family_may_match(data.log_sources.as_deref(), data.class_id, hints)
            {
                files.push((
                    part.clone(),
                    index,
                    data.min_time_us,
                    data.max_time_us,
                    data.rows,
                    data.row_groups as usize,
                ));
            }
        }
    }
    if files.is_empty() {
        return Ok(None);
    }
    files.sort_by(|a, b| b.3.cmp(&a.3).then(b.2.cmp(&a.2)));
    let count_token = count_token(hints);
    let window_files = files.len();
    let mut consulted: Vec<PartDensity> = Vec::new();
    let (mut consulted_files, mut row_groups, mut kept_row_groups) = (0_usize, 0_usize, 0_usize);
    let mut exhausted = false;
    let (mut at, mut size) = (0, FIRST_BATCH_FILES);
    'batches: while at < files.len() {
        let end = (at + size).min(files.len());
        if end > MAX_FETCH_FILES {
            exhausted = true;
            break;
        }
        let batch = &files[at..end];
        (at, size) = (end, (size * 2).min(MAX_BATCH_FILES));
        let wanted = batch
            .iter()
            .map(|(part, index, ..)| (part.clone(), PartFile::Tokens(*index)))
            .collect::<Vec<_>>();
        let tokens = engine
            .fetcher()
            .ensure_files(&wanted)
            .await
            .map_err(map_fetch_error)?;
        for (part, index, min_us, max_us, rows, groups) in batch {
            let Some(local) = tokens.path(&part.part_id, PartFile::Tokens(*index)) else {
                // No index: what is known stops here.
                exhausted = true;
                break 'batches;
            };
            // The selection's own cached evidence (same digest and hints), so
            // the walk's selections reuse it.
            let (Some(mask), Some(fine)) =
                engine
                    .token_cache()
                    .evidence(&local.path, &local.sha256, *groups, hints)
            else {
                exhausted = true;
                break 'batches;
            };
            consulted_files += 1;
            row_groups += groups;
            consulted.push(PartDensity {
                min_us: *min_us,
                max_us: *max_us,
                rows: *rows,
                activity: None,
            });
            // Decoded only for a group where the token is common.
            let mut decoded = None;
            for (group_index, (keep, runs)) in mask.iter().zip(&fine).enumerate() {
                if !*keep {
                    continue;
                }
                kept_row_groups += 1;
                match runs {
                    // Each candidate block holds at least one match (bar a
                    // filter false positive).
                    Some(runs) => {
                        consulted.extend(runs.iter().map(|(from, to, (lo, hi))| PartDensity {
                            min_us: *lo,
                            max_us: *hi,
                            rows: 0,
                            activity: Some(Activity {
                                events: (to - from).div_ceil(u64::from(BLOCK_ROWS)).max(1),
                                first_us: *lo,
                                last_us: *hi,
                            }),
                        }))
                    }
                    None => {
                        let decoded = decoded.get_or_insert_with(|| {
                            engine.token_cache().get(&local.path, &local.sha256)
                        });
                        let Some(group) =
                            decoded.as_ref().and_then(|groups| groups.get(group_index))
                        else {
                            continue;
                        };
                        consulted.extend(common_group(group, count_token.as_deref()));
                    }
                }
            }
            if density::events_in(&consulted, start_us, end_us) >= target as f64 {
                break 'batches;
            }
        }
        drop(tokens);
    }
    if consulted_files == 0 {
        return Ok(None);
    }
    let complete = !exhausted && consulted_files == window_files;
    let (events, _, first_start_us) = density::plan(&consulted, start_us, end_us, target, complete);
    Ok(Some(TokenEstimate {
        events,
        consulted_files,
        window_files,
        complete,
        row_groups,
        kept_row_groups,
        first_start_us,
    }))
}

/// The one token v3 counts can answer for: a single keyword hint whose
/// needle is one alphanumeric token (as `keyword_count` serves).
fn count_token(hints: &[CandidateHint]) -> Option<String> {
    let mut keywords = hints
        .iter()
        .filter(|hint| matches!(hint, CandidateHint::Keyword { .. }));
    match (keywords.next(), keywords.next()) {
        (Some(CandidateHint::Keyword { mode, value }), None) if mode == "token" => {
            crate::parts::token_counts::single_token(value)
        }
        _ => None,
    }
}

/// The estimate of a row group where the token is common: v3 counts (a
/// token with 16+ rows in the group) give exact matches per minute; without
/// them more than 1/COMMON_DIVISOR of its blocks are candidates, each
/// holding a match.
fn common_group(group: &TokenGroup, count_token: Option<&str>) -> Vec<PartDensity> {
    let span = |first_us: i64, last_us: i64, events: u64| PartDensity {
        min_us: first_us,
        max_us: last_us,
        rows: 0,
        activity: Some(Activity {
            events,
            first_us,
            last_us,
        }),
    };
    if let Some(minutes) = count_token.and_then(|token| {
        group
            .counts
            .as_ref()?
            .lookup(token.as_bytes())
            .ok()
            .flatten()
    }) {
        return minutes
            .into_iter()
            .map(|(minute, rows)| {
                let first_us = minute.saturating_mul(60_000_000);
                span(
                    first_us,
                    first_us.saturating_add(59_999_999),
                    u64::from(rows),
                )
            })
            .collect();
    }
    let Some(index) = group.blocks.as_ref() else {
        return Vec::new();
    };
    let (lo, hi) = index
        .times
        .iter()
        .fold((i64::MAX, i64::MIN), |(lo, hi), (a, b)| {
            (lo.min(*a), hi.max(*b))
        });
    if lo > hi {
        return Vec::new();
    }
    vec![span(lo, hi, (index.blocks() / COMMON_DIVISOR) as u64 + 1)]
}
