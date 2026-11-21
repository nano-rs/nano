// SPDX-License-Identifier: AGPL-3.0-or-later

//! Streaming search types and helpers
//!
//! Defines SSE event types for streaming search results and helpers
//! to determine whether a query can stream rows incrementally.

use chrono::{DateTime, Utc};
use serde::Serialize;

// Scoped to one authenticated request; never stored on a shared SearchService.
tokio::task_local! {
    /// NAN-3077: a progressive `| lateral` answers a pending marker at once
    /// instead of tracing every hop inside the request.
    pub static DEFER_LATERAL_VIEW: bool;
    /// NAN-3077: where a streamed `| lateral` sends its cumulative graph after
    /// each hop (`view_update` events).
    pub static LATERAL_VIEW_SINK: tokio::sync::mpsc::Sender<SearchStreamEvent>;
}

/// SSE event types sent during a streaming search
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", content = "data")]
pub enum SearchStreamEvent {
    /// Search is queued behind other queries
    #[serde(rename = "queued")]
    Queued {
        queue_position: usize,
        estimated_wait_seconds: u64,
    },

    /// Search execution has started
    #[serde(rename = "started")]
    Started {
        job_id: String,
        query_id: String,
        is_streaming: bool,
    },

    /// Progress update (rows scanned so far)
    #[serde(rename = "progress")]
    Progress {
        rows_scanned: u64,
        rows_total: u64,
        percent: u8,
        elapsed_ms: u64,
    },

    /// A batch of result rows
    #[serde(rename = "rows")]
    Rows {
        rows: Vec<serde_json::Value>,
        batch_index: u32,
        cumulative_count: u64,
    },

    /// Query metadata (sent after all rows, or with the single batch for non-streaming)
    #[serde(rename = "metadata")]
    Metadata {
        total_count: u64,
        execution_time_ms: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        server_wall_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        queue_wait_ms: Option<u64>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        fields: Vec<crate::search::FieldInfo>,
        #[serde(skip_serializing_if = "Option::is_none")]
        histogram: Option<Vec<crate::search::HistogramBucket>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        warnings: Option<Vec<super::types::QueryWarningOutput>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cost_score: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        display_type: Option<crate::search::DisplayType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        column_order: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        generated_sql: Option<crate::search::display_sql::DisplaySql>,
    },

    /// Cumulative product graph. Replaces the previous snapshot, not raw rows
    /// (NAN-3077: `| lateral` after each hop).
    #[serde(rename = "view_update")]
    ViewUpdate {
        view: String,
        rows: Vec<serde_json::Value>,
        completed_hops: usize,
        complete: bool,
    },

    /// Search completed successfully
    #[serde(rename = "completed")]
    Completed { total_rows_delivered: u64 },

    /// Search failed
    #[serde(rename = "error")]
    Error { code: String, message: String },
}

/// Chunk emitted by the streaming ClickHouse executor
#[derive(Debug)]
pub enum StreamingChunk {
    /// A batch of parsed, post-processed rows
    Rows(Vec<serde_json::Value>),
    /// An error occurred during streaming
    Error(String),
}

/// Determine whether a parsed query can stream result rows incrementally.
///
/// Returns `true` for non-aggregate queries without post-processing that
/// requires the full result set (lookup enrichment, prevalence filtering,
/// tree/asset views).
///
/// Queries that CAN stream:
///   - Raw event searches: `error`, `src_ip="1.2.3.4" | sort -timestamp`
///   - Simple filtering: `* | where status > 400 | head 100`
///   - `| table` display commands on raw events
///   - Aggregations: `| stats count by src_ip`, `| timechart` (streamed without daily chunking)
///
/// Queries that CANNOT stream (need full result set for Rust post-processing):
///   - Lookup enrichment: `| lookup threats ...`
///   - Prevalence filtering: `| prevalence host_count < 5`
///   - Tree/Asset/Cloud views: `| tree`, `| asset`, `| cloud`
///   - Baseline view: `| baseline` — `build_baseline_view` discards the initial
///     fetch and re-queries the entity-keyed agg + a bounded raw scan. Streaming
///     would deliver the throwaway raw events instead of the baseline rows.
///   - Funnel dropper attribution: `| funnel by ...` emits `_droppers_<field>`
///     sample arrays that `build_funnel_view` folds into a compact
///     `dropper_top_attrs` JSON structure. Streaming would deliver the raw
///     internal arrays to the frontend.
///   - InputLookup: `| inputlookup ...`
///   - Command-page directives: `| service`, `| trace`, `| metric`, `| services`
///     short-circuit to a synthetic marker row in `core_search` (NAN-1560), so
///     they must route through the non-streaming path.
pub fn is_query_streamable(
    _query: &crate::query::Query,
    has_lookup: bool,
    has_inputlookup: bool,
    has_prevalence: bool,
    has_tree: bool,
    has_asset: bool,
    has_cloud: bool,
    has_ai: bool,
    has_lateral: bool,
    has_funnel: bool,
    has_baseline: bool,
    has_command_page: bool,
) -> bool {
    // Post-processing stages that require the full result set in Rust
    // (can't stream because Rust code needs to transform/enrich all rows)
    if has_lookup
        || has_inputlookup
        || has_prevalence
        || has_tree
        || has_asset
        || has_cloud
        || has_ai
        || has_lateral
        || has_funnel
        || has_baseline
        || has_command_page
    {
        return false;
    }

    true
}

/// How the streaming path may split a non-aggregate query over time (NAN-5693).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkPlan {
    /// Run one query per day, newest first, and concatenate the rows. Only
    /// sound when concatenating the chunks gives exactly the rows one query
    /// over the whole window gives. `row_cap` is the pipeline's global row
    /// cap (`head N`, `sort … limit=N`), which bounds the rows streamed across
    /// ALL chunks, not per chunk.
    Daily { row_cap: Option<usize> },
    /// Run the pipeline as one query over the whole window.
    Single,
}

/// Whether `name` is (or aliases) the time key the chunks are ordered by.
/// Case-insensitive, and covers the dataset's own time column (`start_time`
/// on spans) as `command_keeps_natural_event_order` does in the generator.
fn is_time_field(name: &str, time_column: &str) -> bool {
    ["time", "timestamp", "_time", time_column]
        .iter()
        .any(|key| name.eq_ignore_ascii_case(key))
}

/// True when the expression carries a `field IN [search …]` subsearch, which
/// would be re-bounded to each chunk's day instead of the whole window.
fn expr_has_subsearch(expr: &crate::query::SearchExpr) -> bool {
    use crate::query::SearchExpr;
    match expr {
        SearchExpr::InSubsearch { .. } => true,
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            expr_has_subsearch(left) || expr_has_subsearch(right)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => expr_has_subsearch(inner),
        _ => false,
    }
}

/// Decide whether a streamable, non-aggregate query can run as daily chunks.
///
/// Daily chunking concatenates per-day results newest first. That equals the
/// single-query answer only when every command is row-local (its output for a
/// row depends on that row alone, with no window-derived argument and no row
/// cap of its own) and the rows stay in the default newest-first order on an
/// untouched time key. Anything else must see the whole window at once, or
/// each day is sorted / deduplicated / joined / capped on its own and the page
/// shows N rows per day instead of N in total (NAN-5693). This is an
/// allowlist: a command or argument form not listed here runs as one query,
/// which is always correct. Excluded on purpose:
/// - `bin`: `bins=N` derives its span from the generation window (each day
///   would get its own width), `hop=` multiplies rows, and it can rewrite the
///   time key;
/// - `mvexpand`: always carries a `LIMIT` (`limit=N` or the default cap),
///   which would apply per day.
///
/// `head N` stays chunkable when only non-filtering, row-local commands follow
/// it: the first N rows of the newest-first concatenation are the global first
/// N, so the plan carries `row_cap = N` and the caller stops after N rows in
/// total. `time_column` is the dataset's primary time column.
pub fn chunk_plan(query: &crate::query::Query, time_column: &str) -> ChunkPlan {
    use crate::query::{Command, Query, RexMode};

    let is_key = |name: &str| is_time_field(name, time_column);
    let mut commands: Vec<&Command> = Vec::new();
    let mut node = query;
    let root = loop {
        match node {
            Query::Piped { source, command } => {
                commands.push(command);
                node = source;
            }
            Query::Search(expr) => break expr,
        }
    };
    commands.reverse();
    if expr_has_subsearch(root) {
        return ChunkPlan::Single;
    }

    let mut row_cap: Option<usize> = None;
    for command in commands {
        let row_local = match command {
            // Row-local, never drop or add rows; Single when they touch the
            // time key the chunks are ordered by.
            Command::Eval { assignments } => !assignments.iter().any(|a| is_key(&a.field)),
            Command::Rename { mappings } => !mappings.iter().any(|m| is_key(&m.from) || is_key(&m.to)),
            Command::Table { fields } => fields.iter().all(|f| match f.alias.as_deref() {
                Some(alias) => is_key(alias) == is_key(&f.name),
                None => true,
            }),
            Command::Fields { fields, keep } => *keep || !fields.iter().any(|f| is_key(f)),
            Command::Rex { field, pattern, mode } => {
                let lowered = pattern.to_ascii_lowercase();
                let captures_key = ["time", "timestamp", "_time", time_column]
                    .iter()
                    .any(|key| lowered.contains(&format!("<{}>", key.to_ascii_lowercase())));
                let sed_target_is_key =
                    matches!(mode, RexMode::Sed { .. }) && field.as_deref().is_some_and(is_key);
                !captures_key && !sed_target_is_key
            }
            // Only a named, non-key output: a bare `spath` may extract any key.
            Command::Spath { output, path, .. } => {
                output.as_deref().or(path.as_deref()).is_some_and(|target| !is_key(target))
            }
            Command::Fillnull { fields, .. } => {
                fields.as_ref().is_some_and(|fields| !fields.iter().any(|f| is_key(f)))
            }
            // Row-local filter: a global `head` before it must see the whole
            // window first.
            Command::Where { condition } => row_cap.is_none() && !expr_has_subsearch(condition),
            Command::Head { count } => {
                row_cap = Some(row_cap.map_or(*count, |cap| cap.min(*count)));
                true
            }
            // Only the default newest-first order survives chunking.
            Command::Sort { fields, limit } => {
                let default_order = matches!(
                    fields.as_slice(),
                    [only] if only.descending && is_key(&only.field)
                );
                if let Some(limit) = limit {
                    row_cap = Some(row_cap.map_or(*limit, |cap| cap.min(*limit)));
                }
                default_order
            }
            _ => false,
        };
        if !row_local {
            return ChunkPlan::Single;
        }
    }
    ChunkPlan::Daily { row_cap }
}

/// Whether the query ends in a `timechart`. The search service builds a
/// complete, pivoted bucket set for it (`complete_timechart`), so the stream
/// must take the buffered path; the raw streaming path would page the
/// long-form buckets by the caller's page size (NAN-5701).
pub fn ends_in_timechart(query: &crate::query::Query) -> bool {
    matches!(
        query,
        crate::query::Query::Piped { command: crate::query::Command::Timechart { .. }, .. }
    )
}

/// Most chunks one streamed search is split into (security review 2026-11-08,
/// NAN-5026). Each chunk is one sequential ClickHouse query, and the chunk
/// list was sized by the raw request span (a 400-year range meant ~146k
/// queries; a year-262143 range allocated gigabytes before any SQL ran).
/// 400 covers the default 365-day retention one day per partition with room
/// to spare; anything older collapses into the final chunk.
pub const MAX_DAILY_CHUNKS: usize = 400;

/// Split a time range into daily chunks ordered newest-first.
///
/// Each chunk aligns to day boundaries (`00:00:00 UTC`) except the first and last
/// which use the original `start`/`end` timestamps. This matches ClickHouse's
/// `toYYYYMMDD(timestamp)` daily partitioning so each chunk targets a single
/// partition, enabling fast per-partition sorts.
///
/// At most [`MAX_DAILY_CHUNKS`] chunks are produced. When the range spans more
/// days than that, the final (oldest) chunk covers everything from `start` to
/// the oldest daily boundary, so the chunks still tile the whole range and
/// return exactly the same rows; only the oldest stretch is read as one
/// multi-partition query.
///
/// Returns an empty vec if `start >= end`.
pub fn compute_daily_chunks(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    if start >= end {
        return Vec::new();
    }

    let mut chunks = Vec::new();

    // Walk backwards from `end` to `start` in day-aligned steps
    let mut chunk_end = end;
    loop {
        // Day boundary = start of `chunk_end`'s calendar day (00:00:00 UTC)
        let mut day_start = chunk_end
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();

        // If chunk_end is exactly at midnight, day_start == chunk_end which would
        // produce a zero-width chunk and never advance. Step back to the previous day.
        if day_start == chunk_end {
            day_start -= chrono::Duration::days(1);
        }

        // Chunk start is the later of the day boundary and the overall start.
        // The last permitted chunk takes the whole remaining span.
        let chunk_start = if chunks.len() + 1 >= MAX_DAILY_CHUNKS {
            start
        } else {
            day_start.max(start)
        };

        chunks.push((chunk_start, chunk_end));

        if chunk_start <= start {
            break;
        }

        // Move to end of previous day
        chunk_end = day_start;
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, m: u32, d: u32, h: u32, min: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, s).unwrap()
    }

    /// NAN-1868: `| baseline` re-queries in post-processing (`build_baseline_view`
    /// only runs on the buffered path), so it must NOT stream — otherwise the
    /// throwaway initial fetch's raw events are delivered instead of the baseline
    /// rows. Mirrors the asset/cloud/lateral force-buffered contract; this is the
    /// exact class of bug the `is_command_page_marker` comment records for retro.
    #[test]
    fn baseline_flag_forces_buffered_path() {
        let q = crate::query::parse_query("src_host=\"ws-1\" | baseline").unwrap();
        // has_baseline=true forces false regardless of every other flag being false.
        assert!(
            !is_query_streamable(
                &q, false, false, false, false, false, false, false, false, false, true, false,
            ),
            "| baseline must route to the buffered path"
        );
        // Control: a plain non-aggregate query with all flags false IS streamable.
        assert!(is_query_streamable(
            &q, false, false, false, false, false, false, false, false, false, false, false,
        ));
    }

    #[test]
    fn test_empty_when_start_equals_end() {
        let t = utc(2024, 1, 15, 12, 0, 0);
        assert!(compute_daily_chunks(t, t).is_empty());
    }

    #[test]
    fn test_empty_when_start_after_end() {
        let chunks = compute_daily_chunks(utc(2024, 1, 16, 0, 0, 0), utc(2024, 1, 15, 0, 0, 0));
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_single_day_intraday() {
        // Both within the same calendar day
        let start = utc(2024, 1, 15, 8, 0, 0);
        let end = utc(2024, 1, 15, 20, 0, 0);
        let chunks = compute_daily_chunks(start, end);

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], (start, end));
    }

    #[test]
    fn test_two_days_newest_first() {
        let start = utc(2024, 1, 14, 10, 0, 0);
        let end = utc(2024, 1, 15, 18, 0, 0);
        let chunks = compute_daily_chunks(start, end);

        // Newest first: Jan 15 chunk, then Jan 14 chunk
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], (utc(2024, 1, 15, 0, 0, 0), end));
        assert_eq!(chunks[1], (start, utc(2024, 1, 15, 0, 0, 0)));
    }

    #[test]
    fn test_midnight_boundary_no_infinite_loop() {
        // End is exactly midnight — the bug that crashed the Mac
        let start = utc(2024, 1, 13, 6, 0, 0);
        let end = utc(2024, 1, 15, 0, 0, 0);
        let chunks = compute_daily_chunks(start, end);

        // Should be: Jan 14 00:00→Jan 15 00:00, Jan 13 06:00→Jan 14 00:00
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], (utc(2024, 1, 14, 0, 0, 0), end));
        assert_eq!(chunks[1], (start, utc(2024, 1, 14, 0, 0, 0)));
    }

    #[test]
    fn test_both_boundaries_midnight() {
        let start = utc(2024, 1, 13, 0, 0, 0);
        let end = utc(2024, 1, 15, 0, 0, 0);
        let chunks = compute_daily_chunks(start, end);

        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks[0],
            (utc(2024, 1, 14, 0, 0, 0), utc(2024, 1, 15, 0, 0, 0))
        );
        assert_eq!(
            chunks[1],
            (utc(2024, 1, 13, 0, 0, 0), utc(2024, 1, 14, 0, 0, 0))
        );
    }

    #[test]
    fn test_multi_day_range() {
        let start = utc(2024, 1, 10, 0, 0, 0);
        let end = utc(2024, 1, 14, 12, 0, 0);
        let chunks = compute_daily_chunks(start, end);

        // 4 full days + partial = Jan 14 partial, Jan 13, Jan 12, Jan 11, Jan 10
        assert_eq!(chunks.len(), 5);
        // Newest first
        assert_eq!(chunks[0].0, utc(2024, 1, 14, 0, 0, 0));
        assert_eq!(chunks[0].1, end);
        // Oldest last
        assert_eq!(chunks[4].0, start);
        assert_eq!(chunks[4].1, utc(2024, 1, 11, 0, 0, 0));
    }

    #[test]
    fn test_chunks_cover_full_range_no_gaps() {
        let start = utc(2024, 1, 10, 3, 30, 0);
        let end = utc(2024, 1, 13, 22, 15, 0);
        let chunks = compute_daily_chunks(start, end);

        // Verify contiguous: each chunk's start == previous chunk's end
        for i in 0..chunks.len() - 1 {
            assert_eq!(
                chunks[i].0,
                chunks[i + 1].1,
                "gap between chunk {} and {}",
                i,
                i + 1
            );
        }
        // First chunk ends at overall end, last chunk starts at overall start
        assert_eq!(chunks.first().unwrap().1, end);
        assert_eq!(chunks.last().unwrap().0, start);
    }
}

#[cfg(test)]
#[path = "streaming_bounds_tests.rs"]
mod bounds_tests;

#[cfg(test)]
#[path = "streaming_chunk_plan_tests.rs"]
mod chunk_plan_tests;
