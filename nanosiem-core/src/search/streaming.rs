// SPDX-License-Identifier: AGPL-3.0-or-later

//! Streaming search types and helpers
//!
//! Defines SSE event types for streaming search results and helpers
//! to determine whether a query can stream rows incrementally.

use chrono::{DateTime, Utc};
use serde::Serialize;

// Scoped to one authenticated request; never stored on a shared SearchService.
tokio::task_local! {
    pub static DEFER_LATERAL_VIEW: bool;
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

    /// NAN-3644: a lean-cell read is fetching uncached data (or waiting for
    /// the cell's heavy cold-read slot). Sent as a `progress` event whose
    /// `phase` is `cold_scan`, so a client that only knows the row fields
    /// still shows a percent; `cold_bytes_total` is the bytes the admitted
    /// leases will read and may grow as later chunks are admitted.
    #[serde(rename = "progress")]
    ColdScanProgress {
        phase: &'static str,
        cold_bytes_read: u64,
        cold_bytes_total: u64,
        queued: bool,
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

    /// Cumulative product graph. Replaces the previous snapshot, not raw rows.
    #[serde(rename = "view_update")]
    ViewUpdate {
        view: String,
        rows: Vec<serde_json::Value>,
        completed_hops: usize,
        complete: bool,
    },

    /// Query metadata (sent after all rows, or with the single batch for non-streaming)
    #[serde(rename = "metadata")]
    Metadata {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        completeness: Option<super::types::EventCompleteness>,
        total_count: u64,
        /// NAN-2550: whether `total_count` is exact rather than a proven lower
        /// bound. `#[serde(default)]` decodes a missing field as `false`
        /// ("assume not exact"), matching [`crate::search::SearchResponse`].
        #[serde(default)]
        total_count_exact: bool,
        execution_time_ms: u64,
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
        generated_sql: Option<String>,
    },

    /// Follow-stream liveness (NAN-3264). A follow emits this from its own
    /// head loop whenever it has sent nothing else for a few seconds, so a
    /// client can tell a follow that is still advancing from one whose
    /// executor is stuck (the transport keepalive comment cannot: it is
    /// written by the HTTP handler even while the follow is wedged).
    /// Carries no tenant data.
    #[serde(rename = "heartbeat")]
    Heartbeat { delivered: u64 },

    /// Search completed successfully
    #[serde(rename = "completed")]
    Completed { total_rows_delivered: u64 },

    /// Search failed
    #[serde(rename = "error")]
    Error { code: String, message: String },
    /// NAN-3644: the reader's cold-read ceiling (an OOM safety net) with
    /// exact byte metadata. A cold read under it is never refused.
    #[serde(rename = "error")]
    ColdScanError {
        code: &'static str,
        message: String,
        reason: &'static str,
        needed_bytes: u64,
        ceiling_bytes: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        background_ceiling_bytes: Option<u64>,
        retryable: bool,
    },
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

/// Split a time range into daily chunks ordered newest-first.
///
/// Each chunk aligns to day boundaries (`00:00:00 UTC`) except the first and last
/// which use the original `start`/`end` timestamps. This matches ClickHouse's
/// `toYYYYMMDD(timestamp)` daily partitioning so each chunk targets a single
/// partition, enabling fast per-partition sorts.
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

        // Chunk start is the later of the day boundary and the overall start
        let chunk_start = day_start.max(start);

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

    #[test]
    fn metadata_serializes_the_worker_completeness_display_decision() {
        for notice in [false, true] {
            let completeness = serde_json::from_value(serde_json::json!({
                "status": "stale",
                "reason": "publication_consumer_lag",
                "events_complete_through_ms": 1_755_000_000_000_i64,
                "freshness_notice_required": notice,
            })).unwrap();
            let metadata = SearchStreamEvent::Metadata {
                completeness: Some(completeness),
                total_count: 0,
                total_count_exact: true,
                execution_time_ms: 1,
                fields: vec![],
                histogram: None,
                warnings: None,
                cost_score: None,
                display_type: None,
                column_order: None,
                generated_sql: None,
            };
            let json = serde_json::to_value(metadata).unwrap();
            assert_eq!(json["data"]["completeness"]["freshness_notice_required"], notice);
            assert_eq!(
                json["data"]["completeness"]["events_complete_through_ms"],
                1_755_000_000_000_i64,
            );
        }
    }

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

/// NAN-3644: the `progress` event for a cold read's live bytes. `percent`
/// stays below 100 until the stream completes.
pub fn cold_scan_progress_event(cold_bytes_read: u64, cold_bytes_total: u64, queued: bool, elapsed_ms: u64) -> SearchStreamEvent {
    let percent = if cold_bytes_total == 0 {
        0
    } else {
        ((cold_bytes_read.min(cold_bytes_total) as f64 / cold_bytes_total as f64) * 100.0).min(99.0) as u8
    };
    SearchStreamEvent::ColdScanProgress {
        phase: "cold_scan",
        cold_bytes_read,
        cold_bytes_total,
        queued,
        rows_scanned: 0,
        rows_total: 0,
        percent,
        elapsed_ms,
    }
}
