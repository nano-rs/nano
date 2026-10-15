// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3715: a bounded ring of this process's slow real searches, so the
//! queries worth tuning can be replayed through the SQL probe
//! (`scripts/lake-probe.sh capture <tenant>`, then a variants run under knob
//! set A vs B) without a build or a roll.
//!
//! Each entry holds what a replay needs and what explains the cost: the nPL
//! text, the window (and its width), the page shape, the compiled
//! statement's digest, the wall time and the request's phase record
//! (`query_timing::Phases`: native, select sub-stages, prune funnel), and
//! the knob values in effect. **Never row data.** Bounded to
//! [`RING_ENTRIES`] entries and [`RING_BYTES`] bytes; an nPL over
//! [`MAX_NPL_BYTES`] is kept by hash only (not replayable). Served only on
//! `GET /v1/debug/slow-queries`, operator-admitted like the probe.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A real search slower than this (wall, ms) is captured.
pub const SLOW_QUERY_MS: f64 = 1_000.0;
/// Entries kept (oldest dropped first).
pub const RING_ENTRIES: usize = 500;
/// Serialized bytes kept across entries (oldest dropped first).
pub const RING_BYTES: usize = 8 * 1024 * 1024;
/// Longest nPL kept as text.
pub const MAX_NPL_BYTES: usize = 16 * 1024;

/// What the caller knows about one finished search.
pub struct Observed<'a> {
    pub route: &'static str,
    pub request_id: &'a str,
    pub dataset: &'a str,
    pub npl: &'a str,
    pub start: &'a str,
    pub end: &'a str,
    pub limit: usize,
    pub offset: usize,
    pub table_view: bool,
    pub deny_source_types: Vec<String>,
    pub wall_ms: f64,
    /// `None` on success, else the error's reason code (never its text:
    /// a native error may echo the statement).
    pub error: Option<&'static str>,
    /// The answer, for its digest and counts (rows are not read).
    pub answer: Option<&'a Value>,
    /// The request's phase record, serialized.
    pub phases: Value,
}

impl<'a> Observed<'a> {
    /// A finished `broad_npl` search (`/v1/query` or `/v1/query/pages`).
    pub fn broad(
        route: &'static str,
        request: &'a super::engine::BroadNplRequest,
        wall_ms: f64,
        error: Option<&'static str>,
        answer: Option<&'a Value>,
        phases: Value,
    ) -> Self {
        Self {
            route,
            request_id: &request.request_id,
            dataset: &request.dataset,
            npl: &request.query,
            start: &request.start,
            end: &request.end,
            limit: request.limit,
            offset: request.offset,
            table_view: request.table_view,
            deny_source_types: request.deny_source_types.iter().cloned().collect(),
            wall_ms,
            error,
            answer,
            phases,
        }
    }
}

#[derive(Default)]
pub struct SlowQueries {
    ring: Mutex<(VecDeque<(u64, usize, Value)>, usize)>,
    seq: AtomicU64,
    dropped: AtomicU64,
}

fn window_seconds(start: &str, end: &str) -> Option<i64> {
    let start = chrono::DateTime::parse_from_rfc3339(start).ok()?;
    let end = chrono::DateTime::parse_from_rfc3339(end).ok()?;
    Some((end - start).num_seconds())
}

/// The knob values in effect for a request: each probe knob's process env
/// value, and the debug header's overrides if it had any.
fn knobs_in_effect() -> Value {
    let env = crate::perf_overrides::PROBE_KNOBS
        .iter()
        .filter_map(|knob| {
            knob.env
                .map(|env| (knob.name.to_string(), json!(std::env::var(env).ok())))
        })
        .collect::<serde_json::Map<_, _>>();
    json!({"env": env, "overrides": crate::perf_overrides::evidence()})
}

impl SlowQueries {
    /// Record `observed` if it was slow. Returns whether it was kept.
    pub fn observe(&self, observed: Observed<'_>) -> bool {
        if observed.wall_ms < SLOW_QUERY_MS {
            return false;
        }
        let replayable = observed.npl.len() <= MAX_NPL_BYTES;
        let answer = observed.answer;
        let result = answer.map(|answer| &answer["result"]);
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = json!({
            "seq": seq,
            "at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "route": observed.route,
            "request_class": if observed.request_id.contains("-hist") { "companion" } else { "primary" },
            "dataset": observed.dataset,
            "npl": replayable.then_some(observed.npl),
            "npl_sha256": hex::encode(Sha256::digest(observed.npl.as_bytes())),
            "npl_bytes": observed.npl.len(),
            "start": observed.start,
            "end": observed.end,
            "window_seconds": window_seconds(observed.start, observed.end),
            "limit": observed.limit,
            "offset": observed.offset,
            "table_view": observed.table_view,
            "deny_source_types": observed.deny_source_types,
            "wall_ms": observed.wall_ms,
            "outcome": if observed.error.is_none() { "ok" } else { "error" },
            "error_reason": observed.error,
            "query_sha256": answer.and_then(|answer| answer.get("query_sha256")).cloned(),
            "rows": result.and_then(|result| result.get("result_rows")).cloned(),
            "storage_rows": result.and_then(|result| result.get("storage_rows")).cloned(),
            "storage_bytes": result.and_then(|result| result.get("storage_bytes")).cloned(),
            "cache_hit": result.and_then(|result| result.get("query_result_cache_hit")).cloned(),
            "phases": observed.phases,
            "knobs": knobs_in_effect(),
        });
        let bytes = entry.to_string().len();
        if bytes > RING_BYTES {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let (entries, total) = &mut *ring;
        entries.push_back((seq, bytes, entry));
        *total += bytes;
        while entries.len() > RING_ENTRIES || *total > RING_BYTES {
            let Some((_, gone, _)) = entries.pop_front() else {
                break;
            };
            *total -= gone;
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    /// Entries at least `min_ms` slow, newest first, at most `limit`.
    pub fn snapshot(&self, min_ms: f64, limit: usize) -> Value {
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let (entries, total) = &*ring;
        let kept = entries
            .iter()
            .rev()
            .filter(|(_, _, entry)| entry["wall_ms"].as_f64().unwrap_or(0.0) >= min_ms)
            .take(limit)
            .map(|(_, _, entry)| entry.clone())
            .collect::<Vec<_>>();
        json!({
            "ok": true,
            "schema": "nano.lake-slow-queries.v1",
            "threshold_ms": SLOW_QUERY_MS,
            "ring_entries": entries.len(),
            "ring_bytes": total,
            "ring_capacity": RING_ENTRIES,
            "dropped": self.dropped.load(Ordering::Relaxed),
            "entries": kept,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(wall_ms: f64, npl: &str) -> Observed<'_> {
        Observed {
            route: "query",
            request_id: "r1",
            dataset: "logs",
            npl,
            start: "2026-10-12T00:00:00Z",
            end: "2026-10-12T06:00:00Z",
            limit: 100,
            offset: 0,
            table_view: true,
            deny_source_types: Vec::new(),
            wall_ms,
            error: None,
            answer: None,
            phases: json!({"chdb_ms": 12.0}),
        }
    }

    #[test]
    fn keeps_only_slow_searches_bounded_and_newest_first() {
        let ring = SlowQueries::default();
        assert!(!ring.observe(observed(999.0, "fast")));
        for index in 0..(RING_ENTRIES + 7) {
            assert!(ring.observe(observed(1_000.0 + index as f64, "slow | stats count()")));
        }
        let snapshot = ring.snapshot(0.0, usize::MAX);
        assert_eq!(snapshot["ring_entries"], RING_ENTRIES);
        assert_eq!(snapshot["dropped"], 7);
        let entries = snapshot["entries"].as_array().unwrap();
        assert_eq!(
            entries[0]["seq"].as_u64(),
            Some((RING_ENTRIES + 7) as u64),
            "newest first"
        );
        assert_eq!(entries[0]["window_seconds"], 6 * 3600);
        assert_eq!(entries[0]["npl"], "slow | stats count()");
        assert!(
            entries[0].get("rows").is_some_and(Value::is_null),
            "no answer: no counts, and never rows"
        );
        assert_eq!(
            ring.snapshot(1_400.0, 3)["entries"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn long_npl_is_kept_by_hash_only() {
        let ring = SlowQueries::default();
        let long = "x".repeat(MAX_NPL_BYTES + 1);
        assert!(ring.observe(observed(5_000.0, &long)));
        let entry = &ring.snapshot(0.0, 1)["entries"][0];
        assert!(entry["npl"].is_null());
        assert_eq!(entry["npl_bytes"], MAX_NPL_BYTES + 1);
        assert_eq!(entry["npl_sha256"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn answers_contribute_digest_and_counts_never_rows() {
        let ring = SlowQueries::default();
        let answer = json!({"query_sha256": "ab", "result": {"result_rows": 2, "rows": [{"secret": "x"}],
            "storage_rows": 10, "storage_bytes": 99, "query_result_cache_hit": false}});
        let mut seen = observed(2_000.0, "q");
        seen.answer = Some(&answer);
        ring.observe(seen);
        let text = ring.snapshot(0.0, 1).to_string();
        assert!(text.contains("\"storage_bytes\":99") && text.contains("\"query_sha256\":\"ab\""));
        assert!(!text.contains("secret"), "row data is never captured");
    }
}
