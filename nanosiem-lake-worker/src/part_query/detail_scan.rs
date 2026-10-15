// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3766: a newest-first, budgeted artifact detail scan.
//!
//! Detail facets (top hosts, users, sources, processes, files, network) are
//! counted from raw rows. A rare artifact touches few parts (NAN-3760
//! locator/bloom hints), but a common one is in every part, so one statement
//! over a 7d/30d window at 50-100 GB/day cannot finish inside the publisher's
//! 10-second budget and never published at all ("Context is still being
//! prepared").
//!
//! The scan instead walks disjoint time slices back from the window's end,
//! like the reader's progressive newest-first page walk
//! ([`super::progressive`]): a small newest slice first, then slices sized
//! from the measured rate to fit the remaining budget. Each slice selects
//! (and fetches) only its own parts and returns facet groups, which merge
//! exactly ([`crate::prevalence::DetailMerge`]). When the budget runs out
//! the result covers `[scanned_start, window_end]` and says so in its
//! `coverage`; it is never presented as the whole window. When every slice
//! ran, the merged answer equals the single whole-window statement.
//!
//! Pre-aggregated prevalence partials cannot answer this: they keep per
//! artifact only hashed host ids, counts and first/last seen, with no host
//! names, users, sources, processes or ports. Row sampling saves nothing on
//! Parquet (a `rand()` filter still decodes every row) and its counts could
//! not be bounded honestly.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::engine::{PartQueryEngine, PartQueryError, QueryResult};
use super::partials::PrevalenceDetailRequest;
use crate::prevalence::{DetailMerge, DetailSlice, PrevalenceError};

/// How long a detail build may scan, and when it must have a first answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DetailBudget {
    /// Execution time from the start of the build (selection and every
    /// statement) to the last slice. NAN-3858: under build authority each
    /// slice takes the idle slot on its own, and the wait for it is not
    /// charged here: on tenant-a a window build's statement holds that slot for
    /// tens of seconds to minutes, and a budget that counted the wait timed
    /// out before the scan had run at all.
    pub total: Duration,
    /// A scan that will continue past this publishes what it has first, so
    /// an expanded row shows facets within two seconds.
    pub first: Duration,
    /// NAN-3858: the target length of one slice statement. The idle slot is
    /// released between slices, so a background statement that has deferred
    /// [`super::product_state::MAX_DEFERRAL`] gets it within about this long.
    pub slice: Duration,
}

/// NAN-3858: the publisher's detail build. tenant-a 24h for a common IP (134 k
/// events/day, one product thread, cold part cache) covered 40 min of the
/// window in 7.4 s, so the whole day needs roughly 4-5 minutes of scan:
/// ten minutes of execution completes it with room; a 7d/30d walk of a
/// common artifact still ends as a flagged partial instead of running for
/// hours. Rare artifacts finish in a few slices.
pub(super) const DETAIL_BUDGET: DetailBudget = DetailBudget {
    total: Duration::from_secs(600), first: Duration::from_millis(1_500), slice: Duration::from_secs(5) };

tokio::task_local! {
    /// Tests shrink the budget for one build; a consumer's quick detail
    /// (NAN-3791) runs with its own first-answer budget.
    pub(super) static BUDGET: DetailBudget;
    /// NAN-3791: a cap on each slice statement's `max_threads` (and so its
    /// `max_parsing_threads`) for a consumer's quick detail on query[T].
    pub(super) static THREAD_CAP: u64;
}

fn budget() -> DetailBudget {
    BUDGET.try_with(|budget| *budget).unwrap_or(DETAIL_BUDGET)
}

/// How long a `refining` answer may wait for the next, wider one. Progress
/// is published every [`PROGRESS_EVERY`] of scanning, but between two slices
/// a background statement may hold the idle slot (tenant-a: fold steps up to
/// ~30 s, window/explorer statements up to their 120 s cap and a degraded
/// retry). A refining answer not replaced by then was abandoned: the build
/// failed, hit its cap, or its process died. It is then served as what it
/// is, a final partial answer.
const REFINING_DEADLINE: Duration = Duration::from_secs(300);
/// NAN-3858: a long walk republishes its widening partial answer this often
/// (scan time), so a polling viewer sees coverage grow.
const PROGRESS_EVERY: Duration = Duration::from_secs(10);
/// Internal: when a `refining` first answer stops being refining. Readers
/// settle and strip it ([`settle_refining`]); it never reaches the API.
const REFINING_UNTIL: &str = "refining_until_us";

/// The newest slice: small enough to answer fast at any ingest rate.
const NEWEST_SLICE_US: i64 = 5 * 60 * 1_000_000;
/// A slice that times out is cut down, but never below one minute.
const MIN_SLICE_US: i64 = 60 * 1_000_000;
/// Each slice covers at most this many times the previous one.
const MAX_GROWTH: i64 = 8;
/// Do not start another statement with less than this left.
const MIN_STATEMENT: Duration = Duration::from_millis(200);
/// Size the next slice to use about this share of the remaining budget.
const SLICE_SHARE: f64 = 0.5;

/// What part of the window a detail answer counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Coverage {
    pub window_from_us: i64,
    pub window_to_us: i64,
    /// Rows with `scanned_from_us <= time <= window_to_us` were counted.
    pub scanned_from_us: i64,
    /// A slice's facet had more groups than the merge keeps.
    pub approximate: bool,
    /// A wider answer for the same request is still being built.
    pub refining: bool,
}

impl Coverage {
    pub fn complete(&self) -> bool {
        self.scanned_from_us <= self.window_from_us
    }

    pub fn to_json(self) -> Value {
        let time = |us: i64| chrono::DateTime::<chrono::Utc>::from_timestamp_micros(us)
            .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
        json!({
            "complete": self.complete(),
            "approximate": self.approximate,
            "refining": self.refining,
            "scanned_start": time(self.scanned_from_us.max(self.window_from_us)),
            "scanned_end": time(self.window_to_us),
            "window_start": time(self.window_from_us),
            "window_end": time(self.window_to_us),
        })
    }
}

/// The slice walk's state.
struct Walk {
    merge: DetailMerge,
    /// Oldest instant counted so far (`window_to_us + 1` before any slice).
    covered_from_us: i64,
    any_objects: bool,
}

impl Walk {
    fn answer(&self, request: &PrevalenceDetailRequest, from_us: i64, to_us: i64, refining: bool) -> QueryResult<Value> {
        let coverage = Coverage { window_from_us: from_us, window_to_us: to_us, scanned_from_us: self.covered_from_us,
            approximate: self.merge.approximate(), refining };
        let mut result = if self.any_objects {
            serde_json::to_value(self.merge.result().map_err(internal)?).map_err(internal)?
        } else {
            json!({"artifact": request.artifact, "artifact_type": nanosiem_core::prevalence::ArtifactType::detect(&request.artifact),
                "top_hosts": [], "top_users": [], "source_types": [], "processes": [], "top_file_names": [], "network": [], "geo": [], "threat_intel": []})
        };
        result["coverage"] = coverage.to_json();
        if refining {
            let until = chrono::Utc::now().timestamp_micros().saturating_add(REFINING_DEADLINE.as_micros() as i64);
            result["coverage"][REFINING_UNTIL] = json!(until);
        }
        Ok(result)
    }
}

fn internal(error: impl std::fmt::Display) -> PartQueryError {
    super::engine::internal_text(error.to_string())
}

enum SliceError {
    Timeout,
    Failed(PartQueryError),
}

/// One slice `[from_us, to_us]` (`to_us` exclusive unless `inclusive`):
/// select only its parts, then count its facet groups within `limit`.
async fn read_slice(engine: &PartQueryEngine, request: &PrevalenceDetailRequest, hints: &[crate::planner::CandidateHint],
    from_us: i64, to_us: i64, inclusive: bool, limit: Duration) -> Result<(DetailSlice, bool), SliceError> {
    let mut selection = engine.select(from_us, to_us, hints).await.map_err(SliceError::Failed)?;
    // NAN-3168: the detail scan runs on the product thread budget.
    selection.tenant.threads = super::product_state::statement_threads(selection.tenant.threads);
    if let Ok(cap) = THREAD_CAP.try_with(|cap| *cap) {
        selection.tenant.threads = selection.tenant.threads.min(cap.max(1));
    }
    if selection.manifest.objects.is_empty() {
        return Ok((DetailSlice::default(), false));
    }
    let (source, mut params) = crate::planner::trusted_iceberg_source(&selection.tenant).map_err(|error| SliceError::Failed(internal(error)))?;
    let scope = super::partials::detail_scope_filter(&request.deny_source_types, &mut params).map_err(SliceError::Failed)?;
    match crate::prevalence::read_part_detail_slice(engine.executor(), &selection.tenant, &selection.manifest,
        source, params, scope, &request.artifact, from_us, to_us, inclusive, limit).await {
        Ok(slice) => Ok((slice, true)),
        Err(PrevalenceError::Timeout) => Err(SliceError::Timeout),
        Err(error) => Err(SliceError::Failed(internal(error))),
    }
}

/// Count `request`'s detail facets over `[from_us, to_us]`, newest first,
/// within the build budget measured from `started`. `first` receives a
/// partial answer (`coverage.refining = true`) when the walk is about to
/// run past [`DetailBudget::first`], and again every [`PROGRESS_EVERY`] of a
/// longer walk; the returned answer is final.
///
/// NAN-3858: under build authority every slice takes the product process's
/// idle slot on its own ([`super::product_state::idle_for_demand`]) and
/// releases it after, so a demand interleaves with a long window build
/// instead of waiting for it, and time spent waiting for the slot is not
/// charged to the budget. Outside build authority (a consumer's quick
/// detail, which holds its own admission) the budget is wall time, as before.
pub(super) async fn scan(engine: &PartQueryEngine, request: &PrevalenceDetailRequest, from_us: i64, to_us: i64,
    started: Instant, mut first: impl FnMut(&Value) -> QueryResult<()>) -> QueryResult<Value> {
    let budget = budget();
    let per_slice_slot = super::product_state::building();
    let _demand = per_slice_slot.then(super::product_state::demand_active);
    // Wall time spent waiting for the idle slot: never part of the budget.
    let mut waited = Duration::ZERO;
    let spent = |waited: Duration| started.elapsed().saturating_sub(waited);
    let (_, schema, _, _) = engine.snapshot(from_us, to_us).await?;
    let hints = crate::prevalence::detail_candidate_hints(&request.artifact, &crate::generation::schema_leaf_types(&schema));
    let mut walk = Walk { merge: DetailMerge::new(&request.artifact), covered_from_us: to_us.saturating_add(1), any_objects: false };
    let mut span = NEWEST_SLICE_US.min(to_us.saturating_sub(from_us).saturating_add(1)).max(1);
    let mut scanned = false;
    let mut last_sent: Option<Duration> = None;
    let mut slices = 0_u32;
    while walk.covered_from_us > from_us {
        let slot = if per_slice_slot {
            let wait = Instant::now();
            let slot = super::product_state::idle_for_demand(engine).await;
            waited += wait.elapsed();
            Some(slot)
        } else {
            None
        };
        let remaining = budget.total.saturating_sub(spent(waited));
        // The newest slice always runs (with at least the first-answer
        // budget), so every build publishes something.
        if scanned && remaining < MIN_STATEMENT {
            break;
        }
        // One statement never runs much past the slice target, so the idle
        // slot frees regularly (NAN-3858).
        let cap = budget.slice.saturating_mul(2);
        let limit = if scanned { remaining.min(cap) } else { remaining.min(cap).max(budget.first) };
        let (upper, inclusive) = if scanned { (walk.covered_from_us, false) } else { (to_us, true) };
        let lower = upper.saturating_sub(span).max(from_us);
        let slice_started = Instant::now();
        let read = read_slice(engine, request, &hints, lower, upper, inclusive, limit).await;
        drop(slot);
        match read {
            Ok((slice, objects)) => {
                walk.merge.add(slice);
                walk.any_objects |= objects;
                walk.covered_from_us = lower;
                scanned = true;
                slices += 1;
                // Size the next slice from the rate just measured: about half
                // of what is left (at most one slice target), growing at most
                // MAX_GROWTH-fold.
                let elapsed_us = slice_started.elapsed().as_micros().max(20_000) as f64;
                let left_us = budget.total.saturating_sub(spent(waited)).min(budget.slice.saturating_mul(2)).as_micros() as f64;
                let rate = span as f64 / elapsed_us;
                let next = ((rate * left_us * SLICE_SHARE) as i64).clamp(MIN_SLICE_US.min(span), span.saturating_mul(MAX_GROWTH));
                let projected = Duration::from_micros((next as f64 / rate) as u64);
                span = next;
                let more = walk.covered_from_us > from_us;
                let due = match last_sent {
                    None => spent(waited) + projected > budget.first,
                    Some(at) => spent(waited).saturating_sub(at) >= PROGRESS_EVERY,
                };
                if more && due {
                    first(&walk.answer(request, from_us, to_us, true)?)?;
                    last_sent = Some(spent(waited));
                }
            }
            Err(SliceError::Timeout) if span > MIN_SLICE_US => {
                // Too dense for the time left: retry a quarter of it.
                span = (span / 4).max(MIN_SLICE_US);
                if scanned && budget.total.saturating_sub(spent(waited)) < MIN_STATEMENT {
                    break;
                }
            }
            Err(SliceError::Timeout) if scanned => break,
            Err(SliceError::Timeout) => return Err(PartQueryError::Unavailable(
                "prevalence detail: one minute of this artifact's events exceeds the detail budget".into())),
            Err(SliceError::Failed(error)) => return Err(error),
        }
    }
    let answer = walk.answer(request, from_us, to_us, false)?;
    tracing::info!(slices, complete = walk.covered_from_us <= from_us, approximate = walk.merge.approximate(),
        covered_ms = (to_us - walk.covered_from_us.max(from_us)) / 1_000, window_ms = (to_us - from_us) / 1_000,
        wall_ms = started.elapsed().as_millis() as u64, scan_ms = spent(waited).as_millis() as u64,
        slot_wait_ms = waited.as_millis() as u64, "prevalence detail scan");
    Ok(answer)
}

/// Settle a stored detail answer for serving at `now_us`: a first answer
/// whose final build never replaced it by its deadline is no longer
/// refining (it stays incomplete, with its exact covered range), so a
/// viewer never waits on "refining" indefinitely. Strips the internal
/// deadline either way.
pub(super) fn settle_refining(answer: &mut Value, now_us: i64) {
    let Some(coverage) = answer.get_mut("coverage").and_then(Value::as_object_mut) else { return };
    let until = coverage.remove(REFINING_UNTIL).and_then(|until| until.as_i64());
    if coverage.get("refining") == Some(&Value::Bool(true)) && until.is_none_or(|until| now_us > until) {
        coverage.insert("refining".into(), Value::Bool(false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refining_first_answer_settles_to_a_final_partial_after_its_deadline() {
        let now = chrono::Utc::now().timestamp_micros();
        let first = |until: Option<i64>| {
            let mut coverage = json!({"complete": false, "approximate": false, "refining": true,
                "scanned_start": "2026-10-13T09:00:00.000000Z", "scanned_end": "2026-10-13T15:00:00.000000Z"});
            if let Some(until) = until { coverage[REFINING_UNTIL] = json!(until); }
            json!({"top_hosts": [{"host": "h", "count": 3}], "coverage": coverage})
        };
        // Within the deadline: still refining, deadline stripped.
        let mut fresh = first(Some(now + 1_000_000));
        settle_refining(&mut fresh, now);
        assert_eq!(fresh["coverage"]["refining"], true);
        assert!(fresh["coverage"].get(REFINING_UNTIL).is_none());
        // Past it (final build failed/timed out) or without one: a final
        // partial answer with its exact range, never refining.
        for stale in [first(Some(now - 1)), first(None)] {
            let mut stale = stale;
            settle_refining(&mut stale, now);
            assert_eq!(stale["coverage"]["refining"], false);
            assert_eq!(stale["coverage"]["complete"], false);
            assert_eq!(stale["coverage"]["scanned_start"], "2026-10-13T09:00:00.000000Z");
            assert_eq!(stale["top_hosts"][0]["count"], 3);
        }
        // Final answers and answers without coverage are untouched.
        let mut done = json!({"coverage": {"complete": true, "refining": false}});
        settle_refining(&mut done, now);
        assert_eq!(done, json!({"coverage": {"complete": true, "refining": false}}));
        let mut legacy = json!({"top_hosts": []});
        settle_refining(&mut legacy, now);
        assert_eq!(legacy, json!({"top_hosts": []}));
    }

    #[test]
    fn the_refining_deadline_outlasts_a_gap_between_progress_publishes() {
        // Between two published answers: one progress period, one slice,
        // and a background statement that deferred and then ran (its cap).
        let gap = PROGRESS_EVERY + DETAIL_BUDGET.slice * 2 + super::super::product_state::MAX_DEFERRAL + Duration::from_secs(120);
        assert!(REFINING_DEADLINE > gap, "{REFINING_DEADLINE:?} vs {gap:?}");
    }

    #[test]
    fn coverage_reports_the_scanned_newest_range_and_completeness() {
        let hour = 3_600_000_000_i64;
        let partial = Coverage { window_from_us: 0, window_to_us: 7 * 24 * hour, scanned_from_us: 7 * 24 * hour - 6 * hour,
            approximate: false, refining: true };
        let value = partial.to_json();
        assert_eq!(value["complete"], false);
        assert_eq!(value["refining"], true);
        assert_eq!(value["scanned_start"], "1970-01-07T18:00:00.000000Z");
        assert_eq!(value["scanned_end"], value["window_end"]);
        let full = Coverage { scanned_from_us: -5, ..partial };
        assert!(full.complete());
        assert_eq!(full.to_json()["scanned_start"], full.to_json()["window_start"], "never claims time before the window");
    }

    #[test]
    fn the_production_budget_fits_the_publisher_deadline() {
        assert!(DETAIL_BUDGET.first < Duration::from_secs(2));
        assert!(DETAIL_BUDGET.slice < super::super::product_state::MAX_DEFERRAL);
        assert!(DETAIL_BUDGET.total < super::super::product_publish::DETAIL_BUILD_WALL);
        assert_eq!(budget(), DETAIL_BUDGET);
    }
}
