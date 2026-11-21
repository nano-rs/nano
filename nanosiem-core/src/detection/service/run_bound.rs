// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5736: bounded detection runs that never drop an entity.
//!
//! A scheduled run used to fetch up to the 1M search ceiling as full events
//! and hold them all in memory while grouping and alerting: a rule matching
//! every Sysmon event (~700k rows) OOM-killed `nano-jobs` on every run.
//!
//! A raw-event rule now fetches at most `max_matches_per_run + 1` rows. When it
//! matched more, a plain truncation would drop detections: an entity whose
//! events are older than the newest `max_matches_per_run` would never alert,
//! and a flood of one noisy entity could blind the rule for every other one
//! (worse with a sliding lookback, where the same newest rows come back,
//! already matched, run after run). So an overflowing run additionally fetches
//! the NEWEST event of every distinct value of every field the alert path
//! groups by (`| dedup <field>` — one ClickHouse `LIMIT 1 BY`, no sort), plus
//! one event lacking all of them. Every entity group in the window is then
//! present, so grouping, dedup and cooldown decide per entity exactly as they
//! would over the full set; only individual events beyond the cap are not
//! stored. The representatives lead the rows, so the alert's stored sample
//! shows them. The run is recorded as PARTIAL.
//!
//! When even that is too large (more than `per_field_limit` distinct values
//! of one field, or the expansion budget is spent), the run alerts LOUDLY: a
//! coverage-incomplete row joins the results, raising an alert at the rule's
//! severity, and the PARTIAL note says coverage is incomplete.
//!
//! Only rules whose rows are events of the base search are bounded this way
//! (a search, optionally followed by `where` / `eval` / `rex`). Aggregations,
//! `| risk`, prevalence and every other command keep the full fetch: their
//! output depends on every input row, and truncating it would change what
//! they detect. If any expansion query fails, the run falls back to the full
//! fetch as well: detection correctness first.

use std::collections::HashSet;

use serde_json::Value;
use tracing::warn;

use crate::detection::DetectionError;
use crate::models::DetectionRule;
use crate::query::{parse_query, Command, Query};
use crate::search::TimeRangeInput;

use super::DetectionService;

/// Default for [`super::DetectionServiceConfig::max_matches_per_run`].
pub const DEFAULT_MAX_MATCHES_PER_RUN: usize = 2_000;

/// Marker on the coverage-incomplete row (NAN-5736).
pub const COVERAGE_INCOMPLETE_MARKER: &str = "_nano_coverage_incomplete";

/// `DETECTION_MAX_MATCHES_PER_RUN`, within `[1, max search limit - 1]` so
/// `cap + 1` (which tells a capped run from an exact one) is never clipped by
/// the search service's own ceiling.
pub fn configured_max_matches_per_run() -> usize {
    parse_max_matches_per_run(std::env::var("DETECTION_MAX_MATCHES_PER_RUN").ok().as_deref())
}

pub(crate) fn parse_max_matches_per_run(value: Option<&str>) -> usize {
    value
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_MATCHES_PER_RUN)
        .clamp(1, crate::query::ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT - 1)
}

/// Whether a rule's rows are events of its base search, so a run may be
/// bounded by keeping per-entity representatives (see the module docs).
pub(crate) fn is_boundable_raw_query(query: &Query) -> bool {
    match query {
        Query::Search(_) => true,
        Query::Piped { source, command } => {
            matches!(
                command,
                Command::Where { .. } | Command::Eval { .. } | Command::Rex { .. }
            ) && is_boundable_raw_query(source)
        }
    }
}

/// Distinct values fetched per entity field when a run overflows.
pub(crate) fn per_field_limit(cap: usize) -> usize {
    (cap / 2).max(1)
}

/// Rows the per-entity expansion may add in total.
pub(crate) fn expansion_budget(cap: usize) -> usize {
    cap.saturating_mul(4).max(1)
}

/// Quote a field for an nPL pipe (`dedup`, `where`).
fn npl_field(field: &str) -> String {
    if field.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.')) {
        field.to_string()
    } else {
        format!("`{}`", field.replace('`', ""))
    }
}

/// `<query> | dedup <field> | head <n>`: the newest event per distinct value.
pub(crate) fn representatives_query(rule_query: &str, field: &str, limit: usize) -> String {
    format!("{rule_query} | dedup {} | head {limit}", npl_field(field))
}

/// `<query> | where <no entity field set> | head 1`.
pub(crate) fn no_entity_query(rule_query: &str, fields: &[String]) -> String {
    let missing: Vec<String> = fields
        .iter()
        .map(|f| {
            let f = npl_field(f);
            format!("(isnull({f}) OR {f}=\"\")")
        })
        .collect();
    format!("{rule_query} | where {} | head 1", missing.join(" AND "))
}

/// The PARTIAL note of a run bounded with full entity coverage.
pub(crate) fn run_bounded_message(cap: usize, kept: usize) -> String {
    format!(
        "matched more than {cap} events in one run; evaluated the newest {cap} plus the newest event of every distinct entity ({kept} events in all), so every entity was alerted on, but events beyond those were not stored (DETECTION_MAX_MATCHES_PER_RUN)"
    )
}

/// The PARTIAL note (and alert text) of a run whose entity coverage is
/// incomplete.
pub(crate) fn coverage_incomplete_message(cap: usize, fields: &[String]) -> String {
    format!(
        "DETECTION COVERAGE INCOMPLETE: matched more than {cap} events in one run and too many distinct values of {} to evaluate every entity; entities beyond the newest were NOT evaluated. Narrow the rule (DETECTION_MAX_MATCHES_PER_RUN)",
        fields.join(", ")
    )
}

/// The coverage-incomplete row: alerts at the rule's severity. Its id is
/// stable per window end, so one alert per incomplete window. It carries no
/// `source_type`, so the alert path stamps the window's real source types
/// (the NAN-1800 companion, fail-closed).
pub(crate) fn coverage_incomplete_row(rule: &DetectionRule, window_end: chrono::DateTime<chrono::Utc>, message: &str) -> Value {
    serde_json::json!({
        "log_id": format!("nano-coverage-incomplete-{}-{}", rule.id, window_end.timestamp_millis()),
        "timestamp": window_end.to_rfc3339(),
        "message": message,
        COVERAGE_INCOMPLETE_MARKER: true,
    })
}

/// Append to `kept` every event of `extra` not already there (by
/// `matched_event_id`). Returns how many were added.
pub(crate) fn merge_unique(kept: &mut Vec<Value>, seen: &mut HashSet<String>, extra: Vec<Value>) -> usize {
    let mut added = 0;
    for event in extra {
        if seen.insert(super::helpers::matched_event_id(&event)) {
            kept.push(event);
            added += 1;
        }
    }
    added
}

impl DetectionService {
    /// The fields the alert path groups this rule's events by (see
    /// `group_events_by_entity`).
    fn entity_fields(&self, rule: &DetectionRule) -> Vec<String> {
        match rule.risk_entity_field.as_deref() {
            Some(field) => vec![field.to_string()],
            None => {
                let mut fields: Vec<String> = Vec::new();
                for &(_, field) in self.active_profile.entity_extraction_order() {
                    if !fields.iter().any(|f| f == field) {
                        fields.push(field.to_string());
                    }
                }
                fields
            }
        }
    }

    /// The rows one scheduled run evaluates (NAN-5736, see the module docs).
    pub(super) async fn evaluate_rule_run(
        &self,
        rule: &DetectionRule,
        time_range: &TimeRangeInput,
    ) -> Result<Vec<Value>, DetectionError> {
        let scope = crate::auth::ScopeSet::unrestricted();
        let cap = self.config.max_matches_per_run.max(1);
        let boundable = parse_query(&rule.query).map(|q| is_boundable_raw_query(&q)).unwrap_or(false);
        if !boundable {
            return Box::pin(self.evaluate_window(
                &rule.query,
                time_range.clone(),
                rule.dataset.clone(),
                &scope,
            ))
            .await;
        }
        let mut rows = Box::pin(self
            .evaluate_window_with_limit(
                &rule.query,
                time_range.clone(),
                rule.dataset.clone(),
                cap + 1,
                &scope,
            ))
            .await?;
        if rows.len() <= cap {
            return Ok(rows);
        }
        rows.truncate(cap);
        metrics::counter!("nanosiem_detection_runs_bounded_total").increment(1);

        // Boxed: the nested search futures are large in debug builds.
        match Box::pin(self.add_entity_representatives(rule, time_range, cap, &mut rows)).await {
            Ok(None) => {
                crate::search::partial_run::note(run_bounded_message(cap, rows.len()));
                Ok(rows)
            }
            Ok(Some(incomplete_fields)) => {
                metrics::counter!("nanosiem_detection_runs_coverage_incomplete_total").increment(1);
                let message = coverage_incomplete_message(cap, &incomplete_fields);
                warn!(rule_id = %rule.id, rule_name = %rule.name, "{message}");
                rows.insert(0, coverage_incomplete_row(rule, time_range.end, &message));
                crate::search::partial_run::note(message);
                Ok(rows)
            }
            Err(e) => {
                // Never trade detections for memory: an expansion that cannot
                // run falls back to the full fetch.
                warn!(
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    "Per-entity expansion of a bounded run failed ({e}); evaluating the full window instead"
                );
                drop(rows);
                Box::pin(self.evaluate_window(&rule.query, time_range.clone(), rule.dataset.clone(), &scope))
                    .await
            }
        }
    }

    /// Add the newest event of every distinct entity value (and one event
    /// with no entity) to `rows`. `Ok(Some(fields))` names the fields whose
    /// distinct values could not all be fetched.
    async fn add_entity_representatives(
        &self,
        rule: &DetectionRule,
        time_range: &TimeRangeInput,
        cap: usize,
        rows: &mut Vec<Value>,
    ) -> Result<Option<Vec<String>>, DetectionError> {
        let scope = crate::auth::ScopeSet::unrestricted();
        let fields = self.entity_fields(rule);
        let limit = per_field_limit(cap);
        let mut budget = expansion_budget(cap);
        let mut incomplete: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = rows.iter().map(super::helpers::matched_event_id).collect();
        // Representatives of entities the newest rows do not cover. They go
        // FIRST: the alert's stored sample and the bounded detection_matches
        // row keep the leading rows, and these are the evidence an analyst
        // must see (the quiet entity next to a flood).
        let mut extra: Vec<Value> = Vec::new();

        for field in &fields {
            if budget == 0 {
                incomplete.push(field.clone());
                continue;
            }
            let fetch = limit.min(budget);
            let mut reps = Box::pin(self
                .evaluate_window_with_limit(
                    &representatives_query(&rule.query, field, fetch + 1),
                    time_range.clone(),
                    rule.dataset.clone(),
                    fetch + 1,
                    &scope,
                ))
                .await?;
            if reps.len() > fetch {
                reps.truncate(fetch);
                incomplete.push(field.clone());
            }
            crate::db::pg_text::sanitize_events_for_pg(&mut reps);
            let added = merge_unique(&mut extra, &mut seen, reps);
            budget = budget.saturating_sub(added);
        }
        if rule.risk_entity_field.is_none() {
            let mut unattributed = Box::pin(self
                .evaluate_window_with_limit(
                    &no_entity_query(&rule.query, &fields),
                    time_range.clone(),
                    rule.dataset.clone(),
                    1,
                    &scope,
                ))
                .await?;
            crate::db::pg_text::sanitize_events_for_pg(&mut unattributed);
            merge_unique(&mut extra, &mut seen, unattributed);
        }
        extra.append(rows);
        *rows = extra;
        Ok((!incomplete.is_empty()).then_some(incomplete))
    }
}

#[cfg(test)]
#[path = "run_bound_tests.rs"]
mod tests;
