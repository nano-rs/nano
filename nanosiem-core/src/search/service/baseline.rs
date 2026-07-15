// SPDX-License-Identifier: AGPL-3.0-or-later

//! `| baseline` view builder (NAN-1868) — exposes entity baselining in general
//! search. Given a resolved entity and the search's time range (the "current"
//! window under examination), it looks back `window` days before that window and
//! reports the values the entity has NOT done in that lookback, per dimension,
//! with a coverage flag. It reuses the shadow-investigator primitives
//! (`crate::baseline`) and the entity-keyed `SearchService` methods
//! (`entity_dimension_firsts` / `entity_activity_buckets` /
//! `entity_hourly_activity_scoped`) — no reimplementation of the anti-join or the
//! coverage gating.

use super::*;
use crate::auth::ScopeSet;
use crate::baseline::{self, BaselineSpans};
use crate::search::query_processing::BaselineCommandInfo;

/// Current window (the analyst's search range) is capped so `<wide range> |
/// baseline` can't become a full scan — baseline scans this window PLUS the
/// lookback.
const MAX_BASELINE_CURRENT_DAYS: i64 = 7;

/// Upper bound on the `window=` lookback. The new-to-entity check scans raw logs
/// per dimension (~0.3–0.8 GiB/entity at 7d), so an unbounded window is a
/// request-level DoS vector; and values large enough to overflow
/// `chrono::Duration::days` (~1.07e8 days) panic `BaselineSpans::new`. Reject
/// anything beyond this rather than clamp, so the analyst knows the window was
/// too wide. 90d is a generous interactive ceiling (default is 7d).
const MAX_BASELINE_NEW_WINDOW_DAYS: i64 = 90;

/// Validate and normalise the requested `window=` lookback into whole days.
/// Rejects oversized windows (DoS + `chrono::Duration::days` overflow) with a
/// clear error; floors at 1 day. Pure so it is unit-testable without a DB.
fn validated_new_window_days(window: std::time::Duration) -> Result<i64, SearchError> {
    // as_secs() is u64; divide first so an astronomically large duration can't
    // wrap when narrowed to i64. The bound is checked in u64.
    let requested = window.as_secs() / 86_400;
    if requested > MAX_BASELINE_NEW_WINDOW_DAYS as u64 {
        return Err(SearchError::SqlValidationError(format!(
            "| baseline window is limited to {MAX_BASELINE_NEW_WINDOW_DAYS} days (requested \
             {requested}d) — narrow the window. The lookback scans raw logs per dimension, so \
             it is deliberately bounded."
        )));
    }
    Ok((requested.max(1)) as i64)
}

impl SearchService {
    /// Build the `| baseline` result rows for one resolved entity.
    pub(crate) async fn build_baseline_view(
        &self,
        info: &BaselineCommandInfo,
        entity: (String, String),
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        use serde_json::json;

        let (entity_type, entity_value) = entity;

        if !baseline::is_baselineable(&entity_type) {
            return Err(SearchError::SqlValidationError(format!(
                "| baseline supports host / user / ip entities, not '{entity_type}'. Give one with \
                 host=/user=/ip=\"…\" or a src_host / src_ip / user filter."
            )));
        }

        // Bound the scan.
        if (time_range.end - time_range.start).num_days() > MAX_BASELINE_CURRENT_DAYS {
            return Err(SearchError::SqlValidationError(format!(
                "| baseline current window is limited to {MAX_BASELINE_CURRENT_DAYS} days — narrow \
                 your time range. Baseline scans this window PLUS the lookback used for the \
                 new-value comparison."
            )));
        }

        let new_window_days = validated_new_window_days(info.window)?;
        let scope_restricted = scope.is_restricted();
        // The agg (`entity_time_range_agg`) has no source_type column, so it cannot
        // be scoped — a restricted search draws coverage from a SCOPED raw hourly
        // scan instead, kept to the short window. Unrestricted uses the cheap agg.
        let activity_days = if scope_restricted {
            new_window_days
        } else {
            baseline::activity_days()
        };
        let spans = BaselineSpans::new(
            time_range.start,
            time_range.end,
            activity_days,
            new_window_days,
        );

        // Coverage from the entity's activity buckets.
        let buckets: Vec<(chrono::DateTime<chrono::Utc>, u64)> = if scope_restricted {
            self.entity_hourly_activity_scoped(
                scope,
                &entity_type,
                &entity_value,
                spans.activity_start,
                spans.coverage_end(),
            )
            .await?
        } else {
            self.entity_activity_buckets(
                &entity_type,
                &entity_value,
                spans.activity_start,
                spans.coverage_end(),
            )
            .await?
        }
        .into_iter()
        .map(|b| (b.hour_start, b.event_count))
        .collect();
        let summary = baseline::summarize_activity(&buckets, &spans);

        // Which dimensions the analyst asked for (None = all for the type).
        let wants = |field: &str| -> bool {
            info.dims
                .as_ref()
                .is_none_or(|d| d.iter().any(|w| w == field))
        };

        // New-to-entity — one consolidated scoped scan per filter group.
        let mut dimensions = Vec::new();
        if !summary.coverage.is_blind() {
            let mut firsts = Vec::new();
            for (source_side_only, dims) in
                baseline::dimension_scope_groups(&entity_type, true, true, true)
            {
                let fields: Vec<&str> =
                    dims.iter().map(|d| d.field).filter(|f| wants(f)).collect();
                if fields.is_empty() {
                    continue;
                }
                let rows = self
                    .entity_dimension_firsts(
                        scope,
                        &entity_type,
                        &entity_value,
                        source_side_only,
                        &fields,
                        spans.new_start,
                        spans.incident_end,
                        baseline::NEW_TO_ENTITY_ROW_CAP,
                    )
                    .await?;
                firsts.extend(rows);
            }
            for dim in baseline::dimensions_for(&entity_type, true, true, true) {
                if !wants(dim.field) {
                    continue;
                }
                let dim_rows: Vec<(String, u64, chrono::DateTime<chrono::Utc>)> = firsts
                    .iter()
                    .filter(|f| f.dimension == dim.field)
                    .map(|f| (f.value.clone(), f.count, f.first_seen))
                    .collect();
                dimensions.push(baseline::parse_dimension_firsts(
                    dim.label,
                    dim_rows,
                    baseline::NEW_TO_ENTITY_ROW_CAP,
                    spans.incident_start,
                    summary.coverage,
                ));
            }
        }

        // Emit one row per new value; carry the coverage flag on every row.
        let coverage_label = summary.coverage.label();
        let mut out: Vec<serde_json::Value> = Vec::new();
        for d in &dimensions {
            for p in &d.new_to_entity {
                out.push(json!({
                    "entity": entity_value,
                    "entity_type": entity_type,
                    "dimension": d.label,
                    "value": p.value,
                    "count": p.count,
                    "first_seen": p.first_seen.to_rfc3339(),
                    "coverage": coverage_label,
                    // True when the whole result cap was new values, so the
                    // baseline could not be established (a scan) — not a confirmed
                    // "never seen before".
                    "baseline_unknown": d.baseline_unknown,
                }));
            }
        }

        // Always give the analyst feedback — a summary row with the coverage even
        // when nothing was new, so "no rows" is never ambiguous.
        if out.is_empty() {
            let note = if summary.coverage.is_blind() {
                format!(
                    "no activity in the last {new_window_days}d — baseline UNKNOWN, cannot judge \
                     what is new for this {entity_type}"
                )
            } else {
                format!(
                    "nothing new in the last {new_window_days}d for this {entity_type} \
                     (coverage: {coverage_label})"
                )
            };
            out.push(json!({
                "entity": entity_value,
                "entity_type": entity_type,
                "dimension": serde_json::Value::Null,
                "value": serde_json::Value::Null,
                "count": 0,
                "first_seen": serde_json::Value::Null,
                "coverage": coverage_label,
                "note": note,
            }));
        }

        Ok(out)
    }
}

#[cfg(test)]
mod parse_tests {
    use crate::query::{parse_query, Command, PrettyPrint, Query};

    fn baseline_of(q: &str) -> Command {
        // Walk to the trailing `| baseline` command.
        fn last(query: &Query) -> Option<Command> {
            match query {
                Query::Search(_) => None,
                Query::Piped { command, .. } => Some(command.clone()),
            }
        }
        last(&parse_query(q).expect("parses")).expect("has trailing command")
    }

    #[test]
    fn infers_entity_form_parses_to_baseline() {
        let cmd = baseline_of("src_host=\"ws-1\" | baseline");
        assert!(matches!(
            cmd,
            Command::Baseline {
                entity_type: None,
                entity_value: None,
                ..
            }
        ));
    }

    #[test]
    fn explicit_host_and_window_and_dims_parse() {
        let cmd = baseline_of("* | baseline host=\"ws-1\" window=14d dims=process_name,dest_ip");
        match cmd {
            Command::Baseline {
                entity_type,
                entity_value,
                window,
                dims,
            } => {
                assert_eq!(entity_type.as_deref(), Some("host"));
                assert_eq!(entity_value.as_deref(), Some("ws-1"));
                assert_eq!(window, std::time::Duration::from_secs(14 * 86400));
                assert_eq!(
                    dims,
                    Some(vec!["process_name".to_string(), "dest_ip".to_string()])
                );
            }
            other => panic!("expected Baseline, got {other:?}"),
        }
    }

    #[test]
    fn user_and_ip_shorthands_parse() {
        assert!(matches!(
            baseline_of("* | baseline user=\"bob\""),
            Command::Baseline { entity_type, .. } if entity_type.as_deref() == Some("user")
        ));
        assert!(matches!(
            baseline_of("* | baseline ip=\"10.0.0.1\""),
            Command::Baseline { entity_type, .. } if entity_type.as_deref() == Some("ip")
        ));
    }

    #[test]
    fn default_window_is_seven_days() {
        if let Command::Baseline { window, .. } = baseline_of("* | baseline host=\"ws-1\"") {
            assert_eq!(window, std::time::Duration::from_secs(7 * 86400));
        } else {
            panic!("expected Baseline");
        }
    }

    #[test]
    fn round_trips_through_pretty_print() {
        // Detection enrichment re-parses pretty-printed queries; the command must
        // survive the round-trip.
        let original = "* | baseline host=\"ws-1\" window=14d dims=process_name";
        let parsed = parse_query(original).unwrap();
        let printed = parsed.pretty_print();
        let reparsed = parse_query(&printed).expect("pretty-printed form re-parses");
        assert_eq!(parsed, reparsed, "round-trip changed the AST: {printed}");
    }

    /// NAN-1868 (codex second-pass): an oversized `window=` must be rejected, not
    /// panic `chrono::Duration::days` or launch an unbounded raw scan.
    #[test]
    fn window_days_validation_bounds_and_floors() {
        use super::{validated_new_window_days, MAX_BASELINE_NEW_WINDOW_DAYS};
        use std::time::Duration;
        let days = |d: u64| Duration::from_secs(d * 86_400);

        assert_eq!(validated_new_window_days(days(7)).unwrap(), 7);
        // Sub-day floors to 1.
        assert_eq!(
            validated_new_window_days(Duration::from_secs(3600)).unwrap(),
            1
        );
        // The ceiling itself is allowed.
        assert_eq!(
            validated_new_window_days(days(MAX_BASELINE_NEW_WINDOW_DAYS as u64)).unwrap(),
            MAX_BASELINE_NEW_WINDOW_DAYS
        );
        // One day over → rejected, no panic.
        assert!(validated_new_window_days(days(MAX_BASELINE_NEW_WINDOW_DAYS as u64 + 1)).is_err());
        // The exact chrono-overflow value codex found → rejected, no panic.
        assert!(validated_new_window_days(days(106_751_992)).is_err());
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::schema::OcsfProfile;
    use crate::{DualPool, DualPoolConfig, SearchRequest, TimeRangeInput};
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Arc;

    async fn local() -> Option<SearchService> {
        let config = DualPoolConfig::with_auth(
            "postgres://nanosiem:nanosiem@localhost:5432/nanosiem",
            "http://localhost:8123",
            "nanosiem",
            "default",
            "",
        );
        match DualPool::new(&config).await {
            Ok(pool) => Some(SearchService::with_dual_pool_and_profile(
                &pool,
                Arc::new(OcsfProfile::new()),
            )),
            Err(e) => {
                eprintln!("Could not connect to local DBs ({e}); is the stack up?");
                None
            }
        }
    }

    fn req(query: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> SearchRequest {
        SearchRequest {
            query: query.to_string(),
            time_range: TimeRangeInput::new(start, end),
            limit: Some(200),
            offset: None,
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: Some("interactive".to_string()),
            dataset: None,
        }
    }

    /// Drives the full search() path for `| baseline` against the local stack.
    /// `#[ignore]` — requires local ClickHouse + Postgres. Run:
    ///   cargo test -p nanosiem-core --lib baseline_command_live -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "requires local ClickHouse + Postgres"]
    async fn baseline_command_live() {
        let Some(ss) = local().await else {
            return;
        };
        // Current window where ws-fin-001's new processes appear (2026-07-11 15:13).
        let start = Utc.with_ymd_and_hms(2026, 7, 11, 15, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 7, 11, 15, 28, 0).unwrap();

        for query in [
            "src_host=\"ws-fin-001.corp.local\" | baseline",
            "* | baseline host=\"ws-fin-001.corp.local\" window=7d",
        ] {
            println!("\n=== {query} ===");
            let resp = ss
                .search(req(query, start, end), &ScopeSet::unrestricted())
                .await
                .expect("search runs");
            assert_eq!(resp.display_type, Some(DisplayType::Baseline));
            assert!(!resp.results.is_empty(), "should return at least a summary row");
            for row in &resp.results {
                println!("{}", serde_json::to_string(row).unwrap());
            }
        }
    }
}
