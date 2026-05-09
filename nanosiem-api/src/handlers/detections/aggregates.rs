// SPDX-License-Identifier: AGPL-3.0-or-later

//! Home-page aggregate endpoints (NAN-370).
//!
//! Small, bounded aggregate queries over existing detection + tuning tables. No
//! schema changes; all aggregates run over `detection_rules`,
//! `detection_daily_stats`, and `tuning_notifications`.

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use uuid::Uuid;

use super::types::*;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

// Thresholds — tuned once we have real usage; kept as consts so a future knob/setting
// can replace them without chasing magic numbers.
const NOISY_WEEKLY_THRESHOLD: i64 = 500;
const TREND_UP_RATIO: f64 = 1.2;
const TREND_DOWN_RATIO: f64 = 0.8;
const DEFAULT_NOISY_LIMIT: i32 = 5;
const MAX_NOISY_LIMIT: i32 = 20;

// Fleet-health thresholds (NAN-612). Held as consts so a future settings UI can
// replace them without chasing magic numbers.
//
// `SLOW_DURATION_MS`: a rule whose most-recent recorded execution time is at
// or above this value is classified Slow. 5s comfortably exceeds the typical
// few-hundred ms a small ClickHouse aggregate takes; rules pushing past it
// are usually ones with no PREWHERE filter or a broad time window.
//
// `STUCK_THRESHOLD_SECS`: how far past `next_run_at` a rule must fall before
// we count it as Errors. Default scheduler poll is 30s and execution timeout
// is 60s, so 300s (5 min) means a rule has missed at least ~3 expected
// poll cycles — consistent with a stuck claim or repeated timeouts.
//
// `RECENT_METRICS_WINDOW_HOURS`: how far back to look in
// `detection_rule_metrics` for the most-recent execution time per rule. 24h
// matches the rest of the rules-overview cells (24h alerts, 24h velocity).
const SLOW_DURATION_MS: i64 = 5_000;
const STUCK_THRESHOLD_SECS: i64 = 300;
const RECENT_METRICS_WINDOW_HOURS: i32 = 24;

/// Detection health summary for the Home page "Detection health" pulse card.
///
/// Three aggregate counts over existing tables:
/// - `needs_tuning`: unread `tuning_notifications` rows (`read_at IS NULL`)
/// - `noisy_count`: rules whose 7-day `match_count` sum exceeds [`NOISY_WEEKLY_THRESHOLD`]
/// - `silent_count`: rules in Live/Alerting mode with no matches in the last 7 days
#[utoipa::path(
    get,
    path = "/api/rules/health-summary",
    tag = "detections",
    responses(
        (status = 200, description = "Detection engine health summary", body = DetectionHealthSummary),
        (status = 403, description = "Missing permission: detections:view", body = crate::error::ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_detection_health_summary(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<DetectionHealthSummary>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    let needs_tuning: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)::bigint FROM tuning_notifications WHERE read_at IS NULL"#,
    )
    .fetch_one(&state.pool)
    .await?;

    let noisy_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint FROM (
            SELECT rule_id
            FROM detection_daily_stats
            WHERE date >= CURRENT_DATE - 7
            GROUP BY rule_id
            HAVING SUM(match_count) > $1
        ) noisy
        "#,
    )
    .bind(NOISY_WEEKLY_THRESHOLD)
    .fetch_one(&state.pool)
    .await?;

    // Silent = a rule that is *supposed* to be running (Live or Alerting mode) but
    // hasn't produced any matches in the last 7 days. `last_match_at IS NULL`
    // counts rules that never matched.
    let silent_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint FROM detection_rules
        WHERE mode IN ('live', 'alerting')
          AND (last_match_at IS NULL OR last_match_at < NOW() - INTERVAL '7 days')
        "#,
    )
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(DetectionHealthSummary {
        needs_tuning,
        noisy_count,
        silent_count,
    }))
}

/// Top-N noisiest detection rules, ranked by 7-day match count.
///
/// Computed in a single query with three CTEs so trend is consistent with the
/// totals returned. The `fp_rate` field is currently `alert_count / match_count`
/// as a stand-in for a real analyst-feedback-driven FP metric; the frontend
/// treats it as informational, not ranking.
#[utoipa::path(
    get,
    path = "/api/rules/noisy",
    tag = "detections",
    params(NoisyRulesQuery),
    responses(
        (status = 200, description = "Top noisy rules", body = NoisyRulesResponse),
        (status = 403, description = "Missing permission: detections:view", body = crate::error::ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_noisy_rules(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<NoisyRulesQuery>,
) -> Result<Json<NoisyRulesResponse>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    let limit = params
        .limit
        .unwrap_or(DEFAULT_NOISY_LIMIT)
        .clamp(1, MAX_NOISY_LIMIT);

    let rows: Vec<(Uuid, String, i64, i64, Option<i64>, Option<i64>)> = sqlx::query_as(
        r#"
        WITH last_7d AS (
            SELECT rule_id,
                   SUM(match_count)::bigint AS total_matches,
                   SUM(alert_count)::bigint AS total_alerts
            FROM detection_daily_stats
            WHERE date >= CURRENT_DATE - 7
            GROUP BY rule_id
        ),
        current_24h AS (
            SELECT rule_id, SUM(match_count)::bigint AS cur_count
            FROM detection_daily_stats
            WHERE date >= CURRENT_DATE - 1
            GROUP BY rule_id
        ),
        prior_24h AS (
            SELECT rule_id, SUM(match_count)::bigint AS prior_count
            FROM detection_daily_stats
            WHERE date >= CURRENT_DATE - 2 AND date < CURRENT_DATE - 1
            GROUP BY rule_id
        )
        SELECT
            dr.id,
            dr.name,
            l.total_matches,
            l.total_alerts,
            c.cur_count,
            p.prior_count
        FROM detection_rules dr
        INNER JOIN last_7d l ON dr.id = l.rule_id
        LEFT JOIN current_24h c ON dr.id = c.rule_id
        LEFT JOIN prior_24h p ON dr.id = p.rule_id
        WHERE dr.mode IN ('live', 'alerting')
          AND l.total_matches > 0
        ORDER BY l.total_matches DESC
        LIMIT $1
        "#,
    )
    .bind(limit as i64)
    .fetch_all(&state.pool)
    .await?;

    let rules = rows
        .into_iter()
        .map(|(id, name, matches, alerts, cur_24h, prior_24h)| {
            let fp_rate = if matches > 0 {
                (alerts as f64) / (matches as f64)
            } else {
                0.0
            };
            let trend = classify_trend(cur_24h.unwrap_or(0), prior_24h.unwrap_or(0));
            NoisyRule {
                rule_id: nanosiem_core::typeid::encode("rule", &id),
                rule_name: name,
                match_count: matches,
                alert_count: alerts,
                fp_rate,
                trend,
            }
        })
        .collect();

    Ok(Json(NoisyRulesResponse { rules }))
}

/// Fleet-health rollup for the `/rules` overview strip "Fleet health" cell.
///
/// Operates over the **schedulable** fleet only — Live/Alerting, scheduled
/// detection_mode, with a `schedule_cron`. Real-time materialized-view rules
/// are excluded because they do not flow through the scheduler claim/release
/// path that produces these signals.
///
/// Buckets:
/// - `errors`: `next_run_at` more than `STUCK_THRESHOLD_SECS` past due. The
///   scheduler can't advance the rule — execution timing out, node crashed
///   mid-claim, or the rule itself throws. Computed first so a stuck-and-slow
///   rule still surfaces as an error.
/// - `slow`: not stuck, and the most-recent `detection_rule_metrics` row in
///   the last `RECENT_METRICS_WINDOW_HOURS` reports `execution_time_ms >=
///   SLOW_DURATION_MS`.
/// - `healthy`: not stuck, has run at least once (`last_run_at IS NOT NULL`),
///   and either has no recent metrics row (treated as fast — metrics collector
///   only populates after the rule is actively producing alerts) or the most
///   recent row is fast.
///
/// Note on accuracy: `detection_rule_metrics.execution_time_ms` is recorded
/// per metrics-collection pass by `tuning::metrics::collect_all_metrics`,
/// which only runs for rules with alerting activity. Rules that ran but never
/// matched will appear as Healthy regardless of duration. This is acceptable
/// for the at-a-glance card; true per-run duration tracking is a punted
/// follow-up requiring `detection_rules.last_run_duration_ms`.
#[utoipa::path(
    get,
    path = "/api/rules/fleet-health",
    tag = "detections",
    responses(
        (status = 200, description = "Fleet health rollup over the schedulable rule fleet", body = FleetHealthSummary),
        (status = 403, description = "Missing permission: detections:view", body = crate::error::ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_fleet_health(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<FleetHealthSummary>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    // Single round-trip. The CTE pulls the latest in-window metrics row per
    // rule (DISTINCT ON), then a CASE expression buckets each rule. Rules
    // without `last_run_at` (haven't run their first cycle yet) are counted in
    // `total` but no bucket — the frontend shows the remainder implicitly.
    let row: (i64, i64, i64, i64) = sqlx::query_as(
        r#"
        WITH fleet AS (
            SELECT id, last_run_at, next_run_at
            FROM detection_rules
            WHERE archived = false
              AND mode IN ('live', 'alerting')
              AND detection_mode = 'scheduled'
              AND schedule_cron IS NOT NULL
        ),
        latest_metrics AS (
            SELECT DISTINCT ON (rule_id)
                rule_id, execution_time_ms
            FROM detection_rule_metrics
            WHERE timestamp >= NOW() - make_interval(hours => $3)
            ORDER BY rule_id, timestamp DESC
        )
        SELECT
            COUNT(*)::bigint AS total,
            COUNT(*) FILTER (
                WHERE f.last_run_at IS NOT NULL
                  AND (f.next_run_at IS NULL OR f.next_run_at >= NOW() - make_interval(secs => $1))
                  AND COALESCE(m.execution_time_ms, 0) < $2
            )::bigint AS healthy,
            COUNT(*) FILTER (
                WHERE f.last_run_at IS NOT NULL
                  AND (f.next_run_at IS NULL OR f.next_run_at >= NOW() - make_interval(secs => $1))
                  AND m.execution_time_ms >= $2
            )::bigint AS slow,
            COUNT(*) FILTER (
                WHERE f.next_run_at IS NOT NULL
                  AND f.next_run_at < NOW() - make_interval(secs => $1)
            )::bigint AS errors
        FROM fleet f
        LEFT JOIN latest_metrics m ON m.rule_id = f.id
        "#,
    )
    // NAN-616: bind as integers, not f64. PostgreSQL's `make_interval` is
    // overloaded only on integer parameters — passing double precision yields
    // `function make_interval(hours => double precision) does not exist` and
    // 500s the whole endpoint. The constants are already i64/i32.
    .bind(STUCK_THRESHOLD_SECS)
    .bind(SLOW_DURATION_MS)
    .bind(RECENT_METRICS_WINDOW_HOURS)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(FleetHealthSummary {
        total: row.0,
        healthy: row.1,
        slow: row.2,
        errors: row.3,
    }))
}

fn classify_trend(current: i64, prior: i64) -> String {
    // If there's no prior data, growing from zero is "up" by definition.
    if prior == 0 {
        return if current > 0 { "up" } else { "flat" }.to_string();
    }
    let ratio = current as f64 / prior as f64;
    if ratio >= TREND_UP_RATIO {
        "up".to_string()
    } else if ratio <= TREND_DOWN_RATIO {
        "down".to_string()
    } else {
        "flat".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trend_flat_when_prior_zero_and_no_current() {
        assert_eq!(classify_trend(0, 0), "flat");
    }

    #[test]
    fn trend_up_when_growing_from_zero() {
        assert_eq!(classify_trend(5, 0), "up");
    }

    #[test]
    fn trend_up_over_120_percent() {
        // 150 vs 100 = 1.5x → up
        assert_eq!(classify_trend(150, 100), "up");
    }

    #[test]
    fn trend_down_under_80_percent() {
        // 70 vs 100 = 0.7x → down
        assert_eq!(classify_trend(70, 100), "down");
    }

    #[test]
    fn trend_flat_within_band() {
        // 100 vs 100 = 1.0x → flat
        assert_eq!(classify_trend(100, 100), "flat");
        // 110 vs 100 = 1.1x → flat (below 1.2 threshold)
        assert_eq!(classify_trend(110, 100), "flat");
        // 90 vs 100 = 0.9x → flat (above 0.8 threshold)
        assert_eq!(classify_trend(90, 100), "flat");
    }
}
