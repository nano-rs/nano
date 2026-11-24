// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5424: detection execution health — the one definition of a "failing"
//! rule, shared by the rule-health API, `/health/detailed` and SIEM Health so
//! a rule that cannot persist its matches is never reported healthy.
//!
//! A rule is failing when its executions are failing now
//! (`consecutive_failures > 0`, a pending size-class catch-up retry, or a
//! crash attributed to it — NAN-5736, kept across a coverage gap), or
//! when within the last 24 hours it recorded an execution / skipped-event
//! error or a coverage gap.
//!
//! NAN-5629: only a rule failing NOW makes detection health `critical`. A rule
//! that failed (or left a coverage gap) in the last 24 hours but whose last
//! run succeeded is a recent-failure warning (`degraded`), never critical:
//! before, one coverage gap recorded on a rule that had since recovered held
//! `/health/detailed` at `critical` for 24 hours while
//! `currently_failing_rules` read 0.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgExecutor;
use uuid::Uuid;

/// SQL predicate over `detection_rules r` (binds nothing): the rule's
/// executions are failing right now.
const CURRENTLY_FAILING_PREDICATE: &str = r#"
    r.archived = false
    AND r.mode IN ('live', 'alerting')
    AND (r.consecutive_failures > 0 OR r.catchup_size_failures > 0 OR r.crash_streak > 0)
"#;

/// SQL predicate over `detection_rules r` (binds nothing): failing now, or
/// with an error / coverage gap in the last 24h.
const FAILING_PREDICATE: &str = r#"
    r.archived = false
    AND r.mode IN ('live', 'alerting')
    AND (
        r.consecutive_failures > 0
        OR r.catchup_size_failures > 0
        OR r.crash_streak > 0
        OR r.last_error_at >= NOW() - make_interval(hours => 24)
        OR EXISTS (
            SELECT 1 FROM detection_coverage_gaps g
            WHERE g.rule_id = r.id
              AND g.recorded_at >= NOW() - make_interval(hours => 24)
        )
    )
"#;

/// Rollup for health endpoints.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct DetectionExecutionHealth {
    /// `"ok"`; `"degraded"` when a rule recorded an error or a coverage gap
    /// (a detection window never evaluated) in the last 24h but is running
    /// again; `"critical"` only while a rule's executions are failing now
    /// (NAN-5629).
    pub status: String,
    /// Rules failing now or with an error / coverage gap in the last 24h.
    pub failing_rules: i64,
    /// Rules whose executions are failing right now.
    pub currently_failing_rules: i64,
    /// Coverage gaps recorded in the last 24h (windows never evaluated).
    pub coverage_gaps_24h: i64,
}

/// One failing rule, for SIEM Health.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailingRuleSummary {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub consecutive_failures: i16,
    pub failing_since: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
    /// NAN-5629: the rule's executions are failing right now (consecutive
    /// failures or a pending catch-up retry), not only within the last 24h.
    #[serde(default)]
    pub failing_now: bool,
}

/// The rollup status (NAN-5629): `critical` only for rules failing now; a
/// recent error or coverage gap on a recovered rule is `degraded` at most.
pub fn execution_status(currently_failing_rules: i64, failing_rules: i64, coverage_gaps_24h: i64) -> &'static str {
    if currently_failing_rules > 0 {
        "critical"
    } else if failing_rules > 0 || coverage_gaps_24h > 0 {
        "degraded"
    } else {
        "ok"
    }
}

/// Number of rules whose executions are failing right now.
pub async fn count_currently_failing_rules<'e>(db: impl PgExecutor<'e>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*)::bigint FROM detection_rules r WHERE {CURRENTLY_FAILING_PREDICATE}"
    )))
    .fetch_one(db)
    .await
}

/// Number of failing rules (see the module docs).
pub async fn count_failing_rules<'e>(db: impl PgExecutor<'e>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*)::bigint FROM detection_rules r WHERE {FAILING_PREDICATE}"
    )))
    .fetch_one(db)
    .await
}

/// The health rollup used by `/health/detailed`.
pub async fn read_execution_health<'e>(
    db: impl PgExecutor<'e>,
) -> Result<DetectionExecutionHealth, sqlx::Error> {
    let (failing_rules, currently_failing_rules, coverage_gaps_24h): (i64, i64, i64) =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            r#"
            SELECT
                (SELECT COUNT(*)::bigint FROM detection_rules r WHERE {FAILING_PREDICATE}),
                (SELECT COUNT(*)::bigint FROM detection_rules r WHERE {CURRENTLY_FAILING_PREDICATE}),
                (SELECT COUNT(*)::bigint FROM detection_coverage_gaps g
                  JOIN detection_rules r ON r.id = g.rule_id
                  WHERE g.recorded_at >= NOW() - make_interval(hours => 24)
                    AND {COVERAGE_GAP_RULE_PREDICATE})
            "#
        )))
        .fetch_one(db)
        .await?;
    Ok(DetectionExecutionHealth {
        status: execution_status(currently_failing_rules, failing_rules, coverage_gaps_24h).to_string(),
        failing_rules,
        currently_failing_rules,
        coverage_gaps_24h,
    })
}

/// NAN-5772: SQL predicate over `detection_rules r` for a coverage gap's rule.
/// Deleting a rule archives it instead of removing the row, so its gaps no
/// longer cascade away; a deleted rule's gaps must not degrade health.
const COVERAGE_GAP_RULE_PREDICATE: &str = "r.archived = false";

/// NAN-5772: SQL predicate over `detection_rules r` (binds nothing): a rule
/// that exists and is meant to run, the rule set `GET /api/rules/noisy` lists.
/// Deleting a rule archives it (NAN-5672), so a count must join the rule and
/// check `archived` rather than read `detection_daily_stats` alone.
const RUNNING_RULE_PREDICATE: &str = "r.archived = false AND r.mode IN ('live', 'alerting')";

/// NAN-5772: number of noisy rules: running rules whose matches over the last
/// 7 days sum past `weekly_threshold`. Uses the same rule set as
/// `GET /api/rules/noisy`, so an archived (deleted) rule drops out at once
/// rather than after its stats age past the 7-day window.
pub async fn count_noisy_rules<'e>(db: impl PgExecutor<'e>, weekly_threshold: i64) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        r#"
        SELECT COUNT(*)::bigint FROM (
            SELECT s.rule_id
            FROM detection_daily_stats s
            JOIN detection_rules r ON r.id = s.rule_id
            WHERE s.date >= CURRENT_DATE - 7 AND {RUNNING_RULE_PREDICATE}
            GROUP BY s.rule_id
            HAVING SUM(s.match_count) > $1
        ) noisy
        "#
    )))
    .bind(weekly_threshold)
    .fetch_one(db)
    .await
}

/// Failing rules (failing now or within the last 24h), rules failing now
/// first, then most recent error first (capped at `limit`).
pub async fn list_failing_rules<'e>(
    db: impl PgExecutor<'e>,
    limit: i64,
) -> Result<Vec<FailingRuleSummary>, sqlx::Error> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(Uuid, String, i16, Option<DateTime<Utc>>, Option<String>, Option<DateTime<Utc>>, bool)> =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            r#"
            SELECT r.id, r.name, r.consecutive_failures, r.failing_since, r.last_error, r.last_error_at,
                   (r.consecutive_failures > 0 OR r.catchup_size_failures > 0 OR r.crash_streak > 0) AS failing_now
            FROM detection_rules r
            WHERE {FAILING_PREDICATE}
            ORDER BY failing_now DESC, r.last_error_at DESC NULLS LAST, r.name
            LIMIT $1
            "#
        )))
        .bind(limit)
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(
            |(rule_id, rule_name, consecutive_failures, failing_since, last_error, last_error_at, failing_now)| {
                FailingRuleSummary {
                    rule_id,
                    rule_name,
                    consecutive_failures,
                    failing_since,
                    last_error,
                    last_error_at,
                    failing_now,
                }
            },
        )
        .collect())
}

#[cfg(test)]
#[path = "health_status_tests.rs"]
mod health_status_tests;
