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
use sqlx::PgPool;
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
pub async fn count_currently_failing_rules(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*)::bigint FROM detection_rules r WHERE {CURRENTLY_FAILING_PREDICATE}"
    )))
    .fetch_one(pool)
    .await
}

/// Number of failing rules (see the module docs).
pub async fn count_failing_rules(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*)::bigint FROM detection_rules r WHERE {FAILING_PREDICATE}"
    )))
    .fetch_one(pool)
    .await
}

/// The health rollup used by `/health/detailed`.
pub async fn read_execution_health(pool: &PgPool) -> Result<DetectionExecutionHealth, sqlx::Error> {
    let (failing_rules, currently_failing_rules, coverage_gaps_24h): (i64, i64, i64) =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            r#"
            SELECT
                (SELECT COUNT(*)::bigint FROM detection_rules r WHERE {FAILING_PREDICATE}),
                (SELECT COUNT(*)::bigint FROM detection_rules r WHERE {CURRENTLY_FAILING_PREDICATE}),
                (SELECT COUNT(*)::bigint FROM detection_coverage_gaps
                  WHERE recorded_at >= NOW() - make_interval(hours => 24))
            "#
        )))
        .fetch_one(pool)
        .await?;
    Ok(DetectionExecutionHealth {
        status: execution_status(currently_failing_rules, failing_rules, coverage_gaps_24h).to_string(),
        failing_rules,
        currently_failing_rules,
        coverage_gaps_24h,
    })
}

/// Failing rules (failing now or within the last 24h), rules failing now
/// first, then most recent error first (capped at `limit`).
pub async fn list_failing_rules(pool: &PgPool, limit: i64) -> Result<Vec<FailingRuleSummary>, sqlx::Error> {
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
        .fetch_all(pool)
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
