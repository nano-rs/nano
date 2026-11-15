// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5424: detection execution health — the one definition of a "failing"
//! rule, shared by the rule-health API, `/health/detailed` and SIEM Health so
//! a rule that cannot persist its matches is never reported healthy.
//!
//! A rule is failing when its executions are failing now
//! (`consecutive_failures > 0`, or a pending size-class catch-up retry), or
//! when within the last 24 hours it recorded an execution / skipped-event
//! error or a coverage gap.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// SQL predicate over `detection_rules r` (binds nothing).
const FAILING_PREDICATE: &str = r#"
    r.archived = false
    AND r.mode IN ('live', 'alerting')
    AND (
        r.consecutive_failures > 0
        OR r.catchup_size_failures > 0
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
    /// `"ok"`; `"degraded"` when a rule recorded an error in the last 24h
    /// but is running again; `"critical"` while a rule is failing or after a
    /// detection window went unevaluated (coverage gap) in the last 24h.
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
}

/// Number of failing rules (see the module docs).
pub async fn count_failing_rules(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(&format!(
        "SELECT COUNT(*)::bigint FROM detection_rules r WHERE {FAILING_PREDICATE}"
    ))
    .fetch_one(pool)
    .await
}

/// The health rollup used by `/health/detailed`.
pub async fn read_execution_health(pool: &PgPool) -> Result<DetectionExecutionHealth, sqlx::Error> {
    let (failing_rules, currently_failing_rules, coverage_gaps_24h): (i64, i64, i64) =
        sqlx::query_as(&format!(
            r#"
            SELECT
                (SELECT COUNT(*)::bigint FROM detection_rules r WHERE {FAILING_PREDICATE}),
                (SELECT COUNT(*)::bigint FROM detection_rules r
                  WHERE r.archived = false
                    AND r.mode IN ('live', 'alerting')
                    AND (r.consecutive_failures > 0 OR r.catchup_size_failures > 0)),
                (SELECT COUNT(*)::bigint FROM detection_coverage_gaps
                  WHERE recorded_at >= NOW() - make_interval(hours => 24))
            "#
        ))
        .fetch_one(pool)
        .await?;
    Ok(DetectionExecutionHealth {
        status: if currently_failing_rules > 0 || coverage_gaps_24h > 0 {
            "critical"
        } else if failing_rules > 0 {
            "degraded"
        } else {
            "ok"
        }
        .to_string(),
        failing_rules,
        currently_failing_rules,
        coverage_gaps_24h,
    })
}

/// Failing rules, most recent error first (capped at `limit`).
pub async fn list_failing_rules(pool: &PgPool, limit: i64) -> Result<Vec<FailingRuleSummary>, sqlx::Error> {
    let rows: Vec<(Uuid, String, i16, Option<DateTime<Utc>>, Option<String>, Option<DateTime<Utc>>)> =
        sqlx::query_as(&format!(
            r#"
            SELECT r.id, r.name, r.consecutive_failures, r.failing_since, r.last_error, r.last_error_at
            FROM detection_rules r
            WHERE {FAILING_PREDICATE}
            ORDER BY r.last_error_at DESC NULLS LAST, r.name
            LIMIT $1
            "#
        ))
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(
            |(rule_id, rule_name, consecutive_failures, failing_since, last_error, last_error_at)| {
                FailingRuleSummary {
                    rule_id,
                    rule_name,
                    consecutive_failures,
                    failing_since,
                    last_error,
                    last_error_at,
                }
            },
        )
        .collect())
}
