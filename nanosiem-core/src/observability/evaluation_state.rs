// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable monitor and SLO evaluation state (NAN-3894, O3b).
//!
//! The dedicated schedulers write their latest result per metric-monitor
//! series (`observability_metric_monitor_state`, migration 292, written by
//! [`super::metric_alert_lifecycle::advance_cursor`]) and per SLO
//! (`observability_slo_evaluations`, migration 295, written here). The
//! console reads them to say "last evaluated N s ago · breaching / ok / no
//! data / partial" instead of guessing from an empty chart.
//!
//! Definitions stay the source of truth: a state row is only returned while
//! its `definition_updated_at` matches the definition's `updated_at` (an edit
//! invalidates it) and while it is fresh (a stopped evaluator ages out
//! instead of reporting a stale "ok" forever).
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use super::eval::SloEvaluation;
use super::SloDefinition;

/// An SLO result older than this is not served (the scheduler ticks every
/// 60 s; ten missed ticks means it is not running).
pub const SLO_EVALUATION_FRESH_SECS: i64 = 600;

/// One metric-monitor series result from the current evaluation.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema, sqlx::FromRow)]
pub struct MetricMonitorEvaluation {
    #[serde(with = "crate::typeid::metric_monitor")]
    #[schema(value_type = String)]
    pub monitor_id: Uuid,
    /// Grouped series value (`""` for an ungrouped monitor, or for "the
    /// evaluation returned no series at all").
    pub series_key: String,
    /// Aggregate value; `null` when the window had no samples (never 0).
    pub value: Option<f64>,
    pub breaching: bool,
    pub no_data: bool,
    pub evaluated_at: DateTime<Utc>,
}

/// Series rows returned per monitor (breaching first). The status summary
/// is computed over ALL of a monitor's current series, independent of it.
pub const MONITOR_SERIES_SAMPLE: i64 = 100;

/// Complete status of one monitor's current evaluation generation.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema, sqlx::FromRow)]
pub struct MetricMonitorEvaluationSummary {
    #[serde(with = "crate::typeid::metric_monitor")]
    #[schema(value_type = String)]
    pub monitor_id: Uuid,
    pub evaluated_at: DateTime<Utc>,
    /// Series in the current evaluation.
    pub series: i64,
    pub breaching: i64,
    pub no_data: i64,
    /// True when `evaluations` carries only a sample of this monitor's series.
    pub truncated: bool,
}

/// Current evaluation state of every enabled monitor: a complete per-monitor
/// summary plus a bounded per-monitor sample of series rows (breaching
/// first, at most [`MONITOR_SERIES_SAMPLE`]).
///
/// "Current" = the monitor's evaluation generation (migration 295), for its
/// current definition, evaluated within `max(10 min, 2 × eval_interval)`. A
/// disabled, edited or unevaluated monitor has neither (the console shows
/// "Awaiting evaluation", not "healthy").
pub async fn list_current_metric_monitor_state(
    pool: &PgPool,
) -> Result<(Vec<MetricMonitorEvaluationSummary>, Vec<MetricMonitorEvaluation>), sqlx::Error> {
    const CURRENT: &str = "SELECT s.monitor_id, s.series_key, s.value, s.breaching, s.no_data, s.evaluated_at \
           FROM observability_metric_monitor_state s \
           JOIN observability_metric_monitors d ON d.id = s.monitor_id \
           JOIN observability_metric_monitor_generation g \
             ON g.monitor_id = s.monitor_id AND g.evaluated_at = s.evaluated_at \
          WHERE d.enabled \
            AND s.definition_updated_at = d.updated_at \
            AND s.evaluated_at > NOW() - GREATEST(INTERVAL '10 minutes', \
                                                  d.eval_interval_secs * INTERVAL '2 seconds')";
    let summaries = sqlx::query_as(&format!(
        "SELECT monitor_id, max(evaluated_at) AS evaluated_at, count(*) AS series, \
                count(*) FILTER (WHERE breaching) AS breaching, \
                count(*) FILTER (WHERE no_data) AS no_data, \
                count(*) > $1 AS truncated \
           FROM ({CURRENT}) c GROUP BY monitor_id ORDER BY monitor_id"
    ))
    .bind(MONITOR_SERIES_SAMPLE)
    .fetch_all(pool)
    .await?;
    let sample = sqlx::query_as(&format!(
        "SELECT monitor_id, series_key, value, breaching, no_data, evaluated_at FROM ( \
           SELECT c.*, row_number() OVER (PARTITION BY monitor_id \
                    ORDER BY breaching DESC, no_data ASC, series_key) AS rn \
             FROM ({CURRENT}) c) ranked \
          WHERE rn <= $1 ORDER BY monitor_id, rn"
    ))
    .bind(MONITOR_SERIES_SAMPLE)
    .fetch_all(pool)
    .await?;
    Ok((summaries, sample))
}

/// Persisted SLO result, as served on the list endpoint.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema, sqlx::FromRow)]
pub struct SloEvaluationRecord {
    #[serde(with = "crate::typeid::slo")]
    #[schema(value_type = String)]
    pub slo_id: Uuid,
    pub current: Option<f64>,
    pub total: i64,
    pub no_data: bool,
    pub budget_remaining_pct: Option<f64>,
    pub burn_fast: Option<f64>,
    pub burn_slow: Option<f64>,
    pub status: String,
    pub evaluated_at: DateTime<Utc>,
}

/// Record one SLO evaluation taken at `now`. Fenced twice:
/// - on the definition: nothing is written unless the SLO still exists with
///   the `updated_at` the evaluation read (an edit or delete mid-evaluation
///   drops the stale result);
/// - on time: an existing row is only replaced by a newer evaluation, so a
///   slow evaluator (e.g. across a jobs leader failover) cannot overwrite a
///   newer result.
///
/// Attainment, budget and burn are stored only when known (`partial` and
/// `no_data` store NULL). Returns whether the row was written.
pub async fn record_slo_evaluation(
    pool: &PgPool,
    slo: &SloDefinition,
    current: f64,
    total: i64,
    no_data: bool,
    evaluation: &SloEvaluation,
    now: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let known = evaluation.known();
    let written = sqlx::query(
        "INSERT INTO observability_slo_evaluations \
           (slo_id, current, total, no_data, budget_remaining_pct, burn_fast, burn_slow, \
            status, definition_updated_at, evaluated_at) \
         SELECT d.id, $3, $4, $5, $6, $7, $7, $8, d.updated_at, $9 \
           FROM observability_slos d WHERE d.id = $1 AND d.updated_at = $2 \
         ON CONFLICT (slo_id) DO UPDATE SET \
           current = EXCLUDED.current, total = EXCLUDED.total, no_data = EXCLUDED.no_data, \
           budget_remaining_pct = EXCLUDED.budget_remaining_pct, \
           burn_fast = EXCLUDED.burn_fast, burn_slow = EXCLUDED.burn_slow, \
           status = EXCLUDED.status, definition_updated_at = EXCLUDED.definition_updated_at, \
           evaluated_at = EXCLUDED.evaluated_at \
         WHERE observability_slo_evaluations.evaluated_at < EXCLUDED.evaluated_at",
    )
    .bind(slo.id)
    .bind(slo.updated_at)
    .bind(known.then_some(current))
    .bind(total.max(0))
    .bind(no_data)
    .bind(known.then_some(evaluation.budget_remaining_pct))
    .bind(known.then_some(evaluation.burn_rate))
    .bind(evaluation.status)
    .bind(now)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(written > 0)
}

/// Fresh persisted SLO results for the current definitions.
pub async fn list_fresh_slo_evaluations(
    pool: &PgPool,
) -> Result<Vec<SloEvaluationRecord>, sqlx::Error> {
    sqlx::query_as(
        "SELECT e.slo_id, e.current, e.total, e.no_data, e.budget_remaining_pct, \
                e.burn_fast, e.burn_slow, e.status, e.evaluated_at \
           FROM observability_slo_evaluations e \
           JOIN observability_slos d ON d.id = e.slo_id \
          WHERE e.definition_updated_at = d.updated_at \
            AND e.evaluated_at > NOW() - make_interval(secs => $1)",
    )
    .bind(SLO_EVALUATION_FRESH_SECS as f64)
    .fetch_all(pool)
    .await
}

/// An SLO breach alert admitted by [`admit_slo_alert`].
#[derive(Debug, Clone)]
pub struct AdmittedSloAlert {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Raise the `kind:"slo"` breach alert for the evaluation recorded at
/// `evaluated_at` — only if it is STILL the current persisted result.
///
/// One transaction: lock the SLO's state row, require it to still be
/// `(slo_id, evaluated_at, status = 'breaching')` for the definition the
/// evaluation read, apply the durable re-arm check against the newest
/// `kind:"slo"` alert, then insert the alert. A newer result (e.g. a healthy
/// evaluation written by another leader while this one was between its write
/// and its alert) makes this a no-op, so a superseded breach never raises an
/// alert or a webhook. The row lock also serializes two evaluators racing to
/// alert on the same result. `None` = nothing raised.
pub async fn admit_slo_alert(
    pool: &PgPool,
    slo: &SloDefinition,
    evaluated_at: DateTime<Utc>,
    rearm_secs: u64,
    payload: &serde_json::Value,
) -> Result<Option<AdmittedSloAlert>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let current: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM observability_slo_evaluations \
          WHERE slo_id = $1 AND evaluated_at = $2 AND status = 'breaching' \
            AND definition_updated_at = $3 \
          FOR UPDATE",
    )
    .bind(slo.id)
    .bind(evaluated_at)
    .bind(slo.updated_at)
    .fetch_optional(&mut *tx)
    .await?;
    if current.is_none() {
        return Ok(None);
    }
    let source = slo.id.to_string();
    let last: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT max(created_at) FROM alerts WHERE kind = 'slo' AND source_id = $1",
    )
    .bind(&source)
    .fetch_one(&mut *tx)
    .await?;
    if last.is_some_and(|last| super::eval::within_rearm(last, Utc::now(), rearm_secs)) {
        return Ok(None);
    }
    let (id, created_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO alerts (kind, rule_id, source_id, severity, matched_events) \
         VALUES ('slo', NULL, $1, 'high', $2) RETURNING id, created_at",
    )
    .bind(&source)
    .bind(payload)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(AdmittedSloAlert { id, created_at }))
}
