// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection scheduling lag (NAN-3064).
//!
//! A tenant running a couple hundred rules needs to know when the detection
//! scheduler is falling behind, not just that it is running. Lag is measured
//! per active scheduled rule as `now - next_run_at` once the rule is due:
//! `next_run_at` already carries the rule's phase offset (NAN-3063), so a
//! positive lag is time the rule has spent waiting for, or in, its run. A rule
//! whose `next_run_at` is in the future has lag 0.
//!
//! The summary is a pure function over rows so the dedicated handler, the
//! enterprise-shared (lean) handler and the runtimes' health signal all agree.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use uuid::Uuid;

use super::scheduler::schedule_interval;

/// A due rule is "behind schedule" once it has waited longer than this. It
/// absorbs the poll interval (5 s) plus a normal claim/refill turn.
pub const BEHIND_SCHEDULE_GRACE_SECS: i64 = 30;
/// A rule lagging more than this multiple of its own interval has missed at
/// least one whole run: the tenant's detection health is degraded.
pub const DEGRADED_INTERVAL_MULTIPLE: i64 = 2;
/// Worst-lagging rules returned for display.
pub const WORST_RULES_LIMIT: usize = 10;

/// One active scheduled rule as the lag summary needs it.
#[derive(Debug, Clone)]
pub struct ScheduleLagRow {
    pub rule_id: Uuid,
    pub name: String,
    pub schedule_cron: Option<String>,
    /// Lean near-real-time lane: fixed interval, cron ignored.
    pub near_real_time_interval_seconds: Option<i32>,
    pub next_run_at: Option<DateTime<Utc>>,
}

/// A rule that is behind schedule.
#[derive(Debug, Clone, PartialEq, Serialize, utoipa::ToSchema)]
pub struct LaggingRule {
    /// Detection rule ID (TypeID-encoded string)
    pub rule_id: String,
    pub rule_name: String,
    /// Seconds past the rule's scheduled run time.
    pub lag_secs: i64,
    /// The rule's schedule interval in seconds (null when the cron is invalid).
    pub interval_secs: Option<i64>,
    /// `lag_secs > 2 × interval_secs`: the rule has missed at least one run.
    pub over_2x_interval: bool,
}

/// Per-tenant detection scheduling lag.
#[derive(Debug, Clone, PartialEq, Serialize, utoipa::ToSchema)]
pub struct ScheduleLagSummary {
    /// Active scheduled rules measured (Live/Alerting, not archived, with a schedule).
    pub total: i64,
    /// Rules due for more than `behind_grace_secs`.
    pub behind_schedule: i64,
    /// Rules whose lag exceeds twice their own schedule interval.
    pub over_2x_interval: i64,
    /// Largest lag across the fleet, in seconds.
    pub max_lag_secs: i64,
    /// 95th-percentile lag across the fleet (rules not yet due count as 0), in seconds.
    pub p95_lag_secs: i64,
    /// Grace before a due rule counts as behind schedule, in seconds.
    pub behind_grace_secs: i64,
    /// `true` when any rule lags more than twice its interval: the scheduler
    /// cannot keep up and detections are running late.
    pub degraded: bool,
    /// The most-lagging rules (at most 10), worst first.
    pub worst: Vec<LaggingRule>,
    /// When the summary was computed.
    pub measured_at: DateTime<Utc>,
}

/// Interval of one row, if it can be derived.
pub fn row_interval(row: &ScheduleLagRow, now: DateTime<Utc>) -> Option<Duration> {
    if let Some(seconds) = row.near_real_time_interval_seconds {
        return (seconds > 0).then(|| Duration::seconds(i64::from(seconds)));
    }
    row.schedule_cron
        .as_deref()
        .and_then(|cron| schedule_interval(cron, now))
}

/// Summarize `rows` at `now`.
pub fn summarize_schedule_lag(rows: &[ScheduleLagRow], now: DateTime<Utc>) -> ScheduleLagSummary {
    let mut lags: Vec<i64> = Vec::with_capacity(rows.len());
    let mut behind = Vec::new();
    let mut over_2x = 0i64;
    for row in rows {
        let lag = row
            .next_run_at
            .map(|at| (now - at).num_seconds().max(0))
            .unwrap_or(0);
        lags.push(lag);
        if lag <= BEHIND_SCHEDULE_GRACE_SECS {
            continue;
        }
        let interval = row_interval(row, now).map(|d| d.num_seconds());
        let degraded = interval.is_some_and(|secs| lag > secs * DEGRADED_INTERVAL_MULTIPLE);
        if degraded {
            over_2x += 1;
        }
        behind.push(LaggingRule {
            rule_id: crate::typeid::encode("rule", &row.rule_id),
            rule_name: row.name.clone(),
            lag_secs: lag,
            interval_secs: interval,
            over_2x_interval: degraded,
        });
    }
    lags.sort_unstable();
    let p95 = percentile(&lags, 95);
    behind.sort_by(|a, b| b.lag_secs.cmp(&a.lag_secs).then_with(|| a.rule_name.cmp(&b.rule_name)));
    let behind_schedule = behind.len() as i64;
    behind.truncate(WORST_RULES_LIMIT);
    ScheduleLagSummary {
        total: rows.len() as i64,
        behind_schedule,
        over_2x_interval: over_2x,
        max_lag_secs: lags.last().copied().unwrap_or(0),
        p95_lag_secs: p95,
        behind_grace_secs: BEHIND_SCHEDULE_GRACE_SECS,
        degraded: over_2x > 0,
        worst: behind,
        measured_at: now,
    }
}

/// Read the dedicated (single-tenant) schedulable fleet and summarize it.
/// Same fleet as `GET /api/rules/fleet-health`.
pub async fn read_dedicated_schedule_lag(pool: &sqlx::PgPool) -> Result<ScheduleLagSummary, sqlx::Error> {
    let rows: Vec<(Uuid, String, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, name, schedule_cron, next_run_at, NOW() FROM detection_rules \
          WHERE archived = false AND mode IN ('live', 'alerting') \
            AND detection_mode = 'scheduled' AND schedule_cron IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    let now = rows.first().map(|r| r.4).unwrap_or_else(Utc::now);
    let rows: Vec<ScheduleLagRow> = rows
        .into_iter()
        .map(|(rule_id, name, schedule_cron, next_run_at, _)| ScheduleLagRow {
            rule_id,
            name,
            schedule_cron,
            near_real_time_interval_seconds: None,
            next_run_at,
        })
        .collect();
    Ok(summarize_schedule_lag(&rows, now))
}

/// Nearest-rank percentile of an ascending slice.
fn percentile(sorted: &[i64], pct: usize) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct * sorted.len()).div_ceil(100).max(1);
    sorted[rank.min(sorted.len()) - 1]
}

/// Emit the lag summary as Prometheus gauges and WARN when degraded.
/// `tenant` labels the lean (per-tenant) runtime; the dedicated scheduler
/// passes `None`.
pub fn record_schedule_lag(summary: &ScheduleLagSummary, tenant: Option<Uuid>) {
    let tenant_label = tenant.map(|t| t.to_string()).unwrap_or_else(|| "dedicated".into());
    // NAN-4031: identify the rule behind a max-lag page. Clear the previous
    // labelled series when the worst rule changes (or recovers), so a stale
    // failure cannot remain the maximum forever. Existing consumers can
    // continue aggregating the same metric name by tenant.
    static WORST_GAUGES: OnceLock<Mutex<HashMap<String, metrics::Gauge>>> = OnceLock::new();
    let mut previous = WORST_GAUGES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(gauge) = previous.remove(&tenant_label) {
        gauge.set(0.0);
    }
    let rule_id = summary.worst.first().map(|rule| rule.rule_id.clone()).unwrap_or_default();
    let gauge = metrics::gauge!("nanosiem_detection_schedule_lag_max_seconds",
        "tenant" => tenant_label.clone(), "rule_id" => rule_id);
    gauge.set(summary.max_lag_secs as f64);
    previous.insert(tenant_label.clone(), gauge);
    drop(previous);
    metrics::gauge!("nanosiem_detection_schedule_lag_p95_seconds", "tenant" => tenant_label.clone())
        .set(summary.p95_lag_secs as f64);
    metrics::gauge!("nanosiem_detection_rules_behind_schedule", "tenant" => tenant_label.clone())
        .set(summary.behind_schedule as f64);
    metrics::gauge!("nanosiem_detection_rules_lagging_over_2x_interval", "tenant" => tenant_label.clone())
        .set(summary.over_2x_interval as f64);
    metrics::gauge!("nanosiem_detection_schedule_degraded", "tenant" => tenant_label)
        .set(if summary.degraded { 1.0 } else { 0.0 });
    if summary.degraded {
        let worst = summary.worst.first();
        tracing::warn!(
            tenant_id = ?tenant,
            rules = summary.total,
            behind_schedule = summary.behind_schedule,
            over_2x_interval = summary.over_2x_interval,
            max_lag_secs = summary.max_lag_secs,
            p95_lag_secs = summary.p95_lag_secs,
            worst_rule = worst.map(|r| r.rule_name.as_str()).unwrap_or(""),
            worst_interval_secs = worst.and_then(|r| r.interval_secs).unwrap_or(0),
            "detection scheduling degraded: rules are lagging more than twice their interval"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn row(n: u128, cron: &str, next: &str) -> ScheduleLagRow {
        ScheduleLagRow {
            rule_id: Uuid::from_u128(n),
            name: format!("rule-{n}"),
            schedule_cron: Some(cron.into()),
            near_real_time_interval_seconds: None,
            next_run_at: Some(t(next)),
        }
    }

    #[test]
    fn empty_fleet_is_healthy() {
        let s = summarize_schedule_lag(&[], t("2026-07-05T12:00:00Z"));
        assert_eq!((s.total, s.behind_schedule, s.max_lag_secs, s.p95_lag_secs, s.degraded), (0, 0, 0, 0, false));
    }

    #[test]
    fn future_and_just_due_rules_are_on_schedule() {
        let now = t("2026-07-05T12:00:00Z");
        let rows = vec![row(1, "*/5 * * * *", "2026-07-05T12:03:00Z"), row(2, "*/1 * * * *", "2026-07-05T11:59:40Z")];
        let s = summarize_schedule_lag(&rows, now);
        assert_eq!(s.behind_schedule, 0);
        assert_eq!(s.max_lag_secs, 20);
        assert!(!s.degraded);
        assert!(s.worst.is_empty());
    }

    #[test]
    fn lag_beyond_twice_the_interval_is_degraded() {
        let now = t("2026-07-05T12:00:00Z");
        let rows = vec![
            // */1 rule 3 min late: > 2 × 60 s.
            row(1, "*/1 * * * *", "2026-07-05T11:57:00Z"),
            // */5 rule 3 min late: behind, but < 2 × 300 s.
            row(2, "*/5 * * * *", "2026-07-05T11:57:00Z"),
            row(3, "*/5 * * * *", "2026-07-05T12:04:00Z"),
        ];
        let s = summarize_schedule_lag(&rows, now);
        assert_eq!(s.behind_schedule, 2);
        assert_eq!(s.over_2x_interval, 1);
        assert!(s.degraded);
        assert_eq!(s.max_lag_secs, 180);
        assert_eq!(s.worst.len(), 2);
        assert!(s.worst.iter().any(|r| r.over_2x_interval && r.interval_secs == Some(60)));
        assert!(s.worst.iter().any(|r| !r.over_2x_interval && r.interval_secs == Some(300)));
    }

    #[test]
    fn near_real_time_rows_use_their_fixed_interval() {
        let now = t("2026-07-05T12:00:00Z");
        let mut r = row(1, "* * * * *", "2026-07-05T11:58:59Z");
        r.near_real_time_interval_seconds = Some(30);
        let s = summarize_schedule_lag(&[r], now);
        assert_eq!(s.worst[0].interval_secs, Some(30));
        assert!(s.degraded);
    }

    #[test]
    fn p95_counts_on_time_rules_as_zero_and_worst_is_bounded() {
        let now = t("2026-07-05T12:00:00Z");
        let mut rows: Vec<ScheduleLagRow> = (0..190).map(|i| row(i, "*/5 * * * *", "2026-07-05T12:02:00Z")).collect();
        // 10 rules, 40..=400 s late.
        for i in 0..10u128 {
            let next = now - Duration::seconds(40 * (i as i64 + 1));
            rows.push(ScheduleLagRow { next_run_at: Some(next), ..row(1000 + i, "*/5 * * * *", "2026-07-05T12:00:00Z") });
        }
        let s = summarize_schedule_lag(&rows, now);
        assert_eq!(s.total, 200);
        assert_eq!(s.behind_schedule, 10);
        assert_eq!(s.max_lag_secs, 400);
        // Rank 190 of 200 is still an on-time rule.
        assert_eq!(s.p95_lag_secs, 0);
        assert_eq!(s.worst.len(), WORST_RULES_LIMIT);
        assert_eq!(s.worst[0].lag_secs, 400);
        assert_eq!(s.over_2x_interval, 0, "400 s < 2 × 300 s");
        assert!(!s.degraded);
    }

    #[test]
    fn percentile_is_nearest_rank() {
        assert_eq!(percentile(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95), 10);
        assert_eq!(percentile(&[5], 95), 5);
        assert_eq!(percentile(&(1..=100).collect::<Vec<_>>(), 95), 95);
    }
}
