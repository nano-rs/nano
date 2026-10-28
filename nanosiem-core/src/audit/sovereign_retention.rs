//! NAN-4722: platform audit retention on a sovereign install.
//!
//! Hosted prunes `platform_audit_events` past 400 days from
//! `nano_shared.run_stamping_retention` (the control plane's stamping GC
//! loop). Single-host never runs that loop, so nano-jobs calls the same
//! purge definer, `nano_shared.prune_platform_audit_events`, directly. Only
//! the jobs login (`nano_product_runtime`) may execute it
//! (`scripts/sovereign/sql/single-host-grants.sql`). The definer owns the
//! 400-day cutoff, the batch bound and the guard marker; this side only
//! loops while a batch comes back full.

use serde_json::Value;
use sqlx::PgPool;
use std::time::Duration;

/// Rows per call. The definer refuses anything outside 1..=10000.
pub const BATCH: i32 = 5_000;
/// Full batches per pass before yielding to the next tick.
pub const MAX_BATCHES_PER_PASS: u32 = 20;
/// Pass interval. Retention is in days, so hourly is plenty.
pub const INTERVAL: Duration = Duration::from_secs(3_600);

#[derive(Debug, thiserror::Error)]
pub enum AuditRetentionError {
    #[error("platform audit retention query failed: {0}")]
    Query(#[from] sqlx::Error),
    #[error("platform audit retention reported {0}")]
    Reported(String),
    #[error("platform audit retention returned an unexpected report: {0}")]
    Report(Value),
}

/// Whether the purge definer exists (enterprise overlay 9015670).
pub async fn available(pool: &PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT to_regprocedure('nano_shared.prune_platform_audit_events(boolean,integer)') IS NOT NULL",
    )
    .fetch_one(pool)
    .await
}

/// Parse one definer report: rows pruned, or the SQLSTATE it swallowed.
pub fn pruned_from_report(report: &Value) -> Result<u64, AuditRetentionError> {
    if let Some(code) = report
        .get("platform_audit_events_gc_error")
        .and_then(Value::as_str)
    {
        return Err(AuditRetentionError::Reported(format!("SQLSTATE {code}")));
    }
    report
        .get("platform_audit_events_pruned")
        .and_then(Value::as_u64)
        .ok_or_else(|| AuditRetentionError::Report(report.clone()))
}

/// One pass: prune full batches until a short batch (or the per-pass cap).
pub async fn prune_pass(pool: &PgPool) -> Result<u64, AuditRetentionError> {
    let mut total = 0u64;
    for _ in 0..MAX_BATCHES_PER_PASS {
        let report: Value =
            sqlx::query_scalar("SELECT nano_shared.prune_platform_audit_events(false, $1)")
                .bind(BATCH)
                .fetch_one(pool)
                .await?;
        let pruned = pruned_from_report(&report)?;
        total += pruned;
        if pruned < BATCH as u64 {
            break;
        }
    }
    Ok(total)
}

/// Delay before the first pass, so boot is not slowed and a restarting
/// jobs process still prunes.
pub const FIRST_PASS_DELAY: Duration = Duration::from_secs(300);

/// The nano-jobs loop: first pass after [`FIRST_PASS_DELAY`], then hourly.
pub async fn run(pool: PgPool) {
    tokio::time::sleep(FIRST_PASS_DELAY).await;
    let mut interval = tokio::time::interval(INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        match prune_pass(&pool).await {
            Ok(0) => {}
            Ok(pruned) => {
                tracing::info!(pruned, "platform audit retention pruned rows past 400 days")
            }
            Err(error) => tracing::warn!(%error, "platform audit retention pass failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn report_parsing() {
        assert_eq!(
            pruned_from_report(&json!({"platform_audit_events_pruned": 7})).unwrap(),
            7
        );
        assert!(matches!(
            pruned_from_report(&json!({"platform_audit_events_pruned": 0, "platform_audit_events_gc_error": "42501"})),
            Err(AuditRetentionError::Reported(code)) if code.contains("42501")
        ));
        assert!(matches!(
            pruned_from_report(&json!({"platform_audit_events_due": 3})),
            Err(AuditRetentionError::Report(_))
        ));
    }
}
