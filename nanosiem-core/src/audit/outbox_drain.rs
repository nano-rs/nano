// SPDX-License-Identifier: AGPL-3.0-or-later

//! Retrying delivery of security-critical audit events from the PostgreSQL
//! outbox (`security_audit_events`) into ClickHouse (NAN-4954).
//!
//! Runs on every jobs node. Rows are claimed with `FOR UPDATE SKIP LOCKED`, so
//! replicas share the work without double delivery. Before re-inserting, the
//! drainer checks ClickHouse for the UDM row's content-derived id and for the
//! OCSF mirror row's id (= `event_id`), so a write that landed but whose
//! delivery stamp was lost is never duplicated in either table.
//!
//! The drainer also owns the operator signal: while any event is past its
//! inline window and still undelivered, it keeps a `system_health_events`
//! condition active (critical once the oldest event is 15 minutes old) and
//! resolves it when the backlog clears.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::emitter::udm_row_id;
use super::outbox::{AuditOutboxStats, SecurityAuditOutbox};
use super::{AuditEmitter, AuditEvent};
use crate::shutdown::ShutdownToken;
use crate::system_health::{
    HealthCategory, HealthSeverity, PublishHealthEvent, SystemHealthRepository,
};

/// Stable dedup key of the backlog health condition.
pub const BACKLOG_HEALTH_DEDUP_KEY: &str = "audit:security_events:clickhouse_delivery_backlog";

/// Oldest-pending age at which the backlog condition escalates to critical.
const CRITICAL_BACKLOG_AGE_SECS: i64 = 15 * 60;

/// Re-publish an unchanged active condition at most this often (each publish
/// bumps the lifecycle's occurrence counter).
const HEALTH_REPUBLISH_INTERVAL: Duration = Duration::from_secs(300);

/// Most batches drained per tick, so one tick stays bounded.
const MAX_BATCHES_PER_TICK: usize = 20;

/// Result of one [`AuditOutboxDrainer::drain_once`] pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Rows claimed in this pass.
    pub claimed: usize,
    /// Rows fully delivered (closed out) in this pass.
    pub delivered: u64,
    /// UDM rows found already present in ClickHouse and not re-inserted.
    pub already_present: usize,
    /// OCSF mirror rows found already present and not re-inserted.
    pub already_present_ocsf: usize,
    /// Rows that failed and were rescheduled.
    pub failed: usize,
    /// The ClickHouse error that rescheduled them.
    pub error: Option<String>,
}

#[derive(Default)]
struct HealthState {
    active: bool,
    severity: Option<HealthSeverity>,
    last_published: Option<std::time::Instant>,
}

/// Drains the security-critical audit outbox into ClickHouse.
pub struct AuditOutboxDrainer {
    emitter: Arc<AuditEmitter>,
    outbox: SecurityAuditOutbox,
    health: SystemHealthRepository,
    batch_size: i64,
    interval: Duration,
    health_state: Mutex<HealthState>,
}

impl AuditOutboxDrainer {
    pub fn new(emitter: Arc<AuditEmitter>, pool: PgPool) -> Self {
        Self {
            outbox: emitter.outbox().clone(),
            emitter,
            health: SystemHealthRepository::new(pool),
            batch_size: 200,
            interval: Duration::from_secs(10),
            health_state: Mutex::new(HealthState::default()),
        }
    }

    pub fn with_batch_size(mut self, batch_size: i64) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Claim one batch of due rows and try to deliver it. Everything happens in
    /// one transaction: the row locks hold until the delivery stamps (or the
    /// retry schedule) commit.
    pub async fn drain_once(&self) -> Result<DrainOutcome, sqlx::Error> {
        let mut tx = self.outbox.pool().begin().await?;
        let claimed = SecurityAuditOutbox::claim_due(&mut tx, self.batch_size).await?;
        let mut outcome = DrainOutcome {
            claimed: claimed.len(),
            ..Default::default()
        };
        if claimed.is_empty() {
            tx.commit().await?;
            return Ok(outcome);
        }
        let all_ids: Vec<Uuid> = claimed.iter().map(|p| p.event_id).collect();
        let ocsf_required = self.emitter.mirrors_ocsf();

        // UDM half.
        let need_udm: Vec<&super::outbox::PendingAuditEvent> =
            claimed.iter().filter(|p| !p.udm_delivered).collect();
        if !need_udm.is_empty() {
            let events: Vec<AuditEvent> = need_udm.iter().map(|p| p.event.clone()).collect();
            let present = match self.emitter.existing_udm_ids(&events).await {
                Ok(present) => present,
                Err(e) => {
                    return self.reschedule(tx, &all_ids, e.to_string(), outcome).await;
                }
            };
            let to_insert: Vec<AuditEvent> = events
                .iter()
                .filter(|e| !present.contains(&udm_row_id(e)))
                .cloned()
                .collect();
            outcome.already_present = events.len() - to_insert.len();
            if !to_insert.is_empty() {
                if let Err(e) = self.emitter.deliver_udm(&to_insert).await {
                    return self.reschedule(tx, &all_ids, e.to_string(), outcome).await;
                }
            }
            let ids: Vec<Uuid> = need_udm.iter().map(|p| p.event_id).collect();
            SecurityAuditOutbox::mark_udm_delivered(&mut tx, &ids).await?;
        }

        // OCSF mirror half.
        if ocsf_required {
            let need_ocsf: Vec<&super::outbox::PendingAuditEvent> =
                claimed.iter().filter(|p| !p.ocsf_delivered).collect();
            if !need_ocsf.is_empty() {
                let events: Vec<AuditEvent> = need_ocsf.iter().map(|p| p.event.clone()).collect();
                let ids: Vec<Uuid> = need_ocsf.iter().map(|p| p.event_id).collect();
                // Skip mirrors that already landed (their row id is the
                // event_id), so an ambiguous earlier delivery never yields a
                // second OCSF event.
                let present = match self.emitter.existing_ocsf_ids(&events).await {
                    Ok(present) => present,
                    Err(e) => {
                        let error = e.to_string();
                        SecurityAuditOutbox::record_retry(&mut tx, &ids, &error).await?;
                        outcome.failed = ids.len();
                        outcome.error = Some(error);
                        outcome.delivered =
                            SecurityAuditOutbox::finalize_delivered(&mut tx, &all_ids, ocsf_required)
                                .await?;
                        tx.commit().await?;
                        return Ok(outcome);
                    }
                };
                let to_insert: Vec<AuditEvent> = events
                    .iter()
                    .filter(|e| !present.contains(&e.event_id))
                    .cloned()
                    .collect();
                outcome.already_present_ocsf = events.len() - to_insert.len();
                let result = if to_insert.is_empty() {
                    Ok(())
                } else {
                    self.emitter.deliver_ocsf(&to_insert).await
                };
                match result {
                    Ok(()) => SecurityAuditOutbox::mark_ocsf_delivered(&mut tx, &ids).await?,
                    Err(e) => {
                        // The UDM stamps above still commit; only the mirror
                        // half is retried.
                        let error = e.to_string();
                        SecurityAuditOutbox::record_retry(&mut tx, &ids, &error).await?;
                        outcome.failed = ids.len();
                        outcome.error = Some(error);
                    }
                }
            }
        }

        outcome.delivered =
            SecurityAuditOutbox::finalize_delivered(&mut tx, &all_ids, ocsf_required).await?;
        tx.commit().await?;
        if outcome.delivered > 0 {
            tracing::info!(
                delivered = outcome.delivered,
                already_present = outcome.already_present,
                "Delivered deferred security-critical audit events to ClickHouse"
            );
            metrics::counter!("nanosiem_audit_outbox_delivered_total").increment(outcome.delivered);
        }
        Ok(outcome)
    }

    async fn reschedule(
        &self,
        mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
        ids: &[Uuid],
        error: String,
        mut outcome: DrainOutcome,
    ) -> Result<DrainOutcome, sqlx::Error> {
        SecurityAuditOutbox::record_retry(&mut tx, ids, &error).await?;
        tx.commit().await?;
        tracing::warn!(
            rows = ids.len(),
            error = %error,
            "Security-critical audit events still undeliverable to ClickHouse; retry scheduled"
        );
        outcome.failed = ids.len();
        outcome.error = Some(error);
        Ok(outcome)
    }

    /// One scheduler tick: drain until empty, a failure, or the per-tick batch
    /// cap; then refresh the health condition. Returns the post-tick stats.
    pub async fn tick(&self) -> Result<AuditOutboxStats, sqlx::Error> {
        for _ in 0..MAX_BATCHES_PER_TICK {
            let outcome = self.drain_once().await?;
            if outcome.claimed == 0 || outcome.failed > 0 {
                break;
            }
        }
        let stats = self.outbox.stats().await?;
        self.refresh_health(&stats).await;
        Ok(stats)
    }

    /// Publish, escalate, or resolve the backlog health condition.
    pub async fn refresh_health(&self, stats: &AuditOutboxStats) {
        let mut state = self.health_state.lock().await;
        if !stats.is_backlogged() {
            // Resolve once per transition (and once after process start, when
            // a previous process may have left the condition active).
            if state.active || state.last_published.is_none() {
                match self.health.resolve_by_dedup_key(BACKLOG_HEALTH_DEDUP_KEY).await {
                    Ok(_) => {
                        state.active = false;
                        state.severity = None;
                        state.last_published = Some(std::time::Instant::now());
                    }
                    Err(e) => tracing::warn!(error = %e, "Failed to resolve the audit outbox health event"),
                }
            }
            return;
        }

        let severity = if stats.oldest_pending_age_secs.unwrap_or(0) >= CRITICAL_BACKLOG_AGE_SECS {
            HealthSeverity::Critical
        } else {
            HealthSeverity::High
        };
        let due = !state.active
            || state.severity != Some(severity)
            || state
                .last_published
                .map(|t| t.elapsed() >= HEALTH_REPUBLISH_INTERVAL)
                .unwrap_or(true);
        if !due {
            return;
        }
        let event = backlog_health_event(stats, severity);
        match self.health.publish(&event).await {
            Ok(_) => {
                state.active = true;
                state.severity = Some(severity);
                state.last_published = Some(std::time::Instant::now());
            }
            Err(e) => tracing::warn!(error = %e, "Failed to publish the audit outbox health event"),
        }
    }

    /// Run until shutdown: a tick every `interval`, plus an hourly prune of
    /// delivered rows past retention.
    pub fn start(self: Arc<Self>, shutdown: ShutdownToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut last_prune = std::time::Instant::now() - Duration::from_secs(3600);
            loop {
                if let Err(e) = self.tick().await {
                    tracing::warn!(error = %e, "Audit outbox drain tick failed");
                }
                if last_prune.elapsed() >= Duration::from_secs(3600) {
                    match self.outbox.prune_delivered().await {
                        Ok(n) if n > 0 => tracing::info!(rows = n, "Pruned delivered security audit outbox rows past retention"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "Audit outbox prune failed"),
                    }
                    last_prune = std::time::Instant::now();
                }
                if shutdown
                    .run_until_cancelled(tokio::time::sleep(self.interval))
                    .await
                    .is_none()
                {
                    break;
                }
            }
        })
    }
}

/// The `system_health_events` condition for an undelivered backlog.
pub fn backlog_health_event(stats: &AuditOutboxStats, severity: HealthSeverity) -> PublishHealthEvent {
    let age_min = stats.oldest_pending_age_secs.unwrap_or(0) / 60;
    let mut event = PublishHealthEvent::new(
        BACKLOG_HEALTH_DEDUP_KEY,
        HealthCategory::Storage,
        severity,
        "Security audit events are not reaching ClickHouse",
        format!(
            "{} security-critical audit event(s) are recorded in PostgreSQL but not yet in \
             ClickHouse (oldest {} min). They are safe and will be delivered automatically; \
             until then audit search and the audit page are missing them. Last ClickHouse \
             error: {}",
            stats.overdue,
            age_min,
            stats.last_error.as_deref().unwrap_or("none recorded"),
        ),
        "audit_outbox",
        "audit_outbox_drainer",
    );
    event.resource_name = Some("security_audit_events".to_string());
    event.diagnostic_context = serde_json::to_value(stats).unwrap_or_default();
    event.remediation = Some(
        "Check ClickHouse health (memory limit / MEMORY_LIMIT_EXCEEDED, disk, availability). \
         Delivery resumes on its own once ClickHouse accepts inserts."
            .to_string(),
    );
    event
}
