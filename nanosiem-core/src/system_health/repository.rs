// SPDX-License-Identifier: AGPL-3.0-or-later

use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use super::types::{
    ClaimedHealthDelivery, HealthBusSummary, HealthDelivery, PublishHealthEvent, SystemHealthEvent,
    DEFAULT_TENANT_ID, SYSTEM_HEALTH_EVENT_TYPE,
};

const MAX_DELIVERY_ATTEMPTS: i32 = 8;

#[derive(Debug, Error)]
pub enum SystemHealthError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("system health event not found: {0}")]
    NotFound(Uuid),
    #[error("invalid health event: {0}")]
    Invalid(String),
}

#[derive(Clone)]
pub struct SystemHealthRepository {
    pool: PgPool,
}

impl SystemHealthRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }

    /// Publish or group an active condition. Only the first occurrence creates
    /// outbound work; subsequent identical failures increment the lifecycle's
    /// counter without producing a per-run alert storm.
    pub async fn publish(
        &self,
        event: &PublishHealthEvent,
    ) -> Result<SystemHealthEvent, SystemHealthError> {
        validate_publish(event)?;
        let mut tx = self.pool.begin().await?;

        // Serialize publishers for one logical condition before checking the
        // partial unique index. Without this lock, two scheduler/task replicas
        // can both observe no active row and one loses to a unique violation
        // instead of cleanly joining the same lifecycle.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, hashtextextended($2, 0)))")
            .bind(&event.tenant_id)
            .bind(&event.dedup_key)
            .fetch_one(&mut *tx)
            .await?;

        let existing = sqlx::query_as::<_, SystemHealthEvent>(
            r#"
            SELECT id, tenant_id, dedup_key, category, severity, status, title, summary,
                   resource_type, resource_id, resource_name, diagnostic_context,
                   remediation, source, occurrence_count, first_seen_at, last_seen_at,
                   last_notified_at, acknowledged_at, acknowledged_by, resolved_at,
                   created_at, updated_at
            FROM system_health_events
            WHERE tenant_id = $1 AND dedup_key = $2 AND status = 'active'
            FOR UPDATE
            "#,
        )
        .bind(&event.tenant_id)
        .bind(&event.dedup_key)
        .fetch_optional(&mut *tx)
        .await?;

        let (stored, first_occurrence, severity_escalated) = if let Some(existing) = existing {
            let severity_escalated =
                severity_rank(event.severity.as_str()) < severity_rank(&existing.severity);
            let updated = sqlx::query_as::<_, SystemHealthEvent>(
                r#"
                UPDATE system_health_events
                SET category = $2, severity = $3, title = $4, summary = $5,
                    resource_type = $6, resource_id = $7, resource_name = $8,
                    diagnostic_context = $9, remediation = $10, source = $11,
                    occurrence_count = occurrence_count + 1,
                    last_seen_at = NOW(), updated_at = NOW()
                WHERE id = $1
                RETURNING id, tenant_id, dedup_key, category, severity, status, title, summary,
                          resource_type, resource_id, resource_name, diagnostic_context,
                          remediation, source, occurrence_count, first_seen_at, last_seen_at,
                          last_notified_at, acknowledged_at, acknowledged_by, resolved_at,
                          created_at, updated_at
                "#,
            )
            .bind(existing.id)
            .bind(event.category.as_str())
            .bind(event.severity.as_str())
            .bind(&event.title)
            .bind(&event.summary)
            .bind(&event.resource_type)
            .bind(&event.resource_id)
            .bind(&event.resource_name)
            .bind(&event.diagnostic_context)
            .bind(&event.remediation)
            .bind(&event.source)
            .fetch_one(&mut *tx)
            .await?;
            (updated, false, severity_escalated)
        } else {
            let inserted = sqlx::query_as::<_, SystemHealthEvent>(
                r#"
                INSERT INTO system_health_events (
                    tenant_id, dedup_key, category, severity, title, summary,
                    resource_type, resource_id, resource_name, diagnostic_context,
                    remediation, source
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                RETURNING id, tenant_id, dedup_key, category, severity, status, title, summary,
                          resource_type, resource_id, resource_name, diagnostic_context,
                          remediation, source, occurrence_count, first_seen_at, last_seen_at,
                          last_notified_at, acknowledged_at, acknowledged_by, resolved_at,
                          created_at, updated_at
                "#,
            )
            .bind(&event.tenant_id)
            .bind(&event.dedup_key)
            .bind(event.category.as_str())
            .bind(event.severity.as_str())
            .bind(&event.title)
            .bind(&event.summary)
            .bind(&event.resource_type)
            .bind(&event.resource_id)
            .bind(&event.resource_name)
            .bind(&event.diagnostic_context)
            .bind(&event.remediation)
            .bind(&event.source)
            .fetch_one(&mut *tx)
            .await?;
            (inserted, true, false)
        };

        if first_occurrence {
            enqueue_matching_destinations(&mut tx, &stored, "triggered").await?;
        } else if severity_escalated {
            // Update existing PagerDuty incidents and other owner channels when
            // a grouped condition becomes materially more urgent. One reminder
            // per lifecycle keeps the escalation idempotent and storm-free.
            enqueue_matching_destinations(&mut tx, &stored, "reminder").await?;
        }
        tx.commit().await?;
        Ok(stored)
    }

    pub async fn resolve_by_dedup_key(
        &self,
        dedup_key: &str,
    ) -> Result<Option<SystemHealthEvent>, SystemHealthError> {
        self.resolve_active(DEFAULT_TENANT_ID, Some(dedup_key), None)
            .await
    }

    pub async fn resolve_by_id(&self, id: Uuid) -> Result<SystemHealthEvent, SystemHealthError> {
        self.resolve_active(DEFAULT_TENANT_ID, None, Some(id))
            .await?
            .ok_or(SystemHealthError::NotFound(id))
    }

    async fn resolve_active(
        &self,
        tenant_id: &str,
        dedup_key: Option<&str>,
        id: Option<Uuid>,
    ) -> Result<Option<SystemHealthEvent>, SystemHealthError> {
        let mut tx = self.pool.begin().await?;
        let event = sqlx::query_as::<_, SystemHealthEvent>(
            r#"
            UPDATE system_health_events
            SET status = 'resolved', resolved_at = NOW(), last_seen_at = NOW(), updated_at = NOW()
            WHERE tenant_id = $1 AND status = 'active'
              AND ($2::text IS NULL OR dedup_key = $2)
              AND ($3::uuid IS NULL OR id = $3)
            RETURNING id, tenant_id, dedup_key, category, severity, status, title, summary,
                      resource_type, resource_id, resource_name, diagnostic_context,
                      remediation, source, occurrence_count, first_seen_at, last_seen_at,
                      last_notified_at, acknowledged_at, acknowledged_by, resolved_at,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(dedup_key)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(ref event) = event {
            enqueue_matching_destinations(&mut tx, event, "resolved").await?;
        }
        tx.commit().await?;
        Ok(event)
    }

    pub async fn acknowledge(
        &self,
        id: Uuid,
        actor_id: Uuid,
    ) -> Result<SystemHealthEvent, SystemHealthError> {
        sqlx::query_as::<_, SystemHealthEvent>(
            r#"
            UPDATE system_health_events
            SET acknowledged_at = COALESCE(acknowledged_at, NOW()),
                acknowledged_by = COALESCE(acknowledged_by, $3), updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, dedup_key, category, severity, status, title, summary,
                      resource_type, resource_id, resource_name, diagnostic_context,
                      remediation, source, occurrence_count, first_seen_at, last_seen_at,
                      last_notified_at, acknowledged_at, acknowledged_by, resolved_at,
                      created_at, updated_at
            "#,
        )
        .bind(DEFAULT_TENANT_ID)
        .bind(id)
        .bind(actor_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SystemHealthError::NotFound(id))
    }

    pub async fn get(&self, id: Uuid) -> Result<SystemHealthEvent, SystemHealthError> {
        sqlx::query_as::<_, SystemHealthEvent>(
            r#"
            SELECT id, tenant_id, dedup_key, category, severity, status, title, summary,
                   resource_type, resource_id, resource_name, diagnostic_context,
                   remediation, source, occurrence_count, first_seen_at, last_seen_at,
                   last_notified_at, acknowledged_at, acknowledged_by, resolved_at,
                   created_at, updated_at
            FROM system_health_events WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(DEFAULT_TENANT_ID)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SystemHealthError::NotFound(id))
    }

    pub async fn list(
        &self,
        status: Option<&str>,
        category: Option<&str>,
        severity: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<SystemHealthEvent>, i64), SystemHealthError> {
        let limit = limit.clamp(1, 200);
        let offset = offset.max(0);
        let events = sqlx::query_as::<_, SystemHealthEvent>(
            r#"
            SELECT id, tenant_id, dedup_key, category, severity, status, title, summary,
                   resource_type, resource_id, resource_name, diagnostic_context,
                   remediation, source, occurrence_count, first_seen_at, last_seen_at,
                   last_notified_at, acknowledged_at, acknowledged_by, resolved_at,
                   created_at, updated_at
            FROM system_health_events
            WHERE tenant_id = $1
              AND ($2::text IS NULL OR status = $2)
              AND ($3::text IS NULL OR category = $3)
              AND ($4::text IS NULL OR severity = $4)
            ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,
                     CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                         WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                     last_seen_at DESC
            LIMIT $5 OFFSET $6
            "#,
        )
        .bind(DEFAULT_TENANT_ID)
        .bind(status)
        .bind(category)
        .bind(severity)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM system_health_events
            WHERE tenant_id = $1
              AND ($2::text IS NULL OR status = $2)
              AND ($3::text IS NULL OR category = $3)
              AND ($4::text IS NULL OR severity = $4)
            "#,
        )
        .bind(DEFAULT_TENANT_ID)
        .bind(status)
        .bind(category)
        .bind(severity)
        .fetch_one(&self.pool)
        .await?;
        Ok((events, total))
    }

    pub async fn summary(&self) -> Result<HealthBusSummary, SystemHealthError> {
        let row: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
              COUNT(*) FILTER (WHERE status = 'active'),
              COUNT(*) FILTER (WHERE status = 'active' AND acknowledged_at IS NULL),
              COUNT(*) FILTER (WHERE status = 'active' AND severity = 'critical'),
              COUNT(*) FILTER (WHERE status = 'active' AND severity = 'high'),
              (SELECT COUNT(*) FROM system_health_outbox
                 WHERE tenant_id = $1 AND status IN ('pending','retry','delivering')),
              (SELECT COUNT(*) FROM system_health_outbox
                 WHERE tenant_id = $1 AND status = 'dead')
            FROM system_health_events WHERE tenant_id = $1
            "#,
        )
        .bind(DEFAULT_TENANT_ID)
        .fetch_one(&self.pool)
        .await?;
        Ok(HealthBusSummary {
            active: row.0,
            unacknowledged: row.1,
            critical: row.2,
            high: row.3,
            delivery_pending: row.4,
            delivery_dead: row.5,
        })
    }

    pub async fn list_deliveries(
        &self,
        event_id: Uuid,
        limit: i64,
    ) -> Result<Vec<HealthDelivery>, SystemHealthError> {
        Ok(sqlx::query_as::<_, HealthDelivery>(
            r#"
            SELECT o.id, o.event_id, o.webhook_id, w.name AS webhook_name,
                   o.event_action, o.status, o.attempt_count, o.next_attempt_at,
                   o.delivered_at, o.last_status_code, o.last_error,
                   o.created_at, o.updated_at
            FROM system_health_outbox o
            JOIN webhooks w ON w.id = o.webhook_id
            JOIN system_health_events e ON e.id = o.event_id AND e.tenant_id = o.tenant_id
            WHERE o.tenant_id = $1 AND o.event_id = $2
            ORDER BY o.created_at DESC LIMIT $3
            "#,
        )
        .bind(DEFAULT_TENANT_ID)
        .bind(event_id)
        .bind(limit.clamp(1, 200))
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn claim_delivery(
        &self,
        worker_id: &str,
    ) -> Result<Option<ClaimedHealthDelivery>, SystemHealthError> {
        Ok(sqlx::query_as::<_, ClaimedHealthDelivery>(
            r#"
            WITH candidate AS (
                SELECT candidate.id FROM system_health_outbox candidate
                WHERE candidate.tenant_id = $1
                  AND candidate.next_attempt_at <= NOW()
                  AND (candidate.status IN ('pending','retry')
                       OR (candidate.status = 'delivering'
                           AND candidate.locked_at < NOW() - INTERVAL '5 minutes'))
                  -- Preserve lifecycle order for a destination. In particular,
                  -- a recovery can never overtake a trigger that is retrying or
                  -- currently held by another dispatcher replica.
                  AND NOT EXISTS (
                      SELECT 1 FROM system_health_outbox predecessor
                      WHERE predecessor.tenant_id = candidate.tenant_id
                        AND predecessor.event_id = candidate.event_id
                        AND predecessor.webhook_id = candidate.webhook_id
                        AND CASE predecessor.event_action
                              WHEN 'triggered' THEN 0 WHEN 'reminder' THEN 1 ELSE 2 END
                            < CASE candidate.event_action
                                WHEN 'triggered' THEN 0 WHEN 'reminder' THEN 1 ELSE 2 END
                        AND predecessor.status NOT IN ('delivered', 'dead')
                  )
                ORDER BY candidate.next_attempt_at, candidate.created_at
                FOR UPDATE SKIP LOCKED LIMIT 1
            )
            UPDATE system_health_outbox o
            SET status = 'delivering', locked_at = NOW(), locked_by = $2,
                attempt_count = attempt_count + 1, updated_at = NOW()
            FROM candidate c WHERE o.id = c.id
            RETURNING o.id, o.event_id, o.webhook_id, o.event_action, o.attempt_count
            "#,
        )
        .bind(DEFAULT_TENANT_ID)
        .bind(worker_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn finish_delivery(
        &self,
        delivery: &ClaimedHealthDelivery,
        success: bool,
        status_code: Option<i32>,
        error: Option<&str>,
    ) -> Result<(), SystemHealthError> {
        let terminal = !success && delivery.attempt_count >= MAX_DELIVERY_ATTEMPTS;
        let next_delay_seconds = 1_i64 << delivery.attempt_count.min(10);
        let mut tx = self.pool.begin().await?;
        let finished = sqlx::query_as::<_, (Uuid, String)>(
            r#"
            UPDATE system_health_outbox
            SET status = CASE WHEN $2 THEN 'delivered'
                              WHEN $3 THEN 'dead' ELSE 'retry' END,
                delivered_at = CASE WHEN $2 THEN NOW() ELSE delivered_at END,
                next_attempt_at = CASE WHEN $2 OR $3 THEN next_attempt_at
                                       ELSE NOW() + ($4 * INTERVAL '1 second') END,
                last_status_code = $5, last_error = $6,
                locked_at = NULL, locked_by = NULL, updated_at = NOW()
            WHERE id = $1 AND status = 'delivering'
            RETURNING event_id, event_action
            "#,
        )
        .bind(delivery.id)
        .bind(success)
        .bind(terminal)
        .bind(next_delay_seconds)
        .bind(status_code)
        .bind(error.map(|e| truncate(e, 2000)))
        .fetch_optional(&mut *tx)
        .await?;
        if success {
            if let Some((event_id, _event_action)) = finished {
                sqlx::query(
                    "UPDATE system_health_events SET last_notified_at = NOW(), updated_at = NOW() WHERE id = $1",
                )
                .bind(event_id)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }
}

async fn enqueue_matching_destinations(
    tx: &mut Transaction<'_, Postgres>,
    event: &SystemHealthEvent,
    event_action: &str,
) -> Result<(), sqlx::Error> {
    if event_action == "resolved" {
        // A lifecycle recovery belongs to the destinations selected when the
        // incident opened, not whatever routes happen to match now. This avoids
        // orphan recoveries on newly-created channels and preserves PagerDuty
        // incident closure after severity/category filters change.
        sqlx::query(
            r#"
            INSERT INTO system_health_outbox
                (tenant_id, event_id, webhook_id, event_action)
            SELECT DISTINCT $1, $2, prior.webhook_id, $3
            FROM system_health_outbox prior
            WHERE prior.tenant_id = $1
              AND prior.event_id = $2
              AND prior.event_action IN ('triggered', 'reminder')
            ON CONFLICT (tenant_id, event_id, webhook_id, event_action) DO NOTHING
            "#,
        )
        .bind(&event.tenant_id)
        .bind(event.id)
        .bind(event_action)
        .execute(&mut **tx)
        .await?;
        return Ok(());
    }

    sqlx::query(
        r#"
        INSERT INTO system_health_outbox
            (tenant_id, event_id, webhook_id, event_action)
        SELECT $1, $2, w.id, $3
        FROM webhooks w
        WHERE w.enabled = true
          AND (cardinality(w.event_types) = 0 OR $4 = ANY(w.event_types))
          AND (w.severity_filter IS NULL OR cardinality(w.severity_filter) = 0
               OR $5 = ANY(w.severity_filter))
          AND (w.health_category_filter IS NULL OR cardinality(w.health_category_filter) = 0
               OR $6 = ANY(w.health_category_filter))
          AND (w.health_resource_filter IS NULL OR cardinality(w.health_resource_filter) = 0
               OR $7 = ANY(w.health_resource_filter))
        ON CONFLICT (tenant_id, event_id, webhook_id, event_action) DO NOTHING
        "#,
    )
    .bind(&event.tenant_id)
    .bind(event.id)
    .bind(event_action)
    .bind(SYSTEM_HEALTH_EVENT_TYPE)
    .bind(&event.severity)
    .bind(&event.category)
    .bind(&event.resource_type)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn validate_publish(event: &PublishHealthEvent) -> Result<(), SystemHealthError> {
    if event.tenant_id.trim().is_empty() || event.tenant_id.len() > 100 {
        return Err(SystemHealthError::Invalid(
            "tenant_id must be between 1 and 100 bytes".to_string(),
        ));
    }
    if event.dedup_key.trim().is_empty() || event.dedup_key.len() > 512 {
        return Err(SystemHealthError::Invalid(
            "dedup_key must be between 1 and 512 bytes".to_string(),
        ));
    }
    if event.title.trim().is_empty() || event.title.len() > 300 {
        return Err(SystemHealthError::Invalid(
            "title must be between 1 and 300 bytes".to_string(),
        ));
    }
    if event.summary.len() > 4000 {
        return Err(SystemHealthError::Invalid(
            "summary must not exceed 4000 bytes".to_string(),
        ));
    }
    if event.resource_type.trim().is_empty() || event.resource_type.len() > 64 {
        return Err(SystemHealthError::Invalid(
            "resource_type must be between 1 and 64 bytes".to_string(),
        ));
    }
    if event.source.trim().is_empty() || event.source.len() > 128 {
        return Err(SystemHealthError::Invalid(
            "source must be between 1 and 128 bytes".to_string(),
        ));
    }
    if !event.diagnostic_context.is_object() {
        return Err(SystemHealthError::Invalid(
            "diagnostic_context must be a JSON object".to_string(),
        ));
    }
    if event.diagnostic_context.to_string().len() > 64 * 1024 {
        return Err(SystemHealthError::Invalid(
            "diagnostic_context must not exceed 64 KiB".to_string(),
        ));
    }
    Ok(())
}

fn truncate(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_health::{HealthCategory, HealthSeverity};

    #[test]
    fn publisher_rejects_unbounded_context() {
        let mut event = PublishHealthEvent::new(
            "integration:1:failed",
            HealthCategory::Integration,
            HealthSeverity::High,
            "failed",
            "summary",
            "integration",
            "test",
        );
        event.diagnostic_context = serde_json::json!({"body": "x".repeat(70 * 1024)});
        assert!(matches!(
            validate_publish(&event),
            Err(SystemHealthError::Invalid(_))
        ));
    }

    #[test]
    fn error_truncation_preserves_utf8_boundaries() {
        let input = "a".repeat(1999) + "🔒";
        let truncated = truncate(&input, 2000);
        assert_eq!(truncated.len(), 1999);
    }

    #[test]
    fn migration_contract_is_durable_tenant_scoped_and_ordered() {
        let migration =
            include_str!("../../../migrations/postgres/282_system_health_event_bus.sql");

        assert!(
            migration.contains("UNIQUE INDEX IF NOT EXISTS idx_system_health_events_active_dedup")
        );
        assert!(migration.contains("ON system_health_events (tenant_id, dedup_key)"));
        assert!(migration.contains("UNIQUE (tenant_id, event_id, webhook_id, event_action)"));

        // Guard the row-claim semantics that make the dispatcher safe across
        // leader handover and multiple workers.
        let source = include_str!("repository.rs");
        assert!(source.contains("FOR UPDATE SKIP LOCKED"));
        assert!(source.contains("predecessor.status NOT IN ('delivered', 'dead')"));
        assert!(source.contains("prior.event_action IN ('triggered', 'reminder')"));
        assert!(source.contains("enqueue_matching_destinations(&mut tx, &stored, \"reminder\")"));
    }

    #[test]
    fn severity_escalation_is_strictly_more_urgent() {
        assert!(severity_rank("critical") < severity_rank("high"));
        assert!(severity_rank("high") < severity_rank("medium"));
        assert!(severity_rank("medium") < severity_rank("low"));
        assert!(severity_rank("low") < severity_rank("informational"));
        assert!(!(severity_rank("medium") < severity_rank("high")));
    }
}
