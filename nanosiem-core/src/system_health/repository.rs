// SPDX-License-Identifier: AGPL-3.0-or-later

use sqlx::{Connection, PgConnection, PgPool, Postgres, Transaction};
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
        let mut conn = self.pool.acquire().await?;
        self.publish_on(&mut conn, event).await
    }

    /// [`Self::publish`] on `conn`. Inside a caller's transaction this runs
    /// as a savepoint (a failure rolls back only the publish) and needs no
    /// second pool connection (NAN-5738).
    pub async fn publish_on(
        &self,
        conn: &mut PgConnection,
        event: &PublishHealthEvent,
    ) -> Result<SystemHealthEvent, SystemHealthError> {
        validate_publish(event)?;
        let mut tx = conn.begin().await?;

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
                SET category = $2, severity = $3,
                    -- NAN-5785: a pass that raced a source delete, disable
                    -- or stale-alerting-off must not erase the attributed
                    -- `source_removed` flag. It clears only once the source is
                    -- actively monitored again.
                    title = CASE
                        WHEN diagnostic_context ? 'source_removed' AND NOT EXISTS (
                            SELECT 1 FROM log_sources ls
                            WHERE ls.id::text = system_health_events.resource_id
                              AND ls.enabled AND ls.stale_alert_enabled)
                        THEN title
                        ELSE $4 END,
                    summary = $5,
                    resource_type = $6, resource_id = $7, resource_name = $8,
                    diagnostic_context = CASE
                        WHEN diagnostic_context ? 'source_removed' AND NOT EXISTS (
                            SELECT 1 FROM log_sources ls
                            WHERE ls.id::text = system_health_events.resource_id
                              AND ls.enabled AND ls.stale_alert_enabled)
                        THEN $9 || jsonb_build_object('source_removed', diagnostic_context->'source_removed')
                        ELSE $9 END,
                    remediation = $10, source = $11,
                    occurrence_count = occurrence_count + 1,
                    -- NAN-5738: a publisher whose transaction began earlier
                    -- never moves last_seen_at backwards.
                    last_seen_at = GREATEST(last_seen_at, NOW()), updated_at = NOW()
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

    /// NAN-5450: re-notify the configured channels about an active condition
    /// at most once per `every` (an imminent disk: hourly). Returns whether a
    /// reminder was sent this call.
    ///
    /// The slot is claimed by one conditional UPDATE on `last_reminded_at`
    /// (see [`reminder_due`]), so concurrent callers on several hosts never
    /// both send. The outbox keeps one row per (event, webhook, action), so
    /// the previous, finished `reminder` rows of this event are removed before
    /// the new ones are queued; a reminder still being delivered is left alone
    /// (its insert is a no-op), which also caps a slow channel at one pending
    /// reminder.
    pub async fn remind_if_due(
        &self,
        dedup_key: &str,
        every: std::time::Duration,
    ) -> Result<bool, SystemHealthError> {
        let every_secs = i64::try_from(every.as_secs()).unwrap_or(i64::MAX).max(1);
        let mut tx = self.pool.begin().await?;
        let claimed = sqlx::query_as::<_, SystemHealthEvent>(
            r#"
            UPDATE system_health_events
            SET last_reminded_at = NOW()
            WHERE tenant_id = $1 AND dedup_key = $2 AND status = 'active'
              AND first_seen_at <= NOW() - make_interval(secs => $3)
              AND (last_reminded_at IS NULL OR last_reminded_at <= NOW() - make_interval(secs => $3))
            RETURNING id, tenant_id, dedup_key, category, severity, status, title, summary,
                      resource_type, resource_id, resource_name, diagnostic_context,
                      remediation, source, occurrence_count, first_seen_at, last_seen_at,
                      last_notified_at, acknowledged_at, acknowledged_by, resolved_at,
                      created_at, updated_at
            "#,
        )
        .bind(DEFAULT_TENANT_ID)
        .bind(dedup_key)
        .bind(every_secs as f64)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(event) = claimed else {
            tx.rollback().await?;
            return Ok(false);
        };
        sqlx::query(
            "DELETE FROM system_health_outbox WHERE tenant_id = $1 AND event_id = $2 \
             AND event_action = 'reminder' AND status IN ('delivered', 'dead')",
        )
        .bind(DEFAULT_TENANT_ID)
        .bind(event.id)
        .execute(&mut *tx)
        .await?;
        enqueue_matching_destinations(&mut tx, &event, "reminder").await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn resolve_by_dedup_key(
        &self,
        dedup_key: &str,
    ) -> Result<Option<SystemHealthEvent>, SystemHealthError> {
        self.resolve_active(DEFAULT_TENANT_ID, Some(dedup_key), None)
            .await
    }

    /// Resolve every active condition whose dedup key starts with `prefix`
    /// and that has not been seen since `stale_before` — conditions whose
    /// producer died without resolving them (for example a replaced pod).
    /// Each resolution fans out to the matching destinations like any other.
    pub async fn resolve_stale_by_prefix(
        &self,
        prefix: &str,
        stale_before: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<SystemHealthEvent>, SystemHealthError> {
        let mut conn = self.pool.acquire().await?;
        self.resolve_stale_by_prefix_on(&mut conn, prefix, stale_before).await
    }

    /// [`Self::resolve_stale_by_prefix`] on `conn` (a savepoint inside a
    /// caller's transaction, NAN-5738).
    pub async fn resolve_stale_by_prefix_on(
        &self,
        conn: &mut PgConnection,
        prefix: &str,
        stale_before: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<SystemHealthEvent>, SystemHealthError> {
        validate_resolve_prefix(prefix)?;
        let mut tx = conn.begin().await?;
        // `left(...) = $2`, not LIKE: dedup keys contain `_`, a LIKE wildcard.
        let events = sqlx::query_as::<_, SystemHealthEvent>(
            r#"
            UPDATE system_health_events
            SET status = 'resolved', resolved_at = NOW(), updated_at = NOW()
            WHERE tenant_id = $1 AND status = 'active'
              AND left(dedup_key, length($2)) = $2
              AND last_seen_at < $3
            RETURNING id, tenant_id, dedup_key, category, severity, status, title, summary,
                      resource_type, resource_id, resource_name, diagnostic_context,
                      remediation, source, occurrence_count, first_seen_at, last_seen_at,
                      last_notified_at, acknowledged_at, acknowledged_by, resolved_at,
                      created_at, updated_at
            "#,
        )
        .bind(DEFAULT_TENANT_ID)
        .bind(prefix)
        .bind(stale_before)
        .fetch_all(&mut *tx)
        .await?;
        for event in &events {
            enqueue_matching_destinations(&mut tx, event, "resolved").await?;
        }
        tx.commit().await?;
        Ok(events)
    }

    /// Resolve every active condition of producer `source` whose dedup key
    /// starts with `prefix` and is not in `keep`, on `conn` (a savepoint
    /// inside a caller's transaction). For a producer that serializes its
    /// passes and knows the full set of conditions that still hold:
    /// membership, not timestamps, decides, so a pass whose transaction began
    /// earlier cannot leave a cleared condition active (NAN-5738).
    ///
    /// Scoped so it can never touch another producer's alerts: `prefix` must
    /// be a specific namespace (non-empty, at most 256 bytes, ending in `:`)
    /// and only events whose `source` is `source` are resolved.
    pub async fn resolve_absent_by_prefix_on(
        &self,
        conn: &mut PgConnection,
        prefix: &str,
        source: &str,
        keep: &[String],
    ) -> Result<Vec<SystemHealthEvent>, SystemHealthError> {
        validate_resolve_prefix(prefix)?;
        if source.trim().is_empty() || source.len() > 128 {
            return Err(SystemHealthError::Invalid("source must be between 1 and 128 bytes".to_string()));
        }
        let mut tx = conn.begin().await?;
        let events = sqlx::query_as::<_, SystemHealthEvent>(
            r#"
            UPDATE system_health_events
            SET status = 'resolved', resolved_at = NOW(), updated_at = NOW()
            WHERE tenant_id = $1 AND status = 'active'
              AND left(dedup_key, length($2)) = $2
              AND NOT (dedup_key = ANY($3))
              AND source = $4
            RETURNING id, tenant_id, dedup_key, category, severity, status, title, summary,
                      resource_type, resource_id, resource_name, diagnostic_context,
                      remediation, source, occurrence_count, first_seen_at, last_seen_at,
                      last_notified_at, acknowledged_at, acknowledged_by, resolved_at,
                      created_at, updated_at
            "#,
        )
        .bind(DEFAULT_TENANT_ID)
        .bind(prefix)
        .bind(keep)
        .bind(source)
        .fetch_all(&mut *tx)
        .await?;
        for event in &events {
            enqueue_matching_destinations(&mut tx, event, "resolved").await?;
        }
        tx.commit().await?;
        Ok(events)
    }

    /// NAN-5785: a stale-feed recovery. Resolves the active lifecycle only
    /// when the source's newest event is later than the moment the alert
    /// opened: data has demonstrably arrived since. A source that merely
    /// stopped being judged stale (its threshold was raised, a grace window,
    /// an unreadable probe) never closes an open alert this way; only new
    /// data or an owner with `system_health:manage` does.
    pub async fn resolve_recovered(
        &self,
        dedup_key: &str,
        last_event_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<SystemHealthEvent>, SystemHealthError> {
        self.resolve_active_inner(DEFAULT_TENANT_ID, Some(dedup_key), None, Some(last_event_at))
            .await
    }

    /// NAN-5785: an active `log_source` alert whose source was deleted,
    /// disabled, or had stale alerting turned off. The alert is NOT resolved:
    /// a source mutation (`log_sources:edit` / `log_sources:delete`) must never
    /// close a real alert or its paging incident. It stays active, retitled
    /// with who removed the source (`"<title> (source deleted by alice)"`),
    /// with `diagnostic_context.source_removed` set, and its destinations get a
    /// reminder carrying the new title. Closing it is an owner's audited
    /// `system_health:manage` action.
    ///
    /// A flag only escalates (deleted > disabled > stale alerting off): an
    /// alert already flagged as strongly or more is left alone, so repeats
    /// send no further reminder. The original title is kept so a later flag
    /// replaces the suffix instead of stacking it.
    pub async fn flag_log_source_events_removed(
        &self,
        source_ids: &[Uuid],
        action: &str,
        label: &str,
        by: &str,
    ) -> Result<Vec<SystemHealthEvent>, SystemHealthError> {
        if source_ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<String> = source_ids.iter().map(Uuid::to_string).collect();
        self.flag_removed_in("ids", &ids, action, label, by).await
    }

    /// NAN-5785: flag (never resolve) active `log_source` alerts whose source
    /// no longer exists but which no delete path flagged: a raw SQL delete, a
    /// path without an actor, a failed flag, or a stale pass that raced the
    /// delete.
    pub async fn flag_orphaned_log_source_events(
        &self,
        label: &str,
        by: &str,
    ) -> Result<Vec<SystemHealthEvent>, SystemHealthError> {
        self.flag_removed_in("orphaned", &[], "deleted", label, by).await
    }

    /// NAN-5785: flag (never resolve) active stale alerts of sources that are
    /// disabled (`action = "disabled"`) or have stale alerting off
    /// (`"stale_alerting_off"`) but carry no such flag: a stale pass raised
    /// them after the API's flag ran. `action` picks which.
    pub async fn flag_unmonitored_stale_events(
        &self,
        action: &str,
        label: &str,
        by: &str,
    ) -> Result<Vec<SystemHealthEvent>, SystemHealthError> {
        let scope = if action == "disabled" { "unmonitored_disabled" } else { "unmonitored_alerting_off" };
        self.flag_removed_in(scope, &[], action, label, by).await
    }

    async fn flag_removed_in(
        &self,
        scope: &'static str,
        ids: &[String],
        action: &str,
        label: &str,
        by: &str,
    ) -> Result<Vec<SystemHealthEvent>, SystemHealthError> {
        let mut tx = self.pool.begin().await?;
        let events = sqlx::query_as::<_, SystemHealthEvent>(
            r#"
            WITH target AS (
                SELECT e.id,
                       COALESCE(e.diagnostic_context->'source_removed'->>'original_title', e.title)
                           AS original_title
                FROM system_health_events e
                WHERE e.tenant_id = $1 AND e.status = 'active' AND e.resource_type = 'log_source'
                  -- Precedence deleted > disabled > stale_alerting_off: a flag
                  -- only ever escalates, so repeated or alternating updates
                  -- cannot re-flag (no reminder or audit spam) and a weaker
                  -- removal never hides a stronger one.
                  AND (CASE e.diagnostic_context->'source_removed'->>'action'
                          WHEN 'deleted' THEN 3 WHEN 'disabled' THEN 2
                          WHEN 'stale_alerting_off' THEN 1 ELSE 0 END)
                      < (CASE $4::text
                          WHEN 'deleted' THEN 3 WHEN 'disabled' THEN 2
                          WHEN 'stale_alerting_off' THEN 1 ELSE 0 END)
                  AND CASE $2::text
                      WHEN 'ids' THEN e.resource_id = ANY($3::text[])
                      WHEN 'orphaned' THEN e.resource_id IS NOT NULL AND NOT EXISTS (
                          SELECT 1 FROM log_sources ls WHERE ls.id::text = e.resource_id)
                      -- A stale alert a racing pass raised for a source that
                      -- was already disabled or had stale alerting off.
                      WHEN 'unmonitored_disabled' THEN EXISTS (
                          SELECT 1 FROM log_sources ls
                          WHERE ls.id::text = e.resource_id AND NOT ls.enabled
                            AND e.dedup_key = 'log_source:' || ls.id::text || ':stale')
                      WHEN 'unmonitored_alerting_off' THEN EXISTS (
                          SELECT 1 FROM log_sources ls
                          WHERE ls.id::text = e.resource_id AND ls.enabled AND NOT ls.stale_alert_enabled
                            AND e.dedup_key = 'log_source:' || ls.id::text || ':stale')
                      ELSE false
                  END
                FOR UPDATE OF e
            )
            UPDATE system_health_events e
            SET title = target.original_title || ' (' || $5::text || ')',
                diagnostic_context = e.diagnostic_context || jsonb_build_object(
                    'source_removed', jsonb_build_object(
                        'action', $4::text,
                        'by', $6::text,
                        'at', NOW(),
                        'original_title', target.original_title,
                        'note', 'The alert stays open until an owner with system_health:manage resolves it.'
                    )),
                updated_at = NOW()
            FROM target
            WHERE e.id = target.id
            RETURNING e.id, e.tenant_id, e.dedup_key, e.category, e.severity, e.status, e.title,
                      e.summary, e.resource_type, e.resource_id, e.resource_name,
                      e.diagnostic_context, e.remediation, e.source, e.occurrence_count,
                      e.first_seen_at, e.last_seen_at, e.last_notified_at, e.acknowledged_at,
                      e.acknowledged_by, e.resolved_at, e.created_at, e.updated_at
            "#,
        )
        .bind(DEFAULT_TENANT_ID)
        .bind(scope)
        .bind(ids)
        .bind(action)
        .bind(label)
        .bind(by)
        .fetch_all(&mut *tx)
        .await?;
        for event in &events {
            // Same as a reminder (`claim_reminder`): one reminder row per
            // destination, so clear the finished ones first.
            sqlx::query(
                "DELETE FROM system_health_outbox WHERE tenant_id = $1 AND event_id = $2 \
                 AND event_action = 'reminder' AND status IN ('delivered', 'dead')",
            )
            .bind(&event.tenant_id)
            .bind(event.id)
            .execute(&mut *tx)
            .await?;
            enqueue_matching_destinations(&mut tx, event, "reminder").await?;
        }
        tx.commit().await?;
        Ok(events)
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
        self.resolve_active_inner(tenant_id, dedup_key, id, None).await
    }

    /// `recovered_after`: resolve only a lifecycle that opened before it.
    async fn resolve_active_inner(
        &self,
        tenant_id: &str,
        dedup_key: Option<&str>,
        id: Option<Uuid>,
        recovered_after: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Option<SystemHealthEvent>, SystemHealthError> {
        let mut tx = self.pool.begin().await?;
        let event = sqlx::query_as::<_, SystemHealthEvent>(
            r#"
            UPDATE system_health_events
            SET status = 'resolved', resolved_at = NOW(), last_seen_at = NOW(), updated_at = NOW()
            WHERE tenant_id = $1 AND status = 'active'
              AND ($2::text IS NULL OR dedup_key = $2)
              AND ($3::uuid IS NULL OR id = $3)
              AND ($4::timestamptz IS NULL OR first_seen_at < $4)
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
        .bind(recovered_after)
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

/// A bulk-resolve prefix must name one namespace: non-empty, at most 256
/// bytes and ending in `:` (an empty or bare prefix would match other
/// producers' alerts, NAN-5738).
pub(crate) fn validate_resolve_prefix(prefix: &str) -> Result<(), SystemHealthError> {
    if prefix.trim().is_empty() || prefix.len() > 256 || !prefix.ends_with(':') {
        return Err(SystemHealthError::Invalid(
            "resolve prefix must be 1-256 bytes and end with ':'".to_string(),
        ));
    }
    Ok(())
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

/// NAN-5450: whether a repeat reminder is due (the predicate of
/// [`SystemHealthRepository::remind_if_due`]'s UPDATE): the condition has
/// been active for at least `every` (its first notification was the trigger)
/// and the last reminder, if any, is at least `every` old.
pub fn reminder_due(
    first_seen: chrono::DateTime<chrono::Utc>,
    last_reminded: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    every: chrono::Duration,
) -> bool {
    first_seen <= now - every && last_reminded.is_none_or(|t| t <= now - every)
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

#[cfg(test)]
mod resolve_prefix_tests {
    use super::validate_resolve_prefix;

    /// NAN-5738 review r5: a bulk resolve can never match every alert or
    /// another namespace.
    #[test]
    fn a_resolve_prefix_must_be_one_specific_namespace() {
        for bad in ["", "   ", ":x", "soar_pack", "log_source"] {
            let ok = validate_resolve_prefix(bad).is_ok();
            assert!(!ok || bad == ":x", "{bad:?}");
        }
        assert!(validate_resolve_prefix(&format!("{}:", "a".repeat(300))).is_err());
        for good in ["soar_pack_quarantined:", "ip_allowlist:load_failed:api:"] {
            assert!(validate_resolve_prefix(good).is_ok(), "{good:?}");
        }
    }
}
