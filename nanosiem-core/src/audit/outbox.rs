// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL record of truth + ClickHouse delivery outbox for security-critical
//! audit events (NAN-4954).
//!
//! Since NAN-1622 ClickHouse is the audit store, and a failed synchronous
//! insert (MEMORY_LIMIT_EXCEEDED 241, timeout, outage) left a security-critical
//! event only in an application log line. Every event in
//! [`super::SECURITY_CRITICAL_ACTIONS`] is now written to
//! `security_audit_events` BEFORE the ClickHouse write is attempted:
//!
//! - inline ClickHouse success stamps the delivery columns;
//! - inline failure leaves the row pending, and
//!   [`super::outbox_drain::AuditOutboxDrainer`] retries it with backoff until
//!   ClickHouse accepts it;
//! - `GET /api/audit` reads these rows (flagged degraded) when ClickHouse cannot
//!   answer;
//! - SIEM Health reads [`SecurityAuditOutbox::stats`].
//!
//! Routine (non-critical, floodable) events do not come here: a PostgreSQL
//! write per routine event would let an attacker flood the control-plane DB.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::query::{ClickHouseAuditEntry, ClickHouseAuditQuery};
use super::AuditEvent;

/// How long a freshly enqueued row is left to its inline ClickHouse attempt
/// before the drainer may pick it up. Longer than every inline bound (API 4s,
/// emitter backstop 10s), so the drainer and the inline write never race on
/// the same row in the normal case. (A race is still harmless: the drainer
/// skips rows whose UDM id already exists in ClickHouse.)
pub const INLINE_GRACE_SECS: i64 = 30;

/// Longest retry backoff between drainer attempts for one row.
pub const MAX_BACKOFF_SECS: i64 = 300;

/// How long delivered rows are kept in PostgreSQL. Pending rows are never
/// pruned.
pub const DELIVERED_RETENTION_DAYS: i64 = 90;

/// A pending row claimed by the drainer.
#[derive(Debug, Clone)]
pub struct PendingAuditEvent {
    pub event_id: Uuid,
    pub event: AuditEvent,
    pub udm_delivered: bool,
    pub ocsf_delivered: bool,
    pub attempts: i32,
}

/// Backlog / failure picture of the outbox, for SIEM Health and the drainer's
/// system-health event.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AuditOutboxStats {
    /// Rows not yet delivered to ClickHouse.
    pub pending: i64,
    /// Pending rows past the inline grace window: the inline write failed (or
    /// the process died before it finished) and only the drainer can deliver
    /// them now.
    pub overdue: i64,
    /// Age in seconds of the oldest pending row.
    pub oldest_pending_age_secs: Option<i64>,
    /// Highest attempt count among pending rows.
    pub max_attempts: i32,
    /// Most recent ClickHouse error recorded on a pending row.
    pub last_error: Option<String>,
    /// When that error was recorded.
    pub last_error_at: Option<DateTime<Utc>>,
    /// Security-critical events recorded in the last 24h.
    pub recorded_24h: i64,
    /// Of those, how many needed at least one retry (the inline ClickHouse
    /// write failed) — the audit-write failure count.
    pub deferred_24h: i64,
}

impl AuditOutboxStats {
    /// True when some security-critical event is not in ClickHouse and its
    /// inline write is over: ClickHouse audit search is missing events.
    pub fn is_backlogged(&self) -> bool {
        self.overdue > 0
    }
}

#[derive(sqlx::FromRow)]
struct PendingRow {
    event_id: Uuid,
    event: sqlx::types::Json<AuditEvent>,
    udm_delivered_at: Option<DateTime<Utc>>,
    ocsf_delivered_at: Option<DateTime<Utc>>,
    attempts: i32,
}

#[derive(sqlx::FromRow)]
struct EventRow {
    event_id: Uuid,
    occurred_at: DateTime<Utc>,
    event: sqlx::types::Json<AuditEvent>,
}

/// Repository over `security_audit_events`.
#[derive(Clone)]
pub struct SecurityAuditOutbox {
    pool: PgPool,
}

impl SecurityAuditOutbox {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Record a security-critical event. `due_now` skips the inline grace
    /// window (used when no inline ClickHouse attempt will be made, e.g. the
    /// durable-insert concurrency cap is saturated). Idempotent on `event_id`.
    pub async fn enqueue(&self, event: &AuditEvent, due_now: bool) -> Result<(), sqlx::Error> {
        let grace = if due_now { 0 } else { INLINE_GRACE_SECS };
        sqlx::query(
            r#"
            INSERT INTO security_audit_events
                (event_id, occurred_at, source, action, actor_id, resource_type, success,
                 event, next_attempt_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW() + make_interval(secs => $9))
            ON CONFLICT (event_id) DO NOTHING
            "#,
        )
        .bind(event.event_id)
        .bind(event.occurred_at)
        .bind(event.source.to_string())
        .bind(&event.action)
        .bind(event.actor_id)
        .bind(&event.resource_type)
        .bind(event.success)
        .bind(sqlx::types::Json(event))
        .bind(grace as f64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record a security-critical event inside the caller's transaction, so the
    /// audit record commits atomically with the state change it describes
    /// (NAN-4954). Leaves the inline grace window in place: the caller hands
    /// the event to [`crate::audit::AuditEmitter::deliver_recorded`] after
    /// commit, and the drainer covers it if that never happens.
    pub async fn enqueue_tx(
        tx: &mut Transaction<'_, Postgres>,
        event: &AuditEvent,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO security_audit_events
                (event_id, occurred_at, source, action, actor_id, resource_type, success,
                 event, next_attempt_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW() + make_interval(secs => $9))
            ON CONFLICT (event_id) DO NOTHING
            "#,
        )
        .bind(event.event_id)
        .bind(event.occurred_at)
        .bind(event.source.to_string())
        .bind(&event.action)
        .bind(event.actor_id)
        .bind(&event.resource_type)
        .bind(event.success)
        .bind(sqlx::types::Json(event))
        .bind(INLINE_GRACE_SECS as f64)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Stamp a row delivered after a successful inline ClickHouse write.
    /// `ocsf_required` is false when the deployment writes no OCSF mirror.
    pub async fn mark_delivered(
        &self,
        event_id: Uuid,
        ocsf_required: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE security_audit_events
            SET udm_delivered_at = COALESCE(udm_delivered_at, NOW()),
                ocsf_delivered_at = CASE WHEN $2 THEN COALESCE(ocsf_delivered_at, NOW())
                                         ELSE ocsf_delivered_at END,
                delivered_at = COALESCE(delivered_at, NOW())
            WHERE event_id = $1
            "#,
        )
        .bind(event_id)
        .bind(ocsf_required)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record the inline ClickHouse failure on a pending row, so SIEM Health
    /// can show WHY the backlog exists before the drainer's first retry.
    pub async fn record_inline_failure(&self, event_id: Uuid, error: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE security_audit_events
            SET attempts = attempts + 1, last_error = $2, last_attempt_at = NOW()
            WHERE event_id = $1 AND delivered_at IS NULL
            "#,
        )
        .bind(event_id)
        .bind(truncate_error(error))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lock up to `limit` due pending rows for delivery (`FOR UPDATE SKIP
    /// LOCKED`, so every jobs replica can drain concurrently without
    /// double-delivering). The rows stay locked until `tx` commits.
    pub async fn claim_due(
        tx: &mut Transaction<'_, Postgres>,
        limit: i64,
    ) -> Result<Vec<PendingAuditEvent>, sqlx::Error> {
        let rows: Vec<PendingRow> = sqlx::query_as(
            r#"
            SELECT event_id, event, udm_delivered_at, ocsf_delivered_at, attempts
            FROM security_audit_events
            WHERE delivered_at IS NULL AND next_attempt_at <= NOW()
            ORDER BY next_attempt_at, occurred_at
            LIMIT $1
            FOR UPDATE SKIP LOCKED
            "#,
        )
        .bind(limit)
        .fetch_all(&mut **tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| PendingAuditEvent {
                event_id: r.event_id,
                event: r.event.0,
                udm_delivered: r.udm_delivered_at.is_some(),
                ocsf_delivered: r.ocsf_delivered_at.is_some(),
                attempts: r.attempts,
            })
            .collect())
    }

    /// Stamp the UDM half delivered for `ids` (inside the claim transaction).
    pub async fn mark_udm_delivered(
        tx: &mut Transaction<'_, Postgres>,
        ids: &[Uuid],
    ) -> Result<(), sqlx::Error> {
        if ids.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "UPDATE security_audit_events SET udm_delivered_at = COALESCE(udm_delivered_at, NOW()) \
             WHERE event_id = ANY($1)",
        )
        .bind(ids)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Stamp the OCSF mirror half delivered for `ids`.
    pub async fn mark_ocsf_delivered(
        tx: &mut Transaction<'_, Postgres>,
        ids: &[Uuid],
    ) -> Result<(), sqlx::Error> {
        if ids.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "UPDATE security_audit_events SET ocsf_delivered_at = COALESCE(ocsf_delivered_at, NOW()) \
             WHERE event_id = ANY($1)",
        )
        .bind(ids)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Close out every claimed row whose required halves are now delivered.
    pub async fn finalize_delivered(
        tx: &mut Transaction<'_, Postgres>,
        ids: &[Uuid],
        ocsf_required: bool,
    ) -> Result<u64, sqlx::Error> {
        if ids.is_empty() {
            return Ok(0);
        }
        let done = sqlx::query(
            r#"
            UPDATE security_audit_events
            SET delivered_at = NOW(), last_attempt_at = NOW()
            WHERE event_id = ANY($1)
              AND delivered_at IS NULL
              AND udm_delivered_at IS NOT NULL
              AND (NOT $2 OR ocsf_delivered_at IS NOT NULL)
            "#,
        )
        .bind(ids)
        .bind(ocsf_required)
        .execute(&mut **tx)
        .await?;
        Ok(done.rows_affected())
    }

    /// Record a failed drainer attempt and schedule the retry with exponential
    /// backoff (2^attempts seconds, capped at [`MAX_BACKOFF_SECS`]).
    pub async fn record_retry(
        tx: &mut Transaction<'_, Postgres>,
        ids: &[Uuid],
        error: &str,
    ) -> Result<(), sqlx::Error> {
        if ids.is_empty() {
            return Ok(());
        }
        sqlx::query(
            r#"
            UPDATE security_audit_events
            SET attempts = attempts + 1,
                last_error = $2,
                last_attempt_at = NOW(),
                next_attempt_at = NOW() + make_interval(
                    secs => LEAST(power(2, LEAST(attempts + 1, 16))::float8, $3::float8))
            WHERE event_id = ANY($1) AND delivered_at IS NULL
            "#,
        )
        .bind(ids)
        .bind(truncate_error(error))
        .bind(MAX_BACKOFF_SECS as f64)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Backlog / failure snapshot.
    pub async fn stats(&self) -> Result<AuditOutboxStats, sqlx::Error> {
        let (pending, overdue, oldest, max_attempts): (i64, i64, Option<f64>, Option<i32>) =
            sqlx::query_as(
                r#"
                SELECT COUNT(*),
                       COUNT(*) FILTER (WHERE created_at < NOW() - make_interval(secs => $1)),
                       EXTRACT(EPOCH FROM (NOW() - MIN(created_at)))::float8,
                       MAX(attempts)
                FROM security_audit_events
                WHERE delivered_at IS NULL
                "#,
            )
            .bind(INLINE_GRACE_SECS as f64)
            .fetch_one(&self.pool)
            .await?;

        let last: Option<(Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
            r#"
            SELECT last_error, last_attempt_at
            FROM security_audit_events
            WHERE delivered_at IS NULL AND last_error IS NOT NULL
            ORDER BY last_attempt_at DESC NULLS LAST
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        let (recorded_24h, deferred_24h): (i64, i64) = sqlx::query_as(
            r#"
            SELECT COUNT(*), COUNT(*) FILTER (WHERE attempts > 0)
            FROM security_audit_events
            WHERE occurred_at >= NOW() - INTERVAL '24 hours'
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let (last_error, last_error_at) = last.unwrap_or((None, None));
        Ok(AuditOutboxStats {
            pending,
            overdue,
            oldest_pending_age_secs: oldest.map(|s| s.max(0.0) as i64),
            max_attempts: max_attempts.unwrap_or(0),
            last_error,
            last_error_at,
            recorded_24h,
            deferred_24h,
        })
    }

    /// Delete delivered rows older than the retention window, in bounded
    /// batches. Pending rows are never pruned.
    pub async fn prune_delivered(&self) -> Result<u64, sqlx::Error> {
        let done = sqlx::query(
            r#"
            DELETE FROM security_audit_events
            WHERE event_id IN (
                SELECT event_id FROM security_audit_events
                WHERE delivered_at IS NOT NULL
                  AND occurred_at < NOW() - make_interval(days => $1)
                LIMIT 5000
            )
            "#,
        )
        .bind(DELIVERED_RETENTION_DAYS as i32)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Degraded read path for `GET /api/audit`: the security-critical events
    /// matching `query`, newest first, in the same entry shape the ClickHouse
    /// path returns. Only covers security-critical actions — the caller must
    /// flag the response as partial.
    pub async fn query(
        &self,
        query: &ClickHouseAuditQuery,
    ) -> Result<(Vec<ClickHouseAuditEntry>, i64), sqlx::Error> {
        let start = query
            .start_time
            .unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
        let end = query.end_time.unwrap_or_else(Utc::now);
        let limit = query.limit.unwrap_or(50).clamp(1, 1000);
        let offset = query.offset.unwrap_or(0).max(0);
        let search = super::query::normalize_audit_search(query.search.as_deref());

        // Optional filters bound as NULL-able parameters ($n IS NULL OR col = $n)
        // so the statement text is fixed and fully parameterized.
        const FILTER: &str = r#"
            FROM security_audit_events
            WHERE occurred_at >= $1 AND occurred_at <= $2
              AND ($3::uuid IS NULL OR actor_id = $3)
              AND ($4::text IS NULL OR action = $4)
              AND ($5::text IS NULL OR source = $5)
              AND ($6::text IS NULL OR resource_type = $6)
              AND ($7::boolean IS NULL OR success = $7)
              -- Free-text search; JSON object keys stripped so they never match.
              AND ($8::text IS NULL OR strpos(
                    lower(regexp_replace(event::text, '"([^"\\]|\\.)*"\s*:', ' ', 'g')),
                    lower($8)) > 0)
        "#;

        let rows: Vec<EventRow> = sqlx::query_as(&format!(
            "SELECT event_id, occurred_at, event {FILTER} ORDER BY occurred_at DESC LIMIT $9 OFFSET $10"
        ))
        .bind(start)
        .bind(end)
        .bind(query.actor_id)
        .bind(&query.action)
        .bind(&query.source)
        .bind(&query.resource_type)
        .bind(query.success)
        .bind(&search)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) {FILTER}"))
            .bind(start)
            .bind(end)
            .bind(query.actor_id)
            .bind(&query.action)
            .bind(&query.source)
            .bind(&query.resource_type)
            .bind(query.success)
            .bind(&search)
            .fetch_one(&self.pool)
            .await?;

        Ok((rows.into_iter().map(row_to_entry).collect(), total))
    }
}

fn row_to_entry(row: EventRow) -> ClickHouseAuditEntry {
    let e = row.event.0;
    let metadata = e.metadata_json();
    ClickHouseAuditEntry {
        event_id: row.event_id.to_string(),
        timestamp: row.occurred_at,
        user: e.actor_name.clone(),
        action: Some(e.action.clone()),
        source: Some(e.source.to_string()),
        src_ip: e.ip_address.clone(),
        user_agent: e.user_agent.clone(),
        status: Some(if e.success { "success" } else { "failure" }.to_string()),
        message: e.message(),
        actor_id: e.actor_id.map(|id| id.to_string()),
        resource_type: e.resource_type.clone(),
        resource_id: e.resource_id.map(|id| id.to_string()),
        resource_name: e.resource_name.clone(),
        api_key_id: e.api_key_id.map(|id| id.to_string()),
        api_key_name: e.api_key_name.clone(),
        metadata,
    }
}

/// Keep stored errors bounded (ClickHouse exceptions can carry long stacks).
fn truncate_error(error: &str) -> String {
    const MAX: usize = 2000;
    if error.len() <= MAX {
        return error.to_string();
    }
    let mut end = MAX;
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &error[..end])
}
