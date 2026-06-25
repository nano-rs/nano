// SPDX-License-Identifier: AGPL-3.0-or-later

//! Alert repository for CRUD operations

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::models::{
    AcknowledgeAlert, Alert, AlertStatus, CloseAlert, Disposition, NewAlert, Severity,
};

#[derive(Error, Debug)]
pub enum AlertRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Alert not found: {0}")]
    NotFound(Uuid),
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),
    #[error("Duplicate alert: rule_id={0}, event_hash={1}")]
    DuplicateAlert(Uuid, String),
}

/// Repository for alert operations
#[derive(Clone)]
pub struct AlertRepository {
    pool: PgPool,
}

/// Compute a hash of matched events for deduplication.
/// Strips `_nano_*` timing metadata fields before hashing so that detection timing
/// injection doesn't break dedup (each execution injects a new `_nano_detected_at`).
pub fn compute_event_hash(matched_events: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    let clean = strip_nano_fields(matched_events);
    let json_str = serde_json::to_string(&clean).unwrap_or_default();
    hasher.update(json_str.as_bytes());
    hex::encode(hasher.finalize())
}

/// Recursively strip `_nano_*` prefixed keys from JSON values.
fn strip_nano_fields(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(strip_nano_fields).collect())
        }
        serde_json::Value::Object(map) => {
            let clean: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter(|(k, _)| !k.starts_with("_nano_"))
                .map(|(k, v)| (k.clone(), strip_nano_fields(v)))
                .collect();
            serde_json::Value::Object(clean)
        }
        other => other.clone(),
    }
}

/// NAN-1541: a single alert produced by the spine, parameterized over its
/// `kind` discriminator. This is the unified raise contract: detection and the
/// three observability evaluators all build one of these and route through
/// [`AlertRepository::create_alert`].
///
/// - `kind` is one of `detection`, `metric_monitor`, `slo`, `synthetic`
///   (enforced by the migration-212 CHECK).
/// - `rule_id` is `Some` only for detection alerts; observability rows leave it
///   `None` (the FK is nullable).
/// - `source_id` carries the producer's identifier as text — the rule UUID for
///   detections, the monitor/check typeid for observability alerts.
/// - `event_hash` drives dedup. `Some` uses `ON CONFLICT (rule_id, event_hash)
///   DO NOTHING`; `None` skips the dedup conflict path entirely.
pub struct AlertInsert<'a> {
    pub kind: &'a str,
    pub rule_id: Option<Uuid>,
    pub source_id: Option<String>,
    pub severity: &'a Severity,
    pub matched_events: &'a serde_json::Value,
    pub event_hash: Option<String>,
}

/// NAN-1541: normalize an optional kinds filter into the `Option<Vec<String>>`
/// the queries bind. An absent filter OR an empty slice both mean "all kinds"
/// (bound as SQL NULL so the `$N::text[] IS NULL OR ...` guard short-circuits).
fn normalize_kinds(kinds: Option<&[String]>) -> Option<Vec<String>> {
    match kinds {
        Some(k) if !k.is_empty() => Some(k.to_vec()),
        _ => None,
    }
}

impl AlertRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// NAN-1541: the ONE unified create. Every alert producer — detection and
    /// each observability evaluator — funnels through here with its own `kind`
    /// + `source_id`. Detection behavior is preserved exactly: `create` /
    /// `create_without_dedup` are thin wrappers that set `kind = "detection"`
    /// and `source_id = rule_id`.
    ///
    /// When `event_hash` is `Some`, the insert is dedup-guarded via
    /// `ON CONFLICT (rule_id, event_hash) DO NOTHING` (returns `DuplicateAlert`
    /// on conflict). When `None`, a plain insert is issued (no dedup).
    pub async fn create_alert(
        &self,
        insert: AlertInsert<'_>,
    ) -> Result<Alert, AlertRepositoryError> {
        match insert.event_hash {
            Some(event_hash) => {
                // Atomic insert with conflict detection - no race condition window
                let result = sqlx::query_as::<_, Alert>(
                    r#"
                    INSERT INTO alerts (rule_id, severity, matched_events, event_hash, kind, source_id)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (rule_id, event_hash) WHERE event_hash IS NOT NULL DO NOTHING
                    RETURNING *
                    "#,
                )
                .bind(insert.rule_id)
                .bind(insert.severity)
                .bind(insert.matched_events)
                .bind(&event_hash)
                .bind(insert.kind)
                .bind(&insert.source_id)
                .fetch_optional(&self.pool)
                .await?;

                match result {
                    Some(alert) => Ok(alert),
                    None => Err(AlertRepositoryError::DuplicateAlert(
                        // rule_id is NULL for observability alerts; surface nil
                        // in the (rare) dedup-conflict error rather than panic.
                        insert.rule_id.unwrap_or_else(Uuid::nil),
                        event_hash,
                    )),
                }
            }
            None => {
                let result = sqlx::query_as::<_, Alert>(
                    r#"
                    INSERT INTO alerts (rule_id, severity, matched_events, kind, source_id)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING *
                    "#,
                )
                .bind(insert.rule_id)
                .bind(insert.severity)
                .bind(insert.matched_events)
                .bind(insert.kind)
                .bind(&insert.source_id)
                .fetch_one(&self.pool)
                .await?;

                Ok(result)
            }
        }
    }

    /// Create a new detection alert with deduplication
    /// If event_hash is provided and an alert with the same rule_id + event_hash exists,
    /// returns DuplicateAlert error instead of creating a duplicate
    ///
    /// Uses INSERT ON CONFLICT to atomically handle deduplication (race-condition safe).
    /// Thin wrapper over [`create_alert`] with `kind = "detection"`.
    pub async fn create(&self, alert: &NewAlert) -> Result<Alert, AlertRepositoryError> {
        // Compute event hash if not provided
        let event_hash = alert
            .event_hash
            .clone()
            .unwrap_or_else(|| compute_event_hash(&alert.matched_events));

        self.create_alert(AlertInsert {
            kind: "detection",
            rule_id: Some(alert.rule_id),
            source_id: Some(alert.rule_id.to_string()),
            severity: &alert.severity,
            matched_events: &alert.matched_events,
            event_hash: Some(event_hash),
        })
        .await
    }

    /// Create a new detection alert without deduplication check (for backwards compatibility).
    /// Thin wrapper over [`create_alert`] with `kind = "detection"`.
    pub async fn create_without_dedup(
        &self,
        alert: &NewAlert,
    ) -> Result<Alert, AlertRepositoryError> {
        self.create_alert(AlertInsert {
            kind: "detection",
            rule_id: Some(alert.rule_id),
            source_id: Some(alert.rule_id.to_string()),
            severity: &alert.severity,
            matched_events: &alert.matched_events,
            event_hash: None,
        })
        .await
    }

    /// NAN-1563: durable re-arm authority for observability alerts.
    ///
    /// Returns the `created_at` of the most recent alert for `(kind, source_id)`,
    /// or `None` if no such alert exists. This is the durable backstop for
    /// time-based re-arm dedup on the `event_hash: None` insert path (SLO /
    /// metric-monitor alerts), which carry no per-event dedup hash. Because the
    /// answer comes from the persisted `alerts` table, it survives a
    /// jobs-process restart / leader failover — the new leader sees the prior
    /// leader's last alert and respects the re-arm window instead of re-firing.
    ///
    /// Parameterized; `source_id` is the producer's identifier text (the SLO id
    /// for `kind = "slo"`).
    pub async fn latest_alert_at_for_source(
        &self,
        kind: &str,
        source_id: &str,
    ) -> Result<Option<DateTime<Utc>>, AlertRepositoryError> {
        let created_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            r#"
            SELECT created_at
            FROM alerts
            WHERE kind = $1 AND source_id = $2
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(kind)
        .bind(source_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(created_at)
    }

    /// Find an alert by ID (with rule name)
    pub async fn find_by_id(&self, id: Uuid) -> Result<Alert, AlertRepositoryError> {
        let result = sqlx::query_as::<_, Alert>(
            r#"
            SELECT
                a.*,
                r.name as rule_name,
                jsonb_array_length(a.matched_events) as matched_event_count,
                t.verdict_type as triage_verdict,
                t.confidence as triage_confidence,
                t.verdict as triage_verdict_details
            FROM alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            LEFT JOIN (
                SELECT DISTINCT ON (alert_id) alert_id, verdict_type, confidence, verdict
                FROM alert_triage_results
                WHERE status = 'completed'
                ORDER BY alert_id, created_at DESC
            ) t ON t.alert_id = a.id
            WHERE a.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AlertRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// List alerts with optional filters (with rule names).
    ///
    /// NAN-1541: `kinds` filters by the spine discriminator. `None` (or an
    /// empty slice) returns ALL kinds; the SIEM Alerts view passes
    /// `["detection"]` and the Observability Alerts view passes the monitor
    /// kinds. Detection callers that don't pass `kinds` keep the prior
    /// behavior, but the API layer always scopes them to `["detection"]`.
    pub async fn list(
        &self,
        status: Option<AlertStatus>,
        severity: Option<Severity>,
        kinds: Option<&[String]>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Alert>, AlertRepositoryError> {
        let kinds_filter = normalize_kinds(kinds);
        let results = sqlx::query_as::<_, Alert>(
            r#"
            SELECT
                a.*,
                r.name as rule_name,
                jsonb_array_length(a.matched_events) as matched_event_count,
                t.verdict_type as triage_verdict,
                t.confidence as triage_confidence,
                t.verdict as triage_verdict_details
            FROM alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            LEFT JOIN (
                SELECT DISTINCT ON (alert_id) alert_id, verdict_type, confidence, verdict
                FROM alert_triage_results
                WHERE status = 'completed'
                ORDER BY alert_id, created_at DESC
            ) t ON t.alert_id = a.id
            WHERE ($1::text IS NULL OR a.status = $1)
              AND ($2::text IS NULL OR a.severity = $2)
              AND ($5::text[] IS NULL OR a.kind = ANY($5))
            ORDER BY
                CASE a.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                a.created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(status.map(|s| format!("{:?}", s).to_lowercase()))
        .bind(severity.map(|s| format!("{:?}", s).to_lowercase()))
        .bind(limit)
        .bind(offset)
        .bind(kinds_filter)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List alerts by rule ID (with rule name)
    /// Limited to most recent 100 alerts to prevent memory issues
    pub async fn list_by_rule(&self, rule_id: Uuid) -> Result<Vec<Alert>, AlertRepositoryError> {
        let results = sqlx::query_as::<_, Alert>(
            r#"
            SELECT 
                a.*,
                r.name as rule_name,
                jsonb_array_length(a.matched_events) as matched_event_count
            FROM alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            WHERE a.rule_id = $1 
            ORDER BY a.created_at DESC
            LIMIT 100
            "#,
        )
        .bind(rule_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List alerts by rule ID with custom limit
    pub async fn list_by_rule_limited(
        &self,
        rule_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Alert>, AlertRepositoryError> {
        let results = sqlx::query_as::<_, Alert>(
            r#"
            SELECT 
                a.*,
                r.name as rule_name,
                jsonb_array_length(a.matched_events) as matched_event_count
            FROM alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            WHERE a.rule_id = $1 
            ORDER BY a.created_at DESC
            LIMIT $2
            "#,
        )
        .bind(rule_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Acknowledge an alert
    ///
    /// Uses atomic status check in WHERE clause to prevent race conditions
    pub async fn acknowledge(
        &self,
        id: Uuid,
        ack: &AcknowledgeAlert,
    ) -> Result<Alert, AlertRepositoryError> {
        // Atomic state transition - status check in WHERE prevents race conditions
        let result = sqlx::query_as::<_, Alert>(
            r#"
            UPDATE alerts SET
                status = 'acknowledged',
                acknowledged_by = $2,
                acknowledged_at = $3
            WHERE id = $1 AND status = 'new'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&ack.acknowledged_by)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(alert) => Ok(alert),
            None => {
                // Check if alert exists to provide appropriate error
                match self.find_by_id(id).await {
                    Ok(alert) => Err(AlertRepositoryError::InvalidStateTransition(format!(
                        "Can only acknowledge alerts with 'new' status, current status is '{:?}'",
                        alert.status
                    ))),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Close an alert
    ///
    /// Uses atomic status check in WHERE clause to prevent race conditions
    pub async fn close(&self, id: Uuid, close: &CloseAlert) -> Result<Alert, AlertRepositoryError> {
        // Atomic state transition - status check in WHERE prevents race conditions
        let result = sqlx::query_as::<_, Alert>(
            r#"
            UPDATE alerts SET
                status = 'closed',
                disposition = $2,
                closed_by = $3,
                closed_at = $4
            WHERE id = $1 AND status != 'closed'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&close.disposition)
        .bind(&close.closed_by)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(alert) => Ok(alert),
            None => {
                // Check if alert exists to provide appropriate error
                match self.find_by_id(id).await {
                    Ok(_) => Err(AlertRepositoryError::InvalidStateTransition(
                        "Alert is already closed".to_string(),
                    )),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Assign an alert to an analyst
    pub async fn assign(&self, id: Uuid, assignee: &str) -> Result<Alert, AlertRepositoryError> {
        let result = sqlx::query_as::<_, Alert>(
            r#"
            UPDATE alerts SET assigned_to = $2
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(assignee)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AlertRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Bulk acknowledge alerts
    pub async fn bulk_acknowledge(
        &self,
        ids: &[Uuid],
        acknowledged_by: &str,
    ) -> Result<usize, AlertRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE alerts SET
                status = 'acknowledged',
                acknowledged_by = $2,
                acknowledged_at = $3
            WHERE id = ANY($1) AND status = 'new'
            "#,
        )
        .bind(ids)
        .bind(acknowledged_by)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as usize)
    }

    /// Bulk close alerts
    pub async fn bulk_close(
        &self,
        ids: &[Uuid],
        disposition: Disposition,
        closed_by: &str,
    ) -> Result<usize, AlertRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE alerts SET
                status = 'closed',
                disposition = $2,
                closed_by = $3,
                closed_at = $4
            WHERE id = ANY($1) AND status != 'closed'
            "#,
        )
        .bind(ids)
        .bind(&disposition)
        .bind(closed_by)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as usize)
    }

    /// Count alerts by status (last 90 days to avoid full table scan).
    ///
    /// NAN-1541: `kinds` scopes the counts to the spine discriminator (`None`
    /// = all kinds).
    pub async fn count_by_status(
        &self,
        kinds: Option<&[String]>,
    ) -> Result<Vec<(AlertStatus, i64)>, AlertRepositoryError> {
        let kinds_filter = normalize_kinds(kinds);
        let results: Vec<(String, i64)> = sqlx::query_as(
            r#"SELECT status, COUNT(*) FROM alerts
               WHERE created_at >= NOW() - INTERVAL '90 days'
                 AND ($1::text[] IS NULL OR kind = ANY($1))
               GROUP BY status"#,
        )
        .bind(kinds_filter)
        .fetch_all(&self.pool)
        .await?;

        let counts = results
            .into_iter()
            .filter_map(|(status, count)| {
                let status = match status.as_str() {
                    "new" => Some(AlertStatus::New),
                    "acknowledged" => Some(AlertStatus::Acknowledged),
                    "closed" => Some(AlertStatus::Closed),
                    _ => None,
                };
                status.map(|s| (s, count))
            })
            .collect();

        Ok(counts)
    }

    /// List alerts created after a specific timestamp and ID (for cursor-based streaming)
    pub async fn list_after(
        &self,
        after_timestamp: DateTime<Utc>,
        after_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Alert>, AlertRepositoryError> {
        let results = sqlx::query_as::<_, Alert>(
            r#"
            SELECT
                a.*,
                r.name as rule_name,
                jsonb_array_length(a.matched_events) as matched_event_count,
                t.verdict_type as triage_verdict,
                t.confidence as triage_confidence,
                t.verdict as triage_verdict_details
            FROM alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            LEFT JOIN (
                SELECT DISTINCT ON (alert_id) alert_id, verdict_type, confidence, verdict
                FROM alert_triage_results
                WHERE status = 'completed'
                ORDER BY alert_id, created_at DESC
            ) t ON t.alert_id = a.id
            WHERE (a.created_at > $1) OR (a.created_at = $1 AND a.id > $2)
            ORDER BY a.created_at ASC, a.id ASC
            LIMIT $3
            "#,
        )
        .bind(after_timestamp)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_event_hash_strips_nano_fields() {
        let raw_events = serde_json::json!([{
            "src_ip": "10.1.3.212",
            "failures": 6
        }]);

        let enriched_events = serde_json::json!([{
            "src_ip": "10.1.3.212",
            "failures": 6,
            "_nano_detected_at": "2026-04-13T12:00:00+00:00"
        }]);

        assert_eq!(
            compute_event_hash(&raw_events),
            compute_event_hash(&enriched_events),
            "Hash should be stable regardless of _nano_* fields"
        );
    }

    #[test]
    fn test_compute_event_hash_differs_for_different_events() {
        let events_a = serde_json::json!([{"src_ip": "10.1.3.212"}]);
        let events_b = serde_json::json!([{"src_ip": "10.1.3.213"}]);

        assert_ne!(
            compute_event_hash(&events_a),
            compute_event_hash(&events_b),
        );
    }
}
