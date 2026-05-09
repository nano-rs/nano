// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repository for /health finding suppressions (NAN-615).
//!
//! Active suppressions are loaded by the scheduler before each report run
//! and injected into the AI system prompt so previously-flagged-as-
//! not-an-issue findings are omitted.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum SuppressionRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Suppression not found: {0}")]
    NotFound(Uuid),
}

/// One active or undone suppression. Used by both the scheduler (active
/// suppressions feed the prompt) and the API (full list for the admin view).
///
/// Storage is a UUID primary key; over the wire we serialize as a typeid
/// (`hsupp_<base32>`) per the prefix registered in `typeid.rs`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct FindingSuppression {
    #[serde(with = "crate::typeid::siem_health_suppression")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub finding_signature: String,
    pub title: String,
    pub reason: String,
    #[serde(with = "crate::typeid::user")]
    #[schema(value_type = String)]
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub deactivated_at: Option<DateTime<Utc>>,
    #[serde(with = "crate::typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub deactivated_by: Option<Uuid>,
}

#[derive(Clone)]
pub struct SuppressionRepository {
    pool: PgPool,
}

impl SuppressionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new active suppression. If an active suppression already
    /// exists for this signature, return the existing row instead of
    /// erroring — the partial unique index would reject it anyway, and the
    /// double-click case should be idempotent.
    pub async fn create(
        &self,
        finding_signature: &str,
        title: &str,
        reason: &str,
        created_by: Uuid,
    ) -> Result<FindingSuppression, SuppressionRepositoryError> {
        let row = sqlx::query(
            r#"
            INSERT INTO siem_health_finding_suppressions
                (finding_signature, title, reason, created_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (finding_signature) WHERE deactivated_at IS NULL DO UPDATE
                SET reason = EXCLUDED.reason,
                    title = EXCLUDED.title,
                    created_by = EXCLUDED.created_by
            RETURNING id, finding_signature, title, reason, created_by, created_at,
                      deactivated_at, deactivated_by
            "#,
        )
        .bind(finding_signature)
        .bind(title)
        .bind(reason)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;

        Ok(Self::row_to_suppression(&row))
    }

    /// All currently-active suppressions, oldest first so the prompt's
    /// "previously suppressed" list reads chronologically.
    pub async fn list_active(
        &self,
    ) -> Result<Vec<FindingSuppression>, SuppressionRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, finding_signature, title, reason, created_by, created_at,
                   deactivated_at, deactivated_by
            FROM siem_health_finding_suppressions
            WHERE deactivated_at IS NULL
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_suppression).collect())
    }

    /// All suppressions including deactivated ones, newest first. For the
    /// admin "show suppressed" view.
    pub async fn list_all(
        &self,
    ) -> Result<Vec<FindingSuppression>, SuppressionRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, finding_signature, title, reason, created_by, created_at,
                   deactivated_at, deactivated_by
            FROM siem_health_finding_suppressions
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_suppression).collect())
    }

    /// Deactivate a suppression so the next report run will surface findings
    /// of that class again.
    pub async fn deactivate(
        &self,
        id: Uuid,
        deactivated_by: Uuid,
    ) -> Result<FindingSuppression, SuppressionRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE siem_health_finding_suppressions
            SET deactivated_at = NOW(),
                deactivated_by = $2
            WHERE id = $1
              AND deactivated_at IS NULL
            RETURNING id, finding_signature, title, reason, created_by, created_at,
                      deactivated_at, deactivated_by
            "#,
        )
        .bind(id)
        .bind(deactivated_by)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SuppressionRepositoryError::NotFound(id))?;

        Ok(Self::row_to_suppression(&row))
    }

    fn row_to_suppression(row: &sqlx::postgres::PgRow) -> FindingSuppression {
        FindingSuppression {
            id: row.get("id"),
            finding_signature: row.get("finding_signature"),
            title: row.get("title"),
            reason: row.get("reason"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            deactivated_at: row.get("deactivated_at"),
            deactivated_by: row.get("deactivated_by"),
        }
    }
}
