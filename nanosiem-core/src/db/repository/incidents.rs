// SPDX-License-Identifier: AGPL-3.0-or-later

//! Incident repository (NAN-417).
//!
//! Persists the parent-container grouping for cases. An incident is a thin
//! row in `public.incidents`; cases attach via `cases.incident_id`.
//! See migration `153_incidents_schema.sql` for the storage layout.

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::models::incident::{Incident, NewIncident};

/// Repository errors for incident operations. Mirrors the shape of
/// `CaseRepositoryError` so callers can compose the two the same way.
#[derive(Error, Debug)]
pub enum IncidentRepositoryError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Incident not found: {0}")]
    NotFound(Uuid),
    #[error("Access denied")]
    AccessDenied,
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),
}

/// Repository for incident CRUD + case attach/detach operations.
#[derive(Clone)]
pub struct IncidentRepository {
    pool: PgPool,
}

impl IncidentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new incident and attach the given cases in a single
    /// transaction. Returns the inserted incident row.
    ///
    /// NOTE: The caller (service layer) is responsible for verifying that
    /// every `case_id` in `new.case_ids` is visible to the acting user.
    /// This repo method does not re-check visibility — it just writes.
    pub async fn create_from_cases(
        &self,
        new: &NewIncident,
    ) -> Result<Incident, IncidentRepositoryError> {
        let mut tx = self.pool.begin().await?;

        let inserted = sqlx::query_as::<_, Incident>(
            r#"
            INSERT INTO incidents (
                title, severity, source, detector, confidence, signature,
                tags, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(&new.title)
        .bind(&new.severity)
        .bind(&new.source)
        .bind(&new.detector)
        .bind(new.confidence)
        .bind(&new.signature)
        .bind(&new.tags)
        .bind(new.created_by)
        .fetch_one(&mut *tx)
        .await?;

        if !new.case_ids.is_empty() {
            sqlx::query(
                r#"
                UPDATE cases
                   SET incident_id = $1,
                       updated_at = NOW()
                 WHERE id = ANY($2::uuid[])
                "#,
            )
            .bind(inserted.id)
            .bind(&new.case_ids)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(inserted)
    }

    /// Find an incident by id.
    pub async fn find_by_id(&self, id: Uuid) -> Result<Incident, IncidentRepositoryError> {
        let result = sqlx::query_as::<_, Incident>(
            r#"SELECT * FROM incidents WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(IncidentRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// List incidents with optional status filter, paginated.
    pub async fn list(
        &self,
        status_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Incident>, IncidentRepositoryError> {
        let results = sqlx::query_as::<_, Incident>(
            r#"
            SELECT *
              FROM incidents
             WHERE ($1::text IS NULL OR status = $1)
             ORDER BY opened_at DESC
             LIMIT $2 OFFSET $3
            "#,
        )
        .bind(status_filter)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Count incidents matching the optional status filter.
    pub async fn count(
        &self,
        status_filter: Option<&str>,
    ) -> Result<i64, IncidentRepositoryError> {
        let (count,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::bigint
              FROM incidents
             WHERE ($1::text IS NULL OR status = $1)
            "#,
        )
        .bind(status_filter)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Attach a case to an incident. Errors when the case is already attached
    /// to a different incident — the caller must explicitly remove-then-add if
    /// they want to re-parent.
    pub async fn add_case(
        &self,
        incident_id: Uuid,
        case_id: Uuid,
    ) -> Result<(), IncidentRepositoryError> {
        // First make sure the incident exists (otherwise the FK update would
        // silently UPDATE 0 rows and we'd return Ok(()) for a bogus incident).
        let _ = self.find_by_id(incident_id).await?;

        let current: Option<Option<Uuid>> = sqlx::query_scalar(
            r#"SELECT incident_id FROM cases WHERE id = $1"#,
        )
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?;

        match current {
            None => {
                return Err(IncidentRepositoryError::InvalidStateTransition(format!(
                    "case {case_id} not found"
                )));
            }
            Some(Some(existing)) if existing != incident_id => {
                return Err(IncidentRepositoryError::InvalidStateTransition(format!(
                    "case {case_id} is already attached to incident {existing}"
                )));
            }
            Some(Some(_)) => {
                // Already in this incident — idempotent success.
                return Ok(());
            }
            Some(None) => {}
        }

        sqlx::query(
            r#"
            UPDATE cases
               SET incident_id = $1,
                   updated_at = NOW()
             WHERE id = $2
            "#,
        )
        .bind(incident_id)
        .bind(case_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Detach a case from an incident. Scoped by `incident_id` so a stale
    /// call from a different incident's UI doesn't drop a case from the
    /// wrong parent.
    pub async fn remove_case(
        &self,
        incident_id: Uuid,
        case_id: Uuid,
    ) -> Result<(), IncidentRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE cases
               SET incident_id = NULL,
                   updated_at = NOW()
             WHERE id = $1
               AND incident_id = $2
            "#,
        )
        .bind(case_id)
        .bind(incident_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(IncidentRepositoryError::InvalidStateTransition(format!(
                "case {case_id} is not attached to incident {incident_id}"
            )));
        }

        Ok(())
    }

    /// List the child-case ids for an incident. Callers hydrate to
    /// `CaseWithDetails` via `CaseRepository::find_by_id_for_user`.
    pub async fn list_child_cases(
        &self,
        incident_id: Uuid,
    ) -> Result<Vec<Uuid>, IncidentRepositoryError> {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            r#"
            SELECT id
              FROM cases
             WHERE incident_id = $1
             ORDER BY created_at ASC
            "#,
        )
        .bind(incident_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(ids)
    }
}
