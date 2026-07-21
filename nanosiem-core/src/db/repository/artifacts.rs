// SPDX-License-Identifier: AGPL-3.0-or-later

//! Artifact-analysis store repository (NAN-1977).
//!
//! CRUD for the SHARED artifact collection. There is no per-user visibility
//! model — every holder of `artifacts:view` sees the whole store — so `list`
//! returns all rows (a summary projection without the heavy specimen text) and
//! access is gated entirely by the RBAC permission at the handler.

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::models::{Artifact, ArtifactSummary, NewArtifact, UpdateArtifact};

/// Default cap on how many artifacts `list` returns (newest first).
pub const ARTIFACT_LIST_LIMIT: i64 = 500;

#[derive(Error, Debug)]
pub enum ArtifactRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Artifact not found: {0}")]
    NotFound(Uuid),
}

/// Repository for artifact-analysis store operations.
#[derive(Clone)]
pub struct ArtifactRepository {
    pool: PgPool,
}

impl ArtifactRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Add an artifact. `created_by` is the authenticated user (never
    /// client-supplied); `None` leaves the column NULL (the column is nullable
    /// with `ON DELETE SET NULL`).
    pub async fn create(
        &self,
        new: &NewArtifact,
        created_by: Option<Uuid>,
    ) -> Result<Artifact, ArtifactRepositoryError> {
        let artifact = sqlx::query_as::<_, Artifact>(
            r#"
            INSERT INTO artifacts (
                name, sha256, size_bytes, source, verdict, score, original,
                deobfuscated, passes, iocs, mitre, behavior, layer_chain,
                agent_note, entropy, summary, status_line, case_tag, correlation,
                analysis_secs, engine, case_id, created_by, static_analysis
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                    $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
            RETURNING *
            "#,
        )
        .bind(&new.name)
        .bind(&new.sha256)
        .bind(new.size_bytes)
        .bind(&new.source)
        .bind(&new.verdict)
        .bind(new.score)
        .bind(&new.original)
        .bind(&new.deobfuscated)
        .bind(&new.passes)
        .bind(&new.iocs)
        .bind(&new.mitre)
        .bind(&new.behavior)
        .bind(&new.layer_chain)
        .bind(&new.agent_note)
        .bind(new.entropy)
        .bind(&new.summary)
        .bind(&new.status_line)
        .bind(&new.case_tag)
        .bind(&new.correlation)
        .bind(new.analysis_secs)
        .bind(&new.engine)
        .bind(new.case_id)
        .bind(created_by)
        .bind(&new.static_analysis)
        .fetch_one(&self.pool)
        .await?;

        Ok(artifact)
    }

    /// List the whole shared store, newest first — summary projection (no
    /// `original` / `deobfuscated` bodies).
    pub async fn list(&self) -> Result<Vec<ArtifactSummary>, ArtifactRepositoryError> {
        let artifacts = sqlx::query_as::<_, ArtifactSummary>(
            r#"
            SELECT id, name, sha256, size_bytes, source, verdict, score, passes,
                   iocs, mitre, behavior, layer_chain, agent_note, entropy,
                   summary, status_line, case_tag, correlation, analysis_secs,
                   engine, static_analysis, case_id, created_by, created_at,
                   updated_at
            FROM artifacts
            ORDER BY created_at DESC
            LIMIT $1
            "#,
        )
        .bind(ARTIFACT_LIST_LIMIT)
        .fetch_all(&self.pool)
        .await?;

        Ok(artifacts)
    }

    /// Fetch a single artifact fully hydrated (includes the specimen text).
    pub async fn find_by_id(&self, id: Uuid) -> Result<Artifact, ArtifactRepositoryError> {
        let artifact = sqlx::query_as::<_, Artifact>(r#"SELECT * FROM artifacts WHERE id = $1"#)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ArtifactRepositoryError::NotFound(id))?;

        Ok(artifact)
    }

    /// Apply a partial update (analysis write-back / sha256 patch). Omitted
    /// fields (`NULL` bind) leave their column untouched via COALESCE.
    pub async fn update(
        &self,
        id: Uuid,
        patch: &UpdateArtifact,
    ) -> Result<Artifact, ArtifactRepositoryError> {
        let artifact = sqlx::query_as::<_, Artifact>(
            r#"
            UPDATE artifacts SET
                sha256        = COALESCE($2, sha256),
                verdict       = COALESCE($3, verdict),
                score         = COALESCE($4, score),
                deobfuscated  = COALESCE($5, deobfuscated),
                passes        = COALESCE($6, passes),
                iocs          = COALESCE($7, iocs),
                mitre         = COALESCE($8, mitre),
                behavior      = COALESCE($9, behavior),
                layer_chain   = COALESCE($10, layer_chain),
                agent_note    = COALESCE($11, agent_note),
                entropy       = COALESCE($12, entropy),
                summary       = COALESCE($13, summary),
                status_line   = COALESCE($14, status_line),
                case_tag      = COALESCE($15, case_tag),
                correlation   = COALESCE($16, correlation),
                analysis_secs = COALESCE($17, analysis_secs),
                engine        = COALESCE($18, engine),
                case_id       = COALESCE($19, case_id),
                static_analysis = COALESCE($20, static_analysis),
                updated_at    = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&patch.sha256)
        .bind(&patch.verdict)
        .bind(patch.score)
        .bind(&patch.deobfuscated)
        .bind(&patch.passes)
        .bind(&patch.iocs)
        .bind(&patch.mitre)
        .bind(&patch.behavior)
        .bind(&patch.layer_chain)
        .bind(&patch.agent_note)
        .bind(patch.entropy)
        .bind(&patch.summary)
        .bind(&patch.status_line)
        .bind(&patch.case_tag)
        .bind(&patch.correlation)
        .bind(patch.analysis_secs)
        .bind(&patch.engine)
        .bind(patch.case_id)
        .bind(&patch.static_analysis)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ArtifactRepositoryError::NotFound(id))?;

        Ok(artifact)
    }

    /// Delete an artifact from the store.
    pub async fn delete(&self, id: Uuid) -> Result<(), ArtifactRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM artifacts WHERE id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(ArtifactRepositoryError::NotFound(id));
        }

        Ok(())
    }
}
