// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled report repository (NAN-1793).
//!
//! PostgreSQL data access for report definitions, run history, and artifacts.
//! The distributed-claim methods mirror the scheduled-jobs repository
//! (SKIP LOCKED claim, generation-guarded renew/release) so exactly one replica
//! executes a due definition and a crashed node's claim is reclaimed.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use super::types::*;

#[derive(Debug, Error)]
pub enum ReportRepositoryError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Report definition not found: {0}")]
    DefinitionNotFound(Uuid),
    #[error("Report run not found: {0}")]
    RunNotFound(Uuid),
    #[error("Report artifact not found: {0}")]
    ArtifactNotFound(Uuid),
    #[error("Invalid report data: {0}")]
    InvalidData(String),
}

#[derive(Clone)]
pub struct ReportRepository {
    pool: PgPool,
}

impl ReportRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ==================== DEFINITION CRUD ====================

    pub async fn create_definition(
        &self,
        new: &NewReportDefinition,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<ReportDefinition, ReportRepositoryError> {
        let id = Uuid::now_v7();
        let row = sqlx::query_as::<_, ReportDefinitionRow>(
            r#"
            INSERT INTO report_definitions (
                id, name, description, source_type, source_query, saved_query_id,
                source_dashboard_id, time_range_seconds, cron_expression, owner_id,
                enabled, retention_runs, next_run_at
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            RETURNING *, NULL::text AS owner_name
            "#,
        )
        .bind(id)
        .bind(&new.name)
        .bind(&new.description)
        .bind(new.source_type.as_str())
        .bind(&new.source_query)
        .bind(new.saved_query_id)
        .bind(new.source_dashboard_id)
        .bind(new.time_range_seconds)
        .bind(&new.cron_expression)
        .bind(new.owner_id)
        .bind(new.enabled)
        .bind(new.retention_runs)
        .bind(next_run_at)
        .fetch_one(&self.pool)
        .await?;

        row.try_into().map_err(ReportRepositoryError::InvalidData)
    }

    pub async fn get_definition(
        &self,
        id: Uuid,
    ) -> Result<ReportDefinition, ReportRepositoryError> {
        let row = sqlx::query_as::<_, ReportDefinitionRow>(
            r#"
            SELECT rd.*, u.name AS owner_name
            FROM report_definitions rd
            LEFT JOIN users u ON u.id = rd.owner_id
            WHERE rd.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ReportRepositoryError::DefinitionNotFound(id))?;

        row.try_into().map_err(ReportRepositoryError::InvalidData)
    }

    /// List definitions. When `owner_id` is `Some`, scope to that owner; when
    /// `None`, return all (admin view).
    pub async fn list_definitions(
        &self,
        owner_id: Option<Uuid>,
    ) -> Result<Vec<ReportDefinition>, ReportRepositoryError> {
        let rows = if let Some(owner) = owner_id {
            sqlx::query_as::<_, ReportDefinitionRow>(
                r#"
                SELECT rd.*, u.name AS owner_name
                FROM report_definitions rd
                LEFT JOIN users u ON u.id = rd.owner_id
                WHERE rd.owner_id = $1
                ORDER BY rd.created_at DESC
                "#,
            )
            .bind(owner)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, ReportDefinitionRow>(
                r#"
                SELECT rd.*, u.name AS owner_name
                FROM report_definitions rd
                LEFT JOIN users u ON u.id = rd.owner_id
                ORDER BY rd.created_at DESC
                "#,
            )
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter()
            .map(|r| r.try_into().map_err(ReportRepositoryError::InvalidData))
            .collect()
    }

    pub async fn update_definition(
        &self,
        id: Uuid,
        update: &UpdateReportDefinition,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<ReportDefinition, ReportRepositoryError> {
        // COALESCE keeps unchanged fields; next_run_at only advances when a new
        // cron was supplied (caller passes Some).
        let description_set = update.description.is_some();
        let description_val = update.description.clone().flatten();
        let row = sqlx::query_as::<_, ReportDefinitionRow>(
            r#"
            UPDATE report_definitions SET
                name = COALESCE($2, name),
                description = CASE WHEN $3 THEN $4 ELSE description END,
                source_query = COALESCE($5, source_query),
                time_range_seconds = COALESCE($6, time_range_seconds),
                cron_expression = COALESCE($7, cron_expression),
                enabled = COALESCE($8, enabled),
                retention_runs = COALESCE($9, retention_runs),
                next_run_at = COALESCE($10, next_run_at),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *, NULL::text AS owner_name
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(description_set)
        .bind(description_val)
        .bind(&update.source_query)
        .bind(update.time_range_seconds)
        .bind(&update.cron_expression)
        .bind(update.enabled)
        .bind(update.retention_runs)
        .bind(next_run_at)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ReportRepositoryError::DefinitionNotFound(id))?;

        row.try_into().map_err(ReportRepositoryError::InvalidData)
    }

    pub async fn delete_definition(&self, id: Uuid) -> Result<bool, ReportRepositoryError> {
        let result = sqlx::query("DELETE FROM report_definitions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ==================== DISTRIBUTED CLAIMING ====================

    /// Atomically claim due definitions via SKIP LOCKED. Mirrors
    /// `SchedulerRepository::claim_due_jobs`. Reclaims stale claims older than
    /// `stale_timeout_secs`.
    pub async fn claim_due_definitions(
        &self,
        batch_size: i64,
        node_id: &str,
        stale_timeout_secs: i64,
    ) -> Result<Vec<ClaimedReportDefinition>, ReportRepositoryError> {
        let rows = sqlx::query_as::<_, ReportDefinitionRow>(
            r#"
            WITH claimable AS (
                SELECT id FROM report_definitions
                WHERE enabled = true
                  AND next_run_at IS NOT NULL AND next_run_at <= NOW()
                  AND (claimed_by IS NULL OR claimed_at < NOW() - make_interval(secs => $3))
                  -- F-32: never schedule a run for a definition whose OWNER is
                  -- no longer active — a disabled user's reports must not keep
                  -- executing (and producing downloadable artifacts) under the
                  -- owner's identity.
                  AND EXISTS (
                      SELECT 1 FROM users u
                      WHERE u.id = report_definitions.owner_id
                        AND u.status = 'active'
                  )
                ORDER BY next_run_at ASC
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE report_definitions SET
                claimed_by = $2,
                claimed_at = NOW(),
                claim_generation = report_definitions.claim_generation + 1,
                claim_run_id = COALESCE(report_definitions.claim_run_id, gen_random_uuid()),
                last_run_status = 'running'
            WHERE id IN (SELECT id FROM claimable)
            RETURNING *, NULL::text AS owner_name
            "#,
        )
        .bind(batch_size)
        .bind(node_id)
        .bind(stale_timeout_secs as f64)
        .fetch_all(&self.pool)
        .await?;

        let mut claimed = Vec::with_capacity(rows.len());
        for row in rows {
            let generation = row.claim_generation;
            let run_id = row
                .claim_run_id
                .ok_or_else(|| ReportRepositoryError::InvalidData("claim missing run id".into()))?;
            let definition: ReportDefinition =
                row.try_into().map_err(ReportRepositoryError::InvalidData)?;
            claimed.push(ClaimedReportDefinition {
                definition,
                claim_generation: generation,
                claim_run_id: run_id,
            });
        }
        Ok(claimed)
    }

    // NOTE: there is deliberately NO standalone `renew_claim` here. A bare
    // renew followed by a separate durable write is a TOCTOU race (the claim can
    // be lost in between, letting a paused node clobber the new owner's result).
    // The claim is re-asserted INSIDE the write transaction instead — see
    // `fence_claim_in_tx`, used by `store_run_success` / `store_run_failure`.

    /// Release a claim after execution (generation-guarded), recording status and
    /// the next scheduled run.
    #[allow(clippy::too_many_arguments)]
    pub async fn release_claim(
        &self,
        id: Uuid,
        node_id: &str,
        generation: i64,
        status: ReportRunStatus,
        error: Option<&str>,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<bool, ReportRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE report_definitions SET
                claimed_by = NULL,
                claimed_at = NULL,
                claim_run_id = NULL,
                last_run_at = NOW(),
                last_run_status = $4,
                last_run_error = $5,
                next_run_at = $6
            WHERE id = $1 AND claimed_by = $2 AND claim_generation = $3
            "#,
        )
        .bind(id)
        .bind(node_id)
        .bind(generation)
        .bind(status.as_str())
        .bind(error)
        .bind(next_run_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Release all claims held by a node (graceful shutdown); in-flight runs
    /// re-run on the next due tick.
    pub async fn release_all_claims(&self, node_id: &str) -> Result<u64, ReportRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE report_definitions
            SET claimed_by = NULL, claimed_at = NULL, last_run_status = NULL
            WHERE claimed_by = $1
            "#,
        )
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    // ==================== RUNS + ARTIFACTS ====================

    /// Create (or reset, on reclaim) the run row keyed by the durable run id.
    pub async fn upsert_run_running(
        &self,
        run_id: Uuid,
        definition_id: Uuid,
        triggered_by: &str,
    ) -> Result<(), ReportRepositoryError> {
        sqlx::query(
            r#"
            INSERT INTO report_runs (id, definition_id, status, triggered_by, started_at)
            VALUES ($1, $2, 'running', $3, NOW())
            ON CONFLICT (id) DO UPDATE
                SET status = 'running', started_at = NOW(),
                    finished_at = NULL, error = NULL
            "#,
        )
        .bind(run_id)
        .bind(definition_id)
        .bind(triggered_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Re-assert a distributed claim INSIDE an open transaction.
    ///
    /// This is the real fence for a durable write. A bare `renew_claim` followed
    /// by a separate write is a TOCTOU race: a paused node can renew, lose the
    /// claim to a stale-reclaim, and then still write — clobbering the new
    /// owner's result. Performing the guarded UPDATE inside the write transaction
    /// takes a row lock on the definition that is held until commit, so a
    /// concurrent reclaim BLOCKS instead of racing, and a caller whose generation
    /// is already stale sees `rows_affected() == 0` and rolls back.
    ///
    /// Returns `false` when the claim is no longer held by `(node_id, generation)`.
    async fn fence_claim_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        definition_id: Uuid,
        node_id: &str,
        generation: i64,
    ) -> Result<bool, ReportRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE report_definitions SET claimed_at = NOW()
            WHERE id = $1 AND claimed_by = $2 AND claim_generation = $3
            "#,
        )
        .bind(definition_id)
        .bind(node_id)
        .bind(generation)
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Persist a successful run and its artifacts in one transaction (replacing
    /// any artifacts from a prior reclaimed attempt).
    ///
    /// `fence` is `Some((node_id, generation))` for scheduled runs: the claim is
    /// re-asserted inside this transaction (see [`fence_claim_in_tx`]) and the
    /// whole write is abandoned — returning `Ok(false)` — if it was reclaimed.
    /// Manual runs pass `None` (they hold no claim; their run id is unique).
    #[allow(clippy::too_many_arguments)]
    pub async fn store_run_success(
        &self,
        run_id: Uuid,
        definition_id: Uuid,
        fence: Option<(&str, i64)>,
        duration_ms: i64,
        row_count: Option<i64>,
        result_truncated: bool,
        artifact_truncated: bool,
        artifacts: &[RenderedArtifact],
        // F-31: source_type manifest of the produced artifacts + completeness.
        source_types: &[String],
        source_types_complete: bool,
    ) -> Result<bool, ReportRepositoryError> {
        let mut tx = self.pool.begin().await?;

        if let Some((node_id, generation)) = fence {
            if !Self::fence_claim_in_tx(&mut tx, definition_id, node_id, generation).await? {
                tx.rollback().await?;
                return Ok(false);
            }
        }

        sqlx::query("DELETE FROM report_run_artifacts WHERE run_id = $1")
            .bind(run_id)
            .execute(&mut *tx)
            .await?;

        for artifact in artifacts {
            sqlx::query(
                r#"
                INSERT INTO report_run_artifacts
                    (id, run_id, kind, filename, content_type, size_bytes, content)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(run_id)
            .bind(&artifact.kind)
            .bind(&artifact.filename)
            .bind(&artifact.content_type)
            .bind(artifact.content.len() as i64)
            .bind(&artifact.content)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            r#"
            UPDATE report_runs SET
                status = 'success',
                finished_at = NOW(),
                duration_ms = $2,
                row_count = $3,
                truncated = $4,
                artifact_truncated = $5,
                source_types = $6,
                source_types_complete = $7,
                error = NULL
            WHERE id = $1
            "#,
        )
        .bind(run_id)
        .bind(duration_ms)
        .bind(row_count)
        .bind(result_truncated)
        .bind(artifact_truncated)
        .bind(source_types)
        .bind(source_types_complete)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    /// Record a failed run (no artifacts), under the same transactional claim
    /// fence as [`store_run_success`] — so a paused/panicking node cannot mark a
    /// run failed after a reclaiming replica has already completed it.
    /// Returns `false` when the claim was lost (nothing written).
    pub async fn store_run_failure(
        &self,
        run_id: Uuid,
        definition_id: Uuid,
        fence: Option<(&str, i64)>,
        duration_ms: i64,
        error: &str,
    ) -> Result<bool, ReportRepositoryError> {
        let mut tx = self.pool.begin().await?;

        if let Some((node_id, generation)) = fence {
            if !Self::fence_claim_in_tx(&mut tx, definition_id, node_id, generation).await? {
                tx.rollback().await?;
                return Ok(false);
            }
        }

        sqlx::query(
            r#"
            UPDATE report_runs SET
                status = 'failed',
                finished_at = NOW(),
                duration_ms = $2,
                error = $3
            WHERE id = $1
            "#,
        )
        .bind(run_id)
        .bind(duration_ms)
        .bind(error)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    /// Retention: keep the most-recent `keep` runs for a definition, delete the
    /// rest (artifacts cascade). Returns rows deleted.
    pub async fn prune_runs(
        &self,
        definition_id: Uuid,
        keep: i64,
    ) -> Result<u64, ReportRepositoryError> {
        let keep = keep.max(1);
        let result = sqlx::query(
            r#"
            DELETE FROM report_runs
            WHERE definition_id = $1
              AND id NOT IN (
                  SELECT id FROM report_runs
                  WHERE definition_id = $1
                  ORDER BY started_at DESC
                  LIMIT $2
              )
            "#,
        )
        .bind(definition_id)
        .bind(keep)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn list_runs(
        &self,
        definition_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ReportRun>, ReportRepositoryError> {
        let rows = sqlx::query_as::<_, ReportRunRow>(
            r#"
            SELECT * FROM report_runs
            WHERE definition_id = $1
            ORDER BY started_at DESC
            LIMIT $2
            "#,
        )
        .bind(definition_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(ReportRun::from).collect())
    }

    /// Fetch a single run with its artifact metadata (no bytes).
    pub async fn get_run(&self, run_id: Uuid) -> Result<ReportRun, ReportRepositoryError> {
        let row = sqlx::query_as::<_, ReportRunRow>("SELECT * FROM report_runs WHERE id = $1")
            .bind(run_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ReportRepositoryError::RunNotFound(run_id))?;
        let mut run = ReportRun::from(row);
        run.artifacts = self.list_artifacts_meta(run_id).await?;
        Ok(run)
    }

    pub async fn list_artifacts_meta(
        &self,
        run_id: Uuid,
    ) -> Result<Vec<ReportArtifactMeta>, ReportRepositoryError> {
        let rows = sqlx::query_as::<_, ReportArtifactMeta>(
            r#"
            SELECT id, run_id, kind, filename, content_type, size_bytes, created_at
            FROM report_run_artifacts
            WHERE run_id = $1
            ORDER BY created_at ASC, kind ASC
            "#,
        )
        .bind(run_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Fetch artifact bytes for download. Returns the artifact plus the
    /// [`ArtifactScope`] of its owning run (definition id + source_type manifest)
    /// so the handler can enforce BOTH ownership and F-31 source-scope access.
    pub async fn get_artifact_content(
        &self,
        artifact_id: Uuid,
    ) -> Result<(ReportArtifactContent, ArtifactScope), ReportRepositoryError> {
        let row = sqlx::query_as::<_, ArtifactContentRow>(
            r#"
            SELECT a.filename, a.content_type, a.content,
                   r.definition_id, r.source_types, r.source_types_complete
            FROM report_run_artifacts a
            JOIN report_runs r ON r.id = a.run_id
            WHERE a.id = $1
            "#,
        )
        .bind(artifact_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ReportRepositoryError::ArtifactNotFound(artifact_id))?;

        Ok((
            ReportArtifactContent {
                filename: row.filename,
                content_type: row.content_type,
                content: row.content,
            },
            ArtifactScope {
                definition_id: row.definition_id,
                source_types: row.source_types,
                source_types_complete: row.source_types_complete,
            },
        ))
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ArtifactContentRow {
    filename: String,
    content_type: String,
    content: Vec<u8>,
    definition_id: Uuid,
    #[sqlx(default)]
    source_types: Vec<String>,
    #[sqlx(default)]
    source_types_complete: bool,
}
