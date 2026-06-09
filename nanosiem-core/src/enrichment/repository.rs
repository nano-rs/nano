// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment repository for database operations

use sqlx::PgPool;
use thiserror::Error;
use tracing::instrument;

use super::types::*;

#[derive(Error, Debug)]
pub enum EnrichmentRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Source not found: {0}")]
    SourceNotFound(String),
}

// NAN-1112: the `IocError` variant + `From<IocRepositoryError>` impl
// were removed alongside the PG-backed `IocRepository` itself. CH-side
// IOC lookups now flow through `enrichment::ioc::IocLookupError` and
// don't go via this error type.

/// Repository for enrichment data operations
#[derive(Clone)]
pub struct EnrichmentRepository {
    pool: PgPool,
}

impl EnrichmentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the underlying database pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // ========================================================================
    // Enrichment Source Operations
    // ========================================================================

    /// List all enrichment sources
    #[instrument(skip(self))]
    pub async fn list_sources(&self) -> Result<Vec<EnrichmentSource>, EnrichmentRepositoryError> {
        let sources =
            sqlx::query_as::<_, EnrichmentSource>("SELECT * FROM enrichment_sources ORDER BY name")
                .fetch_all(&self.pool)
                .await?;

        Ok(sources)
    }

    /// Get an enrichment source by ID
    #[instrument(skip(self))]
    pub async fn get_source(
        &self,
        id: &str,
    ) -> Result<EnrichmentSource, EnrichmentRepositoryError> {
        sqlx::query_as::<_, EnrichmentSource>("SELECT * FROM enrichment_sources WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| EnrichmentRepositoryError::SourceNotFound(id.to_string()))
    }

    /// Create or update an enrichment source
    #[instrument(skip(self))]
    pub async fn upsert_source(
        &self,
        config: &EnrichmentSourceConfig,
    ) -> Result<EnrichmentSource, EnrichmentRepositoryError> {
        let source = sqlx::query_as::<_, EnrichmentSource>(
            r#"
            INSERT INTO enrichment_sources (id, name, source_type, description, download_url, config, enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                source_type = EXCLUDED.source_type,
                description = EXCLUDED.description,
                download_url = EXCLUDED.download_url,
                config = EXCLUDED.config,
                enabled = EXCLUDED.enabled,
                updated_at = NOW()
            RETURNING *
            "#
        )
        .bind(&config.id)
        .bind(&config.name)
        .bind(&config.source_type)
        .bind(&config.description)
        .bind(&config.download_url)
        .bind(&config.config)
        .bind(config.enabled)
        .fetch_one(&self.pool)
        .await?;

        Ok(source)
    }

    /// Update sync status for a source
    #[instrument(skip(self))]
    pub async fn update_sync_status(
        &self,
        source_id: &str,
        status: SyncStatus,
        error: Option<&str>,
        record_count: Option<i64>,
        file_hash: Option<&str>,
    ) -> Result<(), EnrichmentRepositoryError> {
        sqlx::query(
            r#"
            UPDATE enrichment_sources SET
                last_sync_at = CASE WHEN $2 = 'success' THEN NOW() ELSE last_sync_at END,
                last_sync_status = $2,
                last_sync_error = $3,
                record_count = COALESCE($4, record_count),
                file_hash = COALESCE($5, file_hash),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(source_id)
        .bind(status.to_string())
        .bind(error)
        .bind(record_count)
        .bind(file_hash)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Reset sources stuck in `in_progress` to `pending` for an immediate
    /// re-sync. Called once at scheduler startup (NAN-1280).
    ///
    /// A freshly started process holds no in-flight sync task (the scheduler's
    /// per-process `running` guard is empty at boot), so any source still marked
    /// `in_progress` in Postgres is orphaned from a previous process killed
    /// mid-sync — e.g. a deploy, since graceful shutdown aborts the
    /// fire-and-forget sync task after 30s and it never writes a terminal
    /// status. Without this, recovery waits out the 60-min stale-detection
    /// window plus the 60-min failure cooldown (~2h).
    ///
    /// We re-queue (`pending`) rather than mark `failed`: a restart is not a
    /// feed failure, so the anti-hammer failure cooldown is inappropriate.
    /// `needs_sync` honors `pending` immediately, so the next scheduler tick
    /// re-runs it. The interruption is recorded in `last_sync_error` for the
    /// audit trail. Returns the ids that were reset.
    ///
    /// Safe against clobbering a live sibling sync: the enrichment scheduler is
    /// leader-only (advisory-lock election in `jobs`), so at most one instance
    /// runs it.
    #[instrument(skip(self))]
    pub async fn reset_interrupted_syncs(
        &self,
    ) -> Result<Vec<String>, EnrichmentRepositoryError> {
        let ids: Vec<String> = sqlx::query_scalar(
            r#"
            UPDATE enrichment_sources SET
                last_sync_status = $1,
                last_sync_error = $2,
                updated_at = NOW()
            WHERE last_sync_status = 'in_progress'
            RETURNING id
            "#,
        )
        .bind(SyncStatus::Pending.to_string())
        .bind("Previous sync interrupted by service restart")
        .fetch_all(&self.pool)
        .await?;

        Ok(ids)
    }

    /// Enable or disable an enrichment source
    #[instrument(skip(self))]
    pub async fn set_source_enabled(
        &self,
        source_id: &str,
        enabled: bool,
    ) -> Result<(), EnrichmentRepositoryError> {
        let result = sqlx::query(
            "UPDATE enrichment_sources SET enabled = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(source_id)
        .bind(enabled)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(EnrichmentRepositoryError::SourceNotFound(
                source_id.to_string(),
            ));
        }

        Ok(())
    }

    /// Update source configuration (for auto-sync settings, etc.)
    #[instrument(skip(self, config))]
    pub async fn update_source_config(
        &self,
        source_id: &str,
        config: serde_json::Value,
    ) -> Result<(), EnrichmentRepositoryError> {
        let result = sqlx::query(
            "UPDATE enrichment_sources SET config = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(source_id)
        .bind(config)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(EnrichmentRepositoryError::SourceNotFound(
                source_id.to_string(),
            ));
        }

        Ok(())
    }

    /// Update source download URL
    #[instrument(skip(self))]
    pub async fn update_source_url(
        &self,
        source_id: &str,
        url: &str,
    ) -> Result<(), EnrichmentRepositoryError> {
        let result = sqlx::query(
            "UPDATE enrichment_sources SET download_url = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(source_id)
        .bind(url)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(EnrichmentRepositoryError::SourceNotFound(
                source_id.to_string(),
            ));
        }

        Ok(())
    }

    // ========================================================================
    // Statistics (config side)
    // ========================================================================
    //
    // NAN-1117: the IP enrichment *payload* (lookup_ip / lookup_ips_bulk /
    // staging insert+swap / bulk insert) moved to ClickHouse along with the
    // ip_enrichment_dict source. Those PG methods were deleted. The repository
    // is now PG-only for enrichment_sources config/metadata. Record counting
    // lives on EnrichmentService against ClickHouse; this repo only owns the
    // enabled-source config count.

    /// Count enabled enrichment sources (config/metadata stays in PG).
    #[instrument(skip(self))]
    pub async fn count_enabled_sources(&self) -> Result<i64, EnrichmentRepositoryError> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM enrichment_sources WHERE enabled = true")
                .fetch_one(&self.pool)
                .await?;
        Ok(count)
    }
}

/// Enrichment statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct EnrichmentStats {
    pub enabled_sources: i64,
    pub total_ip_records: i64,
}
