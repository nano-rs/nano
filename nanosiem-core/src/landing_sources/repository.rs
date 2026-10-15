// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL reads of `landing_sources` / `landing_files` (364).
//! The tables are install-wide (open core is single-tenant).

use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use super::{clamp_files_limit, LandingFile, LandingSourceStatus};

#[derive(Error, Debug)]
pub enum LandingSourceRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct LandingSourceRepository {
    pool: PgPool,
}

fn row_to_status(row: &sqlx::postgres::PgRow) -> Result<LandingSourceStatus, sqlx::Error> {
    Ok(LandingSourceStatus {
        source_id: row.try_get("source_id")?,
        name: row.try_get("name")?,
        route_key: row.try_get("route_key")?,
        credential_id: row.try_get("credential_id")?,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
        revoked_at: row.try_get("revoked_at")?,
        files_accepted: row.try_get("files_accepted")?,
        files_refused: row.try_get("files_refused")?,
        files_in_progress: row.try_get("files_in_progress")?,
        rows_accepted: row.try_get("rows_accepted")?,
        rows_refused: row.try_get("rows_refused")?,
        redeliveries: row.try_get("redeliveries")?,
        last_seen_at: row.try_get("last_seen_at")?,
        last_finished_at: row.try_get("last_finished_at")?,
        last_refusal_reason: row.try_get("last_refusal_reason")?,
        last_refusal_at: row.try_get("last_refusal_at")?,
    })
}

fn row_to_file(row: &sqlx::postgres::PgRow) -> Result<LandingFile, sqlx::Error> {
    Ok(LandingFile {
        id: row.try_get("id")?,
        object_key: row.try_get("object_key")?,
        etag: row.try_get("etag")?,
        source_id: row.try_get("source_id")?,
        size_bytes: row.try_get("size_bytes")?,
        state: row.try_get("state")?,
        rows_accepted: row.try_get("rows_accepted")?,
        rows_refused: row.try_get("rows_refused")?,
        reason: row.try_get("reason")?,
        content_sha256: row.try_get("content_sha256")?,
        bronze_key: row.try_get("bronze_key")?,
        attempts: row.try_get("attempts")?,
        redeliveries: row.try_get("redeliveries")?,
        lease_until: row.try_get("lease_until")?,
        first_seen_at: row.try_get("first_seen_at")?,
        finished_at: row.try_get("finished_at")?,
    })
}

impl LandingSourceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Every bucket-drop source with its totals, active first, newest first.
    pub async fn list_sources(
        &self,
    ) -> Result<Vec<LandingSourceStatus>, LandingSourceRepositoryError> {
        let rows = sqlx::query(
            "SELECT s.source_id, ls.name, s.route_key, s.credential_id, s.state,
                    s.created_at, s.revoked_at,
                    COALESCE(f.files_accepted, 0)::BIGINT AS files_accepted,
                    COALESCE(f.files_refused, 0)::BIGINT AS files_refused,
                    COALESCE(f.files_in_progress, 0)::BIGINT AS files_in_progress,
                    COALESCE(f.rows_accepted, 0)::BIGINT AS rows_accepted,
                    COALESCE(f.rows_refused, 0)::BIGINT AS rows_refused,
                    COALESCE(f.redeliveries, 0)::BIGINT AS redeliveries,
                    f.last_seen_at, f.last_finished_at,
                    r.reason AS last_refusal_reason,
                    r.finished_at AS last_refusal_at
             FROM landing_sources s
             JOIN log_sources ls ON ls.id = s.source_id
             LEFT JOIN LATERAL (
                 SELECT COUNT(*) FILTER (WHERE state = 'accepted') AS files_accepted,
                        COUNT(*) FILTER (WHERE state = 'refused') AS files_refused,
                        COUNT(*) FILTER (WHERE state = 'claimed') AS files_in_progress,
                        SUM(rows_accepted) AS rows_accepted,
                        SUM(rows_refused) AS rows_refused,
                        SUM(redeliveries) AS redeliveries,
                        MAX(first_seen_at) AS last_seen_at,
                        MAX(finished_at) AS last_finished_at
                 FROM landing_files
                 WHERE source_id = s.source_id
             ) f ON TRUE
             LEFT JOIN LATERAL (
                 SELECT reason, COALESCE(finished_at, first_seen_at) AS finished_at
                 FROM landing_files
                 WHERE source_id = s.source_id AND state = 'refused'
                 ORDER BY finished_at DESC NULLS LAST, id DESC
                 LIMIT 1
             ) r ON TRUE
             ORDER BY (s.state = 'active') DESC, s.created_at DESC, s.source_id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_status).collect::<Result<_, _>>()?)
    }

    /// The source's most recent files, newest first. `limit` is clamped to
    /// `1..=200`; `state` must already be validated by the caller.
    pub async fn list_files(
        &self,
        source_id: Uuid,
        limit: Option<i64>,
        state: Option<&str>,
    ) -> Result<Vec<LandingFile>, LandingSourceRepositoryError> {
        let rows = sqlx::query(
            "SELECT id, object_key, etag, source_id, size_bytes, state, rows_accepted,
                    rows_refused, reason, content_sha256, bronze_key, attempts, redeliveries,
                    lease_until, first_seen_at, finished_at
             FROM landing_files
             WHERE source_id = $1 AND ($2::TEXT IS NULL OR state = $2)
             ORDER BY first_seen_at DESC, id DESC
             LIMIT $3",
        )
        .bind(source_id)
        .bind(state)
        .bind(clamp_files_limit(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_file).collect::<Result<_, _>>()?)
    }

    /// Whether `source_id` is a bucket-drop source.
    pub async fn source_exists(&self, source_id: Uuid) -> Result<bool, LandingSourceRepositoryError> {
        let row = sqlx::query("SELECT EXISTS (SELECT 1 FROM landing_sources WHERE source_id = $1)")
            .bind(source_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get(0)?)
    }
}
