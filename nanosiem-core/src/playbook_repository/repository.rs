// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database repositories for external playbook repositories.

use chrono::NaiveDate;
use sqlx::{PgPool, QueryBuilder};
use thiserror::Error;
use uuid::Uuid;

use super::models::{
    NewPlaybookRepository, PlaybookImport, PlaybookRepository, RepositoryPlaybook,
    RepositoryPlaybookFilter, UpdatePlaybookRepository,
};

// =============================================================================
// Playbook Repository (the repositories table)
// =============================================================================

#[derive(Debug, Error)]
pub enum PlaybookRepoRepositoryError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Repository not found: {0}")]
    NotFound(Uuid),

    #[error("Repository already exists: {0}")]
    AlreadyExists(String),
}

#[derive(Clone)]
pub struct PlaybookRepoRepository {
    pool: PgPool,
}

impl PlaybookRepoRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        repo: &NewPlaybookRepository,
        created_by: Option<Uuid>,
    ) -> Result<PlaybookRepository, PlaybookRepoRepositoryError> {
        let slug = repo.slug.clone().unwrap_or_else(|| {
            repo.url
                .trim_end_matches('/')
                .trim_end_matches(".git")
                .split("github.com/")
                .last()
                .unwrap_or(&repo.name)
                .to_lowercase()
        });

        let result = sqlx::query_as::<_, PlaybookRepository>(
            r#"
            INSERT INTO playbook_repositories (
                name, slug, description, url, branch, playbooks_path,
                auto_sync_enabled, sync_interval_hours, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(&repo.name)
        .bind(&slug)
        .bind(&repo.description)
        .bind(&repo.url)
        .bind(repo.branch.as_deref().unwrap_or("main"))
        .bind(repo.playbooks_path.as_deref().unwrap_or(""))
        .bind(repo.auto_sync_enabled.unwrap_or(false))
        .bind(repo.sync_interval_hours.unwrap_or(24))
        .bind(created_by)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("playbook_repositories_name_key")
                    || db_err.constraint() == Some("playbook_repositories_slug_key")
                {
                    return PlaybookRepoRepositoryError::AlreadyExists(repo.name.clone());
                }
            }
            PlaybookRepoRepositoryError::Database(e)
        })?;

        Ok(result)
    }

    pub async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<PlaybookRepository, PlaybookRepoRepositoryError> {
        sqlx::query_as::<_, PlaybookRepository>("SELECT * FROM playbook_repositories WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(PlaybookRepoRepositoryError::NotFound(id))
    }

    pub async fn find_by_slug(
        &self,
        slug: &str,
    ) -> Result<PlaybookRepository, PlaybookRepoRepositoryError> {
        sqlx::query_as::<_, PlaybookRepository>(
            "SELECT * FROM playbook_repositories WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| PlaybookRepoRepositoryError::NotFound(Uuid::nil()))
    }

    pub async fn list(&self) -> Result<Vec<PlaybookRepository>, PlaybookRepoRepositoryError> {
        // Clean up stuck syncing statuses first
        let _ = sqlx::query(
            r#"
            UPDATE playbook_repositories
            SET last_sync_status = 'failed',
                last_sync_error = 'Sync timed out or was interrupted',
                updated_at = NOW()
            WHERE last_sync_status = 'syncing'
              AND updated_at < NOW() - INTERVAL '10 minutes'
            "#,
        )
        .execute(&self.pool)
        .await;

        let rows = sqlx::query_as::<_, PlaybookRepository>(
            "SELECT * FROM playbook_repositories ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdatePlaybookRepository,
    ) -> Result<PlaybookRepository, PlaybookRepoRepositoryError> {
        let repo = self.find_by_id(id).await?;

        let result = sqlx::query_as::<_, PlaybookRepository>(
            r#"
            UPDATE playbook_repositories SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                branch = COALESCE($4, branch),
                playbooks_path = COALESCE($5, playbooks_path),
                auto_sync_enabled = COALESCE($6, auto_sync_enabled),
                sync_interval_hours = COALESCE($7, sync_interval_hours),
                enabled = COALESCE($8, enabled),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(update.name.as_ref().unwrap_or(&repo.name))
        .bind(update.description.as_ref().or(repo.description.as_ref()))
        .bind(update.branch.as_ref().unwrap_or(&repo.branch))
        .bind(update.playbooks_path.as_ref().or(repo.playbooks_path.as_ref()))
        .bind(update.auto_sync_enabled.or(repo.auto_sync_enabled))
        .bind(update.sync_interval_hours.or(repo.sync_interval_hours))
        .bind(update.enabled.or(repo.enabled))
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn update_sync_status(
        &self,
        id: Uuid,
        status: &str,
        commit: Option<&str>,
        playbook_count: Option<i32>,
        error: Option<&str>,
    ) -> Result<(), PlaybookRepoRepositoryError> {
        sqlx::query(
            r#"
            UPDATE playbook_repositories SET
                last_sync_status = $2,
                last_sync_commit = COALESCE($3, last_sync_commit),
                last_synced_at = CASE WHEN $2 = 'success' THEN NOW() ELSE last_synced_at END,
                playbook_count = COALESCE($4, playbook_count),
                last_sync_error = $5,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(commit)
        .bind(playbook_count)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), PlaybookRepoRepositoryError> {
        let result = sqlx::query("DELETE FROM playbook_repositories WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(PlaybookRepoRepositoryError::NotFound(id));
        }
        Ok(())
    }
}

// =============================================================================
// Repository Playbooks (cached content)
// =============================================================================

#[derive(Debug, Error)]
pub enum RepositoryPlaybooksRepositoryError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Playbook not found: {0}")]
    NotFound(String),
}

#[derive(Clone)]
pub struct RepositoryPlaybooksRepository {
    pool: PgPool,
}

impl RepositoryPlaybooksRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upsert(
        &self,
        repository_id: Uuid,
        file_path: &str,
        file_sha: Option<&str>,
        raw_content: &str,
        title: Option<&str>,
        subtitle: Option<&str>,
        category: Option<&str>,
        match_signals: Option<&[String]>,
        tags: Option<&[String]>,
        owner_team: Option<&str>,
        authored_date: Option<NaiveDate>,
        danger_policy: Option<&serde_json::Value>,
        review_cadence: Option<&str>,
        scope: Option<&str>,
        parse_status: &str,
        parse_error: Option<&str>,
        step_count: Option<i32>,
    ) -> Result<RepositoryPlaybook, RepositoryPlaybooksRepositoryError> {
        let result = sqlx::query_as::<_, RepositoryPlaybook>(
            r#"
            INSERT INTO repository_playbooks (
                repository_id, file_path, file_sha, raw_content,
                title, subtitle, category, match_signals, tags,
                owner_team, authored_date, danger_policy, review_cadence, scope,
                parse_status, parse_error, step_count
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            ON CONFLICT (repository_id, file_path) DO UPDATE SET
                file_sha = EXCLUDED.file_sha,
                raw_content = EXCLUDED.raw_content,
                title = EXCLUDED.title,
                subtitle = EXCLUDED.subtitle,
                category = EXCLUDED.category,
                match_signals = EXCLUDED.match_signals,
                tags = EXCLUDED.tags,
                owner_team = EXCLUDED.owner_team,
                authored_date = EXCLUDED.authored_date,
                danger_policy = EXCLUDED.danger_policy,
                review_cadence = EXCLUDED.review_cadence,
                scope = EXCLUDED.scope,
                parse_status = EXCLUDED.parse_status,
                parse_error = EXCLUDED.parse_error,
                step_count = EXCLUDED.step_count,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(repository_id)
        .bind(file_path)
        .bind(file_sha)
        .bind(raw_content)
        .bind(title)
        .bind(subtitle)
        .bind(category)
        .bind(match_signals.map(|s| s.to_vec()))
        .bind(tags.map(|s| s.to_vec()))
        .bind(owner_team)
        .bind(authored_date)
        .bind(danger_policy)
        .bind(review_cadence)
        .bind(scope)
        .bind(parse_status)
        .bind(parse_error)
        .bind(step_count)
        .fetch_one(&self.pool)
        .await?;
        Ok(result)
    }

    pub async fn find_by_path(
        &self,
        repository_id: Uuid,
        file_path: &str,
    ) -> Result<RepositoryPlaybook, RepositoryPlaybooksRepositoryError> {
        sqlx::query_as::<_, RepositoryPlaybook>(
            "SELECT * FROM repository_playbooks WHERE repository_id = $1 AND file_path = $2",
        )
        .bind(repository_id)
        .bind(file_path)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| RepositoryPlaybooksRepositoryError::NotFound(file_path.to_string()))
    }

    pub async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<RepositoryPlaybook, RepositoryPlaybooksRepositoryError> {
        sqlx::query_as::<_, RepositoryPlaybook>("SELECT * FROM repository_playbooks WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| RepositoryPlaybooksRepositoryError::NotFound(id.to_string()))
    }

    pub async fn list(
        &self,
        repository_id: Uuid,
        filter: &RepositoryPlaybookFilter,
    ) -> Result<Vec<RepositoryPlaybook>, RepositoryPlaybooksRepositoryError> {
        let mut qb: QueryBuilder<sqlx::Postgres> =
            QueryBuilder::new("SELECT * FROM repository_playbooks WHERE repository_id = ");
        qb.push_bind(repository_id);
        if let Some(ref cat) = filter.category {
            qb.push(" AND category = ").push_bind(cat.clone());
        }
        if let Some(ref ps) = filter.parse_status {
            qb.push(" AND parse_status = ").push_bind(ps.clone());
        }
        if let Some(ref s) = filter.search {
            let pattern = format!("%{}%", s);
            qb.push(" AND (COALESCE(title, '') ILIKE ").push_bind(pattern.clone());
            qb.push(" OR file_path ILIKE ").push_bind(pattern);
            qb.push(")");
        }
        qb.push(" ORDER BY file_path ASC");
        let limit = filter.limit.unwrap_or(500).clamp(1, 5000);
        let offset = filter.offset.unwrap_or(0).max(0);
        qb.push(" LIMIT ").push_bind(limit);
        qb.push(" OFFSET ").push_bind(offset);

        let rows: Vec<RepositoryPlaybook> = qb.build_query_as().fetch_all(&self.pool).await?;
        Ok(rows)
    }

    pub async fn delete_by_repository(
        &self,
        repository_id: Uuid,
    ) -> Result<i64, RepositoryPlaybooksRepositoryError> {
        let result = sqlx::query("DELETE FROM repository_playbooks WHERE repository_id = $1")
            .bind(repository_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() as i64)
    }

    pub async fn delete_not_in_paths(
        &self,
        repository_id: Uuid,
        paths: &[String],
    ) -> Result<i64, RepositoryPlaybooksRepositoryError> {
        if paths.is_empty() {
            return self.delete_by_repository(repository_id).await;
        }
        let result = sqlx::query(
            "DELETE FROM repository_playbooks WHERE repository_id = $1 AND file_path != ALL($2)",
        )
        .bind(repository_id)
        .bind(paths)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() as i64)
    }
}

// =============================================================================
// Playbook Imports
// =============================================================================

#[derive(Debug, Error)]
pub enum PlaybookImportsRepositoryError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Import not found: {0}")]
    NotFound(Uuid),

    #[error("Import already exists")]
    AlreadyExists,
}

#[derive(Clone)]
pub struct PlaybookImportsRepository {
    pool: PgPool,
}

impl PlaybookImportsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        repository_playbook_id: Uuid,
        playbook_id: Uuid,
        import_type: &str,
        imported_by: Option<Uuid>,
        imported_commit: Option<&str>,
    ) -> Result<PlaybookImport, PlaybookImportsRepositoryError> {
        let result = sqlx::query_as::<_, PlaybookImport>(
            r#"
            INSERT INTO playbook_imports (
                repository_playbook_id, playbook_id, import_type,
                imported_by, imported_commit, last_sync_commit
            )
            VALUES ($1, $2, $3, $4, $5, $5)
            RETURNING *
            "#,
        )
        .bind(repository_playbook_id)
        .bind(playbook_id)
        .bind(import_type)
        .bind(imported_by)
        .bind(imported_commit)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint().is_some() {
                    return PlaybookImportsRepositoryError::AlreadyExists;
                }
            }
            PlaybookImportsRepositoryError::Database(e)
        })?;

        Ok(result)
    }

    pub async fn find_by_repository_playbook(
        &self,
        repository_playbook_id: Uuid,
    ) -> Result<Vec<PlaybookImport>, PlaybookImportsRepositoryError> {
        let rows = sqlx::query_as::<_, PlaybookImport>(
            "SELECT * FROM playbook_imports WHERE repository_playbook_id = $1",
        )
        .bind(repository_playbook_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn mark_upstream_changed(
        &self,
        repository_playbook_id: Uuid,
    ) -> Result<u64, PlaybookImportsRepositoryError> {
        let result = sqlx::query(
            "UPDATE playbook_imports SET upstream_changed = TRUE WHERE repository_playbook_id = $1",
        )
        .bind(repository_playbook_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}
