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

/// Both kinds — mirrors the `playbook_repositories.allowed_kinds` column
/// default from migration 9000057, for the create path that names the column.
fn default_allowed_kinds() -> Vec<String> {
    vec!["response".to_string(), "hunt".to_string()]
}

// =============================================================================
// Playbook Repository (the repositories table)
// =============================================================================

// NAN-1618: consolidated into `crate::db::RepoError` (alias preserves the
// public name and the variants matched in service/crud.rs).
pub use crate::db::repo_error::RepoError as PlaybookRepoRepositoryError;

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
        let slug = crate::db::repo_store::slug_from_url(&repo.url, &repo.name, repo.slug.as_deref());

        let result = sqlx::query_as::<_, PlaybookRepository>(
            r#"
            INSERT INTO playbook_repositories (
                name, slug, description, url, branch, playbooks_path,
                auto_sync_enabled, sync_interval_hours, allowed_kinds, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
        .bind(
            repo.allowed_kinds
                .clone()
                .unwrap_or_else(default_allowed_kinds),
        )
        .bind(created_by)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            crate::db::repo_store::map_unique_violation(e, "playbook_repositories", &repo.name)
        })?;

        Ok(result)
    }

    pub async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<PlaybookRepository, PlaybookRepoRepositoryError> {
        crate::db::repo_store::find_by_id(&self.pool, "playbook_repositories", id).await
    }

    pub async fn find_by_slug(
        &self,
        slug: &str,
    ) -> Result<PlaybookRepository, PlaybookRepoRepositoryError> {
        crate::db::repo_store::find_by_slug(&self.pool, "playbook_repositories", slug).await
    }

    pub async fn list(&self) -> Result<Vec<PlaybookRepository>, PlaybookRepoRepositoryError> {
        crate::db::repo_store::list(&self.pool, "playbook_repositories").await
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
                allowed_kinds = COALESCE($9, allowed_kinds),
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
        .bind(update.allowed_kinds.clone())
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
        crate::db::repo_store::update_sync_status(
            &self.pool,
            "playbook_repositories",
            "playbook_count",
            id,
            status,
            commit,
            playbook_count,
            error,
        )
        .await
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), PlaybookRepoRepositoryError> {
        crate::db::repo_store::delete(&self.pool, "playbook_repositories", id).await
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
        // From the file's own frontmatter. Never derived from `file_path`.
        kind: &str,
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
                repository_id, file_path, file_sha, raw_content, kind,
                title, subtitle, category, match_signals, tags,
                owner_team, authored_date, danger_policy, review_cadence, scope,
                parse_status, parse_error, step_count
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
            ON CONFLICT (repository_id, file_path) DO UPDATE SET
                file_sha = EXCLUDED.file_sha,
                raw_content = EXCLUDED.raw_content,
                kind = EXCLUDED.kind,
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
        .bind(kind)
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
        Ok(crate::db::repo_store::delete_by_repository(
            &self.pool,
            "repository_playbooks",
            repository_id,
        )
        .await?)
    }

    pub async fn delete_not_in_paths(
        &self,
        repository_id: Uuid,
        paths: &[String],
    ) -> Result<i64, RepositoryPlaybooksRepositoryError> {
        if paths.is_empty() {
            return self.delete_by_repository(repository_id).await;
        }
        Ok(crate::db::repo_store::prune_not_in_paths(
            &self.pool,
            "repository_playbooks",
            repository_id,
            paths,
        )
        .await?)
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
