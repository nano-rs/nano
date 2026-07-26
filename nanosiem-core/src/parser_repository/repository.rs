// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database repositories for parser repository feature

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use super::models::{
    NewParserRepository, ParserImport, ParserRepository, RepositoryParser, RepositoryParserFilter,
    UpdateParserRepository,
};

// =============================================================================
// Parser Repository Repository
// =============================================================================

// NAN-1618: the byte-identical parser/playbook/rule repository-layer error is
// consolidated into `crate::db::RepoError`; alias keeps the public name and the
// `NotFound` / `AlreadyExists` variants used by service.rs `match` arms.
pub use crate::db::repo_error::RepoError as ParserRepositoryRepositoryError;

#[derive(Clone)]
pub struct ParserRepositoryRepository {
    pool: PgPool,
}

impl ParserRepositoryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        repo: &NewParserRepository,
        created_by: Option<Uuid>,
    ) -> Result<ParserRepository, ParserRepositoryRepositoryError> {
        let slug = crate::db::repo_store::slug_from_url(&repo.url, &repo.name, repo.slug.as_deref());

        let result = sqlx::query_as::<_, ParserRepository>(
            r#"
            INSERT INTO parser_repositories (
                name, slug, description, url, branch, parsers_path,
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
        .bind(repo.parsers_path.as_deref().unwrap_or("parsers/"))
        .bind(repo.auto_sync_enabled.unwrap_or(false))
        .bind(repo.sync_interval_hours.unwrap_or(24))
        .bind(created_by)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            crate::db::repo_store::map_unique_violation(e, "parser_repositories", &repo.name)
        })?;

        Ok(result)
    }

    pub async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<ParserRepository, ParserRepositoryRepositoryError> {
        crate::db::repo_store::find_by_id(&self.pool, "parser_repositories", id).await
    }

    pub async fn find_by_slug(
        &self,
        slug: &str,
    ) -> Result<ParserRepository, ParserRepositoryRepositoryError> {
        crate::db::repo_store::find_by_slug(&self.pool, "parser_repositories", slug).await
    }

    pub async fn list_for_auto_sync(
        &self,
    ) -> Result<Vec<ParserRepository>, ParserRepositoryRepositoryError> {
        crate::db::repo_store::list_for_auto_sync(&self.pool, "parser_repositories").await
    }

    pub async fn list(&self) -> Result<Vec<ParserRepository>, ParserRepositoryRepositoryError> {
        crate::db::repo_store::list(&self.pool, "parser_repositories").await
    }

    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdateParserRepository,
    ) -> Result<ParserRepository, ParserRepositoryRepositoryError> {
        let result = sqlx::query_as::<_, ParserRepository>(
            r#"
            UPDATE parser_repositories SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                branch = COALESCE($4, branch),
                parsers_path = COALESCE($5, parsers_path),
                auto_sync_enabled = COALESCE($6, auto_sync_enabled),
                sync_interval_hours = COALESCE($7, sync_interval_hours),
                enabled = COALESCE($8, enabled)
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(&update.description)
        .bind(&update.branch)
        .bind(&update.parsers_path)
        .bind(update.auto_sync_enabled)
        .bind(update.sync_interval_hours)
        .bind(update.enabled)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryRepositoryError::NotFound(id))?;

        Ok(result)
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), ParserRepositoryRepositoryError> {
        crate::db::repo_store::delete(&self.pool, "parser_repositories", id).await
    }

    pub async fn update_sync_status(
        &self,
        id: Uuid,
        status: &str,
        commit: Option<&str>,
        parser_count: Option<i32>,
        error: Option<&str>,
    ) -> Result<(), ParserRepositoryRepositoryError> {
        crate::db::repo_store::update_sync_status(
            &self.pool,
            "parser_repositories",
            "parser_count",
            id,
            status,
            commit,
            parser_count,
            error,
        )
        .await
    }
}

// =============================================================================
// Repository Parsers Repository
// =============================================================================

#[derive(Debug, Error)]
pub enum RepositoryParsersRepositoryError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct RepositoryParsersRepository {
    pool: PgPool,
}

impl RepositoryParsersRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn upsert(
        &self,
        repository_id: Uuid,
        file_path: &str,
        file_sha: Option<&str>,
        raw_content: &str,
        name: Option<&str>,
        display_name: Option<&str>,
        description: Option<&str>,
        version: Option<&str>,
        category: Option<&str>,
        vendor: Option<&str>,
        product: Option<&str>,
        parser_vrl: Option<&str>,
        // NAN-1149: enrichment-parser fields (kind defaults "parser" for logs).
        kind: &str,
        enrich_kind: Option<&str>,
        enrich_source: Option<&str>,
        target_table: Option<&str>,
        normalize_vrl: Option<&str>,
    ) -> Result<RepositoryParser, RepositoryParsersRepositoryError> {
        let result = sqlx::query_as::<_, RepositoryParser>(
            r#"
            INSERT INTO repository_parsers (
                repository_id, file_path, file_sha, raw_content,
                name, display_name, description, version, category, vendor, product, parser_vrl,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            ON CONFLICT (repository_id, file_path) DO UPDATE SET
                file_sha = EXCLUDED.file_sha,
                raw_content = EXCLUDED.raw_content,
                name = EXCLUDED.name,
                display_name = EXCLUDED.display_name,
                description = EXCLUDED.description,
                version = EXCLUDED.version,
                category = EXCLUDED.category,
                vendor = EXCLUDED.vendor,
                product = EXCLUDED.product,
                parser_vrl = EXCLUDED.parser_vrl,
                kind = EXCLUDED.kind,
                enrich_kind = EXCLUDED.enrich_kind,
                enrich_source = EXCLUDED.enrich_source,
                target_table = EXCLUDED.target_table,
                normalize_vrl = EXCLUDED.normalize_vrl,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(repository_id)
        .bind(file_path)
        .bind(file_sha)
        .bind(raw_content)
        .bind(name)
        .bind(display_name)
        .bind(description)
        .bind(version)
        .bind(category)
        .bind(vendor)
        .bind(product)
        .bind(parser_vrl)
        .bind(kind)
        .bind(enrich_kind)
        .bind(enrich_source)
        .bind(target_table)
        .bind(normalize_vrl)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn list(
        &self,
        repository_id: Uuid,
        filter: &RepositoryParserFilter,
    ) -> Result<Vec<RepositoryParser>, RepositoryParsersRepositoryError> {
        let mut query = String::from("SELECT * FROM repository_parsers WHERE repository_id = $1");
        let mut param_count = 1;

        if filter.category.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND lower(category) = lower(${param_count})"));
        }

        if filter.search.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (name ILIKE '%' || ${param_count} || '%' OR display_name ILIKE '%' || ${param_count} || '%' OR file_path ILIKE '%' || ${param_count} || '%')"
            ));
        }

        query.push_str(" ORDER BY file_path ASC");

        if let Some(limit) = filter.limit {
            param_count += 1;
            query.push_str(&format!(" LIMIT ${param_count}"));
            let _ = limit; // used below in bind
        }

        if let Some(offset) = filter.offset {
            param_count += 1;
            query.push_str(&format!(" OFFSET ${param_count}"));
            let _ = offset;
        }

        // Build the query dynamically with binds
        let mut q = sqlx::query_as::<_, RepositoryParser>(&query).bind(repository_id);

        if let Some(ref category) = filter.category {
            q = q.bind(category);
        }
        if let Some(ref search) = filter.search {
            q = q.bind(search);
        }
        if let Some(limit) = filter.limit {
            q = q.bind(limit);
        }
        if let Some(offset) = filter.offset {
            q = q.bind(offset);
        }

        let results = q.fetch_all(&self.pool).await?;
        Ok(results)
    }

    pub async fn find_by_path(
        &self,
        repository_id: Uuid,
        file_path: &str,
    ) -> Result<Option<RepositoryParser>, RepositoryParsersRepositoryError> {
        let result = sqlx::query_as::<_, RepositoryParser>(
            "SELECT * FROM repository_parsers WHERE repository_id = $1 AND file_path = $2",
        )
        .bind(repository_id)
        .bind(file_path)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<RepositoryParser>, RepositoryParsersRepositoryError> {
        let result =
            sqlx::query_as::<_, RepositoryParser>("SELECT * FROM repository_parsers WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(result)
    }

    pub async fn count(
        &self,
        repository_id: Uuid,
    ) -> Result<i64, RepositoryParsersRepositoryError> {
        Ok(crate::db::repo_store::count_for_repository(
            &self.pool,
            "repository_parsers",
            repository_id,
        )
        .await?)
    }

    pub async fn delete_all(
        &self,
        repository_id: Uuid,
    ) -> Result<(), RepositoryParsersRepositoryError> {
        // Discard the affected-row count to preserve the historical `()` return.
        crate::db::repo_store::delete_by_repository(&self.pool, "repository_parsers", repository_id)
            .await?;
        Ok(())
    }

    /// Delete parsers not in the given paths (cleanup after sync).
    ///
    /// NOTE: unlike the playbook/rule items-repos, this intentionally has no
    /// empty-`paths` guard — `file_path != ALL('{}')` already deletes every row
    /// for the repository, matching the original behavior.
    pub async fn delete_not_in_paths(
        &self,
        repository_id: Uuid,
        paths: &[String],
    ) -> Result<i64, RepositoryParsersRepositoryError> {
        Ok(crate::db::repo_store::prune_not_in_paths(
            &self.pool,
            "repository_parsers",
            repository_id,
            paths,
        )
        .await?)
    }
}

// =============================================================================
// Parser Imports Repository
// =============================================================================

#[derive(Debug, Error)]
pub enum ParserImportsRepositoryError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct ParserImportsRepository {
    pool: PgPool,
}

impl ParserImportsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        repository_parser_id: Uuid,
        log_source_id: Uuid,
        import_type: &str,
        imported_by: Option<Uuid>,
        imported_commit: Option<&str>,
    ) -> Result<ParserImport, ParserImportsRepositoryError> {
        let result = sqlx::query_as::<_, ParserImport>(
            r#"
            INSERT INTO parser_imports (
                repository_parser_id, log_source_id, import_type,
                imported_by, imported_commit, last_sync_commit
            )
            VALUES ($1, $2, $3, $4, $5, $5)
            RETURNING *
            "#,
        )
        .bind(repository_parser_id)
        .bind(log_source_id)
        .bind(import_type)
        .bind(imported_by)
        .bind(imported_commit)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn find_by_log_source(
        &self,
        log_source_id: Uuid,
    ) -> Result<Option<ParserImport>, ParserImportsRepositoryError> {
        let result = sqlx::query_as::<_, ParserImport>(
            "SELECT * FROM parser_imports WHERE log_source_id = $1",
        )
        .bind(log_source_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn find_by_repository_parser(
        &self,
        repository_parser_id: Uuid,
    ) -> Result<Vec<ParserImport>, ParserImportsRepositoryError> {
        let results = sqlx::query_as::<_, ParserImport>(
            "SELECT * FROM parser_imports WHERE repository_parser_id = $1",
        )
        .bind(repository_parser_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    pub async fn list_for_repository(
        &self,
        repository_id: Uuid,
    ) -> Result<Vec<ParserImport>, ParserImportsRepositoryError> {
        let results = sqlx::query_as::<_, ParserImport>(
            r#"
            SELECT pi.* FROM parser_imports pi
            JOIN repository_parsers rp ON pi.repository_parser_id = rp.id
            WHERE rp.repository_id = $1
            "#,
        )
        .bind(repository_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    pub async fn list_upstream_changed(
        &self,
        repository_id: Uuid,
    ) -> Result<Vec<ParserImport>, ParserImportsRepositoryError> {
        let results = sqlx::query_as::<_, ParserImport>(
            r#"
            SELECT pi.* FROM parser_imports pi
            JOIN repository_parsers rp ON pi.repository_parser_id = rp.id
            WHERE rp.repository_id = $1 AND pi.upstream_changed = TRUE
            "#,
        )
        .bind(repository_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    pub async fn mark_upstream_changed(
        &self,
        repository_parser_id: Uuid,
    ) -> Result<(), ParserImportsRepositoryError> {
        sqlx::query(
            "UPDATE parser_imports SET upstream_changed = TRUE WHERE repository_parser_id = $1",
        )
        .bind(repository_parser_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn dismiss_upstream_changes(
        &self,
        log_source_id: Uuid,
    ) -> Result<(), ParserImportsRepositoryError> {
        sqlx::query("UPDATE parser_imports SET upstream_changed = FALSE WHERE log_source_id = $1")
            .bind(log_source_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn update_sync_commit(
        &self,
        id: Uuid,
        commit: &str,
    ) -> Result<(), ParserImportsRepositoryError> {
        sqlx::query(
            "UPDATE parser_imports SET last_sync_commit = $2, upstream_changed = FALSE WHERE id = $1"
        )
        .bind(id)
        .bind(commit)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_by_log_source(
        &self,
        log_source_id: Uuid,
    ) -> Result<(), ParserImportsRepositoryError> {
        sqlx::query("DELETE FROM parser_imports WHERE log_source_id = $1")
            .bind(log_source_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List all imports with their upstream YAML content for match_values fixup
    /// Imported log sources and their upstream YAML, for ONE repository.
    ///
    /// NAN-2120: this used to return every import across every repository, which
    /// let a single repair request rewrite live routing metadata tenant-wide.
    /// The repository filter is applied inside the SQL so the caller cannot
    /// widen the blast radius after the fact.
    pub async fn list_with_raw_content(
        &self,
        repository_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>, ParserImportsRepositoryError> {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            r#"
            SELECT pi.log_source_id, rp.raw_content
            FROM parser_imports pi
            JOIN repository_parsers rp ON pi.repository_parser_id = rp.id
            WHERE rp.repository_id = $1
            "#,
        )
        .bind(repository_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}
