// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database repositories for rule repository feature

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use super::models::{
    NewRuleRepository, RepositoryRule, RepositoryRuleFilter, RuleImport, RuleRepository,
    UpdateRuleRepository,
};

// =============================================================================
// Rule Repository Repository
// =============================================================================

// NAN-1618: consolidated into `crate::db::RepoError` (alias preserves the
// public name and the variants matched in service/crud.rs and service/import.rs).
pub use crate::db::repo_error::RepoError as RuleRepositoryRepositoryError;

#[derive(Clone)]
pub struct RuleRepositoryRepository {
    pool: PgPool,
}

impl RuleRepositoryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        repo: &NewRuleRepository,
        created_by: Option<Uuid>,
    ) -> Result<RuleRepository, RuleRepositoryRepositoryError> {
        // Generate slug from URL: github.com/owner/repo -> owner/repo
        let slug = crate::db::repo_store::slug_from_url(&repo.url, &repo.name, repo.slug.as_deref());

        let result = sqlx::query_as::<_, RuleRepository>(
            r#"
            INSERT INTO rule_repositories (
                name, slug, description, url, branch, rules_path, rule_format,
                auto_sync_enabled, sync_interval_hours, created_by
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
        .bind(repo.rules_path.as_deref().unwrap_or("rules/"))
        .bind(repo.rule_format.as_deref().unwrap_or("sigma"))
        .bind(repo.auto_sync_enabled.unwrap_or(false))
        .bind(repo.sync_interval_hours.unwrap_or(24))
        .bind(created_by)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            crate::db::repo_store::map_unique_violation(e, "rule_repositories", &repo.name)
        })?;

        Ok(result)
    }

    pub async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<RuleRepository, RuleRepositoryRepositoryError> {
        crate::db::repo_store::find_by_id(&self.pool, "rule_repositories", id).await
    }

    pub async fn find_by_slug(
        &self,
        slug: &str,
    ) -> Result<RuleRepository, RuleRepositoryRepositoryError> {
        crate::db::repo_store::find_by_slug(&self.pool, "rule_repositories", slug).await
    }

    pub async fn list(&self) -> Result<Vec<RuleRepository>, RuleRepositoryRepositoryError> {
        crate::db::repo_store::list(&self.pool, "rule_repositories").await
    }

    pub async fn list_enabled(&self) -> Result<Vec<RuleRepository>, RuleRepositoryRepositoryError> {
        let repos = sqlx::query_as::<_, RuleRepository>(
            "SELECT * FROM rule_repositories WHERE enabled = TRUE ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(repos)
    }

    pub async fn list_for_auto_sync(
        &self,
    ) -> Result<Vec<RuleRepository>, RuleRepositoryRepositoryError> {
        crate::db::repo_store::list_for_auto_sync(&self.pool, "rule_repositories").await
    }

    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdateRuleRepository,
    ) -> Result<RuleRepository, RuleRepositoryRepositoryError> {
        let repo = self.find_by_id(id).await?;

        // Handle selected_paths specially - if Some is passed, use it (even if empty), if None keep existing
        let selected_paths = if update.selected_paths.is_some() {
            update.selected_paths.clone()
        } else {
            repo.selected_paths.clone()
        };

        // If selected_paths changed, clear last_sync_commit to force a full re-sync
        let paths_changed = update.selected_paths.is_some()
            && update.selected_paths != repo.selected_paths;

        let result = sqlx::query_as::<_, RuleRepository>(
            r#"
            UPDATE rule_repositories
            SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                branch = COALESCE($4, branch),
                rules_path = COALESCE($5, rules_path),
                auto_sync_enabled = COALESCE($6, auto_sync_enabled),
                sync_interval_hours = COALESCE($7, sync_interval_hours),
                enabled = COALESCE($8, enabled),
                selected_paths = $9,
                last_sync_commit = CASE WHEN $10 THEN NULL ELSE last_sync_commit END,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.name.as_ref().unwrap_or(&repo.name))
        .bind(&update.description.as_ref().or(repo.description.as_ref()))
        .bind(&update.branch.as_ref().unwrap_or(&repo.branch))
        .bind(&update.rules_path.as_ref().or(repo.rules_path.as_ref()))
        .bind(update.auto_sync_enabled.unwrap_or(repo.auto_sync_enabled))
        .bind(
            update
                .sync_interval_hours
                .unwrap_or(repo.sync_interval_hours),
        )
        .bind(update.enabled.unwrap_or(repo.enabled))
        .bind(&selected_paths)
        .bind(paths_changed)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn update_sync_status(
        &self,
        id: Uuid,
        status: &str,
        commit: Option<&str>,
        rule_count: Option<i32>,
        error: Option<&str>,
    ) -> Result<(), RuleRepositoryRepositoryError> {
        crate::db::repo_store::update_sync_status(
            &self.pool,
            "rule_repositories",
            "rule_count",
            id,
            status,
            commit,
            rule_count,
            error,
        )
        .await
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), RuleRepositoryRepositoryError> {
        crate::db::repo_store::delete(&self.pool, "rule_repositories", id).await
    }
}

// =============================================================================
// Repository Rules Repository
// =============================================================================

#[derive(Debug, Error)]
pub enum RepositoryRulesRepositoryError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Rule not found: {0}")]
    NotFound(String),
}

#[derive(Clone)]
pub struct RepositoryRulesRepository {
    pool: PgPool,
}

impl RepositoryRulesRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn upsert(
        &self,
        repository_id: Uuid,
        file_path: &str,
        file_sha: Option<&str>,
        raw_content: &str,
        title: Option<&str>,
        description: Option<&str>,
        severity: Option<&str>,
        mitre_tactics: Option<&[String]>,
        mitre_techniques: Option<&[String]>,
        tags: Option<&[String]>,
        requires_fields: Option<&[String]>,
        requires_source_types: Option<&[String]>,
        conversion_status: Option<&str>,
    ) -> Result<RepositoryRule, RepositoryRulesRepositoryError> {
        let result = sqlx::query_as::<_, RepositoryRule>(
            r#"
            INSERT INTO repository_rules (
                repository_id, file_path, file_sha, raw_content,
                title, description, severity, mitre_tactics, mitre_techniques, tags,
                requires_fields, requires_source_types, conversion_status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, COALESCE($13, 'pending'))
            ON CONFLICT (repository_id, file_path) DO UPDATE SET
                file_sha = EXCLUDED.file_sha,
                raw_content = EXCLUDED.raw_content,
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                severity = EXCLUDED.severity,
                mitre_tactics = EXCLUDED.mitre_tactics,
                mitre_techniques = EXCLUDED.mitre_techniques,
                tags = EXCLUDED.tags,
                requires_fields = EXCLUDED.requires_fields,
                requires_source_types = EXCLUDED.requires_source_types,
                conversion_status = COALESCE(EXCLUDED.conversion_status, repository_rules.conversion_status),
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(repository_id)
        .bind(file_path)
        .bind(file_sha)
        .bind(raw_content)
        .bind(title)
        .bind(description)
        .bind(severity)
        .bind(mitre_tactics)
        .bind(mitre_techniques)
        .bind(tags)
        .bind(requires_fields)
        .bind(requires_source_types)
        .bind(conversion_status)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    pub async fn find_by_path(
        &self,
        repository_id: Uuid,
        file_path: &str,
    ) -> Result<RepositoryRule, RepositoryRulesRepositoryError> {
        sqlx::query_as::<_, RepositoryRule>(
            "SELECT * FROM repository_rules WHERE repository_id = $1 AND file_path = $2",
        )
        .bind(repository_id)
        .bind(file_path)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| RepositoryRulesRepositoryError::NotFound(file_path.to_string()))
    }

    pub async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<RepositoryRule, RepositoryRulesRepositoryError> {
        sqlx::query_as::<_, RepositoryRule>("SELECT * FROM repository_rules WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| RepositoryRulesRepositoryError::NotFound(id.to_string()))
    }

    pub async fn list(
        &self,
        repository_id: Uuid,
        filter: &RepositoryRuleFilter,
    ) -> Result<Vec<RepositoryRule>, RepositoryRulesRepositoryError> {
        let mut query = String::from("SELECT * FROM repository_rules WHERE repository_id = $1");
        let mut param_count = 1;

        if filter.path_prefix.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND file_path LIKE ${} || '%'", param_count));
        }

        if filter.severity.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND severity = ${}", param_count));
        }

        if filter.conversion_status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND conversion_status = ${}", param_count));
        }

        if filter.coverage_status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND coverage_status = ${}", param_count));
        }

        if filter.search.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (title ILIKE '%' || ${0} || '%' OR file_path ILIKE '%' || ${0} || '%')",
                param_count
            ));
        }

        if let Some(has_npl) = filter.has_npl {
            if has_npl {
                query.push_str(" AND converted_npl IS NOT NULL");
            } else {
                query.push_str(" AND converted_npl IS NULL");
            }
        }

        query.push_str(" ORDER BY file_path ASC");

        if filter.limit.is_some() {
            param_count += 1;
            query.push_str(&format!(" LIMIT ${}", param_count));
        }

        if filter.offset.is_some() {
            param_count += 1;
            query.push_str(&format!(" OFFSET ${}", param_count));
        }

        // Build the query with dynamic parameters
        let mut sqlx_query = sqlx::query_as::<_, RepositoryRule>(&query);
        sqlx_query = sqlx_query.bind(repository_id);

        if let Some(ref path_prefix) = filter.path_prefix {
            sqlx_query = sqlx_query.bind(path_prefix);
        }
        if let Some(ref severity) = filter.severity {
            sqlx_query = sqlx_query.bind(severity);
        }
        if let Some(ref conversion_status) = filter.conversion_status {
            sqlx_query = sqlx_query.bind(conversion_status);
        }
        if let Some(ref coverage_status) = filter.coverage_status {
            sqlx_query = sqlx_query.bind(coverage_status);
        }
        if let Some(ref search) = filter.search {
            sqlx_query = sqlx_query.bind(search);
        }
        if let Some(limit) = filter.limit {
            sqlx_query = sqlx_query.bind(limit);
        }
        if let Some(offset) = filter.offset {
            sqlx_query = sqlx_query.bind(offset);
        }

        let rules = sqlx_query.fetch_all(&self.pool).await?;
        Ok(rules)
    }

    pub async fn count(&self, repository_id: Uuid) -> Result<i64, RepositoryRulesRepositoryError> {
        Ok(crate::db::repo_store::count_for_repository(
            &self.pool,
            "repository_rules",
            repository_id,
        )
        .await?)
    }

    pub async fn update_conversion(
        &self,
        id: Uuid,
        status: &str,
        npl: Option<&str>,
        confidence: Option<f64>,
        warnings: Option<&[String]>,
        field_mappings: Option<&serde_json::Value>,
    ) -> Result<(), RepositoryRulesRepositoryError> {
        sqlx::query(
            r#"
            UPDATE repository_rules
            SET
                conversion_status = $2,
                converted_npl = $3,
                conversion_confidence = $4,
                conversion_warnings = $5,
                conversion_field_mappings = $6,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(npl)
        .bind(confidence)
        .bind(warnings)
        .bind(field_mappings)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_coverage(
        &self,
        id: Uuid,
        status: &str,
        missing_fields: Option<&[String]>,
    ) -> Result<(), RepositoryRulesRepositoryError> {
        sqlx::query(
            r#"
            UPDATE repository_rules
            SET
                coverage_status = $2,
                coverage_missing_fields = $3,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(missing_fields)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_by_repository(
        &self,
        repository_id: Uuid,
    ) -> Result<i64, RepositoryRulesRepositoryError> {
        Ok(crate::db::repo_store::delete_by_repository(
            &self.pool,
            "repository_rules",
            repository_id,
        )
        .await?)
    }

    pub async fn delete_not_in_paths(
        &self,
        repository_id: Uuid,
        paths: &[String],
    ) -> Result<i64, RepositoryRulesRepositoryError> {
        if paths.is_empty() {
            return self.delete_by_repository(repository_id).await;
        }

        Ok(crate::db::repo_store::prune_not_in_paths(
            &self.pool,
            "repository_rules",
            repository_id,
            paths,
        )
        .await?)
    }
}

// =============================================================================
// Rule Imports Repository
// =============================================================================

#[derive(Debug, Error)]
pub enum RuleImportsRepositoryError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Import not found: {0}")]
    NotFound(Uuid),

    #[error("Import already exists")]
    AlreadyExists,
}

#[derive(Clone)]
pub struct RuleImportsRepository {
    pool: PgPool,
}

impl RuleImportsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        repository_rule_id: Uuid,
        detection_rule_id: Uuid,
        import_type: &str,
        imported_by: Option<Uuid>,
        imported_commit: Option<&str>,
        customizations: Option<serde_json::Value>,
    ) -> Result<RuleImport, RuleImportsRepositoryError> {
        let result = sqlx::query_as::<_, RuleImport>(
            r#"
            INSERT INTO rule_imports (
                repository_rule_id, detection_rule_id, import_type,
                imported_by, imported_commit, last_sync_commit, customizations
            )
            VALUES ($1, $2, $3, $4, $5, $5, $6)
            RETURNING *
            "#,
        )
        .bind(repository_rule_id)
        .bind(detection_rule_id)
        .bind(import_type)
        .bind(imported_by)
        .bind(imported_commit)
        .bind(&customizations)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint().is_some() {
                    return RuleImportsRepositoryError::AlreadyExists;
                }
            }
            RuleImportsRepositoryError::Database(e)
        })?;

        Ok(result)
    }

    pub async fn find_by_detection_rule(
        &self,
        detection_rule_id: Uuid,
    ) -> Result<Option<RuleImport>, RuleImportsRepositoryError> {
        let import = sqlx::query_as::<_, RuleImport>(
            "SELECT * FROM rule_imports WHERE detection_rule_id = $1",
        )
        .bind(detection_rule_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(import)
    }

    pub async fn find_by_repository_rule(
        &self,
        repository_rule_id: Uuid,
    ) -> Result<Vec<RuleImport>, RuleImportsRepositoryError> {
        let imports = sqlx::query_as::<_, RuleImport>(
            "SELECT * FROM rule_imports WHERE repository_rule_id = $1",
        )
        .bind(repository_rule_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(imports)
    }

    pub async fn list_linked_with_updates(
        &self,
    ) -> Result<Vec<RuleImport>, RuleImportsRepositoryError> {
        let imports = sqlx::query_as::<_, RuleImport>(
            r#"
            SELECT * FROM rule_imports
            WHERE import_type = 'linked' AND upstream_changed = TRUE
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(imports)
    }

    /// List all imports that have upstream changes (both linked and forked)
    pub async fn list_with_upstream_changes(
        &self,
    ) -> Result<Vec<RuleImport>, RuleImportsRepositoryError> {
        let imports = sqlx::query_as::<_, RuleImport>(
            r#"
            SELECT * FROM rule_imports
            WHERE upstream_changed = TRUE
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(imports)
    }

    /// List imports with upstream changes for a specific repository
    pub async fn list_with_upstream_changes_for_repo(
        &self,
        repository_id: Uuid,
    ) -> Result<Vec<RuleImport>, RuleImportsRepositoryError> {
        let imports = sqlx::query_as::<_, RuleImport>(
            r#"
            SELECT ri.* FROM rule_imports ri
            JOIN repository_rules rr ON ri.repository_rule_id = rr.id
            WHERE rr.repository_id = $1 AND ri.upstream_changed = TRUE
            "#,
        )
        .bind(repository_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(imports)
    }

    pub async fn mark_upstream_changed(
        &self,
        repository_rule_id: Uuid,
    ) -> Result<u64, RuleImportsRepositoryError> {
        // Mark ALL imports (linked and forked) as having upstream changes
        let result = sqlx::query(
            r#"
            UPDATE rule_imports
            SET upstream_changed = TRUE
            WHERE repository_rule_id = $1
            "#,
        )
        .bind(repository_rule_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Clear upstream_changed flag after user acknowledges/updates
    pub async fn clear_upstream_changed(&self, id: Uuid) -> Result<(), RuleImportsRepositoryError> {
        sqlx::query(
            r#"
            UPDATE rule_imports
            SET upstream_changed = FALSE
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_sync(
        &self,
        id: Uuid,
        commit: &str,
    ) -> Result<(), RuleImportsRepositoryError> {
        sqlx::query(
            r#"
            UPDATE rule_imports
            SET last_sync_commit = $2, upstream_changed = FALSE
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(commit)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), RuleImportsRepositoryError> {
        let result = sqlx::query("DELETE FROM rule_imports WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(RuleImportsRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// List all imports for rules in a specific repository
    pub async fn list_for_repository(
        &self,
        repository_id: Uuid,
    ) -> Result<Vec<RuleImport>, RuleImportsRepositoryError> {
        let imports = sqlx::query_as::<_, RuleImport>(
            r#"
            SELECT ri.* FROM rule_imports ri
            JOIN repository_rules rr ON ri.repository_rule_id = rr.id
            WHERE rr.repository_id = $1
            "#,
        )
        .bind(repository_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(imports)
    }
}
