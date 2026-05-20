// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser Repository Service
//!
//! Provides high-level operations for managing external parser repositories,
//! syncing parsers from GitHub, and importing parsers as log sources.

use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

use crate::log_sources::{LogSourceRepository, NewLogSource, UpdateLogSource};
use crate::rule_repository::GitHubClient;

use super::error::ParserRepositoryError;
use super::models::{
    ApplyUpstreamUpdateResult, BulkApplyUpstreamResult, NewParserRepository, ParserImport,
    ParserImportPreview, ParserImportRequest, ParserImportType, ParserRepository, RepositoryParser,
    RepositoryParserFilter, SyncResult, SyncStatus, UpdateParserRepository, UpstreamParserDiff,
};
use super::repository::{
    ParserImportsRepository, ParserRepositoryRepository, RepositoryParsersRepository,
};
use super::yaml_parser::parse_parser_yaml;

/// Allowed parser repository sources (owner/repo format, lowercase)
const ALLOWED_REPOSITORIES: &[&str] = &["nano-rs/parsers"];

/// Configuration for the parser repository service
#[derive(Debug, Clone)]
pub struct ParserRepositoryServiceConfig {
    pub max_parsers_per_repo: usize,
}

impl Default for ParserRepositoryServiceConfig {
    fn default() -> Self {
        Self {
            max_parsers_per_repo: 1000,
        }
    }
}

/// Service for managing parser repositories
pub struct ParserRepositoryService {
    repo_repository: ParserRepositoryRepository,
    parsers_repository: RepositoryParsersRepository,
    imports_repository: ParserImportsRepository,
    github_client: GitHubClient,
    log_source_repository: Option<LogSourceRepository>,
    config: ParserRepositoryServiceConfig,
    pg_pool: PgPool,
    syncing_repos: Arc<RwLock<std::collections::HashSet<Uuid>>>,
}

impl ParserRepositoryService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo_repository: ParserRepositoryRepository::new(pool.clone()),
            parsers_repository: RepositoryParsersRepository::new(pool.clone()),
            imports_repository: ParserImportsRepository::new(pool.clone()),
            github_client: GitHubClient::new(),
            log_source_repository: Some(LogSourceRepository::new(pool.clone())),
            config: ParserRepositoryServiceConfig::default(),
            pg_pool: pool,
            syncing_repos: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    pub fn with_config(mut self, config: ParserRepositoryServiceConfig) -> Self {
        self.config = config;
        self
    }

    // =========================================================================
    // Repository CRUD
    // =========================================================================

    pub async fn list_repositories(&self) -> Result<Vec<ParserRepository>, ParserRepositoryError> {
        self.repo_repository
            .list()
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))
    }

    pub async fn get_repository(
        &self,
        id: Uuid,
    ) -> Result<ParserRepository, ParserRepositoryError> {
        self.repo_repository
            .find_by_id(id)
            .await
            .map_err(|e| match e {
                super::repository::ParserRepositoryRepositoryError::NotFound(id) => {
                    ParserRepositoryError::RepositoryNotFound(id)
                }
                other => ParserRepositoryError::Internal(other.to_string()),
            })
    }

    pub async fn create_repository(
        &self,
        req: NewParserRepository,
        user_id: Option<Uuid>,
    ) -> Result<ParserRepository, ParserRepositoryError> {
        // Validate URL is in allowlist
        self.validate_url(&req.url)?;

        self.repo_repository
            .create(&req, user_id)
            .await
            .map_err(|e| match e {
                super::repository::ParserRepositoryRepositoryError::AlreadyExists(name) => {
                    ParserRepositoryError::RepositoryAlreadyExists(name)
                }
                other => ParserRepositoryError::Internal(other.to_string()),
            })
    }

    pub async fn update_repository(
        &self,
        id: Uuid,
        update: UpdateParserRepository,
    ) -> Result<ParserRepository, ParserRepositoryError> {
        self.repo_repository
            .update(id, &update)
            .await
            .map_err(|e| match e {
                super::repository::ParserRepositoryRepositoryError::NotFound(id) => {
                    ParserRepositoryError::RepositoryNotFound(id)
                }
                other => ParserRepositoryError::Internal(other.to_string()),
            })
    }

    pub async fn delete_repository(&self, id: Uuid) -> Result<(), ParserRepositoryError> {
        self.repo_repository.delete(id).await.map_err(|e| match e {
            super::repository::ParserRepositoryRepositoryError::NotFound(id) => {
                ParserRepositoryError::RepositoryNotFound(id)
            }
            other => ParserRepositoryError::Internal(other.to_string()),
        })
    }

    // =========================================================================
    // Sync
    // =========================================================================

    /// Start a background sync task
    pub async fn start_sync(&self, id: Uuid) -> Result<(), ParserRepositoryError> {
        let repo = self.get_repository(id).await?;

        if !repo.enabled {
            return Err(ParserRepositoryError::RepositoryDisabled);
        }

        // Check if already syncing
        {
            let syncing = self.syncing_repos.read().await;
            if syncing.contains(&id) {
                return Err(ParserRepositoryError::SyncInProgress(id));
            }
        }

        // Mark as syncing
        self.repo_repository
            .update_sync_status(id, "syncing", None, None, None)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        // Spawn background task
        let pool = self.pg_pool.clone();
        let syncing_repos = self.syncing_repos.clone();

        tokio::spawn(async move {
            {
                let mut syncing = syncing_repos.write().await;
                syncing.insert(id);
            }

            let service = ParserRepositoryService::new(pool);
            let result = service.run_sync(id).await;

            {
                let mut syncing = syncing_repos.write().await;
                syncing.remove(&id);
            }

            if let Err(e) = result {
                warn!(repo_id = %id, error = %e, "Parser repository sync failed");
            }
        });

        Ok(())
    }

    /// Run sync (blocking, called from background task)
    async fn run_sync(&self, id: Uuid) -> Result<SyncResult, ParserRepositoryError> {
        let start = Instant::now();
        let repo = self.get_repository(id).await?;

        let (owner, repo_name) = GitHubClient::parse_url(&repo.url).map_err(
            |e: crate::rule_repository::GitHubClientError| {
                ParserRepositoryError::GitHubApi(e.to_string())
            },
        )?;

        let parsers_path = repo.parsers_path.as_deref().unwrap_or("parsers/");
        let branch = &repo.branch;

        info!(repo_id = %id, owner = %owner, repo = %repo_name, "Starting parser repository sync");

        // Get the latest commit
        let commit = self
            .github_client
            .get_latest_commit(&owner, &repo_name, branch)
            .await
            .map_err(|e| ParserRepositoryError::GitHubApi(e.to_string()))?;

        // Get tree to find parser.yaml files
        let tree = self
            .github_client
            .get_tree(&owner, &repo_name, branch, Some(parsers_path))
            .await
            .map_err(|e| ParserRepositoryError::GitHubApi(e.to_string()))?;

        let yaml_files: Vec<_> = tree
            .iter()
            .filter(|entry| {
                entry.path.ends_with("/parser.yaml") || entry.path.ends_with("/parser.yml")
            })
            .collect();

        let mut added = 0i32;
        let mut updated = 0i32;
        let mut synced_paths = Vec::new();

        for entry in &yaml_files {
            if synced_paths.len() >= self.config.max_parsers_per_repo {
                warn!(repo_id = %id, "Max parsers per repo reached, stopping sync");
                break;
            }

            let full_path = if entry.path.starts_with(parsers_path) {
                entry.path.clone()
            } else {
                format!("{}{}", parsers_path, entry.path)
            };

            // Check if file changed (by SHA)
            let existing = self
                .parsers_repository
                .find_by_path(id, &entry.path)
                .await
                .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

            let file_sha = Some(entry.sha.as_str());
            let needs_update = existing
                .as_ref()
                .map(|e| e.file_sha.as_deref() != file_sha)
                .unwrap_or(true);

            if !needs_update {
                synced_paths.push(entry.path.clone());
                continue;
            }

            // Fetch file content using commit SHA (not branch ref) to avoid CDN caching
            let content = self
                .github_client
                .get_raw_file(&owner, &repo_name, &full_path, &commit)
                .await
                .map_err(|e| ParserRepositoryError::GitHubApi(e.to_string()))?;

            // Parse YAML
            match parse_parser_yaml(&content) {
                Ok(parsed) => {
                    let is_new = existing.is_none();
                    self.parsers_repository
                        .upsert(
                            id,
                            &entry.path,
                            file_sha,
                            &content,
                            Some(&parsed.name),
                            parsed.display_name.as_deref(),
                            parsed.description.as_deref(),
                            parsed.version.as_deref(),
                            parsed.category.as_deref(),
                            parsed.vendor.as_deref(),
                            parsed.product.as_deref(),
                            parsed.parser_vrl.as_deref(),
                        )
                        .await
                        .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

                    if is_new {
                        added += 1;
                    } else {
                        updated += 1;
                        // Mark linked imports as upstream_changed
                        self.imports_repository
                            .mark_upstream_changed(existing.unwrap().id)
                            .await
                            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;
                    }

                    synced_paths.push(entry.path.clone());
                }
                Err(e) => {
                    warn!(
                        repo_id = %id,
                        path = %entry.path,
                        error = %e,
                        "Failed to parse parser.yaml"
                    );
                    // Still track the path so we don't delete it
                    synced_paths.push(entry.path.clone());
                }
            }
        }

        // Remove parsers no longer in repo
        let removed =
            self.parsers_repository
                .delete_not_in_paths(id, &synced_paths)
                .await
                .map_err(|e| ParserRepositoryError::Internal(e.to_string()))? as i32;

        let total = synced_paths.len() as i32;
        let duration_ms = start.elapsed().as_millis() as u64;

        // Update repo status
        self.repo_repository
            .update_sync_status(id, "success", Some(&commit), Some(total), None)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        let result = SyncResult {
            repository_id: id,
            status: SyncStatus::Success,
            commit: Some(commit),
            parsers_added: added,
            parsers_updated: updated,
            parsers_removed: removed,
            parsers_total: total,
            duration_ms,
            error: None,
        };

        info!(
            repo_id = %id,
            added = added,
            updated = updated,
            removed = removed,
            total = total,
            duration_ms = duration_ms,
            "Parser repository sync completed"
        );

        // Re-sync match_values for all imported log sources from upstream YAML
        if let Err(e) = self.fixup_imported_match_values().await {
            warn!("Failed to fixup imported match_values during sync: {}", e);
        }

        Ok(result)
    }

    // =========================================================================
    // Browse Parsers
    // =========================================================================

    pub async fn list_parsers(
        &self,
        repo_id: Uuid,
        filter: &RepositoryParserFilter,
    ) -> Result<Vec<RepositoryParser>, ParserRepositoryError> {
        // Verify repo exists
        let _ = self.get_repository(repo_id).await?;

        self.parsers_repository
            .list(repo_id, filter)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))
    }

    pub async fn get_parser(
        &self,
        repo_id: Uuid,
        path: &str,
    ) -> Result<RepositoryParser, ParserRepositoryError> {
        self.parsers_repository
            .find_by_path(repo_id, path)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?
            .ok_or_else(|| ParserRepositoryError::ParserNotFound {
                repo_id,
                path: path.to_string(),
            })
    }

    // =========================================================================
    // Import Preview
    // =========================================================================

    pub async fn preview_import(
        &self,
        repo_id: Uuid,
        path: &str,
    ) -> Result<ParserImportPreview, ParserRepositoryError> {
        let parser = self.get_parser(repo_id, path).await?;

        // Check if already imported
        let imports = self
            .imports_repository
            .find_by_repository_parser(parser.id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        let already_imported = !imports.is_empty();
        let existing_import_type = imports.first().map(|i| i.import_type.clone());
        let existing_log_source_id = imports.first().map(|i| i.log_source_id);

        let proposed_name = parser
            .display_name
            .clone()
            .unwrap_or_else(|| parser.name.clone().unwrap_or_else(|| path.to_string()));

        Ok(ParserImportPreview {
            proposed_name,
            proposed_description: parser.description.clone(),
            proposed_category: parser.category.clone(),
            proposed_vendor: parser.vendor.clone(),
            proposed_product: parser.product.clone(),
            already_imported,
            existing_import_type,
            existing_log_source_id,
            repository_parser: parser,
        })
    }

    // =========================================================================
    // Import Parser as Log Source
    // =========================================================================

    pub async fn import_parser(
        &self,
        repo_id: Uuid,
        path: &str,
        req: &ParserImportRequest,
        user_id: Option<Uuid>,
    ) -> Result<Uuid, ParserRepositoryError> {
        let repo = self.get_repository(repo_id).await?;
        let parser = self.get_parser(repo_id, path).await?;

        // Check not already imported
        let existing = self
            .imports_repository
            .find_by_repository_parser(parser.id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        if !existing.is_empty() {
            return Err(ParserRepositoryError::AlreadyImported {
                import_type: existing[0].import_type.clone(),
            });
        }

        let parser_vrl = parser.parser_vrl.clone().unwrap_or_default();

        // Build log source name from parser name
        let display_name = parser
            .display_name
            .clone()
            .unwrap_or_else(|| parser.name.clone().unwrap_or_else(|| path.to_string()));

        // match_values: union the UI's `source_type` override (parser name
        // by default), the YAML's `match_values` list, and the parser's
        // canonical name as a fallback. See `resolve_match_values` for the
        // ordering rationale. NAN-920.
        let parsed_yaml = super::yaml_parser::parse_parser_yaml(&parser.raw_content).ok();
        let yaml_match_values = parsed_yaml
            .as_ref()
            .and_then(|y| y.match_values.clone())
            .unwrap_or_default();
        let match_values = Self::resolve_match_values(
            req.source_type.as_deref(),
            &yaml_match_values,
            parser.name.as_deref(),
        );

        // ingestion_method: how logs arrive (routed, kafka, aws_s3, etc.)
        let ingestion_method = req
            .ingestion_method
            .clone()
            .unwrap_or_else(|| "routed".to_string());

        let new_log_source = NewLogSource {
            name: display_name,
            description: parser.description.clone(),
            namespace: "default".to_string(),
            timezone: "UTC".to_string(),
            source_type: ingestion_method,
            source_config: serde_json::json!({}),
            parser_vrl,
            output_fields: None,
            credential_id: None,
            category: parser.category.clone(),
            vendor: parser.vendor.clone(),
            product: parser.product.clone(),
            icon: None,
            color: None,
            match_field: None,
            match_pattern: None,
            match_values: Some(match_values),
            sampling_ratio: None,
            sampling_exclude_condition: None,
        };

        // Create log source via repository
        let ls_repo = self.log_source_repository.as_ref().ok_or_else(|| {
            ParserRepositoryError::Internal("Log source repository not available".to_string())
        })?;

        let log_source = ls_repo
            .create(&new_log_source)
            .await
            .map_err(|e| ParserRepositoryError::LogSourceService(e.to_string()))?;

        let log_source_id = log_source.id;
        let is_linked = matches!(req.import_type, ParserImportType::Linked);

        // Set parser_only=true, validated, and source repository tracking
        sqlx::query(
            r#"
            UPDATE log_sources SET
                parser_only = true,
                validated = true,
                validation_error = NULL,
                source_parser_repository_id = $2,
                source_parser_path = $3,
                source_parser_linked = $4
            WHERE id = $1
            "#,
        )
        .bind(log_source_id)
        .bind(repo_id)
        .bind(path)
        .bind(is_linked)
        .execute(&self.pg_pool)
        .await
        .map_err(ParserRepositoryError::Database)?;

        // Create import record
        self.imports_repository
            .create(
                parser.id,
                log_source_id,
                &req.import_type.to_string(),
                user_id,
                repo.last_sync_commit.as_deref(),
            )
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        info!(
            repo_id = %repo_id,
            parser_path = %path,
            log_source_id = %log_source_id,
            import_type = %req.import_type,
            "Parser imported as log source"
        );

        Ok(log_source_id)
    }

    // =========================================================================
    // Batch Import
    // =========================================================================

    pub async fn batch_import(
        &self,
        repo_id: Uuid,
        paths: &[String],
        import_type: &ParserImportType,
        user_id: Option<Uuid>,
    ) -> Result<Vec<Result<Uuid, String>>, ParserRepositoryError> {
        let mut results = Vec::new();

        for path in paths {
            let req = ParserImportRequest {
                import_type: import_type.clone(),
                source_type: None,
                ingestion_method: None, // Defaults to "routed"
            };
            match self.import_parser(repo_id, path, &req, user_id).await {
                Ok(id) => results.push(Ok(id)),
                Err(ParserRepositoryError::AlreadyImported { .. }) => {
                    results.push(Err("Already imported".to_string()));
                }
                Err(e) => {
                    results.push(Err(e.to_string()));
                }
            }
        }

        Ok(results)
    }

    // =========================================================================
    // Remove All Imported
    // =========================================================================

    pub async fn remove_all_imported(
        &self,
        repo_id: Uuid,
    ) -> Result<(i32, i32), ParserRepositoryError> {
        let imports = self
            .imports_repository
            .list_for_repository(repo_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        let ls_repo = self.log_source_repository.as_ref().ok_or_else(|| {
            ParserRepositoryError::Internal("Log source repository not available".to_string())
        })?;

        let mut removed = 0i32;
        let mut failed = 0i32;

        for import in &imports {
            match ls_repo.delete(import.log_source_id).await {
                Ok(_) => removed += 1,
                Err(e) => {
                    warn!(log_source_id = %import.log_source_id, error = %e, "Failed to delete imported log source");
                    failed += 1;
                }
            }
        }

        Ok((removed, failed))
    }

    // =========================================================================
    // Upstream Changes
    // =========================================================================

    pub async fn get_upstream_updates(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<super::models::ParserUpstreamUpdate>, ParserRepositoryError> {
        let imports = self
            .imports_repository
            .list_upstream_changed(repo_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        let mut updates = Vec::with_capacity(imports.len());
        for import in imports {
            let parser = self
                .parsers_repository
                .find_by_id(import.repository_parser_id)
                .await
                .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

            updates.push(super::models::ParserUpstreamUpdate {
                log_source_id: import.log_source_id,
                repository_parser_id: import.repository_parser_id,
                file_path: parser
                    .as_ref()
                    .map(|p| p.file_path.clone())
                    .unwrap_or_default(),
                display_name: parser.and_then(|p| p.display_name.or(p.name)),
                version: None, // version from upstream comes via get_upstream_diff
                import_type: import.import_type,
            });
        }
        Ok(updates)
    }

    pub async fn get_upstream_diff(
        &self,
        log_source_id: Uuid,
    ) -> Result<UpstreamParserDiff, ParserRepositoryError> {
        let import = self
            .imports_repository
            .find_by_log_source(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?
            .ok_or(ParserRepositoryError::ImportNotFound(log_source_id))?;

        let repo_parser = self
            .parsers_repository
            .find_by_id(import.repository_parser_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?
            .ok_or_else(|| {
                ParserRepositoryError::Internal("Repository parser not found".to_string())
            })?;

        // Get current log source VRL
        let ls_repo = self.log_source_repository.as_ref().ok_or_else(|| {
            ParserRepositoryError::Internal("Log source repository not available".to_string())
        })?;

        let log_source = ls_repo
            .find_by_id(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::LogSourceService(e.to_string()))?;

        let upstream_vrl = repo_parser.parser_vrl.clone().unwrap_or_default();
        let current_vrl = log_source.parser_vrl.clone();
        let has_changes = upstream_vrl != current_vrl;

        Ok(UpstreamParserDiff {
            log_source_id,
            repository_parser_id: repo_parser.id,
            file_path: repo_parser.file_path.clone(),
            upstream_display_name: repo_parser.display_name.clone(),
            upstream_description: repo_parser.description.clone(),
            upstream_version: repo_parser.version.clone(),
            upstream_vrl,
            current_vrl,
            has_changes,
        })
    }

    pub async fn dismiss_upstream_changes(
        &self,
        log_source_id: Uuid,
    ) -> Result<(), ParserRepositoryError> {
        self.imports_repository
            .dismiss_upstream_changes(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))
    }

    /// Apply upstream parser update to a log source.
    /// Updates the VRL code and clears the upstream_changed flag.
    pub async fn apply_upstream_update(
        &self,
        log_source_id: Uuid,
    ) -> Result<ApplyUpstreamUpdateResult, ParserRepositoryError> {
        let ls_repo = self.log_source_repository.as_ref().ok_or_else(|| {
            ParserRepositoryError::Internal("Log source repository not available".to_string())
        })?;

        // Get the import record
        let import = self
            .imports_repository
            .find_by_log_source(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?
            .ok_or(ParserRepositoryError::ImportNotFound(log_source_id))?;

        // Get the upstream parser
        let repo_parser = self
            .parsers_repository
            .find_by_id(import.repository_parser_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?
            .ok_or_else(|| {
                ParserRepositoryError::Internal("Repository parser not found".to_string())
            })?;

        let upstream_vrl = repo_parser.parser_vrl.clone().ok_or_else(|| {
            ParserRepositoryError::Internal("Upstream parser has no VRL".to_string())
        })?;

        // Get current log source to check deployed state
        let log_source = ls_repo
            .find_by_id(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::LogSourceService(e.to_string()))?;

        // Update the log source VRL
        let mut update = UpdateLogSource::default();
        update.parser_vrl = Some(upstream_vrl);
        // Also update description if upstream has one
        if let Some(ref desc) = repo_parser.description {
            update.description = Some(desc.clone());
        }

        ls_repo
            .update(log_source_id, &update)
            .await
            .map_err(|e| ParserRepositoryError::LogSourceService(e.to_string()))?;

        // Clear upstream_changed flag
        self.imports_repository
            .dismiss_upstream_changes(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        info!(
            "Applied upstream update for log source '{}' from {}",
            log_source.name, repo_parser.file_path
        );

        Ok(ApplyUpstreamUpdateResult {
            log_source_id,
            updated: true,
            needs_deploy: log_source.deployed,
            message: format!("Updated '{}' parser VRL from upstream", log_source.name),
        })
    }

    /// Apply all pending upstream updates for a repository.
    pub async fn apply_all_upstream_updates(
        &self,
        repo_id: Uuid,
    ) -> Result<BulkApplyUpstreamResult, ParserRepositoryError> {
        let updates = self.get_upstream_updates(repo_id).await?;

        let mut results = Vec::new();
        let mut updated = 0u32;
        let mut failed = 0u32;

        for update in updates {
            match self.apply_upstream_update(update.log_source_id).await {
                Ok(result) => {
                    updated += 1;
                    results.push(result);
                }
                Err(e) => {
                    failed += 1;
                    warn!(
                        "Failed to apply upstream update for log source {}: {}",
                        update.log_source_id, e
                    );
                    results.push(ApplyUpstreamUpdateResult {
                        log_source_id: update.log_source_id,
                        updated: false,
                        needs_deploy: false,
                        message: format!("Failed: {}", e),
                    });
                }
            }
        }

        Ok(BulkApplyUpstreamResult {
            updated,
            failed,
            results,
        })
    }

    // =========================================================================
    // Imports lookup
    // =========================================================================

    pub async fn get_imports_for_repository(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<ParserImport>, ParserRepositoryError> {
        self.imports_repository
            .list_for_repository(repo_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))
    }

    // =========================================================================
    // Match values fixup
    // =========================================================================

    /// Re-sync match_values from upstream YAML for all imported log sources.
    /// This fixes log sources that were imported before match_values threading was added.
    pub async fn fixup_imported_match_values(&self) -> Result<u32, ParserRepositoryError> {
        let ls_repo = self.log_source_repository.as_ref().ok_or_else(|| {
            ParserRepositoryError::Internal("Log source repository not available".to_string())
        })?;

        let rows = self
            .imports_repository
            .list_with_raw_content()
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        let mut updated = 0u32;
        for (log_source_id, raw_content) in &rows {
            let parsed = match super::yaml_parser::parse_parser_yaml(raw_content) {
                Ok(p) => p,
                Err(_) => continue,
            };
            // Use the same union logic as import_parser so periodic sync
            // doesn't clobber the parser's canonical name from match_values.
            // We don't track the original UI-provided source_type override
            // across syncs, so we pass None — the parser's name (from the
            // YAML's `name:` field) is what we anchor on. NAN-920.
            let yaml_match_values = parsed.match_values.clone().unwrap_or_default();
            let resolved = Self::resolve_match_values(
                None,
                &yaml_match_values,
                Some(parsed.name.as_str()),
            );
            if resolved.is_empty() {
                continue;
            }

            let update = crate::log_sources::UpdateLogSource {
                match_values: Some(resolved),
                ..Default::default()
            };
            if let Err(e) = ls_repo.update(*log_source_id, &update).await {
                warn!(
                    "Failed to fixup match_values for log source {}: {}",
                    log_source_id, e
                );
                continue;
            }
            updated += 1;
        }

        if updated > 0 {
            info!("Fixed match_values for {} imported log sources", updated);
        }
        Ok(updated)
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// NAN-920: build the `match_values` list for an imported / re-synced
    /// log source. We union three sources, dedup-preserving order:
    ///
    /// 1. UI override (`req.source_type`) — when present, lands first so
    ///    the parser's canonical identifier is the primary entry.
    /// 2. YAML's `match_values` — legacy aliases that drive OOTB routing
    ///    rule targets (e.g. apache_http_server's YAML declares
    ///    `[apache, apache_access, apache_error]`; without these, HEC's
    ///    seeded rules with target `apache` would render as orphans).
    /// 3. Parser name fallback — last-resort identifier when neither of
    ///    the above produced any entries.
    ///
    /// Falls back to `["unknown"]` if all sources are empty (e.g. a
    /// minimal parser YAML with no name and no UI input).
    pub(super) fn resolve_match_values(
        ui_source_type: Option<&str>,
        yaml_match_values: &[String],
        parser_name: Option<&str>,
    ) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let push = |out: &mut Vec<String>,
                    seen: &mut std::collections::HashSet<String>,
                    value: &str| {
            let trimmed = value.trim();
            if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
                out.push(trimmed.to_string());
            }
        };

        if let Some(st) = ui_source_type {
            push(&mut out, &mut seen, st);
        }
        for alias in yaml_match_values {
            push(&mut out, &mut seen, alias);
        }
        if out.is_empty() {
            if let Some(n) = parser_name {
                push(&mut out, &mut seen, n);
            }
        }
        if out.is_empty() {
            out.push("unknown".to_string());
        }
        out
    }

    fn validate_url(&self, url: &str) -> Result<(), ParserRepositoryError> {
        let normalized = url
            .trim_end_matches('/')
            .trim_end_matches(".git")
            .to_lowercase();

        let is_allowed = ALLOWED_REPOSITORIES.iter().any(|allowed| {
            let suffix = format!("github.com/{}", allowed);
            normalized == format!("https://{}", suffix)
                || normalized == format!("http://{}", suffix)
        });

        if !is_allowed {
            return Err(ParserRepositoryError::RepositoryNotAllowed(url.to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-920: a UI source_type override (e.g. parser name) plus YAML
    /// match_values aliases unions cleanly with the override first and
    /// no duplicates.
    #[test]
    fn resolve_match_values_unions_ui_override_and_yaml_aliases() {
        let result = ParserRepositoryService::resolve_match_values(
            Some("apache_http_server"),
            &["apache".into(), "apache_access".into(), "apache_error".into()],
            Some("apache_http_server"),
        );
        assert_eq!(
            result,
            vec![
                "apache_http_server".to_string(),
                "apache".to_string(),
                "apache_access".to_string(),
                "apache_error".to_string(),
            ]
        );
    }

    /// Dedups when the UI override appears in YAML match_values too —
    /// preserves first-occurrence ordering.
    #[test]
    fn resolve_match_values_dedups_when_override_is_in_yaml() {
        let result = ParserRepositoryService::resolve_match_values(
            Some("apache"),
            &["apache".into(), "apache_access".into()],
            Some("apache"),
        );
        assert_eq!(result, vec!["apache".to_string(), "apache_access".to_string()]);
    }

    /// Fixup path: no UI override (None), parser name + YAML aliases.
    #[test]
    fn resolve_match_values_fixup_path_includes_parser_name_if_no_yaml_match() {
        let result =
            ParserRepositoryService::resolve_match_values(None, &[], Some("custom_parser"));
        assert_eq!(result, vec!["custom_parser".to_string()]);
    }

    /// Fixup path with YAML aliases that already include the parser name —
    /// doesn't duplicate.
    #[test]
    fn resolve_match_values_fixup_path_with_yaml_aliases() {
        let result = ParserRepositoryService::resolve_match_values(
            None,
            &["apache_http_server".into(), "apache".into()],
            Some("apache_http_server"),
        );
        assert_eq!(
            result,
            vec!["apache_http_server".to_string(), "apache".to_string()]
        );
    }

    /// Empty / whitespace-only entries are skipped, never end up in the
    /// list. Guards against bad YAML.
    #[test]
    fn resolve_match_values_skips_empty_and_whitespace_entries() {
        let result = ParserRepositoryService::resolve_match_values(
            Some(""),
            &["".into(), "   ".into(), "apache".into()],
            Some(""),
        );
        assert_eq!(result, vec!["apache".to_string()]);
    }

    /// Last-resort fallback when literally everything is empty: ["unknown"].
    #[test]
    fn resolve_match_values_falls_back_to_unknown() {
        let result = ParserRepositoryService::resolve_match_values(None, &[], None);
        assert_eq!(result, vec!["unknown".to_string()]);
    }
}
