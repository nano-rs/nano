// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sync operations for rule repositories.
//!
//! Handles syncing rules from GitHub repositories, including both
//! background (non-blocking) and foreground (blocking) sync modes,
//! upstream change detection, and diff computation.

use std::time::Instant;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::super::error::RuleRepositoryError;
use super::super::github_client::{GitHubClient, TreeEntry};
use super::super::models::{RuleRepository, SyncResult, SyncStatus, UpdatedRule, UpstreamDiff};
use super::super::npl_parser::parse_npl;
use super::super::repository::{
    RepositoryRulesRepository, RuleImportsRepository, RuleRepositoryRepository,
};
use super::super::sigma_parser::{
    extract_mitre_tactics, extract_mitre_techniques, extract_required_fields,
    map_logsource_to_source_types, map_severity, parse_sigma,
};
use super::helpers::{apply_customizations_to_query, collect_rule_files};
use super::{RuleRepositoryService, RuleRepositoryServiceConfig};

impl RuleRepositoryService {
    // =========================================================================
    // Sync Operations
    // =========================================================================

    /// Start a sync in the background (non-blocking)
    pub async fn start_sync(&self, id: Uuid) -> Result<(), RuleRepositoryError> {
        // Check if sync is already in progress
        {
            let mut syncing = self.syncing_repos.write().await;
            if syncing.contains(&id) {
                return Err(RuleRepositoryError::SyncInProgress(id));
            }
            syncing.insert(id);
        }

        let repo = self.get_repository(id).await?;

        if !repo.enabled {
            // Remove from syncing set since we're not actually syncing
            let mut syncing = self.syncing_repos.write().await;
            syncing.remove(&id);
            return Err(RuleRepositoryError::RepositoryDisabled);
        }

        // Mark sync as in progress
        let _ = self
            .repo_repository
            .update_sync_status(id, "syncing", None, None, None)
            .await;

        // Clone what we need for the background task
        let repo_repository = self.repo_repository.clone();
        let rules_repository = self.rules_repository.clone();
        let imports_repository = self.imports_repository.clone();
        let github_client = self.github_client.clone();
        let config = self.config.clone();
        let syncing_repos = self.syncing_repos.clone();

        // Spawn the sync task
        tokio::spawn(async move {
            let result = Self::run_sync(
                id,
                repo,
                repo_repository.clone(),
                rules_repository,
                imports_repository,
                github_client,
                config,
            )
            .await;

            // Update status based on result
            match result {
                Ok(sync_result) => {
                    let _ = repo_repository
                        .update_sync_status(
                            id,
                            "success",
                            sync_result.commit.as_deref(),
                            Some(sync_result.rules_total),
                            None,
                        )
                        .await;
                    info!(
                        "Background sync complete for repo {}: {} added, {} updated, {} removed",
                        id,
                        sync_result.rules_added,
                        sync_result.rules_updated,
                        sync_result.rules_removed
                    );
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    let _ = repo_repository
                        .update_sync_status(id, "failed", None, None, Some(&error_msg))
                        .await;
                    warn!("Background sync failed for repo {}: {}", id, error_msg);
                }
            }

            // Remove from syncing set
            let mut syncing = syncing_repos.write().await;
            syncing.remove(&id);
        });

        Ok(())
    }

    /// Internal sync implementation (runs in background task)
    pub(crate) async fn run_sync(
        id: Uuid,
        repo: RuleRepository,
        _repo_repository: RuleRepositoryRepository,
        rules_repository: RepositoryRulesRepository,
        imports_repository: RuleImportsRepository,
        github_client: GitHubClient,
        config: RuleRepositoryServiceConfig,
    ) -> Result<SyncResult, RuleRepositoryError> {
        let start = Instant::now();

        // Parse GitHub URL
        let (owner, repo_name) = GitHubClient::parse_url(&repo.url)
            .map_err(|_| RuleRepositoryError::InvalidUrl(repo.url.clone()))?;

        info!("Syncing repository {}/{} ({})", owner, repo_name, repo.name);

        // Get rule files - use git sparse-checkout for selected paths (avoids API rate limits entirely)
        let rules_path = repo.rules_path.as_deref().unwrap_or("rules/");

        let (rule_files, temp_dir, commit) = if let Some(ref selected) = repo.selected_paths {
            if !selected.is_empty() {
                // Use git sparse-checkout to clone only selected paths (NO API CALLS!)
                info!("Using sparse checkout for paths: {:?}", selected);

                let temp_dir = tempfile::tempdir().map_err(|e| {
                    RuleRepositoryError::Internal(format!("Failed to create temp dir: {}", e))
                })?;

                github_client
                    .sparse_clone(&owner, &repo_name, &repo.branch, selected, temp_dir.path())
                    .await
                    .map_err(|e| RuleRepositoryError::GitHubApi(e.to_string()))?;

                let commit = GitHubClient::get_local_commit(temp_dir.path())
                    .await
                    .map_err(|e| RuleRepositoryError::GitHubApi(e.to_string()))?;

                // Skip if commit hasn't changed
                if repo.last_sync_commit.as_ref() == Some(&commit) {
                    info!(
                        "Repository {} is up to date at commit {}",
                        repo.name, commit
                    );
                    return Ok(SyncResult {
                        repository_id: id,
                        status: SyncStatus::Success,
                        commit: Some(commit),
                        rules_added: 0,
                        rules_updated: 0,
                        rules_removed: 0,
                        rules_total: repo.rule_count,
                        conversion_succeeded: 0,
                        conversion_failed: 0,
                        duration_ms: start.elapsed().as_millis() as u64,
                        error: None,
                    });
                }

                // Walk local filesystem to find rule files
                let mut files = Vec::new();
                let temp_canonical = temp_dir.path().canonicalize().map_err(|e| {
                    RuleRepositoryError::Internal(format!("Failed to canonicalize temp dir: {}", e))
                })?;

                for selected_path in selected {
                    // Reject paths with traversal sequences before joining
                    if selected_path.contains("..") {
                        warn!("Path traversal attempt blocked: {}", selected_path);
                        continue;
                    }

                    let full_path = temp_dir.path().join(selected_path);

                    info!("Checking path: {:?} (exists={})", full_path, full_path.exists());
                    // Debug: list directory contents
                    if let Ok(entries) = std::fs::read_dir(&full_path) {
                        for entry in entries.flatten() {
                            info!("  dir entry: {:?} (is_file={}, is_dir={})", entry.path(), entry.path().is_file(), entry.path().is_dir());
                        }
                    }
                    info!("  rule_extensions: {:?}", config.rule_extensions);
                    // Verify the canonicalized path is within the temp directory
                    if full_path.exists() {
                        let canonical = match full_path.canonicalize() {
                            Ok(p) => p,
                            Err(_) => continue, // Skip if canonicalization fails
                        };

                        if !canonical.starts_with(&temp_canonical) {
                            warn!(
                                "Path traversal attempt blocked (escaped temp dir): {}",
                                selected_path
                            );
                            continue;
                        }

                        collect_rule_files(
                            &canonical,
                            &temp_canonical,
                            &config.rule_extensions,
                            &mut files,
                        );
                    }
                }

                info!("Found {} rule files via sparse checkout (selected_paths={:?}, temp_dir={:?})", files.len(), selected, temp_dir.path());
                for f in &files {
                    info!("  rule file: {}", f.path);
                }
                (files, Some(temp_dir), commit)
            } else {
                // Empty selected_paths means sync nothing
                let commit = github_client
                    .get_latest_commit(&owner, &repo_name, &repo.branch)
                    .await
                    .map_err(|e| RuleRepositoryError::GitHubApi(e.to_string()))?;
                (Vec::new(), None, commit)
            }
        } else {
            // No selected_paths - use API (Tree API for files, get_latest_commit for change detection)
            let commit = github_client
                .get_latest_commit(&owner, &repo_name, &repo.branch)
                .await
                .map_err(|e| RuleRepositoryError::GitHubApi(e.to_string()))?;

            // Skip if commit hasn't changed
            if repo.last_sync_commit.as_ref() == Some(&commit) {
                info!(
                    "Repository {} is up to date at commit {}",
                    repo.name, commit
                );
                return Ok(SyncResult {
                    repository_id: id,
                    status: SyncStatus::Success,
                    commit: Some(commit),
                    rules_added: 0,
                    rules_updated: 0,
                    rules_removed: 0,
                    rules_total: repo.rule_count,
                    conversion_succeeded: 0,
                    conversion_failed: 0,
                    duration_ms: start.elapsed().as_millis() as u64,
                    error: None,
                });
            }

            let tree = github_client
                .get_tree(&owner, &repo_name, &repo.branch, Some(rules_path))
                .await
                .map_err(|e| RuleRepositoryError::GitHubApi(e.to_string()))?;

            let files: Vec<TreeEntry> = tree
                .into_iter()
                .filter(|e| {
                    e.entry_type == "blob"
                        && config
                            .rule_extensions
                            .iter()
                            .any(|ext| e.path.ends_with(ext))
                })
                .collect();

            (files, None, commit)
        };

        // Apply max limit
        let mut rule_files = rule_files;
        rule_files.truncate(config.max_rules_per_repo);

        debug!("Found {} rule files in repository", rule_files.len());

        let mut rules_added = 0;
        let mut rules_updated = 0;
        let mut synced_paths = Vec::new();

        // Process each rule file
        for entry in &rule_files {
            synced_paths.push(entry.path.clone());

            // For local files (sparse checkout), we compare by content hash since SHA is empty
            // For API-fetched files, we use the GitHub SHA
            let existing = rules_repository.find_by_path(id, &entry.path).await.ok();

            // Fetch file content - from local filesystem if we have temp_dir, otherwise via API
            let content = if let Some(ref dir) = temp_dir {
                let file_path = dir.path().join(&entry.path);
                match std::fs::read_to_string(&file_path) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Failed to read local file {}: {}", entry.path, e);
                        continue;
                    }
                }
            } else {
                match github_client
                    .get_raw_file(&owner, &repo_name, &entry.path, &repo.branch)
                    .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Failed to fetch {}: {}", entry.path, e);
                        continue;
                    }
                }
            };

            // Compute content hash for change detection (used for local files)
            use sha2::{Digest, Sha256};
            let content_hash = hex::encode(Sha256::digest(content.as_bytes()));

            // Check if content has changed (use content hash for sparse checkout, SHA for API)
            if let Some(ref existing_rule) = existing {
                let stored_sha = existing_rule.file_sha.as_deref().unwrap_or("");
                if !entry.sha.is_empty() && stored_sha == entry.sha {
                    continue; // No changes (API path)
                }
                if entry.sha.is_empty() && stored_sha == content_hash {
                    continue; // No changes (sparse checkout path)
                }
            }

            // Use content hash as SHA for local files
            let file_sha = if entry.sha.is_empty() {
                &content_hash
            } else {
                &entry.sha
            };

            // Parse based on format
            let (
                title,
                description,
                severity,
                mitre_tactics,
                mitre_techniques,
                tags,
                requires_fields,
                requires_source_types,
                conversion_status,
            ) = if repo.rule_format == "sigma" {
                match parse_sigma(&content) {
                    Ok(sigma) => {
                        let fields = extract_required_fields(&sigma);
                        let source_types = map_logsource_to_source_types(&sigma.logsource);
                        let tactics = extract_mitre_tactics(&sigma.tags);
                        let techniques = extract_mitre_techniques(&sigma.tags);
                        (
                            Some(sigma.title),
                            sigma.description,
                            Some(map_severity(sigma.level.as_deref())),
                            if tactics.is_empty() {
                                None
                            } else {
                                Some(tactics)
                            },
                            if techniques.is_empty() {
                                None
                            } else {
                                Some(techniques)
                            },
                            if sigma.tags.is_empty() {
                                None
                            } else {
                                Some(sigma.tags)
                            },
                            if fields.is_empty() {
                                None
                            } else {
                                Some(fields)
                            },
                            if source_types.is_empty() {
                                None
                            } else {
                                Some(source_types)
                            },
                            None, // Sigma rules stay pending until AI conversion
                        )
                    }
                    Err(e) => {
                        warn!("Failed to parse Sigma rule {}: {}", entry.path, e);
                        // Store anyway with minimal metadata
                        (None, None, None, None, None, None, None, None, Some("failed"))
                    }
                }
            } else {
                // nano/nPL format - parse YAML frontmatter and extract metadata
                match parse_npl(&content) {
                    Ok(npl) => (
                        Some(npl.title),
                        npl.description,
                        npl.severity,
                        if npl.mitre_tactics.is_empty() {
                            None
                        } else {
                            Some(npl.mitre_tactics)
                        },
                        if npl.mitre_techniques.is_empty() {
                            None
                        } else {
                            Some(npl.mitre_techniques)
                        },
                        if npl.tags.is_empty() {
                            None
                        } else {
                            Some(npl.tags)
                        },
                        if npl.required_fields.is_empty() {
                            None
                        } else {
                            Some(npl.required_fields)
                        },
                        if npl.source_types.is_empty() {
                            None
                        } else {
                            Some(npl.source_types)
                        },
                        Some("success"), // nPL rules are already native format
                    ),
                    Err(e) => {
                        warn!("Failed to parse nPL rule {}: {}", entry.path, e);
                        // Store anyway with minimal metadata
                        (None, None, None, None, None, None, None, None, Some("failed"))
                    }
                }
            };

            // Upsert the rule
            let _ = rules_repository
                .upsert(
                    id,
                    &entry.path,
                    Some(file_sha),
                    &content,
                    title.as_deref(),
                    description.as_deref(),
                    severity.as_deref(),
                    mitre_tactics.as_deref(),
                    mitre_techniques.as_deref(),
                    tags.as_deref(),
                    requires_fields.as_deref(),
                    requires_source_types.as_deref(),
                    conversion_status,
                )
                .await;

            if existing.is_some() {
                rules_updated += 1;

                // Mark any linked imports as having upstream changes
                if let Ok(existing_rule) = rules_repository.find_by_path(id, &entry.path).await {
                    let _ = imports_repository
                        .mark_upstream_changed(existing_rule.id)
                        .await;
                }
            } else {
                rules_added += 1;
            }
        }

        // Remove rules that no longer exist in the repository
        let rules_removed = rules_repository
            .delete_not_in_paths(id, &synced_paths)
            .await
            .unwrap_or(0) as i32;

        let rules_total = rule_files.len() as i32;

        info!(
            "Sync complete for {}: {} added, {} updated, {} removed, {} total",
            repo.name, rules_added, rules_updated, rules_removed, rules_total
        );

        Ok(SyncResult {
            repository_id: id,
            status: SyncStatus::Success,
            commit: Some(commit),
            rules_added,
            rules_updated,
            rules_removed,
            rules_total,
            conversion_succeeded: 0,
            conversion_failed: 0,
            duration_ms: start.elapsed().as_millis() as u64,
            error: None,
        })
    }

    /// Sync rules from a repository (blocking - waits for completion)
    /// Note: Prefer `start_sync` for non-blocking sync that won't get stuck if client disconnects
    pub async fn sync_repository(&self, id: Uuid) -> Result<SyncResult, RuleRepositoryError> {
        // Check if sync is already in progress
        {
            let mut syncing = self.syncing_repos.write().await;
            if syncing.contains(&id) {
                return Err(RuleRepositoryError::SyncInProgress(id));
            }
            syncing.insert(id);
        }

        let repo = self.get_repository(id).await?;

        if !repo.enabled {
            let mut syncing = self.syncing_repos.write().await;
            syncing.remove(&id);
            return Err(RuleRepositoryError::RepositoryDisabled);
        }

        // Mark sync as in progress
        let _ = self
            .repo_repository
            .update_sync_status(id, "syncing", None, None, None)
            .await;

        // Run the sync
        let result = Self::run_sync(
            id,
            repo,
            self.repo_repository.clone(),
            self.rules_repository.clone(),
            self.imports_repository.clone(),
            self.github_client.clone(),
            self.config.clone(),
        )
        .await;

        // Update status based on result
        match &result {
            Ok(sync_result) => {
                let _ = self
                    .repo_repository
                    .update_sync_status(
                        id,
                        "success",
                        sync_result.commit.as_deref(),
                        Some(sync_result.rules_total),
                        None,
                    )
                    .await;
            }
            Err(e) => {
                let _ = self
                    .repo_repository
                    .update_sync_status(id, "failed", None, None, Some(&e.to_string()))
                    .await;
            }
        }

        // Clean up syncing flag
        {
            let mut syncing = self.syncing_repos.write().await;
            syncing.remove(&id);
        }

        result
    }

    /// Check for updates in imported rules (both linked and forked)
    pub async fn check_for_updates(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<UpdatedRule>, RuleRepositoryError> {
        let imports = self
            .imports_repository
            .list_with_upstream_changes_for_repo(repo_id)
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))?;

        let mut updated = Vec::new();
        for import in imports {
            if let Ok(repo_rule) = self
                .rules_repository
                .find_by_id(import.repository_rule_id)
                .await
            {
                updated.push(UpdatedRule {
                    repository_rule_id: import.repository_rule_id,
                    detection_rule_id: import.detection_rule_id,
                    file_path: repo_rule.file_path,
                    title: repo_rule.title,
                    change_type: "modified".to_string(),
                    old_sha: import.last_sync_commit,
                    new_sha: repo_rule.file_sha,
                });
            }
        }

        Ok(updated)
    }

    /// Get count of rules with upstream changes across all repos
    pub async fn count_upstream_changes(&self) -> Result<i64, RuleRepositoryError> {
        let imports = self
            .imports_repository
            .list_with_upstream_changes()
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))?;

        Ok(imports.len() as i64)
    }

    /// Get diff between imported detection rule and current upstream rule
    pub async fn get_upstream_diff(
        &self,
        detection_rule_id: Uuid,
    ) -> Result<UpstreamDiff, RuleRepositoryError> {
        // Find the import record
        let import = self
            .imports_repository
            .find_by_detection_rule(detection_rule_id)
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))?
            .ok_or_else(|| RuleRepositoryError::ImportNotFound(detection_rule_id))?;

        // Get the upstream repository rule
        let repo_rule = self
            .rules_repository
            .find_by_id(import.repository_rule_id)
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))?;

        // Get the detection rule to compare
        let detection_service = self.detection_service.as_ref().ok_or_else(|| {
            RuleRepositoryError::Internal("Detection service not configured".to_string())
        })?;

        let detection_rule = detection_service
            .get_rule(detection_rule_id)
            .await
            .map_err(|e| RuleRepositoryError::Internal(e.to_string()))?;

        // Get the upstream query (parse nPL or use converted)
        let repo = self.get_repository(repo_rule.repository_id).await?;
        let upstream_query = if repo.rule_format == "nanosiem" {
            parse_npl(&repo_rule.raw_content)
                .map(|npl| npl.query)
                .unwrap_or_else(|_| repo_rule.raw_content.clone())
        } else {
            repo_rule.converted_npl.clone().unwrap_or_default()
        };

        // Apply stored customizations (source_type mappings) so diffs only show real upstream changes
        let customizations_applied = import.customizations.is_some();
        let upstream_query = apply_customizations_to_query(upstream_query, &import.customizations);

        Ok(UpstreamDiff {
            detection_rule_id,
            repository_rule_id: repo_rule.id,
            file_path: repo_rule.file_path,
            upstream_title: repo_rule.title,
            upstream_description: repo_rule.description,
            upstream_severity: repo_rule.severity,
            upstream_query,
            upstream_raw_content: repo_rule.raw_content,
            current_query: detection_rule.query,
            current_title: detection_rule.name,
            current_description: detection_rule.description,
            has_changes: import.upstream_changed,
            customizations_applied: Some(customizations_applied),
        })
    }

    /// Dismiss upstream changes (mark as acknowledged without updating)
    pub async fn dismiss_upstream_changes(
        &self,
        detection_rule_id: Uuid,
    ) -> Result<(), RuleRepositoryError> {
        let import = self
            .imports_repository
            .find_by_detection_rule(detection_rule_id)
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))?
            .ok_or_else(|| RuleRepositoryError::ImportNotFound(detection_rule_id))?;

        self.imports_repository
            .clear_upstream_changed(import.id)
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))?;

        Ok(())
    }
}
