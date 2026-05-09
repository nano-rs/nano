// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repository CRUD operations.
//!
//! Handles creating, reading, updating, and deleting rule repositories,
//! as well as listing folders within a repository.

use std::collections::HashMap;
use tracing::warn;
use uuid::Uuid;

use super::super::error::RuleRepositoryError;
use super::super::github_client::GitHubClient;
use super::super::models::{FolderInfo, NewRuleRepository, RuleRepository, UpdateRuleRepository};
use super::RuleRepositoryService;
use super::ALLOWED_REPOSITORIES;

impl RuleRepositoryService {
    // =========================================================================
    // Repository CRUD
    // =========================================================================

    /// List all repositories
    pub async fn list_repositories(&self) -> Result<Vec<RuleRepository>, RuleRepositoryError> {
        self.repo_repository
            .list()
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))
    }

    /// Get a repository by ID
    pub async fn get_repository(&self, id: Uuid) -> Result<RuleRepository, RuleRepositoryError> {
        self.repo_repository
            .find_by_id(id)
            .await
            .map_err(|e| match e {
                super::super::repository::RuleRepositoryRepositoryError::NotFound(_) => {
                    RuleRepositoryError::RepositoryNotFound(id)
                }
                _ => RuleRepositoryError::from_repo_error(e),
            })
    }

    /// Get a repository by slug
    pub async fn get_repository_by_slug(
        &self,
        slug: &str,
    ) -> Result<RuleRepository, RuleRepositoryError> {
        self.repo_repository
            .find_by_slug(slug)
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))
    }

    /// Create a new repository
    pub async fn create_repository(
        &self,
        req: NewRuleRepository,
        user_id: Option<Uuid>,
    ) -> Result<RuleRepository, RuleRepositoryError> {
        // Validate URL format
        let (owner, repo_name) = GitHubClient::parse_url(&req.url)
            .map_err(|_| RuleRepositoryError::InvalidUrl(req.url.clone()))?;

        // Check against allowlist - only permitted repositories can be added
        let repo_key = format!("{}/{}", owner.to_lowercase(), repo_name.to_lowercase());
        if !ALLOWED_REPOSITORIES.contains(&repo_key.as_str()) {
            warn!("Attempted to add non-allowlisted repository: {}", repo_key);
            return Err(RuleRepositoryError::RepositoryNotAllowed(repo_key));
        }

        self.repo_repository
            .create(&req, user_id)
            .await
            .map_err(|e| match e {
                super::super::repository::RuleRepositoryRepositoryError::AlreadyExists(name) => {
                    RuleRepositoryError::RepositoryAlreadyExists(name)
                }
                _ => RuleRepositoryError::from_repo_error(e),
            })
    }

    /// Update a repository
    pub async fn update_repository(
        &self,
        id: Uuid,
        req: UpdateRuleRepository,
    ) -> Result<RuleRepository, RuleRepositoryError> {
        self.repo_repository
            .update(id, &req)
            .await
            .map_err(|e| match e {
                super::super::repository::RuleRepositoryRepositoryError::NotFound(_) => {
                    RuleRepositoryError::RepositoryNotFound(id)
                }
                _ => RuleRepositoryError::from_repo_error(e),
            })
    }

    /// Delete a repository
    pub async fn delete_repository(&self, id: Uuid) -> Result<(), RuleRepositoryError> {
        self.repo_repository.delete(id).await.map_err(|e| match e {
            super::super::repository::RuleRepositoryRepositoryError::NotFound(_) => {
                RuleRepositoryError::RepositoryNotFound(id)
            }
            _ => RuleRepositoryError::from_repo_error(e),
        })
    }

    /// List available folders in a repository (for folder selection UI)
    pub async fn list_folders(&self, id: Uuid) -> Result<Vec<FolderInfo>, RuleRepositoryError> {
        let repo = self.get_repository(id).await?;

        // Parse GitHub URL
        let (owner, repo_name) = GitHubClient::parse_url(&repo.url)
            .map_err(|_| RuleRepositoryError::InvalidUrl(repo.url.clone()))?;
        let rules_path = repo.rules_path.as_deref().unwrap_or("rules/");

        // Fetch tree from GitHub
        let tree = self
            .github_client
            .get_tree(&owner, &repo_name, &repo.branch, Some(rules_path))
            .await
            .map_err(|e| RuleRepositoryError::GitHubApi(e.to_string()))?;

        // Extract unique top-level folders under rules_path
        let rules_path_normalized = rules_path.trim_start_matches('/').trim_end_matches('/');
        let prefix_len = if rules_path_normalized.is_empty() {
            0
        } else {
            rules_path_normalized.len() + 1
        };

        let mut folder_counts: HashMap<String, (i32, i32)> = HashMap::new();

        for entry in &tree {
            if entry.entry_type != "blob" {
                continue;
            }
            // Get relative path after rules_path
            let relative_path = if entry.path.len() > prefix_len {
                &entry.path[prefix_len..]
            } else {
                continue;
            };

            // Get first folder component
            if let Some(slash_pos) = relative_path.find('/') {
                let folder = &relative_path[..slash_pos];
                let entry = folder_counts.entry(folder.to_string()).or_insert((0, 0));
                entry.0 += 1; // file count

                // Check if it's a yml/yaml file (rule)
                if relative_path.ends_with(".yml") || relative_path.ends_with(".yaml") {
                    entry.1 += 1; // rule count
                }
            }
        }

        let mut folders: Vec<FolderInfo> = folder_counts
            .into_iter()
            .map(|(name, (file_count, rule_count))| FolderInfo {
                name: name.clone(),
                path: if rules_path_normalized.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", rules_path_normalized, name)
                },
                file_count,
                rule_count,
            })
            .collect();

        folders.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(folders)
    }
}
