// SPDX-License-Identifier: AGPL-3.0-or-later

//! Playbook repository service — syncs + imports external playbooks.
//!
//! Mirrors the `rule_repository::service` layout:
//!   * [`crud`] — repository CRUD
//!   * [`sync`] — GitHub sync (background + blocking)
//!   * [`import`] — import into the main `playbooks` table

mod crud;
mod import;
mod sync;

use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::rule_repository::GitHubClient;

use super::repository::{
    PlaybookImportsRepository, PlaybookRepoRepository, RepositoryPlaybooksRepository,
};

/// Allowed playbook repository sources (owner/repo format, lowercase).
const ALLOWED_REPOSITORIES: &[&str] = &["nanos-sh/playbooks"];

/// Configuration for the playbook repository service.
#[derive(Debug, Clone)]
pub struct PlaybookRepositoryServiceConfig {
    pub max_playbooks_per_repo: usize,
    pub playbook_extensions: Vec<String>,
}

impl Default for PlaybookRepositoryServiceConfig {
    fn default() -> Self {
        Self {
            max_playbooks_per_repo: 1000,
            playbook_extensions: vec!["md".to_string(), "markdown".to_string()],
        }
    }
}

/// Service for managing external playbook repositories.
#[derive(Clone)]
pub struct PlaybookRepositoryService {
    pub(crate) repo_repository: PlaybookRepoRepository,
    pub(crate) playbooks_repository: RepositoryPlaybooksRepository,
    pub(crate) imports_repository: PlaybookImportsRepository,
    pub(crate) github_client: GitHubClient,
    pub(crate) config: PlaybookRepositoryServiceConfig,
    pub(crate) pg_pool: PgPool,
    pub(crate) syncing_repos: Arc<RwLock<std::collections::HashSet<uuid::Uuid>>>,
}

impl PlaybookRepositoryService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo_repository: PlaybookRepoRepository::new(pool.clone()),
            playbooks_repository: RepositoryPlaybooksRepository::new(pool.clone()),
            imports_repository: PlaybookImportsRepository::new(pool.clone()),
            github_client: GitHubClient::new(),
            config: PlaybookRepositoryServiceConfig::default(),
            pg_pool: pool,
            syncing_repos: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    pub fn with_config(mut self, config: PlaybookRepositoryServiceConfig) -> Self {
        self.config = config;
        self
    }

    pub(crate) fn allowed_repos() -> &'static [&'static str] {
        ALLOWED_REPOSITORIES
    }
}
