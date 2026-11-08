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
#[doc(hidden)]
pub use sync::{staged_row, StagedRow, StagedSync};

use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::rule_repository::GitHubClient;

use super::repository::{
    PlaybookImportsRepository, PlaybookRepoRepository, RepositoryPlaybooksRepository,
};

/// Allowed playbook repository sources (owner/repo format, lowercase).
const ALLOWED_REPOSITORIES: &[&str] = &["nano-rs/playbooks"];
/// Synthetic repository signed air-gap playbook bundles are applied to.
const AIRGAP_PLAYBOOKS_URL: &str = "airgap://playbooks";

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
    /// NAN-4947: leader fence for sync writes. Disabled for operator-driven
    /// API syncs; the jobs leader's scheduler passes its armed fence.
    pub(crate) fence: crate::leader::LeaderFence,
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
            fence: crate::leader::LeaderFence::disabled(),
        }
    }

    /// Fence every sync write with the leader's lease epoch (NAN-4947): the
    /// network fetch runs unfenced, then the catalog writes, prune, import
    /// marking and status update commit in ONE transaction that first checks
    /// this process still holds the current epoch.
    pub fn with_fence(mut self, fence: crate::leader::LeaderFence) -> Self {
        self.fence = fence;
        self
    }

    /// NAN-4947: only nano first-party repositories (and the air-gap bundle
    /// repository) are admissible.
    pub fn first_party(url: &str) -> bool {
        crate::content_catalog_defaults::is_allowed_repository(url, ALLOWED_REPOSITORIES, AIRGAP_PLAYBOOKS_URL)
    }
}
