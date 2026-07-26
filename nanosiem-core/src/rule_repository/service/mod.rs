// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule Repository Service
//!
//! Provides high-level operations for managing external rule repositories,
//! syncing rules from GitHub, and importing rules into NanoSIEM.
//!
//! This module is organized into focused submodules:
//! - [`crud`] - Repository CRUD operations and folder listing
//! - [`sync`] - Sync operations, upstream change detection, and diffs
//! - [`browse`] - Rule browsing and import preview
//! - [`import`] - Rule import into detection engine
//! - [`coverage`] - Coverage analysis operations
//! - [`helpers`] - Utility functions (string conversion, MITRE mapping, etc.)

mod browse;
mod coverage;
mod crud;
pub(crate) mod helpers;
pub(crate) mod import;
mod sync;

#[cfg(test)]
#[path = "import_authz_tests.rs"]
mod import_authz_tests;

pub use import::{RuleImportAction, RuleImportPlan};

use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::db::DualPool;
use crate::detection::DetectionService;

use super::coverage::CoverageAnalyzer;
use super::github_client::GitHubClient;
use super::repository::{
    RepositoryRulesRepository, RuleImportsRepository, RuleRepositoryRepository,
};

/// Allowed repository sources (owner/repo format, lowercase for comparison)
/// Only these repositories can be added - prevents arbitrary external code sync
const ALLOWED_REPOSITORIES: &[&str] = &["nano-rs/rules", "sigmahq/sigma"];

/// Configuration for the rule repository service
#[derive(Debug, Clone)]
pub struct RuleRepositoryServiceConfig {
    /// Maximum rules to sync per repository
    pub max_rules_per_repo: usize,
    /// Whether to auto-convert Sigma rules during sync
    pub auto_convert_sigma: bool,
    /// Whether to auto-analyze coverage during sync
    pub auto_analyze_coverage: bool,
    /// File extensions to consider as rules
    pub rule_extensions: Vec<String>,
}

impl Default for RuleRepositoryServiceConfig {
    fn default() -> Self {
        Self {
            max_rules_per_repo: 10000,
            auto_convert_sigma: false, // Disabled by default - conversion via AI is expensive
            auto_analyze_coverage: true,
            rule_extensions: vec!["yml".to_string(), "yaml".to_string()],
        }
    }
}

/// Service for managing rule repositories
pub struct RuleRepositoryService {
    repo_repository: RuleRepositoryRepository,
    rules_repository: RepositoryRulesRepository,
    imports_repository: RuleImportsRepository,
    github_client: GitHubClient,
    coverage_analyzer: Arc<RwLock<CoverageAnalyzer>>,
    detection_service: Option<Arc<DetectionService>>,
    config: RuleRepositoryServiceConfig,
    pg_pool: PgPool,
    /// Track repositories currently being synced
    syncing_repos: Arc<RwLock<std::collections::HashSet<uuid::Uuid>>>,
}

impl RuleRepositoryService {
    /// Create a new service with DualPool (includes ClickHouse for coverage analysis)
    pub fn with_dual_pool(dual_pool: &DualPool) -> Self {
        let pg_pool = dual_pool.postgres().clone();
        Self {
            repo_repository: RuleRepositoryRepository::new(pg_pool.clone()),
            rules_repository: RepositoryRulesRepository::new(pg_pool.clone()),
            imports_repository: RuleImportsRepository::new(pg_pool.clone()),
            github_client: GitHubClient::new(),
            coverage_analyzer: Arc::new(RwLock::new(CoverageAnalyzer::new(dual_pool.clone()))),
            detection_service: None,
            config: RuleRepositoryServiceConfig::default(),
            pg_pool,
            syncing_repos: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Set the detection service for importing rules
    pub fn with_detection_service(mut self, detection_service: Arc<DetectionService>) -> Self {
        self.detection_service = Some(detection_service);
        self
    }

    /// Set custom configuration
    pub fn with_config(mut self, config: RuleRepositoryServiceConfig) -> Self {
        self.config = config;
        self
    }
}
