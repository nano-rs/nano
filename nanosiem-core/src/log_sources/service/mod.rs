// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Source service for business logic
//!
//! Handles validation, deployment, and lifecycle management of log sources.
//!
//! Organized into focused submodules:
//! - `crud` — Create, read, update, delete operations
//! - `status` — Enable, disable, toggle operations
//! - `validation` — VRL validation and testing
//! - `deployment` — Deploy, undeploy, deploy_all operations
//! - `health` — Health metrics and ingestion history
//! - `versioning` — Version management, publish, revert, draft status
//! - `helpers` — Credential injection and conversion utilities

mod crud;
mod deployment;
mod health;
mod helpers;
mod status;
mod validation;
mod versioning;

use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;

use super::repository::{LogSourceRepository, LogSourceRepositoryError};
use super::version_repository::{LogSourceVersionError, LogSourceVersionRepository};
use crate::db::DualPool;
use crate::parsers::{
    CredentialRepository, CredentialRepositoryError, VectorConfigError, VectorConfigManager,
    VrlValidator,
};

#[derive(Error, Debug)]
pub enum LogSourceServiceError {
    #[error("Repository error: {0}")]
    RepositoryError(#[from] LogSourceRepositoryError),
    #[error("Credential error: {0}")]
    CredentialError(#[from] CredentialRepositoryError),
    #[error("Invalid VRL: {0}")]
    InvalidVrl(String),
    #[error("Invalid source type: {0}")]
    InvalidSourceType(String),
    #[error("Log source must be validated before enabling")]
    NotValidated,
    #[error("Vector config error: {0}")]
    VectorConfigError(#[from] VectorConfigError),
    #[error("VRL validation failed: {0}")]
    VrlValidationFailed(String),
    #[error("Vector validation failed: {0}")]
    VectorValidationFailed(String),
    #[error("Deployment failed: {0}")]
    DeploymentFailed(String),
    #[error("Reload failed")]
    ReloadFailed,
    #[error("Rollback failed: {0}")]
    RollbackFailed(String),
    #[error("Version error: {0}")]
    VersionError(#[from] LogSourceVersionError),
}

/// Log source service for managing log sources
#[derive(Clone)]
pub struct LogSourceService {
    pool: PgPool,
    ch_client: Option<ClickHouseClient>,
    /// Used by VRL live-test to fetch sample messages from the raw `logs`
    /// table (`validation.rs::live_test`). Distinct from `table_names` —
    /// `logs_table` is a static name, `table_names` resolves the per-call
    /// cluster-aware variant for rollup reads.
    logs_table: &'static str,
    /// Carried through to LogSourceRepository so rollup-backed reads pick
    /// the `_distributed` wrapper in cluster mode (NAN-734).
    table_names: crate::db::TableNames,
    vector_config: Arc<VectorConfigManager>,
    vrl_validator: Arc<VrlValidator>,
}

impl LogSourceService {
    /// Create with DualPool and custom Vector config directory
    pub fn with_dual_pool_and_config_dir(
        dual_pool: &DualPool,
        config_dir: impl AsRef<std::path::Path>,
    ) -> Self {
        Self {
            pool: dual_pool.postgres().clone(),
            ch_client: Some(dual_pool.clickhouse().clone()),
            logs_table: dual_pool.logs_table(),
            table_names: dual_pool.table_names(),
            vector_config: Arc::new(VectorConfigManager::new(config_dir)),
            vrl_validator: Arc::new(VrlValidator::new()),
        }
    }

    fn repository(&self) -> LogSourceRepository {
        if let Some(ref ch_client) = self.ch_client {
            LogSourceRepository::with_clickhouse(
                self.pool.clone(),
                ch_client.clone(),
                self.table_names.clone(),
            )
        } else {
            LogSourceRepository::new(self.pool.clone())
        }
    }

    fn credential_repository(&self) -> CredentialRepository {
        CredentialRepository::new(self.pool.clone())
    }

    fn version_repository(&self) -> LogSourceVersionRepository {
        LogSourceVersionRepository::new(self.pool.clone())
    }
}
