// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser service for business logic
//!
//! Submodules organized by concern:
//! - `crud`: Parser CRUD operations (create, read, update, delete, enable, disable)
//! - `deployment`: Parser deployment lifecycle (deploy, undeploy, rollback)
//! - `validation`: VRL and UDM field validation

mod crud;
mod deployment;
mod validation;

#[cfg(test)]
mod tests;

use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;

use super::repository::ParserRepository;
use super::repository::ParserRepositoryError;
use super::validator::VrlValidator;
use super::vector_config::{VectorConfigError, VectorConfigManager};

#[derive(Error, Debug)]
pub enum ParserServiceError {
    #[error("Repository error: {0}")]
    RepositoryError(#[from] ParserRepositoryError),
    #[error("Invalid VRL: {0}")]
    InvalidVrl(String),
    #[error("Invalid source type: {0}")]
    InvalidSourceType(String),
    /// NAN-2305: the requested name is unique as a string but generates a
    /// Vector identifier another log source already holds. Kept separate from
    /// `RepositoryError(DuplicateName)` because the remedy differs — the names
    /// are visibly different, so the message has to explain what they share.
    #[error("{0}")]
    NameCollision(String),
    #[error("Parser must be validated before enabling")]
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
}

/// Parser service for managing VRL parsers
#[derive(Clone)]
pub struct ParserService {
    pool: PgPool,
    vector_config: Arc<VectorConfigManager>,
    vrl_validator: Arc<VrlValidator>,
}

impl ParserService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            vector_config: Arc::new(VectorConfigManager::with_defaults()),
            vrl_validator: Arc::new(VrlValidator::new()),
        }
    }

    /// Create with a custom Vector config directory
    pub fn with_vector_config_dir(pool: PgPool, config_dir: impl AsRef<std::path::Path>) -> Self {
        Self {
            pool,
            vector_config: Arc::new(VectorConfigManager::new(config_dir)),
            vrl_validator: Arc::new(VrlValidator::new()),
        }
    }

    /// Hand out a clone of the inner `VectorConfigManager`'s deploy lock.
    /// Lets other services (e.g. `SourceConfigService`) serialize their
    /// `_router.toml` mutations against this service's parser deploys.
    /// NAN-948.
    pub fn deploy_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.vector_config.deploy_lock()
    }

    /// Hand out the shared config manager so other services deploy through the
    /// SAME instance — and therefore the same deploy mutex.
    ///
    /// NAN-2297: `LogSourceService` used to build its own `VectorConfigManager`,
    /// so its lock was a different mutex from the one `ParserService` and
    /// `SourceConfigService` share. Publishing a log source and deploying a
    /// parser could interleave freely over one staging directory.
    pub fn vector_config(&self) -> Arc<VectorConfigManager> {
        Arc::clone(&self.vector_config)
    }

    fn repository(&self) -> ParserRepository {
        ParserRepository::new(self.pool.clone())
    }
}
