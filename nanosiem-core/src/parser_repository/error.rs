// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error types for parser repository operations

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during parser repository operations
#[derive(Debug, Error)]
pub enum ParserRepositoryError {
    #[error("Repository not found: {0}")]
    RepositoryNotFound(Uuid),

    #[error("Repository parser not found: {repo_id}/{path}")]
    ParserNotFound { repo_id: Uuid, path: String },

    #[error("Repository already exists: {0}")]
    RepositoryAlreadyExists(String),

    #[error("Invalid repository URL: {0}")]
    InvalidUrl(String),

    #[error("Repository not in allowlist: {0}")]
    RepositoryNotAllowed(String),

    #[error("GitHub API error: {0}")]
    GitHubApi(String),

    #[error("Rate limited by GitHub API, retry after {0} seconds")]
    RateLimited(u64),

    #[error("YAML parsing error: {0}")]
    YamlParse(String),

    #[error("Parser already imported as {import_type}")]
    AlreadyImported { import_type: String },

    #[error("Import not found for log source: {0}")]
    ImportNotFound(Uuid),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Sync already in progress for repository: {0}")]
    SyncInProgress(Uuid),

    #[error("Repository is disabled")]
    RepositoryDisabled,

    #[error("Log source service error: {0}")]
    LogSourceService(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl ParserRepositoryError {
    pub fn from_repo_error<E: std::fmt::Display>(e: E) -> Self {
        ParserRepositoryError::Internal(e.to_string())
    }

    pub fn is_retriable(&self) -> bool {
        matches!(
            self,
            ParserRepositoryError::RateLimited(_)
                | ParserRepositoryError::GitHubApi(_)
                | ParserRepositoryError::SyncInProgress(_)
        )
    }

    pub fn status_code(&self) -> u16 {
        match self {
            ParserRepositoryError::RepositoryNotFound(_) => 404,
            ParserRepositoryError::ParserNotFound { .. } => 404,
            ParserRepositoryError::ImportNotFound(_) => 404,
            ParserRepositoryError::RepositoryAlreadyExists(_) => 409,
            ParserRepositoryError::AlreadyImported { .. } => 409,
            ParserRepositoryError::InvalidUrl(_) => 400,
            ParserRepositoryError::RepositoryNotAllowed(_) => 403,
            ParserRepositoryError::YamlParse(_) => 400,
            ParserRepositoryError::RateLimited(_) => 429,
            ParserRepositoryError::SyncInProgress(_) => 409,
            ParserRepositoryError::RepositoryDisabled => 403,
            _ => 500,
        }
    }
}
