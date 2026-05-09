// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error types for playbook repository operations

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum PlaybookRepositoryError {
    #[error("Repository not found: {0}")]
    RepositoryNotFound(Uuid),

    #[error("Repository playbook not found: {repo_id}/{path}")]
    PlaybookNotFound { repo_id: Uuid, path: String },

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

    #[error("Playbook parse error: {0}")]
    Parse(String),

    #[error("Playbook already imported as {import_type}")]
    AlreadyImported { import_type: String },

    #[error("Import not found for playbook: {0}")]
    ImportNotFound(Uuid),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Sync already in progress for repository: {0}")]
    SyncInProgress(Uuid),

    #[error("Repository is disabled")]
    RepositoryDisabled,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl PlaybookRepositoryError {
    pub fn from_repo_error<E: std::fmt::Display>(e: E) -> Self {
        PlaybookRepositoryError::Internal(e.to_string())
    }

    pub fn status_code(&self) -> u16 {
        match self {
            PlaybookRepositoryError::RepositoryNotFound(_) => 404,
            PlaybookRepositoryError::PlaybookNotFound { .. } => 404,
            PlaybookRepositoryError::ImportNotFound(_) => 404,
            PlaybookRepositoryError::RepositoryAlreadyExists(_) => 409,
            PlaybookRepositoryError::AlreadyImported { .. } => 409,
            PlaybookRepositoryError::InvalidUrl(_) => 400,
            PlaybookRepositoryError::RepositoryNotAllowed(_) => 403,
            PlaybookRepositoryError::Parse(_) => 400,
            PlaybookRepositoryError::RateLimited(_) => 429,
            PlaybookRepositoryError::SyncInProgress(_) => 409,
            PlaybookRepositoryError::RepositoryDisabled => 403,
            _ => 500,
        }
    }
}
