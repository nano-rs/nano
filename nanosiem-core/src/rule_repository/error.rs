// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error types for rule repository operations

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during rule repository operations
#[derive(Debug, Error)]
pub enum RuleRepositoryError {
    #[error("Repository not found: {0}")]
    RepositoryNotFound(Uuid),

    #[error("Repository rule not found: {repo_id}/{path}")]
    RuleNotFound { repo_id: Uuid, path: String },

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

    /// NAN-5272: Sigma → nPL conversion was retired. A repository row still
    /// marked `rule_format = 'sigma'` is refused on sync, preview, import and
    /// upstream diff instead of being half-processed.
    #[error("Sigma-format repositories are no longer supported; nano rules use nPL/OCSF")]
    SigmaFormatUnsupported,

    #[error("Rule import failed: {0}")]
    ConversionFailed(String),

    #[error("Rule already imported as {import_type}")]
    AlreadyImported { import_type: String },

    #[error("Import not found for detection rule: {0}")]
    ImportNotFound(Uuid),

    #[error("Coverage analysis failed: {0}")]
    CoverageAnalysis(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Sync already in progress for repository: {0}")]
    SyncInProgress(Uuid),

    #[error("Repository is disabled")]
    RepositoryDisabled,

    #[error("Detection service error: {0}")]
    DetectionService(String),

    /// The caller holds the repository capability but not the target-resource
    /// capability the import would consume (NAN-2118). Carries the canonical
    /// permission string so the HTTP layer renders the same
    /// `Missing permission: <capability>` body as the direct detection route.
    #[error("Missing permission: {0}")]
    Forbidden(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl RuleRepositoryError {
    /// Create a Database error from a repository-level error that wraps sqlx::Error
    pub fn from_repo_error<E: std::fmt::Display>(e: E) -> Self {
        RuleRepositoryError::Internal(e.to_string())
    }

    /// Returns true if this error is retriable
    pub fn is_retriable(&self) -> bool {
        matches!(
            self,
            RuleRepositoryError::RateLimited(_)
                | RuleRepositoryError::GitHubApi(_)
                | RuleRepositoryError::SyncInProgress(_)
        )
    }

    /// Returns the HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            RuleRepositoryError::RepositoryNotFound(_) => 404,
            RuleRepositoryError::RuleNotFound { .. } => 404,
            RuleRepositoryError::ImportNotFound(_) => 404,
            RuleRepositoryError::RepositoryAlreadyExists(_) => 409,
            RuleRepositoryError::AlreadyImported { .. } => 409,
            RuleRepositoryError::InvalidUrl(_) => 400,
            RuleRepositoryError::RepositoryNotAllowed(_) => 403,
            RuleRepositoryError::SigmaFormatUnsupported => 400,
            RuleRepositoryError::ConversionFailed(_) => 422,
            RuleRepositoryError::RateLimited(_) => 429,
            RuleRepositoryError::SyncInProgress(_) => 409,
            RuleRepositoryError::RepositoryDisabled => 403,
            RuleRepositoryError::Forbidden(_) => 403,
            _ => 500,
        }
    }
}
