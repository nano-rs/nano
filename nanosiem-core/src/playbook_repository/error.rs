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

    /// The file declares a kind this repository is not allowed to produce
    /// (NAN-2238). A runbook is a document a human follows; a hunt is a process
    /// that executes on a cadence — `playbook_repositories.allowed_kinds` lets
    /// an operator gate the two separately instead of having one merge gate
    /// stand for both.
    #[error("Repository does not accept playbooks of kind `{kind}` (allowed: {allowed})")]
    KindNotAllowed { kind: String, allowed: String },

    /// The file declares `kind: hunt` but its frontmatter or step vocabulary
    /// does not satisfy the hunt contract.
    #[error("Invalid hunt definition: {0}")]
    HuntSpec(String),

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

    /// The caller holds the repository capability but not a TARGET-resource
    /// capability the operation consumes (NAN-2119) — e.g. importing a catalog
    /// playbook into the library without `playbooks:manage`. Message is
    /// byte-identical to what the canonical route returns.
    #[error("{0}")]
    Forbidden(String),

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
            // 403, not 400: the file is well-formed, the repository is not
            // authorized to produce that kind. Mirrors `RepositoryNotAllowed`.
            PlaybookRepositoryError::KindNotAllowed { .. } => 403,
            PlaybookRepositoryError::HuntSpec(_) => 400,
            PlaybookRepositoryError::RateLimited(_) => 429,
            PlaybookRepositoryError::SyncInProgress(_) => 409,
            PlaybookRepositoryError::RepositoryDisabled => 403,
            PlaybookRepositoryError::Forbidden(_) => 403,
            _ => 500,
        }
    }
}
