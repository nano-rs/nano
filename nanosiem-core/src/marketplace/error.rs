// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error types for marketplace operations

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during marketplace operations
#[derive(Debug, Error)]
pub enum MarketplaceError {
    #[error("Catalog entry not found: {0}")]
    CatalogEntryNotFound(String),

    #[error("Repository not found: {0}")]
    RepositoryNotFound(Uuid),

    #[error("Slug already exists: {0}")]
    SlugAlreadyExists(String),

    /// NAN-3490: `_mock` slugs and the `config.validation_mock` marker belong
    /// to operator live-validation rows.
    #[error("Reserved for live-validation mock entries: {0}")]
    ReservedValidationMock(String),

    #[error("Repository already exists: {0}")]
    RepositoryAlreadyExists(String),

    #[error("Enrichment not installed: {0}")]
    NotInstalled(String),

    #[error("Enrichment already installed: {0}")]
    AlreadyInstalled(String),

    #[error("Invalid repository URL: {0}")]
    InvalidUrl(String),

    #[error("Credential required for this enrichment")]
    CredentialRequired,

    /// A supplied credential field failed validation before being persisted.
    ///
    /// NAN-2343: carries the field name so the UI can attach the message to the
    /// offending input instead of showing a bare toast. Previously a malformed
    /// `download_url` was stored verbatim and only surfaced at sync time as a
    /// "URL rejected by SSRF check" failure, which named the wrong cause and
    /// gave the operator nothing to correct.
    #[error("Invalid value for '{field}': {reason}")]
    InvalidCredential { field: String, reason: String },

    #[error("Git operation failed: {0}")]
    GitError(String),

    #[error("Manifest parse error: {0}")]
    ManifestParseError(String),

    #[error("Sync already in progress for repository: {0}")]
    SyncInProgress(Uuid),

    /// The entry's execution backend is not part of this build's edition.
    ///
    /// NAN-3463: Deno-backed feeds run in the enterprise custom-enrichment
    /// sandbox and are stored in `custom_enrichments`, which the open schema
    /// does not have. Installing one in open used to fail with a 500.
    #[error("{0}")]
    BackendUnavailable(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl MarketplaceError {
    /// Returns the HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            MarketplaceError::CatalogEntryNotFound(_) => 404,
            MarketplaceError::RepositoryNotFound(_) => 404,
            MarketplaceError::SlugAlreadyExists(_) => 409,
            MarketplaceError::ReservedValidationMock(_) => 409,
            MarketplaceError::RepositoryAlreadyExists(_) => 409,
            MarketplaceError::NotInstalled(_) => 400,
            MarketplaceError::AlreadyInstalled(_) => 409,
            MarketplaceError::InvalidUrl(_) => 400,
            MarketplaceError::CredentialRequired => 400,
            MarketplaceError::InvalidCredential { .. } => 422,
            MarketplaceError::GitError(_) => 502,
            MarketplaceError::ManifestParseError(_) => 422,
            MarketplaceError::SyncInProgress(_) => 409,
            MarketplaceError::BackendUnavailable(_) => 403,
            MarketplaceError::Database(_) => 500,
            MarketplaceError::Internal(_) => 500,
        }
    }
}
