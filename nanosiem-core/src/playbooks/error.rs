// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error types for playbook operations

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during playbook operations
#[derive(Debug, Error)]
pub enum PlaybookError {
    #[error("Playbook not found: {0}")]
    NotFound(Uuid),

    #[error("Invalid category: {0}")]
    InvalidCategory(String),

    #[error("Invalid status: {0}")]
    InvalidStatus(String),

    #[error("Invalid scope: {0}")]
    InvalidScope(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Frontmatter parse error: {0}")]
    Frontmatter(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Version not found for playbook {playbook_id}: version {version}")]
    VersionNotFound { playbook_id: Uuid, version: i32 },

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl PlaybookError {
    /// Returns the HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            PlaybookError::NotFound(_) => 404,
            PlaybookError::VersionNotFound { .. } => 404,
            PlaybookError::InvalidCategory(_)
            | PlaybookError::InvalidStatus(_)
            | PlaybookError::InvalidScope(_)
            | PlaybookError::Parse(_)
            | PlaybookError::Frontmatter(_) => 400,
            PlaybookError::Forbidden(_) => 403,
            _ => 500,
        }
    }
}
