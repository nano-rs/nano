// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared error type for git-synced repository CRUD (NAN-1618).
//!
//! The parser / playbook / rule "repositories" tables expose byte-identical
//! repository-layer error enums: a `Database` wrapper over [`sqlx::Error`], a
//! `NotFound(Uuid)`, and an `AlreadyExists(String)`, with identical `Display`
//! messages. They are consolidated here so the three feature modules can alias
//! their public error names to this single type without changing message text,
//! variant shapes, or the service-layer `match` arms that translate them into
//! HTTP status codes (NotFound -> 404, AlreadyExists -> 409).

use thiserror::Error;
use uuid::Uuid;

/// Repository-layer error for git-synced repository CRUD operations.
///
/// Aliased as `ParserRepositoryRepositoryError`, `PlaybookRepoRepositoryError`
/// and `RuleRepositoryRepositoryError` so existing public APIs and `match`
/// arms keep compiling unchanged.
#[derive(Debug, Error)]
pub enum RepoError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Repository not found: {0}")]
    NotFound(Uuid),

    #[error("Repository already exists: {0}")]
    AlreadyExists(String),
}
