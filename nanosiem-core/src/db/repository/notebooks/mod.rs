// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notebook repository for CRUD operations
//!
//! Handles notebooks, entries, shares, and references with access control

mod bulk_sharing;
mod cases;
mod crud;
mod entries;
mod references;
mod shares;
mod tabs;

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum NotebookRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Notebook not found: {0}")]
    NotFound(Uuid),
    #[error("Access denied to notebook: {0}")]
    AccessDenied(Uuid),
    #[error("Entry not found: {0}")]
    EntryNotFound(Uuid),
    #[error("Share not found: {0}")]
    ShareNotFound(Uuid),
    #[error("Reference not found: {0}")]
    ReferenceNotFound(Uuid),
    #[error("Reference already exists")]
    ReferenceAlreadyExists,
    #[error("Invalid share target: must specify either user or group, not both")]
    InvalidShareTarget,
    #[error("Case already has a notebook: {0}")]
    CaseAlreadyHasNotebook(Uuid),
    #[error("Notebook is already linked to a case")]
    NotebookAlreadyLinked,
    #[error("Tab not found: {0}")]
    TabNotFound(Uuid),
}

/// Repository for notebook operations
#[derive(Clone)]
pub struct NotebookRepository {
    pool: PgPool,
}

impl NotebookRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
