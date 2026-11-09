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

use super::case_visibility::case_visible_predicate;

/// A linked notebook's ACL is subordinate to current case visibility — BOTH
/// halves of it (NAN-5028): the case ACL and the per-source scope. A notebook
/// of a case that `GET /api/cases/{id}` hides from this viewer is hidden too.
/// Stale ownership and shares remain stored but grant no access to a case the
/// viewer cannot see.
///
/// `deny_param` is `Some` exactly when the viewer is source-restricted
/// (`ViewerScope::deny_param`); `None` keeps the SQL byte-identical to the
/// ACL-only form for an unrestricted viewer.
pub(crate) fn notebook_case_visible_to_user(user_param: u16, deny_param: Option<u16>) -> String {
    let case_visible = case_visible_predicate("c", user_param, deny_param);
    format!("(n.case_id IS NULL OR EXISTS (SELECT 1 FROM cases c WHERE c.id = n.case_id AND {case_visible}))")
}

/// Canonical visibility over notebook alias `n`, actor bound at `$2`.
pub(crate) fn notebook_visible_to_user(deny_param: Option<u16>) -> String {
    notebook_visible_to_user_at(2, deny_param)
}

pub(crate) fn notebook_visible_to_user_at(user_param: u16, deny_param: Option<u16>) -> String {
    let case_visible = notebook_case_visible_to_user(user_param, deny_param);
    format!(
        r#"({case_visible} AND (
        n.case_id IS NOT NULL
        OR n.owner_id = ${user_param}
        OR n.visibility = 'public'
        OR EXISTS (
            SELECT 1 FROM notebook_shares ns
            LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = ${user_param}
            WHERE ns.notebook_id = n.id
              AND (ns.shared_with_user_id = ${user_param} OR ug.user_id IS NOT NULL)
        )
    ))"#
    )
}

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
