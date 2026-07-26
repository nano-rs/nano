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

use super::case_visibility::case_acl_predicate;

/// The canonical "may `$2` currently see notebook `n`?" predicate.
///
/// NAN-2101: this is the SAME disjunction `find_by_id_for_user` and
/// `list_for_user` apply, extracted so the tab surface cannot drift from it.
/// Tab rows outlived the access that created them — `open_tab` preflighted
/// correctly, but every later read/mutation filtered on `notebook_tabs.user_id`
/// alone, so a revoked share left the notebook's title, status, entry count and
/// linked `case_id` readable indefinitely (and pinnable, which excludes the row
/// from stale cleanup).
///
/// Requires the `notebooks` row to be aliased `n` and the user id to be bound at
/// `$2`. `notebook_shares` / `user_groups` are joined inside the EXISTS rather
/// than in the outer query so callers do not need a `DISTINCT`.
///
/// NAN-1739: `public` frees only NON-case notebooks — case notebooks are stamped
/// `visibility='public'` at creation, so an unconditional public disjunct would
/// make the case-visibility EXISTS dead code and re-open that bypass.
///
/// NAN-2168: generate the case-linked disjunct from the shared case ACL
/// builder. This surface does not receive a per-source deny set, so using the
/// ACL-only builder preserves its existing contract without another copied
/// predicate that can drift.
pub(crate) fn notebook_visible_to_user() -> String {
    let case_acl = case_acl_predicate("c", 2);
    format!(
        r#"(
    n.owner_id = $2
    OR (n.case_id IS NULL AND n.visibility = 'public')
    OR EXISTS (
        SELECT 1 FROM notebook_shares ns
        LEFT JOIN user_groups ug
               ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $2
        WHERE ns.notebook_id = n.id
          AND (ns.shared_with_user_id = $2 OR ug.user_id IS NOT NULL)
    )
    OR (
        n.case_id IS NOT NULL
        AND EXISTS (
            SELECT 1 FROM cases c
            WHERE c.id = n.case_id
              AND {case_acl}
        )
    )
)"#
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
