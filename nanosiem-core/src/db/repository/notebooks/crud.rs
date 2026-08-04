// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notebook CRUD operations: create, find, list, update, delete

use chrono::Utc;
use uuid::Uuid;

use crate::models::notebook::{
    NewNotebook, Notebook, NotebookSummary, NotebookWithOwner, UpdateNotebook,
};

use super::{NotebookRepository, NotebookRepositoryError};

impl NotebookRepository {
    /// Create a new notebook
    pub async fn create(
        &self,
        notebook: &NewNotebook,
    ) -> Result<Notebook, NotebookRepositoryError> {
        let visibility = match notebook.visibility {
            crate::models::notebook::NotebookVisibility::Private => "private",
            crate::models::notebook::NotebookVisibility::Shared => "shared",
            crate::models::notebook::NotebookVisibility::Public => "public",
        };

        let result = sqlx::query_as::<_, Notebook>(
            r#"
            INSERT INTO notebooks (title, owner_id, case_id, visibility, status)
            VALUES ($1, $2, $3, $4, 'active')
            RETURNING *
            "#,
        )
        .bind(&notebook.title)
        .bind(notebook.owner_id)
        .bind(notebook.case_id)
        .bind(visibility)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Find a notebook by ID
    pub async fn find_by_id(&self, id: Uuid) -> Result<Notebook, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, Notebook>(r#"SELECT * FROM notebooks WHERE id = $1"#)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(NotebookRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Find a notebook by ID with owner name
    pub async fn find_by_id_with_owner(
        &self,
        id: Uuid,
    ) -> Result<NotebookWithOwner, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, NotebookWithOwner>(
            r#"
            SELECT n.*, u.name as owner_name
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            WHERE n.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotebookRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Find a notebook by ID, checking access for a specific user.
    /// User has access if: owner, public, shared with them, or — for a
    /// case-linked notebook — they can see the underlying case.
    ///
    /// NAN-1739: case notebooks previously granted access to ANY analyst
    /// whenever `case_id IS NOT NULL`, ignoring case visibility. A notebook
    /// must never expose more than its underlying case: the case-linked
    /// disjunct now requires that the caller passes the SAME visibility rules
    /// enforced by `CaseRepository::check_user_access`
    /// (created_by / assigned_to / public / group-membership).
    pub async fn find_by_id_for_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<NotebookWithOwner, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, NotebookWithOwner>(
            r#"
            SELECT DISTINCT n.*, u.name as owner_name
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            LEFT JOIN notebook_shares ns ON ns.notebook_id = n.id
            LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $2
            WHERE n.id = $1
              AND (
                  n.owner_id = $2
                  -- NAN-1739: `public` only frees NON-case notebooks. Case
                  -- notebooks are stamped visibility='public' at creation
                  -- (notebooks/cases.rs), so an unconditional public disjunct
                  -- would make the case-access EXISTS below dead code and
                  -- re-open the bypass. Gate it on case_id IS NULL.
                  OR (n.case_id IS NULL AND n.visibility = 'public')
                  OR ns.shared_with_user_id = $2
                  OR ug.user_id IS NOT NULL
                  OR (
                      n.case_id IS NOT NULL
                      AND EXISTS (
                          SELECT 1 FROM cases c
                          WHERE c.id = n.case_id
                            AND (
                                c.created_by = $2
                                OR c.assigned_to = $2
                                OR c.visibility = 'public'
                                OR (c.visibility = 'group' AND EXISTS (
                                    SELECT 1 FROM case_groups cg
                                    JOIN user_groups cug ON cug.group_id = cg.group_id
                                    WHERE cg.case_id = c.id AND cug.user_id = $2
                                ))
                            )
                      )
                  )
              )
            "#,
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotebookRepositoryError::AccessDenied(id))?;

        Ok(result)
    }

    /// Whether `user_id` can see the given case, mirroring
    /// `CaseRepository::check_user_access` visibility rules
    /// (created_by / assigned_to / public / group-membership).
    ///
    /// NAN-1739: used to gate access to case-linked notebooks so a notebook
    /// can never expose or accept mutations beyond the underlying case's
    /// visibility. Kept in the notebook repo (nanosiem-core) which can query
    /// the `cases` / `case_groups` / `user_groups` tables directly.
    pub async fn user_can_access_case(
        &self,
        case_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, NotebookRepositoryError> {
        let has_access = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM cases c
                WHERE c.id = $1
                  AND (
                      c.created_by = $2
                      OR c.assigned_to = $2
                      OR c.visibility = 'public'
                      OR (c.visibility = 'group' AND EXISTS (
                          SELECT 1 FROM case_groups cg
                          JOIN user_groups ug ON ug.group_id = cg.group_id
                          WHERE cg.case_id = c.id AND ug.user_id = $2
                      ))
                  )
            )
            "#,
        )
        .bind(case_id)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(has_access)
    }

    /// Check if user can edit a notebook (owner or has edit permission)
    pub async fn can_user_edit(
        &self,
        notebook_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, NotebookRepositoryError> {
        let result = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM notebooks n
                LEFT JOIN notebook_shares ns ON ns.notebook_id = n.id
                LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $2
                WHERE n.id = $1
                  AND (
                      n.owner_id = $2
                      OR (ns.shared_with_user_id = $2 AND ns.permission = 'edit')
                      OR (ug.user_id IS NOT NULL AND ns.permission = 'edit')
                  )
            )
            "#,
        )
        .bind(notebook_id)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// List notebooks accessible to a user with entry counts
    pub async fn list_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let results = sqlx::query_as::<_, NotebookSummary>(
            r#"
            SELECT DISTINCT
                n.*,
                u.name as owner_name,
                COALESCE(ec.entry_count, 0) as entry_count
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            LEFT JOIN notebook_shares ns ON ns.notebook_id = n.id
            LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $1
            LEFT JOIN (
                SELECT notebook_id, COUNT(*) as entry_count
                FROM notebook_entries
                GROUP BY notebook_id
            ) ec ON ec.notebook_id = n.id
            WHERE n.owner_id = $1
               -- NAN-1739: case notebooks are visibility='public'; gate the
               -- public disjunct on case_id IS NULL and govern case notebooks
               -- by case visibility so they don't leak into every user's list.
               OR (n.case_id IS NULL AND n.visibility = 'public')
               OR ns.shared_with_user_id = $1
               OR ug.user_id IS NOT NULL
               OR (
                   n.case_id IS NOT NULL
                   AND EXISTS (
                       SELECT 1 FROM cases c
                       WHERE c.id = n.case_id
                         AND (
                             c.created_by = $1
                             OR c.assigned_to = $1
                             OR c.visibility = 'public'
                             OR (c.visibility = 'group' AND EXISTS (
                                 SELECT 1 FROM case_groups cg
                                 JOIN user_groups cug ON cug.group_id = cg.group_id
                                 WHERE cg.case_id = c.id AND cug.user_id = $1
                             ))
                         )
                   )
               )
            ORDER BY n.updated_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// One updated-at-ordered page of every notebook visible to the user.
    pub async fn list_for_user_page(
        &self,
        user_id: Uuid,
        status: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let results = sqlx::query_as::<_, NotebookSummary>(
            r#"
            SELECT DISTINCT
                n.*,
                u.name as owner_name,
                COALESCE(ec.entry_count, 0) as entry_count
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            LEFT JOIN notebook_shares ns ON ns.notebook_id = n.id
            LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $1
            LEFT JOIN (
                SELECT notebook_id, COUNT(*) as entry_count
                FROM notebook_entries
                GROUP BY notebook_id
            ) ec ON ec.notebook_id = n.id
            WHERE (
                   n.owner_id = $1
                OR (n.case_id IS NULL AND n.visibility = 'public')
                OR ns.shared_with_user_id = $1
                OR ug.user_id IS NOT NULL
                OR (
                    n.case_id IS NOT NULL
                    AND EXISTS (
                        SELECT 1 FROM cases c
                        WHERE c.id = n.case_id
                          AND (
                              c.created_by = $1
                              OR c.assigned_to = $1
                              OR c.visibility = 'public'
                              OR (c.visibility = 'group' AND EXISTS (
                                  SELECT 1 FROM case_groups cg
                                  JOIN user_groups cug ON cug.group_id = cg.group_id
                                  WHERE cg.case_id = c.id AND cug.user_id = $1
                              ))
                          )
                    )
                )
            )
              AND ($2 = 'all' OR n.status = $2)
            ORDER BY n.updated_at DESC, n.id DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(user_id)
        .bind(status)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List only the user's own notebooks
    pub async fn list_owned_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let results = sqlx::query_as::<_, NotebookSummary>(
            r#"
            SELECT
                n.*,
                u.name as owner_name,
                COALESCE(ec.entry_count, 0) as entry_count
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            LEFT JOIN (
                SELECT notebook_id, COUNT(*) as entry_count
                FROM notebook_entries
                GROUP BY notebook_id
            ) ec ON ec.notebook_id = n.id
            WHERE n.owner_id = $1
            ORDER BY n.updated_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// One updated-at-ordered page of notebooks owned by the user.
    pub async fn list_owned_by_user_page(
        &self,
        user_id: Uuid,
        status: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let results = sqlx::query_as::<_, NotebookSummary>(
            r#"
            SELECT
                n.*,
                u.name as owner_name,
                COALESCE(ec.entry_count, 0) as entry_count
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            LEFT JOIN (
                SELECT notebook_id, COUNT(*) as entry_count
                FROM notebook_entries
                GROUP BY notebook_id
            ) ec ON ec.notebook_id = n.id
            WHERE n.owner_id = $1
              AND ($2 = 'all' OR n.status = $2)
            ORDER BY n.updated_at DESC, n.id DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(user_id)
        .bind(status)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List notebooks shared with a user
    pub async fn list_shared_with_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let results = sqlx::query_as::<_, NotebookSummary>(
            r#"
            SELECT DISTINCT
                n.*,
                u.name as owner_name,
                COALESCE(ec.entry_count, 0) as entry_count
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            LEFT JOIN notebook_shares ns ON ns.notebook_id = n.id
            LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $1
            LEFT JOIN (
                SELECT notebook_id, COUNT(*) as entry_count
                FROM notebook_entries
                GROUP BY notebook_id
            ) ec ON ec.notebook_id = n.id
            WHERE n.owner_id != $1
              AND (ns.shared_with_user_id = $1 OR ug.user_id IS NOT NULL)
            ORDER BY n.updated_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// One updated-at-ordered page of notebooks shared with the user.
    pub async fn list_shared_with_user_page(
        &self,
        user_id: Uuid,
        status: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let results = sqlx::query_as::<_, NotebookSummary>(
            r#"
            SELECT DISTINCT
                n.*,
                u.name as owner_name,
                COALESCE(ec.entry_count, 0) as entry_count
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            LEFT JOIN notebook_shares ns ON ns.notebook_id = n.id
            LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $1
            LEFT JOIN (
                SELECT notebook_id, COUNT(*) as entry_count
                FROM notebook_entries
                GROUP BY notebook_id
            ) ec ON ec.notebook_id = n.id
            WHERE n.owner_id != $1
              AND (ns.shared_with_user_id = $1 OR ug.user_id IS NOT NULL)
              AND ($2 = 'all' OR n.status = $2)
            ORDER BY n.updated_at DESC, n.id DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(user_id)
        .bind(status)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Get active notebook for user (if any)
    pub async fn get_active_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Option<NotebookWithOwner>, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, NotebookWithOwner>(
            r#"
            SELECT n.*, u.name as owner_name
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            WHERE n.owner_id = $1 AND n.status = 'active'
            ORDER BY n.updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    /// Update a notebook
    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdateNotebook,
    ) -> Result<Notebook, NotebookRepositoryError> {
        let visibility = update.visibility.as_ref().map(|v| match v {
            crate::models::notebook::NotebookVisibility::Private => "private",
            crate::models::notebook::NotebookVisibility::Shared => "shared",
            crate::models::notebook::NotebookVisibility::Public => "public",
        });

        let status = update.status.as_ref().map(|s| match s {
            crate::models::notebook::NotebookStatus::Active => "active",
            crate::models::notebook::NotebookStatus::Paused => "paused",
            crate::models::notebook::NotebookStatus::Closed => "closed",
            crate::models::notebook::NotebookStatus::Merged => "merged",
        });

        // Handle closed_at timestamp
        let closed_at = if status == Some("closed") {
            Some(Utc::now())
        } else {
            None
        };

        let result = sqlx::query_as::<_, Notebook>(
            r#"
            UPDATE notebooks SET
                title = COALESCE($2, title),
                visibility = COALESCE($3, visibility),
                status = COALESCE($4, status),
                summary = COALESCE($5, summary),
                closed_at = CASE WHEN $4 = 'closed' AND closed_at IS NULL THEN $6 ELSE closed_at END,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.title)
        .bind(visibility)
        .bind(status)
        .bind(&update.summary)
        .bind(closed_at)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotebookRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Update a notebook, verifying ownership or access rights.
    ///
    /// Case-linked notebooks are shared investigation workspaces editable by
    /// case collaborators — but NAN-1739: only by callers who can actually
    /// SEE the underlying case. Previously any caller could mutate a case
    /// notebook merely because `case_id IS NOT NULL`, ignoring case
    /// visibility. The case-linked branch now requires the same visibility
    /// the case itself enforces.
    pub async fn update_owned(
        &self,
        id: Uuid,
        user_id: Uuid,
        update: &UpdateNotebook,
    ) -> Result<Notebook, NotebookRepositoryError> {
        let notebook = self.find_by_id(id).await?;

        // Owner always has access
        let is_owner = notebook.owner_id == user_id;
        // Case-linked notebooks: caller must be able to see the underlying case.
        let has_case_access = match notebook.case_id {
            Some(case_id) if !is_owner => self.user_can_access_case(case_id, user_id).await?,
            _ => false,
        };
        // Explicit share grants access (only relevant for non-case notebooks).
        let has_edit_share = if !is_owner && notebook.case_id.is_none() {
            self.can_user_edit(id, user_id).await?
        } else {
            false
        };

        if !is_owner && !has_case_access && !has_edit_share {
            return Err(NotebookRepositoryError::AccessDenied(id));
        }

        self.update(id, update).await
    }

    /// Delete a notebook
    pub async fn delete(&self, id: Uuid) -> Result<(), NotebookRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM notebooks WHERE id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(NotebookRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Delete a notebook, verifying ownership
    pub async fn delete_owned(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<(), NotebookRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM notebooks WHERE id = $1 AND owner_id = $2"#)
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(NotebookRepositoryError::AccessDenied(id));
        }

        Ok(())
    }
}
