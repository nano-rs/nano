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
    /// User has access if: owner, public, shared with them, or case-linked
    /// (case notebooks are shared investigation workspaces accessible to all analysts).
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
                  OR n.visibility = 'public'
                  OR n.case_id IS NOT NULL
                  OR ns.shared_with_user_id = $2
                  OR ug.user_id IS NOT NULL
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
               OR n.visibility = 'public'
               OR ns.shared_with_user_id = $1
               OR ug.user_id IS NOT NULL
            ORDER BY n.updated_at DESC
            "#,
        )
        .bind(user_id)
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
    /// Case-linked notebooks (created by auto-investigation) are editable by
    /// any user with notebooks:edit permission since they are shared investigation artifacts.
    pub async fn update_owned(
        &self,
        id: Uuid,
        user_id: Uuid,
        update: &UpdateNotebook,
    ) -> Result<Notebook, NotebookRepositoryError> {
        let notebook = self.find_by_id(id).await?;

        // Owner always has access
        let is_owner = notebook.owner_id == user_id;
        // Case-linked notebooks are shared investigation workspaces
        let is_case_notebook = notebook.case_id.is_some();
        // Explicit share grants access
        let has_edit_share = if !is_owner && !is_case_notebook {
            self.can_user_edit(id, user_id).await?
        } else {
            false
        };

        if !is_owner && !is_case_notebook && !has_edit_share {
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
