// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notebook CRUD operations: create, find, list, update, delete

use chrono::Utc;
use uuid::Uuid;

use crate::auth::ViewerScope;

use crate::models::notebook::{
    NewNotebook, Notebook, NotebookSummary, NotebookWithOwner, UpdateNotebook,
};

use super::{
    notebook_case_visible_to_user, notebook_visible_to_user_at, NotebookRepository,
    NotebookRepositoryError,
};

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

    /// Find a notebook using current visibility. Linked case visibility is
    /// mandatory; ownership and stored shares apply only to standalone notebooks.
    pub async fn find_by_id_for_user(
        &self,
        id: Uuid,
        viewer: &ViewerScope,
    ) -> Result<NotebookWithOwner, NotebookRepositoryError> {
        let sql = format!(
            r#"
            SELECT DISTINCT n.*, u.name as owner_name
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            LEFT JOIN notebook_shares ns ON ns.notebook_id = n.id
            LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $2
            WHERE n.id = $1 AND {visible}
            "#,
            visible = notebook_visible_to_user_at(2, viewer.deny_param(3)),
        );
        let mut query = sqlx::query_as::<_, NotebookWithOwner>(&sql)
            .bind(id)
            .bind(viewer.user_id());
        if let Some(deny) = viewer.deny_bind() {
            query = query.bind(deny);
        }
        let result = query
            .fetch_optional(&self.pool)
            .await?
            .ok_or(NotebookRepositoryError::AccessDenied(id))?;

        Ok(result)
    }

    /// Check if user can edit a notebook (owner or has edit permission)
    pub async fn can_user_edit(
        &self,
        notebook_id: Uuid,
        viewer: &ViewerScope,
    ) -> Result<bool, NotebookRepositoryError> {
        let sql = format!(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM notebooks n
                LEFT JOIN notebook_shares ns ON ns.notebook_id = n.id
                LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $2
                WHERE n.id = $1 AND {case_visible}
                  AND (
                      n.owner_id = $2
                      OR (ns.shared_with_user_id = $2 AND ns.permission = 'edit')
                      OR (ug.user_id IS NOT NULL AND ns.permission = 'edit')
                  )
            )
            "#,
            case_visible = notebook_case_visible_to_user(2, viewer.deny_param(3)),
        );
        let mut query = sqlx::query_scalar::<_, bool>(&sql)
            .bind(notebook_id)
            .bind(viewer.user_id());
        if let Some(deny) = viewer.deny_bind() {
            query = query.bind(deny);
        }
        let result = query.fetch_one(&self.pool).await?;

        Ok(result)
    }

    /// List notebooks accessible to a user with entry counts
    pub async fn list_for_user(
        &self,
        viewer: &ViewerScope,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let sql = format!(
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
            WHERE {visible}
            ORDER BY n.updated_at DESC
            "#,
            visible = notebook_visible_to_user_at(1, viewer.deny_param(2)),
        );
        let mut query = sqlx::query_as::<_, NotebookSummary>(&sql)
            .bind(viewer.user_id());
        if let Some(deny) = viewer.deny_bind() {
            query = query.bind(deny);
        }
        let results = query.fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// One updated-at-ordered page of every notebook visible to the user.
    pub async fn list_for_user_page(
        &self,
        viewer: &ViewerScope,
        status: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let sql = format!(
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
            WHERE {visible}
              AND ($2 = 'all' OR n.status = $2)
            ORDER BY n.updated_at DESC, n.id DESC
            LIMIT $3 OFFSET $4
            "#,
            visible = notebook_visible_to_user_at(1, viewer.deny_param(5)),
        );
        let mut query = sqlx::query_as::<_, NotebookSummary>(&sql)
            .bind(viewer.user_id())
            .bind(status)
            .bind(limit)
            .bind(offset);
        if let Some(deny) = viewer.deny_bind() {
            query = query.bind(deny);
        }
        let results = query.fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// List only the user's own notebooks
    pub async fn list_owned_by_user(
        &self,
        viewer: &ViewerScope,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let sql = format!(
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
            WHERE {case_visible} AND n.owner_id = $1
            ORDER BY n.updated_at DESC
            "#,
            case_visible = notebook_case_visible_to_user(1, viewer.deny_param(2)),
        );
        let mut query = sqlx::query_as::<_, NotebookSummary>(&sql)
            .bind(viewer.user_id());
        if let Some(deny) = viewer.deny_bind() {
            query = query.bind(deny);
        }
        let results = query.fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// One updated-at-ordered page of notebooks owned by the user.
    pub async fn list_owned_by_user_page(
        &self,
        viewer: &ViewerScope,
        status: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let sql = format!(
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
            WHERE {case_visible} AND n.owner_id = $1
              AND ($2 = 'all' OR n.status = $2)
            ORDER BY n.updated_at DESC, n.id DESC
            LIMIT $3 OFFSET $4
            "#,
            case_visible = notebook_case_visible_to_user(1, viewer.deny_param(5)),
        );
        let mut query = sqlx::query_as::<_, NotebookSummary>(&sql)
            .bind(viewer.user_id())
            .bind(status)
            .bind(limit)
            .bind(offset);
        if let Some(deny) = viewer.deny_bind() {
            query = query.bind(deny);
        }
        let results = query.fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// List notebooks shared with a user
    pub async fn list_shared_with_user(
        &self,
        viewer: &ViewerScope,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let sql = format!(
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
            WHERE {case_visible} AND n.owner_id != $1
              AND (ns.shared_with_user_id = $1 OR ug.user_id IS NOT NULL)
            ORDER BY n.updated_at DESC
            "#,
            case_visible = notebook_case_visible_to_user(1, viewer.deny_param(2)),
        );
        let mut query = sqlx::query_as::<_, NotebookSummary>(&sql)
            .bind(viewer.user_id());
        if let Some(deny) = viewer.deny_bind() {
            query = query.bind(deny);
        }
        let results = query.fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// One updated-at-ordered page of notebooks shared with the user.
    pub async fn list_shared_with_user_page(
        &self,
        viewer: &ViewerScope,
        status: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let sql = format!(
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
            WHERE {case_visible} AND n.owner_id != $1
              AND (ns.shared_with_user_id = $1 OR ug.user_id IS NOT NULL)
              AND ($2 = 'all' OR n.status = $2)
            ORDER BY n.updated_at DESC, n.id DESC
            LIMIT $3 OFFSET $4
            "#,
            case_visible = notebook_case_visible_to_user(1, viewer.deny_param(5)),
        );
        let mut query = sqlx::query_as::<_, NotebookSummary>(&sql)
            .bind(viewer.user_id())
            .bind(status)
            .bind(limit)
            .bind(offset);
        if let Some(deny) = viewer.deny_bind() {
            query = query.bind(deny);
        }
        let results = query.fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// Get active notebook for user (if any)
    pub async fn get_active_for_user(
        &self,
        viewer: &ViewerScope,
    ) -> Result<Option<NotebookWithOwner>, NotebookRepositoryError> {
        let sql = format!(
            r#"
            SELECT n.*, u.name as owner_name
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            WHERE {case_visible} AND n.owner_id = $1 AND n.status = 'active'
            ORDER BY n.updated_at DESC
            LIMIT 1
            "#,
            case_visible = notebook_case_visible_to_user(1, viewer.deny_param(2)),
        );
        let mut query = sqlx::query_as::<_, NotebookWithOwner>(&sql)
            .bind(viewer.user_id());
        if let Some(deny) = viewer.deny_bind() {
            query = query.bind(deny);
        }
        let result = query.fetch_optional(&self.pool).await?;

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
    ///
    /// NAN-5229: `visibility` is owner-only and only on a standalone
    /// notebook — a linked notebook's access is governed by its case. Edit
    /// shares and case collaborators keep title/summary/status edits, but a
    /// request from them that carries `visibility` matches no row and fails
    /// with `AccessDenied` (403) instead of being applied or silently dropped.
    pub async fn update_owned(
        &self,
        id: Uuid,
        viewer: &ViewerScope,
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
        let sql = format!(r#"
            UPDATE notebooks n SET title = COALESCE($3, title),
                visibility = COALESCE($4, visibility), status = COALESCE($5, status),
                summary = COALESCE($6, summary),
                closed_at = CASE WHEN $5 = 'closed' AND closed_at IS NULL THEN NOW() ELSE closed_at END,
                updated_at = NOW()
            WHERE n.id = $1 AND {visible}
              AND (n.case_id IS NOT NULL OR n.owner_id = $2 OR EXISTS (
                  SELECT 1 FROM notebook_shares ns
                  LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $2
                  WHERE ns.notebook_id = n.id AND ns.permission = 'edit'
                    AND (ns.shared_with_user_id = $2 OR ug.user_id IS NOT NULL)
              ))
              AND ($4::text IS NULL OR (n.owner_id = $2 AND n.case_id IS NULL))
              RETURNING n.*
        "#, visible = notebook_visible_to_user_at(2, viewer.deny_param(7)));
        let mut query = sqlx::query_as::<_, Notebook>(&sql)
            .bind(id).bind(viewer.user_id()).bind(&update.title).bind(visibility).bind(status).bind(&update.summary);
        if let Some(deny) = viewer.deny_bind() {
            query = query.bind(deny);
        }
        query
            .fetch_optional(&self.pool).await?
            .ok_or(NotebookRepositoryError::AccessDenied(id))
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
        viewer: &ViewerScope,
    ) -> Result<(), NotebookRepositoryError> {
        let sql = format!(
            "DELETE FROM notebooks n WHERE id = $1 AND owner_id = $2 AND {}",
            notebook_case_visible_to_user(2, viewer.deny_param(3))
        );
        let mut query = sqlx::query(&sql)
            .bind(id)
            .bind(viewer.user_id());
        if let Some(deny) = viewer.deny_bind() {
            query = query.bind(deny);
        }
        let result = query.execute(&self.pool).await?;

        if result.rows_affected() == 0 {
            return Err(NotebookRepositoryError::AccessDenied(id));
        }

        Ok(())
    }
}
