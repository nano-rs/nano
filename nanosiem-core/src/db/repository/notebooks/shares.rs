// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notebook share operations: add, list, delete shares

use uuid::Uuid;

use crate::models::notebook::{NewNotebookShare, NotebookShare, NotebookShareWithNames};

use super::{NotebookRepository, NotebookRepositoryError};

impl NotebookRepository {
    /// Add a share to a notebook
    pub async fn add_share(
        &self,
        share: &NewNotebookShare,
    ) -> Result<NotebookShare, NotebookRepositoryError> {
        // Validate that exactly one of user or group is set
        if share.shared_with_user_id.is_some() == share.shared_with_group_id.is_some() {
            return Err(NotebookRepositoryError::InvalidShareTarget);
        }

        let permission = match share.permission {
            crate::models::notebook::SharePermission::View => "view",
            crate::models::notebook::SharePermission::Edit => "edit",
        };

        let result = sqlx::query_as::<_, NotebookShare>(
            r#"
            INSERT INTO notebook_shares (notebook_id, shared_with_user_id, shared_with_group_id, permission)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(share.notebook_id)
        .bind(share.shared_with_user_id)
        .bind(share.shared_with_group_id)
        .bind(permission)
        .fetch_one(&self.pool)
        .await?;

        // Update notebook visibility to 'shared' if it was 'private'
        sqlx::query(
            r#"UPDATE notebooks SET visibility = 'shared' WHERE id = $1 AND visibility = 'private'"#,
        )
        .bind(share.notebook_id)
        .execute(&self.pool)
        .await?;

        Ok(result)
    }

    /// Get shares for a notebook
    pub async fn get_shares(
        &self,
        notebook_id: Uuid,
    ) -> Result<Vec<NotebookShareWithNames>, NotebookRepositoryError> {
        let results = sqlx::query_as::<_, NotebookShareWithNames>(
            r#"
            SELECT
                s.*,
                u.name as user_name,
                g.name as group_name
            FROM notebook_shares s
            LEFT JOIN users u ON s.shared_with_user_id = u.id
            LEFT JOIN groups g ON s.shared_with_group_id = g.id
            WHERE s.notebook_id = $1
            ORDER BY s.created_at ASC
            "#,
        )
        .bind(notebook_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Delete a share
    pub async fn delete_share(&self, share_id: Uuid) -> Result<(), NotebookRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM notebook_shares WHERE id = $1"#)
            .bind(share_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(NotebookRepositoryError::ShareNotFound(share_id));
        }

        Ok(())
    }

    /// Delete a share only if it belongs to the specified notebook.
    pub async fn delete_share_in_notebook(
        &self,
        notebook_id: Uuid,
        share_id: Uuid,
    ) -> Result<(), NotebookRepositoryError> {
        let result =
            sqlx::query(r#"DELETE FROM notebook_shares WHERE id = $1 AND notebook_id = $2"#)
                .bind(share_id)
                .bind(notebook_id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(NotebookRepositoryError::ShareNotFound(share_id));
        }

        Ok(())
    }

    /// Delete all shares for a notebook (when changing to private)
    pub async fn delete_all_shares(
        &self,
        notebook_id: Uuid,
    ) -> Result<(), NotebookRepositoryError> {
        sqlx::query(r#"DELETE FROM notebook_shares WHERE notebook_id = $1"#)
            .bind(notebook_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
