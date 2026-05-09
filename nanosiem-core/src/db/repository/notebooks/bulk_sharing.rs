// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bulk notebook sharing: visibility + group share sync

use uuid::Uuid;

use crate::models::notebook::{
    NotebookAffectedUser, NotebookShareResult, NotebookSharedGroup, NotebookSummary,
    ShareNotebookRequest,
};

use super::{NotebookRepository, NotebookRepositoryError};

impl NotebookRepository {
    /// Get groups a notebook is shared with (group shares only)
    pub async fn get_shared_groups(
        &self,
        notebook_id: Uuid,
    ) -> Result<Vec<NotebookSharedGroup>, NotebookRepositoryError> {
        let groups = sqlx::query_as::<_, NotebookSharedGroup>(
            r#"
            SELECT g.id, g.name
            FROM notebook_shares ns
            JOIN groups g ON g.id = ns.shared_with_group_id
            WHERE ns.notebook_id = $1 AND ns.shared_with_group_id IS NOT NULL
            ORDER BY g.name
            "#,
        )
        .bind(notebook_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(groups)
    }

    /// Get users in specified groups (for affected users calculation)
    async fn get_users_in_groups(
        &self,
        group_ids: &[Uuid],
        exclude_user_id: Uuid,
    ) -> Result<Vec<NotebookAffectedUser>, NotebookRepositoryError> {
        if group_ids.is_empty() {
            return Ok(vec![]);
        }

        let users = sqlx::query_as::<_, NotebookAffectedUser>(
            r#"
            SELECT DISTINCT u.id as user_id, u.name as user_name, u.email as user_email
            FROM users u
            JOIN user_groups ug ON ug.user_id = u.id
            WHERE ug.group_id = ANY($1)
              AND u.id != $2
            ORDER BY u.name
            "#,
        )
        .bind(group_ids)
        .bind(exclude_user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    /// Share a notebook (owner only) - bulk visibility + group update
    /// This updates visibility and syncs group shares while preserving user shares
    pub async fn share(
        &self,
        id: Uuid,
        request: &ShareNotebookRequest,
        user_id: Uuid,
    ) -> Result<NotebookShareResult, NotebookRepositoryError> {
        // Get the notebook and verify ownership
        let notebook = self.find_by_id(id).await?;

        if notebook.owner_id != user_id {
            return Err(NotebookRepositoryError::AccessDenied(id));
        }

        // Get old groups before change (to detect removed groups)
        let old_groups = self.get_shared_groups(id).await?;
        let old_group_ids: Vec<Uuid> = old_groups.iter().map(|g| g.id).collect();

        // Determine new groups
        let new_group_ids: Vec<Uuid> = if request.visibility == "shared" {
            request.group_ids.clone().unwrap_or_default()
        } else {
            vec![]
        };

        // Find removed groups (in old but not in new)
        let removed_group_ids: Vec<Uuid> = old_group_ids
            .iter()
            .filter(|id| !new_group_ids.contains(id))
            .copied()
            .collect();

        // Get affected users (those who will lose access)
        let users_who_lost_access = self
            .get_users_in_groups(&removed_group_ids, user_id)
            .await?;

        // Update visibility
        sqlx::query(
            r#"
            UPDATE notebooks SET visibility = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&request.visibility)
        .execute(&self.pool)
        .await?;

        // Delete all GROUP shares (preserve user shares)
        sqlx::query(
            r#"DELETE FROM notebook_shares WHERE notebook_id = $1 AND shared_with_group_id IS NOT NULL"#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        // Insert new group shares if visibility is 'shared'
        if request.visibility == "shared" {
            for group_id in &new_group_ids {
                sqlx::query(
                    r#"
                    INSERT INTO notebook_shares (notebook_id, shared_with_group_id, permission)
                    VALUES ($1, $2, 'view')
                    ON CONFLICT DO NOTHING
                    "#,
                )
                .bind(id)
                .bind(group_id)
                .execute(&self.pool)
                .await?;
            }
        }

        // Fetch the updated notebook summary
        let notebook_summary = self.get_notebook_summary(id, user_id).await?;

        // Fetch the updated shared groups
        let shared_groups = self.get_shared_groups(id).await?;

        Ok(NotebookShareResult {
            notebook: notebook_summary,
            shared_groups,
            users_who_lost_access,
        })
    }

    /// Get a notebook summary by ID for a specific user
    async fn get_notebook_summary(
        &self,
        id: Uuid,
        _user_id: Uuid,
    ) -> Result<NotebookSummary, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, NotebookSummary>(
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
            WHERE n.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotebookRepositoryError::NotFound(id))?;

        Ok(result)
    }
}
