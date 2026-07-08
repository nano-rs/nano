// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notebook tab operations: list, open, close, reorder, cleanup

use uuid::Uuid;

use crate::models::notebook::{NotebookTab, NotebookTabWithDetails};

use super::{NotebookRepository, NotebookRepositoryError};

impl NotebookRepository {
    /// List all open tabs for a user, ordered by tab_order
    /// Also performs stale tab cleanup (removes unpinned tabs older than 7 days)
    pub async fn list_tabs_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<NotebookTabWithDetails>, NotebookRepositoryError> {
        // First, cleanup stale tabs (unpinned tabs not accessed in 7 days)
        self.cleanup_stale_tabs(7).await?;

        let results = sqlx::query_as::<_, NotebookTabWithDetails>(
            r#"
            SELECT
                t.id,
                t.user_id,
                t.notebook_id,
                t.is_pinned,
                t.is_active,
                t.tab_order,
                t.last_accessed_at,
                t.created_at,
                n.title as notebook_title,
                n.status as notebook_status,
                COALESCE(ec.entry_count, 0) as entry_count,
                n.case_id
            FROM notebook_tabs t
            JOIN notebooks n ON t.notebook_id = n.id
            LEFT JOIN (
                SELECT notebook_id, COUNT(*) as entry_count
                FROM notebook_entries
                GROUP BY notebook_id
            ) ec ON ec.notebook_id = n.id
            WHERE t.user_id = $1
            ORDER BY t.tab_order ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Open a notebook as a tab (upsert - creates if not exists, updates if exists)
    /// Sets the tab as active and updates last_accessed_at
    pub async fn open_tab(
        &self,
        user_id: Uuid,
        notebook_id: Uuid,
    ) -> Result<NotebookTab, NotebookRepositoryError> {
        // Verify user has access to this notebook
        self.find_by_id_for_user(notebook_id, user_id).await?;

        // Get max tab_order for this user
        let max_order = sqlx::query_scalar::<_, Option<i32>>(
            r#"SELECT MAX(tab_order) FROM notebook_tabs WHERE user_id = $1"#,
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?
        .unwrap_or(0);

        // Deactivate all other tabs for this user
        sqlx::query(r#"UPDATE notebook_tabs SET is_active = false WHERE user_id = $1"#)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        // Upsert the tab
        let result = sqlx::query_as::<_, NotebookTab>(
            r#"
            INSERT INTO notebook_tabs (user_id, notebook_id, is_active, tab_order, last_accessed_at)
            VALUES ($1, $2, true, $3, NOW())
            ON CONFLICT (user_id, notebook_id)
            DO UPDATE SET
                is_active = true,
                last_accessed_at = NOW()
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(notebook_id)
        .bind(max_order + 1)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Close a tab (remove it)
    pub async fn close_tab(
        &self,
        tab_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), NotebookRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM notebook_tabs WHERE id = $1 AND user_id = $2"#)
            .bind(tab_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(NotebookRepositoryError::TabNotFound(tab_id));
        }

        Ok(())
    }

    /// Set a tab as active (switch to it)
    /// Updates last_accessed_at and deactivates other tabs
    pub async fn set_active_tab(
        &self,
        user_id: Uuid,
        notebook_id: Uuid,
    ) -> Result<NotebookTab, NotebookRepositoryError> {
        // Deactivate all tabs for this user
        sqlx::query(r#"UPDATE notebook_tabs SET is_active = false WHERE user_id = $1"#)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        // Activate the specified tab and update last_accessed_at
        let result = sqlx::query_as::<_, NotebookTab>(
            r#"
            UPDATE notebook_tabs
            SET is_active = true, last_accessed_at = NOW()
            WHERE user_id = $1 AND notebook_id = $2
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(notebook_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotebookRepositoryError::NotFound(notebook_id))?;

        Ok(result)
    }

    /// Update a tab (pin/unpin)
    pub async fn update_tab(
        &self,
        tab_id: Uuid,
        user_id: Uuid,
        is_pinned: Option<bool>,
    ) -> Result<NotebookTab, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, NotebookTab>(
            r#"
            UPDATE notebook_tabs
            SET is_pinned = COALESCE($3, is_pinned)
            WHERE id = $1 AND user_id = $2
            RETURNING *
            "#,
        )
        .bind(tab_id)
        .bind(user_id)
        .bind(is_pinned)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotebookRepositoryError::TabNotFound(tab_id))?;

        Ok(result)
    }

    /// Reorder tabs by setting tab_order based on the provided list of tab IDs
    ///
    /// N8: the per-id UPDATEs run inside a single transaction so concurrent
    /// reorders can't interleave and leave `tab_order` in an inconsistent state
    /// (partial application of two competing orderings). Either the whole new
    /// ordering commits or none of it does.
    pub async fn reorder_tabs(
        &self,
        user_id: Uuid,
        tab_ids: &[Uuid],
    ) -> Result<(), NotebookRepositoryError> {
        let mut tx = self.pool.begin().await?;

        for (index, tab_id) in tab_ids.iter().enumerate() {
            sqlx::query(
                r#"
                UPDATE notebook_tabs
                SET tab_order = $3
                WHERE id = $1 AND user_id = $2
                "#,
            )
            .bind(tab_id)
            .bind(user_id)
            .bind(index as i32)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(())
    }

    /// Cleanup stale tabs (delete unpinned tabs older than N days)
    pub async fn cleanup_stale_tabs(&self, days: i32) -> Result<i64, NotebookRepositoryError> {
        let result = sqlx::query(
            r#"
            DELETE FROM notebook_tabs
            WHERE is_pinned = false
            AND last_accessed_at < NOW() - ($1 || ' days')::interval
            "#,
        )
        .bind(days)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }
}
