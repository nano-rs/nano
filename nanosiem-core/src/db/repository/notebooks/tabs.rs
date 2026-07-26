// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notebook tab operations: list, open, close, reorder, cleanup

use uuid::Uuid;

use crate::models::notebook::{NotebookTab, NotebookTabWithDetails};

use super::{notebook_visible_to_user, NotebookRepository, NotebookRepositoryError};

impl NotebookRepository {
    /// List all open tabs for a user, ordered by tab_order.
    ///
    /// Also performs stale-tab cleanup (unpinned tabs not accessed in 7 days)
    /// and, since NAN-2101, prunes tabs whose notebook the user can no longer
    /// see.
    ///
    /// NAN-2101: the row set is filtered by the CURRENT access predicate, not
    /// by tab ownership alone. Age-based cleanup was never an authorization
    /// mechanism — and could not be one, because it deliberately never removes
    /// pinned tabs, which is exactly what let a revoked holder keep a private
    /// notebook's title/status/entry-count/`case_id` visible indefinitely.
    pub async fn list_tabs_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<NotebookTabWithDetails>, NotebookRepositoryError> {
        // First, cleanup stale tabs (unpinned tabs not accessed in 7 days)
        self.cleanup_stale_tabs(7).await?;
        // Then drop this user's tabs for notebooks they can no longer access.
        // Defense in depth only: the SELECT below is filtered independently, so
        // a failure here cannot leak. It makes revocation self-healing instead
        // of leaving a row that a future query might forget to filter.
        self.prune_inaccessible_tabs(user_id).await?;

        let results = sqlx::query_as::<_, NotebookTabWithDetails>(&format!(
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
              AND {predicate}
            ORDER BY t.tab_order ASC
            "#,
            predicate = notebook_visible_to_user(),
        ))
        .bind(user_id)
        // $2 — the access predicate's user id. Same value as $1; bound
        // separately so the shared predicate keeps ONE placeholder contract
        // across every query that embeds it.
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// NAN-2101: delete this user's tabs for notebooks they can no longer see.
    ///
    /// Share revocation, a visibility tightening, group removal and case-access
    /// loss all leave `notebook_tabs` rows behind; nothing else removes them.
    /// Scoped to one user so a caller can only ever prune their own rows.
    async fn prune_inaccessible_tabs(&self, user_id: Uuid) -> Result<u64, NotebookRepositoryError> {
        let result = sqlx::query(&format!(
            r#"
            DELETE FROM notebook_tabs t
            WHERE t.user_id = $1
              AND NOT EXISTS (
                  SELECT 1 FROM notebooks n
                  WHERE n.id = t.notebook_id
                    AND {predicate}
              )
            "#,
            predicate = notebook_visible_to_user(),
        ))
        .bind(user_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
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
    ///
    /// NAN-2101: the access predicate lives INSIDE the UPDATE, so a caller who
    /// lost access cannot reactivate a stale tab. Check-then-act was not an
    /// option: it would open a window between the check and the write, and it
    /// would answer "does this notebook exist?" separately from "may you touch
    /// it?". A no-op UPDATE returns the same `NotFound` as an unknown notebook.
    /// The switch is ONE statement over all of the caller's tab rows. Two
    /// earlier shapes are both wrong:
    ///
    /// * deactivate-all then activate — a REFUSED switch still clears the
    ///   caller's legitimate active tab;
    /// * activate then deactivate-others as two statements — two concurrent
    ///   switches interleave into "no active tab", or deadlock on each other's
    ///   row locks (each holds its own target and wants the other's).
    ///
    /// A single `UPDATE` takes all its row locks in one pass under one plan, so
    /// concurrent executions serialize and the single-active-tab invariant
    /// holds. `EXISTS (SELECT 1 FROM target)` makes the whole statement a no-op
    /// when the target is not visible, so nothing is deactivated on refusal.
    pub async fn set_active_tab(
        &self,
        user_id: Uuid,
        notebook_id: Uuid,
    ) -> Result<NotebookTab, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, NotebookTab>(&format!(
            r#"
            WITH target AS (
                SELECT t.id
                FROM notebook_tabs t
                WHERE t.user_id = $1 AND t.notebook_id = $3
                  AND EXISTS (
                      SELECT 1 FROM notebooks n
                      WHERE n.id = t.notebook_id
                        AND {predicate}
                  )
            ),
            switched AS (
                UPDATE notebook_tabs t
                SET is_active = (t.id IN (SELECT id FROM target)),
                    last_accessed_at = CASE
                        WHEN t.id IN (SELECT id FROM target) THEN NOW()
                        ELSE t.last_accessed_at
                    END
                WHERE t.user_id = $1
                  AND EXISTS (SELECT 1 FROM target)
                RETURNING t.*
            )
            SELECT * FROM switched WHERE id IN (SELECT id FROM target)
            "#,
            predicate = notebook_visible_to_user(),
        ))
        .bind(user_id)
        .bind(user_id)
        .bind(notebook_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotebookRepositoryError::NotFound(notebook_id))?;

        Ok(result)
    }

    /// Update a tab (pin/unpin)
    ///
    /// NAN-2101: pinning is the mechanism that made the leak permanent — a
    /// pinned tab is exempt from stale cleanup — and the response echoes the
    /// tab row. The access predicate is INSIDE the UPDATE; a caller who lost
    /// access gets the same `TabNotFound` as a nonexistent tab, so this is not
    /// an existence oracle either.
    ///
    /// Closing a tab is deliberately NOT gated the same way: `close_tab` only
    /// deletes the caller's own row and returns no notebook metadata, and a
    /// revoked holder must still be able to get rid of a stale tab.
    pub async fn update_tab(
        &self,
        tab_id: Uuid,
        user_id: Uuid,
        is_pinned: Option<bool>,
    ) -> Result<NotebookTab, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, NotebookTab>(&format!(
            r#"
            UPDATE notebook_tabs t
            SET is_pinned = COALESCE($3, t.is_pinned)
            WHERE t.id = $1 AND t.user_id = $2
              AND EXISTS (
                  SELECT 1 FROM notebooks n
                  WHERE n.id = t.notebook_id
                    AND {predicate}
              )
            RETURNING t.*
            "#,
            predicate = notebook_visible_to_user(),
        ))
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
