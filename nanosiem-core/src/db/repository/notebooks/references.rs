// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notebook reference operations: add, list, delete, and find by reference

use uuid::Uuid;

use crate::models::notebook::{NewNotebookReference, NotebookReference, NotebookSummary};

use super::{NotebookRepository, NotebookRepositoryError};

impl NotebookRepository {
    /// Add a reference to a notebook
    pub async fn add_reference(
        &self,
        reference: &NewNotebookReference,
    ) -> Result<NotebookReference, NotebookRepositoryError> {
        let ref_type = match reference.reference_type {
            crate::models::notebook::ReferenceType::Alert => "alert",
            crate::models::notebook::ReferenceType::Detection => "detection",
            crate::models::notebook::ReferenceType::SavedSearch => "saved_search",
            crate::models::notebook::ReferenceType::Case => "case",
        };

        let result = sqlx::query_as::<_, NotebookReference>(
            r#"
            INSERT INTO notebook_references (notebook_id, reference_type, reference_id, reference_name)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (notebook_id, reference_type, reference_id) DO NOTHING
            RETURNING *
            "#,
        )
        .bind(reference.notebook_id)
        .bind(ref_type)
        .bind(reference.reference_id)
        .bind(&reference.reference_name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotebookRepositoryError::ReferenceAlreadyExists)?;

        Ok(result)
    }

    /// Get references for a notebook
    pub async fn get_references(
        &self,
        notebook_id: Uuid,
    ) -> Result<Vec<NotebookReference>, NotebookRepositoryError> {
        let results = sqlx::query_as::<_, NotebookReference>(
            r#"
            SELECT * FROM notebook_references
            WHERE notebook_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(notebook_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Get references of a specific type for a notebook
    pub async fn get_references_by_type(
        &self,
        notebook_id: Uuid,
        reference_type: &str,
    ) -> Result<Vec<NotebookReference>, NotebookRepositoryError> {
        let results = sqlx::query_as::<_, NotebookReference>(
            r#"
            SELECT * FROM notebook_references
            WHERE notebook_id = $1 AND reference_type = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(notebook_id)
        .bind(reference_type)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Delete a reference
    pub async fn delete_reference(
        &self,
        reference_id: Uuid,
    ) -> Result<(), NotebookRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM notebook_references WHERE id = $1"#)
            .bind(reference_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(NotebookRepositoryError::ReferenceNotFound(reference_id));
        }

        Ok(())
    }

    /// Delete a reference only if it belongs to the specified notebook.
    ///
    /// NAN-1739: the unscoped `delete_reference` let a caller who could edit
    /// notebook A delete a reference belonging to notebook B (cross-notebook
    /// IDOR). Callers that have already authorized edit access to
    /// `notebook_id` must use this scoped variant. Mirrors
    /// `delete_entry_in_notebook` / `delete_share_in_notebook`.
    pub async fn delete_reference_in_notebook(
        &self,
        notebook_id: Uuid,
        reference_id: Uuid,
    ) -> Result<(), NotebookRepositoryError> {
        let result =
            sqlx::query(r#"DELETE FROM notebook_references WHERE id = $1 AND notebook_id = $2"#)
                .bind(reference_id)
                .bind(notebook_id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(NotebookRepositoryError::ReferenceNotFound(reference_id));
        }

        Ok(())
    }

    /// Find notebooks that reference a specific entity
    pub async fn find_notebooks_referencing(
        &self,
        reference_type: &str,
        reference_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        let results = sqlx::query_as::<_, NotebookSummary>(
            r#"
            SELECT DISTINCT
                n.*,
                u.name as owner_name,
                COALESCE(ec.entry_count, 0) as entry_count
            FROM notebooks n
            JOIN notebook_references nr ON nr.notebook_id = n.id
            LEFT JOIN users u ON n.owner_id = u.id
            LEFT JOIN notebook_shares ns ON ns.notebook_id = n.id
            LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $3
            LEFT JOIN (
                SELECT notebook_id, COUNT(*) as entry_count
                FROM notebook_entries
                GROUP BY notebook_id
            ) ec ON ec.notebook_id = n.id
            WHERE nr.reference_type = $1 AND nr.reference_id = $2
              AND (
                  n.owner_id = $3
                  -- NAN-1739: case notebooks are visibility='public'; the
                  -- public disjunct only frees non-case notebooks, case
                  -- notebooks are governed by case visibility so this lookup
                  -- can't hand a case notebook to a user who can't see the case.
                  OR (n.case_id IS NULL AND n.visibility = 'public')
                  OR ns.shared_with_user_id = $3
                  OR ug.user_id IS NOT NULL
                  OR (
                      n.case_id IS NOT NULL
                      AND EXISTS (
                          SELECT 1 FROM cases c
                          WHERE c.id = n.case_id
                            AND (
                                c.created_by = $3
                                OR c.assigned_to = $3
                                OR c.visibility = 'public'
                                OR (c.visibility = 'group' AND EXISTS (
                                    SELECT 1 FROM case_groups cg
                                    JOIN user_groups cug ON cug.group_id = cg.group_id
                                    WHERE cg.case_id = c.id AND cug.user_id = $3
                                ))
                            )
                      )
                  )
              )
            ORDER BY n.updated_at DESC
            "#,
        )
        .bind(reference_type)
        .bind(reference_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}
