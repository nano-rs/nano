// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case-notebook integration: linking, merging, entity search

use uuid::Uuid;

use crate::models::notebook::{Notebook, NotebookSummary, NotebookWithOwner};

use super::{NotebookRepository, NotebookRepositoryError};

impl NotebookRepository {
    /// Find notebook linked to a case
    pub async fn find_by_case_id(
        &self,
        case_id: Uuid,
    ) -> Result<Option<Notebook>, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, Notebook>(r#"SELECT * FROM notebooks WHERE case_id = $1"#)
            .bind(case_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(result)
    }

    /// Find notebook linked to a case with owner info
    pub async fn find_by_case_id_with_owner(
        &self,
        case_id: Uuid,
    ) -> Result<Option<NotebookWithOwner>, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, NotebookWithOwner>(
            r#"
            SELECT n.*, u.name as owner_name
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            WHERE n.case_id = $1
            "#,
        )
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    /// Create a case notebook (auto-created on case assignment)
    pub async fn create_case_notebook(
        &self,
        case_id: Uuid,
        case_title: &str,
        owner_id: Uuid,
    ) -> Result<Notebook, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, Notebook>(
            r#"
            INSERT INTO notebooks (title, owner_id, case_id, visibility, status)
            VALUES ($1, $2, $3, 'public', 'active')
            RETURNING *
            "#,
        )
        .bind(format!("Case Investigation: {}", case_title))
        .bind(owner_id)
        .bind(case_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Transfer ownership of a notebook to a new user (e.g., when a case is assigned
    /// and the notebook was auto-created by the system AI user).
    pub async fn transfer_ownership(
        &self,
        notebook_id: Uuid,
        new_owner_id: Uuid,
    ) -> Result<(), NotebookRepositoryError> {
        sqlx::query(r#"UPDATE notebooks SET owner_id = $1, updated_at = NOW() WHERE id = $2"#)
            .bind(new_owner_id)
            .bind(notebook_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Link an existing notebook to a case (manual linking)
    pub async fn link_to_case(
        &self,
        notebook_id: Uuid,
        case_id: Uuid,
    ) -> Result<Notebook, NotebookRepositoryError> {
        // First check if case already has a notebook
        let existing = self.find_by_case_id(case_id).await?;
        if existing.is_some() {
            return Err(NotebookRepositoryError::CaseAlreadyHasNotebook(case_id));
        }

        // Check if notebook is already linked to another case
        let notebook = self.find_by_id(notebook_id).await?;
        if notebook.case_id.is_some() {
            return Err(NotebookRepositoryError::NotebookAlreadyLinked);
        }

        let result = sqlx::query_as::<_, Notebook>(
            r#"
            UPDATE notebooks SET
                case_id = $2,
                visibility = 'public',
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(notebook_id)
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotebookRepositoryError::NotFound(notebook_id))?;

        Ok(result)
    }

    /// Unlink a notebook from a case (make it a regular notebook again)
    pub async fn unlink_from_case(
        &self,
        notebook_id: Uuid,
    ) -> Result<Notebook, NotebookRepositoryError> {
        let result = sqlx::query_as::<_, Notebook>(
            r#"
            UPDATE notebooks SET
                case_id = NULL,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(notebook_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotebookRepositoryError::NotFound(notebook_id))?;

        Ok(result)
    }

    /// Merge a source notebook into a target notebook
    /// Copies all entries from source to target with merge markers, then archives the source
    pub async fn merge_notebooks(
        &self,
        source_id: Uuid,
        target_id: Uuid,
    ) -> Result<i64, NotebookRepositoryError> {
        // Verify both notebooks exist and get source title
        let source = self.find_by_id(source_id).await?;
        self.find_by_id(target_id).await?;

        // Copy entries from source to target with merge markers
        // We copy (not move) so the source notebook retains its entries as a read-only archive
        let result = sqlx::query(
            r#"
            INSERT INTO notebook_entries (
                notebook_id, entry_type, content, source_url, created_by, created_at,
                merged_from_notebook_id, merged_from_notebook_title, original_created_at
            )
            SELECT
                $2,
                entry_type,
                content,
                source_url,
                created_by,
                NOW(),
                $1,
                $3,
                created_at
            FROM notebook_entries
            WHERE notebook_id = $1
            "#,
        )
        .bind(source_id)
        .bind(target_id)
        .bind(&source.title)
        .execute(&self.pool)
        .await?;

        let copied_count = result.rows_affected() as i64;

        // Copy references from source to target (ignore conflicts)
        sqlx::query(
            r#"
            INSERT INTO notebook_references (notebook_id, reference_type, reference_id, reference_name)
            SELECT $2, reference_type, reference_id, reference_name
            FROM notebook_references
            WHERE notebook_id = $1
            ON CONFLICT (notebook_id, reference_type, reference_id) DO NOTHING
            "#,
        )
        .bind(source_id)
        .bind(target_id)
        .execute(&self.pool)
        .await?;

        // Mark source notebook as merged (read-only archive)
        let merge_summary = format!(
            "This notebook was merged into another investigation. {} entries were copied to the target notebook.",
            copied_count
        );
        sqlx::query(
            r#"
            UPDATE notebooks SET
                status = 'merged',
                merged_into_id = $2,
                summary = $3,
                closed_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(source_id)
        .bind(target_id)
        .bind(&merge_summary)
        .execute(&self.pool)
        .await?;

        // Update target notebook's updated_at
        sqlx::query(r#"UPDATE notebooks SET updated_at = NOW() WHERE id = $1"#)
            .bind(target_id)
            .execute(&self.pool)
            .await?;

        Ok(copied_count)
    }

    /// Merge multiple source notebooks into a target notebook
    pub async fn merge_notebooks_bulk(
        &self,
        source_ids: &[Uuid],
        target_id: Uuid,
    ) -> Result<i64, NotebookRepositoryError> {
        let mut total_copied = 0i64;

        for source_id in source_ids {
            let copied = self.merge_notebooks(*source_id, target_id).await?;
            total_copied += copied;
        }

        Ok(total_copied)
    }

    /// Find notebooks that have entity references matching given entity values
    /// Used to detect related notebooks when viewing/assigning a case
    pub async fn find_notebooks_with_entities(
        &self,
        entity_values: &[String],
        user_id: Uuid,
        exclude_case_notebooks: bool,
    ) -> Result<Vec<NotebookSummary>, NotebookRepositoryError> {
        if entity_values.is_empty() {
            return Ok(vec![]);
        }

        // Search for notebooks where entries contain entity references matching the given values
        // The content is JSON like {"entity_type": "ip", "value": "192.168.1.1"}
        let case_notebook_filter = if exclude_case_notebooks {
            "AND n.case_id IS NULL"
        } else {
            ""
        };

        let query = format!(
            r#"
            SELECT DISTINCT
                n.*,
                u.name as owner_name,
                COALESCE(ec.entry_count, 0) as entry_count
            FROM notebooks n
            LEFT JOIN users u ON n.owner_id = u.id
            LEFT JOIN notebook_shares ns ON ns.notebook_id = n.id
            LEFT JOIN user_groups ug ON ug.group_id = ns.shared_with_group_id AND ug.user_id = $2
            LEFT JOIN (
                SELECT notebook_id, COUNT(*) as entry_count
                FROM notebook_entries
                GROUP BY notebook_id
            ) ec ON ec.notebook_id = n.id
            WHERE EXISTS (
                SELECT 1 FROM notebook_entries ne
                WHERE ne.notebook_id = n.id
                AND ne.entry_type = 'entity_reference'
                AND ne.content->>'value' = ANY($1)
            )
            {}
            AND (
                n.owner_id = $2
                -- NAN-1739: case notebooks are visibility='public'; gate the
                -- public disjunct on case_id IS NULL and govern case notebooks
                -- by case visibility (the exclude flag above may already drop
                -- them entirely; when included they must respect case access).
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
            ORDER BY n.updated_at DESC
            LIMIT 20
            "#,
            case_notebook_filter
        );

        let results = sqlx::query_as::<_, NotebookSummary>(&query)
            .bind(entity_values)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;

        Ok(results)
    }

    /// Get the entity values from a notebook that match a given set of values
    pub async fn get_matched_entities(
        &self,
        notebook_id: Uuid,
        entity_values: &[String],
    ) -> Result<Vec<String>, NotebookRepositoryError> {
        if entity_values.is_empty() {
            return Ok(vec![]);
        }

        let results = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT content->>'value' as value
            FROM notebook_entries
            WHERE notebook_id = $1
            AND entry_type = 'entity_reference'
            AND content->>'value' = ANY($2)
            "#,
        )
        .bind(notebook_id)
        .bind(entity_values)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}
