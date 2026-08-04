// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notebook entry operations: add, list, delete, finalize streaming

use uuid::Uuid;

use crate::models::notebook::{NewNotebookEntry, NotebookEntry, NotebookEntryWithCreator};

use super::{NotebookRepository, NotebookRepositoryError};

impl NotebookRepository {
    /// Add an entry to a notebook
    pub async fn add_entry(
        &self,
        entry: &NewNotebookEntry,
    ) -> Result<NotebookEntry, NotebookRepositoryError> {
        self.add_entry_with_source(entry, "analyst").await
    }

    /// Add an entry to a notebook with explicit source (e.g., 'shadow_investigation')
    pub async fn add_entry_with_source(
        &self,
        entry: &NewNotebookEntry,
        source: &str,
    ) -> Result<NotebookEntry, NotebookRepositoryError> {
        let entry_type = match entry.entry_type {
            crate::models::notebook::NotebookEntryType::ManualNote => "manual_note",
            crate::models::notebook::NotebookEntryType::SearchExecuted => "search_executed",
            crate::models::notebook::NotebookEntryType::SearchRefined => "search_refined",
            crate::models::notebook::NotebookEntryType::AlertViewed => "alert_viewed",
            crate::models::notebook::NotebookEntryType::AlertActioned => "alert_actioned",
            crate::models::notebook::NotebookEntryType::DetectionViewed => "detection_viewed",
            crate::models::notebook::NotebookEntryType::DetectionModified => "detection_modified",
            crate::models::notebook::NotebookEntryType::AiSuggestion => "ai_suggestion",
            crate::models::notebook::NotebookEntryType::AiSummary => "ai_summary",
            crate::models::notebook::NotebookEntryType::EntityReference => "entity_reference",
            crate::models::notebook::NotebookEntryType::EntityBaseline => "entity_baseline",
            crate::models::notebook::NotebookEntryType::IocMarker => "ioc_marker",
            crate::models::notebook::NotebookEntryType::TimelineMarker => "timeline_marker",
            crate::models::notebook::NotebookEntryType::LinkedAlert => "linked_alert",
            crate::models::notebook::NotebookEntryType::LinkedDetection => "linked_detection",
            crate::models::notebook::NotebookEntryType::AiQuery => "ai_query",
            crate::models::notebook::NotebookEntryType::PivotSuggestions => "pivot_suggestions",
            crate::models::notebook::NotebookEntryType::UserMention => "user_mention",
            crate::models::notebook::NotebookEntryType::CaseEvent => "case_event",
            crate::models::notebook::NotebookEntryType::AiChatMessage => "ai_chat_message",
            crate::models::notebook::NotebookEntryType::AiChatResponse => "ai_chat_response",
            crate::models::notebook::NotebookEntryType::AiSearchResult => "ai_search_result",
        };

        let result = sqlx::query_as::<_, NotebookEntry>(
            r#"
            WITH updated AS (
                UPDATE notebooks SET updated_at = NOW() WHERE id = $1
            )
            INSERT INTO notebook_entries (notebook_id, entry_type, content, source_url, created_by, source, original_created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(entry.notebook_id)
        .bind(entry_type)
        .bind(&entry.content)
        .bind(&entry.source_url)
        .bind(entry.created_by)
        .bind(source)
        .bind(entry.original_created_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Get entries for a notebook
    pub async fn get_entries(
        &self,
        notebook_id: Uuid,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<NotebookEntryWithCreator>, NotebookRepositoryError> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let results = sqlx::query_as::<_, NotebookEntryWithCreator>(
            r#"
            SELECT e.*, u.name as creator_name
            FROM notebook_entries e
            LEFT JOIN users u ON e.created_by = u.id
            WHERE e.notebook_id = $1
            ORDER BY e.created_at ASC, e.id ASC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(notebook_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Get entry count for a notebook
    pub async fn get_entry_count(&self, notebook_id: Uuid) -> Result<i64, NotebookRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>(
            r#"SELECT COUNT(*) FROM notebook_entries WHERE notebook_id = $1"#,
        )
        .bind(notebook_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Delete an entry
    pub async fn delete_entry(&self, entry_id: Uuid) -> Result<(), NotebookRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM notebook_entries WHERE id = $1"#)
            .bind(entry_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(NotebookRepositoryError::EntryNotFound(entry_id));
        }

        Ok(())
    }

    /// Delete an entry only if it belongs to the specified notebook.
    pub async fn delete_entry_in_notebook(
        &self,
        notebook_id: Uuid,
        entry_id: Uuid,
    ) -> Result<(), NotebookRepositoryError> {
        let result =
            sqlx::query(r#"DELETE FROM notebook_entries WHERE id = $1 AND notebook_id = $2"#)
                .bind(entry_id)
                .bind(notebook_id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(NotebookRepositoryError::EntryNotFound(entry_id));
        }

        Ok(())
    }

    /// Finalize intermediate streaming entries for a notebook.
    ///
    /// During the search analysis loop, intermediate AI responses are written
    /// with `"streaming": true` and a "Continuing analysis..." suffix.
    /// Once the final response is written, this removes the streaming flag
    /// and strips the continuation suffix so the entries remain visible
    /// as completed investigation steps.
    pub async fn finalize_streaming_entries(
        &self,
        notebook_id: Uuid,
    ) -> Result<i64, NotebookRepositoryError> {
        let result = sqlx::query(
            r#"UPDATE notebook_entries
               SET content = jsonb_set(
                   content - 'streaming',
                   '{text}',
                   to_jsonb(regexp_replace(content->>'text', E'\n\n---\n\\*Continuing analysis\\.\\.\\.\\*$', '', 'g'))
               )
               WHERE notebook_id = $1
                 AND entry_type = 'ai_chat_response'
                 AND (content->>'streaming')::boolean = true"#,
        )
        .bind(notebook_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }
}
