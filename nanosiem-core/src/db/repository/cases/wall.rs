// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case wall operations: add entries, get entries, internal helper

use uuid::Uuid;

use super::{
    CaseRepository, CaseRepositoryError, CaseWallEntry, CaseWallEntryWithCreator, NewCaseWallEntry,
};
use crate::models::case::CaseWallEntryType;

/// Convert a `CaseWallEntryType` variant into the `snake_case` text value the
/// `case_wall.entry_type` CHECK constraint expects. Must stay in sync with the
/// enum definition + migration 019_cases.sql.
fn wall_entry_type_to_str(kind: &CaseWallEntryType) -> &'static str {
    match kind {
        CaseWallEntryType::Comment => "comment",
        CaseWallEntryType::StatusChange => "status_change",
        CaseWallEntryType::AssignmentChange => "assignment_change",
        CaseWallEntryType::AlertAdded => "alert_added",
        CaseWallEntryType::AlertRemoved => "alert_removed",
        CaseWallEntryType::EntityAdded => "entity_added",
        CaseWallEntryType::EnrichmentResult => "enrichment_result",
        CaseWallEntryType::AiAnalysis => "ai_analysis",
        CaseWallEntryType::ActionTaken => "action_taken",
        CaseWallEntryType::Attachment => "attachment",
        CaseWallEntryType::System => "system",
    }
}

impl CaseRepository {
    // ==================== CASE WALL ====================

    /// Add a wall entry
    pub async fn add_wall_entry(
        &self,
        entry: &NewCaseWallEntry,
    ) -> Result<CaseWallEntry, CaseRepositoryError> {
        // Use the snake_case text representation matching the CHECK constraint
        // on case_wall.entry_type. Previously used `format!("{:?}", ...).to_lowercase()`
        // which collapsed multi-word variants (e.g. ActionTaken → "actiontaken")
        // and silently tripped the check constraint.
        let entry_type_str = wall_entry_type_to_str(&entry.entry_type);

        let result = sqlx::query_as::<_, CaseWallEntry>(
            r#"
            INSERT INTO case_wall (case_id, entry_type, content, metadata, is_internal, created_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(entry.case_id)
        .bind(&entry_type_str)
        .bind(&entry.content)
        .bind(&entry.metadata)
        .bind(entry.is_internal)
        .bind(entry.created_by)
        .fetch_one(&self.pool)
        .await?;

        // Update case timestamps
        sqlx::query(
            r#"UPDATE cases SET updated_at = NOW(), last_activity_at = NOW() WHERE id = $1"#,
        )
        .bind(entry.case_id)
        .execute(&self.pool)
        .await?;

        Ok(result)
    }

    /// Internal helper to add wall entry
    pub(super) async fn add_wall_entry_internal(
        &self,
        case_id: Uuid,
        entry_type: &str,
        content: Option<String>,
        metadata: serde_json::Value,
        created_by: Option<Uuid>,
    ) -> Result<CaseWallEntry, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseWallEntry>(
            r#"
            INSERT INTO case_wall (case_id, entry_type, content, metadata, created_by)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(case_id)
        .bind(entry_type)
        .bind(&content)
        .bind(&metadata)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Get wall entries for a case
    pub async fn get_wall_entries(
        &self,
        case_id: Uuid,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<CaseWallEntryWithCreator>, CaseRepositoryError> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let results = sqlx::query_as::<_, CaseWallEntryWithCreator>(
            r#"
            SELECT w.*, u.name as creator_name
            FROM case_wall w
            LEFT JOIN users u ON w.created_by = u.id
            WHERE w.case_id = $1
            ORDER BY w.created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(case_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Get a single wall entry with creator name
    pub async fn get_wall_entry_with_creator(
        &self,
        entry_id: Uuid,
    ) -> Result<CaseWallEntryWithCreator, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseWallEntryWithCreator>(
            r#"
            SELECT w.*, u.name as creator_name
            FROM case_wall w
            LEFT JOIN users u ON w.created_by = u.id
            WHERE w.id = $1
            "#,
        )
        .bind(entry_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::WallEntryNotFound(entry_id))?;

        Ok(result)
    }
}
