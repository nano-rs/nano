// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser repository for database operations
//!
//! NOTE: As of migration 051, this repository queries the `log_sources` table
//! instead of the deprecated `parsers` table. The `parsers` table was dropped
//! to eliminate data sync issues between the two tables.

use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use super::types::{
    DetectionPattern, NewDetectionPattern, NewParser, NewParserLibraryEntry, Parser,
    ParserDeployment, ParserLibraryEntry, UpdateParser,
};

#[derive(Error, Debug)]
pub enum ParserRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Parser not found: {0}")]
    NotFound(Uuid),
    #[error("Parser with name '{0}' already exists")]
    DuplicateName(String),
}

pub struct ParserRepository {
    pool: PgPool,
}

impl ParserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list(&self) -> Result<Vec<Parser>, ParserRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, name, description, source_type,
                source_config, parser_vrl, output_fields,
                credential_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                created_at, updated_at
            FROM log_sources
            ORDER BY name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_parser).collect())
    }

    pub async fn list_enabled(&self) -> Result<Vec<Parser>, ParserRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, name, description, source_type,
                source_config, parser_vrl, output_fields,
                credential_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                created_at, updated_at
            FROM log_sources
            WHERE enabled = true
            ORDER BY name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_parser).collect())
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                id, name, description, source_type,
                source_config, parser_vrl, output_fields,
                credential_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                created_at, updated_at
            FROM log_sources
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_parser(&row))
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                id, name, description, source_type,
                source_config, parser_vrl, output_fields,
                credential_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                created_at, updated_at
            FROM log_sources
            WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ParserRepositoryError::NotFound(Uuid::nil()))?;

        Ok(row_to_parser(&row))
    }

    pub async fn create(&self, parser: &NewParser) -> Result<Parser, ParserRepositoryError> {
        // Check for duplicate name
        let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM log_sources WHERE name = $1")
            .bind(&parser.name)
            .fetch_one(&self.pool)
            .await?;

        if existing > 0 {
            return Err(ParserRepositoryError::DuplicateName(parser.name.clone()));
        }

        let row = sqlx::query(
            r#"
            INSERT INTO log_sources (name, description, source_type, source_config, parser_vrl, output_fields, credential_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING
                id, name, description, source_type,
                source_config, parser_vrl, output_fields,
                credential_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                created_at, updated_at
            "#
        )
        .bind(&parser.name)
        .bind(&parser.description)
        .bind(&parser.source_type)
        .bind(&parser.source_config)
        .bind(&parser.parser_vrl)
        .bind(&parser.output_fields)
        .bind(parser.credential_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row_to_parser(&row))
    }

    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdateParser,
    ) -> Result<Parser, ParserRepositoryError> {
        // First check if parser exists
        self.find_by_id(id).await?;

        // Check for duplicate name if name is being changed
        if let Some(ref name) = update.name {
            let existing: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM log_sources WHERE name = $1 AND id != $2")
                    .bind(name)
                    .bind(id)
                    .fetch_one(&self.pool)
                    .await?;

            if existing > 0 {
                return Err(ParserRepositoryError::DuplicateName(name.clone()));
            }
        }

        let row = sqlx::query(
            r#"
            UPDATE log_sources SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                source_type = COALESCE($4, source_type),
                source_config = COALESCE($5, source_config),
                parser_vrl = COALESCE($6, parser_vrl),
                output_fields = COALESCE($7, output_fields),
                credential_id = COALESCE($8, credential_id),
                enabled = COALESCE($9, enabled),
                validated = false,
                validation_error = NULL
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                source_config, parser_vrl, output_fields,
                credential_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(&update.description)
        .bind(&update.source_type)
        .bind(&update.source_config)
        .bind(&update.parser_vrl)
        .bind(&update.output_fields)
        .bind(update.credential_id)
        .bind(update.enabled)
        .fetch_one(&self.pool)
        .await?;

        Ok(row_to_parser(&row))
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), ParserRepositoryError> {
        let result = sqlx::query("DELETE FROM log_sources WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(ParserRepositoryError::NotFound(id));
        }

        Ok(())
    }

    pub async fn set_validation_status(
        &self,
        id: Uuid,
        validated: bool,
        error: Option<&str>,
    ) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET
                validated = $2,
                validation_error = $3
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                source_config, parser_vrl, output_fields,
                credential_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(validated)
        .bind(error)
        .fetch_one(&self.pool)
        .await?;

        Ok(row_to_parser(&row))
    }

    pub async fn enable(&self, id: Uuid) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET enabled = true
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                source_config, parser_vrl, output_fields,
                credential_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_parser(&row))
    }

    pub async fn disable(&self, id: Uuid) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET enabled = false
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                source_config, parser_vrl, output_fields,
                credential_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_parser(&row))
    }

    /// Record a deployment action in the log_source_deployments table
    pub async fn record_deployment(
        &self,
        parser_id: Uuid,
        action: &str,
        status: &str,
        error_message: Option<&str>,
        config_snapshot: Option<&str>,
    ) -> Result<ParserDeployment, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            INSERT INTO log_source_deployments (log_source_id, action, status, error_message, config_snapshot)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, log_source_id, action, status, error_message, config_snapshot, deployed_at
            "#
        )
        .bind(parser_id)
        .bind(action)
        .bind(status)
        .bind(error_message)
        .bind(config_snapshot)
        .fetch_one(&self.pool)
        .await?;

        Ok(ParserDeployment {
            id: row.get("id"),
            parser_id: row.get("log_source_id"),
            action: row.get("action"),
            status: row.get("status"),
            error_message: row.get("error_message"),
            config_snapshot: row.get("config_snapshot"),
            deployed_at: row.get("deployed_at"),
        })
    }

    /// Get deployment history for a parser
    pub async fn get_deployment_history(
        &self,
        parser_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ParserDeployment>, ParserRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, log_source_id, action, status, error_message, config_snapshot, deployed_at
            FROM log_source_deployments
            WHERE log_source_id = $1
            ORDER BY deployed_at DESC
            LIMIT $2
            "#,
        )
        .bind(parser_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| ParserDeployment {
                id: row.get("id"),
                parser_id: row.get("log_source_id"),
                action: row.get("action"),
                status: row.get("status"),
                error_message: row.get("error_message"),
                config_snapshot: row.get("config_snapshot"),
                deployed_at: row.get("deployed_at"),
            })
            .collect())
    }

    /// Mark a parser as deployed (enabled and validated)
    pub async fn mark_deployed(&self, id: Uuid) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET
                enabled = true,
                validated = true,
                validation_error = NULL,
                deployed = true,
                deployed_at = NOW()
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                source_config, parser_vrl, output_fields,
                credential_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_parser(&row))
    }

    /// Mark a parser deployment as failed
    pub async fn mark_deployment_failed(
        &self,
        id: Uuid,
        error: &str,
    ) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET
                enabled = false,
                validated = false,
                validation_error = $2,
                deployed = false
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                source_config, parser_vrl, output_fields,
                credential_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(error)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_parser(&row))
    }
}

/// Convert a database row to a Parser struct
fn row_to_parser(row: &sqlx::postgres::PgRow) -> Parser {
    Parser {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        source_type: row.get("source_type"),
        source_config: row.get("source_config"),
        parser_vrl: row.get("parser_vrl"),
        output_fields: row.get("output_fields"),
        feed_id: None, // log_sources doesn't have feed_id
        credential_id: row.get("credential_id"),
        namespace: row
            .try_get("namespace")
            .unwrap_or_else(|_| "default".to_string()),
        enabled: row.get("enabled"),
        validated: row.get("validated"),
        validation_error: row.get("validation_error"),
        timezone: row
            .try_get("timezone")
            .unwrap_or_else(|_| "UTC".to_string()),
        match_values: row.try_get("match_values").ok(),
        sampling_ratio: row.try_get("sampling_ratio").unwrap_or(None),
        sampling_exclude_condition: row.try_get("sampling_exclude_condition").unwrap_or(None),
        extension_vrl: row.try_get("extension_vrl").unwrap_or(None),
        extension_enabled: row.try_get("extension_enabled").unwrap_or(false),
        category: row.get("category"),
        vendor: row.get("vendor"),
        product: row.get("product"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

/// Parser Library Repository for pre-built parsers
pub struct ParserLibraryRepository {
    pool: PgPool,
}

impl ParserLibraryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get all library parsers, optionally filtered by category
    pub async fn get_library_parsers(
        &self,
        category: Option<&str>,
    ) -> Result<Vec<ParserLibraryEntry>, ParserRepositoryError> {
        let rows = if let Some(cat) = category {
            sqlx::query(
                r#"
                SELECT 
                    id, name, display_name, description, category,
                    vendor, source_type, parser_vrl, sample_logs,
                    field_mappings, version, is_system, created_at, updated_at
                FROM parser_library
                WHERE category = $1
                ORDER BY display_name
                "#,
            )
            .bind(cat)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT 
                    id, name, display_name, description, category,
                    vendor, source_type, parser_vrl, sample_logs,
                    field_mappings, version, is_system, created_at, updated_at
                FROM parser_library
                ORDER BY category, display_name
                "#,
            )
            .fetch_all(&self.pool)
            .await?
        };

        Ok(rows.iter().map(row_to_parser_library_entry).collect())
    }

    /// Get a library parser by ID
    pub async fn get_library_parser_by_id(
        &self,
        id: Uuid,
    ) -> Result<ParserLibraryEntry, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT 
                id, name, display_name, description, category,
                vendor, source_type, parser_vrl, sample_logs,
                field_mappings, version, is_system, created_at, updated_at
            FROM parser_library
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_parser_library_entry(&row))
    }

    /// Get a library parser by source type
    pub async fn get_library_parser_by_source_type(
        &self,
        source_type: &str,
    ) -> Result<Option<ParserLibraryEntry>, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT 
                id, name, display_name, description, category,
                vendor, source_type, parser_vrl, sample_logs,
                field_mappings, version, is_system, created_at, updated_at
            FROM parser_library
            WHERE source_type = $1
            "#,
        )
        .bind(source_type)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| row_to_parser_library_entry(&r)))
    }

    /// Create a new library parser entry
    pub async fn create_library_parser(
        &self,
        entry: &NewParserLibraryEntry,
    ) -> Result<ParserLibraryEntry, ParserRepositoryError> {
        // Check for duplicate name
        let existing: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM parser_library WHERE name = $1")
                .bind(&entry.name)
                .fetch_one(&self.pool)
                .await?;

        if existing > 0 {
            return Err(ParserRepositoryError::DuplicateName(entry.name.clone()));
        }

        let row = sqlx::query(
            r#"
            INSERT INTO parser_library (
                name, display_name, description, category, vendor,
                source_type, parser_vrl, sample_logs, field_mappings,
                version, is_system
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING 
                id, name, display_name, description, category,
                vendor, source_type, parser_vrl, sample_logs,
                field_mappings, version, is_system, created_at, updated_at
            "#,
        )
        .bind(&entry.name)
        .bind(&entry.display_name)
        .bind(&entry.description)
        .bind(&entry.category)
        .bind(&entry.vendor)
        .bind(&entry.source_type)
        .bind(&entry.parser_vrl)
        .bind(&entry.sample_logs.clone().unwrap_or(serde_json::json!([])))
        .bind(
            &entry
                .field_mappings
                .clone()
                .unwrap_or(serde_json::json!({})),
        )
        .bind(&entry.version.clone().unwrap_or_else(|| "1.0.0".to_string()))
        .bind(entry.is_system.unwrap_or(true))
        .fetch_one(&self.pool)
        .await?;

        Ok(row_to_parser_library_entry(&row))
    }

    /// Get all system (built-in) parsers
    pub async fn get_system_parsers(
        &self,
    ) -> Result<Vec<ParserLibraryEntry>, ParserRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT 
                id, name, display_name, description, category,
                vendor, source_type, parser_vrl, sample_logs,
                field_mappings, version, is_system, created_at, updated_at
            FROM parser_library
            WHERE is_system = true
            ORDER BY category, display_name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_parser_library_entry).collect())
    }
}

/// Detection Patterns Repository for auto-detection
pub struct DetectionPatternRepository {
    pool: PgPool,
}

impl DetectionPatternRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get all enabled detection patterns ordered by priority
    pub async fn get_detection_patterns(
        &self,
    ) -> Result<Vec<DetectionPattern>, ParserRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, source_type, patterns, priority, enabled, created_at
            FROM detection_patterns
            WHERE enabled = true
            ORDER BY priority DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_detection_pattern).collect())
    }

    /// Get all detection patterns (including disabled)
    pub async fn get_all_detection_patterns(
        &self,
    ) -> Result<Vec<DetectionPattern>, ParserRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, source_type, patterns, priority, enabled, created_at
            FROM detection_patterns
            ORDER BY priority DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_detection_pattern).collect())
    }

    /// Get detection patterns for a specific source type
    pub async fn get_patterns_for_source_type(
        &self,
        source_type: &str,
    ) -> Result<Vec<DetectionPattern>, ParserRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, source_type, patterns, priority, enabled, created_at
            FROM detection_patterns
            WHERE source_type = $1 AND enabled = true
            ORDER BY priority DESC
            "#,
        )
        .bind(source_type)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_detection_pattern).collect())
    }

    /// Create a new detection pattern
    pub async fn create_detection_pattern(
        &self,
        pattern: &NewDetectionPattern,
    ) -> Result<DetectionPattern, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            INSERT INTO detection_patterns (source_type, patterns, priority, enabled)
            VALUES ($1, $2, $3, $4)
            RETURNING id, source_type, patterns, priority, enabled, created_at
            "#,
        )
        .bind(&pattern.source_type)
        .bind(&pattern.patterns)
        .bind(pattern.priority.unwrap_or(0))
        .bind(pattern.enabled.unwrap_or(true))
        .fetch_one(&self.pool)
        .await?;

        Ok(row_to_detection_pattern(&row))
    }

    /// Enable or disable a detection pattern
    pub async fn set_pattern_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<DetectionPattern, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE detection_patterns
            SET enabled = $2
            WHERE id = $1
            RETURNING id, source_type, patterns, priority, enabled, created_at
            "#,
        )
        .bind(id)
        .bind(enabled)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_detection_pattern(&row))
    }

    /// Delete a detection pattern
    pub async fn delete_detection_pattern(&self, id: Uuid) -> Result<(), ParserRepositoryError> {
        let result = sqlx::query("DELETE FROM detection_patterns WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(ParserRepositoryError::NotFound(id));
        }

        Ok(())
    }
}

/// Convert a database row to a ParserLibraryEntry struct
fn row_to_parser_library_entry(row: &sqlx::postgres::PgRow) -> ParserLibraryEntry {
    ParserLibraryEntry {
        id: row.get("id"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        description: row.get("description"),
        category: row.get("category"),
        vendor: row.get("vendor"),
        source_type: row.get("source_type"),
        parser_vrl: row.get("parser_vrl"),
        sample_logs: row.get("sample_logs"),
        field_mappings: row.get("field_mappings"),
        version: row.get("version"),
        is_system: row.get("is_system"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

/// Convert a database row to a DetectionPattern struct
fn row_to_detection_pattern(row: &sqlx::postgres::PgRow) -> DetectionPattern {
    DetectionPattern {
        id: row.get("id"),
        source_type: row.get("source_type"),
        patterns: row.get("patterns"),
        priority: row.get("priority"),
        enabled: row.get("enabled"),
        created_at: row.get("created_at"),
    }
}
