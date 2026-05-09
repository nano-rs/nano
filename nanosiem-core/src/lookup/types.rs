// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup types and data structures
//!
//! Defines types for lookup table operations including table metadata,
//! column definitions, and query structures.
//!
//! Requirements: 2.1, 2.2, 2.3, 3.1, 3.2, 3.3, 3.4, 3.5

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::typeid;

use crate::upload::ColumnType;

/// Summary of the user who created a lookup table.
///
/// Hydrated via LEFT JOIN on `users` from the registry's `created_by_user_id`
/// column. Optional because legacy rows (created before NAN-514) and rows
/// whose creator account was deleted both surface as `None`, which the UI
/// renders as `—`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LookupTableCreator {
    /// Creator's user ID
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub id: Uuid,
    /// Display name
    pub name: String,
    /// Email address
    pub email: String,
}

/// Lookup table metadata stored in the registry
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LookupTable {
    /// Unique table ID
    #[serde(with = "typeid::lookup")]
    #[schema(value_type = String)]
    pub id: Uuid,
    /// User-friendly table name
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Actual PostgreSQL table name (prefixed with lookup_)
    pub table_name: String,
    /// Column definitions
    pub columns: Vec<LookupColumn>,
    /// Primary key column name for efficient lookups
    pub primary_key: Option<String>,
    /// Number of rows in the table
    pub row_count: i64,
    /// Estimated size in bytes
    pub size_bytes: i64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// User who created the table (None for legacy rows or deleted creators)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<LookupTableCreator>,
}

/// Database row representation for lookup table registry.
///
/// `created_by_*` columns are hydrated via LEFT JOIN on `users` and are all
/// `None` when no creator is recorded (NULL FK or deleted user).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LookupTableRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub table_name: String,
    pub columns: sqlx::types::Json<Vec<LookupColumn>>,
    pub primary_key: Option<String>,
    pub row_count: i64,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by_user_id: Option<Uuid>,
    pub created_by_name: Option<String>,
    pub created_by_email: Option<String>,
}

impl From<LookupTableRow> for LookupTable {
    fn from(row: LookupTableRow) -> Self {
        // Only build a creator summary when we have a user ID — the JOIN
        // produces NULLs for both name/email when the FK is unset or the
        // user has been deleted. Name/email may be NULL individually if the
        // users table allows it; fall back to empty strings rather than
        // dropping the creator entirely so the UI can still show the avatar.
        let created_by = row.created_by_user_id.map(|id| LookupTableCreator {
            id,
            name: row.created_by_name.unwrap_or_default(),
            email: row.created_by_email.unwrap_or_default(),
        });

        Self {
            id: row.id,
            name: row.name,
            description: row.description,
            table_name: row.table_name,
            columns: row.columns.0,
            primary_key: row.primary_key,
            row_count: row.row_count,
            size_bytes: row.size_bytes,
            created_at: row.created_at,
            updated_at: row.updated_at,
            created_by,
        }
    }
}

/// Column definition for lookup tables
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LookupColumn {
    /// Column name
    pub name: String,
    /// Data type
    pub data_type: ColumnType,
    /// Whether the column allows null values
    pub nullable: bool,
}

impl LookupColumn {
    /// Create a new column definition
    pub fn new(name: impl Into<String>, data_type: ColumnType, nullable: bool) -> Self {
        Self {
            name: name.into(),
            data_type,
            nullable,
        }
    }

    /// Create a text column
    pub fn text(name: impl Into<String>, nullable: bool) -> Self {
        Self::new(name, ColumnType::Text, nullable)
    }

    /// Create an integer column
    pub fn integer(name: impl Into<String>, nullable: bool) -> Self {
        Self::new(name, ColumnType::Integer, nullable)
    }

    /// Create a boolean column
    pub fn boolean(name: impl Into<String>, nullable: bool) -> Self {
        Self::new(name, ColumnType::Boolean, nullable)
    }

    /// Create a timestamp column
    pub fn timestamp(name: impl Into<String>, nullable: bool) -> Self {
        Self::new(name, ColumnType::Timestamp, nullable)
    }
}

/// Request to create a new lookup table
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewLookupTable {
    /// User-friendly table name
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Column definitions
    pub columns: Vec<LookupColumn>,
    /// Primary key column name
    pub primary_key: Option<String>,
}

impl NewLookupTable {
    /// Generate the actual PostgreSQL table name
    pub fn generate_table_name(&self) -> String {
        // Sanitize the name and prefix with lookup_
        let sanitized = self
            .name
            .to_lowercase()
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>();
        format!("lookup_{}", sanitized)
    }
}

/// Lookup query for retrieving data from lookup tables
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LookupQuery {
    /// Name of the lookup table
    pub table_name: String,
    /// Key field to match on
    pub key_field: String,
    /// Key value to look up
    pub key_value: serde_json::Value,
    /// Optional list of fields to return (None = all fields)
    pub output_fields: Option<Vec<String>>,
    /// Whether to perform case-insensitive matching
    #[serde(default)]
    pub case_insensitive: bool,
}

/// Batch lookup query for multiple keys
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BatchLookupQuery {
    /// Name of the lookup table
    pub table_name: String,
    /// Key field to match on
    pub key_field: String,
    /// Key values to look up
    pub key_values: Vec<serde_json::Value>,
    /// Optional list of fields to return (None = all fields)
    pub output_fields: Option<Vec<String>>,
    /// Whether to perform case-insensitive matching
    #[serde(default)]
    pub case_insensitive: bool,
}

/// Result of a lookup query
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LookupResult {
    /// The matched record fields (None if no match)
    pub fields: Option<HashMap<String, serde_json::Value>>,
    /// Whether a match was found
    pub found: bool,
}

impl LookupResult {
    /// Create a result with matched fields
    pub fn found(fields: HashMap<String, serde_json::Value>) -> Self {
        Self {
            fields: Some(fields),
            found: true,
        }
    }

    /// Create a result with no match
    pub fn not_found() -> Self {
        Self {
            fields: None,
            found: false,
        }
    }
}

/// Result of a batch lookup query
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BatchLookupResult {
    /// Map of key value (as string) to matched fields
    pub results: HashMap<String, HashMap<String, serde_json::Value>>,
    /// Number of keys that had matches
    pub matched_count: usize,
    /// Total number of keys queried
    pub total_count: usize,
}

/// Column type override for table creation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ColumnTypeOverride {
    /// Column name
    pub column: String,
    /// Override type
    pub data_type: ColumnType,
}

/// Paginated rows result
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LookupRowsPage {
    /// Row data (includes hidden _row_id for targeting)
    pub rows: Vec<HashMap<String, serde_json::Value>>,
    /// Total number of rows in the table
    pub total: i64,
    /// Current page number (1-based)
    pub page: i64,
    /// Rows per page
    pub page_size: i64,
    /// Total number of pages
    pub total_pages: i64,
}

/// A detection rule that references a lookup table.
///
/// Returned by `GET /api/lookup-tables/{name}/usage` to power the Usage section
/// of the LookupTableView Details inspector.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LookupUsage {
    /// Detection rule ID (typeid-encoded)
    #[serde(with = "crate::typeid::rule")]
    #[schema(value_type = String)]
    pub rule_id: Uuid,
    /// Detection rule display name
    pub rule_name: String,
    /// First MITRE tactic on the rule, if any (e.g. "initial-access")
    pub tactic: Option<String>,
    /// Number of signal hits in the last 24 hours.
    ///
    /// TODO(NAN-511): currently stubbed to 0 — wiring up per-rule signal counts
    /// from the ClickHouse signals table is deferred to a follow-up.
    pub hits_24h: i64,
    /// Timestamp of the most recent signal, if any.
    ///
    /// TODO(NAN-511): currently stubbed to None — see `hits_24h`.
    pub last_hit: Option<DateTime<Utc>>,
    /// Substring of the rule's nPL query containing the lookup reference.
    /// Best-effort — returns the matching line, or the whole query truncated
    /// to ~200 chars if a clean line cannot be extracted.
    pub sample_join: String,
}

/// Kind of activity recorded for a lookup table.
///
/// Powers the History tab on the redesigned LookupTableView (NAN-510 slice 3 PR 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LookupHistoryKind {
    /// Automated refresh / scheduled ingestion run
    Refresh,
    /// Manual edit (column type change, table metadata update, row edits)
    Edit,
    /// Upload (initial upload or re-upload of rows)
    Upload,
}

/// A single activity entry on a lookup table.
///
/// Returned by `GET /api/lookup-tables/{name}/ingestion-history`. Each entry
/// represents either an automated refresh run or a user-driven edit/upload.
/// The `note` field is server-rendered so the UI can render it verbatim.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LookupHistoryEntry {
    /// When the activity happened (UTC).
    pub when: DateTime<Utc>,
    /// Who performed the action.
    ///
    /// For `refresh` entries this is `"scheduler"`. For `edit` and `upload`
    /// entries this is the audit event's `actor_name` (typically the user's
    /// display name or email), or `"system"` if the audit row has no actor.
    pub actor: String,
    /// Kind of activity (`refresh` | `edit` | `upload`).
    pub kind: LookupHistoryKind,
    /// Short, server-rendered description.
    ///
    /// For `refresh` entries: `"completed"` / `"failed: <error>"`. Row deltas
    /// (`"+N rows · −M rows · K total"`) are deferred — see
    /// `TODO(NAN-512)` in the handler — because the current `scheduled_jobs`
    /// schema does not persist per-run row counts.
    ///
    /// For `edit` / `upload` entries: derived from the audit event action
    /// (e.g. `"table created"`, `"rows added"`).
    pub note: String,
}

/// Maximum number of rows allowed in a lookup table
pub const MAX_LOOKUP_TABLE_ROWS: i64 = 1_000_000;

/// Prefix for dynamically created lookup tables
pub const LOOKUP_TABLE_PREFIX: &str = "lookup_";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_column_creation() {
        let col = LookupColumn::text("name", false);
        assert_eq!(col.name, "name");
        assert_eq!(col.data_type, ColumnType::Text);
        assert!(!col.nullable);

        let col = LookupColumn::integer("count", true);
        assert_eq!(col.data_type, ColumnType::Integer);
        assert!(col.nullable);
    }

    #[test]
    fn test_new_lookup_table_name_generation() {
        let table = NewLookupTable {
            name: "My Assets".to_string(),
            description: None,
            columns: vec![],
            primary_key: None,
        };
        assert_eq!(table.generate_table_name(), "lookup_my_assets");

        let table = NewLookupTable {
            name: "threat-indicators-2024".to_string(),
            description: None,
            columns: vec![],
            primary_key: None,
        };
        assert_eq!(table.generate_table_name(), "lookup_threat_indicators_2024");
    }

    #[test]
    fn test_lookup_result() {
        let result = LookupResult::not_found();
        assert!(!result.found);
        assert!(result.fields.is_none());

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), serde_json::json!("test"));
        let result = LookupResult::found(fields);
        assert!(result.found);
        assert!(result.fields.is_some());
    }
}
