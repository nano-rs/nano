// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request/response types for lookup table API handlers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::{IntoParams, ToSchema};

use nanosiem_core::LookupTable;

/// Request body for creating a lookup table from file upload
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLookupTableConfig {
    /// Name for the lookup table
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Primary key column for efficient lookups
    pub primary_key: Option<String>,
    /// File format (csv, json, ndjson) - auto-detected if not provided
    pub format: Option<String>,
    /// CSV delimiter character
    pub csv_delimiter: Option<String>,
    /// Whether CSV has headers
    pub csv_has_headers: Option<bool>,
    /// Update mode: "replace" or "append" (default: replace)
    pub mode: Option<String>,
    /// Column type overrides
    pub column_types: Option<Vec<ColumnTypeOverrideRequest>>,
    /// Whether to flatten nested JSON objects
    #[serde(default)]
    pub flatten_json: bool,
}

/// Column type override in request
#[derive(Debug, Deserialize, ToSchema)]
pub struct ColumnTypeOverrideRequest {
    pub column: String,
    pub data_type: String,
}

/// Response for lookup table creation
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateLookupTableResponse {
    pub table: LookupTable,
    pub records_inserted: usize,
    /// Columns whose original CSV/JSON header was sanitized to a SQL-safe
    /// identifier on upload (e.g. `Customer Id → customer_id`). Empty if all
    /// original headers were already valid identifiers. See NAN-513.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub renamed_columns: Vec<RenamedColumn>,
}

/// Original → sanitized rename pair surfaced in the create response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RenamedColumn {
    pub original: String,
    pub sanitized: String,
}

/// Query parameters for sample endpoint
#[derive(Debug, Deserialize, IntoParams)]
pub struct SampleQueryParams {
    pub limit: Option<i64>,
}

/// Response for sample rows endpoint
#[derive(Debug, Serialize, ToSchema)]
pub struct SampleRowsResponse {
    pub rows: Vec<HashMap<String, serde_json::Value>>,
}

/// Response for delete operations
#[derive(Debug, Serialize, ToSchema)]
pub struct LookupDeleteResponse {
    pub success: bool,
}

/// Request body for lookup query
#[derive(Debug, Deserialize, ToSchema)]
pub struct LookupQueryRequest {
    /// Name of the lookup table
    pub table_name: String,
    /// Key field to match on
    pub key_field: String,
    /// Single key value to look up
    pub key_value: Option<serde_json::Value>,
    /// Multiple key values for batch lookup
    pub key_values: Option<Vec<serde_json::Value>>,
    /// Optional list of fields to return
    pub output_fields: Option<Vec<String>>,
    /// Whether to perform case-insensitive matching
    pub case_insensitive: Option<bool>,
}

/// Response for lookup query (can be single or batch)
#[derive(Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum LookupQueryResponse {
    Single(nanosiem_core::LookupResult),
    Batch(nanosiem_core::BatchLookupResult),
}

/// Column definition for schema-based creation
#[derive(Debug, Deserialize, ToSchema)]
pub struct SchemaColumnDef {
    /// Column name
    pub name: String,
    /// Data type: text, integer, float, boolean, timestamp, json
    pub data_type: String,
    /// Whether the column allows nulls (default: true)
    #[serde(default = "default_true")]
    pub nullable: bool,
}

pub(crate) fn default_true() -> bool {
    true
}

/// Request body for creating a lookup table from a schema definition
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLookupTableFromSchemaRequest {
    /// Name for the lookup table
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Column definitions
    pub columns: Vec<SchemaColumnDef>,
    /// Primary key column name
    pub primary_key: Option<String>,
}

/// Query parameters for paginated row listing
#[derive(Debug, Deserialize, IntoParams)]
pub struct RowListParams {
    /// Page number (1-based, default: 1)
    pub page: Option<i64>,
    /// Rows per page (1-100, default: 50)
    pub page_size: Option<i64>,
}

/// Request body for adding rows
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddRowsRequest {
    /// Rows to insert (each row is a map of column name to value)
    pub rows: Vec<HashMap<String, serde_json::Value>>,
}

/// Response for adding rows
#[derive(Debug, Serialize, ToSchema)]
pub struct AddRowsResponse {
    /// Number of rows inserted
    pub inserted: usize,
    /// Row IDs of inserted rows
    pub row_ids: Vec<i64>,
}

/// Request body for updating a row
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRowRequest {
    /// Updated field values
    pub fields: HashMap<String, serde_json::Value>,
}

/// Request body for bulk row deletion
#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteRowsRequest {
    /// Row IDs to delete
    pub row_ids: Vec<i64>,
}

/// Response for bulk row deletion
#[derive(Debug, Serialize, ToSchema)]
pub struct DeleteRowsResponse {
    /// Number of rows deleted
    pub deleted: u64,
}
