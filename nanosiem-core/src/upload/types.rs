// SPDX-License-Identifier: AGPL-3.0-or-later

//! Upload types and data structures
//!
//! Defines types for file upload operations including destinations,
//! requests, results, and history records.
//!
//! Requirements: 5.1

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::parser::{FileFormat, ParserConfig, RecordError};

/// Upload destination type
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type")]
pub enum UploadDestination {
    /// Upload data for a lookup table
    #[serde(rename = "lookup")]
    LookupTable {
        /// Name of the lookup table
        table_name: String,
        /// Primary key column for efficient lookups
        #[serde(skip_serializing_if = "Option::is_none")]
        primary_key: Option<String>,
        /// Update mode (replace or append)
        mode: LookupMode,
    },
}

impl UploadDestination {
    /// Get the destination type as a string
    pub fn destination_type(&self) -> &'static str {
        match self {
            Self::LookupTable { .. } => "lookup",
        }
    }

    /// Get the destination name (table_name)
    pub fn destination_name(&self) -> &str {
        match self {
            Self::LookupTable { table_name, .. } => table_name,
        }
    }
}

/// Lookup table update mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LookupMode {
    /// Replace all existing data with new data
    #[default]
    Replace,
    /// Append new data to existing data
    Append,
}

impl LookupMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Replace => "replace",
            Self::Append => "append",
        }
    }
}

/// Upload request
#[derive(Debug, Clone)]
pub struct UploadRequest {
    /// Original filename
    pub filename: String,
    /// File content as bytes
    pub content: Vec<u8>,
    /// Upload destination
    pub destination: UploadDestination,
    /// Parser configuration
    pub config: ParserConfig,
}

/// Upload result
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UploadResult {
    /// Upload ID for tracking
    pub upload_id: Uuid,
    /// Total records processed from file
    pub records_processed: usize,
    /// Records successfully ingested
    pub records_ingested: usize,
    /// Errors encountered during processing
    pub errors: Vec<String>,
    /// Processing duration in milliseconds
    pub duration_ms: u64,
}

/// Upload status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UploadStatus {
    /// Upload is being processed
    Processing,
    /// Upload completed successfully
    Completed,
    /// Upload failed
    Failed,
}

impl UploadStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Processing => "processing",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "processing" => Some(Self::Processing),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

impl std::fmt::Display for UploadStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Upload history record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct UploadRecord {
    /// Unique upload ID
    pub id: Uuid,
    /// Original filename
    pub filename: String,
    /// File size in bytes
    pub file_size: i64,
    /// File format (csv, json, ndjson)
    pub file_format: String,
    /// Destination type (logs or lookup)
    pub destination_type: String,
    /// Destination name (source_type or table_name)
    pub destination_name: String,
    /// Total records in file
    pub records_total: i64,
    /// Successfully processed records
    pub records_success: i64,
    /// Failed records
    pub records_failed: i64,
    /// Upload status
    pub status: String,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Upload creation timestamp
    pub created_at: DateTime<Utc>,
    /// Upload completion timestamp
    pub completed_at: Option<DateTime<Utc>>,
}

impl UploadRecord {
    /// Get the upload status as an enum
    pub fn status_enum(&self) -> Option<UploadStatus> {
        UploadStatus::from_str(&self.status)
    }

    /// Get the file format as an enum
    pub fn format_enum(&self) -> Option<FileFormat> {
        FileFormat::from_str(&self.file_format)
    }

    /// Check if the upload was successful
    pub fn is_success(&self) -> bool {
        self.status == "completed" && self.error_message.is_none()
    }

    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.records_total == 0 {
            100.0
        } else {
            (self.records_success as f64 / self.records_total as f64) * 100.0
        }
    }
}

/// Filter for upload history queries
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UploadFilter {
    /// Filter by destination type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_type: Option<String>,
    /// Filter by destination name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_name: Option<String>,
    /// Filter by status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Filter by start date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_date: Option<DateTime<Utc>>,
    /// Filter by end date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<DateTime<Utc>>,
    /// Maximum number of results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// Offset for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
}

/// Preview result for file upload
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PreviewResult {
    /// Detected file format
    pub format: FileFormat,
    /// Column information
    pub columns: Vec<ColumnInfo>,
    /// Preview rows (first N records)
    pub rows: Vec<serde_json::Map<String, serde_json::Value>>,
    /// Estimated total rows in file
    pub total_rows_estimate: usize,
    /// Number of source lines that failed to parse and were skipped. When
    /// non-zero the preview is partial — surfacing this prevents the
    /// "looks clean" trap during parser/upload review (NAN-1364).
    #[serde(default)]
    pub rejected_count: usize,
    /// Per-line parse errors for rejected lines, capped at
    /// `MAX_PREVIEW_ERRORS` so a fully-malformed file can't amplify the
    /// response. Empty (and omitted) when nothing was rejected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<RecordError>,
}

/// Column information for preview
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ColumnInfo {
    /// Column name
    pub name: String,
    /// Detected column type
    pub detected_type: ColumnType,
    /// Sample values from the column
    pub sample_values: Vec<String>,
    /// Count of null values in sample
    pub null_count: usize,
}

/// Column data types for lookup tables
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ColumnType {
    Text,
    Integer,
    Float,
    Boolean,
    Timestamp,
    Json,
}

impl ColumnType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Integer => "integer",
            Self::Float => "float",
            Self::Boolean => "boolean",
            Self::Timestamp => "timestamp",
            Self::Json => "json",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "text" | "string" | "varchar" => Some(Self::Text),
            "integer" | "int" | "bigint" => Some(Self::Integer),
            "float" | "double" | "decimal" | "numeric" => Some(Self::Float),
            "boolean" | "bool" => Some(Self::Boolean),
            "timestamp" | "datetime" | "timestamptz" => Some(Self::Timestamp),
            "json" | "jsonb" => Some(Self::Json),
            _ => None,
        }
    }

    /// Get the PostgreSQL type for this column type
    pub fn to_postgres_type(&self) -> &'static str {
        match self {
            Self::Text => "TEXT",
            Self::Integer => "BIGINT",
            Self::Float => "DOUBLE PRECISION",
            Self::Boolean => "BOOLEAN",
            Self::Timestamp => "TIMESTAMPTZ",
            Self::Json => "JSONB",
        }
    }
}

impl Default for ColumnType {
    fn default() -> Self {
        Self::Text
    }
}

impl std::fmt::Display for ColumnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
