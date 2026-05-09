// SPDX-License-Identifier: AGPL-3.0-or-later

//! Upload Service
//!
//! Orchestrates file uploads for lookup table creation.
//! Processes uploaded CSV/JSON files and creates lookup tables.
//!
//! Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 7.4

use sqlx::PgPool;
use std::collections::HashMap;
use std::time::Instant;
use thiserror::Error;
use tracing::instrument;
use uuid::Uuid;

use super::parser::{FileParser, ParseError, ParseResult, ParserConfig};
use super::repository::{UploadRepository, UploadRepositoryError};
use super::types::*;

use crate::lookup::{LookupRepository, LookupService, NewLookupTable};

/// Maximum file size allowed for upload (100MB)
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;

/// Default number of preview rows
pub const DEFAULT_PREVIEW_ROWS: usize = 10;

/// Maximum byte length of a single cell value in preview output. Values
/// longer than this are replaced with a truncated string so a pathological
/// row cannot inflate the preview response (NAN-660).
pub const MAX_PREVIEW_CELL_BYTES: usize = 1024;

const PREVIEW_TRUNCATION_SUFFIX: &str = "…[truncated]";

#[derive(Error, Debug)]
pub enum UploadError {
    #[error("File too large: {size} bytes exceeds maximum of {max} bytes")]
    FileTooLarge { size: usize, max: usize },

    #[error("Parse error: {0}")]
    ParseError(#[from] ParseError),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Repository error: {0}")]
    RepositoryError(#[from] UploadRepositoryError),

    #[error("Empty file")]
    EmptyFile,

    #[error("No valid records found")]
    NoValidRecords,

    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    #[error("Ingestion error: {0}")]
    IngestionError(String),
}

/// Upload service for handling file uploads
#[derive(Clone)]
pub struct UploadService {
    pool: PgPool,
    parser: FileParser,
    repository: UploadRepository,
}

impl UploadService {
    /// Create a new upload service
    pub fn new(pool: PgPool) -> Self {
        Self {
            repository: UploadRepository::new(pool.clone()),
            parser: FileParser::new(),
            pool,
        }
    }

    /// Upload a file for log ingestion or lookup table creation
    #[instrument(skip(self, request), fields(filename = %request.filename))]
    pub async fn upload(&self, request: UploadRequest) -> Result<UploadResult, UploadError> {
        let start = Instant::now();

        // Validate file size
        if request.content.len() > MAX_FILE_SIZE {
            return Err(UploadError::FileTooLarge {
                size: request.content.len(),
                max: MAX_FILE_SIZE,
            });
        }

        // Validate file is not empty
        if request.content.is_empty() {
            return Err(UploadError::EmptyFile);
        }

        // Create upload record
        let upload_record = self
            .repository
            .create_upload(
                &request.filename,
                request.content.len() as i64,
                request.config.format,
                &request.destination,
            )
            .await?;

        // Parse the file
        let parse_result = match self.parser.parse(&request.content, &request.config) {
            Ok(result) => result,
            Err(e) => {
                // Mark upload as failed
                self.repository
                    .fail_upload(upload_record.id, &e.to_string())
                    .await?;
                return Err(e.into());
            }
        };

        // Process lookup table upload
        let UploadDestination::LookupTable {
            table_name,
            primary_key,
            mode,
        } = &request.destination;

        let records: Vec<HashMap<String, serde_json::Value>> =
            parse_result.records.into_iter().map(|r| r.fields).collect();

        if records.is_empty() {
            self.repository
                .fail_upload(upload_record.id, "No valid records found")
                .await?;
            return Err(UploadError::NoValidRecords);
        }

        // Detect column types from parsed data
        let columns = LookupService::detect_column_types(&records, None);

        let lookup_repo = LookupRepository::new(self.pool.clone());
        let lookup_service = LookupService::new(lookup_repo);

        let table_exists = lookup_service
            .table_exists(table_name)
            .await
            .map_err(|e| UploadError::IngestionError(e.to_string()))?;

        let lookup_repo_inner = LookupRepository::new(self.pool.clone());

        let records_ingested = match mode {
            super::types::LookupMode::Replace => {
                if table_exists {
                    // Get current table info to find the dynamic table name
                    let existing = lookup_repo_inner
                        .get_table(table_name)
                        .await
                        .map_err(|e| UploadError::IngestionError(e.to_string()))?;

                    // Drop the dynamic PG table (NOT the registry — avoids FK cascade)
                    lookup_repo_inner
                        .drop_dynamic_table(&existing.table_name)
                        .await
                        .map_err(|e| UploadError::IngestionError(e.to_string()))?;

                    // Recreate the dynamic table with new schema
                    lookup_repo_inner
                        .create_dynamic_table(
                            &existing.table_name,
                            &columns,
                            primary_key.as_deref(),
                        )
                        .await
                        .map_err(|e| UploadError::IngestionError(e.to_string()))?;

                    // Update registry columns to match new schema
                    lookup_repo_inner
                        .update_table_columns(table_name, &columns, primary_key.as_deref())
                        .await
                        .map_err(|e| UploadError::IngestionError(e.to_string()))?;
                } else {
                    let new_table = NewLookupTable {
                        name: table_name.clone(),
                        description: None,
                        columns,
                        primary_key: primary_key.clone(),
                    };
                    // Upload service runs in system context (scheduled
                    // ingestion jobs etc.) — no user identity available, so
                    // tables auto-created on ingest have no recorded owner.
                    lookup_service
                        .create_table(new_table, None)
                        .await
                        .map_err(|e| UploadError::IngestionError(e.to_string()))?;
                }

                lookup_service
                    .insert_records(table_name, records)
                    .await
                    .map_err(|e| UploadError::IngestionError(e.to_string()))?
            }
            super::types::LookupMode::Append => {
                if !table_exists {
                    let new_table = NewLookupTable {
                        name: table_name.clone(),
                        description: None,
                        columns,
                        primary_key: primary_key.clone(),
                    };
                    // Upload service runs in system context (scheduled
                    // ingestion jobs etc.) — no user identity available, so
                    // tables auto-created on ingest have no recorded owner.
                    lookup_service
                        .create_table(new_table, None)
                        .await
                        .map_err(|e| UploadError::IngestionError(e.to_string()))?;
                }

                lookup_service
                    .insert_records(table_name, records)
                    .await
                    .map_err(|e| UploadError::IngestionError(e.to_string()))?
            }
        };

        let errors: Vec<String> = parse_result
            .errors
            .iter()
            .map(|e| e.error_message.clone())
            .collect();

        let error_message = if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        };

        self.repository
            .complete_upload(
                upload_record.id,
                parse_result.total_lines as i64,
                records_ingested as i64,
                parse_result.failed as i64,
                error_message.as_deref(),
            )
            .await?;

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(UploadResult {
            upload_id: upload_record.id,
            records_processed: parse_result.total_lines,
            records_ingested,
            errors,
            duration_ms,
        })
    }

    /// Preview file contents without full ingestion
    #[instrument(skip(self, content))]
    pub async fn preview(
        &self,
        content: &[u8],
        config: &ParserConfig,
        limit: Option<usize>,
    ) -> Result<PreviewResult, UploadError> {
        // Mirror upload()'s size guard so preview can't be used to push
        // unbounded content through the parser (NAN-660).
        if content.len() > MAX_FILE_SIZE {
            return Err(UploadError::FileTooLarge {
                size: content.len(),
                max: MAX_FILE_SIZE,
            });
        }

        let limit = limit.unwrap_or(DEFAULT_PREVIEW_ROWS);

        // Parse first N rows
        let parse_result = self.parser.preview(content, config, limit)?;

        // Detect column types from sample data
        let columns = self.detect_columns(&parse_result);

        // Convert records to rows, truncating any oversized cell so a single
        // huge field can't be reflected back amplified in the response.
        let rows: Vec<serde_json::Map<String, serde_json::Value>> = parse_result
            .records
            .iter()
            .map(|r| {
                r.fields
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::truncate_value_for_preview(v)))
                    .collect()
            })
            .collect();

        // Estimate total rows (rough estimate based on file size and sample)
        let total_rows_estimate = if !parse_result.records.is_empty() {
            let avg_record_size = content.len() / parse_result.records.len().max(1);
            content.len() / avg_record_size.max(1)
        } else {
            0
        };

        Ok(PreviewResult {
            format: config.format,
            columns,
            rows,
            total_rows_estimate,
        })
    }

    /// Detect column information from parsed records
    fn detect_columns(&self, parse_result: &ParseResult) -> Vec<ColumnInfo> {
        let mut column_stats: HashMap<String, ColumnStats> = HashMap::new();

        // Collect statistics for each column
        for record in &parse_result.records {
            for (name, value) in &record.fields {
                let stats = column_stats
                    .entry(name.clone())
                    .or_insert_with(|| ColumnStats {
                        sample_values: Vec::new(),
                        null_count: 0,
                        type_counts: HashMap::new(),
                    });

                if value.is_null() {
                    stats.null_count += 1;
                } else {
                    let detected_type = Self::detect_value_type(value);
                    *stats.type_counts.entry(detected_type).or_insert(0) += 1;

                    if stats.sample_values.len() < 5 {
                        let rendered = Self::value_to_string(value);
                        let bounded = if rendered.len() > MAX_PREVIEW_CELL_BYTES {
                            Self::truncate_str_for_preview(&rendered)
                        } else {
                            rendered
                        };
                        stats.sample_values.push(bounded);
                    }
                }
            }
        }

        // Convert stats to ColumnInfo
        let mut columns: Vec<ColumnInfo> = column_stats
            .into_iter()
            .map(|(name, stats)| {
                // Determine the most common type
                let detected_type = stats
                    .type_counts
                    .into_iter()
                    .max_by_key(|(_, count)| *count)
                    .map(|(t, _)| t)
                    .unwrap_or(ColumnType::Text);

                ColumnInfo {
                    name,
                    detected_type,
                    sample_values: stats.sample_values,
                    null_count: stats.null_count,
                }
            })
            .collect();

        // Sort columns by name for consistent ordering
        columns.sort_by(|a, b| a.name.cmp(&b.name));

        columns
    }

    /// Detect the type of a JSON value
    fn detect_value_type(value: &serde_json::Value) -> ColumnType {
        match value {
            serde_json::Value::Null => ColumnType::Text,
            serde_json::Value::Bool(_) => ColumnType::Boolean,
            serde_json::Value::Number(n) => {
                if n.is_i64() || n.is_u64() {
                    ColumnType::Integer
                } else {
                    ColumnType::Float
                }
            }
            serde_json::Value::String(s) => {
                // Try to detect timestamp
                if chrono::DateTime::parse_from_rfc3339(s).is_ok() {
                    return ColumnType::Timestamp;
                }
                // Try ISO 8601 format
                if chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").is_ok() {
                    return ColumnType::Timestamp;
                }
                // Try common date formats
                if chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").is_ok() {
                    return ColumnType::Timestamp;
                }
                ColumnType::Text
            }
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => ColumnType::Json,
        }
    }

    /// Truncate a string to `MAX_PREVIEW_CELL_BYTES` on a UTF-8 boundary,
    /// appending an ellipsis suffix when truncation occurs.
    fn truncate_str_for_preview(s: &str) -> String {
        if s.len() <= MAX_PREVIEW_CELL_BYTES {
            return s.to_string();
        }
        let mut end = MAX_PREVIEW_CELL_BYTES;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        let mut out = String::with_capacity(end + PREVIEW_TRUNCATION_SUFFIX.len());
        out.push_str(&s[..end]);
        out.push_str(PREVIEW_TRUNCATION_SUFFIX);
        out
    }

    /// Truncate oversized JSON values for the preview rows payload. Strings
    /// over the cap are shortened in place; nested arrays/objects whose
    /// serialized form exceeds the cap collapse to a truncated string so a
    /// single deeply-nested field can't blow up the response.
    fn truncate_value_for_preview(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::String(s) if s.len() > MAX_PREVIEW_CELL_BYTES => {
                serde_json::Value::String(Self::truncate_str_for_preview(s))
            }
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                // serde_json::Value is effectively infallible to serialize, but
                // collapse to an explicit marker on Err rather than falling
                // back to "" — an empty serialized form would slip past the
                // size check and reflect the original oversized value.
                let serialized = match serde_json::to_string(value) {
                    Ok(s) => s,
                    Err(_) => {
                        return serde_json::Value::String(format!(
                            "[unserializable]{PREVIEW_TRUNCATION_SUFFIX}"
                        ))
                    }
                };
                if serialized.len() > MAX_PREVIEW_CELL_BYTES {
                    serde_json::Value::String(Self::truncate_str_for_preview(&serialized))
                } else {
                    value.clone()
                }
            }
            _ => value.clone(),
        }
    }

    /// Convert a JSON value to a string for display
    fn value_to_string(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Null => "null".to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                serde_json::to_string(value).unwrap_or_default()
            }
        }
    }

    /// Get upload history with optional filters
    #[instrument(skip(self))]
    pub async fn get_upload_history(
        &self,
        filter: &UploadFilter,
    ) -> Result<Vec<UploadRecord>, UploadError> {
        Ok(self.repository.list_uploads(filter).await?)
    }

    /// Get a specific upload record
    #[instrument(skip(self))]
    pub async fn get_upload(&self, upload_id: Uuid) -> Result<UploadRecord, UploadError> {
        Ok(self.repository.get_upload(upload_id).await?)
    }

    /// Delete an upload record
    #[instrument(skip(self))]
    pub async fn delete_upload(&self, upload_id: Uuid) -> Result<bool, UploadError> {
        Ok(self.repository.delete_upload(upload_id).await?)
    }

    /// Get upload statistics
    #[instrument(skip(self))]
    pub async fn get_stats(&self) -> Result<super::repository::UploadStats, UploadError> {
        Ok(self.repository.get_stats().await?)
    }
}

/// Internal struct for collecting column statistics
struct ColumnStats {
    sample_values: Vec<String>,
    null_count: usize,
    type_counts: HashMap<ColumnType, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_value_type() {
        assert_eq!(
            UploadService::detect_value_type(&serde_json::json!(true)),
            ColumnType::Boolean
        );
        assert_eq!(
            UploadService::detect_value_type(&serde_json::json!(42)),
            ColumnType::Integer
        );
        assert_eq!(
            UploadService::detect_value_type(&serde_json::json!(3.14)),
            ColumnType::Float
        );
        assert_eq!(
            UploadService::detect_value_type(&serde_json::json!("hello")),
            ColumnType::Text
        );
        assert_eq!(
            UploadService::detect_value_type(&serde_json::json!("2024-01-15T10:30:00Z")),
            ColumnType::Timestamp
        );
        assert_eq!(
            UploadService::detect_value_type(&serde_json::json!({"nested": "object"})),
            ColumnType::Json
        );
    }

    #[test]
    fn test_value_to_string() {
        assert_eq!(
            UploadService::value_to_string(&serde_json::json!(null)),
            "null"
        );
        assert_eq!(
            UploadService::value_to_string(&serde_json::json!(true)),
            "true"
        );
        assert_eq!(UploadService::value_to_string(&serde_json::json!(42)), "42");
        assert_eq!(
            UploadService::value_to_string(&serde_json::json!("hello")),
            "hello"
        );
    }

    #[test]
    fn test_truncate_str_for_preview_short_passthrough() {
        let s = "hello world";
        assert_eq!(UploadService::truncate_str_for_preview(s), s);
    }

    #[test]
    fn test_truncate_str_for_preview_long_truncates() {
        let big = "a".repeat(MAX_PREVIEW_CELL_BYTES * 4);
        let out = UploadService::truncate_str_for_preview(&big);
        assert!(out.ends_with(PREVIEW_TRUNCATION_SUFFIX));
        assert!(out.len() <= MAX_PREVIEW_CELL_BYTES + PREVIEW_TRUNCATION_SUFFIX.len());
        assert!(out.len() < big.len());
    }

    #[test]
    fn test_truncate_str_for_preview_respects_utf8_boundary() {
        // 4-byte char repeated past the cap; truncating mid-char would panic
        // without the boundary walk in truncate_str_for_preview.
        let big = "🦀".repeat(MAX_PREVIEW_CELL_BYTES);
        let out = UploadService::truncate_str_for_preview(&big);
        assert!(out.ends_with(PREVIEW_TRUNCATION_SUFFIX));
        // Body before the suffix must still be valid UTF-8 (String construction
        // would have panicked otherwise, but assert explicitly).
        let body = &out[..out.len() - PREVIEW_TRUNCATION_SUFFIX.len()];
        assert!(std::str::from_utf8(body.as_bytes()).is_ok());
    }

    #[test]
    fn test_truncate_value_for_preview_passes_small_values() {
        for v in [
            serde_json::json!(null),
            serde_json::json!(true),
            serde_json::json!(42),
            serde_json::json!(3.14),
            serde_json::json!("short"),
            serde_json::json!({"a": 1}),
            serde_json::json!([1, 2, 3]),
        ] {
            assert_eq!(UploadService::truncate_value_for_preview(&v), v);
        }
    }

    #[test]
    fn test_truncate_value_for_preview_truncates_long_string() {
        let big = serde_json::Value::String("x".repeat(MAX_PREVIEW_CELL_BYTES * 8));
        let out = UploadService::truncate_value_for_preview(&big);
        match out {
            serde_json::Value::String(s) => {
                assert!(s.ends_with(PREVIEW_TRUNCATION_SUFFIX));
                assert!(s.len() <= MAX_PREVIEW_CELL_BYTES + PREVIEW_TRUNCATION_SUFFIX.len());
            }
            other => panic!("expected truncated string, got {:?}", other),
        }
    }

    #[test]
    fn test_truncate_value_for_preview_collapses_oversized_object() {
        let mut obj = serde_json::Map::new();
        for i in 0..200 {
            obj.insert(format!("k{i}"), serde_json::json!("y".repeat(50)));
        }
        let big = serde_json::Value::Object(obj);
        let out = UploadService::truncate_value_for_preview(&big);
        match out {
            serde_json::Value::String(s) => {
                assert!(s.ends_with(PREVIEW_TRUNCATION_SUFFIX));
                assert!(s.len() <= MAX_PREVIEW_CELL_BYTES + PREVIEW_TRUNCATION_SUFFIX.len());
            }
            other => panic!("expected oversized object to collapse to string, got {other:?}"),
        }
    }
}
