// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup service for managing lookup tables
//!
//! Provides high-level operations for creating, querying, and managing
//! lookup tables used for search enrichment.
//!
//! Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.7, 3.1, 3.2, 3.3, 3.4, 3.5, 5.3, 5.4

use std::collections::HashMap;
use thiserror::Error;
use tracing::instrument;

use super::repository::{LookupRepository, LookupRepositoryError, RuleReferenceRow};
use super::types::*;
use crate::upload::ColumnType;

#[derive(Error, Debug)]
pub enum LookupError {
    #[error("Repository error: {0}")]
    RepositoryError(String),
    #[error("Table not found: {0}")]
    TableNotFound(String),
    #[error("Table already exists: {0}")]
    TableAlreadyExists(String),
    #[error("Invalid table name: {0}")]
    InvalidTableName(String),
    #[error("Invalid column: {0}")]
    InvalidColumn(String),
    #[error("Row limit exceeded: maximum {0} rows allowed")]
    RowLimitExceeded(i64),
    #[error("Primary key column not found in columns: {0}")]
    PrimaryKeyNotFound(String),
    #[error("Row not found: {0}")]
    RowNotFound(i64),
}

impl From<LookupRepositoryError> for LookupError {
    fn from(err: LookupRepositoryError) -> Self {
        match err {
            LookupRepositoryError::TableNotFound(n) => LookupError::TableNotFound(n),
            LookupRepositoryError::TableAlreadyExists(n) => LookupError::TableAlreadyExists(n),
            LookupRepositoryError::InvalidTableName(n) => LookupError::InvalidTableName(n),
            LookupRepositoryError::InvalidColumnName(n) => LookupError::InvalidColumn(n),
            LookupRepositoryError::PrimaryKeyNotFound(n) => LookupError::PrimaryKeyNotFound(n),
            LookupRepositoryError::RowLimitExceeded(n) => LookupError::RowLimitExceeded(n),
            LookupRepositoryError::RowNotFound(id) => LookupError::RowNotFound(id),
            LookupRepositoryError::DatabaseError(e) => LookupError::RepositoryError(e.to_string()),
        }
    }
}

/// Service for lookup table operations
#[derive(Clone)]
pub struct LookupService {
    repository: LookupRepository,
}

impl LookupService {
    /// Create a new lookup service
    pub fn new(repository: LookupRepository) -> Self {
        Self { repository }
    }

    // ========================================================================
    // Table Management
    // ========================================================================

    /// List all lookup tables
    #[instrument(skip(self))]
    pub async fn list_tables(&self) -> Result<Vec<LookupTable>, LookupError> {
        Ok(self.repository.list_tables().await?)
    }

    /// Get a lookup table by name
    #[instrument(skip(self))]
    pub async fn get_table(&self, name: &str) -> Result<LookupTable, LookupError> {
        Ok(self.repository.get_table(name).await?)
    }

    /// Find detection rules whose query body references the given lookup table.
    ///
    /// See [`LookupRepository::find_rules_referencing`] for matching semantics.
    #[instrument(skip(self))]
    pub async fn find_rules_referencing(
        &self,
        name: &str,
    ) -> Result<Vec<RuleReferenceRow>, LookupError> {
        Ok(self.repository.find_rules_referencing(name).await?)
    }

    /// Check if a lookup table exists
    #[instrument(skip(self))]
    pub async fn table_exists(&self, name: &str) -> Result<bool, LookupError> {
        Ok(self.repository.table_exists(name).await?)
    }

    /// Create a new lookup table.
    ///
    /// This creates both the registry entry and the actual PostgreSQL table.
    /// `created_by_user_id` records the creator on the registry row; pass
    /// `None` for system-internal callers without a user context.
    #[instrument(skip(self))]
    pub async fn create_table(
        &self,
        new_table: NewLookupTable,
        created_by_user_id: Option<uuid::Uuid>,
    ) -> Result<LookupTable, LookupError> {
        // Validate table name
        if new_table.name.is_empty() {
            return Err(LookupError::InvalidTableName(
                "Table name cannot be empty".to_string(),
            ));
        }

        // Validate columns
        if new_table.columns.is_empty() {
            return Err(LookupError::InvalidColumn(
                "At least one column is required".to_string(),
            ));
        }

        // Validate primary key exists in columns
        if let Some(ref pk) = new_table.primary_key {
            if !new_table.columns.iter().any(|c| &c.name == pk) {
                return Err(LookupError::PrimaryKeyNotFound(pk.clone()));
            }
        }

        // Generate the actual table name
        let actual_table_name = new_table.generate_table_name();

        // Create the dynamic PostgreSQL table
        self.repository
            .create_dynamic_table(
                &actual_table_name,
                &new_table.columns,
                new_table.primary_key.as_deref(),
            )
            .await?;

        // Register in the lookup tables registry
        let table = self
            .repository
            .register_table(&new_table, &actual_table_name, created_by_user_id)
            .await?;

        Ok(table)
    }

    /// Drop a lookup table
    ///
    /// This removes both the registry entry and the actual PostgreSQL table.
    #[instrument(skip(self))]
    pub async fn drop_table(&self, name: &str) -> Result<(), LookupError> {
        // Get the table to find the actual table name
        let table = self.repository.get_table(name).await?;

        // Drop the dynamic table
        self.repository
            .drop_dynamic_table(&table.table_name)
            .await?;

        // Remove from registry
        self.repository.unregister_table(name).await?;

        Ok(())
    }

    /// Insert records into a lookup table (append mode)
    #[instrument(skip(self, records))]
    pub async fn insert_records(
        &self,
        table_name: &str,
        records: Vec<HashMap<String, serde_json::Value>>,
    ) -> Result<usize, LookupError> {
        let table = self.repository.get_table(table_name).await?;

        // Check row limit
        let current_count = self
            .repository
            .get_table_row_count(&table.table_name)
            .await?;
        if current_count + records.len() as i64 > MAX_LOOKUP_TABLE_ROWS {
            return Err(LookupError::RowLimitExceeded(MAX_LOOKUP_TABLE_ROWS));
        }

        // Insert records
        let inserted = self
            .repository
            .insert_records(&table.table_name, &table.columns, &records)
            .await?;

        // Update stats
        let new_count = self
            .repository
            .get_table_row_count(&table.table_name)
            .await?;
        let size = self
            .repository
            .get_table_size(&table.table_name)
            .await
            .unwrap_or(0);
        self.repository
            .update_table_stats(table_name, new_count, size)
            .await?;

        Ok(inserted)
    }

    /// Replace all records in a lookup table
    #[instrument(skip(self, records))]
    pub async fn replace_records(
        &self,
        table_name: &str,
        records: Vec<HashMap<String, serde_json::Value>>,
    ) -> Result<usize, LookupError> {
        let table = self.repository.get_table(table_name).await?;

        // Check row limit
        if records.len() as i64 > MAX_LOOKUP_TABLE_ROWS {
            return Err(LookupError::RowLimitExceeded(MAX_LOOKUP_TABLE_ROWS));
        }

        // Truncate existing data
        self.repository
            .truncate_dynamic_table(&table.table_name)
            .await?;

        // Insert new records
        let inserted = self
            .repository
            .insert_records(&table.table_name, &table.columns, &records)
            .await?;

        // Update stats
        let new_count = self
            .repository
            .get_table_row_count(&table.table_name)
            .await?;
        let size = self
            .repository
            .get_table_size(&table.table_name)
            .await
            .unwrap_or(0);
        self.repository
            .update_table_stats(table_name, new_count, size)
            .await?;

        Ok(inserted)
    }

    // ========================================================================
    // Row-Level CRUD
    // ========================================================================

    /// List rows with pagination
    #[instrument(skip(self))]
    pub async fn list_rows(
        &self,
        table_name: &str,
        page: i64,
        page_size: i64,
    ) -> Result<LookupRowsPage, LookupError> {
        let table = self.repository.get_table(table_name).await?;
        let page_size = page_size.clamp(1, 100);
        let page = page.max(1);
        let offset = (page - 1) * page_size;

        let (rows, total) = self
            .repository
            .list_rows(&table.table_name, page_size, offset)
            .await?;
        let total_pages = if total == 0 {
            1
        } else {
            (total + page_size - 1) / page_size
        };

        Ok(LookupRowsPage {
            rows,
            total,
            page,
            page_size,
            total_pages,
        })
    }

    /// Insert a single row and return the assigned _row_id
    #[instrument(skip(self, record))]
    pub async fn insert_row(
        &self,
        table_name: &str,
        record: HashMap<String, serde_json::Value>,
    ) -> Result<i64, LookupError> {
        let ids = self.insert_rows(table_name, vec![record]).await?;
        Ok(ids[0])
    }

    /// Insert multiple rows in batch, returning assigned _row_ids.
    /// Performs a single table lookup, one row-limit check, and one stats update.
    #[instrument(skip(self, records))]
    pub async fn insert_rows(
        &self,
        table_name: &str,
        records: Vec<HashMap<String, serde_json::Value>>,
    ) -> Result<Vec<i64>, LookupError> {
        if records.is_empty() {
            return Ok(vec![]);
        }

        let table = self.repository.get_table(table_name).await?;

        // Check row limit once for the entire batch
        let current_count = self
            .repository
            .get_table_row_count(&table.table_name)
            .await?;
        if current_count + records.len() as i64 > MAX_LOOKUP_TABLE_ROWS {
            return Err(LookupError::RowLimitExceeded(MAX_LOOKUP_TABLE_ROWS));
        }

        let mut row_ids = Vec::with_capacity(records.len());
        for record in &records {
            let row_id = self
                .repository
                .insert_row(&table.table_name, &table.columns, record)
                .await?;
            row_ids.push(row_id);
        }

        // Update stats once after all inserts
        let new_count = self
            .repository
            .get_table_row_count(&table.table_name)
            .await?;
        let size = self
            .repository
            .get_table_size(&table.table_name)
            .await
            .unwrap_or(0);
        self.repository
            .update_table_stats(table_name, new_count, size)
            .await?;

        Ok(row_ids)
    }

    /// Update a single row by _row_id
    #[instrument(skip(self, record))]
    pub async fn update_row(
        &self,
        table_name: &str,
        row_id: i64,
        record: HashMap<String, serde_json::Value>,
    ) -> Result<(), LookupError> {
        let table = self.repository.get_table(table_name).await?;
        self.repository
            .update_row(&table.table_name, row_id, &table.columns, &record)
            .await?;

        // Update stats (size may change)
        let count = self
            .repository
            .get_table_row_count(&table.table_name)
            .await?;
        let size = self
            .repository
            .get_table_size(&table.table_name)
            .await
            .unwrap_or(0);
        self.repository
            .update_table_stats(table_name, count, size)
            .await?;

        Ok(())
    }

    /// Delete a single row by _row_id
    #[instrument(skip(self))]
    pub async fn delete_row(&self, table_name: &str, row_id: i64) -> Result<(), LookupError> {
        let table = self.repository.get_table(table_name).await?;
        self.repository
            .delete_row(&table.table_name, row_id)
            .await?;

        // Update stats
        let count = self
            .repository
            .get_table_row_count(&table.table_name)
            .await?;
        let size = self
            .repository
            .get_table_size(&table.table_name)
            .await
            .unwrap_or(0);
        self.repository
            .update_table_stats(table_name, count, size)
            .await?;

        Ok(())
    }

    /// Delete multiple rows by _row_id
    #[instrument(skip(self, row_ids))]
    pub async fn delete_rows(&self, table_name: &str, row_ids: &[i64]) -> Result<u64, LookupError> {
        let table = self.repository.get_table(table_name).await?;
        let deleted = self
            .repository
            .delete_rows(&table.table_name, row_ids)
            .await?;

        // Update stats
        let count = self
            .repository
            .get_table_row_count(&table.table_name)
            .await?;
        let size = self
            .repository
            .get_table_size(&table.table_name)
            .await
            .unwrap_or(0);
        self.repository
            .update_table_stats(table_name, count, size)
            .await?;

        Ok(deleted)
    }

    // ========================================================================
    // Query Operations
    // ========================================================================

    /// Perform a single key lookup
    #[instrument(skip(self))]
    pub async fn lookup(&self, query: LookupQuery) -> Result<LookupResult, LookupError> {
        let table = self.repository.get_table(&query.table_name).await?;

        let result = self
            .repository
            .lookup(
                &table.table_name,
                &query.key_field,
                &query.key_value,
                query.output_fields.as_deref(),
                query.case_insensitive,
            )
            .await?;

        match result {
            Some(fields) => Ok(LookupResult::found(fields)),
            None => Ok(LookupResult::not_found()),
        }
    }

    /// Perform a batch lookup for multiple keys
    #[instrument(skip(self, query))]
    pub async fn lookup_batch(
        &self,
        query: BatchLookupQuery,
    ) -> Result<BatchLookupResult, LookupError> {
        let table = self.repository.get_table(&query.table_name).await?;

        // Use the table's primary key column for querying, falling back to the provided key_field
        let lookup_key_field = table.primary_key.as_deref().unwrap_or(&query.key_field);

        let results = self
            .repository
            .lookup_batch(
                &table.table_name,
                lookup_key_field,
                &query.key_values,
                query.output_fields.as_deref(),
                query.case_insensitive,
            )
            .await?;

        let matched_count = results.len();
        let total_count = query.key_values.len();

        Ok(BatchLookupResult {
            results,
            matched_count,
            total_count,
        })
    }

    /// Get a sample of rows from a lookup table
    #[instrument(skip(self))]
    pub async fn sample_rows(
        &self,
        table_name: &str,
        limit: i64,
    ) -> Result<Vec<HashMap<String, serde_json::Value>>, LookupError> {
        // Verify the table exists
        let table = self.repository.get_table(table_name).await?;

        // Fetch sample rows
        let rows = self
            .repository
            .sample_rows(&table.table_name, limit)
            .await?;

        Ok(rows)
    }

    // ========================================================================
    // Column Type Detection
    // ========================================================================

    /// Detect column types from sample data
    ///
    /// Analyzes sample values to determine the most appropriate column type.
    /// Requirements: 2.3
    pub fn detect_column_types(
        records: &[HashMap<String, serde_json::Value>],
        type_overrides: Option<&[ColumnTypeOverride]>,
    ) -> Vec<LookupColumn> {
        if records.is_empty() {
            return vec![];
        }

        // Collect all column names from all records
        let mut column_names: Vec<String> = records
            .iter()
            .flat_map(|r| r.keys().cloned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        column_names.sort();

        // Build override map
        let override_map: HashMap<&str, ColumnType> = type_overrides
            .map(|overrides| {
                overrides
                    .iter()
                    .map(|o| (o.column.as_str(), o.data_type))
                    .collect()
            })
            .unwrap_or_default();

        // Detect type for each column
        column_names
            .into_iter()
            .map(|name| {
                // Check for override first
                if let Some(&override_type) = override_map.get(name.as_str()) {
                    return LookupColumn::new(name, override_type, true);
                }

                // Collect non-null values for this column
                let values: Vec<&serde_json::Value> = records
                    .iter()
                    .filter_map(|r| r.get(&name))
                    .filter(|v| !v.is_null())
                    .collect();

                let has_nulls = values.len() < records.len();
                let detected_type = Self::detect_type_from_values(&values);

                LookupColumn::new(name, detected_type, has_nulls)
            })
            .collect()
    }

    /// Detect the column type from a set of values
    fn detect_type_from_values(values: &[&serde_json::Value]) -> ColumnType {
        if values.is_empty() {
            return ColumnType::Text;
        }

        // Check if all values are of the same type
        let mut is_integer = true;
        let mut is_float = true;
        let mut is_boolean = true;
        let mut is_timestamp = true;

        for value in values {
            match value {
                serde_json::Value::Number(n) => {
                    is_boolean = false;
                    is_timestamp = false;
                    if n.is_f64() && !n.is_i64() {
                        is_integer = false;
                    }
                }
                serde_json::Value::Bool(_) => {
                    is_integer = false;
                    is_float = false;
                    is_timestamp = false;
                }
                serde_json::Value::String(s) => {
                    is_integer = false;
                    is_float = false;
                    is_boolean = false;
                    // Check if it looks like a timestamp
                    if !Self::looks_like_timestamp(s) {
                        is_timestamp = false;
                    }
                }
                serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                    // Complex types default to JSON
                    return ColumnType::Json;
                }
                serde_json::Value::Null => {
                    // Nulls don't affect type detection
                }
            }
        }

        // Return the most specific type that matches all values
        if is_boolean {
            ColumnType::Boolean
        } else if is_integer {
            ColumnType::Integer
        } else if is_float {
            ColumnType::Float
        } else if is_timestamp {
            ColumnType::Timestamp
        } else {
            ColumnType::Text
        }
    }

    /// Check if a string looks like a timestamp
    fn looks_like_timestamp(s: &str) -> bool {
        // Common timestamp patterns
        // ISO 8601: 2024-01-15T10:30:00Z
        // RFC 2822: Mon, 15 Jan 2024 10:30:00 +0000
        // Common formats: 2024-01-15 10:30:00, 01/15/2024 10:30:00

        if s.len() < 10 {
            return false;
        }

        // Try parsing with chrono
        chrono::DateTime::parse_from_rfc3339(s).is_ok()
            || chrono::DateTime::parse_from_rfc2822(s).is_ok()
            || chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").is_ok()
            || chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").is_ok()
            || chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
    }

    /// Flatten nested JSON objects into flat column structure
    ///
    /// Converts nested objects like {"user": {"name": "John", "age": 30}}
    /// into flat columns like {"user_name": "John", "user_age": 30}
    pub fn flatten_records(
        records: Vec<HashMap<String, serde_json::Value>>,
    ) -> Vec<HashMap<String, serde_json::Value>> {
        records
            .into_iter()
            .map(|record| Self::flatten_record(record, ""))
            .collect()
    }

    /// Flatten a single record
    fn flatten_record(
        record: HashMap<String, serde_json::Value>,
        prefix: &str,
    ) -> HashMap<String, serde_json::Value> {
        let mut result = HashMap::new();

        for (key, value) in record {
            let full_key = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{}_{}", prefix, key)
            };

            match value {
                serde_json::Value::Object(obj) => {
                    // Recursively flatten nested objects
                    let nested: HashMap<String, serde_json::Value> = obj.into_iter().collect();
                    let flattened = Self::flatten_record(nested, &full_key);
                    result.extend(flattened);
                }
                _ => {
                    result.insert(full_key, value);
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_column_types_integers() {
        let records = vec![
            HashMap::from([("count".to_string(), serde_json::json!(1))]),
            HashMap::from([("count".to_string(), serde_json::json!(2))]),
            HashMap::from([("count".to_string(), serde_json::json!(3))]),
        ];

        let columns = LookupService::detect_column_types(&records, None);
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].name, "count");
        assert_eq!(columns[0].data_type, ColumnType::Integer);
    }

    #[test]
    fn test_detect_column_types_booleans() {
        let records = vec![
            HashMap::from([("active".to_string(), serde_json::json!(true))]),
            HashMap::from([("active".to_string(), serde_json::json!(false))]),
        ];

        let columns = LookupService::detect_column_types(&records, None);
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].data_type, ColumnType::Boolean);
    }

    #[test]
    fn test_detect_column_types_timestamps() {
        let records = vec![
            HashMap::from([(
                "created".to_string(),
                serde_json::json!("2024-01-15T10:30:00Z"),
            )]),
            HashMap::from([(
                "created".to_string(),
                serde_json::json!("2024-01-16T11:00:00Z"),
            )]),
        ];

        let columns = LookupService::detect_column_types(&records, None);
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].data_type, ColumnType::Timestamp);
    }

    #[test]
    fn test_detect_column_types_mixed_defaults_to_text() {
        let records = vec![
            HashMap::from([("value".to_string(), serde_json::json!(1))]),
            HashMap::from([("value".to_string(), serde_json::json!("text"))]),
        ];

        let columns = LookupService::detect_column_types(&records, None);
        assert_eq!(columns.len(), 1);
        // Mixed types should default to text
        assert_eq!(columns[0].data_type, ColumnType::Text);
    }

    #[test]
    fn test_detect_column_types_with_override() {
        let records = vec![HashMap::from([("id".to_string(), serde_json::json!(123))])];

        let overrides = vec![ColumnTypeOverride {
            column: "id".to_string(),
            data_type: ColumnType::Text,
        }];

        let columns = LookupService::detect_column_types(&records, Some(&overrides));
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].data_type, ColumnType::Text);
    }

    #[test]
    fn test_detect_column_types_with_nulls() {
        let records = vec![
            HashMap::from([("name".to_string(), serde_json::json!("Alice"))]),
            HashMap::from([("name".to_string(), serde_json::Value::Null)]),
            HashMap::from([("name".to_string(), serde_json::json!("Bob"))]),
        ];

        let columns = LookupService::detect_column_types(&records, None);
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].data_type, ColumnType::Text);
        assert!(columns[0].nullable);
    }

    #[test]
    fn test_flatten_records() {
        let records = vec![HashMap::from([
            ("name".to_string(), serde_json::json!("Alice")),
            (
                "address".to_string(),
                serde_json::json!({
                    "city": "Seattle",
                    "zip": "98101"
                }),
            ),
        ])];

        let flattened = LookupService::flatten_records(records);
        assert_eq!(flattened.len(), 1);

        let record = &flattened[0];
        assert_eq!(record.get("name"), Some(&serde_json::json!("Alice")));
        assert_eq!(
            record.get("address_city"),
            Some(&serde_json::json!("Seattle"))
        );
        assert_eq!(record.get("address_zip"), Some(&serde_json::json!("98101")));
        assert!(record.get("address").is_none());
    }

    #[test]
    fn test_looks_like_timestamp() {
        assert!(LookupService::looks_like_timestamp("2024-01-15T10:30:00Z"));
        assert!(LookupService::looks_like_timestamp(
            "2024-01-15T10:30:00+00:00"
        ));
        assert!(LookupService::looks_like_timestamp("2024-01-15"));

        assert!(!LookupService::looks_like_timestamp("hello"));
        assert!(!LookupService::looks_like_timestamp("123"));
        assert!(!LookupService::looks_like_timestamp(""));
    }
}
