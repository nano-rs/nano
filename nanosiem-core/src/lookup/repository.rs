// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup repository for database operations
//!
//! Provides database operations for lookup table management including
//! registry operations and dynamic table creation/querying.
//!
//! Requirements: 2.1, 2.2, 2.4, 2.5, 2.7, 3.1, 3.2, 3.3, 3.4, 3.5, 5.3, 5.4

use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::{Column, PgPool, Row, TypeInfo};
use std::collections::HashMap;
use thiserror::Error;
use tracing::instrument;
use uuid::Uuid;

use super::types::*;
use crate::upload::ColumnType;

#[derive(Error, Debug)]
pub enum LookupRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Lookup table not found: {0}")]
    TableNotFound(String),
    #[error("Lookup table already exists: {0}")]
    TableAlreadyExists(String),
    #[error("Invalid column name: {0}")]
    InvalidColumnName(String),
    #[error("Invalid table name: {0}")]
    InvalidTableName(String),
    #[error("Primary key column not found: {0}")]
    PrimaryKeyNotFound(String),
    #[error("Row limit exceeded: maximum {0} rows allowed")]
    RowLimitExceeded(i64),
    #[error("Row not found: {0}")]
    RowNotFound(i64),
}

/// Internal columns that should be excluded from enrichment/display results
const INTERNAL_COLUMNS: &[&str] = &["_row_id"];

/// Row returned by [`LookupRepository::find_rules_referencing`].
///
/// Carries enough fields for the API layer to extract the sample-join clause
/// without forcing the repository to know about presentation concerns.
#[derive(Debug, Clone)]
pub struct RuleReferenceRow {
    pub id: Uuid,
    pub name: String,
    pub mitre_tactics: Vec<String>,
    pub query: String,
}

/// Repository for lookup table operations
#[derive(Clone)]
pub struct LookupRepository {
    pool: PgPool,
}

impl LookupRepository {
    /// Create a new lookup repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ========================================================================
    // Registry Operations
    // ========================================================================

    /// SELECT clause that hydrates the registry row plus the creator
    /// summary via LEFT JOIN on `users`. Must be paired with the FROM /
    /// WHERE clause in `LOOKUP_TABLES_FROM_JOIN` so column aliases line up
    /// with `LookupTableRow`.
    const LOOKUP_TABLES_SELECT: &'static str = "lt.id, lt.name, lt.description, lt.table_name, \
         lt.columns, lt.primary_key, lt.row_count, lt.size_bytes, \
         lt.created_at, lt.updated_at, lt.created_by_user_id, \
         u.name AS created_by_name, u.email AS created_by_email";

    const LOOKUP_TABLES_FROM_JOIN: &'static str =
        "FROM lookup_tables_registry lt LEFT JOIN users u ON u.id = lt.created_by_user_id";

    /// List all lookup tables from the registry
    #[instrument(skip(self))]
    pub async fn list_tables(&self) -> Result<Vec<LookupTable>, LookupRepositoryError> {
        let sql = format!(
            "SELECT {} {} ORDER BY lt.name",
            Self::LOOKUP_TABLES_SELECT,
            Self::LOOKUP_TABLES_FROM_JOIN,
        );
        let rows = sqlx::query_as::<_, LookupTableRow>(&sql)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.into_iter().map(LookupTable::from).collect())
    }

    /// Get a lookup table by name
    #[instrument(skip(self))]
    pub async fn get_table(&self, name: &str) -> Result<LookupTable, LookupRepositoryError> {
        let sql = format!(
            "SELECT {} {} WHERE lt.name = $1",
            Self::LOOKUP_TABLES_SELECT,
            Self::LOOKUP_TABLES_FROM_JOIN,
        );
        let row = sqlx::query_as::<_, LookupTableRow>(&sql)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| LookupRepositoryError::TableNotFound(name.to_string()))?;

        Ok(LookupTable::from(row))
    }

    /// Get a lookup table by ID
    #[instrument(skip(self))]

    /// Check if a lookup table exists by name
    #[instrument(skip(self))]
    pub async fn table_exists(&self, name: &str) -> Result<bool, LookupRepositoryError> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM lookup_tables_registry WHERE name = $1)",
        )
        .bind(name)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    /// Register a new lookup table in the registry.
    ///
    /// `created_by_user_id` records who created the table; pass `None` for
    /// system-internal callers that don't carry a user context. The insert
    /// returns just the registry row (no JOIN), so the resulting
    /// `LookupTable.created_by` is `None` here even when a user ID is set —
    /// callers that need the populated creator summary should re-fetch via
    /// `get_table` (which is what the API handler already does to pick up
    /// row_count / size after inserts).
    #[instrument(skip(self))]
    pub async fn register_table(
        &self,
        new_table: &NewLookupTable,
        actual_table_name: &str,
        created_by_user_id: Option<Uuid>,
    ) -> Result<LookupTable, LookupRepositoryError> {
        // Check if table already exists
        if self.table_exists(&new_table.name).await? {
            return Err(LookupRepositoryError::TableAlreadyExists(
                new_table.name.clone(),
            ));
        }

        let columns_json = serde_json::to_value(&new_table.columns).map_err(|e| {
            LookupRepositoryError::DatabaseError(sqlx::Error::Protocol(e.to_string()))
        })?;

        let row = sqlx::query_as::<_, LookupTableRow>(
            r#"
            INSERT INTO lookup_tables_registry
                (name, description, table_name, columns, primary_key, created_by_user_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, name, description, table_name, columns, primary_key,
                      row_count, size_bytes, created_at, updated_at,
                      created_by_user_id,
                      NULL::TEXT AS created_by_name,
                      NULL::TEXT AS created_by_email
            "#,
        )
        .bind(&new_table.name)
        .bind(&new_table.description)
        .bind(actual_table_name)
        .bind(columns_json)
        .bind(&new_table.primary_key)
        .bind(created_by_user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(LookupTable::from(row))
    }

    /// Update lookup table metadata (row count, size)
    #[instrument(skip(self))]
    pub async fn update_table_stats(
        &self,
        name: &str,
        row_count: i64,
        size_bytes: i64,
    ) -> Result<(), LookupRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE lookup_tables_registry 
            SET row_count = $2, size_bytes = $3, updated_at = NOW()
            WHERE name = $1
            "#,
        )
        .bind(name)
        .bind(row_count)
        .bind(size_bytes)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(LookupRepositoryError::TableNotFound(name.to_string()));
        }

        Ok(())
    }

    /// Remove a lookup table from the registry.
    ///
    /// Returns the deleted row's metadata. Creator name/email aren't
    /// populated here (no JOIN on a DELETE…RETURNING) — only the FK is
    /// returned, which is sufficient for audit logging.
    #[instrument(skip(self))]
    pub async fn unregister_table(&self, name: &str) -> Result<LookupTable, LookupRepositoryError> {
        let row = sqlx::query_as::<_, LookupTableRow>(
            r#"
            DELETE FROM lookup_tables_registry WHERE name = $1
            RETURNING id, name, description, table_name, columns, primary_key,
                      row_count, size_bytes, created_at, updated_at,
                      created_by_user_id,
                      NULL::TEXT AS created_by_name,
                      NULL::TEXT AS created_by_email
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| LookupRepositoryError::TableNotFound(name.to_string()))?;

        Ok(LookupTable::from(row))
    }

    /// Update the columns and primary key of an existing registry entry
    #[instrument(skip(self))]
    pub async fn update_table_columns(
        &self,
        name: &str,
        columns: &[crate::lookup::LookupColumn],
        primary_key: Option<&str>,
    ) -> Result<(), LookupRepositoryError> {
        let columns_json = serde_json::to_value(columns).map_err(|e| {
            LookupRepositoryError::DatabaseError(sqlx::Error::Protocol(e.to_string()))
        })?;

        sqlx::query(
            r#"
            UPDATE lookup_tables_registry
            SET columns = $2, primary_key = $3, updated_at = NOW()
            WHERE name = $1
            "#,
        )
        .bind(name)
        .bind(columns_json)
        .bind(primary_key)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ========================================================================
    // Dynamic Table Operations
    // ========================================================================

    /// Create the actual PostgreSQL table for lookup data
    #[instrument(skip(self))]
    pub async fn create_dynamic_table(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        primary_key: Option<&str>,
    ) -> Result<(), LookupRepositoryError> {
        // Validate table name
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        // Validate column names
        for col in columns {
            if !Self::is_valid_identifier(&col.name) {
                return Err(LookupRepositoryError::InvalidColumnName(col.name.clone()));
            }
        }

        // Validate primary key exists in columns
        if let Some(pk) = primary_key {
            if !columns.iter().any(|c| c.name == pk) {
                return Err(LookupRepositoryError::PrimaryKeyNotFound(pk.to_string()));
            }
        }

        // Build CREATE TABLE statement (prepend hidden _row_id for stable row identification)
        let mut column_defs = vec!["\"_row_id\" BIGSERIAL".to_string()];
        for col in columns {
            let null_constraint = if col.nullable { "" } else { " NOT NULL" };
            column_defs.push(format!(
                "\"{}\" {}{}",
                col.name,
                col.data_type.to_postgres_type(),
                null_constraint
            ));
        }

        let create_sql = format!(
            "CREATE TABLE IF NOT EXISTS \"{}\" ({})",
            table_name,
            column_defs.join(", ")
        );

        sqlx::query(&create_sql).execute(&self.pool).await?;

        // Create index on primary key if specified
        if let Some(pk) = primary_key {
            let index_name = format!("idx_{}_{}", table_name, pk);
            let index_sql = format!(
                "CREATE INDEX IF NOT EXISTS \"{}\" ON \"{}\" (\"{}\")",
                index_name, table_name, pk
            );
            sqlx::query(&index_sql).execute(&self.pool).await?;
        }

        Ok(())
    }

    /// Drop a dynamic lookup table
    #[instrument(skip(self))]
    pub async fn drop_dynamic_table(&self, table_name: &str) -> Result<(), LookupRepositoryError> {
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        let drop_sql = format!("DROP TABLE IF EXISTS \"{}\" CASCADE", table_name);
        sqlx::query(&drop_sql).execute(&self.pool).await?;

        Ok(())
    }

    /// Truncate a dynamic lookup table (for replace mode)
    #[instrument(skip(self))]
    pub async fn truncate_dynamic_table(
        &self,
        table_name: &str,
    ) -> Result<(), LookupRepositoryError> {
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        let truncate_sql = format!("TRUNCATE TABLE \"{}\"", table_name);
        sqlx::query(&truncate_sql).execute(&self.pool).await?;

        Ok(())
    }

    /// Atomically swap a freshly-built staging table in for the live one
    /// (NAN-1362). In a single transaction: drop the old physical table, rename
    /// the staging table to the old physical name, and update the registry
    /// schema/stats. Postgres has transactional DDL, so if anything here fails
    /// the old table is left fully intact. The caller is responsible for having
    /// already created + populated `staging_physical`.
    #[instrument(skip(self, columns))]
    pub async fn swap_staged_table(
        &self,
        old_physical: &str,
        staging_physical: &str,
        registry_name: &str,
        columns: &[LookupColumn],
        primary_key: Option<&str>,
        row_count: i64,
    ) -> Result<(), LookupRepositoryError> {
        if !Self::is_valid_identifier(old_physical) {
            return Err(LookupRepositoryError::InvalidTableName(
                old_physical.to_string(),
            ));
        }
        if !Self::is_valid_identifier(staging_physical) {
            return Err(LookupRepositoryError::InvalidTableName(
                staging_physical.to_string(),
            ));
        }

        let columns_json = serde_json::to_value(columns).map_err(|e| {
            LookupRepositoryError::DatabaseError(sqlx::Error::Protocol(e.to_string()))
        })?;

        let mut tx = self.pool.begin().await?;

        sqlx::query(&format!("DROP TABLE IF EXISTS \"{}\" CASCADE", old_physical))
            .execute(&mut *tx)
            .await?;

        sqlx::query(&format!(
            "ALTER TABLE \"{}\" RENAME TO \"{}\"",
            staging_physical, old_physical
        ))
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE lookup_tables_registry
            SET columns = $2, primary_key = $3, row_count = $4,
                size_bytes = 0, updated_at = NOW()
            WHERE name = $1
            "#,
        )
        .bind(registry_name)
        .bind(columns_json)
        .bind(primary_key)
        .bind(row_count)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Insert records into a dynamic lookup table
    #[instrument(skip(self, records))]
    pub async fn insert_records(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        records: &[HashMap<String, serde_json::Value>],
    ) -> Result<usize, LookupRepositoryError> {
        if records.is_empty() {
            return Ok(0);
        }

        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        let column_names: Vec<&str> = columns.iter().map(|c| c.name.as_str()).collect();
        let mut inserted = 0usize;

        // Insert in batches of 500
        for chunk in records.chunks(500) {
            let mut values_parts = Vec::new();
            let mut param_idx = 1;

            for _ in chunk {
                let placeholders: Vec<String> = (0..column_names.len())
                    .map(|_| {
                        let p = format!("${}", param_idx);
                        param_idx += 1;
                        p
                    })
                    .collect();
                values_parts.push(format!("({})", placeholders.join(", ")));
            }

            let quoted_columns: Vec<String> =
                column_names.iter().map(|c| format!("\"{}\"", c)).collect();

            let insert_sql = format!(
                "INSERT INTO \"{}\" ({}) VALUES {}",
                table_name,
                quoted_columns.join(", "),
                values_parts.join(", ")
            );

            let mut query = sqlx::query(&insert_sql);

            for record in chunk {
                for (col_idx, col_name) in column_names.iter().enumerate() {
                    let value = record.get(*col_name);
                    let col_type = &columns[col_idx].data_type;
                    query = Self::bind_value(query, value, col_type);
                }
            }

            let result = query.execute(&self.pool).await?;
            inserted += result.rows_affected() as usize;
        }

        Ok(inserted)
    }

    /// Get the row count for a dynamic table
    #[instrument(skip(self))]
    pub async fn get_table_row_count(
        &self,
        table_name: &str,
    ) -> Result<i64, LookupRepositoryError> {
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        let count_sql = format!("SELECT COUNT(*) FROM \"{}\"", table_name);
        let count: (i64,) = sqlx::query_as(&count_sql).fetch_one(&self.pool).await?;

        Ok(count.0)
    }

    /// Get the estimated size of a dynamic table in bytes
    #[instrument(skip(self))]
    pub async fn get_table_size(&self, table_name: &str) -> Result<i64, LookupRepositoryError> {
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        let size: (i64,) = sqlx::query_as("SELECT pg_total_relation_size($1::regclass)")
            .bind(table_name)
            .fetch_one(&self.pool)
            .await?;

        Ok(size.0)
    }

    // ========================================================================
    // Query Operations
    // ========================================================================

    /// Perform a single key lookup
    #[instrument(skip(self))]
    pub async fn lookup(
        &self,
        table_name: &str,
        key_field: &str,
        key_value: &serde_json::Value,
        output_fields: Option<&[String]>,
        case_insensitive: bool,
    ) -> Result<Option<HashMap<String, serde_json::Value>>, LookupRepositoryError> {
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }
        if !Self::is_valid_identifier(key_field) {
            return Err(LookupRepositoryError::InvalidColumnName(
                key_field.to_string(),
            ));
        }

        // Build SELECT clause
        let select_clause = match output_fields {
            Some(fields) => {
                for f in fields {
                    if !Self::is_valid_identifier(f) {
                        return Err(LookupRepositoryError::InvalidColumnName(f.clone()));
                    }
                }
                fields
                    .iter()
                    .map(|f| format!("\"{}\"", f))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
            None => "*".to_string(),
        };

        // Build WHERE clause based on case sensitivity
        let where_clause = if case_insensitive {
            format!("LOWER(\"{}\") = LOWER($1)", key_field)
        } else {
            format!("\"{}\" = $1", key_field)
        };

        let query_sql = format!(
            "SELECT {} FROM \"{}\" WHERE {} LIMIT 1",
            select_clause, table_name, where_clause
        );

        // Convert key value to string for binding
        let key_str = Self::json_value_to_string(key_value);

        let row: Option<sqlx::postgres::PgRow> = sqlx::query(&query_sql)
            .bind(&key_str)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => {
                let mut fields = Self::row_to_hashmap(&row)?;
                Self::strip_internal_columns(&mut fields);
                Ok(Some(fields))
            }
            None => Ok(None),
        }
    }

    /// Perform a batch lookup for multiple keys
    #[instrument(skip(self, key_values))]
    pub async fn lookup_batch(
        &self,
        table_name: &str,
        key_field: &str,
        key_values: &[serde_json::Value],
        output_fields: Option<&[String]>,
        case_insensitive: bool,
    ) -> Result<HashMap<String, HashMap<String, serde_json::Value>>, LookupRepositoryError> {
        if key_values.is_empty() {
            return Ok(HashMap::new());
        }

        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }
        if !Self::is_valid_identifier(key_field) {
            return Err(LookupRepositoryError::InvalidColumnName(
                key_field.to_string(),
            ));
        }

        // Build SELECT clause
        let select_clause = match output_fields {
            Some(fields) => {
                for f in fields {
                    if !Self::is_valid_identifier(f) {
                        return Err(LookupRepositoryError::InvalidColumnName(f.clone()));
                    }
                }
                let mut cols: Vec<String> = fields.iter().map(|f| format!("\"{}\"", f)).collect();
                // Always include key field for mapping results
                if !fields.contains(&key_field.to_string()) {
                    cols.insert(0, format!("\"{}\"", key_field));
                }
                cols.join(", ")
            }
            None => "*".to_string(),
        };

        // Convert key values to strings
        let key_strings: Vec<String> = key_values.iter().map(Self::json_value_to_string).collect();

        // Build WHERE clause
        let where_clause = if case_insensitive {
            format!(
                "LOWER(\"{}\") = ANY(SELECT LOWER(unnest($1::text[])))",
                key_field
            )
        } else {
            format!("\"{}\" = ANY($1::text[])", key_field)
        };

        let query_sql = format!(
            "SELECT {} FROM \"{}\" WHERE {}",
            select_clause, table_name, where_clause
        );

        let rows = sqlx::query(&query_sql)
            .bind(&key_strings)
            .fetch_all(&self.pool)
            .await?;

        let mut results = HashMap::new();
        for row in rows {
            let mut fields = Self::row_to_hashmap(&row)?;
            Self::strip_internal_columns(&mut fields);
            if let Some(key_val) = fields.get(key_field) {
                let key_str = Self::json_value_to_string(key_val);
                results.insert(key_str, fields);
            }
        }

        Ok(results)
    }

    /// Get a sample of rows from a lookup table
    #[instrument(skip(self))]
    pub async fn sample_rows(
        &self,
        table_name: &str,
        limit: i64,
    ) -> Result<Vec<HashMap<String, serde_json::Value>>, LookupRepositoryError> {
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        let limit = limit.min(100); // Cap at 100 rows for safety

        let query_sql = format!("SELECT * FROM \"{}\" LIMIT {}", table_name, limit);

        let rows = sqlx::query(&query_sql).fetch_all(&self.pool).await?;

        let mut results = Vec::new();
        for row in rows {
            let mut fields = Self::row_to_hashmap(&row)?;
            Self::strip_internal_columns(&mut fields);
            results.push(fields);
        }

        Ok(results)
    }

    // ========================================================================
    // Row-Level CRUD Operations
    // ========================================================================

    /// List rows with pagination (includes _row_id for targeting edits/deletes)
    #[instrument(skip(self))]
    pub async fn list_rows(
        &self,
        table_name: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<HashMap<String, serde_json::Value>>, i64), LookupRepositoryError> {
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        let total = self.get_table_row_count(table_name).await?;

        let query_sql = format!(
            "SELECT * FROM \"{}\" ORDER BY _row_id LIMIT {} OFFSET {}",
            table_name, limit, offset
        );

        let rows = sqlx::query(&query_sql).fetch_all(&self.pool).await?;

        let mut results = Vec::new();
        for row in rows {
            let fields = Self::row_to_hashmap(&row)?;
            // Keep _row_id in list_rows results (needed for edit/delete targeting)
            results.push(fields);
        }

        Ok((results, total))
    }

    /// Insert a single row, returning the assigned _row_id
    #[instrument(skip(self, record))]
    pub async fn insert_row(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        record: &HashMap<String, serde_json::Value>,
    ) -> Result<i64, LookupRepositoryError> {
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        // Only include user-defined columns (skip _row_id)
        let column_names: Vec<&str> = columns.iter().map(|c| c.name.as_str()).collect();

        let placeholders: Vec<String> = (1..=column_names.len())
            .map(|i| format!("${}", i))
            .collect();

        let quoted_columns: Vec<String> =
            column_names.iter().map(|c| format!("\"{}\"", c)).collect();

        let insert_sql = format!(
            "INSERT INTO \"{}\" ({}) VALUES ({}) RETURNING _row_id",
            table_name,
            quoted_columns.join(", "),
            placeholders.join(", ")
        );

        let mut query = sqlx::query_scalar::<_, i64>(&insert_sql);

        for (col_idx, col_name) in column_names.iter().enumerate() {
            let value = record.get(*col_name);
            let col_type = &columns[col_idx].data_type;
            query = Self::bind_value_scalar(query, value, col_type);
        }

        let row_id = query.fetch_one(&self.pool).await?;
        Ok(row_id)
    }

    /// Update a single row identified by _row_id
    #[instrument(skip(self, record))]
    pub async fn update_row(
        &self,
        table_name: &str,
        row_id: i64,
        columns: &[LookupColumn],
        record: &HashMap<String, serde_json::Value>,
    ) -> Result<(), LookupRepositoryError> {
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        // Build SET clause from provided columns
        let column_names: Vec<&str> = columns.iter().map(|c| c.name.as_str()).collect();
        let set_parts: Vec<String> = column_names
            .iter()
            .enumerate()
            .map(|(i, name)| format!("\"{}\" = ${}", name, i + 1))
            .collect();

        let update_sql = format!(
            "UPDATE \"{}\" SET {} WHERE _row_id = ${}",
            table_name,
            set_parts.join(", "),
            column_names.len() + 1
        );

        let mut query = sqlx::query(&update_sql);

        for (col_idx, col_name) in column_names.iter().enumerate() {
            let value = record.get(*col_name);
            let col_type = &columns[col_idx].data_type;
            query = Self::bind_value(query, value, col_type);
        }

        query = query.bind(row_id);

        let result = query.execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(LookupRepositoryError::RowNotFound(row_id));
        }

        Ok(())
    }

    /// Delete a single row by _row_id
    #[instrument(skip(self))]
    pub async fn delete_row(
        &self,
        table_name: &str,
        row_id: i64,
    ) -> Result<(), LookupRepositoryError> {
        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        let delete_sql = format!("DELETE FROM \"{}\" WHERE _row_id = $1", table_name);
        let result = sqlx::query(&delete_sql)
            .bind(row_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(LookupRepositoryError::RowNotFound(row_id));
        }

        Ok(())
    }

    /// Delete multiple rows by _row_id
    #[instrument(skip(self, row_ids))]
    pub async fn delete_rows(
        &self,
        table_name: &str,
        row_ids: &[i64],
    ) -> Result<u64, LookupRepositoryError> {
        if row_ids.is_empty() {
            return Ok(0);
        }

        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }

        let delete_sql = format!(
            "DELETE FROM \"{}\" WHERE _row_id = ANY($1::bigint[])",
            table_name
        );
        let result = sqlx::query(&delete_sql)
            .bind(row_ids)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    // ========================================================================
    // Usage / cross-references
    // ========================================================================

    /// Find detection rules whose nPL `query` body references this lookup table
    /// via `@<table_name>` (with or without a trailing `.column`).
    ///
    /// Match strategy: substring match on `@<name>` over the `query` column,
    /// then post-filtered in Rust to require the `@` token to be word-bounded
    /// (i.e. not preceded by an alphanumeric/underscore and followed by a non-
    /// identifier char or end-of-string). This avoids false positives where
    /// `@foo_bar` would otherwise match a query for `@foo`.
    ///
    /// Returns `(rule_id, rule_name, mitre_tactics, query)` for each match.
    /// Archived rules are excluded.
    #[instrument(skip(self))]
    pub async fn find_rules_referencing(
        &self,
        table_name: &str,
    ) -> Result<Vec<RuleReferenceRow>, LookupRepositoryError> {
        let token = format!("@{}", table_name);
        let like_pattern = format!("%{}%", token);

        // Use ILIKE for case-insensitive match. The PG planner can still use a
        // seq scan on the (small) detection_rules table; this is fine for v1.
        let rows: Vec<(Uuid, String, Option<Vec<String>>, String)> = sqlx::query_as(
            r#"
            SELECT id, name, mitre_tactics, query
            FROM detection_rules
            WHERE archived = FALSE
              AND query ILIKE $1
            ORDER BY name
            "#,
        )
        .bind(&like_pattern)
        .fetch_all(&self.pool)
        .await?;

        let token_lc = token.to_lowercase();
        let mut out = Vec::new();
        for (id, name, tactics, query) in rows {
            if Self::has_word_bounded_token(&query, &token_lc) {
                out.push(RuleReferenceRow {
                    id,
                    name,
                    mitre_tactics: tactics.unwrap_or_default(),
                    query,
                });
            }
        }
        Ok(out)
    }

    /// True if `haystack` contains `token` (case-insensitive) at a position
    /// where the next character (if any) is NOT an identifier continuation
    /// character (alphanumeric or underscore). This treats `@foo` as distinct
    /// from `@foobar` while still matching `@foo`, `@foo.col`, `@foo)`, etc.
    fn has_word_bounded_token(haystack: &str, token_lc: &str) -> bool {
        if token_lc.is_empty() {
            return false;
        }
        let hay_lc = haystack.to_lowercase();
        let mut start = 0;
        while let Some(idx) = hay_lc[start..].find(token_lc) {
            let pos = start + idx;
            let end = pos + token_lc.len();
            let next_char = hay_lc[end..].chars().next();
            let is_bounded = match next_char {
                None => true,
                Some(c) => !(c.is_ascii_alphanumeric() || c == '_'),
            };
            if is_bounded {
                return true;
            }
            start = end;
        }
        false
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Strip internal columns from a result HashMap
    fn strip_internal_columns(map: &mut HashMap<String, serde_json::Value>) {
        for col in INTERNAL_COLUMNS {
            map.remove(*col);
        }
    }

    /// Validate that an identifier is safe for use in SQL
    fn is_valid_identifier(name: &str) -> bool {
        if name.is_empty() || name.len() > 63 {
            return false;
        }
        // Must start with letter or underscore
        let first = name.chars().next().unwrap();
        if !first.is_ascii_alphabetic() && first != '_' {
            return false;
        }
        // Rest must be alphanumeric or underscore
        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// Convert a JSON value to a string for SQL binding
    fn json_value_to_string(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Null => String::new(),
            _ => value.to_string(),
        }
    }

    /// Parse a timestamp string into a DateTime<Utc>, trying multiple common formats
    fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
        // Try RFC 3339 / ISO 8601 with timezone
        if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
            return Some(dt.with_timezone(&Utc));
        }
        // Try ISO 8601 with space separator
        if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%z") {
            return Some(dt.with_timezone(&Utc));
        }
        // Try without timezone (assume UTC)
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
            return Some(ndt.and_utc());
        }
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
            return Some(ndt.and_utc());
        }
        // Date only
        if let Ok(nd) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
            return nd.and_hms_opt(0, 0, 0).map(|ndt| ndt.and_utc());
        }
        tracing::warn!(value = %s, "Failed to parse timestamp string, binding as NULL");
        None
    }

    /// Bind a JSON value to a query based on column type
    fn bind_value<'q>(
        query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
        value: Option<&serde_json::Value>,
        col_type: &ColumnType,
    ) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
        match value {
            // NAN-1361: bind a type-correct NULL per column. Binding `None::<String>`
            // for a non-text column (e.g. a bigint column missing from a ragged row)
            // sends a text parameter into that column -> SQLSTATE 42804 datatype_mismatch
            // -> 500. A typed NULL inserts cleanly.
            None | Some(serde_json::Value::Null) => match col_type {
                ColumnType::Text => query.bind(None::<String>),
                ColumnType::Integer => query.bind(None::<i64>),
                ColumnType::Float => query.bind(None::<f64>),
                ColumnType::Boolean => query.bind(None::<bool>),
                ColumnType::Timestamp => query.bind(None::<DateTime<Utc>>),
                ColumnType::Json => query.bind(None::<serde_json::Value>),
            },
            Some(v) => match col_type {
                ColumnType::Text => query.bind(Self::json_value_to_string(v)),
                ColumnType::Integer => {
                    let int_val = v.as_i64();
                    query.bind(int_val)
                }
                ColumnType::Float => {
                    let float_val = v.as_f64();
                    query.bind(float_val)
                }
                ColumnType::Boolean => {
                    let bool_val = v.as_bool();
                    query.bind(bool_val)
                }
                ColumnType::Timestamp => {
                    let ts_str = Self::json_value_to_string(v);
                    query.bind(Self::parse_timestamp(&ts_str))
                }
                ColumnType::Json => query.bind(v.clone()),
            },
        }
    }

    /// Bind a JSON value to a scalar query based on column type (for RETURNING queries)
    fn bind_value_scalar<'q, O>(
        query: sqlx::query::QueryScalar<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
        value: Option<&serde_json::Value>,
        col_type: &ColumnType,
    ) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
        match value {
            // NAN-1361: bind a type-correct NULL per column. Binding `None::<String>`
            // for a non-text column (e.g. a bigint column missing from a ragged row)
            // sends a text parameter into that column -> SQLSTATE 42804 datatype_mismatch
            // -> 500. A typed NULL inserts cleanly.
            None | Some(serde_json::Value::Null) => match col_type {
                ColumnType::Text => query.bind(None::<String>),
                ColumnType::Integer => query.bind(None::<i64>),
                ColumnType::Float => query.bind(None::<f64>),
                ColumnType::Boolean => query.bind(None::<bool>),
                ColumnType::Timestamp => query.bind(None::<DateTime<Utc>>),
                ColumnType::Json => query.bind(None::<serde_json::Value>),
            },
            Some(v) => match col_type {
                ColumnType::Text => query.bind(Self::json_value_to_string(v)),
                ColumnType::Integer => query.bind(v.as_i64()),
                ColumnType::Float => query.bind(v.as_f64()),
                ColumnType::Boolean => query.bind(v.as_bool()),
                ColumnType::Timestamp => {
                    let ts_str = Self::json_value_to_string(v);
                    query.bind(Self::parse_timestamp(&ts_str))
                }
                ColumnType::Json => query.bind(v.clone()),
            },
        }
    }

    /// Convert a PostgreSQL row to a HashMap
    fn row_to_hashmap(
        row: &sqlx::postgres::PgRow,
    ) -> Result<HashMap<String, serde_json::Value>, LookupRepositoryError> {
        let mut map = HashMap::new();
        let columns = row.columns();

        for col in columns {
            let name = col.name().to_string();
            let value: Option<serde_json::Value> = match col.type_info().name() {
                "TEXT" | "VARCHAR" | "CHAR" | "NAME" => row
                    .try_get::<Option<String>, _>(col.ordinal())
                    .ok()
                    .flatten()
                    .map(serde_json::Value::String),
                "INT2" | "INT4" | "INT8" | "BIGINT" => row
                    .try_get::<Option<i64>, _>(col.ordinal())
                    .ok()
                    .flatten()
                    .map(|v| serde_json::Value::Number(v.into())),
                "FLOAT4" | "FLOAT8" | "NUMERIC" => row
                    .try_get::<Option<f64>, _>(col.ordinal())
                    .ok()
                    .flatten()
                    .and_then(|v| serde_json::Number::from_f64(v))
                    .map(serde_json::Value::Number),
                "BOOL" => row
                    .try_get::<Option<bool>, _>(col.ordinal())
                    .ok()
                    .flatten()
                    .map(serde_json::Value::Bool),
                "TIMESTAMPTZ" | "TIMESTAMP" => row
                    .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(col.ordinal())
                    .ok()
                    .flatten()
                    .map(|v| serde_json::Value::String(v.to_rfc3339())),
                "JSON" | "JSONB" => row
                    .try_get::<Option<serde_json::Value>, _>(col.ordinal())
                    .ok()
                    .flatten(),
                _ => {
                    // Default to string representation
                    row.try_get::<Option<String>, _>(col.ordinal())
                        .ok()
                        .flatten()
                        .map(serde_json::Value::String)
                }
            };

            map.insert(name, value.unwrap_or(serde_json::Value::Null));
        }

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_identifier() {
        assert!(LookupRepository::is_valid_identifier("valid_name"));
        assert!(LookupRepository::is_valid_identifier("_private"));
        assert!(LookupRepository::is_valid_identifier("Table123"));

        assert!(!LookupRepository::is_valid_identifier(""));
        assert!(!LookupRepository::is_valid_identifier("123start"));
        assert!(!LookupRepository::is_valid_identifier("has-dash"));
        assert!(!LookupRepository::is_valid_identifier("has space"));
        assert!(!LookupRepository::is_valid_identifier("has.dot"));
    }

    #[test]
    fn test_word_bounded_token_match() {
        // exact end-of-string match
        assert!(LookupRepository::has_word_bounded_token(
            "foo @bar",
            "@bar"
        ));
        // followed by dot (column ref)
        assert!(LookupRepository::has_word_bounded_token(
            "x IN @bar.col",
            "@bar"
        ));
        // followed by space / paren / comma
        assert!(LookupRepository::has_word_bounded_token(
            "where x = @bar)",
            "@bar"
        ));
        // case-insensitive
        assert!(LookupRepository::has_word_bounded_token(
            "WHERE x = @BAR",
            "@bar"
        ));
        // NOT a match: token is a prefix of a longer identifier
        assert!(!LookupRepository::has_word_bounded_token(
            "use @bar_baz",
            "@bar"
        ));
        // NOT a match: missing entirely
        assert!(!LookupRepository::has_word_bounded_token(
            "use @other",
            "@bar"
        ));
    }

    #[test]
    fn test_json_value_to_string() {
        assert_eq!(
            LookupRepository::json_value_to_string(&serde_json::json!("hello")),
            "hello"
        );
        assert_eq!(
            LookupRepository::json_value_to_string(&serde_json::json!(42)),
            "42"
        );
        assert_eq!(
            LookupRepository::json_value_to_string(&serde_json::json!(true)),
            "true"
        );
        assert_eq!(
            LookupRepository::json_value_to_string(&serde_json::Value::Null),
            ""
        );
    }
}
