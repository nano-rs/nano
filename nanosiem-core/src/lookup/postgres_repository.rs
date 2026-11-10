// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL-backed lookup repository (the default storage backend).
//!
//! Provides database operations for lookup table management including
//! registry operations and dynamic table creation/querying. This is the
//! original `LookupRepository` implementation; it is now one of two backends
//! behind the [`LookupStore`](super::repository::LookupStore) trait (NAN-1581).
//! Registry metadata always lives in Postgres regardless of backend; this impl
//! additionally stores the ROW DATA as one dynamically-created Postgres table
//! per lookup.
//!
//! Requirements: 2.1, 2.2, 2.4, 2.5, 2.7, 3.1, 3.2, 3.3, 3.4, 3.5, 5.3, 5.4

use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::{Column, PgPool, Row, TypeInfo};
use std::collections::HashMap;
use tracing::instrument;
use uuid::Uuid;

use super::repository::{
    LookupMutationGuard, LookupRepositoryError, LookupStore, RuleReferenceRow,
};
use super::types::*;
use crate::upload::ColumnType;

/// Internal columns that should be excluded from enrichment/display results
const INTERNAL_COLUMNS: &[&str] = &["_row_id"];

/// PostgreSQL-backed repository for lookup table operations.
///
/// Aliased as `LookupRepository` for backward compatibility — existing call
/// sites that do `LookupRepository::new(pool)` continue to construct this.
#[derive(Clone)]
pub struct PostgresLookupRepository {
    pool: PgPool,
}

impl PostgresLookupRepository {
    /// Create a new PostgreSQL-backed lookup repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Acquire the transaction-scoped advisory lock shared by every mutator of
    /// one logical lookup. The transaction deliberately carries no data work:
    /// it is an ownership guard around backend writes that may live in another
    /// database (ClickHouse).
    pub async fn lock_logical_table(
        &self,
        name: &str,
    ) -> Result<LookupMutationGuard, LookupRepositoryError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('nanosiem.lookup:' || $1, 0))")
            .bind(name)
            .execute(&mut *transaction)
            .await?;
        Ok(LookupMutationGuard::locked(transaction))
    }

    pub async fn record_staged_generation(
        &self,
        logical_name: &str,
        physical_name: &str,
        storage_backend: &str,
    ) -> Result<(), LookupRepositoryError> {
        sqlx::query(
            r#"
            INSERT INTO lookup_generation_cleanup
                (physical_name, logical_name, storage_backend, generation_state)
            VALUES ($1, $2, $3, 'staged')
            ON CONFLICT (physical_name) DO UPDATE
            SET logical_name = EXCLUDED.logical_name,
                storage_backend = EXCLUDED.storage_backend,
                generation_state = 'staged',
                attempt_count = 0,
                next_attempt_at = NOW(),
                last_error = NULL,
                updated_at = NOW()
            "#,
        )
        .bind(physical_name)
        .bind(logical_name)
        .bind(storage_backend)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_generation_live(
        &self,
        physical_name: &str,
    ) -> Result<(), LookupRepositoryError> {
        sqlx::query("DELETE FROM lookup_generation_cleanup WHERE physical_name = $1")
            .bind(physical_name)
            .execute(&self.pool)
            .await?;
        Ok(())
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

    /// Resolve the column definitions for a lookup by its PHYSICAL table name
    /// (the `table_name` column in the registry, e.g. `lookup_assets`).
    ///
    /// The ClickHouse backend (NAN-1581) receives the physical name in its row
    /// methods and needs the registry's typed columns to encode/decode
    /// `cols_json`. Errors with `TableNotFound` if no registry row matches.
    #[instrument(skip(self))]
    pub async fn get_columns_for_physical(
        &self,
        table_name: &str,
    ) -> Result<Vec<LookupColumn>, LookupRepositoryError> {
        let cols = sqlx::query_scalar::<_, sqlx::types::Json<Vec<LookupColumn>>>(
            "SELECT columns FROM lookup_tables_registry WHERE table_name = $1",
        )
        .bind(table_name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| LookupRepositoryError::TableNotFound(table_name.to_string()))?;
        Ok(cols.0)
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

    /// Point the registry entry `name` at a fully staged replacement in one
    /// locked PostgreSQL transaction (NAN-2875 review fix).
    ///
    /// The staged generation lives under its own physical name, so until this
    /// commits every reader still resolves the old physical name and sees only
    /// old data; after it commits they resolve the staging name and see only
    /// new data. There is never a moment where both generations answer.
    ///
    /// The physical name is the compare-and-swap revision: every replace stages
    /// under a fresh random name, so if the row's `table_name` is no longer
    /// `expected_physical` a concurrent replace or delete already moved it and
    /// this one is refused. The caller purges `expected_physical` only after
    /// this returns `Ok`.
    pub async fn publish_staged_table(
        &self,
        name: &str,
        expected_physical: &str,
        staging_physical: &str,
        columns: &[LookupColumn],
        primary_key: Option<&str>,
        row_count: i64,
        storage_backend: &str,
    ) -> Result<(), LookupRepositoryError> {
        let columns_json = serde_json::to_value(columns).map_err(|error| {
            LookupRepositoryError::DatabaseError(sqlx::Error::Protocol(error.to_string()))
        })?;
        let mut tx = self.pool.begin().await?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT table_name FROM lookup_tables_registry WHERE name = $1 FOR UPDATE",
        )
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        match current {
            None => return Err(LookupRepositoryError::TableNotFound(name.to_string())),
            Some(current) if current != expected_physical => {
                return Err(LookupRepositoryError::ConcurrentModification(
                    name.to_string(),
                ))
            }
            Some(_) => {}
        }
        sqlx::query(
            "UPDATE lookup_tables_registry SET table_name = $2, columns = $3, primary_key = $4, \
             row_count = $5, size_bytes = 0, updated_at = NOW() WHERE name = $1",
        )
        .bind(name)
        .bind(staging_physical)
        .bind(columns_json)
        .bind(primary_key)
        .bind(row_count)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO lookup_generation_cleanup
                (physical_name, logical_name, storage_backend, generation_state)
            VALUES ($1, $2, $3, 'retired')
            ON CONFLICT (physical_name) DO UPDATE
            SET logical_name = EXCLUDED.logical_name,
                storage_backend = EXCLUDED.storage_backend,
                generation_state = 'retired',
                attempt_count = 0,
                next_attempt_at = NOW(),
                last_error = NULL,
                updated_at = NOW()
            "#,
        )
        .bind(expected_physical)
        .bind(name)
        .bind(storage_backend)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM lookup_generation_cleanup WHERE physical_name = $1")
            .bind(staging_physical)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Delete the registry entry for `table` only if no active detection rule
    /// depends on it, with the check and the delete serialized (NAN-2875
    /// review fix).
    ///
    /// - `FOR UPDATE` on the registry row fences a concurrent replace/delete.
    /// - `LOCK TABLE detection_rules IN SHARE MODE` blocks rule inserts and
    ///   updates until this commits (and waits out in-flight ones), so a rule
    ///   cannot gain the reference between the check and the delete.
    /// - The reference check parses each candidate rule with the nPL parser
    ///   ([`super::references`]), not a single textual spelling.
    ///
    /// With `drop_physical_in_tx` the PostgreSQL row table is dropped in the
    /// same transaction (transactional DDL). The ClickHouse backend passes
    /// `false` and purges its rows after this commits.
    pub async fn delete_table_guarded(
        &self,
        table: &LookupTable,
        drop_physical_in_tx: bool,
        storage_backend: &str,
    ) -> Result<(), LookupRepositoryError> {
        if drop_physical_in_tx && !Self::is_valid_identifier(&table.table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table.table_name.clone(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        let locked: Option<String> = sqlx::query_scalar(
            "SELECT table_name FROM lookup_tables_registry WHERE id = $1 AND name = $2 FOR UPDATE",
        )
        .bind(table.id)
        .bind(&table.name)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(physical) = locked else {
            return Err(LookupRepositoryError::TableNotFound(table.name.clone()));
        };
        if physical != table.table_name {
            return Err(LookupRepositoryError::ConcurrentModification(
                table.name.clone(),
            ));
        }
        sqlx::query("LOCK TABLE detection_rules IN SHARE MODE")
            .execute(&mut *tx)
            .await?;
        let rules = Self::rules_referencing(&mut *tx, &table.name).await?;
        if !rules.is_empty() {
            let names = rules
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(LookupRepositoryError::TableInUse(names));
        }
        sqlx::query("DELETE FROM lookup_tables_registry WHERE id = $1 AND name = $2")
            .bind(table.id)
            .bind(&table.name)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                if error.as_database_error().and_then(|db| db.code()).as_deref() == Some("23503") {
                    tracing::warn!(table_name = %table.name, error = %error, "Lookup table delete blocked by database reference");
                    LookupRepositoryError::ReferenceConflict
                } else {
                    LookupRepositoryError::DatabaseError(error)
                }
            })?;
        sqlx::query(
            r#"
            INSERT INTO lookup_generation_cleanup
                (physical_name, logical_name, storage_backend, generation_state)
            VALUES ($1, $2, $3, 'retired')
            ON CONFLICT (physical_name) DO UPDATE
            SET logical_name = EXCLUDED.logical_name,
                storage_backend = EXCLUDED.storage_backend,
                generation_state = 'retired',
                attempt_count = 0,
                next_attempt_at = NOW(),
                last_error = NULL,
                updated_at = NOW()
            "#,
        )
        .bind(&table.table_name)
        .bind(&table.name)
        .bind(storage_backend)
        .execute(&mut *tx)
        .await?;
        if drop_physical_in_tx {
            sqlx::query(&format!(
                "DROP TABLE IF EXISTS \"{}\" CASCADE",
                table.table_name
            ))
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM lookup_generation_cleanup WHERE physical_name = $1")
                .bind(&table.table_name)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
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
        let mut column_defs = vec!["\"_row_id\" BIGSERIAL PRIMARY KEY".to_string()];
        for col in columns {
            let null_constraint = if col.nullable { "" } else { " NOT NULL" };
            column_defs.push(format!(
                "\"{}\" {}{}",
                col.name,
                col.data_type.to_postgres_type(),
                null_constraint
            ));
        }

        // NAN-5230: plain CREATE TABLE. Every caller asks for a fresh
        // generation; `IF NOT EXISTS` silently handed back another lookup's
        // table when two names collided, and the caller's failure cleanup then
        // dropped it. A collision is reported, never adopted.
        let create_sql = format!(
            "CREATE TABLE \"{}\" ({})",
            table_name,
            column_defs.join(", ")
        );

        if let Err(error) = sqlx::query(&create_sql).execute(&self.pool).await {
            let duplicate = error
                .as_database_error()
                .and_then(|db| db.code())
                .is_some_and(|code| code == "42P07");
            if duplicate {
                return Err(LookupRepositoryError::TableAlreadyExists(
                    table_name.to_string(),
                ));
            }
            return Err(error.into());
        }

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

    pub async fn cleanup_generation(&self, table_name: &str) -> Result<(), LookupRepositoryError> {
        self.drop_dynamic_table(table_name).await?;
        self.mark_generation_live(table_name).await
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
        // Switch the registry pointer to the staged table (locked, CAS on the
        // old physical name), then drop the old table only after the commit.
        self.publish_staged_table(
            registry_name,
            old_physical,
            staging_physical,
            columns,
            primary_key,
            row_count,
            "postgres",
        )
        .await?;
        if let Err(error) = self.cleanup_generation(old_physical).await {
            tracing::warn!(old_physical, %error, "replaced lookup table left behind; registry already points at the new table");
        }
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

    async fn ensure_idempotent_row_index(
        &self,
        table_name: &str,
    ) -> Result<(), LookupRepositoryError> {
        use std::hash::{Hash, Hasher};

        if !Self::is_valid_identifier(table_name) {
            return Err(LookupRepositoryError::InvalidTableName(
                table_name.to_string(),
            ));
        }
        let already_unique: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM pg_index i
                JOIN pg_attribute a
                  ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
                WHERE i.indrelid = to_regclass($1)
                  AND i.indisunique
                  AND i.indnkeyatts = 1
                  AND a.attname = '_row_id'
            )
            "#,
        )
        .bind(table_name)
        .fetch_one(&self.pool)
        .await?;
        if already_unique {
            return Ok(());
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        table_name.hash(&mut hasher);
        let index_name = format!("idx_lookup_idem_{:016x}", hasher.finish());
        let sql = format!(
            "CREATE UNIQUE INDEX IF NOT EXISTS \"{}\" ON \"{}\" (\"_row_id\")",
            index_name, table_name
        );
        sqlx::query(&sql).execute(&self.pool).await?;
        Ok(())
    }

    fn idempotent_pg_row_ids(idempotency_key: Uuid, record_count: usize) -> Vec<i64> {
        (0..record_count)
            .map(|index| {
                let magnitude = (super::repository::idempotent_row_id(idempotency_key, index)
                    & i64::MAX as u64)
                    .max(1);
                -(magnitude as i64)
            })
            .collect()
    }

    pub async fn idempotent_record_counts(
        &self,
        table_name: &str,
        idempotency_key: Uuid,
        record_count: usize,
    ) -> Result<(i64, usize), LookupRepositoryError> {
        if record_count == 0 {
            return Ok((self.get_table_row_count(table_name).await?, 0));
        }
        self.ensure_idempotent_row_index(table_name).await?;
        let row_ids = Self::idempotent_pg_row_ids(idempotency_key, record_count);
        let sql = format!(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE \"_row_id\" = ANY($1)) FROM \"{}\"",
            table_name
        );
        let (current, existing): (i64, i64) = sqlx::query_as(&sql)
            .bind(&row_ids)
            .fetch_one(&self.pool)
            .await?;
        Ok((current, record_count.saturating_sub(existing as usize)))
    }

    pub async fn insert_records_idempotent(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        records: &[HashMap<String, serde_json::Value>],
        idempotency_key: Uuid,
    ) -> Result<usize, LookupRepositoryError> {
        if records.is_empty() {
            return Ok(0);
        }
        self.ensure_idempotent_row_index(table_name).await?;

        let column_names: Vec<&str> = columns.iter().map(|c| c.name.as_str()).collect();
        let row_ids = Self::idempotent_pg_row_ids(idempotency_key, records.len());
        let mut inserted = 0usize;

        for (chunk_index, chunk) in records.chunks(500).enumerate() {
            let mut values_parts = Vec::with_capacity(chunk.len());
            let mut param_idx = 1;
            for _ in chunk {
                let placeholders: Vec<String> = (0..=column_names.len())
                    .map(|_| {
                        let placeholder = format!("${}", param_idx);
                        param_idx += 1;
                        placeholder
                    })
                    .collect();
                values_parts.push(format!("({})", placeholders.join(", ")));
            }

            let mut quoted_columns = vec!["\"_row_id\"".to_string()];
            quoted_columns.extend(column_names.iter().map(|c| format!("\"{}\"", c)));
            let insert_sql = format!(
                "INSERT INTO \"{}\" ({}) VALUES {} ON CONFLICT (\"_row_id\") DO NOTHING",
                table_name,
                quoted_columns.join(", "),
                values_parts.join(", ")
            );
            let mut query = sqlx::query(&insert_sql);
            for (offset, record) in chunk.iter().enumerate() {
                query = query.bind(row_ids[chunk_index * 500 + offset]);
                for (column_index, column_name) in column_names.iter().enumerate() {
                    query = Self::bind_value(
                        query,
                        record.get(*column_name),
                        &columns[column_index].data_type,
                    );
                }
            }
            inserted += query.execute(&self.pool).await?.rows_affected() as usize;
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
        Self::rules_referencing(&self.pool, table_name).await
    }

    /// Active rules whose nPL depends on lookup `table_name`. A cheap
    /// `ILIKE '%name%'` narrows the candidates (every real reference contains
    /// the name); each candidate is then judged by
    /// [`super::references::query_text_references_lookup`], which parses it.
    async fn rules_referencing<'e, E>(
        executor: E,
        table_name: &str,
    ) -> Result<Vec<RuleReferenceRow>, LookupRepositoryError>
    where
        E: sqlx::PgExecutor<'e>,
    {
        let escaped = table_name
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let like_pattern = format!("%{escaped}%");
        let rows: Vec<(Uuid, String, Option<Vec<String>>, String)> = sqlx::query_as(
            r#"
            SELECT id, name, mitre_tactics, query
            FROM detection_rules
            WHERE archived = FALSE
              AND query ILIKE $1 ESCAPE '\'
            ORDER BY name
            "#,
        )
        .bind(&like_pattern)
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .filter(|(_, _, _, query)| {
                super::references::query_text_references_lookup(query, table_name)
            })
            .map(|(id, name, tactics, query)| RuleReferenceRow {
                id,
                name,
                mitre_tactics: tactics.unwrap_or_default(),
                query,
            })
            .collect())
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

/// `LookupStore` is satisfied by forwarding to the inherent methods above.
/// Inherent methods take resolution priority, so `self.method(..)` here calls
/// the concrete Postgres implementation rather than recursing through the trait.
#[async_trait]
impl LookupStore for PostgresLookupRepository {
    async fn lock_logical_table(
        &self,
        name: &str,
    ) -> Result<LookupMutationGuard, LookupRepositoryError> {
        PostgresLookupRepository::lock_logical_table(self, name).await
    }

    async fn list_tables(&self) -> Result<Vec<LookupTable>, LookupRepositoryError> {
        PostgresLookupRepository::list_tables(self).await
    }

    async fn get_table(&self, name: &str) -> Result<LookupTable, LookupRepositoryError> {
        PostgresLookupRepository::get_table(self, name).await
    }

    async fn table_exists(&self, name: &str) -> Result<bool, LookupRepositoryError> {
        PostgresLookupRepository::table_exists(self, name).await
    }

    async fn register_table(
        &self,
        new_table: &NewLookupTable,
        actual_table_name: &str,
        created_by_user_id: Option<Uuid>,
    ) -> Result<LookupTable, LookupRepositoryError> {
        PostgresLookupRepository::register_table(
            self,
            new_table,
            actual_table_name,
            created_by_user_id,
        )
        .await
    }

    async fn update_table_stats(
        &self,
        name: &str,
        row_count: i64,
        size_bytes: i64,
    ) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::update_table_stats(self, name, row_count, size_bytes).await
    }

    async fn unregister_table(&self, name: &str) -> Result<LookupTable, LookupRepositoryError> {
        PostgresLookupRepository::unregister_table(self, name).await
    }

    async fn delete_table(&self, table: &LookupTable) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::delete_table_guarded(self, table, false, "postgres").await?;
        if let Err(error) =
            PostgresLookupRepository::cleanup_generation(self, &table.table_name).await
        {
            tracing::warn!(table = %table.table_name, %error, "deleted lookup table left for durable cleanup");
        }
        Ok(())
    }

    async fn update_table_columns(
        &self,
        name: &str,
        columns: &[LookupColumn],
        primary_key: Option<&str>,
    ) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::update_table_columns(self, name, columns, primary_key).await
    }

    async fn create_dynamic_table(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        primary_key: Option<&str>,
    ) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::create_dynamic_table(self, table_name, columns, primary_key).await
    }

    async fn drop_dynamic_table(&self, table_name: &str) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::drop_dynamic_table(self, table_name).await
    }

    async fn record_staged_generation(
        &self,
        logical_name: &str,
        physical_name: &str,
    ) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::record_staged_generation(
            self,
            logical_name,
            physical_name,
            "postgres",
        )
        .await
    }

    async fn mark_generation_live(&self, physical_name: &str) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::mark_generation_live(self, physical_name).await
    }

    async fn cleanup_generation(&self, physical_name: &str) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::cleanup_generation(self, physical_name).await
    }

    async fn truncate_dynamic_table(&self, table_name: &str) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::truncate_dynamic_table(self, table_name).await
    }

    async fn swap_staged_table(
        &self,
        old_physical: &str,
        staging_physical: &str,
        registry_name: &str,
        columns: &[LookupColumn],
        primary_key: Option<&str>,
        row_count: i64,
    ) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::swap_staged_table(
            self,
            old_physical,
            staging_physical,
            registry_name,
            columns,
            primary_key,
            row_count,
        )
        .await
    }

    async fn insert_records(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        records: &[HashMap<String, serde_json::Value>],
    ) -> Result<usize, LookupRepositoryError> {
        PostgresLookupRepository::insert_records(self, table_name, columns, records).await
    }

    async fn idempotent_record_counts(
        &self,
        table_name: &str,
        idempotency_key: Uuid,
        record_count: usize,
    ) -> Result<(i64, usize), LookupRepositoryError> {
        PostgresLookupRepository::idempotent_record_counts(
            self,
            table_name,
            idempotency_key,
            record_count,
        )
        .await
    }

    async fn insert_records_idempotent(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        records: &[HashMap<String, serde_json::Value>],
        idempotency_key: Uuid,
    ) -> Result<usize, LookupRepositoryError> {
        PostgresLookupRepository::insert_records_idempotent(
            self,
            table_name,
            columns,
            records,
            idempotency_key,
        )
        .await
    }

    async fn get_table_row_count(&self, table_name: &str) -> Result<i64, LookupRepositoryError> {
        PostgresLookupRepository::get_table_row_count(self, table_name).await
    }

    async fn get_table_size(&self, table_name: &str) -> Result<i64, LookupRepositoryError> {
        PostgresLookupRepository::get_table_size(self, table_name).await
    }

    async fn lookup(
        &self,
        table_name: &str,
        _columns: &[LookupColumn],
        key_field: &str,
        key_value: &serde_json::Value,
        output_fields: Option<&[String]>,
        case_insensitive: bool,
    ) -> Result<Option<HashMap<String, serde_json::Value>>, LookupRepositoryError> {
        PostgresLookupRepository::lookup(
            self,
            table_name,
            key_field,
            key_value,
            output_fields,
            case_insensitive,
        )
        .await
    }

    async fn lookup_batch(
        &self,
        table_name: &str,
        _columns: &[LookupColumn],
        key_field: &str,
        key_values: &[serde_json::Value],
        output_fields: Option<&[String]>,
        case_insensitive: bool,
    ) -> Result<HashMap<String, HashMap<String, serde_json::Value>>, LookupRepositoryError> {
        PostgresLookupRepository::lookup_batch(
            self,
            table_name,
            key_field,
            key_values,
            output_fields,
            case_insensitive,
        )
        .await
    }

    async fn sample_rows(
        &self,
        table_name: &str,
        limit: i64,
    ) -> Result<Vec<HashMap<String, serde_json::Value>>, LookupRepositoryError> {
        PostgresLookupRepository::sample_rows(self, table_name, limit).await
    }

    async fn list_rows(
        &self,
        table_name: &str,
        _columns: &[LookupColumn],
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<HashMap<String, serde_json::Value>>, i64), LookupRepositoryError> {
        PostgresLookupRepository::list_rows(self, table_name, limit, offset).await
    }

    async fn insert_row(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        record: &HashMap<String, serde_json::Value>,
    ) -> Result<i64, LookupRepositoryError> {
        PostgresLookupRepository::insert_row(self, table_name, columns, record).await
    }

    async fn update_row(
        &self,
        table_name: &str,
        row_id: i64,
        columns: &[LookupColumn],
        record: &HashMap<String, serde_json::Value>,
    ) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::update_row(self, table_name, row_id, columns, record).await
    }

    async fn delete_row(&self, table_name: &str, row_id: i64) -> Result<(), LookupRepositoryError> {
        PostgresLookupRepository::delete_row(self, table_name, row_id).await
    }

    async fn delete_rows(
        &self,
        table_name: &str,
        row_ids: &[i64],
    ) -> Result<u64, LookupRepositoryError> {
        PostgresLookupRepository::delete_rows(self, table_name, row_ids).await
    }

    async fn find_rules_referencing(
        &self,
        table_name: &str,
    ) -> Result<Vec<RuleReferenceRow>, LookupRepositoryError> {
        PostgresLookupRepository::find_rules_referencing(self, table_name).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_identifier() {
        assert!(PostgresLookupRepository::is_valid_identifier("valid_name"));
        assert!(PostgresLookupRepository::is_valid_identifier("_private"));
        assert!(PostgresLookupRepository::is_valid_identifier("Table123"));

        assert!(!PostgresLookupRepository::is_valid_identifier(""));
        assert!(!PostgresLookupRepository::is_valid_identifier("123start"));
        assert!(!PostgresLookupRepository::is_valid_identifier("has-dash"));
        assert!(!PostgresLookupRepository::is_valid_identifier("has space"));
        assert!(!PostgresLookupRepository::is_valid_identifier("has.dot"));
    }

    #[test]
    fn test_json_value_to_string() {
        assert_eq!(
            PostgresLookupRepository::json_value_to_string(&serde_json::json!("hello")),
            "hello"
        );
        assert_eq!(
            PostgresLookupRepository::json_value_to_string(&serde_json::json!(42)),
            "42"
        );
        assert_eq!(
            PostgresLookupRepository::json_value_to_string(&serde_json::json!(true)),
            "true"
        );
        assert_eq!(
            PostgresLookupRepository::json_value_to_string(&serde_json::Value::Null),
            ""
        );
    }
}
