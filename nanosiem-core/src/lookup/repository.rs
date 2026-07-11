// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup storage abstraction.
//!
//! Defines the [`LookupStore`] trait — the storage surface the
//! [`LookupService`](super::service::LookupService) drives — plus the shared
//! error type and the `RuleReferenceRow` carrier. Two backends implement it:
//!
//! - [`ClickHouseLookupRepository`](super::clickhouse_repository::ClickHouseLookupRepository)
//!   (default, NAN-1581): registry stays in Postgres, but row data lives in ONE
//!   shared ClickHouse `lookup_rows` table (ReplacingMergeTree, argMax dedup on
//!   read).
//! - [`PostgresLookupRepository`](super::postgres_repository::PostgresLookupRepository)
//!   (rollback-only): registry in Postgres + one dynamically-created Postgres
//!   table per lookup for the row data. Re-exported as `LookupRepository` for
//!   backward compatibility.
//!
//! Registry metadata (names, columns, primary key, counts) ALWAYS lives in
//! Postgres regardless of backend; only the row data placement differs. Both
//! impls therefore carry the Postgres pool for the registry methods.
//!
//! The active backend is selected at runtime by `LOOKUP_STORAGE_BACKEND`
//! (default `clickhouse`; `postgres` is rollback-only) — see
//! [`LookupStorageBackend`].

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use super::types::*;

#[derive(Error, Debug)]
pub enum LookupRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("ClickHouse error: {0}")]
    ClickHouseError(String),
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

/// Row returned by [`LookupStore::find_rules_referencing`].
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

/// Selects which storage backend holds lookup ROW DATA (NAN-1581).
///
/// The registry always lives in Postgres; this only toggles where row data is
/// read from and written to. Defaults to `ClickHouse` — moving lookup row data
/// off Postgres is the intended state. `LOOKUP_STORAGE_BACKEND=postgres` remains
/// solely as an emergency operator rollback (the legacy per-name PG tables are
/// kept one release for that); it is not the default and not where we're going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupStorageBackend {
    Postgres,
    ClickHouse,
}

impl LookupStorageBackend {
    /// Resolve the backend from the `LOOKUP_STORAGE_BACKEND` env var.
    ///
    /// Default (unset) is `ClickHouse`. Accepts `clickhouse`/`postgres`
    /// (case-insensitive); `postgres` is the emergency rollback only. An
    /// unrecognized value logs a warning and uses the `ClickHouse` default
    /// rather than failing boot.
    pub fn from_env() -> Self {
        match std::env::var("LOOKUP_STORAGE_BACKEND") {
            Ok(v) => Self::from_str(&v),
            Err(_) => Self::ClickHouse,
        }
    }

    /// Parse a backend name (case-insensitive); unknown → `ClickHouse` (default).
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "clickhouse" | "ch" => Self::ClickHouse,
            "postgres" | "postgresql" | "pg" => Self::Postgres,
            other => {
                tracing::warn!(
                    value = %other,
                    "Unrecognized LOOKUP_STORAGE_BACKEND; defaulting to clickhouse"
                );
                Self::ClickHouse
            }
        }
    }
}

/// Storage surface for lookup tables.
///
/// Mirrors the original `LookupRepository` public surface so the service is
/// backend-agnostic. Registry methods (`list_tables`, `get_table`,
/// `register_table`, `update_table_stats`, `unregister_table`,
/// `update_table_columns`, `find_rules_referencing`) are Postgres-backed in
/// BOTH impls. The data methods differ per backend.
#[async_trait]
pub trait LookupStore: Send + Sync {
    // ---- Registry (always Postgres) ----
    async fn list_tables(&self) -> Result<Vec<LookupTable>, LookupRepositoryError>;
    async fn get_table(&self, name: &str) -> Result<LookupTable, LookupRepositoryError>;
    async fn table_exists(&self, name: &str) -> Result<bool, LookupRepositoryError>;
    async fn register_table(
        &self,
        new_table: &NewLookupTable,
        actual_table_name: &str,
        created_by_user_id: Option<Uuid>,
    ) -> Result<LookupTable, LookupRepositoryError>;
    async fn update_table_stats(
        &self,
        name: &str,
        row_count: i64,
        size_bytes: i64,
    ) -> Result<(), LookupRepositoryError>;
    async fn unregister_table(&self, name: &str) -> Result<LookupTable, LookupRepositoryError>;
    async fn update_table_columns(
        &self,
        name: &str,
        columns: &[LookupColumn],
        primary_key: Option<&str>,
    ) -> Result<(), LookupRepositoryError>;
    async fn find_rules_referencing(
        &self,
        table_name: &str,
    ) -> Result<Vec<RuleReferenceRow>, LookupRepositoryError>;

    // ---- Schema / lifecycle (backend-specific) ----
    async fn create_dynamic_table(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        primary_key: Option<&str>,
    ) -> Result<(), LookupRepositoryError>;
    async fn drop_dynamic_table(&self, table_name: &str) -> Result<(), LookupRepositoryError>;
    async fn truncate_dynamic_table(&self, table_name: &str)
        -> Result<(), LookupRepositoryError>;
    #[allow(clippy::too_many_arguments)]
    async fn swap_staged_table(
        &self,
        old_physical: &str,
        staging_physical: &str,
        registry_name: &str,
        columns: &[LookupColumn],
        primary_key: Option<&str>,
        row_count: i64,
    ) -> Result<(), LookupRepositoryError>;

    // ---- Row data (backend-specific) ----
    async fn insert_records(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        records: &[HashMap<String, serde_json::Value>],
    ) -> Result<usize, LookupRepositoryError>;
    /// Return the current table count and records from an idempotent batch that
    /// do not already exist.
    ///
    /// Backends that do not override this retain the conservative row-limit
    /// behavior used by ordinary append writes.
    async fn idempotent_record_counts(
        &self,
        table_name: &str,
        _idempotency_key: Uuid,
        record_count: usize,
    ) -> Result<(i64, usize), LookupRepositoryError> {
        Ok((self.get_table_row_count(table_name).await?, record_count))
    }
    /// Insert an append batch using stable row identities derived from the key.
    async fn insert_records_idempotent(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        records: &[HashMap<String, serde_json::Value>],
        _idempotency_key: Uuid,
    ) -> Result<usize, LookupRepositoryError> {
        self.insert_records(table_name, columns, records).await
    }
    async fn get_table_row_count(&self, table_name: &str) -> Result<i64, LookupRepositoryError>;
    async fn get_table_size(&self, table_name: &str) -> Result<i64, LookupRepositoryError>;
    async fn lookup(
        &self,
        table_name: &str,
        key_field: &str,
        key_value: &serde_json::Value,
        output_fields: Option<&[String]>,
        case_insensitive: bool,
    ) -> Result<Option<HashMap<String, serde_json::Value>>, LookupRepositoryError>;
    async fn lookup_batch(
        &self,
        table_name: &str,
        key_field: &str,
        key_values: &[serde_json::Value],
        output_fields: Option<&[String]>,
        case_insensitive: bool,
    ) -> Result<HashMap<String, HashMap<String, serde_json::Value>>, LookupRepositoryError>;
    async fn sample_rows(
        &self,
        table_name: &str,
        limit: i64,
    ) -> Result<Vec<HashMap<String, serde_json::Value>>, LookupRepositoryError>;
    async fn list_rows(
        &self,
        table_name: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<HashMap<String, serde_json::Value>>, i64), LookupRepositoryError>;
    async fn insert_row(
        &self,
        table_name: &str,
        columns: &[LookupColumn],
        record: &HashMap<String, serde_json::Value>,
    ) -> Result<i64, LookupRepositoryError>;
    async fn update_row(
        &self,
        table_name: &str,
        row_id: i64,
        columns: &[LookupColumn],
        record: &HashMap<String, serde_json::Value>,
    ) -> Result<(), LookupRepositoryError>;
    async fn delete_row(&self, table_name: &str, row_id: i64)
        -> Result<(), LookupRepositoryError>;
    async fn delete_rows(
        &self,
        table_name: &str,
        row_ids: &[i64],
    ) -> Result<u64, LookupRepositoryError>;
}

/// Stable row identity for a record within one logical append execution.
///
/// The high bit keeps these identities outside the positive snowflake range.
pub(crate) fn idempotent_row_id(idempotency_key: Uuid, record_index: usize) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"nanosiem-lookup-append-v1\0");
    hasher.update(idempotency_key.as_bytes());
    hasher.update((record_index as u64).to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes) | (1u64 << 63)
}

#[cfg(test)]
mod idempotency_tests {
    use super::idempotent_row_id;
    use uuid::Uuid;

    #[test]
    fn append_row_ids_are_stable_and_record_scoped() {
        let key = Uuid::parse_str("018f5e5b-3b31-7cd7-a8b5-6c51a92aa001").unwrap();
        assert_eq!(idempotent_row_id(key, 0), idempotent_row_id(key, 0));
        assert_ne!(idempotent_row_id(key, 0), idempotent_row_id(key, 1));
        assert_ne!(
            idempotent_row_id(key, 0),
            idempotent_row_id(Uuid::now_v7(), 0)
        );
        assert_ne!(idempotent_row_id(key, 0) & (1u64 << 63), 0);
    }
}

/// Backward-compatible alias: `LookupRepository` is the PostgreSQL backend.
///
/// Existing call sites construct `LookupRepository::new(pg_pool)` and pass it
/// to `LookupService::new(..)`; both continue to work unchanged.
pub use super::postgres_repository::PostgresLookupRepository as LookupRepository;
