// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Source repository for database operations
//!
//! Supports both PostgreSQL-only and dual-pool modes:
//! - PostgreSQL is always used for log source metadata (CRUD operations)
//! - ClickHouse is used for log statistics when configured

mod crud;
mod deployments;
mod health;
mod helpers;
mod status;

use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LogSourceRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("ClickHouse error: {0}")]
    ClickHouseError(String),
    #[error("Log source not found: {0}")]
    NotFound(String),
    #[error("Log source name already exists: {0}")]
    DuplicateName(String),
    /// Optimistic-concurrency precondition failed: the row changed after the
    /// caller last read it.
    #[error("Log source was modified by another update: {0}")]
    StaleVersion(uuid::Uuid),
}

pub struct LogSourceRepository {
    pool: PgPool,
    ch_client: Option<ClickHouseClient>,
    /// TableNames resolver — used by rollup-backed reads (NAN-733) to pick
    /// the `_distributed` wrapper in cluster mode. Standalone deploys get
    /// `TableNames::new(false)` and read the local table directly.
    table_names: crate::db::TableNames,
}

impl LogSourceRepository {
    /// Create a new repository with PostgreSQL only
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            ch_client: None,
            table_names: crate::db::TableNames::new(false),
        }
    }

    /// Create a new repository with ClickHouse for log stats. `table_names`
    /// resolves to the `_distributed` rollup variant in cluster mode (NAN-733).
    pub fn with_clickhouse(
        pool: PgPool,
        ch_client: ClickHouseClient,
        table_names: crate::db::TableNames,
    ) -> Self {
        Self {
            pool,
            ch_client: Some(ch_client),
            table_names,
        }
    }
}
