// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database connection and pool management

pub mod clickhouse_migrate;
pub mod clickhouse_transport;
pub mod config;
pub mod dual_pool;
pub mod future_timestamp_repair;
pub mod migration_refresh;
pub mod migrations;
pub mod pool;
pub mod repo_error;
pub mod repo_store;
pub mod repository;

pub use clickhouse_migrate::{ClickHouseMigrateError, ClickHouseMigrator};
pub use config::DatabaseConfig;
pub use dual_pool::{DualPool, DualPoolConfig, DualPoolError, HealthStatus, TableNames};
pub use migrations::{
    ensure_migrator_is_current, ensure_postgres_schema_is_current, run_postgres_migrations,
    MigrationError, MigrationMode, SchemaCheckError,
};
pub use pool::Database;
pub use repo_error::RepoError;
pub use repository::*;
