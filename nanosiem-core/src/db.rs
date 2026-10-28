// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database connection and pool management

pub mod clickhouse_migrate;
pub mod config;
pub mod contention;
pub mod connection_budget;
pub mod dual_pool;
pub mod edition_sql;
pub mod migrations;
pub mod pool;
pub mod pooler;
pub mod repo_error;
pub mod repo_store;
pub mod repository;

pub use clickhouse_migrate::{ClickHouseMigrateError, ClickHouseMigrator};
pub use config::DatabaseConfig;
pub use dual_pool::{DualPool, DualPoolConfig, DualPoolError, HealthStatus, TableNames};
pub use migrations::{
    embedded_postgres_versions, run_postgres_migrations, verify_postgres_schema_head, MigrationError,
    MigrationMode, SchemaHeadError,
};
pub use pool::Database;
pub use repo_error::RepoError;
pub use repository::*;
