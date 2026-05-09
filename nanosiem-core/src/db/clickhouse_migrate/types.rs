// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core types for the ClickHouse migration system.

use thiserror::Error;

/// Errors that can occur during ClickHouse migrations
#[derive(Error, Debug)]
pub enum ClickHouseMigrateError {
    #[error("ClickHouse error: {0}")]
    ClickHouse(String),

    #[error("IO error reading migrations: {0}")]
    Io(#[from] std::io::Error),

    #[error("Migration file name invalid: {0}")]
    InvalidFileName(String),

    #[error(
        "missing migration(s) not yet applied: {missing:?}. Run the clickhouse_migrator \
         binary (or the pre-deploy migration Job) before starting nanosiem-api."
    )]
    SchemaBehind { missing: Vec<String> },

    #[error(
        "migration content drift detected — file checksum does not match the row in \
         _migrations. Files edited after being applied: {drifted:?}. Migration files \
         must be immutable once applied; create a new numbered migration instead."
    )]
    ChecksumMismatch { drifted: Vec<String> },
}

/// A single migration file
#[derive(Debug, Clone)]
pub struct Migration {
    /// Version/ordering prefix (e.g., "001", "002")
    pub version: String,
    /// Human-readable name from filename
    pub name: String,
    /// Full filename
    pub filename: String,
    /// SQL content
    pub sql: String,
}

/// ClickHouse migration runner
pub struct ClickHouseMigrator {
    pub(super) client: clickhouse::Client,
    pub(super) database: String,
    /// Whether this is a ClickHouse Cloud instance (detected on first run)
    pub(super) is_cloud: Option<bool>,
    /// Cluster name if running against a sharded cluster (detected on first run)
    pub(super) cluster: Option<Option<String>>,
}

impl ClickHouseMigrator {
    /// Create a new migrator with the given ClickHouse client
    pub fn new(client: clickhouse::Client, database: impl Into<String>) -> Self {
        Self {
            client,
            database: database.into(),
            is_cloud: None,
            cluster: None,
        }
    }
}
